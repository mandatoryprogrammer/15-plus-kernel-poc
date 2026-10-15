package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	initialBuild = "iBoot-8737.0.0.101.5"
)

func validateRecoveryBuild(stage uint64, build string) error {
	switch stage {
	case 0x25:
		if !strings.HasPrefix(build, "iBoot-") || len(build) <= len("iBoot-") {
			return fmt.Errorf("unsupported initial loader identity %q", build)
		}
		return nil
	case 0x24:
		if build != canonicalRuntime.LoaderBuild {
			return fmt.Errorf("unsupported runtime loader %q; runtime profile requires %q", build, canonicalRuntime.LoaderBuild)
		}
		return nil
	default:
		return fmt.Errorf("unsupported Recovery stage IBFL=%02x", stage)
	}
}

type bootStep struct{ role, command string }

//go:embed boot.json
var bootSequenceJSON []byte

type bootSequenceManifest struct {
	Profile  string `json:"profile"`
	Firmware []struct {
		Role    string `json:"role"`
		Command string `json:"command"`
	} `json:"firmware"`
}

func firmwareSequence(images map[string][]byte) ([]bootStep, error) {
	var manifest bootSequenceManifest
	if err := json.Unmarshal(bootSequenceJSON, &manifest); err != nil {
		return nil, err
	}
	if manifest.Profile != canonicalRuntime.ID || len(manifest.Firmware) == 0 {
		return nil, errors.New("boot sequence does not match the selected runtime profile")
	}
	seen := map[string]bool{}
	steps := make([]bootStep, 0, len(manifest.Firmware))
	for index, row := range manifest.Firmware {
		if row.Role == "" || row.Command != "firmware" || seen[row.Role] || len(images[row.Role]) == 0 {
			return nil, fmt.Errorf("invalid firmware sequence entry %d for role %q", index, row.Role)
		}
		seen[row.Role] = true
		steps = append(steps, bootStep{row.Role, row.Command})
	}
	return steps, nil
}

// prepareBoot resolves the exact public and prepared component identities and
// wraps each typed IM4P in a freshly generated structural IMG4 policy.  It does
// not mutate cached objects; all returned images live in process memory.
func prepareBoot(ctx context.Context, c *cache) (map[string][]byte, error) {
	var public []asset
	if err := json.Unmarshal(assetManifest, &public); err != nil {
		return nil, err
	}
	bootRoles := map[string]bool{"ibec": true, "kernel": true, "sptm": true, "txm": true, "device-tree": true, "trust-cache": true}
	prepared, err := preparedSet("boot", bootRoles)
	if err != nil {
		return nil, fmt.Errorf("derived boot component set: %w", err)
	}
	roles := map[string]asset{}
	for _, a := range public {
		roles[a.Role] = a
	}
	for _, a := range prepared {
		roles[a.Role] = a
	}
	images := map[string][]byte{}
	for _, a := range roles {
		path, err := c.resolve(ctx, a)
		if err != nil {
			return nil, err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if a.Role == "ibec" {
			b, _, err = unwrapImage(b)
			if err != nil {
				return nil, errors.New("invalid prepared iBEC envelope")
			}
		} else {
			if kind, ok := map[string]string{"logo": "rlgo", "restoredcp": "rdcp"}[a.Role]; ok {
				fields, e := imageFields(b, "IM4P")
				if e != nil || len(fields) < 4 {
					return nil, errors.New("invalid firmware envelope")
				}
				b, err = replacePayload(b, kind, fields[3].body)
				if err != nil {
					return nil, err
				}
			}
		}
		manifest, manifestErr := policyManifest(b)
		if manifestErr != nil {
			return nil, fmt.Errorf("%s policy: %w", a.Role, manifestErr)
		}
		b, err = wrapImage(b, manifest)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a.Role, err)
		}
		images[a.Role] = b
	}
	return images, nil
}

// prepareRuntime overlays the verified volatile kernel and ramdisk set on the
// public firmware manifest, applies the guarded kernel/iBEC/trust changes, and
// gives every uploaded component a generated structural Image4 policy.
func prepareRuntime(ctx context.Context, c *cache) (map[string][]byte, runtimeLayout, error) {
	images, err := prepareBoot(ctx, c)
	if err != nil {
		return nil, runtimeLayout{}, err
	}
	runtimeRoles := map[string]bool{"ibec": true, "ramdisk": true, "kernel": true, "sptm": true, "txm": true, "trust-cache": true}
	rows, err := preparedSet("runtime", runtimeRoles)
	if err != nil {
		return nil, runtimeLayout{}, fmt.Errorf("prepared runtime: %w; import or derive the bootstrap component set described in README.md", err)
	}
	for _, row := range rows {
		if err = verifyFile(ctx, c.object(row), row); err != nil {
			return nil, runtimeLayout{}, err
		}
		component, readErr := os.ReadFile(c.object(row))
		if readErr != nil {
			return nil, runtimeLayout{}, readErr
		}
		if row.Role == "ibec" {
			component, _, err = unwrapImage(component)
			if err != nil {
				return nil, runtimeLayout{}, fmt.Errorf("%s envelope: %w", row.Role, err)
			}
		} else if row.Role == "kernel" {
			component, err = prepareRuntimeKernel(component)
			if err != nil {
				return nil, runtimeLayout{}, fmt.Errorf("%s policy: %w", row.Role, err)
			}
		}
		manifest, manifestErr := policyManifest(component)
		if manifestErr != nil {
			return nil, runtimeLayout{}, fmt.Errorf("%s policy: %w", row.Role, manifestErr)
		}
		component, err = wrapImage(component, manifest)
		if err != nil {
			return nil, runtimeLayout{}, fmt.Errorf("%s: %w", row.Role, err)
		}
		images[row.Role] = component
	}
	additions, err := loadPayloadAdditions(c)
	if err != nil {
		return nil, runtimeLayout{}, err
	}
	layout, err := preparePayloadTrust(images, additions)
	if err != nil {
		return nil, runtimeLayout{}, fmt.Errorf("prepare payload admission: %w", err)
	}
	return images, layout, nil
}

func waitRecovery(ctx context.Context, c *cache, want device, stage uint64, build string) error {
	return waitFor(ctx, c.out, fmt.Sprintf("Recovery stage %02X", stage), 25*time.Second, time.Second, func(ctx context.Context) (bool, error) {
		d, err := discover(ctx)
		if err != nil {
			return false, err
		}
		if d.ECID != want.ECID {
			return false, errors.New("attached device identity changed")
		}
		if d.IBFL != stage {
			return false, fmt.Errorf("observed stage %02X", d.IBFL)
		}
		u, err := openRecovery(ctx, d)
		if err != nil {
			return false, err
		}
		defer u.Close()
		version, err := u.Getenv(ctx, "build-version")
		if err != nil {
			return false, err
		}
		if version != build {
			return false, fmt.Errorf("observed bootloader %q", version)
		}
		return true, nil
	})
}

func uploadStep(ctx context.Context, c *cache, d device, initialBuild string, images map[string][]byte, step bootStep) error {
	b, ok := images[step.role]
	if !ok {
		return fmt.Errorf("missing component %s", step.role)
	}
	u, err := openRecovery(ctx, d)
	if err != nil {
		return err
	}
	err = u.Upload(ctx, step.role, b, c.out)
	closeErr := u.Close()
	if err != nil || closeErr != nil || step.command == "" {
		return errors.Join(err, closeErr)
	}
	fmt.Fprintln(c.out, "Waiting for the initial loader to commit the uploaded image (limit 2s)")
	settle := time.NewTimer(2 * time.Second)
	select {
	case <-ctx.Done():
		settle.Stop()
		return ctx.Err()
	case <-settle.C:
	}

	if step.command != "go" {
		u, err = openRecovery(ctx, d)
		if err != nil {
			return err
		}
		defer u.Close()
		return u.Command(ctx, step.command)
	}
	return executeIBEC(ctx, c, d, initialBuild)
}

// executeIBEC retries only the idempotent execution request. Some initial
// loaders acknowledge a command before their USB command worker consumes it.
// Before each retry, check the board, stage, and loader build. An unknown
// state fails closed without another upload or another instruction write. The
// transition uses a wall-clock bound instead of assuming a firmware-specific
// number of command-worker iterations.
func executeIBEC(ctx context.Context, c *cache, want device, initialBuild string) error {
	const handoffLimit = 40 * time.Second
	handoffCtx, cancel := context.WithTimeout(ctx, handoffLimit)
	defer cancel()
	attempt := 0
	for {
		if err := handoffCtx.Err(); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("iBEC execution did not advance the same board from Recovery stage 25 within %s after %d requests", handoffLimit, attempt)
		}
		current, err := discover(handoffCtx)
		if err != nil {
			return err
		}
		advanced, err := classifyIBECStage(want, current)
		if err != nil {
			return err
		}
		if advanced {
			return nil
		}

		u, err := openRecovery(handoffCtx, current)
		if err != nil {
			return err
		}
		build, buildErr := u.Getenv(handoffCtx, "build-version")
		if buildErr == nil && build != initialBuild {
			u.Close()
			return fmt.Errorf("initial loader changed during iBEC handoff: %q", build)
		}
		if buildErr != nil {
			u.Close()
			return buildErr
		}
		attempt++
		fmt.Fprintf(c.out, "Requesting iBEC execution (request %d, limit %s)\n", attempt, handoffLimit)
		commandErr := u.Command(handoffCtx, "go")
		closeErr := u.Close()
		if commandErr != nil {
			fmt.Fprintf(c.out, "iBEC execution changed USB availability: %v; checking the next stage\n", commandErr)
		}
		if closeErr != nil {
			return closeErr
		}

		advanced, err = observeIBECStage(handoffCtx, want, 4*time.Second)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
				return fmt.Errorf("iBEC execution did not advance the same board from Recovery stage 25 within %s after %d requests", handoffLimit, attempt)
			}
			return err
		}
		if advanced {
			return nil
		}
		fmt.Fprintln(c.out, "The same initial loader is still ready; retrying its execution request")
	}
}

func classifyIBECStage(want, current device) (bool, error) {
	if current.ECID != want.ECID {
		return false, errors.New("attached device identity changed during iBEC handoff")
	}
	switch current.IBFL {
	case 0x24:
		return true, nil
	case 0x25:
		return false, nil
	default:
		return false, fmt.Errorf("iBEC handoff observed unsupported Recovery stage %02X", current.IBFL)
	}
}

func observeIBECStage(ctx context.Context, want device, limit time.Duration) (bool, error) {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		current, err := discover(ctx)
		if err == nil {
			advanced, stageErr := classifyIBECStage(want, current)
			if advanced || stageErr != nil {
				return advanced, stageErr
			}
		} else if !errors.Is(err, errNoRecovery) {
			return false, err
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-deadline.C:
			return false, nil
		case <-tick.C:
		}
	}
}

func sendStep(ctx context.Context, c *cache, u *recoveryUSB, images map[string][]byte, step bootStep) error {
	b, ok := images[step.role]
	if !ok {
		return fmt.Errorf("missing component %s", step.role)
	}
	if err := u.Upload(ctx, step.role, b, c.out); err != nil {
		return err
	}
	if step.command != "" {
		err := u.Command(ctx, step.command)
		if step.command == "go" && err != nil {
			// Executing iBEC can tear down endpoint zero before its status
			// acknowledgement. Check the build and stage next.
			fmt.Fprintf(c.out, "iBEC execution changed USB availability: %v; checking the next stage\n", err)
			return nil
		}
		if err == nil && step.command != "go" {
			build, e := u.Getenv(ctx, "build-version")
			if e != nil {
				return e
			}
			if build != canonicalRuntime.LoaderBuild {
				return fmt.Errorf("loader changed after %s: %s", step.role, build)
			}
		}
		return err
	}
	return nil
}

func bootLocked(ctx context.Context, c *cache, terminal bool, command []string) (err error) {
	// Keep this sequence linear. After each transport change, check the loader
	// build, stage, or device readiness marker before opening the next transport.
	if err = doctor(ctx, c.out); err != nil {
		return err
	}
	d, err := discover(ctx)
	if err != nil {
		return err
	}
	initialLoaderBuild, err := recoveryBuild(ctx, d)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.out, "Verifying assets and preparing the boot payload")
	images, layout, err := prepareRuntime(ctx, c)
	if err != nil {
		return err
	}
	firmware, err := firmwareSequence(images)
	if err != nil {
		return err
	}
	access, err := ensureSSHAccess(ctx, c, d.ECID)
	if err != nil {
		return err
	}
	probeSerial, err := findProbeSerial(ctx)
	if err != nil {
		return err
	}
	if err = bindRecoveryToProbe(ctx, c, d, initialLoaderBuild); err != nil {
		return err
	}
	if err = waitRecovery(ctx, c, d, 0x25, initialLoaderBuild); err != nil {
		return err
	}
	loaderBase, err := prepareInitialLoader(ctx, c, initialLoaderBuild)
	if err != nil {
		return err
	}
	if err = waitRecovery(ctx, c, d, 0x25, initialLoaderBuild); err != nil {
		return err
	}
	if err = uploadStep(ctx, c, d, initialLoaderBuild, images, bootStep{"ibec", "go"}); err != nil {
		return err
	}
	if err = waitRecovery(ctx, c, d, 0x24, canonicalRuntime.LoaderBuild); err != nil {
		return err
	}
	d.IBFL = 0x24
	fmt.Fprintln(c.out, "Matching iBEC ready; loading verified firmware")
	// Keep the device in Recovery after an ordinary restart, as required by the
	// tethered chain. These two commands persist only the auto-boot preference.
	u, err := openRecovery(ctx, d)
	if err != nil {
		return err
	}
	defer u.Close()
	for _, command := range []string{"setenv auto-boot false", "saveenv"} {
		if err = u.Command(ctx, command); err != nil {
			break
		}
	}
	if err != nil {
		return err
	}
	if err = sendStep(ctx, c, u, images, bootStep{"logo", "setpicture 4"}); err != nil {
		return err
	}
	err = u.Command(ctx, "bgcolor 0 0 0")
	if err != nil {
		return err
	}
	for _, step := range firmware {
		if err = sendStep(ctx, c, u, images, step); err != nil {
			return err
		}
	}
	if err = sendStep(ctx, c, u, images, bootStep{"ramdisk", "ramdisk"}); err != nil {
		return err
	}
	if err = sendStep(ctx, c, u, images, bootStep{"device-tree", "devicetree"}); err != nil {
		return err
	}
	selector, err := armRootSelection(ctx, c.out, loaderBase, layout)
	if err != nil {
		return err
	}
	defer selector.Close()
	// The application UART endpoint survives the later kernel handoff, but a
	// descriptor opened before the warm reset remains attached to the retired
	// target-side stream. Acquire it only after the matching loader is stable.
	serial, err := startSerial(c, probeSerial)
	if err != nil {
		return err
	}
	defer serial.Close()
	if err = sendStep(ctx, c, u, images, bootStep{"sep", "sep-firmware"}); err != nil {
		return err
	}
	err = u.Upload(ctx, "kernel", images["kernel"], c.out)
	if err == nil {
		_, _ = u.control(ctx, 0x21, 1, nil)
		err = u.Command(ctx, "setenv boot-args "+canonicalRuntime.Root.BootArguments)
	}
	if err == nil {
		args, e := u.Getenv(ctx, "boot-args")
		if e != nil {
			return e
		}
		fmt.Fprintln(c.out, "Kernel arguments:", args)
		err = u.Command(ctx, "bootx")
	}
	u.Close()
	if err != nil {
		return err
	}
	if err = selector.waitAndSelect(ctx); err != nil {
		return err
	}
	if err = waitFor(ctx, c.out, "root service", 90*time.Second, 2*time.Second, func(context.Context) (bool, error) {
		b, readErr := os.ReadFile(serial.log.Name())
		return strings.Contains(string(b), "PDS1|READY|"), readErr
	}); err != nil {
		return err
	}
	if _, err = rootRequest(ctx, serial, "ping"); err != nil {
		return fmt.Errorf("root service: %w", err)
	}
	if response, mountErr := rootExec(ctx, serial, "/sbin/mount -uw /"); mountErr != nil {
		return fmt.Errorf("make volatile root writable: %w: %s", mountErr, response)
	}
	if err = mountInternalStorage(ctx, c, serial); err != nil {
		return err
	}
	if err = installBuiltins(ctx, c, serial); err != nil {
		return err
	}
	additions, err := loadPayloadAdditions(c)
	if err != nil {
		return err
	}
	if err = installPayload(ctx, c, serial, additions); err != nil {
		return err
	}
	if err = installSSHAccess(ctx, c, serial, access); err != nil {
		return err
	}
	if response, nvramErr := rootExec(ctx, serial, "/usr/sbin/nvram restored-host-timeout=0"); nvramErr != nil {
		return fmt.Errorf("set temporary USB-service deadline: %w: %s", nvramErr, response)
	}
	defer func() {
		if err == nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, cleanupErr := rootExec(cleanupCtx, serial, "/bin/bash -c '/usr/sbin/nvram -d restored-host-timeout 2>/dev/null || true'")
		err = errors.Join(err, cleanupErr)
	}()
	launch := `/bin/bash -c '/usr/local/bin/restored_external >/dev/console 2>&1 </dev/null & /usr/local/sbin/sshd -t -f /private/etc/ssh/sshd_config -h /private/etc/ssh/ssh_host_ed25519_key && /usr/local/sbin/sshd -f /private/etc/ssh/sshd_config -h /private/etc/ssh/ssh_host_ed25519_key'`
	response, err := rootExec(ctx, serial, launch)
	if err != nil {
		return fmt.Errorf("start SSH environment: %w: %s", err, response)
	}
	fmt.Fprintln(c.out, "XNU and the temporary root are running; waiting for SSH")
	return connectSSH(ctx, c, terminal, command, true)
}

func resetToRecovery(ctx context.Context, c *cache) error {
	return withDeviceLock(c, func() error { return resetToRecoveryLocked(ctx, c) })
}

// requestRunningRootReset asks the serial root service to restart a partial
// boot before using the probe reset line.
func requestRunningRootReset(ctx context.Context, c *cache, probeSerial string) bool {
	attempt, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	serial, err := startSerial(c, probeSerial)
	if err != nil {
		return false
	}
	defer serial.Close()
	if _, err = rootRequest(attempt, serial, "ping"); err != nil {
		return false
	}
	command := `/bin/bash -c '/usr/sbin/nvram auto-boot=false; /usr/sbin/nvram -d restored-host-timeout 2>/dev/null || true; /sbin/reboot >/dev/null 2>&1 </dev/null &'`
	if _, err = rootExec(attempt, serial, command); err != nil {
		return false
	}
	fmt.Fprintln(c.out, "Running root service requested a Recovery restart")
	return true
}

func resetToRecoveryLocked(ctx context.Context, c *cache) (err error) {
	probeSerial, err := findProbeSerial(ctx)
	if err != nil {
		return err
	}
	session, err := newProbeSession(ctx)
	if err != nil {
		return err
	}
	defer session.Close()
	rootReset := false
	if _, discoverErr := discover(ctx); errors.Is(discoverErr, errNoRecovery) {
		rootReset = requestRunningRootReset(ctx, c, probeSerial)
	}
	if !rootReset {
		err = session.pulseReset(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintln(c.out, "Target reset pulse sent; securing Recovery boot policy")
	}
	var wantECID uint64
	var wantBuild string
	secureRecovery := func(ctx context.Context) (bool, error) {
		d, discoverErr := discover(ctx)
		if discoverErr != nil {
			return false, discoverErr
		}
		if d.IBFL != 0x25 || wantECID != 0 && d.ECID != wantECID {
			return false, errors.New("reset produced a different board identity or Recovery stage")
		}
		wantECID = d.ECID
		u, openErr := openRecovery(ctx, d)
		if openErr != nil {
			return false, openErr
		}
		build, buildErr := u.Getenv(ctx, "build-version")
		if buildErr != nil {
			u.Close()
			return false, buildErr
		}
		if buildErr = validateRecoveryBuild(d.IBFL, build); buildErr != nil {
			u.Close()
			return false, buildErr
		}
		wantBuild = build
		for _, command := range []string{"setenv auto-boot false", "saveenv"} {
			if commandErr := u.Command(ctx, command); commandErr != nil {
				u.Close()
				return false, commandErr
			}
		}
		autoBoot, commandErr := u.Getenv(ctx, "auto-boot")
		if commandErr != nil {
			u.Close()
			return false, commandErr
		}
		if autoBoot != "false" {
			u.Close()
			return false, fmt.Errorf("auto-boot preference is %q", autoBoot)
		}
		rebootErr := u.Command(ctx, "reboot")
		u.Close()
		// Execution can remove endpoint zero before the status phase. The later
		// USB detach, reattach, and the loader build confirm the reboot.
		if rebootErr != nil {
			fmt.Fprintf(c.out, "Recovery reboot changed USB availability: %v; checking the restart\n", rebootErr)
		}
		return true, nil
	}
	if err = waitFor(ctx, c.out, "transient Recovery", 20*time.Second, 50*time.Millisecond, secureRecovery); err != nil {
		fmt.Fprintf(c.out, "Recovery USB did not enumerate after the reset pulse (%v); restarting the unmodified loader through the verified debug topology\n", err)
		if recoveryErr := restartUnmodifiedInitialLoader(ctx, c); recoveryErr != nil {
			return errors.Join(err, recoveryErr)
		}
		if err = waitFor(ctx, c.out, "recovered transient Recovery", 25*time.Second, 100*time.Millisecond, secureRecovery); err != nil {
			return err
		}
	}
	fmt.Fprintln(c.out, "Recovery policy saved; waiting for the persistent Recovery restart")
	detached := false
	return waitFor(ctx, c.out, "persistent Recovery", 60*time.Second, 100*time.Millisecond, func(ctx context.Context) (bool, error) {
		d, discoverErr := discover(ctx)
		if discoverErr != nil {
			detached = true
			return false, discoverErr
		}
		if !detached {
			return false, errors.New("waiting for Recovery USB to detach")
		}
		if d.ECID != wantECID || d.IBFL != 0x25 {
			return false, errors.New("restart produced a different board identity or Recovery stage")
		}
		u, openErr := openRecovery(ctx, d)
		if openErr != nil {
			return false, openErr
		}
		defer u.Close()
		build, buildErr := u.Getenv(ctx, "build-version")
		if buildErr != nil {
			return false, buildErr
		}
		if build != wantBuild {
			return false, fmt.Errorf("bootloader changed across reset: got %q, want %q", build, wantBuild)
		}
		return true, nil
	})
}
