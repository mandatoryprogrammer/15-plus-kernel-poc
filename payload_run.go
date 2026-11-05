package main

import (
	"bytes"
	"context"
	"debug/macho"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const targetAdmissionReceipt = "/private/var/run/15-plus-kernel-poc-admission"

type admissionIdentity struct {
	Runtime string         `json:"runtime"`
	Payload []payloadEntry `json:"payload"`
	Trust   []trustEntry   `json:"trust,omitempty"`
}

type payloadRunReport struct {
	Schema               string         `json:"schema"`
	StartedAt            string         `json:"started_at"`
	FinishedAt           string         `json:"finished_at"`
	Source               string         `json:"source"`
	Destination          string         `json:"destination"`
	SHA256               string         `json:"sha256"`
	CDHash               string         `json:"cdhash"`
	AdmissionFingerprint string         `json:"admission_fingerprint"`
	ConfigurationChanged bool           `json:"configuration_changed"`
	EnvironmentReused    bool           `json:"environment_reused"`
	ExactReadback        bool           `json:"exact_readback"`
	Dependencies         []string       `json:"dependencies,omitempty"`
	LCUUIDAdded          bool           `json:"lc_uuid_added"`
	Includes             []payloadEntry `json:"includes,omitempty"`
	Arguments            []string       `json:"arguments,omitempty"`
	Exit                 string         `json:"exit"`
	Error                string         `json:"error,omitempty"`
}

func payloadAdmissionFingerprint(c *cache) (string, error) {
	payload, err := loadPayloadAdditions(c)
	if err != nil {
		return "", err
	}
	trust, err := loadTrustAdditions(c)
	if err != nil {
		return "", err
	}
	sort.Slice(payload, func(i, j int) bool { return payload[i].Destination < payload[j].Destination })
	sort.Slice(trust, func(i, j int) bool { return trust[i].Name < trust[j].Name })
	identity := admissionIdentity{Runtime: canonicalRuntime.IOSVersion, Payload: payload, Trust: trust}
	b, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	return digest(b), nil
}

func writePayloadRunReport(c *cache, report payloadRunReport) error {
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	name := filepath.Join(c.root, "private", "payload-run-latest.json")
	tmp, err := os.CreateTemp(filepath.Dir(name), "payload-run-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(append(b, '\n'))
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, name)
}

func splitPayloadInclude(value string) (string, string, error) {
	at := strings.LastIndexByte(value, '=')
	if at <= 0 || at == len(value)-1 {
		return "", "", errors.New("--include must be FILE=/usr/local/lib/NAME or FILE=/usr/local/libexec/NAME")
	}
	source, destination := value[:at], value[at+1:]
	if !validPayloadDestination(destination) {
		return "", "", fmt.Errorf("invalid include destination %q", destination)
	}
	return source, destination, nil
}

func parsePayloadRun(args []string) (source, destination string, includes [][2]string, commandArgs []string, err error) {
	if len(args) == 0 || args[0] == "--" {
		err = errors.New("usage: payload run FILE [--dest /usr/local/bin/NAME] [--include FILE=/usr/local/lib/NAME]... [-- ARG...]")
		return
	}
	source = args[0]
	destination = "/usr/local/bin/" + filepath.Base(source)
	for index := 1; index < len(args); index++ {
		switch args[index] {
		case "--":
			commandArgs = append([]string(nil), args[index+1:]...)
			return
		case "--dest":
			if index+1 >= len(args) {
				err = errors.New("--dest needs a path")
				return
			}
			index++
			destination = args[index]
		case "--include":
			if index+1 >= len(args) {
				err = errors.New("--include needs FILE=DEST")
				return
			}
			index++
			var includeSource, includeDestination string
			includeSource, includeDestination, err = splitPayloadInclude(args[index])
			if err != nil {
				return
			}
			includes = append(includes, [2]string{includeSource, includeDestination})
		default:
			err = fmt.Errorf("unknown payload run option %q; put target arguments after --", args[index])
			return
		}
	}
	return
}

func readRemoteFile(ctx context.Context, access sshAccess, destination string) ([]byte, error) {
	var body bytes.Buffer
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := runSSH(readCtx, access, false, []string{"/bin/cat", destination}, nil, &body, os.Stderr); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

func runningAdmissionMatches(ctx context.Context, c *cache, fingerprint string) bool {
	access, err := loadAccess(ctx, c)
	if err != nil || probeSSH(ctx, c) != nil {
		return false
	}
	body, err := readRemoteFile(ctx, access, targetAdmissionReceipt)
	return err == nil && string(body) == fingerprint+"\n"
}

func retryAdmissionReset(out io.Writer, reset func() error) error {
	var failures []error
	for attempt := 1; attempt <= 2; attempt++ {
		if err := reset(); err == nil {
			return nil
		} else {
			failures = append(failures, fmt.Errorf("attempt %d: %w", attempt, err))
			if attempt < 2 {
				fmt.Fprintln(out, "First Recovery observation missed re-enumeration; issuing one bounded second reset pulse")
			}
		}
	}
	return fmt.Errorf("apply changed admission set after two reset attempts: %w", errors.Join(failures...))
}

func verifyPayloadReadback(ctx context.Context, c *cache, access sshAccess, entries []payloadEntry) error {
	for _, entry := range entries {
		a := asset{Role: "payload", SHA256: entry.SHA256, Size: entry.Size}
		if err := verifyFile(ctx, c.object(a), a); err != nil {
			return err
		}
		want, err := os.ReadFile(c.object(a))
		if err != nil {
			return err
		}
		got, err := readRemoteFile(ctx, access, entry.Destination)
		if err != nil {
			return fmt.Errorf("read back %s: %w", entry.Destination, err)
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("payload readback mismatch for %s: got %d bytes, want %d", entry.Destination, len(got), len(want))
		}
		fmt.Fprintf(c.out, "Verified target bytes %s (%s)\n", entry.Destination, entry.SHA256)
	}
	return nil
}

func runPreparedPayload(ctx context.Context, c *cache, main payloadEntry, includes []payloadEntry, args []string) error {
	return withDeviceLock(c, func() error {
		access, err := loadAccess(ctx, c)
		if err != nil {
			return err
		}
		entries := append([]payloadEntry{main}, includes...)
		if err = verifyPayloadReadback(ctx, c, access, entries); err != nil {
			return err
		}
		checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		err = runSSH(checkCtx, access, false, []string{"/bin/bash", "-c", "test -x " + shellQuote(main.Destination)}, nil, io.Discard, os.Stderr)
		cancel()
		if err != nil {
			return fmt.Errorf("payload is not executable: %s: %w", main.Destination, err)
		}
		command := append([]string{main.Destination}, args...)
		fmt.Fprintf(c.out, "Executing admitted payload: %s\n", remoteCommand(command))
		return runSSH(ctx, access, false, command, os.Stdin, os.Stdout, os.Stderr)
	})
}

// runPayload is the single high-level path for a caller-provided executable.
// It owns signing, CDHash derivation, trust composition, boot/reuse selection,
// exact target readback, and argument-safe execution.
func runPayload(ctx context.Context, c *cache, args []string) (runErr error) {
	source, destination, includes, commandArgs, err := parsePayloadRun(args)
	if err != nil {
		return err
	}
	main, err := preparePayload(source, destination)
	if err != nil {
		return err
	}
	if main.FileType != macho.TypeExec {
		return errors.New("payload run main input must be a Mach-O executable; use --include for dylibs")
	}
	prepared := []preparedPayload{main}
	seen := map[string]bool{destination: true}
	for _, include := range includes {
		if seen[include[1]] {
			return fmt.Errorf("duplicate payload destination %s", include[1])
		}
		seen[include[1]] = true
		dependency, prepareErr := preparePayload(include[0], include[1])
		if prepareErr != nil {
			return fmt.Errorf("prepare include %s: %w", include[0], prepareErr)
		}
		prepared = append(prepared, dependency)
	}
	changed, err := storePayloadPlan(ctx, c, prepared)
	if err != nil {
		return err
	}
	fingerprint, err := payloadAdmissionFingerprint(c)
	if err != nil {
		return err
	}
	report := payloadRunReport{
		Schema: "15-plus-kernel-poc.payload-run.v1", StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Source: source, Destination: main.Entry.Destination, SHA256: main.Entry.SHA256, CDHash: main.Entry.CDHash,
		AdmissionFingerprint: fingerprint, ConfigurationChanged: changed, Dependencies: main.Dependencies,
		LCUUIDAdded: main.LCUUIDAdded, Arguments: commandArgs, Exit: "incomplete",
	}
	for _, dependency := range prepared[1:] {
		report.Includes = append(report.Includes, dependency.Entry)
	}
	defer func() {
		report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if runErr != nil {
			report.Exit = "failed"
			report.Error = runErr.Error()
		} else {
			report.Exit = "zero"
		}
		if reportErr := writePayloadRunReport(c, report); reportErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("write latest payload run report: %w", reportErr))
		}
	}()
	matching := runningAdmissionMatches(ctx, c, fingerprint)
	report.EnvironmentReused = matching
	if !matching && probeSSH(ctx, c) == nil {
		fmt.Fprintln(c.out, "Running environment has a different admission set; restarting to apply the new trust plan")
		if err = retryAdmissionReset(c.out, func() error { return resetToRecovery(ctx, c) }); err != nil {
			return err
		}
	}
	// A harmless command makes ensureShellEnvironment either reuse the matching
	// target or perform the complete tethered boot. Execution happens only after
	// a separate exact readback below.
	if err = smartExec(ctx, c, []string{"/bin/bash", "-c", "exit 0"}); err != nil {
		return err
	}
	if !runningAdmissionMatches(ctx, c, fingerprint) {
		return errors.New("running target admission receipt does not match the prepared payload plan")
	}
	if err = runPreparedPayload(ctx, c, main.Entry, report.Includes, commandArgs); err != nil {
		return err
	}
	report.ExactReadback = true
	return nil
}
