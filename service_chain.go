package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	serviceChainSchema                  = "15-plus-kernel-poc.service-chain.v1"
	defaultServiceChainExecutionTimeout = 10 * time.Second
	minimumServiceChainExecutionTimeout = 1 * time.Second
	maximumServiceChainExecutionTimeout = 5 * time.Minute
)

var serviceChainRegistry = map[string]struct {
	Label      string
	Activation string
}{
	"appledisplayplatformd": {Label: "com.apple.appledisplayplatformd", Activation: "com.apple.xpc.adp"},
	"hidd.nonui":            {Label: "com.apple.hidd.nonui"},
	"SwitchBoard":           {Label: "com.apple.SwitchBoard"},
}

var machServiceName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,127}$`)

type serviceChainManifest struct {
	Schema           string   `json:"schema"`
	Name             string   `json:"name"`
	Services         []string `json:"services"`
	ExecutionTimeout string   `json:"execution_timeout,omitempty"`
}

type serviceChainReport struct {
	Schema                        string                   `json:"schema"`
	StartedAt                     string                   `json:"started_at"`
	FinishedAt                    string                   `json:"finished_at"`
	Manifest                      string                   `json:"manifest"`
	ManifestSHA256                string                   `json:"manifest_sha256"`
	Name                          string                   `json:"name"`
	Services                      []string                 `json:"services"`
	LauncherMode                  string                   `json:"launcher_mode"`
	Arguments                     []string                 `json:"arguments"`
	Program                       uiProgram                `json:"program"`
	PreservedNativeExecutable     string                   `json:"preserved_native_executable,omitempty"`
	SystemOSCryptex               *systemOSCryptexEvidence `json:"systemos_cryptex,omitempty"`
	ChainReady                    bool                     `json:"chain_ready"`
	ProgramReached                bool                     `json:"program_reached"`
	ExecutionTimeout              string                   `json:"execution_timeout"`
	ExecutionTimedOut             bool                     `json:"execution_timed_out"`
	ExecutionKilled               bool                     `json:"execution_killed"`
	ExecutionSerialLog            string                   `json:"execution_serial_log,omitempty"`
	ExecutionSerialBytes          int64                    `json:"execution_serial_bytes,omitempty"`
	ExecutionSerialSHA256         string                   `json:"execution_serial_sha256,omitempty"`
	ExecutionSerialDrainQuiet     string                   `json:"execution_serial_drain_quiet,omitempty"`
	ExecutionSerialDrainLimit     string                   `json:"execution_serial_drain_limit,omitempty"`
	ExecutionSerialDrainElapsed   string                   `json:"execution_serial_drain_elapsed,omitempty"`
	ExecutionSerialDrainQuiescent bool                     `json:"execution_serial_drain_quiescent,omitempty"`
	ExecutionTerminal             string                   `json:"execution_terminal,omitempty"`
	RecoveryCleanup               string                   `json:"recovery_cleanup,omitempty"`
	Markers                       []string                 `json:"markers,omitempty"`
	OutputTruncated               bool                     `json:"output_truncated,omitempty"`
	ReducedEvidence               string                   `json:"reduced_evidence,omitempty"`
	Exit                          string                   `json:"exit"`
	Error                         string                   `json:"error,omitempty"`
}

type machServiceReport struct {
	Schema          string   `json:"schema"`
	StartedAt       string   `json:"started_at"`
	FinishedAt      string   `json:"finished_at"`
	Service         string   `json:"service"`
	LauncherMode    string   `json:"launcher_mode"`
	ActivationExact bool     `json:"activation_exact"`
	Markers         []string `json:"markers,omitempty"`
	OutputTruncated bool     `json:"output_truncated,omitempty"`
	Exit            string   `json:"exit"`
	Error           string   `json:"error,omitempty"`
}

type boundedTargetCapture struct {
	mu        sync.Mutex
	body      []byte
	truncated bool
}

func (capture *boundedTargetCapture) Write(body []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	const limit = 1 << 20
	remaining := limit - len(capture.body)
	if remaining > 0 {
		if remaining > len(body) {
			remaining = len(body)
		}
		capture.body = append(capture.body, body[:remaining]...)
	}
	if remaining != len(body) {
		capture.truncated = true
	}
	return len(body), nil
}

func (capture *boundedTargetCapture) snapshot() ([]byte, bool) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]byte(nil), capture.body...), capture.truncated
}

func selectedTargetMarkers(body []byte, prefixes ...string) []string {
	lines := strings.Split(strings.ReplaceAll(string(body), "\r", ""), "\n")
	markers := make([]string, 0, 16)
	for _, line := range lines {
		if len(line) > 4096 {
			continue
		}
		for _, prefix := range prefixes {
			if strings.HasPrefix(line, prefix) {
				markers = append(markers, line)
				break
			}
		}
		if len(markers) == 128 {
			break
		}
	}
	return markers
}

func markerContains(markers []string, fragment string) bool {
	for _, marker := range markers {
		if strings.Contains(marker, fragment) {
			return true
		}
	}
	return false
}

func serviceChainExecutionTimeout(value serviceChainManifest) (time.Duration, error) {
	if value.ExecutionTimeout == "" {
		return defaultServiceChainExecutionTimeout, nil
	}
	timeout, err := time.ParseDuration(value.ExecutionTimeout)
	if err != nil {
		return 0, fmt.Errorf("service-chain execution_timeout %q: %w", value.ExecutionTimeout, err)
	}
	if timeout < minimumServiceChainExecutionTimeout || timeout > maximumServiceChainExecutionTimeout {
		return 0, fmt.Errorf("service-chain execution_timeout must be between %s and %s", minimumServiceChainExecutionTimeout, maximumServiceChainExecutionTimeout)
	}
	return timeout, nil
}

func serviceChainExecutionContext(ctx context.Context, timeout time.Duration,
	serial *payloadExecutionSerialEvidence) context.Context {
	return withPayloadExecutionSerialCapture(
		withPayloadExecutionTimeout(ctx, timeout), serial)
}

func recordServiceChainExecutionSerial(report *serviceChainReport,
	serial *payloadExecutionSerialEvidence) {
	if serial == nil {
		return
	}
	report.ExecutionSerialLog = serial.Path
	report.ExecutionSerialBytes = serial.Bytes
	report.ExecutionSerialSHA256 = serial.SHA256
	if serial.DrainLimit > 0 {
		report.ExecutionSerialDrainQuiet = serial.DrainQuiet.String()
		report.ExecutionSerialDrainLimit = serial.DrainLimit.String()
		report.ExecutionSerialDrainElapsed = serial.DrainElapsed.Round(time.Millisecond).String()
		report.ExecutionSerialDrainQuiescent = serial.DrainQuiescent
	}
}

func validateServiceChainManifest(value serviceChainManifest) error {
	if value.Schema != serviceChainSchema {
		return fmt.Errorf("service-chain schema %q, want %q", value.Schema, serviceChainSchema)
	}
	if value.Name == "" || len(value.Name) > 80 || !machServiceName.MatchString(value.Name) {
		return errors.New("service-chain name must contain 1..80 letters, digits, dot, underscore, or hyphen")
	}
	if len(value.Services) == 0 || len(value.Services) > len(serviceChainRegistry) {
		return fmt.Errorf("service-chain must contain 1..%d services", len(serviceChainRegistry))
	}
	seen := make(map[string]bool, len(value.Services))
	for index, service := range value.Services {
		if _, ok := serviceChainRegistry[service]; !ok {
			return fmt.Errorf("service-chain service %d %q is unsupported", index, service)
		}
		if seen[service] {
			return fmt.Errorf("service-chain service %q is duplicated", service)
		}
		seen[service] = true
	}
	if _, err := serviceChainExecutionTimeout(value); err != nil {
		return err
	}
	return nil
}

func loadServiceChainManifest(name string) (serviceChainManifest, string, error) {
	var value serviceChainManifest
	abs, err := filepath.Abs(name)
	if err != nil {
		return value, "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return value, "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64<<10 {
		return value, "", errors.New("service-chain manifest must be one regular file of at most 64 KiB")
	}
	body, err := os.ReadFile(abs)
	if err != nil {
		return value, "", err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&value); err != nil {
		return value, "", fmt.Errorf("decode service-chain manifest: %w", err)
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return value, "", errors.New("service-chain manifest contains trailing JSON")
		}
		return value, "", fmt.Errorf("decode trailing service-chain data: %w", err)
	}
	if err = validateServiceChainManifest(value); err != nil {
		return value, "", err
	}
	hash := sha256.Sum256(body)
	return value, hex.EncodeToString(hash[:]), nil
}

func writePrivateJSON(c *cache, leaf string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Join(c.root, "private")
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, leaf+"-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(append(body, '\n'))
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryName, filepath.Join(directory, leaf+"-latest.json"))
}

func serviceChainRunArguments(c *cache, profile uiProfile, manifest serviceChainManifest,
	nativeExecutable *[2]string, programArguments []string) ([]string, error) {
	if err := validateServiceChainManifest(manifest); err != nil {
		return nil, err
	}
	runArguments, err := uiPayloadRunArgumentsMode(c, profile, "--service-chain-v1", []string{strings.Join(manifest.Services, ",")}, programArguments)
	if err != nil || nativeExecutable == nil {
		return runArguments, err
	}
	if nativeExecutable[0] == "" || nativeExecutable[1] == "" || !validPayloadDestination(nativeExecutable[1]) {
		return nil, errors.New("service-chain byte-preserved native executable is invalid")
	}
	delimiter := -1
	for index, value := range runArguments {
		if value == "--" {
			delimiter = index
			break
		}
	}
	if delimiter < 0 {
		return nil, errors.New("service-chain payload arguments lack the launcher delimiter")
	}
	result := make([]string, 0, len(runArguments)+2)
	result = append(result, runArguments[:delimiter]...)
	result = append(result, "--preserve-native", nativeExecutable[0]+"="+nativeExecutable[1])
	return append(result, runArguments[delimiter:]...), nil
}

func newServiceChainReport(manifestPath, manifestHash string,
	manifest serviceChainManifest, programArguments []string,
	program uiProgram, executionTimeout time.Duration,
	nativeExecutable *[2]string) serviceChainReport {
	preservedDestination := ""
	if nativeExecutable != nil {
		preservedDestination = nativeExecutable[1]
	}
	return serviceChainReport{
		Schema: "15-plus-kernel-poc.service-chain-report.v1", StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Manifest: manifestPath, ManifestSHA256: manifestHash, Name: manifest.Name,
		Services: append([]string(nil), manifest.Services...), LauncherMode: "--service-chain-v1",
		Arguments: append([]string(nil), programArguments...), Program: program,
		PreservedNativeExecutable: preservedDestination,
		ExecutionTimeout:          executionTimeout.String(), Exit: "running",
	}
}

func runServiceChain(ctx context.Context, c *cache, manifestPath string,
	nativeExecutable *[2]string, systemOSCryptexPath, systemOSCryptexTrustPath string,
	programArguments []string) (runErr error) {
	manifest, manifestHash, err := loadServiceChainManifest(manifestPath)
	if err != nil {
		return err
	}
	executionTimeout, err := serviceChainExecutionTimeout(manifest)
	if err != nil {
		return err
	}
	manifestPath, err = filepath.Abs(manifestPath)
	if err != nil {
		return err
	}
	if programArguments == nil {
		programArguments = []string{"-l", "-a", "-d", "16"}
	}
	profile, err := loadUIProfile(ctx, c)
	if err != nil {
		return err
	}
	runArguments, err := serviceChainRunArguments(c, profile, manifest, nativeExecutable, programArguments)
	if err != nil {
		return err
	}
	report := newServiceChainReport(manifestPath, manifestHash, manifest,
		programArguments, *profile.Program, executionTimeout, nativeExecutable)
	var cryptexRuntime *systemOSCryptexRuntime
	var cryptexTrustPlan *systemOSCryptexTrustPlan
	if systemOSCryptexTrustPath != "" {
		if systemOSCryptexPath == "" {
			return errors.New("--systemos-cryptex-trust-cache requires --systemos-cryptex")
		}
		plan, prepareErr := prepareSystemOSCryptexTrustCache(systemOSCryptexTrustPath, c.out)
		if prepareErr != nil {
			return prepareErr
		}
		cryptexTrustPlan = &plan
	}
	if systemOSCryptexPath != "" {
		plan, prepareErr := prepareSystemOSCryptex(systemOSCryptexPath, c.out)
		if prepareErr != nil {
			return prepareErr
		}
		evidence := &systemOSCryptexEvidence{
			Source: plan.Source, Bytes: plan.Bytes, SHA256: plan.SHA256,
			TargetImage:        systemOSCryptexTargetImage,
			ProductMountpoint:  systemOSCryptexProductMount,
			ProductVisibleRoot: systemOSCryptexVisibleRoot,
		}
		if cryptexTrustPlan != nil {
			evidence.TrustCacheSource = cryptexTrustPlan.Source
			evidence.TrustCacheBytes = cryptexTrustPlan.Bytes
			evidence.TrustCacheSHA256 = cryptexTrustPlan.SHA256
			evidence.TrustCacheImageType = systemOSCryptexTrustType
			evidence.TrustCacheVersion = cryptexTrustPlan.Version
			evidence.TrustCacheEntryCount = cryptexTrustPlan.EntryCount
		}
		cryptexRuntime = &systemOSCryptexRuntime{Plan: plan, TrustCache: cryptexTrustPlan, Evidence: evidence}
		report.SystemOSCryptex = evidence
	}
	if err = writePrivateJSON(c, "service-chain-run", report); err != nil {
		return fmt.Errorf("write initial service-chain report: %w", err)
	}
	defer func() {
		report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if runErr != nil {
			report.Exit = "failed"
			report.Error = runErr.Error()
		} else {
			report.Exit = "zero"
		}
		report.ReducedEvidence = filepath.Join(c.root, "private", "service-chain-evidence-latest.json")
		if reportErr := writePrivateJSON(c, "service-chain-run", report); reportErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("write service-chain report: %w", reportErr))
		}
		if evidenceErr := reduceServiceChainEvidence(c, report); evidenceErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("reduce service-chain evidence: %w", evidenceErr))
		}
	}()
	fmt.Fprintf(c.out, "Launching service chain %q in order %s through the imported ProductOS root launcher (target execution deadline %s)\n", manifest.Name, strings.Join(manifest.Services, " -> "), executionTimeout)
	originalOutput := c.targetOut
	outputWriter := originalOutput
	if outputWriter == nil {
		outputWriter = os.Stdout
	}
	capture := &boundedTargetCapture{}
	c.targetOut = io.MultiWriter(outputWriter, capture)
	originalError := c.targetErr
	errorWriter := originalError
	if errorWriter == nil {
		errorWriter = os.Stderr
	}
	c.targetErr = io.MultiWriter(errorWriter, capture)
	serialEvidence := &payloadExecutionSerialEvidence{}
	executionContext := serviceChainExecutionContext(ctx, executionTimeout,
		serialEvidence)
	if cryptexRuntime != nil {
		executionContext = withSystemOSCryptex(executionContext, cryptexRuntime)
	}
	runErr = runPayload(executionContext, c, runArguments)
	recordServiceChainExecutionSerial(&report, serialEvidence)
	c.targetOut = originalOutput
	c.targetErr = originalError
	captured, truncated := capture.snapshot()
	report.Markers = selectedTargetMarkers(captured,
		"PRODUCT_SERVICE_CHAIN ", "CHROOT_UI_DIRFD_TRANSITION ",
		"DISPLAYPLATFORM_LAUNCHD_SERVICE_POSTIMAGE ", "HIDD_LAUNCHD_SERVICE_POSTIMAGE ",
		"SWITCHBOARD_LAUNCHD_SERVICE_POSTIMAGE ", "PRODUCTOS_CAR_LOGICAL_BOUNDS_PROBE_V1 ",
		"CAR_LOGICAL_BOUNDS_DISPLAY ", "CAR_LOGICAL_BOUNDS_SUPERVISOR ",
		"PROBE_STAGE ", "PROBE_TIMEOUT ", "PROBE_RESULT ",
		"PRODUCTOS_TOOLING_SMOKE_V1")
	report.OutputTruncated = truncated
	report.ChainReady = markerContains(report.Markers, "PRODUCT_SERVICE_CHAIN stage=ready")
	report.ProgramReached = markerContains(report.Markers, "CHROOT_UI_DIRFD_TRANSITION stage=exec")
	report.ProgramReached = report.ProgramReached ||
		markerContains(report.Markers, "PRODUCT_SERVICE_CHAIN stage=hidd-producer-probe-spawn") ||
		markerContains(report.Markers, "CAR_LOGICAL_BOUNDS_SUPERVISOR stage=invocation")
	report.ExecutionTimedOut = errors.Is(runErr, errPayloadExecutionTimeout)
	report.ExecutionKilled = errors.Is(runErr, errPayloadExecutionKilled)
	if report.ExecutionTimedOut {
		report.ExecutionTerminal = "local-execution-deadline"
	} else if report.ExecutionKilled {
		report.ExecutionTerminal = "remote-signal-KILL-before-local-deadline"
	}
	if report.ExecutionTimedOut || report.ExecutionKilled {
		cleanupErr := retryAdmissionReset(c.out, func() error { return resetToRecovery(ctx, c) })
		if cleanupErr != nil {
			report.RecoveryCleanup = "failed: " + cleanupErr.Error()
			runErr = errors.Join(runErr, fmt.Errorf("recover target after execution timeout: %w", cleanupErr))
		} else {
			report.RecoveryCleanup = "persistent-recovery-verified"
		}
	}
	return runErr
}

func serviceChainCommand(ctx context.Context, c *cache, args []string) error {
	if len(args) >= 1 && args[0] == "profile" {
		return serviceChainProfileCommand(ctx, c, args[1:])
	}
	if len(args) == 2 && args[0] == "validate" {
		manifest, hash, err := loadServiceChainManifest(args[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(c.out, "Service chain %q valid: %s manifest_sha256=%s\n", manifest.Name, strings.Join(manifest.Services, " -> "), hash)
		return nil
	}
	if len(args) >= 2 && args[0] == "run" {
		runArgs, programPath, err := extractServiceChainProgram(args[1:])
		if err != nil {
			return err
		}
		manifestPath, nativeExecutable, systemOSCryptexPath, systemOSCryptexTrustPath, programArguments, err := parseServiceChainRunArguments(runArgs)
		if err != nil {
			return err
		}
		var runProfile *serviceChainProfile
		programArgv0 := ""
		if manifestPath == "default" {
			manifestPath = filepath.Join(filepath.Dir(c.root), "examples", "productos-display-chain.json")
		} else if profile, ok, profileErr := loadServiceChainProfile(c, manifestPath); profileErr != nil {
			return profileErr
		} else if ok {
			selected := profile
			runProfile = &selected
			programArgv0 = profile.ProgramArgv0
			manifestPath = profile.Manifest.Path
			if nativeExecutable != nil || systemOSCryptexPath != "" || systemOSCryptexTrustPath != "" {
				return errors.New("named profile inputs cannot be overridden")
			}
			if profile.PreservedNative != nil {
				nativeExecutable = &[2]string{profile.PreservedNative.Path, profile.PreservedDestination}
			}
			if profile.SystemOSCryptex != nil {
				systemOSCryptexPath = profile.SystemOSCryptex.Path
			}
			if profile.SystemOSTrust != nil {
				systemOSCryptexTrustPath = profile.SystemOSTrust.Path
			}
		}
		var priorProfile *uiProfile
		if programPath != "" || runProfile != nil && runProfile.Launcher != nil {
			profile, loadErr := loadUIProfile(ctx, c)
			if loadErr != nil {
				return loadErr
			}
			priorProfile = &profile
		}
		if runProfile != nil && runProfile.Launcher != nil {
			if err = importUIRootLauncher(ctx, c, runProfile.Launcher.Path); err != nil {
				return fmt.Errorf("select service-chain launcher: %w", err)
			}
		}
		if programPath != "" {
			if err = importUIProgram(ctx, c, programPath, programArgv0); err != nil {
				if priorProfile != nil {
					_ = writeUIProfile(c, *priorProfile)
				}
				return fmt.Errorf("select service-chain program: %w", err)
			}
		}
		runErr := runServiceChain(ctx, c, manifestPath, nativeExecutable,
			systemOSCryptexPath, systemOSCryptexTrustPath, programArguments)
		if priorProfile != nil {
			if restoreErr := writeUIProfile(c, *priorProfile); restoreErr != nil {
				runErr = errors.Join(runErr, fmt.Errorf("restore prior UI profile: %w", restoreErr))
			} else {
				fmt.Fprintln(c.out, "Restored prior UI launcher and program profile after service-chain run")
			}
		}
		return runErr
	}
	return errors.New("usage: service-chain profile bind|show ... | service-chain validate MANIFEST | service-chain run MANIFEST|PROFILE|default [--program FILE] [--preserve-native FILE=DEST] [--systemos-cryptex IMAGE --systemos-cryptex-trust-cache FILE] [-- PROGRAM-ARG...]")
}

func parseServiceChainRunArguments(args []string) (manifestPath string,
	nativeExecutable *[2]string, systemOSCryptexPath, systemOSCryptexTrustPath string,
	programArguments []string, err error) {
	if len(args) == 0 {
		err = errors.New("usage: service-chain run MANIFEST|default [--preserve-native FILE=DEST] [--systemos-cryptex IMAGE --systemos-cryptex-trust-cache FILE] [-- PROGRAM-ARG...]")
		return
	}
	manifestPath = args[0]
parseOptions:
	for index := 1; index < len(args); index++ {
		switch args[index] {
		case "--":
			programArguments = append([]string{}, args[index+1:]...)
			break parseOptions
		case "--preserve-native":
			if nativeExecutable != nil || index+1 >= len(args) {
				err = errors.New("service-chain run accepts exactly one --preserve-native FILE=DEST")
				return
			}
			index++
			source, destination, splitErr := splitPayloadInclude(args[index])
			if splitErr != nil {
				err = fmt.Errorf("parse --preserve-native: %w", splitErr)
				return
			}
			nativeExecutable = &[2]string{source, destination}
		case "--systemos-cryptex":
			if systemOSCryptexPath != "" || index+1 >= len(args) {
				err = errors.New("service-chain run accepts exactly one --systemos-cryptex IMAGE")
				return
			}
			index++
			if args[index] == "" {
				err = errors.New("--systemos-cryptex needs a nonempty path")
				return
			}
			systemOSCryptexPath = args[index]
		case "--systemos-cryptex-trust-cache":
			if systemOSCryptexTrustPath != "" || index+1 >= len(args) {
				err = errors.New("service-chain run accepts exactly one --systemos-cryptex-trust-cache FILE")
				return
			}
			index++
			if args[index] == "" {
				err = errors.New("--systemos-cryptex-trust-cache needs a nonempty path")
				return
			}
			systemOSCryptexTrustPath = args[index]
		default:
			err = fmt.Errorf("unknown service-chain run option %q; put target arguments after --", args[index])
			return
		}
	}
	if systemOSCryptexTrustPath != "" && systemOSCryptexPath == "" {
		err = errors.New("--systemos-cryptex-trust-cache requires --systemos-cryptex")
	}
	return
}

func machServiceCommand(ctx context.Context, c *cache, args []string) error {
	if len(args) != 2 || args[0] != "probe" {
		return errors.New("usage: mach-service probe SERVICE")
	}
	if !machServiceName.MatchString(args[1]) {
		return errors.New("Mach service must contain 1..127 letters, digits, dot, underscore, or hyphen")
	}
	profile, err := loadUIProfile(ctx, c)
	if err != nil {
		return err
	}
	runArguments, err := uiLauncherRunArguments(c, profile, []string{"--mach-service-probe-v1", args[1]})
	if err != nil {
		return err
	}
	report := machServiceReport{
		Schema: "15-plus-kernel-poc.mach-service-probe.v1", StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Service: args[1], LauncherMode: "--mach-service-probe-v1", Exit: "running",
	}
	if err = writePrivateJSON(c, "mach-service-probe", report); err != nil {
		return fmt.Errorf("write initial Mach-service report: %w", err)
	}
	fmt.Fprintf(c.out, "Demand-probing Mach service %s with bounded lookup, send, and right cleanup\n", args[1])
	originalOutput := c.targetOut
	outputWriter := originalOutput
	if outputWriter == nil {
		outputWriter = os.Stdout
	}
	capture := &boundedTargetCapture{}
	c.targetOut = io.MultiWriter(outputWriter, capture)
	originalError := c.targetErr
	errorWriter := originalError
	if errorWriter == nil {
		errorWriter = os.Stderr
	}
	c.targetErr = io.MultiWriter(errorWriter, capture)
	runErr := runPayload(ctx, c, runArguments)
	c.targetOut = originalOutput
	c.targetErr = originalError
	captured, truncated := capture.snapshot()
	report.Markers = selectedTargetMarkers(captured, "MACH_SERVICE_PROBE ", "MACH_SERVICE_PROBE_LAUNCHD_DEMAND ")
	report.OutputTruncated = truncated
	report.ActivationExact = markerContains(report.Markers, "MACH_SERVICE_PROBE stage=complete") && markerContains(report.Markers, "exact=1")
	report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if runErr != nil {
		report.Exit, report.Error = "failed", runErr.Error()
	} else {
		report.Exit = "zero"
	}
	if reportErr := writePrivateJSON(c, "mach-service-probe", report); reportErr != nil {
		return errors.Join(runErr, fmt.Errorf("write Mach-service report: %w", reportErr))
	}
	return runErr
}
