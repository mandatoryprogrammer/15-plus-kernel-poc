package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	probeBuildTimeout = 2 * time.Minute
	probeSourceLimit  = 4 << 20
)

var (
	probeLinkNamePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_+.-]{0,127}$`)
	probeSymbolPattern   = regexp.MustCompile(`^[_A-Za-z][_A-Za-z0-9.$]{0,255}$`)
	probeMarkerPattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,63}$`)
)

type probeNormalizedIdentity struct {
	Object       string   `json:"object"`
	Target       string   `json:"target"`
	SHA256       string   `json:"sha256"`
	CDHash       string   `json:"cdhash"`
	Size         int64    `json:"size"`
	LCUUIDAdded  bool     `json:"lc_uuid_added"`
	LinkerSigned bool     `json:"linker_signed"`
	AdHocSigned  bool     `json:"ad_hoc_signed"`
	Dependencies []string `json:"dependencies,omitempty"`
}

type probeNormalizeReport struct {
	Schema     string                  `json:"schema"`
	StartedAt  string                  `json:"started_at"`
	FinishedAt string                  `json:"finished_at"`
	Source     string                  `json:"source"`
	InputSize  int64                   `json:"input_size,omitempty"`
	InputHash  string                  `json:"input_sha256,omitempty"`
	Normalized probeNormalizedIdentity `json:"normalized"`
	Exit       string                  `json:"exit"`
	Error      string                  `json:"error,omitempty"`
}

type probeBuildReport struct {
	Schema          string                  `json:"schema"`
	StartedAt       string                  `json:"started_at"`
	FinishedAt      string                  `json:"finished_at"`
	Source          string                  `json:"source"`
	SourceSHA256    string                  `json:"source_sha256,omitempty"`
	Sysroot         string                  `json:"sysroot"`
	MinimumIOS      string                  `json:"minimum_ios"`
	Frameworks      []string                `json:"frameworks,omitempty"`
	Libraries       []string                `json:"libraries,omitempty"`
	CompilerArgs    []string                `json:"compiler_args,omitempty"`
	RawBuildsEqual  bool                    `json:"raw_builds_equal"`
	RawSHA256       string                  `json:"raw_sha256,omitempty"`
	RawSize         int64                   `json:"raw_size,omitempty"`
	NormalizedEqual bool                    `json:"normalized_builds_equal"`
	Normalized      probeNormalizedIdentity `json:"normalized"`
	Exit            string                  `json:"exit"`
	Error           string                  `json:"error,omitempty"`
}

type probeRunEvidence struct {
	Schema     string            `json:"schema"`
	StartedAt  string            `json:"started_at"`
	FinishedAt string            `json:"finished_at"`
	Invocation []string          `json:"invocation"`
	Payload    *payloadRunReport `json:"payload,omitempty"`
	Exit       string            `json:"exit"`
	Error      string            `json:"error,omitempty"`
}

type frameworkSupervisorSpec struct {
	Symbol    string
	Markers   []string
	TimeoutMS int
}

type probeSupervisorReport struct {
	Schema    string   `json:"schema"`
	Symbol    string   `json:"symbol"`
	Source    string   `json:"source"`
	SHA256    string   `json:"sha256"`
	Markers   []string `json:"markers"`
	TimeoutMS int      `json:"timeout_ms"`
}

func probeCommand(ctx context.Context, c *cache, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: probe normalize FILE [--dest /usr/local/bin/NAME] | probe build SOURCE --sysroot ROOT [--framework NAME]... [--library NAME]... [--min-ios VERSION] | probe run FILE [payload options] [-- ARG...] | probe supervisor --symbol NAME [--marker PREFIX] [--timeout-ms N] [--dest FILE]")
	}
	switch args[0] {
	case "normalize":
		return probeNormalizeCommand(ctx, c, args[1:])
	case "build":
		return probeBuildCommand(ctx, c, args[1:])
	case "run":
		return probeRunCommand(ctx, c, args[1:])
	case "supervisor":
		return probeSupervisorCommand(c, args[1:])
	default:
		return fmt.Errorf("unknown probe command %q", args[0])
	}
}

func probeDefaultTarget(source string) (string, error) {
	name := filepath.Base(source)
	if extension := filepath.Ext(name); extension != "" {
		name = strings.TrimSuffix(name, extension)
	}
	if name == "" || name == "." || name == string(filepath.Separator) || strings.ContainsAny(name, "\x00/\\\r\n") {
		return "", fmt.Errorf("cannot derive target executable name from %q", source)
	}
	target := "/usr/local/bin/" + name
	if !validPayloadDestination(target) || reservedPayloadDestinations[target] {
		return "", fmt.Errorf("derived target destination is invalid or reserved: %s", target)
	}
	return target, nil
}

func probeFileIdentity(name string) (int64, string, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return 0, "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > payloadLimit {
		return 0, "", fmt.Errorf("%s must be a non-empty regular file no larger than %d bytes", name, payloadLimit)
	}
	body, err := os.ReadFile(name)
	if err != nil {
		return 0, "", err
	}
	return int64(len(body)), digest(body), nil
}

func probeNormalized(prepared preparedPayload, object string) probeNormalizedIdentity {
	return probeNormalizedIdentity{
		Object: object, Target: prepared.Entry.Destination, SHA256: prepared.Entry.SHA256,
		CDHash: prepared.Entry.CDHash, Size: prepared.Entry.Size, LCUUIDAdded: prepared.LCUUIDAdded,
		LinkerSigned: prepared.LinkerSigned, AdHocSigned: prepared.Signed,
		Dependencies: append([]string(nil), prepared.Dependencies...),
	}
}

func storeProbeObject(ctx context.Context, c *cache, body []byte) (string, error) {
	a := asset{Role: "probe", SHA256: digest(body), Size: int64(len(body)), Recipe: "deterministic probe normalization"}
	name := c.object(a)
	if err := verifyFile(ctx, name, a); err == nil {
		return name, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("existing normalized probe object: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Join(c.root, "tmp"), "probe-object-")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(body)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	if err = os.Rename(tmpName, name); err != nil {
		return "", err
	}
	if err = verifyFile(ctx, name, a); err != nil {
		return "", err
	}
	return name, nil
}

func writeProbeFile(name string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".probe-write-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(body)
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

func writeProbeJSON(c *cache, base string, value any) error {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeProbeFile(filepath.Join(c.root, "private", base), append(body, '\n'), 0o600)
}

func probeNormalizeCommand(ctx context.Context, c *cache, args []string) (runErr error) {
	if len(args) == 0 {
		return errors.New("usage: probe normalize FILE [--dest /usr/local/bin/NAME]")
	}
	source := args[0]
	target, err := probeDefaultTarget(source)
	if err != nil {
		return err
	}
	for index := 1; index < len(args); index++ {
		if args[index] != "--dest" || index+1 >= len(args) {
			return fmt.Errorf("unknown or incomplete probe normalize option %q", args[index])
		}
		index++
		target = args[index]
	}
	report := probeNormalizeReport{Schema: "15-plus-kernel-poc.probe-normalize.v1", StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Source: source, Exit: "incomplete"}
	defer func() {
		report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if runErr != nil {
			report.Exit, report.Error = "failed", runErr.Error()
		} else {
			report.Exit = "zero"
		}
		if reportErr := writeProbeJSON(c, "probe-normalize-latest.json", report); reportErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("write normalize report: %w", reportErr))
		}
	}()
	report.InputSize, report.InputHash, runErr = probeFileIdentity(source)
	if runErr != nil {
		return runErr
	}
	prepared, err := preparePayload(source, target)
	if err != nil {
		return err
	}
	object, err := storeProbeObject(ctx, c, prepared.Body)
	if err != nil {
		return err
	}
	report.Normalized = probeNormalized(prepared, object)
	fmt.Fprintf(c.out, "Normalized probe target=%s bytes=%d sha256=%s cdhash=%s object=%s\n", target, prepared.Entry.Size, prepared.Entry.SHA256, prepared.Entry.CDHash, object)
	return nil
}

type probeBuildOptions struct {
	Source, Sysroot, MinimumIOS, RuntimeLibrary string
	Frameworks, Libraries, LibraryPaths         []string
}

func parseProbeBuild(args []string) (probeBuildOptions, error) {
	var result probeBuildOptions
	minimumSet := false
	seenFrameworks, seenLibraries := map[string]bool{}, map[string]bool{}
	if len(args) == 0 {
		return result, errors.New("usage: probe build SOURCE --sysroot ROOT [--framework NAME]... [--library NAME]... [--min-ios VERSION]")
	}
	result.Source, result.MinimumIOS = args[0], canonicalRuntime.IOSVersion
	for index := 1; index < len(args); index++ {
		if index+1 >= len(args) {
			return result, fmt.Errorf("%s needs a value", args[index])
		}
		value := args[index+1]
		index++
		switch args[index-1] {
		case "--sysroot":
			if result.Sysroot != "" {
				return result, errors.New("--sysroot may appear only once")
			}
			result.Sysroot = value
		case "--framework":
			if !probeLinkNamePattern.MatchString(value) {
				return result, fmt.Errorf("invalid framework name %q", value)
			}
			if seenFrameworks[value] {
				return result, fmt.Errorf("duplicate framework %q", value)
			}
			seenFrameworks[value] = true
			result.Frameworks = append(result.Frameworks, value)
		case "--library":
			if !probeLinkNamePattern.MatchString(value) {
				return result, fmt.Errorf("invalid library name %q", value)
			}
			if seenLibraries[value] {
				return result, fmt.Errorf("duplicate library %q", value)
			}
			seenLibraries[value] = true
			result.Libraries = append(result.Libraries, value)
		case "--min-ios":
			if minimumSet {
				return result, errors.New("--min-ios may appear only once")
			}
			minimumSet = true
			result.MinimumIOS = value
		default:
			return result, fmt.Errorf("unknown probe build option %q", args[index-1])
		}
	}
	if result.Sysroot == "" {
		return result, errors.New("probe build requires --sysroot ROOT")
	}
	minimum, err := packedPlatformVersion(result.MinimumIOS)
	if err != nil {
		return result, err
	}
	maximum, err := packedPlatformVersion(canonicalRuntime.IOSVersion)
	if err != nil {
		return result, err
	}
	if minimum > maximum {
		return result, fmt.Errorf("minimum iOS %s exceeds target runtime %s", result.MinimumIOS, canonicalRuntime.IOSVersion)
	}
	return result, nil
}

func probeCompilerArgs(options probeBuildOptions, output string) []string {
	args := []string{
		"clang",
		"-target", "arm64-apple-ios" + options.MinimumIOS,
		"-isysroot", options.Sysroot,
		"-std=c17", "-Os", "-fno-ident", "-fno-common", "-fvisibility=hidden", "-nostdlib",
		"-ffile-prefix-map=" + filepath.Dir(options.Source) + "=/probe/src",
		"-fdebug-prefix-map=" + filepath.Dir(options.Source) + "=/probe/src",
		"-Wl,-no_uuid", "-Wl,-no_adhoc_codesign", "-Wl,-dead_strip", "-Wl,-undefined,dynamic_lookup",
	}
	for _, framework := range options.Frameworks {
		args = append(args, "-framework", framework)
	}
	args = append(args, options.LibraryPaths...)
	return append(args, "-o", output, options.Source, options.RuntimeLibrary)
}

func resolveProbeLinkInputs(options *probeBuildOptions) error {
	frameworkRoot := filepath.Join(options.Sysroot, "System", "Library", "Frameworks")
	for _, framework := range options.Frameworks {
		binary := filepath.Join(frameworkRoot, framework+".framework", framework)
		stub := binary + ".tbd"
		if info, err := os.Lstat(binary); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
			continue
		}
		if info, err := os.Lstat(stub); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
			continue
		}
		return fmt.Errorf("framework %s is absent from ProductOS sysroot %s (expected %s or %s)", framework, options.Sysroot, binary, stub)
	}
	for _, library := range options.Libraries {
		if library == "System" {
			continue
		}
		candidates := []string{
			filepath.Join(options.Sysroot, "usr", "lib", "lib"+library+".dylib"),
			filepath.Join(options.Sysroot, "usr", "lib", "lib"+library+".tbd"),
		}
		resolved := ""
		for _, candidate := range candidates {
			if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
				resolved = candidate
				break
			}
		}
		if resolved == "" {
			return fmt.Errorf("library %s is absent from ProductOS sysroot %s (expected %s)", library, options.Sysroot, strings.Join(candidates, " or "))
		}
		options.LibraryPaths = append(options.LibraryPaths, resolved)
	}
	return nil
}

type probeSerializedWriter struct {
	mu  sync.Mutex
	out io.Writer
}

func (w *probeSerializedWriter) Write(body []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.out.Write(body)
}

func runProbeProcess(ctx context.Context, out io.Writer, scratch, purpose, executable string, args []string, limit time.Duration) error {
	stream := &probeSerializedWriter{out: out}
	commandCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	command := exec.CommandContext(commandCtx, executable, args...)
	command.Stdout, command.Stderr = stream, stream
	command.Env = append(os.Environ(), "LC_ALL=C", "ZERO_AR_DATE=1")
	started := time.Now()
	if err := command.Start(); err != nil {
		return fmt.Errorf("start %s: %w", purpose, err)
	}
	fmt.Fprintf(stream, "Started pid=%d purpose=%s deadline=%s expected=zero-exit log_dir=%s\n", command.Process.Pid, purpose, limit, scratch)
	stop := heartbeat(stream, purpose, limit)
	err := command.Wait()
	stop()
	if commandCtx.Err() != nil {
		return fmt.Errorf("%s exceeded %s: %w", purpose, limit, commandCtx.Err())
	}
	if err != nil {
		return fmt.Errorf("%s failed after %s: %w", purpose, time.Since(started).Round(time.Millisecond), err)
	}
	fmt.Fprintf(stream, "Completed pid=%d purpose=%s elapsed=%s terminal=zero-exit\n", command.Process.Pid, purpose, time.Since(started).Round(time.Millisecond))
	return nil
}

func probeBuildCommand(ctx context.Context, c *cache, args []string) (runErr error) {
	options, err := parseProbeBuild(args)
	if err != nil {
		return err
	}
	options.Source, err = filepath.Abs(options.Source)
	if err != nil {
		return err
	}
	options.Sysroot, err = filepath.Abs(options.Sysroot)
	if err != nil {
		return err
	}
	info, err := os.Stat(options.Sysroot)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("sysroot must be an existing directory: %s", options.Sysroot)
	}
	options.RuntimeLibrary = filepath.Join(options.Sysroot, "usr", "lib", "libSystem.B.dylib")
	runtimeInfo, err := os.Lstat(options.RuntimeLibrary)
	if err != nil || !runtimeInfo.Mode().IsRegular() || runtimeInfo.Size() <= 0 {
		return fmt.Errorf("sysroot lacks a regular ProductOS runtime library: %s", options.RuntimeLibrary)
	}
	if err = resolveProbeLinkInputs(&options); err != nil {
		return err
	}
	target, err := probeDefaultTarget(options.Source)
	if err != nil {
		return err
	}
	report := probeBuildReport{
		Schema: "15-plus-kernel-poc.probe-build.v1", StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Source: options.Source, Sysroot: options.Sysroot, MinimumIOS: options.MinimumIOS,
		Frameworks: append([]string(nil), options.Frameworks...), Libraries: append([]string(nil), options.Libraries...), Exit: "incomplete",
	}
	defer func() {
		report.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if runErr != nil {
			report.Exit, report.Error = "failed", runErr.Error()
		} else {
			report.Exit = "zero"
		}
		if reportErr := writeProbeJSON(c, "probe-build-latest.json", report); reportErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("write build report: %w", reportErr))
		}
	}()
	sourceInfo, err := os.Lstat(options.Source)
	if err != nil {
		return err
	}
	if !sourceInfo.Mode().IsRegular() || sourceInfo.Size() <= 0 || sourceInfo.Size() > probeSourceLimit {
		return fmt.Errorf("probe source must be a non-empty regular file no larger than %d bytes", probeSourceLimit)
	}
	sourceBody, err := os.ReadFile(options.Source)
	if err != nil {
		return err
	}
	report.SourceSHA256 = digest(sourceBody)
	scratch, err := os.MkdirTemp(filepath.Join(c.root, "tmp"), "probe-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	outputs := []string{filepath.Join(scratch, "first", "probe"), filepath.Join(scratch, "second", "probe")}
	for index, output := range outputs {
		if err = os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
			return err
		}
		compilerArgs := probeCompilerArgs(options, output)
		if index == 0 {
			report.CompilerArgs = append([]string(nil), compilerArgs...)
			for argument := 0; argument+1 < len(report.CompilerArgs); argument++ {
				if report.CompilerArgs[argument] == "-o" {
					report.CompilerArgs[argument+1] = "<isolated-output>"
					break
				}
			}
		}
		if err = runProbeProcess(ctx, c.out, scratch, fmt.Sprintf("deterministic probe build %d/2", index+1), "xcrun", compilerArgs, probeBuildTimeout); err != nil {
			return err
		}
	}
	first, err := os.ReadFile(outputs[0])
	if err != nil {
		return err
	}
	second, err := os.ReadFile(outputs[1])
	if err != nil {
		return err
	}
	report.RawBuildsEqual = bytes.Equal(first, second)
	if !report.RawBuildsEqual {
		return fmt.Errorf("compiler output is not reproducible: first sha256=%s second sha256=%s", digest(first), digest(second))
	}
	report.RawSHA256, report.RawSize = digest(first), int64(len(first))
	afterSource, err := os.ReadFile(options.Source)
	if err != nil {
		return err
	}
	if !bytes.Equal(sourceBody, afterSource) {
		return errors.New("probe source changed during the deterministic build")
	}
	preparedFirst, err := preparePayload(outputs[0], target)
	if err != nil {
		return fmt.Errorf("normalize first compiler output: %w", err)
	}
	preparedSecond, err := preparePayload(outputs[1], target)
	if err != nil {
		return fmt.Errorf("normalize second compiler output: %w", err)
	}
	report.NormalizedEqual = bytes.Equal(preparedFirst.Body, preparedSecond.Body)
	if !report.NormalizedEqual {
		return fmt.Errorf("normalization is not reproducible: first sha256=%s second sha256=%s", digest(preparedFirst.Body), digest(preparedSecond.Body))
	}
	object, err := storeProbeObject(ctx, c, preparedFirst.Body)
	if err != nil {
		return err
	}
	report.Normalized = probeNormalized(preparedFirst, object)
	fmt.Fprintf(c.out, "Built reproducible probe raw_bytes=%d raw_sha256=%s normalized_bytes=%d normalized_sha256=%s cdhash=%s object=%s\n", len(first), digest(first), preparedFirst.Entry.Size, preparedFirst.Entry.SHA256, preparedFirst.Entry.CDHash, object)
	return nil
}

func probeRunCommand(ctx context.Context, c *cache, args []string) (runErr error) {
	if len(args) == 0 {
		return errors.New("usage: probe run FILE [payload options] [-- ARG...]")
	}
	priorName := filepath.Join(c.root, "private", "payload-run-latest.json")
	prior, _ := os.ReadFile(priorName)
	evidence := probeRunEvidence{
		Schema: "15-plus-kernel-poc.probe-run.v1", StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Invocation: append([]string(nil), args...), Exit: "incomplete",
	}
	defer func() {
		latest, readErr := os.ReadFile(priorName)
		if readErr == nil && !bytes.Equal(prior, latest) {
			var payload payloadRunReport
			if json.Unmarshal(latest, &payload) == nil && payload.Source == args[0] {
				evidence.Payload = &payload
			}
		}
		evidence.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if runErr != nil {
			evidence.Exit, evidence.Error = "failed", runErr.Error()
		} else {
			evidence.Exit = "zero"
		}
		if reportErr := writeProbeJSON(c, "probe-run-latest.json", evidence); reportErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("write combined probe run evidence: %w", reportErr))
		}
	}()
	return runPayload(ctx, c, args)
}

func normalizeSupervisorMarkers(markers []string) ([]string, error) {
	switch len(markers) {
	case 0:
		markers = []string{"probe.entry", "probe.resolved", "probe.return"}
	case 1:
		markers = []string{markers[0] + ".entry", markers[0] + ".resolved", markers[0] + ".return"}
	case 3:
		markers = append([]string(nil), markers...)
	default:
		return nil, errors.New("supply zero markers, one marker prefix, or exactly three stage markers")
	}
	seen := map[string]bool{}
	for _, marker := range markers {
		if !probeMarkerPattern.MatchString(marker) || seen[marker] {
			return nil, fmt.Errorf("invalid or duplicate probe marker %q", marker)
		}
		seen[marker] = true
	}
	return markers, nil
}

func renderFrameworkCallSupervisor(spec frameworkSupervisorSpec) ([]byte, error) {
	if !probeSymbolPattern.MatchString(spec.Symbol) {
		return nil, fmt.Errorf("invalid framework symbol %q", spec.Symbol)
	}
	markers, err := normalizeSupervisorMarkers(spec.Markers)
	if err != nil {
		return nil, err
	}
	if spec.TimeoutMS < 10 || spec.TimeoutMS > 60000 {
		return nil, errors.New("supervisor timeout must be between 10 and 60000 milliseconds")
	}
	source := fmt.Sprintf(`/* Header-free by design: ProductOS roots are runtimes, not SDKs. */
typedef unsigned long probe_uintptr;
typedef unsigned long long probe_u64;
typedef void *probe_pthread;
struct probe_timebase_info { unsigned numer; unsigned denom; };

extern void *dlsym(void *, const char *);
extern char *dlerror(void);
extern int dprintf(int, const char *, ...);
extern int pthread_create(probe_pthread *, const void *, void *(*)(void *), void *);
extern int pthread_join(probe_pthread, void **);
extern int pthread_detach(probe_pthread);
extern int sched_yield(void);
extern int usleep(unsigned);
extern probe_u64 mach_absolute_time(void);
extern int mach_timebase_info(struct probe_timebase_info *);

#define PROBE_RTLD_DEFAULT ((void *)-2L)
static const char *const probe_markers[3] = {%q, %q, %q};
static _Atomic unsigned probe_stage_index;
static _Atomic int probe_done;

static void probe_emit(unsigned index) {
    __c11_atomic_store(&probe_stage_index, index + 1, __ATOMIC_RELEASE);
    dprintf(2, "PROBE_STAGE index=%%u marker=%%s\n", index, probe_markers[index]);
}

/* Edit only this adapter when the target has arguments or a non-integer return. */
static probe_uintptr probe_invoke(void *address) {
    return ((probe_uintptr (*)(void))address)();
}

static void *probe_worker(void *unused) {
    (void)unused;
    probe_emit(0);
    dlerror();
    void *address = dlsym(PROBE_RTLD_DEFAULT, %q);
    const char *error = dlerror();
    if (error != (void *)0 || address == (void *)0) {
        dprintf(2, "PROBE_RESOLVE_ERROR symbol=%s error=%%s\n", error ? error : "missing");
        __c11_atomic_store(&probe_done, -1, __ATOMIC_RELEASE);
        return (void *)0;
    }
    probe_emit(1);
    probe_uintptr result = probe_invoke(address);
    dprintf(2, "PROBE_RESULT value=0x%%llx\n", (unsigned long long)result);
    probe_emit(2);
    __c11_atomic_store(&probe_done, 1, __ATOMIC_RELEASE);
    return (void *)0;
}

static probe_u64 monotonic_milliseconds(void) {
    static struct probe_timebase_info scale;
    if (scale.denom == 0 && mach_timebase_info(&scale) != 0) return ~(probe_u64)0;
    probe_u64 ticks = mach_absolute_time();
    return (ticks / scale.denom) * scale.numer / 1000000u;
}

int main(void) {
    probe_pthread worker;
    if (pthread_create(&worker, (void *)0, probe_worker, (void *)0) != 0) {
        dprintf(2, "PROBE_THREAD_ERROR\n");
        return 70;
    }
    const probe_u64 started = monotonic_milliseconds();
    for (;;) {
        int done = __c11_atomic_load(&probe_done, __ATOMIC_ACQUIRE);
        if (done != 0) {
            pthread_join(worker, (void *)0);
            return done > 0 ? 0 : 69;
        }
        probe_u64 now = monotonic_milliseconds();
        if (now == ~(probe_u64)0 || now - started >= %d) {
            unsigned stage = __c11_atomic_load(&probe_stage_index, __ATOMIC_ACQUIRE);
            dprintf(2, "PROBE_TIMEOUT timeout_ms=%d stage=%%u marker=%%s\n", stage, stage ? probe_markers[stage - 1] : "not-entered");
            pthread_detach(worker);
            return 124;
        }
        usleep(1000);
        sched_yield();
    }
}
`, markers[0], markers[1], markers[2], spec.Symbol, spec.Symbol, spec.TimeoutMS, spec.TimeoutMS)
	return []byte(source), nil
}

func probeSupervisorCommand(c *cache, args []string) error {
	var spec frameworkSupervisorSpec
	var destination string
	spec.TimeoutMS = 2000
	for index := 0; index < len(args); index++ {
		if index+1 >= len(args) {
			return fmt.Errorf("%s needs a value", args[index])
		}
		value := args[index+1]
		index++
		switch args[index-1] {
		case "--symbol":
			if spec.Symbol != "" {
				return errors.New("--symbol may appear only once")
			}
			spec.Symbol = value
		case "--marker":
			spec.Markers = append(spec.Markers, value)
		case "--timeout-ms":
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("invalid --timeout-ms %q", value)
			}
			spec.TimeoutMS = parsed
		case "--dest":
			if destination != "" {
				return errors.New("--dest may appear only once")
			}
			destination = value
		default:
			return fmt.Errorf("unknown probe supervisor option %q", args[index-1])
		}
	}
	if spec.Symbol == "" {
		return errors.New("probe supervisor requires --symbol NAME")
	}
	if destination == "" {
		destination = filepath.Join(c.root, "private", "probe-supervisor.c")
	} else {
		absolute, err := filepath.Abs(destination)
		if err != nil {
			return err
		}
		destination = absolute
	}
	source, err := renderFrameworkCallSupervisor(spec)
	if err != nil {
		return err
	}
	if err = writeProbeFile(destination, source, 0o600); err != nil {
		return err
	}
	markers, _ := normalizeSupervisorMarkers(spec.Markers)
	report := probeSupervisorReport{
		Schema: "15-plus-kernel-poc.probe-supervisor.v1", Symbol: spec.Symbol,
		Source: destination, SHA256: digest(source), Markers: markers, TimeoutMS: spec.TimeoutMS,
	}
	if err = writeProbeJSON(c, "probe-supervisor-latest.json", report); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Generated pthread probe supervisor symbol=%s timeout_ms=%d sha256=%s source=%s\n", spec.Symbol, spec.TimeoutMS, digest(source), destination)
	return nil
}
