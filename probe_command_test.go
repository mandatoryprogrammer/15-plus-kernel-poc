package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newProbeTestCache(t *testing.T) *cache {
	t.Helper()
	c, err := newCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.out = &bytes.Buffer{}
	return c
}

func TestProbeNormalizeUsesCanonicalPreparationAndAtomicReport(t *testing.T) {
	c := newProbeTestCache(t)
	source := filepath.Join(t.TempDir(), "unsigned-probe")
	if err := os.WriteFile(source, unsignedRuntimeMachOFixture(2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probeCommand(context.Background(), c, []string{"normalize", source, "--dest", "/usr/local/bin/normalized-probe"}); err != nil {
		t.Fatal(err)
	}
	var report probeNormalizeReport
	body, err := os.ReadFile(filepath.Join(c.root, "private", "probe-normalize-latest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.Exit != "zero" || report.Normalized.Target != "/usr/local/bin/normalized-probe" ||
		report.Normalized.Size <= 0 || len(report.Normalized.SHA256) != 64 || len(report.Normalized.CDHash) != 40 ||
		!report.Normalized.LCUUIDAdded || !report.Normalized.LinkerSigned || !report.Normalized.AdHocSigned {
		t.Fatalf("unexpected normalize report: %+v", report)
	}
	stored, err := os.ReadFile(report.Normalized.Object)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(stored)) != report.Normalized.Size || digest(stored) != report.Normalized.SHA256 {
		t.Fatalf("normalized object identity mismatch: bytes=%d report=%+v", len(stored), report.Normalized)
	}
	entries, err := os.ReadDir(filepath.Join(c.root, "private"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "probe-normalize-latest.json" {
		t.Fatalf("atomic report left scratch: entries=%v err=%v", entries, err)
	}
	if output := c.out.(*bytes.Buffer).String(); !strings.Contains(output, "sha256="+report.Normalized.SHA256) || !strings.Contains(output, "cdhash="+report.Normalized.CDHash) {
		t.Fatalf("terminal identity is incomplete: %s", output)
	}
}

func installFakeXcrun(t *testing.T, fixture []byte, nondeterministic bool) string {
	t.Helper()
	root := t.TempDir()
	fixtureName := filepath.Join(root, "fixture")
	if err := os.WriteFile(fixtureName, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
set -eu
output=
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-o" ]; then
        shift
        output=$1
    fi
    shift
done
test -n "$output"
cp "$FAKE_PROBE_BINARY" "$output"
`
	if nondeterministic {
		script += `if [ -e "$FAKE_PROBE_COUNT" ]; then
    printf x >> "$output"
else
    : > "$FAKE_PROBE_COUNT"
fi
`
	}
	xcrun := filepath.Join(root, "xcrun")
	if err := os.WriteFile(xcrun, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_PROBE_BINARY", fixtureName)
	t.Setenv("FAKE_PROBE_COUNT", filepath.Join(root, "count"))
	return root
}

func createFakeProbeSysroot(t *testing.T, root string) {
	t.Helper()
	libraryDirectory := filepath.Join(root, "usr", "lib")
	if err := os.MkdirAll(libraryDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(libraryDirectory, "libSystem.B.dylib"), []byte("fake-runtime-library"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, framework := range []string{"QuartzCore", "Foundation"} {
		frameworkDirectory := filepath.Join(root, "System", "Library", "Frameworks", framework+".framework")
		if err := os.MkdirAll(frameworkDirectory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(frameworkDirectory, framework), []byte("fake-framework"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProbeBuildRequiresTwoIdenticalBuildsThenNormalizes(t *testing.T) {
	c := newProbeTestCache(t)
	installFakeXcrun(t, unsignedRuntimeMachOFixture(2), false)
	inputRoot := t.TempDir()
	source := filepath.Join(inputRoot, "DisplayProbe.c")
	sysroot := filepath.Join(inputRoot, "sysroot")
	createFakeProbeSysroot(t, sysroot)
	if err := os.WriteFile(source, []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := probeCommand(context.Background(), c, []string{
		"build", source, "--sysroot", sysroot, "--framework", "QuartzCore", "--framework", "Foundation", "--library", "System", "--min-ios", "26.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	var report probeBuildReport
	body, err := os.ReadFile(filepath.Join(c.root, "private", "probe-build-latest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.Exit != "zero" || !report.RawBuildsEqual || !report.NormalizedEqual || report.RawSHA256 == "" || report.Normalized.SHA256 == "" {
		t.Fatalf("unexpected build report: %+v", report)
	}
	joined := strings.Join(report.CompilerArgs, " ")
	for _, required := range []string{"clang -target arm64-apple-ios26.0", "-isysroot " + sysroot, "-nostdlib", "-Wl,-no_uuid", "-Wl,-no_adhoc_codesign", "-Wl,-undefined,dynamic_lookup", "-framework QuartzCore", "-framework Foundation", "-o <isolated-output>", filepath.Join(sysroot, "usr", "lib", "libSystem.B.dylib")} {
		if !strings.Contains(joined, required) {
			t.Fatalf("compiler arguments omit %q: %s", required, joined)
		}
	}
	if _, err = os.Stat(report.Normalized.Object); err != nil {
		t.Fatalf("normalized build object absent: %v", err)
	}
	tmpEntries, err := os.ReadDir(filepath.Join(c.root, "tmp"))
	if err != nil || len(tmpEntries) != 0 {
		t.Fatalf("build scratch leaked: entries=%v err=%v", tmpEntries, err)
	}
	output := c.out.(*bytes.Buffer).String()
	if strings.Count(output, "Started pid=") != 2 || strings.Count(output, "terminal=zero-exit") != 2 {
		t.Fatalf("subprocess lifecycle was not visible: %s", output)
	}
}

func TestProbeBuildSignsAndReportsSourceDeclaredEntitlements(t *testing.T) {
	const key = "com.apple.private.xpc.launchd.job-manager"
	xml := []byte(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>` + key + `</key><true/></dict></plist>`)
	c := newProbeTestCache(t)
	installFakeXcrun(t, unsignedRuntimeMachOEntitlementsFixture(xml), false)
	inputRoot := t.TempDir()
	source := filepath.Join(inputRoot, "EntitledProbe.c")
	sysroot := filepath.Join(inputRoot, "sysroot")
	createFakeProbeSysroot(t, sysroot)
	if err := os.WriteFile(source, []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probeCommand(context.Background(), c, []string{"build", source, "--sysroot", sysroot}); err != nil {
		t.Fatal(err)
	}
	var report probeBuildReport
	body, err := os.ReadFile(filepath.Join(c.root, "private", "probe-build-latest.json"))
	if err != nil || json.Unmarshal(body, &report) != nil {
		t.Fatalf("read entitlement build report: %v", err)
	}
	if report.Schema != "15-plus-kernel-poc.probe-build.v1" || report.Exit != "zero" ||
		len(report.Normalized.EntitlementKeys) != 1 || report.Normalized.EntitlementKeys[0] != key ||
		!report.Normalized.DEREntitlementsPresent || len(report.Normalized.XMLEntitlementsSHA256) != 64 ||
		len(report.Normalized.DEREntitlementsSHA256) != 64 {
		t.Fatalf("entitlement report is incomplete: %+v", report)
	}
	object, err := os.ReadFile(report.Normalized.Object)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := extractEmbeddedPayloadAuthority(object)
	if err != nil || authority == nil {
		t.Fatalf("normalized source authority is absent: authority=%+v err=%v", authority, err)
	}
	if err = validateSignedPayloadAuthority(object, authority); err != nil {
		t.Fatal(err)
	}
}

func TestProbeBuildAgainstMountedIOSRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("requires the Darwin clang driver")
	}
	sysroot := "/Volumes/ramdisk"
	if _, err := os.Stat(filepath.Join(sysroot, "usr", "lib", "libSystem.B.dylib")); err != nil {
		t.Skip("mounted iOS runtime is unavailable")
	}
	if _, err := exec.LookPath("xcrun"); err != nil {
		t.Skip("xcrun is unavailable")
	}
	c := newProbeTestCache(t)
	source := filepath.Join(t.TempDir(), "LiveRuntimeProbe.c")
	program := "extern long write(int, const void *, unsigned long); int main(void) { return write(1, \"ok\\n\", 3) == 3 ? 0 : 1; }\n"
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probeCommand(context.Background(), c, []string{"build", source, "--sysroot", sysroot, "--framework", "Foundation", "--min-ios", "26.0"}); err != nil {
		t.Fatalf("real xcrun clang build failed: %v\n%s", err, c.out.(*bytes.Buffer).String())
	}
	var report probeBuildReport
	body, err := os.ReadFile(filepath.Join(c.root, "private", "probe-build-latest.json"))
	if err != nil || json.Unmarshal(body, &report) != nil || report.Exit != "zero" || !report.RawBuildsEqual || !report.NormalizedEqual {
		t.Fatalf("real build evidence incomplete: report=%+v err=%v", report, err)
	}
}

func TestProbeBuildRejectsNondeterministicCompilerAndCleansScratch(t *testing.T) {
	c := newProbeTestCache(t)
	installFakeXcrun(t, unsignedRuntimeMachOFixture(2), true)
	inputRoot := t.TempDir()
	source := filepath.Join(inputRoot, "probe.c")
	sysroot := filepath.Join(inputRoot, "sysroot")
	createFakeProbeSysroot(t, sysroot)
	if err := os.WriteFile(source, []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := probeCommand(context.Background(), c, []string{"build", source, "--sysroot", sysroot})
	if err == nil || !strings.Contains(err.Error(), "not reproducible") {
		t.Fatalf("nondeterministic compiler accepted: %v", err)
	}
	var report probeBuildReport
	body, readErr := os.ReadFile(filepath.Join(c.root, "private", "probe-build-latest.json"))
	if readErr != nil || json.Unmarshal(body, &report) != nil || report.Exit != "failed" || report.RawBuildsEqual {
		t.Fatalf("failure report missing: report=%+v read=%v body=%s", report, readErr, body)
	}
	entries, readErr := os.ReadDir(filepath.Join(c.root, "tmp"))
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("failed build scratch leaked: entries=%v err=%v", entries, readErr)
	}
}

func TestProbeBuildParserRejectsUnboundedInputs(t *testing.T) {
	bad := [][]string{
		{"source.c"},
		{"source.c", "--sysroot", "/tmp", "--framework", "Bad/Name"},
		{"source.c", "--sysroot", "/tmp", "--library", "-force_load"},
		{"source.c", "--sysroot", "/tmp", "--min-ios", "999.0"},
		{"source.c", "--sysroot", "/tmp", "--flag", "arbitrary"},
	}
	for _, args := range bad {
		if _, err := parseProbeBuild(args); err == nil {
			t.Fatalf("unsafe build arguments accepted: %v", args)
		}
	}
}

func TestProbeBuildParsesLaunchdAppServerCapability(t *testing.T) {
	options, err := parseProbeBuild([]string{
		"source.c", "--sysroot", "/tmp/sysroot", "--capability", "launchd-app-server",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sortStringsEqual(options.Capabilities, []string{"launchd-app-server"}) ||
		!sortStringsEqual(options.CapabilityEntitlements, []string{"com.apple.private.xpc.launchd.app-server"}) {
		t.Fatalf("app-server capability changed: %+v", options)
	}
}

func TestProbeBuildFailsClearlyWhenRequestedLinkInputIsAbsent(t *testing.T) {
	c := newProbeTestCache(t)
	installFakeXcrun(t, unsignedRuntimeMachOFixture(2), false)
	root := t.TempDir()
	source, sysroot := filepath.Join(root, "probe.c"), filepath.Join(root, "sysroot")
	createFakeProbeSysroot(t, sysroot)
	if err := os.WriteFile(source, []byte("int main(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probeCommand(context.Background(), c, []string{"build", source, "--sysroot", sysroot, "--framework", "MissingKit"}); err == nil || !strings.Contains(err.Error(), "framework MissingKit is absent") {
		t.Fatalf("missing framework did not fail clearly: %v", err)
	}
	if err := probeCommand(context.Background(), c, []string{"build", source, "--sysroot", sysroot, "--library", "Missing"}); err == nil || !strings.Contains(err.Error(), "library Missing is absent") {
		t.Fatalf("missing library did not fail clearly: %v", err)
	}
}

func TestProbeRunDelegatesAndAlwaysWritesCombinedEvidence(t *testing.T) {
	c := newProbeTestCache(t)
	missing := filepath.Join(t.TempDir(), "missing-probe")
	err := probeCommand(context.Background(), c, []string{"run", missing, "--", "argument"})
	if err == nil {
		t.Fatal("missing payload unexpectedly ran")
	}
	var evidence probeRunEvidence
	body, readErr := os.ReadFile(filepath.Join(c.root, "private", "probe-run-latest.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err = json.Unmarshal(body, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Exit != "failed" || evidence.Error == "" || evidence.Payload != nil || len(evidence.Invocation) != 3 || evidence.Invocation[2] != "argument" {
		t.Fatalf("combined run evidence changed: %+v", evidence)
	}
}

func TestFrameworkSupervisorGenerationIsBoundedAndForkFree(t *testing.T) {
	source, err := renderFrameworkCallSupervisor(frameworkSupervisorSpec{
		Symbol: "getpid", Markers: []string{"display"}, TimeoutMS: 250,
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{"pthread_create", "_Atomic", "display.entry", "display.resolved", "display.return", "PROBE_TIMEOUT timeout_ms=250", `dlsym(PROBE_RTLD_DEFAULT, "getpid")`, "Header-free by design"} {
		if !strings.Contains(text, required) {
			t.Fatalf("supervisor omits %q", required)
		}
	}
	if strings.Contains(text, "fork(") {
		t.Fatal("target supervisor uses fork")
	}
	if runtime.GOOS == "darwin" {
		compiler, lookErr := exec.LookPath("cc")
		if lookErr == nil {
			root := t.TempDir()
			input, output := filepath.Join(root, "supervisor.c"), filepath.Join(root, "supervisor")
			if err = os.WriteFile(input, source, 0o600); err != nil {
				t.Fatal(err)
			}
			compileCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			command := exec.CommandContext(compileCtx, compiler, "-Wall", "-Wextra", "-Werror", input, "-o", output)
			compileOutput, compileErr := command.CombinedOutput()
			cancel()
			if compileErr != nil {
				t.Fatalf("generated supervisor does not compile: %v\n%s", compileErr, compileOutput)
			}
			runCtx, runCancel := context.WithTimeout(context.Background(), 2*time.Second)
			runOutput, runErr := exec.CommandContext(runCtx, output).CombinedOutput()
			runCancel()
			if runErr != nil || !strings.Contains(string(runOutput), "display.return") {
				t.Fatalf("generated supervisor did not complete: %v\n%s", runErr, runOutput)
			}
		}
	}
}

func TestGeneratedSupervisorBuildsAgainstMountedIOSRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("requires the Darwin clang driver")
	}
	sysroot := "/Volumes/ramdisk"
	if _, err := os.Stat(filepath.Join(sysroot, "usr", "lib", "libSystem.B.dylib")); err != nil {
		t.Skip("mounted iOS runtime is unavailable")
	}
	c := newProbeTestCache(t)
	source, err := renderFrameworkCallSupervisor(frameworkSupervisorSpec{Symbol: "getpid", Markers: []string{"target"}, TimeoutMS: 250})
	if err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(t.TempDir(), "GeneratedSupervisor.c")
	if err = os.WriteFile(input, source, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = probeCommand(context.Background(), c, []string{"build", input, "--sysroot", sysroot, "--min-ios", "26.0"}); err != nil {
		t.Fatalf("generated supervisor did not pass its own builder: %v\n%s", err, c.out.(*bytes.Buffer).String())
	}
}

func TestProbeSupervisorCommandValidatesAndReportsSource(t *testing.T) {
	c := newProbeTestCache(t)
	destination := filepath.Join(t.TempDir(), "display-supervisor.c")
	if err := probeCommand(context.Background(), c, []string{
		"supervisor", "--symbol", "CARenderServerGetDisplayLogicalBounds", "--marker", "ui.entry", "--marker", "ui.resolved", "--marker", "ui.return", "--timeout-ms", "1750", "--dest", destination,
	}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(destination)
	if err != nil || !strings.Contains(string(body), "CARenderServerGetDisplayLogicalBounds") {
		t.Fatalf("supervisor source absent: err=%v body=%s", err, body)
	}
	report, err := os.ReadFile(filepath.Join(c.root, "private", "probe-supervisor-latest.json"))
	if err != nil || !strings.Contains(string(report), digest(body)) || !strings.Contains(string(report), destination) {
		t.Fatalf("supervisor report incomplete: err=%v report=%s", err, report)
	}
	for _, bad := range [][]string{
		{"supervisor", "--symbol", "bad symbol"},
		{"supervisor", "--symbol", "good", "--timeout-ms", "1"},
		{"supervisor", "--symbol", "good", "--marker", "one", "--marker", "two"},
	} {
		if err = probeCommand(context.Background(), c, bad); err == nil {
			t.Fatalf("invalid supervisor accepted: %v", bad)
		}
	}
}
