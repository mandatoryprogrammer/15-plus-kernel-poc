package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestContractBindSortsInputsAndPrunesSupersededObject(t *testing.T) {
	c := newProbeTestCache(t)
	root := t.TempDir()
	first, second := filepath.Join(root, "first"), filepath.Join(root, "second")
	if err := os.WriteFile(first, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := contractCommand(context.Background(), c, []string{"bind", "--input", "zeta=" + second, "--input", "alpha=" + first}); err != nil {
		t.Fatal(err)
	}
	var contract exactInputContract
	body, err := os.ReadFile(filepath.Join(c.root, "private", "input-contract-latest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(body, &contract); err != nil {
		t.Fatal(err)
	}
	if contract.Schema != exactInputContractSchema || len(contract.Inputs) != 2 || contract.Inputs[0].Name != "alpha" || contract.Inputs[1].Name != "zeta" {
		t.Fatalf("unexpected contract: %+v", contract)
	}
	if err = os.WriteFile(second, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = contractCommand(context.Background(), c, []string{"bind", "--input", "zeta=" + second}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(c.root, "private", "input-contracts"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("superseded contracts not pruned: %v %v", entries, err)
	}
}

func TestCapabilitySourceMergesExistingAuthorityAndNamedCapabilities(t *testing.T) {
	source := []byte(`__attribute__((used, section("__TEXT,__entitlements")))
static const char authority[] = "<plist><dict><key>com.apple.existing</key><true/></dict></plist>";
int main(void) { return 0; }
`)
	options := probeBuildOptions{Source: "source.c", Capabilities: []string{"target-task-control", "spawn-subsystem-root"}, CapabilityEntitlements: []string{"com.apple.system-task-ports.control", "com.apple.private.spawn-subsystem-root"}}
	scratch := t.TempDir()
	if err := mergeProbeCapabilitySource(source, &options, scratch); err != nil {
		t.Fatal(err)
	}
	sanitized, err := os.ReadFile(options.Source)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := os.ReadFile(options.CapabilitySource)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sanitized, []byte("__entitlements")) {
		t.Fatal("old authority was not removed")
	}
	for _, key := range []string{"com.apple.existing", "com.apple.private.spawn-subsystem-root", "com.apple.system-task-ports.control"} {
		if !bytes.Contains(authority, []byte(key)) {
			t.Fatalf("merged authority lacks %s: %s", key, authority)
		}
	}
	if !sortStringsEqual(options.CapabilityEntitlements, []string{"com.apple.existing", "com.apple.private.spawn-subsystem-root", "com.apple.system-task-ports.control"}) {
		t.Fatalf("entitlement report changed: %v", options.CapabilityEntitlements)
	}
}

func sortStringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func syntheticTargetImageContract() targetImageContract {
	return targetImageContract{Schema: targetImageContractSchema, CacheUUID: "11CAD49B-2122-31EE-8B7C-CCF1BC3A6728", ImageUUID: "EC544EA0-5157-34A8-A85A-0F3BCCE6D272", CacheStaticBase: 0x180000000, StaticBase: 0x183ae8000,
		LooseDyld: &targetLooseDyld{Path: "/usr/lib/dyld", UUID: "E1111111-2222-3333-4444-555555555555", StaticBase: 0x180000000, Notifier: targetImageSymbol{Name: "_lldb_image_notifier", Address: 0x1801317e0, ImageOffset: 0x1317e0, PreimageHex: "c0035fd6d00080d2011000d403010054"}},
		Symbols:   []targetImageSymbol{{Name: "_CARenderServerRegister", Address: 0x183d46e2c, ImageOffset: 0x25ee2c, FileOffset: 0x25ee2c, PreimageHex: "76d1ff17ded4ff177f2303d5fc6fbca9", PreimageSHA256: "ac03f0f8009206b1fa27a3bb0008c2257bd2f644fa30e3f4ac3701a3acecf3b9"}}}
}

func TestTargetControlModuleOwnsResolutionTransitionAndCleanup(t *testing.T) {
	source, err := renderTargetControlModule(syntheticTargetImageContract(), []string{"target-dyld", "hardware-breakpoints", "structured-cleanup"})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"TASK_DYLD_INFO", "POC_TASK_DYLD_INFO_COUNT 5", "poc_target_dyld_snapshot_read", "poc_target_image_resolve", "poc_expected_cache_uuid", "poc_xpaci", "poc_target_dyld_notifier_resolve", "poc_breakpoint_install_dyld_notifier", "poc_breakpoints[POC_BREAKPOINT_COUNT]", "poc_validate_breakpoint_preimage", "poc_breakpoint_temporary_to_final", "task_get_exception_ports", "poc_controller_cleanup", "POC_TARGET_CONTROL {\\\"phase\\\""} {
		if !bytes.Contains(source, []byte(required)) {
			t.Fatalf("generated target controller lacks %q", required)
		}
	}
	if bytes.Contains(source, []byte("0x0ULL, {0x00")) {
		t.Fatal("generated target controller lost the exact preimage")
	}
}

func syntheticTargetRoleInputs(t *testing.T) (targetImageContract, []byte, map[string]any) {
	t.Helper()
	image := make([]byte, 64)
	registration := []byte{0x7f, 0x23, 0x03, 0xd5, 0xfa, 0x67, 0xbb, 0xa9, 0xf8, 0x5f, 0x01, 0xa9, 0xf6, 0x57, 0x02, 0xa9}
	callback := []byte{0x7f, 0x23, 0x03, 0xd5, 0xff, 0xc3, 0x02, 0xd1, 0xf4, 0x4f, 0x09, 0xa9, 0xfd, 0x7b, 0x0a, 0xa9}
	copy(image[16:32], registration)
	copy(image[32:48], callback)
	contract := targetImageContract{
		Schema: targetImageContractSchema, CacheUUID: "11CAD49B-2122-31EE-8B7C-CCF1BC3A6728",
		ImagePath: "/System/Library/Frameworks/QuartzCore.framework/QuartzCore",
		ImageUUID: "EC544EA0-5157-34A8-A85A-0F3BCCE6D272", StaticBase: 0x1000,
		Segments: []contractSegment{{Name: "__TEXT", VMAddress: 0x1000, VMSize: 64, FileOffset: 0, FileSize: 64}},
	}
	report := map[string]any{
		"schema":       "productos-carenderserver-display-list-contract.v2",
		"shared_cache": map[string]any{"uuid": "11cad49b212231ee8b7cccf1bc3a6728"},
		"quartzcore": map[string]any{
			"path": contract.ImagePath, "uuid": "ec544ea0515734a8a85a0f3bcce6d272", "load_address": "0x1000",
		},
		"functions": []any{
			map[string]any{"role": "producer-registration", "start": "0x1010", "bytes": len(registration), "sha256": digest(registration), "hex": fmt.Sprintf("%x", registration)},
			map[string]any{"role": "producer-callback", "start": "0x1020", "bytes": len(callback), "sha256": digest(callback), "hex": fmt.Sprintf("%x", callback)},
		},
	}
	return contract, image, report
}

func targetRoleReportBody(t *testing.T, report map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestTargetImageContractBindsStrippedReportRolesToExtractedPreimages(t *testing.T) {
	contract, image, report := syntheticTargetRoleInputs(t)
	symbols, schema, err := targetReportRoleSymbols(contract, targetRoleReportBody(t, report), image,
		[]string{"producer-registration", "producer-callback"})
	if err != nil {
		t.Fatal(err)
	}
	if schema != "productos-carenderserver-display-list-contract.v2" || len(symbols) != 2 ||
		symbols[0].Name != "producer-registration" || symbols[0].Address != 0x1010 ||
		symbols[1].Name != "producer-callback" || symbols[1].Address != 0x1020 {
		t.Fatalf("report roles were not bound exactly: schema=%q symbols=%+v", schema, symbols)
	}
	for _, symbol := range symbols {
		if len(symbol.PreimageHex) != 32 || symbol.PreimageSHA256 == "" {
			t.Fatalf("report role lost its exact preimage: %+v", symbol)
		}
	}
}

func TestTargetImageContractReportRoleMutationsReachNamedChecks(t *testing.T) {
	contract, image, base := syntheticTargetRoleInputs(t)
	tests := []struct {
		name, want string
		mutate     func(map[string]any, []byte) []byte
	}{
		{"schema", "schema", func(report map[string]any, image []byte) []byte { report["schema"] = "wrong.v1"; return image }},
		{"cache identity", "cache/image identity", func(report map[string]any, image []byte) []byte {
			report["shared_cache"].(map[string]any)["uuid"] = "00"
			return image
		}},
		{"function identity", "function identity", func(report map[string]any, image []byte) []byte {
			report["functions"].([]any)[0].(map[string]any)["sha256"] = strings.Repeat("0", 64)
			return image
		}},
		{"extracted preimage", "preimage does not match", func(report map[string]any, image []byte) []byte {
			changed := bytes.Clone(image)
			changed[16] ^= 1
			return changed
		}},
		{"missing role", "lacks role", func(report map[string]any, image []byte) []byte {
			report["functions"] = report["functions"].([]any)[:1]
			return image
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			var report map[string]any
			if err = json.Unmarshal(encoded, &report); err != nil {
				t.Fatal(err)
			}
			mutatedImage := test.mutate(report, image)
			_, _, err = targetReportRoleSymbols(contract, targetRoleReportBody(t, report), mutatedImage,
				[]string{"producer-registration", "producer-callback"})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("mutation error=%v want site containing %q", err, test.want)
			}
		})
	}
}

func TestTargetImageContractReportRoleArgumentsFailClosed(t *testing.T) {
	valid, err := parseTargetImageContract([]string{"--cache", "cache", "--image", "image", "--report", "report", "--role", "producer-registration"})
	if err != nil || valid.Report != "report" || len(valid.Roles) != 1 || valid.Roles[0] != "producer-registration" {
		t.Fatalf("canonical report role was rejected: options=%+v err=%v", valid, err)
	}
	for _, args := range [][]string{
		{"--cache", "cache", "--image", "image", "--report", "report"},
		{"--cache", "cache", "--image", "image", "--role", "producer-registration"},
		{"--cache", "cache", "--image", "image", "--report", "report", "--role", "producer-registration", "--role", "producer-registration"},
		{"--cache", "cache", "--image", "image", "--report", "report", "--role", "../producer-registration"},
	} {
		if _, err := parseTargetImageContract(args); err == nil {
			t.Fatalf("invalid report-role arguments were accepted: %v", args)
		}
	}
}

func TestTargetControlModuleUsesLiveTaskDyldABIAndPinned64BitLayout(t *testing.T) {
	source, err := renderTargetControlModule(syntheticTargetImageContract(), []string{"target-dyld", "hardware-breakpoints", "structured-cleanup"})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"#define POC_TASK_DYLD_INFO_COUNT 5",
		"#define POC_DYLD_ALL_IMAGE_INFOS_READ_SIZE 192",
		"#define POC_DYLD_ALL_IMAGE_INFOS_MIN_CACHE_SIZE 184",
		"#define POC_DYLD_SHARED_CACHE_SLIDE_OFFSET 152",
		"#define POC_DYLD_SHARED_CACHE_UUID_OFFSET 160",
		"#define POC_DYLD_SHARED_CACHE_BASE_OFFSET 176",
		"#define POC_SHARED_CACHE_SLIDE_ALIGNMENT 0x4000ULL",
		"#define POC_SHARED_CACHE_MAX_SLIDE 0x20000000ULL",
		"snapshot->count != POC_TASK_DYLD_INFO_COUNT",
		"snapshot->read_status=-1",
		"poc_remote_read_exact(task,snapshot->info.address",
		"out->cache_slide > POC_SHARED_CACHE_MAX_SLIDE",
		"out->cache_slide & (POC_SHARED_CACHE_SLIDE_ALIGNMENT-1)",
		"__asm__ volatile(\"xpaci %0\"",
	} {
		if !bytes.Contains(source, []byte(required)) {
			t.Fatalf("generated target controller lacks live ABI/layout assertion %q", required)
		}
	}
	for _, forbidden := range []string{
		"remote+136", "remote[144+i]", "remote+160", "0x0000ffffffffffffULL",
	} {
		if bytes.Contains(source, []byte(forbidden)) {
			t.Fatalf("generated target controller retained stale layout or pointer mask %q", forbidden)
		}
	}
}

func TestTargetControlModuleCompilesAgainstMountedRuntime(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("requires Darwin clang")
	}
	if _, err := os.Stat("/Volumes/ramdisk/usr/lib/libSystem.B.dylib"); err != nil {
		t.Skip("mounted runtime unavailable")
	}
	if _, err := exec.LookPath("xcrun"); err != nil {
		t.Skip("xcrun unavailable")
	}
	root := t.TempDir()
	header := filepath.Join(root, "poc-target-control.h")
	sourceName := filepath.Join(root, "smoke.c")
	output := filepath.Join(root, "smoke")
	source, err := renderTargetControlModule(syntheticTargetImageContract(), []string{"target-dyld", "hardware-breakpoints", "structured-cleanup"})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(header, source, 0o600); err != nil {
		t.Fatal(err)
	}
	program := `#include "poc-target-control.h"
int main(void) { struct poc_target_controller value = {0}; poc_controller_json(&value, "compile", 0); return 0; }
`
	if err = os.WriteFile(sourceName, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("xcrun", "clang", "-target", "arm64-apple-ios26.0", "-isysroot", "/Volumes/ramdisk", "-std=c17", "-nostdlib", "-Wl,-undefined,dynamic_lookup", "-o", output, sourceName, "/Volumes/ramdisk/usr/lib/libSystem.B.dylib")
	if body, runErr := command.CombinedOutput(); runErr != nil {
		t.Fatalf("generated target module did not compile: %v\n%s", runErr, body)
	}
}

func TestServiceChainProfileBindsExactInputsAndRejectsMutation(t *testing.T) {
	c := newProbeTestCache(t)
	root := t.TempDir()
	manifest := filepath.Join(root, "chain.json")
	native := filepath.Join(root, "native")
	cryptex := filepath.Join(root, "cryptex")
	trust := filepath.Join(root, "trust")
	launcher := filepath.Join(root, "launcher")
	manifestBody := []byte("{\n  \"schema\": \"15-plus-kernel-poc.service-chain.v1\",\n  \"name\": \"test\",\n  \"services\": [\"hidd.nonui\"]\n}\n")
	for name, body := range map[string][]byte{manifest: manifestBody, launcher: []byte("launcher"), native: []byte("native"), cryptex: []byte("cryptex"), trust: []byte("trust")} {
		if err := os.WriteFile(name, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"bind", "product-hidd-systemos", "--manifest", manifest, "--launcher", launcher, "--program-argv0", "/usr/local/libexec/productos-car-producer-state", "--preserve-native", native + "=/usr/local/libexec/hidd", "--systemos-cryptex", cryptex, "--systemos-cryptex-trust-cache", trust}
	if err := serviceChainProfileCommand(context.Background(), c, args); err != nil {
		t.Fatal(err)
	}
	profile, ok, err := loadServiceChainProfile(c, "product-hidd-systemos")
	if err != nil || !ok || profile.Launcher == nil || profile.PreservedNative == nil || profile.SystemOSCryptex == nil || profile.SystemOSTrust == nil || profile.PreservedDestination != "/usr/local/libexec/hidd" ||
		profile.Launcher.Path != launcher || profile.ProgramArgv0 != "/usr/local/libexec/productos-car-producer-state" || profile.PreservedNative.Path != native || profile.SystemOSCryptex.Path != cryptex || profile.SystemOSTrust.Path != trust {
		t.Fatalf("profile incomplete: %+v ok=%v err=%v", profile, ok, err)
	}
	if err = os.WriteFile(native, []byte("mutated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = loadServiceChainProfile(c, "product-hidd-systemos"); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("mutated profile input accepted: %v", err)
	}
}

func TestServiceChainEvidenceReductionIsStructuredAndPrunes(t *testing.T) {
	c := newProbeTestCache(t)
	report := serviceChainReport{Schema: "15-plus-kernel-poc.service-chain-report.v1", ManifestSHA256: strings.Repeat("a", 64), Program: uiProgram{SHA256: strings.Repeat("b", 64)}, ChainReady: true, ProgramReached: true, Exit: "failed", RecoveryCleanup: "persistent-recovery-verified", Markers: []string{"PRODUCT_SERVICE_CHAIN stage=ready", "POC_TARGET_CONTROL {\"phase\":\"resolved\"}"}}
	if err := reduceServiceChainEvidence(c, report); err != nil {
		t.Fatal(err)
	}
	var evidence serviceChainReducedEvidence
	body, err := os.ReadFile(filepath.Join(c.root, "private", "service-chain-evidence-latest.json"))
	if err != nil || json.Unmarshal(body, &evidence) != nil {
		t.Fatalf("read reduced evidence: %v %s", err, body)
	}
	if evidence.Outcome != "program-failed" || !evidence.CleanupExact || len(evidence.Markers) != 2 {
		t.Fatalf("reduction lost outcome: %+v", evidence)
	}
}

func TestServiceChainEvidenceRecognizesProducerProgramBoundary(t *testing.T) {
	c := newProbeTestCache(t)
	report := serviceChainReport{Schema: "15-plus-kernel-poc.service-chain-report.v1", Exit: "failed", Markers: []string{"PRODUCT_SERVICE_CHAIN stage=hidd-producer-probe-spawn child=217", "CAR_LOGICAL_BOUNDS_SUPERVISOR stage=invocation held_target_mode=1"}}
	if err := reduceServiceChainEvidence(c, report); err != nil {
		t.Fatal(err)
	}
	var evidence serviceChainReducedEvidence
	body, err := os.ReadFile(filepath.Join(c.root, "private", "service-chain-evidence-latest.json"))
	if err != nil || json.Unmarshal(body, &evidence) != nil {
		t.Fatalf("read evidence: %v", err)
	}
	if !evidence.ProgramReached || evidence.Outcome != "program-failed" {
		t.Fatalf("producer program boundary was misclassified: %+v", evidence)
	}
}

func TestRealDyldImageContractWhenConfigured(t *testing.T) {
	cachePath := os.Getenv("POC_TEST_DYLD_CACHE")
	if cachePath == "" {
		t.Skip("POC_TEST_DYLD_CACHE is unset")
	}
	if _, err := exec.LookPath("ipsw"); err != nil {
		t.Skip("ipsw unavailable")
	}
	c := newProbeTestCache(t)
	destination := filepath.Join(t.TempDir(), "contract.json")
	if err := targetImageContractCommand(context.Background(), c, []string{"--cache", cachePath, "--image", "/System/Library/Frameworks/QuartzCore.framework/QuartzCore", "--symbol", "CARenderServerRegister", "--section", "__TEXT,__text", "--dest", destination}); err != nil {
		t.Fatal(err)
	}
	contract, _, _, err := loadTargetImageContract(destination)
	if err != nil {
		t.Fatal(err)
	}
	if contract.CacheStaticBase == 0 || contract.StaticBase == 0 || len(contract.Symbols) != 1 || len(contract.Symbols[0].PreimageHex) != 32 {
		t.Fatalf("real contract incomplete: %+v", contract)
	}
}
