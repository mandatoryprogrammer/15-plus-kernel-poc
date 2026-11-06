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
	for _, required := range []string{"TASK_DYLD_INFO", "poc_target_image_resolve", "poc_expected_cache_uuid", "poc_strip_pac", "poc_breakpoint_install_dyld_notifier", "poc_validate_breakpoint_preimage", "poc_breakpoint_temporary_to_final", "task_get_exception_ports", "poc_controller_cleanup", "POC_TARGET_CONTROL {\\\"phase\\\""} {
		if !bytes.Contains(source, []byte(required)) {
			t.Fatalf("generated target controller lacks %q", required)
		}
	}
	if bytes.Contains(source, []byte("0x0ULL, {0x00")) {
		t.Fatal("generated target controller lost the exact preimage")
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
	manifestBody := []byte("{\n  \"schema\": \"15-plus-kernel-poc.service-chain.v1\",\n  \"name\": \"test\",\n  \"services\": [\"hidd.nonui\"]\n}\n")
	for name, body := range map[string][]byte{manifest: manifestBody, native: []byte("native"), cryptex: []byte("cryptex"), trust: []byte("trust")} {
		if err := os.WriteFile(name, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"bind", "product-hidd-systemos", "--manifest", manifest, "--preserve-native", native + "=/usr/local/libexec/hidd", "--systemos-cryptex", cryptex, "--systemos-cryptex-trust-cache", trust}
	if err := serviceChainProfileCommand(context.Background(), c, args); err != nil {
		t.Fatal(err)
	}
	profile, ok, err := loadServiceChainProfile(c, "product-hidd-systemos")
	if err != nil || !ok || profile.PreservedNative == nil || profile.SystemOSCryptex == nil || profile.SystemOSTrust == nil || profile.PreservedDestination != "/usr/local/libexec/hidd" ||
		profile.PreservedNative.Path != native || profile.SystemOSCryptex.Path != cryptex || profile.SystemOSTrust.Path != trust {
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
	if evidence.Outcome != "program-reached" || !evidence.CleanupExact || len(evidence.Markers) != 2 {
		t.Fatalf("reduction lost outcome: %+v", evidence)
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
