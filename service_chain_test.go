package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestServiceChainManifestAndLauncherArguments(t *testing.T) {
	manifest := serviceChainManifest{
		Schema: serviceChainSchema,
		Name:   "product-display",
		Services: []string{
			"appledisplayplatformd", "hidd.nonui", "SwitchBoard",
		},
	}
	if err := validateServiceChainManifest(manifest); err != nil {
		t.Fatal(err)
	}
	c := &cache{root: t.TempDir()}
	profile := uiProfile{
		Schema: "15-plus-kernel-poc.ui-profile.v3",
		Launcher: &uiObject{
			Relative: uiRootLauncherName, SHA256: "launcher",
		},
		Program: &uiProgram{SHA256: "active-program", Size: 123, CDHash: "cdhash", Argv0: "/usr/local/bin/test-program"},
		Files: []uiObject{
			{Relative: uiExecutableRelative, SHA256: "monkeybars"},
			{Relative: uiFrameworkRelative, SHA256: "framebuffer"},
		},
	}
	got, err := serviceChainRunArguments(c, profile, manifest, []string{"-h"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(c.root, "objects", "launcher"), "--dest", uiRootLauncherTarget,
		"--include", filepath.Join(c.root, "objects", "active-program") + "=" + uiStagedTarget,
		"--include", filepath.Join(c.root, "objects", "framebuffer") + "=" + uiFrameworkTarget,
		"--", "--service-chain-v1", "appledisplayplatformd,hidd.nonui,SwitchBoard", "--program-v1", "/usr/local/bin/test-program", "--", "-h",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("service-chain payload arguments changed:\n got: %q\nwant: %q", got, want)
	}
}

func TestBoundedTargetCaptureAndMarkerReduction(t *testing.T) {
	capture := &boundedTargetCapture{}
	input := []byte("host line\nPRODUCT_SERVICE_CHAIN stage=ready count=3 exact=1\r\nCHROOT_UI_DIRFD_TRANSITION stage=exec\nPROBE_STAGE stage=1\nPROBE_TIMEOUT elapsed_ms=10000\nPROBE_RESULT result=timeout\nPRODUCTOS_TOOLING_SMOKE_V1\n")
	if written, err := capture.Write(input); err != nil || written != len(input) {
		t.Fatalf("capture write=%d err=%v", written, err)
	}
	body, truncated := capture.snapshot()
	markers := selectedTargetMarkers(body, "PRODUCT_SERVICE_CHAIN ", "CHROOT_UI_DIRFD_TRANSITION ", "PROBE_STAGE ", "PROBE_TIMEOUT ", "PROBE_RESULT ", "PRODUCTOS_TOOLING_SMOKE_V1")
	if truncated || len(markers) != 6 || !markerContains(markers, "stage=ready") || !markerContains(markers, "stage=exec") || !markerContains(markers, "PROBE_STAGE") || !markerContains(markers, "PROBE_TIMEOUT") || !markerContains(markers, "PROBE_RESULT") || !markerContains(markers, "PRODUCTOS_TOOLING_SMOKE_V1") {
		t.Fatalf("marker reduction changed: truncated=%t markers=%q", truncated, markers)
	}
	large := bytes.Repeat([]byte{'x'}, (1<<20)+1)
	if _, err := capture.Write(large); err != nil {
		t.Fatal(err)
	}
	_, truncated = capture.snapshot()
	if !truncated {
		t.Fatal("oversized output was not marked truncated")
	}
}

func TestServiceChainRejectsUnknownDuplicateAndDrift(t *testing.T) {
	base := serviceChainManifest{Schema: serviceChainSchema, Name: "display", Services: []string{"hidd.nonui"}}
	for _, mutate := range []func(*serviceChainManifest){
		func(value *serviceChainManifest) { value.Schema = "wrong" },
		func(value *serviceChainManifest) { value.Name = "bad name" },
		func(value *serviceChainManifest) { value.Services = nil },
		func(value *serviceChainManifest) { value.Services = []string{"unknown"} },
		func(value *serviceChainManifest) { value.Services = []string{"hidd.nonui", "hidd.nonui"} },
	} {
		value := base
		value.Services = append([]string(nil), base.Services...)
		mutate(&value)
		if err := validateServiceChainManifest(value); err == nil {
			t.Fatalf("invalid service chain accepted: %+v", value)
		}
	}
}

func TestServiceChainExecutionTimeoutDefaultAndValidatedOverride(t *testing.T) {
	base := serviceChainManifest{
		Schema:   serviceChainSchema,
		Name:     "display",
		Services: []string{"hidd.nonui"},
	}
	timeout, err := serviceChainExecutionTimeout(base)
	if err != nil || timeout != 10*time.Second {
		t.Fatalf("compatibility timeout=%s err=%v, want 10s", timeout, err)
	}
	base.ExecutionTimeout = "16s"
	timeout, err = serviceChainExecutionTimeout(base)
	if err != nil || timeout != 16*time.Second {
		t.Fatalf("manifest timeout=%s err=%v, want 16s", timeout, err)
	}
	if err = validateServiceChainManifest(base); err != nil {
		t.Fatalf("validated 16s timeout rejected: %v", err)
	}
	for _, value := range []string{"0s", "-1s", "999ms", "5m1s", "not-a-duration"} {
		invalid := base
		invalid.ExecutionTimeout = value
		if _, err = serviceChainExecutionTimeout(invalid); err == nil {
			t.Fatalf("invalid service-chain execution timeout accepted: %q", value)
		}
		if err = validateServiceChainManifest(invalid); err == nil {
			t.Fatalf("manifest accepted invalid execution timeout: %q", value)
		}
	}
}

func TestDefaultDisplayChainSelectsReportedExecutionTimeout(t *testing.T) {
	manifest, _, err := loadServiceChainManifest("examples/productos-display-chain.json")
	if err != nil {
		t.Fatal(err)
	}
	timeout, err := serviceChainExecutionTimeout(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if timeout < 16*time.Second {
		t.Fatalf("default display-chain timeout=%s, want at least 16s", timeout)
	}
	report := newServiceChainReport("manifest.json", "manifest-sha",
		manifest, []string{"-h"}, uiProgram{SHA256: "program-sha"}, timeout)
	if report.ExecutionTimeout != "16s" {
		t.Fatalf("reported execution timeout=%q, want 16s", report.ExecutionTimeout)
	}
	if report.Manifest != "manifest.json" ||
		report.ManifestSHA256 != "manifest-sha" ||
		report.Program.SHA256 != "program-sha" ||
		!reflect.DeepEqual(report.Arguments, []string{"-h"}) {
		t.Fatalf("initial report lost run identity: %+v", report)
	}
}

func TestLoadServiceChainManifestIsStrictAndHashesExactInput(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "chain.json")
	body := []byte("{\n  \"schema\": \"15-plus-kernel-poc.service-chain.v1\",\n  \"name\": \"display\",\n  \"services\": [\"appledisplayplatformd\", \"hidd.nonui\"]\n}\n")
	if err := os.WriteFile(name, body, 0600); err != nil {
		t.Fatal(err)
	}
	value, hash, err := loadServiceChainManifest(name)
	if err != nil || len(hash) != 64 || len(value.Services) != 2 {
		t.Fatalf("load result value=%+v hash=%q err=%v", value, hash, err)
	}
	if err = os.WriteFile(name, []byte(strings.Replace(string(body), "\n}\n", ",\n  \"unexpected\": true\n}\n", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = loadServiceChainManifest(name); err == nil {
		t.Fatal("unknown manifest field accepted")
	}
}

func TestMachServiceValidationAndLauncherArguments(t *testing.T) {
	for _, value := range []string{"com.apple.xpc.adp", "com.apple.CARenderServer", "service-1"} {
		if !machServiceName.MatchString(value) {
			t.Fatalf("valid Mach service rejected: %q", value)
		}
	}
	for _, value := range []string{"", "has space", strings.Repeat("x", 128)} {
		if machServiceName.MatchString(value) {
			t.Fatalf("invalid Mach service accepted: %q", value)
		}
	}
	c := &cache{root: t.TempDir()}
	profile := uiProfile{Launcher: &uiObject{Relative: uiRootLauncherName, SHA256: "launcher"}}
	got, err := uiLauncherRunArguments(c, profile, []string{"--mach-service-probe-v1", "com.apple.xpc.adp"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(c.root, "objects", "launcher"), "--dest", uiRootLauncherTarget, "--", "--mach-service-probe-v1", "com.apple.xpc.adp"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Mach service launcher arguments changed: got=%q want=%q", got, want)
	}
}
