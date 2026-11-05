package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
		Schema: "15-plus-kernel-poc.ui-profile.v2",
		Launcher: &uiObject{
			Relative: uiRootLauncherName, SHA256: "launcher",
		},
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
		"--include", filepath.Join(c.root, "objects", "monkeybars") + "=" + uiStagedTarget,
		"--include", filepath.Join(c.root, "objects", "framebuffer") + "=" + uiFrameworkTarget,
		"--", "--service-chain-v1", "appledisplayplatformd,hidd.nonui,SwitchBoard", "--", "-h",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("service-chain payload arguments changed:\n got: %q\nwant: %q", got, want)
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
