package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestUIRunUsesProductRootLauncherAndStagesExactInputs(t *testing.T) {
	c := &cache{root: t.TempDir()}
	profile := uiProfile{
		Schema:   "15-plus-kernel-poc.ui-profile.v2",
		Launcher: &uiObject{Relative: uiRootLauncherName, SHA256: "launcher"},
		Files: []uiObject{
			{Relative: uiExecutableRelative, SHA256: "monkeybars"},
			{Relative: uiFrameworkRelative, SHA256: "framebuffer"},
		},
	}
	got, err := uiPayloadRunArguments(c, profile, []string{"-h"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(c.root, "objects", "launcher"),
		"--dest", uiRootLauncherTarget,
		"--include", filepath.Join(c.root, "objects", "monkeybars") + "=" + uiStagedTarget,
		"--include", filepath.Join(c.root, "objects", "framebuffer") + "=" + uiFrameworkTarget,
		"--", uiRootLauncherMode, "-h",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rooted UI payload arguments changed:\n got: %q\nwant: %q", got, want)
	}
	profile.Launcher = nil
	if _, err = uiPayloadRunArguments(c, profile, nil); err == nil {
		t.Fatal("UI run accepted a profile without the root launcher")
	}
}
