package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestUIRunUsesProductRootLauncherAndStagesExactInputs(t *testing.T) {
	c := &cache{root: t.TempDir()}
	profile := uiProfile{
		Schema:   "15-plus-kernel-poc.ui-profile.v3",
		Launcher: &uiObject{Relative: uiRootLauncherName, SHA256: "launcher"},
		Program:  &uiProgram{SHA256: "active-program", Size: 123, CDHash: "cdhash", Argv0: "/usr/local/bin/test-program"},
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
		"--include", filepath.Join(c.root, "objects", "active-program") + "=" + uiStagedTarget,
		"--include", filepath.Join(c.root, "objects", "framebuffer") + "=" + uiFrameworkTarget,
		"--", uiRootLauncherMode, "--program-v1", "/usr/local/bin/test-program", "--", "-h",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rooted UI payload arguments changed:\n got: %q\nwant: %q", got, want)
	}
	profile.Launcher = nil
	if _, err = uiPayloadRunArguments(c, profile, nil); err == nil {
		t.Fatal("UI run accepted a profile without the root launcher")
	}
}

func storeUITestBytes(t *testing.T, c *cache, body []byte) uiObject {
	t.Helper()
	object := uiObject{SHA256: digest(body), Size: int64(len(body))}
	if err := os.WriteFile(c.object(asset{SHA256: object.SHA256}), body, 0600); err != nil {
		t.Fatal(err)
	}
	return object
}

func newUIProgramTestProfile(t *testing.T) (*cache, uiProfile, []byte, []byte) {
	t.Helper()
	c, err := newCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.out = io.Discard
	original := unsignedRuntimeMachOFixtureSize(2, 0x4000)
	profile := uiProfile{Schema: "15-plus-kernel-poc.ui-profile.v3"}
	for _, relative := range uiBundleFiles {
		body := []byte("immutable bundle object: " + relative)
		if relative == uiExecutableRelative {
			body = original
		}
		object := storeUITestBytes(t, c, body)
		object.Relative = relative
		profile.Files = append(profile.Files, object)
	}
	launcherBody := []byte("immutable launcher object")
	launcher := storeUITestBytes(t, c, launcherBody)
	launcher.Relative = uiRootLauncherName
	profile.Launcher = &launcher
	source := c.object(asset{SHA256: profile.Files[uiBundleFileIndex(t, uiExecutableRelative)].SHA256})
	prepared, err := preparePayload(source, uiStagedTarget)
	if err != nil {
		t.Fatal(err)
	}
	programObject := storeUITestBytes(t, c, prepared.Body)
	profile.Program = &uiProgram{SHA256: programObject.SHA256, Size: programObject.Size, CDHash: prepared.Entry.CDHash, Argv0: uiExecutableTarget}
	if err = writeUIProfile(c, profile); err != nil {
		t.Fatal(err)
	}
	return c, profile, original, launcherBody
}

func uiBundleFileIndex(t *testing.T, relative string) int {
	t.Helper()
	for index, candidate := range uiBundleFiles {
		if candidate == relative {
			return index
		}
	}
	t.Fatalf("missing UI bundle fixture path %q", relative)
	return -1
}

func TestUIProgramImportResetUsesPreparedBodyWithoutMutatingBundleOrLauncher(t *testing.T) {
	c, baseline, originalBody, launcherBody := newUIProgramTestProfile(t)
	// The deployed cache can still hold the prior v2 profile. Program import is
	// its explicit, lossless migration to v3.
	baseline.Schema = "15-plus-kernel-poc.ui-profile.v2"
	baseline.Program = nil
	if err := writeUIProfile(c, baseline); err != nil {
		t.Fatal(err)
	}
	baselineFiles := append([]uiObject(nil), baseline.Files...)
	baselineLauncher := *baseline.Launcher
	originalObject := baseline.Files[uiBundleFileIndex(t, uiExecutableRelative)]

	var imported []*uiProgram
	for index, textSize := range []int{0x8000, 0xc000} {
		name := filepath.Join(c.root, "candidate-program-"+string(rune('a'+index)))
		if err := os.WriteFile(name, unsignedRuntimeMachOFixtureSize(2, textSize), 0600); err != nil {
			t.Fatal(err)
		}
		argv0 := ""
		if index == 1 {
			argv0 = "/usr/local/bin/second-ui-probe"
		}
		if err := importUIProgram(context.Background(), c, name, argv0); err != nil {
			t.Fatal(err)
		}
		profile, err := loadUIProfile(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(profile.Files, baselineFiles) || *profile.Launcher != baselineLauncher {
			t.Fatal("program import mutated the preserved UI bundle or launcher record")
		}
		wantArgv0 := uiStagedTarget
		if argv0 != "" {
			wantArgv0 = argv0
		}
		if profile.Schema != "15-plus-kernel-poc.ui-profile.v3" || profile.Program == nil || profile.Program.Argv0 != wantArgv0 || len(profile.Program.CDHash) != 40 {
			t.Fatalf("active program contract changed: %+v", profile.Program)
		}
		prepared, err := preparePayload(name, uiStagedTarget)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := os.ReadFile(c.object(asset{SHA256: profile.Program.SHA256}))
		if err != nil || !bytes.Equal(stored, prepared.Body) || profile.Program.Size != int64(len(prepared.Body)) {
			t.Fatalf("prepared program body was not stored exactly: bytes=%d size=%d err=%v", len(stored), profile.Program.Size, err)
		}
		reprepared, err := preparePayload(c.object(asset{SHA256: profile.Program.SHA256}), uiStagedTarget)
		if err != nil || reprepared.Entry.SHA256 != profile.Program.SHA256 || reprepared.Entry.Size != profile.Program.Size || reprepared.Entry.CDHash != profile.Program.CDHash || !bytes.Equal(reprepared.Body, stored) {
			t.Fatalf("stored program was not normalization-idempotent: got=%+v want=%+v err=%v", reprepared.Entry, profile.Program, err)
		}
		copyProgram := *profile.Program
		imported = append(imported, &copyProgram)
	}
	if imported[0].Size == imported[1].Size || imported[0].SHA256 == imported[1].SHA256 || imported[0].CDHash == imported[1].CDHash {
		t.Fatalf("different-sized programs collapsed to one identity: first=%+v second=%+v", imported[0], imported[1])
	}

	if err := resetUIProgram(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	reset, err := loadUIProfile(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	originalSource := c.object(asset{SHA256: originalObject.SHA256})
	wantOriginal, err := preparePayload(originalSource, uiStagedTarget)
	if err != nil {
		t.Fatal(err)
	}
	if reset.Program == nil || reset.Program.SHA256 != wantOriginal.Entry.SHA256 || reset.Program.Size != wantOriginal.Entry.Size || reset.Program.CDHash != wantOriginal.Entry.CDHash || reset.Program.Argv0 != uiExecutableTarget {
		t.Fatalf("program reset did not restore preserved MonkeyBars: got=%+v want=%+v", reset.Program, wantOriginal.Entry)
	}
	if !reflect.DeepEqual(reset.Files, baselineFiles) || *reset.Launcher != baselineLauncher {
		t.Fatal("program reset mutated the preserved UI bundle or launcher record")
	}
	gotOriginal, err := os.ReadFile(c.object(asset{SHA256: originalObject.SHA256}))
	if err != nil || !bytes.Equal(gotOriginal, originalBody) {
		t.Fatalf("original MonkeyBars object mutated: err=%v", err)
	}
	gotLauncher, err := os.ReadFile(c.object(asset{SHA256: baselineLauncher.SHA256}))
	if err != nil || !bytes.Equal(gotLauncher, launcherBody) {
		t.Fatalf("launcher object mutated: err=%v", err)
	}
}

func TestUIProfileRejectsTamperedProgramIdentity(t *testing.T) {
	c, profile, _, _ := newUIProgramTestProfile(t)
	profile.Program.CDHash = "0000000000000000000000000000000000000000"
	if err := writeUIProfile(c, profile); err != nil {
		t.Fatal(err)
	}
	if _, err := loadUIProfile(context.Background(), c); err == nil {
		t.Fatal("UI profile accepted a program CDHash that did not identify the stored executable")
	}
}

func TestUIProgramArgv0Validation(t *testing.T) {
	for _, value := range []string{"", "relative", "/dirty/../path", "/line\nbreak", "/" + string(bytes.Repeat([]byte{'x'}, 4097))} {
		if validUIArgv0(value) {
			t.Fatalf("invalid argv0 accepted: %q", value)
		}
	}
	for _, value := range []string{uiStagedTarget, uiExecutableTarget, "/usr/local/bin/custom probe"} {
		if !validUIArgv0(value) {
			t.Fatalf("valid argv0 rejected: %q", value)
		}
	}
}
