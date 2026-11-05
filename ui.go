package main

import (
	"bytes"
	"context"
	"debug/macho"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	uiExecutableRelative = "usr/local/bin/monkeybars"
	uiFrameworkRelative  = "AppleInternal/Library/Frameworks/iRemoteFramebuffer.framework/iRemoteFramebuffer"
	uiExecutableTarget   = "/usr/local/bin/monkeybars"
	uiStagedTarget       = "/usr/local/libexec/productos-ui"
	uiFrameworkTarget    = "/usr/local/lib/iRemoteFramebuffer.framework/iRemoteFramebuffer"
	uiRootLauncherTarget = "/usr/local/bin/productos-ui-root-launcher"
	uiRootLauncherName   = "ProductOSUIRootLauncher"
	uiRootLauncherMode   = "--chroot-ui-dirfd"
)

var uiBundleFiles = []string{
	"PROVENANCE.json",
	"System/Library/CoreServices/SystemVersion.plist",
	uiExecutableRelative,
	uiFrameworkRelative,
	"AppleInternal/Library/Frameworks/iRemoteFramebuffer.framework/Info.plist",
	"AppleInternal/Library/Frameworks/iRemoteFramebuffer.framework/_CodeSignature/CodeResources",
	"AppleInternal/Library/LaunchDaemons/com.apple.internal.monkeybars.cameraserver.plist",
	"AppleInternal/Library/LaunchDaemons/com.apple.internal.monkeybars.screenserver.plist",
	"AppleInternal/Library/LaunchDaemons/com.apple.monkeybars.plist",
	"AppleInternal/Lockdown/ServiceAgents/com.apple.internal.monkeybars.cameraserver.service.plist",
	"AppleInternal/Lockdown/ServiceAgents/com.apple.internal.monkeybars.screenserver.service.plist",
	"AppleInternal/Lockdown/ServiceAgents/com.apple.monkeybars.service.plist",
}

type uiObject struct {
	Relative string `json:"relative"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

type uiProgram struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	CDHash string `json:"cdhash"`
	Argv0  string `json:"argv0"`
}

type uiProfile struct {
	Schema   string     `json:"schema"`
	Files    []uiObject `json:"files"`
	Launcher *uiObject  `json:"launcher,omitempty"`
	Program  *uiProgram `json:"program,omitempty"`
}

func uiProfilePath(c *cache) string { return filepath.Join(c.root, "private", "ui-profile.json") }

func writeUIProfile(c *cache, profile uiProfile) error {
	body, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Join(c.root, "private"), "ui-profile-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(append(body, '\n'))
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
	return os.Rename(name, uiProfilePath(c))
}

func loadUIProfile(ctx context.Context, c *cache) (uiProfile, error) {
	var profile uiProfile
	body, err := os.ReadFile(uiProfilePath(c))
	if errors.Is(err, os.ErrNotExist) {
		return profile, errors.New("UI bundle is not imported; run: 15-plus-kernel-poc ui import DIRECTORY")
	}
	if err != nil {
		return profile, err
	}
	if err = json.Unmarshal(body, &profile); err != nil ||
		(profile.Schema != "15-plus-kernel-poc.ui-profile.v1" && profile.Schema != "15-plus-kernel-poc.ui-profile.v2" && profile.Schema != "15-plus-kernel-poc.ui-profile.v3") ||
		len(profile.Files) != len(uiBundleFiles) {
		return profile, errors.New("invalid UI profile")
	}
	seen := map[string]bool{}
	for _, object := range profile.Files {
		if seen[object.Relative] {
			return profile, errors.New("duplicate UI profile path")
		}
		seen[object.Relative] = true
		a := asset{Role: "ui-bundle", SHA256: object.SHA256, Size: object.Size}
		if err = verifyFile(ctx, c.object(a), a); err != nil {
			return profile, fmt.Errorf("verify UI object %s: %w", object.Relative, err)
		}
	}
	for _, relative := range uiBundleFiles {
		if !seen[relative] {
			return profile, fmt.Errorf("UI profile is missing %s", relative)
		}
	}
	if profile.Schema == "15-plus-kernel-poc.ui-profile.v2" || profile.Schema == "15-plus-kernel-poc.ui-profile.v3" {
		if profile.Launcher == nil || profile.Launcher.Relative != uiRootLauncherName {
			return profile, errors.New("UI profile is missing the ProductOS root launcher")
		}
		a := asset{Role: "ui-root-launcher", SHA256: profile.Launcher.SHA256, Size: profile.Launcher.Size}
		if err = verifyFile(ctx, c.object(a), a); err != nil {
			return profile, fmt.Errorf("verify UI root launcher: %w", err)
		}
	} else if profile.Launcher != nil {
		return profile, errors.New("v1 UI profile unexpectedly contains a root launcher")
	}
	if profile.Schema == "15-plus-kernel-poc.ui-profile.v3" {
		if err = verifyUIProgram(ctx, c, profile.Program); err != nil {
			return profile, err
		}
	} else if profile.Program != nil {
		return profile, fmt.Errorf("%s UI profile unexpectedly contains an active program", profile.Schema)
	}
	return profile, nil
}

func validUIArgv0(value string) bool {
	return len(value) > 1 && len(value) <= 4096 && filepath.IsAbs(value) && filepath.Clean(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func verifyUIProgram(ctx context.Context, c *cache, program *uiProgram) error {
	if program == nil || !digestPattern.MatchString(program.SHA256) || program.Size <= 0 ||
		len(program.CDHash) != 40 || !validUIArgv0(program.Argv0) {
		return errors.New("UI profile has an invalid active program")
	}
	a := asset{Role: "ui-program", SHA256: program.SHA256, Size: program.Size}
	if err := verifyFile(ctx, c.object(a), a); err != nil {
		return fmt.Errorf("verify active UI program: %w", err)
	}
	cdhash, err := inspectExecutableFile(c.object(a))
	if err != nil {
		return fmt.Errorf("inspect active UI program: %w", err)
	}
	if cdhash != program.CDHash {
		return errors.New("active UI program CDHash mismatch")
	}
	return nil
}

func inspectExecutableFile(name string) (string, error) {
	body, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return inspectExecutable(body)
}

func uiObjectPath(c *cache, profile uiProfile, relative string) (string, error) {
	for _, object := range profile.Files {
		if object.Relative == relative {
			return c.object(asset{SHA256: object.SHA256}), nil
		}
	}
	return "", fmt.Errorf("UI profile is missing %s", relative)
}

func importUI(ctx context.Context, c *cache, root string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	var profile = uiProfile{Schema: "15-plus-kernel-poc.ui-profile.v1"}
	for index, relative := range uiBundleFiles {
		name := filepath.Join(root, filepath.FromSlash(relative))
		info, statErr := os.Lstat(name)
		if statErr != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
			return fmt.Errorf("UI bundle file %s is missing or not regular", relative)
		}
		body, readErr := os.ReadFile(name)
		if readErr != nil {
			return readErr
		}
		if relative == uiExecutableRelative || relative == uiFrameworkRelative {
			destination := uiExecutableTarget
			if relative == uiFrameworkRelative {
				destination = uiFrameworkTarget
			}
			prepared, prepareErr := preparePayload(name, destination)
			if prepareErr != nil {
				return fmt.Errorf("qualify %s: %w", relative, prepareErr)
			}
			if relative == uiExecutableRelative && prepared.FileType != macho.TypeExec {
				return errors.New("MonkeyBars input is not an executable")
			}
		}
		a := asset{Role: fmt.Sprintf("ui-%02d", index), SHA256: digest(body), Size: int64(len(body)), Recipe: "Imported complete MonkeyBars bundle", Compatibility: "ProductOS remote UI"}
		if _, err = c.store(ctx, a, bytes.NewReader(body)); err != nil {
			return err
		}
		profile.Files = append(profile.Files, uiObject{Relative: relative, SHA256: a.SHA256, Size: a.Size})
	}
	sort.Slice(profile.Files, func(i, j int) bool { return profile.Files[i].Relative < profile.Files[j].Relative })
	if err = writeUIProfile(c, profile); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Imported and verified complete UI bundle (%d files). Future ui run commands need no source paths or hashes.\n", len(profile.Files))
	return nil
}

func importUIRootLauncher(ctx context.Context, c *cache, name string) error {
	profile, err := loadUIProfile(ctx, c)
	if err != nil {
		return err
	}
	name, err = filepath.Abs(name)
	if err != nil {
		return err
	}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return errors.New("UI root launcher is missing or not regular")
	}
	prepared, err := preparePayload(name, uiRootLauncherTarget)
	if err != nil {
		return fmt.Errorf("qualify UI root launcher: %w", err)
	}
	if prepared.FileType != macho.TypeExec {
		return errors.New("UI root launcher input is not an executable")
	}
	body, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	a := asset{Role: "ui-root-launcher", SHA256: digest(body), Size: int64(len(body)), Recipe: "Imported repository-built ProductOS root launcher", Compatibility: "ProductOS remote UI"}
	if _, err = c.store(ctx, a, bytes.NewReader(body)); err != nil {
		return err
	}
	profile.Launcher = &uiObject{Relative: uiRootLauncherName, SHA256: a.SHA256, Size: a.Size}
	program, err := prepareUIProgram(ctx, c, profile, "", uiExecutableTarget)
	if err != nil {
		return fmt.Errorf("prepare original MonkeyBars program: %w", err)
	}
	profile.Schema = "15-plus-kernel-poc.ui-profile.v3"
	profile.Program = &program
	if err = writeUIProfile(c, profile); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Imported and verified ProductOS UI root launcher (%d bytes).\n", a.Size)
	return nil
}

func prepareUIProgram(ctx context.Context, c *cache, profile uiProfile, source, argv0 string) (uiProgram, error) {
	var result uiProgram
	if !validUIArgv0(argv0) {
		return result, errors.New("UI program argv0 must be a clean absolute path of at most 4096 bytes without NUL, CR, or LF")
	}
	if source == "" {
		var err error
		source, err = uiObjectPath(c, profile, uiExecutableRelative)
		if err != nil {
			return result, err
		}
	}
	prepared, err := preparePayload(source, uiStagedTarget)
	if err != nil {
		return result, fmt.Errorf("prepare UI program: %w", err)
	}
	if prepared.FileType != macho.TypeExec {
		return result, errors.New("UI program input is not an executable")
	}
	a := asset{
		Role: "ui-program", SHA256: prepared.Entry.SHA256, Size: prepared.Entry.Size,
		Recipe: "Deterministically normalized active ProductOS UI program", Compatibility: "ProductOS remote UI",
	}
	if _, err = c.store(ctx, a, bytes.NewReader(prepared.Body)); err != nil {
		return result, err
	}
	return uiProgram{SHA256: a.SHA256, Size: a.Size, CDHash: prepared.Entry.CDHash, Argv0: argv0}, nil
}

func importUIProgram(ctx context.Context, c *cache, name, argv0 string) error {
	profile, err := loadUIProfile(ctx, c)
	if err != nil {
		return err
	}
	if profile.Launcher == nil {
		return errors.New("UI root launcher is not imported; run: 15-plus-kernel-poc ui launcher import FILE")
	}
	name, err = filepath.Abs(name)
	if err != nil {
		return err
	}
	if argv0 == "" {
		argv0 = uiStagedTarget
	}
	program, err := prepareUIProgram(ctx, c, profile, name, argv0)
	if err != nil {
		return err
	}
	profile.Schema = "15-plus-kernel-poc.ui-profile.v3"
	profile.Program = &program
	if err = writeUIProfile(c, profile); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Imported active UI program (%d bytes, cdhash %s, argv0 %s); bundle and launcher unchanged.\n", program.Size, program.CDHash, program.Argv0)
	return nil
}

func resetUIProgram(ctx context.Context, c *cache) error {
	profile, err := loadUIProfile(ctx, c)
	if err != nil {
		return err
	}
	if profile.Launcher == nil {
		return errors.New("UI root launcher is not imported; run: 15-plus-kernel-poc ui launcher import FILE")
	}
	program, err := prepareUIProgram(ctx, c, profile, "", uiExecutableTarget)
	if err != nil {
		return err
	}
	profile.Schema = "15-plus-kernel-poc.ui-profile.v3"
	profile.Program = &program
	if err = writeUIProfile(c, profile); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Reset active UI program to the preserved MonkeyBars bundle object (%d bytes, cdhash %s).\n", program.Size, program.CDHash)
	return nil
}

func uiPayloadRunArgumentsMode(c *cache, profile uiProfile, launcherMode string, modeArgs, programArgs []string) ([]string, error) {
	if profile.Launcher == nil || profile.Launcher.Relative != uiRootLauncherName {
		return nil, errors.New("UI root launcher is not imported; run: 15-plus-kernel-poc ui launcher import FILE")
	}
	if launcherMode == "" {
		return nil, errors.New("UI launcher mode is empty")
	}
	if profile.Schema != "15-plus-kernel-poc.ui-profile.v3" || profile.Program == nil {
		return nil, errors.New("active UI program is not configured; run: 15-plus-kernel-poc ui program reset")
	}
	launcher := c.object(asset{SHA256: profile.Launcher.SHA256})
	executable := c.object(asset{SHA256: profile.Program.SHA256})
	framework, err := uiObjectPath(c, profile, uiFrameworkRelative)
	if err != nil {
		return nil, err
	}
	runArgs := []string{
		launcher, "--dest", uiRootLauncherTarget,
		"--include", executable + "=" + uiStagedTarget,
		"--include", framework + "=" + uiFrameworkTarget,
		"--", launcherMode,
	}
	runArgs = append(runArgs, modeArgs...)
	runArgs = append(runArgs, "--program-v1", profile.Program.Argv0, "--")
	return append(runArgs, programArgs...), nil
}

func uiPayloadRunArguments(c *cache, profile uiProfile, programArgs []string) ([]string, error) {
	return uiPayloadRunArgumentsMode(c, profile, uiRootLauncherMode, nil, programArgs)
}

func uiLauncherRunArguments(c *cache, profile uiProfile, launcherArgs []string) ([]string, error) {
	if profile.Launcher == nil || profile.Launcher.Relative != uiRootLauncherName {
		return nil, errors.New("UI root launcher is not imported; run: 15-plus-kernel-poc ui launcher import FILE")
	}
	if len(launcherArgs) == 0 {
		return nil, errors.New("UI launcher arguments are empty")
	}
	launcher := c.object(asset{SHA256: profile.Launcher.SHA256})
	runArgs := []string{launcher, "--dest", uiRootLauncherTarget, "--"}
	return append(runArgs, launcherArgs...), nil
}

func runUI(ctx context.Context, c *cache, args []string) error {
	profile, err := loadUIProfile(ctx, c)
	if err != nil {
		return err
	}
	programArgs := []string{"-l", "-a", "-d", "16"}
	if len(args) > 0 {
		if args[0] != "--" {
			return errors.New("usage: ui run [-- MONKEYBARS-ARG...]")
		}
		programArgs = append([]string(nil), args[1:]...)
	}
	runArgs, err := uiPayloadRunArguments(c, profile, programArgs)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Launching active UI program %s with automatic signing, exact staging, and a child-only ProductOS root\n", profile.Program.SHA256)
	return runPayload(ctx, c, runArgs)
}

func uiCommand(ctx context.Context, c *cache, args []string) error {
	if len(args) == 2 && args[0] == "import" {
		return importUI(ctx, c, args[1])
	}
	if len(args) == 3 && args[0] == "launcher" && args[1] == "import" {
		return importUIRootLauncher(ctx, c, args[2])
	}
	if len(args) >= 2 && args[0] == "program" && args[1] == "import" {
		if len(args) == 3 {
			return importUIProgram(ctx, c, args[2], "")
		}
		if len(args) == 5 && args[3] == "--argv0" {
			return importUIProgram(ctx, c, args[2], args[4])
		}
		return errors.New("usage: ui program import FILE [--argv0 VALUE]")
	}
	if len(args) == 2 && args[0] == "program" && args[1] == "reset" {
		return resetUIProgram(ctx, c)
	}
	if len(args) >= 1 && args[0] == "run" {
		return runUI(ctx, c, args[1:])
	}
	if len(args) == 1 && args[0] == "capture" {
		return captureUIFrame(ctx, c)
	}
	if len(args) >= 1 && args[0] == "tap" {
		return tapUIFrame(ctx, c, args[1:])
	}
	if len(args) >= 1 && args[0] == "verify" {
		return verifyUICommand(ctx, c, args[1:])
	}
	if len(args) == 1 && args[0] == "status" {
		profile, err := loadUIProfile(ctx, c)
		if err != nil {
			return err
		}
		if profile.Launcher == nil {
			fmt.Fprintf(c.out, "UI bundle ready: %d exact objects; root launcher not imported\n", len(profile.Files))
		} else if profile.Program == nil {
			fmt.Fprintf(c.out, "UI bundle ready: %d exact objects plus ProductOS root launcher; active program not configured\n", len(profile.Files))
		} else {
			fmt.Fprintf(c.out, "UI bundle ready: %d exact objects plus ProductOS root launcher; active program sha256=%s cdhash=%s argv0=%s; use: 15-plus-kernel-poc ui run\n", len(profile.Files), profile.Program.SHA256, profile.Program.CDHash, profile.Program.Argv0)
		}
		return nil
	}
	return errors.New("usage: ui import DIRECTORY | ui launcher import FILE | ui program import FILE [--argv0 VALUE] | ui program reset | ui status | ui run [-- PROGRAM-ARG...] | ui capture | ui tap X Y | ui verify [--x X --y Y --settle DURATION]")
}
