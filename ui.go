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

type uiProfile struct {
	Schema   string     `json:"schema"`
	Files    []uiObject `json:"files"`
	Launcher *uiObject  `json:"launcher,omitempty"`
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
		(profile.Schema != "15-plus-kernel-poc.ui-profile.v1" && profile.Schema != "15-plus-kernel-poc.ui-profile.v2") ||
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
	if profile.Schema == "15-plus-kernel-poc.ui-profile.v2" {
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
	return profile, nil
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
	profile.Schema = "15-plus-kernel-poc.ui-profile.v2"
	profile.Launcher = &uiObject{Relative: uiRootLauncherName, SHA256: a.SHA256, Size: a.Size}
	if err = writeUIProfile(c, profile); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Imported and verified ProductOS UI root launcher (%d bytes).\n", a.Size)
	return nil
}

func uiPayloadRunArgumentsMode(c *cache, profile uiProfile, launcherMode string, programArgs []string) ([]string, error) {
	if profile.Launcher == nil || profile.Launcher.Relative != uiRootLauncherName {
		return nil, errors.New("UI root launcher is not imported; run: 15-plus-kernel-poc ui launcher import FILE")
	}
	if launcherMode == "" {
		return nil, errors.New("UI launcher mode is empty")
	}
	launcher := c.object(asset{SHA256: profile.Launcher.SHA256})
	executable, err := uiObjectPath(c, profile, uiExecutableRelative)
	if err != nil {
		return nil, err
	}
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
	return append(runArgs, programArgs...), nil
}

func uiPayloadRunArguments(c *cache, profile uiProfile, programArgs []string) ([]string, error) {
	return uiPayloadRunArgumentsMode(c, profile, uiRootLauncherMode, programArgs)
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
	fmt.Fprintln(c.out, "Launching imported MonkeyBars UI with automatic signing, exact staging, and a child-only ProductOS root")
	return runPayload(ctx, c, runArgs)
}

func uiCommand(ctx context.Context, c *cache, args []string) error {
	if len(args) == 2 && args[0] == "import" {
		return importUI(ctx, c, args[1])
	}
	if len(args) == 3 && args[0] == "launcher" && args[1] == "import" {
		return importUIRootLauncher(ctx, c, args[2])
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
		} else {
			fmt.Fprintf(c.out, "UI bundle ready: %d exact objects plus ProductOS root launcher; use: 15-plus-kernel-poc ui run\n", len(profile.Files))
		}
		return nil
	}
	return errors.New("usage: ui import DIRECTORY | ui launcher import FILE | ui status | ui run [-- MONKEYBARS-ARG...] | ui capture | ui tap X Y | ui verify [--x X --y Y --settle DURATION]")
}
