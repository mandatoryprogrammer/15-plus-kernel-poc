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
	uiFrameworkTarget    = "/usr/local/lib/iRemoteFramebuffer.framework/iRemoteFramebuffer"
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
	Schema string     `json:"schema"`
	Files  []uiObject `json:"files"`
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
	if err = json.Unmarshal(body, &profile); err != nil || profile.Schema != "15-plus-kernel-poc.ui-profile.v1" || len(profile.Files) != len(uiBundleFiles) {
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

func runUI(ctx context.Context, c *cache, args []string) error {
	profile, err := loadUIProfile(ctx, c)
	if err != nil {
		return err
	}
	executable, err := uiObjectPath(c, profile, uiExecutableRelative)
	if err != nil {
		return err
	}
	framework, err := uiObjectPath(c, profile, uiFrameworkRelative)
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
	runArgs := []string{
		executable, "--dest", uiExecutableTarget,
		"--include", framework + "=" + uiFrameworkTarget,
		"--env", "DYLD_ROOT_PATH=/mnt/iphone/system",
		"--env", "DYLD_FRAMEWORK_PATH=/usr/local/lib",
		"--env", "DYLD_SHARED_CACHE_DIR=/mnt/iphone/system/System/Library/Caches/com.apple.dyld",
		"--",
	}
	runArgs = append(runArgs, programArgs...)
	fmt.Fprintln(c.out, "Launching imported MonkeyBars UI with automatic signing, dependency staging, ProductOS library routing, and live-environment reuse")
	return runPayload(ctx, c, runArgs)
}

func uiCommand(ctx context.Context, c *cache, args []string) error {
	if len(args) == 2 && args[0] == "import" {
		return importUI(ctx, c, args[1])
	}
	if len(args) >= 1 && args[0] == "run" {
		return runUI(ctx, c, args[1:])
	}
	if len(args) == 1 && args[0] == "status" {
		profile, err := loadUIProfile(ctx, c)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.out, "UI bundle ready: %d exact objects; use: 15-plus-kernel-poc ui run\n", len(profile.Files))
		return nil
	}
	return errors.New("usage: ui import DIRECTORY | ui status | ui run [-- MONKEYBARS-ARG...]")
}
