package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	systemOSCryptexBytes  int64 = 1926136882
	systemOSCryptexSHA256       = "6534bd9d9860ea0f4b8dc63431b5d2f73a7d925226b70335f917bd94a1162118"

	systemOSCryptexOwnedDirectory = "/mnt/iphone/preboot/Cryptexes/CodexSystemOS"
	systemOSCryptexOwnerPath      = systemOSCryptexOwnedDirectory + "/.15-plus-kernel-poc-owner"
	systemOSCryptexOwnerMarker    = "15-plus-kernel-poc SystemOS cryptex v1"
	systemOSCryptexTargetImage    = systemOSCryptexOwnedDirectory + "/LuckD23D127.D38SystemCryptex.ulfo.dmg"
	systemOSCryptexPartialImage   = systemOSCryptexTargetImage + ".partial"

	systemOSCryptexPrebootMount = "/mnt/iphone/preboot"
	systemOSCryptexVisibleRoot  = "/mnt/iphone/system/System/Cryptexes/OS"
	// The live Product mount returns the visible path from cd -P/pwd -P even
	// though the sealed image records a relative private/preboot symlink. Bind
	// the mount syscall to the observed namespace instead of inferring an alias.
	systemOSCryptexProductMount = systemOSCryptexVisibleRoot
	systemOSCryptexCacheMain    = systemOSCryptexVisibleRoot + "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e"
	systemOSCryptexCacheBytes   = int64(606208)
	systemOSCryptexCacheSHA256  = "ee74b8950fecf4bb7f52cd244307019a535880cb0b3f340efbfef1dca23a2de7"

	systemOSCryptexRequiredFree = uint64(systemOSCryptexBytes) + (4 << 20)
	systemOSCryptexProgressTick = 4 * time.Second
)

type systemOSCryptexPlan struct {
	Source string
	Bytes  int64
	SHA256 string
}

type systemOSCryptexEvidence struct {
	Source                  string   `json:"source"`
	Bytes                   int64    `json:"bytes"`
	SHA256                  string   `json:"sha256"`
	TargetImage             string   `json:"target_image"`
	ProductMountpoint       string   `json:"product_mountpoint"`
	ProductVisibleRoot      string   `json:"product_visible_root"`
	ProductResolution       string   `json:"product_resolution,omitempty"`
	ProductResolutionExact  bool     `json:"product_resolution_exact"`
	ProductFallbackExact    bool     `json:"product_fallback_exact"`
	PreflightPassed         bool     `json:"preflight_passed"`
	PrebootMountSource      string   `json:"preboot_mount_source,omitempty"`
	PrebootPreimageReadOnly bool     `json:"preboot_preimage_read_only"`
	AvailableBytes          uint64   `json:"available_bytes,omitempty"`
	StagePreimage           string   `json:"stage_preimage,omitempty"`
	StageReused             bool     `json:"stage_reused"`
	StageWriteStarted       bool     `json:"stage_write_started"`
	TransferredBytes        int64    `json:"transferred_bytes,omitempty"`
	TargetImageVerified     bool     `json:"target_image_verified"`
	OwnedDevices            []string `json:"owned_devices,omitempty"`
	MountedDevice           string   `json:"mounted_device,omitempty"`
	MountReadOnly           bool     `json:"mount_read_only"`
	MountNoBrowse           bool     `json:"mount_nobrowse"`
	CacheMainBytes          int64    `json:"cache_main_bytes,omitempty"`
	CacheMainSHA256         string   `json:"cache_main_sha256,omitempty"`
	CacheMainVerified       bool     `json:"cache_main_verified"`
	CleanupUnmounted        bool     `json:"cleanup_unmounted"`
	CleanupDevicesEjected   bool     `json:"cleanup_devices_ejected"`
	CleanupPrebootReadOnly  bool     `json:"cleanup_preboot_read_only"`
	IncompleteStageRemoved  bool     `json:"incomplete_stage_removed"`
	CompleteStageRetained   bool     `json:"complete_stage_retained"`
	CleanupExact            bool     `json:"cleanup_exact"`
}

type systemOSCryptexRuntime struct {
	Plan     systemOSCryptexPlan
	Evidence *systemOSCryptexEvidence
}

type systemOSCryptexContextKey struct{}

func withSystemOSCryptex(ctx context.Context, runtime *systemOSCryptexRuntime) context.Context {
	return context.WithValue(ctx, systemOSCryptexContextKey{}, runtime)
}

func systemOSCryptexFromContext(ctx context.Context) *systemOSCryptexRuntime {
	runtime, _ := ctx.Value(systemOSCryptexContextKey{}).(*systemOSCryptexRuntime)
	return runtime
}

func validateSystemOSCryptexIdentity(size int64, sha string) error {
	if size != systemOSCryptexBytes {
		return fmt.Errorf("SystemOS cryptex bytes=%d, want %d", size, systemOSCryptexBytes)
	}
	if sha != systemOSCryptexSHA256 {
		return fmt.Errorf("SystemOS cryptex sha256=%s, want %s", sha, systemOSCryptexSHA256)
	}
	return nil
}

func hashRegularFileWithProgress(path string, out io.Writer) (int64, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return 0, "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return 0, "", err
	}
	if !info.Mode().IsRegular() {
		return 0, "", errors.New("SystemOS cryptex input must be one regular file, not a symlink")
	}
	file, err := os.Open(abs)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	hasher := sha256.New()
	buffer := make([]byte, 4<<20)
	var total int64
	checkpoint := time.Now().Add(systemOSCryptexProgressTick)
	for {
		count, readErr := file.Read(buffer)
		if count > 0 {
			total += int64(count)
			if _, err = hasher.Write(buffer[:count]); err != nil {
				return 0, "", err
			}
		}
		if out != nil && !time.Now().Before(checkpoint) {
			fmt.Fprintf(out, "SystemOS cryptex host identity progress: %d/%d bytes\n", total, info.Size())
			checkpoint = time.Now().Add(systemOSCryptexProgressTick)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return 0, "", readErr
		}
	}
	if err = file.Close(); err != nil {
		return 0, "", err
	}
	return total, hex.EncodeToString(hasher.Sum(nil)), nil
}

func prepareSystemOSCryptex(path string, out io.Writer) (systemOSCryptexPlan, error) {
	var plan systemOSCryptexPlan
	abs, err := filepath.Abs(path)
	if err != nil {
		return plan, err
	}
	fmt.Fprintf(out, "Validating exact SystemOS cryptex input by streaming SHA-256: %s\n", abs)
	size, sha, err := hashRegularFileWithProgress(abs, out)
	if err != nil {
		return plan, err
	}
	if err = validateSystemOSCryptexIdentity(size, sha); err != nil {
		return plan, err
	}
	plan = systemOSCryptexPlan{Source: abs, Bytes: size, SHA256: sha}
	fmt.Fprintf(out, "Validated exact SystemOS cryptex input: %d bytes sha256=%s\n", size, sha)
	return plan, nil
}

type systemOSMount struct {
	Source  string
	Target  string
	Options map[string]bool
}

func parseSystemOSMountTable(body string) []systemOSMount {
	var mounts []systemOSMount
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r", ""), "\n") {
		at := strings.Index(line, " on ")
		open := strings.LastIndex(line, " (")
		if at <= 0 || open <= at+4 || !strings.HasSuffix(line, ")") {
			continue
		}
		mount := systemOSMount{
			Source:  strings.TrimSpace(line[:at]),
			Target:  strings.TrimSpace(line[at+4 : open]),
			Options: make(map[string]bool),
		}
		for _, option := range strings.Split(line[open+2:len(line)-1], ",") {
			mount.Options[strings.TrimSpace(option)] = true
		}
		mounts = append(mounts, mount)
	}
	return mounts
}

var systemOSDiskSource = regexp.MustCompile(`^/dev/disk[0-9]+(?:s[0-9]+)*$`)
var systemOSBaseDevice = regexp.MustCompile(`^/dev/disk(?:[2-9]|[1-9][0-9]|1[01][0-9]|12[0-7])$`)

func requireSystemOSMount(body, target string, readOnly bool) (systemOSMount, error) {
	var matches []systemOSMount
	for _, mount := range parseSystemOSMountTable(body) {
		if mount.Target == target {
			matches = append(matches, mount)
		}
	}
	if len(matches) != 1 {
		return systemOSMount{}, fmt.Errorf("mountpoint %s has %d mount-table entries", target, len(matches))
	}
	mount := matches[0]
	if !systemOSDiskSource.MatchString(mount.Source) || !mount.Options["apfs"] || !mount.Options["local"] {
		return systemOSMount{}, fmt.Errorf("mountpoint %s has invalid source/options: %+v", target, mount)
	}
	if readOnly && (!mount.Options["read-only"] || !mount.Options["nobrowse"]) {
		return systemOSMount{}, fmt.Errorf("mountpoint %s is not read-only,nobrowse: %+v", target, mount)
	}
	if !readOnly && mount.Options["read-only"] {
		return systemOSMount{}, fmt.Errorf("mountpoint %s remained read-only", target)
	}
	return mount, nil
}

func requireSystemOSMountAbsent(body, target string) error {
	for _, mount := range parseSystemOSMountTable(body) {
		if mount.Target == target {
			return fmt.Errorf("mountpoint %s unexpectedly mounted from %s", target, mount.Source)
		}
	}
	return nil
}

type systemOSPreflight struct {
	Physical        string
	ResolutionExact bool
	FallbackExact   bool
	Stage           string
	Mounts          string
}

func parseKeyValueLine(line, prefix string) (map[string]string, error) {
	if !strings.HasPrefix(line, prefix) {
		return nil, fmt.Errorf("line %q lacks prefix %q", line, prefix)
	}
	result := make(map[string]string)
	for _, field := range strings.Fields(strings.TrimPrefix(line, prefix)) {
		parts := strings.SplitN(field, "=", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || result[parts[0]] != "" {
			return nil, fmt.Errorf("invalid key/value field %q", field)
		}
		result[parts[0]] = parts[1]
	}
	return result, nil
}

func parseSystemOSPreflight(body []byte) (systemOSPreflight, error) {
	var result systemOSPreflight
	normalized := strings.ReplaceAll(string(body), "\r", "")
	const prefix = "SYSTEMOS_CRYPTEX_PREFLIGHT "
	var marker string
	for _, line := range strings.Split(normalized, "\n") {
		if strings.HasPrefix(line, prefix) {
			if marker != "" {
				return result, errors.New("duplicate SystemOS cryptex preflight marker")
			}
			marker = line
		}
	}
	fields, err := parseKeyValueLine(marker, prefix)
	if err != nil {
		return result, err
	}
	result.Physical = fields["physical"]
	result.ResolutionExact = fields["resolution_exact"] == "1"
	if result.Physical != systemOSCryptexProductMount || !result.ResolutionExact {
		return result, fmt.Errorf("Product cryptex path resolved to %q, want %q",
			result.Physical, systemOSCryptexProductMount)
	}
	result.FallbackExact = fields["fallback_exact"] == "1"
	for _, assertion := range []struct {
		field string
		want  string
	}{
		{"fallback_exact", "1"},
		{"target_entries", "1"},
		{"system_entries", "1"},
		{"library_entries", "2"},
		{"framework_entries", "2"},
		{"private_framework_entries", "3"},
		{"cache_main", "0"},
	} {
		if fields[assertion.field] != assertion.want {
			return result, fmt.Errorf("Product cryptex fallback %s=%q, want %q",
				assertion.field, fields[assertion.field], assertion.want)
		}
	}
	switch fields["stage"] {
	case "absent":
		if fields["owner"] != "0" || fields["final"] != "0" || fields["partial"] != "0" || fields["stage_entries"] != "0" {
			return result, fmt.Errorf("absent stage has files: %v", fields)
		}
	case "complete":
		if fields["owner"] != "1" || fields["final"] != "1" || fields["partial"] != "0" || fields["stage_entries"] != "2" {
			return result, fmt.Errorf("complete stage shape changed: %v", fields)
		}
	case "incomplete":
		if fields["owner"] != "1" || fields["final"] != "0" || fields["stage_entries"] != "1" && fields["stage_entries"] != "2" {
			return result, fmt.Errorf("incomplete stage shape changed: %v", fields)
		}
	default:
		return result, fmt.Errorf("unowned or invalid stage state %q", fields["stage"])
	}
	begin := strings.Index(normalized, "SYSTEMOS_MOUNTS_BEGIN\n")
	end := strings.Index(normalized, "SYSTEMOS_MOUNTS_END\n")
	if begin < 0 || end <= begin || strings.Count(normalized, "SYSTEMOS_MOUNTS_BEGIN\n") != 1 || strings.Count(normalized, "SYSTEMOS_MOUNTS_END\n") != 1 {
		return result, errors.New("SystemOS mount-table envelope is missing or duplicated")
	}
	result.Stage = fields["stage"]
	result.Mounts = normalized[begin+len("SYSTEMOS_MOUNTS_BEGIN\n") : end]
	if err = requireSystemOSMountAbsent(result.Mounts, systemOSCryptexProductMount); err != nil {
		return result, err
	}
	return result, nil
}

func systemOSPreflightScript() string {
	return systemOSPreflightScriptFor(systemOSCryptexVisibleRoot,
		systemOSCryptexProductMount, systemOSCryptexCacheMain)
}

func systemOSPreflightScriptFor(visibleRoot, productMount, cacheMain string) string {
	return "set -u; " +
		"physical=unavailable; resolution_exact=0; fallback_exact=0; target_entry_count=-1; system_entry_count=-1; library_entry_count=-1; framework_entry_count=-1; private_framework_entry_count=-1; cache_main=-1; shopt -s nullglob dotglob; " +
		"if resolved=$(cd -P " + shellQuote(visibleRoot) + " 2>/dev/null && pwd -P); then " +
		"physical=$resolved; target_entries=(" + shellQuote(visibleRoot) + "/*); target_entry_count=${#target_entries[@]}; " +
		"system_entries=(" + shellQuote(visibleRoot+"/System") + "/*); system_entry_count=${#system_entries[@]}; " +
		"library_entries=(" + shellQuote(visibleRoot+"/System/Library") + "/*); library_entry_count=${#library_entries[@]}; " +
		"framework_entries=(" + shellQuote(visibleRoot+"/System/Library/Frameworks") + "/*); framework_entry_count=${#framework_entries[@]}; " +
		"private_framework_entries=(" + shellQuote(visibleRoot+"/System/Library/PrivateFrameworks") + "/*); private_framework_entry_count=${#private_framework_entries[@]}; " +
		"cache_main=0; if test -e " + shellQuote(cacheMain) + " || test -L " + shellQuote(cacheMain) + "; then cache_main=1; fi; " +
		"test \"$physical\" = " + shellQuote(productMount) + " && resolution_exact=1 || true; " +
		"if test $resolution_exact -eq 1 && test $target_entry_count -eq 1 && test $system_entry_count -eq 1 && test $library_entry_count -eq 2 && test $framework_entry_count -eq 2 && test $private_framework_entry_count -eq 3 && test $cache_main -eq 0 && " +
		"test -d " + shellQuote(visibleRoot+"/System") + " && test ! -L " + shellQuote(visibleRoot+"/System") + " && " +
		"test -d " + shellQuote(visibleRoot+"/System/Library") + " && test ! -L " + shellQuote(visibleRoot+"/System/Library") + " && " +
		"test -d " + shellQuote(visibleRoot+"/System/Library/Frameworks") + " && test ! -L " + shellQuote(visibleRoot+"/System/Library/Frameworks") + " && " +
		"test -d " + shellQuote(visibleRoot+"/System/Library/PrivateFrameworks") + " && test ! -L " + shellQuote(visibleRoot+"/System/Library/PrivateFrameworks") + " && " +
		"test -d " + shellQuote(visibleRoot+"/System/Library/Frameworks/JavaScriptCore.framework") + " && test ! -L " + shellQuote(visibleRoot+"/System/Library/Frameworks/JavaScriptCore.framework") + " && " +
		"test -d " + shellQuote(visibleRoot+"/System/Library/Frameworks/WebKit.framework") + " && test ! -L " + shellQuote(visibleRoot+"/System/Library/Frameworks/WebKit.framework") + " && " +
		"test -d " + shellQuote(visibleRoot+"/System/Library/PrivateFrameworks/WebCore.framework") + " && test ! -L " + shellQuote(visibleRoot+"/System/Library/PrivateFrameworks/WebCore.framework") + " && " +
		"test -d " + shellQuote(visibleRoot+"/System/Library/PrivateFrameworks/WebInspector.framework") + " && test ! -L " + shellQuote(visibleRoot+"/System/Library/PrivateFrameworks/WebInspector.framework") + " && " +
		"test -d " + shellQuote(visibleRoot+"/System/Library/PrivateFrameworks/WebKitLegacy.framework") + " && test ! -L " + shellQuote(visibleRoot+"/System/Library/PrivateFrameworks/WebKitLegacy.framework") + "; then fallback_exact=1; fi; fi; " +
		"stage=absent; owner=0; final=0; partial=0; stage_entries=0; " +
		"if test -e " + shellQuote(systemOSCryptexOwnedDirectory) + "; then if test -d " + shellQuote(systemOSCryptexOwnedDirectory) + "; then " +
		"stage_files=(" + shellQuote(systemOSCryptexOwnedDirectory) + "/*); stage_entries=${#stage_files[@]}; " +
		"test -f " + shellQuote(systemOSCryptexOwnerPath) + " && test \"$(<" + shellQuote(systemOSCryptexOwnerPath) + ")\" = " + shellQuote(systemOSCryptexOwnerMarker) + " && owner=1; " +
		"test -f " + shellQuote(systemOSCryptexTargetImage) + " && final=1; test -f " + shellQuote(systemOSCryptexPartialImage) + " && partial=1; " +
		"valid=1; for entry in \"${stage_files[@]}\"; do case \"$entry\" in " +
		shellQuote(systemOSCryptexOwnerPath) + "|" + shellQuote(systemOSCryptexTargetImage) + "|" + shellQuote(systemOSCryptexPartialImage) + ") ;; *) valid=0 ;; esac; done; " +
		"if test $valid -eq 1 && test $owner -eq 1 && test $final -eq 1 && test $partial -eq 0; then stage=complete; " +
		"elif test $valid -eq 1 && test $owner -eq 1 && test $final -eq 0; then stage=incomplete; else stage=invalid; fi; else stage=invalid; fi; fi; " +
		"printf 'SYSTEMOS_CRYPTEX_PREFLIGHT physical=%s resolution_exact=%d fallback_exact=%d target_entries=%d system_entries=%d library_entries=%d framework_entries=%d private_framework_entries=%d cache_main=%d stage=%s owner=%d final=%d partial=%d stage_entries=%d\\n' \"$physical\" \"$resolution_exact\" \"$fallback_exact\" \"$target_entry_count\" \"$system_entry_count\" \"$library_entry_count\" \"$framework_entry_count\" \"$private_framework_entry_count\" \"$cache_main\" \"$stage\" \"$owner\" \"$final\" \"$partial\" \"$stage_entries\"; " +
		"printf 'SYSTEMOS_MOUNTS_BEGIN\\n'; /sbin/mount || true; printf 'SYSTEMOS_MOUNTS_END\\n'"
}

type systemOSVerifierResult struct {
	Mode      string
	Path      string
	Bytes     int64
	SHA256    string
	Available uint64
	Source    string
}

func parseSystemOSVerifier(body []byte, mode string) (systemOSVerifierResult, error) {
	var result systemOSVerifierResult
	prefix := "SYSTEMOS_CRYPTEX_FILE "
	if mode == "space" {
		prefix = "SYSTEMOS_CRYPTEX_SPACE "
	} else if mode == "unmount" {
		prefix = "SYSTEMOS_CRYPTEX_UNMOUNT "
	}
	var marker string
	for _, line := range strings.Split(strings.ReplaceAll(string(body), "\r", ""), "\n") {
		if strings.HasPrefix(line, prefix) {
			if marker != "" {
				return result, fmt.Errorf("duplicate %s marker", mode)
			}
			marker = line
		}
	}
	fields, err := parseKeyValueLine(marker, prefix)
	if err != nil {
		return result, err
	}
	if fields["exact"] != "1" {
		return result, fmt.Errorf("target verifier did not report exact success: %v", fields)
	}
	result.Mode, result.Path, result.SHA256, result.Source = fields["mode"], fields["path"], fields["sha256"], fields["source"]
	switch mode {
	case "space":
		if result.Path != systemOSCryptexPrebootMount || fields["readonly"] != "1" || fields["fstype"] != "apfs" || fields["required"] != strconv.FormatUint(systemOSCryptexRequiredFree, 10) || !systemOSDiskSource.MatchString(result.Source) {
			return result, fmt.Errorf("target space contract changed: %v", fields)
		}
		result.Available, err = strconv.ParseUint(fields["available"], 10, 64)
		if err != nil || result.Available < systemOSCryptexRequiredFree {
			return result, fmt.Errorf("target Preboot capacity is insufficient: %q", fields["available"])
		}
	case "read", "commit":
		if result.Mode != mode || fields["fsync"] != map[bool]string{true: "1", false: "0"}[mode == "commit"] {
			return result, fmt.Errorf("target file verifier mode changed: %v", fields)
		}
		result.Bytes, err = strconv.ParseInt(fields["bytes"], 10, 64)
		if err != nil {
			return result, err
		}
		if result.Path == systemOSCryptexCacheMain {
			if mode != "read" || result.Bytes != systemOSCryptexCacheBytes || result.SHA256 != systemOSCryptexCacheSHA256 {
				return result, fmt.Errorf("target cache identity changed: %v", fields)
			}
		} else if (result.Path != systemOSCryptexTargetImage && result.Path != systemOSCryptexPartialImage) || result.Bytes != systemOSCryptexBytes || result.SHA256 != systemOSCryptexSHA256 {
			return result, fmt.Errorf("target cryptex identity changed: %v", fields)
		}
	case "unmount":
		if result.Path != systemOSCryptexProductMount || fields["status"] != "0" || fields["absent"] != "1" || !systemOSDiskSource.MatchString(result.Source) {
			return result, fmt.Errorf("target unmount contract changed: %v", fields)
		}
	default:
		return result, fmt.Errorf("unsupported verifier mode %q", mode)
	}
	return result, nil
}

func runSystemOSObservedSSH(ctx context.Context, c *cache, access sshAccess,
	phase string, command []string, stdin io.Reader, stdout, stderr io.Writer) error {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(systemOSCryptexProgressTick)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				fmt.Fprintf(c.out, "SystemOS cryptex checkpoint: phase=%s still-running=1\n", phase)
			}
		}
	}()
	err := runSSH(ctx, access, false, command, stdin, stdout, stderr)
	close(done)
	<-stopped
	return err
}

func runSystemOSCapture(ctx context.Context, c *cache, access sshAccess,
	phase string, command []string) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	deadline, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	err := runSystemOSObservedSSH(deadline, c, access, phase, command, nil,
		&stdout, &stderr)
	if stdout.Len() > 0 {
		_, _ = c.out.Write(stdout.Bytes())
	}
	if stderr.Len() > 0 {
		_, _ = c.out.Write(stderr.Bytes())
	}
	return stdout.Bytes(), stderr.Bytes(), err
}

func runSystemOSVerifier(ctx context.Context, c *cache, access sshAccess,
	mode string, arguments ...string) (systemOSVerifierResult, error) {
	command := []string{targetPayloadRunner, "--systemos-cryptex-file-v1", mode}
	command = append(command, arguments...)
	stdout, stderr, err := runSystemOSCapture(ctx, c, access, "target-verifier-"+mode, command)
	if err != nil {
		return systemOSVerifierResult{}, fmt.Errorf("target SystemOS %s verifier: %w: %s", mode, err, stderr)
	}
	result, err := parseSystemOSVerifier(stdout, mode)
	if err != nil {
		return result, fmt.Errorf("parse target SystemOS %s verifier: %w", mode, err)
	}
	return result, nil
}

type systemOSStreamingReader struct {
	file  *os.File
	hash  hash.Hash
	bytes atomic.Int64
}

func (reader *systemOSStreamingReader) Read(body []byte) (int, error) {
	count, err := reader.file.Read(body)
	if count > 0 {
		_, _ = reader.hash.Write(body[:count])
		reader.bytes.Add(int64(count))
	}
	return count, err
}

func streamSystemOSCryptex(ctx context.Context, c *cache, access sshAccess,
	plan systemOSCryptexPlan) (int64, string, error) {
	file, err := os.Open(plan.Source)
	if err != nil {
		return 0, "", err
	}
	reader := &systemOSStreamingReader{file: file, hash: sha256.New()}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(systemOSCryptexProgressTick)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				fmt.Fprintf(c.out, "SystemOS cryptex transfer progress: %d/%d bytes\n", reader.bytes.Load(), plan.Bytes)
			}
		}
	}()
	uploadCtx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	script := "set -eu -o noclobber; /bin/cat > " + shellQuote(systemOSCryptexPartialImage)
	var stderr bytes.Buffer
	err = runSSH(uploadCtx, access, false, []string{"/bin/bash", "-c", script}, reader, io.Discard, &stderr)
	cancel()
	close(done)
	<-stopped
	if stderr.Len() > 0 {
		_, _ = c.out.Write(stderr.Bytes())
	}
	closeErr := file.Close()
	if err != nil {
		return reader.bytes.Load(), "", err
	}
	if closeErr != nil {
		return reader.bytes.Load(), "", closeErr
	}
	sha := hex.EncodeToString(reader.hash.Sum(nil))
	if err = validateSystemOSCryptexIdentity(reader.bytes.Load(), sha); err != nil {
		return reader.bytes.Load(), sha, fmt.Errorf("streamed SystemOS cryptex changed: %w", err)
	}
	return reader.bytes.Load(), sha, nil
}

func systemOSDeviceInventoryCommand() []string {
	script := "for number in {2..127}; do test -e /dev/disk$number && printf '/dev/disk%d\\n' $number || true; done"
	return []string{"/bin/bash", "-c", script}
}

func parseSystemOSDeviceInventory(body []byte) (map[string]bool, error) {
	result := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(strings.ReplaceAll(string(body), "\r", "")), "\n") {
		if line == "" {
			continue
		}
		if !systemOSBaseDevice.MatchString(line) || result[line] {
			return nil, fmt.Errorf("invalid or duplicate device inventory line %q", line)
		}
		result[line] = true
	}
	return result, nil
}

var systemOSHDIKDeviceLine = regexp.MustCompile(`(?m)^(/dev/disk([0-9]+)(?:s[0-9]+)*)\b`)

func parseSystemOSHDIKOutput(body []byte, preimage map[string]bool) (ownedBases, candidates []string, err error) {
	baseSet, candidateSet := make(map[string]bool), make(map[string]bool)
	for _, match := range systemOSHDIKDeviceLine.FindAllSubmatch(body, -1) {
		path := string(match[1])
		base := "/dev/disk" + string(match[2])
		if preimage[base] {
			return nil, nil, fmt.Errorf("hdik returned pre-existing device %s", base)
		}
		baseSet[base] = true
		if path != base {
			candidateSet[path] = true
		}
	}
	if len(baseSet) != 1 {
		return nil, nil, fmt.Errorf("hdik returned %d newly owned base devices", len(baseSet))
	}
	for base := range baseSet {
		ownedBases = append(ownedBases, base)
		if len(candidateSet) == 0 {
			candidateSet[base] = true
		}
	}
	for candidate := range candidateSet {
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if len(candidates[i]) == len(candidates[j]) {
			return candidates[i] < candidates[j]
		}
		return len(candidates[i]) > len(candidates[j])
	})
	return ownedBases, candidates, nil
}

func detectedSystemOSHDIKBases(body []byte, preimage map[string]bool) []string {
	set := make(map[string]bool)
	for _, match := range systemOSHDIKDeviceLine.FindAllSubmatch(body, -1) {
		base := "/dev/disk" + string(match[2])
		if !preimage[base] {
			set[base] = true
		}
	}
	var result []string
	for base := range set {
		result = append(result, base)
	}
	sort.Strings(result)
	return result
}

type systemOSCryptexSession struct {
	ctx              context.Context
	c                *cache
	access           sshAccess
	runtime          *systemOSCryptexRuntime
	prebootSource    string
	prebootWritable  bool
	stagingMayExist  bool
	stageComplete    bool
	mounted          bool
	ownedBases       []string
	mountedDevice    string
	cleanupAttempted bool
}

func (session *systemOSCryptexSession) mountTable() (string, error) {
	stdout, stderr, err := runSystemOSCapture(session.ctx, session.c, session.access,
		"mount-table", []string{"/sbin/mount"})
	if err != nil {
		return "", fmt.Errorf("read target mount table: %w: %s", err, stderr)
	}
	return string(stdout), nil
}

func (session *systemOSCryptexSession) remountPreboot(readOnly bool) error {
	option := "-uw"
	phase := "preboot-remount-rw"
	if readOnly {
		option, phase = "-ur", "preboot-remount-ro"
	}
	_, stderr, err := runSystemOSCapture(session.ctx, session.c, session.access,
		phase, []string{"/sbin/mount", option, systemOSCryptexPrebootMount})
	if err != nil {
		return fmt.Errorf("%s: %w: %s", phase, err, stderr)
	}
	mounts, err := session.mountTable()
	if err != nil {
		return err
	}
	mount, err := requireSystemOSMount(mounts, systemOSCryptexPrebootMount, readOnly)
	if err != nil {
		return err
	}
	if session.prebootSource != "" && mount.Source != session.prebootSource {
		return fmt.Errorf("Preboot source changed from %s to %s", session.prebootSource, mount.Source)
	}
	session.prebootWritable = !readOnly
	session.runtime.Evidence.CleanupPrebootReadOnly = readOnly
	return nil
}

func systemOSIncompleteCleanupScript() string {
	return "set -eu; if test -d " + shellQuote(systemOSCryptexOwnedDirectory) +
		" && test -f " + shellQuote(systemOSCryptexOwnerPath) +
		" && test \"$(<" + shellQuote(systemOSCryptexOwnerPath) + ")\" = " + shellQuote(systemOSCryptexOwnerMarker) +
		"; then /bin/rm -f " + shellQuote(systemOSCryptexPartialImage) + " " +
		shellQuote(systemOSCryptexTargetImage) + " " + shellQuote(systemOSCryptexOwnerPath) +
		"; /bin/rmdir " + shellQuote(systemOSCryptexOwnedDirectory) + "; fi; test ! -e " +
		shellQuote(systemOSCryptexOwnedDirectory)
}

func (session *systemOSCryptexSession) removeIncompleteStage() error {
	if !session.prebootWritable {
		if err := session.remountPreboot(false); err != nil {
			return err
		}
	}
	_, stderr, err := runSystemOSCapture(session.ctx, session.c, session.access,
		"remove-incomplete-stage", []string{"/bin/bash", "-c", systemOSIncompleteCleanupScript()})
	if err != nil {
		return fmt.Errorf("remove incomplete SystemOS stage: %w: %s", err, stderr)
	}
	session.stagingMayExist = false
	session.runtime.Evidence.IncompleteStageRemoved = true
	return nil
}

func (session *systemOSCryptexSession) createAndStreamStage() error {
	if err := session.remountPreboot(false); err != nil {
		return err
	}
	session.runtime.Evidence.StageWriteStarted = true
	session.stagingMayExist = true
	script := "set -eu; test ! -e " + shellQuote(systemOSCryptexOwnedDirectory) +
		"; test -d /mnt/iphone/preboot/Cryptexes; /bin/mkdir " + shellQuote(systemOSCryptexOwnedDirectory) +
		"; printf '%s' " + shellQuote(systemOSCryptexOwnerMarker) + " > " + shellQuote(systemOSCryptexOwnerPath) +
		"; test \"$(<" + shellQuote(systemOSCryptexOwnerPath) + ")\" = " + shellQuote(systemOSCryptexOwnerMarker)
	_, stderr, err := runSystemOSCapture(session.ctx, session.c, session.access,
		"create-owned-stage", []string{"/bin/bash", "-c", script})
	if err != nil {
		return fmt.Errorf("create owned SystemOS stage: %w: %s", err, stderr)
	}
	fmt.Fprintf(session.c.out, "Streaming exact SystemOS cryptex to owned target partial file (%d bytes)\n", session.runtime.Plan.Bytes)
	bytesSent, _, err := streamSystemOSCryptex(session.ctx, session.c, session.access, session.runtime.Plan)
	session.runtime.Evidence.TransferredBytes = bytesSent
	if err != nil {
		return fmt.Errorf("stream SystemOS cryptex: %w", err)
	}
	if _, err = runSystemOSVerifier(session.ctx, session.c, session.access, "commit", systemOSCryptexPartialImage); err != nil {
		return err
	}
	_, stderr, err = runSystemOSCapture(session.ctx, session.c, session.access,
		"commit-stage-name", []string{"/bin/mv", systemOSCryptexPartialImage, systemOSCryptexTargetImage})
	if err != nil {
		return fmt.Errorf("commit SystemOS stage name: %w: %s", err, stderr)
	}
	if _, err = runSystemOSVerifier(session.ctx, session.c, session.access, "commit", systemOSCryptexTargetImage); err != nil {
		return err
	}
	session.stageComplete = true
	session.stagingMayExist = false
	session.runtime.Evidence.TargetImageVerified = true
	session.runtime.Evidence.CompleteStageRetained = true
	return session.remountPreboot(true)
}

func (session *systemOSCryptexSession) attachAndMount() error {
	preBody, stderr, err := runSystemOSCapture(session.ctx, session.c, session.access,
		"device-preimage", systemOSDeviceInventoryCommand())
	if err != nil {
		return fmt.Errorf("read device preimage: %w: %s", err, stderr)
	}
	preimage, err := parseSystemOSDeviceInventory(preBody)
	if err != nil {
		return err
	}
	stdout, stderr, err := runSystemOSCapture(session.ctx, session.c, session.access,
		"hdik-attach", []string{"/usr/sbin/hdik", "-nomount", systemOSCryptexTargetImage})
	attachErr := err
	combined := append(append([]byte(nil), stdout...), stderr...)
	detected := detectedSystemOSHDIKBases(combined, preimage)
	postBody, postStderr, postErr := runSystemOSCapture(session.ctx, session.c, session.access,
		"device-postimage", systemOSDeviceInventoryCommand())
	var newlyPresent []string
	if postErr == nil {
		postimage, parseErr := parseSystemOSDeviceInventory(postBody)
		if parseErr != nil {
			postErr = parseErr
		} else {
			for device := range postimage {
				if !preimage[device] {
					newlyPresent = append(newlyPresent, device)
				}
			}
		}
	}
	sort.Strings(newlyPresent)
	ownedSet := make(map[string]bool)
	for _, device := range detected {
		ownedSet[device] = true
	}
	for _, device := range newlyPresent {
		ownedSet[device] = true
	}
	for device := range ownedSet {
		session.ownedBases = append(session.ownedBases, device)
	}
	sort.Strings(session.ownedBases)
	session.runtime.Evidence.OwnedDevices = append([]string(nil), session.ownedBases...)
	if postErr != nil {
		return fmt.Errorf("read device postimage: %w: %s", postErr, postStderr)
	}
	if attachErr != nil {
		return fmt.Errorf("attach SystemOS cryptex: %w: %s", attachErr, stderr)
	}
	parsedOwned, candidates, parseErr := parseSystemOSHDIKOutput(combined, preimage)
	if parseErr != nil {
		return parseErr
	}
	if len(newlyPresent) != len(parsedOwned) || len(parsedOwned) != 1 ||
		newlyPresent[0] != parsedOwned[0] || len(session.ownedBases) != 1 ||
		session.ownedBases[0] != parsedOwned[0] {
		return fmt.Errorf("hdik device postimage=%v, parsed=%v, cleanup-owned=%v",
			newlyPresent, parsedOwned, session.ownedBases)
	}
	var failures []string
	for _, candidate := range candidates {
		_, mountStderr, mountErr := runSystemOSCapture(session.ctx, session.c, session.access,
			"mount-systemos", []string{"/sbin/mount_apfs", "-o", "rdonly,nobrowse", candidate, systemOSCryptexProductMount})
		if mountErr != nil {
			failures = append(failures, candidate+": "+strings.TrimSpace(string(mountStderr)))
			continue
		}
		session.mounted = true
		session.mountedDevice = candidate
		mounts, tableErr := session.mountTable()
		if tableErr != nil {
			return tableErr
		}
		mount, tableErr := requireSystemOSMount(mounts, systemOSCryptexProductMount, true)
		if tableErr != nil || mount.Source != candidate {
			return fmt.Errorf("SystemOS mount postimage source=%q candidate=%q: %w", mount.Source, candidate, tableErr)
		}
		cache, verifyErr := runSystemOSVerifier(session.ctx, session.c, session.access, "read", systemOSCryptexCacheMain)
		if verifyErr != nil {
			return verifyErr
		}
		session.runtime.Evidence.MountedDevice = candidate
		session.runtime.Evidence.MountReadOnly = mount.Options["read-only"]
		session.runtime.Evidence.MountNoBrowse = mount.Options["nobrowse"]
		session.runtime.Evidence.CacheMainBytes = cache.Bytes
		session.runtime.Evidence.CacheMainSHA256 = cache.SHA256
		session.runtime.Evidence.CacheMainVerified = true
		return nil
	}
	return fmt.Errorf("no hdik-returned SystemOS device mounted as APFS: %s", strings.Join(failures, "; "))
}

func (session *systemOSCryptexSession) waitOwnedDevicesAbsent() error {
	for attempt := 0; attempt < 20; attempt++ {
		body, stderr, err := runSystemOSCapture(session.ctx, session.c, session.access,
			"device-cleanup-readback", systemOSDeviceInventoryCommand())
		if err != nil {
			return fmt.Errorf("read device cleanup postimage: %w: %s", err, stderr)
		}
		inventory, err := parseSystemOSDeviceInventory(body)
		if err != nil {
			return err
		}
		remaining := ""
		for _, device := range session.ownedBases {
			if inventory[device] {
				remaining = device
				break
			}
		}
		if remaining == "" {
			return nil
		}
		fmt.Fprintf(session.c.out,
			"SystemOS cryptex cleanup checkpoint: attempt=%d remaining=%s\n",
			attempt+1, remaining)
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-session.ctx.Done():
			timer.Stop()
			return session.ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("owned devices remain after eject: %v", session.ownedBases)
}

func (session *systemOSCryptexSession) cleanup() (cleanupErr error) {
	if session.cleanupAttempted {
		return nil
	}
	session.cleanupAttempted = true
	if session.mounted {
		if _, err := runSystemOSVerifier(session.ctx, session.c, session.access, "unmount"); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		} else {
			session.mounted = false
			session.runtime.Evidence.CleanupUnmounted = true
		}
	}
	allEjected := len(session.ownedBases) > 0
	for _, device := range session.ownedBases {
		_, stderr, err := runSystemOSCapture(session.ctx, session.c, session.access,
			"hdik-eject", []string{"/usr/sbin/hdik", "-e", device})
		if err != nil {
			allEjected = false
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("eject %s: %w: %s", device, err, stderr))
		}
	}
	if len(session.ownedBases) > 0 {
		if err := session.waitOwnedDevicesAbsent(); err != nil {
			allEjected = false
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	session.runtime.Evidence.CleanupDevicesEjected = allEjected
	if !session.stageComplete && session.stagingMayExist {
		if err := session.removeIncompleteStage(); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if session.prebootWritable {
		if err := session.remountPreboot(true); err != nil {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	if mounts, err := session.mountTable(); err != nil {
		cleanupErr = errors.Join(cleanupErr, err)
	} else {
		if preboot, prebootErr := requireSystemOSMount(mounts,
			systemOSCryptexPrebootMount, true); prebootErr != nil {
			cleanupErr = errors.Join(cleanupErr, prebootErr)
		} else {
			session.runtime.Evidence.CleanupPrebootReadOnly = true
			if session.prebootSource == "" {
				session.prebootSource = preboot.Source
				session.runtime.Evidence.PrebootMountSource = preboot.Source
				session.runtime.Evidence.PrebootPreimageReadOnly = true
			}
		}
		if absentErr := requireSystemOSMountAbsent(mounts,
			systemOSCryptexProductMount); absentErr != nil {
			cleanupErr = errors.Join(cleanupErr, absentErr)
		}
	}
	session.runtime.Evidence.CleanupExact = cleanupErr == nil &&
		(!session.runtime.Evidence.MountReadOnly || session.runtime.Evidence.CleanupUnmounted) &&
		(len(session.ownedBases) == 0 || session.runtime.Evidence.CleanupDevicesEjected) &&
		!session.prebootWritable && session.runtime.Evidence.CleanupPrebootReadOnly
	return cleanupErr
}

func stageAndMountSystemOSCryptex(ctx context.Context, c *cache, access sshAccess,
	runtime *systemOSCryptexRuntime) (cleanup func() error, runErr error) {
	session := &systemOSCryptexSession{ctx: ctx, c: c, access: access, runtime: runtime}
	defer func() {
		if runErr != nil {
			runErr = errors.Join(runErr, session.cleanup())
		}
	}()
	stdout, stderr, err := runSystemOSCapture(ctx, c, access, "preflight",
		[]string{"/bin/bash", "-c", systemOSPreflightScript()})
	if err != nil {
		return nil, fmt.Errorf("SystemOS cryptex preflight: %w: %s", err, stderr)
	}
	preflight, err := parseSystemOSPreflight(stdout)
	runtime.Evidence.ProductResolution = preflight.Physical
	runtime.Evidence.ProductResolutionExact = preflight.ResolutionExact
	runtime.Evidence.ProductFallbackExact = preflight.FallbackExact
	if err != nil {
		return nil, err
	}
	runtime.Evidence.PreflightPassed = true
	preboot, err := requireSystemOSMount(preflight.Mounts, systemOSCryptexPrebootMount, true)
	if err != nil {
		return nil, err
	}
	session.prebootSource = preboot.Source
	runtime.Evidence.PrebootMountSource = preboot.Source
	runtime.Evidence.PrebootPreimageReadOnly = true
	runtime.Evidence.CleanupPrebootReadOnly = true
	runtime.Evidence.StagePreimage = preflight.Stage
	switch preflight.Stage {
	case "incomplete":
		session.stagingMayExist = true
		if err = session.removeIncompleteStage(); err != nil {
			return nil, err
		}
		if err = session.remountPreboot(true); err != nil {
			return nil, err
		}
		fallthrough
	case "absent":
		space, spaceErr := runSystemOSVerifier(ctx, c, access, "space")
		if spaceErr != nil {
			return nil, spaceErr
		}
		if space.Source != preboot.Source {
			return nil, fmt.Errorf("target statfs source=%s, mount table source=%s", space.Source, preboot.Source)
		}
		runtime.Evidence.AvailableBytes = space.Available
		if err = session.createAndStreamStage(); err != nil {
			return nil, err
		}
	case "complete":
		if _, err = runSystemOSVerifier(ctx, c, access, "read", systemOSCryptexTargetImage); err != nil {
			return nil, err
		}
		session.stageComplete = true
		runtime.Evidence.StageReused = true
		runtime.Evidence.TargetImageVerified = true
		runtime.Evidence.CompleteStageRetained = true
	}
	if err = session.attachAndMount(); err != nil {
		return nil, err
	}
	fmt.Fprintf(c.out, "SystemOS cryptex mounted exactly: %s from %s (read-only,nobrowse); cache sha256=%s\n",
		systemOSCryptexProductMount, session.mountedDevice, systemOSCryptexCacheSHA256)
	return session.cleanup, nil
}
