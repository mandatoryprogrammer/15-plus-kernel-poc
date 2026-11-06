package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func systemOSMountFixture(productMounted bool) string {
	body := "/dev/disk3s3 on /mnt/iphone/preboot (apfs, local, read-only, journaled, nobrowse)\n" +
		"/dev/disk3s1s1 on /mnt/iphone/system (apfs, sealed, local, read-only, journaled, nobrowse)\n"
	if productMounted {
		body += "/dev/disk12s1 on " + systemOSCryptexProductMount + " (apfs, local, read-only, journaled, nobrowse)\n"
	}
	return body
}

func systemOSPreflightFixture(stage string) []byte {
	owner, final, partial, entries := "0", "0", "0", "0"
	switch stage {
	case "complete":
		owner, final, entries = "1", "1", "2"
	case "incomplete":
		owner, partial, entries = "1", "1", "2"
	}
	return []byte("SYSTEMOS_CRYPTEX_PREFLIGHT physical=" + systemOSCryptexProductMount +
		" resolution_exact=1 fallback_exact=1 target_entries=1 system_entries=1 library_entries=2" +
		" framework_entries=2 private_framework_entries=3 cache_main=0 stage=" + stage + " owner=" + owner + " final=" + final +
		" partial=" + partial + " stage_entries=" + entries + "\nSYSTEMOS_MOUNTS_BEGIN\n" +
		systemOSMountFixture(false) + "SYSTEMOS_MOUNTS_END\n")
}

func TestSystemOSCryptexExactIdentityIsSeparateFromPortableHashing(t *testing.T) {
	if err := validateSystemOSCryptexIdentity(systemOSCryptexBytes, systemOSCryptexSHA256); err != nil {
		t.Fatal(err)
	}
	if err := validateSystemOSCryptexIdentity(systemOSCryptexBytes-1, systemOSCryptexSHA256); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("size mutation did not reach exact size assertion: %v", err)
	}
	mutated := "0" + systemOSCryptexSHA256[1:]
	if err := validateSystemOSCryptexIdentity(systemOSCryptexBytes, mutated); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("hash mutation did not reach exact hash assertion: %v", err)
	}

	path := filepath.Join(t.TempDir(), "portable-fixture")
	body := []byte("portable SystemOS streaming fixture\n")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	bytesRead, hash, err := hashRegularFileWithProgress(path, nil)
	wantHash := sha256.Sum256(body)
	if err != nil || bytesRead != int64(len(body)) || hash != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("portable streaming hash bytes=%d hash=%s err=%v", bytesRead, hash, err)
	}
	symlink := filepath.Join(t.TempDir(), "symlink")
	if err = os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, _, err = hashRegularFileWithProgress(symlink, nil); err == nil || !strings.Contains(err.Error(), "not a symlink") {
		t.Fatalf("symlink input was not rejected at file-shape assertion: %v", err)
	}
	if systemOSCryptexProgressTick > 5*time.Second {
		t.Fatalf("progress interval=%s exceeds five-second observability bound", systemOSCryptexProgressTick)
	}
}

func TestSystemOSCryptexMountTableContract(t *testing.T) {
	mount, err := requireSystemOSMount(systemOSMountFixture(false), systemOSCryptexPrebootMount, true)
	if err != nil || mount.Source != "/dev/disk3s3" || !mount.Options["nobrowse"] {
		t.Fatalf("Preboot mount parse=%+v err=%v", mount, err)
	}
	mount, err = requireSystemOSMount(systemOSMountFixture(true), systemOSCryptexProductMount, true)
	if err != nil || mount.Source != "/dev/disk12s1" {
		t.Fatalf("SystemOS mount parse=%+v err=%v", mount, err)
	}
	mutations := []struct {
		name string
		body string
		want string
	}{
		{"duplicate", systemOSMountFixture(false) + "/dev/disk4s3 on /mnt/iphone/preboot (apfs, local, read-only, nobrowse)\n", "2 mount-table"},
		{"source", strings.Replace(systemOSMountFixture(false), "/dev/disk3s3", "not-a-device", 1), "invalid source"},
		{"filesystem", strings.Replace(systemOSMountFixture(false), "(apfs,", "(hfs,", 1), "invalid source"},
		{"writable", strings.Replace(systemOSMountFixture(false), "read-only, ", "", 1), "not read-only"},
		{"browse", strings.Replace(systemOSMountFixture(false), "nobrowse", "browse", 1), "not read-only"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			_, err := requireSystemOSMount(mutation.body, systemOSCryptexPrebootMount, true)
			if err == nil || !strings.Contains(err.Error(), mutation.want) {
				t.Fatalf("site-specific mount mutation err=%v, want %q", err, mutation.want)
			}
		})
	}
}

func TestSystemOSCryptexPreflightBindsProductResolutionAndOwnedStage(t *testing.T) {
	for _, stage := range []string{"absent", "incomplete", "complete"} {
		preflight, err := parseSystemOSPreflight(systemOSPreflightFixture(stage))
		if err != nil || preflight.Stage != stage {
			t.Fatalf("stage=%s parsed=%+v err=%v", stage, preflight, err)
		}
	}
	mutations := []struct {
		name, old, new, want string
	}{
		{"physical namespace", systemOSCryptexProductMount, systemOSCryptexPrebootMount + "/Cryptexes/OS", "resolved to"},
		{"resolution assertion", "resolution_exact=1", "resolution_exact=0", "resolved to"},
		{"fallback assertion", "fallback_exact=1", "fallback_exact=0", "fallback fallback_exact"},
		{"top-level fallback", "target_entries=1", "target_entries=2", "fallback target_entries"},
		{"System fallback", "system_entries=1", "system_entries=2", "fallback system_entries"},
		{"Library fallback", "library_entries=2", "library_entries=3", "fallback library_entries"},
		{"Frameworks fallback", "framework_entries=2", "framework_entries=3", "fallback framework_entries"},
		{"PrivateFrameworks fallback", "private_framework_entries=3", "private_framework_entries=4", "fallback private_framework_entries"},
		{"cache absent", "cache_main=0", "cache_main=1", "fallback cache_main"},
		{"owner", "stage=complete owner=1", "stage=complete owner=0", "complete stage"},
		{"partial", "final=1 partial=0", "final=1 partial=1", "complete stage"},
		{"unowned", "stage=complete", "stage=invalid", "invalid stage"},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			body := strings.Replace(string(systemOSPreflightFixture("complete")), mutation.old, mutation.new, 1)
			_, err := parseSystemOSPreflight([]byte(body))
			if err == nil || !strings.Contains(err.Error(), mutation.want) {
				t.Fatalf("site-specific preflight mutation err=%v, want %q", err, mutation.want)
			}
		})
	}
	unresolvedBody := string(systemOSPreflightFixture("absent"))
	unresolvedBody = strings.Replace(unresolvedBody,
		"physical="+systemOSCryptexProductMount+" resolution_exact=1 fallback_exact=1 target_entries=1 system_entries=1 library_entries=2 framework_entries=2 private_framework_entries=3 cache_main=0",
		"physical=unavailable resolution_exact=0 fallback_exact=0 target_entries=-1 system_entries=-1 library_entries=-1 framework_entries=-1 private_framework_entries=-1 cache_main=-1", 1)
	unresolved, err := parseSystemOSPreflight([]byte(unresolvedBody))
	if err == nil || unresolved.Physical != "unavailable" ||
		unresolved.ResolutionExact || !strings.Contains(err.Error(), "resolved to") {
		t.Fatalf("unresolved Product path result=%+v err=%v", unresolved, err)
	}
	body := append(systemOSPreflightFixture("absent"), systemOSPreflightFixture("absent")...)
	if _, err := parseSystemOSPreflight(body); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate preflight marker was not rejected: %v", err)
	}
	if script := systemOSPreflightScript(); !strings.Contains(script, "cd -P") ||
		!strings.Contains(script, "physical=unavailable") ||
		!strings.Contains(script, "resolution_exact=%d") ||
		!strings.Contains(script, "fallback_exact=%d") ||
		!strings.Contains(script, systemOSCryptexVisibleRoot) ||
		!strings.Contains(script, systemOSCryptexProductMount) ||
		!strings.Contains(script, systemOSCryptexCacheMain) ||
		!strings.Contains(script, "JavaScriptCore.framework") ||
		!strings.Contains(script, "WebKit.framework") ||
		!strings.Contains(script, "WebCore.framework") ||
		!strings.Contains(script, "WebInspector.framework") ||
		!strings.Contains(script, "WebKitLegacy.framework") ||
		strings.Contains(script, "/mnt/iphone/preboot/Cryptexes/OS\" && pwd") {
		t.Fatalf("preflight script lost the Product-resolved namespace contract: %s", script)
	}
}

func makePortableSystemOSFallback(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "OS")
	for _, directory := range []string{
		"System/Library/Frameworks/JavaScriptCore.framework",
		"System/Library/Frameworks/WebKit.framework",
		"System/Library/PrivateFrameworks/WebCore.framework",
		"System/Library/PrivateFrameworks/WebInspector.framework",
		"System/Library/PrivateFrameworks/WebKitLegacy.framework",
	} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	physical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return physical
}

func runPortableSystemOSPreflight(t *testing.T, root string) map[string]string {
	t.Helper()
	cacheMain := filepath.Join(root, "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e")
	output, err := exec.Command("/bin/bash", "-c",
		systemOSPreflightScriptFor(root, root, cacheMain)).CombinedOutput()
	if err != nil {
		t.Fatalf("portable preflight failed: %v\n%s", err, output)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.HasPrefix(line, "SYSTEMOS_CRYPTEX_PREFLIGHT ") {
			fields, parseErr := parseKeyValueLine(line, "SYSTEMOS_CRYPTEX_PREFLIGHT ")
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			return fields
		}
	}
	t.Fatalf("portable preflight marker absent:\n%s", output)
	return nil
}

func TestSystemOSCryptexPortableFallbackShape(t *testing.T) {
	root := makePortableSystemOSFallback(t)
	fields := runPortableSystemOSPreflight(t, root)
	for field, want := range map[string]string{
		"resolution_exact": "1", "fallback_exact": "1", "target_entries": "1",
		"system_entries": "1", "library_entries": "2", "framework_entries": "2",
		"private_framework_entries": "3", "cache_main": "0",
	} {
		if fields[field] != want {
			t.Fatalf("portable exact fallback %s=%q, want %q: %v", field, fields[field], want, fields)
		}
	}

	t.Run("unexpected name", func(t *testing.T) {
		root := makePortableSystemOSFallback(t)
		if err := os.WriteFile(filepath.Join(root, "unexpected"), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		fields := runPortableSystemOSPreflight(t, root)
		if fields["target_entries"] != "2" || fields["fallback_exact"] != "0" {
			t.Fatalf("unexpected fallback entry was not rejected at shape assertion: %v", fields)
		}
	})

	t.Run("symlink substitution", func(t *testing.T) {
		root := makePortableSystemOSFallback(t)
		webKit := filepath.Join(root, "System/Library/Frameworks/WebKit.framework")
		if err := os.Remove(webKit); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("JavaScriptCore.framework", webKit); err != nil {
			t.Fatal(err)
		}
		fields := runPortableSystemOSPreflight(t, root)
		if fields["framework_entries"] != "2" || fields["fallback_exact"] != "0" {
			t.Fatalf("fallback symlink substitution was not rejected at type assertion: %v", fields)
		}
	})

	t.Run("cache present", func(t *testing.T) {
		root := makePortableSystemOSFallback(t)
		cache := filepath.Join(root, "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e")
		if err := os.MkdirAll(filepath.Dir(cache), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cache, []byte("unexpected"), 0600); err != nil {
			t.Fatal(err)
		}
		fields := runPortableSystemOSPreflight(t, root)
		if fields["cache_main"] != "1" || fields["fallback_exact"] != "0" {
			t.Fatalf("existing cache was not rejected at cache assertion: %v", fields)
		}
	})
}

func TestSystemOSCryptexTargetVerifierContract(t *testing.T) {
	space := []byte("SYSTEMOS_CRYPTEX_SPACE path=" + systemOSCryptexPrebootMount +
		" source=/dev/disk3s3 fstype=apfs readonly=1 available=9999999999 required=" +
		strconv.FormatUint(systemOSCryptexRequiredFree, 10) + " exact=1\n")
	result, err := parseSystemOSVerifier(space, "space")
	if err != nil || result.Source != "/dev/disk3s3" || result.Available != 9999999999 {
		t.Fatalf("space result=%+v err=%v", result, err)
	}
	file := []byte("SYSTEMOS_CRYPTEX_FILE mode=read path=" + systemOSCryptexTargetImage +
		" bytes=1926136882 sha256=" + systemOSCryptexSHA256 + " fsync=0 exact=1\n")
	result, err = parseSystemOSVerifier(file, "read")
	if err != nil || result.Bytes != systemOSCryptexBytes {
		t.Fatalf("file result=%+v err=%v", result, err)
	}
	commit := bytesReplace(file, "mode=read", "mode=commit", "fsync=0", "fsync=1")
	if _, err = parseSystemOSVerifier(commit, "commit"); err != nil {
		t.Fatal(err)
	}
	cache := []byte("SYSTEMOS_CRYPTEX_FILE mode=read path=" + systemOSCryptexCacheMain +
		" bytes=606208 sha256=" + systemOSCryptexCacheSHA256 + " fsync=0 exact=1\n")
	if _, err = parseSystemOSVerifier(cache, "read"); err != nil {
		t.Fatal(err)
	}
	unmount := []byte("SYSTEMOS_CRYPTEX_UNMOUNT path=" + systemOSCryptexProductMount +
		" source=/dev/disk12s1 status=0 absent=1 exact=1\n")
	if _, err = parseSystemOSVerifier(unmount, "unmount"); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ name, body, mode, want string }{
		{"space source", strings.Replace(string(space), "/dev/disk3s3", "tmpfs", 1), "space", "space contract"},
		{"space capacity", strings.Replace(string(space), "9999999999", "1", 1), "space", "insufficient"},
		{"file size", strings.Replace(string(file), "1926136882", "1926136881", 1), "read", "identity"},
		{"file hash", strings.Replace(string(file), systemOSCryptexSHA256, strings.Repeat("0", 64), 1), "read", "identity"},
		{"file fsync", strings.Replace(string(file), "fsync=0", "fsync=1", 1), "read", "mode"},
		{"unmount status", strings.Replace(string(unmount), "status=0", "status=1", 1), "unmount", "unmount contract"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			_, err := parseSystemOSVerifier([]byte(mutation.body), mutation.mode)
			if err == nil || !strings.Contains(err.Error(), mutation.want) {
				t.Fatalf("site-specific verifier mutation err=%v want=%q", err, mutation.want)
			}
		})
	}
}

func bytesReplace(body []byte, replacements ...string) []byte {
	value := string(body)
	for index := 0; index < len(replacements); index += 2 {
		value = strings.Replace(value, replacements[index], replacements[index+1], 1)
	}
	return []byte(value)
}

func TestSystemOSCryptexHDIKOwnershipContract(t *testing.T) {
	preimage, err := parseSystemOSDeviceInventory([]byte("/dev/disk2\n/dev/disk3\n"))
	if err != nil {
		t.Fatal(err)
	}
	output := []byte("/dev/disk12              GUID_partition_scheme\n/dev/disk12s1            Apple_APFS\n")
	owned, candidates, err := parseSystemOSHDIKOutput(output, preimage)
	if err != nil || !reflect.DeepEqual(owned, []string{"/dev/disk12"}) || !reflect.DeepEqual(candidates, []string{"/dev/disk12s1"}) {
		t.Fatalf("owned=%v candidates=%v err=%v", owned, candidates, err)
	}
	if _, _, err = parseSystemOSHDIKOutput([]byte("/dev/disk3\n/dev/disk3s1\n"), preimage); err == nil || !strings.Contains(err.Error(), "pre-existing") {
		t.Fatalf("pre-existing hdik device accepted: %v", err)
	}
	if _, _, err = parseSystemOSHDIKOutput([]byte("/dev/disk12\n/dev/disk13\n"), preimage); err == nil || !strings.Contains(err.Error(), "2 newly") {
		t.Fatalf("ambiguous hdik devices accepted: %v", err)
	}
	if _, _, err = parseSystemOSHDIKOutput([]byte("noise only\n"), preimage); err == nil || !strings.Contains(err.Error(), "0 newly") {
		t.Fatalf("empty hdik ownership accepted: %v", err)
	}
	if _, err = parseSystemOSDeviceInventory([]byte("/dev/disk2\n/dev/disk2\n")); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate device inventory accepted: %v", err)
	}
}

func TestSystemOSCryptexContextCarriesOneExactPlan(t *testing.T) {
	evidence := &systemOSCryptexEvidence{Source: "/host/image", Bytes: systemOSCryptexBytes, SHA256: systemOSCryptexSHA256}
	runtime := &systemOSCryptexRuntime{
		Plan:     systemOSCryptexPlan{Source: evidence.Source, Bytes: evidence.Bytes, SHA256: evidence.SHA256},
		Evidence: evidence,
	}
	ctx := withSystemOSCryptex(context.Background(), runtime)
	if systemOSCryptexFromContext(ctx) != runtime || systemOSCryptexFromContext(context.Background()) != nil {
		t.Fatal("SystemOS cryptex context boundary changed")
	}
}

func TestSystemOSCryptexIncompleteCleanupIsOwnedAndExact(t *testing.T) {
	script := systemOSIncompleteCleanupScript()
	for _, token := range []string{
		"test -d " + shellQuote(systemOSCryptexOwnedDirectory),
		"test -f " + shellQuote(systemOSCryptexOwnerPath),
		shellQuote(systemOSCryptexOwnerMarker),
		"/bin/rm -f " + shellQuote(systemOSCryptexPartialImage) + " " + shellQuote(systemOSCryptexTargetImage) + " " + shellQuote(systemOSCryptexOwnerPath),
		"/bin/rmdir " + shellQuote(systemOSCryptexOwnedDirectory),
		"test ! -e " + shellQuote(systemOSCryptexOwnedDirectory),
	} {
		if !strings.Contains(script, token) {
			t.Fatalf("owned incomplete cleanup missing %q: %s", token, script)
		}
	}
	if strings.Contains(script, "rm -rf") || strings.Contains(script, "/mnt/iphone/preboot/*") {
		t.Fatalf("owned incomplete cleanup widened its target: %s", script)
	}
}

func TestSystemOSCryptexExactExternalIntegration(t *testing.T) {
	const enableInput = "SYSTEMOS_CRYPTEX_INTEGRATION"
	if os.Getenv(enableInput) == "" {
		return
	}
	if os.Getenv(enableInput) != "1" {
		t.Fatalf("%s must equal 1 when set", enableInput)
	}
	path := os.Getenv("SYSTEMOS_CRYPTEX_PATH")
	if !filepath.IsAbs(path) {
		t.Fatal("explicit SystemOS cryptex integration requires absolute SYSTEMOS_CRYPTEX_PATH")
	}
	plan, err := prepareSystemOSCryptex(path, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Source != path || plan.Bytes != systemOSCryptexBytes || plan.SHA256 != systemOSCryptexSHA256 {
		t.Fatalf("exact SystemOS integration identity changed: %+v", plan)
	}
}
