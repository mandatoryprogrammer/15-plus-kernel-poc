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

func TestSystemOSCryptexTrustIdentityAndSemanticsAreIndependent(t *testing.T) {
	if err := validateSystemOSCryptexTrustIdentity(systemOSCryptexTrustBytes, systemOSCryptexTrustSHA256); err != nil {
		t.Fatal(err)
	}
	if err := validateSystemOSCryptexTrustIdentity(systemOSCryptexTrustBytes-1, systemOSCryptexTrustSHA256); err == nil || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("trust-cache size mutation did not reach size assertion: %v", err)
	}
	mutatedHash := "0" + systemOSCryptexTrustSHA256[1:]
	if err := validateSystemOSCryptexTrustIdentity(systemOSCryptexTrustBytes, mutatedHash); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("trust-cache hash mutation did not reach hash assertion: %v", err)
	}

	fixture := func(kind string, version uint32, count int) []byte {
		rows := make([][]byte, 0, count)
		for index := 0; index < count; index++ {
			rows = append(rows, completeTrustRow(version, byte(index)))
		}
		return trustImageWithRows(kind, version, rows...)
	}
	semanticFixture := fixture(systemOSCryptexTrustType, systemOSCryptexTrustVersion, systemOSCryptexTrustEntries)
	parsed, err := validateSystemOSCryptexTrustSemantics(semanticFixture)
	if err != nil || parsed.version != systemOSCryptexTrustVersion || len(parsed.rows) != systemOSCryptexTrustEntries {
		t.Fatalf("portable trust-cache semantic fixture rejected: version=%d entries=%d err=%v", parsed.version, len(parsed.rows), err)
	}
	if _, err = validateSystemOSCryptexTrustSemantics(fixture("trst", systemOSCryptexTrustVersion, systemOSCryptexTrustEntries)); err == nil || !strings.Contains(err.Error(), "type") {
		t.Fatalf("type mutation did not reach semantic type assertion: %v", err)
	}
	if _, err = validateSystemOSCryptexTrustSemantics(fixture(systemOSCryptexTrustType, 1, systemOSCryptexTrustEntries)); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("version mutation did not reach semantic version assertion: %v", err)
	}
	if _, err = validateSystemOSCryptexTrustSemantics(fixture(systemOSCryptexTrustType, systemOSCryptexTrustVersion, systemOSCryptexTrustEntries-1)); err == nil || !strings.Contains(err.Error(), "entry count") {
		t.Fatalf("entry-count mutation did not reach semantic count assertion: %v", err)
	}
	unsortedRows := make([][]byte, 0, systemOSCryptexTrustEntries)
	for index := 0; index < systemOSCryptexTrustEntries; index++ {
		unsortedRows = append(unsortedRows, completeTrustRow(systemOSCryptexTrustVersion, byte(index)))
	}
	unsortedRows[0], unsortedRows[1] = unsortedRows[1], unsortedRows[0]
	if _, err = validateSystemOSCryptexTrustSemantics(trustImageWithRows(systemOSCryptexTrustType, systemOSCryptexTrustVersion, unsortedRows...)); err == nil || !strings.Contains(err.Error(), "sorted") {
		t.Fatalf("ordering mutation did not reach semantic row-order assertion: %v", err)
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

func TestSystemOSCryptexPrebootReadOnlyPlan(t *testing.T) {
	const source = "/dev/disk3s3"
	wantCommand := []string{"/sbin/mount_apfs", "-o", "rdonly,nobrowse", source,
		systemOSCryptexPrebootMount}
	if command := systemOSPrebootReadOnlyMountCommand(source); !reflect.DeepEqual(command, wantCommand) {
		t.Fatalf("read-only remount command=%v, want %v", command, wantCommand)
	}
	ready, err := planSystemOSPrebootReadOnly(systemOSMountFixture(false), source)
	if err != nil || ready.Action != "ready" || ready.Source != source {
		t.Fatalf("read-only plan=%+v err=%v", ready, err)
	}
	writableBody := strings.Replace(systemOSMountFixture(false), "read-only, ", "", 1)
	writable, err := planSystemOSPrebootReadOnly(writableBody, source)
	if err != nil || writable.Action != "unmount-remount" || writable.Source != source {
		t.Fatalf("writable plan=%+v err=%v", writable, err)
	}
	absentBody := "/dev/disk3s1s1 on /mnt/iphone/system (apfs, sealed, local, read-only, journaled, nobrowse)\n"
	absent, err := planSystemOSPrebootReadOnly(absentBody, source)
	if err != nil || absent.Action != "remount" || absent.Source != source {
		t.Fatalf("absent plan=%+v err=%v", absent, err)
	}
	for _, mutation := range []struct {
		name, body, expected, want string
	}{
		{"source", systemOSMountFixture(false), "/dev/disk4s3", "source/options"},
		{"expected source", absentBody, "not-a-device", "invalid expected"},
		{"browse", strings.Replace(systemOSMountFixture(false), "nobrowse", "browse", 1), source, "lost nobrowse"},
		{"duplicate", systemOSMountFixture(false) + source + " on " + systemOSCryptexPrebootMount + " (apfs, local, journaled)\n", source, "2 mount-table"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			_, err := planSystemOSPrebootReadOnly(mutation.body, mutation.expected)
			if err == nil || !strings.Contains(err.Error(), mutation.want) {
				t.Fatalf("site-specific Preboot plan mutation err=%v, want %q", err, mutation.want)
			}
		})
	}
}

func validateSystemOSCryptexInverseQualificationSource(source []byte) string {
	for _, assertion := range []struct {
		site  string
		token string
	}{
		{"qualifier sequence", "if err := session.remountPreboot(false); err != nil {\n\t\treturn err\n\t}\n\tif err := session.remountPreboot(true); err != nil {\n\t\treturn err\n\t}\n\tsession.runtime.Evidence.PrebootInverseQualified = true"},
		{"staged-image inverse", "session.runtime.Evidence.CompleteStageRetained = true\n\tif err = session.remountPreboot(true); err != nil {\n\t\treturn err\n\t}\n\tsession.runtime.Evidence.PrebootInverseQualified = true"},
		{"reused-image inverse", "runtime.Evidence.CompleteStageRetained = true\n\t\tif err = session.qualifyPrebootReadOnlyInverse(); err != nil {\n\t\t\treturn nil, err\n\t\t}"},
		{"inverse before attach", "\t}\n\tif err = session.attachAndMount(); err != nil {"},
	} {
		if !strings.Contains(string(source), assertion.token) {
			return assertion.site
		}
	}
	return ""
}

func TestSystemOSCryptexInverseQualificationSourceContract(t *testing.T) {
	source, err := os.ReadFile("systemos_cryptex.go")
	if err != nil {
		t.Fatal(err)
	}
	if site := validateSystemOSCryptexInverseQualificationSource(source); site != "" {
		t.Fatalf("canonical inverse qualification failed at %s", site)
	}
	for _, mutation := range []struct {
		name, old, replacement, want string
	}{
		{"qualifier writable transition", "if err := session.remountPreboot(false); err != nil {", "if err := session.remountPreboot(true); err != nil {", "qualifier sequence"},
		{"staged result", "session.runtime.Evidence.CompleteStageRetained = true\n\tif err = session.remountPreboot(true); err != nil {\n\t\treturn err\n\t}\n\tsession.runtime.Evidence.PrebootInverseQualified = true", "session.runtime.Evidence.CompleteStageRetained = true\n\tif err = session.remountPreboot(true); err != nil {\n\t\treturn err\n\t}\n\tsession.runtime.Evidence.PrebootInverseQualified = false", "staged-image inverse"},
		{"reuse call", "if err = session.qualifyPrebootReadOnlyInverse(); err != nil {", "if err = session.remountPreboot(true); err != nil {", "reused-image inverse"},
		{"attach order", "\t}\n\tif err = session.attachAndMount(); err != nil {", "\t}\n\tif err = session.cleanup(); err != nil {", "inverse before attach"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := bytesReplace(source, mutation.old, mutation.replacement)
			if string(mutated) == string(source) {
				t.Fatalf("mutation did not change source at %q", mutation.old)
			}
			if site := validateSystemOSCryptexInverseQualificationSource(mutated); site != mutation.want {
				t.Fatalf("mutation reached site %q, want %q", site, mutation.want)
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
	prebootUnmount := []byte("SYSTEMOS_CRYPTEX_PREBOOT_UNMOUNT path=" + systemOSCryptexPrebootMount +
		" source=/dev/disk3s3 readonly=0 status=0 absent=1 exact=1\n")
	if _, err = parseSystemOSVerifier(prebootUnmount, "preboot-unmount"); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ name, body, mode, want string }{
		{"space source", strings.Replace(string(space), "/dev/disk3s3", "tmpfs", 1), "space", "space contract"},
		{"space capacity", strings.Replace(string(space), "9999999999", "1", 1), "space", "insufficient"},
		{"file size", strings.Replace(string(file), "1926136882", "1926136881", 1), "read", "identity"},
		{"file hash", strings.Replace(string(file), systemOSCryptexSHA256, strings.Repeat("0", 64), 1), "read", "identity"},
		{"file fsync", strings.Replace(string(file), "fsync=0", "fsync=1", 1), "read", "mode"},
		{"unmount status", strings.Replace(string(unmount), "status=0", "status=1", 1), "unmount", "unmount contract"},
		{"Preboot unmount path", strings.Replace(string(prebootUnmount), systemOSCryptexPrebootMount, systemOSCryptexProductMount, 1), "preboot-unmount", "Preboot unmount contract"},
		{"Preboot unmount source", strings.Replace(string(prebootUnmount), "/dev/disk3s3", "tmpfs", 1), "preboot-unmount", "Preboot unmount contract"},
		{"Preboot unmount readonly", strings.Replace(string(prebootUnmount), "readonly=0", "readonly=1", 1), "preboot-unmount", "Preboot unmount contract"},
		{"Preboot unmount status", strings.Replace(string(prebootUnmount), "status=0", "status=1", 1), "preboot-unmount", "Preboot unmount contract"},
		{"Preboot unmount absent", strings.Replace(string(prebootUnmount), "absent=1", "absent=0", 1), "preboot-unmount", "Preboot unmount contract"},
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
	owned, attached, candidates, err := parseSystemOSHDIKOutput(output, preimage)
	if err != nil || !reflect.DeepEqual(owned, []string{"/dev/disk12"}) ||
		!reflect.DeepEqual(attached, []string{"/dev/disk12"}) ||
		!reflect.DeepEqual(candidates, []string{"/dev/disk12s1"}) {
		t.Fatalf("owned=%v attached=%v candidates=%v err=%v", owned, attached, candidates, err)
	}
	if _, _, _, err = parseSystemOSHDIKOutput([]byte("/dev/disk3\n/dev/disk3s1\n"), preimage); err == nil || !strings.Contains(err.Error(), "pre-existing") {
		t.Fatalf("pre-existing hdik device accepted: %v", err)
	}
	if _, _, _, err = parseSystemOSHDIKOutput([]byte("/dev/disk12\n/dev/disk13\n"), preimage); err == nil || !strings.Contains(err.Error(), "two-base topology has 2 records") {
		t.Fatalf("ambiguous hdik devices accepted: %v", err)
	}
	if _, _, _, err = parseSystemOSHDIKOutput([]byte("noise only\n"), preimage); err == nil || !strings.Contains(err.Error(), "0 newly attached") {
		t.Fatalf("empty hdik ownership accepted: %v", err)
	}
	if _, err = parseSystemOSDeviceInventory([]byte("/dev/disk2\n/dev/disk2\n")); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate device inventory accepted: %v", err)
	}
}

func TestSystemOSCryptexHDIKObservedTwoBaseTopology(t *testing.T) {
	preimage, err := parseSystemOSDeviceInventory([]byte("/dev/disk2\n"))
	if err != nil {
		t.Fatal(err)
	}
	observed := "/dev/disk3          \t                               \t\r\n" +
		"/dev/disk4          \t" + systemOSHDIKSecondBaseType + "\t\r\n" +
		"/dev/disk4s1        \t" + systemOSHDIKVolumeType + "\t\r\n"
	owned, attached, candidates, err := parseSystemOSHDIKOutput([]byte(observed), preimage)
	if err != nil || !reflect.DeepEqual(owned, []string{"/dev/disk3"}) ||
		!reflect.DeepEqual(attached, []string{"/dev/disk3", "/dev/disk4"}) ||
		!reflect.DeepEqual(candidates, []string{"/dev/disk4s1"}) {
		t.Fatalf("owned=%v attached=%v candidates=%v err=%v", owned, attached, candidates, err)
	}

	for _, mutation := range []struct {
		name string
		body string
		want string
	}{
		{"root type", strings.Replace(observed, "/dev/disk3          \t                               \t", "/dev/disk3 ROOT", 1), "root record changed"},
		{"second type", strings.Replace(observed, systemOSHDIKSecondBaseType, "EF57347C-0000-11AA-AA11-0030655", 1), "second record changed"},
		{"volume type", strings.Replace(observed, systemOSHDIKVolumeType, "41504653-0000-11AA-AA11-0030655", 1), "volume record changed"},
		{"nonconsecutive", strings.NewReplacer("/dev/disk4s1", "/dev/disk5s1", "/dev/disk4", "/dev/disk5").Replace(observed), "not consecutive"},
		{"wrong partition", strings.Replace(observed, "/dev/disk4s1", "/dev/disk4s2", 1), "volume record changed"},
		{"extra base", observed + "/dev/disk6\n", "3 newly attached"},
		{"missing volume", strings.Replace(observed, "/dev/disk4s1        \t"+systemOSHDIKVolumeType+"\t\r\n", "", 1), "two-base topology has 2 records"},
		{"duplicate path", observed + "/dev/disk4s1 " + systemOSHDIKVolumeType + "\n", "duplicate hdik device path"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			_, _, _, gotErr := parseSystemOSHDIKOutput([]byte(mutation.body), preimage)
			if gotErr == nil || !strings.Contains(gotErr.Error(), mutation.want) {
				t.Fatalf("site-specific topology mutation err=%v want=%q", gotErr, mutation.want)
			}
		})
	}

	preexistingSecond, err := parseSystemOSDeviceInventory([]byte("/dev/disk2\n/dev/disk4\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = parseSystemOSHDIKOutput([]byte(observed), preexistingSecond); err == nil ||
		!strings.Contains(err.Error(), "pre-existing device /dev/disk4") {
		t.Fatalf("pre-existing second base accepted: %v", err)
	}
}

func TestSystemOSCryptexContextCarriesOneExactPlan(t *testing.T) {
	evidence := &systemOSCryptexEvidence{Source: "/host/image", Bytes: systemOSCryptexBytes, SHA256: systemOSCryptexSHA256}
	trust := &systemOSCryptexTrustPlan{Source: "/host/trust", Bytes: systemOSCryptexTrustBytes, SHA256: systemOSCryptexTrustSHA256}
	runtime := &systemOSCryptexRuntime{
		Plan:       systemOSCryptexPlan{Source: evidence.Source, Bytes: evidence.Bytes, SHA256: evidence.SHA256},
		TrustCache: trust,
		Evidence:   evidence,
	}
	ctx := withSystemOSCryptex(context.Background(), runtime)
	if systemOSCryptexFromContext(ctx) != runtime || systemOSCryptexFromContext(ctx).TrustCache != trust || systemOSCryptexFromContext(context.Background()) != nil {
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

func TestSystemOSCryptexTrustExactExternalIntegration(t *testing.T) {
	const enableInput = "SYSTEMOS_CRYPTEX_TRUST_INTEGRATION"
	if os.Getenv(enableInput) == "" {
		return
	}
	if os.Getenv(enableInput) != "1" {
		t.Fatalf("%s must equal 1 when set", enableInput)
	}
	path := os.Getenv("SYSTEMOS_CRYPTEX_TRUST_PATH")
	if !filepath.IsAbs(path) {
		t.Fatal("explicit SystemOS cryptex trust integration requires absolute SYSTEMOS_CRYPTEX_TRUST_PATH")
	}
	plan, err := prepareSystemOSCryptexTrustCache(path, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Source != path || plan.Bytes != systemOSCryptexTrustBytes || plan.SHA256 != systemOSCryptexTrustSHA256 || plan.Version != systemOSCryptexTrustVersion || plan.EntryCount != systemOSCryptexTrustEntries {
		t.Fatalf("exact SystemOS trust integration identity changed: %+v", plan)
	}
	if err = validateSystemOSCryptexTrustPlan(&plan); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	c, err := newCache(root)
	if err != nil {
		t.Fatal(err)
	}
	c.out = os.Stderr
	before, err := payloadAdmissionFingerprint(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &systemOSCryptexEvidence{}
	ctx := withSystemOSCryptex(context.Background(), &systemOSCryptexRuntime{TrustCache: &plan, Evidence: evidence})
	after, err := payloadAdmissionFingerprint(ctx, c)
	if err != nil || after == before {
		t.Fatalf("exact cryptex trust did not change admission fingerprint: before=%s after=%s err=%v", before, after, err)
	}
}
