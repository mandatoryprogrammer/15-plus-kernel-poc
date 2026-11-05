package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testUISystemVersion = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>16.0</string>
<key>ProductBuildVersion</key><string>20A5312i</string>
</dict></plist>`

func storeRuntimeTestObject(t *testing.T, c *cache, role string, body []byte) asset {
	t.Helper()
	row := asset{Role: role, SHA256: digest(body), Size: int64(len(body)), Recipe: "test", Compatibility: "test"}
	if err := os.WriteFile(c.object(row), body, 0600); err != nil {
		t.Fatal(err)
	}
	return row
}

func installRuntimeTestUI(t *testing.T, c *cache) {
	t.Helper()
	profile := uiProfile{Schema: "15-plus-kernel-poc.ui-profile.v2"}
	for index, relative := range uiBundleFiles {
		body := []byte("ui-object-" + relative)
		if relative == "System/Library/CoreServices/SystemVersion.plist" {
			body = []byte(testUISystemVersion)
		}
		object := storeRuntimeTestObject(t, c, "ui-bundle", body)
		profile.Files = append(profile.Files, uiObject{Relative: relative, SHA256: object.SHA256, Size: object.Size})
		_ = index
	}
	launcher := storeRuntimeTestObject(t, c, "ui-root-launcher", []byte("launcher"))
	profile.Launcher = &uiObject{Relative: uiRootLauncherName, SHA256: launcher.SHA256, Size: launcher.Size}
	if err := writeUIProfile(c, profile); err != nil {
		t.Fatal(err)
	}
}

func newRuntimeQualificationTestCache(t *testing.T, withSystemTrust bool) (*cache, []byte) {
	t.Helper()
	c, err := newCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.out = io.Discard
	roles := []string{"ibec", "ramdisk", "kernel", "sptm", "txm", "trust-cache"}
	rows := make([]asset, 0, len(roles))
	for _, role := range roles {
		body := []byte("prepared-" + role)
		if role == "trust-cache" {
			body = trustImageWithRows("rtsc", 2, completeTrustRow(2, 0x10))
		}
		rows = append(rows, storeRuntimeTestObject(t, c, role, body))
	}
	originalBootstrap := bytes.Clone(bootstrapManifest)
	t.Cleanup(func() { bootstrapManifest = originalBootstrap })
	bootstrapManifest, err = json.Marshal(bootstrapSets{Runtime: rows})
	if err != nil {
		t.Fatal(err)
	}
	systemIM4P := trustImageWithRows("trst", 2, completeTrustRow(2, 0x20))
	if withSystemTrust {
		input := filepath.Join(c.root, "system-trust.img4")
		if err = os.WriteFile(input, wrapTrustForImport(t, systemIM4P), 0600); err != nil {
			t.Fatal(err)
		}
		if err = importSystemTrustContext(context.Background(), c, []string{input}); err != nil {
			t.Fatal(err)
		}
	}
	installRuntimeTestUI(t, c)
	return c, systemIM4P
}

func TestQualifyRuntimeValidatesPreparedTrustUIAndAdmission(t *testing.T) {
	c, _ := newRuntimeQualificationTestCache(t, true)
	report, err := qualifyRuntime(context.Background(), c, "")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Qualified || len(report.PreparedRoles) != 6 || report.SystemTrust == nil || report.SystemTrust.MergedEntries != 2 || report.UI == nil || report.UI.Schema != "15-plus-kernel-poc.ui-profile.v2" || report.UI.ProductVersion != "16.0" || report.UI.ProductBuild != "20A5312i" || len(report.AdmissionFingerprint) != 64 {
		t.Fatalf("qualification omitted a boundary: %+v", report)
	}
	started, startErr := time.Parse(time.RFC3339Nano, report.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339Nano, report.FinishedAt)
	if startErr != nil || finishErr != nil || finished.Before(started) {
		t.Fatalf("invalid qualification interval: start=%q finish=%q errors=%v/%v", report.StartedAt, report.FinishedAt, startErr, finishErr)
	}
	body, err := os.ReadFile(filepath.Join(c.root, "private", "runtime-qualify-latest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored runtimeQualificationReport
	if err = json.Unmarshal(body, &stored); err != nil || !stored.Qualified || stored.AdmissionFingerprint != report.AdmissionFingerprint {
		t.Fatalf("latest report changed: stored=%+v err=%v", stored, err)
	}
}

func TestQualifyRuntimeBindsOptionalProductRoot(t *testing.T) {
	c, systemTrust := newRuntimeQualificationTestCache(t, true)
	root := targetTestRoot(t)
	trustName := filepath.Join(root, "private", "var", "db", "StaticTrustCache")
	if err := os.WriteFile(trustName, systemTrust, 0600); err != nil {
		t.Fatal(err)
	}
	report, err := qualifyRuntime(context.Background(), c, root)
	if err != nil {
		t.Fatal(err)
	}
	if report.ProductOSRoot == nil || len(report.ProductOSRoot.IndexSHA256) != 64 || report.ProductOSRoot.ProductBuild != canonicalRuntime.OSBuild || report.ProductOSRoot.SharedCaches != 2 {
		t.Fatalf("root qualification changed: %+v", report.ProductOSRoot)
	}
}

func TestQualifyRuntimeFailsClosedAndStillWritesReport(t *testing.T) {
	c, _ := newRuntimeQualificationTestCache(t, false)
	report, err := qualifyRuntime(context.Background(), c, "")
	if err == nil || !strings.Contains(err.Error(), "complete system trust context is not configured") || report.Qualified || report.Error == "" {
		t.Fatalf("missing trust accepted: report=%+v err=%v", report, err)
	}
	body, readErr := os.ReadFile(filepath.Join(c.root, "private", "runtime-qualify-latest.json"))
	if readErr != nil || !bytes.Contains(body, []byte(`"qualified": false`)) || !bytes.Contains(body, []byte("complete system trust context")) {
		t.Fatalf("failure report absent: body=%s err=%v", body, readErr)
	}
}

func TestRuntimeQualificationRejectsMismatchedRootTrust(t *testing.T) {
	c, _ := newRuntimeQualificationTestCache(t, true)
	_, err := qualifyRuntime(context.Background(), c, targetTestRoot(t))
	if err == nil || !strings.Contains(err.Error(), "does not match the configured complete system trust context") {
		t.Fatalf("mismatched ProductOS root accepted: %v", err)
	}
}

func TestRuntimeQualificationAgainstCurrentCache(t *testing.T) {
	if os.Getenv("KERNEL_POC_TEST_CURRENT_CACHE") != "1" {
		t.Skip("set KERNEL_POC_TEST_CURRENT_CACHE=1 to verify the repository's imported runtime")
	}
	root, err := projectRoot()
	if err != nil {
		t.Fatal(err)
	}
	c, err := newCache(filepath.Join(root, ".cache"))
	if err != nil {
		t.Fatal(err)
	}
	c.out = io.Discard
	report, err := qualifyRuntime(context.Background(), c, "")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Qualified || report.UI == nil || report.UI.ProductBuild != "20A5312i" || report.OSBuild != "23D127" {
		t.Fatalf("current runtime tuple changed: %+v", report)
	}
}
