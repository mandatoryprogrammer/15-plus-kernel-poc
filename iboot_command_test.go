package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func offlineIBootFixture(t *testing.T, directory string, offset uint64) string {
	t.Helper()
	image := semanticFixture(t)
	path := filepath.Join(directory, "loader.bin")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	metadata := fmt.Sprintf("build=iBoot-fixture.1\nbase=0x1fc064000\noffset=0x%x\nsize=%d\nsha256=%s\n", offset, len(image), digest(image))
	if err := os.WriteFile(path+".txt", []byte(metadata), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestIBootCommandAnalyzePatchVerifyEndToEnd(t *testing.T) {
	directory := t.TempDir()
	input := offlineIBootFixture(t, directory, 0x20000)
	var analysis bytes.Buffer
	if err := ibootCommand([]string{"analyze", input, "--json"}, &analysis, &analysis); err != nil {
		t.Fatal(err)
	}
	var report ibootPatchReport
	if err := json.Unmarshal(analysis.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Exact || report.PatchCount != 17 || report.GuardCount == 0 || report.Build != "iBoot-fixture.1" || report.ImageOffset != 0x20000 {
		t.Fatalf("analysis report: %+v", report)
	}
	original, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "friendly-output.bin")
	reportPath := filepath.Join(directory, "patch-report.json")
	var patchOutput bytes.Buffer
	if err = ibootCommand([]string{"patch", input, "--out", output, "--report", reportPath}, &patchOutput, &patchOutput); err != nil {
		t.Fatal(err)
	}
	patched, err := os.ReadFile(output)
	if err != nil || bytes.Equal(patched, original) {
		t.Fatal("patch output was not created", err)
	}
	unchanged, _ := os.ReadFile(input)
	if !bytes.Equal(unchanged, original) {
		t.Fatal("patch command modified its source")
	}
	var verification bytes.Buffer
	if err = ibootCommand([]string{"verify", input, output, "--json"}, &verification, &verification); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(verification.Bytes(), &report); err != nil || !report.Exact || report.OutputSHA256 != digest(patched) || report.ChangedBytes == 0 {
		t.Fatalf("verification report: %+v err=%v", report, err)
	}
	if data, readErr := os.ReadFile(reportPath); readErr != nil || json.Unmarshal(data, &report) != nil || !report.Exact {
		t.Fatal("machine report is not valid", readErr)
	}
}

func TestIBootCommandErgonomicsAndNoClobber(t *testing.T) {
	directory := t.TempDir()
	input := offlineIBootFixture(t, directory, 0)
	defaultOutput := input + ".patched"
	var output bytes.Buffer
	if err := ibootCommand([]string{"patch", input}, &output, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(defaultOutput); err != nil {
		t.Fatal("default output absent", err)
	}
	if err := ibootCommand([]string{"patch", "--force", input}, ioDiscard{}, ioDiscard{}); err != nil {
		t.Fatal("force did not replace exact output", err)
	}
	if err := ibootCommand([]string{"patch", input}, ioDiscard{}, ioDiscard{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing output was not protected: %v", err)
	}
	if err := ibootCommand([]string{"patch", "--out", input, input}, ioDiscard{}, ioDiscard{}); err == nil || !strings.Contains(err.Error(), "source snapshot") {
		t.Fatalf("source overwrite was not rejected: %v", err)
	}
	if err := ibootCommand([]string{"patch", "--force", "--report", input, input}, ioDiscard{}, ioDiscard{}); err == nil || !strings.Contains(err.Error(), "source snapshot") {
		t.Fatalf("report source overwrite was not rejected: %v", err)
	}
	collision := filepath.Join(directory, "collision")
	if err := ibootCommand([]string{"patch", "--force", "--out", collision, "--report", collision, input}, ioDiscard{}, ioDiscard{}); err == nil || !strings.Contains(err.Error(), "different files") {
		t.Fatalf("output/report collision was not rejected: %v", err)
	}
}

func TestIBootCommandCheckedAdapterFallback(t *testing.T) {
	directory := t.TempDir()
	adapter := initialLoaderAdapters[0]
	const offset = uint64(0x30000)
	image := make([]byte, 0x10000)
	for _, guard := range adapter.guards {
		binary.LittleEndian.PutUint32(image[guard.offset-offset:], guard.value)
	}
	for _, patch := range adapter.patches {
		binary.LittleEndian.PutUint32(image[patch.offset-offset:], patch.before)
	}
	path := filepath.Join(directory, "adapter.bin")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	metadata := fmt.Sprintf("build=%s\nbase=0x1fc064000\noffset=0x%x\nsize=%d\nsha256=%s\n", adapter.build, offset, len(image), digest(image))
	if err := os.WriteFile(path+".txt", []byte(metadata), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := ibootCommand([]string{"patch", path, "--json"}, &output, &output); err != nil {
		t.Fatal(err)
	}
	var report ibootPatchReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || report.Analyzer != "stored checked adapter" || report.PatchCount != len(adapter.patches) || !report.Exact {
		t.Fatalf("adapter report=%+v err=%v", report, err)
	}
}

func TestIBootCommandAutoBuildDeduplicatesAndRejectsMismatch(t *testing.T) {
	directory := t.TempDir()
	image := semanticFixture(t)
	copy(image[0x100:], "iBoot-9275.0.0.101.11\x00")
	copy(image[0x200:], "iBoot-9275.0.0.101.11\x00")
	path := filepath.Join(directory, "full.bin")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ibootCommand([]string{"analyze", path}, ioDiscard{}, ioDiscard{}); err != nil {
		t.Fatal("duplicate identical build strings should auto-resolve", err)
	}
	copy(image[0x200:], "iBoot-another.1\x00")
	if err := os.WriteFile(path, image, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ibootCommand([]string{"analyze", path}, ioDiscard{}, ioDiscard{}); err == nil || !strings.Contains(err.Error(), "expected one") {
		t.Fatalf("distinct build identities accepted: %v", err)
	}
	if err := ibootCommand([]string{"analyze", "--build", "iBoot-missing.1", path}, ioDiscard{}, ioDiscard{}); err == nil {
		t.Fatal("explicit absent build identity accepted")
	}
}

func TestIBootCommandFailsClosed(t *testing.T) {
	directory := t.TempDir()
	input := offlineIBootFixture(t, directory, 0)
	metadata, err := os.ReadFile(input + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(input+".txt", bytes.Replace(metadata, []byte("sha256="), []byte("sha256=00"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = ibootCommand([]string{"analyze", input}, ioDiscard{}, ioDiscard{}); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("bad metadata accepted: %v", err)
	}
	if err = os.Remove(input + ".txt"); err != nil {
		t.Fatal(err)
	}
	if err = ibootCommand([]string{"analyze", "--build", "iBoot-fixture.1", input}, ioDiscard{}, ioDiscard{}); err != nil {
		t.Fatal(err)
	}
	output := input + ".patched"
	if err = ibootCommand([]string{"patch", "--build", "iBoot-fixture.1", input}, ioDiscard{}, ioDiscard{}); err != nil {
		t.Fatal(err)
	}
	changed, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	changed[len(changed)-1] ^= 1
	if err = os.WriteFile(output, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = ibootCommand([]string{"verify", "--build", "iBoot-fixture.1", input, output}, ioDiscard{}, ioDiscard{}); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("undeclared output mutation accepted: %v", err)
	}
	if err = ibootCommand([]string{"analyze", "--build", "iBoot-fixture.1", output}, ioDiscard{}, ioDiscard{}); err == nil {
		t.Fatal("already-patched input was accepted as a fresh source")
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
