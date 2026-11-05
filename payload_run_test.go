package main

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePayloadRunOwnsArgumentsAndIncludes(t *testing.T) {
	source, destination, includes, arguments, err := parsePayloadRun([]string{
		"tool", "--dest", "/usr/local/bin/ui-tool",
		"--include", "libui.dylib=/usr/local/lib/libui.dylib",
		"--", "--frame", "caller value",
	})
	if err != nil {
		t.Fatal(err)
	}
	if source != "tool" || destination != "/usr/local/bin/ui-tool" || len(includes) != 1 ||
		includes[0] != [2]string{"libui.dylib", "/usr/local/lib/libui.dylib"} ||
		len(arguments) != 2 || arguments[0] != "--frame" || arguments[1] != "caller value" {
		t.Fatalf("parsed run changed: source=%q destination=%q includes=%v arguments=%v", source, destination, includes, arguments)
	}
	if _, _, _, _, err = parsePayloadRun([]string{"tool", "unquoted-target-argument"}); err == nil {
		t.Fatal("target argument without -- accepted")
	}
	if _, _, err = splitPayloadInclude("lib=/tmp/lib"); err == nil {
		t.Fatal("unsafe include destination accepted")
	}
}

func TestPayloadRunPreparationAndAdmissionFingerprint(t *testing.T) {
	root := t.TempDir()
	c, err := newCache(root)
	if err != nil {
		t.Fatal(err)
	}
	c.out = io.Discard
	source := filepath.Join(root, "probe")
	unsigned := make([]byte, 128)
	le := binary.LittleEndian
	for index, value := range []uint32{0xfeedfacf, 0x100000c, 0, 2, 1, 24, 0, 0, 0x32, 24, 2, 0x1a0000, 0x1a0000, 0} {
		le.PutUint32(unsigned[index*4:], value)
	}
	if err := os.WriteFile(source, unsigned, 0600); err != nil {
		t.Fatal(err)
	}
	prepared, err := preparePayload(source, "/usr/local/bin/probe")
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Entry.CDHash == "" || prepared.Entry.SHA256 == "" || prepared.FileType != 2 || !prepared.Signed || !prepared.LCUUIDAdded {
		t.Fatalf("prepared payload changed: %+v", prepared)
	}
	changed, err := storePayloadPlan(context.Background(), c, []preparedPayload{prepared})
	if err != nil || !changed {
		t.Fatalf("first store changed=%t err=%v", changed, err)
	}
	changed, err = storePayloadPlan(context.Background(), c, []preparedPayload{prepared})
	if err != nil || changed {
		t.Fatalf("idempotent store changed=%t err=%v", changed, err)
	}
	first, err := payloadAdmissionFingerprint(c)
	if err != nil || len(first) != 64 {
		t.Fatalf("fingerprint=%q err=%v", first, err)
	}
	if err = writeTrustAdditions(c, []trustEntry{{Name: "runtime", CDHash: strings.Repeat("ab", 20), Origin: "test"}}); err != nil {
		t.Fatal(err)
	}
	second, err := payloadAdmissionFingerprint(c)
	if err != nil || first == second {
		t.Fatalf("trust change did not alter fingerprint: first=%s second=%s err=%v", first, second, err)
	}
	if _, err = os.Stat(c.object(asset{SHA256: prepared.Entry.SHA256})); err != nil {
		t.Fatalf("prepared payload object absent: %v", err)
	}
}

func TestPayloadRunReportReplacesPriorResult(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "private"), 0700); err != nil {
		t.Fatal(err)
	}
	c := &cache{root: root, out: io.Discard}
	if err := writePayloadRunReport(c, payloadRunReport{Schema: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := writePayloadRunReport(c, payloadRunReport{Schema: "second"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "private", "payload-run-latest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "first") || !strings.Contains(string(b), "second") {
		t.Fatalf("latest report was appended instead of replaced: %s", b)
	}
	entries, err := os.ReadDir(filepath.Join(root, "private"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("report scratch leaked: entries=%v err=%v", entries, err)
	}
}

func TestPayloadObjectOwnershipDeletesReplacedAndRemovedBytes(t *testing.T) {
	root := t.TempDir()
	c, err := newCache(root)
	if err != nil {
		t.Fatal(err)
	}
	c.out = io.Discard
	entry := func(body string, cdhash string) preparedPayload {
		return preparedPayload{Body: []byte(body), Entry: payloadEntry{
			Destination: "/usr/local/bin/probe", SHA256: digest([]byte(body)), Size: int64(len(body)), CDHash: cdhash, Origin: "test",
		}}
	}
	first := entry("first", strings.Repeat("11", 20))
	second := entry("second", strings.Repeat("22", 20))
	if changed, storeErr := storePayloadPlan(context.Background(), c, []preparedPayload{first}); storeErr != nil || !changed {
		t.Fatalf("first store changed=%t err=%v", changed, storeErr)
	}
	if changed, storeErr := storePayloadPlan(context.Background(), c, []preparedPayload{second}); storeErr != nil || !changed {
		t.Fatalf("replacement store changed=%t err=%v", changed, storeErr)
	}
	if _, statErr := os.Stat(c.object(asset{SHA256: first.Entry.SHA256})); !os.IsNotExist(statErr) {
		t.Fatalf("replaced payload object retained: %v", statErr)
	}
	if _, statErr := os.Stat(c.object(asset{SHA256: second.Entry.SHA256})); statErr != nil {
		t.Fatalf("active payload object absent: %v", statErr)
	}
	if err = removePayload(c, []string{second.Entry.Destination}); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(c.object(asset{SHA256: second.Entry.SHA256})); !os.IsNotExist(statErr) {
		t.Fatalf("removed payload object retained: %v", statErr)
	}
}

func TestAdmissionResetRetriesExactlyOnce(t *testing.T) {
	var output strings.Builder
	attempts := 0
	err := retryAdmissionReset(&output, func() error {
		attempts++
		if attempts == 1 {
			return context.DeadlineExceeded
		}
		return nil
	})
	if err != nil || attempts != 2 || !strings.Contains(output.String(), "second reset pulse") {
		t.Fatalf("bounded successful retry attempts=%d output=%q err=%v", attempts, output.String(), err)
	}
	attempts = 0
	err = retryAdmissionReset(io.Discard, func() error {
		attempts++
		return context.DeadlineExceeded
	})
	if err == nil || attempts != 2 || !strings.Contains(err.Error(), "after two reset attempts") {
		t.Fatalf("bounded failed retry attempts=%d err=%v", attempts, err)
	}
}
