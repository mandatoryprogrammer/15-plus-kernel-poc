package main

import (
	"bytes"
	"context"
	"debug/macho"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParsePayloadRunOwnsArgumentsAndIncludes(t *testing.T) {
	source, destination, includes, nativeExecutables, environment, arguments, err := parsePayloadRun([]string{
		"tool", "--dest", "/usr/local/bin/ui-tool",
		"--include", "libui.dylib=/usr/local/lib/libui.dylib",
		"--preserve-native", "hidd.nonui=/usr/local/libexec/productos-hidd.nonui",
		"--env", "DYLD_FRAMEWORK_PATH=/usr/local/lib",
		"--", "--frame", "caller value",
	})
	if err != nil {
		t.Fatal(err)
	}
	if source != "tool" || destination != "/usr/local/bin/ui-tool" || len(includes) != 1 ||
		includes[0] != [2]string{"libui.dylib", "/usr/local/lib/libui.dylib"} ||
		len(nativeExecutables) != 1 || nativeExecutables[0] != [2]string{"hidd.nonui", "/usr/local/libexec/productos-hidd.nonui"} ||
		len(environment) != 1 || environment[0] != "DYLD_FRAMEWORK_PATH=/usr/local/lib" ||
		len(arguments) != 2 || arguments[0] != "--frame" || arguments[1] != "caller value" {
		t.Fatalf("parsed run changed: source=%q destination=%q includes=%v native=%v environment=%v arguments=%v", source, destination, includes, nativeExecutables, environment, arguments)
	}
	if _, _, _, _, _, _, err = parsePayloadRun([]string{"tool", "unquoted-target-argument"}); err == nil {
		t.Fatal("target argument without -- accepted")
	}
	if _, _, _, _, _, _, err = parsePayloadRun([]string{"tool", "--env", "BAD-NAME=value"}); err == nil {
		t.Fatal("invalid environment accepted")
	}
	if _, _, err = splitPayloadInclude("lib=/tmp/lib"); err == nil {
		t.Fatal("unsafe include destination accepted")
	}
}

func nativeExecutableFixture(t *testing.T, fileType macho.Type) []byte {
	t.Helper()
	signed, err := adHocSignExecutable(unsignedRuntimeMachOFixture(fileType), "native-preserve-fixture")
	if err != nil {
		t.Fatal(err)
	}
	signed, changed, err := addDeterministicLCUUID(signed)
	if err != nil || !changed {
		t.Fatalf("add fixture LC_UUID changed=%t err=%v", changed, err)
	}
	signature, directory := runtimeSignatureForTest(t, signed)
	be := binary.BigEndian
	be.PutUint32(directory[12:], be.Uint32(directory[12:])&^codeDirectoryAdHocFlag)
	count := int(be.Uint32(signature[8:]))
	for index := 0; index < count; index++ {
		row := signature[12+index*8:]
		if be.Uint32(row) != codeSignatureCMSSlot {
			continue
		}
		offset := int(be.Uint32(row[4:]))
		if offset+12 > len(signature) || be.Uint32(signature[offset:]) != 0xfade0b01 {
			t.Fatal("fixture CMS slot is invalid")
		}
		be.PutUint32(signature[offset+4:], 12)
		copy(signature[offset+8:offset+12], []byte{0x30, 0x02, 0x05, 0x00})
		if superSize := int(be.Uint32(signature[4:])); superSize < offset+12 {
			be.PutUint32(signature[4:], uint32(offset+12))
		}
		if _, inspectErr := inspectExecutable(signed); inspectErr != nil {
			t.Fatalf("native fixture signature invalid: %v", inspectErr)
		}
		return signed
	}
	t.Fatal("fixture CMS slot is absent")
	return nil
}

func TestPrepareNativeExecutablePreservesExactSignedBytes(t *testing.T) {
	root := t.TempDir()
	body := nativeExecutableFixture(t, macho.TypeExec)
	source := filepath.Join(root, "native-hidd")
	if err := os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareNativeExecutable(source, "/usr/local/libexec/productos-hidd.nonui")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prepared.Body, body) || prepared.Entry.SHA256 != digest(body) ||
		prepared.Entry.Size != int64(len(body)) || len(prepared.Entry.CDHash) != 40 ||
		!prepared.Entry.BytePreserved || !prepared.Entry.NativeSignature ||
		prepared.Signed || prepared.LCUUIDAdded || prepared.LinkerSigned || prepared.FileType != macho.TypeExec {
		t.Fatalf("native executable was not preserved exactly: %+v", prepared)
	}
	if _, err = preparePayload(source, "/usr/local/libexec/productos-hidd.nonui"); err == nil || !strings.Contains(err.Error(), "not ad-hoc") {
		t.Fatalf("ordinary normalization unexpectedly accepted native signature: %v", err)
	}

	mutated := bytes.Clone(body)
	mutated[0x200] ^= 1
	mutatedSource := filepath.Join(root, "mutated-native")
	if err = os.WriteFile(mutatedSource, mutated, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = prepareNativeExecutable(mutatedSource, "/usr/local/libexec/mutated-native"); err == nil || !strings.Contains(err.Error(), "code signature page") {
		t.Fatalf("mutated native code was accepted: %v", err)
	}

	adHocFlags := bytes.Clone(body)
	_, directory := runtimeSignatureForTest(t, adHocFlags)
	binary.BigEndian.PutUint32(directory[12:], binary.BigEndian.Uint32(directory[12:])|codeDirectoryAdHocFlag)
	adHocFlagsSource := filepath.Join(root, "native-with-ad-hoc-flags")
	if err = os.WriteFile(adHocFlagsSource, adHocFlags, 0600); err != nil {
		t.Fatal(err)
	}
	preparedAdHoc, err := prepareNativeExecutable(adHocFlagsSource,
		"/usr/local/libexec/native-with-ad-hoc-flags")
	if err != nil || !bytes.Equal(preparedAdHoc.Body, adHocFlags) ||
		!preparedAdHoc.Entry.BytePreserved || !preparedAdHoc.Entry.NativeSignature {
		t.Fatalf("valid ad-hoc CodeDirectory was not preserved: %+v err=%v",
			preparedAdHoc, err)
	}

	badCMS := bytes.Clone(body)
	signature, _ := runtimeSignatureForTest(t, badCMS)
	for index := 0; index < int(binary.BigEndian.Uint32(signature[8:])); index++ {
		row := signature[12+index*8:]
		if binary.BigEndian.Uint32(row) == codeSignatureCMSSlot {
			offset := int(binary.BigEndian.Uint32(row[4:]))
			signature[offset] ^= 1
		}
	}
	badCMSSource := filepath.Join(root, "native-with-bad-cms")
	if err = os.WriteFile(badCMSSource, badCMS, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = prepareNativeExecutable(badCMSSource, "/usr/local/libexec/native-with-bad-cms"); err == nil || !strings.Contains(err.Error(), "CMS") {
		t.Fatalf("invalid CMS envelope was accepted: %v", err)
	}

	dylibSource := filepath.Join(root, "native-dylib")
	if err = os.WriteFile(dylibSource, nativeExecutableFixture(t, macho.TypeDylib), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = prepareNativeExecutable(dylibSource, "/usr/local/libexec/native-dylib"); err == nil || !strings.Contains(err.Error(), "not an executable") {
		t.Fatalf("native dylib was accepted as an executable: %v", err)
	}

}

func TestPrepareNativeExecutableAcceptsAdHocCodeDirectoryWithEmptyCMSWrapper(t *testing.T) {
	root := t.TempDir()
	body := nativeExecutableFixture(t, macho.TypeExec)
	signature, directory := runtimeSignatureForTest(t, body)
	be := binary.BigEndian
	be.PutUint32(directory[12:], be.Uint32(directory[12:])|codeDirectoryAdHocFlag)
	for index := 0; index < int(be.Uint32(signature[8:])); index++ {
		row := signature[12+index*8:]
		if be.Uint32(row) != codeSignatureCMSSlot {
			continue
		}
		offset := int(be.Uint32(row[4:]))
		if offset > len(signature)-8 || be.Uint32(signature[offset:]) != 0xfade0b01 {
			t.Fatal("fixture CMS slot is invalid")
		}
		be.PutUint32(signature[offset+4:], 8)
		be.PutUint32(signature[4:], uint32(offset+8))
		source := filepath.Join(root, "native-empty-cms")
		if err := os.WriteFile(source, body, 0600); err != nil {
			t.Fatal(err)
		}
		prepared, err := prepareNativeExecutable(source,
			"/usr/local/libexec/productos-hidd.nonui")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(prepared.Body, body) || !prepared.Entry.BytePreserved ||
			!prepared.Entry.NativeSignature {
			t.Fatalf("empty CMS wrapper input was not preserved: %+v", prepared)
		}
		return
	}
	t.Fatal("fixture CMS slot is absent")
}

func TestPrepareNativeExecutableExactExternalIntegration(t *testing.T) {
	const (
		enableInput = "NATIVE_EXECUTABLE_INTEGRATION"
		pathInput   = "NATIVE_EXECUTABLE_PATH"
		shaInput    = "NATIVE_EXECUTABLE_SHA256"
	)
	enabled := os.Getenv(enableInput)
	if enabled == "" {
		return
	}
	if enabled != "1" {
		t.Fatalf("%s must equal 1 when set", enableInput)
	}
	source, expectedSHA := os.Getenv(pathInput), os.Getenv(shaInput)
	if !filepath.IsAbs(source) || len(expectedSHA) != 64 {
		t.Fatalf("explicit integration requires absolute %s and 64-character %s",
			pathInput, shaInput)
	}
	body, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if got := digest(body); got != expectedSHA {
		t.Fatalf("external native executable sha256=%s want=%s", got, expectedSHA)
	}
	prepared, err := prepareNativeExecutable(source,
		"/usr/local/libexec/productos-hidd.nonui")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prepared.Body, body) || prepared.Entry.SHA256 != expectedSHA ||
		prepared.Entry.Size != int64(len(body)) || !prepared.Entry.BytePreserved ||
		!prepared.Entry.NativeSignature {
		t.Fatalf("external native executable was not preserved exactly: %+v", prepared)
	}
}

func TestPayloadPlanRequiresPairedNativePreservationIdentity(t *testing.T) {
	entry := payloadEntry{
		Destination: "/usr/local/libexec/native", SHA256: strings.Repeat("a", 64),
		Size: 1, CDHash: strings.Repeat("b", 40), BytePreserved: true, NativeSignature: true,
	}
	if _, err := payloadPlan(nil, []payloadEntry{entry}, payloadLimit); err != nil {
		t.Fatalf("complete native preservation identity rejected: %v", err)
	}
	for _, mutate := range []func(*payloadEntry){
		func(value *payloadEntry) { value.BytePreserved = false },
		func(value *payloadEntry) { value.NativeSignature = false },
	} {
		candidate := entry
		mutate(&candidate)
		if _, err := payloadPlan(nil, []payloadEntry{candidate}, payloadLimit); err == nil || !strings.Contains(err.Error(), "byte-preserved native") {
			t.Fatalf("split native preservation identity accepted: %+v err=%v", candidate, err)
		}
	}
}

func TestPayloadExecutionTimeoutAppliesOnlyWhenExplicit(t *testing.T) {
	base := context.Background()
	if timeout := payloadExecutionTimeout(base); timeout != 0 {
		t.Fatalf("plain context has execution timeout %s", timeout)
	}
	bounded := withPayloadExecutionTimeout(base, 7*time.Second)
	if timeout := payloadExecutionTimeout(bounded); timeout != 7*time.Second {
		t.Fatalf("execution timeout=%s, want 7s", timeout)
	}
	if _, ok := bounded.Deadline(); ok {
		t.Fatal("execution metadata unexpectedly shortened boot/transfer context")
	}
	if timeout := payloadExecutionTimeout(withPayloadExecutionTimeout(base, -time.Second)); timeout != 0 {
		t.Fatalf("negative execution timeout was accepted: %s", timeout)
	}
}

func TestPayloadExecutionSerialCaptureIsExplicitAndBindsIdentity(t *testing.T) {
	base := context.Background()
	if payloadExecutionSerialCapture(base) != nil {
		t.Fatal("plain context requested execution UART capture")
	}
	evidence := &payloadExecutionSerialEvidence{}
	bounded := withPayloadExecutionSerialCapture(base, evidence)
	if payloadExecutionSerialCapture(bounded) != evidence {
		t.Fatal("execution UART evidence pointer was not preserved")
	}
	body := []byte("launchd execution UART\n")
	path := filepath.Join(t.TempDir(), "serial.log")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := bindPayloadExecutionSerialEvidence(evidence, path); err != nil {
		t.Fatal(err)
	}
	if evidence.Path != path || evidence.Bytes != int64(len(body)) ||
		evidence.SHA256 != digest(body) {
		t.Fatalf("execution UART identity changed: %+v", evidence)
	}
}

func TestPayloadExecutionSerialDrainTrackerRequiresQuietAfterLastGrowth(t *testing.T) {
	start := time.Unix(100, 0)
	tracker := newPayloadExecutionSerialDrainTracker(start, 100)
	quiet := 500 * time.Millisecond
	if tracker.observe(start.Add(499*time.Millisecond), 100, quiet) {
		t.Fatal("initial short quiet interval completed the drain")
	}
	if tracker.observe(start.Add(500*time.Millisecond), 120, quiet) {
		t.Fatal("log growth completed the drain")
	}
	if tracker.observe(start.Add(999*time.Millisecond), 120, quiet) {
		t.Fatal("quiet interval was measured from capture start instead of last growth")
	}
	if !tracker.observe(start.Add(time.Second), 120, quiet) {
		t.Fatal("complete post-growth quiet interval did not finish the drain")
	}
	if payloadExecutionSerialDrainLimit > 5*time.Second ||
		payloadExecutionSerialDrainLimit < payloadExecutionSerialDrainQuiet {
		t.Fatalf("invalid bounded drain quiet=%s limit=%s",
			payloadExecutionSerialDrainQuiet, payloadExecutionSerialDrainLimit)
	}
}

func TestPayloadExecutionDeadlineClassificationHandlesSSHExitRace(t *testing.T) {
	exitErr := errors.New("remote process exited with signal KILL")
	timeout := 10 * time.Second
	if payloadExecutionDeadlineReached(context.Background(), nil, timeout, timeout) {
		t.Fatal("successful target exit classified as timeout")
	}
	if payloadExecutionDeadlineReached(context.Background(), exitErr, 9*time.Second, timeout) {
		t.Fatal("early target failure classified as timeout")
	}
	if !payloadExecutionDeadlineReached(context.Background(), exitErr, timeout-100*time.Millisecond, timeout) {
		t.Fatal("near-deadline SSH signal race was not classified as timeout")
	}
	deadline, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if !payloadExecutionDeadlineReached(deadline, exitErr, time.Second, timeout) {
		t.Fatal("expired execution context was not classified as timeout")
	}
}

type signaledPayloadExit struct{ signal string }

func (exit signaledPayloadExit) Error() string  { return "remote signal " + exit.signal }
func (exit signaledPayloadExit) Signal() string { return exit.signal }

func TestPayloadExecutionKilledClassificationIsStructured(t *testing.T) {
	if !payloadExecutionWasKilled(signaledPayloadExit{signal: "KILL"}) {
		t.Fatal("structured remote KILL was not classified")
	}
	for _, err := range []error{nil, signaledPayloadExit{signal: "TERM"}, errors.New("Process exited with status 137 from signal KILL")} {
		if payloadExecutionWasKilled(err) {
			t.Fatalf("non-structured or different terminal was classified as KILL: %v", err)
		}
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
	unsigned := unsignedRuntimeMachOFixture(2)
	if err := os.WriteFile(source, unsigned, 0600); err != nil {
		t.Fatal(err)
	}
	prepared, err := preparePayload(source, "/usr/local/bin/probe")
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Entry.CDHash == "" || prepared.Entry.SHA256 == "" || prepared.FileType != 2 || !prepared.Signed || !prepared.LCUUIDAdded || !prepared.LinkerSigned {
		t.Fatalf("prepared payload changed: %+v", prepared)
	}
	if flags := primaryCodeDirectoryFlagsForTest(t, prepared.Body); flags&2 == 0 || flags&callerLinkerSignedFlag == 0 {
		t.Fatalf("caller admission flags=%#x", flags)
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
	secondSource := filepath.Join(root, "probe-two")
	if err = os.WriteFile(secondSource, unsigned, 0600); err != nil {
		t.Fatal(err)
	}
	secondPayload, err := preparePayload(secondSource, "/usr/local/bin/probe-two")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = storePayloadPlan(context.Background(), c, []preparedPayload{secondPayload}); err != nil {
		t.Fatal(err)
	}
	unchanged, err := payloadAdmissionFingerprint(c)
	if err != nil || unchanged != first {
		t.Fatalf("caller payload changed boot policy fingerprint: first=%s second=%s err=%v", first, unchanged, err)
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

func primaryCodeDirectoryFlagsForTest(t *testing.T, body []byte) uint32 {
	t.Helper()
	le, be := binary.LittleEndian, binary.BigEndian
	at := 32
	for index := 0; index < int(le.Uint32(body[16:])); index++ {
		size := int(le.Uint32(body[at+4:]))
		if le.Uint32(body[at:]) == 0x1d {
			offset := int(le.Uint32(body[at+8:]))
			signature := body[offset : offset+int(le.Uint32(body[at+12:]))]
			for entry := 0; entry < int(be.Uint32(signature[8:])); entry++ {
				row := signature[12+entry*8:]
				if be.Uint32(row) == 0 {
					return be.Uint32(signature[int(be.Uint32(row[4:]))+12:])
				}
			}
		}
		at += size
	}
	t.Fatal("primary CodeDirectory absent")
	return 0
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

func TestPayloadExecutableSlotProbeFailsClosed(t *testing.T) {
	ready, err := parsePayloadExecutableSlotProbe([]byte("ready\n"))
	if err != nil || !ready {
		t.Fatalf("ready probe ready=%t err=%v", ready, err)
	}
	ready, err = parsePayloadExecutableSlotProbe([]byte("unprepared\n"))
	if err != nil || ready {
		t.Fatalf("unprepared probe ready=%t err=%v", ready, err)
	}
	for _, output := range [][]byte{nil, []byte("ready"), []byte("ready\nunprepared\n"), []byte("unknown\n")} {
		if ready, err = parsePayloadExecutableSlotProbe(output); err == nil || ready {
			t.Fatalf("ambiguous probe %q accepted: ready=%t err=%v", output, ready, err)
		}
	}
}
