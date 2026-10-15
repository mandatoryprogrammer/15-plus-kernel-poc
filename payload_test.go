package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

func trustFixture(hashes ...byte) []byte {
	return trustFixtureVersion(1, hashes...)
}

func trustFixtureVersion(version uint32, hashes ...byte) []byte {
	_, rowSize, err := trustCacheRow(version, make([]byte, 20))
	if err != nil {
		panic(err)
	}
	payload := make([]byte, 24, 24+len(hashes)*rowSize)
	binary.LittleEndian.PutUint32(payload, version)
	binary.LittleEndian.PutUint32(payload[20:], uint32(len(hashes)))
	for _, value := range hashes {
		row, _, _ := trustCacheRow(version, bytes.Repeat([]byte{value}, 20))
		payload = append(payload, row...)
	}
	body := bytes.Join([][]byte{encodeDER(0x16, []byte("IM4P")), encodeDER(0x16, []byte("rtsc")), encodeDER(0x16, []byte("1")), encodeDER(4, payload)}, nil)
	return encodeDER(0x30, body)
}

func TestTrustExtensionPreservesSupportedFormats(t *testing.T) {
	for _, version := range []uint32{0, 1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			fixture := trustFixtureVersion(version, 0x10, 0x30)
			got, err := extendTrustCache(fixture, []payloadEntry{{Destination: "/usr/local/bin/x", CDHash: strings.Repeat("20", 20)}})
			if err != nil {
				t.Fatal(err)
			}
			fields, _ := imageFields(got, "IM4P")
			payload := fields[3].body
			_, rowSize, _ := trustCacheRow(version, make([]byte, 20))
			if binary.LittleEndian.Uint32(payload[:4]) != version || len(payload) != 24+3*rowSize || payload[24+rowSize] != 0x20 {
				t.Fatalf("version %d layout changed: %x", version, payload)
			}
		})
	}
}

func TestTrustExtensionPreservesPreimageAndOrdering(t *testing.T) {
	fixture := trustFixture(0x10, 0x30)
	if got, err := extendTrustCache(fixture, []payloadEntry{{CDHash: strings.Repeat("10", 20)}}); err != nil || !bytes.Equal(got, fixture) {
		t.Fatal("existing trust entry changed the image", err)
	}
	got, err := extendTrustCache(fixture, []payloadEntry{{Destination: "/usr/local/bin/x", CDHash: strings.Repeat("20", 20)}})
	if err != nil {
		t.Fatal(err)
	}
	fields, _ := imageFields(got, "IM4P")
	payload := fields[3].body
	if binary.LittleEndian.Uint32(payload[20:24]) != 3 || payload[24] != 0x10 || payload[46] != 0x20 || payload[68] != 0x30 {
		t.Fatalf("entry insertion is not sorted: %x", payload[24:])
	}
}

func putPattern(image []byte, offset int, pattern []semanticInstruction) {
	for index, instruction := range pattern {
		binary.LittleEndian.PutUint32(image[offset+index*4:], instruction.value)
	}
}

func TestRuntimeLayoutIsDerivedFromAuthenticatedInstructions(t *testing.T) {
	image := make([]byte, 0x5000)
	build := "iBoot-test.runtime"
	copy(image[0x280:], append([]byte(build), 0))
	copy(image[0x3800:], append([]byte(build), 0)) // Diagnostic text outside the header may repeat the build.
	policy := []semanticInstruction{
		exactInstruction(0x910f43e1), exactInstruction(0x910323e4),
		exactInstruction(0xaa1303e0), exactInstruction(0xaa1603e3),
		exactInstruction(0x94000000), exactInstruction(0x34000060),
		exactInstruction(0x51007b14), exactInstruction(0x14000000),
	}
	root := []semanticInstruction{
		exactInstruction(0x52888a80), exactInstruction(0x72a78aa0),
		exactInstruction(0x52800001), exactInstruction(0x94000000),
		exactInstruction(0x90000003), exactInstruction(0x91146063),
		exactInstruction(0x94000000), exactInstruction(0x94000000),
		exactInstruction(0xaa0003f4),
	}
	putPattern(image, 0x1200, policy)
	putPattern(image, 0x2000, root)
	root[len(root)-1] = exactInstruction(0xaa0003f5)
	putPattern(image, 0x2200, root)
	identity := artifactIdentity{DecodedSize: len(image), DecodedSHA256: digest(image)}
	layout, edit, err := analyzeRuntimeIBEC(image, identity, build)
	if err != nil {
		t.Fatal(err)
	}
	if edit.Offset != 0x1214 || edit.Before != "60000034" || edit.After != "03000014" || layout.BuildOffset != 0x280 || len(layout.RootCalls) != 2 || layout.RootCalls[0] != 0x201c || layout.RootCalls[1] != 0x221c {
		t.Fatalf("unexpected runtime resolution: layout=%+v edit=%+v", layout, edit)
	}
	onePath := bytes.Clone(image)
	clear(onePath[0x2200 : 0x2200+len(root)*4])
	oneIdentity := artifactIdentity{DecodedSize: len(onePath), DecodedSHA256: digest(onePath)}
	oneLayout, _, err := analyzeRuntimeIBEC(onePath, oneIdentity, build)
	if err != nil || len(oneLayout.RootCalls) != 1 || oneLayout.RootCalls[0] != 0x201c {
		t.Fatalf("single derived root path: layout=%+v err=%v", oneLayout, err)
	}
	threePaths := bytes.Clone(image)
	putPattern(threePaths, 0x2400, root)
	threeIdentity := artifactIdentity{DecodedSize: len(threePaths), DecodedSHA256: digest(threePaths)}
	if _, _, err = analyzeRuntimeIBEC(threePaths, threeIdentity, build); err == nil {
		t.Fatal("unbounded root path set accepted")
	}
	image[0x1217] = 0
	identity.DecodedSHA256 = digest(image)
	if _, _, err = analyzeRuntimeIBEC(image, identity, build); err == nil {
		t.Fatal("missing runtime instruction relationship was accepted")
	}
}

func TestPayloadComposition(t *testing.T) {
	base, err := basePayload()
	if err != nil {
		t.Fatal(err)
	}
	commands, err := builtInCommands()
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{
		"/usr/bin/commands": false,
		"/usr/bin/env":      false,
		"/usr/bin/find":     false,
		"/usr/bin/grep":     false,
		"/usr/bin/id":       false,
		"/usr/bin/ls":       false,
		"/usr/bin/ps":       false,
		"/usr/bin/storage":  false,
		"/usr/bin/uname":    false,
		"/usr/bin/whoami":   false,
	}
	found := map[string]payloadEntry{}
	for _, entry := range base {
		found[entry.Destination] = entry
	}
	for _, command := range commands {
		entry, ok := found[command.Destination]
		if !ok || entry.SHA256 != digest(command.Body) || entry.Size != int64(len(command.Body)) || entry.Origin != "built-in shell command" {
			t.Fatalf("built-in command does not match payload inventory: %s", command.Destination)
		}
		if _, ok = required[command.Destination]; ok {
			required[command.Destination] = true
		}
	}
	for destination, present := range required {
		if !present {
			t.Errorf("required built-in command is missing: %s", destination)
		}
	}
	a := payloadEntry{Destination: "/usr/local/bin/example", SHA256: strings.Repeat("a", 64), CDHash: strings.Repeat("b", 40), Size: 4097}
	if _, err := payloadPlan(base, []payloadEntry{a}, 8192); err != nil {
		t.Fatal(err)
	}
	if _, err := payloadPlan(base, []payloadEntry{a}, 8191); err == nil {
		t.Fatal("capacity rounding ignored")
	}
	if _, err := payloadPlan(base, []payloadEntry{a, a}, 16384); err == nil {
		t.Fatal("duplicate accepted")
	}
	for _, dest := range []string{"/bin/sh", "/usr/local/bin/../bad", "/usr/local/bin/a/b", "/tmp/tool", "/usr/local/bin/a\x00b"} {
		copy := a
		copy.Destination = dest
		if _, err := payloadPlan(base, []payloadEntry{copy}, 1<<20); err == nil {
			t.Errorf("accepted %q", dest)
		}
	}
	for dest := range reservedPayloadDestinations {
		copy := a
		copy.Destination = dest
		if _, err := payloadPlan(base, []payloadEntry{copy}, 1<<20); err == nil {
			t.Errorf("accepted reserved destination %q", dest)
		}
	}
}

func TestPackedPlatformVersionComesFromRuntimeProfile(t *testing.T) {
	for value, want := range map[string]uint32{
		"26.3":   0x001a0300,
		"17.4.1": 0x00110401,
	} {
		got, err := packedPlatformVersion(value)
		if err != nil || got != want {
			t.Fatalf("packed %q as 0x%x: %v", value, got, err)
		}
	}
	for _, value := range []string{"26", "26.3.1.2", "26.256", "x.3"} {
		if _, err := packedPlatformVersion(value); err == nil {
			t.Fatalf("accepted invalid version %q", value)
		}
	}
}

// A minimal synthetic iOS Mach-O: two load commands, one signed code page.
func signedFixture(platform uint32) []byte {
	b := make([]byte, 80+20+44+32)
	le, be := binary.LittleEndian, binary.BigEndian
	for i, v := range []uint32{0xfeedfacf, 0x100000c, 0, 2, 2, 40, 0, 0, 0x32, 24, platform, 0x1a0000, 0x1a0000, 0, 0x1d, 16, 80, 96} {
		le.PutUint32(b[i*4:], v)
	}
	sig := b[80:]
	be.PutUint32(sig, 0xfade0cc0)
	be.PutUint32(sig[4:], 96)
	be.PutUint32(sig[8:], 1)
	be.PutUint32(sig[16:], 20)
	cd := sig[20:]
	be.PutUint32(cd, 0xfade0c02)
	be.PutUint32(cd[4:], 76)
	be.PutUint32(cd[8:], 0x20100)
	be.PutUint32(cd[12:], 2)
	be.PutUint32(cd[16:], 44)
	be.PutUint32(cd[28:], 1)
	be.PutUint32(cd[32:], 80)
	cd[36] = 32
	cd[37] = 2
	cd[39] = 12
	h := sha256.Sum256(b[:80])
	copy(cd[44:], h[:])
	return b
}

func TestExecutableArchitectureAndCodePages(t *testing.T) {
	b := signedFixture(2)
	hash, err := inspectExecutable(b)
	if err != nil || len(hash) != 40 {
		t.Fatalf("valid iOS executable: %s %v", hash, err)
	}
	b[73] ^= 1
	if _, err := inspectExecutable(b); err == nil {
		t.Fatal("modified signed page accepted")
	}
	if _, err := inspectExecutable(signedFixture(1)); err == nil {
		t.Fatal("macOS executable accepted")
	}
	b = signedFixture(2)
	binary.LittleEndian.PutUint32(b[4:], 0x1000007)
	if _, err := inspectExecutable(b); err == nil {
		t.Fatal("Intel executable accepted")
	}
	if _, err := inspectExecutable([]byte("#! /bin/sh")); err == nil {
		t.Fatal("script accepted")
	}
	b = signedFixture(2)
	binary.LittleEndian.PutUint32(b[32:], 0x25)
	binary.LittleEndian.PutUint32(b[40:], 0x1a0400)
	if _, err := inspectExecutable(b); err == nil || !strings.Contains(err.Error(), "newer than 26.3") {
		t.Fatalf("newer LC_VERSION_MIN_IPHONEOS accepted: %v", err)
	}
}

func TestNativeAdHocSigning(t *testing.T) {
	b := make([]byte, 96)
	le := binary.LittleEndian
	for i, value := range []uint32{0xfeedfacf, 0x100000c, 0, 2, 1, 24, 0, 0, 0x32, 24, 2, 0x1a0000, 0x1a0000, 0} {
		le.PutUint32(b[i*4:], value)
	}
	signed, err := adHocSignExecutable(b, "example")
	if err != nil {
		t.Fatal(err)
	}
	if hash, err := inspectExecutable(signed); err != nil || len(hash) != 40 {
		t.Fatalf("native signature rejected: %q %v", hash, err)
	}
	signed[90] ^= 1
	if _, err := inspectExecutable(signed); err == nil {
		t.Fatal("native signature accepted modified code")
	}
}
