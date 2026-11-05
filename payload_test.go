package main

import (
	"bytes"
	"crypto/sha256"
	"debug/macho"
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
	return signedFixtureType(platform, macho.TypeExec)
}

func signedFixtureType(platform uint32, fileType macho.Type) []byte {
	b := make([]byte, 80+20+44+32)
	le, be := binary.LittleEndian, binary.BigEndian
	for i, v := range []uint32{0xfeedfacf, 0x100000c, 0, uint32(fileType), 2, 40, 0, 0, 0x32, 24, platform, 0x1a0000, 0x1a0000, 0, 0x1d, 16, 80, 96} {
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

func TestSignedDylibArchitectureAndCodePages(t *testing.T) {
	b := signedFixtureType(2, macho.TypeDylib)
	hash, err := inspectExecutable(b)
	if err != nil || len(hash) != 40 {
		t.Fatalf("valid iOS dylib: %s %v", hash, err)
	}
	if _, err := inspectExecutable(signedFixtureType(2, macho.TypeBundle)); err == nil {
		t.Fatal("Mach-O bundle accepted as a payload trust input")
	}
	b[73] ^= 1
	if _, err := inspectExecutable(b); err == nil {
		t.Fatal("modified signed dylib page accepted")
	}
}

func TestSignedDynamicLinkerArchitectureAndCodePages(t *testing.T) {
	b := signedFixtureType(2, machoTypeDylinker)
	hash, err := inspectExecutable(b)
	if err != nil || len(hash) != 40 {
		t.Fatalf("valid iOS dynamic linker: %s %v", hash, err)
	}
	b[73] ^= 1
	if _, err := inspectExecutable(b); err == nil {
		t.Fatal("modified signed dynamic-linker page accepted")
	}
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

func unsignedRuntimeMachOFixture(fileType macho.Type) []byte {
	return unsignedRuntimeMachOFixtureSize(fileType, 0x4000)
}

func unsignedRuntimeMachOFixtureSize(fileType macho.Type, textFileSize int) []byte {
	const linkeditSize = 0x20
	b := make([]byte, textFileSize+linkeditSize)
	le := binary.LittleEndian
	for index, value := range []uint32{
		0xfeedfacf, 0x100000c, 0, uint32(fileType), 3, 168, 0, 0,
	} {
		le.PutUint32(b[index*4:], value)
	}
	putSegment := func(at int, name string, vmaddr, vmSize, fileOffset, fileSize uint64, protections uint32) {
		le.PutUint32(b[at:], 0x19)
		le.PutUint32(b[at+4:], 72)
		copy(b[at+8:at+24], name)
		le.PutUint64(b[at+24:], vmaddr)
		le.PutUint64(b[at+32:], vmSize)
		le.PutUint64(b[at+40:], fileOffset)
		le.PutUint64(b[at+48:], fileSize)
		le.PutUint32(b[at+56:], protections)
		le.PutUint32(b[at+60:], protections)
	}
	putSegment(32, "__TEXT", 0x100000000, uint64(textFileSize), 0, uint64(textFileSize), 5)
	putSegment(104, "__LINKEDIT", 0x100000000+uint64(textFileSize), 0x4000, uint64(textFileSize), linkeditSize, 1)
	le.PutUint32(b[176:], 0x32)
	le.PutUint32(b[180:], 24)
	le.PutUint32(b[184:], 2)
	le.PutUint32(b[188:], 0x1a0000)
	le.PutUint32(b[192:], 0x1a0000)
	copy(b[textFileSize:], []byte("deterministic-linkedit-fixture"))
	return b
}

func runtimeSignatureForTest(t *testing.T, body []byte) ([]byte, []byte) {
	t.Helper()
	le, be := binary.LittleEndian, binary.BigEndian
	at := 32
	for index := 0; index < int(le.Uint32(body[16:])); index++ {
		size := int(le.Uint32(body[at+4:]))
		if le.Uint32(body[at:]) == 0x1d {
			offset, signatureSize := int(le.Uint32(body[at+8:])), int(le.Uint32(body[at+12:]))
			signature := body[offset : offset+signatureSize]
			for entry := 0; entry < int(be.Uint32(signature[8:])); entry++ {
				row := signature[12+entry*8:]
				if be.Uint32(row) == 0 {
					codeOffset := int(be.Uint32(row[4:]))
					codeSize := int(be.Uint32(signature[codeOffset+4:]))
					return signature, signature[codeOffset : codeOffset+codeSize]
				}
			}
		}
		at += size
	}
	t.Fatal("runtime signature lacks a primary CodeDirectory")
	return nil, nil
}

func TestNativeAdHocSigning(t *testing.T) {
	for _, fileType := range []macho.Type{macho.TypeExec, macho.TypeDylib, machoTypeDylinker} {
		b := unsignedRuntimeMachOFixture(fileType)
		signed, err := adHocSignExecutable(b, "example")
		if err != nil {
			t.Fatal(err)
		}
		if hash, err := inspectExecutable(signed); err != nil || len(hash) != 40 {
			t.Fatalf("native signature rejected type=%d: %q %v", fileType, hash, err)
		}
		signed[0x200] ^= 1
		if _, err := inspectExecutable(signed); err == nil {
			t.Fatalf("native signature accepted modified code type=%d", fileType)
		}
	}
}

func TestNativeAdHocSigningUsesRuntimeCompatibleEnvelope(t *testing.T) {
	be := binary.BigEndian
	for _, fileType := range []macho.Type{macho.TypeExec, macho.TypeDylib, machoTypeDylinker} {
		signed, err := adHocSignExecutable(unsignedRuntimeMachOFixture(fileType), "runtime-envelope")
		if err != nil {
			t.Fatal(err)
		}
		signature, directory := runtimeSignatureForTest(t, signed)
		if len(signature) != codeSignatureMinimumBytes || int(be.Uint32(signature[4:])) >= len(signature) || !bytes.Equal(signature[be.Uint32(signature[4:]):], make([]byte, len(signature)-int(be.Uint32(signature[4:])))) {
			t.Fatalf("signature allocation is not bounded zero padding: bytes=%d super=%d", len(signature), be.Uint32(signature[4:]))
		}
		if be.Uint32(signature[8:]) != 3 || be.Uint32(directory[8:]) != codeDirectoryVersionExecSeg || directory[39] != codeDirectoryPagePower || be.Uint32(directory[24:]) != codeSignatureRequirementsSlot {
			t.Fatalf("runtime CodeDirectory geometry changed: count=%d version=%#x page=%d special=%d", be.Uint32(signature[8:]), be.Uint32(directory[8:]), directory[39], be.Uint32(directory[24:]))
		}
		wantExecFlags := uint64(0)
		if fileType == macho.TypeExec {
			wantExecFlags = codeDirectoryMainBinaryFlag
		}
		if be.Uint64(directory[64:]) != 0 || be.Uint64(directory[72:]) != 0x4000 || be.Uint64(directory[80:]) != wantExecFlags {
			t.Fatalf("executable-segment contract changed for type=%d: base=%#x limit=%#x flags=%#x", fileType, be.Uint64(directory[64:]), be.Uint64(directory[72:]), be.Uint64(directory[80:]))
		}
		entries := map[uint32][]byte{}
		for index := 0; index < int(be.Uint32(signature[8:])); index++ {
			row := signature[12+index*8:]
			typeID, offset := be.Uint32(row), int(be.Uint32(row[4:]))
			blobSize := int(be.Uint32(signature[offset+4:]))
			entries[typeID] = signature[offset : offset+blobSize]
		}
		requirements, cms := entries[codeSignatureRequirementsSlot], entries[codeSignatureCMSSlot]
		if len(requirements) != 12 || be.Uint32(requirements) != 0xfade0c01 || be.Uint32(requirements[8:]) != 0 || len(cms) != 8 || be.Uint32(cms) != 0xfade0b01 {
			t.Fatalf("runtime signature side blobs changed: requirements=%x cms=%x", requirements, cms)
		}
		hashOffset := int(be.Uint32(directory[16:]))
		requirementsHash := sha256.Sum256(requirements)
		if !bytes.Equal(directory[hashOffset-2*sha256.Size:hashOffset-sha256.Size], requirementsHash[:]) {
			t.Fatal("requirements special slot is not content-bound")
		}
		if _, changed, err := enableCallerLinkerSigned(signed); err != nil || changed {
			t.Fatalf("runtime envelope was not idempotently admitted: changed=%t err=%v", changed, err)
		}
	}
}

func TestCallerAdmissionRejectsLegacyNormalizerGeometry(t *testing.T) {
	be := binary.BigEndian
	baseline, err := adHocSignExecutable(unsignedRuntimeMachOFixture(macho.TypeExec), "fail-closed")
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte){
		"legacy-version":    func(directory []byte) { be.PutUint32(directory[8:], 0x20001) },
		"unsupported-pages": func(directory []byte) { directory[39] = 13 },
		"wrong-exec-limit":  func(directory []byte) { be.PutUint64(directory[72:], 0x3fff) },
		"missing-main-flag": func(directory []byte) { be.PutUint64(directory[80:], 0) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := bytes.Clone(baseline)
			_, directory := runtimeSignatureForTest(t, candidate)
			mutate(directory)
			if _, _, err := enableCallerLinkerSigned(candidate); err == nil || !strings.Contains(err.Error(), "runtime-incompatible") {
				t.Fatalf("legacy or malformed caller envelope was accepted: %v", err)
			}
		})
	}
}

func TestCallerAdmissionRetainsModernFourKiBCodeDirectories(t *testing.T) {
	signed, err := adHocSignExecutable(unsignedRuntimeMachOFixtureSize(macho.TypeExec, 0x800), "four-kib-compatible")
	if err != nil {
		t.Fatal(err)
	}
	_, directory := runtimeSignatureForTest(t, signed)
	directory[39] = 12
	if _, changed, err := enableCallerLinkerSigned(signed); err != nil || changed {
		t.Fatalf("modern 4 KiB CodeDirectory was rejected: changed=%t err=%v", changed, err)
	}
}

func TestAutomaticLCUUIDRehashesExistingAdHocSignature(t *testing.T) {
	b := unsignedRuntimeMachOFixture(macho.TypeExec)
	signed, err := adHocSignExecutable(b, "missing-uuid")
	if err != nil {
		t.Fatal(err)
	}
	normalized, changed, err := addDeterministicLCUUID(signed)
	if err != nil || !changed {
		t.Fatalf("normalize LC_UUID changed=%t err=%v", changed, err)
	}
	if hash, inspectErr := inspectExecutable(normalized); inspectErr != nil || len(hash) != 40 {
		t.Fatalf("normalized signature rejected: hash=%q err=%v", hash, inspectErr)
	}
	f, err := macho.NewFile(bytes.NewReader(normalized))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	found := false
	for _, load := range f.Loads {
		if binary.LittleEndian.Uint32(load.Raw()) == 0x1b {
			found = true
		}
	}
	if !found {
		t.Fatal("normalized Mach-O lacks LC_UUID")
	}
	second, changed, err := addDeterministicLCUUID(normalized)
	if err != nil || changed || !bytes.Equal(second, normalized) {
		t.Fatalf("LC_UUID normalization is not idempotent: changed=%t err=%v", changed, err)
	}
}
