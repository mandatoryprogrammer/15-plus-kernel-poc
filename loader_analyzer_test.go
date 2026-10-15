package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

var semanticFixtureOffsets = [][]uint64{
	{0x36020}, {0x3602c}, {0x36084}, {0x362d8}, {0x361e8, 0x3620c},
	{0x37100}, {0x371e4}, {0x37394}, {0x37438}, {0x37464},
	{0x12184c},
}

const loaderFixtureSize = 6 * loaderScanChunk

func semanticFixture(t *testing.T) []byte {
	t.Helper()
	image := make([]byte, loaderFixtureSize)
	for locatorIndex, locator := range initialLoaderSemanticLocators {
		for siteIndex, offset := range semanticFixtureOffsets[locatorIndex] {
			center := int(offset)
			start := center - locator.patchIndex*4
			for wordIndex, instruction := range locator.pattern {
				at := start + wordIndex*4
				previous := binary.LittleEndian.Uint32(image[at:])
				if previous != 0 && normalizeARM64(previous)&instruction.mask != instruction.value {
					t.Fatalf("fixture locator overlap at 0x%x", at)
				}
				word := instruction.value
				switch normalized := normalizeARM64(word); {
				case normalized == 0x94000000:
					word |= uint32((locatorIndex+wordIndex+siteIndex+1)*7) & 0x03ffffff
				case normalized&0xff000010 == 0x54000000:
					word |= uint32((locatorIndex+wordIndex+siteIndex+1)*5) << 5
				case normalized&0xff00001f == 0x34000000:
					word |= uint32((locatorIndex+wordIndex+siteIndex+1)*3) << 5
				}
				binary.LittleEndian.PutUint32(image[at:], word)
			}
			if locator.kind == semanticResultBranch {
				binary.LittleEndian.PutUint32(image[center:], 0xaa0003f5)
				binary.LittleEndian.PutUint32(image[center+4:], 0x34000100|uint32(locatorIndex&0x7)<<5)
			} else if locator.kind == semanticSignatureResult {
				binary.LittleEndian.PutUint32(image[center:], 0x350009a0)
			}
		}
	}
	return image
}

func TestAnalyzeInitialLoaderSemanticPlan(t *testing.T) {
	const base = uint64(0x1fc164000)
	image := semanticFixture(t)
	plan, err := analyzeInitialLoader(image, 0, base, "iBoot-unseen")
	if err != nil {
		t.Fatal(err)
	}
	if plan.source != "ARM64 instruction analyzer" || len(plan.patches) != 17 || plan.snapshotSHA256 != digest(image) {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	var nops, moves, branches int
	for _, patch := range plan.patches {
		switch patch.after {
		case 0xd503201f:
			nops++
		default:
			switch {
			case patch.before&0xffffffe0 == 0xaa0003e0 && patch.after == patch.before|0x001f0000:
				moves++
			case patch.before&0xff00001f == 0x34000000 && patch.after&0xfc000000 == 0x14000000:
				branches++
			default:
				t.Fatalf("unexpected transformation at 0x%x: %08x -> %08x", patch.address, patch.before, patch.after)
			}
		}
	}
	if nops != 7 || moves != 5 || branches != 5 {
		t.Fatalf("incomplete semantic transaction: nops=%d moves=%d branches=%d", nops, moves, branches)
	}
}

func TestAnalyzeInitialLoaderRequiresUniqueCompleteProof(t *testing.T) {
	image := semanticFixture(t)
	locator := initialLoaderSemanticLocators[0]
	duplicateAt := 0x1000
	for i, word := range locator.pattern {
		binary.LittleEndian.PutUint32(image[duplicateAt+i*4:], word.value)
	}
	if _, err := analyzeInitialLoader(image, 0, 0x1fc064000, "iBoot-duplicate"); err != nil {
		t.Fatalf("unrelated normalized duplicate should be excluded by its neighborhood: %v", err)
	}

	image = semanticFixture(t)
	copy(image[0x80000:0x80400], image[0x36000:0x36400])
	if _, err := analyzeInitialLoader(image, 0, 0x1fc064000, "iBoot-ambiguous"); err == nil || !strings.Contains(err.Error(), "complete neighborhoods") {
		t.Fatalf("second complete semantic neighborhood was not rejected: %v", err)
	}

	image = semanticFixture(t)
	center := int(semanticFixtureOffsets[3][0])
	binary.LittleEndian.PutUint32(image[center:], 0xd503201f)
	if _, err := analyzeInitialLoader(image, 0, 0x1fc064000, "iBoot-missing"); err == nil {
		t.Fatal("incomplete semantic proof was accepted")
	}
}

func TestAnalyzeInitialLoaderAllowsMaskedRegisterAllocation(t *testing.T) {
	image := semanticFixture(t)
	locator := initialLoaderSemanticLocators[0]
	center := int(semanticFixtureOffsets[0][0])
	start := center - locator.patchIndex*4
	binary.LittleEndian.PutUint32(image[start+4:], 0x51007800|3<<5|4)
	if _, err := analyzeInitialLoader(image, 0, 0x1fc064000, "iBoot-register-allocation"); err != nil {
		t.Fatalf("masked register allocation rejected: %v", err)
	}
}

func TestLoaderBuildAndKnownAdapterSelection(t *testing.T) {
	header := append(make([]byte, 91), []byte("iBoot-9275.0.0.101.12\x00")...)
	build, err := loaderBuild(header, "")
	if err != nil || build != "iBoot-9275.0.0.101.12" {
		t.Fatalf("build=%q err=%v", build, err)
	}
	multiple := append(header, []byte("iBoot-second\x00")...)
	if _, err = loaderBuild(multiple, ""); err == nil {
		t.Fatal("multiple build strings accepted")
	}
	if build, err = loaderBuild(multiple, "iBoot-9275.0.0.101.12"); err != nil || build != "iBoot-9275.0.0.101.12" {
		t.Fatalf("Recovery-correlated build=%q err=%v", build, err)
	}
	if _, err = loaderBuild(multiple, "iBoot-missing"); err == nil {
		t.Fatal("absent Recovery identity accepted")
	}
	if knownInitialLoader(initialBuild) == nil || knownInitialLoader("iBoot-unseen") != nil {
		t.Fatal("initial-loader adapter selection changed")
	}
}

func TestBranchToCBZTarget(t *testing.T) {
	for _, before := range []uint32{0x34002d00, 0x34000000, 0x34ffffe0} {
		after, err := branchToCBZTarget(before)
		if err != nil {
			t.Fatal(err)
		}
		cbDelta := signedImmediate((before>>5)&0x7ffff, 19)
		bDelta := signedImmediate(after&0x03ffffff, 26)
		if cbDelta != bDelta {
			t.Fatalf("target changed: CBZ=%d B=%d", cbDelta, bDelta)
		}
	}
	if _, err := branchToCBZTarget(0x35000000); err == nil {
		t.Fatal("CBNZ accepted as result branch")
	}
}

func TestCachedLoaderSnapshotRequiresContentAndGeometry(t *testing.T) {
	root := t.TempDir()
	image := semanticFixture(t)
	path, err := saveLoaderSnapshot(root, "iBoot-test", 0x1fc064000, 0, image)
	if err != nil {
		t.Fatal(err)
	}
	got := cachedLoaderSnapshots(root, "iBoot-test", 16*loaderScanChunk)
	if len(got) != 1 || got[0].path != path || got[0].offset != 0 || digest(got[0].image) != digest(image) {
		t.Fatalf("valid snapshot not selected: %+v", got)
	}
	if got = cachedLoaderSnapshots(root, "iBoot-other", 16*loaderScanChunk); len(got) != 0 {
		t.Fatal("snapshot selected for a different build")
	}
	if got = cachedLoaderSnapshots(root, "iBoot-test", uint64(len(image)-loaderScanChunk)); len(got) != 0 {
		t.Fatal("snapshot outside the live SRAM bound was accepted")
	}
	if err = os.WriteFile(path, append([]byte(nil), image[:len(image)-4]...), 0o600); err != nil {
		t.Fatal(err)
	}
	if got = cachedLoaderSnapshots(root, "iBoot-test", 16*loaderScanChunk); len(got) != 0 {
		t.Fatal("truncated snapshot accepted")
	}
}

func TestCachedLoaderSnapshotsRetainSameBuildVariants(t *testing.T) {
	root := t.TempDir()
	first := semanticFixture(t)
	second := bytes.Clone(first)
	second[len(second)-1] ^= 0x5a
	if _, err := saveLoaderSnapshot(root, "iBoot-same-build", 0x1fc064000, 0, first); err != nil {
		t.Fatal(err)
	}
	if _, err := saveLoaderSnapshot(root, "iBoot-same-build", 0x1fc064000, 0, second); err != nil {
		t.Fatal(err)
	}
	got := cachedLoaderSnapshots(root, "iBoot-same-build", 16*loaderScanChunk)
	if len(got) != 2 {
		t.Fatalf("same-build content variants collapsed: got %d", len(got))
	}
	hashes := map[string]bool{digest(got[0].image): true, digest(got[1].image): true}
	if !hashes[digest(first)] || !hashes[digest(second)] {
		t.Fatal("same-build cache lost a content identity")
	}
}
