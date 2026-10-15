package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	loaderScanChunk     = 0x40000
	debugReadChunk      = 0x400
	loaderAnalysisLimit = 3 * time.Minute
)

type relativeWord struct {
	offset uint64
	value  uint32
}

type relativePatch struct {
	offset        uint64
	before, after uint32
}

// initialLoaderAdapter stores the bytes checked for a loader tested on hardware.
// Addresses are relative to the caught entry point, so relocation does not
// change the adapter.
type initialLoaderAdapter struct {
	build       string
	entry       string
	buildOffset uint64
	buildBytes  string
	guards      []relativeWord
	patches     []relativePatch
}

var initialLoaderAdapters = []initialLoaderAdapter{{
	build:       initialBuild,
	entry:       "02113cd542005eb2420065b202111cd5df3f03d5000000900000009121170058aa1001943f0000eb200a0054e2160058420001cb42fc009142e47a92e50300aae60302aae70301aa0300028b2400028bde1800581f0004ebea0000543f0003ebaa000054260000eb6c020054e50304aa660004cb2a1800584b180058090001cb4a01098b6b01098b68010acb29170058ee0309aa4c35c1a82c3581a85f010bebabffff541f7508d59f3f03d5df3f03d5c0011fd6aa160058cb160058290000cb4a0109cb6b0109cbf0ffff171f2003d50a2cc1a80c34c1a80e3cc1a81044c1a82a2c81a82c3481a82e3c81a8304481a8420001f1ecfeff541f7508d59f3f03d5",
	buildOffset: 0x280,
	buildBytes:  "69426f6f742d383733372e302e302e3130312e35000000000000000000000000",
	guards: []relativeWord{
		{0x337c4, 0xa94e6ffc}, {0x34ef8, 0x35fff728}, {0x34f04, 0x54fff6c1},
		{0x3a794, 0x37ff9720}, {0x3a79c, 0x37ff96e0},
	},
	patches: []relativePatch{
		{0x36020, 0x34001760, 0xd503201f}, {0x3602c, 0x54001700, 0xd503201f},
		{0x36084, 0x35001440, 0xd503201f}, {0x362d8, 0x350001a0, 0xd503201f},
		{0x361e8, 0x54000841, 0xd503201f}, {0x3620c, 0x540007e1, 0xd503201f},
		{0x37100, 0xaa0003f5, 0xaa1f03f5}, {0x37104, 0x34002d00, 0x14000168},
		{0x371e4, 0xaa0003f5, 0xaa1f03f5}, {0x37394, 0xaa0003f5, 0xaa1f03f5},
		{0x37438, 0xaa0003f5, 0xaa1f03f5}, {0x37464, 0xaa0003f5, 0xaa1f03f5},
		{0x371e8, 0x340025e0, 0x1400012f}, {0x37398, 0x34001860, 0x140000c3},
		{0x3743c, 0x34001340, 0x1400009a}, {0x37468, 0x340011e0, 0x1400008f},
	},
}}

type semanticPatchKind uint8

const (
	semanticNOP semanticPatchKind = iota
	semanticResultBranch
	semanticSignatureResult
)

type semanticLocator struct {
	name       string
	kind       semanticPatchKind
	pattern    []semanticInstruction
	patchIndex int
	minimum    int
}

type semanticInstruction struct {
	value uint32
	mask  uint32
}

func exactInstruction(value uint32) semanticInstruction {
	return semanticInstruction{value: value, mask: ^uint32(0)}
}

func maskedInstruction(value, mask uint32) semanticInstruction {
	return semanticInstruction{value: value & mask, mask: mask}
}

// These signatures describe instruction relationships around the admission
// decisions. PC-relative and branch immediates are removed by normalizeARM64;
// constants, required register roles, conditions, and neighboring data flow
// remain part of the check. Global duplicates are filtered by a unique local
// control-flow neighborhood; minimum counts express required distinct checks.
var initialLoaderSemanticLocators = []semanticLocator{
	{
		"policy-result-a", semanticNOP,
		[]semanticInstruction{
			exactInstruction(0x94000000),
			maskedInstruction(0x51007800, 0xfffffc00), // SUB Wn, Wn, #0x1e; register allocation may vary.
			exactInstruction(0x34000000),
			exactInstruction(0x94000000),
			exactInstruction(0xeb00027f),
		}, 2, 1,
	},
	{
		"policy-result-b", semanticNOP,
		[]semanticInstruction{
			exactInstruction(0x94000000),
			exactInstruction(0xeb00027f),
			exactInstruction(0x54000000),
		}, 2, 1,
	},
	{
		"policy-result-c", semanticNOP,
		[]semanticInstruction{
			exactInstruction(0xaa1303e3),
			exactInstruction(0x94000000),
			exactInstruction(0x35000000),
			exactInstruction(0x910062b4),
		}, 2, 1,
	},
	{
		"policy-result-d", semanticNOP,
		[]semanticInstruction{
			exactInstruction(0x94000000),
			maskedInstruction(0xf94067e0, 0xffffffe0), // LDR Xn, [SP,#0xc8].
			exactInstruction(0x35000000),
			exactInstruction(0x52800028),
			maskedInstruction(0x390003e8, 0xffc003ff), // STRB W8, [SP,#frame-field].
		}, 2, 1,
	},
	{
		"policy-byte-results", semanticNOP,
		[]semanticInstruction{
			maskedInstruction(0x394003e9, 0xffc003ff), // LDRB W9, [SP,#frame-field].
			exactInstruction(0x6b48213f),
			exactInstruction(0x54000001),
			maskedInstruction(0x394003e8, 0xffc003ff), // LDRB W8, [SP,#frame-field].
			exactInstruction(0x34000008),
		}, 2, 2,
	},
	{
		"component-result-a", semanticResultBranch,
		[]semanticInstruction{
			exactInstruction(0x72a8a861),
			exactInstruction(0x94000000),
			maskedInstruction(0xaa0003e0, 0xffffffe0), // MOV Xresult, X0.
			exactInstruction(0x34000000),
			exactInstruction(0x52800220),
		}, 2, 1,
	},
	{
		"component-result-b", semanticResultBranch,
		[]semanticInstruction{
			exactInstruction(0xaa0603e7),
			exactInstruction(0x94000000),
			maskedInstruction(0xaa0003e0, 0xffffffe0),
			exactInstruction(0x34000000),
			exactInstruction(0x94000000),
		}, 2, 1,
	},
	{
		"component-result-c", semanticResultBranch,
		[]semanticInstruction{
			exactInstruction(0x94000000),
			maskedInstruction(0xaa0003e0, 0xffffffe0),
			exactInstruction(0x34000000),
			exactInstruction(0x94000000),
			exactInstruction(0x11002513),
		}, 1, 1,
	},
	{
		"component-result-d", semanticResultBranch,
		[]semanticInstruction{
			exactInstruction(0x72a86a00),
			exactInstruction(0x94000000),
			maskedInstruction(0xaa0003e0, 0xffffffe0),
			exactInstruction(0x34000000),
			exactInstruction(0x94000000),
		}, 2, 1,
	},
	{
		"component-result-e", semanticResultBranch,
		[]semanticInstruction{
			exactInstruction(0x72a86a60),
			exactInstruction(0x94000000),
			maskedInstruction(0xaa0003e0, 0xffffffe0),
			exactInstruction(0x34000000),
			exactInstruction(0x94000000),
		}, 2, 1,
	},
	{
		"signature-result", semanticSignatureResult,
		[]semanticInstruction{
			maskedInstruction(0xaa0003e4, 0xffe0ffff), // MOV X4, Xn.
			maskedInstruction(0xaa0003e6, 0xffe0ffff), // MOV X6, Xn.
			maskedInstruction(0xaa0003e7, 0xffe0ffff), // MOV X7, Xn.
			maskedInstruction(0xd63f081f, 0xfffffc1f), // BLRAAZ Xn.
			exactInstruction(0x35000000),              // CBNZ W0, failure.
			maskedInstruction(0x52800020, 0xffffffe0), // MOV Wn, #1.
			maskedInstruction(0x91000000, 0xffc00000), // ADD Xn, Xn, #structure-field.
			maskedInstruction(0x91000000, 0xffc00000),
		}, 4, 1,
	},
}

type loaderPlan struct {
	build, source, snapshotSHA256 string
	base, extent                  uint64
	expectedPatches               int
	patches                       []codePatch
	guards                        []codeGuard
}

type codeGuard struct {
	address uint64
	value   uint32
	mask    uint32
}

func knownInitialLoader(build string) *initialLoaderAdapter {
	for i := range initialLoaderAdapters {
		if initialLoaderAdapters[i].build == build {
			return &initialLoaderAdapters[i]
		}
	}
	return nil
}

func (a *initialLoaderAdapter) plan(ctx context.Context, d *targetDebug, base uint64) (loaderPlan, error) {
	if err := d.requireHex(ctx, base, a.entry); err != nil {
		return loaderPlan{}, fmt.Errorf("adapter entry bytes: %w", err)
	}
	if err := d.requireHex(ctx, base+a.buildOffset, a.buildBytes); err != nil {
		return loaderPlan{}, fmt.Errorf("adapter build bytes: %w", err)
	}
	for _, guard := range a.guards {
		actual, err := d.word(ctx, base+guard.offset)
		if err != nil || actual != guard.value {
			return loaderPlan{}, errors.Join(fmt.Errorf("loader guard mismatch at +0x%x", guard.offset), err)
		}
	}
	plan := loaderPlan{build: a.build, source: "stored adapter", base: base, extent: d.silicon.LoaderHigh - base, expectedPatches: len(a.patches)}
	for _, patch := range a.patches {
		plan.patches = append(plan.patches, codePatch{base + patch.offset, patch.before, patch.after})
	}
	return plan, validateLoaderPlan(plan)
}

func normalizeARM64(word uint32) uint32 {
	switch {
	case word&0x7c000000 == 0x14000000: // B and BL
		return word & 0xfc000000
	case word&0xff000010 == 0x54000000: // B.cond
		return word & 0xff00001f
	case word&0x7e000000 == 0x34000000: // CBZ and CBNZ
		return word & 0xff00001f
	case word&0x7e000000 == 0x36000000: // TBZ and TBNZ
		return word & 0xfff8001f
	case word&0x1f000000 == 0x10000000: // ADR and ADRP
		return word & 0x9f00001f
	case word&0x3b000000 == 0x18000000: // literal loads
		return word & 0xff00001f
	default:
		return word
	}
}

func semanticOffsets(image []byte, locator semanticLocator) ([]int, error) {
	if len(image)%4 != 0 || len(locator.pattern) == 0 || locator.patchIndex < 0 || locator.patchIndex >= len(locator.pattern) || locator.minimum < 1 {
		return nil, errors.New("invalid loader analysis input or semantic locator")
	}
	var found []int
	for at := 0; at+len(locator.pattern)*4 <= len(image); at += 4 {
		match := true
		for i, want := range locator.pattern {
			word := binary.LittleEndian.Uint32(image[at+i*4:])
			if normalizeARM64(word)&want.mask != want.value {
				match = false
				break
			}
		}
		if match {
			found = append(found, at+locator.patchIndex*4)
		}
	}
	if len(found) < locator.minimum {
		return nil, fmt.Errorf("%s: requires at least %d semantic matches, found %d", locator.name, locator.minimum, len(found))
	}
	return found, nil
}

func semanticCluster(locators []semanticLocator, found [][]int, kind semanticPatchKind, width int) ([][]int, error) {
	// A compiler may emit the same normalized sequence elsewhere. Select the
	// unique compact neighborhood containing every required semantic role.
	var anchors []int
	for index, locator := range locators {
		if locator.kind == kind {
			anchors = append(anchors, found[index]...)
		}
	}
	type candidate struct {
		key      string
		selected [][]int
	}
	unique := map[string]candidate{}
	for _, low := range anchors {
		selected := make([][]int, len(locators))
		valid := true
		var key strings.Builder
		for index, locator := range locators {
			if locator.kind != kind {
				continue
			}
			for _, site := range found[index] {
				if site >= low && site-low <= width {
					selected[index] = append(selected[index], site)
					fmt.Fprintf(&key, "%d:%x,", index, site)
				}
			}
			if len(selected[index]) < locator.minimum {
				valid = false
				break
			}
		}
		if valid {
			value := key.String()
			unique[value] = candidate{key: value, selected: selected}
		}
	}
	if len(unique) != 1 {
		return nil, fmt.Errorf("semantic %d sites form %d complete neighborhoods", kind, len(unique))
	}
	for _, result := range unique {
		return result.selected, nil
	}
	panic("unreachable")
}

func signedImmediate(value uint32, bits uint) int64 {
	mask := uint64(1<<bits) - 1
	v := uint64(value) & mask
	if v&(1<<(bits-1)) != 0 {
		v |= ^mask
	}
	return int64(v)
}

func branchToCBZTarget(word uint32) (uint32, error) {
	if word&0xff00001f != 0x34000000 {
		return 0, fmt.Errorf("result branch is not CBZ W0: 0x%08x", word)
	}
	deltaWords := signedImmediate((word>>5)&0x7ffff, 19)
	if deltaWords < -(1<<25) || deltaWords >= 1<<25 {
		return 0, errors.New("CBZ target is outside unconditional branch range")
	}
	return 0x14000000 | uint32(uint64(deltaWords)&0x03ffffff), nil
}

func analyzeInitialLoader(image []byte, imageOffset, base uint64, build string) (loaderPlan, error) {
	if len(image) < 20 || imageOffset%4 != 0 || base%0x1000 != 0 {
		return loaderPlan{}, errors.New("invalid initial-loader analysis range")
	}
	plan := loaderPlan{build: build, source: "ARM64 instruction analyzer", base: base, extent: imageOffset + uint64(len(image)), snapshotSHA256: digest(image)}
	found := make([][]int, len(initialLoaderSemanticLocators))
	for index, locator := range initialLoaderSemanticLocators {
		sites, err := semanticOffsets(image, locator)
		if err != nil {
			return loaderPlan{}, err
		}
		found[index] = sites
	}
	nopSelection, err := semanticCluster(initialLoaderSemanticLocators, found, semanticNOP, 0x400)
	if err != nil {
		return loaderPlan{}, err
	}
	resultSelection, err := semanticCluster(initialLoaderSemanticLocators, found, semanticResultBranch, 0x800)
	if err != nil {
		return loaderPlan{}, err
	}
	selected := make([][]int, len(found))
	var resultFloor int
	for index, locator := range initialLoaderSemanticLocators {
		switch locator.kind {
		case semanticNOP:
			selected[index] = nopSelection[index]
		case semanticResultBranch:
			selected[index] = resultSelection[index]
			for _, site := range selected[index] {
				if resultFloor == 0 || site < resultFloor {
					resultFloor = site
				}
			}
		}
	}
	var signatures []struct{ index, site int }
	for index, locator := range initialLoaderSemanticLocators {
		if locator.kind != semanticSignatureResult {
			continue
		}
		for _, site := range found[index] {
			if site > resultFloor && site-resultFloor <= 0x200000 {
				signatures = append(signatures, struct{ index, site int }{index, site})
			}
		}
	}
	if len(signatures) != 1 {
		return loaderPlan{}, fmt.Errorf("signature-result sites form %d admissible continuations", len(signatures))
	}
	selected[signatures[0].index] = []int{signatures[0].site}
	var nopOffsets, resultOffsets, signatureOffsets []uint64
	for locatorIndex, locator := range initialLoaderSemanticLocators {
		sites := selected[locatorIndex]
		for _, at := range sites {
			offset := imageOffset + uint64(at)
			before := binary.LittleEndian.Uint32(image[at:])
			start := at - locator.patchIndex*4
			for instructionIndex, instruction := range locator.pattern {
				plan.guards = append(plan.guards, codeGuard{
					address: base + imageOffset + uint64(start+instructionIndex*4),
					value:   instruction.value,
					mask:    instruction.mask,
				})
			}
			switch locator.kind {
			case semanticNOP:
				if before&0xff000010 != 0x54000000 && before&0x7e000000 != 0x34000000 {
					return loaderPlan{}, fmt.Errorf("%s resolved to unsupported condition 0x%08x", locator.name, before)
				}
				plan.patches = append(plan.patches, codePatch{base + offset, before, 0xd503201f})
				plan.expectedPatches++
				nopOffsets = append(nopOffsets, offset)
			case semanticResultBranch:
				if before&0xffffffe0 != 0xaa0003e0 {
					return loaderPlan{}, fmt.Errorf("%s result move changed: 0x%08x", locator.name, before)
				}
				branch := binary.LittleEndian.Uint32(image[at+4:])
				afterBranch, branchErr := branchToCBZTarget(branch)
				if branchErr != nil {
					return loaderPlan{}, fmt.Errorf("%s: %w", locator.name, branchErr)
				}
				plan.patches = append(plan.patches,
					codePatch{base + offset, before, before | 0x001f0000},
					codePatch{base + offset + 4, branch, afterBranch},
				)
				plan.expectedPatches += 2
				resultOffsets = append(resultOffsets, offset)
			case semanticSignatureResult:
				if normalizeARM64(before) != 0x35000000 {
					return loaderPlan{}, fmt.Errorf("%s result branch changed: 0x%08x", locator.name, before)
				}
				plan.patches = append(plan.patches, codePatch{base + offset, before, 0xd503201f})
				plan.expectedPatches++
				signatureOffsets = append(signatureOffsets, offset)
			default:
				return loaderPlan{}, errors.New("unknown semantic patch kind")
			}
		}
	}
	if span(nopOffsets) > 0x400 || span(resultOffsets) > 0x800 || distance(nopOffsets, resultOffsets) > 0x4000 || len(signatureOffsets) != 1 {
		return loaderPlan{}, errors.New("initial-loader semantic sites do not form the expected control-flow neighborhoods")
	}
	sort.Slice(plan.patches, func(i, j int) bool { return plan.patches[i].address < plan.patches[j].address })
	return plan, validateLoaderPlan(plan)
}

func span(offsets []uint64) uint64 {
	if len(offsets) == 0 {
		return ^uint64(0)
	}
	low, high := offsets[0], offsets[0]
	for _, offset := range offsets[1:] {
		low = min(low, offset)
		high = max(high, offset)
	}
	return high - low
}

func distance(a, b []uint64) uint64 {
	if len(a) == 0 || len(b) == 0 {
		return ^uint64(0)
	}
	lowA, lowB := a[0], b[0]
	for _, value := range a[1:] {
		lowA = min(lowA, value)
	}
	for _, value := range b[1:] {
		lowB = min(lowB, value)
	}
	if lowA > lowB {
		return lowA - lowB
	}
	return lowB - lowA
}

func validateLoaderPlan(plan loaderPlan) error {
	if plan.base%0x1000 != 0 || plan.extent < 4 || plan.expectedPatches < 1 || len(plan.patches) != plan.expectedPatches {
		return errors.New("initial-loader plan has invalid base or incomplete patch set")
	}
	seen := map[uint64]bool{}
	for _, patch := range plan.patches {
		if patch.address < plan.base || patch.address-plan.base > plan.extent-4 || patch.address%4 != 0 || patch.before == patch.after || seen[patch.address] {
			return fmt.Errorf("invalid initial-loader patch at 0x%x", patch.address)
		}
		seen[patch.address] = true
	}
	return nil
}

func loaderBuild(header []byte, expected string) (string, error) {
	const prefix = "iBoot-"
	var builds []string
	for cursor := 0; cursor < len(header); {
		relative := bytes.Index(header[cursor:], []byte(prefix))
		if relative < 0 {
			break
		}
		start := cursor + relative
		end := start
		for end < len(header) {
			c := header[end]
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-' || c == '.') {
				break
			}
			end++
		}
		builds = append(builds, string(header[start:end]))
		cursor = end
	}
	if expected != "" {
		for _, build := range builds {
			if build == expected {
				return expected, nil
			}
		}
		return "", fmt.Errorf("live initial-loader header does not contain Recovery identity %q", expected)
	}
	if len(builds) != 1 || builds[0] == prefix {
		return "", fmt.Errorf("expected one initial-loader build string, found %d", len(builds))
	}
	return builds[0], nil
}

func readDebugRange(ctx context.Context, d *targetDebug, out io.Writer, name string, address uint64, size int) ([]byte, error) {
	if size <= 0 || size%debugReadChunk != 0 {
		return nil, errors.New("debug snapshot range must use whole bounded chunks")
	}
	result := make([]byte, 0, size)
	for offset := 0; offset < size; offset += debugReadChunk {
		if offset%(32*debugReadChunk) == 0 {
			fmt.Fprintf(out, "%s: %d/%d KiB\n", name, offset>>10, size>>10)
		}
		part, err := d.read(ctx, address+uint64(offset), debugReadChunk)
		if err != nil {
			return nil, fmt.Errorf("%s at +0x%x: %w", name, offset, err)
		}
		result = append(result, part...)
	}
	return result, nil
}

func saveLoaderSnapshot(cacheRoot, build string, base, offset uint64, image []byte) (string, error) {
	directory := filepath.Join(cacheRoot, "loader-analysis")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	name := digest(image) + ".bin"
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, image, 0o600); err != nil {
		return "", err
	}
	metadata := fmt.Sprintf("build=%s\nbase=0x%x\noffset=0x%x\nsize=%d\nsha256=%s\n", build, base, offset, len(image), digest(image))
	if err := os.WriteFile(path+".txt", []byte(metadata), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

type loaderSnapshot struct {
	image  []byte
	offset uint64
	path   string
}

// cachedLoaderSnapshots returns every content-addressed snapshot whose sidecar
// describes the same loader build and fits the live scan geometry. Build text
// does not identify unique bytes. The caller reruns each instruction check
// against halted memory before accepting a candidate.
func cachedLoaderSnapshots(cacheRoot, build string, maximum uint64) []loaderSnapshot {
	directory := filepath.Join(cacheRoot, "loader-analysis")
	sidecars, err := filepath.Glob(filepath.Join(directory, "*.bin.txt"))
	if err != nil {
		return nil
	}
	var snapshots []loaderSnapshot
	for _, sidecar := range sidecars {
		metadata, readErr := os.ReadFile(sidecar)
		if readErr != nil {
			continue
		}
		values := map[string]string{}
		for _, line := range strings.Split(string(metadata), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok {
				values[key] = value
			}
		}
		size, sizeErr := strconv.Atoi(values["size"])
		offset, offsetErr := strconv.ParseUint(strings.TrimPrefix(values["offset"], "0x"), 16, 64)
		path := strings.TrimSuffix(sidecar, ".txt")
		nameHash := strings.TrimSuffix(filepath.Base(path), ".bin")
		if values["build"] != build || sizeErr != nil || size < 2*loaderScanChunk || uint64(size) > maximum || size%loaderScanChunk != 0 || offsetErr != nil || offset != 0 || values["sha256"] != nameHash {
			continue
		}
		image, imageErr := os.ReadFile(path)
		if imageErr != nil || len(image) != size || digest(image) != nameHash {
			continue
		}
		snapshots = append(snapshots, loaderSnapshot{image: image, offset: offset, path: path})
	}
	sort.Slice(snapshots, func(i, j int) bool {
		if len(snapshots[i].image) != len(snapshots[j].image) {
			return len(snapshots[i].image) > len(snapshots[j].image)
		}
		return snapshots[i].path < snapshots[j].path
	})
	return snapshots
}

// verifySemanticLoaderPlan reruns the selected masked instruction checks on
// the halted loader. A cached snapshot can save a bulk read, but its build
// string or hash alone can never authorize a write.
func verifySemanticLoaderPlan(ctx context.Context, d *targetDebug, plan loaderPlan) error {
	for index, guard := range plan.guards {
		actual, err := d.word(ctx, guard.address)
		if err != nil {
			return err
		}
		if normalizeARM64(actual)&guard.mask != guard.value {
			return fmt.Errorf("live instruction check changed at guard %d", index)
		}
	}
	return nil
}

func sameLoaderPatches(a, b loaderPlan) bool {
	if len(a.patches) != len(b.patches) {
		return false
	}
	for index := range a.patches {
		if a.patches[index] != b.patches[index] {
			return false
		}
	}
	return true
}

// readAndAnalyzeInitialLoader grows the live read until a complete semantic
// plan remains unchanged across another bounded chunk. The executable layout
// therefore determines the captured range instead of a build-specific size.
func readAndAnalyzeInitialLoader(ctx context.Context, d *targetDebug, out io.Writer, build string) (loaderSnapshot, loaderPlan, error) {
	available := d.silicon.LoaderHigh - d.loaderBase
	limit := available
	limit -= limit % loaderScanChunk
	if limit < 2*loaderScanChunk {
		return loaderSnapshot{}, loaderPlan{}, errors.New("initial-loader executable SRAM range is too small")
	}
	image := make([]byte, 0, limit)
	analysisContext, cancel := context.WithTimeout(ctx, loaderAnalysisLimit)
	defer cancel()
	var stable *loaderPlan
	var last error
	for uint64(len(image)) < limit {
		address := d.loaderBase + uint64(len(image))
		part, err := readDebugRange(analysisContext, d, out, fmt.Sprintf("Initial-loader analysis after %d KiB", len(image)>>10), address, loaderScanChunk)
		if err != nil {
			return loaderSnapshot{image: image, offset: 0}, loaderPlan{}, err
		}
		image = append(image, part...)
		plan, analyzeErr := analyzeInitialLoader(image, 0, d.loaderBase, build)
		if analyzeErr != nil {
			last, stable = analyzeErr, nil
			continue
		}
		if stable != nil && sameLoaderPatches(*stable, plan) {
			return loaderSnapshot{image: image, offset: 0}, plan, nil
		}
		stable = &plan
	}
	if stable != nil {
		last = errors.New("complete semantic plan reached the scan boundary before a confirming chunk")
	}
	return loaderSnapshot{image: image, offset: 0}, loaderPlan{}, fmt.Errorf("no complete initial-loader semantic plan within %d KiB: %w", limit>>10, last)
}
