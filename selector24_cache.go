package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	selector24GateAddress          = uint64(0xfffffff008021880)
	selector24GateOffset           = 0x101d880
	selector24GatePreimageBytes    = 663
	selector24CaveBytes            = 0x781
	selector24ResultOffset         = 0x1584a58
	selector24ResultPreimage       = uint32(0x17ea638a)
	selector24NativeSuccess        = uint64(0xfffffff008588a6c)
	selector24StockFailure         = uint64(0xfffffff008588a5c)
	selector24NextPolicyOffset     = selector24GateOffset + 664
	selector24NextPolicyEntry      = uint32(0xd503245f)
	selector24GatePreimageSHA256   = "a60807456c3447ff4d658e07be550edaf286a1ff6e536bfbc0a4c590fb083f95"
	selector24GatePayloadSHA256    = "7fe9bb342ec5f6f5b0ce417071d73eb792e8fff4a05f3f66cc8b6c1410b198e3"
	selector24GatePostimageSHA256  = "ddc538019411cc800ba6e27718db2cb378cc81723c56c905ca00d6caf64463c0"
	selector24GateChangedPositions = 642
	selector24KernelDecodedSHA256  = "cd21966679aca5862bc35d39399a684911c88638104cd111c0c7ace159151a1f"
	selector24KernelIM4PSHA256     = "0cbb3888dcb21c458c221f16df0a6b7b35e0e69ae8fae6e21261d75acb8b6249"
	selector24KernelIM4PBytes      = 20356632
	selector24CavePreimageSHA256   = "aa653e956e6c8810b4574f932ff80c8a195066b67c303748f89bdfec6a86d584"
	dyldCacheCDHashTableSHA256     = "f8e15119da869a4a2890445cb252904535a19fe42fe4463cd101cbf4ba883b65"
	dyldCacheSelector24HashBytes   = 20
	dyldCacheSelector24HashCount   = 27
	dyldCacheSelector24Instruction = 24
)

func dyldCacheTrustNames() []string {
	const base = "dyld_shared_cache_arm64e"
	names := make([]string, 0, dyldCacheSelector24HashCount)
	names = append(names, base)
	for index := 1; index <= 24; index++ {
		names = append(names, fmt.Sprintf("%s.%02d", base, index))
	}
	names = append(names, base+".25.dylddata", base+".26.dyldlinkedit")
	return names
}

// dyldCacheSelector24Hashes enables the cache gate only for the complete,
// pinned production cache set. A partial or renamed set is an error rather
// than a request to broaden the kernel policy.
func dyldCacheSelector24Hashes(entries []trustEntry) ([][]byte, bool, error) {
	names := dyldCacheTrustNames()
	wanted := make(map[string]int, len(names))
	for index, name := range names {
		wanted[name] = index
	}
	selected := make([][]byte, len(names))
	seen := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name, "dyld_shared_cache_arm64e") {
			continue
		}
		index, ok := wanted[entry.Name]
		if !ok {
			return nil, false, fmt.Errorf("unexpected dyld cache trust identity %q", entry.Name)
		}
		if selected[index] != nil {
			return nil, false, fmt.Errorf("duplicate dyld cache trust identity %q", entry.Name)
		}
		hash, err := hex.DecodeString(entry.CDHash)
		if err != nil || len(hash) != dyldCacheSelector24HashBytes {
			return nil, false, fmt.Errorf("invalid dyld cache cdhash for %s", entry.Name)
		}
		selected[index] = hash
		seen++
	}
	if seen == 0 {
		return nil, false, nil
	}
	if seen != len(names) {
		return nil, false, fmt.Errorf("incomplete dyld cache trust set: got %d, want %d", seen, len(names))
	}
	flat := make([]byte, 0, len(names)*dyldCacheSelector24HashBytes)
	for index, hash := range selected {
		if len(hash) != dyldCacheSelector24HashBytes {
			return nil, false, fmt.Errorf("missing dyld cache trust identity %s", names[index])
		}
		flat = append(flat, hash...)
	}
	if digest(flat) != dyldCacheCDHashTableSHA256 {
		return nil, false, errors.New("dyld cache cdhash table identity mismatch")
	}
	return selected, true, nil
}

func encodeRelativeImmediate(from, to uint64, bits uint) (uint32, error) {
	delta := int64(to) - int64(from)
	if delta&3 != 0 {
		return 0, errors.New("ARM64 branch target is not word aligned")
	}
	words := delta / 4
	minimum, maximum := -(int64(1) << (bits - 1)), (int64(1)<<(bits-1))-1
	if words < minimum || words > maximum {
		return 0, errors.New("ARM64 branch target is out of range")
	}
	return uint32(uint64(words) & ((uint64(1) << bits) - 1)), nil
}

func encodeSelector24B(from, to uint64) (uint32, error) {
	immediate, err := encodeRelativeImmediate(from, to, 26)
	return 0x14000000 | immediate, err
}

func encodeSelector24BCond(from, to uint64, condition uint32) (uint32, error) {
	if condition > 0xf {
		return 0, errors.New("invalid ARM64 condition")
	}
	immediate, err := encodeRelativeImmediate(from, to, 19)
	return 0x54000000 | immediate<<5 | condition, err
}

func encodeSelector24CBZ64(from, to uint64, register uint32) (uint32, error) {
	if register > 31 {
		return 0, errors.New("invalid ARM64 register")
	}
	immediate, err := encodeRelativeImmediate(from, to, 19)
	return 0xb4000000 | immediate<<5 | register, err
}

func encodeSelector24ADR(from, to uint64, register uint32) (uint32, error) {
	if register > 31 {
		return 0, errors.New("invalid ARM64 register")
	}
	delta := int64(to) - int64(from)
	if delta < -(1<<20) || delta >= 1<<20 {
		return 0, errors.New("ARM64 ADR target is out of range")
	}
	immediate := uint32(uint64(delta) & 0x1fffff)
	return 0x10000000 | (immediate&3)<<29 | ((immediate>>2)&0x7ffff)<<5 | register, nil
}

func selector24BranchTarget(address uint64, word uint32, bits uint, shift uint) uint64 {
	immediate := int64((word >> shift) & uint32((uint64(1)<<bits)-1))
	if immediate&(1<<(bits-1)) != 0 {
		immediate -= 1 << bits
	}
	return uint64(int64(address) + immediate*4)
}

func selector24ADRTarget(address uint64, word uint32) uint64 {
	immediate := int64(((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2))
	if immediate&(1<<20) != 0 {
		immediate -= 1 << 21
	}
	return uint64(int64(address) + immediate)
}

func buildDyldCacheSelector24Gate(hashes [][]byte) ([]byte, error) {
	if len(hashes) != dyldCacheSelector24HashCount {
		return nil, fmt.Errorf("dyld cache selector-24 gate has %d hashes, want %d", len(hashes), dyldCacheSelector24HashCount)
	}
	flat := make([]byte, 0, len(hashes)*dyldCacheSelector24HashBytes)
	for _, hash := range hashes {
		if len(hash) != dyldCacheSelector24HashBytes {
			return nil, errors.New("dyld cache selector-24 hash width changed")
		}
		flat = append(flat, hash...)
	}
	if digest(flat) != dyldCacheCDHashTableSHA256 {
		return nil, errors.New("dyld cache selector-24 table changed")
	}
	const (
		outerLoop = 8
		innerLoop = 11
		mismatch  = 19
		success   = 22
		failure   = 23
	)
	words := []uint32{
		0xd503249f, // BTI j.
		0,          // CBZ X0,success.
		0x7100141f, // CMP W0,#5.
		0,          // B.NE failure.
		0,          // CBZ X19,failure.
		0x91016269, // ADD X9,X19,#0x58 (csb_cdhash).
		0,          // ADR X10,table.
		0x5280036b, // MOV W11,#27.
		0xaa0903ed, // MOV X13,X9.
		0xaa0a03ee, // MOV X14,X10.
		0x5280028f, // MOV W15,#20.
		0x394001b0, // LDRB W16,[X13].
		0x394001d1, // LDRB W17,[X14].
		0x6b11021f, // CMP W16,W17.
		0,          // B.NE mismatch.
		0x910005ad, // ADD X13,X13,#1.
		0x910005ce, // ADD X14,X14,#1.
		0x710005ef, // SUBS W15,W15,#1.
		0,          // B.NE innerLoop.
		0x9100514a, // ADD X10,X10,#20.
		0x7100056b, // SUBS W11,W11,#1.
		0,          // B.NE outerLoop.
		0,          // B native success.
		0,          // B stock failure.
	}
	if len(words) != dyldCacheSelector24Instruction {
		return nil, errors.New("dyld cache selector-24 instruction count changed")
	}
	address := func(index int) uint64 { return selector24GateAddress + uint64(index*4) }
	tableAddress := selector24GateAddress + uint64(len(words)*4)
	var err error
	words[1], err = encodeSelector24CBZ64(address(1), address(success), 0)
	if err != nil {
		return nil, err
	}
	words[3], err = encodeSelector24BCond(address(3), address(failure), 1)
	if err != nil {
		return nil, err
	}
	words[4], err = encodeSelector24CBZ64(address(4), address(failure), 19)
	if err != nil {
		return nil, err
	}
	words[6], err = encodeSelector24ADR(address(6), tableAddress, 10)
	if err != nil {
		return nil, err
	}
	words[14], err = encodeSelector24BCond(address(14), address(mismatch), 1)
	if err != nil {
		return nil, err
	}
	words[18], err = encodeSelector24BCond(address(18), address(innerLoop), 1)
	if err != nil {
		return nil, err
	}
	words[21], err = encodeSelector24BCond(address(21), address(outerLoop), 1)
	if err != nil {
		return nil, err
	}
	words[22], err = encodeSelector24B(address(success), selector24NativeSuccess)
	if err != nil {
		return nil, err
	}
	words[23], err = encodeSelector24B(address(failure), selector24StockFailure)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, len(words)*4, len(words)*4+len(flat))
	for index, word := range words {
		binary.LittleEndian.PutUint32(payload[index*4:], word)
	}
	payload = append(payload, flat...)
	if err = validateDyldCacheSelector24Gate(payload); err != nil {
		return nil, err
	}
	if digest(payload) != selector24GatePayloadSHA256 {
		return nil, errors.New("dyld cache selector-24 payload identity changed")
	}
	return payload, nil
}

func validateDyldCacheSelector24Gate(payload []byte) error {
	if len(payload) != dyldCacheSelector24Instruction*4+dyldCacheSelector24HashCount*dyldCacheSelector24HashBytes || len(payload) > selector24GatePreimageBytes {
		return errors.New("dyld cache selector-24 payload size changed")
	}
	word := func(index int) uint32 { return binary.LittleEndian.Uint32(payload[index*4:]) }
	address := func(index int) uint64 { return selector24GateAddress + uint64(index*4) }
	if word(0) != 0xd503249f || word(2) != 0x7100141f || word(5) != 0x91016269 || word(7) != 0x5280036b ||
		word(8) != 0xaa0903ed || word(9) != 0xaa0a03ee || word(10) != 0x5280028f ||
		word(11) != 0x394001b0 || word(12) != 0x394001d1 || word(13) != 0x6b11021f ||
		word(19) != 0x9100514a || word(20) != 0x7100056b {
		return errors.New("dyld cache selector-24 fixed instruction changed")
	}
	wantBranches := map[int]uint64{
		1: address(22), 3: address(23), 4: address(23), 14: address(19),
		18: address(11), 21: address(8), 22: selector24NativeSuccess, 23: selector24StockFailure,
	}
	for index, want := range wantBranches {
		bits, shift := uint(19), uint(5)
		if index >= 22 {
			bits, shift = 26, 0
		}
		if got := selector24BranchTarget(address(index), word(index), bits, shift); got != want {
			return fmt.Errorf("dyld cache selector-24 branch %d targets %#x, want %#x", index, got, want)
		}
	}
	if got, want := selector24ADRTarget(address(6), word(6)), selector24GateAddress+dyldCacheSelector24Instruction*4; got != want {
		return fmt.Errorf("dyld cache selector-24 table address %#x, want %#x", got, want)
	}
	if digest(payload[dyldCacheSelector24Instruction*4:]) != dyldCacheCDHashTableSHA256 {
		return errors.New("dyld cache selector-24 embedded table changed")
	}
	return nil
}

func patchRuntimeSelector24DyldCacheGate(raw []byte, entries []trustEntry) (bool, error) {
	hashes, enabled, err := dyldCacheSelector24Hashes(entries)
	if err != nil || !enabled {
		return false, err
	}
	if selector24GateOffset > len(raw)-selector24CaveBytes || selector24ResultOffset > len(raw)-4 || selector24NextPolicyOffset > len(raw)-4 {
		return false, errors.New("runtime kernel lacks selector-24 policy range")
	}
	if digest(raw[selector24GateOffset:selector24GateOffset+selector24CaveBytes]) != selector24CavePreimageSHA256 ||
		digest(raw[selector24GateOffset:selector24GateOffset+selector24GatePreimageBytes]) != selector24GatePreimageSHA256 ||
		binary.LittleEndian.Uint32(raw[selector24ResultOffset:]) != selector24ResultPreimage ||
		raw[selector24GateOffset+selector24GatePreimageBytes] != 0 ||
		binary.LittleEndian.Uint32(raw[selector24NextPolicyOffset:]) != selector24NextPolicyEntry {
		return false, errors.New("runtime kernel selector-24 gate preimage changed")
	}
	payload, err := buildDyldCacheSelector24Gate(hashes)
	if err != nil {
		return false, err
	}
	postimage := make([]byte, selector24GatePreimageBytes)
	copy(postimage, payload)
	changed := 0
	for index, before := range raw[selector24GateOffset : selector24GateOffset+selector24GatePreimageBytes] {
		if before != postimage[index] {
			changed++
		}
	}
	if digest(postimage) != selector24GatePostimageSHA256 || changed != selector24GateChangedPositions {
		return false, errors.New("runtime kernel selector-24 gate derived postimage changed")
	}
	copy(raw[selector24GateOffset:selector24GateOffset+selector24GatePreimageBytes], postimage)
	if !bytes.Equal(raw[selector24GateOffset:selector24GateOffset+len(payload)], payload) ||
		raw[selector24GateOffset+selector24GatePreimageBytes] != 0 ||
		binary.LittleEndian.Uint32(raw[selector24NextPolicyOffset:]) != selector24NextPolicyEntry {
		return false, errors.New("runtime kernel selector-24 gate postimage changed")
	}
	return true, nil
}
