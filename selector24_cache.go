package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	selector24GateAddress          = uint64(0xfffffff008021880)
	selector24GateOffset           = 0x101d880
	selector24CaveBytes            = 0x781
	selector24ResultOffset         = 0x1584a58
	selector24ResultPreimage       = uint32(0x17ea638a)
	selector24NativeSuccess        = uint64(0xfffffff008588a6c)
	selector24StockFailure         = uint64(0xfffffff008588a5c)
	selector24GatePreimageSHA256   = "61f26011a8b7eee4a4a9388173878f3c6b6b6c709e72c9bd62b52d4b29e13bfb"
	selector24GatePayloadSHA256    = "be46c3143b09063d9c509c71755d5a1e0d751c22d35c93bf81885736a786d6e1"
	selector33GatePostimageSHA256  = "e32a8fb3725b89ad3341a6e3cf8a6baa485219d440ed6e3be5195ed34c3a1771"
	selector24GateChangedPositions = 5
	selector24KernelDecodedSHA256  = "db77ede6f8e14c117ed23fe4ac415ff2165388298e0cab38c6ec284ff6ccfc22"
	selector24KernelIM4PSHA256     = "a13957e74baea0b6951881a99a9e19c03ed349409f4761da568495f24b4b0c0f"
	selector24KernelIM4PBytes      = 20356524
	selector24CavePreimageSHA256   = "aa653e956e6c8810b4574f932ff80c8a195066b67c303748f89bdfec6a86d584"
	dyldCacheCDHashTableSHA256     = "f8e15119da869a4a2890445cb252904535a19fe42fe4463cd101cbf4ba883b65"
	dyldCacheSelector24HashBytes   = 20
	dyldCacheSelector24HashCount   = 27
	dyldCacheSelector24Instruction = 36
	callerLinkerSignedFlag         = uint32(0x00020000)
	selector33CallAddress          = uint64(0xfffffff008588b48)
	selector33CallOffset           = 0x1584b48
	selector33OriginalTarget       = uint64(0xfffffff008564dbc)
	selector33GateInstructions     = 28
	selector33OldGateOffset        = 664
	selector24UniversalWords       = 30
)

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

func encodeSelector24BL(from, to uint64) (uint32, error) {
	immediate, err := encodeRelativeImmediate(from, to, 26)
	return 0x94000000 | immediate, err
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

func encodeSelector24TestBit(from, to uint64, register, bit uint32, nonzero bool) (uint32, error) {
	if register > 31 || bit > 63 {
		return 0, errors.New("invalid ARM64 test-bit operand")
	}
	immediate, err := encodeRelativeImmediate(from, to, 14)
	if err != nil {
		return 0, err
	}
	word := uint32(0x36000000) | ((bit >> 5) << 31) | ((bit & 31) << 19) | immediate<<5 | register
	if nonzero {
		word |= 0x01000000
	}
	return word, nil
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
		dyldPath  = 16
		outerLoop = 19
		innerLoop = 22
		mismatch  = 31
		success   = 34
		failure   = 35
	)
	words := []uint32{
		0xd503249f, // BTI j.
		0,          // CBZ X0,success.
		0x7100141f, // CMP W0,#5.
		0,          // B.NE failure.
		0,          // CBZ X19,failure.
		0xf9404269, // LDR X9,[X19,#0x80] (csb_cd).
		0,          // CBZ X9,dyld cache path.
		0xb940012a, // LDR W10,[X9] (CodeDirectory magic).
		0x529bdf4b, // MOV W11,#0xdefa.
		0x72a0418b, // MOVK W11,#0x020c,LSL#16.
		0x6b0b015f, // CMP W10,W11.
		0,          // B.NE dyld cache path.
		0x39403d2a, // LDRB W10,[X9,#15] (CS_ADHOC byte).
		0,          // TBZ W10,#1,dyld cache path.
		0x3940352a, // LDRB W10,[X9,#13] (CS_LINKER_SIGNED byte).
		0,          // TBNZ W10,#1,success.
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
		0,          // B success after all 20 bytes match.
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
	words[6], err = encodeSelector24CBZ64(address(6), address(dyldPath), 9)
	if err != nil {
		return nil, err
	}
	words[11], err = encodeSelector24BCond(address(11), address(dyldPath), 1)
	if err != nil {
		return nil, err
	}
	words[13], err = encodeSelector24TestBit(address(13), address(dyldPath), 10, 1, false)
	if err != nil {
		return nil, err
	}
	words[15], err = encodeSelector24TestBit(address(15), address(success), 10, 1, true)
	if err != nil {
		return nil, err
	}
	words[17], err = encodeSelector24ADR(address(17), tableAddress, 10)
	if err != nil {
		return nil, err
	}
	words[25], err = encodeSelector24BCond(address(25), address(mismatch), 1)
	if err != nil {
		return nil, err
	}
	words[29], err = encodeSelector24BCond(address(29), address(innerLoop), 1)
	if err != nil {
		return nil, err
	}
	words[30], err = encodeSelector24B(address(30), address(success))
	if err != nil {
		return nil, err
	}
	words[33], err = encodeSelector24BCond(address(33), address(outerLoop), 1)
	if err != nil {
		return nil, err
	}
	words[34], err = encodeSelector24B(address(success), selector24NativeSuccess)
	if err != nil {
		return nil, err
	}
	words[35], err = encodeSelector24B(address(failure), selector24StockFailure)
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
	if len(payload) != dyldCacheSelector24Instruction*4+dyldCacheSelector24HashCount*dyldCacheSelector24HashBytes || len(payload) > selector24CaveBytes {
		return errors.New("dyld cache selector-24 payload size changed")
	}
	word := func(index int) uint32 { return binary.LittleEndian.Uint32(payload[index*4:]) }
	address := func(index int) uint64 { return selector24GateAddress + uint64(index*4) }
	if word(0) != 0xd503249f || word(2) != 0x7100141f || word(5) != 0xf9404269 ||
		word(7) != 0xb940012a || word(8) != 0x529bdf4b || word(9) != 0x72a0418b || word(10) != 0x6b0b015f ||
		word(12) != 0x39403d2a || word(14) != 0x3940352a || word(16) != 0x91016269 || word(18) != 0x5280036b ||
		word(19) != 0xaa0903ed || word(20) != 0xaa0a03ee || word(21) != 0x5280028f ||
		word(22) != 0x394001b0 || word(23) != 0x394001d1 || word(24) != 0x6b11021f ||
		word(31) != 0x9100514a || word(32) != 0x7100056b {
		return errors.New("dyld cache selector-24 fixed instruction changed")
	}
	wantBranches := map[int]uint64{
		1: address(34), 3: address(35), 4: address(35), 6: address(16), 11: address(16),
		13: address(16), 15: address(34), 25: address(31), 29: address(22),
		30: address(34), 33: address(19), 34: selector24NativeSuccess, 35: selector24StockFailure,
	}
	for index, want := range wantBranches {
		bits, shift := uint(19), uint(5)
		if index == 13 || index == 15 {
			bits = 14
		}
		if index == 30 || index >= 34 {
			bits, shift = 26, 0
		}
		if got := selector24BranchTarget(address(index), word(index), bits, shift); got != want {
			return fmt.Errorf("dyld cache selector-24 branch %d targets %#x, want %#x", index, got, want)
		}
	}
	if got, want := selector24ADRTarget(address(17), word(17)), selector24GateAddress+dyldCacheSelector24Instruction*4; got != want {
		return fmt.Errorf("dyld cache selector-24 table address %#x, want %#x", got, want)
	}
	if digest(payload[dyldCacheSelector24Instruction*4:]) != dyldCacheCDHashTableSHA256 {
		return errors.New("dyld cache selector-24 embedded table changed")
	}
	return nil
}

// buildUniversalSelector24Gate is the physically qualified selector-24
// transform. It touches only caller-saved X9-X11 and preserves every system
// identity on the native path. In particular, it does not embed or iterate a
// CDHash table: the previous table loop clobbered live continuation registers
// and was never safe to combine with this gate.
func buildUniversalSelector24Gate() ([]byte, error) {
	const success, failure = 28, 29
	words := []uint32{
		0xd503249f, 0, 0x7100141f, 0, 0, 0xf9404269, 0, 0xb940012a,
		0x529bdf4b, 0x72a0418b, 0x6b0b015f, 0, 0x39403d2a, 0, 0x3940352a, 0,
		0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f,
		0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f,
		0, 0,
	}
	if len(words) != selector24UniversalWords {
		return nil, errors.New("universal selector-24 instruction count changed")
	}
	address := func(index int) uint64 { return selector24GateAddress + uint64(index*4) }
	var err error
	words[1], err = encodeSelector24CBZ64(address(1), address(success), 0)
	if err != nil {
		return nil, err
	}
	for _, index := range []int{3, 11} {
		words[index], err = encodeSelector24BCond(address(index), address(failure), 1)
		if err != nil {
			return nil, err
		}
	}
	for _, spec := range []struct {
		index    int
		register uint32
	}{{4, 19}, {6, 9}} {
		words[spec.index], err = encodeSelector24CBZ64(address(spec.index), address(failure), spec.register)
		if err != nil {
			return nil, err
		}
	}
	for _, index := range []int{13, 15} {
		words[index], err = encodeSelector24TestBit(address(index), address(failure), 10, 1, false)
		if err != nil {
			return nil, err
		}
	}
	words[success], err = encodeSelector24B(address(success), selector24NativeSuccess)
	if err != nil {
		return nil, err
	}
	words[failure], err = encodeSelector24B(address(failure), selector24StockFailure)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, len(words)*4)
	for index, word := range words {
		binary.LittleEndian.PutUint32(payload[index*4:], word)
	}
	if err = validateUniversalSelector24Gate(payload); err != nil {
		return nil, err
	}
	if digest(payload) != selector24GatePayloadSHA256 {
		return nil, errors.New("universal selector-24 payload identity changed")
	}
	return payload, nil
}

func validateUniversalSelector24Gate(payload []byte) error {
	if len(payload) != selector24UniversalWords*4 {
		return errors.New("universal selector-24 payload size changed")
	}
	word := func(index int) uint32 { return binary.LittleEndian.Uint32(payload[index*4:]) }
	address := func(index int) uint64 { return selector24GateAddress + uint64(index*4) }
	if word(0) != 0xd503249f || word(2) != 0x7100141f || word(5) != 0xf9404269 ||
		word(7) != 0xb940012a || word(8) != 0x529bdf4b || word(9) != 0x72a0418b ||
		word(10) != 0x6b0b015f || word(12) != 0x39403d2a || word(14) != 0x3940352a {
		return errors.New("universal selector-24 fixed instruction changed")
	}
	for index := 16; index <= 27; index++ {
		if word(index) != 0xd503201f {
			return errors.New("universal selector-24 identifier-free padding changed")
		}
	}
	want := map[int]uint64{1: address(28), 3: address(29), 4: address(29), 6: address(29), 11: address(29), 13: address(29), 15: address(29), 28: selector24NativeSuccess, 29: selector24StockFailure}
	for index, target := range want {
		bits, shift := uint(19), uint(5)
		if index == 13 || index == 15 {
			bits = 14
		}
		if index >= 28 {
			bits, shift = 26, 0
		}
		if got := selector24BranchTarget(address(index), word(index), bits, shift); got != target {
			return fmt.Errorf("universal selector-24 branch %d targets %#x, want %#x", index, got, target)
		}
	}
	return nil
}

func buildSelector33LinkerSignedGate(address uint64) ([]byte, error) {
	const tail = 27
	words := []uint32{
		0xd503245f, 0, 0xf9404269, 0, 0xb940012a, 0x529bdf4b, 0x72a0418b, 0x6b0b015f, 0,
		0x39403d2a, 0, 0x3940352a, 0,
		0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f,
		0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f,
		0x52800000, 0xd65f03c0, 0xd503201f, 0,
	}
	if len(words) != selector33GateInstructions {
		return nil, errors.New("selector-33 linker-signed gate instruction count changed")
	}
	addressAt := func(index int) uint64 { return address + uint64(index*4) }
	var err error
	words[1], err = encodeSelector24CBZ64(addressAt(1), addressAt(tail), 19)
	if err != nil {
		return nil, err
	}
	words[3], err = encodeSelector24CBZ64(addressAt(3), addressAt(tail), 9)
	if err != nil {
		return nil, err
	}
	words[8], err = encodeSelector24BCond(addressAt(8), addressAt(tail), 1)
	if err != nil {
		return nil, err
	}
	words[10], err = encodeSelector24TestBit(addressAt(10), addressAt(tail), 10, 1, false)
	if err != nil {
		return nil, err
	}
	words[12], err = encodeSelector24TestBit(addressAt(12), addressAt(tail), 10, 1, false)
	if err != nil {
		return nil, err
	}
	words[27], err = encodeSelector24B(addressAt(27), selector33OriginalTarget)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, len(words)*4)
	for index, word := range words {
		binary.LittleEndian.PutUint32(payload[index*4:], word)
	}
	return payload, validateSelector33LinkerSignedGate(address, payload)
}

func validateSelector33LinkerSignedGate(address uint64, payload []byte) error {
	if len(payload) != selector33GateInstructions*4 {
		return errors.New("selector-33 linker-signed gate size changed")
	}
	word := func(index int) uint32 { return binary.LittleEndian.Uint32(payload[index*4:]) }
	if word(0) != 0xd503245f || word(2) != 0xf9404269 || word(4) != 0xb940012a ||
		word(5) != 0x529bdf4b || word(6) != 0x72a0418b || word(7) != 0x6b0b015f ||
		word(9) != 0x39403d2a || word(11) != 0x3940352a || word(24) != 0x52800000 ||
		word(25) != 0xd65f03c0 || word(26) != 0xd503201f {
		return errors.New("selector-33 linker-signed gate fixed instruction changed")
	}
	want := map[int]uint64{1: address + 27*4, 3: address + 27*4, 8: address + 27*4, 10: address + 27*4, 12: address + 27*4, 27: selector33OriginalTarget}
	for index, target := range want {
		bits, shift := uint(19), uint(5)
		if index == 10 || index == 12 {
			bits = 14
		}
		if index == 27 {
			bits, shift = 26, 0
		}
		if got := selector24BranchTarget(address+uint64(index*4), word(index), bits, shift); got != target {
			return fmt.Errorf("selector-33 linker-signed branch %d targets %#x, want %#x", index, got, target)
		}
	}
	return nil
}

func patchRuntimeCallerAuthorizationGate(raw []byte, entries []trustEntry) (bool, error) {
	// Payload and legacy trust rows do not alter the physically qualified gate.
	// They are accepted only by their separate manifest validators.
	_ = entries
	if selector24GateOffset > len(raw)-selector24CaveBytes || selector24ResultOffset > len(raw)-4 || selector33CallOffset > len(raw)-4 {
		return false, errors.New("runtime kernel lacks selector-24 policy range")
	}
	wrapperOffset := selector33OldGateOffset
	wrapperAddress := selector24GateAddress + uint64(wrapperOffset)
	oldSelector33Call, callErr := encodeSelector24BL(selector33CallAddress, wrapperAddress)
	if callErr != nil {
		return false, callErr
	}
	selector24End := selector24GateOffset + selector24UniversalWords*4
	selector33Offset := selector24GateOffset + wrapperOffset
	selector33End := selector33Offset + selector33GateInstructions*4
	if digest(raw[selector24GateOffset:selector24GateOffset+selector24CaveBytes]) != selector24CavePreimageSHA256 ||
		digest(raw[selector24GateOffset:selector24End]) != selector24GatePreimageSHA256 ||
		digest(raw[selector33Offset:selector33End]) != selector33GatePostimageSHA256 ||
		binary.LittleEndian.Uint32(raw[selector24ResultOffset:]) != selector24ResultPreimage ||
		binary.LittleEndian.Uint32(raw[selector33CallOffset:]) != oldSelector33Call {
		return false, fmt.Errorf("runtime kernel selector gate preimage changed: cave=%s selector24=%s selector33=%s result=%08x call=%08x", digest(raw[selector24GateOffset:selector24GateOffset+selector24CaveBytes]), digest(raw[selector24GateOffset:selector24End]), digest(raw[selector33Offset:selector33End]), binary.LittleEndian.Uint32(raw[selector24ResultOffset:]), binary.LittleEndian.Uint32(raw[selector33CallOffset:]))
	}
	payload, err := buildUniversalSelector24Gate()
	if err != nil {
		return false, err
	}
	wrapper, err := buildSelector33LinkerSignedGate(wrapperAddress)
	if err != nil {
		return false, err
	}
	changed := 0
	for index, before := range raw[selector24GateOffset:selector24End] {
		if before != payload[index] {
			changed++
		}
	}
	if !bytes.Equal(raw[selector33Offset:selector33End], wrapper) || digest(wrapper) != selector33GatePostimageSHA256 || selector24GateChangedPositions != 0 && changed != selector24GateChangedPositions {
		return false, errors.New("runtime kernel selector-24 gate derived postimage changed")
	}
	copy(raw[selector24GateOffset:selector24End], payload)
	if !bytes.Equal(raw[selector24GateOffset:selector24End], payload) ||
		!bytes.Equal(raw[selector33Offset:selector33End], wrapper) ||
		binary.LittleEndian.Uint32(raw[selector33CallOffset:]) != oldSelector33Call {
		return false, errors.New("runtime kernel selector-24 gate postimage changed")
	}
	return true, nil
}
