package main

import (
	"bytes"
	"os"
	"testing"
)

func decodeRuntimeKernelForTest(t *testing.T, component []byte) []byte {
	t.Helper()
	fields, err := imageFields(component, "IM4P")
	if err != nil || len(fields) < 4 {
		t.Fatalf("runtime kernel IM4P: fields=%d err=%v", len(fields), err)
	}
	raw, err := compression(fields[3].body, canonicalRuntime.Kernel.DecodedSize, false, false)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRuntimeCallerAuthorizationGate(t *testing.T) {
	path := os.Getenv("KERNEL_POC_PREPARED_KERNEL")
	if path == "" {
		t.Skip("set KERNEL_POC_PREPARED_KERNEL for the exact prepared-kernel integration check")
	}
	component, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := buildUniversalSelector24Gate()
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 120 || digest(payload) != selector24GatePayloadSHA256 {
		t.Fatalf("payload bytes=%d want 120", len(payload))
	}

	raw := decodeRuntimeKernelForTest(t, component)
	preimage := bytes.Clone(raw)
	enabled, err := patchRuntimeCallerAuthorizationGate(raw, nil)
	if err != nil || !enabled {
		t.Fatalf("patch exact cache gate: enabled=%t err=%v", enabled, err)
	}
	wrapperOffset := selector33OldGateOffset
	wrapper, err := buildSelector33LinkerSignedGate(selector24GateAddress + uint64(wrapperOffset))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw[selector24GateOffset:selector24GateOffset+len(payload)], payload) ||
		!bytes.Equal(raw[selector24GateOffset+wrapperOffset:selector24GateOffset+wrapperOffset+len(wrapper)], wrapper) {
		t.Fatal("combined selector-24/selector-33 payload changed")
	}
	for index := range raw {
		inSelector24 := index >= selector24GateOffset && index < selector24GateOffset+len(payload)
		inSelector33 := index >= selector24GateOffset+wrapperOffset && index < selector24GateOffset+wrapperOffset+len(wrapper)
		if !inSelector24 && !inSelector33 && raw[index] != preimage[index] {
			t.Fatalf("authorization gate changed byte outside its two exact ranges at %#x", index)
		}
	}
	changed := 0
	for index := range raw {
		if raw[index] != preimage[index] {
			changed++
		}
	}
	inverse := bytes.Clone(raw)
	copy(inverse[selector24GateOffset:selector24GateOffset+len(payload)], preimage[selector24GateOffset:selector24GateOffset+len(payload)])
	copy(inverse[selector24GateOffset+wrapperOffset:selector24GateOffset+wrapperOffset+len(wrapper)], preimage[selector24GateOffset+wrapperOffset:selector24GateOffset+wrapperOffset+len(wrapper)])
	if selector24GateChangedPositions != 0 && changed != selector24GateChangedPositions || digest(wrapper) != selector33GatePostimageSHA256 || !bytes.Equal(inverse, preimage) {
		t.Fatal("combined authorization gate inverse is not exact")
	}

	baseComponent, err := prepareRuntimeKernel(component)
	if err != nil {
		t.Fatal(err)
	}
	gatedComponent, err := prepareRuntimeKernelWithTrust(component, nil)
	if err != nil {
		t.Fatal(err)
	}
	baseRaw := decodeRuntimeKernelForTest(t, baseComponent)
	gatedRaw := decodeRuntimeKernelForTest(t, gatedComponent)
	if selector24KernelDecodedSHA256 != "" && (digest(gatedRaw) != selector24KernelDecodedSHA256 || digest(gatedComponent) != selector24KernelIM4PSHA256 || len(gatedComponent) != selector24KernelIM4PBytes) {
		t.Fatalf("prepared selector-24 gate identity changed: decoded=%s im4p=%s bytes=%d", digest(gatedRaw), digest(gatedComponent), len(gatedComponent))
	}
	if !bytes.Equal(baseRaw, gatedRaw) || !bytes.Equal(gatedRaw[selector24GateOffset:selector24GateOffset+len(payload)], payload) {
		t.Fatal("legacy dyld rows changed the automatic authorization kernel")
	}

	noGate := bytes.Clone(preimage)
	if active, noGateErr := patchRuntimeCallerAuthorizationGate(noGate, nil); noGateErr != nil || !active || !bytes.Equal(noGate, raw) {
		t.Fatalf("automatic profile did not reproduce gate: active=%t err=%v", active, noGateErr)
	}
	t.Logf("selector24_payload_sha256=%s selector33_wrapper_sha256=%s changed_positions=%d prepared_kernel_decoded_sha256=%s prepared_kernel_sha256=%s prepared_kernel_bytes=%d", digest(payload), digest(wrapper), changed, digest(gatedRaw), digest(gatedComponent), len(gatedComponent))
}
