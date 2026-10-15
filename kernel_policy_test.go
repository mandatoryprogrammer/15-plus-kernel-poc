package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestNeutralKernelPolicyRemovesDeviceAdmissionData(t *testing.T) {
	input, err := policyManifest(testIM4P("krnl", []byte("kernel")))
	if err != nil {
		t.Fatal(err)
	}
	output, err := neutralKernelPolicy(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("ECID"), []byte("UDID")} {
		if bytes.Contains(output, forbidden) {
			t.Fatalf("neutral policy retains %s", forbidden)
		}
	}
	fields, err := imageFields(output, "IM4M")
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 5 || !bytes.Equal(fields[3].body, make([]byte, len(fields[3].body))) || len(fields[4].body) != 0 {
		t.Fatal("neutral policy retained signature or certificate data")
	}
}

func TestLocateKernelPolicyFromStructure(t *testing.T) {
	policy, err := policyManifest(testIM4P("krnl", []byte("kernel")))
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 0x30000)
	policyAt, instructionAt := 0x20000, 0x18000
	copy(raw[policyAt:], policy)
	instruction := uint32(0xd2800004) | uint32(len(policy))<<5
	binary.LittleEndian.PutUint32(raw[instructionAt:], instruction)
	location, err := locateKernelPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	if location.policy != policyAt || location.capacity != len(policy) || location.lengthInstruction != instructionAt {
		t.Fatalf("unexpected location: %+v", location)
	}
	binary.LittleEndian.PutUint32(raw[instructionAt+4:], instruction)
	if _, err = locateKernelPolicy(raw); err == nil {
		t.Fatal("accepted ambiguous policy-length instruction")
	}
}
