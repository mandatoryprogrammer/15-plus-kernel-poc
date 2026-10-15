package main

import (
	"bytes"
	"testing"
)

func TestRootSelectionFieldIsDerivedFromLiveOwner(t *testing.T) {
	block := bytes.Repeat([]byte{0xa5}, 2048)
	field := 517
	actual := "-v serial=3 debug=0x14e keepsym"
	for index := field; index < len(block); index++ {
		block[index] = 0
	}
	copy(block[field:], actual)
	at, before, after, err := rootArgumentEdit(block, canonicalRuntime.Root.BootArguments, canonicalRuntime.Root.RootArguments)
	if err != nil {
		t.Fatal(err)
	}
	if at != field || string(bytes.TrimRight(before, "\x00")) != actual || string(bytes.TrimRight(after, "\x00")) != canonicalRuntime.Root.RootArguments {
		t.Fatalf("unexpected dynamic edit at=%d before=%q after=%q", at, before, after)
	}
	copy(block[900:], actual)
	block[900+len(actual)] = 0
	if _, _, _, err = rootArgumentEdit(block, canonicalRuntime.Root.BootArguments, canonicalRuntime.Root.RootArguments); err == nil {
		t.Fatal("ambiguous live command-line fields accepted")
	}
}

func TestAccessPortIdentityIgnoresRevisionAndIndex(t *testing.T) {
	for id, want := range map[uint32]string{
		0x04770002: "control",
		0x34770002: "control",
		0x04760010: "router",
		0xa4760010: "router",
		0x04770004: "application",
		0xf4770004: "application",
		0x04770003: "",
	} {
		if got := accessPortRole(id); got != want {
			t.Fatalf("access port 0x%08x: got %q, want %q", id, got, want)
		}
	}
}

func TestProbeDescriptorAllowsFirmwareVariation(t *testing.T) {
	for _, descriptor := range [][]byte{
		{0x0a, 0, 0, 0, 0x22, 0x81, 0, 1},
		{0x0b, 0, 0, 0, 0x23, 0x81, 0, 2, 1, 0, 0, 0},
	} {
		if err := validateProbeDescriptor(descriptor); err != nil {
			t.Fatalf("compatible firmware descriptor rejected: %v", err)
		}
	}
	for _, descriptor := range [][]byte{
		nil,
		make([]byte, 7),
		make([]byte, 8),
		bytes.Repeat([]byte{0xff}, 8),
		make([]byte, 257),
	} {
		if err := validateProbeDescriptor(descriptor); err == nil {
			t.Fatalf("invalid firmware descriptor accepted: %x", descriptor)
		}
	}
}

func TestProbeMemoryNegotiationPreservesAtomicWidths(t *testing.T) {
	if got := reducedProbeMemoryLimit(1024, 4); got != 1024 {
		t.Fatalf("word access changed bulk limit to %d", got)
	}
	if got := reducedProbeMemoryLimit(1024, 8); got != 1024 {
		t.Fatalf("doubleword access changed bulk limit to %d", got)
	}
	if got := reducedProbeMemoryLimit(1024, 1024); got != 512 {
		t.Fatalf("bulk failure reduced limit to %d", got)
	}
	if got := reducedProbeMemoryLimit(16, 12); got != 8 {
		t.Fatalf("bulk limit crossed atomic floor: %d", got)
	}
}

func TestLoaderIdentityChallengeIsAlignedAndReversible(t *testing.T) {
	build := "iBoot-1234.5"
	header := make([]byte, 0x1000)
	copy(header[0x283:], append([]byte(build), 0))
	offset, before, after, marker, err := loaderIdentityChallenge(header, build)
	if err != nil {
		t.Fatal(err)
	}
	if offset%4 != 0 || len(before)%4 != 0 || len(before) != len(after) || marker == build || len(marker) != len(build) {
		t.Fatalf("invalid challenge geometry: offset=%x before=%d after=%d marker=%q", offset, len(before), len(after), marker)
	}
	challenged := bytes.Clone(header)
	copy(challenged[offset:], after)
	if got, err := loaderBuild(challenged, marker); err != nil || got != marker {
		t.Fatalf("challenge is not observable: got=%q err=%v", got, err)
	}
	copy(challenged[offset:], before)
	if !bytes.Equal(challenged, header) {
		t.Fatal("challenge restoration changed the loader header")
	}
}
