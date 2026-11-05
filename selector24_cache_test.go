package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func dyldCacheSelector24Fixture(t *testing.T) []trustEntry {
	t.Helper()
	hashes := []string{
		"8ffe11d6449361c060b04d009e65c6bc704aa5d1",
		"23aa87f4d718410092a79d2c5381243608c9c0b4",
		"db6adf5298c372eee0543e57689471a69f650ea4",
		"df8209618a5b099f14ca8c31f3235ddfa6c2cb8c",
		"86989eaa8c046f0b2a5dfefb7e2ecd385e1ad13a",
		"5bc2607be7be341c976c9851ec30a1bb2d1612ac",
		"49cb92c62ec8466dbc24634904de2a1acf74eca7",
		"d31cea1dda80145977f36d90d2a2d3c487fefa09",
		"2739df3e5677fd6560b528b85db58205f3b53a79",
		"bd4ce55fb4e6d499fa4f9b779ee5d65003415128",
		"4553ed8f4339af112591acdf14686cb89c1f0134",
		"5d310e3ffad856d6b995ac7d9232bc8e6291c69b",
		"f529a04cf041d2f5282c1b1f57a39a68dbc393c7",
		"840abd913534268af63fea542dd8730a2ea0e1d1",
		"cd6ced0933ff0ee14706e94f29607d9a797731c1",
		"c19896ee37ac45b0d0ceed4e0c13bf74c4aebf5e",
		"b18c39f17f653b9f0780e93f67836c6a3066ca83",
		"5961595aee002a2559abde721894ae673dd91d66",
		"0369bc7530dacb7f4a775ac2cdcba568c0732175",
		"c044e57da0d5d9760629a1be46c6c5393b895458",
		"13168a38a472bfad87d16bac6b70b8b0b6c9ca40",
		"ebf55966a27e140e6434879a38442960d01305ae",
		"88de33b7b54e990dea871224ae38e43a72bb2b5a",
		"c254c1c5438b55d9fae32149114f57d279680fd4",
		"15f8975eecf93d6a093ae3d322a4cd192317c17e",
		"c75937357056e4c673e90cdd250c420a9c6b3dc1",
		"17bad4bc91da8372d963990eca50de6835750db7",
	}
	names := dyldCacheTrustNames()
	if len(names) != len(hashes) {
		t.Fatalf("fixture names=%d hashes=%d", len(names), len(hashes))
	}
	entries := make([]trustEntry, len(names))
	for index := range names {
		entries[index] = trustEntry{Name: names[index], CDHash: hashes[index], Origin: "exact iOS 17.0 NonUI production cache"}
	}
	return entries
}

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

func TestRuntimeSelector24DyldCacheGate(t *testing.T) {
	path := os.Getenv("KERNEL_POC_PREPARED_KERNEL")
	if path == "" {
		t.Skip("set KERNEL_POC_PREPARED_KERNEL for the exact prepared-kernel integration check")
	}
	component, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := dyldCacheSelector24Fixture(t)
	hashes, enabled, err := dyldCacheSelector24Hashes(entries)
	if err != nil || !enabled {
		t.Fatalf("exact cache set: enabled=%t err=%v", enabled, err)
	}
	payload, err := buildDyldCacheSelector24Gate(hashes)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 636 || digest(payload) != selector24GatePayloadSHA256 {
		t.Fatalf("payload bytes=%d want 636", len(payload))
	}

	raw := decodeRuntimeKernelForTest(t, component)
	preimage := bytes.Clone(raw)
	enabled, err = patchRuntimeSelector24DyldCacheGate(raw, entries)
	if err != nil || !enabled {
		t.Fatalf("patch exact cache gate: enabled=%t err=%v", enabled, err)
	}
	if !bytes.Equal(raw[:selector24GateOffset], preimage[:selector24GateOffset]) ||
		!bytes.Equal(raw[selector24GateOffset+selector24GatePreimageBytes:], preimage[selector24GateOffset+selector24GatePreimageBytes:]) {
		t.Fatal("selector-24 cache gate changed bytes outside its exact preimage")
	}
	if !bytes.Equal(raw[selector24GateOffset:selector24GateOffset+len(payload)], payload) ||
		!bytes.Equal(raw[selector24GateOffset+len(payload):selector24GateOffset+selector24GatePreimageBytes], make([]byte, selector24GatePreimageBytes-len(payload))) {
		t.Fatal("selector-24 cache gate payload or bounded zero fill changed")
	}
	changed := 0
	for index := range raw {
		if raw[index] != preimage[index] {
			changed++
		}
	}
	inverse := bytes.Clone(raw)
	copy(inverse[selector24GateOffset:selector24GateOffset+selector24GatePreimageBytes], preimage[selector24GateOffset:selector24GateOffset+selector24GatePreimageBytes])
	if changed != selector24GateChangedPositions || digest(raw[selector24GateOffset:selector24GateOffset+selector24GatePreimageBytes]) != selector24GatePostimageSHA256 || !bytes.Equal(inverse, preimage) {
		t.Fatal("selector-24 cache gate inverse is not exact")
	}

	baseComponent, err := prepareRuntimeKernel(component)
	if err != nil {
		t.Fatal(err)
	}
	gatedComponent, err := prepareRuntimeKernelWithTrust(component, entries)
	if err != nil {
		t.Fatal(err)
	}
	baseRaw := decodeRuntimeKernelForTest(t, baseComponent)
	gatedRaw := decodeRuntimeKernelForTest(t, gatedComponent)
	if digest(gatedRaw) != selector24KernelDecodedSHA256 || digest(gatedComponent) != selector24KernelIM4PSHA256 || len(gatedComponent) != selector24KernelIM4PBytes {
		t.Fatal("prepared selector-24 cache kernel identity changed")
	}
	if !bytes.Equal(baseRaw[:selector24GateOffset], gatedRaw[:selector24GateOffset]) ||
		!bytes.Equal(baseRaw[selector24GateOffset+selector24GatePreimageBytes:], gatedRaw[selector24GateOffset+selector24GatePreimageBytes:]) ||
		!bytes.Equal(gatedRaw[selector24GateOffset:selector24GateOffset+len(payload)], payload) {
		t.Fatal("runtime kernel integration changed bytes outside the cache gate")
	}

	noGate := bytes.Clone(preimage)
	if active, noGateErr := patchRuntimeSelector24DyldCacheGate(noGate, nil); noGateErr != nil || active || !bytes.Equal(noGate, preimage) {
		t.Fatalf("empty trust set changed kernel: active=%t err=%v", active, noGateErr)
	}
	partial := bytes.Clone(preimage)
	if active, partialErr := patchRuntimeSelector24DyldCacheGate(partial, entries[:len(entries)-1]); partialErr == nil || active || !bytes.Equal(partial, preimage) {
		t.Fatalf("partial trust set did not fail closed: active=%t err=%v", active, partialErr)
	}
	mutatedEntries := append([]trustEntry(nil), entries...)
	mutatedEntries[0].CDHash = "0" + mutatedEntries[0].CDHash[1:]
	mutated := bytes.Clone(preimage)
	if active, mutationErr := patchRuntimeSelector24DyldCacheGate(mutated, mutatedEntries); mutationErr == nil || active || !bytes.Equal(mutated, preimage) {
		t.Fatalf("changed cache identity did not fail closed: active=%t err=%v", active, mutationErr)
	}
	extraEntries := append([]trustEntry(nil), entries...)
	extraEntries = append(extraEntries, trustEntry{Name: "dyld_shared_cache_arm64e.extra", CDHash: strings.Repeat("1", 40)})
	extra := bytes.Clone(preimage)
	if active, extraErr := patchRuntimeSelector24DyldCacheGate(extra, extraEntries); extraErr == nil || active || !bytes.Equal(extra, preimage) {
		t.Fatalf("extra cache identity did not fail closed: active=%t err=%v", active, extraErr)
	}
	t.Logf("selector24_payload_sha256=%s gate_postimage_sha256=%s changed_positions=%d prepared_kernel_decoded_sha256=%s prepared_kernel_sha256=%s prepared_kernel_bytes=%d", digest(payload), digest(raw[selector24GateOffset:selector24GateOffset+selector24GatePreimageBytes]), changed, digest(gatedRaw), digest(gatedComponent), len(gatedComponent))
}
