package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestTrustOnlyCodeDirectoryProjection(t *testing.T) {
	entries, err := parseTrustTSV(strings.NewReader("dyld_shared_cache_arm64e\t" + strings.Repeat("20", 20) + "\n" +
		"dyld_shared_cache_arm64e.01\t" + strings.Repeat("30", 20) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	projected := trustPayloadEntries(entries)
	if len(projected) != 2 || projected[0].Destination != "trust:dyld_shared_cache_arm64e" || projected[1].Destination != "trust:dyld_shared_cache_arm64e.01" {
		t.Fatalf("trust projection changed: %+v", projected)
	}
	got, err := extendTrustCache(trustFixture(0x10, 0x40), projected)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := imageFields(got, "IM4P")
	if err != nil {
		t.Fatal(err)
	}
	payload := fields[3].body
	if binary.LittleEndian.Uint32(payload[20:24]) != 4 || !bytes.Equal(payload[24:46], append(bytes.Repeat([]byte{0x10}, 20), 2, 0)) ||
		payload[46] != 0x20 || payload[68] != 0x30 || payload[90] != 0x40 {
		t.Fatalf("trust-only entries were not inserted exactly: %x", payload[24:])
	}
}

func TestTrustOnlyImportRejectsMalformedRows(t *testing.T) {
	valid := strings.Repeat("20", 20)
	lettered := strings.Repeat("ab", 20)
	cases := map[string]string{
		"wrong-fields":   "name " + valid,
		"invalid-name":   "../cache\t" + valid,
		"uppercase-hash": "cache\t" + strings.ToUpper(lettered),
		"duplicate-name": "cache\t" + valid + "\ncache\t" + strings.Repeat("30", 20),
		"duplicate-hash": "cache\t" + valid + "\ncache.01\t" + valid,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTrustTSV(strings.NewReader(input)); err == nil {
				t.Fatal("malformed trust import accepted")
			}
		})
	}
}
