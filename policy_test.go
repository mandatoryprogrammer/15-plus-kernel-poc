package main

import (
	"bytes"
	"crypto/sha512"
	"testing"
)

func testIM4P(kind string, payload []byte) []byte {
	return encodeDER(0x30, bytes.Join([][]byte{
		encodeDER(0x16, []byte("IM4P")),
		encodeDER(0x16, []byte(kind)),
		encodeDER(0x16, []byte("test")),
		encodeDER(4, payload),
	}, nil))
}

func TestPolicyManifestIsUnsignedAndComponentBound(t *testing.T) {
	component := testIM4P("ibec", []byte("component"))
	manifest, err := policyManifest(component)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := imageFields(manifest, "IM4M")
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 5 || fields[3].tag != 4 || len(fields[3].body) != 512 || !bytes.Equal(fields[3].body, make([]byte, 512)) {
		t.Fatal("policy signature field is not the expected zero placeholder")
	}
	if fields[4].tag != 0x30 || len(fields[4].body) != 0 {
		t.Fatal("policy certificate sequence is not empty")
	}
	want := sha512.Sum384(component)
	if bytes.Count(manifest, want[:]) != 1 {
		t.Fatal("component SHA-384 is not represented exactly once")
	}
	for _, forbidden := range [][]byte{[]byte("ApECID"), []byte("CERT"), []byte("NONC")} {
		if bytes.Contains(manifest, forbidden) {
			t.Fatalf("unexpected board-bound property %q", forbidden)
		}
	}
}

func TestPolicyManifestChangesWithComponent(t *testing.T) {
	a, err := policyManifest(testIM4P("ibec", []byte("a")))
	if err != nil {
		t.Fatal(err)
	}
	b, err := policyManifest(testIM4P("ibec", []byte("b")))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("different components received identical policies")
	}
}
