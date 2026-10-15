package main

import (
	"bytes"
	"testing"
)

func TestImageRoundTripAndTailPreservation(t *testing.T) {
	p := encodeDER(0x30, bytes.Join([][]byte{encodeDER(0x16, []byte("IM4P")), encodeDER(0x16, []byte("krnl")), encodeDER(0x16, []byte("1")), encodeDER(4, []byte("payload")), encodeDER(0xa0, []byte{1, 2, 3})}, nil))
	policy := encodeDER(0x30, encodeDER(0x16, []byte("IM4M")))
	wrapped, err := wrapImage(p, policy)
	if err != nil {
		t.Fatal(err)
	}
	got, manifest, err := unwrapImage(wrapped)
	if err != nil || !bytes.Equal(got, p) || !bytes.Equal(manifest, policy) {
		t.Fatal("round trip", err)
	}
	changed, err := replacePayload(p, "rkrn", []byte("different"))
	if err != nil {
		t.Fatal(err)
	}
	fields, err := imageFields(changed, "IM4P")
	if err != nil || string(fields[1].body) != "rkrn" || string(fields[3].body) != "different" || !bytes.Equal(fields[4].body, []byte{1, 2, 3}) {
		t.Fatal("field preservation", err)
	}
}

func TestDERRejectsMalformed(t *testing.T) {
	for _, b := range [][]byte{nil, {0x30}, {0x30, 0x80}, {0x30, 0x81, 0x01, 0}, {0x30, 0x82, 0, 1, 0}, {0x30, 10, 1}, {0xff, 0x80}} {
		if _, _, err := readDER(b); err == nil {
			t.Errorf("accepted %x", b)
		}
	}
}

func TestGuardedPatches(t *testing.T) {
	source := []byte{0, 1, 2, 3, 4}
	hash := digest(source)
	got, err := patchBytes(source, hash, []patch{{1, "0102", "0405"}})
	if err != nil || !bytes.Equal(got, []byte{0, 4, 5, 3, 4}) || source[1] != 1 {
		t.Fatal("patch", got, err)
	}
	for _, patches := range [][]patch{{{-1, "01", "02"}}, {{4, "0102", "0304"}}, {{1, "02", "04"}}, {{1, "01", "0000"}}, {{1, "0102", "0304"}, {2, "02", "03"}}} {
		if _, err := patchBytes(source, hash, patches); err == nil {
			t.Fatal("invalid patch accepted")
		}
	}
	if _, err := patchBytes(source, digest([]byte("other")), nil); err == nil {
		t.Fatal("wrong hash accepted")
	}
}

func TestUniqueOffset(t *testing.T) {
	at, err := uniqueOffset([]byte("prefix-value-suffix"), []byte("value"), "test value")
	if err != nil || at != 7 {
		t.Fatalf("unique offset = %d, %v", at, err)
	}
	for _, input := range [][]byte{[]byte("missing"), []byte("value-value")} {
		if _, err = uniqueOffset(input, []byte("value"), "test value"); err == nil {
			t.Fatalf("accepted ambiguous input %q", input)
		}
	}
	if _, err = uniqueOffset(nil, nil, "test value"); err == nil {
		t.Fatal("accepted empty pattern")
	}
}

func FuzzDER(f *testing.F) {
	f.Add([]byte{0x30, 3, 0x16, 1, 'x'})
	f.Fuzz(func(t *testing.T, b []byte) {
		if d, rest, err := readDER(b); err == nil {
			if len(d.raw)+len(rest) != len(b) {
				t.Fatal("length")
			}
		}
	})
}
