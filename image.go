package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

func digest(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// uniqueOffset locates structural data whose value is already authenticated by
// a surrounding component hash.  Requiring exactly one occurrence avoids
// turning a format-derived lookup into an ambiguous pattern scan.
func uniqueOffset(input, pattern []byte, name string) (int, error) {
	if len(pattern) == 0 {
		return 0, fmt.Errorf("%s pattern is empty", name)
	}
	at := bytes.Index(input, pattern)
	if at < 0 {
		return 0, fmt.Errorf("%s is absent", name)
	}
	if bytes.Index(input[at+len(pattern):], pattern) >= 0 {
		return 0, fmt.Errorf("%s is not unique", name)
	}
	return at, nil
}

// DER parsing preserves optional Image4 fields byte for byte. High-tag-number
// elements occur in personalized manifests; lengths must be canonical and bounded.
type der struct {
	tag       byte
	raw, body []byte
}

func readDER(b []byte) (der, []byte, error) {
	if len(b) < 2 {
		return der{}, nil, errors.New("truncated DER")
	}
	pos := 1
	if b[0]&31 == 31 {
		for n := 0; ; n++ {
			if pos >= len(b) || n >= 6 {
				return der{}, nil, errors.New("invalid DER tag")
			}
			v := b[pos]
			pos++
			if v&128 == 0 {
				break
			}
		}
	}
	if pos >= len(b) {
		return der{}, nil, errors.New("missing DER length")
	}
	n := int(b[pos])
	pos++
	if n&128 != 0 {
		count := n & 127
		if count == 0 || count > 4 || pos+count > len(b) || b[pos] == 0 {
			return der{}, nil, errors.New("invalid DER length")
		}
		n = 0
		for i := 0; i < count; i++ {
			n = n<<8 | int(b[pos])
			pos++
		}
		if n < 128 {
			return der{}, nil, errors.New("noncanonical DER length")
		}
	}
	if n > len(b)-pos {
		return der{}, nil, errors.New("DER length exceeds input")
	}
	return der{b[0], b[:pos+n], b[pos : pos+n]}, b[pos+n:], nil
}

func children(b []byte) ([]der, error) {
	var out []der
	for len(b) > 0 {
		item, rest, err := readDER(b)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
		b = rest
		if len(out) > 10000 {
			return nil, errors.New("too many DER fields")
		}
	}
	return out, nil
}

func encodeDER(tag byte, body []byte) []byte {
	result := []byte{tag}
	n := len(body)
	if n < 128 {
		result = append(result, byte(n))
	} else {
		var b [8]byte
		i := len(b)
		for n > 0 {
			i--
			b[i] = byte(n)
			n >>= 8
		}
		result = append(result, 0x80|byte(len(b)-i))
		result = append(result, b[i:]...)
	}
	return append(result, body...)
}

func imageFields(b []byte, magic string) ([]der, error) {
	item, rest, err := readDER(b)
	if err != nil {
		return nil, err
	}
	if item.tag != 0x30 || len(rest) != 0 {
		return nil, errors.New("image must be one DER sequence")
	}
	fields, err := children(item.body)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 || fields[0].tag != 0x16 || string(fields[0].body) != magic {
		return nil, fmt.Errorf("expected %s", magic)
	}
	return fields, nil
}

func unwrapImage(b []byte) (payload, manifest []byte, err error) {
	fields, err := imageFields(b, "IMG4")
	if err != nil {
		return nil, nil, err
	}
	if len(fields) != 3 || fields[2].tag != 0xa0 {
		return nil, nil, errors.New("unsupported IMG4 envelope")
	}
	if _, err = imageFields(fields[1].raw, "IM4P"); err != nil {
		return nil, nil, err
	}
	if _, err = imageFields(fields[2].body, "IM4M"); err != nil {
		return nil, nil, err
	}
	return fields[1].raw, fields[2].body, nil
}

func wrapImage(b, manifest []byte) ([]byte, error) {
	if _, err := imageFields(b, "IM4P"); err != nil {
		return nil, err
	}
	if _, err := imageFields(manifest, "IM4M"); err != nil {
		return nil, err
	}
	return encodeDER(0x30, bytes.Join([][]byte{encodeDER(0x16, []byte("IMG4")), b, encodeDER(0xa0, manifest)}, nil)), nil
}

func replacePayload(b []byte, kind string, raw []byte) ([]byte, error) {
	f, err := imageFields(b, "IM4P")
	if err != nil {
		return nil, err
	}
	if len(f) < 4 || f[1].tag != 0x16 || len(f[1].body) != 4 || f[3].tag != 4 || len(kind) != 4 {
		return nil, errors.New("invalid IM4P fields")
	}
	var body []byte
	for i, x := range f {
		switch i {
		case 1:
			body = append(body, encodeDER(0x16, []byte(kind))...)
		case 3:
			body = append(body, encodeDER(4, raw)...)
		default:
			body = append(body, x.raw...)
		}
	}
	return encodeDER(0x30, body), nil
}

type patch struct {
	Offset int    `json:"offset"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// patchBytes is the common guard for every file-backed instruction edit.  A
// patch is permitted only when the complete decoded input has the pinned
// identity and the bytes at every edit site match their recorded preimages.
// Equal-length, non-overlapping replacements keep offsets stable and make a
// partially matching firmware build fail closed instead of being modified.
func patchBytes(input []byte, wantHash string, patches []patch) ([]byte, error) {
	if !digestPattern.MatchString(wantHash) || digest(input) != wantHash {
		return nil, errors.New("patch source SHA-256 mismatch")
	}
	out := bytes.Clone(input)
	touched := make(map[int]bool)
	for i, p := range patches {
		before, err := hex.DecodeString(p.Before)
		if err != nil {
			return nil, err
		}
		after, err := hex.DecodeString(p.After)
		if err != nil {
			return nil, err
		}
		if len(before) == 0 || len(before) != len(after) || p.Offset < 0 || p.Offset > len(input)-len(before) {
			return nil, fmt.Errorf("patch %d: invalid span", i)
		}
		if !bytes.Equal(input[p.Offset:p.Offset+len(before)], before) {
			return nil, fmt.Errorf("patch %d: preimage mismatch at 0x%x", i, p.Offset)
		}
		for j := p.Offset; j < p.Offset+len(before); j++ {
			if touched[j] {
				return nil, errors.New("overlapping patches")
			}
			touched[j] = true
		}
		copy(out[p.Offset:], after)
	}
	return out, nil
}
