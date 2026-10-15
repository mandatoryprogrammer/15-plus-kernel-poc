package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"sort"
)

func encodeTag(tag []byte, body []byte) []byte {
	result := append([]byte(nil), tag...)
	n := len(body)
	if n < 128 {
		result = append(result, byte(n))
	} else {
		var length [8]byte
		i := len(length)
		for n > 0 {
			i--
			length[i] = byte(n)
			n >>= 8
		}
		result = append(result, 0x80|byte(len(length)-i))
		result = append(result, length[i:]...)
	}
	return append(result, body...)
}

func privateTag(name string, body []byte) ([]byte, error) {
	if len(name) != 4 {
		return nil, errors.New("Image4 property names must contain four bytes")
	}
	value := binary.BigEndian.Uint32([]byte(name))
	var groups [5]byte
	i := len(groups)
	for {
		i--
		groups[i] = byte(value & 0x7f)
		value >>= 7
		if value == 0 {
			break
		}
	}
	for j := i; j < len(groups)-1; j++ {
		groups[j] |= 0x80
	}
	tag := append([]byte{0xff}, groups[i:]...)
	return encodeTag(tag, encodeDER(0x30, append(encodeDER(0x16, []byte(name)), body...))), nil
}

func manifestInteger(value uint64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	i := 0
	for i < len(raw)-1 && raw[i] == 0 {
		i++
	}
	b := raw[i:]
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return encodeDER(2, b)
}

func manifestBoolean(value bool) []byte {
	b := byte(0)
	if value {
		b = 0xff
	}
	return encodeDER(1, []byte{b})
}

type manifestProperty struct {
	name  string
	value []byte
}

func propertySet(properties []manifestProperty) ([]byte, error) {
	properties = append([]manifestProperty(nil), properties...)
	sort.Slice(properties, func(i, j int) bool { return properties[i].name < properties[j].name })
	var body []byte
	for _, property := range properties {
		encoded, err := privateTag(property.name, property.value)
		if err != nil {
			return nil, err
		}
		body = append(body, encoded...)
	}
	return encodeDER(0x31, body), nil
}

// policyManifest makes the unsigned, board-neutral policy object consumed by
// the volatile loader adapters. Its zero signature and empty certificate list
// are intentional structural fields; neither is trusted or device-bound.
func policyManifest(component []byte) ([]byte, error) {
	fields, err := imageFields(component, "IM4P")
	if err != nil || len(fields) < 4 || fields[1].tag != 0x16 || len(fields[1].body) != 4 {
		return nil, errors.New("policy input is not a typed IM4P")
	}
	kind := string(fields[1].body)
	hash := sha512.Sum384(component)
	model, err := propertySet([]manifestProperty{
		{"BNCH", encodeDER(4, make([]byte, 32))},
		{"BORD", manifestInteger(supportedFamily.BDID)},
		{"CEPO", manifestInteger(1)},
		{"CHIP", manifestInteger(supportedFamily.CPID)},
		{"CPRO", manifestBoolean(true)},
		{"CSEC", manifestBoolean(true)},
		{"ECID", manifestInteger(1)},
		{"SDOM", manifestInteger(1)},
	})
	if err != nil {
		return nil, err
	}
	part, err := propertySet([]manifestProperty{
		{"DGST", encodeDER(4, hash[:])},
		{"EKEY", manifestBoolean(true)},
		{"EPRO", manifestBoolean(true)},
		{"ESEC", manifestBoolean(true)},
	})
	if err != nil {
		return nil, err
	}
	modelEntry, err := privateTag("MANP", model)
	if err != nil {
		return nil, err
	}
	partEntry, err := privateTag(kind, part)
	if err != nil {
		return nil, err
	}
	body, err := privateTag("MANB", encodeDER(0x31, bytes.Join([][]byte{modelEntry, partEntry}, nil)))
	if err != nil {
		return nil, err
	}
	return encodeDER(0x30, bytes.Join([][]byte{
		encodeDER(0x16, []byte("IM4M")),
		manifestInteger(0),
		encodeDER(0x31, body),
		encodeDER(4, make([]byte, 512)),
		encodeDER(0x30, nil),
	}, nil)), nil
}
