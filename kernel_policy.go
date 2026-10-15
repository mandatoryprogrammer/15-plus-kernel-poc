package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	kernelPolicySearchWindow = 64 << 10
)

type kernelPolicyLocation struct {
	policy, capacity, lengthInstruction int
}

// locateKernelPolicy derives both kernel edit sites from authenticated
// structure: a valid embedded IM4M and the unique nearby ARM64 instruction
// that loads that DER object's original length into X4.  The decoded-image hash
// remains the authority for which kernel is supported.
func locateKernelPolicy(raw []byte) (kernelPolicyLocation, error) {
	marker := []byte{0x16, 0x04, 'I', 'M', '4', 'M'}
	var matches []kernelPolicyLocation
	for cursor := 0; cursor < len(raw); {
		relative := bytes.Index(raw[cursor:], marker)
		if relative < 0 {
			break
		}
		markerAt := cursor + relative
		for headerSize := 2; headerSize <= 6 && markerAt >= headerSize; headerSize++ {
			policyAt := markerAt - headerSize
			item, _, parseErr := readDER(raw[policyAt:])
			if parseErr != nil || item.tag != 0x30 || len(item.raw) > 0xffff {
				continue
			}
			if _, parseErr = imageFields(item.raw, "IM4M"); parseErr != nil {
				continue
			}
			if _, parseErr = neutralKernelPolicy(item.raw); parseErr != nil {
				continue
			}
			instruction := uint32(0xd2800004) | uint32(len(item.raw))<<5
			encoded := make([]byte, 4)
			binary.LittleEndian.PutUint32(encoded, instruction)
			searchAt := max(0, policyAt-kernelPolicySearchWindow)
			instructionAt, locateErr := uniqueOffset(raw[searchAt:policyAt], encoded, "kernel policy-length instruction")
			if locateErr != nil {
				continue
			}
			matches = append(matches, kernelPolicyLocation{policy: policyAt, capacity: len(item.raw), lengthInstruction: searchAt + instructionAt})
		}
		cursor = markerAt + len(marker)
	}
	if len(matches) != 1 {
		return kernelPolicyLocation{}, fmt.Errorf("expected one structural kernel policy and length reference; found %d", len(matches))
	}
	return matches[0], nil
}

func decodeProperty(entry der) (string, der, error) {
	outer, err := children(entry.body)
	if err != nil || len(outer) != 1 || outer[0].tag != 0x30 {
		return "", der{}, errors.New("invalid Image4 property envelope")
	}
	fields, err := children(outer[0].body)
	if err != nil || len(fields) != 2 || fields[0].tag != 0x16 || len(fields[0].body) != 4 {
		return "", der{}, errors.New("invalid Image4 property")
	}
	return string(fields[0].body), fields[1], nil
}

// neutralKernelPolicy retains the public component digests and compatibility
// properties used by the kernel adapters while removing device identity,
// nonces, signatures, and certificates from the embedded policy.
func neutralKernelPolicy(input []byte) ([]byte, error) {
	fields, err := imageFields(input, "IM4M")
	if err != nil || len(fields) != 5 || fields[2].tag != 0x31 || fields[3].tag != 4 || fields[4].tag != 0x30 {
		return nil, errors.New("invalid embedded kernel policy")
	}
	top, err := children(fields[2].body)
	if err != nil || len(top) != 1 {
		return nil, errors.New("invalid embedded policy body")
	}
	name, value, err := decodeProperty(top[0])
	if err != nil || name != "MANB" || value.tag != 0x31 {
		return nil, errors.New("embedded policy has no MANB set")
	}
	entries, err := children(value.body)
	if err != nil || len(entries) < 2 {
		return nil, errors.New("embedded policy component set is empty")
	}
	var rebuilt []byte
	seenModel := false
	for _, entry := range entries {
		entryName, entryValue, decodeErr := decodeProperty(entry)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if entryName != "MANP" {
			rebuilt = append(rebuilt, entry.raw...)
			continue
		}
		if seenModel || entryValue.tag != 0x31 {
			return nil, errors.New("invalid embedded model policy")
		}
		seenModel = true
		modelEntries, childErr := children(entryValue.body)
		if childErr != nil {
			return nil, childErr
		}
		properties := make([]manifestProperty, 0, len(modelEntries))
		for _, modelEntry := range modelEntries {
			propertyName, propertyValue, propertyErr := decodeProperty(modelEntry)
			if propertyErr != nil {
				return nil, propertyErr
			}
			switch propertyName {
			case "ECID", "UDID":
				continue
			case "BNCH", "cnch", "snon", "srvn":
				if propertyValue.tag != 4 {
					return nil, fmt.Errorf("%s is not an octet string", propertyName)
				}
				propertyValue.raw = encodeDER(4, make([]byte, len(propertyValue.body)))
			}
			properties = append(properties, manifestProperty{name: propertyName, value: propertyValue.raw})
		}
		model, propertyErr := propertySet(properties)
		if propertyErr != nil {
			return nil, propertyErr
		}
		modelEntry, propertyErr := privateTag("MANP", model)
		if propertyErr != nil {
			return nil, propertyErr
		}
		rebuilt = append(rebuilt, modelEntry...)
	}
	if !seenModel {
		return nil, errors.New("embedded model policy is missing")
	}
	manb, err := privateTag("MANB", encodeDER(0x31, rebuilt))
	if err != nil {
		return nil, err
	}
	return encodeDER(0x30, bytes.Join([][]byte{
		fields[0].raw,
		fields[1].raw,
		encodeDER(0x31, manb),
		encodeDER(4, make([]byte, len(fields[3].body))),
		encodeDER(0x30, nil),
	}, nil)), nil
}

// prepareRuntimeKernel rewrites the embedded policy in the one decoded kernel
// identity supported by this repository.  It returns a typed IM4P; the caller
// generates the outer structural policy after this transformation succeeds.
func prepareRuntimeKernel(component []byte) ([]byte, error) {
	fields, err := imageFields(component, "IM4P")
	if err != nil || len(fields) < 4 || fields[1].tag != 0x16 || fields[3].tag != 4 {
		return nil, errors.New("invalid runtime kernel IM4P")
	}
	raw, err := compression(fields[3].body, canonicalRuntime.Kernel.DecodedSize, false, false)
	if err != nil {
		return nil, err
	}
	if digest(raw) != canonicalRuntime.Kernel.DecodedSHA256 {
		return nil, errors.New("runtime kernel preimage identity mismatch")
	}
	location, err := locateKernelPolicy(raw)
	if err != nil {
		return nil, err
	}
	policyDER := raw[location.policy : location.policy+location.capacity]
	policy, err := neutralKernelPolicy(policyDER)
	if err != nil {
		return nil, err
	}
	if len(policy) > location.capacity || len(policy) > 0xffff {
		return nil, errors.New("neutral kernel policy exceeds its verified code cave")
	}
	// The replacement policy is shorter than the fixed embedded slot.  Clear
	// the whole slot before copying it, then rewrite the guarded ARM64
	// `MOV X4, #length` instruction consumed by the policy parser.
	copy(raw[location.policy:location.policy+location.capacity], make([]byte, location.capacity))
	copy(raw[location.policy:], policy)
	instruction := uint32(0xd2800004) | uint32(len(policy))<<5
	binary.LittleEndian.PutUint32(raw[location.lengthInstruction:], instruction)
	compressed, err := compression(raw, len(raw)+(1<<20), true, true)
	if err != nil {
		return nil, err
	}
	return replacePayload(component, string(fields[1].body), compressed)
}
