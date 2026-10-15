package main

import (
	"bytes"
	"context"
	"crypto/sha512"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"
)

//go:embed commands/*
var commandScripts embed.FS

type builtInCommand struct {
	Destination string
	Body        []byte
}

func builtInCommands() ([]builtInCommand, error) {
	names, err := fs.Glob(commandScripts, "commands/*")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	commands := make([]builtInCommand, 0, len(names))
	for _, name := range names {
		body, readErr := commandScripts.ReadFile(name)
		if readErr != nil {
			return nil, readErr
		}
		base := strings.TrimPrefix(name, "commands/")
		if base == "" || strings.Contains(base, "/") || !bytes.HasPrefix(body, []byte("#!/bin/bash\n")) {
			return nil, fmt.Errorf("invalid built-in command %q", name)
		}
		commands = append(commands, builtInCommand{Destination: "/usr/bin/" + base, Body: body})
	}
	if len(commands) == 0 {
		return nil, errors.New("built-in command pack is empty")
	}
	return commands, nil
}

type runtimeLayout struct {
	Entry       []byte
	Build       []byte
	BuildOffset uint64
	RootCalls   []uint64
	DecodedSize uint64
}

func normalizedPatternOffsets(image []byte, pattern []semanticInstruction, selected int) ([]int, error) {
	return semanticOffsets(image, semanticLocator{
		name: "runtime instruction relationship", kind: semanticNOP,
		pattern: pattern, patchIndex: selected, minimum: 1,
	})
}

// analyzeRuntimeIBEC derives every runtime code location from authenticated
// decoded bytes. Branch displacements are ignored, while opcodes, constants,
// register roles, and neighboring data flow remain part of each proof.
func analyzeRuntimeIBEC(decoded []byte, identity artifactIdentity, loaderBuild string) (runtimeLayout, patch, error) {
	if len(decoded) < 0x1000 || len(decoded) != identity.DecodedSize || digest(decoded) != identity.DecodedSHA256 || loaderBuild == "" {
		return runtimeLayout{}, patch{}, errors.New("iBEC decoded identity mismatch")
	}
	policyPattern := []semanticInstruction{
		exactInstruction(0x910f43e1), exactInstruction(0x910323e4),
		exactInstruction(0xaa1303e0), exactInstruction(0xaa1603e3),
		exactInstruction(0x94000000), exactInstruction(0x34000000),
		exactInstruction(0x51007b14), exactInstruction(0x14000000),
	}
	policySites, err := normalizedPatternOffsets(decoded, policyPattern, 5)
	if err != nil || len(policySites) != 1 {
		return runtimeLayout{}, patch{}, fmt.Errorf("iBEC policy continuation must resolve once, found %d: %w", len(policySites), err)
	}
	policyAt := policySites[0]
	before := binary.LittleEndian.Uint32(decoded[policyAt:])
	after, err := branchToCBZTarget(before)
	if err != nil {
		return runtimeLayout{}, patch{}, fmt.Errorf("iBEC policy continuation: %w", err)
	}
	wordBytes := func(word uint32) string {
		var value [4]byte
		binary.LittleEndian.PutUint32(value[:], word)
		return hex.EncodeToString(value[:])
	}

	rootPattern := []semanticInstruction{
		exactInstruction(0x52888a80), exactInstruction(0x72a78aa0),
		exactInstruction(0x52800001), exactInstruction(0x94000000),
		exactInstruction(0x90000003), exactInstruction(0x91146063),
		exactInstruction(0x94000000), exactInstruction(0x94000000),
		maskedInstruction(0xaa0003e0, 0xffffffe0),
	}
	rootSites, err := normalizedPatternOffsets(decoded, rootPattern, 7)
	if err != nil || len(rootSites) < 1 || len(rootSites) > 2 || rootSites[len(rootSites)-1]-rootSites[0] > 0x4000 {
		return runtimeLayout{}, patch{}, fmt.Errorf("iBEC root construction must resolve to one bounded path neighborhood, found %d: %w", len(rootSites), err)
	}
	// The executable may also mention its build in diagnostics. The header is
	// the loader's self-identity record, so resolve the NUL-terminated value only
	// within that bounded structural page.
	buildAt, err := uniqueOffset(decoded[:0x1000], append([]byte(loaderBuild), 0), "runtime loader header build")
	if err != nil {
		return runtimeLayout{}, patch{}, err
	}
	layout := runtimeLayout{
		Entry:       bytes.Clone(decoded[:32]),
		Build:       bytes.Clone(decoded[buildAt : buildAt+(len(loaderBuild)+4)&^3]),
		BuildOffset: uint64(buildAt),
		DecodedSize: uint64(len(decoded)),
	}
	for _, site := range rootSites {
		layout.RootCalls = append(layout.RootCalls, uint64(site))
	}
	return layout, patch{Offset: policyAt, Before: wordBytes(before), After: wordBytes(after)}, nil
}

func trustCacheRow(version uint32, hash []byte) ([]byte, int, error) {
	switch version {
	case 0:
		return bytes.Clone(hash), 20, nil
	case 1:
		return append(bytes.Clone(hash), 2, 0), 22, nil
	case 2:
		return append(bytes.Clone(hash), 2, 0, 0, 0), 24, nil
	default:
		return nil, 0, fmt.Errorf("unsupported trust-cache version %d", version)
	}
}

// extendTrustCache preserves the source format and adds only cdhashes produced
// by validatePayload. Versions 0, 1, and 2 differ only in their entry suffix;
// all are kept sorted and unique for deterministic component bytes.
func extendTrustCache(im4p []byte, additions []payloadEntry) ([]byte, error) {
	fields, err := imageFields(im4p, "IM4P")
	if err != nil || len(fields) < 4 {
		return nil, errors.New("invalid trust-cache IM4P")
	}
	payload := fields[3].body
	if len(payload) < 24 {
		return nil, errors.New("truncated trust-cache header")
	}
	version := binary.LittleEndian.Uint32(payload[:4])
	_, rowSize, err := trustCacheRow(version, make([]byte, 20))
	if err != nil {
		return nil, err
	}
	count := int(binary.LittleEndian.Uint32(payload[20:24]))
	if count < 0 || len(payload) != 24+count*rowSize {
		return nil, errors.New("invalid trust-cache entry table")
	}
	entries := make([][]byte, 0, count+len(additions))
	seen := map[string]bool{}
	changed := false
	for i := 0; i < count; i++ {
		row := bytes.Clone(payload[24+i*rowSize : 24+(i+1)*rowSize])
		seen[hex.EncodeToString(row[:20])] = true
		entries = append(entries, row)
	}
	for _, addition := range additions {
		if seen[addition.CDHash] {
			continue
		}
		hash, decodeErr := hex.DecodeString(addition.CDHash)
		if decodeErr != nil || len(hash) != 20 {
			return nil, fmt.Errorf("invalid cdhash for %s", addition.Destination)
		}
		row, _, rowErr := trustCacheRow(version, hash)
		if rowErr != nil {
			return nil, rowErr
		}
		at := len(entries)
		for i, existing := range entries {
			if bytes.Compare(existing[:20], hash) > 0 {
				at = i
				break
			}
		}
		entries = append(entries, nil)
		copy(entries[at+1:], entries[at:])
		entries[at] = row
		seen[addition.CDHash] = true
		changed = true
	}
	if !changed {
		return bytes.Clone(im4p), nil
	}
	updated := bytes.Clone(payload[:24])
	binary.LittleEndian.PutUint32(updated[20:24], uint32(len(entries)))
	for _, row := range entries {
		updated = append(updated, row...)
	}
	return replacePayload(im4p, "rtsc", updated)
}

// prepareRuntimeIBEC unwraps and decompresses only the pinned runtime loader,
// applies its single admission edit and any trust-cache rebinding, then builds
// a new IMG4 envelope around the recompressed typed payload.
func prepareRuntimeIBEC(ibec, oldTrust, newTrust []byte) ([]byte, runtimeLayout, error) {
	im4p, _, err := unwrapImage(ibec)
	if err != nil {
		return nil, runtimeLayout{}, err
	}
	fields, err := imageFields(im4p, "IM4P")
	if err != nil || len(fields) < 4 {
		return nil, runtimeLayout{}, errors.New("invalid iBEC IM4P")
	}
	decoded, err := compression(fields[3].body, canonicalRuntime.IBEC.DecodedSize, false, false)
	if err != nil {
		return nil, runtimeLayout{}, err
	}
	if digest(decoded) != canonicalRuntime.IBEC.DecodedSHA256 {
		return nil, runtimeLayout{}, errors.New("iBEC preimage identity mismatch")
	}
	layout, policyPatch, err := analyzeRuntimeIBEC(decoded, canonicalRuntime.IBEC, canonicalRuntime.LoaderBuild)
	if err != nil {
		return nil, runtimeLayout{}, err
	}
	decoded, err = patchBytes(decoded, canonicalRuntime.IBEC.DecodedSHA256, []patch{policyPatch})
	if err != nil {
		return nil, runtimeLayout{}, fmt.Errorf("iBEC policy patch: %w", err)
	}
	if len(oldTrust) != 0 || len(newTrust) != 0 {
		// iBEC binds the trust cache by its SHA-384 digest.  Require the old
		// digest to occur exactly once, derive its location from the authenticated
		// component, then rebind it to the deterministic cache produced above.
		oldDigest, newDigest := sha512.Sum384(oldTrust), sha512.Sum384(newTrust)
		bindingOffset, locateErr := uniqueOffset(decoded, oldDigest[:], "iBEC trust-cache binding")
		if locateErr != nil {
			return nil, runtimeLayout{}, fmt.Errorf("iBEC trust-cache binding preimage mismatch: %w", locateErr)
		}
		copy(decoded[bindingOffset:bindingOffset+len(newDigest)], newDigest[:])
	}
	compressed, err := compression(decoded, len(decoded)+(1<<20), true, true)
	if err != nil {
		return nil, runtimeLayout{}, err
	}
	im4p, err = replacePayload(im4p, "ibec", compressed)
	if err != nil {
		return nil, runtimeLayout{}, err
	}
	policy, err := policyManifest(im4p)
	if err != nil {
		return nil, runtimeLayout{}, err
	}
	wrapped, err := wrapImage(im4p, policy)
	return wrapped, layout, err
}

// preparePayloadTrust keeps the base trust cache byte-identical when there are
// no additions.  When additions exist it updates both halves of the binding:
// the cache's sorted cdhash table and iBEC's single SHA-384 reference to it.
func preparePayloadTrust(images map[string][]byte, additions []payloadEntry) (runtimeLayout, error) {
	oldTrust, _, err := unwrapImage(images["trust-cache"])
	if err != nil {
		return runtimeLayout{}, err
	}
	newTrust := oldTrust
	if len(additions) != 0 {
		newTrust, err = extendTrustCache(oldTrust, additions)
		if err != nil {
			return runtimeLayout{}, err
		}
	}
	if bytes.Equal(oldTrust, newTrust) {
		oldTrust, newTrust = nil, nil
	}
	var layout runtimeLayout
	images["ibec"], layout, err = prepareRuntimeIBEC(images["ibec"], oldTrust, newTrust)
	if err != nil {
		return runtimeLayout{}, err
	}
	if len(newTrust) == 0 {
		return layout, nil
	}
	policy, err := policyManifest(newTrust)
	if err != nil {
		return runtimeLayout{}, err
	}
	images["trust-cache"], err = wrapImage(newTrust, policy)
	return layout, err
}

func installPayload(ctx context.Context, c *cache, serial *serialCapture, additions []payloadEntry) error {
	for _, addition := range additions {
		a := asset{Role: "payload", SHA256: addition.SHA256, Size: addition.Size}
		if err := verifyFile(ctx, c.object(a), a); err != nil {
			return err
		}
		b, err := os.ReadFile(c.object(a))
		if err != nil {
			return err
		}
		if err = installPayloadFile(ctx, c, serial, addition.Destination, b, addition.SHA256); err != nil {
			return err
		}
		fmt.Fprintf(c.out, "Installed payload %s (%d bytes)\n", addition.Destination, addition.Size)
	}
	return nil
}

func installPayloadFile(ctx context.Context, c *cache, serial *serialCapture, destination string, b []byte, sha string) error {
	return installFile(ctx, c, serial, destination, b, sha, 0755)
}

func installFile(ctx context.Context, c *cache, serial *serialCapture, destination string, b []byte, sha string, mode uint32) error {
	stage := "/private/var/tmp/payload-" + sha[:16]
	begin := fmt.Sprintf("put_begin|%s|%d|%s|%o", hex.EncodeToString([]byte(stage)), len(b), sha, mode)
	if response, err := rootRequest(ctx, serial, begin); err != nil {
		return fmt.Errorf("begin %s: %w: %s", destination, err, response)
	}
	for offset := 0; offset < len(b); {
		// Console input shares a small early-boot ring. Short records avoid
		// overrunning it while the kernel is still emitting startup logs. An
		// exact-offset chunk can also be replayed safely if that noise drops a
		// complete request before the device acknowledges it.
		end := min(offset+1024, len(b))
		command := fmt.Sprintf("put_chunk|%d|%s", offset, hex.EncodeToString(b[offset:end]))
		var response []byte
		var err error
		for attempt := 1; attempt <= 3; attempt++ {
			response, err = rootRequest(ctx, serial, command)
			if err == nil || !errors.Is(err, errRootRequestTimeout) || attempt == 3 {
				break
			}
			fmt.Fprintf(c.out, "Payload upload %s: retrying offset %d after serial congestion (%d/3)\n", destination, offset, attempt+1)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(500 * time.Millisecond):
			}
		}
		if err != nil {
			abortCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, _ = rootRequest(abortCtx, serial, "put_abort")
			cancel()
			return fmt.Errorf("upload %s at %d: %w: %s", destination, offset, err, response)
		}
		offset = end
	}
	if response, err := rootRequest(ctx, serial, "put_commit"); err != nil {
		return fmt.Errorf("commit %s: %w: %s", destination, err, response)
	}
	command := "/bin/mv " + stage + " " + destination
	if response, err := rootExec(ctx, serial, command); err != nil {
		return fmt.Errorf("install %s: %w: %s", destination, err, response)
	}
	return nil
}

func installBuiltins(ctx context.Context, c *cache, serial *serialCapture) error {
	commands, err := builtInCommands()
	if err != nil {
		return err
	}
	for _, command := range commands {
		if err = installPayloadFile(ctx, c, serial, command.Destination, command.Body, digest(command.Body)); err != nil {
			return err
		}
	}
	fmt.Fprintf(c.out, "Installed %d built-in shell commands\n", len(commands))
	return nil
}
