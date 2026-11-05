package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const (
	systemTrustContextSchema = "15-plus-kernel-poc.system-trust-context.v1"
	systemTrustContextLimit  = 16 << 20
)

type systemTrustContext struct {
	Schema     string `json:"schema"`
	Object     asset  `json:"object"`
	ImageType  string `json:"image_type"`
	Version    uint32 `json:"version"`
	EntryCount int    `json:"entry_count"`
}

type parsedTrustCache struct {
	imageType string
	version   uint32
	rowSize   int
	header    []byte
	rows      [][]byte
}

func parseTrustCacheImage(im4p []byte, wantType string) (parsedTrustCache, error) {
	var result parsedTrustCache
	fields, err := imageFields(im4p, "IM4P")
	if err != nil || len(fields) < 4 || fields[1].tag != 0x16 || len(fields[1].body) != 4 || fields[3].tag != 4 {
		return result, errors.New("invalid trust-cache IM4P")
	}
	result.imageType = string(fields[1].body)
	if result.imageType != wantType {
		return result, fmt.Errorf("trust-cache IM4P type %q, want %q", result.imageType, wantType)
	}
	payload := fields[3].body
	if len(payload) < 24 {
		return result, errors.New("truncated trust-cache payload")
	}
	result.version = binary.LittleEndian.Uint32(payload[:4])
	_, result.rowSize, err = trustCacheRow(result.version, make([]byte, 20))
	if err != nil {
		return result, err
	}
	count := uint64(binary.LittleEndian.Uint32(payload[20:24]))
	wantBytes := uint64(24) + count*uint64(result.rowSize)
	if wantBytes != uint64(len(payload)) || count > uint64(systemTrustContextLimit/result.rowSize) {
		return result, errors.New("trust-cache entry table length mismatch")
	}
	result.header = bytes.Clone(payload[:24])
	result.rows = make([][]byte, 0, int(count))
	for index := 0; index < int(count); index++ {
		row := bytes.Clone(payload[24+index*result.rowSize : 24+(index+1)*result.rowSize])
		if index != 0 && bytes.Compare(result.rows[index-1][:20], row[:20]) >= 0 {
			return parsedTrustCache{}, errors.New("trust-cache rows are not strictly hash-sorted and unique")
		}
		result.rows = append(result.rows, row)
	}
	return result, nil
}

func mergeSystemTrustCache(baseRestore, productStatic []byte) ([]byte, int, error) {
	base, err := parseTrustCacheImage(baseRestore, "rtsc")
	if err != nil {
		return nil, 0, fmt.Errorf("base restore trust cache: %w", err)
	}
	system, err := parseTrustCacheImage(productStatic, "trst")
	if err != nil {
		return nil, 0, fmt.Errorf("system static trust cache: %w", err)
	}
	if base.version == 1 && system.version == 2 {
		promoted := make([][]byte, 0, len(base.rows))
		for _, row := range base.rows {
			promoted = append(promoted, append(bytes.Clone(row), 0, 0))
		}
		base.version = 2
		base.rowSize = 24
		base.rows = promoted
		binary.LittleEndian.PutUint32(base.header[:4], 2)
	} else if base.version != system.version || base.rowSize != system.rowSize {
		return nil, 0, fmt.Errorf("trust-cache format mismatch: base version %d, system version %d", base.version, system.version)
	}
	rows := make(map[string][]byte, len(base.rows)+len(system.rows))
	for _, table := range []parsedTrustCache{base, system} {
		for _, row := range table.rows {
			key := string(row[:20])
			if existing, ok := rows[key]; ok {
				if !bytes.Equal(existing, row) {
					return nil, 0, errors.New("trust-cache row metadata conflicts for one hash")
				}
				continue
			}
			rows[key] = row
		}
	}
	ordered := make([][]byte, 0, len(rows))
	for _, row := range rows {
		ordered = append(ordered, row)
	}
	sort.Slice(ordered, func(i, j int) bool { return bytes.Compare(ordered[i][:20], ordered[j][:20]) < 0 })
	payload := bytes.Clone(base.header)
	binary.LittleEndian.PutUint32(payload[20:24], uint32(len(ordered)))
	for _, row := range ordered {
		payload = append(payload, row...)
	}
	merged, err := replacePayload(baseRestore, "rtsc", payload)
	if err != nil {
		return nil, 0, err
	}
	return merged, len(ordered), nil
}

func systemTrustDescriptorPath(c *cache) string {
	return filepath.Join(c.root, "private", "system-trust.json")
}

func writeSystemTrustContext(c *cache, value systemTrustContext) error {
	if value.Schema != systemTrustContextSchema || value.Object.Role != "system-trust-context" || value.Object.URL != "" || value.Object.Member != "" || value.Object.validate() != nil || value.ImageType != "trst" || value.EntryCount < 1 {
		return errors.New("invalid system trust context descriptor")
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Join(c.root, "private"), "system-trust-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(append(body, '\n'))
	}
	if err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, systemTrustDescriptorPath(c))
}

func loadSystemTrustContext(ctx context.Context, c *cache) (*systemTrustContext, []byte, error) {
	descriptor, err := os.ReadFile(systemTrustDescriptorPath(c))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var value systemTrustContext
	if err = json.Unmarshal(descriptor, &value); err != nil {
		return nil, nil, err
	}
	if value.Schema != systemTrustContextSchema || value.Object.Role != "system-trust-context" || value.Object.URL != "" || value.Object.Member != "" || value.Object.validate() != nil || value.ImageType != "trst" || value.EntryCount < 1 {
		return nil, nil, errors.New("invalid system trust context descriptor")
	}
	if err = verifyFile(ctx, c.object(value.Object), value.Object); err != nil {
		return nil, nil, fmt.Errorf("verify system trust context: %w", err)
	}
	wrapper, err := os.ReadFile(c.object(value.Object))
	if err != nil {
		return nil, nil, err
	}
	im4p, _, err := unwrapImage(wrapper)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrap system trust context: %w", err)
	}
	parsed, err := parseTrustCacheImage(im4p, "trst")
	if err != nil || parsed.version != value.Version || len(parsed.rows) != value.EntryCount {
		return nil, nil, errors.New("system trust context descriptor does not match its object")
	}
	return &value, im4p, nil
}

func importSystemTrustContext(ctx context.Context, c *cache, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: system-trust import FILE")
	}
	info, err := os.Lstat(args[0])
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > systemTrustContextLimit {
		return fmt.Errorf("system trust input must be one regular file of at most %d bytes", systemTrustContextLimit)
	}
	input, err := os.Open(args[0])
	if err != nil {
		return err
	}
	body, readErr := io.ReadAll(io.LimitReader(input, systemTrustContextLimit+1))
	closeErr := input.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if int64(len(body)) != info.Size() {
		return errors.New("system trust input changed while it was read")
	}
	im4p, _, err := unwrapImage(body)
	if err != nil {
		return fmt.Errorf("system trust input: %w", err)
	}
	parsed, err := parseTrustCacheImage(im4p, "trst")
	if err != nil {
		return err
	}
	object := asset{
		Role: "system-trust-context", SHA256: digest(body), Size: int64(len(body)),
		Recipe:        "Imported complete system StaticTrustCache IMG4 without projecting per-binary hashes",
		Compatibility: "Caller-selected coherent system volume",
	}
	if _, err = c.store(ctx, object, bytes.NewReader(body)); err != nil {
		return err
	}
	descriptor := systemTrustContext{
		Schema: systemTrustContextSchema, Object: object, ImageType: parsed.imageType,
		Version: parsed.version, EntryCount: len(parsed.rows),
	}
	if err = writeSystemTrustContext(c, descriptor); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Imported complete system trust context %s (%d entries, version %d); the next boot will merge the whole table.\n", object.SHA256, descriptor.EntryCount, descriptor.Version)
	return nil
}

func statusSystemTrustContext(ctx context.Context, c *cache) error {
	value, systemTrust, err := loadSystemTrustContext(ctx, c)
	if err != nil {
		return err
	}
	if value == nil {
		fmt.Fprintln(c.out, "No system trust context is configured.")
		return nil
	}
	runtimeRoles := map[string]bool{"ibec": true, "ramdisk": true, "kernel": true, "sptm": true, "txm": true, "trust-cache": true}
	rows, err := preparedSet("runtime", runtimeRoles)
	if err != nil {
		return err
	}
	var baseAsset asset
	for _, row := range rows {
		if row.Role == "trust-cache" {
			baseAsset = row
			break
		}
	}
	if baseAsset.Role == "" {
		return errors.New("runtime prepared set has no base trust cache")
	}
	if err = verifyFile(ctx, c.object(baseAsset), baseAsset); err != nil {
		return fmt.Errorf("verify runtime base trust cache: %w", err)
	}
	baseTrust, err := os.ReadFile(c.object(baseAsset))
	if err != nil {
		return err
	}
	base, err := parseTrustCacheImage(baseTrust, "rtsc")
	if err != nil {
		return err
	}
	_, mergedCount, err := mergeSystemTrustCache(baseTrust, systemTrust)
	if err != nil {
		return fmt.Errorf("system trust context is incompatible with the pinned runtime: %w", err)
	}
	fmt.Fprintf(c.out, "System trust context %s: %d bytes, version %d, %d complete entries; pinned runtime base %d, merged %d.\n", value.Object.SHA256, value.Object.Size, value.Version, value.EntryCount, len(base.rows), mergedCount)
	return nil
}

func clearSystemTrustContext(c *cache) error {
	err := os.Remove(systemTrustDescriptorPath(c))
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(c.out, "No system trust context was configured.")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(c.out, "Cleared the configured system trust context; cached immutable bytes were retained.")
	return nil
}
