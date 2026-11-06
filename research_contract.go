package main

import (
	"context"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const exactInputContractSchema = "15-plus-kernel-poc.exact-input-contract.v1"

type contractMachO struct {
	CPU      string            `json:"cpu"`
	Type     string            `json:"type"`
	UUID     string            `json:"uuid,omitempty"`
	Segments []contractSegment `json:"segments,omitempty"`
	Symbols  []contractSymbol  `json:"symbols,omitempty"`
}

type contractSegment struct {
	Name       string `json:"name"`
	VMAddress  uint64 `json:"vm_address"`
	VMSize     uint64 `json:"vm_size"`
	FileOffset uint64 `json:"file_offset"`
	FileSize   uint64 `json:"file_size"`
}

type contractSymbol struct {
	Name           string `json:"name"`
	Address        uint64 `json:"address"`
	ImageOffset    uint64 `json:"image_offset"`
	FileOffset     uint64 `json:"file_offset,omitempty"`
	PreimageHex    string `json:"preimage_hex,omitempty"`
	PreimageSHA256 string `json:"preimage_sha256,omitempty"`
}

type exactInputIdentity struct {
	Name   string         `json:"name"`
	Path   string         `json:"path"`
	Bytes  int64          `json:"bytes"`
	SHA256 string         `json:"sha256"`
	MachO  *contractMachO `json:"macho,omitempty"`
}

type exactInputContract struct {
	Schema string               `json:"schema"`
	Inputs []exactInputIdentity `json:"inputs"`
}

func machoUUID(file *macho.File) string {
	for _, load := range file.Loads {
		raw := load.Raw()
		if len(raw) >= 24 && file.ByteOrder.Uint32(raw[:4]) == 0x1b {
			value := hex.EncodeToString(raw[8:24])
			return strings.ToUpper(value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32])
		}
	}
	return ""
}

func inspectContractMachO(path string, requested []string) (*contractMachO, error) {
	file, err := macho.Open(path)
	if err != nil {
		return nil, nil
	}
	defer file.Close()
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	result := &contractMachO{CPU: file.Cpu.String(), Type: file.Type.String(), UUID: machoUUID(file)}
	base := ^uint64(0)
	for _, load := range file.Loads {
		segment, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		result.Segments = append(result.Segments, contractSegment{
			Name: segment.Name, VMAddress: segment.Addr, VMSize: segment.Memsz,
			FileOffset: segment.Offset, FileSize: segment.Filesz,
		})
		if segment.Filesz != 0 && segment.Addr < base {
			base = segment.Addr
		}
	}
	if base == ^uint64(0) {
		base = 0
	}
	wanted := make(map[string]bool, len(requested))
	for _, name := range requested {
		wanted[name], wanted[strings.TrimPrefix(name, "_")] = true, true
	}
	if file.Symtab != nil {
		for _, symbol := range file.Symtab.Syms {
			plain := strings.TrimPrefix(symbol.Name, "_")
			if len(wanted) != 0 && !wanted[symbol.Name] && !wanted[plain] {
				continue
			}
			if symbol.Value < base {
				continue
			}
			entry := contractSymbol{Name: symbol.Name, Address: symbol.Value, ImageOffset: symbol.Value - base}
			if offset, mapErr := machoAddressToOffset(file, symbol.Value, 16); mapErr == nil && offset+16 <= uint64(len(body)) {
				preimage := body[offset : offset+16]
				entry.FileOffset, entry.PreimageHex, entry.PreimageSHA256 = offset, hex.EncodeToString(preimage), digest(preimage)
			}
			result.Symbols = append(result.Symbols, entry)
		}
	}
	sort.Slice(result.Symbols, func(i, j int) bool { return result.Symbols[i].Name < result.Symbols[j].Name })
	if len(requested) != 0 {
		for _, requestedName := range requested {
			found := false
			for _, symbol := range result.Symbols {
				if symbol.Name == requestedName || strings.TrimPrefix(symbol.Name, "_") == strings.TrimPrefix(requestedName, "_") {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("requested symbol %q is absent from %s", requestedName, path)
			}
		}
	}
	return result, nil
}

func readRegularIdentity(path string) (string, int64, string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", 0, "", err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return "", 0, "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", 0, "", fmt.Errorf("%s must be a non-empty regular file", abs)
	}
	body, err := os.ReadFile(abs)
	if err != nil {
		return "", 0, "", err
	}
	return abs, int64(len(body)), digest(body), nil
}

func contractCommand(ctx context.Context, c *cache, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: contract bind --input NAME=PATH [--symbol NAME=SYMBOL]... | contract windows --input NAME=PATH --window NAME=INPUT@ADDRESS+SIZE [--portable] [--dest FILE]")
	}
	switch args[0] {
	case "bind":
		return contractBindCommand(ctx, c, args[1:])
	case "windows":
		return binaryWindowContractCommand(ctx, c, args[1:])
	default:
		return fmt.Errorf("unknown contract command %q", args[0])
	}
}

func contractBindCommand(_ context.Context, c *cache, args []string) error {
	paths := map[string]string{}
	symbols := map[string][]string{}
	for index := 0; index < len(args); index++ {
		if index+1 >= len(args) {
			return fmt.Errorf("%s needs a value", args[index])
		}
		option, value := args[index], args[index+1]
		index++
		name, item, ok := strings.Cut(value, "=")
		if !ok || !machServiceName.MatchString(name) || item == "" {
			return fmt.Errorf("%s value must be NAME=VALUE", option)
		}
		switch option {
		case "--input":
			if _, exists := paths[name]; exists {
				return fmt.Errorf("duplicate input name %q", name)
			}
			paths[name] = item
		case "--symbol":
			symbols[name] = append(symbols[name], item)
		default:
			return fmt.Errorf("unknown contract bind option %q", option)
		}
	}
	if len(paths) == 0 {
		return errors.New("contract bind requires at least one --input NAME=PATH")
	}
	for name := range symbols {
		if paths[name] == "" {
			return fmt.Errorf("symbols refer to unknown input %q", name)
		}
	}
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)
	contract := exactInputContract{Schema: exactInputContractSchema}
	for _, name := range names {
		path, size, sha, err := readRegularIdentity(paths[name])
		if err != nil {
			return err
		}
		metadata, err := inspectContractMachO(path, symbols[name])
		if err != nil {
			return err
		}
		contract.Inputs = append(contract.Inputs, exactInputIdentity{Name: name, Path: path, Bytes: size, SHA256: sha, MachO: metadata})
	}
	body, err := json.MarshalIndent(contract, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	identity := digest(body)
	directory := filepath.Join(c.root, "private", "input-contracts")
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	path := filepath.Join(directory, identity+".json")
	if err = writeProbeFile(path, body, 0o600); err != nil {
		return err
	}
	if err = writeProbeFile(filepath.Join(c.root, "private", "input-contract-latest.json"), body, 0o600); err != nil {
		return err
	}
	entries, _ := os.ReadDir(directory)
	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() != identity+".json" && strings.HasSuffix(entry.Name(), ".json") {
			_ = os.Remove(filepath.Join(directory, entry.Name()))
		}
	}
	fmt.Fprintf(c.out, "Bound %d exact inputs contract_sha256=%s contract=%s\n", len(contract.Inputs), identity, path)
	return nil
}

// Retained here so malformed cache headers can be decoded without unsafe casts.
func uint64At(body []byte, offset int) uint64 {
	return binary.LittleEndian.Uint64(body[offset : offset+8])
}
