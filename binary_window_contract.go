package main

import (
	"context"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const binaryWindowContractSchema = "15-plus-kernel-poc.binary-window-contract.v1"

const maximumBinaryWindowBytes = 1 << 20

type binaryWindowInput struct {
	Name   string         `json:"name"`
	Path   string         `json:"path,omitempty"`
	Bytes  int64          `json:"bytes"`
	SHA256 string         `json:"sha256"`
	MachO  *contractMachO `json:"macho"`
}

type binaryWindow struct {
	Name        string `json:"name"`
	Input       string `json:"input"`
	Start       string `json:"start"`
	End         string `json:"end"`
	ImageOffset string `json:"image_offset"`
	FileStart   string `json:"file_start"`
	FileEnd     string `json:"file_end"`
	Bytes       uint64 `json:"bytes"`
	SHA256      string `json:"sha256"`
	Hex         string `json:"hex"`
}

type binaryWindowContract struct {
	Schema  string              `json:"schema"`
	Inputs  []binaryWindowInput `json:"inputs"`
	Windows []binaryWindow      `json:"windows"`
}

type binaryWindowSpec struct {
	Name, Input    string
	Address, Bytes uint64
}

type binaryWindowOptions struct {
	Inputs      map[string]string
	Windows     []binaryWindowSpec
	Destination string
	Portable    bool
}

func parseBinaryWindowSpec(value string) (binaryWindowSpec, error) {
	var result binaryWindowSpec
	name, target, ok := strings.Cut(value, "=")
	if !ok || !machServiceName.MatchString(name) || target == "" {
		return result, fmt.Errorf("window %q must be NAME=INPUT@ADDRESS+SIZE", value)
	}
	input, span, ok := strings.Cut(target, "@")
	if !ok || !machServiceName.MatchString(input) || span == "" {
		return result, fmt.Errorf("window %q must be NAME=INPUT@ADDRESS+SIZE", value)
	}
	separator := strings.LastIndexByte(span, '+')
	if separator <= 0 || separator == len(span)-1 {
		return result, fmt.Errorf("window %q must be NAME=INPUT@ADDRESS+SIZE", value)
	}
	address, addressErr := strconv.ParseUint(span[:separator], 0, 64)
	size, sizeErr := strconv.ParseUint(span[separator+1:], 0, 64)
	if addressErr != nil || sizeErr != nil || size == 0 || size > maximumBinaryWindowBytes || address+size < address {
		return result, fmt.Errorf("window %q has an invalid address or size (maximum %#x bytes)", value, maximumBinaryWindowBytes)
	}
	return binaryWindowSpec{Name: name, Input: input, Address: address, Bytes: size}, nil
}

func parseBinaryWindowOptions(args []string) (binaryWindowOptions, error) {
	options := binaryWindowOptions{Inputs: make(map[string]string)}
	seenWindows := make(map[string]bool)
	for index := 0; index < len(args); index++ {
		option := args[index]
		if option == "--portable" {
			if options.Portable {
				return options, errors.New("--portable may appear only once")
			}
			options.Portable = true
			continue
		}
		if index+1 >= len(args) {
			return options, fmt.Errorf("%s needs a value", option)
		}
		value := args[index+1]
		index++
		switch option {
		case "--input":
			name, path, ok := strings.Cut(value, "=")
			if !ok || !machServiceName.MatchString(name) || path == "" {
				return options, fmt.Errorf("--input value %q must be NAME=PATH", value)
			}
			if _, exists := options.Inputs[name]; exists {
				return options, fmt.Errorf("duplicate input name %q", name)
			}
			options.Inputs[name] = path
		case "--window":
			window, err := parseBinaryWindowSpec(value)
			if err != nil {
				return options, err
			}
			if seenWindows[window.Name] {
				return options, fmt.Errorf("duplicate window name %q", window.Name)
			}
			seenWindows[window.Name] = true
			options.Windows = append(options.Windows, window)
		case "--dest":
			if options.Destination != "" {
				return options, errors.New("--dest may appear only once")
			}
			options.Destination = value
		default:
			return options, fmt.Errorf("unknown contract windows option %q", option)
		}
	}
	if len(options.Inputs) == 0 || len(options.Windows) == 0 {
		return options, errors.New("contract windows requires at least one --input NAME=PATH and --window NAME=INPUT@ADDRESS+SIZE")
	}
	used := make(map[string]bool)
	for _, window := range options.Windows {
		if options.Inputs[window.Input] == "" {
			return options, fmt.Errorf("window %q refers to unknown input %q", window.Name, window.Input)
		}
		used[window.Input] = true
	}
	for name := range options.Inputs {
		if !used[name] {
			return options, fmt.Errorf("input %q has no declared window", name)
		}
	}
	return options, nil
}

func binaryWindowImageBase(metadata *contractMachO) (uint64, error) {
	base := ^uint64(0)
	for _, segment := range metadata.Segments {
		if segment.FileSize != 0 && segment.VMAddress < base {
			base = segment.VMAddress
		}
	}
	if base == ^uint64(0) {
		return 0, errors.New("Mach-O has no file-backed segment")
	}
	return base, nil
}

func binaryWindowContractCommand(_ context.Context, c *cache, args []string) error {
	options, err := parseBinaryWindowOptions(args)
	if err != nil {
		return err
	}
	inputNames := make([]string, 0, len(options.Inputs))
	for name := range options.Inputs {
		inputNames = append(inputNames, name)
	}
	sort.Strings(inputNames)
	contract := binaryWindowContract{Schema: binaryWindowContractSchema}
	type loadedInput struct {
		body     []byte
		file     *macho.File
		metadata *contractMachO
		base     uint64
	}
	loaded := make(map[string]loadedInput, len(inputNames))
	defer func() {
		for _, input := range loaded {
			_ = input.file.Close()
		}
	}()
	for _, name := range inputNames {
		path, size, sha, readErr := readRegularIdentity(options.Inputs[name])
		if readErr != nil {
			return readErr
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		file, openErr := macho.Open(path)
		if openErr != nil {
			return fmt.Errorf("binary-window input %s is not a thin Mach-O: %w", name, openErr)
		}
		metadata, inspectErr := inspectContractMachO(path, nil)
		if inspectErr != nil || metadata == nil {
			_ = file.Close()
			if inspectErr == nil {
				inspectErr = errors.New("missing Mach-O metadata")
			}
			return fmt.Errorf("inspect binary-window input %s: %w", name, inspectErr)
		}
		base, baseErr := binaryWindowImageBase(metadata)
		if baseErr != nil {
			_ = file.Close()
			return fmt.Errorf("inspect binary-window input %s: %w", name, baseErr)
		}
		identity := binaryWindowInput{Name: name, Bytes: size, SHA256: sha, MachO: metadata}
		if !options.Portable {
			identity.Path = path
		}
		contract.Inputs = append(contract.Inputs, identity)
		loaded[name] = loadedInput{body: body, file: file, metadata: metadata, base: base}
	}
	sort.Slice(options.Windows, func(i, j int) bool { return options.Windows[i].Name < options.Windows[j].Name })
	for _, spec := range options.Windows {
		input := loaded[spec.Input]
		offset, mapErr := machoAddressToOffset(input.file, spec.Address, spec.Bytes)
		if mapErr != nil {
			return fmt.Errorf("window %q: %w", spec.Name, mapErr)
		}
		if offset+spec.Bytes < offset || offset+spec.Bytes > uint64(len(input.body)) || spec.Address < input.base {
			return fmt.Errorf("window %q escapes input %q", spec.Name, spec.Input)
		}
		value := input.body[offset : offset+spec.Bytes]
		contract.Windows = append(contract.Windows, binaryWindow{
			Name: spec.Name, Input: spec.Input,
			Start: fmt.Sprintf("0x%x", spec.Address), End: fmt.Sprintf("0x%x", spec.Address+spec.Bytes),
			ImageOffset: fmt.Sprintf("0x%x", spec.Address-input.base),
			FileStart:   fmt.Sprintf("0x%x", offset), FileEnd: fmt.Sprintf("0x%x", offset+spec.Bytes),
			Bytes: spec.Bytes, SHA256: digest(value), Hex: hex.EncodeToString(value),
		})
	}
	body, err := json.MarshalIndent(contract, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	identity := digest(body)
	directory := filepath.Join(c.root, "private", "binary-window-contracts")
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	stored := filepath.Join(directory, identity+".json")
	if err = writeProbeFile(stored, body, 0o600); err != nil {
		return err
	}
	if err = writeProbeFile(filepath.Join(c.root, "private", "binary-window-contract-latest.json"), body, 0o600); err != nil {
		return err
	}
	if options.Destination != "" {
		destination, absErr := filepath.Abs(options.Destination)
		if absErr != nil {
			return absErr
		}
		if err = writeProbeFile(destination, body, 0o600); err != nil {
			return err
		}
	}
	entries, _ := os.ReadDir(directory)
	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() != identity+".json" && strings.HasSuffix(entry.Name(), ".json") {
			_ = os.Remove(filepath.Join(directory, entry.Name()))
		}
	}
	fmt.Fprintf(c.out, "Bound %d binary windows across %d inputs contract_sha256=%s contract=%s\n", len(contract.Windows), len(contract.Inputs), identity, stored)
	return nil
}
