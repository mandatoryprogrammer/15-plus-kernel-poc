package main

import (
	"bytes"
	"context"
	"debug/macho"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const targetImageContractSchema = "15-plus-kernel-poc.target-image-contract.v1"

type targetImageSection struct {
	Segment    string `json:"segment"`
	Section    string `json:"section"`
	Address    uint64 `json:"address"`
	Size       uint64 `json:"size"`
	FileOffset uint32 `json:"file_offset"`
}

type targetImageSymbol struct {
	Name           string `json:"name"`
	Address        uint64 `json:"address"`
	ImageOffset    uint64 `json:"image_offset"`
	FileOffset     uint64 `json:"file_offset"`
	PreimageHex    string `json:"preimage_hex"`
	PreimageSHA256 string `json:"preimage_sha256"`
}

type targetImageContract struct {
	Schema          string               `json:"schema"`
	CachePath       string               `json:"cache_path"`
	CacheBytes      int64                `json:"cache_bytes"`
	CacheSHA256     string               `json:"cache_sha256"`
	CacheUUID       string               `json:"cache_uuid"`
	CacheStaticBase uint64               `json:"cache_static_base"`
	ImagePath       string               `json:"image_path"`
	ImageSHA256     string               `json:"image_sha256"`
	ImageUUID       string               `json:"image_uuid"`
	StaticBase      uint64               `json:"static_base"`
	Segments        []contractSegment    `json:"segments"`
	Sections        []targetImageSection `json:"sections,omitempty"`
	Symbols         []targetImageSymbol  `json:"symbols"`
	LooseDyld       *targetLooseDyld     `json:"loose_dyld,omitempty"`
	SourceReport    *targetSourceReport  `json:"source_report,omitempty"`
}

type targetSourceReport struct {
	Path   string   `json:"path"`
	Bytes  int64    `json:"bytes"`
	SHA256 string   `json:"sha256"`
	Schema string   `json:"schema"`
	Roles  []string `json:"roles"`
}

type targetLooseDyld struct {
	Path       string            `json:"path"`
	Bytes      int64             `json:"bytes"`
	SHA256     string            `json:"sha256"`
	UUID       string            `json:"uuid"`
	StaticBase uint64            `json:"static_base"`
	Notifier   targetImageSymbol `json:"notifier"`
}

type targetImageContractOptions struct {
	Cache, Image, Destination, Dyld, DyldNotifier, Report string
	Symbols, Sections, Roles                              []string
}

func parseTargetImageContract(args []string) (targetImageContractOptions, error) {
	var options targetImageContractOptions
	for index := 0; index < len(args); index++ {
		if index+1 >= len(args) {
			return options, fmt.Errorf("%s needs a value", args[index])
		}
		option, value := args[index], args[index+1]
		index++
		switch option {
		case "--cache":
			if options.Cache != "" {
				return options, errors.New("--cache may appear only once")
			}
			options.Cache = value
		case "--image":
			if options.Image != "" {
				return options, errors.New("--image may appear only once")
			}
			options.Image = value
		case "--symbol":
			if !probeSymbolPattern.MatchString(value) {
				return options, fmt.Errorf("invalid symbol %q", value)
			}
			options.Symbols = append(options.Symbols, value)
		case "--report":
			if options.Report != "" {
				return options, errors.New("--report may appear only once")
			}
			options.Report = value
		case "--role":
			if !rolePattern.MatchString(value) {
				return options, fmt.Errorf("invalid report role %q", value)
			}
			for _, existing := range options.Roles {
				if existing == value {
					return options, fmt.Errorf("duplicate report role %q", value)
				}
			}
			options.Roles = append(options.Roles, value)
		case "--section":
			parts := strings.Split(value, ",")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return options, fmt.Errorf("section %q must be SEGMENT,SECTION", value)
			}
			options.Sections = append(options.Sections, value)
		case "--dest":
			if options.Destination != "" {
				return options, errors.New("--dest may appear only once")
			}
			options.Destination = value
		case "--dyld":
			if options.Dyld != "" {
				return options, errors.New("--dyld may appear only once")
			}
			options.Dyld = value
		case "--dyld-notifier":
			if options.DyldNotifier != "" {
				return options, errors.New("--dyld-notifier may appear only once")
			}
			options.DyldNotifier = value
		default:
			return options, fmt.Errorf("unknown target image-contract option %q", option)
		}
	}
	if options.Cache == "" || options.Image == "" || len(options.Symbols)+len(options.Roles) == 0 {
		return options, errors.New("target image-contract requires --cache FILE, --image PATH, and at least one --symbol NAME or --report FILE/--role ROLE")
	}
	if (options.Report == "") != (len(options.Roles) == 0) {
		return options, errors.New("--report FILE and at least one --role ROLE must be used together")
	}
	if options.DyldNotifier != "" && options.Dyld == "" {
		return options, errors.New("--dyld-notifier requires --dyld FILE")
	}
	if options.Dyld != "" && options.DyldNotifier == "" {
		options.DyldNotifier = "lldb_image_notifier"
	}
	return options, nil
}

type targetRoleReport struct {
	Schema      string `json:"schema"`
	SharedCache struct {
		UUID string `json:"uuid"`
	} `json:"shared_cache"`
	QuartzCore struct {
		Path        string `json:"path"`
		UUID        string `json:"uuid"`
		LoadAddress string `json:"load_address"`
	} `json:"quartzcore"`
	Functions []struct {
		Role   string `json:"role"`
		Start  string `json:"start"`
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
		Hex    string `json:"hex"`
	} `json:"functions"`
}

func compactTargetUUID(value string) string {
	return strings.ToLower(strings.ReplaceAll(value, "-", ""))
}

func targetContractAddressToOffset(segments []contractSegment, address, length uint64) (uint64, error) {
	for _, segment := range segments {
		if address < segment.VMAddress || address+length < address ||
			address+length > segment.VMAddress+segment.FileSize {
			continue
		}
		return segment.FileOffset + address - segment.VMAddress, nil
	}
	return 0, fmt.Errorf("report target 0x%x is not backed by extracted image bytes", address)
}

func targetReportRoleSymbols(contract targetImageContract, reportBody, imageBody []byte, roles []string) ([]targetImageSymbol, string, error) {
	var report targetRoleReport
	if err := json.Unmarshal(reportBody, &report); err != nil {
		return nil, "", fmt.Errorf("decode target role report: %w", err)
	}
	if report.Schema != "productos-carenderserver-display-list-contract.v2" {
		return nil, report.Schema, fmt.Errorf("target role report schema %q is unsupported", report.Schema)
	}
	loadAddress, err := strconv.ParseUint(report.QuartzCore.LoadAddress, 0, 64)
	if err != nil || compactTargetUUID(report.SharedCache.UUID) != compactTargetUUID(contract.CacheUUID) ||
		compactTargetUUID(report.QuartzCore.UUID) != compactTargetUUID(contract.ImageUUID) ||
		report.QuartzCore.Path != contract.ImagePath || loadAddress != contract.StaticBase {
		return nil, report.Schema, fmt.Errorf("target role report cache/image identity does not match extracted contract")
	}
	wanted := make(map[string]bool, len(roles))
	for _, role := range roles {
		wanted[role] = true
	}
	seen := make(map[string]bool, len(roles))
	var symbols []targetImageSymbol
	for _, function := range report.Functions {
		if !wanted[function.Role] {
			continue
		}
		if seen[function.Role] {
			return nil, report.Schema, fmt.Errorf("target role report contains duplicate role %q", function.Role)
		}
		seen[function.Role] = true
		address, parseErr := strconv.ParseUint(function.Start, 0, 64)
		body, decodeErr := hex.DecodeString(function.Hex)
		if parseErr != nil || decodeErr != nil || function.Bytes < 16 || len(body) != function.Bytes || digest(body) != function.SHA256 {
			return nil, report.Schema, fmt.Errorf("target role %q function identity is invalid", function.Role)
		}
		offset, mapErr := targetContractAddressToOffset(contract.Segments, address, 16)
		if mapErr != nil || offset+16 > uint64(len(imageBody)) || !bytes.Equal(imageBody[offset:offset+16], body[:16]) {
			return nil, report.Schema, fmt.Errorf("target role %q preimage does not match extracted image", function.Role)
		}
		preimage := body[:16]
		symbols = append(symbols, targetImageSymbol{Name: function.Role, Address: address,
			ImageOffset: address - contract.StaticBase, FileOffset: offset,
			PreimageHex: hex.EncodeToString(preimage), PreimageSHA256: digest(preimage)})
	}
	for _, role := range roles {
		if !seen[role] {
			return nil, report.Schema, fmt.Errorf("target role report lacks role %q", role)
		}
	}
	return symbols, report.Schema, nil
}

func inspectLooseDyld(path, notifier string) (*targetLooseDyld, error) {
	abs, size, sha, err := readRegularIdentity(path)
	if err != nil {
		return nil, err
	}
	file, err := macho.Open(abs)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	base := ^uint64(0)
	for _, load := range file.Loads {
		if segment, ok := load.(*macho.Segment); ok && segment.Filesz != 0 && segment.Addr < base {
			base = segment.Addr
		}
	}
	if base == ^uint64(0) || file.Symtab == nil {
		return nil, errors.New("loose dyld lacks a file-backed segment or symbol table")
	}
	for _, symbol := range file.Symtab.Syms {
		if symbol.Name != notifier && strings.TrimPrefix(symbol.Name, "_") != strings.TrimPrefix(notifier, "_") {
			continue
		}
		offset, mapErr := machoAddressToOffset(file, symbol.Value, 16)
		if mapErr != nil {
			return nil, mapErr
		}
		if offset+16 > uint64(len(body)) {
			return nil, errors.New("loose dyld notifier preimage escaped file")
		}
		preimage := body[offset : offset+16]
		return &targetLooseDyld{Path: abs, Bytes: size, SHA256: sha, UUID: machoUUID(file), StaticBase: base, Notifier: targetImageSymbol{Name: symbol.Name, Address: symbol.Value, ImageOffset: symbol.Value - base, FileOffset: offset, PreimageHex: hex.EncodeToString(preimage), PreimageSHA256: digest(preimage)}}, nil
	}
	return nil, fmt.Errorf("loose dyld notifier %q is absent from %s", notifier, abs)
}

func dyldCacheIdentity(path string) (string, uint64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	header := make([]byte, 0x68)
	if _, err = file.ReadAt(header, 0); err != nil {
		return "", 0, err
	}
	if !strings.HasPrefix(string(header[:16]), "dyld_v1") {
		return "", 0, errors.New("input is not a dyld shared cache")
	}
	value := hex.EncodeToString(header[0x58:0x68])
	mappingOffset := uint64(uint32(header[0x10]) | uint32(header[0x11])<<8 | uint32(header[0x12])<<16 | uint32(header[0x13])<<24)
	mapping := make([]byte, 8)
	if mappingOffset < 0x68 || mappingOffset > 1<<20 {
		return "", 0, errors.New("dyld cache mapping offset is invalid")
	}
	if _, err = file.ReadAt(mapping, int64(mappingOffset)); err != nil {
		return "", 0, err
	}
	base := uint64At(mapping, 0)
	if base == 0 {
		return "", 0, errors.New("dyld cache static base is zero")
	}
	return strings.ToUpper(value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32]), base, nil
}

func machoAddressToOffset(file *macho.File, address uint64, length uint64) (uint64, error) {
	for _, load := range file.Loads {
		segment, ok := load.(*macho.Segment)
		if !ok || address < segment.Addr || address+length < address || address+length > segment.Addr+segment.Filesz {
			continue
		}
		return segment.Offset + address - segment.Addr, nil
	}
	return 0, fmt.Errorf("address 0x%x is not backed by image file bytes", address)
}

func targetImageContractCommand(ctx context.Context, c *cache, args []string) error {
	options, err := parseTargetImageContract(args)
	if err != nil {
		return err
	}
	cachePath, cacheBytes, cacheSHA, err := readRegularIdentity(options.Cache)
	if err != nil {
		return err
	}
	cacheUUID, cacheBase, err := dyldCacheIdentity(cachePath)
	if err != nil {
		return err
	}
	ipsw, err := exec.LookPath("ipsw")
	if err != nil {
		return errors.New("target image-contract requires the ipsw primary parser in PATH")
	}
	scratch, err := os.MkdirTemp(filepath.Join(c.root, "tmp"), "target-image-contract-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	if err = runProbeProcess(ctx, c.out, scratch, "extract exact dyld-cache image", ipsw,
		[]string{"dyld", "macho", cachePath, options.Image, "--extract", "--output", scratch, "--force", "--no-color"}, 2*time.Minute); err != nil {
		return err
	}
	extracted := filepath.Join(scratch, filepath.Base(options.Image))
	imageBody, err := os.ReadFile(extracted)
	if err != nil {
		return fmt.Errorf("ipsw did not extract %s: %w", filepath.Base(options.Image), err)
	}
	file, err := macho.Open(extracted)
	if err != nil {
		return err
	}
	defer file.Close()
	contract := targetImageContract{Schema: targetImageContractSchema, CachePath: cachePath, CacheBytes: cacheBytes,
		CacheSHA256: cacheSHA, CacheUUID: cacheUUID, CacheStaticBase: cacheBase, ImagePath: options.Image, ImageSHA256: digest(imageBody), ImageUUID: machoUUID(file)}
	if options.Dyld != "" {
		contract.LooseDyld, err = inspectLooseDyld(options.Dyld, options.DyldNotifier)
		if err != nil {
			return err
		}
	}
	contract.StaticBase = ^uint64(0)
	for _, load := range file.Loads {
		segment, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		contract.Segments = append(contract.Segments, contractSegment{Name: segment.Name, VMAddress: segment.Addr, VMSize: segment.Memsz, FileOffset: segment.Offset, FileSize: segment.Filesz})
		if segment.Filesz != 0 && segment.Addr < contract.StaticBase {
			contract.StaticBase = segment.Addr
		}
	}
	if contract.StaticBase == ^uint64(0) {
		return errors.New("extracted image has no file-backed segment")
	}
	for _, requested := range options.Sections {
		parts := strings.Split(requested, ",")
		found := false
		for _, section := range file.Sections {
			if section.Seg == parts[0] && section.Name == parts[1] {
				contract.Sections = append(contract.Sections, targetImageSection{Segment: section.Seg, Section: section.Name, Address: section.Addr, Size: section.Size, FileOffset: section.Offset})
				found = true
			}
		}
		if !found {
			return fmt.Errorf("requested section %s is absent from %s", requested, options.Image)
		}
	}
	if len(options.Symbols) != 0 && file.Symtab == nil {
		return errors.New("extracted image has no symbol table")
	}
	for _, requested := range options.Symbols {
		found := false
		for _, symbol := range file.Symtab.Syms {
			if symbol.Name != requested && strings.TrimPrefix(symbol.Name, "_") != strings.TrimPrefix(requested, "_") {
				continue
			}
			offset, mapErr := machoAddressToOffset(file, symbol.Value, 16)
			if mapErr != nil {
				return mapErr
			}
			if offset+16 > uint64(len(imageBody)) {
				return errors.New("symbol preimage escaped extracted image")
			}
			preimage := imageBody[offset : offset+16]
			contract.Symbols = append(contract.Symbols, targetImageSymbol{Name: symbol.Name, Address: symbol.Value,
				ImageOffset: symbol.Value - contract.StaticBase, FileOffset: offset, PreimageHex: hex.EncodeToString(preimage), PreimageSHA256: digest(preimage)})
			found = true
			break
		}
		if !found {
			return fmt.Errorf("requested symbol %q is absent from %s", requested, options.Image)
		}
	}
	if options.Report != "" {
		reportPath, reportBytes, reportSHA, reportErr := readRegularIdentity(options.Report)
		if reportErr != nil {
			return reportErr
		}
		reportBody, reportErr := os.ReadFile(reportPath)
		if reportErr != nil {
			return reportErr
		}
		roles, reportSchema, reportErr := targetReportRoleSymbols(contract, reportBody, imageBody, options.Roles)
		if reportErr != nil {
			return reportErr
		}
		contract.Symbols = append(contract.Symbols, roles...)
		contract.SourceReport = &targetSourceReport{Path: reportPath, Bytes: reportBytes,
			SHA256: reportSHA, Schema: reportSchema, Roles: append([]string(nil), options.Roles...)}
	}
	sort.Slice(contract.Symbols, func(i, j int) bool { return contract.Symbols[i].Name < contract.Symbols[j].Name })
	for index, symbol := range contract.Symbols {
		if index != 0 && (symbol.Name == contract.Symbols[index-1].Name || symbol.Address == contract.Symbols[index-1].Address) {
			return fmt.Errorf("duplicate target name or address after report binding: %q at 0x%x", symbol.Name, symbol.Address)
		}
		for prior := 0; prior < index; prior++ {
			if symbol.Address == contract.Symbols[prior].Address {
				return fmt.Errorf("duplicate target address after report binding: 0x%x", symbol.Address)
			}
		}
	}
	body, err := json.MarshalIndent(contract, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	identity := digest(body)
	directory := filepath.Join(c.root, "private", "target-image-contracts")
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	stored := filepath.Join(directory, identity+".json")
	if err = writeProbeFile(stored, body, 0o600); err != nil {
		return err
	}
	if err = writeProbeFile(filepath.Join(c.root, "private", "target-image-contract-latest.json"), body, 0o600); err != nil {
		return err
	}
	if options.Destination != "" {
		options.Destination, err = filepath.Abs(options.Destination)
		if err != nil {
			return err
		}
		if err = writeProbeFile(options.Destination, body, 0o600); err != nil {
			return err
		}
	}
	entries, _ := os.ReadDir(directory)
	for _, entry := range entries {
		if !entry.IsDir() && entry.Name() != identity+".json" && strings.HasSuffix(entry.Name(), ".json") {
			_ = os.Remove(filepath.Join(directory, entry.Name()))
		}
	}
	fmt.Fprintf(c.out, "Bound target image cache_uuid=%s image_uuid=%s static_base=0x%x symbols=%d contract_sha256=%s contract=%s\n",
		contract.CacheUUID, contract.ImageUUID, contract.StaticBase, len(contract.Symbols), identity, stored)
	return nil
}
