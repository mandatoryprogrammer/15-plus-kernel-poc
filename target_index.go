package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	targetIndexSchema    = "15-plus-kernel-poc.target-index.v2"
	targetPlistReadLimit = 32 << 20
)

type targetIndexedFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Format string `json:"format,omitempty"`
}

type targetIndexedPlist struct {
	targetIndexedFile
	Label        string   `json:"label,omitempty"`
	MachServices []string `json:"mach_services,omitempty"`
	ParseError   string   `json:"parse_error,omitempty"`
}

type targetMachService struct {
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
	Plist string `json:"plist"`
}

type targetTrustCache struct {
	targetIndexedFile
	Version     uint32 `json:"version"`
	EntryCount  int    `json:"entry_count"`
	ImageSHA256 string `json:"image_sha256"`
}

type targetIndexedSymlink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

type targetSkippedEntry struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type targetIndex struct {
	Schema            string                 `json:"schema"`
	ProductVersion    string                 `json:"product_version"`
	ProductBuild      string                 `json:"product_build"`
	Executables       []targetIndexedFile    `json:"executables"`
	Plists            []targetIndexedPlist   `json:"plists"`
	MachServices      []targetMachService    `json:"mach_services"`
	SharedCaches      []targetIndexedFile    `json:"shared_caches"`
	StaticTrustCaches []targetTrustCache     `json:"static_trust_caches"`
	Symlinks          []targetIndexedSymlink `json:"symlinks,omitempty"`
	Skipped           []targetSkippedEntry   `json:"skipped,omitempty"`
}

type targetIndexArtifact struct {
	Index  targetIndex
	SHA256 string
	Path   string
}

func targetCommand(ctx context.Context, c *cache, args []string) error {
	if len(args) >= 1 && args[0] == "index" {
		return targetIndexCommand(ctx, c, args[1:])
	}
	if len(args) >= 1 && args[0] == "image-contract" {
		return targetImageContractCommand(ctx, c, args[1:])
	}
	return errors.New("usage: target index PRODUCTOS_ROOT | target image-contract --cache FILE --image PATH (--symbol NAME | --report FILE --role ROLE)... [--dyld FILE --dyld-notifier SYMBOL] [--section SEGMENT,SECTION]... [--dest FILE]")
}

func targetIndexCommand(ctx context.Context, c *cache, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: target index PRODUCTOS_ROOT")
	}
	artifact, err := buildAndStoreTargetIndex(ctx, c, args[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Indexed ProductOS %s (%s): %d executables, %d plists, %d Mach services, %d shared-cache files, %d StaticTrustCache files; index %s\n",
		artifact.Index.ProductVersion, artifact.Index.ProductBuild, len(artifact.Index.Executables), len(artifact.Index.Plists), len(artifact.Index.MachServices), len(artifact.Index.SharedCaches), len(artifact.Index.StaticTrustCaches), artifact.SHA256)
	return nil
}

func buildAndStoreTargetIndex(ctx context.Context, c *cache, root string) (targetIndexArtifact, error) {
	index, err := buildTargetIndexWithOutput(ctx, root, c.out)
	if err != nil {
		return targetIndexArtifact{}, err
	}
	return storeTargetIndex(c, index)
}

func storeTargetIndex(c *cache, index targetIndex) (targetIndexArtifact, error) {
	body, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return targetIndexArtifact{}, err
	}
	body = append(body, '\n')
	identity := digest(body)
	directory := filepath.Join(c.root, "private", "target-indexes")
	if err = os.MkdirAll(directory, 0700); err != nil {
		return targetIndexArtifact{}, err
	}
	objectPath := filepath.Join(directory, identity+".json")
	if err = writeImmutableTargetIndex(objectPath, body); err != nil {
		return targetIndexArtifact{}, err
	}
	if err = writeTargetIndexLatest(filepath.Join(c.root, "private", "target-index-latest.json"), body); err != nil {
		return targetIndexArtifact{}, err
	}
	if err = pruneTargetIndexes(directory, identity); err != nil {
		return targetIndexArtifact{}, err
	}
	return targetIndexArtifact{Index: index, SHA256: identity, Path: objectPath}, nil
}

func pruneTargetIndexes(directory, keep string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || name == keep+".json" || filepath.Ext(name) != ".json" {
			continue
		}
		identity := strings.TrimSuffix(name, ".json")
		if !digestPattern.MatchString(identity) {
			continue
		}
		if err = os.Remove(filepath.Join(directory, name)); err != nil {
			return err
		}
	}
	return nil
}

func writeImmutableTargetIndex(name string, body []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		existing, readErr := os.ReadFile(name)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, body) {
			return errors.New("content-addressed target index identity collision")
		}
		return nil
	}
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	ok = true
	return nil
}

func writeTargetIndexLatest(name string, body []byte) error {
	f, err := os.CreateTemp(filepath.Dir(name), "target-index-")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(body)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary, name)
}

func buildTargetIndex(ctx context.Context, root string) (targetIndex, error) {
	return buildTargetIndexWithOutput(ctx, root, io.Discard)
}

func buildTargetIndexWithOutput(ctx context.Context, root string, out io.Writer) (targetIndex, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	absolute, err := filepath.Abs(root)
	if err != nil {
		return targetIndex{}, err
	}
	absolute = filepath.Clean(absolute)
	info, err := os.Lstat(absolute)
	if err != nil {
		return targetIndex{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return targetIndex{}, errors.New("ProductOS root must be a real directory, not a symlink")
	}
	realRoot, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return targetIndex{}, err
	}
	realRoot, err = filepath.Abs(realRoot)
	if err != nil {
		return targetIndex{}, err
	}
	absolute = filepath.Clean(realRoot)
	fmt.Fprintf(out, "Indexing ProductOS target %s (deadline 2h; symlinks recorded but never followed)\n", absolute)
	stop := heartbeat(out, "Indexing ProductOS target", 2*time.Hour)
	defer stop()
	index := targetIndex{Schema: targetIndexSchema}
	err = filepath.WalkDir(absolute, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(absolute, name)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
			return errors.New("target index path escaped ProductOS root")
		}
		relative = filepath.ToSlash(relative)
		if !validTargetRelativePath(relative) {
			return fmt.Errorf("unsafe ProductOS path %q", relative)
		}
		if relative == ".file" {
			fileInfo, infoErr := entry.Info()
			if infoErr != nil {
				return infoErr
			}
			if !fileInfo.Mode().IsRegular() || fileInfo.Size() != 0 || fileInfo.Mode().Perm() != 0 {
				return errors.New("ProductOS root .file metadata entry has an unexpected identity")
			}
			index.Skipped = append(index.Skipped, targetSkippedEntry{
				Path: relative, Reason: "apfs-root-filesystem-metadata",
			})
			return nil
		}
		mode := entry.Type()
		if mode&os.ModeSymlink != 0 {
			target, readErr := os.Readlink(name)
			if readErr != nil {
				return readErr
			}
			if target == "" || len(target) > 4096 || strings.ContainsAny(target, "\x00\r\n") {
				return fmt.Errorf("ProductOS root contains unsafe symlink %s", relative)
			}
			index.Symlinks = append(index.Symlinks, targetIndexedSymlink{Path: relative, Target: target})
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		fileInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("ProductOS root contains non-regular entry %s", relative)
		}
		return indexTargetFile(ctx, &index, absolute, relative, fileInfo, out)
	})
	if err != nil {
		return targetIndex{}, err
	}
	sortTargetIndex(&index)
	version, build, err := validateSystemVersionPlist(absolute)
	if err != nil {
		return targetIndex{}, err
	}
	index.ProductVersion, index.ProductBuild = version, build
	if !containsTargetPath(index.Executables, "usr/lib/dyld") {
		return targetIndex{}, errors.New("ProductOS root is missing executable usr/lib/dyld")
	}
	return index, nil
}

func validTargetRelativePath(name string) bool {
	if name == "" || name == "." || strings.ContainsAny(name, "\x00\r\n") || strings.HasPrefix(name, "/") {
		return false
	}
	for _, component := range strings.Split(name, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func indexTargetFile(ctx context.Context, index *targetIndex, root, relative string, info fs.FileInfo, out io.Writer) error {
	name := filepath.Join(root, filepath.FromSlash(relative))
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || opened.Size() != info.Size() || !os.SameFile(info, opened) {
		return fmt.Errorf("ProductOS file changed while indexing: %s", relative)
	}
	header := make([]byte, 8)
	n, readErr := io.ReadFull(f, header)
	if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
		return readErr
	}
	header = header[:n]
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	base := filepath.Base(relative)
	isPlist := strings.EqualFold(filepath.Ext(base), ".plist")
	isSharedCache := strings.HasPrefix(base, "dyld_shared_cache_")
	isTrustCache := base == "StaticTrustCache" || strings.HasPrefix(base, "StaticTrustCache.")
	format := targetExecutableFormat(header, info.Mode())
	if format == "" && !isPlist && !isSharedCache && !isTrustCache {
		return nil
	}
	if isTrustCache && (info.Size() <= 0 || info.Size() > systemTrustContextLimit) {
		return fmt.Errorf("validate %s: StaticTrustCache exceeds %d-byte limit", relative, systemTrustContextLimit)
	}
	h := sha256.New()
	var captured bytes.Buffer
	writer := io.Writer(h)
	if info.Size() >= 32<<20 {
		writer = io.MultiWriter(writer, &byteProgress{out: out, name: "Hashing " + relative, total: info.Size(), start: time.Now(), last: time.Now()})
	}
	if (isPlist && info.Size() <= targetPlistReadLimit) || isTrustCache {
		writer = io.MultiWriter(writer, &captured)
	}
	if _, err = copyContext(ctx, writer, f); err != nil {
		return err
	}
	identity := hex.EncodeToString(h.Sum(nil))
	entry := targetIndexedFile{Path: relative, Size: info.Size(), SHA256: identity, Format: format}
	if format != "" {
		index.Executables = append(index.Executables, entry)
	}
	if isSharedCache {
		cacheEntry := entry
		cacheEntry.Format = "dyld-shared-cache"
		index.SharedCaches = append(index.SharedCaches, cacheEntry)
	}
	if isPlist {
		plist := targetIndexedPlist{targetIndexedFile: entry}
		plist.Format = "plist"
		if info.Size() > targetPlistReadLimit {
			plist.ParseError = fmt.Sprintf("plist exceeds %d-byte parse limit", targetPlistReadLimit)
		} else {
			value, parseErr := decodeTargetPlist(captured.Bytes())
			if parseErr != nil {
				plist.ParseError = parseErr.Error()
			} else {
				plist.Label, _ = value["Label"].(string)
				if services, ok := value["MachServices"].(map[string]any); ok {
					for service := range services {
						if service != "" {
							plist.MachServices = append(plist.MachServices, service)
						}
					}
					sort.Strings(plist.MachServices)
					for _, service := range plist.MachServices {
						index.MachServices = append(index.MachServices, targetMachService{Name: service, Label: plist.Label, Plist: relative})
					}
				}
			}
		}
		index.Plists = append(index.Plists, plist)
	}
	if isTrustCache {
		body := captured.Bytes()
		im4p, _, unwrapErr := unwrapImage(body)
		if unwrapErr != nil {
			im4p = body
		}
		parsed, parseErr := parseTrustCacheImage(im4p, "trst")
		if parseErr != nil {
			return fmt.Errorf("validate %s: %w", relative, parseErr)
		}
		trustEntry := targetTrustCache{targetIndexedFile: entry, Version: parsed.version, EntryCount: len(parsed.rows), ImageSHA256: digest(im4p)}
		trustEntry.Format = "static-trust-cache"
		index.StaticTrustCaches = append(index.StaticTrustCaches, trustEntry)
	}
	return nil
}

func targetExecutableFormat(header []byte, mode fs.FileMode) string {
	if len(header) >= 4 {
		switch [4]byte(header[:4]) {
		case [4]byte{0xcf, 0xfa, 0xed, 0xfe}, [4]byte{0xce, 0xfa, 0xed, 0xfe}, [4]byte{0xfe, 0xed, 0xfa, 0xcf}, [4]byte{0xfe, 0xed, 0xfa, 0xce}:
			return "mach-o"
		case [4]byte{0xca, 0xfe, 0xba, 0xbe}, [4]byte{0xbe, 0xba, 0xfe, 0xca}, [4]byte{0xca, 0xfe, 0xba, 0xbf}, [4]byte{0xbf, 0xba, 0xfe, 0xca}:
			return "universal-mach-o"
		}
	}
	if mode.Perm()&0111 != 0 {
		if bytes.HasPrefix(header, []byte("#!")) {
			return "script"
		}
		return "executable"
	}
	return ""
}

func sortTargetIndex(index *targetIndex) {
	sort.Slice(index.Executables, func(i, j int) bool { return index.Executables[i].Path < index.Executables[j].Path })
	sort.Slice(index.Plists, func(i, j int) bool { return index.Plists[i].Path < index.Plists[j].Path })
	sort.Slice(index.MachServices, func(i, j int) bool {
		if index.MachServices[i].Name != index.MachServices[j].Name {
			return index.MachServices[i].Name < index.MachServices[j].Name
		}
		return index.MachServices[i].Plist < index.MachServices[j].Plist
	})
	sort.Slice(index.SharedCaches, func(i, j int) bool { return index.SharedCaches[i].Path < index.SharedCaches[j].Path })
	sort.Slice(index.StaticTrustCaches, func(i, j int) bool { return index.StaticTrustCaches[i].Path < index.StaticTrustCaches[j].Path })
	sort.Slice(index.Symlinks, func(i, j int) bool { return index.Symlinks[i].Path < index.Symlinks[j].Path })
	sort.Slice(index.Skipped, func(i, j int) bool { return index.Skipped[i].Path < index.Skipped[j].Path })
}

func containsTargetPathBase(entries []targetIndexedFile, base string) bool {
	for _, entry := range entries {
		if filepath.Base(entry.Path) == base {
			return true
		}
	}
	return false
}

func containsTargetPath(entries []targetIndexedFile, name string) bool {
	for _, entry := range entries {
		if entry.Path == name {
			return true
		}
	}
	return false
}

func validateSystemVersionPlist(root string) (string, string, error) {
	name := filepath.Join(root, "System", "Library", "CoreServices", "SystemVersion.plist")
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > targetPlistReadLimit {
		return "", "", errors.New("SystemVersion.plist is missing, unsafe, or too large")
	}
	body, err := os.ReadFile(name)
	if err != nil {
		return "", "", err
	}
	value, err := decodeTargetPlist(body)
	if err != nil {
		return "", "", err
	}
	version, versionOK := value["ProductVersion"].(string)
	build, buildOK := value["ProductBuildVersion"].(string)
	if !versionOK || !buildOK || version == "" || build == "" {
		return "", "", errors.New("SystemVersion.plist has no ProductVersion/ProductBuildVersion")
	}
	return version, build, nil
}

func decodeTargetPlist(body []byte) (map[string]any, error) {
	if bytes.HasPrefix(body, []byte("bplist00")) {
		value, err := decodeBinaryTargetPlist(body)
		if err != nil {
			return nil, err
		}
		result, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("binary plist root is not a dictionary")
		}
		return result, nil
	}
	return decodePlist(body)
}

type binaryTargetPlist struct {
	body       []byte
	offsets    []uint64
	objectRefs int
	active     map[uint64]bool
}

func decodeBinaryTargetPlist(body []byte) (any, error) {
	if len(body) < 40 || !bytes.HasPrefix(body, []byte("bplist00")) {
		return nil, errors.New("invalid binary plist header")
	}
	trailer := body[len(body)-32:]
	offsetSize, refSize := int(trailer[6]), int(trailer[7])
	count := binary.BigEndian.Uint64(trailer[8:16])
	top := binary.BigEndian.Uint64(trailer[16:24])
	offsetTable := binary.BigEndian.Uint64(trailer[24:32])
	if offsetSize < 1 || offsetSize > 8 || refSize < 1 || refSize > 8 || count == 0 || count > 1<<24 || top >= count || offsetTable < 8 || offsetTable > uint64(len(body)-32) || count > uint64(len(body))/uint64(offsetSize) || offsetTable+count*uint64(offsetSize) > uint64(len(body)-32) {
		return nil, errors.New("invalid binary plist trailer")
	}
	decoder := binaryTargetPlist{body: body, objectRefs: refSize, active: map[uint64]bool{}, offsets: make([]uint64, count)}
	for index := uint64(0); index < count; index++ {
		offset := readTargetUint(body[offsetTable+index*uint64(offsetSize):], offsetSize)
		if offset < 8 || offset >= offsetTable {
			return nil, errors.New("invalid binary plist object offset")
		}
		decoder.offsets[index] = offset
	}
	return decoder.object(top, 0)
}

func (p *binaryTargetPlist) object(reference uint64, depth int) (any, error) {
	if reference >= uint64(len(p.offsets)) || depth > 128 {
		return nil, errors.New("invalid binary plist object reference")
	}
	if p.active[reference] {
		return nil, errors.New("cyclic binary plist")
	}
	p.active[reference] = true
	defer delete(p.active, reference)
	position := p.offsets[reference]
	marker := p.body[position]
	kind, low := marker>>4, marker&15
	position++
	switch kind {
	case 0:
		switch low {
		case 0:
			return nil, nil
		case 8:
			return false, nil
		case 9:
			return true, nil
		default:
			return nil, errors.New("unsupported binary plist simple object")
		}
	case 1:
		width := 1 << low
		if width > 8 || position+uint64(width) > uint64(len(p.body)) {
			return nil, errors.New("invalid binary plist integer")
		}
		return readTargetUint(p.body[position:], width), nil
	case 4, 5, 6, 10, 13:
		length, start, err := p.objectLength(position, low)
		if err != nil {
			return nil, err
		}
		switch kind {
		case 4:
			if length > uint64(len(p.body)) || start+length > uint64(len(p.body)) {
				return nil, errors.New("invalid binary plist data")
			}
			return bytes.Clone(p.body[start : start+length]), nil
		case 5:
			if length > uint64(len(p.body)) || start+length > uint64(len(p.body)) {
				return nil, errors.New("invalid binary plist ASCII string")
			}
			return string(p.body[start : start+length]), nil
		case 6:
			if length > uint64(len(p.body))/2 || start+length*2 > uint64(len(p.body)) {
				return nil, errors.New("invalid binary plist UTF-16 string")
			}
			units := make([]uint16, length)
			for index := range units {
				units[index] = binary.BigEndian.Uint16(p.body[start+uint64(index*2):])
			}
			return string(utf16.Decode(units)), nil
		case 10:
			if length > uint64(len(p.offsets)) || start+length*uint64(p.objectRefs) > uint64(len(p.body)) {
				return nil, errors.New("invalid binary plist array")
			}
			result := make([]any, length)
			for index := range result {
				child := readTargetUint(p.body[start+uint64(index*p.objectRefs):], p.objectRefs)
				result[index], err = p.object(child, depth+1)
				if err != nil {
					return nil, err
				}
			}
			return result, nil
		case 13:
			bytesNeeded := length * uint64(p.objectRefs) * 2
			if length > uint64(len(p.offsets)) || start+bytesNeeded > uint64(len(p.body)) {
				return nil, errors.New("invalid binary plist dictionary")
			}
			result := make(map[string]any, length)
			values := start + length*uint64(p.objectRefs)
			for index := uint64(0); index < length; index++ {
				keyRef := readTargetUint(p.body[start+index*uint64(p.objectRefs):], p.objectRefs)
				valueRef := readTargetUint(p.body[values+index*uint64(p.objectRefs):], p.objectRefs)
				keyValue, keyErr := p.object(keyRef, depth+1)
				if keyErr != nil {
					return nil, keyErr
				}
				key, ok := keyValue.(string)
				if !ok || key == "" {
					return nil, errors.New("binary plist dictionary key is not a string")
				}
				if _, duplicate := result[key]; duplicate {
					return nil, errors.New("duplicate binary plist dictionary key")
				}
				result[key], err = p.object(valueRef, depth+1)
				if err != nil {
					return nil, err
				}
			}
			return result, nil
		}
	}
	return nil, fmt.Errorf("unsupported binary plist object kind %#x", kind)
}

func (p *binaryTargetPlist) objectLength(position uint64, low byte) (uint64, uint64, error) {
	if low != 15 {
		return uint64(low), position, nil
	}
	if position >= uint64(len(p.body)) || p.body[position]>>4 != 1 {
		return 0, 0, errors.New("invalid binary plist extended length")
	}
	width := 1 << (p.body[position] & 15)
	position++
	if width > 8 || position+uint64(width) > uint64(len(p.body)) {
		return 0, 0, errors.New("invalid binary plist extended length integer")
	}
	return readTargetUint(p.body[position:], width), position + uint64(width), nil
}

func readTargetUint(body []byte, width int) uint64 {
	var value uint64
	for _, b := range body[:width] {
		value = value<<8 | uint64(b)
	}
	return value
}
