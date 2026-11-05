package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	payloadLimit      = 64 << 20
	machoTypeDylinker = macho.Type(7)
)

func packedPlatformVersion(version string) (uint32, error) {
	parts := strings.Split(version, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, fmt.Errorf("invalid runtime iOS version %q", version)
	}
	values := []uint64{0, 0, 0}
	for index, part := range parts {
		value, err := strconv.ParseUint(part, 10, 16)
		if err != nil || index > 0 && value > 0xff {
			return 0, fmt.Errorf("invalid runtime iOS version %q", version)
		}
		values[index] = value
	}
	return uint32(values[0]<<16 | values[1]<<8 | values[2]), nil
}

var reservedPayloadDestinations = map[string]bool{
	"/usr/local/bin/payload-runner":            true,
	"/usr/local/bin/console-service":           true,
	"/usr/local/bin/productos-pds1":            true,
	"/usr/local/bin/productos-restore-utility": true,
	"/usr/local/bin/restored_external":         true,
	"/usr/local/bin/restored_stock":            true,
	"/usr/local/bin/tconctl":                   true,
}

type payloadEntry struct {
	Destination string `json:"destination"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	CDHash      string `json:"cdhash"`
	Origin      string `json:"origin"`
}

func basePayload() ([]payloadEntry, error) {
	var entries []payloadEntry
	if err := json.Unmarshal(payloadManifest, &entries); err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		seen[entry.Destination] = true
	}
	commands, err := builtInCommands()
	if err != nil {
		return nil, err
	}
	for _, command := range commands {
		if seen[command.Destination] {
			return nil, fmt.Errorf("built-in command destination collision: %s", command.Destination)
		}
		entries = append(entries, payloadEntry{
			Destination: command.Destination,
			SHA256:      digest(command.Body),
			Size:        int64(len(command.Body)),
			Origin:      "built-in shell command",
		})
		seen[command.Destination] = true
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Destination < entries[j].Destination })
	return entries, nil
}

func payloadPlan(base, additions []payloadEntry, capacity int64) ([]payloadEntry, error) {
	seen := map[string]bool{}
	var total int64
	for _, b := range base {
		seen[b.Destination] = true
	}
	for _, a := range additions {
		if !validPayloadDestination(a.Destination) {
			return nil, fmt.Errorf("invalid payload destination %q: use /usr/local/bin/NAME, /usr/local/lib/NAME, or /usr/local/libexec/NAME", a.Destination)
		}
		if seen[a.Destination] || reservedPayloadDestinations[a.Destination] {
			return nil, fmt.Errorf("payload destination collision: %s", a.Destination)
		}
		seen[a.Destination] = true
		if !digestPattern.MatchString(a.SHA256) || len(a.CDHash) != 40 || a.Size <= 0 || a.Size > payloadLimit {
			return nil, fmt.Errorf("invalid payload identity: %s", a.Destination)
		}
		if _, err := hex.DecodeString(a.CDHash); err != nil {
			return nil, err
		}
		total += (a.Size + 4095) &^ 4095
		if total > capacity {
			return nil, fmt.Errorf("payload needs %d bytes, capacity is %d", total, capacity)
		}
	}
	return append(append([]payloadEntry{}, base...), additions...), nil
}

func validPayloadDestination(destination string) bool {
	if path.Clean(destination) != destination || strings.ContainsAny(destination, "\x00\r\n") {
		return false
	}
	directory := path.Dir(destination)
	if directory != "/usr/local/bin" && directory != "/usr/local/libexec" && directory != "/usr/local/lib" && !strings.HasPrefix(directory, "/usr/local/lib/") {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(destination, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

// inspectExecutable accepts thin iOS arm64/arm64e executables, dylibs, and
// dynamic linkers and verifies every signed code page. macOS, simulator,
// Intel, malformed, and encrypted inputs fail.
func inspectExecutable(b []byte) (string, error) {
	if len(b) > payloadLimit {
		return "", errors.New("binary exceeds 64 MiB payload limit")
	}
	f, err := macho.NewFile(bytes.NewReader(b))
	if err != nil {
		return "", fmt.Errorf("expected a thin iOS Mach-O executable, dylib, or dynamic linker: %w", err)
	}
	defer f.Close()
	maximumVersion, err := packedPlatformVersion(canonicalRuntime.IOSVersion)
	if err != nil {
		return "", err
	}
	validFileType := f.Type == macho.TypeExec || f.Type == macho.TypeDylib || f.Type == machoTypeDylinker
	if f.Cpu != macho.CpuArm64 || !validFileType || (f.SubCpu&0xffffff) != 0 && (f.SubCpu&0xffffff) != 2 {
		return "", errors.New("binary must be a thin arm64 or arm64e executable, dylib, or dynamic linker")
	}
	ios := false
	var signature []byte
	for _, load := range f.Loads {
		raw := load.Raw()
		if len(raw) < 8 {
			return "", errors.New("short Mach-O load command")
		}
		cmd := f.ByteOrder.Uint32(raw)
		switch cmd {
		case 0x32:
			if len(raw) < 24 {
				return "", errors.New("short build version")
			}
			ios = f.ByteOrder.Uint32(raw[8:]) == 2
			if f.ByteOrder.Uint32(raw[12:]) > maximumVersion {
				return "", fmt.Errorf("binary requires an iOS version newer than %s", canonicalRuntime.IOSVersion)
			}
		case 0x25:
			if len(raw) < 16 {
				return "", errors.New("short iOS version command")
			}
			ios = true
			if f.ByteOrder.Uint32(raw[8:]) > maximumVersion {
				return "", fmt.Errorf("binary requires an iOS version newer than %s", canonicalRuntime.IOSVersion)
			}
		case 0x2c:
			if len(raw) < 24 || f.ByteOrder.Uint32(raw[16:]) != 0 {
				return "", errors.New("encrypted executable is unsupported")
			}
		case 0x1d:
			if len(raw) != 16 {
				return "", errors.New("invalid code signature command")
			}
			off := uint64(f.ByteOrder.Uint32(raw[8:]))
			size := uint64(f.ByteOrder.Uint32(raw[12:]))
			if size == 0 || off+size > uint64(len(b)) || signature != nil {
				return "", errors.New("invalid signature bounds")
			}
			signature = b[off : off+size]
		}
	}
	if !ios {
		return "", errors.New("binary targets macOS or a simulator; supply an iOS arm64 executable")
	}
	if signature == nil {
		return "", errors.New("Mach-O image needs ad-hoc signing before trust preparation")
	}
	return codeHash(b, signature)
}

func codeHash(executable, signature []byte) (string, error) {
	be := binary.BigEndian
	if len(signature) < 12 || be.Uint32(signature) != 0xfade0cc0 || uint64(be.Uint32(signature[4:])) > uint64(len(signature)) {
		return "", errors.New("invalid signature superblob")
	}
	count := int(be.Uint32(signature[8:]))
	if count > 1024 || 12+count*8 > len(signature) {
		return "", errors.New("invalid signature index")
	}
	for i := 0; i < count; i++ {
		index := signature[12+i*8:]
		if be.Uint32(index) != 0 {
			continue
		}
		off := int(be.Uint32(index[4:]))
		if off > len(signature)-44 {
			return "", errors.New("invalid CodeDirectory offset")
		}
		cd := signature[off:]
		n := int(be.Uint32(cd[4:]))
		if n < 44 || n > len(cd) || be.Uint32(cd) != 0xfade0c02 {
			return "", errors.New("invalid CodeDirectory")
		}
		cd = cd[:n]
		limit := int(be.Uint32(cd[32:]))
		slots := int(be.Uint32(cd[28:]))
		hashOff := int(be.Uint32(cd[16:]))
		hashSize := int(cd[36])
		hashType := cd[37]
		pagePower := cd[39]
		if pagePower > 16 || pagePower < 12 || limit > len(executable) || limit <= 0 {
			return "", errors.New("unsupported signature page geometry")
		}
		page := 1 << pagePower
		if slots != (limit+page-1)/page || slots > payloadLimit/4096 || hashOff < 44 || hashOff > len(cd)-slots*hashSize {
			return "", errors.New("invalid signature hash table")
		}
		if (hashType != 1 || hashSize != 20) && (hashType != 2 || hashSize != 32) {
			return "", errors.New("only SHA-1 and SHA-256 CodeDirectories are supported")
		}
		for slot := 0; slot < slots; slot++ {
			chunk := executable[slot*page : min((slot+1)*page, limit)]
			var hash []byte
			if hashType == 2 {
				h := sha256.Sum256(chunk)
				hash = h[:]
			} else {
				h := sha1.Sum(chunk)
				hash = h[:]
			}
			if !bytes.Equal(hash, cd[hashOff+slot*hashSize:hashOff+(slot+1)*hashSize]) {
				return "", fmt.Errorf("code signature page %d does not match", slot)
			}
		}
		if hashType == 2 {
			h := sha256.Sum256(cd)
			return hex.EncodeToString(h[:20]), nil
		}
		h := sha1.Sum(cd)
		return hex.EncodeToString(h[:]), nil
	}
	return "", errors.New("primary CodeDirectory missing")
}

func alignValue(value, alignment int) int { return (value + alignment - 1) &^ (alignment - 1) }

// adHocSignExecutable adds a deterministic SHA-256 CodeDirectory to an
// unsigned thin executable, dylib, or dynamic linker. The input must reserve
// one 16-byte load command in its normal header padding, as images produced by
// the supported toolchain do.
func adHocSignExecutable(input []byte, identifier string) ([]byte, error) {
	if len(input) < 32 || len(input) > payloadLimit || binary.LittleEndian.Uint32(input) != 0xfeedfacf {
		return nil, errors.New("ad-hoc signing requires a thin little-endian 64-bit Mach-O")
	}
	le, be := binary.LittleEndian, binary.BigEndian
	maximumVersion, err := packedPlatformVersion(canonicalRuntime.IOSVersion)
	if err != nil {
		return nil, err
	}
	fileType := macho.Type(le.Uint32(input[12:]))
	validFileType := fileType == macho.TypeExec || fileType == macho.TypeDylib || fileType == machoTypeDylinker
	if le.Uint32(input[4:]) != uint32(macho.CpuArm64) || !validFileType {
		return nil, errors.New("ad-hoc signing requires an arm64 executable, dylib, or dynamic linker")
	}
	ncmds, commandsSize := int(le.Uint32(input[16:])), int(le.Uint32(input[20:]))
	if ncmds < 1 || ncmds > 4096 || commandsSize < 8 || 32+commandsSize > len(input) {
		return nil, errors.New("invalid Mach-O load command geometry")
	}
	firstData, at, linkedit := len(input), 32, -1
	ios := false
	for i := 0; i < ncmds; i++ {
		if at > 32+commandsSize-8 {
			return nil, errors.New("truncated Mach-O load command")
		}
		command, size := le.Uint32(input[at:]), int(le.Uint32(input[at+4:]))
		if size < 8 || size&7 != 0 || at+size > 32+commandsSize {
			return nil, errors.New("invalid Mach-O load command size")
		}
		switch command {
		case 0x1d:
			return nil, errors.New("executable already contains a code-signature command")
		case 0x32:
			if size >= 24 && le.Uint32(input[at+8:]) == 2 && le.Uint32(input[at+12:]) <= maximumVersion {
				ios = true
			}
		case 0x25:
			if size >= 16 && le.Uint32(input[at+8:]) <= maximumVersion {
				ios = true
			}
		case 0x19:
			if size < 72 {
				return nil, errors.New("short 64-bit segment command")
			}
			if string(bytes.TrimRight(input[at+8:at+24], "\x00")) == "__LINKEDIT" {
				linkedit = at
			}
			nsects := int(le.Uint32(input[at+64:]))
			if 72+nsects*80 > size {
				return nil, errors.New("invalid Mach-O section table")
			}
			for section := 0; section < nsects; section++ {
				offset := int(le.Uint32(input[at+72+section*80+48:]))
				if offset > 0 && offset < firstData {
					firstData = offset
				}
			}
		}
		at += size
	}
	if at != 32+commandsSize || !ios {
		return nil, errors.New("executable does not declare a supported iOS platform")
	}
	commandAt := 32 + commandsSize
	if commandAt+16 > firstData || commandAt+16 > len(input) {
		return nil, errors.New("Mach-O has no header padding for a code-signature command")
	}
	if !bytes.Equal(input[commandAt:commandAt+16], make([]byte, 16)) {
		return nil, errors.New("Mach-O signature-command padding is not empty")
	}
	if identifier == "" || strings.ContainsAny(identifier, "\x00\r\n") {
		return nil, errors.New("invalid signing identifier")
	}
	codeLimit := alignValue(len(input), 16)
	codeSlots := (codeLimit + 4095) / 4096
	hashOffset := alignValue(44+len(identifier)+1, 8)
	codeDirectorySize := hashOffset + codeSlots*sha256.Size
	signatureSize := 20 + codeDirectorySize
	if codeLimit+signatureSize > payloadLimit {
		return nil, errors.New("signed executable exceeds 64 MiB payload limit")
	}
	executable := make([]byte, codeLimit, codeLimit+signatureSize)
	copy(executable, input)
	le.PutUint32(executable[16:], uint32(ncmds+1))
	le.PutUint32(executable[20:], uint32(commandsSize+16))
	le.PutUint32(executable[commandAt:], 0x1d)
	le.PutUint32(executable[commandAt+4:], 16)
	le.PutUint32(executable[commandAt+8:], uint32(codeLimit))
	le.PutUint32(executable[commandAt+12:], uint32(signatureSize))
	if linkedit >= 0 {
		fileOffset := le.Uint64(executable[linkedit+40:])
		oldFileSize := le.Uint64(executable[linkedit+48:])
		oldVMSize := le.Uint64(executable[linkedit+32:])
		if fileOffset >= uint64(len(input)) || oldFileSize > uint64(len(input))-fileOffset {
			return nil, errors.New("invalid __LINKEDIT file range")
		}
		fileSize := uint64(codeLimit+signatureSize) - fileOffset
		vmSize := uint64(alignValue(int(fileSize), 0x4000))
		if vmSize < oldVMSize {
			vmSize = oldVMSize
		}
		le.PutUint64(executable[linkedit+48:], fileSize)
		le.PutUint64(executable[linkedit+32:], vmSize)
	}
	codeDirectory := make([]byte, codeDirectorySize)
	be.PutUint32(codeDirectory, 0xfade0c02)
	be.PutUint32(codeDirectory[4:], uint32(codeDirectorySize))
	be.PutUint32(codeDirectory[8:], 0x20001)
	be.PutUint32(codeDirectory[12:], 2|callerLinkerSignedFlag)
	be.PutUint32(codeDirectory[16:], uint32(hashOffset))
	be.PutUint32(codeDirectory[20:], 44)
	be.PutUint32(codeDirectory[28:], uint32(codeSlots))
	be.PutUint32(codeDirectory[32:], uint32(codeLimit))
	codeDirectory[36], codeDirectory[37], codeDirectory[39] = sha256.Size, 2, 12
	copy(codeDirectory[44:], identifier)
	for slot := 0; slot < codeSlots; slot++ {
		hash := sha256.Sum256(executable[slot*4096 : min((slot+1)*4096, codeLimit)])
		copy(codeDirectory[hashOffset+slot*sha256.Size:], hash[:])
	}
	super := make([]byte, 20, signatureSize)
	be.PutUint32(super, 0xfade0cc0)
	be.PutUint32(super[4:], uint32(signatureSize))
	be.PutUint32(super[8:], 1)
	be.PutUint32(super[16:], 20)
	super = append(super, codeDirectory...)
	return append(executable, super...), nil
}

func loadPayloadAdditions(c *cache) ([]payloadEntry, error) {
	b, err := os.ReadFile(filepath.Join(c.root, "private", "payload.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []payloadEntry
	if err = json.Unmarshal(b, &entries); err != nil {
		return nil, err
	}
	_, err = payloadPlan(nil, entries, payloadLimit)
	return entries, err
}

func writePayloadAdditions(c *cache, entries []payloadEntry) error {
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Join(c.root, "private"), "payload-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(append(b, '\n'))
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(c.root, "private", "payload.json"))
}

func loadOwnedPayloadObjects(c *cache) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(c.root, "private", "payload-owned-objects.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var hashes []string
	if err = json.Unmarshal(b, &hashes); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, hash := range hashes {
		if !digestPattern.MatchString(hash) || seen[hash] {
			return nil, errors.New("invalid owned payload object index")
		}
		seen[hash] = true
	}
	return hashes, nil
}

func writeOwnedPayloadObjects(c *cache, hashes []string) error {
	sort.Strings(hashes)
	b, err := json.MarshalIndent(hashes, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Join(c.root, "private"), "payload-owned-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(append(b, '\n'))
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(c.root, "private", "payload-owned-objects.json"))
}

// gcOwnedPayloadObjects deletes only content objects that this payload importer
// itself created and that no configured destination references. Prepared boot
// objects and pre-existing cache content can never enter this ownership index.
func gcOwnedPayloadObjects(c *cache, entries []payloadEntry, owned []string) error {
	retained := make(map[string]bool, len(entries))
	for _, entry := range entries {
		retained[entry.SHA256] = true
	}
	kept := owned[:0]
	for _, hash := range owned {
		if retained[hash] {
			kept = append(kept, hash)
			continue
		}
		if err := os.Remove(c.object(asset{SHA256: hash})); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale payload object %s: %w", hash, err)
		}
		fmt.Fprintln(c.out, "Removed stale payload object", hash)
	}
	return writeOwnedPayloadObjects(c, kept)
}

type preparedPayload struct {
	Entry        payloadEntry
	Body         []byte
	Dependencies []string
	FileType     macho.Type
	Signed       bool
	LCUUIDAdded  bool
	LinkerSigned bool
}

// enableCallerLinkerSigned marks an existing ad-hoc primary CodeDirectory for
// the runtime's identifier-independent caller admission path. The flags live
// inside the CodeDirectory, so this changes its CDHash but no executable page
// or entitlement bytes. Non-ad-hoc signatures retain native handling and are
// rejected instead of being silently reclassified.
func enableCallerLinkerSigned(input []byte) ([]byte, bool, error) {
	if len(input) < 32 || binary.LittleEndian.Uint32(input) != 0xfeedfacf {
		return nil, false, errors.New("caller admission requires a thin little-endian 64-bit Mach-O")
	}
	le, be := binary.LittleEndian, binary.BigEndian
	ncmds, commandsSize := int(le.Uint32(input[16:])), int(le.Uint32(input[20:]))
	at, signatureOffset, signatureSize := 32, -1, 0
	for index := 0; index < ncmds; index++ {
		if at > 32+commandsSize-8 {
			return nil, false, errors.New("truncated Mach-O load command during caller admission")
		}
		command, size := le.Uint32(input[at:]), int(le.Uint32(input[at+4:]))
		if size < 8 || size&7 != 0 || at+size > 32+commandsSize {
			return nil, false, errors.New("invalid Mach-O load command during caller admission")
		}
		if command == 0x1d {
			if size != 16 || signatureOffset >= 0 {
				return nil, false, errors.New("invalid code-signature command during caller admission")
			}
			signatureOffset, signatureSize = int(le.Uint32(input[at+8:])), int(le.Uint32(input[at+12:]))
		}
		at += size
	}
	if signatureOffset <= 0 || signatureSize < 20 || signatureOffset > len(input)-signatureSize {
		return nil, false, errors.New("caller admission requires an embedded CodeDirectory")
	}
	output := bytes.Clone(input)
	signature := output[signatureOffset : signatureOffset+signatureSize]
	if be.Uint32(signature) != 0xfade0cc0 || int(be.Uint32(signature[4:])) > len(signature) {
		return nil, false, errors.New("invalid signature superblob during caller admission")
	}
	count := int(be.Uint32(signature[8:]))
	if count < 1 || count > 1024 || 12+count*8 > len(signature) {
		return nil, false, errors.New("invalid signature index during caller admission")
	}
	primary := -1
	for index := 0; index < count; index++ {
		entry := signature[12+index*8:]
		if be.Uint32(entry) == 0 {
			primary = int(be.Uint32(entry[4:]))
			break
		}
	}
	if primary < 0 || primary > len(signature)-44 || be.Uint32(signature[primary:]) != 0xfade0c02 {
		return nil, false, errors.New("primary CodeDirectory missing during caller admission")
	}
	flags := be.Uint32(signature[primary+12:])
	if flags&2 == 0 {
		return nil, false, errors.New("caller admission accepts unsigned or existing ad-hoc binaries; this signature is not ad-hoc")
	}
	wanted := flags | callerLinkerSignedFlag
	if wanted == flags {
		return output, false, nil
	}
	be.PutUint32(signature[primary+12:], wanted)
	return output, true, nil
}

// addDeterministicLCUUID fills existing Mach-O header padding without moving
// any segment. dyld requires LC_UUID for ordinary execution on this runtime.
// If an embedded ad-hoc signature already exists, its primary CodeDirectory
// page hashes are recomputed after the header-only edit.
func addDeterministicLCUUID(input []byte) ([]byte, bool, error) {
	if len(input) < 32 || binary.LittleEndian.Uint32(input) != 0xfeedfacf {
		return nil, false, errors.New("LC_UUID normalization requires a thin little-endian 64-bit Mach-O")
	}
	le, be := binary.LittleEndian, binary.BigEndian
	ncmds, commandsSize := int(le.Uint32(input[16:])), int(le.Uint32(input[20:]))
	if ncmds < 1 || ncmds > 4096 || commandsSize < 8 || 32+commandsSize > len(input) {
		return nil, false, errors.New("invalid Mach-O load command geometry")
	}
	firstData, at := len(input), 32
	signatureOffset, signatureSize := -1, 0
	for index := 0; index < ncmds; index++ {
		if at > 32+commandsSize-8 {
			return nil, false, errors.New("truncated Mach-O load command")
		}
		command, size := le.Uint32(input[at:]), int(le.Uint32(input[at+4:]))
		if size < 8 || size&7 != 0 || at+size > 32+commandsSize {
			return nil, false, errors.New("invalid Mach-O load command size")
		}
		if command == 0x1b {
			if size != 24 {
				return nil, false, errors.New("invalid LC_UUID size")
			}
			return bytes.Clone(input), false, nil
		}
		if command == 0x1d {
			if size != 16 || signatureOffset >= 0 {
				return nil, false, errors.New("invalid LC_CODE_SIGNATURE command")
			}
			signatureOffset, signatureSize = int(le.Uint32(input[at+8:])), int(le.Uint32(input[at+12:]))
			if signatureOffset <= 0 || signatureSize <= 0 || signatureOffset > len(input)-signatureSize {
				return nil, false, errors.New("invalid embedded signature bounds")
			}
		}
		if command == 0x19 {
			if size < 72 {
				return nil, false, errors.New("short 64-bit segment command")
			}
			nsects := int(le.Uint32(input[at+64:]))
			if 72+nsects*80 > size {
				return nil, false, errors.New("invalid Mach-O section table")
			}
			for section := 0; section < nsects; section++ {
				offset := int(le.Uint32(input[at+72+section*80+48:]))
				if offset > 0 && offset < firstData {
					firstData = offset
				}
			}
		}
		at += size
	}
	if at != 32+commandsSize {
		return nil, false, errors.New("Mach-O load command size mismatch")
	}
	commandAt := 32 + commandsSize
	if commandAt+24 > firstData || commandAt+24 > len(input) || !bytes.Equal(input[commandAt:commandAt+24], make([]byte, 24)) {
		return nil, false, errors.New("Mach-O needs 24 bytes of zero header padding for automatic LC_UUID")
	}
	output := bytes.Clone(input)
	le.PutUint32(output[16:], uint32(ncmds+1))
	le.PutUint32(output[20:], uint32(commandsSize+24))
	le.PutUint32(output[commandAt:], 0x1b)
	le.PutUint32(output[commandAt+4:], 24)
	uuid := sha256.Sum256(input)
	copy(output[commandAt+8:commandAt+24], uuid[:16])
	// Use the conventional RFC 4122 version/variant bits while retaining a
	// deterministic identity derived from the complete input bytes.
	output[commandAt+14] = output[commandAt+14]&0x0f | 0x40
	output[commandAt+16] = output[commandAt+16]&0x3f | 0x80
	if signatureOffset < 0 {
		return output, true, nil
	}
	signature := output[signatureOffset : signatureOffset+signatureSize]
	if len(signature) < 20 || be.Uint32(signature) != 0xfade0cc0 || int(be.Uint32(signature[4:])) > len(signature) {
		return nil, false, errors.New("invalid signature superblob during LC_UUID normalization")
	}
	count := int(be.Uint32(signature[8:]))
	if count < 1 || count > 1024 || 12+count*8 > len(signature) {
		return nil, false, errors.New("invalid signature index during LC_UUID normalization")
	}
	primary := -1
	for index := 0; index < count; index++ {
		entry := signature[12+index*8:]
		if be.Uint32(entry) == 0 {
			primary = int(be.Uint32(entry[4:]))
			break
		}
	}
	if primary < 0 || primary > len(signature)-44 {
		return nil, false, errors.New("primary CodeDirectory missing during LC_UUID normalization")
	}
	cd := signature[primary:]
	cdSize := int(be.Uint32(cd[4:]))
	if be.Uint32(cd) != 0xfade0c02 || cdSize < 44 || cdSize > len(cd) || be.Uint32(cd[12:])&2 == 0 {
		return nil, false, errors.New("automatic LC_UUID normalization requires an ad-hoc primary CodeDirectory")
	}
	cd = cd[:cdSize]
	limit, slots, hashOffset := int(be.Uint32(cd[32:])), int(be.Uint32(cd[28:])), int(be.Uint32(cd[16:]))
	hashSize, hashType, pagePower := int(cd[36]), cd[37], cd[39]
	if pagePower < 12 || pagePower > 16 || limit <= 0 || limit > len(output) || slots != (limit+(1<<pagePower)-1)/(1<<pagePower) || hashOffset < 44 || hashOffset > len(cd)-slots*hashSize {
		return nil, false, errors.New("unsupported CodeDirectory geometry during LC_UUID normalization")
	}
	if (hashType != 1 || hashSize != sha1.Size) && (hashType != 2 || hashSize != sha256.Size) {
		return nil, false, errors.New("unsupported CodeDirectory hash during LC_UUID normalization")
	}
	page := 1 << pagePower
	for slot := 0; slot < slots; slot++ {
		chunk := output[slot*page : min((slot+1)*page, limit)]
		if hashType == 2 {
			hash := sha256.Sum256(chunk)
			copy(cd[hashOffset+slot*hashSize:], hash[:])
		} else {
			hash := sha1.Sum(chunk)
			copy(cd[hashOffset+slot*hashSize:], hash[:])
		}
	}
	return output, true, nil
}

func preparePayload(source, destination string) (preparedPayload, error) {
	var result preparedPayload
	if !validPayloadDestination(destination) || reservedPayloadDestinations[destination] {
		return result, fmt.Errorf("invalid or reserved payload destination %q", destination)
	}
	b, err := os.ReadFile(source)
	if err != nil {
		return result, err
	}
	b, result.LCUUIDAdded, err = addDeterministicLCUUID(b)
	if err != nil {
		return result, err
	}
	f, err := macho.NewFile(bytes.NewReader(b))
	if err != nil {
		return result, fmt.Errorf("inspect Mach-O: %w", err)
	}
	result.FileType = f.Type
	result.Dependencies, _ = f.ImportedLibraries()
	_ = f.Close()
	cdhash, inspectErr := inspectExecutable(b)
	if inspectErr != nil && strings.Contains(inspectErr.Error(), "needs ad-hoc signing") {
		b, err = adHocSignExecutable(b, filepath.Base(destination))
		if err != nil {
			return result, fmt.Errorf("ad-hoc sign compatible Mach-O: %w", err)
		}
		result.Signed = true
		cdhash, inspectErr = inspectExecutable(b)
	}
	if inspectErr != nil {
		return result, inspectErr
	}
	b, _, err = enableCallerLinkerSigned(b)
	if err != nil {
		return result, err
	}
	cdhash, err = inspectExecutable(b)
	if err != nil {
		return result, err
	}
	result.LinkerSigned = true
	result.Body = b
	result.Entry = payloadEntry{Destination: destination, SHA256: digest(b), Size: int64(len(b)), CDHash: cdhash, Origin: "user addition"}
	return result, nil
}

func storePayloadPlan(ctx context.Context, c *cache, prepared []preparedPayload) (bool, error) {
	return storePayloadPlanScope(ctx, c, prepared, false)
}

// storePayloadRunPlan replaces only additions owned by the high-level run
// command. Deliberate `payload add` entries remain persistent, while one-off
// experiments and their content objects cannot accumulate indefinitely.
func storePayloadRunPlan(ctx context.Context, c *cache, prepared []preparedPayload) (bool, error) {
	for index := range prepared {
		prepared[index].Entry.Origin = "payload run"
	}
	return storePayloadPlanScope(ctx, c, prepared, true)
}

func storePayloadPlanScope(ctx context.Context, c *cache, prepared []preparedPayload, replaceRun bool) (bool, error) {
	base, err := basePayload()
	if err != nil {
		return false, err
	}
	additions, err := loadPayloadAdditions(c)
	if err != nil {
		return false, err
	}
	before, err := json.Marshal(additions)
	if err != nil {
		return false, err
	}
	if replaceRun {
		kept := additions[:0]
		for _, entry := range additions {
			if entry.Origin != "payload run" {
				kept = append(kept, entry)
			}
		}
		additions = kept
	}
	for _, candidate := range prepared {
		for i := range additions {
			if additions[i].Destination == candidate.Entry.Destination {
				additions = append(additions[:i], additions[i+1:]...)
				break
			}
		}
		additions = append(additions, candidate.Entry)
	}
	sort.Slice(additions, func(i, j int) bool { return additions[i].Destination < additions[j].Destination })
	if _, err = payloadPlan(base, additions, payloadLimit); err != nil {
		return false, err
	}
	owned, err := loadOwnedPayloadObjects(c)
	if err != nil {
		return false, err
	}
	ownedSet := make(map[string]bool, len(owned))
	for _, hash := range owned {
		ownedSet[hash] = true
	}
	for _, candidate := range prepared {
		a := asset{Role: "payload", SHA256: candidate.Entry.SHA256, Size: candidate.Entry.Size, Recipe: "Imported user Mach-O", Compatibility: "iOS " + canonicalRuntime.IOSVersion + " arm64/arm64e"}
		_, statErr := os.Stat(c.object(a))
		if _, err = c.store(ctx, a, bytes.NewReader(candidate.Body)); err != nil {
			return false, err
		}
		if errors.Is(statErr, os.ErrNotExist) && !ownedSet[a.SHA256] {
			owned = append(owned, a.SHA256)
			ownedSet[a.SHA256] = true
		}
	}
	after, err := json.Marshal(additions)
	if err != nil {
		return false, err
	}
	changed := !bytes.Equal(before, after)
	if changed {
		if err = writePayloadAdditions(c, additions); err != nil {
			return false, err
		}
	}
	if err = gcOwnedPayloadObjects(c, additions, owned); err != nil {
		return false, err
	}
	return changed, nil
}

func addPayload(ctx context.Context, c *cache, args []string) error {
	if len(args) != 1 && len(args) != 3 {
		return errors.New("usage: payload add FILE [--dest /usr/local/bin/NAME]")
	}
	source := args[0]
	destination := "/usr/local/bin/" + filepath.Base(source)
	if len(args) == 3 {
		if args[1] != "--dest" {
			return errors.New("usage: payload add FILE [--dest /usr/local/bin/NAME]")
		}
		destination = args[2]
	}
	prepared, err := preparePayload(source, destination)
	if err != nil {
		return err
	}
	changed, err := storePayloadPlan(ctx, c, []preparedPayload{prepared})
	if err != nil {
		return err
	}
	action := "Already configured"
	if changed {
		action = "Added"
	}
	fmt.Fprintf(c.out, "%s %s (%d bytes, cdhash %s); the next matching boot will admit and install it.\n", action, destination, prepared.Entry.Size, prepared.Entry.CDHash)
	return nil
}

func removePayload(c *cache, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: payload remove /usr/local/bin/NAME")
	}
	destination := args[0]
	additions, err := loadPayloadAdditions(c)
	if err != nil {
		return err
	}
	found := false
	for index := range additions {
		if additions[index].Destination != destination {
			continue
		}
		additions = append(additions[:index], additions[index+1:]...)
		found = true
		break
	}
	if !found {
		return fmt.Errorf("payload addition is absent: %s", destination)
	}
	if err = writePayloadAdditions(c, additions); err != nil {
		return err
	}
	owned, err := loadOwnedPayloadObjects(c)
	if err != nil {
		return err
	}
	if err = gcOwnedPayloadObjects(c, additions, owned); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Removed %s; the next boot will omit it.\n", destination)
	return nil
}

func listPayload(c *cache, out io.Writer) error {
	entries, err := basePayload()
	if err != nil {
		return err
	}
	for _, e := range entries {
		fmt.Fprintf(out, "base  %-46s %8d bytes  %s\n", e.Destination, e.Size, e.Origin)
	}
	additions, err := loadPayloadAdditions(c)
	if err != nil {
		return err
	}
	for _, e := range additions {
		fmt.Fprintf(out, "added %-46s %8d bytes  %s\n", e.Destination, e.Size, e.SHA256)
	}
	return nil
}
