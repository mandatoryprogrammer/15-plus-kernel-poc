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

const payloadLimit = 64 << 20

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
		if !strings.HasPrefix(a.Destination, "/usr/local/bin/") || path.Clean(a.Destination) != a.Destination || path.Dir(a.Destination) != "/usr/local/bin" || strings.ContainsAny(a.Destination, "\x00\r\n") {
			return nil, fmt.Errorf("invalid payload destination %q: use /usr/local/bin/NAME", a.Destination)
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

// inspectExecutable accepts thin iOS arm64/arm64e executables and verifies every
// signed code page. macOS, simulator, Intel, malformed, and encrypted inputs fail.
func inspectExecutable(b []byte) (string, error) {
	if len(b) > payloadLimit {
		return "", errors.New("binary exceeds 64 MiB payload limit")
	}
	f, err := macho.NewFile(bytes.NewReader(b))
	if err != nil {
		return "", fmt.Errorf("expected a thin iOS Mach-O executable: %w", err)
	}
	defer f.Close()
	maximumVersion, err := packedPlatformVersion(canonicalRuntime.IOSVersion)
	if err != nil {
		return "", err
	}
	if f.Cpu != macho.CpuArm64 || f.Type != macho.TypeExec || (f.SubCpu&0xffffff) != 0 && (f.SubCpu&0xffffff) != 2 {
		return "", errors.New("binary must be a thin arm64 or arm64e executable")
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
		return "", errors.New("executable needs ad-hoc signing before trust preparation")
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
// unsigned thin Mach-O. The input must reserve one 16-byte load command in its
// normal header padding, as executables produced by the supported toolchain do.
func adHocSignExecutable(input []byte, identifier string) ([]byte, error) {
	if len(input) < 32 || len(input) > payloadLimit || binary.LittleEndian.Uint32(input) != 0xfeedfacf {
		return nil, errors.New("ad-hoc signing requires a thin little-endian 64-bit Mach-O")
	}
	le, be := binary.LittleEndian, binary.BigEndian
	maximumVersion, err := packedPlatformVersion(canonicalRuntime.IOSVersion)
	if err != nil {
		return nil, err
	}
	if le.Uint32(input[4:]) != uint32(macho.CpuArm64) || le.Uint32(input[12:]) != uint32(macho.TypeExec) {
		return nil, errors.New("ad-hoc signing requires an arm64 executable")
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
	be.PutUint32(codeDirectory[12:], 2)
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
	b, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	cdhash, inspectErr := inspectExecutable(b)
	if inspectErr != nil && strings.Contains(inspectErr.Error(), "needs ad-hoc signing") {
		b, err = adHocSignExecutable(b, filepath.Base(destination))
		if err != nil {
			return fmt.Errorf("ad-hoc sign compatible executable: %w", err)
		}
		cdhash, inspectErr = inspectExecutable(b)
	}
	if inspectErr != nil {
		return inspectErr
	}
	entry := payloadEntry{Destination: destination, SHA256: digest(b), Size: int64(len(b)), CDHash: cdhash, Origin: "user addition"}
	base, err := basePayload()
	if err != nil {
		return err
	}
	additions, err := loadPayloadAdditions(c)
	if err != nil {
		return err
	}
	for i := range additions {
		if additions[i].Destination == destination {
			additions = append(additions[:i], additions[i+1:]...)
			break
		}
	}
	additions = append(additions, entry)
	sort.Slice(additions, func(i, j int) bool { return additions[i].Destination < additions[j].Destination })
	if _, err = payloadPlan(base, additions, payloadLimit); err != nil {
		return err
	}
	a := asset{Role: "payload", SHA256: entry.SHA256, Size: entry.Size, Recipe: "Imported user executable", Compatibility: "iOS " + canonicalRuntime.IOSVersion + " arm64/arm64e"}
	if _, err = c.store(ctx, a, bytes.NewReader(b)); err != nil {
		return err
	}
	if err = writePayloadAdditions(c, additions); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Added %s (%d bytes, cdhash %s); the next boot will admit and install it.\n", destination, entry.Size, entry.CDHash)
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
