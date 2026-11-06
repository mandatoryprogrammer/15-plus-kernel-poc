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
	"encoding/xml"
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
	payloadLimit                     = 64 << 20
	machoTypeDylinker                = macho.Type(7)
	codeDirectoryVersionExecSeg      = 0x20400
	codeDirectoryExecSegBytes        = 88
	codeDirectoryPagePower           = 14
	codeDirectoryPageBytes           = 1 << codeDirectoryPagePower
	codeDirectoryAdHocFlag           = 2
	codeDirectoryMainBinaryFlag      = 1
	codeSignatureRequirementsSlot    = 2
	codeSignatureEntitlementsSlot    = 5
	codeSignatureDEREntitlementsSlot = 7
	codeSignatureCMSSlot             = 0x10000
	codeSignatureMinimumBytes        = 0x4800
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

// executableSegmentContract derives the CodeDirectory executable-segment
// fields from the file-backed executable segments. Modern arm64 iOS code
// signatures carry this geometry even when the executable has no special
// entitlements.
func executableSegmentContract(input []byte) (uint64, uint64, uint64, error) {
	if len(input) < 32 || binary.LittleEndian.Uint32(input) != 0xfeedfacf {
		return 0, 0, 0, errors.New("executable-segment inspection requires a thin little-endian 64-bit Mach-O")
	}
	le := binary.LittleEndian
	ncmds, commandsSize := int(le.Uint32(input[16:])), int(le.Uint32(input[20:]))
	if ncmds < 1 || ncmds > 4096 || commandsSize < 8 || 32+commandsSize > len(input) {
		return 0, 0, 0, errors.New("invalid Mach-O load command geometry during executable-segment inspection")
	}
	at := 32
	var first, last uint64
	found := false
	for index := 0; index < ncmds; index++ {
		if at > 32+commandsSize-8 {
			return 0, 0, 0, errors.New("truncated Mach-O load command during executable-segment inspection")
		}
		command, size := le.Uint32(input[at:]), int(le.Uint32(input[at+4:]))
		if size < 8 || size&7 != 0 || at+size > 32+commandsSize {
			return 0, 0, 0, errors.New("invalid Mach-O load command during executable-segment inspection")
		}
		if command == 0x19 {
			if size < 72 {
				return 0, 0, 0, errors.New("short 64-bit segment command during executable-segment inspection")
			}
			fileOffset, fileSize := le.Uint64(input[at+40:]), le.Uint64(input[at+48:])
			end := fileOffset + fileSize
			if end < fileOffset || end > uint64(len(input)) {
				return 0, 0, 0, errors.New("invalid file-backed segment during executable-segment inspection")
			}
			if le.Uint32(input[at+60:])&4 != 0 && fileSize != 0 {
				if !found || fileOffset < first {
					first = fileOffset
				}
				if !found || end > last {
					last = end
				}
				found = true
			}
		}
		at += size
	}
	if at != 32+commandsSize || !found || last <= first {
		return 0, 0, 0, errors.New("Mach-O has no bounded file-backed executable segment")
	}
	flags := uint64(0)
	if macho.Type(le.Uint32(input[12:])) == macho.TypeExec {
		flags = codeDirectoryMainBinaryFlag
	}
	return first, last - first, flags, nil
}

type embeddedPayloadAuthority struct {
	XML, XMLBlob, DERBlob []byte
	Keys                  []string
	Values                map[string]bool
}

func nextEntitlementXMLToken(decoder *xml.Decoder) (xml.Token, error) {
	for {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch value := token.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(value)) == "" {
				continue
			}
		case xml.ProcInst, xml.Directive, xml.Comment:
			continue
		}
		return token, nil
	}
}

func entitlementXMLStart(token xml.Token, name string) (xml.StartElement, error) {
	start, ok := token.(xml.StartElement)
	if !ok || start.Name.Space != "" || start.Name.Local != name {
		return xml.StartElement{}, fmt.Errorf("source entitlements expected <%s>, got %T %#v", name, token, token)
	}
	return start, nil
}

func decodeEntitlementKey(decoder *xml.Decoder, start xml.StartElement) (string, error) {
	var body strings.Builder
	for {
		token, err := decoder.Token()
		if err != nil {
			return "", err
		}
		switch value := token.(type) {
		case xml.CharData:
			body.Write(value)
		case xml.EndElement:
			if value.Name == start.Name {
				key := body.String()
				if key == "" || key != strings.TrimSpace(key) {
					return "", errors.New("source entitlement key is empty or padded")
				}
				return key, nil
			}
			return "", errors.New("source entitlement key has a mismatched close tag")
		default:
			return "", errors.New("source entitlement key must contain only text")
		}
	}
}

func decodeEntitlementBoolean(decoder *xml.Decoder, start xml.StartElement) (bool, error) {
	if start.Name.Local != "true" && start.Name.Local != "false" || start.Name.Space != "" || len(start.Attr) != 0 {
		return false, errors.New("source entitlement value must be an attribute-free Boolean")
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return false, err
		}
		switch value := token.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(value)) != "" {
				return false, errors.New("source entitlement Boolean contains text")
			}
		case xml.EndElement:
			if value.Name != start.Name {
				return false, errors.New("source entitlement Boolean has a mismatched close tag")
			}
			return start.Name.Local == "true", nil
		default:
			return false, errors.New("source entitlement Boolean contains a nested value")
		}
	}
}

func parseBooleanEntitlementPlist(value []byte) (map[string]bool, []string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(value))
	token, err := nextEntitlementXMLToken(decoder)
	if err != nil {
		return nil, nil, err
	}
	if _, err = entitlementXMLStart(token, "plist"); err != nil {
		return nil, nil, err
	}
	token, err = nextEntitlementXMLToken(decoder)
	if err != nil {
		return nil, nil, err
	}
	if _, err = entitlementXMLStart(token, "dict"); err != nil {
		return nil, nil, err
	}
	values := make(map[string]bool)
	for {
		token, err = nextEntitlementXMLToken(decoder)
		if err != nil {
			return nil, nil, err
		}
		if end, ok := token.(xml.EndElement); ok {
			if end.Name.Space != "" || end.Name.Local != "dict" {
				return nil, nil, errors.New("source entitlement dictionary has a mismatched close tag")
			}
			break
		}
		keyStart, startErr := entitlementXMLStart(token, "key")
		if startErr != nil || len(keyStart.Attr) != 0 {
			return nil, nil, errors.Join(startErr, errors.New("source entitlement dictionary requires attribute-free key/value pairs"))
		}
		key, keyErr := decodeEntitlementKey(decoder, keyStart)
		if keyErr != nil {
			return nil, nil, keyErr
		}
		if _, duplicate := values[key]; duplicate {
			return nil, nil, fmt.Errorf("source entitlement key %q is duplicated", key)
		}
		token, err = nextEntitlementXMLToken(decoder)
		if err != nil {
			return nil, nil, err
		}
		booleanStart, ok := token.(xml.StartElement)
		if !ok {
			return nil, nil, fmt.Errorf("source entitlement %q lacks a Boolean value", key)
		}
		boolean, booleanErr := decodeEntitlementBoolean(decoder, booleanStart)
		if booleanErr != nil {
			return nil, nil, fmt.Errorf("source entitlement %q: %w", key, booleanErr)
		}
		values[key] = boolean
	}
	token, err = nextEntitlementXMLToken(decoder)
	if err != nil {
		return nil, nil, err
	}
	end, ok := token.(xml.EndElement)
	if !ok || end.Name.Space != "" || end.Name.Local != "plist" {
		return nil, nil, errors.New("source entitlement plist has a mismatched close tag")
	}
	if token, err = nextEntitlementXMLToken(decoder); !errors.Is(err, io.EOF) || token != nil {
		return nil, nil, errors.New("source entitlement plist has trailing content")
	}
	if len(values) == 0 {
		return nil, nil, errors.New("source entitlement dictionary is empty")
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return values, keys, nil
}

func entitlementDERTLV(tag byte, payload []byte) ([]byte, error) {
	var length []byte
	switch {
	case len(payload) < 0x80:
		length = []byte{byte(len(payload))}
	case len(payload) <= 0xff:
		length = []byte{0x81, byte(len(payload))}
	case len(payload) <= 0xffff:
		length = []byte{0x82, byte(len(payload) >> 8), byte(len(payload))}
	default:
		return nil, errors.New("source entitlement DER payload is too large")
	}
	result := make([]byte, 1+len(length)+len(payload))
	result[0] = tag
	copy(result[1:], length)
	copy(result[1+len(length):], payload)
	return result, nil
}

func entitlementBlob(magic uint32, payload []byte) []byte {
	result := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(result, magic)
	binary.BigEndian.PutUint32(result[4:], uint32(len(result)))
	copy(result[8:], payload)
	return result
}

func booleanEntitlementsDER(values map[string]bool, keys []string) ([]byte, error) {
	var dictionary []byte
	for _, key := range keys {
		keyTLV, err := entitlementDERTLV(0x0c, []byte(key))
		if err != nil {
			return nil, err
		}
		boolean := byte(0)
		if values[key] {
			boolean = 0xff
		}
		booleanTLV, err := entitlementDERTLV(0x01, []byte{boolean})
		if err != nil {
			return nil, err
		}
		pair, err := entitlementDERTLV(0x30, append(keyTLV, booleanTLV...))
		if err != nil {
			return nil, err
		}
		dictionary = append(dictionary, pair...)
	}
	dictionaryTLV, err := entitlementDERTLV(0xb0, dictionary)
	if err != nil {
		return nil, err
	}
	version, err := entitlementDERTLV(0x02, []byte{1})
	if err != nil {
		return nil, err
	}
	root, err := entitlementDERTLV(0x70, append(version, dictionaryTLV...))
	if err != nil {
		return nil, err
	}
	return entitlementBlob(0xfade7172, root), nil
}

func extractEmbeddedPayloadAuthority(input []byte) (*embeddedPayloadAuthority, error) {
	file, err := macho.NewFile(bytes.NewReader(input))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var source []byte
	for _, section := range file.Sections {
		if section.Name != "__entitlements" {
			continue
		}
		if section.Seg != "__TEXT" || source != nil {
			return nil, errors.New("source entitlements section is misplaced or duplicated")
		}
		source, err = section.Data()
		if err != nil {
			return nil, err
		}
	}
	if source == nil {
		return nil, nil
	}
	source = bytes.TrimRight(source, "\x00")
	values, keys, err := parseBooleanEntitlementPlist(source)
	if err != nil {
		return nil, fmt.Errorf("decode source entitlements: %w", err)
	}
	der, err := booleanEntitlementsDER(values, keys)
	if err != nil {
		return nil, err
	}
	return &embeddedPayloadAuthority{
		XML: source, XMLBlob: entitlementBlob(0xfade7171, source), DERBlob: der,
		Keys: keys, Values: values,
	}, nil
}

func validateSignedPayloadAuthority(input []byte, authority *embeddedPayloadAuthority) error {
	if authority == nil {
		return nil
	}
	le, be := binary.LittleEndian, binary.BigEndian
	if len(input) < 32 || le.Uint32(input) != 0xfeedfacf {
		return errors.New("signed entitlement validation requires a thin little-endian 64-bit Mach-O")
	}
	at, signatureOffset, signatureSize := 32, -1, 0
	for index := 0; index < int(le.Uint32(input[16:])); index++ {
		if at > len(input)-8 {
			return errors.New("signed entitlement validation found a truncated load command")
		}
		size := int(le.Uint32(input[at+4:]))
		if size < 8 || at > len(input)-size {
			return errors.New("signed entitlement validation found an invalid load command")
		}
		if le.Uint32(input[at:]) == 0x1d {
			if signatureOffset >= 0 || size != 16 {
				return errors.New("signed entitlement validation found duplicate signature commands")
			}
			signatureOffset, signatureSize = int(le.Uint32(input[at+8:])), int(le.Uint32(input[at+12:]))
		}
		at += size
	}
	if signatureOffset <= 0 || signatureSize < 12 || signatureOffset > len(input)-signatureSize {
		return errors.New("signed entitlement validation found no bounded signature")
	}
	signature := input[signatureOffset : signatureOffset+signatureSize]
	if be.Uint32(signature) != 0xfade0cc0 || int(be.Uint32(signature[4:])) > len(signature) {
		return errors.New("signed entitlement validation found an invalid SuperBlob")
	}
	count := int(be.Uint32(signature[8:]))
	if count < 1 || count > 1024 || 12+count*8 > len(signature) {
		return errors.New("signed entitlement validation found an invalid index")
	}
	blobs := make(map[uint32][]byte)
	for index := 0; index < count; index++ {
		row := signature[12+index*8:]
		typeID, offset := be.Uint32(row), int(be.Uint32(row[4:]))
		if offset < 12+count*8 || offset > len(signature)-8 {
			return errors.New("signed entitlement validation found an invalid blob offset")
		}
		length := int(be.Uint32(signature[offset+4:]))
		if length < 8 || offset > len(signature)-length {
			return errors.New("signed entitlement validation found an invalid blob length")
		}
		if _, duplicate := blobs[typeID]; duplicate {
			return fmt.Errorf("signed entitlement validation found duplicate slot %d", typeID)
		}
		blobs[typeID] = signature[offset : offset+length]
	}
	if !bytes.Equal(blobs[codeSignatureEntitlementsSlot], authority.XMLBlob) ||
		!bytes.Equal(blobs[codeSignatureDEREntitlementsSlot], authority.DERBlob) {
		return errors.New("signed XML/DER entitlements differ from the source declaration")
	}
	directory := blobs[0]
	if len(directory) < codeDirectoryExecSegBytes || be.Uint32(directory) != 0xfade0c02 ||
		be.Uint32(directory[24:]) < codeSignatureDEREntitlementsSlot || directory[36] != sha256.Size || directory[37] != 2 {
		return errors.New("signed entitlement CodeDirectory lacks the required special slots")
	}
	hashOffset := int(be.Uint32(directory[16:]))
	if hashOffset < codeSignatureDEREntitlementsSlot*sha256.Size || hashOffset > len(directory) {
		return errors.New("signed entitlement CodeDirectory hash geometry is invalid")
	}
	for slot, blob := range map[int][]byte{
		codeSignatureEntitlementsSlot:    authority.XMLBlob,
		codeSignatureDEREntitlementsSlot: authority.DERBlob,
	} {
		hash := sha256.Sum256(blob)
		start := hashOffset - slot*sha256.Size
		if !bytes.Equal(directory[start:start+sha256.Size], hash[:]) {
			return fmt.Errorf("signed entitlement special slot %d is not content-bound", slot)
		}
	}
	return nil
}

// adHocSignExecutable adds a deterministic SHA-256 CodeDirectory to an
// unsigned thin executable, dylib, or dynamic linker. The input must reserve
// one 16-byte load command in its normal header padding, as images produced by
// the supported toolchain do.
func adHocSignExecutable(input []byte, identifier string) ([]byte, error) {
	return adHocSignExecutableWithAuthority(input, identifier, nil)
}

func adHocSignExecutableWithAuthority(input []byte, identifier string, authority *embeddedPayloadAuthority) ([]byte, error) {
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
	if linkedit < 0 {
		return nil, errors.New("Mach-O has no __LINKEDIT segment for an embedded signature")
	}
	commandAt := 32 + commandsSize
	if commandAt+16 > firstData || commandAt+16 > len(input) {
		return nil, errors.New("Mach-O has no header padding for a code-signature command")
	}
	if !bytes.Equal(input[commandAt:commandAt+16], make([]byte, 16)) {
		return nil, errors.New("Mach-O signature-command padding is not empty")
	}
	if identifier == "" || len(identifier) > 255 || strings.ContainsAny(identifier, "\x00\r\n") {
		return nil, errors.New("invalid signing identifier")
	}
	execBase, execLimit, execFlags, err := executableSegmentContract(input)
	if err != nil {
		return nil, err
	}
	codeLimit := alignValue(len(input), 16)
	codeSlots := (codeLimit + codeDirectoryPageBytes - 1) / codeDirectoryPageBytes
	specialSlots := codeSignatureRequirementsSlot
	if authority != nil {
		specialSlots = codeSignatureDEREntitlementsSlot
	}
	hashOffset := codeDirectoryExecSegBytes + len(identifier) + 1 + specialSlots*sha256.Size
	codeDirectorySize := hashOffset + codeSlots*sha256.Size
	requirements := make([]byte, 12)
	be.PutUint32(requirements, 0xfade0c01)
	be.PutUint32(requirements[4:], uint32(len(requirements)))
	// The requirement-set count remains zero for an ad-hoc signature.
	emptyCMS := make([]byte, 8)
	be.PutUint32(emptyCMS, 0xfade0b01)
	be.PutUint32(emptyCMS[4:], uint32(len(emptyCMS)))
	componentCount := 3
	authorityBytes := 0
	if authority != nil {
		componentCount = 5
		authorityBytes = len(authority.XMLBlob) + len(authority.DERBlob)
	}
	superBlobSize := 12 + componentCount*8 + codeDirectorySize + len(requirements) + authorityBytes + len(emptyCMS)
	signatureSize := max(codeSignatureMinimumBytes, alignValue(superBlobSize, 16))
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
	fileOffset := le.Uint64(executable[linkedit+40:])
	oldFileSize := le.Uint64(executable[linkedit+48:])
	oldVMSize := le.Uint64(executable[linkedit+32:])
	if fileOffset >= uint64(len(input)) || oldFileSize > uint64(len(input))-fileOffset || fileOffset+oldFileSize != uint64(len(input)) {
		return nil, errors.New("__LINKEDIT does not end at the unsigned input boundary")
	}
	fileSize := uint64(codeLimit+signatureSize) - fileOffset
	vmSize := uint64(alignValue(int(fileSize), codeDirectoryPageBytes))
	if vmSize < oldVMSize {
		vmSize = oldVMSize
	}
	le.PutUint64(executable[linkedit+48:], fileSize)
	le.PutUint64(executable[linkedit+32:], vmSize)
	codeDirectory := make([]byte, codeDirectorySize)
	be.PutUint32(codeDirectory, 0xfade0c02)
	be.PutUint32(codeDirectory[4:], uint32(codeDirectorySize))
	be.PutUint32(codeDirectory[8:], codeDirectoryVersionExecSeg)
	be.PutUint32(codeDirectory[12:], codeDirectoryAdHocFlag|callerLinkerSignedFlag)
	be.PutUint32(codeDirectory[16:], uint32(hashOffset))
	be.PutUint32(codeDirectory[20:], codeDirectoryExecSegBytes)
	be.PutUint32(codeDirectory[24:], uint32(specialSlots))
	be.PutUint32(codeDirectory[28:], uint32(codeSlots))
	be.PutUint32(codeDirectory[32:], uint32(codeLimit))
	codeDirectory[36], codeDirectory[37], codeDirectory[39] = sha256.Size, 2, codeDirectoryPagePower
	be.PutUint64(codeDirectory[64:], execBase)
	be.PutUint64(codeDirectory[72:], execLimit)
	be.PutUint64(codeDirectory[80:], execFlags)
	copy(codeDirectory[codeDirectoryExecSegBytes:], identifier)
	requirementsHash := sha256.Sum256(requirements)
	copy(codeDirectory[hashOffset-codeSignatureRequirementsSlot*sha256.Size:], requirementsHash[:])
	if authority != nil {
		xmlHash := sha256.Sum256(authority.XMLBlob)
		derHash := sha256.Sum256(authority.DERBlob)
		copy(codeDirectory[hashOffset-codeSignatureEntitlementsSlot*sha256.Size:], xmlHash[:])
		copy(codeDirectory[hashOffset-codeSignatureDEREntitlementsSlot*sha256.Size:], derHash[:])
	}
	for slot := 0; slot < codeSlots; slot++ {
		hash := sha256.Sum256(executable[slot*codeDirectoryPageBytes : min((slot+1)*codeDirectoryPageBytes, codeLimit)])
		copy(codeDirectory[hashOffset+slot*sha256.Size:], hash[:])
	}
	super := make([]byte, signatureSize)
	be.PutUint32(super, 0xfade0cc0)
	be.PutUint32(super[4:], uint32(superBlobSize))
	be.PutUint32(super[8:], uint32(componentCount))
	type signatureComponent struct {
		typeID uint32
		body   []byte
	}
	components := []signatureComponent{{0, codeDirectory}, {codeSignatureRequirementsSlot, requirements}}
	if authority != nil {
		components = append(components,
			signatureComponent{codeSignatureEntitlementsSlot, authority.XMLBlob},
			signatureComponent{codeSignatureDEREntitlementsSlot, authority.DERBlob})
	}
	components = append(components, signatureComponent{codeSignatureCMSSlot, emptyCMS})
	offset := 12 + componentCount*8
	for index, component := range components {
		row := 12 + index*8
		be.PutUint32(super[row:], component.typeID)
		be.PutUint32(super[row+4:], uint32(offset))
		copy(super[offset:], component.body)
		offset += len(component.body)
	}
	if offset != superBlobSize {
		return nil, errors.New("deterministic signature component geometry is inconsistent")
	}
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
	Entry                  payloadEntry
	Body                   []byte
	Dependencies           []string
	EntitlementKeys        []string
	XMLEntitlementsSHA256  string
	DEREntitlementsSHA256  string
	DEREntitlementsPresent bool
	FileType               macho.Type
	Signed                 bool
	LCUUIDAdded            bool
	LinkerSigned           bool
}

func validateRuntimeCallerCodeDirectory(input, codeDirectory []byte) error {
	if len(codeDirectory) < codeDirectoryExecSegBytes || binary.BigEndian.Uint32(codeDirectory) != 0xfade0c02 {
		return errors.New("caller CodeDirectory is truncated")
	}
	be := binary.BigEndian
	if be.Uint32(codeDirectory[8:]) < codeDirectoryVersionExecSeg {
		return errors.New("caller CodeDirectory predates executable-segment metadata")
	}
	pagePower := codeDirectory[39]
	if codeDirectory[36] != sha256.Size || codeDirectory[37] != 2 || pagePower != 12 && pagePower != codeDirectoryPagePower {
		return errors.New("caller CodeDirectory must use SHA-256 with 4 KiB or 16 KiB code slots")
	}
	codeLimit := uint64(be.Uint32(codeDirectory[32:]))
	codeSlots := uint64(be.Uint32(codeDirectory[28:]))
	pageBytes := uint64(1) << pagePower
	if codeLimit == 0 || codeLimit > uint64(len(input)) || codeSlots != (codeLimit+pageBytes-1)/pageBytes {
		return errors.New("caller CodeDirectory has incompatible code-slot geometry")
	}
	hashOffset := uint64(be.Uint32(codeDirectory[16:]))
	if hashOffset < codeDirectoryExecSegBytes || hashOffset > uint64(len(codeDirectory)) || codeSlots > (uint64(len(codeDirectory))-hashOffset)/sha256.Size {
		return errors.New("caller CodeDirectory hash table is out of bounds")
	}
	execBase, execLimit, execFlags, err := executableSegmentContract(input)
	if err != nil {
		return err
	}
	if be.Uint64(codeDirectory[64:]) != execBase || be.Uint64(codeDirectory[72:]) != execLimit || be.Uint64(codeDirectory[80:])&codeDirectoryMainBinaryFlag != execFlags {
		return errors.New("caller CodeDirectory executable-segment metadata differs from the Mach-O")
	}
	return nil
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
	codeDirectorySize := int(be.Uint32(signature[primary+4:]))
	if codeDirectorySize < codeDirectoryExecSegBytes || primary > len(signature)-codeDirectorySize {
		return nil, false, errors.New("primary CodeDirectory is truncated during caller admission")
	}
	codeDirectory := signature[primary : primary+codeDirectorySize]
	if err := validateRuntimeCallerCodeDirectory(input, codeDirectory); err != nil {
		return nil, false, fmt.Errorf("caller admission rejects a runtime-incompatible signature: %w", err)
	}
	flags := be.Uint32(codeDirectory[12:])
	if flags&codeDirectoryAdHocFlag == 0 {
		return nil, false, errors.New("caller admission accepts unsigned or existing ad-hoc binaries; this signature is not ad-hoc")
	}
	wanted := flags | callerLinkerSignedFlag
	if wanted == flags {
		return output, false, nil
	}
	be.PutUint32(codeDirectory[12:], wanted)
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
	authority, err := extractEmbeddedPayloadAuthority(b)
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
		b, err = adHocSignExecutableWithAuthority(b, filepath.Base(destination), authority)
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
	if err = validateSignedPayloadAuthority(b, authority); err != nil {
		return result, err
	}
	if authority != nil {
		result.EntitlementKeys = append([]string(nil), authority.Keys...)
		result.XMLEntitlementsSHA256 = digest(authority.XMLBlob)
		result.DEREntitlementsSHA256 = digest(authority.DERBlob)
		result.DEREntitlementsPresent = true
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
