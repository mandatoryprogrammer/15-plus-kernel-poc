package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maximumOfflineLoaderBytes = 64 << 20

type ibootPatchRecord struct {
	Index       int    `json:"index"`
	Kind        string `json:"kind"`
	FileOffset  uint64 `json:"file_offset"`
	ImageOffset uint64 `json:"image_offset"`
	Address     uint64 `json:"address"`
	Before      string `json:"before"`
	After       string `json:"after"`
}

type ibootPatchReport struct {
	SchemaVersion   int                `json:"schema_version"`
	Operation       string             `json:"operation"`
	Input           string             `json:"input"`
	InputBytes      int                `json:"input_bytes"`
	InputSHA256     string             `json:"input_sha256"`
	Metadata        string             `json:"metadata,omitempty"`
	Build           string             `json:"build"`
	Analyzer        string             `json:"analyzer"`
	Base            uint64             `json:"base"`
	ImageOffset     uint64             `json:"image_offset"`
	GuardCount      int                `json:"guard_count"`
	PatchCount      int                `json:"patch_count"`
	ChangedBytes    int                `json:"changed_bytes,omitempty"`
	Patches         []ibootPatchRecord `json:"patches"`
	Output          string             `json:"output,omitempty"`
	OutputBytes     int                `json:"output_bytes,omitempty"`
	OutputSHA256    string             `json:"output_sha256,omitempty"`
	Exact           bool               `json:"exact"`
	SourceUnchanged bool               `json:"source_unchanged"`
}

type ibootSnapshotMetadata struct {
	path   string
	build  string
	base   uint64
	offset uint64
	size   int
	sha256 string
}

type ibootOptions struct {
	base, offset, build, metadata string
	out, report                   string
	json, force                   bool
}

func ibootUsage(out io.Writer) {
	fmt.Fprintln(out, "usage:")
	fmt.Fprintln(out, "  15-plus-kernel-poc iboot analyze [OPTIONS] SNAPSHOT")
	fmt.Fprintln(out, "  15-plus-kernel-poc iboot patch [OPTIONS] SNAPSHOT")
	fmt.Fprintln(out, "  15-plus-kernel-poc iboot verify [OPTIONS] ORIGINAL PATCHED")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "SNAPSHOT is a decoded, raw iBoot executable or live-memory capture.")
	fmt.Fprintln(out, "Adjacent SNAPSHOT.txt metadata supplies build/base/offset automatically.")
	fmt.Fprintln(out, "Options: --base auto|ADDRESS --offset auto|BYTES --build auto|NAME")
	fmt.Fprintln(out, "         --metadata auto|none|FILE --out FILE --report FILE --json --force")
}

func ibootCommand(args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		ibootUsage(errOut)
		return errors.New("iboot operation is required")
	}
	operation := args[0]
	if operation == "help" || operation == "-h" || operation == "--help" {
		ibootUsage(out)
		return nil
	}
	if operation != "analyze" && operation != "patch" && operation != "verify" {
		ibootUsage(errOut)
		return fmt.Errorf("unknown iboot operation %q", operation)
	}
	ordered, err := reorderIBootFlags(args[1:])
	if err != nil {
		return err
	}
	options := ibootOptions{}
	flags := flag.NewFlagSet("iboot "+operation, flag.ContinueOnError)
	flags.SetOutput(errOut)
	flags.StringVar(&options.base, "base", "auto", "loader image base or auto")
	flags.StringVar(&options.offset, "offset", "auto", "snapshot offset within the image or auto")
	flags.StringVar(&options.build, "build", "auto", "iBoot build identity or auto")
	flags.StringVar(&options.metadata, "metadata", "auto", "snapshot metadata sidecar, auto, or none")
	flags.StringVar(&options.out, "out", "", "patched output path")
	flags.StringVar(&options.out, "output", "", "patched output path")
	flags.StringVar(&options.report, "report", "", "write JSON report to this path")
	flags.BoolVar(&options.json, "json", false, "print JSON instead of text")
	flags.BoolVar(&options.force, "force", false, "replace an existing output or report")
	flags.Usage = func() { ibootUsage(errOut) }
	if err = flags.Parse(ordered); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	positional := flags.Args()
	want := 1
	if operation == "verify" {
		want = 2
	}
	if len(positional) != want {
		flags.Usage()
		return fmt.Errorf("iboot %s requires %d file argument(s), got %d", operation, want, len(positional))
	}
	if operation != "patch" && options.out != "" {
		return fmt.Errorf("--out is valid only for iboot patch")
	}
	inputPath, err := filepath.Abs(positional[0])
	if err != nil {
		return err
	}
	input, err := readOfflineLoader(inputPath)
	if err != nil {
		return err
	}
	var reportPath string
	if options.report != "" {
		if reportPath, err = filepath.Abs(options.report); err != nil {
			return err
		}
		if filepath.Clean(reportPath) == filepath.Clean(inputPath) {
			return errors.New("refusing to replace the source snapshot with --report")
		}
	}
	metadata, err := resolveIBootMetadata(inputPath, input, options.metadata)
	if err != nil {
		return err
	}
	base, err := resolveIBootNumber("base", options.base, metadata.base)
	if err != nil {
		return err
	}
	offset, err := resolveIBootNumber("offset", options.offset, metadata.offset)
	if err != nil {
		return err
	}
	build, err := resolveIBootBuild(input, options.build, metadata.build)
	if err != nil {
		return err
	}
	plan, err := analyzeOfflineInitialLoader(input, offset, base, build)
	if err != nil {
		return fmt.Errorf("iBoot analysis: %w", err)
	}
	report, err := newIBootPatchReport(operation, inputPath, input, metadata.path, offset, plan)
	if err != nil {
		return err
	}
	switch operation {
	case "analyze":
		report.Exact = true
	case "patch":
		patched, changed, applyErr := applyOfflineLoaderPlan(input, offset, plan)
		if applyErr != nil {
			return applyErr
		}
		outputPath := options.out
		if outputPath == "" {
			outputPath = inputPath + ".patched"
		} else if outputPath, err = filepath.Abs(outputPath); err != nil {
			return err
		}
		if filepath.Clean(outputPath) == filepath.Clean(inputPath) {
			return errors.New("refusing to overwrite the source snapshot; choose a separate --out path")
		}
		if reportPath != "" && filepath.Clean(reportPath) == filepath.Clean(outputPath) {
			return errors.New("--report and --out must name different files")
		}
		if err = writeAtomicFile(outputPath, patched, options.force); err != nil {
			return err
		}
		readback, readErr := readOfflineLoader(outputPath)
		if readErr != nil || !bytes.Equal(readback, patched) {
			return errors.Join(errors.New("patched output readback mismatch"), readErr)
		}
		sourceReadback, sourceErr := readOfflineLoader(inputPath)
		if sourceErr != nil || !bytes.Equal(sourceReadback, input) {
			return errors.Join(errors.New("source snapshot changed while publishing output"), sourceErr)
		}
		report.ChangedBytes = changed
		report.Output = outputPath
		report.OutputBytes = len(readback)
		report.OutputSHA256 = digest(readback)
		report.Exact = true
	case "verify":
		candidatePath, pathErr := filepath.Abs(positional[1])
		if pathErr != nil {
			return pathErr
		}
		if reportPath != "" && filepath.Clean(reportPath) == filepath.Clean(candidatePath) {
			return errors.New("refusing to replace the verified snapshot with --report")
		}
		candidate, readErr := readOfflineLoader(candidatePath)
		if readErr != nil {
			return readErr
		}
		expected, changed, applyErr := applyOfflineLoaderPlan(input, offset, plan)
		if applyErr != nil {
			return applyErr
		}
		if !bytes.Equal(candidate, expected) {
			return fmt.Errorf("patched snapshot differs from the derived output at %s", firstByteDifference(candidate, expected))
		}
		report.ChangedBytes = changed
		report.Output = candidatePath
		report.OutputBytes = len(candidate)
		report.OutputSHA256 = digest(candidate)
		report.Exact = true
	}
	if reportPath != "" {
		encoded, encodeErr := json.MarshalIndent(report, "", "  ")
		if encodeErr != nil {
			return encodeErr
		}
		encoded = append(encoded, '\n')
		if err = writeAtomicFile(reportPath, encoded, options.force); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}
	return printIBootReport(out, report, options.json)
}

func reorderIBootFlags(args []string) ([]string, error) {
	valueFlags := map[string]bool{"--base": true, "--offset": true, "--build": true, "--metadata": true, "--out": true, "--output": true, "--report": true}
	boolFlags := map[string]bool{"--json": true, "--force": true, "-h": true, "--help": true}
	var options, positional []string
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if argument == "--" {
			positional = append(positional, args[index+1:]...)
			break
		}
		name := argument
		if before, _, ok := strings.Cut(argument, "="); ok {
			name = before
		}
		switch {
		case valueFlags[name]:
			options = append(options, argument)
			if !strings.Contains(argument, "=") {
				if index+1 >= len(args) {
					return nil, fmt.Errorf("%s requires a value", argument)
				}
				index++
				options = append(options, args[index])
			}
		case boolFlags[name]:
			options = append(options, argument)
		case strings.HasPrefix(argument, "-"):
			return nil, fmt.Errorf("unknown iboot option %q", argument)
		default:
			positional = append(positional, argument)
		}
	}
	return append(options, positional...), nil
}

func readOfflineLoader(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open iBoot snapshot: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 20 || info.Size() > maximumOfflineLoaderBytes || info.Size()%4 != 0 {
		return nil, fmt.Errorf("iBoot snapshot must be a 4-byte-aligned regular file between 20 and %d bytes", maximumOfflineLoaderBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumOfflineLoaderBytes+1))
	if err != nil {
		return nil, err
	}
	if _, imageErr := imageFields(data, "IMG4"); imageErr == nil {
		return nil, errors.New("iBoot patcher expects a decoded raw executable, not an IMG4 envelope")
	}
	if _, imageErr := imageFields(data, "IM4P"); imageErr == nil {
		return nil, errors.New("iBoot patcher expects a decoded raw executable, not an IM4P container")
	}
	return data, nil
}

func resolveIBootMetadata(inputPath string, input []byte, requested string) (ibootSnapshotMetadata, error) {
	if requested == "none" {
		return ibootSnapshotMetadata{}, nil
	}
	path := requested
	if path == "auto" {
		path = inputPath + ".txt"
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			return ibootSnapshotMetadata{}, nil
		} else if err != nil {
			return ibootSnapshotMetadata{}, err
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ibootSnapshotMetadata{}, fmt.Errorf("read iBoot metadata: %w", err)
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || values[key] != "" {
			return ibootSnapshotMetadata{}, fmt.Errorf("invalid iBoot metadata line %q", line)
		}
		values[key] = value
	}
	required := []string{"build", "base", "offset", "size", "sha256"}
	for _, key := range required {
		if values[key] == "" {
			return ibootSnapshotMetadata{}, fmt.Errorf("iBoot metadata is missing %s", key)
		}
	}
	base, err := strconv.ParseUint(values["base"], 0, 64)
	if err != nil {
		return ibootSnapshotMetadata{}, fmt.Errorf("metadata base: %w", err)
	}
	offset, err := strconv.ParseUint(values["offset"], 0, 64)
	if err != nil {
		return ibootSnapshotMetadata{}, fmt.Errorf("metadata offset: %w", err)
	}
	size, err := strconv.Atoi(values["size"])
	if err != nil || size != len(input) {
		return ibootSnapshotMetadata{}, fmt.Errorf("metadata size %q does not match %d-byte input", values["size"], len(input))
	}
	if values["sha256"] != digest(input) {
		return ibootSnapshotMetadata{}, errors.New("metadata SHA-256 does not match the input")
	}
	if len(values) != len(required) {
		return ibootSnapshotMetadata{}, errors.New("iBoot metadata contains unsupported fields")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return ibootSnapshotMetadata{}, err
	}
	return ibootSnapshotMetadata{path: abs, build: values["build"], base: base, offset: offset, size: size, sha256: values["sha256"]}, nil
}

func resolveIBootNumber(name, requested string, automatic uint64) (uint64, error) {
	if requested == "auto" {
		return automatic, nil
	}
	value, err := strconv.ParseUint(requested, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid --%s %q", name, requested)
	}
	if name == "base" && value%0x1000 != 0 {
		return 0, errors.New("--base must be 4 KiB aligned")
	}
	if name == "offset" && value%4 != 0 {
		return 0, errors.New("--offset must be 4-byte aligned")
	}
	return value, nil
}

func resolveIBootBuild(input []byte, requested, automatic string) (string, error) {
	build := requested
	if build == "auto" {
		build = automatic
		if build == "" {
			var err error
			build, err = loaderBuild(input, "")
			if err != nil {
				return "", fmt.Errorf("discover iBoot build; supply --build for a partial snapshot: %w", err)
			}
		}
	}
	if !strings.HasPrefix(build, "iBoot-") || len(build) <= len("iBoot-") {
		return "", fmt.Errorf("invalid iBoot build %q", build)
	}
	if bytes.Contains(input, []byte("iBoot-")) {
		if _, err := loaderBuild(input, build); err != nil {
			return "", err
		}
	}
	return build, nil
}

func applyOfflineLoaderPlan(input []byte, imageOffset uint64, plan loaderPlan) ([]byte, int, error) {
	if err := validateLoaderPlan(plan); err != nil {
		return nil, 0, err
	}
	if plan.snapshotSHA256 == "" || plan.snapshotSHA256 != digest(input) {
		return nil, 0, errors.New("iBoot plan is not bound to this input")
	}
	toLocal := func(address uint64) (int, error) {
		if address < plan.base || address-plan.base < imageOffset {
			return 0, fmt.Errorf("address 0x%x precedes the snapshot", address)
		}
		relative := address - plan.base - imageOffset
		if relative > uint64(len(input)-4) || relative > math.MaxInt {
			return 0, fmt.Errorf("address 0x%x exceeds the snapshot", address)
		}
		return int(relative), nil
	}
	for index, guard := range plan.guards {
		at, err := toLocal(guard.address)
		if err != nil {
			return nil, 0, err
		}
		actual := binary.LittleEndian.Uint32(input[at:])
		if normalizeARM64(actual)&guard.mask != guard.value {
			return nil, 0, fmt.Errorf("iBoot guard %d changed at file offset 0x%x", index, at)
		}
	}
	output := bytes.Clone(input)
	touched := make(map[int]bool)
	changed := 0
	for index, patch := range plan.patches {
		at, err := toLocal(patch.address)
		if err != nil {
			return nil, 0, err
		}
		if binary.LittleEndian.Uint32(input[at:]) != patch.before {
			return nil, 0, fmt.Errorf("iBoot patch %d preimage changed at file offset 0x%x", index, at)
		}
		var after [4]byte
		binary.LittleEndian.PutUint32(after[:], patch.after)
		for byteIndex := 0; byteIndex < 4; byteIndex++ {
			position := at + byteIndex
			if touched[position] {
				return nil, 0, errors.New("iBoot patch spans overlap")
			}
			touched[position] = true
			if input[position] != after[byteIndex] {
				changed++
			}
		}
		copy(output[at:at+4], after[:])
	}
	if changed == 0 {
		return nil, 0, errors.New("iBoot patch transaction changed no bytes")
	}
	for index := range input {
		if input[index] != output[index] && !touched[index] {
			return nil, 0, fmt.Errorf("undeclared iBoot output change at file offset 0x%x", index)
		}
	}
	inverse := bytes.Clone(output)
	for _, patch := range plan.patches {
		at, _ := toLocal(patch.address)
		binary.LittleEndian.PutUint32(inverse[at:], patch.before)
	}
	if !bytes.Equal(inverse, input) {
		return nil, 0, errors.New("iBoot patch inverse is not exact")
	}
	return output, changed, nil
}

func newIBootPatchReport(operation, inputPath string, input []byte, metadataPath string, imageOffset uint64, plan loaderPlan) (ibootPatchReport, error) {
	report := ibootPatchReport{
		SchemaVersion: 1, Operation: operation, Input: inputPath, InputBytes: len(input), InputSHA256: digest(input), Metadata: metadataPath,
		Build: plan.build, Analyzer: plan.source, Base: plan.base, ImageOffset: imageOffset, GuardCount: len(plan.guards), PatchCount: len(plan.patches), SourceUnchanged: true,
	}
	for index, patch := range plan.patches {
		if patch.address < plan.base+imageOffset {
			return ibootPatchReport{}, errors.New("iBoot patch precedes the input snapshot")
		}
		report.Patches = append(report.Patches, ibootPatchRecord{
			Index: index, Kind: ibootPatchKind(patch), FileOffset: patch.address - plan.base - imageOffset,
			ImageOffset: patch.address - plan.base, Address: patch.address,
			Before: fmt.Sprintf("%08x", patch.before), After: fmt.Sprintf("%08x", patch.after),
		})
	}
	return report, nil
}

func ibootPatchKind(patch codePatch) string {
	switch {
	case patch.after == 0xd503201f:
		return "disable-failure-branch"
	case patch.before&0xffffffe0 == 0xaa0003e0 && patch.after == patch.before|0x001f0000:
		return "zero-result-register"
	case patch.before&0xff00001f == 0x34000000 && patch.after&0xfc000000 == 0x14000000:
		return "preserve-success-target"
	default:
		return "checked-instruction-replacement"
	}
}

func printIBootReport(out io.Writer, report ibootPatchReport, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	fmt.Fprintf(out, "iBoot %s: %s\n", report.Operation, report.Build)
	fmt.Fprintf(out, "  input:    %s (%d bytes, sha256 %s)\n", report.Input, report.InputBytes, report.InputSHA256)
	fmt.Fprintf(out, "  geometry: base=0x%x offset=0x%x analyzer=%s\n", report.Base, report.ImageOffset, report.Analyzer)
	fmt.Fprintf(out, "  proof:    %d instruction guards, %d derived patches\n", report.GuardCount, report.PatchCount)
	for _, patch := range report.Patches {
		fmt.Fprintf(out, "  [%02d] +0x%06x  %-24s %s -> %s\n", patch.Index, patch.ImageOffset, patch.Kind, patch.Before, patch.After)
	}
	if report.Output != "" {
		fmt.Fprintf(out, "  output:   %s (%d bytes, sha256 %s, %d changed bytes)\n", report.Output, report.OutputBytes, report.OutputSHA256, report.ChangedBytes)
	}
	fmt.Fprintln(out, "  result:   exact, source unchanged")
	return nil
}

func firstByteDifference(actual, expected []byte) string {
	limit := min(len(actual), len(expected))
	for index := 0; index < limit; index++ {
		if actual[index] != expected[index] {
			return fmt.Sprintf("file offset 0x%x (got %02x, want %02x)", index, actual[index], expected[index])
		}
	}
	return fmt.Sprintf("end of shorter file (got %d bytes, want %d)", len(actual), len(expected))
}

func writeAtomicFile(path string, data []byte, replace bool) (err error) {
	directory := filepath.Dir(path)
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err = temporary.Chmod(0o600); err == nil {
		_, err = temporary.Write(data)
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
	if replace {
		if err = os.Rename(temporaryPath, path); err != nil {
			return err
		}
	} else {
		// Reserve the final name without replacing an existing file. Renaming the
		// fully synced temporary file over our empty reservation publishes all
		// content at once and works on ExFAT, where hard links are unavailable.
		reservation, reserveErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if reserveErr != nil {
			if errors.Is(reserveErr, os.ErrExist) {
				return fmt.Errorf("output already exists: %s (use --force to replace it)", path)
			}
			return reserveErr
		}
		if closeErr := reservation.Close(); closeErr != nil {
			_ = os.Remove(path)
			return closeErr
		}
		if err = os.Rename(temporaryPath, path); err != nil {
			_ = os.Remove(path)
			return err
		}
	}
	dir, openErr := os.Open(directory)
	if openErr != nil {
		return openErr
	}
	err = dir.Sync()
	return errors.Join(err, dir.Close())
}
