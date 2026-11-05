package main

import (
	"bytes"
	"debug/macho"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

func validPayloadEnvironment(value string) bool {
	at := strings.IndexByte(value, '=')
	if at < 1 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for index, r := range value[:at] {
		if r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || index > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func systemPayloadDependency(name string) bool {
	return strings.HasPrefix(name, "/System/") || strings.HasPrefix(name, "/usr/lib/")
}

func payloadDependencySuffix(name string) (string, bool) {
	for _, prefix := range []string{"@rpath/", "@loader_path/", "@executable_path/"} {
		if strings.HasPrefix(name, prefix) {
			suffix := path.Clean(strings.TrimPrefix(name, prefix))
			return suffix, suffix != "." && !strings.HasPrefix(suffix, "../") && !strings.HasPrefix(suffix, "/")
		}
	}
	return "", false
}

func payloadDependencyDestination(name string) (string, error) {
	suffix, ok := payloadDependencySuffix(name)
	if !ok {
		return "", fmt.Errorf("unsupported non-system Mach-O dependency %q", name)
	}
	destination := path.Join("/usr/local/lib", suffix)
	if !validPayloadDestination(destination) {
		return "", fmt.Errorf("dependency %q maps to invalid destination %q", name, destination)
	}
	return destination, nil
}

func machOFile(pathname string) bool {
	f, err := os.Open(pathname)
	if err != nil {
		return false
	}
	defer f.Close()
	header := make([]byte, 4)
	_, err = f.Read(header)
	return err == nil && bytes.Equal(header, []byte{0xcf, 0xfa, 0xed, 0xfe})
}

// findPayloadDependency performs deterministic, bounded local discovery. It
// matches the complete import suffix first and the basename only as a fallback;
// ambiguity fails closed instead of silently choosing a binary.
func findPayloadDependency(root, suffix string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	var exact, fallback []string
	visited := 0
	err = filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		visited++
		if visited > 4096 {
			return errors.New("automatic dependency search exceeded 4096 entries; use --include")
		}
		if entry.IsDir() {
			if name != root && strings.HasPrefix(entry.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || entry.Name() != path.Base(suffix) || !machOFile(name) {
			return nil
		}
		slashName := filepath.ToSlash(name)
		if strings.HasSuffix(slashName, "/"+suffix) {
			exact = append(exact, name)
		} else {
			fallback = append(fallback, name)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	candidates := exact
	if len(candidates) == 0 {
		candidates = fallback
	}
	sort.Strings(candidates)
	if len(candidates) != 1 {
		return "", fmt.Errorf("dependency %s has %d local candidates below %s; use --include", suffix, len(candidates), root)
	}
	return candidates[0], nil
}

// discoverPayloadDependencies closes the caller-owned portion of a Mach-O
// dependency graph. Absolute ProductOS libraries remain runtime-provided. An
// explicit include always wins; otherwise @rpath/@loader_path imports are
// resolved from the source tree and assigned deterministic /usr/local/lib
// destinations.
func discoverPayloadDependencies(mainSource string, prepared []preparedPayload) ([]preparedPayload, error) {
	if len(prepared) == 0 {
		return nil, errors.New("payload dependency graph is empty")
	}
	root := filepath.Dir(mainSource)
	seenDestination := make(map[string]bool, len(prepared))
	seenImport := make(map[string]bool, len(prepared))
	for _, item := range prepared {
		seenDestination[item.Entry.Destination] = true
		seenImport[path.Base(item.Entry.Destination)] = true
	}
	for index := 0; index < len(prepared); index++ {
		owner := prepared[index]
		for _, dependency := range owner.Dependencies {
			if systemPayloadDependency(dependency) || path.Base(dependency) == path.Base(owner.Entry.Destination) || seenImport[path.Base(dependency)] {
				continue
			}
			suffix, ok := payloadDependencySuffix(dependency)
			if !ok {
				return nil, fmt.Errorf("%s imports unresolved non-system dependency %q", owner.Entry.Destination, dependency)
			}
			source, err := findPayloadDependency(root, suffix)
			if err != nil {
				return nil, fmt.Errorf("resolve %s for %s: %w", dependency, owner.Entry.Destination, err)
			}
			destination, err := payloadDependencyDestination(dependency)
			if err != nil {
				return nil, err
			}
			if seenDestination[destination] {
				return nil, fmt.Errorf("automatic dependency destination collision: %s", destination)
			}
			item, err := preparePayload(source, destination)
			if err != nil {
				return nil, fmt.Errorf("prepare automatic dependency %s: %w", source, err)
			}
			if item.FileType != macho.TypeDylib {
				return nil, fmt.Errorf("automatic dependency %s is not a dylib", source)
			}
			item.Entry.Origin = "payload run"
			prepared = append(prepared, item)
			seenDestination[destination], seenImport[path.Base(dependency)] = true, true
		}
	}
	return prepared, nil
}
