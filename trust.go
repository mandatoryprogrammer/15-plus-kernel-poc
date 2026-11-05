package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const trustAdditionLimit = 256

type trustEntry struct {
	Name   string `json:"name"`
	CDHash string `json:"cdhash"`
	Origin string `json:"origin"`
}

func validTrustName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func trustPlan(entries []trustEntry) error {
	if len(entries) > trustAdditionLimit {
		return fmt.Errorf("trust additions exceed %d", trustAdditionLimit)
	}
	names := make(map[string]bool, len(entries))
	hashes := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if !validTrustName(entry.Name) {
			return fmt.Errorf("invalid trust name %q", entry.Name)
		}
		if len(entry.CDHash) != 40 || strings.ToLower(entry.CDHash) != entry.CDHash {
			return fmt.Errorf("invalid cdhash for %s", entry.Name)
		}
		decoded, err := hex.DecodeString(entry.CDHash)
		if err != nil || len(decoded) != 20 {
			return fmt.Errorf("invalid cdhash for %s", entry.Name)
		}
		if names[entry.Name] {
			return fmt.Errorf("duplicate trust name %s", entry.Name)
		}
		if hashes[entry.CDHash] {
			return fmt.Errorf("duplicate trust cdhash %s", entry.CDHash)
		}
		names[entry.Name], hashes[entry.CDHash] = true, true
	}
	return nil
}

func parseTrustTSV(reader io.Reader) ([]trustEntry, error) {
	var entries []trustEntry
	scanner := bufio.NewScanner(reader)
	for line := 1; scanner.Scan(); line++ {
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			continue
		}
		fields := strings.Split(value, "\t")
		if len(fields) != 2 {
			return nil, fmt.Errorf("trust import line %d must be NAME<TAB>CDHASH", line)
		}
		entries = append(entries, trustEntry{Name: fields[0], CDHash: fields[1], Origin: "user trust import"})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("trust import is empty")
	}
	if err := trustPlan(entries); err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func loadTrustAdditions(c *cache) ([]trustEntry, error) {
	b, err := os.ReadFile(filepath.Join(c.root, "private", "trust.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []trustEntry
	if err = json.Unmarshal(b, &entries); err != nil {
		return nil, err
	}
	if err = trustPlan(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func writeTrustAdditions(c *cache, entries []trustEntry) error {
	if err := trustPlan(entries); err != nil {
		return err
	}
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Join(c.root, "private"), "trust-")
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
	return os.Rename(name, filepath.Join(c.root, "private", "trust.json"))
}

func trustPayloadEntries(entries []trustEntry) []payloadEntry {
	result := make([]payloadEntry, 0, len(entries))
	for _, entry := range entries {
		result = append(result, payloadEntry{Destination: "trust:" + entry.Name, CDHash: entry.CDHash, Origin: entry.Origin})
	}
	return result
}

func bootTrustAdditions(entries []trustEntry) []trustEntry {
	result := make([]trustEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name, "dyld_shared_cache_arm64e") {
			continue
		}
		result = append(result, entry)
	}
	return result
}

func importTrust(c *cache, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: trust import FILE")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return err
	}
	entries, parseErr := parseTrustTSV(f)
	closeErr := f.Close()
	if parseErr != nil {
		return parseErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err = writeTrustAdditions(c, entries); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Imported %d trust-only CodeDirectory identities; the next boot will admit them.\n", len(entries))
	return nil
}

func listTrust(c *cache, out io.Writer) error {
	entries, err := loadTrustAdditions(c)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		fmt.Fprintf(out, "%s\t%s\n", entry.Name, entry.CDHash)
	}
	return nil
}
