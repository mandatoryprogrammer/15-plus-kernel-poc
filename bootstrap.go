package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

//go:embed bootstrap.json
var bootstrapManifest []byte

type bootstrapSets struct {
	Boot    []asset `json:"boot"`
	Runtime []asset `json:"runtime"`
}

func validatePreparedSet(rows []asset, allowed map[string]bool) error {
	if len(rows) == 0 {
		return errors.New("empty prepared component set")
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if !allowed[row.Role] || seen[row.Role] || row.URL != "" || row.Member != "" || row.validate() != nil {
			return fmt.Errorf("invalid prepared component role %q", row.Role)
		}
		seen[row.Role] = true
	}
	for role := range allowed {
		if !seen[role] {
			return fmt.Errorf("prepared component set is missing %s", role)
		}
	}
	return nil
}

func preparedSet(name string, allowed map[string]bool) ([]asset, error) {
	var sets bootstrapSets
	if err := json.Unmarshal(bootstrapManifest, &sets); err != nil {
		return nil, err
	}
	var rows []asset
	switch name {
	case "boot":
		rows = sets.Boot
	case "runtime":
		rows = sets.Runtime
	default:
		return nil, errors.New("unknown prepared component set")
	}
	if err := validatePreparedSet(rows, allowed); err != nil {
		return nil, err
	}
	return rows, nil
}

func importBootstrap(ctx context.Context, c *cache, source string) error {
	info, err := os.Stat(source)
	if err != nil || !info.IsDir() {
		return errors.New("bootstrap input must be a directory")
	}
	bootRoles := map[string]bool{"ibec": true, "kernel": true, "sptm": true, "txm": true, "device-tree": true, "trust-cache": true}
	runtimeRoles := map[string]bool{"ibec": true, "ramdisk": true, "kernel": true, "sptm": true, "txm": true, "trust-cache": true}
	bootRows, err := preparedSet("boot", bootRoles)
	if err != nil {
		return err
	}
	runtimeRows, err := preparedSet("runtime", runtimeRoles)
	if err != nil {
		return err
	}
	for _, row := range append(bootRows, runtimeRows...) {
		f, openErr := os.Open(filepath.Join(source, "objects", row.SHA256))
		if openErr != nil {
			return fmt.Errorf("bootstrap object %s: %w", row.SHA256, openErr)
		}
		_, storeErr := c.store(ctx, row, io.LimitReader(f, row.Size+1))
		f.Close()
		if storeErr != nil {
			return storeErr
		}
	}
	fmt.Fprintln(c.out, "Bootstrap components imported and verified.")
	return nil
}
