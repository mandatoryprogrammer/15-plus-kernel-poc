package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var disposableCacheNames = []string{
	"fresh-verification", "final-go-build", "final-go-mod", "go-build-clean",
	"test-go-build", "test-go-build2", "test-go-build3",
	"test-go-mod", "test-go-mod2", "test-go-mod3",
	"test-tmp", "test-tmp2", "test-tmp3",
}

var disposableCachePrefixes = []string{
	"baseline-src.", "clean-go-build-", "clean-go-mod-", "go-build-", "go-mod-",
}

type cacheGCEntry struct {
	Path  string
	Bytes int64
}

func cachePathBytes(name string) (int64, error) {
	var total int64
	err := filepath.WalkDir(name, func(_ string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func disposableCacheName(name string) bool {
	for _, exact := range disposableCacheNames {
		if name == exact {
			return true
		}
	}
	for _, prefix := range disposableCachePrefixes {
		if strings.HasPrefix(name, prefix) && name != "go-build" && name != "go-mod" {
			return true
		}
	}
	return false
}

func cacheGCPlan(c *cache, includeBuildScratch bool, now time.Time) ([]cacheGCEntry, error) {
	root, err := filepath.Abs(c.root)
	if err != nil {
		return nil, err
	}
	var result []cacheGCEntry
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		candidate := filepath.Join(root, entry.Name())
		remove := includeBuildScratch && disposableCacheName(entry.Name())
		if entry.Name() == "tmp" && entry.IsDir() {
			tmpEntries, readErr := os.ReadDir(candidate)
			if readErr != nil {
				return nil, readErr
			}
			for _, tmp := range tmpEntries {
				info, infoErr := tmp.Info()
				if infoErr != nil {
					return nil, infoErr
				}
				if now.Sub(info.ModTime()) < 24*time.Hour {
					continue
				}
				name := filepath.Join(candidate, tmp.Name())
				bytes, sizeErr := cachePathBytes(name)
				if sizeErr != nil {
					return nil, sizeErr
				}
				result = append(result, cacheGCEntry{Path: name, Bytes: bytes})
			}
			continue
		}
		if !remove {
			continue
		}
		bytes, sizeErr := cachePathBytes(candidate)
		if sizeErr != nil {
			return nil, sizeErr
		}
		result = append(result, cacheGCEntry{Path: candidate, Bytes: bytes})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func executeCacheGC(c *cache, entries []cacheGCEntry, dryRun bool) error {
	root, err := filepath.Abs(c.root)
	if err != nil {
		return err
	}
	var total int64
	for _, entry := range entries {
		candidate, absErr := filepath.Abs(entry.Path)
		if absErr != nil || filepath.Dir(candidate) != root && filepath.Dir(filepath.Dir(candidate)) != root || candidate == root {
			return errors.New("cache GC candidate escaped owned cache root")
		}
		total += entry.Bytes
		action := "Would remove"
		if !dryRun {
			if err = os.RemoveAll(candidate); err != nil {
				return err
			}
			action = "Removed"
		}
		fmt.Fprintf(c.out, "%s %s (%d MiB)\n", action, candidate, entry.Bytes>>20)
	}
	verb := "eligible"
	if !dryRun {
		verb = "reclaimed"
	}
	fmt.Fprintf(c.out, "Cache GC: %d paths, %d MiB %s; objects, private state, logs, canonical Go caches, and loader analysis were protected.\n", len(entries), total>>20, verb)
	return nil
}

func cacheGCCommand(c *cache, args []string) error {
	dryRun := false
	if len(args) == 1 && args[0] == "--dry-run" {
		dryRun = true
	} else if len(args) != 0 {
		return errors.New("usage: cache gc [--dry-run]")
	}
	entries, err := cacheGCPlan(c, true, time.Now())
	if err != nil {
		return err
	}
	return executeCacheGC(c, entries, dryRun)
}

func pruneTransientCache(c *cache) {
	entries, err := cacheGCPlan(c, false, time.Now())
	if err != nil {
		fmt.Fprintln(c.out, "warning: transient cache cleanup:", err)
		return
	}
	if err = executeCacheGC(c, entries, false); err != nil {
		fmt.Fprintln(c.out, "warning: transient cache cleanup:", err)
	}
}
