package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCacheGCProtectsDurableStateAndDeletesOnlyOwnedScratch(t *testing.T) {
	c, err := newCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.out = io.Discard
	protected := []string{"objects/object", "private/state", "logs/evidence", "loader-analysis/plan", "go-build/canonical", "go-mod/canonical"}
	for _, relative := range protected {
		name := filepath.Join(c.root, relative)
		if err = os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(name, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, relative := range []string{"test-go-build/x", "go-build-probe/x", "fresh-verification/x"} {
		name := filepath.Join(c.root, relative)
		if err = os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(name, []byte("delete"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	old := filepath.Join(c.root, "tmp", "abandoned")
	if err = os.WriteFile(old, []byte("delete"), 0600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-48 * time.Hour)
	if err = os.Chtimes(old, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	plan, err := cacheGCPlan(c, true, time.Now())
	if err != nil || len(plan) != 4 {
		t.Fatalf("plan=%v err=%v", plan, err)
	}
	if err = executeCacheGC(c, plan, false); err != nil {
		t.Fatal(err)
	}
	for _, relative := range protected {
		if _, err = os.Stat(filepath.Join(c.root, relative)); err != nil {
			t.Fatalf("protected %s removed: %v", relative, err)
		}
	}
	for _, relative := range []string{"test-go-build", "go-build-probe", "fresh-verification", "tmp/abandoned"} {
		if _, err = os.Stat(filepath.Join(c.root, relative)); !os.IsNotExist(err) {
			t.Fatalf("disposable %s retained: %v", relative, err)
		}
	}
}
