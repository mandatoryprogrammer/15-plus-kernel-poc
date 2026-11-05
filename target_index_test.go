package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSystemVersion = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>ProductVersion</key><string>26.3</string>
<key>ProductBuildVersion</key><string>23D127</string>
</dict></plist>`

func writeTargetTestFile(t *testing.T, root, relative string, body []byte, mode os.FileMode) string {
	t.Helper()
	name := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, body, mode); err != nil {
		t.Fatal(err)
	}
	return name
}

func targetTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTargetTestFile(t, root, "System/Library/CoreServices/SystemVersion.plist", []byte(testSystemVersion), 0600)
	launchd := `<?xml version="1.0"?><plist version="1.0"><dict>
<key>Label</key><string>com.example.display</string>
<key>MachServices</key><dict><key>com.example.display</key><true/><key>com.example.control</key><dict/></dict>
</dict></plist>`
	writeTargetTestFile(t, root, "System/Library/LaunchDaemons/com.example.display.plist", []byte(launchd), 0600)
	writeTargetTestFile(t, root, "System/Library/dyld/dyld_shared_cache_arm64e", []byte("dyld_v1  arm64e\x00cache"), 0600)
	writeTargetTestFile(t, root, "System/Library/dyld/dyld_shared_cache_arm64e.01", []byte("dyld_v1  arm64e\x00subcache"), 0600)
	writeTargetTestFile(t, root, "usr/bin/example", append([]byte{0xcf, 0xfa, 0xed, 0xfe}, bytes.Repeat([]byte{0x41}, 32)...), 0755)
	trust := trustImageWithRows("trst", 2, completeTrustRow(2, 0x22))
	writeTargetTestFile(t, root, "private/var/db/StaticTrustCache", trust, 0600)
	return root
}

func TestBuildTargetIndexIsDeterministicAndComplete(t *testing.T) {
	firstRoot := targetTestRoot(t)
	secondRoot := targetTestRoot(t)
	first, err := buildTargetIndex(context.Background(), firstRoot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildTargetIndex(context.Background(), secondRoot)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("index depends on host root: first=%s second=%s", firstJSON, secondJSON)
	}
	if first.ProductVersion != "26.3" || first.ProductBuild != "23D127" || len(first.Executables) != 1 || len(first.Plists) != 2 || len(first.MachServices) != 2 || len(first.SharedCaches) != 2 || len(first.StaticTrustCaches) != 1 {
		t.Fatalf("unexpected index summary: %+v", first)
	}
	if first.MachServices[0].Name != "com.example.control" || first.MachServices[1].Name != "com.example.display" {
		t.Fatalf("Mach service order/content changed: %+v", first.MachServices)
	}
	if first.StaticTrustCaches[0].EntryCount != 1 || first.StaticTrustCaches[0].Version != 2 {
		t.Fatalf("trust-cache identity changed: %+v", first.StaticTrustCaches[0])
	}
}

func TestTargetIndexArtifactIsActualContentAddress(t *testing.T) {
	c, err := newCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.out = io.Discard
	artifact, err := buildAndStoreTargetIndex(context.Background(), c, targetTestRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	if digest(body) != artifact.SHA256 || filepath.Base(artifact.Path) != artifact.SHA256+".json" {
		t.Fatalf("not content addressed: artifact=%+v body=%s", artifact, digest(body))
	}
	latest, err := os.ReadFile(filepath.Join(c.root, "private", "target-index-latest.json"))
	if err != nil || !bytes.Equal(latest, body) {
		t.Fatalf("latest index is not exact: err=%v equal=%t", err, bytes.Equal(latest, body))
	}
	second, err := buildAndStoreTargetIndex(context.Background(), c, targetTestRoot(t))
	if err != nil || second.SHA256 != artifact.SHA256 {
		t.Fatalf("repeat changed identity: first=%s second=%s err=%v", artifact.SHA256, second.SHA256, err)
	}
	root := targetTestRoot(t)
	writeTargetTestFile(t, root, "usr/bin/second", append([]byte{0xcf, 0xfa, 0xed, 0xfe}, []byte("second")...), 0755)
	replacement, err := buildAndStoreTargetIndex(context.Background(), c, root)
	if err != nil || replacement.SHA256 == artifact.SHA256 {
		t.Fatalf("changed inventory retained old identity: replacement=%s err=%v", replacement.SHA256, err)
	}
	if _, err = os.Stat(artifact.Path); !os.IsNotExist(err) {
		t.Fatalf("old target index was not pruned: %v", err)
	}
}

func TestTargetIndexHandlesSymlinksWithoutFollowingAndRejectsMissingInputs(t *testing.T) {
	t.Run("root-symlink", func(t *testing.T) {
		root := targetTestRoot(t)
		link := filepath.Join(t.TempDir(), "root")
		if err := os.Symlink(root, link); err != nil {
			t.Fatal(err)
		}
		if _, err := buildTargetIndex(context.Background(), link); err == nil || !strings.Contains(err.Error(), "not a symlink") {
			t.Fatalf("accepted root symlink: %v", err)
		}
	})
	t.Run("interior-symlink", func(t *testing.T) {
		root := targetTestRoot(t)
		external := writeTargetTestFile(t, t.TempDir(), "external", append([]byte{0xcf, 0xfa, 0xed, 0xfe}, []byte("outside")...), 0755)
		if err := os.Symlink(external, filepath.Join(root, "usr", "bin", "alias")); err != nil {
			t.Fatal(err)
		}
		index, err := buildTargetIndex(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		if len(index.Symlinks) != 1 || index.Symlinks[0].Path != "usr/bin/alias" || len(index.Executables) != 1 {
			t.Fatalf("symlink was followed or not recorded: links=%+v executables=%+v", index.Symlinks, index.Executables)
		}
	})
	t.Run("missing-base-cache", func(t *testing.T) {
		root := targetTestRoot(t)
		if err := os.Remove(filepath.Join(root, "System", "Library", "dyld", "dyld_shared_cache_arm64e")); err != nil {
			t.Fatal(err)
		}
		if _, err := buildTargetIndex(context.Background(), root); err == nil || !strings.Contains(err.Error(), "missing dyld_shared_cache_arm64e") {
			t.Fatalf("accepted incomplete cache inventory: %v", err)
		}
	})
}

func testBinaryLaunchdPlist() []byte {
	objects := [][]byte{
		append([]byte{0x55}, []byte("Label")...),
		append([]byte{0x5f, 0x10, 0x0f}, []byte("com.example.job")...),
		append([]byte{0x5c}, []byte("MachServices")...),
		append([]byte{0x5f, 0x10, 0x13}, []byte("com.example.service")...),
		{0x09},
		{0xd1, 3, 4},
		{0xd2, 0, 2, 1, 5},
	}
	body := []byte("bplist00")
	offsets := make([]byte, len(objects))
	for index, object := range objects {
		offsets[index] = byte(len(body))
		body = append(body, object...)
	}
	offsetTable := len(body)
	body = append(body, offsets...)
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = 1, 1
	binary.BigEndian.PutUint64(trailer[8:16], uint64(len(objects)))
	binary.BigEndian.PutUint64(trailer[16:24], 6)
	binary.BigEndian.PutUint64(trailer[24:32], uint64(offsetTable))
	return append(body, trailer...)
}

func TestDecodeBinaryTargetPlist(t *testing.T) {
	value, err := decodeTargetPlist(testBinaryLaunchdPlist())
	if err != nil {
		t.Fatal(err)
	}
	if value["Label"] != "com.example.job" {
		t.Fatalf("label=%v", value["Label"])
	}
	services, ok := value["MachServices"].(map[string]any)
	if !ok || services["com.example.service"] != true {
		t.Fatalf("services=%#v", value["MachServices"])
	}
}
