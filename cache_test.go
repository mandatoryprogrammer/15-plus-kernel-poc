package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testAsset(b []byte) asset {
	return asset{Role: "sample", SHA256: fmt.Sprintf("%x", sha256.Sum256(b)), Size: int64(len(b))}
}
func testCache(t *testing.T) *cache {
	t.Helper()
	c, err := newCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.out = io.Discard
	return c
}

func TestAssetFetchThenOffline(t *testing.T) {
	content := []byte("a verified external object")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(content) }))
	c := testCache(t)
	c.client = server.Client()
	a := testAsset(content)
	a.URL = server.URL
	path, err := c.resolve(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	server.Close()
	if next, err := c.resolve(t.Context(), a); err != nil || next != path {
		t.Fatalf("offline hit: %s %v", next, err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), len(content)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.resolve(t.Context(), a); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("corruption accepted: %v", err)
	}
}

func TestCacheRejectsUntrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("data")) }))
	defer server.Close()
	c := testCache(t)
	a := testAsset([]byte("data"))
	a.URL = server.URL
	if _, err := c.resolve(t.Context(), a); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
}

func TestCacheDownloadFailuresLeaveNoObjects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{{"hash", 200, "wrong"}, {"short", 200, "x"}, {"oversize", 200, "too many bytes"}, {"status", 403, ""}} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); io.WriteString(w, tc.body) }))
			defer server.Close()
			c := testCache(t)
			c.client = server.Client()
			a := testAsset([]byte("right"))
			a.URL = server.URL
			if _, err := c.resolve(t.Context(), a); err == nil {
				t.Fatal("invalid data accepted")
			}
			for _, dir := range []string{"objects", "tmp"} {
				entries, _ := os.ReadDir(filepath.Join(c.root, dir))
				if len(entries) != 0 {
					t.Fatalf("residue: %v", entries)
				}
			}
		})
	}
}

func TestCacheTimeoutAndCancellation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	c := testCache(t)
	c.client = server.Client()
	a := testAsset([]byte("data"))
	a.URL = server.URL
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := c.resolve(ctx, a); err == nil {
		t.Fatal("timeout ignored")
	}
	if time.Since(started) > time.Second {
		t.Fatal("timeout was not bounded")
	}
	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	if _, err := c.store(ctx, a, strings.NewReader("data")); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestCacheRejectsSymlinksAndInvalidIdentity(t *testing.T) {
	c := testCache(t)
	a := testAsset([]byte("data"))
	source := filepath.Join(c.root, "source")
	os.WriteFile(source, []byte("data"), 0600)
	if err := os.Symlink(source, c.object(a)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.resolve(t.Context(), a); err == nil {
		t.Fatal("symlink accepted")
	}
	for _, bad := range []asset{{Role: "../bad", SHA256: a.SHA256, Size: 4}, {Role: "sample", SHA256: "../bad", Size: 4}, {Role: "sample", SHA256: a.SHA256, Size: 4, URL: "http://example.com"}} {
		if _, err := c.resolve(t.Context(), bad); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
}

func TestMissingPrivateAssetNamesExactImport(t *testing.T) {
	c := testCache(t)
	a := testAsset([]byte("private input"))
	a.Role = "firmware"
	_, err := c.resolve(t.Context(), a)
	if err == nil || !strings.Contains(err.Error(), "assets import firmware /path/to/file") {
		t.Fatal(err)
	}
}
