package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRemovePayloadAddition(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "private"), 0700); err != nil {
		t.Fatal(err)
	}
	c := &cache{root: root, out: io.Discard}
	entries := []payloadEntry{
		{Destination: "/usr/local/bin/d17", SHA256: digest([]byte("d17")), Size: 3, CDHash: "7af5b83410fa9f9b8003c187b14f244e971a1fb2"},
		{Destination: "/usr/local/bin/monkeybars", SHA256: digest([]byte("monkeybars")), Size: 10, CDHash: "5ba4f5e2a0ed862b6473b213b171e26d6d888d36"},
	}
	if err := writePayloadAdditions(c, entries); err != nil {
		t.Fatal(err)
	}
	if err := removePayload(c, []string{"/usr/local/bin/d17"}); err != nil {
		t.Fatal(err)
	}
	got, err := loadPayloadAdditions(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Destination != "/usr/local/bin/monkeybars" {
		t.Fatalf("remaining payload additions: %+v", got)
	}
	if err := removePayload(c, []string{"/usr/local/bin/d17"}); err == nil {
		t.Fatal("removed an absent payload addition")
	}
}
