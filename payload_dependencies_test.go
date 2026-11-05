package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPayloadDependencyClassificationAndDestinations(t *testing.T) {
	for _, name := range []string{"/System/Library/Frameworks/UIKit.framework/UIKit", "/usr/lib/libSystem.B.dylib"} {
		if !systemPayloadDependency(name) {
			t.Fatalf("system dependency not classified: %s", name)
		}
	}
	for input, want := range map[string]string{
		"@rpath/iRemoteFramebuffer.framework/iRemoteFramebuffer": "/usr/local/lib/iRemoteFramebuffer.framework/iRemoteFramebuffer",
		"@loader_path/libProbe.dylib":                            "/usr/local/lib/libProbe.dylib",
	} {
		got, err := payloadDependencyDestination(input)
		if err != nil || got != want {
			t.Fatalf("destination %s=%s, want %s: %v", input, got, want, err)
		}
	}
	if _, err := payloadDependencyDestination("../../escape"); err == nil {
		t.Fatal("escaping dependency accepted")
	}
}

func TestFindPayloadDependencyExactAndAmbiguous(t *testing.T) {
	root := t.TempDir()
	exact := filepath.Join(root, "Frameworks", "Probe.framework", "Probe")
	if err := os.MkdirAll(filepath.Dir(exact), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exact, []byte{0xcf, 0xfa, 0xed, 0xfe}, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := findPayloadDependency(root, "Probe.framework/Probe"); err != nil || got != exact {
		t.Fatalf("exact=%s err=%v", got, err)
	}
	other := filepath.Join(root, "Other", "Probe")
	if err := os.MkdirAll(filepath.Dir(other), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte{0xcf, 0xfa, 0xed, 0xfe}, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := findPayloadDependency(root, "Probe.framework/Probe"); err != nil || got != exact {
		t.Fatalf("exact suffix lost to fallback: got=%s err=%v", got, err)
	}
	if _, err := findPayloadDependency(root, "Probe"); err == nil {
		t.Fatal("ambiguous basename accepted")
	}
}

func TestPayloadDestinationAllowsFrameworkTreeButNotEscape(t *testing.T) {
	if !validPayloadDestination("/usr/local/lib/Probe.framework/Probe") {
		t.Fatal("framework destination rejected")
	}
	for _, bad := range []string{"/usr/local/lib/../bin/x", "/usr/local/share/x", "/usr/local/lib//x"} {
		if validPayloadDestination(bad) {
			t.Fatalf("unsafe destination accepted: %s", bad)
		}
	}
}
