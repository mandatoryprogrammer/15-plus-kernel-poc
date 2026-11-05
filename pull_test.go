package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pullDestination(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "pulled.bin")
}

func assertNoPullResidue(t *testing.T, destination string) {
	t.Helper()
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination residue: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(destination), "."+filepath.Base(destination)+".pull-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("private pull residue: %v", matches)
	}
}

func TestReceiveVerifiedPullPublishesTwoIdenticalReads(t *testing.T) {
	destination := pullDestination(t)
	body := []byte("exact target bytes\x00with binary data")
	reads := 0
	result, err := receiveVerifiedPull(t.Context(), "/mnt/iphone/system/file", destination, func(_ context.Context, output io.Writer) error {
		reads++
		_, err := output.Write(body)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if reads != 2 || result.Size != int64(len(body)) || result.SHA256 != digest(body) {
		t.Fatalf("result = %+v after %d reads", result, reads)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatal("published bytes changed")
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("published mode = %o", info.Mode().Perm())
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(destination), ".pulled.bin.pull-*"))
	if len(matches) != 0 {
		t.Fatalf("private pull residue: %v", matches)
	}
}

func TestReceiveVerifiedPullRefusesDestinationPreimage(t *testing.T) {
	destination := pullDestination(t)
	if err := os.WriteFile(destination, []byte("preserve me"), 0644); err != nil {
		t.Fatal(err)
	}
	reads := 0
	_, err := receiveVerifiedPull(t.Context(), "/remote/file", destination, func(_ context.Context, _ io.Writer) error {
		reads++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") || reads != 0 {
		t.Fatalf("preimage result: reads=%d err=%v", reads, err)
	}
	got, _ := os.ReadFile(destination)
	if string(got) != "preserve me" {
		t.Fatal("destination preimage was changed")
	}
}

func TestReceiveVerifiedPullRemovesPartialRead(t *testing.T) {
	destination := pullDestination(t)
	_, err := receiveVerifiedPull(t.Context(), "/remote/file", destination, func(_ context.Context, output io.Writer) error {
		_, _ = io.WriteString(output, "partial")
		return errors.New("transport failed")
	})
	if err == nil || !strings.Contains(err.Error(), "transport failed") {
		t.Fatal(err)
	}
	assertNoPullResidue(t, destination)
}

func TestReceiveVerifiedPullRejectsChangedSecondRead(t *testing.T) {
	destination := pullDestination(t)
	reads := 0
	_, err := receiveVerifiedPull(t.Context(), "/remote/file", destination, func(_ context.Context, output io.Writer) error {
		reads++
		if reads == 1 {
			_, _ = io.WriteString(output, "first")
		} else {
			_, _ = io.WriteString(output, "second")
		}
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "changed between verified reads") {
		t.Fatal(err)
	}
	assertNoPullResidue(t, destination)
}

func TestReceiveVerifiedPullPreservesConcurrentDestination(t *testing.T) {
	destination := pullDestination(t)
	reads := 0
	_, err := receiveVerifiedPull(t.Context(), "/remote/file", destination, func(_ context.Context, output io.Writer) error {
		reads++
		_, writeErr := io.WriteString(output, "stable")
		if writeErr == nil && reads == 2 {
			writeErr = os.WriteFile(destination, []byte("concurrent owner"), 0644)
		}
		return writeErr
	})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatal(err)
	}
	got, readErr := os.ReadFile(destination)
	if readErr != nil || string(got) != "concurrent owner" {
		t.Fatalf("concurrent destination changed: %q, %v", got, readErr)
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(destination), ".pulled.bin.pull-*"))
	if len(matches) != 0 {
		t.Fatalf("private pull residue: %v", matches)
	}
}

func TestReceiveVerifiedPullRejectsUnsafePaths(t *testing.T) {
	destination := pullDestination(t)
	for _, test := range []struct {
		remote string
		local  string
	}{
		{"relative", destination},
		{"/remote/../file", destination},
		{"/remote/file\nnext", destination},
		{"/remote/file", "relative"},
		{"/remote/file", filepath.Dir(destination) + "/sub/../" + filepath.Base(destination)},
	} {
		if _, err := receiveVerifiedPull(t.Context(), test.remote, test.local, func(_ context.Context, _ io.Writer) error { return nil }); err == nil {
			t.Fatalf("accepted remote=%q local=%q", test.remote, test.local)
		}
	}
}
