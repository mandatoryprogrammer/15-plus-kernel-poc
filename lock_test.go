package main

import (
	"path/filepath"
	"testing"
)

func TestDeviceLockReleasedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.lock")
	first, err := acquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, secondErr := acquireLock(path); secondErr == nil {
		second.Close()
		t.Fatal("second owner acquired an active device lock")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := acquireLock(path)
	if err != nil {
		t.Fatalf("released device lock remained occupied: %v", err)
	}
	third.Close()
}
