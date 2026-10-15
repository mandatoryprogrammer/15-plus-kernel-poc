//go:build darwin && arm64

package main

import "testing"

func TestRecoveryCommandRequest(t *testing.T) {
	for _, command := range []string{"go", "bootx", "reboot", "memboot"} {
		if got := recoveryCommandRequest(command); got != 1 {
			t.Fatalf("%q request = %d, want 1", command, got)
		}
	}
	for _, command := range []string{"getenv build-version", "firmware", "saveenv", "setpicture 4"} {
		if got := recoveryCommandRequest(command); got != 0 {
			t.Fatalf("%q request = %d, want 0", command, got)
		}
	}
}
