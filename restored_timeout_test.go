package main

import (
	"strings"
	"testing"
)

func TestRestoredHostStartTimeoutContract(t *testing.T) {
	if restoredHostStartTimeoutSeconds != 60 {
		t.Fatalf("restored host start timeout=%d, want 60", restoredHostStartTimeoutSeconds)
	}
	set := restoredHostTimeoutSetCommand()
	if set != "/usr/sbin/nvram restored-host-timeout=60" || strings.Contains(set, "=0") {
		t.Fatalf("restored host start timeout set command=%q", set)
	}
	if delete := restoredHostTimeoutDeleteCommand(); !strings.Contains(delete, "-d restored-host-timeout") {
		t.Fatalf("restored host start timeout inverse=%q", delete)
	}

	value, present, err := nvramListingValue([]byte("auto-boot\tfalse\r\nrestored-host-timeout\t60\r\n"), restoredHostTimeoutKey)
	if err != nil || !present || value != "60" {
		t.Fatalf("postimage value=%q present=%t err=%v", value, present, err)
	}
	value, present, err = nvramListingValue([]byte("auto-boot\tfalse\n"), restoredHostTimeoutKey)
	if err != nil || present || value != "" {
		t.Fatalf("absent preimage value=%q present=%t err=%v", value, present, err)
	}

	preimages := []struct {
		name        string
		preimage    restoredHostTimeoutPreimage
		wantCommand string
		value       string
		present     bool
	}{
		{
			name:        "absent",
			preimage:    restoredHostTimeoutPreimage{},
			wantCommand: restoredHostTimeoutDeleteCommand(),
		},
		{
			name:        "exact-zero",
			preimage:    restoredHostTimeoutPreimage{Value: "0", Present: true},
			wantCommand: "/usr/sbin/nvram restored-host-timeout=0",
			value:       "0",
			present:     true,
		},
	}
	for _, test := range preimages {
		t.Run(test.name, func(t *testing.T) {
			command, err := test.preimage.restoreCommand()
			if err != nil {
				t.Fatalf("restore command: %v", err)
			}
			if command != test.wantCommand {
				t.Fatalf("restore command=%q, want %q", command, test.wantCommand)
			}
			if !test.preimage.matches(test.value, test.present) {
				t.Fatalf("exact inverse did not match value=%q present=%t", test.value, test.present)
			}
			if test.preimage.matches("60", true) {
				t.Fatal("temporary postimage matched the preimage")
			}
		})
	}
}

func TestNVRAMListingValueRejectsAmbiguousTimeout(t *testing.T) {
	for _, listing := range [][]byte{
		[]byte("restored-host-timeout\t60\nrestored-host-timeout\t61\n"),
		[]byte("restored-host-timeout\t\n"),
	} {
		if _, _, err := nvramListingValue(listing, restoredHostTimeoutKey); err == nil {
			t.Fatalf("ambiguous listing accepted: %q", listing)
		}
	}
}

func TestRestoredHostTimeoutPreimageRejectsNonNumericValue(t *testing.T) {
	for _, preimage := range []restoredHostTimeoutPreimage{
		{Value: "1; true", Present: true},
		{Value: "", Present: true},
		{Value: "1", Present: false},
	} {
		if _, err := preimage.restoreCommand(); err == nil {
			t.Fatalf("invalid preimage accepted: %#v", preimage)
		}
	}
}
