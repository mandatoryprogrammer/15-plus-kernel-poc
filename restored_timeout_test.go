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
