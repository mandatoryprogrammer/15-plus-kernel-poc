package main

import (
	"strings"
	"testing"
)

func TestDeviceValidation(t *testing.T) {
	serial := "CPID:8120 CPRV:11 CPFM:00 SCEP:00 BDID:0A ECID:12345678 IBFL:25"
	d, err := parseDevice(serial)
	if err != nil || d.ECID != 0x12345678 {
		t.Fatalf("valid device: %+v %v", d, err)
	}
	if _, err := parseDevice(strings.ReplaceAll(serial, "IBFL:25", "IBFL:24")); err != nil {
		t.Fatal(err)
	}
	for _, revision := range []string{"CPRV:01", "CPRV:11", "CPRV:21"} {
		if _, err := parseDevice(strings.ReplaceAll(serial, "CPRV:11", revision)); err != nil {
			t.Fatalf("rejected family-compatible %s: %v", revision, err)
		}
	}
	for _, bad := range []string{strings.ReplaceAll(serial, "CPFM:00", "CPFM:03"), strings.ReplaceAll(serial, "8120", "8130"), strings.ReplaceAll(serial, "BDID:0A", "BDID:0C"), strings.ReplaceAll(serial, "IBFL:25", "IBFL:01"), strings.ReplaceAll(serial, "ECID:12345678", "ECID:0"), strings.ReplaceAll(serial, "CPRV:11 ", ""), strings.ReplaceAll(serial, "SCEP:00 ", ""), strings.ReplaceAll(serial, "CPFM:00 ", ""), serial + " CPID:8120", serial + " ECID:wrong"} {
		if _, err := parseDevice(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestSupportedRecoveryBuild(t *testing.T) {
	for _, test := range []struct {
		stage uint64
		build string
	}{{0x25, initialBuild}, {0x25, "iBoot-9275.0.0.101.12"}, {0x24, canonicalRuntime.LoaderBuild}} {
		if err := validateRecoveryBuild(test.stage, test.build); err != nil {
			t.Fatalf("stage %02x build %q: %v", test.stage, test.build, err)
		}
	}
	for _, test := range []struct {
		stage uint64
		build string
	}{{0x23, initialBuild}, {0x25, "mBoot-1"}, {0x24, initialBuild}} {
		if err := validateRecoveryBuild(test.stage, test.build); err == nil {
			t.Fatalf("accepted stage %02x build %q", test.stage, test.build)
		}
	}
}
