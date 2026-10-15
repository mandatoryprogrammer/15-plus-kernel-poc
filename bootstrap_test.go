package main

import (
	"strings"
	"testing"
)

func TestPreparedSetRequiresExactRoles(t *testing.T) {
	allowed := map[string]bool{"first": true, "second": true}
	row := func(role string) asset {
		return asset{Role: role, SHA256: strings.Repeat("a", 64), Size: 1, Recipe: "verified input", Compatibility: "supported board"}
	}
	if err := validatePreparedSet([]asset{row("first"), row("second")}, allowed); err != nil {
		t.Fatalf("valid descriptor: %v", err)
	}
	for _, rows := range [][]asset{
		{row("first")},
		{row("first"), row("second"), row("third")},
		{row("first"), row("second"), row("second")},
	} {
		if err := validatePreparedSet(rows, allowed); err == nil {
			t.Fatalf("accepted roles: %+v", rows)
		}
	}
	rows := []asset{row("first"), row("second")}
	rows[1].URL = "https://example.invalid/private"
	if err := validatePreparedSet(rows, allowed); err == nil {
		t.Fatal("private descriptor accepted a public source")
	}
}

func TestTrackedBootstrapSetsHaveExactRoles(t *testing.T) {
	bootRoles := map[string]bool{"ibec": true, "kernel": true, "sptm": true, "txm": true, "device-tree": true, "trust-cache": true}
	runtimeRoles := map[string]bool{"ibec": true, "ramdisk": true, "kernel": true, "sptm": true, "txm": true, "trust-cache": true}
	boot, err := preparedSet("boot", bootRoles)
	if err != nil || len(boot) != len(bootRoles) {
		t.Fatalf("boot set: %d %v", len(boot), err)
	}
	runtime, err := preparedSet("runtime", runtimeRoles)
	if err != nil || len(runtime) != len(runtimeRoles) {
		t.Fatalf("runtime set: %d %v", len(runtime), err)
	}
}
