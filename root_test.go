package main

import "testing"

func TestLeadingRootHexIgnoresConsoleInterleaving(t *testing.T) {
	for input, want := range map[string]string{
		"76657273696f6e3d31":                     "76657273696f6e3d31",
		"76657273696f6e3d31Couldn't alloc class": "76657273696f6e3d31",
		"76657273696f6e3d3AppleSPU":              "76657273696f6e3d",
		"Couldn't alloc class":                   "",
		"76657273696f6e3d31\r":                   "76657273696f6e3d31",
	} {
		if got := leadingHexBytes(input); got != want {
			t.Errorf("leadingHexBytes(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRootEndStatusRequiresCompleteRecord(t *testing.T) {
	const id, verb = "host-123_", "exec"
	for _, partial := range []string{
		"PDS1|END|host-123_|",
		"PDS1|END|host-123_|exe",
		"PDS1|END|host-123_|exec|",
		"PDS1|END|host-123_|exec|0",
	} {
		if status, ok := rootEndStatus(partial, id, verb); ok {
			t.Fatalf("accepted partial record %q with status %q", partial, status)
		}
	}
	response := "kernel noise\nPDS1|END|host-123_|exec|0\n"
	if status, ok := rootEndStatus(response, id, verb); !ok || status != "0" {
		t.Fatalf("complete status = %q, %v", status, ok)
	}
	response = "noise PDS1|END|host-123_|exec|7\n"
	if status, ok := rootEndStatus(response, id, verb); !ok || status != "7" {
		t.Fatalf("failure status = %q, %v", status, ok)
	}
}
