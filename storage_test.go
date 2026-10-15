package main

import (
	"strings"
	"testing"
)

const validAPFSInventory = `+-o System@1  <class AppleAPFSVolume, id 0x1>
  |   "Role" = ("System")
  |   "BSD Name" = "disk1s1"
+-o Data@2  <class AppleAPFSVolume, id 0x2>
  |   "Role" = ("Data")
  |   "BSD Name" = "disk1s2"
+-o xART@3  <class AppleAPFSVolume, id 0x3>
  |   "Role" = ("xART")
  |   "BSD Name" = "disk1s3"
+-o Baseband@4  <class AppleAPFSVolume, id 0x4>
  |   "Role" = ("Baseband data")
  |   "BSD Name" = "disk1s4"
+-o Installer@5  <class AppleAPFSVolume, id 0x5>
  |   "Role" = ("Installer")
  |   "BSD Name" = "disk1s5"
+-o Hardware@6  <class AppleAPFSVolume, id 0x6>
  |   "Role" = ("Hardware")
  |   "BSD Name" = "disk1s6"
+-o Preboot@7  <class AppleAPFSVolume, id 0x7>
  |   "Role" = ("Preboot")
  |   "BSD Name" = "disk1s7"
+-o Update@8  <class AppleAPFSVolume, id 0x8>
  |   "Role" = ("Update")
  |   "BSD Name" = "disk1s8"
`

func TestInternalAPFSRoleDiscoveryAndMountVerification(t *testing.T) {
	inventory, err := parseInternalVolumes([]byte(validAPFSInventory))
	if err != nil || len(inventory.Volumes) != 8 || len(inventory.SkippedRoles) != 0 {
		t.Fatalf("valid role inventory: inventory=%+v err=%v", inventory, err)
	}
	volumes := inventory.Volumes
	var mounts strings.Builder
	for _, volume := range volumes {
		mounts.WriteString(volume.Device + " on " + volume.MountPoint + " (apfs, local, nosuid, read-only, journaled, noatime, nobrowse)\n")
	}
	if err = verifyInternalMounts([]byte(mounts.String()), volumes); err != nil {
		t.Fatal(err)
	}
	if err = verifyInternalMounts([]byte(strings.Replace(mounts.String(), "read-only, ", "", 1)), volumes); err == nil {
		t.Fatal("writable mount accepted")
	}
	if err = verifyInternalMounts([]byte(strings.Replace(mounts.String(), "nobrowse", "browse", 1)), volumes); err == nil {
		t.Fatal("mount without nobrowse accepted")
	}
	if err = verifyInternalMounts([]byte(mounts.String()), volumes[:3]); err != nil {
		t.Fatalf("verified subset rejected: %v", err)
	}
}

func TestInternalAPFSRoleDiscoveryFailsClosed(t *testing.T) {
	tests := map[string]string{
		"duplicate role":   strings.Replace(validAPFSInventory, `("Update")`, `("Preboot")`, 1),
		"duplicate device": strings.Replace(validAPFSInventory, `"disk1s8"`, `"disk1s7"`, 1),
		"device injection": strings.Replace(validAPFSInventory, `"disk1s8"`, `"disk1s8;reboot"`, 1),
		"orphan device":    "  |   \"BSD Name\" = \"disk1s1\"\n" + validAPFSInventory,
		"partial pair":     validAPFSInventory + "+-o Partial@9  <class AppleAPFSVolume, id 0x9>\n  |   \"Role\" = (\"System\")\n",
		"missing header":   strings.Replace(validAPFSInventory, "+-o System@1  <class AppleAPFSVolume, id 0x1>\n", "", 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseInternalVolumes([]byte(input)); err == nil {
				t.Fatal("invalid APFS inventory accepted")
			}
		})
	}
}

func TestInternalAPFSRoleDiscoveryAcceptsSupportedSubset(t *testing.T) {
	value := strings.Replace(validAPFSInventory, "+-o Installer@5  <class AppleAPFSVolume, id 0x5>\n  |   \"Role\" = (\"Installer\")\n  |   \"BSD Name\" = \"disk1s5\"\n", "", 1)
	inventory, err := parseInternalVolumes([]byte(value))
	if err != nil || len(inventory.Volumes) != 7 {
		t.Fatalf("supported role subset: inventory=%+v err=%v", inventory, err)
	}
	for _, volume := range inventory.Volumes {
		if volume.Role == "Installer" {
			t.Fatal("absent role appeared in parsed inventory")
		}
	}
}

func TestInternalAPFSRoleDiscoveryUsesRecordBoundaries(t *testing.T) {
	value := strings.Replace(validAPFSInventory,
		`  |   "Role" = ("System")
  |   "BSD Name" = "disk1s1"`,
		`  |   "BSD Name" = "disk1s1"
  |   "Unrelated" = "value"
  |   "Role" = ("System")`, 1)
	inventory, err := parseInternalVolumes([]byte(value))
	if err != nil || len(inventory.Volumes) != 8 || inventory.Volumes[5].Role != "System" {
		t.Fatalf("reordered properties: inventory=%+v err=%v", inventory, err)
	}
}

func TestInternalAPFSRoleDiscoverySkipsUnknownRole(t *testing.T) {
	value := strings.Replace(validAPFSInventory, `("Update")`, `("Diagnostics")`, 1)
	inventory, err := parseInternalVolumes([]byte(value))
	if err != nil || len(inventory.Volumes) != 7 || len(inventory.SkippedRoles) != 1 || inventory.SkippedRoles[0] != "Diagnostics" {
		t.Fatalf("unknown role handling: inventory=%+v err=%v", inventory, err)
	}
}

func TestInternalMountFailureReason(t *testing.T) {
	if got := internalMountFailureReason("Data", "mount_apfs: Operation not permitted"); got != "encrypted volume keys are unavailable in this tethered session" {
		t.Fatalf("Data mount reason = %q", got)
	}
	if got := internalMountFailureReason("System", "SEP is not booted"); got != "encrypted volume keys are unavailable in this tethered session" {
		t.Fatalf("SEP mount reason = %q", got)
	}
	if got := internalMountFailureReason("System", "I/O error"); got != "mount rejected by the running kernel" {
		t.Fatalf("generic mount reason = %q", got)
	}
}
