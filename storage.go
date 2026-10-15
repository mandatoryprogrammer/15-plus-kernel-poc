package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const apfsRoleQuery = `/usr/sbin/ioreg -l -r -c AppleAPFSVolume | /usr/bin/sed -n -e '/^+-o /p' -e '/"Role" = /p' -e '/"BSD Name" = /p'`

type internalVolume struct {
	Role       string
	Device     string
	MountPoint string
}

type internalVolumeInventory struct {
	Volumes      []internalVolume
	SkippedRoles []string
}

var internalVolumeMounts = map[string]string{
	"System":        "/mnt/iphone/system",
	"Data":          "/mnt/iphone/data",
	"xART":          "/mnt/iphone/xart",
	"Baseband data": "/mnt/iphone/baseband",
	"Installer":     "/mnt/iphone/installer",
	"Hardware":      "/mnt/iphone/hardware",
	"Preboot":       "/mnt/iphone/preboot",
	"Update":        "/mnt/iphone/update",
}

var bsdVolumeName = regexp.MustCompile(`^disk[0-9]+s[0-9]+$`)

func parseIORegString(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, `("`) && strings.HasSuffix(value, `")`) {
		value = value[1 : len(value)-1]
	}
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' || strings.Contains(value[1:len(value)-1], `\`) {
		return "", false
	}
	return value[1 : len(value)-1], true
}

func parseInternalVolumes(value []byte) (internalVolumeInventory, error) {
	// Group properties by their registry object instead of relying on the order
	// in which IOKit prints a dictionary. Unknown roles are reported and skipped:
	// only roles with an explicit safe mount point can reach the root command.
	if len(value) == 0 || len(value) > 16<<10 || strings.IndexByte(string(value), 0) >= 0 {
		return internalVolumeInventory{}, errors.New("APFS role inventory is empty or exceeds its bound")
	}
	const recordClass, roleField, deviceField = `<class AppleAPFSVolume,`, `"Role" = `, `"BSD Name" = `
	type registryRecord struct {
		role, device       string
		hasRole, hasDevice bool
	}
	var record registryRecord
	started := false
	volumes := make(map[string]internalVolume, len(internalVolumeMounts))
	roles := make(map[string]bool, len(internalVolumeMounts))
	devices := make(map[string]bool, len(internalVolumeMounts))
	var skipped []string
	finishRecord := func() error {
		if !started {
			return nil
		}
		if !record.hasRole || !record.hasDevice {
			return errors.New("APFS registry record is missing its role or BSD device")
		}
		if roles[record.role] {
			return fmt.Errorf("APFS role %q is duplicated", record.role)
		}
		device := "/dev/" + record.device
		if devices[device] {
			return fmt.Errorf("APFS device %q is duplicated", device)
		}
		roles[record.role], devices[device] = true, true
		mountPoint, supported := internalVolumeMounts[record.role]
		if !supported {
			skipped = append(skipped, record.role)
			return nil
		}
		volumes[record.role] = internalVolume{Role: record.role, Device: device, MountPoint: mountPoint}
		return nil
	}
	scanner := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(string(value), "\r", "")))
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(raw, "+-o ") && strings.Contains(raw, recordClass):
			if err := finishRecord(); err != nil {
				return internalVolumeInventory{}, err
			}
			record, started = registryRecord{}, true
		case strings.Contains(line, roleField):
			if !started || record.hasRole {
				return internalVolumeInventory{}, errors.New("APFS role appeared outside one unique registry record")
			}
			role, ok := parseIORegString(line[strings.Index(line, roleField)+len(roleField):])
			if !ok {
				return internalVolumeInventory{}, fmt.Errorf("malformed APFS role line %q", line)
			}
			record.role, record.hasRole = role, true
		case strings.Contains(line, deviceField):
			if !started || record.hasDevice {
				return internalVolumeInventory{}, errors.New("APFS device appeared outside one unique registry record")
			}
			name, ok := parseIORegString(line[strings.Index(line, deviceField)+len(deviceField):])
			if !ok || !bsdVolumeName.MatchString(name) {
				return internalVolumeInventory{}, fmt.Errorf("invalid APFS BSD device %q", name)
			}
			record.device, record.hasDevice = name, true
		}
	}
	if err := scanner.Err(); err != nil {
		return internalVolumeInventory{}, err
	}
	if err := finishRecord(); err != nil {
		return internalVolumeInventory{}, err
	}
	if len(volumes) == 0 {
		return internalVolumeInventory{}, errors.New("APFS role inventory contains no supported volumes")
	}
	result := make([]internalVolume, 0, len(volumes))
	for _, volume := range volumes {
		result = append(result, volume)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].MountPoint < result[j].MountPoint })
	sort.Strings(skipped)
	return internalVolumeInventory{Volumes: result, SkippedRoles: skipped}, nil
}

func verifyInternalMounts(value []byte, volumes []internalVolume) error {
	lines := strings.Split(strings.ReplaceAll(string(value), "\r", ""), "\n")
	for _, volume := range volumes {
		prefix := volume.Device + " on " + volume.MountPoint + " (apfs, "
		matches := 0
		for _, line := range lines {
			if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, ")") {
				continue
			}
			matches++
			options := make(map[string]bool)
			for _, option := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, prefix), ")"), ",") {
				options[strings.TrimSpace(option)] = true
			}
			if !options["local"] || !options["read-only"] || !options["nobrowse"] {
				return fmt.Errorf("APFS role %s is not mounted with the required read-only options: %s", volume.Role, line)
			}
		}
		if matches != 1 {
			return fmt.Errorf("APFS role %s has %d verified mounts at %s", volume.Role, matches, volume.MountPoint)
		}
	}
	return nil
}

func internalMountFailureReason(role, message string) string {
	if strings.Contains(message, "Failed to unwrap metadata crypto state") || strings.Contains(message, "SEP is not booted") ||
		(role == "Data" && strings.Contains(message, "Operation not permitted")) {
		return "encrypted volume keys are unavailable in this tethered session"
	}
	if strings.Contains(message, "Operation not permitted") {
		return "volume is unavailable in this tethered session"
	}
	return "mount rejected by the running kernel"
}

func mountInternalStorage(ctx context.Context, c *cache, serial *serialCapture) error {
	// Mount every internal volume read-only and nobrowse. Then read the mount
	// table because a successful mount_apfs exit does not confirm the options.
	inventory, err := rootExec(ctx, serial, apfsRoleQuery)
	if err != nil {
		return fmt.Errorf("discover internal APFS roles: %w: %s", err, inventory)
	}
	parsed, err := parseInternalVolumes(inventory)
	if err != nil {
		return err
	}
	for _, role := range parsed.SkippedRoles {
		fmt.Fprintf(c.out, "Skipped APFS role %q: no safe mount path is defined\n", role)
	}
	volumes := parsed.Volumes
	mounted := make([]internalVolume, 0, len(volumes))
	for _, volume := range volumes {
		command := "/bin/mkdir -p " + volume.MountPoint + " && /sbin/mount_apfs -o rdonly,nobrowse " + volume.Device + " " + volume.MountPoint
		response, mountErr := rootExec(ctx, serial, command)
		if mountErr != nil {
			reason := internalMountFailureReason(volume.Role, string(response))
			fmt.Fprintf(c.out, "Skipped %-13s %s: %s\n", volume.Role, volume.Device, reason)
			continue
		}
		mounted = append(mounted, volume)
		fmt.Fprintf(c.out, "Mounted %-13s %s at %s (read-only)\n", volume.Role, volume.Device, volume.MountPoint)
	}
	if len(mounted) == 0 {
		return errors.New("none of the discovered internal APFS volumes could be mounted")
	}
	mounts, err := rootExec(ctx, serial, "/sbin/mount")
	if err != nil {
		return fmt.Errorf("read internal APFS mount table: %w: %s", err, mounts)
	}
	if err = verifyInternalMounts(mounts, mounted); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Verified %d of %d internal APFS volumes under /mnt/iphone\n", len(mounted), len(volumes))
	return nil
}
