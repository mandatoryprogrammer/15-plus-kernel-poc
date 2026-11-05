package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	restoredHostTimeoutKey          = "restored-host-timeout"
	restoredHostStartTimeoutSeconds = 60
)

func restoredHostTimeoutSetCommand() string {
	return fmt.Sprintf("/usr/sbin/nvram %s=%d", restoredHostTimeoutKey, restoredHostStartTimeoutSeconds)
}

func restoredHostTimeoutDeleteCommand() string {
	return "/bin/bash -c '/usr/sbin/nvram -d " + restoredHostTimeoutKey + " 2>/dev/null || true'"
}

func nvramListingValue(listing []byte, key string) (string, bool, error) {
	value := ""
	present := false
	for _, line := range strings.Split(strings.ReplaceAll(string(listing), "\r\n", "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != key {
			continue
		}
		if present {
			return "", false, fmt.Errorf("NVRAM listing contains duplicate %q entries", key)
		}
		value = strings.TrimSpace(line[len(fields[0]):])
		if value == "" {
			return "", false, fmt.Errorf("NVRAM listing contains empty %q value", key)
		}
		present = true
	}
	return value, present, nil
}

func readRestoredHostTimeout(ctx context.Context, serial *serialCapture) (string, bool, error) {
	listing, err := rootExec(ctx, serial, "/usr/sbin/nvram -p")
	if err != nil {
		return "", false, fmt.Errorf("read NVRAM listing: %w: %s", err, listing)
	}
	value, present, err := nvramListingValue(listing, restoredHostTimeoutKey)
	if err != nil {
		return "", false, err
	}
	return value, present, nil
}

func clearTemporaryRestoredHostTimeout(ctx context.Context, serial *serialCapture) error {
	if response, err := rootExec(ctx, serial, restoredHostTimeoutDeleteCommand()); err != nil {
		return fmt.Errorf("delete temporary restored host timeout: %w: %s", err, response)
	}
	value, present, err := readRestoredHostTimeout(ctx, serial)
	if err != nil {
		return err
	}
	if present {
		return fmt.Errorf("temporary restored host timeout remained %q after inverse", value)
	}
	return nil
}

func setTemporaryRestoredHostTimeout(ctx context.Context, serial *serialCapture) error {
	value, present, err := readRestoredHostTimeout(ctx, serial)
	if err != nil {
		return err
	}
	if present {
		return fmt.Errorf("temporary restored host timeout preimage is %q, want absent", value)
	}
	response, err := rootExec(ctx, serial, restoredHostTimeoutSetCommand())
	if err != nil {
		return fmt.Errorf("set temporary restored host timeout: %w: %s", err, response)
	}
	want := fmt.Sprint(restoredHostStartTimeoutSeconds)
	value, present, readbackErr := readRestoredHostTimeout(ctx, serial)
	if readbackErr == nil && present && value == want {
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cleanupErr := clearTemporaryRestoredHostTimeout(cleanupCtx, serial)
	if readbackErr != nil {
		return errors.Join(fmt.Errorf("read temporary restored host timeout postimage: %w", readbackErr), cleanupErr)
	}
	return errors.Join(fmt.Errorf("temporary restored host timeout postimage=%q present=%t, want %q", value, present, want), cleanupErr)
}
