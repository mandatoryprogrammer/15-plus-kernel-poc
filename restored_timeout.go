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

type restoredHostTimeoutPreimage struct {
	Value   string
	Present bool
}

func restoredHostTimeoutSetCommand() string {
	return fmt.Sprintf("/usr/sbin/nvram %s=%d", restoredHostTimeoutKey, restoredHostStartTimeoutSeconds)
}

func restoredHostTimeoutDeleteCommand() string {
	return "/bin/bash -c '/usr/sbin/nvram -d " + restoredHostTimeoutKey + " 2>/dev/null || true'"
}

func (preimage restoredHostTimeoutPreimage) validate() error {
	if !preimage.Present {
		if preimage.Value != "" {
			return errors.New("absent restored host timeout preimage has a value")
		}
		return nil
	}
	if preimage.Value == "" {
		return errors.New("present restored host timeout preimage is empty")
	}
	for _, character := range preimage.Value {
		if character < '0' || character > '9' {
			return fmt.Errorf("restored host timeout preimage %q is not an unsigned integer", preimage.Value)
		}
	}
	return nil
}

func (preimage restoredHostTimeoutPreimage) description() string {
	if !preimage.Present {
		return "absent"
	}
	return preimage.Value
}

func (preimage restoredHostTimeoutPreimage) restoreCommand() (string, error) {
	if err := preimage.validate(); err != nil {
		return "", err
	}
	if !preimage.Present {
		return restoredHostTimeoutDeleteCommand(), nil
	}
	return "/usr/sbin/nvram " + restoredHostTimeoutKey + "=" + preimage.Value, nil
}

func (preimage restoredHostTimeoutPreimage) matches(value string, present bool) bool {
	return preimage.Present == present && (!present || preimage.Value == value)
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

func restoreTemporaryRestoredHostTimeout(ctx context.Context, serial *serialCapture, preimage restoredHostTimeoutPreimage) error {
	command, err := preimage.restoreCommand()
	if err != nil {
		return err
	}
	if response, err := rootExec(ctx, serial, command); err != nil {
		return fmt.Errorf("restore temporary restored host timeout: %w: %s", err, response)
	}
	value, present, err := readRestoredHostTimeout(ctx, serial)
	if err != nil {
		return err
	}
	if !preimage.matches(value, present) {
		return fmt.Errorf("temporary restored host timeout inverse=%q present=%t, want %q", value, present, preimage.description())
	}
	return nil
}

func setTemporaryRestoredHostTimeout(ctx context.Context, serial *serialCapture) (restoredHostTimeoutPreimage, error) {
	value, present, err := readRestoredHostTimeout(ctx, serial)
	if err != nil {
		return restoredHostTimeoutPreimage{}, err
	}
	preimage := restoredHostTimeoutPreimage{Value: value, Present: present}
	if err = preimage.validate(); err != nil {
		return restoredHostTimeoutPreimage{}, err
	}
	response, err := rootExec(ctx, serial, restoredHostTimeoutSetCommand())
	if err != nil {
		return restoredHostTimeoutPreimage{}, fmt.Errorf("set temporary restored host timeout: %w: %s", err, response)
	}
	want := fmt.Sprint(restoredHostStartTimeoutSeconds)
	value, present, readbackErr := readRestoredHostTimeout(ctx, serial)
	if readbackErr == nil && present && value == want {
		return preimage, nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cleanupErr := restoreTemporaryRestoredHostTimeout(cleanupCtx, serial, preimage)
	if readbackErr != nil {
		return restoredHostTimeoutPreimage{}, errors.Join(fmt.Errorf("read temporary restored host timeout postimage: %w", readbackErr), cleanupErr)
	}
	return restoredHostTimeoutPreimage{}, errors.Join(fmt.Errorf("temporary restored host timeout postimage=%q present=%t, want %q", value, present, want), cleanupErr)
}
