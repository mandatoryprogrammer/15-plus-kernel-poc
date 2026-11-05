package main

import (
	"context"
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

func TestRestoredHostTimeoutLeaseFreshBootHandoff(t *testing.T) {
	if lease := restoredHostTimeoutLeaseFromContext(context.Background()); lease != nil {
		t.Fatal("plain context unexpectedly contains a restored host timeout lease")
	}
	ctx, lease := withRestoredHostTimeoutLease(context.Background())
	if got := restoredHostTimeoutLeaseFromContext(ctx); got != lease {
		t.Fatal("context did not retain the exact restored host timeout lease")
	}
	if _, active := lease.current(); active {
		t.Fatal("new restored host timeout lease is active")
	}
	preimage := restoredHostTimeoutPreimage{Value: "0", Present: true}
	if err := lease.bind(preimage, restoredHostTimeoutFreshBootOrigin); err != nil {
		t.Fatalf("bind exact preimage: %v", err)
	}
	got, active := lease.current()
	if !active || got != preimage {
		t.Fatalf("active lease=%t preimage=%#v, want %#v", active, got, preimage)
	}
	if lease.source() != restoredHostTimeoutFreshBootOrigin {
		t.Fatalf("lease origin=%q, want %q", lease.source(), restoredHostTimeoutFreshBootOrigin)
	}
	if err := lease.bind(restoredHostTimeoutPreimage{}, restoredHostTimeoutReusedOrigin); err == nil {
		t.Fatal("active lease accepted a second preimage")
	}
	lease.clear()
	if _, active = lease.current(); active {
		t.Fatal("cleared restored host timeout lease remained active")
	}
	if lease.source() != "" {
		t.Fatalf("cleared lease retained origin %q", lease.source())
	}
}

func TestRestoredHostTimeoutLeaseReusedEnvironmentAcquisition(t *testing.T) {
	lease := &restoredHostTimeoutLease{}
	readCount := 0
	setCount := 0
	restoreCount := 0
	read := func() (string, bool, error) {
		readCount++
		if readCount == 1 {
			return "", false, nil
		}
		return "60", true, nil
	}
	set := func() error {
		setCount++
		return nil
	}
	restore := func(restoredHostTimeoutPreimage) error {
		restoreCount++
		return nil
	}
	if err := acquireRestoredHostTimeoutLease(lease, read, set, restore); err != nil {
		t.Fatalf("acquire reused-environment lease: %v", err)
	}
	preimage, active := lease.current()
	if !active || preimage != (restoredHostTimeoutPreimage{}) {
		t.Fatalf("active=%t preimage=%#v, want exact absence", active, preimage)
	}
	if lease.source() != restoredHostTimeoutReusedOrigin {
		t.Fatalf("lease origin=%q, want %q", lease.source(), restoredHostTimeoutReusedOrigin)
	}
	if readCount != 2 || setCount != 1 || restoreCount != 0 {
		t.Fatalf("read=%d set=%d restore=%d, want 2/1/0", readCount, setCount, restoreCount)
	}
	if err := acquireRestoredHostTimeoutLease(lease, read, set, restore); err != nil {
		t.Fatalf("reacquire active lease: %v", err)
	}
	if readCount != 2 || setCount != 1 || restoreCount != 0 {
		t.Fatalf("active reacquisition performed I/O: read=%d set=%d restore=%d", readCount, setCount, restoreCount)
	}
}

func TestRestoredHostTimeoutLeaseReusedEnvironmentFailureRestoresPreimage(t *testing.T) {
	lease := &restoredHostTimeoutLease{}
	readCount := 0
	preimage := restoredHostTimeoutPreimage{Value: "0", Present: true}
	read := func() (string, bool, error) {
		readCount++
		if readCount == 1 {
			return preimage.Value, preimage.Present, nil
		}
		return "10", true, nil
	}
	var restored restoredHostTimeoutPreimage
	err := acquireRestoredHostTimeoutLease(lease, read, func() error { return nil }, func(got restoredHostTimeoutPreimage) error {
		restored = got
		return nil
	})
	if err == nil {
		t.Fatal("invalid reused-environment postimage was accepted")
	}
	if restored != preimage {
		t.Fatalf("restored preimage=%#v, want %#v", restored, preimage)
	}
	if _, active := lease.current(); active {
		t.Fatal("lease remained active after verified inverse")
	}
}
