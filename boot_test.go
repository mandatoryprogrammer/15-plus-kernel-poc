package main

import (
	"encoding/json"
	"testing"
)

func TestIBECStageTransitionFence(t *testing.T) {
	want := device{ECID: 0x1234, IBFL: 0x25}
	for _, test := range []struct {
		name    string
		current device
		ready   bool
		fails   bool
	}{
		{name: "same initial stage", current: device{ECID: 0x1234, IBFL: 0x25}},
		{name: "matching runtime stage", current: device{ECID: 0x1234, IBFL: 0x24}, ready: true},
		{name: "different board", current: device{ECID: 0x5678, IBFL: 0x24}, fails: true},
		{name: "unexpected stage", current: device{ECID: 0x1234, IBFL: 0x23}, fails: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ready, err := classifyIBECStage(want, test.current)
			if ready != test.ready || (err != nil) != test.fails {
				t.Fatalf("ready=%v err=%v", ready, err)
			}
		})
	}
}

func TestFirmwareSequenceComesFromProfileManifest(t *testing.T) {
	images := map[string][]byte{}
	var manifest bootSequenceManifest
	if err := json.Unmarshal(bootSequenceJSON, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, row := range manifest.Firmware {
		images[row.Role] = []byte{1}
	}
	steps, err := firmwareSequence(images)
	if err != nil || len(steps) != len(manifest.Firmware) {
		t.Fatalf("steps=%d err=%v", len(steps), err)
	}
	delete(images, manifest.Firmware[0].Role)
	if _, err = firmwareSequence(images); err == nil {
		t.Fatal("missing firmware role accepted")
	}
}
