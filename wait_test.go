package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitTransition(t *testing.T) {
	var output bytes.Buffer
	calls := 0
	err := waitFor(t.Context(), &output, "SSH", time.Second, time.Millisecond, func(context.Context) (bool, error) { calls++; return calls == 3, nil })
	if err != nil || calls != 3 {
		t.Fatalf("calls=%d: %v", calls, err)
	}
	if !bytes.Contains(output.Bytes(), []byte("remaining")) || !bytes.Contains(output.Bytes(), []byte("ready")) {
		t.Fatal(output.String())
	}
}

func TestWaitTimeoutAndCancel(t *testing.T) {
	var output bytes.Buffer
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := waitFor(ctx, &output, "Recovery", time.Second, time.Millisecond, func(context.Context) (bool, error) { t.Fatal("called after cancellation"); return false, nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	err = waitFor(t.Context(), &output, "SSH", 5*time.Millisecond, time.Millisecond, func(context.Context) (bool, error) { return false, errors.New("port unavailable") })
	if !errors.Is(err, context.DeadlineExceeded) || !bytes.Contains([]byte(err.Error()), []byte("port unavailable")) {
		t.Fatal(err)
	}
}
