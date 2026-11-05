package main

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestSSHCommandQuotesEveryArgument(t *testing.T) {
	got := remoteCommand([]string{"printf", "%s", "a'$(anything); `command`"})
	want := "'printf' '%s' 'a'\"'\"'$(anything); `command`'"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSSHSessionResultPrefersOwnedContextTerminal(t *testing.T) {
	sessionErr := errors.New("remote process exited with signal KILL")
	if got := sshSessionResult(context.Background(), sessionErr); !errors.Is(got, sessionErr) {
		t.Fatalf("live context result=%v, want session error", got)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := sshSessionResult(cancelled, sessionErr); !errors.Is(got, context.Canceled) {
		t.Fatalf("cancelled context result=%v, want context canceled", got)
	}

	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if got := sshSessionResult(deadline, sessionErr); !errors.Is(got, context.DeadlineExceeded) {
		t.Fatalf("expired context result=%v, want deadline exceeded", got)
	}
}

func TestSSHAccessIsGeneratedLocallyAndReusable(t *testing.T) {
	c, err := newCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.out = io.Discard
	first, err := ensureSSHAccess(context.Background(), c, 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	if first.material.ECID != 0x1234 || first.signer == nil || first.host == nil {
		t.Fatal("generated access is incomplete")
	}
	second, err := ensureSSHAccess(context.Background(), c, 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	if first.material.Client.SHA256 != second.material.Client.SHA256 || first.material.HostPrivate.SHA256 != second.material.HostPrivate.SHA256 {
		t.Fatal("same board did not reuse locally generated access")
	}
	third, err := ensureSSHAccess(context.Background(), c, 0x5678)
	if err != nil {
		t.Fatal(err)
	}
	if third.material.ECID != 0x5678 || third.material.Client.SHA256 == first.material.Client.SHA256 || third.material.HostPrivate.SHA256 == first.material.HostPrivate.SHA256 {
		t.Fatal("new board identity did not receive fresh local access")
	}
}
