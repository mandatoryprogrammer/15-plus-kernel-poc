package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// serialStartSSH resumes the exact post-payload portion of bootLocked after a
// congested serial payload transfer. Payload destinations are first created
// with their final executable mode so authenticated SSH can replace their
// contents without changing the inode mode.
func serialStartSSH(ctx context.Context, c *cache) error {
	return withDeviceLock(c, func() (err error) {
		access, err := loadAccess(ctx, c)
		if err != nil {
			return err
		}
		probe, err := findProbeSerial(ctx)
		if err != nil {
			return err
		}
		serial, err := startSerial(c, probe)
		if err != nil {
			return err
		}
		defer serial.Close()
		if _, err = rootRequest(ctx, serial, "ping"); err != nil {
			return fmt.Errorf("root service: %w", err)
		}
		additions, err := loadPayloadAdditions(c)
		if err != nil {
			return err
		}
		for _, addition := range additions {
			a := asset{Role: "payload", SHA256: addition.SHA256, Size: addition.Size}
			if err = verifyFile(ctx, c.object(a), a); err != nil {
				return err
			}
			if err = installFile(ctx, c, serial, addition.Destination, nil, digest(nil), 0755); err != nil {
				return fmt.Errorf("prepare SSH payload destination %s: %w", addition.Destination, err)
			}
			fmt.Fprintf(c.out, "Prepared executable payload destination %s\n", addition.Destination)
		}
		if probeSSH(ctx, c) == nil {
			fmt.Fprintln(c.out, "Authenticated SSH is already running")
			return nil
		}
		if err = installSSHAccess(ctx, c, serial, access); err != nil {
			return err
		}
		timeoutPreimage, timeoutErr := setTemporaryRestoredHostTimeout(ctx, serial)
		if timeoutErr != nil {
			return timeoutErr
		}
		fmt.Fprintf(c.out, "Temporary restored host start timeout: preimage=%s postimage=%d inverse=restore-after-command-or-bounded-operation\n", timeoutPreimage.description(), restoredHostStartTimeoutSeconds)
		defer func() {
			if err == nil {
				return
			}
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cleanupErr := restoreTemporaryRestoredHostTimeout(cleanupCtx, serial, timeoutPreimage)
			err = errors.Join(err, cleanupErr)
		}()
		launch := `/bin/bash -c '/usr/local/bin/restored_external >/dev/console 2>&1 </dev/null & /usr/local/sbin/sshd -t -f /private/etc/ssh/sshd_config -h /private/etc/ssh/ssh_host_ed25519_key && /usr/local/sbin/sshd -f /private/etc/ssh/sshd_config -h /private/etc/ssh/ssh_host_ed25519_key'`
		response, err := rootExec(ctx, serial, launch)
		if err != nil {
			return fmt.Errorf("start SSH environment: %w: %s", err, response)
		}
		fmt.Fprintln(c.out, "Resumed the upstream SSH environment; waiting for authentication")
		return connectSSH(ctx, c, false, []string{"printf", "kernel-poc-ready"}, true, &timeoutPreimage)
	})
}

// installPayloadOverSSH transfers configured, already-verified payload
// additions through the repository's authenticated usbmux SSH channel and
// requires an exact byte-for-byte readback before returning.
func installPayloadOverSSH(ctx context.Context, c *cache) error {
	return withDeviceLock(c, func() error {
		additions, err := loadPayloadAdditions(c)
		if err != nil {
			return err
		}
		if len(additions) == 0 {
			return fmt.Errorf("no payload additions are configured")
		}
		access, err := loadAccess(ctx, c)
		if err != nil {
			return err
		}
		for _, addition := range additions {
			a := asset{Role: "payload", SHA256: addition.SHA256, Size: addition.Size}
			if err = verifyFile(ctx, c.object(a), a); err != nil {
				return err
			}
			body, readErr := os.ReadFile(c.object(a))
			if readErr != nil {
				return readErr
			}
			fmt.Fprintf(c.out, "Uploading %s over authenticated SSH (%d bytes)\n", addition.Destination, len(body))
			uploadCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			script := "exec /bin/cat > " + shellQuote(addition.Destination)
			err = runSSH(uploadCtx, access, false, []string{"/bin/bash", "-c", script}, bytes.NewReader(body), io.Discard, os.Stderr)
			cancel()
			if err != nil {
				return fmt.Errorf("upload %s over SSH: %w", addition.Destination, err)
			}
			var readback bytes.Buffer
			readCtx, readCancel := context.WithTimeout(ctx, 2*time.Minute)
			err = runSSH(readCtx, access, false, []string{"/bin/cat", addition.Destination}, nil, &readback, os.Stderr)
			readCancel()
			if err != nil {
				return fmt.Errorf("read back %s over SSH: %w", addition.Destination, err)
			}
			if !bytes.Equal(readback.Bytes(), body) {
				return fmt.Errorf("payload readback mismatch for %s: got %d bytes, want %d", addition.Destination, readback.Len(), len(body))
			}
			checkCtx, checkCancel := context.WithTimeout(ctx, 8*time.Second)
			err = runSSH(checkCtx, access, false, []string{"/bin/bash", "-c", "test -x " + shellQuote(addition.Destination)}, nil, io.Discard, os.Stderr)
			checkCancel()
			if err != nil {
				return fmt.Errorf("payload destination is not executable: %s: %w", addition.Destination, err)
			}
			fmt.Fprintf(c.out, "Verified exact executable payload readback %s (%s)\n", addition.Destination, addition.SHA256)
		}
		return nil
	})
}
