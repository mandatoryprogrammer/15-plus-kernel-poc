package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type pullResult struct {
	Size   int64
	SHA256 string
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.n += int64(n)
	return n, err
}

func validatePullPaths(remote, local string) error {
	if strings.ContainsAny(remote, "\x00\r\n") || !path.IsAbs(remote) || remote == "/" || path.Clean(remote) != remote {
		return errors.New("pull remote path must be a clean absolute file path")
	}
	if strings.ContainsRune(local, 0) || !filepath.IsAbs(local) || local == string(filepath.Separator) || filepath.Clean(local) != local {
		return errors.New("pull local path must be a clean absolute file path")
	}
	return nil
}

func requireAbsentPullDestination(local string) error {
	if _, err := os.Lstat(local); err == nil {
		return fmt.Errorf("pull local destination already exists: %s", local)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect pull local destination: %w", err)
	}
	parent := filepath.Dir(local)
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect pull local directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("pull local directory is not a real directory: %s", parent)
	}
	return nil
}

// receiveVerifiedPull materializes two identical reads and publishes the local
// result with link(2), which cannot replace a destination created concurrently.
// Every failure removes the private partial file and leaves the destination
// absent.
func receiveVerifiedPull(ctx context.Context, remote, local string, read func(context.Context, io.Writer) error) (pullResult, error) {
	var result pullResult
	if err := validatePullPaths(remote, local); err != nil {
		return result, err
	}
	if err := requireAbsentPullDestination(local); err != nil {
		return result, err
	}

	tmp, err := os.CreateTemp(filepath.Dir(local), "."+filepath.Base(local)+".pull-*")
	if err != nil {
		return result, fmt.Errorf("create private pull destination: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
	}()
	if err = tmp.Chmod(0600); err != nil {
		return result, fmt.Errorf("protect private pull destination: %w", err)
	}

	firstHash := sha256.New()
	if err = read(ctx, io.MultiWriter(tmp, firstHash)); err != nil {
		return result, fmt.Errorf("read remote file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return result, fmt.Errorf("sync private pull destination: %w", err)
	}
	info, err := tmp.Stat()
	if err != nil {
		return result, fmt.Errorf("inspect private pull destination: %w", err)
	}
	if !info.Mode().IsRegular() {
		return result, errors.New("private pull destination is not a regular file")
	}
	result.Size = info.Size()
	result.SHA256 = hex.EncodeToString(firstHash.Sum(nil))
	if err = tmp.Close(); err != nil {
		return result, fmt.Errorf("close private pull destination: %w", err)
	}
	closed = true

	secondHash := sha256.New()
	second := &countingWriter{w: secondHash}
	if err = read(ctx, second); err != nil {
		return result, fmt.Errorf("verify remote file: %w", err)
	}
	if second.n != result.Size || hex.EncodeToString(secondHash.Sum(nil)) != result.SHA256 {
		return result, errors.New("remote file changed between verified reads")
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = requireAbsentPullDestination(local); err != nil {
		return result, err
	}
	if err = os.Link(tmpPath, local); err != nil {
		return result, fmt.Errorf("publish pull destination without replacement: %w", err)
	}
	published := true
	defer func() {
		if published {
			_ = os.Remove(local)
		}
	}()
	if err = verifyFile(ctx, local, asset{Role: "pull", Size: result.Size, SHA256: result.SHA256}); err != nil {
		return result, fmt.Errorf("verify published pull destination: %w", err)
	}
	directory, err := os.Open(filepath.Dir(local))
	if err != nil {
		return result, fmt.Errorf("open pull destination directory: %w", err)
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil {
		return result, fmt.Errorf("sync pull destination directory: %w", err)
	}
	if closeErr != nil {
		return result, fmt.Errorf("close pull destination directory: %w", closeErr)
	}
	published = false
	return result, nil
}

func smartPull(ctx context.Context, c *cache, remote, local string) error {
	if err := validatePullPaths(remote, local); err != nil {
		return err
	}
	// Reject a local preimage before any device transition. The receiver repeats
	// this check immediately before its atomic publication.
	if err := requireAbsentPullDestination(local); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Preparing read-only pull %s -> %s\n", remote, local)
	if err := ensureShellEnvironment(ctx, c, false, []string{"/bin/bash", "-c", ":"}); err != nil {
		return err
	}
	return withDeviceLock(c, func() error {
		access, err := loadAccess(ctx, c)
		if err != nil {
			return err
		}
		read := func(readCtx context.Context, output io.Writer) error {
			return runSSH(readCtx, access, false, []string{"/bin/cat", remote}, nil, output, c.out)
		}
		pullCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
		defer cancel()
		stop := heartbeat(c.out, "Reading remote file twice for exact verification", 2*time.Hour)
		result, err := receiveVerifiedPull(pullCtx, remote, local, read)
		stop()
		if err != nil {
			return err
		}
		fmt.Fprintf(c.out, "Pulled remote=%s local=%s bytes=%d sha256=%s verified_reads=2\n", remote, local, result.Size, result.SHA256)
		return nil
	})
}
