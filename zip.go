package main

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"
)

func safeMember(name string) bool {
	return name != "" && path.Clean(name) == name && !strings.HasPrefix(name, "/") && !strings.HasPrefix(name, "../") && !strings.ContainsAny(name, "\\\x00") && name != ".."
}

// archive/zip reads only the central directory and selected member. The complete
// member is hash checked, so an untrusted or changed ZIP index cannot admit data.
type remoteZIP struct {
	ctx         context.Context
	client      *http.Client
	url         string
	size        int64
	mu          sync.Mutex
	block       []byte
	blockOffset int64
}

func (r *remoteZIP) ReadAt(b []byte, offset int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if offset < 0 {
		return 0, errors.New("negative ZIP offset")
	}
	n := 0
	for n < len(b) {
		if offset >= r.size {
			return n, io.EOF
		}
		if len(r.block) == 0 || offset < r.blockOffset || offset >= r.blockOffset+int64(len(r.block)) {
			r.blockOffset = (offset / (1 << 20)) * (1 << 20)
			r.block = make([]byte, min(1<<20, r.size-r.blockOffset))
			if _, err := r.fetchRange(r.block, r.blockOffset); err != nil {
				r.block = nil
				return n, err
			}
		}
		count := copy(b[n:], r.block[offset-r.blockOffset:])
		n += count
		offset += int64(count)
	}
	return n, nil
}

func (r *remoteZIP) fetchRange(b []byte, offset int64) (int, error) {
	if offset < 0 || offset >= r.size {
		return 0, io.EOF
	}
	size := int64(len(b))
	if size > r.size-offset {
		size = r.size - offset
	}
	if size == 0 {
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+size-1))
	response, err := r.client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	expected := fmt.Sprintf("bytes %d-%d/%d", offset, offset+size-1, r.size)
	if response.StatusCode != 206 || response.Header.Get("Content-Range") != expected || response.ContentLength != size {
		return 0, fmt.Errorf("invalid range response: HTTP %d, %q", response.StatusCode, response.Header.Get("Content-Range"))
	}
	n, err := io.ReadFull(response.Body, b[:size])
	if err != nil {
		return n, err
	}
	if n < len(b) {
		return n, io.EOF
	}
	return n, nil
}

func (c *cache) fetchMember(ctx context.Context, a asset) (string, error) {
	fmt.Fprintf(c.out, "Fetching %s from Apple firmware (%d bytes)\n", a.Role, a.Size)
	z, err := zip.NewReader(&remoteZIP{ctx: ctx, client: c.client, url: a.URL, size: a.ArchiveSize}, a.ArchiveSize)
	if err != nil {
		return "", fmt.Errorf("firmware ZIP index: %w", err)
	}
	var selected *zip.File
	for _, f := range z.File {
		if f.Name == a.Member {
			if selected != nil {
				return "", errors.New("duplicate firmware ZIP member")
			}
			selected = f
		}
	}
	if selected == nil {
		return "", fmt.Errorf("firmware member missing: %s", a.Member)
	}
	if selected.UncompressedSize64 != uint64(a.Size) || !selected.Mode().IsRegular() {
		return "", errors.New("firmware ZIP member geometry or type changed")
	}
	r, err := selected.Open()
	if err != nil {
		return "", err
	}
	defer r.Close()
	return c.store(ctx, a, r)
}
