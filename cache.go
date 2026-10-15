package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Immutable objects are addressed by verified SHA-256, never by a server filename.
type asset struct {
	Role          string `json:"role"`
	URL           string `json:"url,omitempty"`
	Member        string `json:"member,omitempty"`
	ArchiveSize   int64  `json:"archive_size,omitempty"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	Recipe        string `json:"recipe"`
	Compatibility string `json:"compatibility"`
}

type cache struct {
	root   string
	client *http.Client
	out    io.Writer
	mu     sync.Mutex
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var rolePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

func newCache(root string) (*cache, error) {
	for _, dir := range []string{"objects", "tmp", "logs", "private"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			return nil, err
		}
	}
	return &cache{root: root, out: terminalOutput(os.Stderr), client: &http.Client{
		Timeout: 2 * time.Hour,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return errors.New("refusing non-TLS redirect")
			}
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}}, nil
}

func (a asset) validate() error {
	if !rolePattern.MatchString(a.Role) || !digestPattern.MatchString(a.SHA256) || a.Size <= 0 {
		return fmt.Errorf("invalid asset identity for %q", a.Role)
	}
	if a.URL != "" {
		u, err := url.Parse(a.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return fmt.Errorf("invalid HTTPS source for %s", a.Role)
		}
	}
	if a.Member != "" && (a.URL == "" || a.ArchiveSize <= 0 || !safeMember(a.Member)) {
		return fmt.Errorf("invalid archive member for %s", a.Role)
	}
	return nil
}

func (c *cache) object(a asset) string { return filepath.Join(c.root, "objects", a.SHA256) }

func verifyFile(ctx context.Context, path string, a asset) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != a.Size {
		return fmt.Errorf("%s: size or file type mismatch", a.Role)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := copyContext(ctx, h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return fmt.Errorf("%s: SHA-256 mismatch", a.Role)
	}
	return nil
}

func copyContext(ctx context.Context, w io.Writer, r io.Reader) (int64, error) {
	buf := make([]byte, 256<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := r.Read(buf)
		if n > 0 {
			m, e := w.Write(buf[:n])
			total += int64(m)
			if e != nil {
				return total, e
			}
			if m != n {
				return total, io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

func (c *cache) resolve(ctx context.Context, a asset) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := a.validate(); err != nil {
		return "", err
	}
	path := c.object(a)
	if err := verifyFile(ctx, path, a); err == nil {
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if a.URL == "" {
		return "", fmt.Errorf("%s is not publicly downloadable; import it with: go run . assets import %s /path/to/file", a.Role, a.Role)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	stop := heartbeat(c.out, "Fetching "+a.Role, 2*time.Hour)
	defer stop()
	if a.Member != "" {
		return c.fetchMember(ctx, a)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Accept-Encoding", "identity")
	fmt.Fprintf(c.out, "Fetching %s (%d MiB, deadline 2h)\n", a.Role, a.Size>>20)
	response, err := c.client.Do(request)
	if err != nil {
		return "", fmt.Errorf("fetch %s: %w", a.Role, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s: HTTP %d", a.Role, response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != a.Size {
		return "", fmt.Errorf("fetch %s: wrong Content-Length", a.Role)
	}
	return c.store(ctx, a, response.Body)
}

func (c *cache) store(ctx context.Context, a asset, r io.Reader) (string, error) {
	if err := a.validate(); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Join(c.root, "tmp"), "object-")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	p := &byteProgress{out: c.out, name: a.Role, total: a.Size, start: time.Now(), last: time.Now()}
	n, err := copyContext(ctx, io.MultiWriter(f, h, p), io.LimitReader(r, a.Size+1))
	if err != nil {
		return "", err
	}
	if n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return "", fmt.Errorf("%s: downloaded/imported bytes do not match size and SHA-256", a.Role)
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	path := c.object(a)
	if err := os.Rename(f.Name(), path); err != nil {
		return "", err
	}
	fmt.Fprintf(c.out, "%s verified (%d bytes)\n", a.Role, n)
	return path, nil
}

type byteProgress struct {
	out            io.Writer
	name           string
	total, current int64
	start, last    time.Time
}

func (p *byteProgress) Write(b []byte) (int, error) {
	p.current += int64(len(b))
	if time.Since(p.last) >= 5*time.Second {
		fmt.Fprintf(p.out, "%s: %.1f%% (%d/%d MiB, %s elapsed)\n", p.name, float64(p.current)*100/float64(p.total), p.current>>20, p.total>>20, time.Since(p.start).Round(time.Second))
		p.last = time.Now()
	}
	return len(b), nil
}

func assetsCommand(ctx context.Context, c *cache, args []string) error {
	var manifest []asset
	if err := json.Unmarshal(assetManifest, &manifest); err != nil {
		return err
	}
	if len(args) == 1 && args[0] == "fetch" {
		for _, a := range manifest {
			if _, err := c.resolve(ctx, a); err != nil {
				return err
			}
		}
		fmt.Fprintf(c.out, "Public assets verified (%d roles).\n", len(manifest))
		return nil
	}
	if len(args) == 3 && args[0] == "import" {
		if args[1] == "bootstrap" {
			return importBootstrap(ctx, c, args[2])
		}
		for _, a := range manifest {
			if a.Role != args[1] {
				continue
			}
			f, err := os.Open(args[2])
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = c.store(ctx, a, f)
			return err
		}
		return fmt.Errorf("unknown asset role %q", args[1])
	}
	return errors.New("usage: assets fetch | assets import bootstrap DIRECTORY | assets import ROLE FILE")
}
