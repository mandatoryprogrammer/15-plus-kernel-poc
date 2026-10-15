package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
)

const (
	ansiReset  = "\x1b[0m"
	ansiRed    = "\x1b[1;31m"
	ansiGreen  = "\x1b[1;32m"
	ansiYellow = "\x1b[1;33m"
	ansiCyan   = "\x1b[1;36m"
	ansiBlue   = "\x1b[1;34m"
)

type colorWriter struct {
	out       io.Writer
	enabled   bool
	lineStart bool
	color     string
	mu        sync.Mutex
}

func terminalColorEnabled(file *os.File) bool {
	if file == nil || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func terminalOutput(file *os.File) io.Writer {
	return &colorWriter{out: file, enabled: terminalColorEnabled(file), lineStart: true}
}

func progressColor(line string) string {
	lower := strings.ToLower(strings.TrimSpace(line))
	switch {
	case strings.HasPrefix(lower, "error:"):
		return ansiRed
	case strings.Contains(lower, "retry"), strings.Contains(lower, "did not settle"), strings.Contains(lower, "not ready"), strings.Contains(lower, "changed usb availability"):
		return ansiYellow
	case strings.Contains(lower, " ready after "), strings.HasPrefix(lower, "verified "), strings.HasPrefix(lower, "mounted "), strings.HasPrefix(lower, "installed "), strings.HasPrefix(lower, "uploaded "), strings.HasPrefix(lower, "supported "), strings.Contains(lower, "passed live protocol"), strings.Contains(lower, "verified ("):
		return ansiGreen
	case strings.Contains(lower, "environment found"), strings.HasPrefix(lower, "ssh closed"):
		return ansiGreen
	case strings.HasPrefix(lower, "waiting for "), strings.HasPrefix(lower, "verifying "), strings.HasPrefix(lower, "checking "), strings.HasPrefix(lower, "warm-resetting "), strings.HasPrefix(lower, "matching "), strings.HasPrefix(lower, "opening "), strings.HasPrefix(lower, "xnu "), strings.HasPrefix(lower, "target reset "), strings.HasPrefix(lower, "recovery policy "), strings.HasPrefix(lower, "fetching "):
		return ansiCyan
	case strings.HasPrefix(lower, "kernel arguments:"), strings.Contains(lower, "elapsed"):
		return ansiBlue
	default:
		return ""
	}
}

func (w *colorWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.enabled {
		return w.out.Write(p)
	}
	original := len(p)
	for len(p) != 0 {
		end := bytes.IndexByte(p, '\n')
		if end < 0 {
			end = len(p)
		} else {
			end++
		}
		segment := p[:end]
		if w.lineStart {
			w.color = progressColor(string(segment))
			if w.color != "" {
				if _, err := io.WriteString(w.out, w.color); err != nil {
					return 0, err
				}
			}
			w.lineStart = false
		}
		if _, err := w.out.Write(segment); err != nil {
			return 0, err
		}
		if segment[len(segment)-1] == '\n' {
			if w.color != "" {
				if _, err := io.WriteString(w.out, ansiReset); err != nil {
					return 0, err
				}
			}
			w.color = ""
			w.lineStart = true
		}
		p = p[end:]
	}
	return original, nil
}
