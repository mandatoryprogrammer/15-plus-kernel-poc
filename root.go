package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

var errRootRequestTimeout = errors.New("root request timed out")

// rootRequest is the bounded bootstrap RPC used before networking exists.  Its
// records are aligned for the target's console parser, tagged with a unique ID,
// and recovered from a log because kernel diagnostics share the same UART.
func rootRequest(ctx context.Context, s *serialCapture, command string) ([]byte, error) {
	id := fmt.Sprintf("host-%x", time.Now().UnixNano())
	request := func() []byte { return []byte("PDS1|REQ|" + id + "|" + command + "~") }
	for len(request())%4 != 0 {
		id += "_"
	}
	start, err := s.log.Stat()
	if err != nil {
		return nil, err
	}
	if err = s.writeAll(ctx, request()); err != nil {
		return nil, err
	}
	if err = s.writeAll(ctx, []byte("~")); err != nil {
		return nil, err
	}
	deadline := time.NewTimer(25 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	started, flushed := time.Now(), false
	var response string
	verb := strings.SplitN(command, "|", 2)[0]
	var endStatus string
	for {
		if command == "ping" && !flushed && time.Since(started) >= 2*time.Second {
			if err = s.writeAll(ctx, []byte("~~")); err != nil {
				return nil, err
			}
			flushed = true
		}
		b, readErr := os.ReadFile(s.log.Name())
		if readErr != nil {
			return nil, readErr
		}
		if int64(len(b)) < start.Size() {
			return nil, errors.New("serial log shrank during root request")
		}
		response = strings.ReplaceAll(string(b[start.Size():]), "\r", "")
		if status, complete := rootEndStatus(response, id, verb); complete {
			endStatus = status
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errRootRequestTimeout
		case <-tick.C:
		}
	}
	prefix := "PDS1|DATA|" + id + "|"
	var data []byte
	for _, line := range strings.Split(response, "\n") {
		at := strings.Index(line, prefix)
		if at < 0 {
			continue
		}
		fields := strings.SplitN(line[at:], "|", 5)
		if len(fields) != 5 {
			continue
		}
		// Kernel diagnostics share the early console and can interrupt a DATA
		// record. Decode the complete leading hex bytes; END remains the
		// authoritative command status, and callers never depend on diagnostic
		// DATA being complete after a successful operation.
		chunk := leadingHexBytes(fields[4])
		if chunk == "" {
			continue
		}
		decoded, decodeErr := hex.DecodeString(chunk)
		if decodeErr != nil {
			return nil, fmt.Errorf("decode root response: %w", decodeErr)
		}
		data = append(data, decoded...)
	}
	if endStatus != "0" {
		return data, fmt.Errorf("root command failed: %s", response)
	}
	time.Sleep(20 * time.Millisecond)
	return data, nil
}

// rootEndStatus recognizes only a complete newline-terminated record. The
// serial capture goroutine may append a record in several host writes, so an
// An END prefix alone does not complete the request.
func rootEndStatus(response, id, verb string) (string, bool) {
	prefix := "PDS1|END|" + id + "|" + verb + "|"
	for len(response) > 0 {
		newline := strings.IndexByte(response, '\n')
		if newline < 0 {
			return "", false
		}
		line := response[:newline]
		response = response[newline+1:]
		at := strings.Index(line, prefix)
		if at < 0 {
			continue
		}
		status := strings.TrimSpace(line[at+len(prefix):])
		if status != "" && !strings.Contains(status, "|") {
			return status, true
		}
	}
	return "", false
}

func leadingHexBytes(value string) string {
	end := 0
	for end < len(value) {
		c := value[end]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			break
		}
		end++
	}
	end &^= 1
	return value[:end]
}

func rootExec(ctx context.Context, s *serialCapture, command string) ([]byte, error) {
	// Hex encoding keeps the outer pipe-delimited protocol unambiguous.  The
	// device service passes the decoded command to its fixed shell executor.
	return rootRequest(ctx, s, "exec|"+hex.EncodeToString([]byte(command)))
}
