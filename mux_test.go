package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMuxConnectSelectsExactUSBIdentity(t *testing.T) {
	dir, err := os.MkdirTemp("", "mux")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "mux")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requests := make(chan map[string]any, 2)
	go func() {
		for _, reply := range []string{`<key>DeviceList</key><array><dict><key>DeviceID</key><integer>42</integer><key>Properties</key><dict><key>SerialNumber</key><string>test-board</string><key>ConnectionType</key><string>USB</string></dict></dict></array>`, `<key>Number</key><integer>0</integer>`} {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			func() {
				defer c.Close()
				h := make([]byte, 16)
				if _, e := io.ReadFull(c, h); e != nil {
					return
				}
				b := make([]byte, int(binary.LittleEndian.Uint32(h))-16)
				io.ReadFull(c, b)
				v, _ := decodePlist(b)
				requests <- v
				body := []byte(`<plist><dict>` + reply + `</dict></plist>`)
				binary.LittleEndian.PutUint32(h, uint32(len(body)+16))
				c.Write(append(h, body...))
			}()
		}
	}()
	c, err := muxConnect(t.Context(), socket, "test-board", 22)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if req := <-requests; req["MessageType"] != "ListDevices" {
		t.Fatal(req)
	}
	if req := <-requests; req["DeviceID"] != uint64(42) || req["PortNumber"] != uint64(22<<8) {
		t.Fatal(req)
	}
}

func TestMuxRequestCancellationClosesSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "mux-cancel")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "mux")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan error, 1)
	requestRead := make(chan struct{})
	go func() {
		c, acceptErr := listener.Accept()
		if acceptErr != nil {
			closed <- acceptErr
			return
		}
		defer c.Close()
		header := make([]byte, 16)
		if _, readErr := io.ReadFull(c, header); readErr != nil {
			closed <- readErr
			return
		}
		body := make([]byte, int(binary.LittleEndian.Uint32(header))-16)
		if _, readErr := io.ReadFull(c, body); readErr != nil {
			closed <- readErr
			return
		}
		close(requestRead)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		one := make([]byte, 1)
		_, readErr := c.Read(one)
		closed <- readErr
	}()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, _, requestErr := muxRequest(ctx, socket, `<key>MessageType</key><string>ListDevices</string>`)
		done <- requestErr
	}()
	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("server did not receive request")
	}
	cancel()
	select {
	case requestErr := <-done:
		if requestErr == nil {
			t.Fatal("canceled request succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled request did not return")
	}
	select {
	case readErr := <-closed:
		if readErr != io.EOF {
			t.Fatalf("USB mux socket was not closed: %v", readErr)
		}
	case <-time.After(time.Second):
		t.Fatal("USB mux socket cleanup stalled")
	}
}
