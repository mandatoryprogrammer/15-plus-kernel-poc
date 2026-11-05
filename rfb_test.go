package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func serveRFBTest(t *testing.T, connection net.Conn, afterInit func(net.Conn)) {
	t.Helper()
	defer connection.Close()
	if _, err := connection.Write([]byte("RFB 003.008\n")); err != nil {
		t.Error(err)
		return
	}
	version := make([]byte, 12)
	if _, err := io.ReadFull(connection, version); err != nil || string(version) != "RFB 003.008\n" {
		t.Errorf("client version=%q err=%v", version, err)
		return
	}
	if _, err := connection.Write([]byte{1, 1}); err != nil {
		t.Error(err)
		return
	}
	selection := make([]byte, 1)
	if _, err := io.ReadFull(connection, selection); err != nil || selection[0] != 1 {
		t.Errorf("security selection=%v err=%v", selection, err)
		return
	}
	if _, err := connection.Write([]byte{0, 0, 0, 0}); err != nil {
		t.Error(err)
		return
	}
	shared := make([]byte, 1)
	if _, err := io.ReadFull(connection, shared); err != nil || shared[0] != 1 {
		t.Errorf("shared=%v err=%v", shared, err)
		return
	}
	init := make([]byte, 24)
	binary.BigEndian.PutUint16(init[0:2], 2)
	binary.BigEndian.PutUint16(init[2:4], 1)
	init[4], init[5], init[7] = 32, 24, 1
	binary.BigEndian.PutUint16(init[8:10], 255)
	binary.BigEndian.PutUint16(init[10:12], 255)
	binary.BigEndian.PutUint16(init[12:14], 255)
	init[14], init[15], init[16] = 16, 8, 0
	binary.BigEndian.PutUint32(init[20:24], 4)
	if _, err := connection.Write(append(init, []byte("test")...)); err != nil {
		t.Error(err)
		return
	}
	configuration := make([]byte, 28)
	if _, err := io.ReadFull(connection, configuration); err != nil {
		t.Error(err)
		return
	}
	if configuration[0] != 0 || configuration[20] != 2 {
		t.Errorf("configuration=%v", configuration)
		return
	}
	afterInit(connection)
}

func TestRFBCaptureAndPointerInput(t *testing.T) {
	client, server := net.Pipe()
	go serveRFBTest(t, server, func(connection net.Conn) {
		request := make([]byte, 10)
		if _, err := io.ReadFull(connection, request); err != nil || request[0] != 3 {
			t.Errorf("frame request=%v err=%v", request, err)
			return
		}
		update := []byte{
			0, 0, 0, 1,
			0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0,
			0, 0, 255, 0,
			0, 0, 0, 0,
		}
		_, _ = connection.Write(update)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	session, err := openRFB(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	frame, stats, err := session.capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = session.close()
	if session.width != 2 || session.height != 1 || session.name != "test" || stats.Pixels != 2 || stats.NonBlackPixels != 1 {
		t.Fatalf("session=%+v stats=%+v", session, stats)
	}
	if got := frame.RGBAAt(0, 0); got.R != 255 || got.G != 0 || got.B != 0 || got.A != 255 {
		t.Fatalf("first pixel=%v", got)
	}

	client, server = net.Pipe()
	events := make(chan []byte, 1)
	go serveRFBTest(t, server, func(connection net.Conn) {
		body := make([]byte, 12)
		_, _ = io.ReadFull(connection, body)
		events <- body
	})
	session, err = openRFB(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if err = session.tap(ctx, 1, 0); err != nil {
		t.Fatal(err)
	}
	_ = session.close()
	body := <-events
	if body[0] != 5 || body[1] != 1 || body[6] != 5 || body[7] != 0 || binary.BigEndian.Uint16(body[2:4]) != 1 {
		t.Fatalf("pointer events=%v", body)
	}
}
