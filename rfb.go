package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

const uiRFBPort = 5900

type rfbSession struct {
	connection net.Conn
	width      uint16
	height     uint16
	name       string
}

type rfbFrameStats struct {
	Pixels         uint64
	NonBlackPixels uint64
	RGBA256        string
}

func rfbDeadline(ctx context.Context, maximum time.Duration) time.Time {
	deadline := time.Now().Add(maximum)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		return value
	}
	return deadline
}

func writeRFB(connection net.Conn, body []byte) error {
	_, err := io.Copy(connection, bytes.NewReader(body))
	return err
}

func openRFB(ctx context.Context, connection net.Conn) (*rfbSession, error) {
	ok := false
	defer func() {
		if !ok {
			connection.Close()
		}
	}()
	if err := connection.SetDeadline(rfbDeadline(ctx, 12*time.Second)); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	banner := make([]byte, 12)
	if _, err := io.ReadFull(connection, banner); err != nil {
		return nil, fmt.Errorf("read RFB version: %w", err)
	}
	version := string(banner)
	if version != "RFB 003.003\n" && version != "RFB 003.007\n" && version != "RFB 003.008\n" {
		return nil, fmt.Errorf("unsupported RFB version %q", banner)
	}
	clientVersion := []byte("RFB 003.008\n")
	if version == "RFB 003.003\n" {
		clientVersion = banner
	}
	if err := writeRFB(connection, clientVersion); err != nil {
		return nil, fmt.Errorf("write RFB version: %w", err)
	}
	if version == "RFB 003.003\n" {
		var security [4]byte
		if _, err := io.ReadFull(connection, security[:]); err != nil {
			return nil, fmt.Errorf("read RFB 3.3 security: %w", err)
		}
		if binary.BigEndian.Uint32(security[:]) != 1 {
			return nil, fmt.Errorf("RFB server requires unsupported 3.3 security type %d", binary.BigEndian.Uint32(security[:]))
		}
	} else {
		var count [1]byte
		if _, err := io.ReadFull(connection, count[:]); err != nil {
			return nil, fmt.Errorf("read RFB security count: %w", err)
		}
		if count[0] == 0 {
			return nil, errors.New("RFB server offered no security types")
		}
		types := make([]byte, count[0])
		if _, err := io.ReadFull(connection, types); err != nil {
			return nil, fmt.Errorf("read RFB security types: %w", err)
		}
		none := false
		for _, value := range types {
			if value == 1 {
				none = true
			}
		}
		if !none {
			return nil, fmt.Errorf("RFB server did not offer None security: %v", types)
		}
		if err := writeRFB(connection, []byte{1}); err != nil {
			return nil, fmt.Errorf("select RFB security: %w", err)
		}
		if version == "RFB 003.008\n" {
			var result [4]byte
			if _, err := io.ReadFull(connection, result[:]); err != nil {
				return nil, fmt.Errorf("read RFB security result: %w", err)
			}
			if binary.BigEndian.Uint32(result[:]) != 0 {
				return nil, fmt.Errorf("RFB security failed with status %d", binary.BigEndian.Uint32(result[:]))
			}
		}
	}
	if err := writeRFB(connection, []byte{1}); err != nil {
		return nil, fmt.Errorf("write RFB client init: %w", err)
	}
	var fixed [24]byte
	if _, err := io.ReadFull(connection, fixed[:]); err != nil {
		return nil, fmt.Errorf("read RFB server init: %w", err)
	}
	width := binary.BigEndian.Uint16(fixed[0:2])
	height := binary.BigEndian.Uint16(fixed[2:4])
	nameBytes := binary.BigEndian.Uint32(fixed[20:24])
	if width == 0 || height == 0 || uint64(width)*uint64(height) > 64<<20 || nameBytes > 4096 {
		return nil, fmt.Errorf("invalid RFB geometry %dx%d or name length %d", width, height, nameBytes)
	}
	name := make([]byte, nameBytes)
	if _, err := io.ReadFull(connection, name); err != nil {
		return nil, fmt.Errorf("read RFB desktop name: %w", err)
	}
	if bytes.IndexByte(name, 0) != -1 {
		return nil, errors.New("RFB desktop name contains NUL")
	}
	// Request a deterministic 32-bit little-endian true-color format: the wire
	// bytes for each pixel are blue, green, red, zero.
	pixelFormat := []byte{
		0, 0, 0, 0,
		32, 24, 0, 1,
		0, 255, 0, 255, 0, 255,
		16, 8, 0, 0, 0, 0,
	}
	if err := writeRFB(connection, pixelFormat); err != nil {
		return nil, fmt.Errorf("set RFB pixel format: %w", err)
	}
	// Advertise only raw rectangles so capture has one fail-closed decoder.
	if err := writeRFB(connection, []byte{2, 0, 0, 1, 0, 0, 0, 0}); err != nil {
		return nil, fmt.Errorf("set RFB encoding: %w", err)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return &rfbSession{connection: connection, width: width, height: height, name: string(name)}, nil
}

func (session *rfbSession) close() error {
	if session == nil || session.connection == nil {
		return nil
	}
	return session.connection.Close()
}

func (session *rfbSession) capture(ctx context.Context) (*image.RGBA, rfbFrameStats, error) {
	var stats rfbFrameStats
	if err := session.connection.SetDeadline(rfbDeadline(ctx, 12*time.Second)); err != nil {
		return nil, stats, err
	}
	request := []byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(request[6:8], session.width)
	binary.BigEndian.PutUint16(request[8:10], session.height)
	if err := writeRFB(session.connection, request); err != nil {
		return nil, stats, fmt.Errorf("request RFB frame: %w", err)
	}
	frame := image.NewRGBA(image.Rect(0, 0, int(session.width), int(session.height)))
	covered := make([]bool, int(session.width)*int(session.height))
	for messages := 0; messages < 32; messages++ {
		var message [1]byte
		if _, err := io.ReadFull(session.connection, message[:]); err != nil {
			return nil, stats, fmt.Errorf("read RFB server message: %w", err)
		}
		switch message[0] {
		case 0:
			var header [3]byte
			if _, err := io.ReadFull(session.connection, header[:]); err != nil {
				return nil, stats, fmt.Errorf("read RFB update header: %w", err)
			}
			rectangles := binary.BigEndian.Uint16(header[1:3])
			if rectangles == 0 || rectangles > 4096 {
				return nil, stats, fmt.Errorf("invalid RFB rectangle count %d", rectangles)
			}
			for rectangle := uint16(0); rectangle < rectangles; rectangle++ {
				var descriptor [12]byte
				if _, err := io.ReadFull(session.connection, descriptor[:]); err != nil {
					return nil, stats, fmt.Errorf("read RFB rectangle: %w", err)
				}
				x := binary.BigEndian.Uint16(descriptor[0:2])
				y := binary.BigEndian.Uint16(descriptor[2:4])
				width := binary.BigEndian.Uint16(descriptor[4:6])
				height := binary.BigEndian.Uint16(descriptor[6:8])
				encoding := int32(binary.BigEndian.Uint32(descriptor[8:12]))
				if encoding != 0 || width == 0 || height == 0 ||
					uint32(x)+uint32(width) > uint32(session.width) ||
					uint32(y)+uint32(height) > uint32(session.height) {
					return nil, stats, fmt.Errorf("unsupported RFB rectangle x=%d y=%d width=%d height=%d encoding=%d", x, y, width, height, encoding)
				}
				pixels := make([]byte, int(width)*int(height)*4)
				if _, err := io.ReadFull(session.connection, pixels); err != nil {
					return nil, stats, fmt.Errorf("read RFB raw rectangle: %w", err)
				}
				for row := 0; row < int(height); row++ {
					for column := 0; column < int(width); column++ {
						source := (row*int(width) + column) * 4
						destination := frame.PixOffset(int(x)+column, int(y)+row)
						frame.Pix[destination+0] = pixels[source+2]
						frame.Pix[destination+1] = pixels[source+1]
						frame.Pix[destination+2] = pixels[source+0]
						frame.Pix[destination+3] = 255
						covered[(int(y)+row)*int(session.width)+int(x)+column] = true
					}
				}
			}
			for _, present := range covered {
				if !present {
					return nil, stats, errors.New("RFB non-incremental update did not cover the complete frame")
				}
			}
			stats.Pixels = uint64(session.width) * uint64(session.height)
			for offset := 0; offset < len(frame.Pix); offset += 4 {
				if frame.Pix[offset] != 0 || frame.Pix[offset+1] != 0 || frame.Pix[offset+2] != 0 {
					stats.NonBlackPixels++
				}
			}
			hash := sha256.Sum256(frame.Pix)
			stats.RGBA256 = hex.EncodeToString(hash[:])
			return frame, stats, nil
		case 2:
			// Bell has no body.
		case 3:
			var header [7]byte
			if _, err := io.ReadFull(session.connection, header[:]); err != nil {
				return nil, stats, fmt.Errorf("read RFB clipboard header: %w", err)
			}
			length := binary.BigEndian.Uint32(header[3:7])
			if length > 1<<20 {
				return nil, stats, errors.New("RFB clipboard message is too large")
			}
			if _, err := io.CopyN(io.Discard, session.connection, int64(length)); err != nil {
				return nil, stats, fmt.Errorf("read RFB clipboard body: %w", err)
			}
		default:
			return nil, stats, fmt.Errorf("unsupported RFB server message %d", message[0])
		}
	}
	return nil, stats, errors.New("RFB frame did not arrive within 32 messages")
}

func (session *rfbSession) tap(ctx context.Context, x, y uint16) error {
	if x >= session.width || y >= session.height {
		return fmt.Errorf("RFB tap %d,%d is outside %dx%d", x, y, session.width, session.height)
	}
	if err := session.connection.SetDeadline(rfbDeadline(ctx, 5*time.Second)); err != nil {
		return err
	}
	event := []byte{5, 1, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(event[2:4], x)
	binary.BigEndian.PutUint16(event[4:6], y)
	if err := writeRFB(session.connection, event); err != nil {
		return fmt.Errorf("write RFB pointer down: %w", err)
	}
	event[1] = 0
	if err := writeRFB(session.connection, event); err != nil {
		return fmt.Errorf("write RFB pointer up: %w", err)
	}
	return nil
}

func connectUIRFB(ctx context.Context, c *cache) (*rfbSession, error) {
	access, err := loadAccess(ctx, c)
	if err != nil {
		return nil, err
	}
	serial := fmt.Sprintf("00008120-%016X", access.material.ECID)
	connection, err := muxConnect(ctx, "/var/run/usbmuxd", serial, uiRFBPort)
	if err != nil {
		return nil, err
	}
	return openRFB(ctx, connection)
}

func captureUIFrame(ctx context.Context, c *cache) error {
	session, err := connectUIRFB(ctx, c)
	if err != nil {
		return err
	}
	defer session.close()
	frame, stats, err := session.capture(ctx)
	if err != nil {
		return err
	}
	name := filepath.Join(c.root, "private", "ui-frame-latest.png")
	temporary, err := os.CreateTemp(filepath.Dir(name), "ui-frame-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err = temporary.Chmod(0600); err == nil {
		err = png.Encode(temporary, frame)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(temporaryName, name); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Captured RFB frame %dx%d name=%q pixels=%d nonblack=%d rgba_sha256=%s path=%s\n", session.width, session.height, session.name, stats.Pixels, stats.NonBlackPixels, stats.RGBA256, name)
	return nil
}

func tapUIFrame(ctx context.Context, c *cache, coordinates []string) error {
	if len(coordinates) != 2 {
		return errors.New("usage: ui tap X Y")
	}
	x, err := strconv.ParseUint(coordinates[0], 10, 16)
	if err != nil {
		return errors.New("ui tap X must be an unsigned 16-bit integer")
	}
	y, err := strconv.ParseUint(coordinates[1], 10, 16)
	if err != nil {
		return errors.New("ui tap Y must be an unsigned 16-bit integer")
	}
	session, err := connectUIRFB(ctx, c)
	if err != nil {
		return err
	}
	defer session.close()
	if err = session.tap(ctx, uint16(x), uint16(y)); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "Sent RFB pointer down/up at %d,%d within %dx%d name=%q\n", x, y, session.width, session.height, session.name)
	return nil
}
