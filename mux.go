package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

func plistValue(d *xml.Decoder, start xml.StartElement) (any, error) {
	switch start.Name.Local {
	case "string", "key", "integer":
		var s string
		if err := d.DecodeElement(&s, &start); err != nil {
			return nil, err
		}
		if start.Name.Local == "integer" {
			return strconv.ParseUint(s, 10, 64)
		}
		return s, nil
	case "true", "false":
		if err := d.Skip(); err != nil {
			return nil, err
		}
		return start.Name.Local == "true", nil
	case "dict":
		m := map[string]any{}
		var key string
		for {
			token, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := token.(type) {
			case xml.EndElement:
				return m, nil
			case xml.StartElement:
				v, err := plistValue(d, t)
				if err != nil {
					return nil, err
				}
				if t.Name.Local == "key" {
					key = v.(string)
				} else {
					if key == "" {
						return nil, errors.New("plist value without key")
					}
					if _, ok := m[key]; ok {
						return nil, errors.New("duplicate plist key")
					}
					m[key] = v
					key = ""
				}
			}
		}
	case "array":
		var a []any
		for {
			token, err := d.Token()
			if err != nil {
				return nil, err
			}
			switch t := token.(type) {
			case xml.EndElement:
				return a, nil
			case xml.StartElement:
				v, err := plistValue(d, t)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
		}
	default:
		var discard string
		if err := d.DecodeElement(&discard, &start); err != nil {
			return nil, err
		}
		return discard, nil
	}
}

func decodePlist(b []byte) (map[string]any, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	for {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		if start, ok := token.(xml.StartElement); ok && start.Name.Local == "dict" {
			v, err := plistValue(d, start)
			if err != nil {
				return nil, err
			}
			return v.(map[string]any), nil
		}
	}
}

func muxRequest(ctx context.Context, socket, body string) (net.Conn, map[string]any, error) {
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, nil, err
	}
	ok := false
	defer func() {
		if !ok {
			connection.Close()
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	connection.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	payload := []byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>ClientVersionString</key><string>kernel-poc</string><key>ProgName</key><string>kernel-poc</string><key>kLibUSBMuxVersion</key><integer>3</integer>` + body + `</dict></plist>`)
	frame := make([]byte, 16, len(payload)+16)
	binary.LittleEndian.PutUint32(frame, uint32(len(payload)+16))
	binary.LittleEndian.PutUint32(frame[4:], 1)
	binary.LittleEndian.PutUint32(frame[8:], 8)
	binary.LittleEndian.PutUint32(frame[12:], 1)
	frame = append(frame, payload...)
	if _, err := io.Copy(connection, bytes.NewReader(frame)); err != nil {
		return nil, nil, err
	}
	header := make([]byte, 16)
	if _, err := io.ReadFull(connection, header); err != nil {
		return nil, nil, err
	}
	length := binary.LittleEndian.Uint32(header)
	if length < 16 || length > 1<<20 || binary.LittleEndian.Uint32(header[4:]) != 1 || binary.LittleEndian.Uint32(header[8:]) != 8 || binary.LittleEndian.Uint32(header[12:]) != 1 {
		return nil, nil, errors.New("invalid usbmux response header")
	}
	response := make([]byte, int(length)-16)
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, nil, err
	}
	result, err := decodePlist(response)
	if err != nil {
		return nil, nil, err
	}
	connection.SetDeadline(time.Time{})
	ok = true
	return connection, result, nil
}

func muxConnect(ctx context.Context, socket, serial string, port uint16) (net.Conn, error) {
	// Ask stock macOS usbmuxd for the USB-attached device whose serial encodes
	// the verified ECID, then upgrade the same socket to a raw device-port
	// stream.  SSH runs directly over this connection without a proxy process or
	// occupied localhost port.
	c, list, err := muxRequest(ctx, socket, `<key>MessageType</key><string>ListDevices</string>`)
	if err != nil {
		return nil, err
	}
	c.Close()
	var id uint64
	matches := 0
	devices, _ := list["DeviceList"].([]any)
	for _, v := range devices {
		row, _ := v.(map[string]any)
		props, _ := row["Properties"].(map[string]any)
		if props["SerialNumber"] == serial && props["ConnectionType"] == "USB" {
			id, _ = row["DeviceID"].(uint64)
			matches++
		}
	}
	if matches != 1 || id == 0 {
		return nil, fmt.Errorf("expected one USB device with the verified board identity; found %d", matches)
	}
	wirePort := port<<8 | port>>8
	c, result, err := muxRequest(ctx, socket, fmt.Sprintf(`<key>MessageType</key><string>Connect</string><key>DeviceID</key><integer>%d</integer><key>PortNumber</key><integer>%d</integer>`, id, wirePort))
	if err != nil {
		return nil, err
	}
	code, ok := result["Number"].(uint64)
	if !ok || code != 0 {
		c.Close()
		return nil, fmt.Errorf("device port %d unavailable (usbmux %v)", port, result["Number"])
	}
	return c, nil
}
