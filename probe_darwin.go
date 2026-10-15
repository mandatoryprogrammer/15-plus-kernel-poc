//go:build darwin && arm64

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"
)

const probeVendor = 0x05ac
const probeProduct = 0x162c
const probeClockHz = 4_420_000
const probeMemoryCeiling = 0x400

func reducedProbeMemoryLimit(current, attempted int) int {
	if attempted <= 8 {
		return current
	}
	return min(current, max(8, (attempted/2)&^3))
}

func findProbeSerial(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := initNative(); err != nil {
		return "", err
	}
	var iterator uint32
	if code := native.services(0, native.matching("IOUSBDevice"), &iterator); code != 0 {
		return "", fmt.Errorf("probe enumeration: 0x%x", uint32(code))
	}
	defer native.releaseIO(iterator)
	var serials []string
	for service := native.next(iterator); service != 0; service = native.next(iterator) {
		vid, vok := ioNumber(service, "idVendor")
		pid, pok := ioNumber(service, "idProduct")
		if vok && pok && vid == probeVendor && pid == probeProduct {
			serial := ioString(service, "USB Serial Number")
			if serial != "" {
				serials = append(serials, serial)
			}
		}
		native.releaseIO(service)
	}
	if len(serials) != 1 {
		return "", fmt.Errorf("exactly one supported debug probe is required; found %d", len(serials))
	}
	return serials[0], nil
}

func findProbeUART(serial string) (string, error) {
	if err := initNative(); err != nil {
		return "", err
	}
	var iterator uint32
	if code := native.services(0, native.matching("IOSerialBSDClient"), &iterator); code != 0 {
		return "", fmt.Errorf("serial enumeration: 0x%x", uint32(code))
	}
	defer native.releaseIO(iterator)
	var ports []probeSerialPort
	for service := native.next(iterator); service != 0; service = native.next(iterator) {
		ports = append(ports, probeSerialPort{
			Base:    ioString(service, "IOTTYBaseName"),
			Device:  ioString(service, "IOTTYDevice"),
			Suffix:  ioString(service, "IOTTYSuffix"),
			Callout: ioString(service, "IOCalloutDevice"),
		})
		native.releaseIO(service)
	}
	return selectProbeUART(serial, ports)
}

type probeUSB struct {
	dev, intf unsafe.Pointer
	in, out   uint8
}

type probeSession struct {
	usb         *probeUSB
	next        uint32
	ports       accessPortMap
	memoryLimit int
}

type accessPortMap struct {
	Control, Router, Application uint32
}

// validateProbeDescriptor accepts firmware changes when the information reply
// keeps the required frame. Later clock, channel, DP/AP, topology, and memory
// operations check the behavior used during boot.
func validateProbeDescriptor(response []byte) error {
	if len(response) < 8 || len(response) > 256 {
		return fmt.Errorf("invalid probe information length %d", len(response))
	}
	meaningful := false
	for _, value := range response {
		if value != 0 && value != 0xff {
			meaningful = true
			break
		}
	}
	if !meaningful {
		return errors.New("probe information response is empty")
	}
	return nil
}

func accessPortRole(id uint32) string {
	// The high nibble is the implementation revision. Match the architectural
	// designer/class/type identity so a revised instance may move to another AP.
	switch id & 0x0fffffff {
	case 0x04770002:
		return "control"
	case 0x04760010:
		return "router"
	case 0x04770004:
		return "application"
	default:
		return ""
	}
}

func (s *probeSession) discoverAccessPorts(ctx context.Context) error {
	var found accessPortMap
	seen := map[string]bool{}
	for ap := uint32(0); ap < 16; ap++ {
		value, err := s.accessPort(ctx, ap, 0xfc)
		if err != nil || len(value) != 4 {
			continue
		}
		role := accessPortRole(binary.LittleEndian.Uint32(value))
		if role == "" {
			continue
		}
		if seen[role] {
			return fmt.Errorf("debug topology has duplicate %s access ports", role)
		}
		seen[role] = true
		switch role {
		case "control":
			found.Control = ap
		case "router":
			found.Router = ap
		case "application":
			found.Application = ap
		}
	}
	if !seen["control"] || !seen["router"] || !seen["application"] {
		return fmt.Errorf("debug topology is incomplete: control=%t router=%t application=%t", seen["control"], seen["router"], seen["application"])
	}
	s.ports = found
	return nil
}

func newProbeSession(ctx context.Context) (*probeSession, error) {
	u, err := openProbe(ctx)
	if err != nil {
		return nil, err
	}
	// Eight connection-management messages precede the first device request in
	// the wire protocol, so device request identifiers begin at nine.
	s := &probeSession{usb: u, next: 8, memoryLimit: probeMemoryCeiling}
	if err = s.request(ctx, 0x8001, nil, validateProbeDescriptor); err == nil {
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-timer.C:
		}
		timer.Stop()
	}
	if err == nil {
		err = s.message(ctx, "connected")
	}
	if err == nil {
		err = s.message(ctx, "hostid")
	}
	if err == nil {
		err = s.requestChannel(ctx, 0x8001, 1, nil, validateProbeDescriptor)
	}
	if err == nil {
		clock := make([]byte, 4)
		binary.LittleEndian.PutUint32(clock, probeClockHz)
		err = s.request(ctx, 0x8003, clock, nil)
	}
	if err != nil {
		u.Close()
		return nil, err
	}
	return s, nil
}

func (s *probeSession) selectTarget(ctx context.Context) error {
	steps := []struct {
		op      uint16
		channel byte
		payload []byte
	}{
		{0xc000, 0, messagePayload("ptarget")},
		{0xc000, 0, messagePayload("hostid")},
		// A zero value queries the clock selected during session setup without
		// changing it.
		{0x8003, 0, []byte{0, 0, 0, 0}},
		{0x800b, 0, []byte{0, 0, 0, 0}},
		{0x8007, 0, []byte{1, 0, 0x56, 2, 0, 0}},
		{0x8007, 0, []byte{2, 0, 0x56, 1}},
		{0x8007, 0, []byte{1, 0, 0x56, 2, 0, 0}},
		{0x8007, 0, []byte{2, 0, 0x56, 2}},
		{0x8007, 0, []byte{1, 0, 0x57, 2, 0, 0}},
		{0x8007, 0, []byte{1, 0, 0x55, 2, 0, 0}},
		{0x8007, 0, []byte{1, 0, 0x54, 2, 0, 0}},
		{0xc000, 0, messagePayload("swdackdelay")},
		{0x8002, 0, []byte{1}},
		{0xc000, 0, messagePayload("connected")},
		{0xc000, 0, messagePayload("hostid")},
		{0x9003, 2, nil},
		{0x9003, 2, nil},
		{0x8002, 0, []byte{0xff}},
	}
	for _, step := range steps {
		err := s.requestChannel(ctx, step.op, step.channel, step.payload, nil)
		if err != nil && step.op == 0x9003 {
			// Resetting the target link may tear down the operation before its
			// acknowledgement. Check the debug port next.
			err = nil
		}
		if err != nil {
			return fmt.Errorf("select target operation %04x: %w", step.op, err)
		}
	}
	if err := s.initializeDebugLink(ctx, true, map[uint32]int{5: 1, 6: 1, 7: 1, 8: 1, 9: 1, 10: 1, 11: 1, 12: 1, 13: 3, 14: 3, 15: 3}); err != nil {
		return err
	}
	if err := s.routeApplicationTarget(ctx); err != nil {
		return err
	}
	zero := make([]byte, 4)
	_, _ = s.debugPort(ctx, true, 4, zero)
	return s.request(ctx, 0x8009, nil, nil)
}

func (s *probeSession) routeApplicationTarget(ctx context.Context) error {
	// Reset the multidrop debug-port selection state before walking the eight
	// target bits exposed by the routing access port.
	toggle := func() {
		value := make([]byte, 4)
		binary.LittleEndian.PutUint32(value, 2)
		_, _ = s.debugPort(ctx, true, 8, value)
		_, _ = s.debugPort(ctx, false, 4, nil)
		binary.LittleEndian.PutUint32(value, 0)
		_, _ = s.debugPort(ctx, true, 8, value)
	}
	for attempt := 0; attempt < 2; attempt++ {
		toggle()
	}
	for attempt := 0; attempt < 2; attempt++ {
		_, _ = s.readMemory(ctx, s.ports.Control, 0xffffffff80000fe0, 4)
	}
	toggle()
	_, _ = s.accessPort(ctx, s.ports.Router, 0xfc)
	if err := s.message(ctx, "swdackdelay"); err != nil {
		return err
	}
	channelMessage := messagePayload("swdackdelay")
	channelMessage[2] = 10
	if err := s.requestChannel(ctx, 0xc001, 0, channelMessage, nil); err != nil {
		return err
	}
	for bit := uint32(1); bit <= 0x80; bit <<= 1 {
		value := make([]byte, 4)
		binary.LittleEndian.PutUint32(value, bit)
		// The routing port walks populated and unpopulated target slots. A slot
		// fault is expected. A memory read then checks the selected target.
		_ = s.writeAccessPort(ctx, s.ports.Router, 4, value)
		_, _ = s.accessPort(ctx, s.ports.Router, 8)
		_, _ = s.accessPort(ctx, s.ports.Router, 0)
	}
	if err := s.requestChannel(ctx, 0xc001, 0, messagePayload("swdackdelay"), nil); err != nil {
		return err
	}
	if err := s.requestChannel(ctx, 0x8001, 1, nil, nil); err != nil {
		return err
	}
	_, _ = s.debugPort(ctx, false, 4, nil)
	return nil
}

func (s *probeSession) attachSelectedTarget(ctx context.Context) error {
	for _, step := range []struct {
		op      uint16
		channel byte
		payload []byte
	}{
		{0xc000, 0, messagePayload("connected")},
		{0xc000, 0, messagePayload("hostid")},
		{0x9003, 2, nil},
		{0x8002, 0, []byte{0xff}},
	} {
		err := s.requestChannel(ctx, step.op, step.channel, step.payload, nil)
		if err != nil && step.op == 0x9003 {
			// Link reset can complete by removing the link before its reply.
			err = nil
		}
		if err != nil {
			return fmt.Errorf("attach selected target operation %04x: %w", step.op, err)
		}
	}
	if err := s.initializeDebugLink(ctx, false, map[uint32]int{5: 1, 6: 1, 7: 1, 8: 1, 9: 3, 10: 3, 11: 3, 12: 3, 13: 3, 14: 3, 15: 2}); err != nil {
		return err
	}
	return s.initializeControlAccess(ctx)
}

func (s *probeSession) initializeDebugLink(ctx context.Context, configureApplication bool, sparseAttempts map[uint32]int) error {
	_, _ = s.debugPort(ctx, false, 4, nil)
	_, _ = s.debugPort(ctx, false, 4, nil)
	if err := s.message(ctx, "swdovrrun"); err != nil {
		return err
	}
	value := make([]byte, 4)
	binary.LittleEndian.PutUint32(value, 0x10000000)
	// A running target can report a stale debug-port fault while accepting the
	// overrun configuration. Clear the status, then confirm access with the
	// first memory transaction below.
	_, _ = s.debugPort(ctx, true, 4, value)
	_, _ = s.debugPort(ctx, false, 4, nil)
	if err := s.discoverAccessPorts(ctx); err != nil {
		return err
	}
	for _, ap := range []uint32{s.ports.Control, s.ports.Router, s.ports.Application} {
		for _, address := range []uint64{0xfc, 0, 0xf8, 0xf4, 0} {
			_, _ = s.accessPort(ctx, ap, address)
		}
	}
	if configureApplication {
		if err := s.configureApplicationAccess(ctx); err != nil {
			return err
		}
	}
	for ap := uint32(5); ap <= 15; ap++ {
		attempts := sparseAttempts[ap]
		for attempt := 0; attempt < attempts; attempt++ {
			if _, accessErr := s.accessPort(ctx, ap, 0xfc); accessErr == nil {
				break
			}
		}
	}
	if configureApplication {
		// The target walk probes the complete application component table before
		// switching the multidrop route. These faulting reads are part of the
		// probe firmware's route-settling sequence.
		for attempt := 0; attempt < 37; attempt++ {
			_, _ = s.readMemory(ctx, s.ports.Control, 0xffffffff80000fe0, 4)
		}
	}
	return nil
}

func (s *probeSession) configureApplicationAccess(ctx context.Context) error {
	control := make([]byte, 4)
	const want = uint32(0x30806042)
	binary.LittleEndian.PutUint32(control, want)
	writeErr := s.writeAccessPortRetry(ctx, s.ports.Application, 0, control)
	actual, readErr := s.accessPort(ctx, s.ports.Application, 0)
	if len(actual) == 4 && binary.LittleEndian.Uint32(actual) == want {
		return nil
	}
	if writeErr != nil {
		return fmt.Errorf("configure application access: %w", writeErr)
	}
	if readErr != nil {
		return fmt.Errorf("verify application access control: %w", readErr)
	}
	return errors.New("application access control did not retain its required mode")
}

func (s *probeSession) configureApplicationAccessRetry(ctx context.Context, limit time.Duration) error {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	var last error
	for {
		if last = s.configureApplicationAccess(ctx); last == nil {
			return nil
		}
		_, _ = s.debugPort(ctx, false, 4, nil)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return last
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (s *probeSession) initializeControlAccess(ctx context.Context) error {
	for _, address := range []uint64{0x80000000, 0x80000004, 0x80000008, 0xfd300000} {
		if _, err := s.readWord(ctx, s.ports.Control, address); err != nil {
			return fmt.Errorf("initialize control access at 0x%x: %w", address, err)
		}
	}
	if _, err := s.accessPort(ctx, s.ports.Control, 0); err != nil {
		return err
	}
	control := make([]byte, 4)
	binary.LittleEndian.PutUint32(control, 0x80000052)
	if err := s.writeAccessPortRetry(ctx, s.ports.Control, 0, control); err != nil {
		return err
	}
	if _, err := s.readMemory(ctx, s.ports.Control, 0xfd300fd0, 32); err != nil {
		return err
	}
	if _, err := s.accessPort(ctx, s.ports.Control, 0); err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(control, 0x80000042)
	if err := s.writeAccessPortRetry(ctx, s.ports.Control, 0, control); err != nil {
		return err
	}
	return nil
}

func (s *probeSession) accessPort(ctx context.Context, ap uint32, address uint64) ([]byte, error) {
	payload := make([]byte, 20)
	binary.LittleEndian.PutUint32(payload, 0x18|ap<<24)
	binary.LittleEndian.PutUint64(payload[8:], address)
	binary.LittleEndian.PutUint32(payload[16:], 1)
	var result []byte
	err := s.request(ctx, 0x2001, payload, func(response []byte) error {
		if len(response) != 24 || binary.LittleEndian.Uint32(response)>>24 != ap || binary.LittleEndian.Uint32(response[4:])&0xf0000000 != 0xb0000000 || binary.LittleEndian.Uint64(response[8:]) != address || binary.LittleEndian.Uint32(response[16:]) != 1 {
			return fmt.Errorf("unexpected access port response: %x", response)
		}
		result = append([]byte{}, response[20:]...)
		if binary.LittleEndian.Uint32(response)&0x00ff0000 != 0 {
			return fmt.Errorf("access port fault response: %x", response)
		}
		return nil
	})
	return result, err
}

func (s *probeSession) writeAccessPort(ctx context.Context, ap uint32, address uint64, value []byte) error {
	if len(value) != 4 {
		return errors.New("access port writes require one word")
	}
	payload := make([]byte, 24)
	binary.LittleEndian.PutUint32(payload, 0x8018|ap<<24)
	binary.LittleEndian.PutUint64(payload[8:], address)
	binary.LittleEndian.PutUint32(payload[16:], 1)
	copy(payload[20:], value)
	return s.request(ctx, 0x2001, payload, func(response []byte) error {
		if len(response) != 20 || binary.LittleEndian.Uint32(response)>>24 != ap || binary.LittleEndian.Uint32(response)&0x00ff0000 != 0 || binary.LittleEndian.Uint32(response[4:])&0xf0000000 != 0xb0000000 || binary.LittleEndian.Uint64(response[8:]) != address || binary.LittleEndian.Uint32(response[16:]) != 1 {
			return fmt.Errorf("unexpected access port write response: %x", response)
		}
		return nil
	})
}

func (s *probeSession) writeAccessPortRetry(ctx context.Context, ap uint32, address uint64, value []byte) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = s.writeAccessPort(ctx, ap, address, value); err == nil {
			return nil
		}
	}
	return err
}

func (s *probeSession) readAccessPortRetry(ctx context.Context, ap uint32, address uint64) ([]byte, error) {
	var (
		value []byte
		err   error
	)
	for attempt := 0; attempt < 5; attempt++ {
		if value, err = s.accessPort(ctx, ap, address); err == nil {
			return value, nil
		}
	}
	return nil, err
}

func (s *probeSession) debugPort(ctx context.Context, write bool, address uint64, value []byte) ([]byte, error) {
	payload := make([]byte, 20)
	flags := uint32(1)
	if write {
		flags |= 0x8000
		if len(value) != 4 {
			return nil, errors.New("debug port writes require one word")
		}
		payload = append(payload, value...)
	}
	binary.LittleEndian.PutUint32(payload, flags)
	binary.LittleEndian.PutUint64(payload[8:], address)
	binary.LittleEndian.PutUint32(payload[16:], 1)
	var result []byte
	err := s.request(ctx, 0x2000, payload, func(response []byte) error {
		if write {
			if len(response) != 20 || binary.LittleEndian.Uint32(response)&0x00ff0000 != 0 || binary.LittleEndian.Uint32(response[4:])&0xf0000000 != 0xb0000000 || binary.LittleEndian.Uint64(response[8:]) != address || binary.LittleEndian.Uint32(response[16:]) != 1 {
				return fmt.Errorf("unexpected debug port write response: %x", response)
			}
			return nil
		}
		if len(response) != 24 {
			return fmt.Errorf("unexpected debug port read response: %x", response)
		}
		result = append([]byte{}, response[20:]...)
		return nil
	})
	return result, err
}

func (s *probeSession) Close() error { return s.usb.Close() }

func (s *probeSession) exchangeChannel(ctx context.Context, operation uint16, channel byte, payload []byte) ([]byte, uint16, error) {
	if len(payload) > 0xffff {
		return nil, 0, errors.New("probe payload is too large")
	}
	s.next++
	if s.next > 63 {
		s.next = 1
	}
	request := make([]byte, 8+len(payload))
	binary.LittleEndian.PutUint16(request, operation)
	binary.LittleEndian.PutUint16(request[2:], uint16(len(payload)))
	request[6] = byte(s.next)
	request[7] = channel
	copy(request[8:], payload)
	response, err := s.usb.transact(ctx, request)
	if err != nil {
		return nil, 0, err
	}
	if len(response) < 8 || int(binary.LittleEndian.Uint16(response[2:]))+8 != len(response) || response[6] != byte(s.next) || response[7] != channel {
		return nil, 0, errors.New("probe response framing mismatch")
	}
	timer := time.NewTimer(20 * time.Millisecond)
	select {
	case <-ctx.Done():
		timer.Stop()
		return nil, 0, ctx.Err()
	case <-timer.C:
	}
	return response[8:], binary.LittleEndian.Uint16(response), nil
}

func (s *probeSession) exchange(ctx context.Context, operation uint16, payload []byte) ([]byte, uint16, error) {
	return s.exchangeChannel(ctx, operation, 0, payload)
}

func (s *probeSession) request(ctx context.Context, operation uint16, payload []byte, check func([]byte) error) error {
	return s.requestChannel(ctx, operation, 0, payload, check)
}

func (s *probeSession) requestChannel(ctx context.Context, operation uint16, channel byte, payload []byte, check func([]byte) error) error {
	response, status, err := s.exchangeChannel(ctx, operation, channel, payload)
	if err != nil {
		return err
	}
	if status != 0 {
		return fmt.Errorf("probe operation %04x failed with status %04x", operation, status)
	}
	if check != nil {
		return check(response)
	}
	return nil
}

func (s *probeSession) pulseReset(ctx context.Context) error {
	for index, level := range []byte{0, 1} {
		response, status, err := s.exchange(ctx, 0x9001, []byte{level})
		if err != nil {
			return err
		}
		if len(response) > 1 {
			return fmt.Errorf("unexpected reset response: %x", response)
		}
		// Firmware may report that the target link vanished while the line is
		// changing. Recovery enumeration confirms completion.
		if status != 0 && status != 0xfff8 {
			return fmt.Errorf("probe reset level %d failed with status %04x", level, status)
		}
		if index == 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	return s.request(ctx, 0x8009, nil, nil)
}

func (s *probeSession) message(ctx context.Context, text string) error {
	return s.request(ctx, 0xc000, messagePayload(text), nil)
}

func messagePayload(text string) []byte {
	payload := make([]byte, 20)
	copy(payload[4:], text)
	return payload
}

func (s *probeSession) memory(ctx context.Context, write bool, ap uint32, address uint64, data []byte) (result []byte, err error) {
	if write && (len(data) == 0 || len(data)%4 != 0) {
		return nil, errors.New("debug memory writes must contain whole words")
	}
	if !write && (len(data) == 0 || len(data)%4 != 0) {
		return nil, errors.New("debug memory reads must contain whole words")
	}
	var restore []byte
	if len(data) > 4 {
		control, controlErr := s.readAccessPortRetry(ctx, ap, 0)
		if controlErr != nil {
			return nil, fmt.Errorf("read access-port control for multiword transfer: %w", controlErr)
		}
		if len(control) != 4 {
			return nil, errors.New("short access-port control for multiword transfer")
		}
		current := binary.LittleEndian.Uint32(control)
		transfer := current
		if len(data) == 8 && address%8 == 0 {
			// Eight-byte device registers must be accessed atomically. Select the
			// access port's doubleword width instead of issuing two word writes.
			transfer = current&^uint32(0x7) | 0x3
		} else {
			transfer = current&^uint32(0x30) | 0x10
		}
		if transfer != current {
			restore = append([]byte(nil), control...)
			binary.LittleEndian.PutUint32(control, transfer)
			if controlErr = s.writeAccessPortRetry(ctx, ap, 0, control); controlErr != nil {
				return nil, fmt.Errorf("enable access-port address increment: %w", controlErr)
			}
			defer func() {
				restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
				defer cancel()
				err = errors.Join(err, s.writeAccessPortRetry(restoreCtx, ap, 0, restore))
			}()
		}
	}
	payload := make([]byte, 20)
	flags := uint32(0x18) | ap<<24
	if write {
		flags |= 0x8000
		payload = append(payload, data...)
	}
	binary.LittleEndian.PutUint32(payload, flags)
	binary.LittleEndian.PutUint64(payload[8:], address)
	binary.LittleEndian.PutUint32(payload[16:], uint32(len(data)/4))
	err = s.request(ctx, 0x2003, payload, func(response []byte) error {
		if len(response) < 20 {
			return errors.New("short debug memory response")
		}
		responseFlags := binary.LittleEndian.Uint32(response)
		if responseFlags>>24 != ap || responseFlags&0x00ff0000 != 0 || binary.LittleEndian.Uint32(response[4:])&0xf0000000 != 0xb0000000 || binary.LittleEndian.Uint64(response[8:]) != address || binary.LittleEndian.Uint32(response[16:]) != uint32(len(data)/4) {
			return fmt.Errorf("debug memory response mismatch: %x", response)
		}
		if write {
			if len(response) != 20 {
				return errors.New("unexpected debug memory write response")
			}
			return nil
		}
		if len(response) != 20+len(data) {
			return errors.New("short debug memory read")
		}
		result = append([]byte{}, response[20:]...)
		return nil
	})
	return result, err
}

func (s *probeSession) readMemory(ctx context.Context, ap uint32, address uint64, size int) ([]byte, error) {
	if size <= 0 || size%4 != 0 {
		return nil, errors.New("debug memory reads must contain whole words")
	}
	// Four-byte words and aligned eight-byte device registers have architectural
	// transaction widths. They are never candidates for bulk-size negotiation.
	if size <= 8 {
		return s.memory(ctx, false, ap, address, make([]byte, size))
	}
	limit := min(s.memoryLimit, size)
	var last error
	for limit >= 4 {
		result := make([]byte, 0, size)
		for offset := 0; offset < size; {
			chunk := min(limit, size-offset)
			part, err := s.memory(ctx, false, ap, address+uint64(offset), make([]byte, chunk))
			if err != nil {
				last = err
				break
			}
			result = append(result, part...)
			offset += chunk
		}
		if len(result) == size {
			return result, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if limit <= 8 {
			break
		}
		limit = reducedProbeMemoryLimit(s.memoryLimit, limit)
		s.memoryLimit = limit
	}
	return nil, last
}

func (s *probeSession) writeMemory(ctx context.Context, ap uint32, address uint64, data []byte) error {
	if len(data) == 0 || len(data)%4 != 0 {
		return errors.New("debug memory writes must contain whole words")
	}
	if len(data) <= 8 {
		_, err := s.memory(ctx, true, ap, address, data)
		return err
	}
	limit := min(s.memoryLimit, len(data))
	var last error
	for limit >= 4 {
		complete := true
		for offset := 0; offset < len(data); {
			chunk := min(limit, len(data)-offset)
			if _, err := s.memory(ctx, true, ap, address+uint64(offset), data[offset:offset+chunk]); err != nil {
				last, complete = err, false
				break
			}
			offset += chunk
		}
		if complete {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if limit <= 8 {
			break
		}
		// Repeating an already completed prefix writes the same guarded bytes.
		// This lets a compatible firmware with a smaller transfer window prove
		// its usable limit without leaving a partial requested value.
		limit = reducedProbeMemoryLimit(s.memoryLimit, limit)
		s.memoryLimit = limit
	}
	return last
}

func (s *probeSession) readWord(ctx context.Context, ap uint32, address uint64) (uint32, error) {
	b, err := s.readMemory(ctx, ap, address, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (s *probeSession) writeWord(ctx context.Context, ap uint32, address uint64, value uint32) error {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, value)
	return s.writeMemory(ctx, ap, address, b)
}

func (s *probeSession) writeDoubleWord(ctx context.Context, ap uint32, address, value uint64) error {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, value)
	return s.writeMemory(ctx, ap, address, b)
}

func openProbe(ctx context.Context) (_ *probeUSB, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := initNative(); err != nil {
		return nil, err
	}
	var iterator uint32
	if code := native.services(0, native.matching("IOUSBDevice"), &iterator); code != 0 {
		return nil, fmt.Errorf("probe enumeration: 0x%x", uint32(code))
	}
	defer native.releaseIO(iterator)
	for {
		service := native.next(iterator)
		if service == 0 {
			break
		}
		vid, vok := ioNumber(service, "idVendor")
		pid, pok := ioNumber(service, "idProduct")
		if !vok || !pok || vid != probeVendor || pid != probeProduct {
			native.releaseIO(service)
			continue
		}
		h, e := ioInterface(service, "9DC7B780-9EC0-11D4-A54F-000A27052861", "01A2D0E9-42F6-4A87-8B8B-77057C8CE0CE")
		native.releaseIO(service)
		if e != nil {
			return nil, e
		}
		u := &probeUSB{dev: h}
		defer func() {
			if err != nil {
				u.Close()
			}
		}()
		request := [4]uint16{0xffff, 0xffff, 0xffff, 0xffff}
		var interfaces uint32
		code := method(h, 28, uintptr(unsafe.Pointer(&request)), uintptr(unsafe.Pointer(&interfaces)))
		runtime.KeepAlive(&request)
		runtime.KeepAlive(&interfaces)
		if code != 0 {
			return nil, fmt.Errorf("probe interface enumeration: 0x%x", code)
		}
		svc := native.next(interfaces)
		native.releaseIO(interfaces)
		if svc == 0 {
			return nil, errors.New("supported probe interface missing")
		}
		u.intf, e = ioInterface(svc, "2D9786C6-9EF3-11D4-AD51-000A27052861", "BCEAADDC-884D-4F27-8340-36D69FAB90F6")
		native.releaseIO(svc)
		if e != nil {
			return nil, e
		}
		if code := method(u.intf, 8); code != 0 {
			return nil, fmt.Errorf("probe interface unavailable: 0x%x", code)
		}
		var count uint8
		if code := method(u.intf, 19, uintptr(unsafe.Pointer(&count))); code != 0 {
			return nil, fmt.Errorf("probe endpoints: 0x%x", code)
		}
		for p := uint8(1); p <= count; p++ {
			var direction, number, transfer, interval uint8
			var packet uint16
			code = method(u.intf, 26, uintptr(p), uintptr(unsafe.Pointer(&direction)), uintptr(unsafe.Pointer(&number)), uintptr(unsafe.Pointer(&transfer)), uintptr(unsafe.Pointer(&packet)), uintptr(unsafe.Pointer(&interval)))
			runtime.KeepAlive(&direction)
			runtime.KeepAlive(&number)
			runtime.KeepAlive(&transfer)
			runtime.KeepAlive(&packet)
			runtime.KeepAlive(&interval)
			if code == 0 && transfer == 2 {
				if direction == 1 {
					u.in = p
				} else if direction == 0 {
					u.out = p
				}
				if clear := method(u.intf, 45, uintptr(p)); clear != 0 {
					return nil, fmt.Errorf("clear probe pipe %d: 0x%x", p, clear)
				}
			}
		}
		if u.in == 0 || u.out == 0 {
			return nil, errors.New("supported probe bulk endpoints missing")
		}
		// The interface owns the data pipes. Release the temporary device-level
		// configuration claim before exchanging probe messages.
		method(u.dev, 3)
		u.dev = nil
		return u, nil
	}
	return nil, errors.New("supported debug probe not found")
}

func (u *probeUSB) Close() error {
	if u.intf != nil {
		method(u.intf, 9)
		method(u.intf, 3)
		u.intf = nil
	}
	if u.dev != nil {
		method(u.dev, 9)
		method(u.dev, 3)
		u.dev = nil
	}
	return nil
}

func (u *probeUSB) transact(ctx context.Context, request []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(request) < 8 || len(request) > 0x8000 || int(request[2])|int(request[3])<<8 != len(request)-8 {
		return nil, errors.New("invalid probe request")
	}
	var code uint32
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		code = method(u.intf, 40, uintptr(u.out), uintptr(unsafe.Pointer(&request[0])), uintptr(len(request)), 5000, 5000)
		runtime.KeepAlive(request)
		if code == 0 {
			break
		}
		// A target reset can leave a transient halt on the probe's bulk pipe.
		// Clear only the failed pipe and retry the request before reporting it.
		_ = method(u.intf, 45, uintptr(u.out))
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	if code != 0 {
		return nil, fmt.Errorf("probe write: 0x%x", code)
	}
	response := make([]byte, 0x8000)
	var size uint32
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		size = uint32(len(response))
		code = method(u.intf, 39, uintptr(u.in), uintptr(unsafe.Pointer(&response[0])), uintptr(unsafe.Pointer(&size)), 5000, 5000)
		runtime.KeepAlive(response)
		runtime.KeepAlive(&size)
		if code == 0 && size >= 8 && size <= uint32(len(response)) {
			break
		}
		if code != 0 {
			// The write completed, so do not duplicate it. Recover and wait for
			// its pending response on the same input pipe instead.
			_ = method(u.intf, 45, uintptr(u.in))
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	if code != 0 {
		return nil, fmt.Errorf("probe read: 0x%x", code)
	}
	if size < 8 || size > uint32(len(response)) {
		return nil, errors.New("invalid probe response size")
	}
	return response[:size], nil
}
