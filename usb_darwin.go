//go:build darwin && arm64

package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
)

// IOKit COM interfaces are called through their published macOS ABI. No C
// compiler, third-party USB daemon, or libusb installation is needed.
type nativeAPI struct {
	matching      func(string) uintptr
	services      func(uint32, uintptr, *uint32) int32
	next          func(uint32) uint32
	releaseIO     func(uint32) int32
	property      func(uint32, uintptr, uintptr, uint32) uintptr
	stringCreate  func(uintptr, string, uint32) uintptr
	stringGet     func(uintptr, []byte, int64, uint32) bool
	numberGet     func(uintptr, int32, unsafe.Pointer) bool
	releaseCF     func(uintptr)
	uuidCreate    func(uintptr, uintptr) uintptr
	plugin        func(uint32, uintptr, uintptr, *unsafe.Pointer, *int32) int32
	destroyPlugin func(unsafe.Pointer) int32
	encode        func([]byte, uintptr, []byte, uintptr, uintptr, uint32) uintptr
	decode        func([]byte, uintptr, []byte, uintptr, uintptr, uint32) uintptr
}

var nativeOnce sync.Once
var native nativeAPI
var nativeError error

func initNative() error {
	nativeOnce.Do(func() {
		for _, lib := range []struct {
			path    string
			symbols map[string]any
		}{
			{"/System/Library/Frameworks/IOKit.framework/IOKit", map[string]any{"IOServiceMatching": &native.matching, "IOServiceGetMatchingServices": &native.services, "IOIteratorNext": &native.next, "IOObjectRelease": &native.releaseIO, "IORegistryEntryCreateCFProperty": &native.property, "IOCreatePlugInInterfaceForService": &native.plugin, "IODestroyPlugInInterface": &native.destroyPlugin}},
			{"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", map[string]any{"CFStringCreateWithCString": &native.stringCreate, "CFStringGetCString": &native.stringGet, "CFNumberGetValue": &native.numberGet, "CFRelease": &native.releaseCF, "CFUUIDCreateFromString": &native.uuidCreate}},
			{"/usr/lib/libcompression.dylib", map[string]any{"compression_encode_buffer": &native.encode, "compression_decode_buffer": &native.decode}},
		} {
			h, err := purego.Dlopen(lib.path, purego.RTLD_NOW|purego.RTLD_LOCAL)
			if err != nil {
				nativeError = err
				return
			}
			for name, fn := range lib.symbols {
				purego.RegisterLibFunc(fn, h, name)
			}
		}
	})
	return nativeError
}

func ioNumber(service uint32, key string) (uint32, bool) {
	k := cfString(key)
	defer native.releaseCF(k)
	v := native.property(service, k, 0, 0)
	if v == 0 {
		return 0, false
	}
	defer native.releaseCF(v)
	var n uint32
	if !native.numberGet(v, 3, unsafe.Pointer(&n)) {
		return 0, false
	}
	return n, true
}

func cfString(s string) uintptr { return native.stringCreate(0, s, 0x08000100) }
func cfUUID(s string) uintptr {
	str := cfString(s)
	defer native.releaseCF(str)
	return native.uuidCreate(0, str)
}

func ioString(service uint32, key string) string {
	k := cfString(key)
	defer native.releaseCF(k)
	v := native.property(service, k, 0, 0)
	if v == 0 {
		return ""
	}
	defer native.releaseCF(v)
	b := make([]byte, 1024)
	if !native.stringGet(v, b, int64(len(b)), 0x08000100) {
		return ""
	}
	return strings.TrimRight(string(b), "\x00")
}

//go:uintptrescapes
func method(handle unsafe.Pointer, index int, args ...uintptr) uint32 {
	table := *(*unsafe.Pointer)(handle)
	fn := *(*uintptr)(unsafe.Add(table, uintptr(index)*unsafe.Sizeof(uintptr(0))))
	result, _, _ := purego.SyscallN(fn, append([]uintptr{uintptr(handle)}, args...)...)
	return uint32(result)
}

func ioInterface(service uint32, userUUID, interfaceUUID string) (unsafe.Pointer, error) {
	user := cfUUID(userUUID)
	defer native.releaseCF(user)
	iid := cfUUID("C244E858-109C-11D4-91D4-0050E4C6426F")
	defer native.releaseCF(iid)
	var plugin, handle unsafe.Pointer
	var score int32
	if code := native.plugin(service, user, iid, &plugin, &score); code != 0 {
		return nil, fmt.Errorf("IOKit plugin: 0x%x", uint32(code))
	}
	defer native.destroyPlugin(plugin)
	uuid, err := hex.DecodeString(strings.ReplaceAll(interfaceUUID, "-", ""))
	if err != nil || len(uuid) != 16 {
		return nil, errors.New("invalid interface UUID")
	}
	code := method(plugin, 1, uintptr(binary.LittleEndian.Uint64(uuid[:8])), uintptr(binary.LittleEndian.Uint64(uuid[8:])), uintptr(unsafe.Pointer(&handle)))
	runtime.KeepAlive(&handle)
	if code != 0 {
		return nil, fmt.Errorf("IOKit interface: 0x%x", code)
	}
	return handle, nil
}

type recoveryUSB struct {
	dev, intf unsafe.Pointer
	pipe      uint8
	identity  device
}

func openRecovery(ctx context.Context, expected device) (_ *recoveryUSB, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := initNative(); err != nil {
		return nil, err
	}
	var iterator uint32
	if code := native.services(0, native.matching("IOUSBDevice"), &iterator); code != 0 {
		return nil, fmt.Errorf("USB enumeration: 0x%x", uint32(code))
	}
	defer native.releaseIO(iterator)
	for {
		service := native.next(iterator)
		if service == 0 {
			break
		}
		serial := ioString(service, "USB Serial Number")
		d, e := parseDevice(serial)
		if e != nil || d.ECID != expected.ECID {
			native.releaseIO(service)
			continue
		}
		h, e := ioInterface(service, "9DC7B780-9EC0-11D4-A54F-000A27052861", "01A2D0E9-42F6-4A87-8B8B-77057C8CE0CE")
		native.releaseIO(service)
		if e != nil {
			return nil, e
		}
		u := &recoveryUSB{dev: h, identity: d}
		defer func() {
			if err != nil {
				u.Close()
			}
		}()
		// Boot checks other device processes before acquiring the board. The
		// recovery protocol requires the device-level exclusive-open operation.
		if code := method(h, 29); code != 0 {
			return nil, fmt.Errorf("USB device owned or unavailable: 0x%x; stop the process using this board", code)
		}
		if code := method(h, 23, 1); code != 0 {
			return nil, fmt.Errorf("USB configuration: 0x%x", code)
		}
		request := [4]uint16{0xffff, 0xffff, 0xffff, 0xffff}
		var interfaces uint32
		code := method(h, 28, uintptr(unsafe.Pointer(&request)), uintptr(unsafe.Pointer(&interfaces)))
		runtime.KeepAlive(&request)
		runtime.KeepAlive(&interfaces)
		if code != 0 {
			return nil, fmt.Errorf("USB interface enumeration: 0x%x", code)
		}
		svc := native.next(interfaces)
		native.releaseIO(interfaces)
		if svc == 0 {
			return nil, errors.New("Recovery USB interface missing")
		}
		u.intf, e = ioInterface(svc, "2D9786C6-9EF3-11D4-AD51-000A27052861", "BCEAADDC-884D-4F27-8340-36D69FAB90F6")
		native.releaseIO(svc)
		if e != nil {
			return nil, e
		}
		if code := method(u.intf, 8); code != 0 {
			return nil, fmt.Errorf("USB interface owned or unavailable: 0x%x", code)
		}
		var count uint8
		code = method(u.intf, 19, uintptr(unsafe.Pointer(&count)))
		runtime.KeepAlive(&count)
		if code != 0 {
			return nil, fmt.Errorf("USB endpoints: 0x%x", code)
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
			if code == 0 && direction == 0 && number == 4 && transfer == 2 {
				u.pipe = p
				break
			}
		}
		if u.pipe == 0 {
			return nil, errors.New("Recovery bulk endpoint 04 missing")
		}
		return u, nil
	}
	return nil, errors.New("the selected board disappeared before USB acquisition")
}

func (u *recoveryUSB) Close() error {
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

type usbRequest struct {
	Kind, Request                        uint8
	Value, Index, Length                 uint16
	Data                                 unsafe.Pointer
	Done, IdleTimeout, CompletionTimeout uint32
}

func (u *recoveryUSB) control(ctx context.Context, kind, request uint8, data []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if u.dev == nil || len(data) > 65535 {
		return 0, errors.New("invalid USB control request")
	}
	r := usbRequest{Kind: kind, Request: request, Length: uint16(len(data)), IdleTimeout: 10000, CompletionTimeout: 10000}
	if len(data) > 0 {
		r.Data = unsafe.Pointer(&data[0])
	}
	var pin runtime.Pinner
	pin.Pin(&r)
	if len(data) > 0 {
		pin.Pin(&data[0])
	}
	defer pin.Unpin()
	code := method(u.dev, 30, uintptr(unsafe.Pointer(&r)))
	runtime.KeepAlive(&r)
	runtime.KeepAlive(data)
	if code != 0 {
		return 0, fmt.Errorf("USB control %02x/%02x: 0x%x", kind, request, code)
	}
	return int(r.Done), nil
}

func recoveryCommandRequest(command string) uint8 {
	switch command {
	case "go", "bootx", "reboot", "memboot":
		return 1
	default:
		return 0
	}
}

func (u *recoveryUSB) Command(ctx context.Context, s string) error {
	if s == "" || len(s) >= 256 || strings.ContainsRune(s, 0) {
		return errors.New("invalid Recovery command")
	}
	// Commands that transfer execution use the alternate Recovery request.
	// Sending them as ordinary commands reaches the parser but does not provide
	// the execution handoff semantics required by newer initial loaders.
	_, err := u.control(ctx, 0x40, recoveryCommandRequest(s), append([]byte(s), 0))
	// Recovery command dispatch may use a stalled status stage for commands
	// that do not return data. The command has already reached the parser.
	if err != nil && strings.Contains(err.Error(), "0xe000404f") {
		return nil
	}
	return err
}

func (u *recoveryUSB) Getenv(ctx context.Context, name string) (string, error) {
	if err := u.Command(ctx, "getenv "+name); err != nil {
		return "", err
	}
	b := make([]byte, 255)
	n, err := u.control(ctx, 0xc0, 0, b)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b[:n]), "\x00\r\n"), nil
}

func (u *recoveryUSB) Upload(ctx context.Context, name string, data []byte, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if len(data) == 0 {
		return fmt.Errorf("upload %s: empty image", name)
	}
	// A prior owner can leave the bulk endpoint halted. ResetDevice clears that
	// stale transport state while the selected Recovery device remains open and
	// configured. Keep this at the start of an upload: resetting a fresh command
	// connection after the loader has committed an image can race its execution.
	for range 2 {
		if code := method(u.dev, 25); code != 0 {
			return fmt.Errorf("prepare %s upload endpoint: USB 0x%x", name, code)
		}
	}
	if _, err := u.control(ctx, 0x41, 0, nil); err != nil {
		return err
	}
	// SyscallN crosses into IOKit with raw pointers. Keep the complete backing
	// array pinned until every synchronous transfer has returned.
	var pin runtime.Pinner
	pin.Pin(&data[0])
	defer pin.Unpin()
	p := byteProgress{out: out, name: name, total: int64(len(data)), start: time.Now(), last: time.Now()}
	for at := 0; at < len(data); {
		if err := ctx.Err(); err != nil {
			return err
		}
		// IOUSBLib's Recovery transfer contract checks the endpoint before
		// every write. A completed WritePipeTO alone does not prove that a
		// preceding packet left the host controller and entered iBoot.
		if code := method(u.intf, 27, uintptr(u.pipe)); code != 0 {
			return fmt.Errorf("upload %s pipe status at %d: USB 0x%x", name, at, code)
		}
		end := min(at+0x8000, len(data))
		chunk := data[at:end]
		code := method(u.intf, 40, uintptr(u.pipe), uintptr(unsafe.Pointer(&chunk[0])), uintptr(len(chunk)), 10000, 10000)
		runtime.KeepAlive(data)
		if code != 0 {
			return fmt.Errorf("upload %s at %d: USB 0x%x", name, at, code)
		}
		p.Write(chunk)
		at = end
	}
	if len(data)%512 == 0 {
		if code := method(u.intf, 27, uintptr(u.pipe)); code != 0 {
			return fmt.Errorf("upload %s final pipe status: USB 0x%x", name, code)
		}
		if code := method(u.intf, 40, uintptr(u.pipe), 0, 0, 10000, 10000); code != 0 {
			return fmt.Errorf("upload %s final packet: USB 0x%x", name, code)
		}
	}
	fmt.Fprintf(out, "Uploaded %s (%d bytes)\n", name, len(data))
	return nil
}

func compression(data []byte, size int, encode, iboot bool) ([]byte, error) {
	if err := initNative(); err != nil {
		return nil, err
	}
	if len(data) == 0 || size <= 0 || size > 256<<20 {
		return nil, errors.New("invalid compression buffer geometry")
	}
	out := make([]byte, size)
	algorithm := uint32(0x801)
	if iboot {
		algorithm = 0x891
	}
	fn := native.decode
	if encode {
		fn = native.encode
	}
	n := fn(out, uintptr(len(out)), data, uintptr(len(data)), 0, algorithm)
	if n == 0 || n > uintptr(len(out)) {
		return nil, errors.New("macOS Compression rejected payload")
	}
	return out[:n], nil
}
