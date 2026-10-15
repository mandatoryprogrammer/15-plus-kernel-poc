package main

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestProbeUARTIsSelectedByLiveRegistryProperties(t *testing.T) {
	ports := []probeSerialPort{
		{Base: "other-123", Device: "other-123-ch-0", Suffix: "-ch-0", Callout: "/dev/cu.other-123-ch-0"},
		{Base: "renamed-456", Device: "renamed-456-ch-2", Suffix: "-ch-2", Callout: "/dev/cu.renamed-456-ch-2"},
		{Base: "renamed-456", Device: "renamed-456-ch-0", Suffix: "-ch-0", Callout: "/dev/cu.renamed-456-ch-0"},
	}
	path, err := selectProbeUART("456", ports)
	if err != nil || path != "/dev/cu.renamed-456-ch-0" {
		t.Fatalf("selected %q: %v", path, err)
	}
	if _, err = selectProbeUART("missing", ports); err == nil {
		t.Fatal("missing probe UART accepted")
	}
	ports = append(ports, probeSerialPort{Base: "second-456", Device: "second-456-ch-0", Suffix: "-ch-0", Callout: "/dev/cu.second-456-ch-0"})
	if _, err = selectProbeUART("456", ports); err == nil {
		t.Fatal("ambiguous probe UART accepted")
	}
	fallback := []probeSerialPort{{Base: "future-789", Device: "future-789-uart", Suffix: "-uart", Callout: "/dev/cu.future-789-uart"}}
	if path, err = selectProbeUART("789", fallback); err != nil || path != fallback[0].Callout {
		t.Fatalf("single renamed UART selected as %q: %v", path, err)
	}
}

func TestSerialReadCancelAndRestore(t *testing.T) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	raw, err := master.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var name [128]byte
	var ioctlErr syscall.Errno
	err = raw.Control(func(fd uintptr) {
		for _, request := range []uintptr{syscall.TIOCPTYGRANT, syscall.TIOCPTYUNLK} {
			_, _, ioctlErr = syscall.Syscall(syscall.SYS_IOCTL, fd, request, 0)
			if ioctlErr != 0 {
				return
			}
		}
		_, _, ioctlErr = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0])))
	})
	if err != nil || ioctlErr != 0 {
		t.Fatalf("PTY: %v %v", err, ioctlErr)
	}
	path := strings.TrimRight(string(name[:]), "\x00")
	slave, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	var before, after syscall.Termios
	if err = serialSettings(slave, syscall.TIOCGETA, &before); err != nil {
		t.Fatal(err)
	}
	c, err := newCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := openSerial(c, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = master.Write([]byte("kernel-console-test\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		b, e := os.ReadFile(s.log.Name())
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(b), "kernel-console-test") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("serial reader lost PTY output")
		}
		time.Sleep(10 * time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("serial close did not interrupt an idle read")
	}
	if err = serialSettings(slave, syscall.TIOCGETA, &after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("serial terminal settings were not restored")
	}
}
