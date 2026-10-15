package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type serialCapture struct {
	file, log  *os.File
	saved      syscall.Termios
	stop, done chan struct{}
	once       sync.Once
}

type probeSerialPort struct {
	Base, Device, Suffix, Callout string
}

func selectProbeUART(serial string, ports []probeSerialPort) (string, error) {
	if serial == "" {
		return "", errors.New("probe serial number is empty")
	}
	var associated, channelZero []string
	for _, port := range ports {
		if filepath.Clean(port.Callout) != port.Callout || !strings.HasPrefix(port.Callout, "/dev/") || strings.ContainsAny(port.Callout, "\x00\r\n") {
			continue
		}
		if !strings.Contains(port.Base, serial) && !strings.Contains(port.Device, serial) && !strings.Contains(port.Callout, serial) {
			continue
		}
		associated = append(associated, port.Callout)
		if port.Suffix == "-ch-0" || strings.HasSuffix(port.Device, "-ch-0") || strings.HasSuffix(port.Callout, "-ch-0") {
			channelZero = append(channelZero, port.Callout)
		}
	}
	if len(channelZero) == 1 {
		return channelZero[0], nil
	}
	if len(channelZero) > 1 {
		return "", errors.New("multiple channel-zero UARTs match the selected probe")
	}
	if len(associated) == 1 {
		return associated[0], nil
	}
	return "", fmt.Errorf("expected one application UART for probe %s; found %d matching serial ports", serial, len(associated))
}

func (s *serialCapture) writeAll(ctx context.Context, b []byte) error {
	for len(b) > 0 {
		n, err := s.file.Write(b)
		if n > 0 {
			b = b[n:]
		}
		if err == nil && n > 0 {
			continue
		}
		if err != nil && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	return nil
}

func serialIOCTL(fd uintptr, request uintptr, value *syscall.Termios) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(unsafe.Pointer(value)))
	if e != 0 {
		return e
	}
	return nil
}
func serialSettings(f *os.File, request uintptr, value *syscall.Termios) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var result error
	err = raw.Control(func(fd uintptr) { result = serialIOCTL(fd, request, value) })
	return errors.Join(err, result)
}
func startSerial(c *cache, probe string) (*serialCapture, error) {
	// The probe exposes the application UART as a stock macOS character device;
	// no forwarding process or separately installed serial tool is involved.
	path, err := findProbeUART(probe)
	if err != nil {
		return nil, err
	}
	return openSerial(c, path)
}

func openSerial(c *cache, path string) (*serialCapture, error) {
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	s := &serialCapture{file: f, stop: make(chan struct{}), done: make(chan struct{})}
	if err = serialSettings(f, syscall.TIOCGETA, &s.saved); err != nil {
		f.Close()
		return nil, err
	}
	raw := s.saved
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON | syscall.IXOFF | syscall.IXANY
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8 | syscall.CREAD | syscall.CLOCAL
	raw.Ispeed, raw.Ospeed = syscall.B115200, syscall.B115200
	raw.Cc[syscall.VMIN], raw.Cc[syscall.VTIME] = 0, 0
	if err = serialSettings(f, syscall.TIOCSETA, &raw); err != nil {
		f.Close()
		return nil, err
	}
	s.log, err = os.CreateTemp(filepath.Join(c.root, "logs"), "serial-*.log")
	if err != nil {
		serialSettings(f, syscall.TIOCSETA, &s.saved)
		f.Close()
		return nil, err
	}

	// Capture at most 32 MiB for readiness markers and bootstrap replies.  Close
	// stops this reader and restores the original termios before releasing the
	// descriptor, including on cancellation.
	go func() {
		defer close(s.done)
		var total int
		b := make([]byte, 65536)
		for {
			select {
			case <-s.stop:
				return
			default:
			}
			n, err := s.file.Read(b)
			if n > 0 && total < 32<<20 {
				_, _ = s.log.Write(b[:n])
				total += n
			}
			select {
			case <-s.stop:
				return
			default:
			}
			if errors.Is(err, os.ErrClosed) {
				return
			}
			if errors.Is(err, io.EOF) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR) {
				select {
				case <-s.stop:
					return
				case <-time.After(10 * time.Millisecond):
				}
				continue
			}
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EINTR) {
				fmt.Fprintf(s.log, "\nHost serial read stopped: %v\n", err)
				return
			}
		}
	}()
	return s, nil
}
func (s *serialCapture) Close() {
	s.once.Do(func() {
		close(s.stop)
		s.file.SetReadDeadline(time.Now())
		serialSettings(s.file, syscall.TIOCSETA, &s.saved)
		s.file.Close()
		<-s.done
		s.log.Close()
	})
}
