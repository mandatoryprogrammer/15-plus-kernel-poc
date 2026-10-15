package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
)

type device struct{ CPID, CPRV, BDID, CPFM, SCEP, IBFL, ECID uint64 }

var errNoRecovery = errors.New("no Recovery phone found; attach the supported board in Recovery mode")

func parseDevice(serial string) (device, error) {
	values := map[string]uint64{}
	for _, word := range strings.Fields(serial) {
		pair := strings.SplitN(word, ":", 2)
		if len(pair) != 2 {
			continue
		}
		switch pair[0] {
		case "CPID", "CPRV", "BDID", "CPFM", "SCEP", "IBFL", "ECID":
			v, err := strconv.ParseUint(pair[1], 16, 64)
			if err != nil {
				return device{}, fmt.Errorf("malformed USB identity field %s", pair[0])
			}
			if _, exists := values[pair[0]]; exists {
				return device{}, errors.New("duplicate USB identity field")
			}
			values[pair[0]] = v
		}
	}
	for _, key := range []string{"CPID", "CPRV", "BDID", "CPFM", "SCEP", "IBFL", "ECID"} {
		if _, ok := values[key]; !ok {
			return device{}, fmt.Errorf("missing USB identity field %s", key)
		}
	}
	d := device{
		CPID: values["CPID"], CPRV: values["CPRV"], BDID: values["BDID"],
		CPFM: values["CPFM"], SCEP: values["SCEP"], IBFL: values["IBFL"], ECID: values["ECID"],
	}
	if !supportedFamily.matches(d) || d.ECID == 0 {
		return d, errors.New("unsupported device: requires iPhone 15 Plus d38ap, CPID 8120, BDID 0A, CPFM 00")
	}
	if d.IBFL != 0x25 && d.IBFL != 0x24 {
		return d, fmt.Errorf("unsupported Recovery stage IBFL=%02x", d.IBFL)
	}
	return d, nil
}

func discover(ctx context.Context) (device, error) {
	if err := ctx.Err(); err != nil {
		return device{}, err
	}
	if err := initNative(); err != nil {
		return device{}, err
	}
	var iterator uint32
	if code := native.services(0, native.matching("IOUSBDevice"), &iterator); code != 0 {
		return device{}, fmt.Errorf("inspect USB: 0x%x", uint32(code))
	}
	defer native.releaseIO(iterator)
	var candidates []string
	for service := native.next(iterator); service != 0; service = native.next(iterator) {
		serial := ioString(service, "USB Serial Number")
		if strings.Contains(serial, "CPID:") {
			candidates = append(candidates, serial)
		}
		native.releaseIO(service)
	}
	if len(candidates) == 0 {
		return device{}, errNoRecovery
	}
	if len(candidates) != 1 {
		return device{}, errors.New("multiple Recovery phones found; connect only the supported board")
	}
	return parseDevice(candidates[0])
}

func recoveryBuild(ctx context.Context, d device) (string, error) {
	u, err := openRecovery(ctx, d)
	if err != nil {
		return "", err
	}
	defer u.Close()
	build, err := u.Getenv(ctx, "build-version")
	if err != nil {
		return "", err
	}
	if err = validateRecoveryBuild(d.IBFL, build); err != nil {
		return "", err
	}
	return build, nil
}

func doctor(ctx context.Context, out io.Writer) error {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		return errors.New("this PoC requires macOS on Apple silicon")
	}
	d, err := discover(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Supported iPhone 15 Plus family: CPID=%04X CPRV=%02X BDID=%02X CPFM=%02X SCEP=%02X IBFL=%02X\n", d.CPID, d.CPRV, d.BDID, d.CPFM, d.SCEP, d.IBFL)
	build, err := recoveryBuild(ctx, d)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Recovery USB available; bootloader %s\n", build)
	if d.IBFL == 0x25 {
		if knownInitialLoader(build) != nil {
			fmt.Fprintln(out, "Initial-loader adapter found; shell will check it against live bytes")
		} else {
			fmt.Fprintln(out, "No initial-loader adapter found; shell will analyze live instructions before writing memory")
		}
	} else {
		fmt.Fprintf(out, "Runtime profile: %s\n", canonicalRuntime.ID)
	}
	s, err := newProbeSession(ctx)
	if err != nil {
		return err
	}
	s.Close()
	if err = validateDebugTopology(ctx, out, d); err != nil {
		return err
	}
	serial, err := findProbeSerial(ctx)
	if err != nil {
		return err
	}
	uart, err := findProbeUART(serial)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Native debug USB available; probe %s passed live protocol, target, and UART checks (%s)\n", serial, uart)
	return nil
}
