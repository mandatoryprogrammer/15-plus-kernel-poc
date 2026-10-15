package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	eCoreDebug    = 0x210010000
	coreDebugBase = 0x211010000
	coreWrapper   = 0x211040000
	debugReceive  = coreDebugBase + 0x80
	debugEdit     = coreDebugBase + 0x84
	debugStatus   = coreDebugBase + 0x88
	debugTransmit = coreDebugBase + 0x8c
	resetCatch    = coreDebugBase + 0x24
	debugOSLock   = coreDebugBase + 0x300
	debugPower    = coreDebugBase + 0x314
	holdCores     = 0xfd381014
	warmReset     = 0xfd381018
	resetStatus   = 0xfd32005c
	bootMode      = 0x23d2ec020
	bootProgress  = 0x23d2bf008
	bootCoreMode  = 0x211e449f8
	eCoreMode     = 0x210e449f8
)

type targetDebug struct {
	s          *probeSession
	out        io.Writer
	silicon    siliconProfile
	loaderBase uint64
}

// validateDebugTopology checks the debug routing and register map needed by
// the CPID 8120 family before a loader analyzer can
// make any volatile write. CPRV is reported as identity data rather than used
// as a proxy for this live hardware check.
func validateDebugTopology(ctx context.Context, out io.Writer, identity device) error {
	profile, err := siliconFor(identity)
	if err != nil {
		return err
	}
	d, err := openTargetDebug(ctx, out)
	if err != nil {
		return fmt.Errorf("validate CPID 8120 debug topology: %w", err)
	}
	defer d.Close()
	mode, err := d.word(ctx, bootMode)
	if err != nil {
		return fmt.Errorf("read trusted-boot mode: %w", err)
	}
	status, err := d.word(ctx, debugStatus)
	if err != nil {
		return fmt.Errorf("read boot-core debug status: %w", err)
	}
	wrapper, err := d.read(ctx, coreWrapper, 8)
	if err != nil {
		return fmt.Errorf("read boot-core wrapper: %w", err)
	}
	if mode != 6 {
		return fmt.Errorf("unexpected Recovery trusted-boot mode 0x%x", mode)
	}
	if d.silicon.CPID != profile.CPID {
		return errors.New("debug topology selection changed during validation")
	}
	fmt.Fprintf(out, "%s debug topology verified for CPRV %02X; status=0x%x wrapper=0x%x\n", profile.Name, identity.CPRV, status, binary.LittleEndian.Uint64(wrapper))
	return nil
}

func openTargetDebug(ctx context.Context, out io.Writer) (*targetDebug, error) {
	if err := selectApplicationTarget(ctx, out); err != nil {
		return nil, err
	}
	return openSelectedTargetDebug(ctx, out)
}

func openInitialTargetDebug(ctx context.Context, out io.Writer) (*targetDebug, error) {
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		d, err := openTargetDebug(ctx, out)
		if err == nil {
			mode, modeErr := d.word(ctx, bootMode)
			if modeErr != nil || mode != 6 {
				err = errors.Join(fmt.Errorf("unexpected trusted-boot mode 0x%x", mode), modeErr)
			}
		}
		if err == nil {
			return d, nil
		}
		last = err
		if d != nil {
			d.Close()
		}
		fmt.Fprintf(out, "Recovery target identity attempt %d/3 did not settle: %v\n", attempt, err)
	}
	return nil, fmt.Errorf("acquire Recovery application target: %w", last)
}

func selectApplicationTarget(ctx context.Context, out io.Writer) error {
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		selection, err := newProbeSession(ctx)
		if err == nil {
			err = selection.selectTarget(ctx)
		}
		if selection != nil {
			err = errors.Join(err, selection.Close())
		}
		if err == nil {
			return nil
		}
		last = err
		fmt.Fprintf(out, "Target selection attempt %d/3 did not settle: %v\n", attempt, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("select supported target: %w", last)
}

func openSelectedTargetDebug(ctx context.Context, out io.Writer) (*targetDebug, error) {
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		s, err := newProbeSession(ctx)
		if err == nil {
			err = s.attachSelectedTarget(ctx)
		}
		if err == nil {
			profile, profileErr := siliconFor(device{CPID: supportedFamily.CPID})
			if profileErr != nil {
				s.Close()
				return nil, profileErr
			}
			return &targetDebug{s: s, out: out, silicon: profile}, nil
		}
		last = err
		if s != nil {
			s.Close()
		}
		fmt.Fprintf(out, "Target access attempt %d/3 did not settle: %v\n", attempt, err)
	}
	return nil, fmt.Errorf("attach supported target: %w", last)
}

func (d *targetDebug) Close() error { return d.s.Close() }

func (d *targetDebug) read(ctx context.Context, address uint64, size int) ([]byte, error) {
	var (
		data []byte
		err  error
	)
	for attempt := 0; attempt < 3; attempt++ {
		if data, err = d.s.readMemory(ctx, d.s.ports.Application, address, size); err == nil {
			return data, nil
		}
		_ = d.s.configureApplicationAccess(ctx)
	}
	return nil, err
}

func (d *targetDebug) write(ctx context.Context, address uint64, data []byte) error {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if last = d.s.writeMemory(ctx, d.s.ports.Application, address, data); last == nil {
			var actual []byte
			actual, last = d.read(ctx, address, len(data))
			if last == nil && bytes.Equal(actual, data) {
				return nil
			}
			if last == nil {
				last = fmt.Errorf("debug readback mismatch at 0x%x: wrote %x, read %x", address, data, actual)
			}
		}
		_ = d.s.configureApplicationAccess(ctx)
	}
	return last
}

func (d *targetDebug) word(ctx context.Context, address uint64) (uint32, error) {
	var (
		value uint32
		err   error
	)
	for attempt := 0; attempt < 3; attempt++ {
		if value, err = d.s.readWord(ctx, d.s.ports.Application, address); err == nil {
			return value, nil
		}
		_ = d.s.configureApplicationAccess(ctx)
	}
	return 0, err
}

func (d *targetDebug) putWord(ctx context.Context, address uint64, value uint32) error {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if last = d.s.writeWord(ctx, d.s.ports.Application, address, value); last == nil {
			var actual uint32
			actual, last = d.word(ctx, address)
			if last == nil && actual == value {
				return nil
			}
			if last == nil {
				last = fmt.Errorf("debug word readback mismatch at 0x%x: wrote 0x%x, read 0x%x", address, value, actual)
			}
		}
		_ = d.s.configureApplicationAccess(ctx)
	}
	return last
}

func (d *targetDebug) putDoubleWord(ctx context.Context, address, value uint64) error {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, value)
	return d.write(ctx, address, b)
}

func (d *targetDebug) putBreakpointControl(ctx context.Context, address uint64, value uint32) error {
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if last = d.s.writeWord(ctx, d.s.ports.Application, address, value); last == nil {
			var actual uint32
			actual, last = d.word(ctx, address)
			if last == nil && actual&1 == value&1 {
				return nil
			}
			if last == nil {
				last = fmt.Errorf("breakpoint control at 0x%x did not change enable state", address)
			}
		}
		_ = d.s.configureApplicationAccess(ctx)
	}
	return last
}

func (d *targetDebug) armBreakpoint(ctx context.Context, index, address uint64) error {
	if err := d.s.writeWord(ctx, d.s.ports.Application, debugStatus, 0x4000); err != nil {
		return err
	}
	if _, err := d.word(ctx, debugStatus); err != nil {
		return err
	}
	if err := d.putDoubleWord(ctx, coreDebugBase+0x400+index, address); err != nil {
		return err
	}
	if err := d.execute(ctx, 0xd5033fdf); err != nil {
		return err
	}
	if err := d.putBreakpointControl(ctx, coreDebugBase+0x408+index, 0x21e7); err != nil {
		return err
	}
	return d.execute(ctx, 0xd5033fdf)
}

func (d *targetDebug) controlWord(ctx context.Context, address uint64) (uint32, error) {
	return d.s.readWord(ctx, d.s.ports.Control, address)
}

func (d *targetDebug) putControlWord(ctx context.Context, address uint64, value uint32) error {
	if err := d.s.writeWord(ctx, d.s.ports.Control, address, value); err != nil {
		return err
	}
	actual, err := d.controlWord(ctx, address)
	if err != nil {
		return err
	}
	if actual != value {
		return fmt.Errorf("control word readback mismatch at 0x%x", address)
	}
	return nil
}

func (d *targetDebug) putControlWordRetry(ctx context.Context, address uint64, value uint32, limit time.Duration) error {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	var last error
	for {
		if last = d.putControlWord(ctx, address, value); last == nil {
			return nil
		}
		control := make([]byte, 4)
		binary.LittleEndian.PutUint32(control, 0x80000042)
		_ = d.s.writeAccessPort(ctx, d.s.ports.Control, 0, control)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return last
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (d *targetDebug) putApplicationWordRetry(ctx context.Context, address uint64, value uint32, limit time.Duration) error {
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	var last error
	for {
		_ = d.s.configureApplicationAccess(ctx)
		if last = d.s.writeWord(ctx, d.s.ports.Application, address, value); last == nil {
			actual, readErr := d.s.readWord(ctx, d.s.ports.Application, address)
			if readErr == nil && actual == value {
				return nil
			}
			last = errors.Join(readErr, fmt.Errorf("application word readback at 0x%x is 0x%x", address, actual))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return last
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (d *targetDebug) unlockBootCores(ctx context.Context) error {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	var last error
	for {
		_ = d.s.configureApplicationAccess(ctx)
		modeBytes, readErr := d.read(ctx, bootCoreMode, 8)
		if readErr == nil {
			mode := binary.LittleEndian.Uint64(modeBytes)
			if mode&(uint64(1)<<63) != 0 {
				if writeErr := d.s.writeDoubleWord(ctx, d.s.ports.Application, bootCoreMode, mode&^(uint64(1)<<63)); writeErr != nil {
					last = fmt.Errorf("write boot-core access control: %w", writeErr)
				} else if check, checkErr := d.read(ctx, bootCoreMode, 8); checkErr != nil {
					last = fmt.Errorf("verify boot-core access control: %w", checkErr)
				} else if binary.LittleEndian.Uint64(check)&(uint64(1)<<63) != 0 {
					last = errors.New("boot-core access control remained locked")
				} else {
					mode &^= uint64(1) << 63
				}
			}
			if mode&(uint64(1)<<63) == 0 {
				// The efficiency core is not the boot core on this supported board,
				// but clear its lock here to match the SoC-wide action.
				if eModeBytes, eReadErr := d.read(ctx, eCoreMode, 8); eReadErr == nil {
					eMode := binary.LittleEndian.Uint64(eModeBytes)
					if eMode&(uint64(1)<<63) != 0 {
						_ = d.s.writeDoubleWord(ctx, d.s.ports.Application, eCoreMode, eMode&^(uint64(1)<<63))
					}
				}
				return nil
			}
			if last == nil {
				last = fmt.Errorf("unlock boot core at 0x%x", bootCoreMode)
			}
		} else {
			last = fmt.Errorf("read boot-core control at 0x%x: %w", bootCoreMode, readErr)
		}
		if last == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("no accessible boot core control: %w", last)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (d *targetDebug) unlockBootCoreDebug(ctx context.Context) error {
	var last error
	var lastPower uint32
	for attempt := 1; attempt <= 128; attempt++ {
		power, readErr := d.word(ctx, debugPower)
		lastPower = power
		if readErr == nil {
			if power&1 == 0 {
				last = fmt.Errorf("boot core debug power is unavailable: 0x%x", power)
			} else if power&(1<<6) != 0 {
				last = fmt.Errorf("boot core debug remains locked: 0x%x", power)
			} else if power&(1<<5) == 0 {
				return nil
			} else {
				last = d.s.writeWord(ctx, d.s.ports.Application, debugOSLock, 0)
			}
		} else {
			last = readErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
	return fmt.Errorf("unlock boot-core debug access after 128 writes (power status 0x%x): %v", lastPower, last)
}

func (d *targetDebug) resetToInitialLoader(ctx context.Context) (err error) {
	fmt.Fprintln(d.out, "Warm-resetting the application cores and catching the boot core")
	// Clear the architectural OS lock while the running Recovery environment
	// still admits the write. The warm reset preserves this access state; once
	// the trusted boot monitor has asserted its lock, the same write is ignored.
	if err := d.unlockBootCoreDebug(ctx); err != nil {
		return fmt.Errorf("prepare boot-core debug access for warm reset: %w", err)
	}
	if err := d.putControlWordRetry(ctx, holdCores, 1, 5*time.Second); err != nil {
		fmt.Fprintf(d.out, "Reattaching the reset control fabric before holding cores: %v\n", err)
		_ = d.s.Close()
		refreshed, attachErr := openSelectedTargetDebug(ctx, d.out)
		if attachErr != nil {
			return errors.Join(fmt.Errorf("hold application cores: %w", err), attachErr)
		}
		d.s = refreshed.s
		if retryErr := d.putControlWordRetry(ctx, holdCores, 1, 5*time.Second); retryErr != nil {
			return fmt.Errorf("hold application cores after debug reattach: %w", retryErr)
		}
	}
	// The reset takes the debug fabric down before the write response can be
	// normalized. Confirm completion with the reset-catch write below.
	warmErr := d.s.writeWord(ctx, d.s.ports.Control, warmReset, 1)
	if warmErr != nil {
		fmt.Fprintf(d.out, "Warm-reset request changed the debug fabric: %v\n", warmErr)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(100 * time.Millisecond):
	}
	if err = d.s.configureApplicationAccessRetry(ctx, 5*time.Second); err != nil {
		return fmt.Errorf("restore application access after warm reset: %w", err)
	}
	// Either application cluster can be inaccessible while the warm reset
	// fabric settles. Arm both possible boot cores and use the later halted-PC
	// check to confirm which core stopped.
	_ = d.putApplicationWordRetry(ctx, eCoreDebug+0x24, 2, time.Second)
	if err = d.putApplicationWordRetry(ctx, resetCatch, 2, 5*time.Second); err != nil {
		return fmt.Errorf("arm boot-core reset catch before release: %w", err)
	}
	if err := d.putControlWordRetry(ctx, holdCores, 0, 5*time.Second); err != nil {
		fmt.Fprintf(d.out, "Reattaching the reset debug fabric after control access changed: %v\n", err)
		_ = d.s.Close()
		refreshed, attachErr := openSelectedTargetDebug(ctx, d.out)
		if attachErr != nil {
			return errors.Join(fmt.Errorf("release application cores: %w", err), attachErr)
		}
		d.s = refreshed.s
		_ = d.putApplicationWordRetry(ctx, eCoreDebug+0x24, 2, time.Second)
		if catchErr := d.putApplicationWordRetry(ctx, resetCatch, 2, 5*time.Second); catchErr != nil {
			return fmt.Errorf("restore boot-core reset catch before release: %w", catchErr)
		}
		if err = d.putControlWordRetry(ctx, holdCores, 0, 5*time.Second); err != nil {
			return fmt.Errorf("release application cores after debug reattach: %w", err)
		}
	}
	mode, err := d.word(ctx, bootMode)
	if err == nil {
		fmt.Fprintf(d.out, "Trusted boot mode status: 0x%x\n", mode)
	}
	if err == nil && mode != 2 {
		if err = waitFor(ctx, d.out, "trusted boot initialization", 3*time.Second, 100*time.Millisecond, func(context.Context) (bool, error) {
			value, readErr := d.word(ctx, bootProgress)
			if readErr != nil {
				return false, readErr
			}
			if value != 0x2f {
				return false, fmt.Errorf("observed status 0x%x", value)
			}
			return true, nil
		}); err != nil {
			return fmt.Errorf("trusted boot initialization: %w", err)
		}
	}
	if err = d.unlockBootCores(ctx); err != nil {
		return err
	}
	if err = d.unlockBootCoreDebug(ctx); err != nil {
		return err
	}
	_ = d.s.writeWord(ctx, d.s.ports.Application, eCoreDebug+0x24, 0)
	_ = d.s.writeWord(ctx, d.s.ports.Application, resetCatch, 0)
	status, err := d.controlWord(ctx, resetStatus)
	if err == nil {
		_ = d.s.writeWord(ctx, d.s.ports.Control, resetStatus, status)
		_, _ = d.controlWord(ctx, resetStatus)
	}
	_ = d.s.writeWord(ctx, d.s.ports.Application, eCoreDebug+0x24, 2)
	if err = d.putApplicationWordRetry(ctx, resetCatch, 2, 5*time.Second); err != nil {
		return fmt.Errorf("rearm boot-core reset catch: %w", err)
	}
	if err = d.waitState(ctx, "reset vector catch", 8*time.Second, func(status uint32, wrapper uint64) bool {
		return wrapper&(1<<28) != 0 && status&(1<<24) != 0 && status&(1<<6) == 0
	}); err != nil {
		return err
	}
	if err = d.contextRestart(ctx); err != nil {
		return fmt.Errorf("prepare boot-core context: %w", err)
	}
	if restartErr := d.restartPhase(ctx, 2, 0); restartErr != nil {
		fmt.Fprintf(d.out, "Boot-core restart changed the debug link: %v\n", restartErr)
		_ = d.s.configureApplicationAccess(ctx)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Second):
	}
	if err = d.unlockBootCoreDebug(ctx); err != nil {
		return fmt.Errorf("restore boot-core debug access at loader entry: %w", err)
	}
	if err = d.waitState(ctx, "initial loader entry", 8*time.Second, func(status uint32, wrapper uint64) bool {
		return wrapper&(1<<28) != 0 && status&(1<<24) != 0 && status&(1<<6) == 0
	}); err != nil {
		return err
	}
	var pc uint64
	for attempt := 0; attempt < 10; attempt++ {
		pc, err = d.programCounter(ctx)
		if err == nil && pc >= d.silicon.LoaderLow && pc < d.silicon.LoaderHigh && pc&0xfff == 0 {
			break
		}
		if err == nil {
			err = fmt.Errorf("transient program counter 0x%x is outside executable SRAM", pc)
		}
		_ = d.s.configureApplicationAccess(ctx)
		_ = d.unlockBootCoreDebug(ctx)
		_ = d.waitState(ctx, "initial loader debug transfer", time.Second, func(status uint32, wrapper uint64) bool {
			return wrapper&(1<<28) != 0 && status&(1<<24) != 0 && status&(1<<6) == 0
		})
	}
	if err != nil {
		return fmt.Errorf("read initial loader program counter: %w", err)
	}
	d.loaderBase = pc
	return nil
}

func (d *targetDebug) requireHex(ctx context.Context, address uint64, expected string) error {
	want, err := hex.DecodeString(expected)
	if err != nil {
		return err
	}
	var got []byte
	for attempt := 0; attempt < 3; attempt++ {
		got, err = d.read(ctx, address, len(want))
		if err == nil && bytes.Equal(got, want) {
			return nil
		}
		_ = d.s.configureApplicationAccess(ctx)
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("memory identity mismatch at 0x%x: got %x", address, got)
}

func (d *targetDebug) waitState(ctx context.Context, name string, limit time.Duration, ready func(uint32, uint64) bool) error {
	return waitFor(ctx, d.out, name, limit, 100*time.Millisecond, func(context.Context) (bool, error) {
		status, err := d.word(ctx, debugStatus)
		if err != nil {
			return false, err
		}
		wrapper, err := d.read(ctx, coreWrapper, 8)
		if err != nil {
			return false, err
		}
		wrapperValue := binary.LittleEndian.Uint64(wrapper)
		if !ready(status, wrapperValue) {
			return false, fmt.Errorf("debug status 0x%x, wrapper 0x%x", status, wrapperValue)
		}
		return true, nil
	})
}

func (d *targetDebug) halt(ctx context.Context) error {
	// The wrapper control register is command-like: successful writes are
	// confirmed by the resulting halt state, not by echoing the write value.
	if err := d.s.writeDoubleWord(ctx, d.s.ports.Application, coreWrapper, 0x80000000); err != nil {
		return err
	}
	return d.waitState(ctx, "application core halt", 8*time.Second, func(status uint32, wrapper uint64) bool {
		return wrapper&(1<<28) != 0 && status&(1<<24) != 0 && status&(1<<6) == 0
	})
}

func (d *targetDebug) resume(ctx context.Context) error {
	if err := d.contextRestart(ctx); err != nil {
		return err
	}
	return d.resumeFinal(ctx)
}

func (d *targetDebug) resumeFinal(ctx context.Context) error {
	return d.resumeFinalStatus(ctx, 0)
}

func (d *targetDebug) resumeFinalStatus(ctx context.Context, status uint32) error {
	restartErr := d.restartPhase(ctx, 2, status)
	if restartErr != nil {
		// The core may run before the debug probe acknowledges the command.
		// Restore the access width and check the running wrapper state.
		_ = d.s.configureApplicationAccess(ctx)
	}
	waitErr := d.waitState(ctx, "application core resume", 8*time.Second, func(_ uint32, wrapper uint64) bool {
		return wrapper&(1<<28) == 0
	})
	if waitErr != nil {
		return errors.Join(restartErr, waitErr)
	}
	return nil
}

func (d *targetDebug) contextRestart(ctx context.Context) error {
	restartErr := d.restartPhase(ctx, 6, 0x00c00000)
	if restartErr != nil {
		_ = d.s.configureApplicationAccess(ctx)
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(50 * time.Millisecond):
	}
	waitErr := d.waitState(ctx, "debug context restart", 3*time.Second, func(status uint32, wrapper uint64) bool {
		return wrapper&(1<<28) != 0 && status&(1<<24) != 0 && status&(1<<6) == 0
	})
	if waitErr != nil {
		return errors.Join(restartErr, waitErr)
	}
	return nil
}

func (d *targetDebug) restartPhase(ctx context.Context, catch, status uint32) error {
	if err := d.s.writeWord(ctx, d.s.ports.Application, resetCatch, catch); err != nil {
		return err
	}
	if err := d.s.writeWord(ctx, d.s.ports.Application, debugStatus, status); err != nil {
		return err
	}
	if err := d.execute(ctx, 0xd5033fdf); err != nil {
		return err
	}
	return d.requestResume(ctx, coreWrapper)
}

func (d *targetDebug) requestResume(ctx context.Context, wrapperAddress uint64) error {
	wrapperBytes, err := d.read(ctx, wrapperAddress, 8)
	if err != nil {
		return err
	}
	// The restart request is a read-modify-write operation. Preserve the
	// wrapper's low control field, set RESTART, clear HALT, and discard the
	// read-only upper half.
	wrapper := binary.LittleEndian.Uint64(wrapperBytes)
	restart := wrapper&0x3fffffff | 0x40000000
	return d.s.writeDoubleWord(ctx, d.s.ports.Application, wrapperAddress, restart)
}

func (d *targetDebug) execute(ctx context.Context, instruction uint32) error {
	status, err := d.word(ctx, debugStatus)
	if err != nil {
		return err
	}
	wrapper, err := d.read(ctx, coreWrapper, 8)
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint64(wrapper)&(1<<28) == 0 || status&(1<<24) == 0 || status&(1<<6) != 0 {
		return errors.New("debug instruction transfer is not ready")
	}
	if err = d.s.writeWord(ctx, d.s.ports.Application, debugEdit, instruction); err != nil {
		return err
	}
	deadline := time.NewTimer(250 * time.Millisecond)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		status, err = d.word(ctx, debugStatus)
		if err != nil {
			return err
		}
		if status&(1<<6) != 0 {
			return errors.New("debug instruction transfer failed")
		}
		if status&(1<<24) != 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("debug instruction transfer timed out")
		case <-tick.C:
		}
	}
}

// executeIdempotent tolerates a transient probe transport reset while issuing
// cache and barrier instructions whose effect is safe to repeat.
func (d *targetDebug) executeIdempotent(ctx context.Context, instruction uint32) error {
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		if last = d.execute(ctx, instruction); last == nil {
			return nil
		}
		_ = d.s.configureApplicationAccess(ctx)
		_ = d.unlockBootCoreDebug(ctx)
	}
	return last
}

func (d *targetDebug) readTransfer(ctx context.Context) (uint64, error) {
	hi, err := d.word(ctx, debugReceive)
	if err != nil {
		return 0, err
	}
	lo, err := d.word(ctx, debugTransmit)
	return uint64(hi)<<32 | uint64(lo), err
}

func (d *targetDebug) readRegister(ctx context.Context, register uint32) (uint64, error) {
	if register > 30 {
		return 0, errors.New("invalid general register")
	}
	if err := d.execute(ctx, 0xd5130400|register); err != nil {
		return 0, err
	}
	return d.readTransfer(ctx)
}

func (d *targetDebug) writeRegister(ctx context.Context, register uint32, value uint64) error {
	if register > 30 {
		return errors.New("invalid general register")
	}
	if err := d.s.writeWord(ctx, d.s.ports.Application, debugTransmit, uint32(value>>32)); err != nil {
		return err
	}
	if err := d.s.writeWord(ctx, d.s.ports.Application, debugReceive, uint32(value)); err != nil {
		return err
	}
	return d.execute(ctx, 0xd5330400|register)
}

func (d *targetDebug) programCounter(ctx context.Context) (uint64, error) {
	saved, err := d.readRegister(ctx, 1)
	if err != nil {
		return 0, err
	}
	if err = d.execute(ctx, 0xd53b4521); err != nil {
		return 0, err
	}
	pc, readErr := d.readRegister(ctx, 1)
	restoreErr := d.writeRegister(ctx, 1, saved)
	return pc, errors.Join(readErr, restoreErr)
}

type codePatch struct {
	address       uint64
	before, after uint32
}

func loaderIdentityChallenge(header []byte, build string) (int, []byte, []byte, string, error) {
	needle := append([]byte(build), 0)
	at, err := uniqueOffset(header, needle, "initial-loader header identity")
	if err != nil || len(build) == 0 {
		return 0, nil, nil, "", errors.Join(errors.New("cannot derive initial-loader identity challenge"), err)
	}
	start := at &^ 3
	end := (at + len(needle) + 3) &^ 3
	if end > len(header) {
		return 0, nil, nil, "", errors.New("initial-loader identity challenge exceeds the header")
	}
	before := bytes.Clone(header[start:end])
	after := bytes.Clone(before)
	character := byte('A')
	if build[len(build)-1] == character {
		character = 'B'
	}
	after[at-start+len(build)-1] = character
	challenged := build[:len(build)-1] + string(character)
	return start, before, after, challenged, nil
}

// bindRecoveryToProbe checks that Recovery USB and the debug probe reach the
// same physical board. A one-byte challenge touches only the live build string,
// is observed through Recovery USB, and is then removed by a warm reset before
// any admission instruction is changed.
func bindRecoveryToProbe(ctx context.Context, c *cache, want device, expectedBuild string) (err error) {
	d, err := openInitialTargetDebug(ctx, c.out)
	if err != nil {
		return err
	}
	defer d.Close()
	halted := false
	challenged := false
	verified := false
	defer func() {
		if !challenged {
			if halted {
				err = errors.Join(err, d.resume(context.Background()))
			}
			if err == nil && verified {
				fmt.Fprintln(c.out, "Recovery USB and debug probe verified on the same board")
			}
			return
		}
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cleanupErr := d.resetToInitialLoader(cleanup)
		if cleanupErr == nil {
			halted = true
			header, readErr := readDebugRange(cleanup, d, io.Discard, "", d.loaderBase, 0x1000)
			cleanupErr = readErr
			if cleanupErr == nil {
				_, cleanupErr = loaderBuild(header, expectedBuild)
			}
			cleanupErr = errors.Join(cleanupErr, d.resume(cleanup))
			halted = false
		}
		if cleanupErr != nil && halted {
			cleanupErr = errors.Join(cleanupErr, d.resume(cleanup))
			halted = false
		}
		err = errors.Join(err, cleanupErr)
		if err == nil && verified {
			fmt.Fprintln(c.out, "Recovery USB and debug probe verified on the same board")
		}
	}()
	if err = d.resetToInitialLoader(ctx); err != nil {
		return err
	}
	halted = true
	header, err := readDebugRange(ctx, d, c.out, "Probe/Recovery binding identity", d.loaderBase, 0x1000)
	if err != nil {
		return err
	}
	if _, err = loaderBuild(header, expectedBuild); err != nil {
		return err
	}
	offset, before, after, marker, err := loaderIdentityChallenge(header, expectedBuild)
	if err != nil {
		return err
	}
	address := d.loaderBase + uint64(offset)
	if err = d.write(ctx, address, after); err != nil {
		return err
	}
	challenged = true
	if err = d.resume(ctx); err != nil {
		return err
	}
	halted = false
	err = waitFor(ctx, c.out, "probe/Recovery board binding", 20*time.Second, 250*time.Millisecond, func(ctx context.Context) (bool, error) {
		current, discoverErr := discover(ctx)
		if discoverErr != nil {
			return false, discoverErr
		}
		if current.ECID != want.ECID || current.IBFL != 0x25 {
			return false, errors.New("Recovery identity changed during probe binding")
		}
		build, buildErr := recoveryBuild(ctx, current)
		if buildErr != nil {
			return false, buildErr
		}
		if build != marker {
			return false, fmt.Errorf("USB observed loader %q instead of live challenge %q", build, marker)
		}
		return true, nil
	})
	if err != nil {
		return err
	}
	// Restore the bytes in case reset cleanup itself fails, then let the reset
	// prove that the unmodified loader is what executes next.
	if restoreErr := d.write(ctx, address, before); restoreErr != nil {
		return restoreErr
	}
	challenged = true
	verified = true
	return nil
}

func prepareInitialLoader(ctx context.Context, c *cache, expectedBuild string) (uint64, error) {
	var last error
	for attempt := 1; attempt <= 3; attempt++ {
		d, err := openInitialTargetDebug(ctx, c.out)
		var base uint64
		if err == nil {
			err = prepareInitialLoaderWithTarget(ctx, c, d, expectedBuild)
			base = d.loaderBase
			d.Close()
		}
		if err == nil {
			return base, nil
		}
		last = err
		if attempt < 3 {
			fmt.Fprintf(c.out, "Initial-loader preparation attempt %d/3 changed the debug link: %v; retrying\n", attempt, err)
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	return 0, last
}

// restartUnmodifiedInitialLoader recovers Recovery USB after a reset reached
// trusted boot but the device controller did not re-enumerate. It verifies the
// live loader identity and resumes it without changing any instruction.
func restartUnmodifiedInitialLoader(ctx context.Context, c *cache) (err error) {
	d, err := openInitialTargetDebug(ctx, c.out)
	if err != nil {
		return err
	}
	defer d.Close()
	if err = d.resetToInitialLoader(ctx); err != nil {
		return err
	}
	resumed := false
	defer func() {
		if !resumed {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = errors.Join(err, d.resume(cleanup))
		}
	}()
	header, err := readDebugRange(ctx, d, c.out, "Recovery-loader identity", d.loaderBase, 0x1000)
	if err != nil {
		return err
	}
	build, err := loaderBuild(header, "")
	if err != nil {
		return err
	}
	if err = d.resume(ctx); err != nil {
		return err
	}
	resumed = true
	fmt.Fprintf(c.out, "Restarted unmodified initial loader %s to restore Recovery USB\n", build)
	return nil
}

func prepareInitialLoaderWithTarget(ctx context.Context, c *cache, d *targetDebug, expectedBuild string) (err error) {
	if err = d.resetToInitialLoader(ctx); err != nil {
		return err
	}
	base := d.loaderBase
	resumed := false
	defer func() {
		if !resumed {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = errors.Join(err, d.resume(cleanup))
		}
	}()
	header, err := readDebugRange(ctx, d, c.out, "Initial-loader identity", base, 0x1000)
	if err != nil {
		return err
	}
	build, err := loaderBuild(header, expectedBuild)
	if err != nil {
		return err
	}
	if build != expectedBuild {
		return fmt.Errorf("initial loader changed from Recovery identity %q to live identity %q", expectedBuild, build)
	}
	var plan loaderPlan
	resolved := false
	if adapter := knownInitialLoader(build); adapter != nil {
		plan, err = adapter.plan(ctx, d, base)
		if err == nil {
			resolved = true
		} else {
			fmt.Fprintf(c.out, "Adapter did not match live bytes (%v); analyzing the live instructions\n", err)
			err = nil
		}
	}
	if !resolved {
		var snapshot loaderSnapshot
		cached := false
		for _, candidate := range cachedLoaderSnapshots(c.root, build, d.silicon.LoaderHigh-base) {
			fmt.Fprintf(c.out, "Checking cached instruction analysis for initial loader %s\n", build)
			d.loaderBase = base
			plan, err = analyzeInitialLoader(candidate.image, candidate.offset, base, build)
			if err == nil {
				err = verifySemanticLoaderPlan(ctx, d, plan)
			}
			if err == nil {
				snapshot, cached = candidate, true
				break
			}
			fmt.Fprintf(c.out, "Cached instruction analysis does not match this live image: %v\n", err)
			err = nil
		}
		if !cached {
			fmt.Fprintf(c.out, "Analyzing initial loader %s without writing target memory\n", build)
			snapshot, plan, err = readAndAnalyzeInitialLoader(ctx, d, c.out, build)
			var saveErr error
			if len(snapshot.image) != 0 {
				snapshot.path, saveErr = saveLoaderSnapshot(c.root, build, base, snapshot.offset, snapshot.image)
			}
			if err != nil {
				if saveErr != nil {
					return fmt.Errorf("initial-loader semantic analysis failed: %w; retaining its read-only input also failed: %v", err, saveErr)
				}
				return fmt.Errorf("initial-loader semantic analysis failed: %w; read-only snapshot retained at %s", err, snapshot.path)
			}
			if saveErr != nil || snapshot.path == "" {
				return fmt.Errorf("save initial-loader analysis input: %w", saveErr)
			}
		}
		fmt.Fprintf(c.out, "Initial-loader analysis found one patch plan; snapshot SHA-256 %s\n", plan.snapshotSHA256)
	}
	if err != nil {
		return err
	}
	for _, patch := range plan.patches {
		actual, readErr := d.word(ctx, patch.address)
		if readErr != nil || actual != patch.before {
			return errors.Join(fmt.Errorf("loader patch identity mismatch at 0x%x", patch.address), readErr)
		}
	}
	// Roll back the words already written if a later write or cache operation
	// fails while the core is still stopped.
	written := 0
	defer func() {
		if err == nil {
			return
		}
		for i := written - 1; i >= 0; i-- {
			_ = d.putWord(context.Background(), plan.patches[i].address, plan.patches[i].before)
		}
	}()
	for _, patch := range plan.patches {
		if err = d.putWord(ctx, patch.address, patch.after); err != nil {
			return err
		}
		written++
	}
	for _, instruction := range []uint32{0xd5033f9f, 0xd508711f, 0xd5033f9f, 0xd5033fdf} {
		if err = d.executeIdempotent(ctx, instruction); err != nil {
			return err
		}
	}
	if err = d.resume(ctx); err != nil {
		return err
	}
	resumed = true
	fmt.Fprintf(c.out, "Applied %d checked RAM patches to initial loader %s with the %s; caches synchronized\n", len(plan.patches), build, plan.source)
	return nil
}

type rootSelector struct {
	d      *targetDebug
	calls  []uint64
	closed bool
}

const rootOwnerScanLimit = 16 << 10

// rootArgumentEdit locates the command-line field from the value supplied to
// iBEC instead of assuming a structure offset or capacity. Some loaders retain
// only a NUL-terminated prefix of that value. The prefix, printable bytes, and
// zero extension needed by the replacement must all be unique and explicit.
func rootArgumentEdit(block []byte, bootArguments, rootArguments string) (int, []byte, []byte, error) {
	if strings.IndexByte(bootArguments, 0) >= 0 || strings.IndexByte(rootArguments, 0) >= 0 || rootArguments == "" {
		return 0, nil, nil, errors.New("invalid root-selection arguments")
	}
	tokens := strings.Fields(bootArguments)
	if len(tokens) < 3 {
		return 0, nil, nil, errors.New("boot arguments do not provide a unique search prefix")
	}
	needle := []byte(strings.Join(tokens[:3], " "))
	type candidate struct {
		at            int
		before, after []byte
	}
	var matches []candidate
	for cursor := 0; cursor < len(block); {
		relative := bytes.Index(block[cursor:], needle)
		if relative < 0 {
			break
		}
		at := cursor + relative
		end := at
		for end < len(block) && block[end] != 0 && end-at <= 1024 {
			if block[end] < 0x20 || block[end] > 0x7e {
				break
			}
			end++
		}
		if end < len(block) && block[end] == 0 {
			actual := string(block[at:end])
			span := max(len(actual), len(rootArguments)) + 1
			if strings.HasPrefix(bootArguments, actual) && at+span <= len(block) {
				zeroExtension := true
				for _, value := range block[end : at+span] {
					if value != 0 {
						zeroExtension = false
						break
					}
				}
				if zeroExtension {
					before := bytes.Clone(block[at : at+span])
					after := make([]byte, span)
					copy(after, rootArguments)
					matches = append(matches, candidate{at: at, before: before, after: after})
				}
			}
		}
		cursor = at + 1
	}
	if len(matches) != 1 {
		return 0, nil, nil, fmt.Errorf("expected one compatible live command-line field, found %d", len(matches))
	}
	return matches[0].at, matches[0].before, matches[0].after, nil
}

func armRootSelection(ctx context.Context, out io.Writer, imageBase uint64, layout runtimeLayout) (_ *rootSelector, err error) {
	if imageBase%0x1000 != 0 || len(layout.Entry) < 16 || len(layout.RootCalls) < 1 || len(layout.RootCalls) > 2 || layout.DecodedSize < 0x1000 {
		return nil, errors.New("invalid derived runtime layout")
	}
	d, err := openTargetDebug(ctx, out)
	if err != nil {
		return nil, err
	}
	if imageBase < d.silicon.LoaderLow || imageBase >= d.silicon.LoaderHigh || layout.DecodedSize > d.silicon.LoaderHigh-imageBase {
		d.Close()
		return nil, errors.New("derived runtime layout lies outside executable SRAM")
	}
	ok := false
	defer func() {
		if !ok {
			d.Close()
		}
	}()
	if err = d.halt(ctx); err != nil {
		return nil, err
	}
	resumed := false
	defer func() {
		if err != nil && !resumed {
			_ = d.resume(context.Background())
		}
	}()
	if err = d.requireHex(ctx, imageBase, hex.EncodeToString(layout.Entry)); err != nil {
		return nil, err
	}
	if err = d.requireHex(ctx, imageBase+layout.BuildOffset, hex.EncodeToString(layout.Build)); err != nil {
		return nil, err
	}
	calls := make([]uint64, len(layout.RootCalls))
	for index, offset := range layout.RootCalls {
		if offset+8 > layout.DecodedSize {
			return nil, errors.New("derived root-selection call lies outside iBEC")
		}
		calls[index] = imageBase + offset
		call, callErr := d.word(ctx, calls[index])
		move, moveErr := d.word(ctx, calls[index]+4)
		if callErr != nil || moveErr != nil || normalizeARM64(call) != 0x94000000 || move&0xffffffe0 != 0xaa0003e0 {
			return nil, errors.Join(fmt.Errorf("root-selection path %d no longer matches its decoded instruction relationship", index), callErr, moveErr)
		}
	}
	// Stop on the instructions after the calls that finish populating the
	// command-line field. Stopping on either call itself would let the resumed
	// callee overwrite the selected root.
	breakpoints := make([]uint64, len(calls))
	for index, call := range calls {
		breakpoints[index] = call + 4
	}
	if err = d.contextRestart(ctx); err != nil {
		return nil, err
	}
	for slot, address := range breakpoints {
		if err = d.armBreakpoint(ctx, uint64(slot)*0x10, address); err != nil {
			return nil, err
		}
	}
	if err = d.resumeFinalStatus(ctx, 0x4000); err != nil {
		return nil, err
	}
	for slot := range breakpoints {
		control, readErr := d.word(ctx, coreDebugBase+0x408+uint64(slot)*0x10)
		if readErr != nil || control&1 == 0 {
			return nil, errors.Join(fmt.Errorf("root-selection breakpoint %d did not remain enabled", slot), readErr)
		}
	}
	resumed = true
	fmt.Fprintln(out, "Verified root-selection breakpoints armed")
	ok = true
	return &rootSelector{d: d, calls: calls}, nil
}

func (r *rootSelector) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	return r.d.Close()
}

func (r *rootSelector) waitAndSelect(ctx context.Context) (err error) {
	root := canonicalRuntime.Root
	defer r.Close()
	if err = r.d.waitState(ctx, "verified root selection", 45*time.Second, func(status uint32, wrapper uint64) bool {
		return status&0x3f == 7 && wrapper&(1<<28) != 0
	}); err != nil {
		return err
	}
	resumed := false
	defer func() {
		if !resumed {
			err = errors.Join(err, r.d.resume(context.Background()))
		}
	}()
	pc, err := r.d.programCounter(ctx)
	if err != nil {
		return err
	}
	hit := false
	for _, call := range r.calls {
		if pc == call+4 {
			hit = true
			break
		}
	}
	if !hit {
		return fmt.Errorf("unexpected root-selection address 0x%x", pc)
	}
	for slot := range r.calls {
		if err = r.d.putBreakpointControl(ctx, coreDebugBase+0x408+uint64(slot)*0x10, 0); err != nil {
			return err
		}
	}
	owner, err := r.d.readRegister(ctx, 19)
	if err != nil {
		return err
	}
	if owner < r.d.silicon.LoaderLow || owner >= r.d.silicon.LoaderHigh || owner%8 != 0 {
		return fmt.Errorf("root-selection owner 0x%x is outside executable SRAM", owner)
	}
	scanBytes := min(uint64(rootOwnerScanLimit), r.d.silicon.LoaderHigh-owner)
	if scanBytes < 64 {
		return errors.New("root-selection owner has no bounded command-line search range")
	}
	ownerBytes, err := r.d.read(ctx, owner, int(scanBytes))
	if err != nil {
		return err
	}
	offset, before, after, err := rootArgumentEdit(ownerBytes, root.BootArguments, root.RootArguments)
	if err != nil {
		return err
	}
	field := owner + uint64(offset)
	actual, err := r.d.read(ctx, field, len(before))
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, before) {
		return errors.New("root-selection arguments changed after live derivation")
	}
	// This is a one-time data edit after iBEC has finished constructing its
	// command line.  Selecting rd=md0 makes the uploaded ramdisk the root; it is
	// separate from the admission instruction patches above and is equally
	// volatile.
	if err = r.d.write(ctx, field, after); err != nil {
		return err
	}
	if err = r.d.resume(ctx); err != nil {
		return err
	}
	resumed = true
	fmt.Fprintln(r.d.out, "Verified in-memory root selected; application core resumed")
	return nil
}
