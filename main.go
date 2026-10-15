package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func main() {
	// IOKit's synchronous USB transfers can return kIOReturnAborted when Go's
	// asynchronous preemption signal interrupts their Mach wait. Relaunch once
	// with that signal disabled; cooperative scheduling remains enabled.
	if len(os.Args) > 1 && (os.Args[1] == "shell" || os.Args[1] == "exec" || os.Args[1] == "doctor" || os.Args[1] == "reset") {
		debug := os.Getenv("GODEBUG")
		if !strings.HasSuffix(debug, "asyncpreemptoff=1") {
			exe, err := os.Executable()
			if err == nil {
				err = os.Setenv("GODEBUG", debug+",asyncpreemptoff=1")
			}
			if err == nil {
				err = syscall.Exec(exe, os.Args, os.Environ())
			}
			fmt.Fprintln(terminalOutput(os.Stderr), "error: configuring native USB:", err)
			os.Exit(1)
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(terminalOutput(os.Stderr), "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: 15-plus-kernel-poc shell | exec -- COMMAND | payload list | payload add FILE [--dest /usr/local/bin/NAME] | assets fetch | assets import bootstrap DIRECTORY | doctor | reset")
	}
	root, err := projectRoot()
	if err != nil {
		return err
	}
	cache, err := newCache(filepath.Join(root, ".cache"))
	if err != nil {
		return err
	}
	switch args[0] {
	case "doctor":
		if len(args) != 1 {
			return errors.New("usage: doctor")
		}
		return doctor(ctx, cache.out)
	case "reset":
		if len(args) != 1 {
			return errors.New("usage: reset")
		}
		return resetToRecovery(ctx, cache)
	case "shell":
		if len(args) != 1 {
			return errors.New("usage: shell")
		}
		return smartShell(ctx, cache)
	case "boot":
		return errors.New("boot is automatic; use: 15-plus-kernel-poc shell")
	case "exec":
		if len(args) < 3 || args[1] != "--" {
			return errors.New("usage: exec -- COMMAND [ARG...]")
		}
		return smartExec(ctx, cache, args[2:])
	case "assets":
		return assetsCommand(ctx, cache, args[1:])
	case "payload":
		if len(args) == 2 && args[1] == "list" {
			return listPayload(cache, os.Stdout)
		}
		if len(args) >= 3 && args[1] == "add" {
			return addPayload(ctx, cache, args[2:])
		}
		return errors.New("usage: payload list | payload add FILE [--dest /usr/local/bin/NAME]")
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func withDeviceLock(c *cache, run func() error) error {
	lock, err := acquireLock(filepath.Join(c.root, "device.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	return run()
}

func projectRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
		return wd, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}
