package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

type accessMaterial struct {
	ECID        uint64 `json:"ecid"`
	Client      asset  `json:"client_private"`
	HostPrivate asset  `json:"host_private"`
	HostPublic  asset  `json:"host_public"`
}

func validateHostKey(b []byte) error {
	fields := strings.Fields(string(b))
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		return errors.New("expected an Ed25519 SSH host public key")
	}
	key, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(key) != 51 || binary.BigEndian.Uint32(key) != 11 || string(key[4:15]) != "ssh-ed25519" || binary.BigEndian.Uint32(key[15:19]) != 32 {
		return errors.New("malformed Ed25519 SSH host public key")
	}
	return nil
}

type sshAccess struct {
	material accessMaterial
	signer   ssh.Signer
	host     ssh.PublicKey
}

func storeAccessDescriptor(c *cache, material accessMaterial) error {
	b, err := json.MarshalIndent(material, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Join(c.root, "private"), "access-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(append(b, '\n'))
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(c.root, "private", "access.json"))
}

func generateSSHAccess(ctx context.Context, c *cache, ecid uint64) (sshAccess, error) {
	// Generate both sides locally so the volatile target never needs a bundled
	// password or reusable host key.  The descriptor is scoped to the detected
	// ECID and all private bytes stay in the ignored content-addressed cache.
	var result sshAccess
	if ecid == 0 {
		return result, errors.New("cannot create SSH access without a device identity")
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return result, err
	}
	hostPublic, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return result, err
	}
	marshal := func(key ed25519.PrivateKey, comment string) ([]byte, error) {
		block, marshalErr := ssh.MarshalPrivateKey(key, comment)
		if marshalErr != nil {
			return nil, marshalErr
		}
		return pem.EncodeToMemory(block), nil
	}
	clientBytes, err := marshal(clientPrivate, "kernel-poc-client")
	if err != nil {
		return result, err
	}
	hostBytes, err := marshal(hostPrivate, "kernel-poc-host")
	if err != nil {
		return result, err
	}
	hostKey, err := ssh.NewPublicKey(hostPublic)
	if err != nil {
		return result, err
	}
	publicBytes := ssh.MarshalAuthorizedKey(hostKey)
	result.material.ECID = ecid
	for _, row := range []struct {
		role   string
		body   []byte
		target *asset
	}{
		{"ssh-client-private", clientBytes, &result.material.Client},
		{"ssh-host-private", hostBytes, &result.material.HostPrivate},
		{"ssh-host-public", publicBytes, &result.material.HostPublic},
	} {
		a := asset{Role: row.role, SHA256: digest(row.body), Size: int64(len(row.body)), Recipe: "Generated locally with the Go cryptographic random source", Compatibility: "Any supported board"}
		if _, err = c.store(ctx, a, bytes.NewReader(row.body)); err != nil {
			return result, err
		}
		*row.target = a
	}
	if err = storeAccessDescriptor(c, result.material); err != nil {
		return result, err
	}
	result.signer, err = ssh.NewSignerFromKey(clientPrivate)
	result.host = hostKey
	return result, err
}

func ensureSSHAccess(ctx context.Context, c *cache, ecid uint64) (sshAccess, error) {
	result, err := loadAccess(ctx, c)
	if err == nil && result.material.ECID == ecid {
		return result, nil
	}
	return generateSSHAccess(ctx, c, ecid)
}

func installSSHAccess(ctx context.Context, c *cache, serial *serialCapture, access sshAccess) error {
	if response, err := rootExec(ctx, serial, "/bin/mkdir -p -m 700 /var/root/.ssh /private/etc/ssh"); err != nil {
		return fmt.Errorf("prepare SSH directories: %w: %s", err, response)
	}
	for _, row := range []struct {
		asset asset
		path  string
		mode  uint32
	}{
		{access.material.Client, "/var/root/.ssh/authorized_keys", 0600},
		{access.material.HostPrivate, "/private/etc/ssh/ssh_host_ed25519_key", 0600},
		{access.material.HostPublic, "/private/etc/ssh/ssh_host_ed25519_key.pub", 0644},
	} {
		body, err := os.ReadFile(c.object(row.asset))
		if err != nil {
			return err
		}
		if row.path == "/var/root/.ssh/authorized_keys" {
			signerPublic := ssh.MarshalAuthorizedKey(access.signer.PublicKey())
			body = signerPublic
		}
		if err = installFile(ctx, c, serial, row.path, body, digest(body), row.mode); err != nil {
			return err
		}
	}
	fmt.Fprintln(c.out, "Installed locally generated SSH identity")
	return nil
}

func loadAccess(ctx context.Context, c *cache) (sshAccess, error) {
	var result sshAccess
	b, err := os.ReadFile(filepath.Join(c.root, "private", "access.json"))
	if err != nil {
		return result, errors.New("SSH access is not initialized; run shell with the phone in Recovery mode")
	}
	if err = json.Unmarshal(b, &result.material); err != nil || result.material.ECID == 0 {
		return result, errors.New("invalid board access descriptor")
	}
	for _, a := range []asset{result.material.Client, result.material.HostPrivate, result.material.HostPublic} {
		if a.URL != "" || a.validate() != nil {
			return result, errors.New("invalid generated SSH access descriptor")
		}
		if err = verifyFile(ctx, c.object(a), a); err != nil {
			return result, err
		}
	}
	privateKey, err := os.ReadFile(c.object(result.material.Client))
	if err != nil {
		return result, err
	}
	result.signer, err = ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return result, fmt.Errorf("parse SSH client key: %w", err)
	}
	hostPrivate, err := os.ReadFile(c.object(result.material.HostPrivate))
	if err != nil {
		return result, err
	}
	hostSigner, err := ssh.ParsePrivateKey(hostPrivate)
	if err != nil {
		return result, fmt.Errorf("parse SSH host key: %w", err)
	}
	publicKey, err := os.ReadFile(c.object(result.material.HostPublic))
	if err != nil {
		return result, err
	}
	if err = validateHostKey(publicKey); err != nil {
		return result, err
	}
	result.host, _, _, _, err = ssh.ParseAuthorizedKey(publicKey)
	if err != nil {
		return result, fmt.Errorf("parse SSH host key: %w", err)
	}
	if !bytes.Equal(hostSigner.PublicKey().Marshal(), result.host.Marshal()) {
		return result, errors.New("generated SSH host key pair does not match")
	}
	return result, nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

func remoteCommand(command []string) string {
	quoted := make([]string, len(command))
	for i, value := range command {
		quoted[i] = shellQuote(value)
	}
	return strings.Join(quoted, " ")
}

func openSSH(ctx context.Context, access sshAccess) (*ssh.Client, error) {
	serial := fmt.Sprintf("00008120-%016X", access.material.ECID)
	connection, err := muxConnect(ctx, "/var/run/usbmuxd", serial, 22)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			connection.Close()
		}
	}()
	deadline := time.Now().Add(6 * time.Second)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	_ = connection.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	config := &ssh.ClientConfig{
		User:              "root",
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(access.signer)},
		HostKeyAlgorithms: []string{access.host.Type()},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if key.Type() != access.host.Type() || !bytes.Equal(key.Marshal(), access.host.Marshal()) {
				return errors.New("SSH host key does not match the locally generated identity")
			}
			return nil
		},
		Timeout: 6 * time.Second,
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, "phone:22", config)
	stop()
	if err != nil {
		return nil, err
	}
	_ = connection.SetDeadline(time.Time{})
	ok = true
	return ssh.NewClient(clientConnection, channels, requests), nil
}

type terminalState struct {
	file  *os.File
	saved syscall.Termios
}

func makeRawTerminal(file *os.File) (*terminalState, error) {
	if file == nil {
		return nil, nil
	}
	var saved syscall.Termios
	if err := serialSettings(file, syscall.TIOCGETA, &saved); err != nil {
		return nil, err
	}
	raw := saved
	raw.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cflag &^= syscall.CSIZE | syscall.PARENB
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN], raw.Cc[syscall.VTIME] = 1, 0
	if err := serialSettings(file, syscall.TIOCSETA, &raw); err != nil {
		return nil, err
	}
	return &terminalState{file: file, saved: saved}, nil
}

func (s *terminalState) Close() error {
	if s == nil {
		return nil
	}
	return serialSettings(s.file, syscall.TIOCSETA, &s.saved)
}

type windowSize struct{ Row, Col, Xpixel, Ypixel uint16 }

func terminalSize(file *os.File) (height, width int) {
	if file == nil {
		return 24, 80
	}
	var size windowSize
	raw, err := file.SyscallConn()
	if err != nil {
		return 24, 80
	}
	var ioctlErr syscall.Errno
	if err = raw.Control(func(fd uintptr) {
		_, _, ioctlErr = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&size)))
	}); err != nil || ioctlErr != 0 || size.Row == 0 || size.Col == 0 {
		return 24, 80
	}
	return int(size.Row), int(size.Col)
}

func runSSH(ctx context.Context, access sshAccess, terminal bool, command []string, stdin io.Reader, stdout, stderr io.Writer) error {
	client, err := openSSH(ctx, access)
	if err != nil {
		return err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdin, session.Stdout, session.Stderr = stdin, stdout, stderr
	if terminal {
		height, width := terminalSize(os.Stdin)
		if err = session.RequestPty("xterm-256color", height, width, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 115200, ssh.TTY_OP_OSPEED: 115200}); err != nil {
			return err
		}
		state, rawErr := makeRawTerminal(os.Stdin)
		if rawErr != nil {
			return fmt.Errorf("configure local terminal: %w", rawErr)
		}
		defer state.Close()
		if err = session.Shell(); err != nil {
			return err
		}
	} else {
		if err = session.Start(remoteCommand(command)); err != nil {
			return err
		}
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err = <-done:
		return err
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		client.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		return ctx.Err()
	}
}

func connectSSH(ctx context.Context, c *cache, terminal bool, command []string, wait bool) error {
	access, err := loadAccess(ctx, c)
	if err != nil {
		return err
	}
	if wait {
		// A successful authenticated command proves usbmux routing, both generated
		// keys, sshd readiness, and command execution before the terminal takes over.
		err = waitFor(ctx, c.out, "authenticated SSH", 3*time.Minute, 5*time.Second, func(ctx context.Context) (bool, error) {
			attempt, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			var output bytes.Buffer
			e := runSSH(attempt, access, false, []string{"printf", "kernel-poc-ready"}, nil, &output, io.Discard)
			if e != nil {
				return false, fmt.Errorf("SSH is not ready: %w", e)
			}
			return output.String() == "kernel-poc-ready", nil
		})
		if err != nil {
			return err
		}
		cleanup := []string{"/bin/bash", "-c", `/usr/sbin/nvram auto-boot=false; /usr/sbin/nvram -d restore-outcome 2>/dev/null || true; /usr/sbin/nvram -d restored-host-timeout 2>/dev/null || true`}
		cleanupCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		err = runSSH(cleanupCtx, access, false, cleanup, nil, io.Discard, os.Stderr)
		cancel()
		if err != nil {
			return fmt.Errorf("restore temporary NVRAM state: %w", err)
		}
	}
	if terminal {
		fmt.Fprintln(c.out, "Opening the phone's shell. Type exit to close; the USB connection will be released.")
	}
	err = runSSH(ctx, access, terminal, command, os.Stdin, os.Stdout, os.Stderr)
	fmt.Fprintln(c.out, "SSH closed; USB connections released.")
	return err
}

func probeSSH(ctx context.Context, c *cache) error {
	access, err := loadAccess(ctx, c)
	if err != nil {
		return err
	}
	attempt, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var output bytes.Buffer
	if err = runSSH(attempt, access, false, []string{"printf", "kernel-poc-ready"}, nil, &output, io.Discard); err != nil {
		return err
	}
	if output.String() != "kernel-poc-ready" {
		return errors.New("SSH readiness marker did not match")
	}
	return nil
}

func ensureShellEnvironment(ctx context.Context, c *cache, terminal bool, command []string) error {
	// One exclusive lock covers state detection and any transition, preventing a
	// second invocation from racing the probe, Recovery endpoints, or usbmuxd.
	return withDeviceLock(c, func() error {
		fmt.Fprintln(c.out, "Checking for a running shell environment")
		sshErr := probeSSH(ctx, c)
		if sshErr == nil {
			fmt.Fprintln(c.out, "Running environment found; reconnecting")
			return connectSSH(ctx, c, terminal, command, false)
		}
		recovery, recoveryErr := discover(ctx)
		if recoveryErr == nil {
			if recovery.IBFL != 0x25 {
				fmt.Fprintf(c.out, "Recovery stage %02X is an incomplete prior boot; returning the phone to its initial loader\n", recovery.IBFL)
				if resetErr := resetToRecoveryLocked(ctx, c); resetErr != nil {
					return resetErr
				}
			}
			fmt.Fprintln(c.out, "Supported initial Recovery phone found; starting the tethered boot")
			return bootLocked(ctx, c, terminal, command)
		}
		if errors.Is(recoveryErr, errNoRecovery) {
			fmt.Fprintln(c.out, "Running environment unavailable; resetting the phone to Recovery")
			if resetErr := resetToRecoveryLocked(ctx, c); resetErr != nil {
				return fmt.Errorf("prepare Recovery after SSH failed (%v): %w", sshErr, resetErr)
			}
			return bootLocked(ctx, c, terminal, command)
		}
		return fmt.Errorf("phone is neither an authenticated running environment nor supported Recovery: SSH: %v; Recovery: %v", sshErr, recoveryErr)
	})
}

func smartShell(ctx context.Context, c *cache) error {
	return ensureShellEnvironment(ctx, c, true, nil)
}

func smartExec(ctx context.Context, c *cache, command []string) error {
	return ensureShellEnvironment(ctx, c, false, command)
}
