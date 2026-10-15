# Validation

Tests ran on Apple silicon macOS with Go 1.26.9, the supported debug probe, and CPFM00 iPhone 15 Plus hardware. Probe firmware versions may differ. The CLI tests the protocol and target operations that it uses during boot.

## Automated checks

The following commands passed without network access. Each command used a new Go home, build cache, module cache, and temporary directory on the APFS NVMe.

```sh
CGO_ENABLED=0 GOPROXY=off go test -mod=vendor ./...
CGO_ENABLED=0 GOPROXY=off go vet -mod=vendor ./...
CGO_ENABLED=0 GOPROXY=off go build -mod=vendor -o 15-plus-kernel-poc .
```

The tests cover:

- Asset selection, hashes, TLS rules, archive limits, and firmware order.
- Device identity, Image4 policies, loader and kernel patches, access-port discovery, probe transfer sizes, and UART selection.
- Root-field discovery, trust-cache formats 0 through 2, payload checks, Mach-O signing, and image capacity.
- State changes, timeouts, cancellation, locking, serial records, SSH arguments, and cleanup.

Device operations run no host command-line utility.

`govulncheck` found no vulnerability reachable by this program with Go 1.26.9, `golang.org/x/crypto` v0.58.0, and the vendored modules. It reported an `openpgp` advisory for the full `x/crypto` module. This repository neither imports nor vendors that package.

## Physical matrix

| Installed initial loader | Selection path | Result |
| --- | --- | --- |
| `iBoot-8737.0.0.101.5` | Checked adapter | XNU, authenticated SSH, command pack, clean exit. |
| `iBoot-9275.0.0.101.2` | ARM64 analysis | 17 RAM writes, stage `0x25` to `0x24`, XNU, authenticated SSH, storage discovery, command pack, clean exit. |
| `iBoot-9275.0.0.101.11` | ARM64 analysis | 17 RAM writes, stage `0x25` to `0x24`, XNU, authenticated SSH, storage discovery, command pack, clean exit. |

On 2026-10-14, `./15-plus-kernel-poc shell` booted both 9275 builds. The `.101.2` phone was a separate variant with its own loader snapshot. The analyzer needed no build adapter or source change.

For the 9275 runs, the CLI:

- Found the control, routing, and application access ports from their ID registers.
- Changed one byte in the halted loader identity, read that change through Recovery USB from the same ECID, reset the phone, and confirmed the original byte.
- Derived the iBEC policy and root-construction sites from ARM64 instructions.
- Read back all 17 loader writes.
- Moved from stage `0x25` to `0x24`.
- Reached Darwin 25.3.0, XNU `12377.82.2~2`, and `RELEASE_ARM64_T8120`.

Another reset-to-shell run tested probe-firmware variation. `doctor` accepted the probe after its framing, protocol channels, clock control, access ports, target routing, memory reads, and reset operation passed. `exec` returned `root` from XNU.

A later run found the UART through IOKit, kept four-byte and atomic eight-byte debug accesses at their required widths, used bounded chunks for bulk memory, and found the root field from iBEC's live owner data. It ran `commands`, `ls`, `ps`, and `env`, then exited without leaving a device process, UART descriptor, forwarding listener, or repository lock.

The `.101.2` phone reported seven APFS roles; Installer was absent. The CLI did not invent the missing role or assume property order or slice numbers. It mounted Baseband data, Hardware, Preboot, System, Update, and xART with `read-only,nobrowse` under `/mnt/iphone`. It reported Data but left it unmounted because the temporary environment lacked its encrypted metadata keys.

The physical runs also checked `mount`, `commands`, `head`, Bash, `ioreg`, the SSH server, and a caller-supplied marker. Interactive terminals and `exec` released their USB connections on exit. `reset` restarted the phone, saved `auto-boot=false`, observed USB detach and reattach, and confirmed the loader build. Final inspection found no CLI process, lock holder, forwarding process, or listener. Firmware, prepared objects, keys, captures, and serial logs remain in ignored `.cache/` paths.
