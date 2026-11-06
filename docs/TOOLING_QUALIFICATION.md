# Tooling qualification

Qualification date: 2026-11-05 (America/Los_Angeles)

This report distinguishes tooling success from the remaining ProductOS UI
research boundary. It does not claim a visible UI.

## Host qualification

- `go test ./...` passes, including the exact prepared-kernel integration test
  with base kernel IM4P SHA-256
  `fbea83d1bf68046bb983327efcc11b2379d439f6d9a9475616e91d0d990bc4ae`.
- The final caller-authorization transform changes exactly five decoded-kernel
  bytes inside the 120-byte selector-24 range. The already-qualified
  selector-33 wrapper is byte-for-byte unchanged. Every byte outside that
  selector-24 range is checked unchanged and the inverse is exact.
- Prepared kernel identities are decoded SHA-256
  `db77ede6f8e14c117ed23fe4ac415ff2165388298e0cab38c6ec284ff6ccfc22`
  and IM4P SHA-256
  `a13957e74baea0b6951881a99a9e19c03ed349409f4761da568495f24b4b0c0f`
  (20,356,524 bytes).
- A complete MonkeyBars bundle import verified and content-addressed all 12
  executable, framework, metadata, launchd, Lockdown, version, and provenance
  files. Later runs used no original source path or hand-entered CDHash.
- Guarded cache GC reclaimed 1,679 MiB of owned test/build scratch. Its tests
  prove that objects, private state, logs, loader analysis, and canonical Go
  caches remain protected.

## Physical qualification

The supported CPFM00 iPhone 15 Plus and debug probe passed `doctor` before the
runs. The first integration attempt exposed an unsafe full-cave rewrite and
panicked after the ramdisk mounted. UART evidence identified an undefined
instruction. The implementation was corrected before proceeding: it now
changes only the five measured selector-24 bytes and preserves the existing
selector-33 wrapper plus all other predecessor bytes.

After correction:

1. Two tethered boots reached the root service in approximately two seconds,
   mounted all six accessible internal APFS roles read-only, installed the
   volatile admission receipt, and exposed authenticated SSH.
2. A 2,515,536-byte arm64 caller binary was normalized to
   `CS_ADHOC|CS_LINKER_SIGNED`, uploaded over SSH, read back exactly, and ran to
   the caller-unique terminal `gate-probe-a-ok`.
3. Without resetting, a distinct 1,682,832-byte caller binary replaced it. The
   tool deleted the stale content object, performed exact target readback, and
   ran to `gate-probe-b-ok`. No iBEC, trust-cache, ramdisk, kernel, or firmware
   upload occurred for the second identity.
4. A fresh boot pre-created `/usr/local/bin/payload-runner` and the nested
   iRemoteFramebuffer framework destination. `ui run -- -h` automatically
   normalized and uploaded MonkeyBars (139,440-byte source) and
   iRemoteFramebuffer (215,280-byte source), verified their transformed target
   bytes, and reached dyld execution.
5. Post-run cleanup returned the board to persistent outer Recovery. A separate
   `doctor` then re-proved IBFL `0x25`, the installed iBoot identity, the CPFM00
   topology, probe target operations, and UART availability with no retained
   device-facing process.

## Current product boundary

`ui run` now reduces UI iteration to one command on an existing live boot. Its
current terminal is a real ProductOS runtime boundary, not a tooling or AMFI
admission failure:

```text
dyld cache '(null)' not loaded: code signature registration for shared cache failed
Library not loaded: /System/Library/Frameworks/QuartzCore.framework/QuartzCore
```

MonkeyBars and its caller-owned framework have already passed signing,
authorization, transfer, exact readback, and process entry. The next research
question is therefore narrowly: make the mounted ProductOS shared cache
register/map in this process context, or provide an equivalent ProductOS
execution context that already owns that mapping. Reopening iBoot, per-binary
CDHash wiring, serial chunk uploads, or manual framework staging does not
address this terminal.

## Host-only native-executable staging qualification

Qualification date: 2026-11-06 (America/Los_Angeles). This is a host-tooling
result only; no device run or UI capability is claimed.

- `--preserve-native FILE=DEST` is explicit and leaves ordinary payload and UI
  normalization unchanged.
- The validator requires one regular thin iOS executable, verified primary
  CodeDirectory page hashes, a non-ad-hoc primary CodeDirectory, a nonempty CMS
  envelope, and an existing `LC_UUID` before it records the original SHA-256
  and CDHash.
- Focused tests prove byte-for-byte preservation, reject a modified signed code
  page, ad-hoc flags, an invalid CMS envelope, and a native dylib, and prove the
  exact service-chain option ordering plus unchanged default UI arguments.
- Service-chain parsing permits exactly one native executable before the target
  argument delimiter. The service-chain report records its destination and the
  payload report records its exact preserved identity.
