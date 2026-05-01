# Wireless loopback test + fuzz harness v0

**Last updated:** 2026-05-01
**Type:** Observation + Decision + Pattern
**Status:** Active — loopback runs in QEMU smoke (4 cases pass); 5 host fuzzers run clean for ~95M total executions

## Description

Two parallel verification tracks for the wireless control tier
that landed in `wireless-control-tier-v0.md`. Together they
catch the bulk of bugs that real-hardware bring-up would
otherwise have to expose:

1. **In-kernel loopback test** (`mac80211_hwsim` equivalent) —
   software FakeAp peer + LoopbackDriver wired through the same
   `WirelessDeviceOps` vtable a real driver registers. Exercises
   the full Connect flow (scan + auth + assoc + 4-way handshake +
   key install) in pure software, and asserts both endpoints
   derive the same TK / GTK. Runs as a boot self-test under
   QEMU.
2. **Host fuzz harness** — five libFuzzer-driven binaries that
   exercise the data-decode parsers (`BeaconParse`, `EapolKeyParse`,
   `IwlFirmwareParse`, `RtlFirmwareParse`, `BcmFirmwareParse`)
   under AddressSanitizer + UndefinedBehaviorSanitizer. Catches
   OOB reads, length-overflow mistakes, integer overflow,
   infinite loops on malformed input.

This consolidates everything possible to verify on the dev host
before physical-hardware bring-up. The remaining real-HW-only
gates (DMA-coherent alloc, per-vendor microcode upload,
chip-side TX/RX rings) are still gated as documented in
`wireless-control-tier-v0.md`.

## Files

### Loopback (kernel-side)

- `kernel/net/wireless/test/fake_ap.{h,cpp}` — software AP peer
  state machine. Holds the same PSK as the supplicant, derives
  PMK independently, generates ANonce, builds M1 / M3 with
  proper MICs (computed using its own derived PTK), processes
  M2 / M4 with MIC verification. Exposes the locked-in TK/GTK
  via `FakeApInstalledTk` / `FakeApInstalledGtk` so the test
  can compare against what the supplicant installed.
- `kernel/net/wireless/test/loopback_driver.{h,cpp}` —
  implements all 9 `WirelessDeviceOps` (Up/Down/Scan/
  Authenticate/Associate/Disconnect/InstallKey/SendMgmtFrame/
  SendEapolFrame). Each op routes the request to FakeAp +
  re-enters the supplicant via `WirelessDeliver{Beacon,Mgmt,
  Eapol}` with the synthesized response.
- `kernel/net/wireless/test/wireless_e2e_test.{h,cpp}` — the
  test harness. Four cases:
  1. **Success:** correct PSK → handshake completes →
     `wdev->op_state == Connected`, STA's TK matches AP's TK
     byte-for-byte, STA's GTK matches AP's GTK byte-for-byte.
  2. **Wrong PSK:** STA's PMK ≠ AP's PMK → MIC verify on M2
     fails on the AP side → AP transitions to Failed → STA
     never installs keys.
  3. **Replay:** after a successful handshake, inject an M1
     with a stale (zero) replay counter → state machine
     rejects with `Corrupt` → `retries_seen` advances.
  4. **MIC tamper:** craft an M3 with valid MIC, then flip
     one byte in the body → supplicant's MIC verify rejects
     → `mic_failures` advances.

### Wdev gap-fill

- `kernel/net/wireless/wdev.{h,cpp}` — added `SendEapolFrame`
  to `WirelessDeviceOps`. Filled the gap where
  `WirelessDeliverEapol` processed M1/M3 but never built M2/M4
  to send back. Now: after M1 advances state to AwaitingM3,
  build M2 + call `ops.SendEapolFrame`. After M3 advances to
  AwaitingM4Ack and keys are installed, build M4 + call
  `ops.SendEapolFrame` + transition to Established/Connected.
  Bumped `kWdevMaxDevices` from 4 to 8 to fit the 4 e2e cases
  + the existing WdevSelfTest registration.

### Fuzz harness (host-side)

- `tests/fuzz/Makefile` — standalone Makefile. Builds five
  fuzzer binaries with `clang++ -fsanitize=fuzzer,address,undefined`.
  Targets: `make`, `make run-beacon`, `make run-eapol`,
  `make run-iwl_fw`, `make run-rtl_fw`, `make run-bcm_fw`,
  `make clean`.
- `tests/fuzz/host_shim/` — minimal stubs for kernel-only
  headers so the parser TUs compile in a hosted environment:
  `util/types.h`, `util/result.h`, `core/panic.h`,
  `arch/x86_64/serial.h`, `sync/spinlock.h`, `time/tick.h`,
  `log/klog.h`, `diag/cleanroom_trace.h`,
  `net/wireless/wifi_diag.h`. Stubs are minimal: serial
  output and klog macros are no-ops; spinlocks are no-ops;
  KASSERT delegates to `assert()`.
- `tests/fuzz/fuzz_{beacon,eapol,iwl_fw,rtl_fw,bcm_fw}.cpp`
  — one per parser. Each is a 14-line `LLVMFuzzerTestOneInput`
  driver.
- `tests/fuzz/README.md` — usage docs + scope ("what the
  fuzzers will/won't catch").

## Why this slice

User asked: *"is there a way we could 'Emulate' the hardware
required and at least get some form of verification/testing?"*
The honest answer was three options at different costs:

1. In-kernel software loopback (cheapest, ~1k LOC).
2. QEMU device-model emulation (very expensive, ~3-5k LOC of
   QEMU C, rejected — cost-to-coverage ratio is bad).
3. Frame-level fuzz harness (moderate, complementary).

User picked #1 + #3. This slice delivers both. Together they
cover the full data-decode tier (#3) and the full control-tier
state machines (#1) — i.e., everything that's locally
verifiable without real silicon.

## Scope

### Covered

**Loopback test (4 cases):**
- Successful WPA2-PSK Connect end-to-end with key match
  byte-for-byte between AP and STA endpoints.
- Wrong-PSK rejection (MIC fail on M2).
- Replay-counter rejection (stale M1).
- MIC-tamper rejection (corrupted M3).

**Fuzz coverage (5 parsers):**
- `BeaconParse`: ~8 M executions / 45 s, 1440 new corpus units.
- `EapolKeyParse`: ~22 M executions / 45 s, 12 new units.
- `IwlFirmwareParse`: ~15 M executions / 45 s, 289 new units.
- `RtlFirmwareParse`: ~30 M executions / 45 s, 24 new units.
- `BcmFirmwareParse`: ~20 M executions / 45 s, 43 new units.
- Total: ~95 M executions / 225 s. Zero crashes, zero ASan
  reports, zero UBSan reports.

### Bugs caught while landing this slice

- **PBKDF2-WPA "password"/IEEE KAT had wrong reference
  bytes.** The original hardcoded test value
  (`...3a ab 11 e4 d2 80 18 70`) was wrong; Python's
  `hashlib.pbkdf2_hmac` and our implementation both produce
  `...3a ed 76 2e 97 10 a1 2e`. The error was in my recall of
  the IEEE 802.11i Annex H vector. The kernel code itself was
  correct — only the test fixture was wrong. Fixed.
- **`WirelessDeliverEapol` never sent M2 / M4.** Caught by
  the loopback test: handshake stalled because the supplicant
  derived PTK on M1 but never transmitted M2 to the AP. Fixed
  by extending `WirelessDeviceOps` with `SendEapolFrame` and
  having `WirelessDeliverEapol` build + send M2/M4 after
  state advancement.
- **`kWdevMaxDevices = 4` too small for 4 e2e cases + WdevSelfTest
  registration.** Bumped to 8.

### Deliberately not in scope

- QEMU device-model emulation. Discussed and rejected — cost
  outweighs benefit (would test our matches-Intel-docs, not
  matches-real-silicon).
- Real-HW-gated paths: DMA upload, per-vendor section copy,
  chip-side TX/RX rings, IRQ wiring. These remain gated on
  physical bring-up.
- WPA3-SAE end-to-end (no EC primitives yet; classified
  correctly by `BeaconParse` but the SAE protocol exchange
  isn't implemented).

## Integration points

- `kernel/core/main.cpp` adds one new boot self-test:
  `WirelessE2ESelfTest`. Wired after the per-vendor upload
  self-tests so any failure in the underlying primitives
  surfaces first.
- `kernel/CMakeLists.txt` — no change. Auto-globbed.
- The fuzz harness lives outside the kernel build entirely.
  Run via `make -C tests/fuzz`.

## Observable

Boot log on a passing run (QEMU smoke):

```
[wifi-diag] online — ring capacity 0x200 events
[iwl-fw] selftest pass
[rtl-fw] selftest pass
[bcm-fw] selftest pass
[80211] beacon selftest pass
[wifi-e2e] starting end-to-end loopback self-tests
[wifi-e2e] success-case pass — keys match across endpoints
[wifi-e2e] wrong-psk pass — handshake correctly rejected
[wifi-e2e] replay-protection pass — stale counter rejected
[wifi-e2e] tamper pass — corrupted M3 rejected
[wifi-e2e] all 4 cases pass
```

Fuzz harness output:

```
$ make -C tests/fuzz CXX=clang++
$ make -C tests/fuzz run-iwl_fw
#2  INITED cov: 4 ft: 5 corp: 1/1b exec/s: 0 rss: 32Mb
... (libFuzzer output) ...
stat::number_of_executed_units: 15272072
stat::average_exec_per_sec:     332001
stat::peak_rss_mb:              517
```

If a crash were ever found, libFuzzer drops a `crash-<sha1>`
file next to the binary; replay with
`./build/fuzz_iwl_fw crash-<sha1>` to reproduce.

## Edge cases / what to remember

- **Loopback tests recursion depth.** The full handshake re-enters
  the kernel stack 3 times: `LoopbackDriverDrive` →
  `WirelessDeliverEapol` (M1) → `ops.SendEapolFrame` (M2) →
  `FakeApProcessM2BuildM3` → `WirelessDeliverEapol` (M3) →
  `ops.InstallKey` × 2 → `ops.SendEapolFrame` (M4) →
  `FakeApProcessM4`. Each frame is small (no large locals),
  so the kernel stack handles it. If you add ops that
  re-enter further, watch the stack budget.
- **Test assertions print first mismatch byte.** The success
  case uses `BytesEqual` for TK/GTK comparison. If a future
  change subtly breaks PRF derivation, the assertion prints
  the entire pmk/want hex side-by-side before panicking, which
  is much easier to debug than "byte at index N differs".
- **FakeAp ANonce is deterministic.** v0 generates ANonce as
  `0xA0 ^ ap_mac[i%6] ^ i` so the test is fully reproducible.
  Real APs use a CSRNG. When DuetOS grows a RNG-driven nonce
  source, the test should switch — but for now determinism
  helps debugging.
- **WdevSelfTest reuses the wdev table.** Registering a new
  wdev for each test case (4 e2e + 1 WdevSelfTest = 5) hit the
  4-slot cap. Bumped to 8 — enough for the existing tests
  plus 3 future ones. If we add more, bump again.
- **Fuzz harness uses host clang, not kernel clang.** The
  parsers are pure C++ with no kernel-only dependencies, so
  they compile fine on a hosted target. If a future parser
  starts depending on kernel-internal headers (e.g.
  scheduler), it can't be fuzzed without expanding the shim.
- **Fuzz corpus persists.** Each `run-*` target writes interesting
  inputs to `corpus/<name>/`. Re-running picks up where the
  previous run left off — so over time the fuzzer finds more
  edge cases. To start fresh: `make clean`.
- **Sanitizer triple.** `fuzzer,address,undefined` together.
  ASan catches OOB; UBSan catches integer overflow / unaligned
  access; libFuzzer drives the input-mutation engine.
- **Required packages on Ubuntu/Debian.** `clang` + `libclang-rt-18-dev`
  (the ASan/Fuzzer runtime libs aren't shipped with `clang`
  alone). `apt install clang libclang-rt-18-dev` is sufficient.

## Source attribution

- `mac80211_hwsim` (Linux) is the architectural inspiration for
  the loopback design. No code lifted; the structure is
  directly equivalent (fake driver + state-machine peer +
  same supplicant under test).
- libFuzzer is a clang/LLVM upstream tool. Standard usage.
- IEEE 802.11i / RFC 2898 / RFC 6070 reference test vectors
  used to validate PBKDF2 implementation.

## See also

- `wireless-control-tier-v0.md` — the slice this verifies.
- `feature-gaps-end-user-v0.md` P0 #4 — the underlying gap.
- `ieee80211-beacon-parser-v0.md` — beacon walker fuzzed by
  `fuzz_beacon`.
- `wireless-fw-parsers-v0.md` — three vendor parsers fuzzed
  by `fuzz_{iwl,rtl,bcm}_fw`.
