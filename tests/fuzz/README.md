# DuetOS — wireless parser fuzz harness

Compile and run libFuzzer-driven fuzzers against the wireless data-decode
parsers (beacon walker, EAPOL key parser, vendor firmware envelope
parsers). The fuzzers run on the host (Linux/macOS clang), not on the
target — they exercise the same source files the kernel builds, with a
small `host_shim/` providing stub implementations of the kernel-only
headers (serial output, klog macros, KASSERT, spinlock).

## What's covered

| Fuzzer | Target parser |
|--------|---------------|
| `fuzz_beacon` | `BeaconParse(frame, len, &out)` — IEEE 802.11 management-frame walker (FC validation, MAC header, Capability info, IE walk with bounds-checked length, RSN/Vendor IE recognition) |
| `fuzz_eapol` | `EapolKeyParse(frame, len, &out)` — 802.1X key descriptor frame parser |
| `fuzz_iwl_fw` | `IwlFirmwareParse(blob, size, &out)` — Intel iwlwifi TLV envelope walker |
| `fuzz_rtl_fw` | `RtlFirmwareParse(blob, size, &out)` — Realtek rtlwifi/rtw88/rtw89 32-byte header |
| `fuzz_bcm_fw` | `BcmFirmwareParse(blob, size, &out)` — Broadcom b43 record stream |

## Why these parsers

These five are the only DuetOS code paths that consume bytes from
external sources (vendor firmware blobs from `/lib/firmware/`,
on-air management frames from a wireless driver). Everything else
inside `kernel/net/wireless/` consumes parsed structures, not raw
bytes. Fuzzing the parsers catches OOB reads / pointer arithmetic
mistakes / length-overflow bugs in exactly the places where a
malicious blob or rogue AP could deliver an attack surface.

## Build and run

```bash
sudo apt-get install -y clang     # or use a system clang ≥ 14
make -C tests/fuzz                # build all five fuzzers
make -C tests/fuzz run-beacon     # fuzz one for 60 s
make -C tests/fuzz run-eapol
make -C tests/fuzz run-iwl_fw
make -C tests/fuzz run-rtl_fw
make -C tests/fuzz run-bcm_fw
```

Each `run-*` target creates `corpus/<name>/` and lets libFuzzer
populate it with interesting inputs. Re-running picks up where the
previous run left off (corpus persistence).

## What the fuzzers will and won't catch

**Will catch:**
- Out-of-bounds reads on the input buffer.
- Length fields whose declared size overflows the buffer.
- Integer overflows in offset arithmetic.
- Infinite loops on malformed inputs.
- AddressSanitizer / UBSAN findings.

**Won't catch:**
- State-machine bugs in MLME or 4-way handshake (those are
  exercised by the in-kernel loopback test
  `kernel/net/wireless/test/wireless_e2e_test.cpp`).
- DMA-path bugs (no real DMA in fuzz harness).
- Per-vendor microcode upload errors (those need real silicon).
- Crypto correctness (covered by the in-kernel KAT self-tests).

## Reproducing a crash

When libFuzzer finds an interesting input, it writes
`crash-<sha1>` next to the binary:

```bash
./build/fuzz_beacon crash-deadbeef     # replay the failing input
```

Inspect the file with `xxd` to understand what the malformed frame
looked like, then fix the parser. Re-run the fuzzer to confirm the
crash is gone.
