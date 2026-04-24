# Kernel entropy pool v0 — RDSEED / RDRAND / splitmix

**Last updated:** 2026-04-22
**Type:** Observation
**Status:** Active — live on QEMU TCG (reports RDSEED tier).
Three-tier pool with hardware backing when available; plus a
boot-time self-test and shell observability.

## Tier ladder

| Tier | Source | Quality | Fallback trigger |
| ---- | ------ | ------- | ---------------- |
| `Rdseed`    | CPU RDSEED (NIST TRNG)  | Cryptographic | Up to 32 retries per call |
| `Rdrand`    | CPU RDRAND (NIST DRBG)  | Cryptographic | Up to 10 retries per call |
| `Splitmix`  | Software splitmix64     | Non-cryptographic (flagged in log) | Always succeeds |

`RandomInit` walks the ladder top-down, verifies each tier with a
single probe read, and locks onto the highest one that succeeds.
The tier is logged at boot:

```
[random] tier=RDSEED (NIST TRNG)
[random] self-test OK — 64 bytes non-trivial (first 8 = a9:fb:33:0a:59:d6:21:3b)
```

## Public API

```cpp
duetos::core::RandomInit();                // seed + probe + log
duetos::core::RandomCurrentTier();         // EntropyTier enum
duetos::core::RandomFillBytes(buf, len);   // bulk
duetos::core::RandomU64();                 // one u64
duetos::core::RandomStatsRead();           // call/success/byte counters
duetos::core::RandomSelfTest();            // boot-time sanity
```

Consumers gate on `RandomCurrentTier() != EntropyTier::Splitmix`
when they need cryptographic quality (crypto keys, signing
material). Non-crypto consumers (PRNG for game RNG, shell
`rand`, test jitter) use whatever tier is available.

## Shell integration

Upgraded `rand` command exposes the pool at the user's prompt:

```
> rand               # one u64 hex line
> rand 10            # ten u64 hex lines (cap 100)
> rand -s            # tier + call counters + bytes-produced
> rand -hex 16       # 16 raw bytes on one hex line (cap 512)
```

The old per-command splitmix state is gone; every `rand` call
now drains the shared kernel pool.

## Self-test

`RandomSelfTest` at boot produces 64 bytes, asserts:

- not all zero
- not all 0xFF
- not trivially monotonic (each byte ≠ prev+1)

Any failure logs `[W] core/random : self-test failed — all-zero
/ all-ff / monotonic` instead of panicking. The three checks
catch the "hardware stuck returning a fixed byte" failure mode
that a more subtle entropy test would miss.

## Stack canary — infrastructure, not wired yet

`core::RandomizeStackCanary()` is declared and implemented; it
pulls a u64 from the entropy pool and installs it as
`__stack_chk_guard`. Trying to call it from `kernel_main`
immediately after `RandomInit` tripped `__stack_chk_fail` —
some function currently holding an OLD cookie on its frame
returns after the update.

The fix is either:
1. A "last function before scheduler-enter" callback so every
   boot init has already unwound.
2. Marking `kernel_main` itself with `no_stack_protector`.

The helper is written + compiles clean; the next slice picks
the invocation point and uncomments one line in `main.cpp`.

## Downstream consumers (future slices)

1. **KASLR** — randomize kernel image base at boot. Needs the
   boot-loader to apply a delta, which Multiboot2 doesn't
   support directly; UEFI + PE-style relocation does. Gated on
   future UEFI boot path.

2. **Per-process ASLR** — randomize the 64 KiB stack VA and PE
   ImageBase when spawning a ring-3 task. PE loader already
   applies relocations (ApplyRelocations in pe_loader.cpp); a
   one-line change swaps the hardcoded base for a random one in
   the canonical-low-half range.

3. **Stack canary** — see above.

4. **UUID / session tokens** — `RandomFillBytes(uuid, 16)` +
   version/variant bits for UUID v4. No consumer yet.

5. **crypto keys** — kcrypto subsystem that doesn't exist yet.
   Will gate on `RandomCurrentTier() >= Rdrand`.

## Files

- `kernel/core/random.{h,cpp}` — the pool.
- `kernel/core/stack_canary.{h,cpp}` — dormant randomization.
- `kernel/core/shell.cpp::CmdRand` — user-facing observability.
