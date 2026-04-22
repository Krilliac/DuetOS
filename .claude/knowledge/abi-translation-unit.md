# ABI translation unit

**Last updated:** 2026-04-22
**Type:** Observation
**Status:** Active — LinuxGapFill shipped with 7 translations + on-boot exerciser

## Description

A small peer of `subsystems/linux/` and `subsystems/win32/` that
catches syscalls the primary dispatcher doesn't implement and
either (a) synthesizes them from existing primitives, (b) routes
to a semantically-equivalent operation in another subsystem, or
(c) no-ops when the semantics allow it. Every action logs a
`[translate] …` line so the boot log shows exactly what was
filled and what remains unimplemented.

## Layout

```
kernel/subsystems/translation/
  translate.h       Public API — Result LinuxGapFill(frame)
  translate.cpp     Per-syscall translation table + helpers
```

## Integration

`LinuxSyscallDispatch`'s `default:` arm calls `LinuxGapFill` before
surfacing `-ENOSYS`:

```cpp
default:
{
    const auto t = translation::LinuxGapFill(frame);
    if (t.handled) rv = t.rv;
    // else: rv is still -ENOSYS and the TU already logged the miss.
    break;
}
```

Exposed handler wrappers in `subsystems/linux/syscall.h`:
`LinuxRead`, `LinuxWrite`, `LinuxClockGetTime`, `LinuxNowNs` —
the TU synthesizes larger calls (readv, gettimeofday) from these.

## Current translations (slice 20)

| Linux # | Linux call | Strategy |
|---------|-----------|----------|
| 19 | readv | Loop over LinuxRead per iovec (primary has writev, not readv) |
| 28 | madvise | Noop — hints advisory until real page cache |
| 74 | fsync | Noop — writes unbuffered in kernel, always durable |
| 75 | fdatasync | Noop — same as fsync |
| 96 | gettimeofday | Reshape LinuxNowNs → timeval (tv_sec + tv_usec) |
| 99 | sysinfo | Zeroed struct + uptime from HPET |
| 302 | prlimit64 | RLIM64_INFINITY for old; ignore new |
| 334 | rseq | Deliberate -ENOSYS, logged distinctly |

## Log format

```
[translate] linux/0x<nr_hex> -> <short-target-tag>
[translate] linux/0x<nr_hex> unimplemented -- no translation
```

Grep-friendly:
- `grep '\[translate\]' boot.log | grep -v unimplemented` — what was filled
- `grep '\[translate\].*unimplemented'` — the honest-to-goodness missing set

Target tags in use:
- `linux-self:<description>` — synthesized from other Linux handlers
- `synthetic:<description>` — fabricated from primitives (HPET, constant structs)
- `noop:<why>` — accepted as a no-op with reason
- `native:SYS_X` — routed to a native kernel syscall (future; none ship today)

## Why Win32 isn't wired yet

Win32 in CustomOS is a user-mode shim — each PE gets `ntdll` /
`kernel32` equivalents patched into its IAT, and those stubs
trampoline through native int-0x80 syscalls. There's no peer
kernel dispatch to consult; whatever Win32 "has" is just a
particular native call. The moment native-missing → Linux
translation matters, it goes through this same `Result`-returning
pattern.

## Boot-time exerciser

`SpawnRing3LinuxTranslateSmoke` (in subsystems/linux/ring3_smoke.cpp)
fires a 47-byte ring-3 payload that invokes:
  - `sys_madvise(0x7F000000, 4096, 0)` → TU: noop
  - `sys_rseq(0, 0, 0, 0)` → TU: deliberate -ENOSYS
  - `exit_group(0x42)`

Every boot produces the two `[translate]` lines. Works as a live
smoke; recording any future translation can follow the same
pattern (small dedicated ring-3 task).

## Adding a translation

1. Decide the strategy: synth-from-existing, synth-from-primitive,
   noop, or deliberate-enosys.
2. Add a `TranslateX(frame)` in `translate.cpp`'s anon namespace.
3. Add a `case` to the `LinuxGapFill` switch with a call to
   `LogTranslation(origin, nr, target_tag)` + return `{true, rv}`.
4. If it synthesises from another Linux handler you don't yet
   have wrappered, add a wrapper in `subsystems/linux/syscall.{h,cpp}`.

## Known limits

- Translations don't preserve errno detail from underlying ops
  beyond what the synthetic handlers produce. A composite call
  failing midway returns the first handler's error, not a
  composed error code.
- No native → Linux direction yet. Would need a
  `NativeGapFill(frame)` entry point called from
  `core::SyscallDispatch`. Pattern is identical.
- Stats / counters are not kept — which translations fire most
  often isn't tracked. Adding a u64 `g_translate_hits[256]`
  would surface which ones to promote to primary implementations.

## References

- `kernel/subsystems/translation/translate.{h,cpp}` — the TU
- `kernel/subsystems/linux/syscall.{h,cpp}` — primary dispatcher
  + exposed helper wrappers
- `kernel/subsystems/linux/ring3_smoke.cpp::SpawnRing3LinuxTranslateSmoke`
- `.claude/knowledge/linux-abi-subsystem.md` — primary-dispatch
  syscall table
