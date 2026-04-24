# ABI translation unit

**Last updated:** 2026-04-22 (post bidirectional + expand)
**Type:** Observation
**Status:** Active — bidirectional (Linux + native), 18 Linux translations, 4 native translations, hit-counter telemetry, shell `translate` diagnostic

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

## Linux-side translations (as of slice 24)

| Linux # | Linux call | Strategy |
|---------|-----------|----------|
| 19 | readv | Loop over LinuxRead per iovec |
| 22 | pipe | Deliberate -ENOSYS (no IPC) |
| 28 | madvise | Noop — hints advisory |
| 41 | socket | Deliberate -ENOSYS (no network) |
| 74 | fsync | Noop — writes unbuffered |
| 75 | fdatasync | Noop — same |
| 95 | umask | Return 022 (traditional default) |
| 96 | gettimeofday | Reshape LinuxNowNs → timeval |
| 97 | getrlimit | RLIM_INFINITY for old |
| 99 | sysinfo | Zeroed struct + uptime from HPET |
| 111 | getpgrp | Return 0 |
| 137 | statfs | Zeroed struct with FAT32-style totals |
| 138 | fstatfs | Same as statfs |
| 160 | setrlimit | Accept + no-op |
| 293 | pipe2 | Deliberate -ENOSYS |
| 302 | prlimit64 | RLIM64_INFINITY for old; ignore new |
| 334 | rseq | Deliberate -ENOSYS |

## Native-side translations

Called from `core::SyscallDispatch`'s default arm. Experimental
syscall numbers (0x200+) well past the committed native ABI —
any caller uses them ahead of a formal primary handler.

| Native # | Behavior |
|---|---|
| 0x200 | `NativeClockNs` — returns `LinuxNowNs()` |
| 0x201 | `NativeGetRandom(buf, count)` — xorshift64 from rdtsc |
| 0x210 | `NativeWin32Alloc(size)` — `Win32HeapAlloc` on current process |
| 0x211 | `NativeWin32Free(ptr)` — `Win32HeapFree` |

## Hit counters

`HitTable g_linux_hits` / `g_native_hits` — 1024-bucket arrays
keyed by `syscall_nr & 0x3FF`. Bumped once per successful
translation (saturating at 2^32-1).

Accessors:
```cpp
const HitTable& LinuxHitsRead();
const HitTable& NativeHitsRead();
```

Shell command: `translate` — prints every non-zero bucket per
direction. Run after a workload to see which translations fire
most; those are the ones to consider promoting to primary
handlers.

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

## Win32 integration

Win32 in DuetOS is a user-mode shim — each PE gets `ntdll` /
`kernel32` equivalents patched into its IAT, and those stubs
trampoline through native int-0x80 syscalls. So there's no peer
kernel dispatch to consult; what the TU exposes instead is
direct kernel-side access to the Win32 heap primitives
(`Win32HeapAlloc` / `Win32HeapFree`) via two of its native
translations. Any Win32 stub that wants a Linux semantic (or
vice versa) reaches it via:

```
Win32 stub  ──int 0x80──>  native SyscallDispatch
                                │
                                └─> default arm ──> NativeGapFill
                                                         │
                                                         └─> Linux handler / Win32 heap
```

Same three-layer pattern Linux-side uses:

```
Linux task  ──syscall──>  LinuxSyscallDispatch
                                │
                                └─> default arm ──> LinuxGapFill
                                                         │
                                                         └─> Linux handler / synth
```

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
