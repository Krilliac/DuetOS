# ABI Translation Layer

> **Audience:** ABI implementors, kernel hackers extending Win32 / Linux
> coverage
>
> **Execution context:** Kernel — runs in the syscall dispatch hot path
>
> **Maturity:** v0 — native-gap and NT→Linux fills wired; per-call
> coverage reporter active

## Overview

The translation layer is a thin module that **bridges** the Win32 and
Linux subsystems through the native DuetOS syscall surface. It lives
at [`kernel/subsystems/translation/`](../../kernel/subsystems/translation/).

Its job:

- When the native syscall surface is missing a primitive the Linux ABI
  needs (e.g. an older Linux flavour or a syscall that has no native
  equivalent), `NativeGapFill()` synthesises the right return-shape
  from neighbouring primitives. The Linux caller sees a successful
  result; the native ABI table did not have to grow a row.
- When NT thunks reach the kernel (via `int 0x2E` on the Win32 NT
  surface), `NtTranslateToLinux()` is available as a future bridge for
  paths where the NT shape is close enough to a Linux shape that
  routing through Linux is cheaper than building a dedicated native
  implementation.
- A boot-time **coverage reporter** emits one line summarising how
  many of the in-table Linux + NT syscalls have been observed during
  this boot, with a sample of misses. CI grepss for this.

The layer is intentionally **not** a general-purpose ABI converter.
Every translation it performs is hand-written, with an explicit
argument shuffle and an explicit error-space mapping. There is no
data-driven "table of shapes."

## Why a Translation Layer at All

The [Subsystem Isolation](../kernel/Subsystem-Isolation.md) rule says
"no subsystem-to-subsystem coupling" — Win32 cannot call Linux, Linux
cannot call Win32. The translation layer is the **only** code that
spans both. It exists because:

- Some Linux primitives (`io_uring`, `pidfd_*`, `splice`) have no NT
  analogue worth modelling. When a PE calls them through a compat
  shim, the layer fills the gap.
- The native syscall surface tries to stay small. When growing it
  would mean two near-duplicate calls (native `SYS_FOO` + Linux
  `__NR_foo` with one trivial shape difference), the translation
  layer lets the native side stay generic and the Linux side adapt.

The discipline that keeps the layer from becoming a junk drawer is the
**coverage reporter**: every translation is logged sample-rate-limited,
and a translation that never fires within a boot is a candidate for
removal at the next audit.

## Public Surface

```cpp
namespace translation {

// Fill in a native syscall that returned -ENOSYS by synthesising the
// result from neighbouring primitives. Called from the native dispatch
// path when a row maps to nothing concrete.
void NativeGapFill(TrapFrame*);

// Translate an NT syscall trap frame to a Linux primitive. The Linux
// dispatch path then runs the request and writes the result back
// using NT errno mapping.
void NtTranslateToLinux(TrapFrame*);

// Name lookup — used by the coverage reporter and by kdbg.
const char* LinuxName(u64 nr);
const char* NtName(u64 nr);

// CI hook — emit one line per boot with translation stats.
void TranslatorBootSummaryEmit();

}
```

## Argument Shape Translation

Each cross-ABI call carries three shape concerns:

1. **Argument register layout.** Linux uses the System V AMD64 ABI
   (RDI, RSI, RDX, R10, R8, R9). NT x64 uses RCX, RDX, R8, R9 plus the
   stack. The native syscall ABI uses RDI, RSI, RDX, R10, R8, R9 (deliberately
   chosen to match Linux on the syscall edge — see
   [Syscall ABI](../specifications/Syscall-ABI.md)). Translating from NT
   means a register shuffle.
2. **Argument types.** Path arguments need UTF-16 ↔ UTF-8 in some
   cases. Handle arguments need translating from NT `HANDLE` to native
   handle table indices.
3. **Return-space mapping.** Native returns `Result<T, ErrorCode>`
   (packed into RAX). Linux returns positive value or negative errno.
   NT returns `NTSTATUS` (top-bit-set = error). Mapping rules live in
   `error.h`; the translator picks the right direction.

Example — Linux `clone()` with `CLONE_THREAD|CLONE_VM` is routed to
the native thread-create syscall:

```text
Linux clone():
   rdi = flags    (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND | ...)
   rsi = child_stack
   rdx = parent_tid_ptr
   r10 = child_tid_ptr
   r8  = tls

Native SYS_THREAD_CREATE:
   rdi = entry_rip       (must derive from caller's RIP + child_stack tail)
   rsi = stack_top       (= child_stack)
   rdx = tls_base        (= tls)
   r10 = thread_id_out   (-> *parent_tid_ptr on success)

Return:
   parent: thread id (positive)
   child:  0
```

The errno-space mapping for the same example: native returns
`Ok{tid}` or `Err{ErrorCode::OutOfMemory}` → `NoMemory` translates to
Linux `-ENOMEM` (-12).

## Miss Sampling

A naive log-on-every-miss approach drowns the serial console as soon
as a high-throughput Linux app hits an unmapped syscall. The translation
layer rate-limits its `[translate]` log lines using power-of-two
sampling:

- First **3** misses on a given syscall number — always logged.
- Subsequent misses — logged at hits 4, 8, 16, 32, 64, 128, …

The full miss count is exposed in the boot summary:

```
[translate] native_calls=18234 nt_calls=84 misses=12 (samples: linux:329 nt:0x18)
```

CI greps for `[translate] native_calls=` and asserts the miss count is
zero on a clean boot.

## Coverage Reporter

`TranslatorBootSummaryEmit()` is wired into the late-boot phase. It
walks the per-syscall counters and prints one summary line. The
counters are also queryable from the shell — `translate stats` —
returning per-call hit counts.

Use cases:

- Find Linux syscalls that the smoke profile never exercises. If a
  call site claims to support `__NR_renameat2` but the counter is
  zero across every smoke profile, the support is unverified and
  belongs on the audit list.
- Find NT syscalls that translation has decided to route through
  Linux. A new NT slice may want to claim those for direct native
  implementation.

## Threading and Locking

- The translation calls themselves are **stateless**. They read the
  caller's trap frame, perform the shuffle, and call into the target
  ABI's dispatcher. Concurrent translations on different CPUs are
  independent.
- The coverage counters are atomic `u64` increments. No lock.
- The miss-sample logger uses one atomic per syscall number plus an
  `if (popcount(count) == 1)` test to decide whether to emit.

## Known Limits / GAPs

- **`NtTranslateToLinux` is available but not yet wired** in the NT
  dispatch hot path. The first NT shape that benefits from it lands
  with the next-slice work on `NtCreateThreadEx` argument shuffling.
- **Locale and thread-info classes** are not exposed through
  translation — they are NT-only concepts with no Linux analogue
  worth bridging. `// GAP:` markers in `translate.cpp` pin the
  specific calls.
- **fork() / execve() / clone3()** are intentionally not translated.
  The native ABI does not yet have a process-fork primitive (see
  [Process Model](../kernel/Process-Model.md)) and translation can't
  invent one.
- **No SECCOMP-style filter integration.** Translation runs *before*
  the syscall dispatch; SECCOMP-equivalent gating would need to apply
  after the translation completes.

## Related Pages

- [Subsystem Isolation](../kernel/Subsystem-Isolation.md) — the
  isolation rule the translation layer is the lone exception to
- [Linux ABI](Linux-ABI.md) — the consumer on one side
- [Win32 PE Subsystem](Win32-PE-Subsystem.md) — the consumer on the
  other
- [Syscall ABI](../specifications/Syscall-ABI.md) — native register
  layout
- [Process Model](../kernel/Process-Model.md) — thread creation,
  clone() story
