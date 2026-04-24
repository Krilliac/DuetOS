# Win32 stubs: callee-saved rdi/rsi bug

**Last updated:** 2026-04-22
**Type:** Issue + Pattern
**Status:** Fixed in critical-path stubs; ExitProcess/TerminateProcess/miss-logger still technically buggy but latent (noreturn or unknown-import paths only)

## The bug

Every hand-assembled Win32 stub that translates the MS x64 calling
convention to the Linux int-0x80 ABI does the obvious moves:

```
mov rdi, rcx     ; Win arg1 -> Linux arg1
mov rsi, rdx     ; Win arg2 -> Linux arg2
mov rdx, r8      ; Win arg3 -> Linux arg3
mov eax, SYS_X
int 0x80
ret
```

This violates Win64's callee-saved contract for **RDI and RSI** (both
are nonvolatile — the caller can legitimately keep live values in
them across the call). After the stub's `ret`, the caller's RDI/RSI
are garbage (= whatever Win args ended up there), and any subsequent
use of them corrupts control flow.

The manifestation that caught us:

```
; Caller wants to malloc(256), free(p1), malloc(256) again.
movq 0x4d40(%rip), %rdi   ; load malloc IAT ptr into rdi
callq *%rdi               ; malloc(256) -> p1
; ... compiler keeps rdi alive across free, expecting preservation
callq *free_IAT           ; free stub does `mov rdi, rcx` → rdi = p1
callq *%rdi               ; jumps to p1 (a heap address, NX) → #PF
```

The crash presented as `rip=cr2=0x5000xxxx, err=0x15` — instruction
fetch from the Win32 heap arena. The address 0x50000060 is exactly
the value `free`'s stub overwrote rdi with.

## The fix

For every stub that mutates a nonvolatile register, wrap with
`push`/`pop`. Each added pair costs 2 bytes; to keep stub offsets
stable (every `kOff*` constant is an ABI to the PE loader), absorb
the growth with a cheaper `mov eax, imm` encoding:

```
Before:                       After (same byte count):
  mov rdi, rcx       (3)        push rdi           (1)
  mov eax, SYS_X     (5)        mov rdi, rcx       (3)
  int 0x80           (2)        push SYS_X         (2)   ; imm8
  ret                (1)        pop rax            (1)
                                int 0x80           (2)
  = 11 bytes                    pop rdi            (1)
                                ret                (1)
                                = 11 bytes
```

`push imm8; pop rax` is 3 bytes vs `mov eax, imm32` at 5 bytes, so
each int-0x80 stub can absorb one push/pop pair for free. Stubs
that save both rdi AND rsi (e.g. WriteFile, HeapReAlloc) need two
compressions to cover both pairs; HeapReAlloc and realloc grew by
2 bytes each (14 → 16), which cascaded a +4 shift across every
kOff constant from kOffMissLogger onward.

## Fixed stubs (as of this entry)

- `HeapAlloc`, `HeapFree`, `malloc`, `free`, `HeapSize` — single rdi
- `HeapReAlloc`, `realloc` — rdi + rsi, **grew by 2 bytes each**
- `WriteFile` — rdi + rsi, fit in original 44 bytes
- `SetLastError` — single rdi
- `InitializeCriticalSection` — rdi (`rep stosb` destination)
- `calloc` — rdi (stosb dst)
- `sputn` (basic_streambuf) — rdi + rsi

## Known latent bugs (not yet fixed)

- `ExitProcess` (0x00), `TerminateProcess` (0x58), `kOffTerminate`
  (0xCA), `kOffInvalidParam` (0xD5) — [[noreturn]], never return
  to the caller, so a trashed rdi doesn't matter in practice.
- `miss-logger` (0x24A, was 0x246 pre-shift) — called only for
  **unresolved** imports. User code only hits it if it depends on
  an import DuetOS doesn't stub, which the current workloads
  don't. Still worth fixing for hygiene.

## Rules going forward

1. **Any new stub that touches rdi/rsi/rbx/rbp/r12–r15 MUST
   push/pop it.** Win64 ABI is non-negotiable.
2. **Any new stub with `int 0x80` should use `push imm8; pop rax`
   for its syscall number** (if imm fits in 7 bits). Saves 2 bytes
   per stub; pays for the rdi preservation.
3. **Never shift an existing kOff\* constant without updating every
   consumer** — the PE loader's import resolver reads these
   directly. Use a Python helper (see
   `.claude/knowledge/win32-stubs-rdi-rsi-abi.md` history) to do
   bulk renumbering atomically.

## Detection

`hello_winapi` batch 48 is the canonical multi-primitive stress
test — 4 mutexes + 4 events + 4 VM pages + 4 heap blocks + 8 TLS
slots, 1000 iterations of mixed ops, then verify + cleanup. If any
stub along the Win64-to-Linux bridge trashes rdi/rsi, b48 crashes
with rip pointing into the Win32 heap arena (0x5000xxxx) or into
the caller's stack (0x7fff....). Watch for those crash signatures.
