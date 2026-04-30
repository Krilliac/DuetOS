# mini_browser — a real Windows PE on DuetOS reaches google.com end-to-end

**Last updated:** 2026-04-30
**Type:** Observation + Issue + Pattern
**Status:** Active

## Description

A real Windows PE binary (PE32+, mingw-w64-built, imports
kernel32 + ws2_32) executes in ring 3 on DuetOS and reaches
www.google.com over real DNS + TCP, printing Google's HTTP
response back to the console:

```
[mini_browser] starting
[mini_browser] connected
[mini_browser] request sent
[mini_browser] reply: HTTP/1.1 426 Upgrade Required
[mini_browser] done
```

Previously the only "ran a real Windows PE" data point was
`windows-kill.exe` printing its banner and exiting. mini_browser
extends that by exercising the WinSock 2 surface end-to-end:
WSAStartup → gethostbyname → socket → connect → send → recv →
closesocket → WSACleanup, every call reaching real network I/O.

This is the "rinse and repeat" iteration target the project
roadmap had reserved for "run Chrome." Chrome's full surface
remains years of work — D3D11/12, V8 JIT, multi-process IPC,
schannel TLS, GDI+, etc. — but the L4 portion of "browser
reaches google.com" is now real.

## Reproducer

```bash
# One-time deps
sudo apt-get install -y qemu-system-x86 grub-common grub-pc-bin \
    grub-efi-amd64-bin xorriso mtools ovmf gcc-mingw-w64-x86-64

# Optional: rebuild mini_browser.exe from C source
userland/apps/mini_browser/build.sh

# Build kernel + ISO
cmake --preset x86_64-debug
cmake --build build/x86_64-debug

# Boot the live-internet GRUB entry (passes netsmoke=force).
# mini_browser is in the unconditional ring-3 smoke list, so the
# default entry exercises it too — but the live-internet entry
# also exercises the kernel's own [net-smoke] probe alongside.
DUETOS_PRESET=x86_64-debug DUETOS_TIMEOUT=60 tools/qemu/run.sh \
    2>&1 | grep '^\[mini_browser\]'
```

Expected output: the four PASS lines above (DNS → TCP handshake
→ HTTP send → HTTP/1.1 426 reply from Google). The HTTP 426 is
correct: it's Google's plain-HTTP edge telling unencrypted
clients to upgrade to HTTPS — same status code the kernel-side
[net-smoke] probe receives.

## Source layout

- `userland/apps/mini_browser/browser.c` — minimal C source.
  78 lines. Imports kernel32 (3 functions) + ws2_32 (9 functions).
- `userland/apps/mini_browser/build.sh` — mingw-w64 build script.
- `userland/apps/mini_browser/browser.exe` — checked-in 9.7 KB
  PE32+ binary. Embedded at kernel-build time via the same
  `embed_blob.py` path as `windows-kill.exe`.
- `kernel/proc/ring3_smoke.cpp` — spawns `ring3-mini-browser`
  unconditionally during the boot ring-3 smoke list.

## Five iterations to make it run

The user's brief was "rinse and repeat fixing til it does run".
Each iteration: boot, grep for the failing line, fix the cause,
rebuild, boot again. Five fixes landed:

### 1. ws2_32.dll wasn't preloaded under emulator

**Symptom**: every WS2_32 import resolved via the catch-all
NO-OP stub instead of the real exports in the embedded
`ws2_32.dll`. `gethostbyname` returned NULL, mini_browser exited
with rc=2.

**Cause**: `kernel/proc/ring3_smoke.cpp` flags ws2_32 as
`essential=false`, and under `arch::IsEmulator()` only the
essential DLLs are preloaded (the trim was a CI wall-budget
optimisation). The PE loader couldn't resolve any ws2_32 import
against a preloaded DLL, so each import hit the catch-all.

**Fix**: change `ws2_32.dll`'s preload entry to `essential=true`.
Documented in the call comment.

### 2. gethostbyname was a returns-NULL stub

**Symptom**: `[mini_browser] gethostbyname FAIL` immediately
after WSAStartup OK.

**Cause**: `userland/libs/ws2_32/ws2_32.c` had a one-line stub
that always returned NULL — never actually issued a DNS query.

**Fix**: added a new kernel syscall opcode `kSockOpResolveA = 12`
to `SYS_SOCKET_OP`. Userland gethostbyname copies the hostname
into a static buffer, calls the syscall, and on success returns
a static `hostent` pointing at the kernel-supplied IP. The
kernel side reads the DHCP-supplied resolver, runs
`NetDnsQueryA`, polls `NetDnsResultRead` for up to 3 seconds,
and writes the network-byte-order IPv4 back to userland.

### 3. connect() returned before the TCP handshake completed

**Symptom**: connect() returned success (`[mini_browser]
connected` printed), but the immediately-following `send()`
got -EAGAIN because the kernel TCP slot was still in SynSent.

**Cause**: `kernel/net/socket.cpp::SocketConnect` kicked off
the SYN and immediately returned — non-blocking semantics —
even though POSIX/Win32 connect() is blocking by default.

**Fix**: added a 5-second wait loop after `NetTcpConnect` that
polls `NetTcpActiveSnapshot()` until `established == true`.
Mirrors POSIX/Win32 default blocking-connect semantics.

### 4. SocketConnect raced with the kernel net-smoke task

**Symptom**: with `netsmoke=force` enabled, mini_browser's
SocketConnect rejected with "slot busy" because the kernel's
own [net-smoke] probe was mid-handshake on the same single-slot
active-connect machine.

**Cause**: `g_tcp_owner != 0 && g_tcp_owner != idx + 1` returned
false immediately on contention — no retry. NetTcpConnect itself
also rejects on `state != Closed`. The kernel net-smoke runs in
a parallel kernel task and finishes within ~5 s, but mini_browser
gave it zero time.

**Fix**: two retry loops in `SocketConnect`. The first waits up
to 5 seconds for `g_tcp_owner` to clear; the second retries
`NetTcpConnect` on transient slot-busy. Both yield via
`SchedSleepTicks(1)` so the parallel task makes progress.

### 5. ws2_op inline-asm operand indices were off-by-one

**Symptom (most insidious)**: send() received a bogus length
(`0x143352160` — the buffer pointer rather than 39). Every
3-or-more-arg WS2_32 syscall was silently corrupting r10/r8/r9.

**Cause**: in `userland/libs/ws2_32/ws2_32.c::ws2_op`, the
inline asm used `mov %4, %%r10\nmov %5, %%r8\nmov %6, %%r9`.
Operand indices count from `%0` = first OUTPUT, then inputs in
order. With `"=a"(rv)` as `%0`, the inputs run `%1..%7` and
`%4` is `a2` — not `a3`. So r10 was being loaded with the
*data buffer pointer* instead of the *length*; r8 with `a3`
instead of `a4`; r9 with `a4` instead of `a5`; `a5` was lost
entirely.

This had presumably never been exercised because all prior
WS2_32 callers in the tree either took ≤2 useful args or never
shipped real bytes through `send()`/`recv()`.

**Fix**: shift the operand indices: `%5/%6/%7` instead of
`%4/%5/%6`. One-character edit in the asm string. Documented
the operand-counting convention in the function-level comment
so the next person extending ws2_op doesn't repeat the mistake.

## Where this lives in the broader subsystem story

`subsystems-status.md` is the consolidated single source of
truth for "what works in the Win32 / WS2_32 / NT subsystem
today". With this slice landed:

- Real PE in ring 3: ✅ (already had hello-pe + winkill)
- Real Win32 console output: ✅ (WriteConsoleA via kernel32 thunk)
- Real WS2_32 surface end-to-end: ✅ (this slice)
- Real network I/O from a userspace PE: ✅ (this slice)
- D3D11/12 / V8 / multi-process IPC / TLS / GDI+: ❌ (vast)
- Real Chrome: ❌ (and not feasible without all of the above)

`subsystems-status.md` should grow a "WS2_32 v1" row pointing at
this file the next time it's updated. Same with
`pe-subsystem-v0.md`.

## Audit checklist

```bash
DUETOS_PRESET=x86_64-debug DUETOS_TIMEOUT=60 tools/qemu/run.sh \
    2>&1 | grep '^\[mini_browser\]'
```

Expect exactly the five PASS lines. If the `reply` line is
missing, work backwards through the four iterations above.
