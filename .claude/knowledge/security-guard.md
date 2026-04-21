# Security guard — image-load protection

**Last updated:** 2026-04-21
**Type:** Decision
**Status:** Active (advisory mode shipped; Enforce-mode rough edges noted)

## Description

Every loadable image (ELF, PE, kernel thread, user thread) passes
through `customos::security::Gate()` before the loader maps a page
or the scheduler queues a task. Static-analysis heuristics produce
a `Verdict` — Allow / Warn / Deny — and, in Enforce mode, the user
is prompted via **either** a serial-line prompt on COM1 **or** a
GUI modal drawn on the framebuffer (whichever responds first).

Approved hashes persist across reboots in `tmpfs:/guard-allowed`
(one 16-hex FNV-1a per line), so the same image doesn't re-prompt
on the next boot.

## Files

- `kernel/security/guard.h` — public API (`Gate`, `Inspect`,
  `GateThread`, modes, findings)
- `kernel/security/guard.cpp` — heuristics + state + prompt +
  persistence + self-test
- Hook sites:
  - `kernel/core/elf_loader.cpp:ElfLoad` (gates every ELF)
  - `kernel/core/pe_loader.cpp:PeLoad` (gates every PE incl. DLLs)
  - `kernel/sched/sched.cpp:SchedCreate + SchedCreateUser` (gates
    every thread, name-based only)
- `kernel/core/shell.cpp` — `guard` command: status / mode toggles /
  self-test trigger
- `kernel/drivers/input/ps2kbd.cpp` — new `Ps2KeyboardTryReadChar`
  non-blocking variant for the unified prompt loop

## Modes

| Mode | What happens |
|---|---|
| `Off` | Gate always Allow; Inspect still callable |
| `Advisory` (DEFAULT) | Scan + log every image; always Allow |
| `Enforce` | Scan + log; Warn/Deny triggers user prompt with 10s default-deny |

Flip via shell: `guard advisory` / `guard enforce` / `guard off`.

## Heuristics shipped (v0)

- `NAME_DENY` — filename matches the static deny list (empty seed).
- `HASH_DENY` — FNV-1a of the full image matches the deny list
  (placeholder for SHA-256 once the crypto module lands).
- `PE_INJECTION` — PE contains BOTH `CreateRemoteThread` AND
  `WriteProcessMemory` literals — classic injection combo. **Deny**.
- `PE_SUSPICIOUS` — PE contains 2+ injection-API names
  (NtCreateThreadEx, VirtualAllocEx, SetWindowsHookEx, etc.). **Warn**.
- `PE_NO_IMPORTS` — PE with no `.dll` string reference — likely
  packed / self-contained loader. **Warn**.
- `ELF_WX` — native ELF with a PT_LOAD segment that is both W and X,
  violating our W^X rule. **Warn**.

## User override flow

1. Heuristic triggers Warn/Deny.
2. In Advisory mode: log finding, allow. Done.
3. In Enforce mode: draw GUI modal AND emit serial prompt. Both
   channels poll in the same loop. User hits `y` or `n` on either
   channel, or the 10s timer expires (= default-deny).
4. On "y", the image's FNV-1a hash is appended to
   `tmpfs:/guard-allowed` so the next boot skips the prompt.

## Observed boot-log output (Advisory mode)

```
[boot] Starting security guard.
[guard] init (mode=advisory)
[guard] no persistent allowlist (first boot or cleared)
[guard] self-test OK (clean-elf allowed; injection-pe denied)
...
[guard] ALLOW kind=kthread name="kheartbeat" findings=0
[guard] ALLOW kind=uthread name="ring3-smoke-A" findings=0
[guard] WARN  kind=pe      name="(pe)"         findings=1
[guard]   - PE_NO_IMPORTS: no .dll references in image
```

The WARN on `hello_pe` is a true positive — that image really has
no imports (it's the freestanding Win32 smoke) — and is the exact
class of finding we want to see before flipping Enforce.

## Known rough edges

- **SHA-256 not implemented.** The hash denylist + allowlist use
  FNV-1a as a placeholder. Real signatures need a crypto module.
- **Idle-bsp + reaper gate BEFORE GuardInit runs** (scheduler
  bootstrap precedes the security subsystem). Today they carry
  Advisory defaults via `constinit Mode g_mode = Mode::Advisory`,
  which always allows. If Enforce mode ever needs to be the
  DEFAULT, those two need an explicit boot-allowlist entry.
- **Enforce-mode thread deny leaks Process refs.** If `SchedCreateUser`
  returns null, the caller's Process retain is orphaned. Advisory
  sidesteps; fix before flipping Enforce.
- **Static denylists.** Hot-reload from a tmpfs policy file is a
  follow-up slice.

## Anti-bloat footnote

The two "tight loop" helpers in guard.cpp (`VZero` / `VCopy`)
exist for the same reason the AHCI driver has them: clang's loop
idiom recognizer lowers plain byte loops into `memset` / `memcpy`,
which the freestanding kernel does not link. Use volatile-byte
loops OR these helpers for any stack-array zero-init, struct copy,
or buffer-fill in the kernel — especially at -O3. Adding a real
kernel `memset` is a reasonable next step but requires a conscious
decision about placement (mm? arch? core?) and the compiler-rt
fragment that needs to link against it.
