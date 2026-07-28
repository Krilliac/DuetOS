# DuetOS handoff — 2026-07-28 (PE32 USER32 rung)

Branch `claude/duetos-pe32-game-ladder-4f2vhy` is pushed at `cc2597c`,
one commit ahead of `main` (`b7f01564`). Working tree clean.

---

## Paste this into a new session

> Continue DuetOS work. The PE32 ladder's USER32 rung landed on
> `claude/duetos-pe32-game-ladder-4f2vhy` (`cc2597c`) — `user32_32` and
> `gdi32_32` are real surfaces now and `ring3-pe32-window` passes on a
> live boot. Read `HANDOFF.md` at the repo root first, then
> `wiki/reference/Roadmap.md`.
>
> **Two pre-existing failures are open and neither is mine** — both
> reproduce identically on unmodified `main`, verified by booting a
> worktree of `b7f01564` side by side. See "Open, pre-existing" below.
> `ring3-dx-demo-window` is the one with real substance.
>
> **Next rung candidates, in order:**
> 1. **`msvcrt_32` stdio** (`fopen`/`fread`/`fwrite`) rebased onto the
>    real `kernel32_32` file-I/O surface that landed 2026-07-26. Small,
>    well-scoped, and the next thing a real game exe touches after it
>    has a window.
> 2. **The WaitQueue detach primitive** — still unbuilt. Three
>    independent findings (R1-14 AddressSpace `regions_lock`, R1-15
>    PS/2 ring, C4 unkillable blocked threads) all block on the same
>    missing scheduler ABI: a lock spanning enqueue and detach, i.e.
>    `WaitQueueBlockLocked(wq, lock)`. Each is filed in the Roadmap
>    with its constraint. Building it once unblocks all three.
> 3. **Off-screen surfaces for the display list.** Nearly every
>    remaining `user32_32` / `gdi32_32` STUB traces to this one missing
>    thing — memory DCs, bitmaps, BitBlt and DIB sections are all
>    blocked on it, on both the 32- and 64-bit sides.
>
> Before pushing, read "Verification gotchas" below — the local kernel
> build covers neither host-tests nor fuzz.

---

## What landed (1 commit)

`user32_32` and `gdi32_32` went from **hand-written stubs with zero
syscalls between them** to real surfaces on the same ~40 `SYS_WIN_*` /
`SYS_GDI_*` handlers the 64-bit siblings use. No kernel work was
needed — the handlers already existed; this was the port.

The old symptom was a 32-bit exe that cleared CRT startup, reached its
own code, and settled into a quiet loop. Not a wait it was stuck in:
`RegisterClassA` discarded `lpfnWndProc` and returned a fake atom,
`CreateWindowExA` returned NULL, `GetMessageA` returned 0 forever. A
present-but-lying export is worse than a missing one — a missing import
leaves a `[win32-32miss]` sentinel; this left silence.

Three i386-specific traps, each a silent-corruption bug if missed, all
written up in Win32-Surface-Status §11b and Design-Decisions:

1. **`MSG` is 28 bytes on i386; the kernel's wire struct is 32** and
   `CopyMsgToUser` blind-writes all of it. A pass-through misaligns
   every field AND writes 4 bytes past the caller's struct.
2. **`WNDCLASS` and `WNDCLASSEX` have different i386 offsets.** On
   x86_64 the prepended `cbSize` packs into `style`'s 8-byte slot, so
   the 64-bit `RegisterClassExW` can legitimately forward to
   `RegisterClassW`. Do not copy that forwarding to 32-bit.
3. **`FillRect` / `FrameRect` / `DrawText` / `GetDC` / `BeginPaint` are
   USER32 exports, not GDI32.** Homed only in `gdi32_32`, `FillRect`
   sent a real importer to the NO-OP catch-all — it painted nothing
   while every call reported success. Both DLLs export them now and
   share `userland/libs/common/duet32_gdi_abi.h`.

Proof is a live boot, not a compile: `userland/apps/pe32_window/`
registers a class, creates a window, and runs post → peek → dispatch →
WndProc → paint → quit, asserting 22 conditions including a canary
immediately after its `MSG`. It is an `Always` battery row
(`ring3-pe32-window`), so every ring3 boot exercises it. Two
independent TCG boots: PASS both times, 0 panics, 0 non-deliberate
`[E]`, 241 self-tests OK.

**Tooling / hygiene picked up along the way:**

- `check-syscall-numbers.py` now treats `#define SYS_FOO 42` as an
  assertion, not just `SYS_FOO = 42`. The `=`-only pattern left the
  `#define` blocks opening `user32.c`, `gdi32.c` and every `_32` header
  **entirely unchecked** — where a wrong number does the most damage,
  since one bad `#define` mis-aims every caller of that name at once.
  134 → 239 asserted numbers, all correct; the check was verified to
  fail on a deliberately corrupted define.
- `build-stub-32-dll.sh` globs every `.c` in a companion DLL's
  directory (sorted, for reproducible link order) and gained `-Werror`.
  A `_32` DLL that outgrows one TU needs no build-system edit.
- The i386 syscall trampolines moved to
  `userland/libs/common/duet32_syscall.h`, shared by all three real
  `_32` DLLs, and gained the 5- and 6-arg forms. arg6 travels in `ebp`,
  which cannot be an asm operand, so it is swapped in with `xchg` — a
  `push` would shift any esp-relative memory operand the compiler chose
  for the other inputs.
- Two stale comments corrected: `window_syscall.cpp` claimed the kernel
  runs the WndProc on a synthetic ring-3 frame (it never has — the
  pointer lives in `GWLP_WNDPROC` and `DispatchMessage` calls it
  in-process), and `spawn.cpp` said "today just one entry" over a
  13-entry preload table.

---

## Open, pre-existing (verified against a `main` worktree boot)

Both of these fail identically on unmodified `b7f01564`. I booted a
worktree of `main` side by side specifically to establish this, rather
than assume it. PE-compat goes **1 passed → 2 passed** with this
branch, same 1 failure.

| item | detail |
|---|---|
| **`ring3-dx-demo-window`** | Exits `0xc0000005` with `why=no-verdict`. It is a **64-bit** PE (`image_base=0x1403…`), crashing *after* `D3D11CreateDevice` returns `DX_S_OK` — so the demo passes its own `if (hr != 0 \|\| !sc \|\| !dev \|\| !ctx)` guard and faults downstream in the vtable / Vulkan back-end path. Its `ScDesc11` offsets check out against the DLL's `d + 0 / d + 4 / d + 48` reads, so the desc marshalling is **not** it. Start at `d3d11_swap_alloc` and the vk back end. This is the one worth real time. |
| **`ring3-hello-pe`** | The security guard raises `PE_NO_IMPORTS` and puts up an **interactive modal with a 10 s default-deny** that nothing answers in a headless boot, so `[hello-pe] Hello from a PE executable!` never prints and the smoke gate reports it MISSING. `autonomic.cpp` already suppresses the escalation when a smoke profile is set, but `ctest-boot-smoke.sh` boots with `profile=None` + `pe-smokes=1`, so the suppression does not apply. **Timing-dependent**: the escalation needs a UBSAN/KASAN kernel-integrity finding ~30 s in, which slow TCG reaches before the ring3 battery and fast KVM (CI) does not — which is why CI was green on `b7f01564`. I did not widen the suppression: that is a security-policy call about when the guard may auto-escalate to Enforce and block a PE behind an unanswerable modal, and it deserves its own slice rather than a one-boot judgement. |

Still carried from the previous handoff: the ~60-section Roadmap
backlog, the 19 verified-redundant branches awaiting a manual
`git branch -D`, and `wip/preserved-worktree-2026-07-27` (**do not
merge** — reference only).

---

## Verification gotchas

1. **The local kernel build covers neither host-tests nor fuzz.** Run
   both before pushing:
   - `cmake -S tests/host -B /tmp/ht && cmake --build /tmp/ht && (cd /tmp/ht && ctest)`
     — 51 tests. `include_tracked` is the one that catches a new header
     you forgot to `git add`; it caught exactly that this session.
   - `cd tests/fuzz && make -j4` — 37 targets, ~2 min.
2. **`tests/fuzz` needs `libclang-rt-18-dev`.** Without it every target
   fails at link with `cannot find …/libclang_rt.asan-x86_64.a`, which
   reads like a code break. Now in `wiki/tooling/Dev-Host-Setup.md`.
3. **`ctest-boot-smoke.sh` requires the *debug* build.** It exits 2
   with a SKIP on `x86_64-release` ("expects Info-level signatures").
   The bare `tools/qemu/run.sh` also defaults to `x86_64-debug` and
   runs the battery with everything gated off — you get
   `[pe-compat-smoke] battery complete` and nothing else. Use the ctest
   driver, which bakes `pe-smokes=1` into its own ISO.
4. **`boot-log-analyze.sh <serial.log>` is the triage entrypoint** and
   doubles as a gate. The driver's own stdout is buffered until it
   exits; the serial log at
   `build/<preset>/ctest-smoke-serial.log` is readable live, so grep
   that while a run is still going.
5. **A TCG boot takes ~10 min.** Budget for it; run it in the
   background and do docs meanwhile.
6. **One clean boot proves nothing for intermittent faults.** Measure a
   rate over ≥3 runs. TCG and KVM expose different bugs — `hello-pe`
   above is exactly that.
7. **Do not trust an audit report's mechanism.** Read the current code
   first; "MISFRAMED" is a valid outcome.
