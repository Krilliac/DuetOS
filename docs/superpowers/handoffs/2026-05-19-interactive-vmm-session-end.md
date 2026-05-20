# Handoff — Interactive VMM session (2026-05-19)

> Drop this in a new session along with whatever the next-task prompt is.
> Branch `claude/interactive-vmm` head ≥ `22974a6b` at handoff time.

## TL;DR

**Task 8 of [`docs/superpowers/plans/2026-05-19-interactive-vmm.md`](../plans/2026-05-19-interactive-vmm.md) is complete and verified end-to-end.** The in-house VMM (`tools/vmm/`) boots the unmodified DuetOS kernel under WHP, renders the desktop in a framebuffer window, and routes Win32 keyboard + mouse input through an emulated 8042/PS-2 controller to the guest. F5 from the generated Visual Studio solution Just Works. Six commits landed today on `claude/interactive-vmm`.

The remaining lag the user observes when interacting with the desktop is **debug-build compositor cost** — orthogonal to Task 8's plumbing — and is a clear candidate for the next slice.

## What was on screen at end of session

User F5'd, the guest booted, reached the **DuetOS login screen** (username + password fields, cursor active, red "LOGIN FAILED — CHECK USERNAME / PASSWORD" banner visible from a prior bad guess). On top of the login was the kernel's **interactive `SECURITY GUARD PROMPT`** Y/N modal for a `PE_NO_IMPORTS` WARN-verdict PE binary from the boot self-test battery. Mouse moves smoothly; keystrokes do reach the guest (the red banner proves submit-of-form went through) but with noticeable lag, partly because the login-form text field redraws expensively per keystroke and partly because login + guard-prompt race for the same keyboard ring.

**Default seeded credentials** (`kernel/security/auth.cpp:298-300`):
- `admin` / `admin` (Admin role)
- `guest` / *(empty — just Enter)* (Guest role)

The guard prompt at the front needs `y` (allow) or `n` (deny) before login below can stably accept text — or it auto-denies after 10 s.

## The six commits, in order

| # | SHA | Subject |
|---|---|---|
| 1 | `b96528d0` | `feat(vmm): wire i8042 into VMM + window input — Task 8 [INTEGRATION PASS]` |
| 2 | `8547160f` | `fix(vmm): extract MMIO RMW decoder + TDD coverage` |
| 3 | `21aa0aaf` | `build/feat(vmm): VS F5 fix + host cursor hide + --mem 2048 + 10 Hz mouse coalesce + watch helper` |
| 4 | `ad755a45` | `fix(diag/minidump): reject US-bit-set pages in SafeReadInto under SMAP` |
| 5 | `1d02a12b` | `fix(mm/kheap): bump pool 2 MiB → 64 MiB to fit boot self-test battery` |
| 6 | `22974a6b` | `perf(mouse-reader): cache WindowTopmostAt per packet — halve KASAN-amplified tree walks` |

Each commit message has the full bug-class diagnosis, fix rationale, and verification notes. None are pushed; user reviews/pushes when ready.

## The session's bug-chain — in case it surfaces again

Each fix unlocked the next layer of issue. Class-of-bug pattern matching per `CLAUDE.md`:

| Symptom | Root cause | Layer |
|---|---|---|
| F5 → "Access is denied" dialog naming `ALL_BUILD` | CMake-generated .sln defaults to first-listed project, ALL_BUILD has no .exe → CreateProcess on a directory → ERROR_ACCESS_DENIED | VMM CMake |
| Same dialog after CMake fix | VS `.suo` per-user cache pins old startup project; CMake can't touch `.suo` | VS state, user-side fix (right-click → Set as Startup Project, or delete `.suo`) |
| Kernel #PF cascade in `EmitMinidumpFromTrapFrame` at t~5.2 s | `ReadableKernelAddr`'s `< 0x40000000` whitelist accepts user pages (US=1) → SMAP fires inside the minidump path | Kernel SafeReadInto |
| OOM panic `linux/smoke: AddressSpaceCreate failed` at t~71 s (or 576 s at --mem 512) | `kKernelHeapBytes = 2 MiB` doesn't fit the boot smoke battery | Kernel kheap |
| `mouse-reader` runaway-cpu (98 %) + ring overflow + soft-lockup | KASAN-amplified per-packet tree walks (`WindowTopmostAt` × 2, plus widget hit-tests) + host emitting WM_MOUSEMOVE at 60-240 Hz vs PS/2's 40 Hz | VMM coalesce + kernel topmost cache + kernel mouse-menu-lag fix |
| BSOD message in serial but no FB render | (UNINVESTIGATED) likely panic-time FB writes go to a surface VMM doesn't scan, or compositor halts mid-frame | Open question |
| Boot multi-minute delays | `PromptUser`'s `for(;;)` busy-poll × 10 s default-deny × N PE-compat smoke binaries that hit guard's enforce-mode prompt | Open kernel UX issue |

## Open work — candidates for the next slice

In rough order of "user impact per effort":

1. **Release-build kernel under the VMM.** The whole "cursor lag, login redraw slow" character drops out when you skip KASAN/UBSan/lockaudit/capaudit. Build `cmake --build /root/source/DuetOS/build/x86_64-release --target duetos-kernel` in WSL, copy to `build/x86_64-release/kernel/duetos-kernel.elf` Windows-side, point F5 at it (edit `VS_DEBUGGER_COMMAND_ARGUMENTS` in `tools/vmm/CMakeLists.txt`). Probably 10-15 min including the configure-cache check. **Expected outcome: dev loop feels snappy.**

2. **Gate `PromptUser` during early-boot self-tests.** The image-guard interactive Y/N modal fires for every PE-compat-smoke binary with `PE_NO_IMPORTS` while guard transiently goes into enforce mode. Each prompt busy-polls 10 s if no input → multi-minute boot tail of "nothing visibly happening". Fix shape: `if (kIsBootInit || IsEmulator()) return false;` near the top of `PromptUser` in `kernel/security/guard.cpp`, or have boot self-tests run with guard pinned to advisory. **Expected outcome: boot completes ~10× faster.**

3. **`mouse-reader` cross-iteration caching.** This session's commit `22974a6b` cached `WindowTopmostAt` *within* one packet iteration. Extending the cache *across* iterations — invalidate on a window-list version bump (add/remove/raise/lower/move/resize) — would skip the walk entirely when the cursor stays inside one window's bounds. Same cache shape applies to `WidgetCursorOverButton` and `WidgetTooltipTrack`.

4. **Login text-field per-keystroke redraw.** Same class as #3 — the kernel's login UI redraws the full form on every keystroke instead of dirty-rect'ing the changed character cell. Cleanest fix layered on top of the existing compositor damage-tracking work mentioned in memory `[[compositor-damage-diff-validation]]`.

5. **VMM blit-rate adaptive.** Currently `SetTimer(hwnd, 1, 16, ...)` runs the FB blit at ~60 Hz unconditionally. Could detect window-hidden via WM_ACTIVATE and pause the timer, or expose a `--blit-rate` flag.

6. **BSOD-render investigation.** Open question from the session: the kernel's `[bsod] rendered — waiting for keypress to reboot` fires on a panic, but the FB on screen stays at the pre-panic frame. Either the BSOD writes to a surface the VMM doesn't scan, or compositor halts mid-frame and the live FB never gets the BSOD pixels. Worth verifying by forcing a panic deliberately and inspecting both VMM's `m_mem->FramebufferHost()` and the kernel's compositor state.

7. **Continue Task 8 plan onward:** Task 9 (ISO9660 + Joliet loader, TDD) and Task 10 (`--iso` direct-boot integration) per `docs/superpowers/plans/2026-05-19-interactive-vmm.md`.

## Build & test workflow gotchas (for the next session)

This took most of the session to figure out — write it down so the next session doesn't re-derive it.

### Two checkouts on different branches

- **Windows checkout**: `C:\Users\natew\source\repos\DuetOS`, on `claude/interactive-vmm`. This is the authoritative branch for the VMM work + the kernel patches landed today. Source of truth for git operations.
- **WSL checkout**: `/root/source/DuetOS` (WSL Ubuntu-24.04 runs as root), on `build-iso` at HEAD `ccb22407` (May 17). This is where the kernel actually **builds**. The two branches have semantically different kernel/source content in many files — `git apply -3` fails on cross-branch porting because blob hashes differ; **`patch -p1 -F 5 --no-backup-if-mismatch`** bridges the divergence cleanly because it tolerates surrounding-context drift.

### VMM build (Windows native, via Visual Studio CMake env)

```powershell
cmake -S tools\vmm -B tools\vmm\build -G "Visual Studio 17 2022" -A x64
cmake --build tools\vmm\build --config Debug
```

`clang` is **not** on the Windows PATH; the kernel build that produced `build/x86_64-debug/kernel/duetos-kernel.elf` was driven by VS's CMake integration with `VSInheritEnvironments.txt = clang_cl_x64_x64`. So **don't try `cmake --build` for the kernel target from a plain PowerShell** — it fails because `build.ninja` references VS-bundled ninja from a Developer Command Prompt env.

### Kernel build (WSL, from `/root/source/DuetOS`)

```bash
cd /root/source/DuetOS && cmake --build build/x86_64-debug --target duetos-kernel -j
```

ELF lands at `/root/source/DuetOS/build/x86_64-debug/kernel/duetos-kernel.elf`. To stage to Windows-side where the VMM picks it up:

```bash
cp /root/source/DuetOS/build/x86_64-debug/kernel/duetos-kernel.elf \
   /mnt/c/Users/natew/source/repos/DuetOS/build/x86_64-debug/kernel/duetos-kernel.elf
```

Binary `cp` over `/mnt/c` is safe — the documented `/mnt/c` breakage (memory `[[duetos-wsl-build-workflow]]`) is about *building* over 9p, not copying.

### Cross-branch patch porting (the technique that worked all session)

For any kernel-side fix landing on Windows-side but needing to be built via WSL on `build-iso`:

```bash
# On Windows side, in the unstaged working tree:
git diff -- <files...> > tools/vmm/build/_some-fix.patch

# On WSL:
cd /root/source/DuetOS && patch -p1 -F 5 --no-backup-if-mismatch \
    < /mnt/c/Users/natew/source/repos/DuetOS/tools/vmm/build/_some-fix.patch
```

The `tools/vmm/build/` dir is gitignored after commit `21aa0aaf`, so transient patches/scripts there don't dirty `git status`. Memory `[[duetos-wsl-build-workflow]]` has the same idea ("PORT changed files to ~/source/DuetOS"); this is the patch-flavored variant.

### Don't hardcode user-specific paths

User feedback from this session (memory `[[dont-hardcode-log-paths]]`): never bake `C:\Users\natew\OneDrive\Desktop\DuetOS Logs\` (or any other user-/machine-specific path) into shared source — CMake, scripts, .cpp, launch.vs.json. Prefer env vars, CLI flags, or `${CMAKE_BINARY_DIR}`/working-dir-relative paths. The serial log lands in that folder *because the user set it up*; the kernel/VMM/scripts must not assume it.

### Serial-log triage shortcut

When a fresh boot log shows up at `C:\Users\natew\OneDrive\Desktop\DuetOS Logs\vsfaillog.txt`, the fast triage pattern (from session experience):

1. `Get-Content $log | Measure-Object -Line` — total line count
2. `Select-String -Pattern 'runaway-cpu.+name="([^"]+)"'` grouped by task — shows which task is hogging CPU
3. `Select-String -Pattern 'cpu_busy_pct' -Last 10` — system load trend
4. `Select-String -Pattern 'PANIC|TRIPLE|CRASH DUMP|CPU EXCEPTION|panic-summary'` — fatal markers (many `[E]` lines are deliberate self-tests per memory `[[serial-log-triage]]` — don't chase them blindly)
5. `Select-String -Pattern '\[guard\]|SECURITY GUARD'` — image-guard prompts (the source of the "stuck" symptom)
6. `Get-Content $log -Tail 30` — last activity

## Helper files left in `tools/vmm/build/` (gitignored — local-only)

If the next session needs to re-apply a kernel patch to WSL:

- `tools/vmm/build/_apply-smap-fix.py` — Python helper for the `SafeReadInto` SMAP patch (commit `ad755a45`'s shape)
- `tools/vmm/build/_apply-kheap-bump.py` — kheap pool bump helper (commit `1d02a12b`'s shape)
- `tools/vmm/build/_mouse-menu-lag-fix.patch` — kernel mouse-menu-lag fix (PR #309 / commit `019b1cd8`) ported to `build-iso` via `patch -F 5`
- `tools/vmm/build/_topmost-cache.patch` — the topmost cache (commit `22974a6b`) as a unified diff

These are session-scoped tooling, NOT meant to be committed. The actual fixes are in the commits.

## Memory pointers (session notes worth recalling)

The session wrote two memories the next session inherits:

- `[[dont-hardcode-log-paths]]` — user-specific paths belong in env vars / flags, not in shared source. Same class as `[[duetos-wsl-build-workflow]]`'s `/mnt/c` warning.

And surfaced these existing memories as actively relevant:

- `[[vmm-windows-boot-workflow]]` — VMM standalone-on-Windows build + boots WSL-built kernel ELF
- `[[duetos-wsl-build-workflow]]` — can't build over /mnt/c; PORT changed files
- `[[serial-log-triage]]` — `[E]` doesn't mean "broken"; many are deliberate self-tests
- `[[mouse-menu-lag-fix]]` — the kernel-side hover-gate fix re-applied this session to `build-iso`
- `[[compositor-damage-diff-validation]]` — relevant for the open work item #4

## State at session end (for sanity-checking next session)

```
$ git status         # → clean working tree
$ git log -1         # → 22974a6b perf(mouse-reader): cache WindowTopmostAt per packet...
$ git log 47a6c921..HEAD --oneline    # → 6 commits, none pushed yet
$ ls C:\Users\natew\source\repos\DuetOS\build\x86_64-debug\kernel\duetos-kernel.elf
                     # → 21752816 bytes, mtime ~21:03 (includes topmost cache patch)
$ ls C:\Users\natew\source\repos\DuetOS\tools\vmm\build\Debug\duetos-vmm.exe
                     # → ~ recent (includes 10 Hz coalesce + cursor hide)
```

If the user has F5'd recently, the VMM may still be running. `Get-Process duetos-vmm` to check.

---

Last session reasoned over ~280k tokens. Welcome to the next session — you have a working interactive VMM and clean commits to build on.
