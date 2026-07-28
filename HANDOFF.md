# DuetOS handoff — 2026-07-28 (session 2)

Branch `claude/host-app-compat`, based on `main` @ `37e8e03f`.
**29 commits, 87 files, not pushed.**

**Headline: DuetOS runs off-the-shelf Windows executables it did not
build.** A stock `cl /MT` binary reaches `main()`, prints through the
CRT's own stdio and exits 0. `System32`'s `timeout.exe`, `waitfor.exe`
and `where.exe` return **byte-identical exit codes to real Windows**.

---

## Paste this into a new session

> Continue DuetOS work on `claude/host-app-compat` (base `main` @
> `37e8e03f`). Read `HANDOFF.md` first.
>
> Off-the-shelf Windows .exes now run. Five parallel lanes added ~600
> exports (i386 surface 415-estimated -> **532 counted**) and landed
> Aurora shell phases 1-3. Nine pre-existing bugs were found and fixed
> along the way — read "What the lanes found" below before assuming any
> nearby code is correct.
>
> **Highest-value next slice: a `.rsrc` (PE resource) parser.** It is the
> single largest blocker left and needs **no kernel change** — every
> section including `.rsrc` is already mapped, so a DLL can walk
> DOS -> PE -> data-directory[2] off `GetModuleHandle`. It unblocks
> `LoadStringW` (82 binaries, the highest-demand i386 import,
> deliberately NOT exported today because faking it would lie),
> `LoadImageW`, real icons/cursors, `TranslateAccelerator`, and the
> template half of the dialog manager.
>
> **Second: side-by-side DLL loading.** The Unity launchers on this host
> measure 98.5% import coverage with exactly ONE unresolved import each
> (`UnityPlayer.dll!UnityMain`). Every DLL DuetOS can bind is embedded
> in the kernel image.
>
> **Measure before guessing.** `tools/test/pe-compat-survey.py <dir>`
> ranks host binaries by how much of their import surface DuetOS
> implements; `tools/test/pe-corpus-run.sh <dir>` boots a corpus and
> grades each onto a rung. Both were written this session because "which
> app next" used to be guesswork.

---

## The unlock: `VirtualProtect` on image pages

`DoVirtualProtect` resolved only through `Process::vmap_regions` — the
`VirtualAlloc` bookkeeping — so any other address (the loaded image, the
stack, a preloaded DLL) returned FALSE. MSVC's UCRT caches its resolved
Win32 thunks in its own `.data` and brackets each write with
`VirtualProtect(PAGE_READWRITE)` / `(PAGE_READONLY)`, checking both. The
failure propagated up through `__acrt_initialize_winapi_thunks` to
`__scrt_initialize_crt`, and the CRT called
`__fastfail(FAST_FAIL_FATAL_APP_EXIT)` before `main()`.

**Import coverage was never the problem**, which is why it resisted. A
12-line `hello.c` with **100%** of its imports resolved failed
identically to a 2.4 MB `vulkaninfo.exe`.

**Reuse that technique**: build a minimal MSVC control
(`cl /MT /Zi ... /link /MAP`) and name the faulting RVA from the linker
map. It converted log archaeology into a two-step diagnosis.

`ProtectMappedRange` is not a W^X relaxation: user half only, mapped
pages only, `PAGE_EXECUTE_*` still refused.

---

## What the lanes found — nine pre-existing bugs

These matter more than the exports. Do not assume nearby code is right.

1. **`__C_specific_handler` returned 0** from every provider —
   `ExceptionContinueExecution`, i.e. "resume at the faulting
   instruction": an unbounded fault loop on any real exception. Now 1
   (`ExceptionContinueSearch`).
2. **`_wcsicmp` / `_wcsnicmp` were aliased to a BYTE compare**, which
   stops at the high zero byte of the first ASCII wide char — so **every
   pair of UTF-16 strings compared equal**. Now wide;
   case-insensitivity remains a marked GAP.
3. **`FindClose` issued syscall 9** (`SYS_GETLASTERROR`) under a comment
   claiming `"SYS_FILE_CLOSE (= 9)"`; the real number is 22. Every
   directory enumeration leaked its kernel snapshot until process exit.
   It hid because reading last-error is harmless — `FindClose` returned
   1 and nothing complained.
4. **`ReleaseSemaphore` treated the kernel's PREVIOUS COUNT return as an
   error code**, so any release of a semaphore with a non-zero count
   reported FALSE on a call that had succeeded.
5. **`AdjustTokenPrivileges` never called the kernel** and
   **`LookupPrivilegeValue` returned LUID 1 for every name**, unmarked.
   Not an escalation (authority is kernel-owned and `SYS_TOKEN_ADJUST`
   refuses to add a cap), but it silently broke privilege *dropping*.
6. **Four thunk rows silently shadowed each other** (the hash lookup
   takes whichever sorts first); one claimed success without writing its
   out-param. A `consteval` guard now makes the class impossible.
7. **`g_role_window` had 12 entries against `ThemeRole::kCount == 18`.**
   The tail zero-filled, and **0 is a valid `WindowHandle`**, so
   `ThemeApplyToAll` re-chromed window 0 once per unregistered role.
8. **Time card / show-desktop rail overlapped** — both measured back
   from the same right edge.
9. **`gen-wiki-auto.py` corrupted the wiki when run on Windows** —
   backslash paths and CRLF into the generated blocks.

Plus: **`Design-Decisions.md` held 3136 NUL bytes** from a concurrent
append in an earlier session. `grep` classified the file as binary,
which silently disabled the wiki's stale-reference check — it had been
printing `references missing path 'Binary file ... matches'` instead of
working. No content was lost. With it fixed the check immediately found
a real stale path.

---

## Three ABI rules, now documented not folklore

- **A syscall returning 64 bits in `rax` is unusable from PE32.** The
  compat-mode un-remap leaves only `eax` reaching the caller. This is
  why `GetSystemTimeAsFileTime` avoids `SYS_GETTIME_FT` (its low half
  wraps every ~7 min into a nonsense date) and QPC rebuilds its epoch in
  user space over `SYS_NOW_NS` (which rolls over every ~4.295 s).
- **i386 lock structs are HALF their x86_64 size** — `SRWLOCK` 4 vs 8,
  `CRITICAL_SECTION` 24 vs 40. Copying the x86_64 shape corrupts
  adjacent guest memory with no proximate symptom. **Third instance of
  this class** after the 28-byte `MSG` and `WNDCLASSEX`'s field shift:
  check any struct crossing the i386 boundary *before* writing the code.
- **An i386 `u64` local forces clang to pin EBP** as a frame pointer,
  and `duet_syscall6` needs EBP for arg6 — so every six-arg syscall in
  that TU fails to compile. Stage u64s as aligned u32 pairs.

---

## Corpus on the merged tree (9 binaries, TCG)

| binary | grade | real Windows |
|---|---|---|
| `hello_mt.exe` (`/MT`) | **CLEAN** (0) | 0 |
| `hello_md.exe` (`/MD`) | **CLEAN** (0) | 0 |
| `timeout.exe` | EXIT-0x1 | **1 — exact** |
| `waitfor.exe` | EXIT-0x1 | **1 — exact** |
| `where.exe` | EXIT-0x2 | **2 — exact** |
| `clip.exe` | EXIT-0x1 | 0 |
| `sort.exe` | EXIT-0x1 | 0 |
| `whoami.exe` | EXIT-0x1 | 0 |
| `vulkaninfo.exe` | EXIT-0xc0000005 | see below |

**Zero regressions** — every row identical to its pre-merge result
across ~600 new exports. `sort.exe`'s blocking import moved from
`?terminate@@YAXXZ` to `_wcsncoll`, direct evidence the CRT rows took
effect: it got further and is stuck on the *next* thing.

`where`/`whoami` first graded NOTFOUND; that was the **transient
emulated-block staging flake** the Roadmap already records for the
`run-exe.sh` image, confirmed by re-running both to their exact
pre-merge codes.

---

## Open: `vulkaninfo.exe`

Root-caused, deliberately not fixed. The `[dll-load] GetProcAddress
miss` diagnostic added this session names it: **15 misses, 13 of which
DuetOS already implements** as kernel thunk-page entries rather than DLL
exports. The `GetProcAddress` fallback now resolves the non-no-op ones
(15 -> 8). The rest need either real implementations
(`FlsGetValue2`, `LCIDToLocaleName`) or a policy decision about
returning **no-op** thunks — which would break the very common
`GetProcAddress(h,"Foo") != NULL` feature probe, turning a loud failure
into a quiet wrong answer. See the Roadmap section "GetProcAddress
cannot see the kernel thunk page".

---

## Verification

- Kernel build: **0 warnings**. Host tests: **53/53**. Fuzz: **37
  targets**. clang-format on all 36 changed sources: **clean**.
- `check-dll-def-exports`: 15 `.def`, 0 errors. `check-syscall-numbers`:
  247 asserted, 0 errors. Wiki sync: clean.
- Aurora screenshots `06`/`09` regenerated and **visually confirmed** —
  old taskbar is full-width flush to the edge, new one is an inset
  island. The other seven were deliberately left: they are surfaces
  Aurora does not touch, verified with a live control capture.
- **The screenshot harness was broken and is now fixed.** Every app
  window registers HIDDEN, so a plain boot photographs an empty desktop
  and the committed screenshots were not reproducible. `demo-windows=1`
  raises a representative set through the existing `WindowRaise` path.

### Gotchas that cost real time

1. **`ctest-boot-smoke.sh` REQUIRES a binary-dir argument.** With none it
   exits 2 on a usage line that scrolls past like a pass.
2. **SKIP is not PASS.** On this KVM-less host the smoke routinely
   exhausts its 600 s TCG budget. Use
   `boot-log-analyze.sh build/<preset>/ctest-smoke-serial.log` on the
   partial log for the real signal.
3. **`/tmp` is wiped between `wsl.exe` invocations.** Use
   `DUETOS_LOGDIR`, or run-then-grep inside ONE invocation.
4. **Never `pgrep -f` for a build/QEMU to serialize lanes** — it matches
   the *other waiters' own command lines* and they deadlock each other
   on an idle machine. Use
   `ps -eo comm --no-headers | grep -qE '^(qemu-system-x86|cc1plus|ninja)'`.
   (`pgrep -x qemu-system-x86_64` never matches either: `comm` truncates
   at 15 chars.)
5. **Copy worktree -> WSL only, never the reverse.** The shared WSL tree
   holds every lane's files at once and is not a faithful checkout of
   any branch.

---

## Still carried

The ~60-section Roadmap backlog; 19 verified-redundant branches awaiting
`git branch -D`; `wip/preserved-worktree-2026-07-27` (**do not merge**);
the `ring3-hello-pe` guard-modal security-policy call; and the WaitQueue
detach primitive that would unblock R1-14 / R1-15 / C4 at once.

Aurora phases 4-7 (compositor glass/blur, accent persistence, TTF fonts,
per-app panels) are untouched. Its asymmetric-close-button item is
deliberately deferred: button geometry is duplicated across the paint
pass and **three** hit-test functions, so an asymmetric width means four
sites that can desync a click target from the control it draws — it
wants a shared rect helper first.
