# DuetOS — Claude Code Context

## What is this?

DuetOS is a from-scratch, general-purpose operating system written in C++/Rust/ASM. Its two defining goals are:

1. **Run Windows PE executables natively** — a first-class Win32/NT subsystem (not a VM, not an emulator layer on top of another host OS). Think of the PE loader, NT syscall surface, and Win32 user-mode DLLs as part of the base system, co-equal with the native DuetOS ABI.
2. **Run on typical commodity PC hardware** — x86_64 from day one (Intel/AMD), with first-class driver support for commodity GPUs (Intel iGPU, AMD Radeon, NVIDIA GeForce). ARM64 is a planned second tier.

This is a greenfield project. Treat every file in the tree as intentionally shaped — there is no "legacy" to work around yet, so the cost of sloppy decisions compounds faster than in a mature codebase. Build it right the first time.

### Project pillars (do not drift from these)

- **Kernel**: Hybrid (microkernel-style IPC, monolithic-style in-kernel drivers for hot paths). Preemptive, SMP-aware, per-CPU runqueues.
- **Boot**: UEFI-first (x86_64), with a secondary legacy-BIOS path only if/when a target machine demands it. No MBR-only code paths in new work.
- **Memory**: 4-level paging (x86_64), NX, SMEP/SMAP, KASLR, per-process address spaces. Physical frame allocator + slab/buddy hybrid.
- **Scheduler**: MLFQ + per-CPU runqueues, affinity, work-stealing. Real-time class reserved, not the default.
- **Filesystem**: VFS abstraction. First backend: a native FS tuned for the project's needs. FAT32/exFAT/NTFS read-only tier for interoperability; ext4 read-only tier for Linux data partitions.
- **Executable formats**: Native ELF-like format **and** full PE/COFF. The PE subsystem is a peer, not a shim.
- **Win32 subsystem**: NT syscall layer → user-mode `ntdll`, `kernel32`, `user32`, `gdi32`, `d3d*`, `dxgi`, `winmm`, `xaudio2` reimplementations. Not a Wine fork — studied as prior art, not taken as a dependency.
- **Graphics**: Direct GPU drivers for Intel/AMD/NVIDIA. Kernel-mode DRM-style layer + user-mode API (Vulkan-first, D3D11/D3D12 translation on top for the Win32 subsystem).
- **Drivers**: PCIe enumeration, NVMe, AHCI/SATA, xHCI/USB, Intel HDA/AC'97, e1000/iwlwifi/rtl8169 NICs. Audio and networking user-mode stacks.
- **Security**: W^X enforced, ASLR, stack canaries, control-flow integrity. No setuid; capability-based IPC.

### What DuetOS is **not**

- Not a Linux distribution. No Linux kernel, no GNU userland as a base.
- Not a Wine project. Wine's userland reimplementation is useful prior art; we are writing ours.
- Not a research microkernel (L4, seL4). Pragmatism over academic purity.
- Not a rewrite of ReactOS. ReactOS is useful as a reference for Win32 semantics; we are not forking it.

## Session start (run at the beginning of every session)

**Step 1 — Git sync** (see [Git Sync Workflow](#git-sync-workflow) below for the commands):

Sync your branch with the latest upstream `main` branch. This is the **first thing** to do — before reading code, before making changes, before anything else. Feature branches diverge as other PRs merge; without rebasing you'll be working on stale code.

**Step 2 — Load persistent context:**

```bash
cat .claude/index.md
```

Scan the index for topics relevant to the current task. Read those knowledge files before proceeding.

**Step 3 — Bloat check (once the tree has real code):**

```bash
find kernel drivers subsystems userland -type f \
  \( -name '*.cpp' -o -name '*.c' -o -name '*.rs' \) | xargs wc -l | sort -rn | head -15
```

If the task involves any file over the threshold, trim it first.

## Anti-Bloat Guidelines

AI-assisted development has a structural bias toward complexity: adding features "just in case," creating helpers for single uses, over-engineering simple problems, building systems without wiring them in. In an OS codebase — where the wrong abstraction lives forever in the kernel ABI — this bias is **more** dangerous than in application code. The goal is **sanity, not sacrifice** — keep code clean without stripping legitimate verbosity or readability.

### Sensible Thresholds (Not Hard Limits)

These are **guidelines for when to pause and think**, not absolute rules. A clean 450-line `.cpp` is fine; a cryptic 200-line `.cpp` is not.

| Thing | Threshold | What to do |
|-------|-----------|------------|
| `.cpp` / `.c` / `.rs` file size | ~500 lines | Split if doing multiple jobs; leave if one coherent unit |
| `.h` / `.hpp` file size | ~300 lines | Split if unrelated types; data-heavy headers are fine |
| Public methods per class | ~15 | Ask: "Does each method earn its place?" |
| Function length | ~60 lines | Split if nested branching; clear linear flow is fine |
| Syscall handlers per file | 1 subsystem per file | Consolidate before adding more |
| Parallel subsystems doing the same thing | 0 | Remove the duplicate |

### The Readability Principle

**Never sacrifice readability to hit a line count.** Keep comments that explain "why," use descriptive variable names (`pageTableEntryMask` > `ptm`), maintain vertical whitespace between logical sections, use braces for non-trivial loop bodies, and one statement per line. The question is always: **"Does this make sense to someone reading it for the first time, at 2am, during a triple-fault?"**

### Before Writing Code — Checklist

1. **Does this already exist?** Search before writing — especially for low-level primitives (spinlocks, allocators, list helpers).
2. **Will this be called?** If you can't name the caller, don't write it.
3. **Can existing code do this with a small change?** Prefer editing over adding.
4. **Is this a one-time use?** Inline it — no helper function, no new class.
5. **Am I future-proofing?** Stop. Write only what is needed today.
6. **Adding a new subsystem?** Ask if an existing one can be extended instead.
7. **Adding a new syscall?** Syscall numbers are an ABI. Once published, they are forever. Be sure.
8. **Is the code dead?** Delete it. Don't comment it out — git history exists.
9. **Is a system built but not wired in?** Either wire it in or delete it.
10. **Is this running in kernel or user space?** Be explicit. Kernel code has no `malloc`, no `printf`, no exceptions unless the project explicitly supports them.

## Coding Standards

- **C++23** for kernel and most subsystems (`constexpr`, `enum class`, `std::expected`-style results, concepts, `if consteval`). No RTTI, no exceptions in kernel code — results go through `duetos::core::Result<T, E>` (see `kernel/core/result.h`). Prefer `return Err{ErrorCode::Foo};` + `RESULT_TRY` / `RESULT_TRY_ASSIGN` at call sites over `return -1 / false / nullptr` sentinels.
- **Rust** permitted for greenfield subsystems where memory-safety vs. C++ lifetime invariants matter (filesystem drivers, USB stack, network stack). If you reach for Rust, the subsystem must stand alone — no Rust-in-the-middle of a C++ call chain.
- **ASM**: NASM (Intel syntax) for x86_64 boot, trap frames, context switch. Keep hand-written assembly to the smallest possible surface.
- **Ownership**: `std::unique_ptr` / `UniquePtr` owning, raw pointers non-owning. In kernel, use the project's own smart pointer primitives — `std::` is user-land only.
- **Const-correctness**: `const` on all non-mutating methods and parameters. `constexpr` wherever it works.
- **Naming**: PascalCase classes/methods, camelCase locals, `m_` prefix members, `UPPER_SNAKE` macros and kernel constants, `k_` prefix for kernel-internal globals.
- **Headers**: `#pragma once`, forward-declare where possible, no transitive include bloat.
- **Style**: Allman braces, 4-space indent, 120-col limit (see `.clang-format`). LF line endings everywhere (we are primarily Linux-hosted during development).
- **Zero warnings**: `-Wall -Wextra -Wpedantic -Werror` on GCC/Clang; `/W4 /WX` on MSVC.
- **No naked `new`/`delete`** in portable code. Kernel allocations go through the slab/page allocators explicitly, never through a global `operator new`.
- **No global mutable state** outside the kernel's explicit per-CPU areas. If something looks like a singleton, it is probably a per-CPU or per-process structure.

## Architecture (planned directory layout)

This tree is **aspirational** — the directories will appear as the work does. Do not create a directory until the first file legitimately belongs in it.

```
boot/                     — UEFI loader (x86_64), legacy BIOS stub (later), boot protocol
kernel/
  arch/x86_64/            — Bootstrap, paging, GDT/IDT, trap frames, APIC, context switch
  arch/aarch64/           — (later) ARM64 equivalents
  core/                   — Entry, panic, early init, per-CPU setup
  mm/                     — Physical frame allocator, paging, slab, VMAs, kmalloc
  sched/                  — Scheduler, runqueues, threads, processes, IPC
  fs/                     — VFS, path resolution, mount table, dcache
  net/                    — Protocol stacks (TCP/IP, UDP, ICMP, ARP)
  sync/                   — Spinlocks, mutexes, RW locks, RCU-lite
  time/                   — HPET/TSC/APIC timer, clocksource, scheduler tick
  ipc/                    — Capability-based IPC, ports, shared memory
  syscall/                — Native syscall dispatch
  drivers/                — In-kernel device drivers (see below)
drivers/
  pci/                    — PCIe enumeration
  storage/nvme/           — NVMe
  storage/ahci/           — AHCI/SATA
  usb/xhci/               — xHCI host controller
  usb/class/              — HID, MSC, hub
  net/e1000/              — Intel gigabit NICs
  net/iwlwifi/            — Intel Wi-Fi (later)
  gpu/intel/              — Intel iGPU (Gen9+)
  gpu/amd/                — AMDGPU (GFX9+)
  gpu/nvidia/             — NVIDIA Turing+ (via nouveau-style reverse-engineered interface or NVIDIA's open kernel interface)
  audio/hda/              — Intel HDA
  input/ps2/              — PS/2 keyboard/mouse (legacy fallback)
subsystems/
  win32/
    loader/               — PE/COFF loader, imports, relocations, TLS
    ntdll/                — NT API (NtCreateFile, NtAllocateVirtualMemory, …)
    kernel32/             — Win32 base API
    user32/               — Window manager interface (USER32 calls → our WM)
    gdi32/                — GDI (software path first, GPU-accelerated later)
    d3d11/                — D3D11 → Vulkan translation
    d3d12/                — D3D12 → Vulkan translation
    dxgi/                 — DXGI
    winmm/                — Windows multimedia (audio, timers)
  posix/                  — (later) POSIX-ish syscalls for porting Unix userland
  graphics/               — WM, compositor, Vulkan ICD
  audio/                  — Audio server, mixer
userland/
  libc/                   — Our libc (freestanding + hosted)
  init/                   — PID 1, service supervisor
  shell/                  — Command shell
  tools/                  — Native userland utilities
  apps/                   — Sample/test apps (native + PE)
third_party/              — Vendored dependencies (compiler-rt fragments, zlib, etc.)
tools/
  build/                  — Build helpers, image builders, initrd packer
  qemu/                   — QEMU launch scripts, debug helpers
  test/                   — Integration test harnesses
tests/                    — Unit tests (hosted) + kernel self-tests (on-target)
docs/                     — Architecture docs, ABI specs, design notes
.claude/                  — Persistent AI context (this repo's memory)
```

### Boot path (x86_64)

UEFI firmware → `boot/uefi/BOOTX64.EFI` (PE32+) → loads kernel as ELF with a thin stub → kernel entry in long mode → per-CPU bringup → init process.

### Kernel execution order at boot

Early console → physmem map → paging on → heap → IDT/GDT → APIC/timer → SMP AP bringup → scheduler online → drivers (PCIe → NVMe → graphics → input) → VFS → init.

### Thread safety rules

- **Kernel**: IRQ-off critical sections use `spin_lock_irqsave` / `spin_lock_irqrestore`. Sleeping in an interrupt handler is a bug. Document which locks each subsystem owns at the top of its header.
- **Drivers**: Must state their context (IRQ / softirq / process). No driver holds a sleeping mutex across DMA.
- **Win32 subsystem**: All Win32 DLLs run in the target process's user-mode context; shared state is either per-process or goes through an explicit kernel port.

## Build (to be fleshed out as the build system lands)

Planned:

```bash
# Configure (pick one)
cmake --preset x86_64-release          # Kernel + userland, release
cmake --preset x86_64-debug            # Kernel + userland, debug
cmake --preset x86_64-kasan            # Debug + KASAN-equivalent

# Build
cmake --build build --parallel $(nproc)

# Run in QEMU
tools/qemu/run.sh build/duetos.img

# Run tests (hosted unit tests)
cd build && ctest --output-on-failure
```

Planned toolchain baseline: Clang 18+ / GCC 13+, CMake 3.25+, NASM 2.16+, `lld` preferred as the kernel linker. Rust (if used) via rustup nightly pinned in `rust-toolchain.toml`.

Until the build system exists, **do not invent a fake preset**. If a task asks "build it," answer truthfully: the build system is not yet written; here is what needs to happen to land one.

### Live-test runtime tooling — install on demand

The dev host does not ship with `qemu-system-x86_64`,
`grub-mkrescue`, `xorriso`, `mtools`, or `ovmf`. Build-clean is the
only signal available until they are installed.

**If a task legitimately requires a live-boot smoke test**, install
the packages before proceeding — do not fake it, do not ship a
"compiled cleanly, therefore it works" claim for code whose
correctness can only be proven at runtime:

```bash
sudo apt-get update
sudo apt-get install -y qemu-system-x86 grub-common grub-pc-bin grub-efi-amd64-bin xorriso mtools ovmf
```

Count as "legitimately requires":

- The commit introduces or changes an observable runtime
  behaviour (scheduler ordering, new syscall return codes, new
  boot-log line, new trap path, new sandbox-policy refusal).
- The commit claims end-to-end correctness for a path that a
  compile-time check cannot prove (address-space isolation, TLB
  shootdown, IRQ routing, timer drift, PE-image execution).
- A previous slice's runtime claim has never been verified on
  this host and the new slice depends on it.

Do NOT install for:

- Pure refactors with no behavioural delta.
- Docs / CLAUDE.md / `.claude/knowledge/` changes only.
- Code that compiles but is not yet wired into any live path.

After install, `DUETOS_TIMEOUT=20 tools/qemu/run.sh` is the
canonical headless smoke invocation (see script header for other
env-var overrides). Once CI lands, the same install line goes in
the workflow file.

IMPORTANT: assembly (`.S`) files are NOT formatted by
`clang-format`. Never pass a `.S` file to `clang-format -i` — it
will parse it as C++ and mangle it. Assembly stays hand-formatted.

## Git Sync Workflow

Run this before every session start and before every commit/push. The default upstream branch is `main`.

```bash
git fetch origin main
git log --oneline HEAD..origin/main | wc -l   # check if behind
git rebase origin/main                         # if behind, rebase
# If conflicts: resolve, git add <files>, git rebase --continue
```

**Rules:**
- **Never** commit or push while behind the base branch. Always rebase first.
- Prefer upstream changes for auto-generated content (`<!-- AUTO:* -->` sections) once docs automation is introduced.
- All Claude-driven development happens on the feature branch the harness checked out for the session (`claude/<slug>`). Merge target is `main`. Do not push to other branches without explicit permission.

## Pre-commit checks

Run checks **appropriate to the files you changed**.

### Docs-only changes (`.md`, `docs/`, `.claude/`)

Proofread. Run any doc generators that exist at the time.

### Code changes (`.h`, `.hpp`, `.c`, `.cpp`, `.rs`, `.asm`, `CMakeLists.txt`)

```bash
# 1. Format check (mirror CI once CI is in place)
find kernel drivers subsystems userland \
  \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
  | xargs clang-format --dry-run --Werror 2>&1

# 2. Fix formatting (if step 1 fails)
find kernel drivers subsystems userland \
  \( -name '*.h' -o -name '*.hpp' -o -name '*.c' -o -name '*.cpp' \) \
  | xargs clang-format -i

# 3. CMake configure
cmake --preset x86_64-release 2>&1 | tail -20

# 4. Build
cmake --build build --parallel $(nproc) 2>&1 | tail -30

# 5. Tests
cd build && ctest --output-on-failure && cd ..

# 6. QEMU smoke (when there's a kernel to boot)
tools/qemu/run.sh --headless --timeout 30 build/duetos.img
```

If any step fails, fix before committing. CI (once wired up) will enforce clang-format on every PR.

## Post-PR checks

After creating or pushing to a PR, **always** poll CI and fix failures before moving on. Use the GitHub MCP tools available in this environment — do not shell out to `gh`.

See `.claude/knowledge/github-api-pr-checks.md` for the polling workflow and `.claude/knowledge/ci-reproducible-builds.md` (once written) for local reproduction commands.

## Stream Timeout Prevention

1. Do each numbered task ONE AT A TIME. Complete one task fully, confirm it worked, then move to the next.
2. Never write a file longer than ~150 lines in a single tool call. If a file will be longer, write it in multiple append/edit passes.
3. Start a fresh session if the conversation gets long (20+ tool calls). The error gets worse as the session grows.
4. Keep individual grep/search outputs short. Use flags like `--include` and `-l` (list files only) to limit output size.
5. If you do hit the timeout, retry the same step in a shorter form. Don't repeat the entire task from scratch.

## Wiring Things In — Functionality Is Not Optional

A system that exists but is never initialized, called, or connected is **worse than not existing**. In kernel space, dead code is not merely wasteful — it rots silently until the day a refactor accidentally re-enables it and triple-faults the box.

- **Every driver must be probed.** If `probe()` exists, the bus enumerator must call it for matching devices.
- **Every syscall handler must be in the dispatch table.** A handler that compiles but isn't dispatched is dead code.
- **Every initcall must run.** If a subsystem has an `init()`, it must be on a known init list with a stated ordering.
- **Every sink must have a source.** If a system receives data, something must be sending it.

If you discover a subsystem that is built but not wired in: **either wire it in immediately, or delete it**.

## Persistence Context Database

The `.claude/` directory is persistent AI memory — a knowledge base that Claude reads and writes across sessions. It captures issue fixes, effective workflows, optimizations, codebase observations, and project decisions. See `.claude/README.md` for entry format, rules, and directory structure.

### When to write a new entry

| Trigger | Entry type |
|---------|-----------|
| A problem required multiple attempts to solve | **Issue** |
| A workflow or approach proved consistently effective | **Pattern** |
| A faster/better way to do something was discovered | **Optimization** |
| A non-obvious codebase/tooling fact was discovered | **Observation** |
| An architectural or style decision was made | **Decision** |

After writing, update `.claude/index.md` and commit both alongside code changes.

### At session end

Review whether anything learned warrants a new or updated entry — especially optimizations, patterns, and observations discovered incidentally. Positive learning is equally worth recording.

**Rules:**
- Do not exclude `.claude/` from `.promptignore`
- Always commit context changes — future sessions on any branch benefit
- Prefer updating an existing entry over creating a new one for the same topic
