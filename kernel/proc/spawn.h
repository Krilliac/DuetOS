#pragma once

#include "util/types.h"

// Forward-declares to keep this header lightweight; the
// implementation pulls the heavy mm / loader / ramfs headers.
namespace duetos::fs
{
struct RamfsNode;
}
namespace duetos::core
{
struct CapSet;
}

/*
 * DuetOS — canonical ring-3 process spawn API.
 *
 * WHAT
 *   The three `Spawn*File` entry points and the `Ring3UserEntry`
 *   trampoline form the kernel's loader-bridging API: turn an
 *   in-RAM ELF or PE/COFF blob into a running ring-3 process.
 *   This is the only surface (besides shell `exec` and the
 *   ring-3 probe suite) that constructs a user task from
 *   arbitrary code bytes.
 *
 *   - `SpawnElfFile`  — native-ABI ELF64. Goes through the
 *                       v0 ELF loader, picks a fresh AS, wraps
 *                       in a Process, queues a ring-3 task.
 *   - `SpawnElfLinux` — same plumbing, but flips
 *                       `Process::abi_flavor = kAbiLinux` so the
 *                       task's ring-3 `syscall` instructions land
 *                       on the Linux dispatcher (MSR_LSTAR)
 *                       rather than the native int-0x80 table.
 *                       Auto-selected by `SpawnElfFile` when the
 *                       image's EI_OSABI byte is ELFOSABI_LINUX.
 *   - `SpawnPeFile`   — PE/COFF twin. Pre-loads the standard
 *                       Win32 DLL set (kernel32, ntdll, user32,
 *                       gdi32, …) so import resolution can walk
 *                       their EATs before the task enters ring 3.
 *   - `Ring3UserEntry` — the kernel-side trampoline that every
 *                       spawned task starts at. Reads
 *                       `user_code_va` / `user_stack_va` from
 *                       `CurrentProcess()`, publishes the kernel
 *                       stack top to the TSS, and iretqs into
 *                       ring 3.
 *
 * WHY ITS OWN TU
 *   These functions used to share a TU with the adversarial
 *   ring-3 probe suite (`proc/ring3_smoke.{h,cpp}`). They are
 *   conceptually unrelated: spawn.* is the canonical API every
 *   non-probe caller (shell `exec`, SYS_SPAWN, the desktop's
 *   /APPS launcher, init's user-shell launch, live-update's
 *   reload) goes through. Bundling them with the probe suite
 *   meant every consumer pulled the probe suite's 200+
 *   `generated_*_pe.h` test-PE headers transitively. Splitting
 *   along the actual responsibility line cuts the spawn TU
 *   down to the ~60 DLL preload headers it actually needs and
 *   lets the probe suite TU grow without dragging spawn-time
 *   compile cost along with it.
 *
 * CONTRACT
 *   - Caller owns the byte buffer for the duration of the call.
 *     `Spawn*File` copies what it needs into the new AS.
 *   - Returns the new pid on success, 0 on any failure (invalid
 *     image, OOM, ProcessCreate failure, etc.). On failure any
 *     partial state is cleaned up.
 *   - `caps` is the cap-set the spawned task starts with — the
 *     kernel does not elevate it later. `root` is the ramfs
 *     namespace root the task sees through SYS_FILE_*.
 *   - `frame_budget` / `tick_budget` cap the AS's frame
 *     allocation and the task's runtime tick budget. See
 *     `mm/address_space.h` and `proc/process.h` for the
 *     well-known trusted / sandbox values.
 */

namespace duetos::core
{

/// Kernel-side entry trampoline for every ring-3 task created
/// via `sched::SchedCreateUser`. Runs in ring 0 on a fresh
/// kernel stack with the task's own AS already loaded in CR3.
/// Reads `user_code_va` / `user_stack_va` from
/// `CurrentProcess()`, publishes the kernel stack top to the
/// TSS, and iretqs into ring 3. Never returns.
[[noreturn]] void Ring3UserEntry(void* arg);

/// Load an ELF64 image into a fresh AddressSpace, wrap it in a
/// Process with the given caps + namespace root + budgets, and
/// queue a ring-3 task for it via SchedCreateUser. Returns the
/// new pid on success, or 0 on any failure (invalid ELF, OOM,
/// ProcessCreate failure). On failure, any partial state is
/// cleaned up through AddressSpaceRelease.
///
/// Auto-detects Linux-ABI ELFs by their EI_OSABI byte: if the
/// caller passes ELFOSABI_LINUX (3) the load is delegated to
/// `SpawnElfLinux` so the task's syscall dispatch lands on the
/// Linux dispatcher.
u64 SpawnElfFile(const char* name, const u8* elf_bytes, u64 elf_len, CapSet caps, const fs::RamfsNode* root,
                 u64 frame_budget, u64 tick_budget);

/// Linux-ABI twin of `SpawnElfFile`. Same parse + AS + Process
/// pipeline, but flips `Process::abi_flavor = kAbiLinux` after
/// ProcessCreate so the task's ring-3 `syscall` instructions land
/// on the Linux dispatcher (MSR_LSTAR) rather than the native
/// int-0x80 path. Also seeds `linux_brk_{base,current}` and
/// `linux_mmap_cursor` so brk/mmap have sensible starting anchors.
///
/// The underlying ELF loader does NOT inspect EI_OSABI — caller
/// decides the flavor. A future auto-detector could sniff the
/// ELF's `.note` sections or PT_INTERP contents to pick between
/// this and SpawnElfFile; for now, it's explicit.
u64 SpawnElfLinux(const char* name, const u8* elf_bytes, u64 elf_len, CapSet caps, const fs::RamfsNode* root,
                  u64 frame_budget, u64 tick_budget);

/// PE/COFF twin of `SpawnElfFile`. Loads via the v0 PE loader
/// (freestanding, no imports, no relocations) and queues a
/// ring-3 task at the image's entry point. Pre-loads the
/// standard Win32 DLL set into the new AS before PeLoad runs so
/// ResolveImports can consult their EATs. Same return-code and
/// cleanup contract as `SpawnElfFile`.
u64 SpawnPeFile(const char* name, const u8* pe_bytes, u64 pe_len, CapSet caps, const fs::RamfsNode* root,
                u64 frame_budget, u64 tick_budget);

} // namespace duetos::core
