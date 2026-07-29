#pragma once

#include "loader/dll_loader.h"
#include "util/types.h"

namespace duetos::mm
{
struct AddressSpace;
}

namespace duetos::fs::fat32
{
struct Volume;
}

namespace duetos::loader
{

/*
 * Side-by-side DLL loading — "the app ships its own DLLs".
 *
 * Everything the kernel could bind before this file existed came
 * from inside the kernel image: the ~44-entry preload table in
 * `proc/spawn.cpp`, the ramfs `/lib` tree, or a fixed `/LIB`
 * directory on FAT32 volume 0. A PE whose import names a DLL
 * sitting NEXT TO IT on the volume had no path at all — which is
 * how essentially all real software is shipped.
 *
 * This module supplies that path, and owns the three things the
 * fixed-directory loader in spawn.cpp never had to think about:
 *
 *   1. WHERE the image came from (`SxsSource`), so "beside it" is
 *      a real question with a real answer.
 *   2. Recursion. A side-by-side DLL has its own imports, which
 *      may pull further side-by-side DLLs. Bounded by
 *      `kSxsMaxDepth` + `kSxsMaxLoads`; cycles terminate because a
 *      DLL already present in the set is never loaded twice.
 *   3. The security gate. Bytes read off a FAT32 volume are
 *      guest-writable and end up executing inside the process's
 *      address space with the process's authority. Every disk-
 *      sourced DLL therefore passes `security::Gate` with
 *      `ImageKind::WindowsPE`, exactly like a disk-sourced .exe
 *      does inside `PeLoad`. Blobs compiled into the kernel image
 *      and files under the trusted ramfs root are part of the TCB
 *      and are deliberately NOT re-gated here.
 *
 * Every field read out of the volume is bounds-checked before use:
 * a malformed PE header, an absurd file size, or a directory entry
 * pointing past the end of the volume fails the load rather than
 * the boot.
 *
 * Context: kernel task. Reads block on the storage stack, so this
 * is task-context only — never call from IRQ / softirq.
 */

/// The on-disk origin of a PE image, i.e. the directory its
/// side-by-side DLLs would live in.
struct SxsSource
{
    /// FAT32 volume index (as accepted by `fs::fat32::Fat32Volume`).
    u32 volume;
    /// True when `volume` + `dir` describe a real on-disk origin.
    /// A PE spawned from an embedded blob or from ramfs has none.
    bool valid;
    /// Directory prefix including the trailing '/'. The volume root
    /// is "/". Sized for a FAT32 8.3 path a few levels deep; a path
    /// longer than this makes the source invalid rather than
    /// silently searching the wrong directory.
    char dir[40];
};

/// The mutable DLL-resolution set `SpawnPeFile` builds before
/// `PeLoad` and hands to the import binder. `count` is a pointer
/// because this module appends to the caller's stack-local array.
struct DllSet
{
    core::DllImage* images;
    u64* count;
    u64 cap;
};

/// How deep a side-by-side dependency chain may go: the .exe is
/// depth 0, a DLL it names directly is depth 1. Four levels covers
/// every real launcher shape we have measured while keeping the
/// worst-case work a hostile import table can request bounded.
inline constexpr u32 kSxsMaxDepth = 4;

/// Hard cap on side-by-side DLLs loaded for one spawn, independent
/// of depth. Stops a wide (rather than deep) hostile import table
/// from walking an entire volume into the address space.
inline constexpr u32 kSxsMaxLoads = 16;

/// Largest single DLL this module will read off a volume. Real
/// engine DLLs are big (UnityPlayer.dll is ~26 MiB), so the cap is
/// generous — but it is a cap, and it is checked against the
/// directory entry's advertised size BEFORE any allocation.
inline constexpr u64 kSxsMaxDllBytes = 32ull * 1024 * 1024;

/// Total bytes this module will hold in its never-freed file cache.
/// Reached => further side-by-side loads fail closed. The kernel
/// heap is finite and shared; a guest must not be able to exhaust
/// it by shipping many large DLLs.
inline constexpr u64 kSxsCacheBudgetBytes = 40ull * 1024 * 1024;

/// Derive the search directory from the path an image was read
/// from. `image_path` is a FAT32 path with either shape the
/// existing callers use: "FOO.EXE" (volume root) or
/// "/GAMES/FOO.EXE". Returns false — and leaves `out->valid` false
/// — when the path is absent, too long, or has no basename.
bool SxsSourceFromPath(u32 volume, const char* image_path, SxsSource* out);

/// Load ONE named DLL from the source directory into `as` and
/// append it to `set`. Returns the DLL's base VA, or 0 on any miss
/// or refusal (not found, too large, guard denied, malformed,
/// set full). Idempotent: a DLL already present in `set` under
/// that name returns its existing base without re-reading it.
u64 SxsLoadNamed(const SxsSource& src, const char* dll_name, duetos::mm::AddressSpace* as, const DllSet& set);

/// Satisfy `image`'s imports from the source directory, recursively.
/// For each imported DLL name not already in `set`, tries
/// `SxsLoadNamed`; on success, recurses into the newly loaded DLL's
/// own imports. Returns the number of DLLs loaded.
///
/// `depth` is the caller's depth (0 for the main .exe). Recursion
/// stops at `kSxsMaxDepth`.
u32 SxsResolveImports(const SxsSource& src, const u8* image, u64 image_len, duetos::mm::AddressSpace* as,
                      const DllSet& set, u32 depth);

/// Load every `*.dll` in `dir_path` on `volume` into `as`.
/// This is the fixed-directory `/LIB` convenience path — a user can
/// drop a vendored DLL there and have it bound without rebuilding
/// the kernel. Unlike `SxsResolveImports` it is speculative (it does
/// not consult any import table), so it is only appropriate for a
/// directory the operator curates. Returns the number loaded.
u32 SxsLoadDirectory(u32 volume, const char* dir_path, duetos::mm::AddressSpace* as, const DllSet& set);

/// Bytes currently held by the module's file cache. Exposed so the
/// budget is observable from a self-test / shell status line rather
/// than being an invisible internal number.
u64 SxsCacheBytes();

/// Boot-time self-test: exercises path derivation, the 8.3
/// fallback, and the budget arithmetic. Emits `[sxs-selftest] PASS`
/// on success and a `FAIL <step>` line otherwise.
void SxsSelfTest();

} // namespace duetos::loader
