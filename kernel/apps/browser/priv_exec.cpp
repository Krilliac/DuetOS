#include "apps/browser/priv_exec.h"

#include "fs/fat32.h"
#include "fs/ramfs.h"
#include "mm/address_space.h"
#include "mm/kheap.h"
#include "proc/process.h"
#include "proc/spawn.h"

/*
 * DuetOS browser — privileged SPAWN executor (Phase 2b, spec §6 / plan Task C).
 *
 * PrivSpawnExec is the effect leg of `window.duetos.proc.spawn(path)`: the
 * privileged JS binding has already VALIDATED the request against the armed
 * scope and AUDITED it; this executor performs the load + spawn.
 *
 * SECURITY CRUX: the child process is spawned with a cap-set derived STRICTLY
 * from the broker's armed scope — only the bits the armed scope actually holds
 * are mapped onto kernel caps. The child is NEVER CapSetTrusted(); a privileged
 * page can therefore never hand its child more authority than the operator
 * armed it with.
 */

namespace duetos::apps::browser
{

namespace
{
namespace sp = duetos::security::privilege;

// errno values returned to the binding (negative on failure).
constexpr duetos::i64 kErrIo = -5;     // EIO   — FAT32 read short / failed
constexpr duetos::i64 kErrNoEnt = -2;  // ENOENT — path not found / is a directory
constexpr duetos::i64 kErrInval = -22; // EINVAL — empty / oversize / unknown magic
constexpr duetos::i64 kErrNoMem = -12; // ENOMEM — staging-buffer KMalloc failed
constexpr duetos::i64 kErrNoExec = -8; // ENOEXEC — loader accepted nothing (pid == 0)

// 8 MiB matches the files.cpp launch ceiling (MaybeLaunchFat32Entry).
constexpr duetos::u64 kMaxImageSize = 8 * 1024 * 1024;

// Map the privilege-engine armed scope onto a KERNEL cap-set. Only bits the
// armed scope holds are granted — the child is a strict subset of the broker.
//
// The kernel cap type is duetos::core::CapSet ({ u64 bits; }, no .Add()); the
// free functions CapSetEmpty / CapSetAdd from proc/process.h are the only way
// to build it. KernelRead has no kernel-cap analogue (it is a binding-side
// read facade), so it is intentionally not mapped here.
duetos::core::CapSet DeriveChildCaps(const sp::CapSet& s)
{
    duetos::core::CapSet caps = duetos::core::CapSetEmpty();
    if (s.Has(sp::Cap::FsRead))
    {
        duetos::core::CapSetAdd(caps, duetos::core::kCapFsRead);
    }
    if (s.Has(sp::Cap::FsWrite))
    {
        duetos::core::CapSetAdd(caps, duetos::core::kCapFsWrite);
    }
    if (s.Has(sp::Cap::ProcSpawn))
    {
        duetos::core::CapSetAdd(caps, duetos::core::kCapSpawnThread);
    }
    if (s.Has(sp::Cap::Net))
    {
        duetos::core::CapSetAdd(caps, duetos::core::kCapNet);
    }
    return caps;
}

} // namespace

duetos::i64 PrivSpawnExec(const char* canonPath, const char* const* argv, duetos::u32 argc,
                          const sp::CapSet& armedScope, void* ctx)
{
    (void)argv;
    (void)argc;
    (void)ctx;

    if (canonPath == nullptr)
    {
        return kErrNoEnt;
    }

    const auto* vol = duetos::fs::fat32::Fat32Volume(0);
    if (vol == nullptr)
    {
        return kErrIo;
    }

    // Resolve the canonical (already-contained, by the binding) path.
    duetos::fs::fat32::DirEntry entry{};
    if (!duetos::fs::fat32::Fat32LookupPath(vol, canonPath, &entry))
    {
        return kErrNoEnt;
    }
    // Refuse directories (FAT attribute 0x10) and degenerate sizes.
    if ((entry.attributes & 0x10) != 0)
    {
        return kErrNoEnt;
    }
    if (entry.size_bytes == 0 || entry.size_bytes > kMaxImageSize)
    {
        return kErrInval;
    }

    // Stage the image into a heap buffer (mirrors files.cpp:1028-1040).
    auto* staging = static_cast<duetos::u8*>(duetos::mm::KMalloc(entry.size_bytes));
    if (staging == nullptr)
    {
        return kErrNoMem;
    }
    const auto got = duetos::fs::fat32::Fat32ReadFile(vol, &entry, staging, entry.size_bytes);
    if (got != static_cast<duetos::i64>(entry.size_bytes))
    {
        duetos::mm::KFree(staging);
        return kErrIo;
    }

    // Sniff the image magic: "MZ" => PE/COFF, "\x7fELF" => ELF64.
    const bool is_pe = entry.size_bytes >= 2 && staging[0] == 'M' && staging[1] == 'Z';
    const bool is_elf =
        entry.size_bytes >= 4 && staging[0] == 0x7F && staging[1] == 'E' && staging[2] == 'L' && staging[3] == 'F';
    if (!is_pe && !is_elf)
    {
        duetos::mm::KFree(staging);
        return kErrInval;
    }

    // Child caps are derived strictly from the armed scope — never trusted.
    const duetos::core::CapSet childCaps = DeriveChildCaps(armedScope);

    // GAP: argv not delivered to child — SpawnPe/ElfFile carry no argv vector yet; revisit when the spawn ABI gains one.
    //
    // Spawn into the SANDBOX ramfs namespace (RamfsSandboxRoot, the same
    // minimal one-file root the kernel hands every untrusted process): a
    // page-spawned child IS untrusted, so it must not inherit the trusted
    // ramfs view. The spawn API requires a non-null root — nullptr is rejected
    // up front (spawn.cpp) and would fail every launch — so the sandbox root is
    // both the correct confinement AND the only working choice.
    //
    // Budgets are SANDBOX-class, NOT the trusted launch profile files.cpp uses:
    //   - tick: kTickBudgetSandbox (~10 s) so the scheduler AUTO-KILLS a child
    //     that runs away — a hostile page must not be able to spawn an
    //     infinite-loop binary that starves a CPU core forever.
    //   - frame: a bounded ceiling well below the trusted 8192. kFrameBudgetSandbox
    //     (8) is too tight for a PE (the Win32 import set preloads ~44 DLLs, see
    //     spawn.cpp), so we grant enough headroom for the preload + working set
    //     while staying far from a trusted launch's full region table.
    constexpr duetos::u64 kBrokeredSpawnFrames = 512;
    const duetos::fs::RamfsNode* childRoot = duetos::fs::RamfsSandboxRoot();
    const duetos::u64 pid = is_pe
                                ? duetos::core::SpawnPeFile(canonPath, staging, entry.size_bytes, childCaps, childRoot,
                                                            kBrokeredSpawnFrames, duetos::core::kTickBudgetSandbox)
                                : duetos::core::SpawnElfFile(canonPath, staging, entry.size_bytes, childCaps, childRoot,
                                                             kBrokeredSpawnFrames, duetos::core::kTickBudgetSandbox);

    // Spawn*File copies the bytes into the child's AS during load, so the
    // staging buffer is free to release regardless of spawn success.
    duetos::mm::KFree(staging);

    if (pid == 0)
    {
        return kErrNoExec;
    }
    return static_cast<duetos::i64>(pid);
}

} // namespace duetos::apps::browser
