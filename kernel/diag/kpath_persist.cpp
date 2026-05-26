#include "diag/kpath_persist.h"

#include "arch/x86_64/serial.h"
#include "diag/kpath.h"
#include "fs/fat32.h"
#include "log/klog.h"
#include "util/types.h"

/*
 * KPath persistence — FAT32 sink implementation.
 *
 * Strategy: full rewrite per flush. The TSV body is bounded by
 * the number of sites in `.kpath_sites` plus 256 (syscalls) +
 * 256 (vectors) + ~64 (initcalls) + 45 (probes) + 64 (fix
 * records) ≈ at most a few hundred rows in the foreseeable
 * future. Even with verbose row data each line is well under
 * 256 bytes, so 256 KiB of scratch is more than enough headroom.
 *
 * Mirrors `fix_journal_persist.cpp`'s shape (static .bss scratch
 * + single Fat32CreateAtPath call) but skips rotation — the
 * offline diff tool consumes a single file per boot and the
 * harness archives them externally.
 */

namespace duetos::diag
{

namespace
{

constinit bool g_installed = false;

// Scratch buffer for the assembled TSV body. .bss-resident, never
// freed. Sized generously: each row averages ~80 chars, and total
// row count is bounded by the sum of sites + 256 + 256 + initcalls
// + probes + fix-records. 256 KiB covers any plausible expansion
// for the next several years of subsystem additions.
constexpr ::duetos::u64 kKPathScratchBytes = 256ull * 1024ull;
::duetos::u8 g_kpath_scratch[kKPathScratchBytes] = {};

// Append cursor used inside the TSV-build callback.
struct AppendCtx
{
    ::duetos::u8* buf;
    ::duetos::u64 cap;
    ::duetos::u64 used;
    bool overflow;
};

void AppendBytes(AppendCtx& ac, const char* str)
{
    if (ac.overflow || str == nullptr)
    {
        return;
    }
    for (const char* p = str; *p != '\0'; ++p)
    {
        if (ac.used >= ac.cap)
        {
            ac.overflow = true;
            return;
        }
        ac.buf[ac.used++] = static_cast<::duetos::u8>(*p);
    }
}

void TsvWriteToScratch(const char* str, void* raw)
{
    AppendCtx* ac = static_cast<AppendCtx*>(raw);
    AppendBytes(*ac, str);
}

// Build the TSV into g_kpath_scratch. Returns used byte count.
// `panic_safe` selects the lock-free ledger walk so this is
// callable from the panic path.
::duetos::u64 BuildScratch(bool panic_safe)
{
    AppendCtx ac{};
    ac.buf = g_kpath_scratch;
    ac.cap = kKPathScratchBytes;
    ac.used = 0;
    ac.overflow = false;

    if (panic_safe)
    {
        // Inline the header to avoid going through KPathWriteTSV's
        // callback hop in panic context.
        AppendBytes(ac, "# kpath TSV v1\n");
        AppendBytes(ac, "# fields: category\tname\thits\tfile\tline\tsyscall\tvector\n");

        // Reuse the dump module's TSV writer pointer via the public
        // API. Since KPathWriteTSV internally calls KPathForEach
        // (not the panic-safe variant), inline a minimal walk here
        // for the panic path. Simpler than threading panic-safety
        // through the dump callback chain.
        auto row_cb = [](const KPathIterRow& row, void* raw) -> bool
        {
            AppendCtx* a = static_cast<AppendCtx*>(raw);
            AppendBytes(*a, KPathCatName(row.category));
            AppendBytes(*a, "\t");
            AppendBytes(*a, (row.name != nullptr) ? row.name : "?");
            AppendBytes(*a, "\t");
            char num[24] = {};
            ::duetos::u64 v = row.hits;
            ::duetos::u32 n = 0;
            if (v == 0)
            {
                num[n++] = '0';
            }
            else
            {
                char tmp[24] = {};
                ::duetos::u32 t = 0;
                while (v > 0 && t < sizeof(tmp))
                {
                    tmp[t++] = static_cast<char>('0' + (v % 10));
                    v /= 10;
                }
                for (::duetos::u32 i = 0; i < t; ++i)
                {
                    num[n++] = tmp[t - 1 - i];
                }
            }
            num[n] = '\0';
            AppendBytes(*a, num);
            AppendBytes(*a, "\t");
            AppendBytes(*a, (row.file != nullptr) ? row.file : "?");
            AppendBytes(*a, "\t-\t-\t-\n");
            return !a->overflow;
        };
        KPathForEachPanicSafe(row_cb, &ac);
    }
    else
    {
        KPathWriteTSV(TsvWriteToScratch, &ac);
    }

    return ac.used;
}

bool WriteScratchToVolume(const ::duetos::fs::fat32::Volume* v, ::duetos::u64 length)
{
    namespace fat = ::duetos::fs::fat32;

    // Delete any prior copy so size is exact.
    fat::DirEntry pre;
    if (fat::Fat32LookupPath(v, kKPathTsvPath, &pre))
    {
        fat::Fat32DeleteAtPath(v, kKPathTsvPath);
    }

    const ::duetos::i64 wrote = fat::Fat32CreateAtPath(v, kKPathTsvPath, g_kpath_scratch, length);
    return wrote >= 0;
}

} // namespace

bool KPathPersistInstall()
{
    namespace fat = ::duetos::fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        ::duetos::arch::SerialWrite("[kpath-persist] no FAT32 volume — skipping\n");
        return false;
    }

    const ::duetos::u64 len = BuildScratch(false);
    if (!WriteScratchToVolume(v, len))
    {
        KLOG_WARN("diag/kpath-persist", "initial KERNEL.KPATH.TSV write failed");
        return false;
    }

    g_installed = true;
    KLOG_INFO("diag/kpath-persist", "online — kpath ledger -> KERNEL.KPATH.TSV");
    return true;
}

void KPathPersistFlush()
{
    if (!g_installed)
    {
        return;
    }
    namespace fat = ::duetos::fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        g_installed = false;
        KLOG_WARN("diag/kpath-persist", "FAT32 volume gone — sink offline");
        return;
    }
    const ::duetos::u64 len = BuildScratch(false);
    (void)WriteScratchToVolume(v, len);
}

void KPathPersistFlushPanicSafe()
{
    namespace fat = ::duetos::fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        return;
    }
    const ::duetos::u64 len = BuildScratch(true);
    (void)WriteScratchToVolume(v, len);
}

bool KPathPersistInstalled()
{
    return g_installed;
}

} // namespace duetos::diag
