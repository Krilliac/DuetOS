#include "diag/kpath.h"

#include "arch/x86_64/serial.h"
#include "core/init.h"
#include "debug/probes.h"
#include "log/klog.h"
#include "util/types.h"

/*
 * KPath dump path — boot summary + TSV emitter.
 *
 * KPathEmitBootSummary() emits ONE structured sentinel line that
 * CI greps (`[kpath] visited=N/M ...`) followed by per-category
 * compact summaries via KLOG_INFO so a clean log stays readable.
 *
 * KPathWriteTSV() takes a write callback and walks the unified
 * iterator, emitting one TSV row per visited site. Used by the
 * shell `kpath dump` command (callback = SerialWrite) and the
 * FAT32 persist sink (callback = file write).
 */

namespace duetos::diag
{

namespace
{

// Decimal formatter. Returns characters written (excluding NUL).
// `cap` includes room for the NUL. Used for the `[kpath]` summary
// line — SerialWriteHex would be ugly on small numbers.
::duetos::u32 FormatDec(char* buf, ::duetos::u32 cap, ::duetos::u64 value)
{
    if (cap == 0)
    {
        return 0;
    }
    if (cap == 1)
    {
        buf[0] = '\0';
        return 0;
    }
    char tmp[24] = {};
    ::duetos::u32 n = 0;
    if (value == 0)
    {
        tmp[n++] = '0';
    }
    while (value > 0 && n < sizeof(tmp))
    {
        tmp[n++] = static_cast<char>('0' + (value % 10));
        value /= 10;
    }
    if (n + 1 > cap)
    {
        n = cap - 1;
    }
    for (::duetos::u32 i = 0; i < n; ++i)
    {
        buf[i] = tmp[n - 1 - i];
    }
    buf[n] = '\0';
    return n;
}

void WriteDec(::duetos::u64 value)
{
    char buf[24] = {};
    FormatDec(buf, sizeof(buf), value);
    ::duetos::arch::SerialWrite(buf);
}

void EmitCategoryLine(const char* cat_name, ::duetos::u64 visited, ::duetos::u64 total)
{
    ::duetos::arch::SerialWrite(cat_name);
    ::duetos::arch::SerialWrite(":");
    WriteDec(visited);
    ::duetos::arch::SerialWrite("/");
    WriteDec(total);
}

} // namespace

void KPathEmitBootSummary()
{
    const KPathVisitStats st = KPathSnapshotStats();

    // Total visited = sum across all categories. Total possible =
    // sites_total + 256 (syscalls) + 256 (vectors) + initcalls +
    // probes + fix_records. The denominator is informational — what
    // matters is the per-category breakdown.
    ::duetos::u64 visited_sum = st.sites_visited + st.syscalls_visited + st.vectors_visited + st.initcalls_visited +
                                st.probes_visited + st.fix_records;
    ::duetos::u64 total_sum = st.sites_total + 256 + 256;
    // Initcall total: count registered slots, not visits.
    {
        const ::duetos::u32 ic = ::duetos::core::InitcallCount();
        total_sum += ic;
    }
    // Probe total: kCount sentinel from the probe enum is the upper
    // bound. Read the live row count instead of hard-coding the
    // enum so a future probe addition doesn't drift this denominator.
    {
        ::duetos::debug::ProbeInfo buf[static_cast<::duetos::u64>(::duetos::debug::ProbeId::kCount)] = {};
        const ::duetos::u64 n =
            ::duetos::debug::ProbeList(buf, static_cast<::duetos::u64>(::duetos::debug::ProbeId::kCount));
        total_sum += n;
    }
    // Fix-journal total is conceptually unbounded; use the unique
    // count as both numerator and denominator (visited == total)
    // so it doesn't distort the percentage.
    total_sum += st.fix_records;

    // Percentage = visited * 100 / total (integer math, no FPU).
    const ::duetos::u32 pct = (total_sum > 0) ? static_cast<::duetos::u32>((visited_sum * 100ull) / total_sum) : 0u;

    // Single structured sentinel line — CI greps this verbatim.
    // Held under SerialLineGuard so a concurrent klog can't
    // interleave between the components.
    {
        ::duetos::arch::SerialLineGuard line;
        ::duetos::arch::SerialWrite("[kpath] visited=");
        WriteDec(visited_sum);
        ::duetos::arch::SerialWrite("/");
        WriteDec(total_sum);
        ::duetos::arch::SerialWrite(" (");
        WriteDec(pct);
        ::duetos::arch::SerialWrite("%) cats=");
        EmitCategoryLine("site", st.sites_visited, st.sites_total);
        ::duetos::arch::SerialWrite(" ");
        EmitCategoryLine("syscall", st.syscalls_visited, 256);
        ::duetos::arch::SerialWrite(" ");
        EmitCategoryLine("vector", st.vectors_visited, 256);
        ::duetos::arch::SerialWrite(" ");
        EmitCategoryLine("initcall", st.initcalls_visited, ::duetos::core::InitcallCount());
        ::duetos::arch::SerialWrite(" probe=");
        WriteDec(st.probes_visited);
        ::duetos::arch::SerialWrite(" fix=");
        WriteDec(st.fix_records);
        ::duetos::arch::SerialWrite("\n");
    }

    // Compact per-category readable summary via klog so any operator
    // reading the log at default level sees the breakdown.
    KLOG_INFO_2V("kpath", "summary visited/total", "visited", visited_sum, "total", total_sum);
}

void KPathWriteTSV(void (*write_cb)(const char*, void*), void* ctx)
{
    if (write_cb == nullptr)
    {
        return;
    }

    write_cb("# kpath TSV v1\n", ctx);
    write_cb("# fields: category\tname\thits\tfile\tline\tsyscall\tvector\n", ctx);

    struct EmitCtx
    {
        void (*cb)(const char*, void*);
        void* user;
    };
    EmitCtx ec{write_cb, ctx};

    auto row_cb = [](const KPathIterRow& row, void* raw) -> bool
    {
        EmitCtx* e = static_cast<EmitCtx*>(raw);
        char buf[64] = {};

        e->cb(KPathCatName(row.category), e->user);
        e->cb("\t", e->user);
        e->cb((row.name != nullptr) ? row.name : "?", e->user);
        e->cb("\t", e->user);

        FormatDec(buf, sizeof(buf), row.hits);
        e->cb(buf, e->user);
        e->cb("\t", e->user);

        e->cb((row.file != nullptr) ? row.file : "?", e->user);
        e->cb("\t", e->user);

        FormatDec(buf, sizeof(buf), row.line);
        e->cb(buf, e->user);
        e->cb("\t", e->user);

        if (row.syscall_nr != 0xFFFFu)
        {
            FormatDec(buf, sizeof(buf), row.syscall_nr);
            e->cb(buf, e->user);
        }
        else
        {
            e->cb("-", e->user);
        }
        e->cb("\t", e->user);

        if (row.vector_nr != 0xFFFFu)
        {
            FormatDec(buf, sizeof(buf), row.vector_nr);
            e->cb(buf, e->user);
        }
        else
        {
            e->cb("-", e->user);
        }
        e->cb("\n", e->user);
        return true;
    };
    KPathForEach(row_cb, &ec);
}

} // namespace duetos::diag
