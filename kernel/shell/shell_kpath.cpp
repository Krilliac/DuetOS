#include "shell/shell.h"

#include "diag/kpath.h"
#include "diag/kpath_persist.h"
#include "drivers/video/console.h"
#include "shell/shell_internal.h"

/*
 * `kpath` shell command.
 *
 *   kpath list                 — per-category visit summary
 *   kpath show <category>      — every row in a single category
 *   kpath hits <substring>     — find rows whose name matches
 *   kpath dump                 — full TSV to the console
 *   kpath flush                — rewrite KERNEL.KPATH.TSV
 *
 * Mirrors the `dfix` command's shape — no admin gate on read
 * paths (the data exposed is already in the boot log), no
 * privilege escalation on flush (it writes the same data the
 * smoke completion path would).
 */

namespace duetos::core::shell::internal
{

namespace
{

using ::duetos::drivers::video::ConsoleWrite;
using ::duetos::drivers::video::ConsoleWriteln;

void KpathUsage()
{
    ConsoleWriteln("usage:");
    ConsoleWriteln("  kpath list                 — per-category visit summary");
    ConsoleWriteln("  kpath show <category>      — every row in a category");
    ConsoleWriteln("  kpath hits <substring>     — rows whose name contains substring");
    ConsoleWriteln("  kpath dump                 — full TSV to the console");
    ConsoleWriteln("  kpath flush                — rewrite KERNEL.KPATH.TSV");
    ConsoleWriteln("");
    ConsoleWriteln("categories: manual syscall vector initcall probe fix selftest branch");
}

void DoList()
{
    const ::duetos::diag::KPathVisitStats st = ::duetos::diag::KPathSnapshotStats();
    ConsoleWrite("kpath visit stats:\n");
    ConsoleWrite("  sites    : ");
    WriteU64Dec(st.sites_visited);
    ConsoleWrite(" / ");
    WriteU64Dec(st.sites_total);
    ConsoleWrite("\n  syscalls : ");
    WriteU64Dec(st.syscalls_visited);
    ConsoleWrite(" / 256\n  vectors  : ");
    WriteU64Dec(st.vectors_visited);
    ConsoleWrite(" / 256\n  initcalls: ");
    WriteU64Dec(st.initcalls_visited);
    ConsoleWrite("\n  probes   : ");
    WriteU64Dec(st.probes_visited);
    ConsoleWrite("\n  fix recs : ");
    WriteU64Dec(st.fix_records);
    ConsoleWriteln("");
}

struct ShowCtx
{
    ::duetos::diag::KPathCat want;
    ::duetos::u32 emitted;
};

bool ShowRowCb(const ::duetos::diag::KPathIterRow& row, void* raw)
{
    ShowCtx* ctx = static_cast<ShowCtx*>(raw);
    if (row.category != ctx->want)
    {
        return true;
    }
    ConsoleWrite("  ");
    ConsoleWrite(::duetos::diag::KPathCatName(row.category));
    ConsoleWrite(" ");
    ConsoleWrite((row.name != nullptr) ? row.name : "?");
    if (row.syscall_nr != 0xFFFFu)
    {
        ConsoleWrite(" syscall=");
        WriteU64Dec(row.syscall_nr);
    }
    if (row.vector_nr != 0xFFFFu)
    {
        ConsoleWrite(" vector=");
        WriteU64Dec(row.vector_nr);
    }
    ConsoleWrite(" hits=");
    WriteU64Dec(row.hits);
    ConsoleWriteln("");
    ctx->emitted++;
    return true;
}

::duetos::diag::KPathCat ParseCategory(const char* s)
{
    using ::duetos::diag::KPathCat;
    if (StrEq(s, "manual"))
        return KPathCat::Manual;
    if (StrEq(s, "syscall"))
        return KPathCat::Syscall;
    if (StrEq(s, "vector"))
        return KPathCat::Vector;
    if (StrEq(s, "initcall"))
        return KPathCat::Initcall;
    if (StrEq(s, "probe"))
        return KPathCat::Probe;
    if (StrEq(s, "fix"))
        return KPathCat::Fix;
    if (StrEq(s, "selftest"))
        return KPathCat::SelfTest;
    if (StrEq(s, "branch"))
        return KPathCat::Branch;
    return KPathCat::None;
}

void DoShow(::duetos::u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("usage: kpath show <category>");
        return;
    }
    const ::duetos::diag::KPathCat cat = ParseCategory(argv[2]);
    if (cat == ::duetos::diag::KPathCat::None)
    {
        ConsoleWrite("unknown category: ");
        ConsoleWriteln(argv[2]);
        return;
    }
    ShowCtx ctx{cat, 0};
    ::duetos::diag::KPathForEach(ShowRowCb, &ctx);
    ConsoleWrite("(");
    WriteU64Dec(ctx.emitted);
    ConsoleWriteln(" rows)");
}

bool StrContains(const char* haystack, const char* needle)
{
    if (haystack == nullptr || needle == nullptr)
    {
        return false;
    }
    if (needle[0] == '\0')
    {
        return true;
    }
    for (const char* h = haystack; *h != '\0'; ++h)
    {
        const char* hp = h;
        const char* np = needle;
        while (*hp != '\0' && *np != '\0' && *hp == *np)
        {
            ++hp;
            ++np;
        }
        if (*np == '\0')
        {
            return true;
        }
    }
    return false;
}

struct HitsCtx
{
    const char* needle;
    ::duetos::u32 emitted;
};

bool HitsRowCb(const ::duetos::diag::KPathIterRow& row, void* raw)
{
    HitsCtx* ctx = static_cast<HitsCtx*>(raw);
    if (!StrContains(row.name, ctx->needle))
    {
        return true;
    }
    ConsoleWrite("  ");
    ConsoleWrite(::duetos::diag::KPathCatName(row.category));
    ConsoleWrite(" ");
    ConsoleWrite((row.name != nullptr) ? row.name : "?");
    ConsoleWrite(" hits=");
    WriteU64Dec(row.hits);
    ConsoleWriteln("");
    ctx->emitted++;
    return true;
}

void DoHits(::duetos::u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("usage: kpath hits <substring>");
        return;
    }
    HitsCtx ctx{argv[2], 0};
    ::duetos::diag::KPathForEach(HitsRowCb, &ctx);
    ConsoleWrite("(");
    WriteU64Dec(ctx.emitted);
    ConsoleWriteln(" rows)");
}

void DumpWriteCb(const char* str, void* /*ctx*/)
{
    ConsoleWrite(str);
}

void DoDump()
{
    ::duetos::diag::KPathWriteTSV(DumpWriteCb, nullptr);
}

void DoFlush()
{
    if (!::duetos::diag::KPathPersistInstalled())
    {
        ConsoleWriteln("kpath: persist sink not installed (no FAT32 volume?)");
        return;
    }
    ::duetos::diag::KPathPersistFlush();
    ConsoleWriteln("kpath: KERNEL.KPATH.TSV rewritten");
}

} // namespace

void CmdKpath(::duetos::u32 argc, char** argv)
{
    if (argc < 2)
    {
        KpathUsage();
        return;
    }
    const char* sub = argv[1];
    if (StrEq(sub, "list"))
        DoList();
    else if (StrEq(sub, "show"))
        DoShow(argc, argv);
    else if (StrEq(sub, "hits"))
        DoHits(argc, argv);
    else if (StrEq(sub, "dump"))
        DoDump();
    else if (StrEq(sub, "flush"))
        DoFlush();
    else
        KpathUsage();
}

} // namespace duetos::core::shell::internal
