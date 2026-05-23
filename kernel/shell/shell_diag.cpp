/*
 * DuetOS — kernel shell: dfix command.
 *
 * Live-review surface for the fix journal. Reads the in-RAM ring
 * via `FixJournalSnapshot` and exposes it through five operations:
 *
 *   dfix list [N] [--all] [--detector=<name>]
 *                        — tail the last N records (default 20);
 *                          `--detector=cap_denial` (etc) narrows
 *                          to one record kind for targeted triage
 *   dfix show <seq>      — full record dump for one seq
 *   dfix stats           — per-detector counts + lifetime stats
 *   dfix mark-done <seq> — flip the audited bit so future
 *                          listings filter the record out by
 *                          default (the human/Claude reviewer
 *                          sets this once a real source fix is
 *                          authored)
 *   dfix flush           — force a write to KERNEL.FIX (handy
 *                          right before a planned reboot so the
 *                          on-disk file mirrors the live ring)
 *
 * Audited records are excluded from `list` unless `--all` is
 * passed. This keeps the working set focused on un-triaged gaps
 * even after a long boot.
 */

#include "shell/shell.h"

#include "diag/fix_journal.h"
#include "diag/fix_journal_persist.h"
#include "drivers/video/console.h"
#include "shell/shell_internal.h"
#include "util/symbols.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

constexpr u64 kSnapshotCap = 64; // bounded; matches the "tail N" expectations

// Render `n` left-justified in `width` columns. Caller-supplied
// counters must hold the printable text within the width — over-
// long names just print without padding.
void WritePadLeft(const char* s, u64 width)
{
    u64 len = 0;
    while (s[len] != '\0')
        ++len;
    ConsoleWrite(s);
    while (len < width)
    {
        ConsoleWriteChar(' ');
        ++len;
    }
}

// Parse a positive decimal integer from str. Returns true on
// success; on failure leaves *out unchanged.
bool ParseU32Dec(const char* str, u32* out)
{
    if (str == nullptr || str[0] == '\0')
        return false;
    u64 acc = 0;
    for (u32 i = 0; str[i] != '\0'; ++i)
    {
        const char c = str[i];
        if (c < '0' || c > '9')
            return false;
        acc = acc * 10 + static_cast<u64>(c - '0');
        if (acc > 0xFFFFFFFFu)
            return false;
    }
    *out = static_cast<u32>(acc);
    return true;
}

// Look up a FixDetector by the same name FixDetectorName() returns
// ("stub" / "gap" / "unknown_syscall" / ...). Returns
// FixDetector::None on miss — caller treats None as "no filter,"
// which means an unrecognised name silently degrades to "show all"
// rather than producing an empty result that looks like a clean run.
duetos::diag::FixDetector ParseDetectorName(const char* str)
{
    if (str == nullptr || str[0] == '\0')
        return duetos::diag::FixDetector::None;
    // 7 real detectors plus None — small enough to linear-scan with
    // a direct StrEq against the canonical names.
    for (u8 i = 1; i <= 7; ++i)
    {
        const auto det = static_cast<duetos::diag::FixDetector>(i);
        if (StrEq(str, duetos::diag::FixDetectorName(det)))
            return det;
    }
    return duetos::diag::FixDetector::None;
}

void DfixUsage()
{
    ConsoleWriteln("DFIX: USAGE:");
    ConsoleWriteln("    DFIX LIST [N] [--ALL] [--DETECTOR=<NAME>]");
    ConsoleWriteln("                            TAIL THE LAST N RECORDS (DEFAULT 20)");
    ConsoleWriteln("    DFIX SHOW <SEQ>         DETAILED RECORD DUMP");
    ConsoleWriteln("    DFIX STATS              COUNTERS + PER-DETECTOR BREAKDOWN");
    ConsoleWriteln("    DFIX MARK-DONE <SEQ>    SET THE AUDITED BIT");
    ConsoleWriteln("    DFIX FLUSH              FORCE A KERNEL.FIX WRITE");
    ConsoleWriteln("    DETECTOR NAMES: STUB GAP UNKNOWN_SYSCALL UNMAPPED_THUNK");
    ConsoleWriteln("                    SOFT_FAULT_RECOV LOADER_REJECT CAP_DENIAL");
}

// Snapshot cap when filtering: we may have to walk past many
// non-matching records to surface the requested N matches, so widen
// the working buffer to the ring's full capacity. The shell already
// budgets a 1024-record snapshot worst case in InspectRing-class
// commands; same here.
constexpr u64 kFilterSnapshotCap = 256;

void DoList(u32 argc, char** argv)
{
    u32 n = 20;
    bool show_all = false;
    duetos::diag::FixDetector filter = duetos::diag::FixDetector::None;
    for (u32 i = 2; i < argc; ++i)
    {
        if (StrEq(argv[i], "--all") || StrEq(argv[i], "-a"))
        {
            show_all = true;
        }
        else if (StrStartsWith(argv[i], "--detector="))
        {
            const char* name = argv[i] + 11;
            filter = ParseDetectorName(name);
            if (filter == duetos::diag::FixDetector::None)
            {
                ConsoleWrite("DFIX: UNKNOWN DETECTOR '");
                ConsoleWrite(name);
                ConsoleWriteln("' — IGNORING FILTER (RUN 'DFIX' FOR NAMES)");
            }
        }
        else
        {
            u32 parsed = 0;
            if (ParseU32Dec(argv[i], &parsed) && parsed > 0)
                n = parsed;
        }
    }
    if (n > kFilterSnapshotCap)
        n = kFilterSnapshotCap;

    // With a filter we need the wider walk window so the requested N
    // matches actually surface even when the ring is dominated by
    // other detector kinds. Without a filter we keep the original
    // bounded behaviour.
    const u64 walk_cap = (filter == duetos::diag::FixDetector::None) ? n : kFilterSnapshotCap;
    duetos::diag::FixRecord buf[kFilterSnapshotCap] = {};
    const u64 got = duetos::diag::FixJournalSnapshot(buf, walk_cap);
    if (got == 0)
    {
        ConsoleWriteln("DFIX: NO RECORDS");
        return;
    }

    ConsoleWriteln("DFIX:   SEQ   DETECTOR          REPEAT  AUDITED  SOURCE_PIN / HINT");
    u64 shown = 0;
    for (u64 i = 0; i < got && shown < n; ++i)
    {
        const auto& r = buf[i];
        const bool audited = (r.flags & duetos::diag::kFixFlagAudited) != 0;
        if (audited && !show_all)
            continue;
        if (filter != duetos::diag::FixDetector::None && static_cast<duetos::diag::FixDetector>(r.detector) != filter)
            continue;
        ConsoleWrite("  ");
        WriteU64Dec(r.seq);
        ConsoleWrite("    ");
        const auto det = static_cast<duetos::diag::FixDetector>(r.detector);
        WritePadLeft(duetos::diag::FixDetectorName(det), 18);
        WriteU64Dec(r.repeat_count);
        ConsoleWrite("       ");
        ConsoleWrite(audited ? "yes" : "no");
        ConsoleWrite("       ");
        ConsoleWrite(r.source_pin);
        if (r.hint[0] != '\0')
        {
            ConsoleWrite("  -- ");
            ConsoleWrite(r.hint);
        }
        ConsoleWriteChar('\n');
        ++shown;
    }
    if (shown == 0)
    {
        if (filter != duetos::diag::FixDetector::None)
        {
            ConsoleWrite("DFIX: NO RECORDS MATCH DETECTOR=");
            ConsoleWriteln(duetos::diag::FixDetectorName(filter));
        }
        else
        {
            ConsoleWriteln("DFIX: ALL RECORDS AUDITED (PASS --ALL TO INCLUDE)");
        }
    }
}

void DoShow(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("DFIX: SHOW NEEDS <SEQ>");
        return;
    }
    u32 want = 0;
    if (!ParseU32Dec(argv[2], &want))
    {
        ConsoleWriteln("DFIX: BAD SEQ");
        return;
    }
    duetos::diag::FixRecord buf[kSnapshotCap] = {};
    const u64 got = duetos::diag::FixJournalSnapshot(buf, kSnapshotCap);
    for (u64 i = 0; i < got; ++i)
    {
        if (buf[i].seq != want)
            continue;
        const auto& r = buf[i];
        ConsoleWrite("DFIX SEQ=");
        WriteU64Dec(r.seq);
        ConsoleWriteChar('\n');
        ConsoleWrite("  detector  : ");
        ConsoleWriteln(duetos::diag::FixDetectorName(static_cast<duetos::diag::FixDetector>(r.detector)));
        ConsoleWrite("  ts_ns     : ");
        WriteU64Dec(r.ts_ns);
        ConsoleWriteChar('\n');
        ConsoleWrite("  caller_rip: 0x");
        WriteU64Hex(r.caller_rip, 16);
        // Symbolize the rip if we can — the embedded symbol table
        // gives "<func+offset> (file:line)" for kernel addresses.
        // Output goes to COM1 by way of WriteResolvedAddress; that
        // also lands on the framebuffer console because the
        // serial-tee mirrors there.
        duetos::core::SymbolResolution resolution{};
        if (duetos::core::ResolveAddress(r.caller_rip, &resolution))
        {
            ConsoleWrite("  ");
            duetos::core::WriteResolvedAddress(resolution);
        }
        ConsoleWriteChar('\n');
        ConsoleWrite("  ctx_a     : 0x");
        WriteU64Hex(r.ctx_a, 16);
        ConsoleWriteChar('\n');
        ConsoleWrite("  ctx_b     : 0x");
        WriteU64Hex(r.ctx_b, 16);
        ConsoleWriteChar('\n');
        ConsoleWrite("  repeat    : ");
        WriteU64Dec(r.repeat_count);
        ConsoleWriteChar('\n');
        ConsoleWrite("  severity  : ");
        WriteU64Dec(r.severity);
        ConsoleWriteChar('\n');
        ConsoleWrite("  audited   : ");
        ConsoleWriteln((r.flags & duetos::diag::kFixFlagAudited) ? "yes" : "no");
        ConsoleWrite("  source_pin: ");
        ConsoleWriteln(r.source_pin);
        ConsoleWrite("  hint      : ");
        ConsoleWriteln(r.hint[0] != '\0' ? r.hint : "(none)");
        return;
    }
    ConsoleWriteln("DFIX: SEQ NOT FOUND IN RING");
}

void DoStats()
{
    const auto stats = duetos::diag::FixJournalGetStats();
    ConsoleWrite("DFIX STATS:\n  recorded  : ");
    WriteU64Dec(stats.records_recorded);
    ConsoleWrite("\n  unique    : ");
    WriteU64Dec(stats.records_unique);
    ConsoleWrite("\n  dropped   : ");
    WriteU64Dec(stats.records_dropped);
    ConsoleWrite("\n  dedup-hits: ");
    WriteU64Dec(stats.dedup_hits);
    ConsoleWrite("\n  trap-defer: ");
    WriteU64Dec(stats.trap_deferred);
    ConsoleWrite("\n  fat32-sink: ");
    ConsoleWriteln(duetos::diag::FixJournalPersistInstalled() ? "online" : "offline");

    // Per-detector tally from the ring snapshot. Cheap; bounded.
    duetos::diag::FixRecord buf[kSnapshotCap] = {};
    const u64 got = duetos::diag::FixJournalSnapshot(buf, kSnapshotCap);
    u32 per_detector[8] = {};
    for (u64 i = 0; i < got; ++i)
    {
        const u8 d = buf[i].detector;
        if (d < 8)
            ++per_detector[d];
    }
    ConsoleWriteln("DFIX BY DETECTOR (last snapshot):");
    for (u8 d = 1; d < 8; ++d)
    {
        if (per_detector[d] == 0)
            continue;
        ConsoleWrite("  ");
        WritePadLeft(duetos::diag::FixDetectorName(static_cast<duetos::diag::FixDetector>(d)), 18);
        WriteU64Dec(per_detector[d]);
        ConsoleWriteChar('\n');
    }
}

void DoMarkDone(u32 argc, char** argv)
{
    if (argc < 3)
    {
        ConsoleWriteln("DFIX: MARK-DONE NEEDS <SEQ>");
        return;
    }
    u32 want = 0;
    if (!ParseU32Dec(argv[2], &want))
    {
        ConsoleWriteln("DFIX: BAD SEQ");
        return;
    }
    const auto r = duetos::diag::FixJournalMarkAudited(want);
    if (!r.has_value())
    {
        ConsoleWriteln("DFIX: SEQ NOT FOUND");
        return;
    }
    ConsoleWrite("DFIX: MARKED ");
    WriteU64Dec(want);
    ConsoleWriteln(" AUDITED");
}

void DoFlush()
{
    duetos::diag::FixJournalPersistFlush();
    ConsoleWriteln("DFIX: FLUSH OK");
}

} // namespace

void CmdDfix(u32 argc, char** argv)
{
    if (argc < 2)
    {
        DfixUsage();
        return;
    }
    const char* sub = argv[1];
    if (StrEq(sub, "list"))
        DoList(argc, argv);
    else if (StrEq(sub, "show"))
        DoShow(argc, argv);
    else if (StrEq(sub, "stats"))
        DoStats();
    else if (StrEq(sub, "mark-done"))
        DoMarkDone(argc, argv);
    else if (StrEq(sub, "flush"))
        DoFlush();
    else
        DfixUsage();
}

} // namespace duetos::core::shell::internal
