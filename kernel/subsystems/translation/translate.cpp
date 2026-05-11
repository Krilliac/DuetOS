/*
 * DuetOS — ABI translation unit: implementation.
 *
 * Companion to translate.h — see there for the public
 * translation entry points (Linux <-> DuetOS native, NT ->
 * DuetOS native).
 *
 * WHAT
 *   Bidirectional conversion between foreign-ABI syscall
 *   numbers / argument shapes / errno values and the DuetOS
 *   native equivalents. Used by:
 *     - the Linux subsystem (`syscall` instruction path) when
 *       a SYS_NT_INVOKE arrives from a Win32 PE that wants to
 *       reuse the Linux ABI (rare but supported);
 *     - the NT->Linux translator that lets ntdll Nt* calls
 *       fall through to a Linux SYS_* on the native side.
 *
 * HOW
 *   Translation tables are static arrays sorted by foreign
 *   syscall number. Argument-shape conversion (fd ordering,
 *   open() flags, mmap protection bits) is per-syscall hand
 *   code — too irregular to drive from a generic table.
 *
 *   Errno mapping: Linux errno is positive, NTSTATUS is a
 *   sign-bit-encoded 32-bit space, DuetOS native uses a
 *   `Result<T, ErrorCode>` enum class. This file owns the
 *   tables + helpers that map between them.
 */

#include "subsystems/translation/translate.h"

#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "diag/fix_journal.h"
#include "log/klog.h"
#include "proc/process.h"
#include "util/random.h"
#include "syscall/syscall_names.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "subsystems/linux/linux_syscall_table_generated.h"
#include "subsystems/linux/syscall.h"
#include "subsystems/win32/heap.h"
#include "subsystems/win32/nt_syscall_table_generated.h"

namespace duetos::subsystems::translation
{

namespace
{

// NTSTATUS values we produce for the NT→Linux translator. Only
// the handful we actually need; Windows defines many more.
//   STATUS_SUCCESS              (0)          — fall-through success
//   STATUS_NOT_IMPLEMENTED      (0xC0000002) — no translation
//   STATUS_INVALID_HANDLE       (0xC0000008) — bad FILE_HANDLE
//   STATUS_INVALID_PARAMETER    (0xC000000D) — bad arg shape
//   STATUS_ACCESS_DENIED        (0xC0000022) — cap denied
//   STATUS_UNSUCCESSFUL         (0xC0000001) — catch-all failure
constexpr i64 kStatusSuccess = 0;
constexpr i64 kStatusNotImplemented = static_cast<i64>(0xC0000002ll);
constexpr i64 kStatusInvalidHandle = static_cast<i64>(0xC0000008ll);
constexpr i64 kStatusInvalidParam = static_cast<i64>(0xC000000Dll);
constexpr i64 kStatusAccessDenied = static_cast<i64>(0xC0000022ll);
constexpr i64 kStatusUnsuccessful = static_cast<i64>(0xC0000001ll);

// Native hit counter. Bucketed on syscall_nr & 0x3FF (native
// dispatch is 0..30; one bucket per nr is plenty). Simple
// static table — no dynamic growth needed at this scale.
constinit HitTable g_native_hits = {};

// Translator overhead telemetry. Cheap RDTSC delta around each
// gap-fill call — answers "what does the translator cost?" with
// real numbers instead of guesses. TSC is monotonic on single-
// CPU x86_64; `__rdtsc()` is serialising-free which is exactly
// what we want for low-overhead sampling (we'd pay 30-ish cycles
// for the read itself, versus hundreds-to-thousands for the
// actual gap-fill work we're trying to measure).
struct OverheadTally
{
    u64 calls = 0;
    u64 cycles_total = 0;
    u64 cycles_max = 0;
};
constinit OverheadTally g_native_overhead = {};

// NT-translation telemetry. NT calls don't share the native
// bucket array because the number spaces overlap (NT 0x1D3 is
// a valid native nr too); a separate summary tally keeps the
// CI assertion unambiguous. `calls` counts handled translations
// only; misses are reported separately via the miss-log path.
constinit OverheadTally g_nt_overhead = {};
constinit u64 g_nt_miss_total = 0;

// Miss-log sampling state. Hot probe paths can call unknown numbers
// thousands of times; writing every miss to COM1 dominates runtime.
// Keep the first few misses fully visible, then sample at powers of
// two (1,2,3,4,8,16,...) so long runs still show progress.
struct MissSampleTable
{
    u32 seen[1024] = {};
    u32 suppressed[1024] = {};
    u64 emitted_total = 0;
    u64 suppressed_total = 0;
    u64 suppressed_reported = 0;
};
constinit MissSampleTable g_native_miss_sampling = {};

inline u64 ReadTsc()
{
    u32 lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<u64>(hi) << 32) | lo;
}

void BumpOverhead(OverheadTally& t, u64 delta)
{
    ++t.calls;
    t.cycles_total += delta;
    if (delta > t.cycles_max)
        t.cycles_max = delta;
}

void BumpHits(HitTable& t, u64 nr)
{
    if (t.buckets[nr & 0x3FF] != 0xFFFFFFFFu)
    {
        ++t.buckets[nr & 0x3FF];
    }
}

bool ShouldLogMiss(MissSampleTable& t, u64 nr)
{
    constexpr u32 kFirstAlways = 3;
    const u64 idx = nr & 0x3FF;
    const u32 seen = ++t.seen[idx];
    if (seen <= kFirstAlways || (seen & (seen - 1u)) == 0u)
    {
        ++t.emitted_total;
        return true;
    }

    if (t.suppressed[idx] != 0xFFFFFFFFu)
        ++t.suppressed[idx];
    ++t.suppressed_total;
    return false;
}

// One-shot summary of misses we've suppressed (sampled out)
// since the last dump. Reports cumulative + delta so the
// telemetry consumer can both see history and watch the rate.
void DumpSuppressedMissSummary(const char* origin, MissSampleTable& t)
{
    const u64 cum = t.suppressed_total;
    const u64 delta = cum - t.suppressed_reported;
    t.suppressed_reported = cum;
    arch::SerialWrite("[translate-miss-suppressed] ");
    arch::SerialWrite(origin);
    arch::SerialWrite(" cumulative=");
    arch::SerialWriteHex(cum);
    arch::SerialWrite(" delta=");
    arch::SerialWriteHex(delta);
    arch::SerialWrite(" emitted=");
    arch::SerialWriteHex(t.emitted_total);
    arch::SerialWrite("\n");
}

// Log prefix so boot-log grep is easy.
void LogTranslation(const char* origin, u64 nr, const char* target)
{
    arch::SerialWrite("[translate] ");
    arch::SerialWrite(origin);
    arch::SerialWrite("/");
    arch::SerialWriteHex(nr);
    arch::SerialWrite(" -> ");
    arch::SerialWrite(target);
    arch::SerialWrite("\n");
}

// Linux syscall-number-to-name lookup now comes from
// `linux_syscall_table_generated.h` (374 entries covering the full
// x86_64 ABI: 0..334 + 424..462). The generator flags which numbers
// have a live Do* handler in syscall.cpp so the miss-path log line
// can distinguish "known, unimplemented" from "unknown number".

// Names for the experimental "extension" native syscalls synthesised
// in this TU (kNativeClockNs etc., 0x200..0x211). These numbers are
// not part of the SyscallNumber enum — they live as anonymous-enum
// constants further down — so they can't ride the shared
// kSyscallNames table; we keep them here next to the values they
// describe.
struct NativeExtName
{
    u64 nr;
    const char* name;
};
constexpr NativeExtName kNativeExtNames[] = {
    {0x200, "NativeClockNs"},
    {0x201, "NativeGetRandom"},
    {0x210, "NativeWin32Alloc"},
    {0x211, "NativeWin32Free"},
};

// Full per-call state (known/implemented/unknown) for the more
// informative miss-path log. Returns HandlerState::Unknown for
// numbers outside the generated table.
::duetos::subsystems::linux::HandlerState LinuxState(u64 nr)
{
    const auto* entry = ::duetos::subsystems::linux::LinuxSyscallLookup(nr);
    return (entry != nullptr) ? entry->state : ::duetos::subsystems::linux::HandlerState::Unknown;
}

const char* NativeName(u64 nr)
{
    if (const char* name = ::duetos::core::SyscallNumberName(nr); name != nullptr)
        return name;
    for (const auto& e : kNativeExtNames)
    {
        if (e.nr == nr)
            return e.name;
    }
    return nullptr;
}

// Miss log — rich single-line record so one `grep '[<origin>-miss]'`
// tells you the number, name (when known), caller RIP, and all six
// syscall-ABI arg registers. Arg interpretation varies per syscall,
// but having the raw values in the log is usually enough to figure
// out what the user program was trying to do (e.g. seeing rdi=0x3,
// rsi=<ptr>, rdx=0x200 on an `openat` miss tells you fd=3, some
// path pointer, flags=O_RDWR|O_CLOEXEC).
//
// Linux ABI: rax=nr, args in rdi, rsi, rdx, r10, r8, r9.
// Native ABI (int 0x80): rax=nr, args in rdi, rsi, rdx.
void LogMiss(const char* origin, arch::TrapFrame* f, const char* name)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    SerialWrite("[");
    SerialWrite(origin);
    SerialWrite("-miss] nr=");
    SerialWriteHex(f->rax);
    SerialWrite(" name=\"");
    SerialWrite(name ? name : "<unknown>");
    SerialWrite("\"");
    // For Linux misses, append the handler state so it's obvious
    // from the log whether this was an unknown ABI number or a known-
    // but-unimplemented syscall.
    if (origin != nullptr && origin[0] == 'l' && origin[1] == 'i') // "linux"
    {
        using ::duetos::subsystems::linux::HandlerState;
        const HandlerState st = LinuxState(f->rax);
        SerialWrite(" state=");
        switch (st)
        {
        case HandlerState::Implemented:
            SerialWrite("implemented");
            break;
        case HandlerState::Unimplemented:
            SerialWrite("unimplemented");
            break;
        case HandlerState::Unknown:
            SerialWrite("unknown-nr");
            break;
        default:
            SerialWrite("invalid-state");
            break;
        }
    }
    SerialWrite(" rip=");
    SerialWriteHex(f->rip);
    SerialWrite(" args=[");
    SerialWriteHex(f->rdi);
    SerialWrite(",");
    SerialWriteHex(f->rsi);
    SerialWrite(",");
    SerialWriteHex(f->rdx);
    SerialWrite(",");
    SerialWriteHex(f->r10);
    SerialWrite(",");
    SerialWriteHex(f->r8);
    SerialWrite(",");
    SerialWriteHex(f->r9);
    SerialWrite("]\n");
}

// ----- native → Linux/Win32 translations -----

// Experimental native syscall numbers whose body we synthesise
// by borrowing from Linux. The native dispatch table hasn't
// committed to specific numbers for these, so we're picking
// un-used ones well past the current SYS_* range. Any native
// caller using them is doing so ahead of a formal primary
// handler — useful in practice for kernel-side probes.
enum : u64
{
    kNativeClockNs = 0x200,    // returns NowNs() directly in rax
    kNativeGetRandom = 0x201,  // u64 buf, u64 count -> count (via xorshift)
    kNativeWin32Alloc = 0x210, // u64 size -> user_ptr (via Win32 heap)
    kNativeWin32Free = 0x211,  // u64 user_ptr -> 0
};

// Native: "give me monotonic nanoseconds" — trivially available
// via the already-exposed LinuxNowNs helper.
i64 NativeClockNs(arch::TrapFrame* /*f*/)
{
    return static_cast<i64>(linux::LinuxNowNs());
}

// Native: getrandom(buf, count) — not implemented in core/syscall,
// but the Linux handler exists. Reinvoke via a synthetic inner
// frame: stash the arguments where LinuxGetRandom would expect
// them and call the existing helper.
// Routes through the shared kernel entropy pool
// (`core::RandomFillBytes`) so user-mode callers get the same
// RDSEED/RDRAND backing the rest of the kernel uses.
i64 NativeGetRandom(arch::TrapFrame* f)
{
    const u64 user_buf = f->rdi;
    u64 count = f->rsi;
    if (count == 0)
        return 0;
    if (count > 4096)
        count = 4096;
    static u8 tmp[4096];
    core::RandomFillBytes(tmp, count);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), tmp, count))
        return -14; // -EFAULT
    return static_cast<i64>(count);
}

// Native: Win32HeapAlloc proxy — a non-Win32 process that wants
// Win32-style heap semantics can reach it through the TU. Uses
// the same per-process heap the Win32 PE loader sets up; caller
// gets back an 8-aligned user pointer or 0 on failure.
i64 NativeWin32Alloc(arch::TrapFrame* f)
{
    auto* p = core::CurrentProcess();
    if (p == nullptr)
        return 0;
    return static_cast<i64>(::duetos::win32::Win32HeapAlloc(p, f->rdi));
}

// Native: Win32HeapFree proxy.
i64 NativeWin32Free(arch::TrapFrame* f)
{
    auto* p = core::CurrentProcess();
    if (p == nullptr)
        return 0;
    ::duetos::win32::Win32HeapFree(p, f->rdi);
    return 0;
}

// ---------------------------------------------------------------
// NT → Linux translator.
//
// Each NtDo<Name> handler reads NT-ABI arguments out of the
// trap frame (rsi..r9 — remember rdi carries the NT number
// for SYS_NT_INVOKE), fabricates the Linux-ABI arg shape the
// matching Linux* wrapper expects, and maps the POSIX errno
// return to an NTSTATUS.
//
// Signature convention: each NtDo<Name> returns the final
// NTSTATUS directly; the SYS_NT_INVOKE dispatcher writes that
// into frame->rax as the caller-visible return.
// ---------------------------------------------------------------

// Bedrock NT syscall numbers we translate. Kept as a handful
// with clean 1:1 Linux mappings — expand as real ntdll-shim
// demand arrives. Numbers come from the j00ru table embedded in
// `kernel/subsystems/win32/nt_syscall_table_generated.h`.
enum : u64
{
    kNtClose = 0x000F,
    kNtYieldExecution = 0x0046,
    kNtDelayExecution = 0x0034,
    kNtQueryPerformanceCounter = 0x0031,
    kNtGetCurrentProcessorNumber = 0x00DA,
    kNtTerminateThread = 0x0053,
    kNtTerminateProcess = 0x002C,
    kNtFlushBuffersFile = 0x004B,
    kNtGetTickCount = 0x0171,
    kNtQuerySystemTime = 0x005A,
    // v0 safe synthetic-success calls — NT semantics are a no-op
    // in our subset, so a one-line success keeps the ntdll shim
    // moving without pretending we honour every info class.
    kNtSetInformationThread = 0x000D,
    kNtQueryDefaultLocale = 0x0015,
    kNtQueryDefaultUILanguage = 0x0044,
    kNtFlushInstructionCache = 0x00F1,
    kNtTestAlert = 0x01D3,
};

// POSIX errno (Linux helpers return negative) → NTSTATUS.
i64 ErrnoToNtStatus(i64 posix_rv)
{
    if (posix_rv >= 0)
        return kStatusSuccess;
    switch (-posix_rv)
    {
    case 9: // EBADF
        return kStatusInvalidHandle;
    case 13: // EACCES
    case 1:  // EPERM
        return kStatusAccessDenied;
    case 14: // EFAULT
    case 22: // EINVAL
        return kStatusInvalidParam;
    case 38: // ENOSYS
        return kStatusNotImplemented;
    default:
        return kStatusUnsuccessful;
    }
}

// NtClose(HANDLE). In v0 every Win32 handle comes from our own
// stable numbering; FAT32 fds (linux-ABI) occupy [3, 16). Forward
// to LinuxClose when the argument looks like an fd; for the
// Win32-shaped handle ranges, return success (the Win32
// file-close path is SYS_FILE_CLOSE and ntdll should route there
// separately).
i64 NtDoClose(arch::TrapFrame* f)
{
    const u64 h = f->rsi;
    if (h >= 3 && h < 16)
    {
        const i64 rv = ::duetos::subsystems::linux::LinuxClose(h);
        return ErrnoToNtStatus(rv);
    }
    // Out-of-our-range handle: treat as already-closed success.
    // Win32 CloseHandle is defined to succeed on previously-
    // closed handles anyway.
    return kStatusSuccess;
}

// NtYieldExecution(): drop the remaining time slice.
i64 NtDoYieldExecution(arch::TrapFrame* /*f*/)
{
    ::duetos::subsystems::linux::LinuxSchedYield();
    return kStatusSuccess;
}

// NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER Interval).
// Interval is in 100 ns units, negative means relative.
// Translate to a Linux timespec and call LinuxNanosleep.
i64 NtDoDelayExecution(arch::TrapFrame* f)
{
    const u64 user_interval = f->rdx;
    if (user_interval == 0)
        return kStatusInvalidParam;
    // Read the LARGE_INTEGER (i64) from user space.
    i64 interval = 0;
    if (!mm::CopyFromUser(&interval, reinterpret_cast<const void*>(user_interval), sizeof(interval)))
        return kStatusInvalidParam;
    // Negative = relative (the common case for Sleep(ms)).
    // Positive = absolute since 1601 — we don't do absolute;
    // just diff from NowNs for an approximation.
    u64 ns = 0;
    if (interval < 0)
    {
        ns = static_cast<u64>(-interval) * 100ull;
    }
    else
    {
        // Approximate: compute now in Win FILETIME units, diff.
        // Good enough for v0; precise absolute wait arrives with
        // the RTC integration.
        const u64 now_ns = ::duetos::subsystems::linux::LinuxNowNs();
        const u64 abs_ns = static_cast<u64>(interval) * 100ull;
        ns = (abs_ns > now_ns) ? (abs_ns - now_ns) : 0;
    }
    struct
    {
        i64 tv_sec;
        i64 tv_nsec;
    } req{static_cast<i64>(ns / 1'000'000'000ull), static_cast<i64>(ns % 1'000'000'000ull)};
    // Build a temporary bounce buffer in kernel — user_rem=0.
    // LinuxNanosleep reads via CopyFromUser, so we need a user-
    // accessible address. Instead, call the internal helper
    // directly by faking: for v0 we just compute the tick count
    // and SchedSleepTicks. Simpler than round-tripping.
    const u64 total_ns = static_cast<u64>(req.tv_sec) * 1'000'000'000ull + static_cast<u64>(req.tv_nsec);
    const u64 ticks = (total_ns + 9'999'999ull) / 10'000'000ull; // 10 ms/tick
    if (ticks > 0)
        sched::SchedSleepTicks(ticks);
    return kStatusSuccess;
}

// NtQueryPerformanceCounter(PLARGE_INTEGER Counter, PLARGE_INTEGER
// Frequency): counter = NowNs(), freq = 1_000_000_000 (1 GHz virtual).
i64 NtDoQueryPerformanceCounter(arch::TrapFrame* f)
{
    const u64 user_counter = f->rsi;
    const u64 user_freq = f->rdx;
    if (user_counter == 0)
        return kStatusInvalidParam;
    const i64 counter = static_cast<i64>(::duetos::subsystems::linux::LinuxNowNs());
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_counter), &counter, sizeof(counter)))
        return kStatusInvalidParam;
    if (user_freq != 0)
    {
        const i64 freq = 1'000'000'000;
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_freq), &freq, sizeof(freq)))
            return kStatusInvalidParam;
    }
    return kStatusSuccess;
}

// NtGetCurrentProcessorNumber(): BSP-only → 0.
i64 NtDoGetCurrentProcessorNumber(arch::TrapFrame* /*f*/)
{
    return 0;
}

// NtTerminateThread(HANDLE Thread, NTSTATUS ExitStatus): we have
// one task per process in v0, so this behaves like exit.
[[noreturn]] void NtDoTerminateThread(arch::TrapFrame* f)
{
    const u64 exit_status = f->rdx;
    ::duetos::subsystems::linux::LinuxExit(exit_status);
}

// NtTerminateProcess(HANDLE Process, NTSTATUS ExitStatus): same as
// above for single-task-per-process. A proper implementation would
// null-check the handle (NULL = current) and reap all threads.
[[noreturn]] void NtDoTerminateProcess(arch::TrapFrame* f)
{
    const u64 exit_status = f->rdx;
    ::duetos::subsystems::linux::LinuxExit(exit_status);
}

// NtFlushBuffersFile(HANDLE, PIO_STATUS_BLOCK): forward to fsync
// when the handle looks like an fd.
i64 NtDoFlushBuffersFile(arch::TrapFrame* f)
{
    const u64 h = f->rsi;
    if (h < 3 || h >= 16)
        return kStatusInvalidHandle;
    const i64 rv = ::duetos::subsystems::linux::LinuxFsync(h);
    return ErrnoToNtStatus(rv);
}

// NtGetTickCount(): milliseconds since boot.
i64 NtDoGetTickCount(arch::TrapFrame* /*f*/)
{
    const u64 ns = ::duetos::subsystems::linux::LinuxNowNs();
    return static_cast<i64>(ns / 1'000'000ull);
}

// NtQuerySystemTime(PLARGE_INTEGER Time): current time as FILETIME
// (100 ns ticks since 1601). We only know ns-since-boot — report
// that directly (FILETIME semantics will fall out once the RTC
// integration provides a real epoch).
i64 NtDoQuerySystemTime(arch::TrapFrame* f)
{
    const u64 user_time = f->rsi;
    if (user_time == 0)
        return kStatusInvalidParam;
    const i64 ft = static_cast<i64>(::duetos::subsystems::linux::LinuxNowNs() / 100ull);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_time), &ft, sizeof(ft)))
        return kStatusInvalidParam;
    return kStatusSuccess;
}

// NtSetInformationThread(HANDLE Thread, THREADINFOCLASS Class,
// PVOID Info, ULONG Length): real Windows treats most info classes
// as silent-success no-ops once validation passes; v0 has no
// thread-info-class effects (priority/affinity/etc.) so synthetic
// STATUS_SUCCESS matches what the CRT startup sequence expects.
// GAP: thread-info classes that DO matter (TLS slot, exit status)
// — revisit when a real workload depends on one.
i64 NtDoSetInformationThread(arch::TrapFrame* /*f*/)
{
    return kStatusSuccess;
}

// NtQueryDefaultLocale(BOOLEAN UserProfile, PLCID DefaultLocaleId).
// We report LOCALE_NEUTRAL_LCID en-US (0x0409); the ntdll shim that
// asks at startup just wants a stable value to thread through to
// the user-mode locale tables.
// GAP: locale is not settable — NtSetDefaultLocale not wired.
i64 NtDoQueryDefaultLocale(arch::TrapFrame* f)
{
    const u64 user_lcid = f->rdx;
    if (user_lcid == 0)
        return kStatusInvalidParam;
    const u32 lcid = 0x0409u; // en-US
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_lcid), &lcid, sizeof(lcid)))
        return kStatusInvalidParam;
    return kStatusSuccess;
}

// NtQueryDefaultUILanguage(PLANGID DefaultUILanguageId). Same
// shape as the LCID variant; report 0x0409 (LANGIDFROMLCID of
// en-US).
// GAP: UI language is not settable — NtSetDefaultUILanguage not wired.
i64 NtDoQueryDefaultUILanguage(arch::TrapFrame* f)
{
    const u64 user_langid = f->rsi;
    if (user_langid == 0)
        return kStatusInvalidParam;
    const u16 langid = 0x0409u; // en-US
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_langid), &langid, sizeof(langid)))
        return kStatusInvalidParam;
    return kStatusSuccess;
}

// NtFlushInstructionCache(HANDLE Process, PVOID Addr, SIZE_T Len):
// x86_64 has coherent instruction caches across stores in the
// same address space, so a same-process flush is architecturally
// a no-op. Cross-process flushes would need IPI fan-out; v0
// doesn't ship cross-process JIT, so synthetic success is correct
// for the only callers we see.
i64 NtDoFlushInstructionCache(arch::TrapFrame* /*f*/)
{
    return kStatusSuccess;
}

// NtTestAlert(): drain a pending alert. v0 has no alertable-wait
// state machine, so there's nothing to drain — STATUS_SUCCESS
// matches the "no alert was pending" Windows behaviour.
// GAP: alertable waits not wired — once they land this should
// consume the alert flag and run any queued user-APC.
i64 NtDoTestAlert(arch::TrapFrame* /*f*/)
{
    return kStatusSuccess;
}

// Log an NT-translation entry so the boot log is grep-able.
void LogNtTranslation(u64 nt_nr, const char* target)
{
    arch::SerialWrite("[nt-translate] ");
    arch::SerialWriteHex(nt_nr);
    arch::SerialWrite(" -> ");
    arch::SerialWrite(target);
    arch::SerialWrite("\n");
}

} // namespace

// Public name-lookup helpers — the generated Linux + NT syscall
// tables compile in here, so any subsystem that wants to log a
// syscall by name comes through these single entry points.
const char* LinuxName(u64 nr)
{
    const auto* entry = ::duetos::subsystems::linux::LinuxSyscallLookup(nr);
    return (entry != nullptr) ? entry->name : nullptr;
}

const char* NtName(u64 nr)
{
    if (nr > 0xFFFF)
        return nullptr;
    const auto* entry = ::duetos::subsystems::win32::NtSyscallByNumber(u16(nr));
    return (entry != nullptr) ? entry->nt_name : nullptr;
}

const HitTable& NativeHitsRead()
{
    return g_native_hits;
}

Result NativeGapFill(arch::TrapFrame* frame)
{
    KLOG_TRACE_SCOPE("translate", "NativeGapFill");
    const u64 tsc_entry = ReadTsc();
    const u64 nr = frame->rax;
    Result r{false, 0};
    switch (nr)
    {
    case kNativeClockNs:
        LogTranslation("native", nr, "linux-self:NowNs");
        r = {true, NativeClockNs(frame)};
        break;
    case kNativeGetRandom:
        LogTranslation("native", nr, "synthetic:xorshift-from-rdtsc");
        r = {true, NativeGetRandom(frame)};
        break;
    case kNativeWin32Alloc:
        LogTranslation("native", nr, "win32:HeapAlloc");
        r = {true, NativeWin32Alloc(frame)};
        break;
    case kNativeWin32Free:
        LogTranslation("native", nr, "win32:HeapFree");
        r = {true, NativeWin32Free(frame)};
        break;
    default:
        if (ShouldLogMiss(g_native_miss_sampling, nr))
            LogMiss("native", frame, NativeName(nr));
        break;
    }
    if (r.handled)
        BumpHits(g_native_hits, nr);
    BumpOverhead(g_native_overhead, ReadTsc() - tsc_entry);
    return r;
}

// Translate an NT syscall invocation into a call on a Linux
// primitive. See translate.h for the ABI. NT-number lives in
// frame->rdi (SYS_NT_INVOKE convention); each handler re-reads
// rsi..r9 for its specific NT-ABI arguments.
Result NtTranslateToLinux(arch::TrapFrame* frame)
{
    KLOG_TRACE_SCOPE("translate", "NtTranslateToLinux");
    const u64 tsc_entry = ReadTsc();
    const u64 nt_nr = frame->rdi;
    Result r{false, 0};
    switch (nt_nr)
    {
    case kNtClose:
        LogNtTranslation(nt_nr, "linux:close");
        r = {true, NtDoClose(frame)};
        break;
    case kNtYieldExecution:
        LogNtTranslation(nt_nr, "linux:sched_yield");
        r = {true, NtDoYieldExecution(frame)};
        break;
    case kNtDelayExecution:
        LogNtTranslation(nt_nr, "linux:nanosleep");
        r = {true, NtDoDelayExecution(frame)};
        break;
    case kNtQueryPerformanceCounter:
        LogNtTranslation(nt_nr, "linux:clock_gettime");
        r = {true, NtDoQueryPerformanceCounter(frame)};
        break;
    case kNtGetCurrentProcessorNumber:
        LogNtTranslation(nt_nr, "synthetic:zero");
        r = {true, NtDoGetCurrentProcessorNumber(frame)};
        break;
    case kNtFlushBuffersFile:
        LogNtTranslation(nt_nr, "linux:fsync");
        r = {true, NtDoFlushBuffersFile(frame)};
        break;
    case kNtGetTickCount:
        LogNtTranslation(nt_nr, "linux:now-ns/ms");
        r = {true, NtDoGetTickCount(frame)};
        break;
    case kNtQuerySystemTime:
        LogNtTranslation(nt_nr, "linux:now-ns->filetime");
        r = {true, NtDoQuerySystemTime(frame)};
        break;
    case kNtSetInformationThread:
        LogNtTranslation(nt_nr, "synthetic:success-noop");
        r = {true, NtDoSetInformationThread(frame)};
        break;
    case kNtQueryDefaultLocale:
        LogNtTranslation(nt_nr, "synthetic:en-US-lcid");
        r = {true, NtDoQueryDefaultLocale(frame)};
        break;
    case kNtQueryDefaultUILanguage:
        LogNtTranslation(nt_nr, "synthetic:en-US-langid");
        r = {true, NtDoQueryDefaultUILanguage(frame)};
        break;
    case kNtFlushInstructionCache:
        LogNtTranslation(nt_nr, "synthetic:icache-coherent-x86");
        r = {true, NtDoFlushInstructionCache(frame)};
        break;
    case kNtTestAlert:
        LogNtTranslation(nt_nr, "synthetic:no-alert-pending");
        r = {true, NtDoTestAlert(frame)};
        break;
    case kNtTerminateThread:
        LogNtTranslation(nt_nr, "linux:exit");
        NtDoTerminateThread(frame); // [[noreturn]]
        break;
    case kNtTerminateProcess:
        LogNtTranslation(nt_nr, "linux:exit_group");
        NtDoTerminateProcess(frame); // [[noreturn]]
        break;
    default:
        // Nothing wired for this NT number — let the caller see
        // STATUS_NOT_IMPLEMENTED so the ntdll shim can bail
        // cleanly. Log once at the same sampling cadence as the
        // Linux-miss path.
        ++g_nt_miss_total;
        if (ShouldLogMiss(g_native_miss_sampling, nt_nr))
        {
            arch::SerialWrite("[nt-translate-miss] nt_nr=");
            arch::SerialWriteHex(nt_nr);
            arch::SerialWrite(" name=\"");
            const char* name = NtName(nt_nr);
            arch::SerialWrite(name ? name : "<unknown>");
            arch::SerialWrite("\"\n");
        }
        r = {false, kStatusNotImplemented};
        break;
    }
    if (r.handled)
        BumpOverhead(g_nt_overhead, ReadTsc() - tsc_entry);
    return r;
}

// Emit a one-shot summary of translator overhead. Called by the
// kheartbeat loop so the numbers roll into the normal telemetry
// cadence without a dedicated shell command. Format:
//   [translate-overhead] native calls=N total_c=C avg_c=A max_c=M
//   [translate-overhead] nt     calls=N total_c=C avg_c=A max_c=M
// Cycles are raw TSC deltas; on the QEMU host TSC runs at the
// CPU's nominal frequency (qemu reports a fixed rate) so dividing
// by that frequency yields nanoseconds. We emit raw cycles and
// let the reader do the conversion — the host kernel's dmesg can
// tell you the TSC Hz.
void TranslatorOverheadDump()
{
    arch::SerialWrite("[translate-overhead] native calls=");
    arch::SerialWriteHex(g_native_overhead.calls);
    arch::SerialWrite(" total_c=");
    arch::SerialWriteHex(g_native_overhead.cycles_total);
    if (g_native_overhead.calls > 0)
    {
        arch::SerialWrite(" avg_c=");
        arch::SerialWriteHex(g_native_overhead.cycles_total / g_native_overhead.calls);
    }
    arch::SerialWrite(" max_c=");
    arch::SerialWriteHex(g_native_overhead.cycles_max);
    arch::SerialWrite("\n");

    arch::SerialWrite("[translate-overhead] nt     calls=");
    arch::SerialWriteHex(g_nt_overhead.calls);
    arch::SerialWrite(" total_c=");
    arch::SerialWriteHex(g_nt_overhead.cycles_total);
    if (g_nt_overhead.calls > 0)
    {
        arch::SerialWrite(" avg_c=");
        arch::SerialWriteHex(g_nt_overhead.cycles_total / g_nt_overhead.calls);
    }
    arch::SerialWrite(" max_c=");
    arch::SerialWriteHex(g_nt_overhead.cycles_max);
    arch::SerialWrite(" miss_total=");
    arch::SerialWriteHex(g_nt_miss_total);
    arch::SerialWrite("\n");

    DumpSuppressedMissSummary("native", g_native_miss_sampling);
}

// One-shot, end-of-boot structured summary that CI smoke harnesses
// grep for. Single line, space-separated `key=hexvalue` pairs so
// `tools/qemu/run-fix-cycle.sh`-style consumers can `awk` against
// it without parsing the multi-line overhead dump. Keys are stable;
// adding new ones is backwards-compatible.
void TranslatorBootSummaryEmit()
{
    arch::SerialWrite("[smoke] translate_summary");
    arch::SerialWrite(" native_calls=");
    arch::SerialWriteHex(g_native_overhead.calls);
    arch::SerialWrite(" native_total_c=");
    arch::SerialWriteHex(g_native_overhead.cycles_total);
    arch::SerialWrite(" native_max_c=");
    arch::SerialWriteHex(g_native_overhead.cycles_max);
    arch::SerialWrite(" native_miss_emitted=");
    arch::SerialWriteHex(g_native_miss_sampling.emitted_total);
    arch::SerialWrite(" native_miss_suppressed=");
    arch::SerialWriteHex(g_native_miss_sampling.suppressed_total);
    arch::SerialWrite(" nt_calls=");
    arch::SerialWriteHex(g_nt_overhead.calls);
    arch::SerialWrite(" nt_total_c=");
    arch::SerialWriteHex(g_nt_overhead.cycles_total);
    arch::SerialWrite(" nt_max_c=");
    arch::SerialWriteHex(g_nt_overhead.cycles_max);
    arch::SerialWrite(" nt_miss_total=");
    arch::SerialWriteHex(g_nt_miss_total);
    arch::SerialWrite("\n");
}

} // namespace duetos::subsystems::translation
