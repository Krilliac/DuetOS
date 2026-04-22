#include "syscall.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/rtc.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/timer.h"
#include "../debug/breakpoints.h"
#include "../fs/vfs.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../mm/paging.h"
#include "../sched/sched.h"
#include "../subsystems/translation/translate.h"
#include "../subsystems/win32/heap.h"
#include "klog.h"
#include "process.h"
#include "ring3_smoke.h"

// Defined in exceptions.S (via `ISR_NOERR 128`) — the .global label for
// the int-0x80 stub. SyscallInit installs its address into the IDT with
// a DPL=3 gate, which is the only bit that makes the int legal from ring
// 3. The function itself has no C-callable signature; we take its
// address as an opaque u64.
extern "C" void isr_128();

namespace customos::core
{

namespace
{

constexpr u8 kSyscallVector = 0x80;

// Cap on the maximum bytes a single SYS_WRITE copies out of user
// memory. v0 keeps the kernel-side bounce buffer on-stack, so this
// can't grow without bound. 256 is comfortable for the first
// consumer (a "hello" print from the ring-3 smoke task) and leaves
// plenty of headroom on a 16 KiB kernel stack. Larger writes get
// truncated to this length and the returned byte count reflects
// the truncation — standard POSIX write() semantics.
constexpr u64 kSyscallWriteMax = 256;

// Cap on path length for SYS_STAT. Same rationale as kSyscallWriteMax:
// on-kernel-stack bounce buffer, no unbounded copy. 256 bytes is
// well past anything a sandboxed process should be naming in v0.
constexpr u64 kSyscallPathMax = 256;

// Pretty-printer for boot diagnostics — the Warn path for an
// unrecognised syscall number should be noisy enough to catch during
// bring-up but cheap enough to leave in release builds.
void ReportUnknownSyscall(u64 num, u64 rip)
{
    arch::SerialWrite("[sys] WARN unknown syscall num=");
    arch::SerialWriteHex(num);
    arch::SerialWrite(" rip=");
    arch::SerialWriteHex(rip);
    arch::SerialWrite("\n");
}

// Convert an RtcTime (Gregorian date + UTC time-of-day) to a
// Windows FILETIME — 100-nanosecond ticks since 1601-01-01
// 00:00:00 UTC. Pure arithmetic; no MSR / HPET reads.
//
// Algorithm: day-of-Gregorian computation by the classic "civil
// from days" family. We compute days since 1970-01-01 (Unix
// epoch), then add the fixed 1970→1601 offset (134 774 days =
// 369 years * 365 + 89 leap days between 1601..1969) to land
// at the Windows epoch.
u64 RtcToFileTime(const arch::RtcTime& t)
{
    // Leap years: divisible by 4, except those divisible by 100
    // unless also by 400.
    auto is_leap = [](u32 y) { return (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0); };
    constexpr u32 kDaysBeforeMonth[12] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

    // Days from 1970-01-01 to (t.year - 1, 12, 31).
    u64 days = 0;
    for (u32 y = 1970; y < t.year; ++y)
        days += is_leap(y) ? 366 : 365;
    const u32 m = (t.month >= 1 && t.month <= 12) ? (t.month - 1) : 0;
    days += kDaysBeforeMonth[m];
    if (m >= 2 && is_leap(t.year))
        days += 1;
    days += (t.day >= 1) ? (t.day - 1) : 0;

    // Shift the epoch from 1970-01-01 to 1601-01-01. The interval
    // 1601-01-01 .. 1970-01-01 is 369 years = 269 non-leap +
    // 100 leap days counted as 89 (century rule drops 3 of every
    // 4) = 134774 days.
    constexpr u64 k1970To1601Days = 134774;
    const u64 total_days = days + k1970To1601Days;

    const u64 seconds = total_days * 86400ULL + u64(t.hour) * 3600 + u64(t.minute) * 60 + u64(t.second);
    return seconds * 10'000'000ULL; // 100-ns ticks per second
}

// SYS_WRITE body. Copies up to `len` bytes from the user buffer,
// truncates to kSyscallWriteMax, and spits them straight at COM1.
// Only fd=1 (stdout) is recognised today — anything else is a
// caller error and returns -1 so the pattern is immediately
// auditable. Returns the actual byte count written (possibly
// truncated) or -1 on failure.
//
// Cap check: fd=1 requires kCapSerialConsole. A sandboxed process
// with an empty cap set sees -1 and nothing reaches the kernel
// serial console. The denial is logged so it's trivially
// auditable — without the log we'd be silently swallowing a
// sandbox policy hit.
i64 DoWrite(u64 fd, const void* user_buf, u64 len)
{
    if (fd != 1)
    {
        return -1;
    }

    Process* proc = CurrentProcess();
    if (proc == nullptr || !CapSetHas(proc->caps, kCapSerialConsole))
    {
        // Emit a single-line denial record. Machine-readable format
        // so a future audit tool can grep boot logs: "[sys] denied
        // syscall=N pid=P cap=NAME". pid=0 indicates a caller with
        // no Process (kernel bug — kernel threads shouldn't be
        // issuing SYS_WRITE via the syscall gate).
        const u64 pid = (proc != nullptr) ? proc->pid : 0;
        RecordSandboxDenial(kCapSerialConsole);
        // Rate-limit the log line so a hostile burst doesn't
        // flood COM1. Denial is still counted every time — only
        // the visible print is gated — so the threshold kill
        // still fires at the right count.
        if (proc != nullptr && ShouldLogDenial(proc->sandbox_denials))
        {
            arch::SerialWrite("[sys] denied syscall=SYS_WRITE pid=");
            arch::SerialWriteHex(pid);
            arch::SerialWrite(" cap=");
            arch::SerialWrite(CapName(kCapSerialConsole));
            arch::SerialWrite(" denial_idx=");
            arch::SerialWriteHex(proc->sandbox_denials);
            arch::SerialWrite("\n");
        }
        return -1;
    }

    const u64 to_copy = (len > kSyscallWriteMax) ? kSyscallWriteMax : len;
    if (to_copy == 0)
    {
        return 0;
    }

    // Kernel-stack bounce buffer. The CopyFromUser gate ensures the
    // user pointer is in-range + SMAP-allowed; we never touch the
    // raw user address after the copy, which closes the "TOCTOU
    // between validation and read" class of bugs on its own.
    u8 kbuf[kSyscallWriteMax];
    if (!mm::CopyFromUser(kbuf, user_buf, to_copy))
    {
        return -1;
    }

    // Drive COM1 one byte at a time. SerialWrite() is null-terminated,
    // which is wrong for an arbitrary byte stream — use the per-char
    // helper via a tiny 2-char buffer so any \0 inside the user
    // payload gets forwarded faithfully as a literal 0.
    for (u64 i = 0; i < to_copy; ++i)
    {
        const char two[2] = {static_cast<char>(kbuf[i]), '\0'};
        arch::SerialWrite(two);
    }
    return static_cast<i64>(to_copy);
}

} // namespace

void SyscallInit()
{
    arch::IdtSetUserGate(kSyscallVector, reinterpret_cast<u64>(&isr_128));
    Log(LogLevel::Info, "sys", "syscall gate online at int 0x80");
}

void SyscallDispatch(arch::TrapFrame* frame)
{
    const u64 num = frame->rax;
    switch (num)
    {
    case SYS_EXIT:
    {
        const u64 code = frame->rdi;
        LogWithValue(LogLevel::Info, "sys", "exit rc", code);
        // SchedExit is [[noreturn]] — it marks the current task Dead,
        // wakes the reaper, and Schedule()s away forever. The trap
        // frame on this task's kernel stack becomes orphaned and
        // will be KFree'd by the reaper along with the stack itself.
        sched::SchedExit();
    }

    case SYS_GETPID:
    {
        // First syscall that actually exercises the return-value
        // half of the ABI: the dispatcher writes frame->rax and
        // isr_common's pop-all + iretq delivers it to ring 3.
        frame->rax = sched::CurrentTaskId();
        return;
    }

    case SYS_GETPROCID:
    {
        // Process id, as distinct from task (scheduler) id. See
        // the SYS_GETPROCID comment in syscall.h for why the two
        // live in different counters. No caps needed — it's
        // the caller's own pid.
        Process* proc = CurrentProcess();
        frame->rax = (proc != nullptr) ? proc->pid : 0;
        return;
    }

    case SYS_GETLASTERROR:
    {
        // Read Process.win32_last_error. Unprivileged — the
        // slot belongs to the caller. Returns 0 if no process
        // (shouldn't happen from ring 3, but defensive).
        Process* proc = CurrentProcess();
        frame->rax = (proc != nullptr) ? u64(proc->win32_last_error) : 0;
        return;
    }

    case SYS_SETLASTERROR:
    {
        // Write rdi (low 32 bits) into Process.win32_last_error.
        // No return value (Win32 SetLastError is void). Still
        // populate rax so the stub's epilogue doesn't leak the
        // syscall number; use the PREVIOUS error so callers
        // that want a read-modify-write can get it in one
        // trip if we ever expose that pattern.
        Process* proc = CurrentProcess();
        if (proc != nullptr)
        {
            frame->rax = u64(proc->win32_last_error);
            proc->win32_last_error = u32(frame->rdi & 0xFFFFFFFFULL);
        }
        else
        {
            frame->rax = 0;
        }
        return;
    }

    case SYS_HEAP_ALLOC:
    {
        // rdi = size in bytes. Returns user VA or 0 on OOM.
        // See kernel/subsystems/win32/heap.cpp for the first-fit
        // allocator. Unprivileged — every Win32 process gets
        // its own heap mapped during PeLoad; the syscall only
        // reads/writes that region through the process's own
        // frames.
        Process* proc = CurrentProcess();
        frame->rax = (proc != nullptr) ? win32::Win32HeapAlloc(proc, frame->rdi) : 0;
        return;
    }

    case SYS_HEAP_FREE:
    {
        // rdi = user ptr (or 0 for no-op). Returns 0.
        Process* proc = CurrentProcess();
        if (proc != nullptr)
            win32::Win32HeapFree(proc, frame->rdi);
        frame->rax = 0;
        return;
    }

    case SYS_HEAP_SIZE:
    {
        // rdi = user ptr. Returns payload capacity in bytes
        // (block header size - 16). 0 for null / out-of-range.
        Process* proc = CurrentProcess();
        frame->rax = (proc != nullptr) ? win32::Win32HeapSize(proc, frame->rdi) : 0;
        return;
    }

    case SYS_HEAP_REALLOC:
    {
        // rdi = existing user ptr (or 0), rsi = new size.
        // Returns new user VA or 0 on failure (see
        // Win32HeapRealloc doc comment for full semantics).
        Process* proc = CurrentProcess();
        frame->rax = (proc != nullptr) ? win32::Win32HeapRealloc(proc, frame->rdi, frame->rsi) : 0;
        return;
    }

    case SYS_PERF_COUNTER:
    {
        // No args. Return the kernel tick counter —
        // monotonically increasing u64 at 100 Hz. Used by
        // the Win32 QueryPerformanceCounter + GetTickCount
        // stubs.
        frame->rax = arch::TimerTicks();
        return;
    }

    case SYS_NOW_NS:
    {
        // No args. Return HPET counter × period_fs / 1'000'000
        // = nanoseconds since boot. HPET is in use as the high-
        // res clocksource; the LAPIC tick counter is still the
        // scheduler's time-slice driver.
        const u64 counter = arch::HpetReadCounter();
        const u64 period_fs = arch::HpetPeriodFemtoseconds();
        // fs / 1e6 == ns. Overflow window: counter × period_fs
        // fits in u64 for any realistic uptime — 64-bit counter
        // at 14.3 MHz with 70k fs period saturates after ~10^16
        // ticks = ~22 billion years. Safe.
        frame->rax = (counter * period_fs) / 1'000'000ULL;
        return;
    }

    case SYS_GETTIME_FT:
    {
        // No args. Sample the CMOS RTC and return the current
        // wall-clock as a Windows FILETIME (100 ns ticks since
        // 1601-01-01 00:00:00 UTC) in rax.
        arch::RtcTime t = {};
        arch::RtcRead(&t);
        frame->rax = RtcToFileTime(t);
        return;
    }

    case SYS_WIN32_MISS_LOG:
    {
        // rdi = IAT slot VA that the miss-logger trampoline
        // decoded from its caller's `call [rip+disp32]`.
        // Search CurrentProcess()->win32_iat_misses; if found,
        // emit a [win32-miss] line with the function name.
        const u64 slot_va = frame->rdi;
        Process* proc = CurrentProcess();
        const char* name = nullptr;
        if (proc != nullptr)
        {
            for (u64 i = 0; i < proc->win32_iat_miss_count; ++i)
            {
                if (proc->win32_iat_misses[i].slot_va == slot_va)
                {
                    name = proc->win32_iat_misses[i].name;
                    break;
                }
            }
        }
        arch::SerialWrite("[win32-miss] slot=");
        arch::SerialWriteHex(slot_va);
        arch::SerialWrite(" called fn=\"");
        arch::SerialWrite(name ? name : "<unmapped>");
        arch::SerialWrite("\"\n");
        // Trampoline zeroes rax itself; set here too for
        // clarity (we overwrite rax anyway via the syscall
        // return value mechanism).
        frame->rax = 0;
        return;
    }

    case SYS_WRITE:
    {
        // rdi = fd, rsi = user buf, rdx = len. DoWrite validates
        // the pointer + length via mm::CopyFromUser, SMAP-gates
        // the actual read, and returns the (possibly truncated)
        // byte count or -1 on failure.
        const i64 rc = DoWrite(frame->rdi, reinterpret_cast<const void*>(frame->rsi), frame->rdx);
        frame->rax = static_cast<u64>(rc);
        return;
    }

    case SYS_YIELD:
    {
        // Cooperative-yield from ring 3. The kernel-side SchedYield
        // briefly cli / Schedule / sti; by the time we return here,
        // either the same task was picked (no-op from ring 3's
        // perspective) or another task ran and eventually switched
        // us back in. Returns 0 — reserved for an "I was preempted"
        // boolean later if any consumer cares.
        sched::SchedYield();
        frame->rax = 0;
        return;
    }

    case SYS_FILE_OPEN:
    {
        // Path-based open backed by VfsLookup. Returns a Win32
        // pseudo-handle (kWin32HandleBase + slot_idx) on success
        // or u64(-1) on any failure. Cap-gated on kCapFsRead;
        // the per-handle cursor lives on the Process struct.
        Process* proc = CurrentProcess();
        if (proc == nullptr || !CapSetHas(proc->caps, kCapFsRead))
        {
            const u64 pid = (proc != nullptr) ? proc->pid : 0;
            RecordSandboxDenial(kCapFsRead);
            if (proc != nullptr && ShouldLogDenial(proc->sandbox_denials))
            {
                arch::SerialWrite("[sys] denied syscall=SYS_FILE_OPEN pid=");
                arch::SerialWriteHex(pid);
                arch::SerialWrite(" cap=");
                arch::SerialWrite(CapName(kCapFsRead));
                arch::SerialWrite(" denial_idx=");
                arch::SerialWriteHex(proc->sandbox_denials);
                arch::SerialWrite("\n");
            }
            frame->rax = static_cast<u64>(-1);
            return;
        }

        u64 path_cap = frame->rsi;
        if (path_cap >= kSyscallPathMax)
            path_cap = kSyscallPathMax - 1;
        if (path_cap == 0)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        char kpath[kSyscallPathMax];
        if (!mm::CopyFromUser(kpath, reinterpret_cast<const void*>(frame->rdi), path_cap))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        kpath[path_cap] = '\0';
        kpath[kSyscallPathMax - 1] = '\0';

        const fs::RamfsNode* n = fs::VfsLookup(proc->root, kpath, kSyscallPathMax);
        if (n == nullptr || n->type != fs::RamfsNodeType::kFile)
        {
            arch::SerialWrite("[sys] file_open miss pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite(" path=\"");
            arch::SerialWrite(kpath);
            arch::SerialWrite("\"\n");
            frame->rax = static_cast<u64>(-1);
            return;
        }

        // Find a free slot.
        u64 slot = Process::kWin32HandleCap;
        for (u64 i = 0; i < Process::kWin32HandleCap; ++i)
        {
            if (proc->win32_handles[i].node == nullptr)
            {
                slot = i;
                break;
            }
        }
        if (slot == Process::kWin32HandleCap)
        {
            arch::SerialWrite("[sys] file_open out-of-handles pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite("\n");
            frame->rax = static_cast<u64>(-1);
            return;
        }
        proc->win32_handles[slot].node = n;
        proc->win32_handles[slot].cursor = 0;
        const u64 handle = Process::kWin32HandleBase + slot;
        arch::SerialWrite("[sys] file_open ok pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" path=\"");
        arch::SerialWrite(kpath);
        arch::SerialWrite("\" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite(" size=");
        arch::SerialWriteHex(n->file_size);
        arch::SerialWrite("\n");
        frame->rax = handle;
        return;
    }

    case SYS_FILE_READ:
    {
        // Read up to rdx bytes from the handle into rsi. Returns
        // bytes copied (0 at EOF) or -1 on bad handle / bad user
        // ptr. Cursor advances by the returned count.
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 handle = frame->rdi;
        if (handle < Process::kWin32HandleBase || handle >= Process::kWin32HandleBase + Process::kWin32HandleCap)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 slot = handle - Process::kWin32HandleBase;
        Process::Win32FileHandle& h = proc->win32_handles[slot];
        if (h.node == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 cap_bytes = frame->rdx;
        if (cap_bytes == 0)
        {
            frame->rax = 0;
            return;
        }
        if (h.cursor >= h.node->file_size)
        {
            frame->rax = 0; // EOF
            return;
        }
        const u64 remaining = h.node->file_size - h.cursor;
        const u64 to_copy = (cap_bytes < remaining) ? cap_bytes : remaining;
        if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), h.node->file_bytes + h.cursor, to_copy))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        h.cursor += to_copy;
        frame->rax = to_copy;
        return;
    }

    case SYS_FILE_CLOSE:
    {
        // Generic Win32 CloseHandle. Dispatches by handle range:
        // file table (0x100..0x10F) or mutex table (0x200..0x207).
        // Out-of-range handles are a documented no-op per the
        // Win32 contract. An owned mutex closed by its owner is
        // implicitly released first; closing one we DON'T own is
        // also accepted (Win32's "abandoned mutex" semantics —
        // the next waiter would see WAIT_ABANDONED on real
        // Windows; v0 just frees the slot).
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = 0;
            return;
        }
        const u64 handle = frame->rdi;
        if (handle >= Process::kWin32HandleBase && handle < Process::kWin32HandleBase + Process::kWin32HandleCap)
        {
            const u64 slot = handle - Process::kWin32HandleBase;
            proc->win32_handles[slot].node = nullptr;
            proc->win32_handles[slot].cursor = 0;
        }
        else if (handle >= Process::kWin32MutexBase && handle < Process::kWin32MutexBase + Process::kWin32MutexCap)
        {
            const u64 slot = handle - Process::kWin32MutexBase;
            arch::Cli();
            Process::Win32MutexHandle& m = proc->win32_mutexes[slot];
            // If owned, treat as abandoned: clear owner + wake one
            // waiter so the queue makes progress.
            sched::Task* next = sched::WaitQueueWakeOne(&m.waiters);
            m.owner = next; // nullptr if no waiters; else hand off
            m.recursion = (next != nullptr) ? 1 : 0;
            m.in_use = false;
            arch::Sti();
        }
        else if (handle >= Process::kWin32EventBase && handle < Process::kWin32EventBase + Process::kWin32EventCap)
        {
            const u64 slot = handle - Process::kWin32EventBase;
            arch::Cli();
            Process::Win32EventHandle& e = proc->win32_events[slot];
            // Wake all waiters (they'll see in_use = false and
            // return WAIT_ABANDONED-style from their wait; we
            // just wake them so they don't block forever).
            (void)sched::WaitQueueWakeAll(&e.waiters);
            e.in_use = false;
            e.signaled = false;
            arch::Sti();
        }
        frame->rax = 0;
        return;
    }

    case SYS_MUTEX_CREATE:
    {
        // Allocate a mutex slot; record the calling task as the
        // initial owner if rdi==1 (Win32 bInitialOwner).
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        u64 slot = Process::kWin32MutexCap;
        arch::Cli();
        for (u64 i = 0; i < Process::kWin32MutexCap; ++i)
        {
            if (!proc->win32_mutexes[i].in_use)
            {
                slot = i;
                break;
            }
        }
        if (slot == Process::kWin32MutexCap)
        {
            arch::Sti();
            arch::SerialWrite("[sys] mutex_create out-of-slots pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite("\n");
            frame->rax = static_cast<u64>(-1);
            return;
        }
        Process::Win32MutexHandle& m = proc->win32_mutexes[slot];
        m.in_use = true;
        m.waiters.head = nullptr;
        m.waiters.tail = nullptr;
        if (frame->rdi != 0)
        {
            m.owner = sched::CurrentTask();
            m.recursion = 1;
        }
        else
        {
            m.owner = nullptr;
            m.recursion = 0;
        }
        arch::Sti();
        const u64 handle = Process::kWin32MutexBase + slot;
        arch::SerialWrite("[sys] mutex_create ok pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite(" initial_owner=");
        arch::SerialWriteHex(frame->rdi);
        arch::SerialWrite("\n");
        frame->rax = handle;
        return;
    }

    case SYS_MUTEX_WAIT:
    {
        // Acquire-or-block-with-timeout. Recursive owner check
        // first; otherwise WaitQueueBlockTimeout. ReleaseMutex's
        // hand-off sets m.owner = us before WaitQueueWakeOne, so
        // a successful wake means the lock is already ours.
        constexpr u64 kInfiniteMs = 0xFFFFFFFFu;
        constexpr u64 kWaitObject0 = 0;
        constexpr u64 kWaitTimeout = 0x102;
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 handle = frame->rdi;
        if (handle < Process::kWin32MutexBase || handle >= Process::kWin32MutexBase + Process::kWin32MutexCap)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 slot = handle - Process::kWin32MutexBase;
        Process::Win32MutexHandle& m = proc->win32_mutexes[slot];
        if (!m.in_use)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 timeout_ms = frame->rsi & 0xFFFFFFFFu;
        sched::Task* me = sched::CurrentTask();
        arch::Cli();
        if (m.owner == nullptr)
        {
            // Uncontended.
            m.owner = me;
            m.recursion = 1;
            arch::Sti();
            frame->rax = kWaitObject0;
            return;
        }
        if (m.owner == me)
        {
            // Recursive acquire by current owner.
            m.recursion += 1;
            arch::Sti();
            frame->rax = kWaitObject0;
            return;
        }
        // Contended. Block on the waitqueue. Hand-off in
        // SYS_MUTEX_RELEASE sets m.owner = us before waking, so
        // an explicit wake means the lock is ours.
        if (timeout_ms == kInfiniteMs)
        {
            sched::WaitQueueBlock(&m.waiters);
            arch::Sti();
            frame->rax = kWaitObject0;
            return;
        }
        // Convert ms -> ticks (round up; 100 Hz = 10 ms grain).
        constexpr u64 kMsPerTick = 10;
        const u64 ticks = (timeout_ms + (kMsPerTick - 1)) / kMsPerTick;
        const bool got = sched::WaitQueueBlockTimeout(&m.waiters, ticks);
        arch::Sti();
        frame->rax = got ? kWaitObject0 : kWaitTimeout;
        return;
    }

    case SYS_MUTEX_RELEASE:
    {
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 handle = frame->rdi;
        if (handle < Process::kWin32MutexBase || handle >= Process::kWin32MutexBase + Process::kWin32MutexCap)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 slot = handle - Process::kWin32MutexBase;
        Process::Win32MutexHandle& m = proc->win32_mutexes[slot];
        sched::Task* me = sched::CurrentTask();
        arch::Cli();
        if (!m.in_use || m.owner != me)
        {
            arch::Sti();
            frame->rax = static_cast<u64>(-1);
            return;
        }
        m.recursion -= 1;
        if (m.recursion > 0)
        {
            arch::Sti();
            frame->rax = 0;
            return;
        }
        // Final release. Hand off to the longest-waiting blocker
        // by setting owner BEFORE waking so the woken task sees
        // the lock as already theirs.
        sched::Task* next = sched::WaitQueueWakeOne(&m.waiters);
        m.owner = next;
        m.recursion = (next != nullptr) ? 1 : 0;
        arch::Sti();
        frame->rax = 0;
        return;
    }

    case SYS_EVENT_CREATE:
    {
        // Allocate an event slot. rdi = bManualReset, rsi = bInitialState.
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        u64 slot = Process::kWin32EventCap;
        arch::Cli();
        for (u64 i = 0; i < Process::kWin32EventCap; ++i)
        {
            if (!proc->win32_events[i].in_use)
            {
                slot = i;
                break;
            }
        }
        if (slot == Process::kWin32EventCap)
        {
            arch::Sti();
            frame->rax = static_cast<u64>(-1);
            return;
        }
        Process::Win32EventHandle& e = proc->win32_events[slot];
        e.in_use = true;
        e.manual_reset = (frame->rdi != 0);
        e.signaled = (frame->rsi != 0);
        e.waiters.head = nullptr;
        e.waiters.tail = nullptr;
        arch::Sti();
        const u64 handle = Process::kWin32EventBase + slot;
        arch::SerialWrite("[sys] event_create ok pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" handle=");
        arch::SerialWriteHex(handle);
        arch::SerialWrite(" manual=");
        arch::SerialWriteHex(e.manual_reset ? 1 : 0);
        arch::SerialWrite(" signaled=");
        arch::SerialWriteHex(e.signaled ? 1 : 0);
        arch::SerialWrite("\n");
        frame->rax = handle;
        return;
    }

    case SYS_EVENT_SET:
    {
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 handle = frame->rdi;
        if (handle < Process::kWin32EventBase || handle >= Process::kWin32EventBase + Process::kWin32EventCap)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        Process::Win32EventHandle& e = proc->win32_events[handle - Process::kWin32EventBase];
        arch::Cli();
        if (!e.in_use)
        {
            arch::Sti();
            frame->rax = static_cast<u64>(-1);
            return;
        }
        e.signaled = true;
        if (e.manual_reset)
        {
            // Manual: wake ALL waiters; signal stays set.
            (void)sched::WaitQueueWakeAll(&e.waiters);
        }
        else
        {
            // Auto: wake ONE; if woken, auto-clear signal.
            sched::Task* next = sched::WaitQueueWakeOne(&e.waiters);
            if (next != nullptr)
                e.signaled = false;
        }
        arch::Sti();
        frame->rax = 0;
        return;
    }

    case SYS_EVENT_RESET:
    {
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 handle = frame->rdi;
        if (handle < Process::kWin32EventBase || handle >= Process::kWin32EventBase + Process::kWin32EventCap)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        Process::Win32EventHandle& e = proc->win32_events[handle - Process::kWin32EventBase];
        arch::Cli();
        if (e.in_use)
            e.signaled = false;
        arch::Sti();
        frame->rax = e.in_use ? 0 : static_cast<u64>(-1);
        return;
    }

    case SYS_EVENT_WAIT:
    {
        constexpr u64 kInfiniteMs = 0xFFFFFFFFu;
        constexpr u64 kWaitObject0 = 0;
        constexpr u64 kWaitTimeout = 0x102;
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 handle = frame->rdi;
        if (handle < Process::kWin32EventBase || handle >= Process::kWin32EventBase + Process::kWin32EventCap)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        Process::Win32EventHandle& e = proc->win32_events[handle - Process::kWin32EventBase];
        arch::Cli();
        if (!e.in_use)
        {
            arch::Sti();
            frame->rax = static_cast<u64>(-1);
            return;
        }
        if (e.signaled)
        {
            // Already signaled. Auto-reset events clear the
            // signal for us; manual-reset events keep it.
            if (!e.manual_reset)
                e.signaled = false;
            arch::Sti();
            frame->rax = kWaitObject0;
            return;
        }
        // Not signaled — block.
        const u64 timeout_ms = frame->rsi & 0xFFFFFFFFu;
        if (timeout_ms == kInfiniteMs)
        {
            sched::WaitQueueBlock(&e.waiters);
            // On wake, SYS_EVENT_SET has already cleared the
            // signal for auto-reset events; manual-reset leaves
            // it set so subsequent waits fall through.
            arch::Sti();
            frame->rax = kWaitObject0;
            return;
        }
        constexpr u64 kMsPerTick = 10;
        const u64 ticks = (timeout_ms + (kMsPerTick - 1)) / kMsPerTick;
        const bool got = sched::WaitQueueBlockTimeout(&e.waiters, ticks);
        arch::Sti();
        frame->rax = got ? kWaitObject0 : kWaitTimeout;
        return;
    }

    case SYS_TLS_ALLOC:
    {
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        arch::Cli();
        // Find the lowest clear bit in tls_slot_in_use.
        u64 slot = Process::kWin32TlsCap;
        for (u64 i = 0; i < Process::kWin32TlsCap; ++i)
        {
            if ((proc->tls_slot_in_use & (1ULL << i)) == 0)
            {
                slot = i;
                break;
            }
        }
        if (slot == Process::kWin32TlsCap)
        {
            arch::Sti();
            frame->rax = static_cast<u64>(-1);
            return;
        }
        proc->tls_slot_in_use |= (1ULL << slot);
        proc->tls_slot_value[slot] = 0; // TlsAlloc docs: initial value is NULL
        arch::Sti();
        frame->rax = slot;
        return;
    }

    case SYS_TLS_FREE:
    {
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 idx = frame->rdi;
        if (idx >= Process::kWin32TlsCap)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        arch::Cli();
        if ((proc->tls_slot_in_use & (1ULL << idx)) == 0)
        {
            arch::Sti();
            frame->rax = static_cast<u64>(-1);
            return;
        }
        proc->tls_slot_in_use &= ~(1ULL << idx);
        proc->tls_slot_value[idx] = 0;
        arch::Sti();
        frame->rax = 0;
        return;
    }

    case SYS_TLS_GET:
    {
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = 0;
            return;
        }
        const u64 idx = frame->rdi;
        if (idx >= Process::kWin32TlsCap)
        {
            frame->rax = 0;
            return;
        }
        // Win32 TlsGetValue returns 0 for unallocated slots too,
        // so no in-use check; just return the stored value.
        frame->rax = proc->tls_slot_value[idx];
        return;
    }

    case SYS_TLS_SET:
    {
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 idx = frame->rdi;
        if (idx >= Process::kWin32TlsCap)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        proc->tls_slot_value[idx] = frame->rsi;
        frame->rax = 0;
        return;
    }

    case SYS_BP_INSTALL:
    {
        // rdi = va, rsi = BpKind (1=exec, 2=write, 3=read/write),
        // rdx = length (1/2/4/8). Returns bp_id > 0 on success,
        // u64(-1) on any rejection (cap, bad args, no slot).
        Process* proc = CurrentProcess();
        if (proc == nullptr || !CapSetHas(proc->caps, kCapDebug))
        {
            const u64 pid = (proc != nullptr) ? proc->pid : 0;
            RecordSandboxDenial(kCapDebug);
            if (proc != nullptr && ShouldLogDenial(proc->sandbox_denials))
            {
                arch::SerialWrite("[sys] denied syscall=SYS_BP_INSTALL pid=");
                arch::SerialWriteHex(pid);
                arch::SerialWrite(" cap=");
                arch::SerialWrite(CapName(kCapDebug));
                arch::SerialWrite("\n");
            }
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 va = frame->rdi;
        const u64 kind_u = frame->rsi;
        const u64 len_u = frame->rdx;
        debug::BpKind kind = debug::BpKind::HwExecute;
        switch (kind_u)
        {
        case 1:
            kind = debug::BpKind::HwExecute;
            break;
        case 2:
            kind = debug::BpKind::HwWrite;
            break;
        case 3:
            kind = debug::BpKind::HwReadWrite;
            break;
        default:
            frame->rax = static_cast<u64>(-1);
            return;
        }
        debug::BpLen len = debug::BpLen::One;
        switch (len_u)
        {
        case 1:
            len = debug::BpLen::One;
            break;
        case 2:
            len = debug::BpLen::Two;
            break;
        case 4:
            len = debug::BpLen::Four;
            break;
        case 8:
            len = debug::BpLen::Eight;
            break;
        default:
            frame->rax = static_cast<u64>(-1);
            return;
        }
        debug::BpError err = debug::BpError::None;
        const debug::BreakpointId id = debug::BpInstallHardware(va, kind, len, proc->pid, &err);
        if (err != debug::BpError::None || id.value == 0)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        frame->rax = static_cast<u64>(id.value);
        return;
    }

    case SYS_BP_REMOVE:
    {
        // rdi = bp_id. Returns 0 on success, u64(-1) on unknown
        // id or cross-owner attempt.
        Process* proc = CurrentProcess();
        if (proc == nullptr || !CapSetHas(proc->caps, kCapDebug))
        {
            const u64 pid = (proc != nullptr) ? proc->pid : 0;
            RecordSandboxDenial(kCapDebug);
            if (proc != nullptr && ShouldLogDenial(proc->sandbox_denials))
            {
                arch::SerialWrite("[sys] denied syscall=SYS_BP_REMOVE pid=");
                arch::SerialWriteHex(pid);
                arch::SerialWrite(" cap=");
                arch::SerialWrite(CapName(kCapDebug));
                arch::SerialWrite("\n");
            }
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const debug::BreakpointId id = {static_cast<u32>(frame->rdi)};
        const debug::BpError err = debug::BpRemove(id, proc->pid);
        frame->rax = (err == debug::BpError::None) ? 0ULL : static_cast<u64>(-1);
        return;
    }

    case SYS_VMAP:
    {
        // Bump-arena VirtualAlloc. Rounds size up to pages,
        // allocates + maps fresh frames, bumps the cursor.
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = 0;
            return;
        }
        const u64 bytes = frame->rdi;
        if (bytes == 0)
        {
            frame->rax = 0;
            return;
        }
        const u64 pages = (bytes + mm::kPageSize - 1) / mm::kPageSize;
        if (pages == 0 || proc->vmap_pages_used + pages > Process::kWin32VmapCapPages)
        {
            arch::SerialWrite("[sys] vmap oom pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite(" bytes=");
            arch::SerialWriteHex(bytes);
            arch::SerialWrite(" pages=");
            arch::SerialWriteHex(pages);
            arch::SerialWrite(" used=");
            arch::SerialWriteHex(proc->vmap_pages_used);
            arch::SerialWrite("\n");
            frame->rax = 0;
            return;
        }
        const u64 base = proc->vmap_base + proc->vmap_pages_used * mm::kPageSize;
        for (u64 i = 0; i < pages; ++i)
        {
            const mm::PhysAddr f = mm::AllocateFrame();
            if (f == mm::kNullFrame)
            {
                // OOM partway through — frames already mapped
                // stay mapped but their VA is unreachable to
                // the caller since we bail here. Bump cursor
                // anyway so the stranded VAs are never reused
                // (simpler than unwinding; v0 accepts the leak).
                proc->vmap_pages_used += i;
                arch::SerialWrite("[sys] vmap partial-oom pid=");
                arch::SerialWriteHex(proc->pid);
                arch::SerialWrite(" mapped=");
                arch::SerialWriteHex(i);
                arch::SerialWrite("/");
                arch::SerialWriteHex(pages);
                arch::SerialWrite("\n");
                frame->rax = 0;
                return;
            }
            mm::AddressSpaceMapUserPage(proc->as, base + i * mm::kPageSize, f,
                                        mm::kPagePresent | mm::kPageUser | mm::kPageWritable | mm::kPageNoExecute);
        }
        proc->vmap_pages_used += pages;
        arch::SerialWrite("[sys] vmap ok pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" va=");
        arch::SerialWriteHex(base);
        arch::SerialWrite(" pages=");
        arch::SerialWriteHex(pages);
        arch::SerialWrite("\n");
        frame->rax = base;
        return;
    }

    case SYS_VUNMAP:
    {
        // v0: no-op with a range-validity check. A bump-only
        // arena can't free individual regions without turning
        // into a real allocator, so VirtualFree is documented
        // as a leak. The check still catches obvious caller
        // bugs (passing a pointer that was never VirtualAlloc'd).
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 va = frame->rdi;
        const u64 arena_end = proc->vmap_base + Process::kWin32VmapCapPages * mm::kPageSize;
        if (va < proc->vmap_base || va >= arena_end)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        frame->rax = 0;
        return;
    }

    case SYS_FILE_SEEK:
    {
        // SET / CUR / END seeking with clamp to [0, file_size].
        // Returns the new cursor or -1 on bad handle.
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 handle = frame->rdi;
        if (handle < Process::kWin32HandleBase || handle >= Process::kWin32HandleBase + Process::kWin32HandleCap)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 slot = handle - Process::kWin32HandleBase;
        Process::Win32FileHandle& h = proc->win32_handles[slot];
        if (h.node == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const i64 offset = static_cast<i64>(frame->rsi);
        const u64 whence = frame->rdx;
        i64 base;
        switch (whence)
        {
        case 0:
            base = 0;
            break;
        case 1:
            base = static_cast<i64>(h.cursor);
            break;
        case 2:
            base = static_cast<i64>(h.node->file_size);
            break;
        default:
            frame->rax = static_cast<u64>(-1);
            return;
        }
        i64 newpos = base + offset;
        if (newpos < 0)
            newpos = 0;
        if (static_cast<u64>(newpos) > h.node->file_size)
            newpos = static_cast<i64>(h.node->file_size);
        h.cursor = static_cast<u64>(newpos);
        frame->rax = h.cursor;
        return;
    }

    case SYS_FILE_FSTAT:
    {
        // Non-destructive size query for an open Win32 handle.
        // GetFileSizeEx maps here directly. Distinct from
        // SEEK_END so the read cursor isn't perturbed.
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 handle = frame->rdi;
        if (handle < Process::kWin32HandleBase || handle >= Process::kWin32HandleBase + Process::kWin32HandleCap)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 slot = handle - Process::kWin32HandleBase;
        const Process::Win32FileHandle& h = proc->win32_handles[slot];
        if (h.node == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 size = h.node->file_size;
        if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), &size, sizeof(size)))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        frame->rax = 0;
        return;
    }

    case SYS_SLEEP_MS:
    {
        // rdi = ms. ms == 0 -> equivalent to SchedYield. Otherwise
        // convert to ticks (round up so a sub-tick request still
        // sleeps at least one tick — Sleep is "at least", never
        // "at most") and call SchedSleepTicks. Caller wakes when
        // the timer has advanced past the deadline; spurious
        // early wakes are not a thing in v0.
        const u64 ms = frame->rdi;
        if (ms == 0)
        {
            sched::SchedYield();
        }
        else
        {
            // 100 Hz tick = 10 ms per tick. Round up: (ms + 9) / 10.
            constexpr u64 kMsPerTick = 10;
            const u64 ticks = (ms + (kMsPerTick - 1)) / kMsPerTick;
            sched::SchedSleepTicks(ticks);
        }
        frame->rax = 0;
        return;
    }

    case SYS_READ:
    {
        // rdi = user pointer to NUL-terminated path.
        // rsi = user pointer to destination buffer.
        // rdx = buffer capacity in bytes.
        // Returns bytes copied on success, -1 on any failure.
        //
        // Same cap + jail composition as SYS_STAT: kCapFsRead gates
        // the call, Process::root bounds what can be named. The
        // leaf-node check also rejects reading a directory —
        // "read a dir entry by entry" is a future getdents-style
        // syscall.
        Process* proc = CurrentProcess();
        if (proc == nullptr || !CapSetHas(proc->caps, kCapFsRead))
        {
            const u64 pid = (proc != nullptr) ? proc->pid : 0;
            RecordSandboxDenial(kCapFsRead);
            if (proc != nullptr && ShouldLogDenial(proc->sandbox_denials))
            {
                arch::SerialWrite("[sys] denied syscall=SYS_READ pid=");
                arch::SerialWriteHex(pid);
                arch::SerialWrite(" cap=");
                arch::SerialWrite(CapName(kCapFsRead));
                arch::SerialWrite(" denial_idx=");
                arch::SerialWriteHex(proc->sandbox_denials);
                arch::SerialWrite("\n");
            }
            frame->rax = static_cast<u64>(-1);
            return;
        }

        char kpath[kSyscallPathMax];
        if (!mm::CopyFromUser(kpath, reinterpret_cast<const void*>(frame->rdi), kSyscallPathMax))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        kpath[kSyscallPathMax - 1] = '\0';

        const fs::RamfsNode* n = fs::VfsLookup(proc->root, kpath, kSyscallPathMax);
        if (n == nullptr)
        {
            arch::SerialWrite("[fs] read miss pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite(" path=\"");
            arch::SerialWrite(kpath);
            arch::SerialWrite("\"\n");
            frame->rax = static_cast<u64>(-1);
            return;
        }
        if (n->type != fs::RamfsNodeType::kFile)
        {
            arch::SerialWrite("[fs] read not-file pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite(" path=\"");
            arch::SerialWrite(kpath);
            arch::SerialWrite("\"\n");
            frame->rax = static_cast<u64>(-1);
            return;
        }

        // Clamp the copy to whichever is smaller: the caller's
        // buffer capacity or the file size. Short reads are normal
        // — the caller gets the actual bytes-written count back in
        // rax and handles partial reads.
        const u64 cap_bytes = frame->rdx;
        const u64 to_copy = (n->file_size < cap_bytes) ? n->file_size : cap_bytes;
        if (to_copy == 0)
        {
            frame->rax = 0;
            return;
        }

        if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), n->file_bytes, to_copy))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

        arch::SerialWrite("[fs] read ok pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" path=\"");
        arch::SerialWrite(kpath);
        arch::SerialWrite("\" bytes=");
        arch::SerialWriteHex(to_copy);
        arch::SerialWrite("\n");
        frame->rax = to_copy;
        return;
    }

    case SYS_STAT:
    {
        // rdi = user pointer to NUL-terminated path.
        // rsi = user pointer to u64 output slot (receives file size).
        // Returns 0 on success, -1 on any failure.
        //
        // Cap check first — a process without kCapFsRead can't even
        // ATTEMPT a lookup. Denial is logged for auditability,
        // identical format to SYS_WRITE.
        Process* proc = CurrentProcess();
        if (proc == nullptr || !CapSetHas(proc->caps, kCapFsRead))
        {
            const u64 pid = (proc != nullptr) ? proc->pid : 0;
            RecordSandboxDenial(kCapFsRead);
            if (proc != nullptr && ShouldLogDenial(proc->sandbox_denials))
            {
                arch::SerialWrite("[sys] denied syscall=SYS_STAT pid=");
                arch::SerialWriteHex(pid);
                arch::SerialWrite(" cap=");
                arch::SerialWrite(CapName(kCapFsRead));
                arch::SerialWrite(" denial_idx=");
                arch::SerialWriteHex(proc->sandbox_denials);
                arch::SerialWrite("\n");
            }
            frame->rax = static_cast<u64>(-1);
            return;
        }

        // Bounce the user path onto the kernel stack. CopyFromUser
        // validates pointer range + walks the active AS's PML4
        // (cap + namespace jail compose on top of that: even after
        // copy, lookup is bounded by proc->root).
        char kpath[kSyscallPathMax];
        if (!mm::CopyFromUser(kpath, reinterpret_cast<const void*>(frame->rdi), kSyscallPathMax))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        // Ensure terminal NUL within the buffer — a user pointer
        // to an unterminated buffer would let VfsLookup wander;
        // force-terminate at kSyscallPathMax - 1.
        kpath[kSyscallPathMax - 1] = '\0';

        const fs::RamfsNode* n = fs::VfsLookup(proc->root, kpath, kSyscallPathMax);
        if (n == nullptr)
        {
            // Lookup miss. Could be: component not found, ".." hit
            // (jail-escape attempt), or a walk-through-file. All
            // surface as -1 to ring 3; the log line says which
            // process tried what, without leaking structure of
            // what exists vs. what's blocked.
            arch::SerialWrite("[fs] stat miss pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite(" path=\"");
            arch::SerialWrite(kpath);
            arch::SerialWrite("\"\n");
            frame->rax = static_cast<u64>(-1);
            return;
        }

        // Hit. Write the file size back to the user's output slot.
        // Directories report size=0 — the existence alone is the
        // answer the caller needed.
        const u64 size = (n->type == fs::RamfsNodeType::kFile) ? n->file_size : 0;
        if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), &size, sizeof(size)))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

        arch::SerialWrite("[fs] stat ok pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" path=\"");
        arch::SerialWrite(kpath);
        arch::SerialWrite("\" size=");
        arch::SerialWriteHex(size);
        arch::SerialWrite("\n");
        frame->rax = 0;
        return;
    }

    case SYS_SPAWN:
    {
        // rdi = user path pointer, rsi = path length.
        // Inherits caller's caps + namespace root — a sandboxed
        // process spawning a binary gets an equally-sandboxed
        // child. Cap-gated on kCapFsRead because the observable
        // primitive is "the caller named a file path"; without
        // it, even the lookup is not something the process is
        // authorised to perform.
        Process* proc = CurrentProcess();
        if (proc == nullptr || !CapSetHas(proc->caps, kCapFsRead))
        {
            const u64 pid = (proc != nullptr) ? proc->pid : 0;
            RecordSandboxDenial(kCapFsRead);
            if (proc != nullptr && ShouldLogDenial(proc->sandbox_denials))
            {
                arch::SerialWrite("[sys] denied syscall=SYS_SPAWN pid=");
                arch::SerialWriteHex(pid);
                arch::SerialWrite(" cap=");
                arch::SerialWrite(CapName(kCapFsRead));
                arch::SerialWrite(" denial_idx=");
                arch::SerialWriteHex(proc->sandbox_denials);
                arch::SerialWrite("\n");
            }
            frame->rax = static_cast<u64>(-1);
            return;
        }
        char kpath[kSyscallPathMax];
        u64 plen = frame->rsi;
        if (plen >= kSyscallPathMax)
        {
            plen = kSyscallPathMax - 1;
        }
        if (plen == 0)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        if (!mm::CopyFromUser(kpath, reinterpret_cast<const void*>(frame->rdi), plen))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        kpath[plen] = '\0';
        const fs::RamfsNode* n = fs::VfsLookup(proc->root, kpath, kSyscallPathMax);
        if (n == nullptr || n->type != fs::RamfsNodeType::kFile)
        {
            arch::SerialWrite("[sys] spawn miss pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite(" path=\"");
            arch::SerialWrite(kpath);
            arch::SerialWrite("\"\n");
            frame->rax = static_cast<u64>(-1);
            return;
        }
        // Inherit caps + root + trusted budgets. Later slices can
        // differentiate spawn from a sandboxed parent by dropping
        // caps after SpawnElfFile.
        const u64 child_pid = SpawnElfFile(kpath, n->file_bytes, n->file_size, proc->caps, proc->root,
                                           mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        if (child_pid == 0)
        {
            arch::SerialWrite("[sys] spawn fail pid=");
            arch::SerialWriteHex(proc->pid);
            arch::SerialWrite(" path=\"");
            arch::SerialWrite(kpath);
            arch::SerialWrite("\"\n");
            frame->rax = static_cast<u64>(-1);
            return;
        }
        arch::SerialWrite("[sys] spawn ok parent=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" child=");
        arch::SerialWriteHex(child_pid);
        arch::SerialWrite(" path=\"");
        arch::SerialWrite(kpath);
        arch::SerialWrite("\"\n");
        frame->rax = child_pid;
        return;
    }

    case SYS_DROPCAPS:
    {
        // rdi = bitmask of caps to remove. No cap check on this
        // syscall itself — anyone can voluntarily deprivilege.
        // Irreversible: once bits are cleared from proc->caps,
        // no syscall path can set them back (we never expose a
        // SYS_GRANTCAPS).
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 drop_mask = frame->rdi;
        const u64 before = proc->caps.bits;
        proc->caps.bits &= ~drop_mask;
        arch::SerialWrite("[sys] dropcaps pid=");
        arch::SerialWriteHex(proc->pid);
        arch::SerialWrite(" mask=");
        arch::SerialWriteHex(drop_mask);
        arch::SerialWrite(" caps=");
        arch::SerialWriteHex(before);
        arch::SerialWrite("->");
        arch::SerialWriteHex(proc->caps.bits);
        arch::SerialWrite("\n");
        frame->rax = 0;
        return;
    }

    default:
    {
        // Offer to the translation unit before surfacing the
        // "unknown syscall" warning. The TU may synthesise the
        // call from Linux primitives or route through the Win32
        // subsystem's kernel-side helpers (heap, etc.); its own
        // log lines distinguish success from miss.
        const auto t = subsystems::translation::NativeGapFill(frame);
        if (t.handled)
        {
            frame->rax = static_cast<u64>(t.rv);
            return;
        }
        ReportUnknownSyscall(num, frame->rip);
        // Convention: -1 back to the caller for a bad syscall number.
        // Two's-complement cast keeps the rax payload machine-visible
        // as 0xFFFFFFFFFFFFFFFF rather than relying on enum promotion.
        frame->rax = static_cast<u64>(-1);
        return;
    }
    }
}

} // namespace customos::core
