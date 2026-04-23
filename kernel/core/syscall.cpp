#include "syscall.h"

#include "../arch/x86_64/cpu.h"
#include "../arch/x86_64/hpet.h"
#include "../arch/x86_64/idt.h"
#include "../arch/x86_64/rtc.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/timer.h"
#include "../debug/bp_syscall.h"
#include "../debug/breakpoints.h"
#include "../debug/probes.h"
#include "../fs/vfs.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../mm/paging.h"
#include "../sched/sched.h"
#include "../subsystems/translation/translate.h"
#include "../subsystems/win32/heap_syscall.h"
#include "../subsystems/win32/vmap_syscall.h"
#include "../subsystems/win32/tls_syscall.h"
#include "../subsystems/win32/file_syscall.h"
#include "../subsystems/win32/thread_syscall.h"
#include "../subsystems/win32/mutex_syscall.h"
#include "../subsystems/win32/event_syscall.h"
#include "../subsystems/win32/heap.h"
#include "klog.h"
#include "process.h"
#include "ring3_smoke.h"
#include "time_syscall.h"

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
// kSyscallPathMax now in syscall.h

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

    // Heap family: handlers live in subsystems/win32/heap_syscall.cpp.
    case SYS_HEAP_ALLOC:
        subsystems::win32::DoHeapAlloc(frame);
        return;
    case SYS_HEAP_FREE:
        subsystems::win32::DoHeapFree(frame);
        return;
    case SYS_HEAP_SIZE:
        subsystems::win32::DoHeapSize(frame);
        return;
    case SYS_HEAP_REALLOC:
        subsystems::win32::DoHeapRealloc(frame);
        return;

    // Time family: handlers live in kernel/core/time_syscall.cpp
    // so the dispatcher is a thin router. Same ABI, same rax
    // contract — the extraction only moves code, not behaviour.
    case SYS_PERF_COUNTER:
        DoPerfCounter(frame);
        return;
    case SYS_NOW_NS:
        DoNowNs(frame);
        return;
    case SYS_GETTIME_FT:
        DoGetTimeFt(frame);
        return;
    case SYS_GETTIME_ST:
        DoGetTimeSt(frame);
        return;
    case SYS_ST_TO_FT:
        DoStToFt(frame);
        return;
    case SYS_FT_TO_ST:
        DoFtToSt(frame);
        return;


    case SYS_WIN32_MISS_LOG:
    {
        KBP_PROBE_V(::customos::debug::ProbeId::kWin32StubMiss, frame->rdi);

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
        subsystems::win32::DoFileOpen(frame);
        return;
    case SYS_FILE_READ:
        subsystems::win32::DoFileRead(frame);
        return;
    case SYS_FILE_CLOSE:
        subsystems::win32::DoFileClose(frame);
        return;

    case SYS_MUTEX_CREATE:
        subsystems::win32::DoMutexCreate(frame);
        return;
    case SYS_MUTEX_WAIT:
        subsystems::win32::DoMutexWait(frame);
        return;
    case SYS_MUTEX_RELEASE:
        subsystems::win32::DoMutexRelease(frame);
        return;

    case SYS_EVENT_CREATE:
        subsystems::win32::DoEventCreate(frame);
        return;
    case SYS_EVENT_SET:
        subsystems::win32::DoEventSet(frame);
        return;
    case SYS_EVENT_RESET:
        subsystems::win32::DoEventReset(frame);
        return;
    case SYS_EVENT_WAIT:
        subsystems::win32::DoEventWait(frame);
        return;

    case SYS_TLS_ALLOC:
        subsystems::win32::DoTlsAlloc(frame);
        return;
    case SYS_TLS_FREE:
        subsystems::win32::DoTlsFree(frame);
        return;
    case SYS_TLS_GET:
        subsystems::win32::DoTlsGet(frame);
        return;
    case SYS_TLS_SET:
        subsystems::win32::DoTlsSet(frame);
        return;

    case SYS_BP_INSTALL:
        debug::DoBpInstall(frame);
        return;
    case SYS_BP_REMOVE:
        debug::DoBpRemove(frame);
        return;

    case SYS_VMAP:
        subsystems::win32::DoVmap(frame);
        return;
    case SYS_VUNMAP:
        subsystems::win32::DoVunmap(frame);
        return;


    case SYS_FILE_SEEK:
        subsystems::win32::DoFileSeek(frame);
        return;
    case SYS_FILE_FSTAT:
        subsystems::win32::DoFileFstat(frame);
        return;
    case SYS_FILE_WRITE:
        subsystems::win32::DoFileWrite(frame);
        return;
    case SYS_FILE_CREATE:
        subsystems::win32::DoFileCreate(frame);
        return;
    case SYS_THREAD_CREATE:
        subsystems::win32::DoThreadCreate(frame);
        return;

    case SYS_DEBUG_PRINT:
    {
        // rdi = user ptr to NUL-terminated ASCII string. Cap-gated
        // on kCapSerialConsole (same gate as SYS_WRITE fd=1).
        // Unknown caller / no cap → silent -1 on the first call,
        // then rate-limited denial log like SYS_WRITE.
        Process* proc = CurrentProcess();
        if (proc == nullptr || !CapSetHas(proc->caps, kCapSerialConsole))
        {
            const u64 pid = (proc != nullptr) ? proc->pid : 0;
            RecordSandboxDenial(kCapSerialConsole);
            if (proc != nullptr && ShouldLogDenial(proc->sandbox_denials))
            {
                arch::SerialWrite("[sys] denied syscall=SYS_DEBUG_PRINT pid=");
                arch::SerialWriteHex(pid);
                arch::SerialWrite(" cap=");
                arch::SerialWrite(CapName(kCapSerialConsole));
                arch::SerialWrite("\n");
            }
            frame->rax = static_cast<u64>(-1);
            return;
        }

        // Bounce buffer on kernel stack, +1 for the hard terminator
        // so a user string that exactly fills the ceiling still
        // prints bounded.
        char kbuf[kSyscallDebugPrintMax + 1];
        // Freestanding: no memset, so clear via byte loop.
        for (u64 i = 0; i < sizeof(kbuf); ++i)
            kbuf[i] = 0;
        if (!mm::CopyFromUser(kbuf, reinterpret_cast<const void*>(frame->rdi), kSyscallDebugPrintMax))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        kbuf[kSyscallDebugPrintMax] = '\0';

        arch::SerialWrite("[odbg] ");
        arch::SerialWrite(kbuf);
        // Append newline if the user string didn't end with one — a
        // Win32 OutputDebugString call is one "event" so the serial
        // log should show one line per call.
        u64 len = 0;
        while (len < kSyscallDebugPrintMax && kbuf[len] != '\0')
            ++len;
        if (len == 0 || kbuf[len - 1] != '\n')
            arch::SerialWrite("\n");

        frame->rax = 0;
        return;
    }

    case SYS_MEM_STATUS:
    {
        // rdi = user pointer to a Win32 MEMORYSTATUSEX struct (64
        // bytes). Layout (offsets in bytes):
        //   0x00 DWORD dwLength            — caller-set (must be 64)
        //   0x04 DWORD dwMemoryLoad        — 0..100
        //   0x08 ULONGLONG ullTotalPhys
        //   0x10 ULONGLONG ullAvailPhys
        //   0x18 ULONGLONG ullTotalPageFile
        //   0x20 ULONGLONG ullAvailPageFile
        //   0x28 ULONGLONG ullTotalVirtual
        //   0x30 ULONGLONG ullAvailVirtual
        //   0x38 ULONGLONG ullAvailExtendedVirtual
        struct __attribute__((packed)) MemoryStatusEx
        {
            u32 dwLength;
            u32 dwMemoryLoad;
            u64 ullTotalPhys;
            u64 ullAvailPhys;
            u64 ullTotalPageFile;
            u64 ullAvailPageFile;
            u64 ullTotalVirtual;
            u64 ullAvailVirtual;
            u64 ullAvailExtendedVirtual;
        };
        static_assert(sizeof(MemoryStatusEx) == 64, "MEMORYSTATUSEX must be 64 bytes");

        // Validate dwLength field before filling — Win32 contract
        // says the caller sets dwLength = sizeof(MEMORYSTATUSEX) as
        // a version discriminator. We refuse other sizes so a
        // miscompiled caller gets a deterministic error rather than
        // a partially-populated struct.
        u32 user_len = 0;
        if (!mm::CopyFromUser(&user_len, reinterpret_cast<const void*>(frame->rdi), sizeof(user_len)))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        if (user_len != sizeof(MemoryStatusEx))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

        MemoryStatusEx st;
        // Freestanding kernel: no memset, no implicit zero-init via = {}.
        // Byte-loop clear via a volatile write so the optimizer won't
        // convert this back into memset.
        for (u64 i = 0; i < sizeof(st); ++i)
            reinterpret_cast<volatile u8*>(&st)[i] = 0;
        st.dwLength = sizeof(MemoryStatusEx);
        const u64 total_pages = mm::TotalFrames();
        const u64 free_pages = mm::FreeFramesCount();
        const u64 used_pages = (total_pages >= free_pages) ? (total_pages - free_pages) : 0;
        st.ullTotalPhys = total_pages * mm::kPageSize;
        st.ullAvailPhys = free_pages * mm::kPageSize;
        // No pagefile — report same totals (Win32 convention when
        // there's no backing file: total == phys, avail == phys).
        st.ullTotalPageFile = st.ullTotalPhys;
        st.ullAvailPageFile = st.ullAvailPhys;
        // User-virtual range is the canonical lower half (first
        // 128 TiB). Avail is a synthetic figure: total minus the
        // sum of the caller's mapped user regions.
        constexpr u64 kUserVirtualBytes = 1ULL << 47; // 128 TiB
        st.ullTotalVirtual = kUserVirtualBytes;
        u64 mapped_bytes = 0;
        Process* proc = CurrentProcess();
        if (proc != nullptr && proc->as != nullptr)
        {
            for (u8 i = 0; i < proc->as->region_count; ++i)
                mapped_bytes += mm::kPageSize;
        }
        st.ullAvailVirtual = (kUserVirtualBytes >= mapped_bytes) ? (kUserVirtualBytes - mapped_bytes) : 0;
        st.ullAvailExtendedVirtual = 0;
        // Memory load = used/total * 100. Guard against divide-by-zero.
        st.dwMemoryLoad = (total_pages == 0) ? 0 : static_cast<u32>((used_pages * 100) / total_pages);

        if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rdi), &st, sizeof(st)))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        frame->rax = 0;
        return;
    }

    case SYS_SYSTEM_INFO:
    {
        // rdi = user pointer to SYSTEM_INFO (48 bytes).
        struct __attribute__((packed)) SystemInfo
        {
            u16 wProcessorArchitecture;
            u16 wReserved;
            u32 dwPageSize;
            u64 lpMinimumApplicationAddress;
            u64 lpMaximumApplicationAddress;
            u64 dwActiveProcessorMask;
            u32 dwNumberOfProcessors;
            u32 dwProcessorType;
            u32 dwAllocationGranularity;
            u16 wProcessorLevel;
            u16 wProcessorRevision;
        };
        static_assert(sizeof(SystemInfo) == 48, "SYSTEM_INFO must be 48 bytes");

        SystemInfo si;
        for (u64 i = 0; i < sizeof(si); ++i)
            reinterpret_cast<volatile u8*>(&si)[i] = 0;
        si.wProcessorArchitecture = 9; // AMD64
        si.dwPageSize = 4096;
        si.lpMinimumApplicationAddress = 0x10000ULL;
        si.lpMaximumApplicationAddress = 0x7FFFFFFE0000ULL;
        si.dwActiveProcessorMask = 1;
        si.dwNumberOfProcessors = 1;
        si.dwProcessorType = 8664; // PROCESSOR_AMD_X8664
        si.dwAllocationGranularity = 0x10000;
        si.wProcessorLevel = 6;
        si.wProcessorRevision = 0;

        if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rdi), &si, sizeof(si)))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        frame->rax = 0;
        return;
    }

    case SYS_DEBUG_PRINTW:
    {
        // rdi = user ptr to NUL-terminated UTF-16LE string. Cap
        // gate mirrors SYS_DEBUG_PRINT.
        Process* proc = CurrentProcess();
        if (proc == nullptr || !CapSetHas(proc->caps, kCapSerialConsole))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

        // Read up to kSyscallDebugPrintMax wide-chars (2 bytes each).
        u16 wbuf[kSyscallDebugPrintMax + 1];
        for (u64 i = 0; i < kSyscallDebugPrintMax + 1; ++i)
            wbuf[i] = 0;
        if (!mm::CopyFromUser(wbuf, reinterpret_cast<const void*>(frame->rdi), kSyscallDebugPrintMax * sizeof(u16)))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        wbuf[kSyscallDebugPrintMax] = 0;

        // Strip to ASCII — non-ASCII → '?'. Single-pass, stops at
        // first NUL wide-char.
        char abuf[kSyscallDebugPrintMax + 1];
        u64 n = 0;
        for (; n < kSyscallDebugPrintMax; ++n)
        {
            const u16 w = wbuf[n];
            if (w == 0)
                break;
            abuf[n] = (w < 0x80) ? static_cast<char>(w) : '?';
        }
        abuf[n] = '\0';

        arch::SerialWrite("[odbgw] ");
        arch::SerialWrite(abuf);
        if (n == 0 || abuf[n - 1] != '\n')
            arch::SerialWrite("\n");

        frame->rax = 0;
        return;
    }

    case SYS_WAIT_MULTI:
    {
        // rdi = count, rsi = user handle array, rdx = wait_all,
        // r10 = timeout_ms. v0 polls + yields.
        const u64 count = frame->rdi;
        const u64 user_handles_va = frame->rsi;
        const u64 wait_all = frame->rdx;
        const u64 timeout_ms = frame->r10;

        if (count == 0 || count > kSyscallWaitMultiMax)
        {
            frame->rax = static_cast<u64>(-1); // WAIT_FAILED
            return;
        }

        u64 handles[kSyscallWaitMultiMax];
        for (u64 i = 0; i < kSyscallWaitMultiMax; ++i)
            handles[i] = 0;
        if (!mm::CopyFromUser(handles, reinterpret_cast<const void*>(user_handles_va), count * sizeof(u64)))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

        // Poll-and-yield loop. Budget: kMaxIterations iterations of
        // SchedYield for infinite waits, or deadline_ticks for timed
        // waits. 10 ms per tick means a 100-ms wait is ~10 iters.
        constexpr u64 kInfinite = 0xFFFFFFFFULL;
        const u64 now_ticks = sched::SchedNowTicks();
        const u64 deadline = (timeout_ms == kInfinite) ? u64(-1) : now_ticks + ((timeout_ms + 9) / 10); // 10 ms/tick

        for (;;)
        {
            // Poll each handle's signaled state. Supported handle
            // families:
            //   * Events (0x300..): query Process.win32_events[slot].signaled
            //   * Mutexes (0x200..): try a non-blocking acquire
            //   * Threads (0x400..): signaled iff the task is Dead
            //   * Anything else: never signaled → contributes FALSE
            u64 signaled_count = 0;
            u64 first_signaled = u64(-1);
            Process* proc = CurrentProcess();
            for (u64 i = 0; i < count; ++i)
            {
                const u64 h = handles[i];
                bool sig = false;
                if (proc != nullptr)
                {
                    if (h >= Process::kWin32EventBase && h < Process::kWin32EventBase + Process::kWin32EventCap)
                    {
                        const u64 slot = h - Process::kWin32EventBase;
                        const auto& ev = proc->win32_events[slot];
                        if (ev.in_use && ev.signaled)
                        {
                            sig = true;
                            // Auto-reset: clear only when we're
                            // ACTUALLY going to wake (wait-any
                            // picks this slot, or wait-all
                            // completes with this satisfied).
                            // Handled below, after we know the
                            // whole wait is satisfied.
                        }
                    }
                    else if (h >= Process::kWin32ThreadBase && h < Process::kWin32ThreadBase + Process::kWin32ThreadCap)
                    {
                        const u64 slot = h - Process::kWin32ThreadBase;
                        const auto& th = proc->win32_threads[slot];
                        if (th.in_use && sched::TaskIsDead(th.task))
                            sig = true;
                    }
                    // Mutex handles: v0 doesn't try-acquire here —
                    // would need to thread the owner through. Skip
                    // for now; callers wait on events + threads
                    // (the common pattern).
                }
                if (sig)
                {
                    ++signaled_count;
                    if (first_signaled == u64(-1))
                        first_signaled = i;
                }
            }

            const bool satisfied = (wait_all != 0) ? (signaled_count == count) : (signaled_count > 0);
            if (satisfied)
            {
                // Auto-reset events we're waking on: clear the
                // signal. For wait-any, only the winning handle;
                // for wait-all, every auto-reset event in the set.
                if (proc != nullptr)
                {
                    for (u64 i = 0; i < count; ++i)
                    {
                        const u64 h = handles[i];
                        if (h >= Process::kWin32EventBase && h < Process::kWin32EventBase + Process::kWin32EventCap)
                        {
                            const u64 slot = h - Process::kWin32EventBase;
                            auto& ev = proc->win32_events[slot];
                            if (!ev.in_use || !ev.manual_reset)
                                continue;
                            // Manual-reset: leave signaled. Skip.
                        }
                        if (h >= Process::kWin32EventBase && h < Process::kWin32EventBase + Process::kWin32EventCap)
                        {
                            const u64 slot = h - Process::kWin32EventBase;
                            auto& ev = proc->win32_events[slot];
                            if (!ev.manual_reset && ev.signaled && (wait_all != 0 || i == first_signaled))
                                ev.signaled = false;
                        }
                    }
                }
                frame->rax = (wait_all != 0) ? 0 : first_signaled; // WAIT_OBJECT_0 + i
                return;
            }

            // Check deadline.
            if (timeout_ms != kInfinite && sched::SchedNowTicks() >= deadline)
            {
                frame->rax = 0x102; // WAIT_TIMEOUT
                return;
            }

            // Give up a slice. SchedYield if no timeout pressure;
            // SchedSleepTicks(1) for a timed wait so we don't
            // re-enter the loop faster than the timer tick.
            if (timeout_ms == kInfinite)
                sched::SchedYield();
            else
                sched::SchedSleepTicks(1);
        }
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
