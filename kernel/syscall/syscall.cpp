/*
 * DuetOS — native int-0x80 syscall dispatcher: implementation.
 *
 * Companion to syscall.h — see there for the calling convention
 * (rax=number, rdi/rsi/rdx args, rax return), the SYS_* enum, the
 * capability gating contract, and the ABI-stability rules.
 *
 * WHAT
 *   `SyscallDispatch` is the C++ entry point the int-0x80 IDT
 *   vector (0x80, DPL=3) routes into via the shared trap path in
 *   exceptions.S. It pulls the syscall number out of the trap
 *   frame's rax, looks up the handler, runs it inside the calling
 *   task's address space, and writes the return value back into
 *   the frame's rax slot.
 *
 * HOW
 *   Dispatch is a single big `switch (num)` rather than a
 *   function-pointer table. Reasons:
 *     - A dense switch over an enum compiles to a jump table
 *       anyway.
 *     - Every handler shares scratch state and early-exit paths
 *       (klog, capability checks, fault-domain entry/exit)
 *       without per-handler boilerplate.
 *     - SYS_* numbers are ABI; a switch makes "added at the tail,
 *       never reused" visually obvious.
 *
 *   Each case typically: (1) checks the caller's capability
 *   bitmask, (2) translates user pointers through CopyFromUser /
 *   CopyToUser (which trap-fix #PFs), (3) delegates to a
 *   subsystem (vfs, sched, win32::*, mm::*) and maps its
 *   Result<T,E> onto a positive-or-negative-errno return.
 *
 *   Trace tags (`klog::Trace("syscall", ...)`) bracket every
 *   handler. The `loglevel t` shell command turns them on for
 *   live observability without rebuild.
 *
 * WHY THIS FILE IS LARGE
 *   v0 has ~80 syscalls live; each handler is short (10-40 lines)
 *   but they accumulate. Splitting per-subsystem would mean the
 *   dispatch table chases function pointers across TUs at every
 *   syscall — measurable in tight loops, and the indirection
 *   breaks the compiler's jump-table optimisation. Keep handlers
 *   together until profile data argues otherwise.
 */

#include "syscall/cap_gate.h"
#include "syscall/error.h"
#include "syscall/syscall.h"

#include "drivers/video/cursor.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/hpet.h"
#include "arch/x86_64/idt.h"
#include "arch/x86_64/rtc.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "debug/bp_syscall.h"
#include "debug/breakpoints.h"
#include "debug/probes.h"
#include "fs/fat32.h"
#include "fs/file_route.h"
#include "ipc/handle_table.h"
#include "ipc/kevent.h"
#include "ipc/kobject.h"
#include "ipc/ksemaphore.h"
#include "loader/elf_loader.h"
#include "mm/kheap.h"
#include "fs/vfs.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "net/socket.h"
#include "net/stack.h"
#include "sched/sched.h"
#include "subsystems/graphics/graphics.h"
#include "subsystems/translation/translate.h"
#include "subsystems/win32/gdi_objects.h"
#include "subsystems/win32/heap_syscall.h"
#include "subsystems/win32/vmap_syscall.h"
#include "util/debug_assert.h"
#include "subsystems/win32/tls_syscall.h"
#include "subsystems/win32/file_syscall.h"
#include "subsystems/win32/thread_syscall.h"
#include "subsystems/win32/mutex_syscall.h"
#include "subsystems/win32/event_syscall.h"
#include "subsystems/win32/named_kobj_syscall.h"
#include "subsystems/win32/semaphore_syscall.h"
#include "subsystems/win32/dir_syscall.h"
#include "subsystems/win32/iocp_job.h"
#include "subsystems/win32/section.h"
#include "subsystems/win32/spawn_syscall.h"
#include "subsystems/win32/token_syscall.h"
#include "subsystems/win32/window_syscall.h"
#include "subsystems/win32/heap.h"
#include "subsystems/win32/custom.h"
#include "subsystems/win32/registry.h"
#include "log/klog.h"
#include "diag/cleanroom_trace.h"
#include "diag/event_trace.h"
#include "diag/fix_journal.h"
#include "diag/log_names.h"
#include "proc/process.h"
#include "proc/ring3_smoke.h"
#include "syscall/time_syscall.h"

// Defined in exceptions.S (via `ISR_NOERR 128`) — the .global label for
// the int-0x80 stub. SyscallInit installs its address into the IDT with
// a DPL=3 gate, which is the only bit that makes the int legal from ring
// 3. The function itself has no C-callable signature; we take its
// address as an opaque u64.
extern "C" void isr_128();

namespace duetos::core
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
//
// Bumped 256 -> 4096 for 7za.exe's help-text path: 7-Zip prints
// its full usage block as a single ~3 KiB fputs/fwrite call. With
// the 256-byte cap the help text was truncated mid-line at "  h :
// Calculate hash v". 4 KiB is one page, still bounded, and stays
// well inside the 16 KiB kernel stack budget. Real-world stdio
// rarely exceeds a page in a single call; programs that do (mmap
// dumps, large memcpy-into-stdout) will see correct truncation +
// partial-write semantics from POSIX-style retry loops.
constexpr u64 kSyscallWriteMax = 4096;
// kSyscallPathMax now in syscall.h

// Cross-AS VM transfer direction. Read = target → caller buffer;
// Write = caller buffer → target.
enum class CrossAsDir
{
    Read,
    Write,
};

// Walk `target`'s region table page-by-page, copy `len` bytes
// between `target_va` (in `target->as`) and `caller_buf` (in the
// active AS — i.e. the syscall caller's). Stops at the first
// unmapped target page; the count actually moved is returned via
// `out_bytes`. Returns true iff the full requested length was
// transferred.
//
// Both buffers may straddle page boundaries on either side. The
// loop chunks against the smaller of "remaining target page" /
// "remaining caller-side run we want to copy" (we always copy
// the same byte count on both sides — only the page geometry
// matters for the chunking).
//
// Caller-side I/O still goes through CopyFromUser / CopyToUser,
// so SMAP gating + range validation happen there for free.
bool CrossAsTransfer(Process* target, u64 target_va, void* caller_buf, u64 len, CrossAsDir dir, u64* out_bytes)
{
    *out_bytes = 0;
    if (target == nullptr || target->as == nullptr || len == 0)
    {
        return len == 0; // zero-length is trivially full success
    }

    u64 remaining = len;
    u64 t_va = target_va;
    auto* c_byte = static_cast<u8*>(caller_buf);

    while (remaining > 0)
    {
        const u64 page_va = t_va & ~0xFFFULL;
        const u64 page_off = t_va - page_va;
        const u64 chunk = (remaining < (mm::kPageSize - page_off)) ? remaining : (mm::kPageSize - page_off);

        const mm::PhysAddr frame = mm::AddressSpaceLookupUserFrame(target->as, page_va);
        if (frame == mm::kNullFrame)
        {
            return false; // partial copy; caller surfaces what we did move
        }
        auto* direct = static_cast<u8*>(mm::PhysToVirt(frame)) + page_off;

        if (dir == CrossAsDir::Read)
        {
            // target → caller. Copy from kernel direct map into a
            // bounce, then CopyToUser into the caller's buffer.
            // Use a small on-stack bounce so we don't have to
            // think about CopyToUser tolerating the source being
            // a kernel direct-map alias of a user frame (it does,
            // but the bounce keeps the contract obvious).
            u8 bounce[256];
            u64 moved = 0;
            while (moved < chunk)
            {
                const u64 step = (chunk - moved < sizeof(bounce)) ? (chunk - moved) : sizeof(bounce);
                for (u64 b = 0; b < step; ++b)
                {
                    bounce[b] = direct[moved + b];
                }
                if (!mm::CopyToUser(c_byte + moved, bounce, step))
                {
                    return false;
                }
                moved += step;
            }
        }
        else
        {
            // caller → target. CopyFromUser into a bounce, write
            // through the kernel direct map into the target frame.
            u8 bounce[256];
            u64 moved = 0;
            while (moved < chunk)
            {
                const u64 step = (chunk - moved < sizeof(bounce)) ? (chunk - moved) : sizeof(bounce);
                if (!mm::CopyFromUser(bounce, c_byte + moved, step))
                {
                    return false;
                }
                for (u64 b = 0; b < step; ++b)
                {
                    direct[moved + b] = bounce[b];
                }
                moved += step;
            }
        }

        *out_bytes += chunk;
        t_va += chunk;
        c_byte += chunk;
        remaining -= chunk;
    }
    return true;
}

// Resolve a Win32 thread handle to the kernel Task it refers to.
// Accepts BOTH ranges: local thread handles (kWin32ThreadBase +
// idx, returned by CreateThread / SYS_THREAD_CREATE — these
// back the caller's own threads) and foreign thread handles
// (kWin32ForeignThreadBase + idx, returned by NtOpenThread —
// these back a target task in a different process, with the
// target's owning Process refcount-pinned by the open call).
// Returns nullptr on any out-of-range / not-in-use handle.
//
// Used by SYS_THREAD_SUSPEND / RESUME / GET_CONTEXT /
// SET_CONTEXT — every cross-task thread op flows through here.
sched::Task* LookupThreadHandle(Process* caller, u64 handle)
{
    if (caller == nullptr)
    {
        return nullptr;
    }
    if (handle >= Process::kWin32ThreadBase && handle < Process::kWin32ThreadBase + Process::kWin32ThreadCap)
    {
        const u64 idx = handle - Process::kWin32ThreadBase;
        if (caller->win32_threads[idx].in_use)
        {
            return caller->win32_threads[idx].task;
        }
        return nullptr;
    }
    if (handle >= Process::kWin32ForeignThreadBase &&
        handle < Process::kWin32ForeignThreadBase + Process::kWin32ForeignThreadCap)
    {
        const u64 idx = handle - Process::kWin32ForeignThreadBase;
        if (caller->win32_foreign_threads[idx].in_use)
        {
            return caller->win32_foreign_threads[idx].task;
        }
        return nullptr;
    }
    return nullptr;
}

// Resolve a Win32 process handle (kWin32ProcessBase + idx) on
// `caller` to the `Process*` it refers to. Returns nullptr on
// any out-of-range / not-in-use handle.
Process* LookupProcessHandle(Process* caller, u64 handle)
{
    if (caller == nullptr || handle < Process::kWin32ProcessBase)
    {
        return nullptr;
    }
    const u64 idx = handle - Process::kWin32ProcessBase;
    if (idx >= Process::kWin32ProcessCap)
    {
        return nullptr;
    }
    if (!caller->win32_proc_handles[idx].in_use)
    {
        return nullptr;
    }
    return caller->win32_proc_handles[idx].target;
}

// Win32 NTSTATUS values used by the cross-process VM family.
// Matches winnt.h conventions for the few statuses we surface.
constexpr u64 kStatusSuccess = 0;
constexpr u64 kStatusAccessViolation = 0xC0000005ULL;
constexpr u64 kStatusInvalidHandle = 0xC0000008ULL;
constexpr u64 kStatusInvalidParameter = 0xC000000DULL;
constexpr u64 kStatusAccessDenied = 0xC0000022ULL;
constexpr u64 kStatusNotImplemented = 0xC0000002ULL;
constexpr u64 kStatusNoMemory = 0xC0000017ULL;
constexpr u64 kStatusConflictingAddresses = 0xC0000018ULL;

// Layout the SYS_PROCESS_VM_QUERY caller buffer must conform to.
// Byte-compatible with the prefix of MEMORY_BASIC_INFORMATION
// that v0 actually populates. Each field is the same size and
// offset as the matching Win32 field; the trailing bytes (Type,
// AllocationProtect alignment) are reserved for future growth.
struct Win32MemoryBasicInfo
{
    u64 base_address;       // 4 KiB-aligned page start
    u64 allocation_base;    // == base_address in v0
    u32 allocation_protect; // PAGE_READWRITE for any mapped page
    u32 _pad0;
    u64 region_size; // 4096 in v0 (no coalescing)
    u32 state;       // MEM_COMMIT / MEM_FREE
    u32 protect;     // == allocation_protect
    u32 type;        // MEM_PRIVATE
    u32 _pad1;
};
static_assert(sizeof(Win32MemoryBasicInfo) == 48, "Win32MemoryBasicInfo layout");

constexpr u32 kMemCommit = 0x1000;
constexpr u32 kMemFree = 0x10000;
constexpr u32 kMemPrivate = 0x20000;
constexpr u32 kPageReadWrite = 0x04;

// Pretty-printer for boot diagnostics — the Warn path for an
// unrecognised syscall number should be noisy enough to catch during
// bring-up but cheap enough to leave in release builds.
void ReportUnknownSyscall(u64 num, u64 rip)
{
    arch::SerialWrite("[sys] WARN unknown syscall num=");
    arch::SerialWriteHex(num);
    arch::SerialWrite("(");
    arch::SerialWrite(SyscallName(num));
    arch::SerialWrite(") rip=");
    arch::SerialWriteHex(rip);
    arch::SerialWrite("\n");
    KLOG_WARN_2V("syscall", "unknown syscall number", "num", num, "rip", rip);
    KLOG_WARN_S("syscall", "unknown syscall name", "name", SyscallName(num));
}

// SYS_WRITE body. Copies up to `len` bytes from the user buffer,
// truncates to kSyscallWriteMax, and spits them straight at COM1.
// Only fd=1 (stdout) is recognised today — anything else is a
// caller error and returns -EBADF so the pattern is immediately
// auditable. Returns the actual byte count written (possibly
// truncated) or a negative errno on failure.
//
// Cap check: fd=1 requires kCapSerialConsole. A sandboxed process
// with an empty cap set sees -EACCES and nothing reaches the kernel
// serial console. The denial is logged so it's trivially
// auditable — without the log we'd be silently swallowing a
// sandbox policy hit.
i64 DoWrite(u64 fd, const void* user_buf, u64 len)
{
    if (fd != 1)
    {
        return kSysErrnoEBADF;
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
        return kSysErrnoEACCES;
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
        return kSysErrnoEFAULT;
    }

    // Drive COM1 with one SerialWriteN call — the per-port lock is
    // held for the whole byte run, so no other thread (smoke ticker,
    // klog sink, etc.) can interleave between bytes. The previous
    // per-byte SerialWrite loop would release + re-acquire the lock
    // 256 times for a 256-byte write, and under TCG slowness that
    // window was wide enough for the smoke-ticker thread to insert
    // its `[smoke] tick=...` line mid-write — splitting a single
    // logical user line across two physical lines on the serial
    // log, which signature-grep CI tests can't reassemble. Cost:
    // ~2.2ms of IRQs-off at 115200 baud for a max-size 256-byte
    // write; bounded and acceptable for v0.
    arch::SerialWriteN(reinterpret_cast<const char*>(kbuf), to_copy);
    return static_cast<i64>(to_copy);
}

} // namespace

void SyscallInit()
{
    KLOG_TRACE_SCOPE("syscall", "SyscallInit");
    arch::IdtSetUserGate(kSyscallVector, reinterpret_cast<u64>(&isr_128));
    Log(LogLevel::Info, "sys", "syscall gate online at int 0x80");
    KLOG_INFO_V("syscall", "SyscallInit: int gate installed at vector", kSyscallVector);
}

void SyscallDispatch(arch::TrapFrame* frame)
{
    // Defensive: the int-0x80 trap stub can never legitimately
    // hand us a null trap frame, but a future caller (or a
    // mis-routed direct call) could. Refuse loudly instead of
    // dereferencing rax through a null pointer.
    if (frame == nullptr)
    {
        KLOG_ONCE_WARN("syscall", "SyscallDispatch called with null TrapFrame");
        return;
    }
    const u64 num = frame->rax;
    // Capture the syscall args at entry so an RAII guard (below)
    // can push the (nr, args, ret, ts) entry into the calling
    // task's trail ring on every return path. Reading from `frame`
    // directly in the destructor would race with handlers that
    // mutate frame->rdi/rsi/etc. before returning (e.g. SYS_EXIT
    // doesn't touch them but signal-delivery does).
    struct SyscallTrailGuard
    {
        arch::TrapFrame* f;
        u64 num;
        u64 a0, a1, a2, a3;
        ~SyscallTrailGuard()
        {
            ::duetos::sched::SyscallTrailRecord(::duetos::sched::kSyscallAbiNative, static_cast<u32>(num), a0, a1, a2,
                                                a3, f->rax);
        }
    };
    SyscallTrailGuard trail_guard{frame, num, frame->rdi, frame->rsi, frame->rdx, frame->r10};

    // Outer-scope process pointer for the dispatcher header. Renamed
    // away from `proc` so the per-case `Process* proc = ...`
    // declarations in the switch below don't trip -Wshadow.
    const Process* dispatch_proc = CurrentProcess();
    const u64 dispatch_pid = (dispatch_proc != nullptr) ? dispatch_proc->pid : 0;
    KLOG_TRACE_V("syscall", "SyscallDispatch: enter (number)", num);
    CleanroomTraceRecord("syscall", "native-dispatch", num, dispatch_pid, frame->rip);
    // Event-tracer enter (D2 instrumentation). Tag the event
    // with the syscall number + first arg so a `tracer dump`
    // correlates to the in-flight syscall stream.
    ::duetos::diag::EventTrace(::duetos::diag::kEventSyscallEnter, num, frame->rdi);
    // Win32 custom flight recorder. No-op unless the caller has
    // opted into kPolicyFlightRecorder via SYS_WIN32_CUSTOM. Cheap
    // (one inline policy-bit check) when off. We hand the hook a
    // mutable Process* because the recorder needs to write into the
    // process's lazy-allocated state — but the dispatcher itself
    // never mutates the process struct from this scope.
    subsystems::win32::custom::OnSyscallEntry(const_cast<Process*>(dispatch_proc), num, frame);

    // Centralised capability gate (plan A4). Consults
    // `kSyscallCapTable` for syscalls whose authorisation reduces
    // to a single static cap. Returns Ok for anything not in the
    // table; the per-handler conditional checks (foreign vs self
    // PID, fd=1 vs fd=2, etc.) still live in the switch arms below
    // and remain authoritative for those cases.
    const Result<void> gate_result = SyscallGate(num, dispatch_proc);
    if (!gate_result.has_value())
    {
        KLOG_WARN_2V("syscall", "SyscallDispatch: capability gate denied", "num", num, "pid", dispatch_pid);
        frame->rax = ErrorCodeToNativeSyscallReturn(gate_result.error());
        return;
    }

    switch (num)
    {
    case SYS_EXIT:
    {
        const u64 code = frame->rdi;
        LogWithValue(LogLevel::Info, "sys", "exit rc", code);
        // Batch 59: if the exiting task owns a Win32 thread-handle
        // slot in its Process, record the exit code there so
        // GetExitCodeThread on that handle can return a real
        // value instead of STILL_ACTIVE.
        Process* proc = CurrentProcess();
        sched::Task* self = sched::CurrentTask();
        if (proc != nullptr && self != nullptr)
        {
            for (u32 i = 0; i < Process::kWin32ThreadCap; ++i)
            {
                if (proc->win32_threads[i].in_use && proc->win32_threads[i].task == self)
                {
                    proc->win32_threads[i].exit_code = static_cast<u32>(code & 0xFFFFFFFFu);
                    break;
                }
            }
        }
        // SchedExit is [[noreturn]] — it marks the current task Dead,
        // wakes the reaper, and Schedule()s away forever. The trap
        // frame on this task's kernel stack becomes orphaned and
        // will be KFree'd by the reaper along with the stack itself.
        sched::SchedExit();
        DEBUG_UNREACHABLE("syscall", "SYS_EXIT returned from SchedExit");
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
        // Read the current Task's Win32 last-error slot. Windows
        // LastError is thread-local; keeping it on Task preserves
        // that contract even while the v0 TEB page is still mostly
        // read-only scaffolding. Kernel-only callers defensively see
        // ERROR_SUCCESS.
        frame->rax = u64(sched::CurrentTaskWin32LastError());
        return;
    }

    case SYS_SETLASTERROR:
    {
        // Write rdi (low 32 bits) into the current Task's Win32
        // last-error slot. Win32 SetLastError is void, but we keep
        // returning the previous value in rax for diagnostics and
        // for parity with the historical syscall behavior.
        const u32 new_err = u32(frame->rdi & 0xFFFFFFFFULL);
        frame->rax = u64(sched::SetCurrentTaskWin32LastError(new_err));

        // Win32 custom error-provenance hook — records the RIP that
        // just stamped the error so a debugger can answer "where did
        // this code come from?" in one shot. The provenance record
        // remains process-scoped because it is diagnostic metadata,
        // not the LastError slot itself.
        Process* proc = CurrentProcess();
        if (proc != nullptr)
        {
            subsystems::win32::custom::OnLastErrorSet(proc, new_err, frame->rip, static_cast<u32>(SYS_SETLASTERROR));
        }
        return;
    }

    case SYS_WIN32_CUSTOM:
        subsystems::win32::custom::DoCustom(frame);
        return;

    case SYS_REGISTRY:
        subsystems::win32::registry::DoRegistry(frame);
        return;

    case SYS_PROCESS_OPEN:
    {
        // NtOpenProcess: PID in rdi → kernel handle in rax (or 0 on
        // any failure). Cap-gated on kCapDebug — see syscall.h. The
        // refcount held on the target keeps it alive past its task's
        // exit; CloseHandle drops it.
        Process* caller = CurrentProcess();
        if (caller == nullptr || !CapSetHas(caller->caps, kCapDebug))
        {
            RecordSandboxDenial(kCapDebug);
            if (caller != nullptr && ShouldLogDenial(caller->sandbox_denials))
            {
                arch::SerialWrite("[sys] denied syscall=SYS_PROCESS_OPEN pid=");
                arch::SerialWriteHex(caller->pid);
                arch::SerialWrite(" cap=Debug denial_idx=");
                arch::SerialWriteHex(caller->sandbox_denials);
                arch::SerialWrite("\n");
            }
            frame->rax = 0;
            return;
        }
        const u64 target_pid = frame->rdi;
        Process* target = sched::SchedFindProcessByPid(target_pid);
        if (target == nullptr)
        {
            frame->rax = 0;
            return;
        }
        u64 idx = Process::kWin32ProcessCap;
        for (u64 i = 0; i < Process::kWin32ProcessCap; ++i)
        {
            if (!caller->win32_proc_handles[i].in_use)
            {
                idx = i;
                break;
            }
        }
        if (idx == Process::kWin32ProcessCap)
        {
            frame->rax = 0; // table full
            return;
        }
        ProcessRetain(target);
        caller->win32_proc_handles[idx].in_use = true;
        caller->win32_proc_handles[idx].target = target;
        frame->rax = Process::kWin32ProcessBase + idx;
        return;
    }

    case SYS_PROCESS_VM_READ:
    case SYS_PROCESS_VM_WRITE:
    {
        Process* caller = CurrentProcess();
        if (caller == nullptr || !CapSetHas(caller->caps, kCapDebug))
        {
            RecordSandboxDenial(kCapDebug);
            frame->rax = kStatusAccessDenied;
            return;
        }
        Process* target = LookupProcessHandle(caller, frame->rdi);
        if (target == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        const u64 target_va = frame->rsi;
        void* caller_buf = reinterpret_cast<void*>(frame->rdx);
        u64 len = frame->r10;
        const u64 bytes_out_va = frame->r8;

        if (len > kSyscallProcessVmMax)
        {
            len = kSyscallProcessVmMax;
        }

        u64 moved = 0;
        const bool ok = CrossAsTransfer(target, target_va, caller_buf, len,
                                        (num == SYS_PROCESS_VM_READ) ? CrossAsDir::Read : CrossAsDir::Write, &moved);

        if (bytes_out_va != 0)
        {
            // Best-effort writeback. If the caller's out-pointer
            // is bogus the transfer status still carries the
            // truth in rax — we don't escalate a writeback miss
            // into a different NTSTATUS.
            mm::CopyToUser(reinterpret_cast<void*>(bytes_out_va), &moved, sizeof(moved));
        }

        frame->rax = ok ? kStatusSuccess : kStatusAccessViolation;
        return;
    }

    case SYS_PROCESS_VM_QUERY:
    {
        Process* caller = CurrentProcess();
        if (caller == nullptr || !CapSetHas(caller->caps, kCapDebug))
        {
            RecordSandboxDenial(kCapDebug);
            frame->rax = kStatusAccessDenied;
            return;
        }
        Process* target = LookupProcessHandle(caller, frame->rdi);
        if (target == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        const u64 probe_va = frame->rsi;
        void* out_user = reinterpret_cast<void*>(frame->rdx);
        if (out_user == nullptr)
        {
            frame->rax = kStatusInvalidParameter;
            return;
        }

        const u64 page_va = probe_va & ~0xFFFULL;
        const mm::PhysAddr frame_pa = mm::AddressSpaceLookupUserFrame(target->as, page_va);
        Win32MemoryBasicInfo info{};
        info.base_address = page_va;
        info.allocation_base = page_va;
        info.region_size = mm::kPageSize;
        if (frame_pa != mm::kNullFrame)
        {
            info.state = kMemCommit;
            info.allocation_protect = kPageReadWrite;
            info.protect = kPageReadWrite;
            info.type = kMemPrivate;
        }
        else
        {
            info.state = kMemFree;
            info.allocation_protect = 0;
            info.protect = 0;
            info.type = 0;
        }

        if (!mm::CopyToUser(out_user, &info, sizeof(info)))
        {
            frame->rax = kStatusAccessViolation;
            return;
        }
        frame->rax = kStatusSuccess;
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

    // Time family: handlers live in kernel/syscall/time_syscall.cpp
    // so the dispatcher is a thin router. Same ABI, same rax
    // contract — the extraction only moves code, not behaviour.
    case SYS_PERF_COUNTER:
        DoPerfCounter(frame);
        return;
    case SYS_SYSTEM_PERFORMANCE_INFO:
    {
        if (frame->rdi == 0 || frame->rsi < sizeof(SystemPerformanceInfo))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

        const u64 total_frames = mm::TotalFrames();
        const u64 free_frames = mm::FreeFramesCount();
        const u64 used_frames = (total_frames >= free_frames) ? (total_frames - free_frames) : 0;
        const auto sched_stats = sched::SchedStatsRead();

        SystemPerformanceInfo info{};
        info.cb = static_cast<u32>(sizeof(SystemPerformanceInfo));
        info.CommitTotal = used_frames;
        info.CommitLimit = total_frames;
        info.CommitPeak = mm::PeakUsedFrames();
        info.PhysicalTotal = total_frames;
        info.PhysicalAvailable = free_frames;
        // These Windows fields require ledgers DuetOS does not keep yet
        // (cache residency, paged/nonpaged pool, global handle total).
        // Leave them zero rather than publishing fabricated values.
        info.SystemCache = 0;
        info.KernelTotal = 0;
        info.KernelPaged = 0;
        info.KernelNonpaged = 0;
        info.PageSize = mm::kPageSize;
        info.HandleCount = 0;
        info.ProcessCount = static_cast<u32>(ProcessLiveCount());
        info.ThreadCount = static_cast<u32>(sched_stats.tasks_live);

        if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rdi), &info, sizeof(info)))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        frame->rax = 0;
        return;
    }
    case SYS_NAMED_KOBJ_OPEN_OR_CREATE:
        ::duetos::subsystems::win32::DoNamedKObjOpenOrCreate(frame);
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
        KBP_PROBE_V(::duetos::debug::ProbeId::kWin32StubMiss, frame->rdi);

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
    case SYS_FILE_UNLINK:
        subsystems::win32::DoFileUnlink(frame);
        return;
    case SYS_FILE_RENAME:
        subsystems::win32::DoFileRename(frame);
        return;
    case SYS_FILE_MKDIR:
        subsystems::win32::DoFileMkdir(frame);
        return;
    case SYS_FILE_SYMLINK:
        subsystems::win32::DoFileSymlink(frame);
        return;
    case SYS_FILE_LINK:
        subsystems::win32::DoFileLink(frame);
        return;
    case SYS_FILE_READLINK:
        subsystems::win32::DoFileReadlink(frame);
        return;

    case SYS_PROCESS_TERMINATE:
    {
        // rdi = ProcessHandle (NtCurrentProcess() = -1 for self),
        // rsi = exit status. Self path bypasses the handle table
        // and goes straight to SchedExit; foreign path requires
        // kCapDebug.
        Process* caller = CurrentProcess();
        if (caller == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        const u64 handle = frame->rdi;
        constexpr u64 kCurrentProcess = static_cast<u64>(-1);
        if (handle == kCurrentProcess)
        {
            // Self-terminate. Whole-process semantics: kill every
            // sibling task in this Process before the calling
            // task exits, so a multi-threaded PE that calls
            // NtTerminateProcess(NtCurrentProcess()) actually
            // brings the whole task group down rather than just
            // the caller.
            (void)sched::SchedKillByProcess(caller);
            sched::SchedExit();
        }
        if (!CapSetHas(caller->caps, kCapDebug))
        {
            RecordSandboxDenial(kCapDebug);
            frame->rax = kStatusAccessDenied;
            return;
        }
        Process* target = LookupProcessHandle(caller, handle);
        if (target == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        const u64 killed = sched::SchedKillByProcess(target);
        frame->rax = killed; // count of tasks signalled
        return;
    }

    case SYS_THREAD_TERMINATE:
    {
        Process* caller = CurrentProcess();
        if (caller == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        const u64 handle = frame->rdi;
        constexpr u64 kCurrentThread = static_cast<u64>(-2);
        if (handle == kCurrentThread)
        {
            // Self-thread-exit. Same SchedExit path as SYS_EXIT.
            sched::SchedExit();
        }
        // LookupThreadHandle handles BOTH local thread handles
        // (caller->win32_threads[]) and foreign-process thread
        // handles (caller->win32_foreign_threads[] populated by
        // NtOpenThread). The foreign-handle case requires
        // kCapDebug — same gate NtOpenThread itself imposes.
        if (handle >= Process::kWin32ForeignThreadBase &&
            handle < Process::kWin32ForeignThreadBase + Process::kWin32ForeignThreadCap)
        {
            if (!CapSetHas(caller->caps, kCapDebug))
            {
                RecordSandboxDenial(kCapDebug);
                frame->rax = kStatusAccessDenied;
                return;
            }
        }
        sched::Task* t = LookupThreadHandle(caller, handle);
        if (t == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        const sched::KillResult r = sched::SchedKillByPid(sched::TaskId(t));
        if (r == sched::KillResult::Signaled || r == sched::KillResult::Blocked)
        {
            frame->rax = kStatusSuccess;
            return;
        }
        if (r == sched::KillResult::AlreadyDead)
        {
            frame->rax = kStatusSuccess; // Windows treats already-dead as success
            return;
        }
        frame->rax = kStatusInvalidHandle;
        return;
    }

    case SYS_PROCESS_QUERY_INFO:
    {
        // rdi = ProcessHandle (-1 for self), rsi = info class
        // (only ProcessBasicInformation = 0 honoured in v0),
        // rdx = user buffer, r10 = buffer cap,
        // r8 = user u32* return_length.
        Process* caller = CurrentProcess();
        if (caller == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        const u64 handle = frame->rdi;
        const u64 info_class = frame->rsi;
        const u64 user_buf = frame->rdx;
        const u64 buf_cap = frame->r10;
        const u64 user_retlen = frame->r8;
        constexpr u64 kCurrentProcess = static_cast<u64>(-1);
        constexpr u64 kProcessBasicInformation = 0;
        Process* target = caller;
        if (handle != kCurrentProcess)
        {
            if (!CapSetHas(caller->caps, kCapDebug))
            {
                RecordSandboxDenial(kCapDebug);
                frame->rax = kStatusAccessDenied;
                return;
            }
            target = LookupProcessHandle(caller, handle);
            if (target == nullptr)
            {
                frame->rax = kStatusInvalidHandle;
                return;
            }
        }
        if (info_class != kProcessBasicInformation)
        {
            frame->rax = kStatusNotImplemented;
            return;
        }
        // PROCESS_BASIC_INFORMATION layout (48 bytes on x64):
        //   PVOID  Reserved1;        // ExitStatus
        //   PVOID  PebBaseAddress;
        //   PVOID  Reserved2[2];     // AffinityMask, BasePriority
        //   ULONG_PTR UniqueProcessId;
        //   ULONG_PTR Reserved3;     // InheritedFromUniqueProcessId
        struct ProcessBasicInfo
        {
            u64 exit_status;
            u64 peb_base;
            u64 affinity_mask;
            u64 base_priority;
            u64 unique_pid;
            u64 inherited_from_pid;
        };
        ProcessBasicInfo info{};
        info.exit_status = 0; // STILL_ACTIVE if running, 0 here
        info.peb_base = target->user_gs_base;
        info.affinity_mask = 1; // single-CPU v0
        info.base_priority = 8; // NORMAL_PRIORITY_CLASS midpoint
        info.unique_pid = target->pid;
        info.inherited_from_pid = 0;
        if (buf_cap < sizeof(info))
        {
            constexpr u64 kStatusInfoLengthMismatch = 0xC0000004ULL;
            if (user_retlen != 0)
            {
                u32 needed = sizeof(info);
                (void)mm::CopyToUser(reinterpret_cast<void*>(user_retlen), &needed, sizeof(needed));
            }
            frame->rax = kStatusInfoLengthMismatch;
            return;
        }
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_buf), &info, sizeof(info)))
        {
            frame->rax = kStatusAccessViolation;
            return;
        }
        if (user_retlen != 0)
        {
            u32 written = sizeof(info);
            (void)mm::CopyToUser(reinterpret_cast<void*>(user_retlen), &written, sizeof(written));
        }
        frame->rax = kStatusSuccess;
        return;
    }

    case SYS_VM_ALLOCATE:
    {
        // NtAllocateVirtualMemory(handle, *base, *size, type, protect, *out_base).
        // Self path needs no cap; foreign requires kCapDebug.
        Process* caller = CurrentProcess();
        if (caller == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        const u64 handle = frame->rdi;
        const u64 hint_va = frame->rsi;
        const u64 size = frame->rdx;
        const u32 protect = static_cast<u32>(frame->r8);
        const u64 user_out = frame->r9;
        if (size == 0 || size > 0x40000000ULL /* 1 GiB cap */)
        {
            frame->rax = kStatusInvalidParameter;
            return;
        }
        constexpr u64 kCurrentProcess = static_cast<u64>(-1);
        Process* target = caller;
        if (handle != kCurrentProcess)
        {
            if (!CapSetHas(caller->caps, kCapDebug))
            {
                RecordSandboxDenial(kCapDebug);
                frame->rax = kStatusAccessDenied;
                return;
            }
            target = LookupProcessHandle(caller, handle);
            if (target == nullptr)
            {
                frame->rax = kStatusInvalidHandle;
                return;
            }
        }
        // Translate PAGE_* protect to AS PTE flags. W^X is silently
        // enforced — RWX/EXECUTE_WRITECOPY downgrade to RW + NX.
        u64 pte_flags = mm::kPageUser | mm::kPageNoExecute;
        switch (protect & 0xFF)
        {
        case 0x01: // PAGE_NOACCESS — best effort: RO + NX
        case 0x02: // PAGE_READONLY
            break;
        case 0x04: // PAGE_READWRITE
        case 0x08: // PAGE_WRITECOPY (no COW; treat as RW)
        case 0x40: // PAGE_EXECUTE_READWRITE — W^X downgrade
        case 0x80: // PAGE_EXECUTE_WRITECOPY — same
            pte_flags |= mm::kPageWritable;
            break;
        case 0x10: // PAGE_EXECUTE
        case 0x20: // PAGE_EXECUTE_READ
            pte_flags &= ~mm::kPageNoExecute;
            break;
        default:
            frame->rax = kStatusInvalidParameter;
            return;
        }
        const u64 page_size = mm::kPageSize;
        const u64 aligned_size = (size + page_size - 1) & ~(page_size - 1);
        u64 base_va = hint_va;
        if (base_va == 0)
        {
            base_va = target->linux_mmap_cursor;
        }
        else
        {
            base_va &= ~(page_size - 1);
        }
        // Reject ranges that aren't fully inside the canonical user low
        // half. Without this gate a hostile (or buggy) caller can pass
        // hint_va in kernel-half and drive AddressSpaceMapUserPage into
        // PanicAs — a DoS available to any process even without caps.
        constexpr u64 kVmUserMax = 0x00007FFFFFFFFFFFULL;
        if (base_va > kVmUserMax || aligned_size == 0 || (aligned_size - 1) > (kVmUserMax - base_va))
        {
            frame->rax = kStatusInvalidParameter;
            return;
        }
        for (u64 va = base_va; va < base_va + aligned_size; va += page_size)
        {
            const mm::PhysAddr fp = mm::AllocateFrame();
            if (fp == mm::kNullFrame)
            {
                frame->rax = kStatusNoMemory;
                return;
            }
            // Zero-fill — Windows guarantees zero-init.
            u8* kva = static_cast<u8*>(mm::PhysToVirt(fp));
            for (u64 i = 0; i < page_size; ++i)
                kva[i] = 0;
            mm::AddressSpaceMapUserPage(target->as, va, fp, pte_flags | mm::kPagePresent);
        }
        if (hint_va == 0)
            target->linux_mmap_cursor = base_va + aligned_size;
        if (user_out != 0)
        {
            (void)mm::CopyToUser(reinterpret_cast<void*>(user_out), &base_va, sizeof(base_va));
        }
        frame->rax = kStatusSuccess;
        return;
    }

    case SYS_VM_FREE:
    {
        // NtFreeVirtualMemory(handle, base, size, FreeType). v0
        // always releases (MEM_RELEASE / MEM_DECOMMIT collapse
        // onto the same unmap-and-free path).
        Process* caller = CurrentProcess();
        if (caller == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        const u64 handle = frame->rdi;
        const u64 base = frame->rsi;
        const u64 size = frame->rdx;
        constexpr u64 kCurrentProcess = static_cast<u64>(-1);
        Process* target = caller;
        if (handle != kCurrentProcess)
        {
            if (!CapSetHas(caller->caps, kCapDebug))
            {
                RecordSandboxDenial(kCapDebug);
                frame->rax = kStatusAccessDenied;
                return;
            }
            target = LookupProcessHandle(caller, handle);
            if (target == nullptr)
            {
                frame->rax = kStatusInvalidHandle;
                return;
            }
        }
        const u64 page_size = mm::kPageSize;
        const u64 aligned_size = (size + page_size - 1) & ~(page_size - 1);
        const u64 aligned_base = base & ~(page_size - 1);
        for (u64 va = aligned_base; va < aligned_base + aligned_size; va += page_size)
        {
            (void)mm::AddressSpaceUnmapUserPage(target->as, va);
        }
        frame->rax = kStatusSuccess;
        return;
    }

    case SYS_VM_PROTECT:
    {
        // NtProtectVirtualMemory(handle, base, size, new_protect, *old_protect).
        Process* caller = CurrentProcess();
        if (caller == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        const u64 handle = frame->rdi;
        const u64 base = frame->rsi;
        const u64 size = frame->rdx;
        const u32 protect = static_cast<u32>(frame->r10);
        const u64 user_old = frame->r8;
        constexpr u64 kCurrentProcess = static_cast<u64>(-1);
        Process* target = caller;
        if (handle != kCurrentProcess)
        {
            if (!CapSetHas(caller->caps, kCapDebug))
            {
                RecordSandboxDenial(kCapDebug);
                frame->rax = kStatusAccessDenied;
                return;
            }
            target = LookupProcessHandle(caller, handle);
            if (target == nullptr)
            {
                frame->rax = kStatusInvalidHandle;
                return;
            }
        }
        u64 pte_flags = mm::kPageUser | mm::kPageNoExecute;
        switch (protect & 0xFF)
        {
        case 0x01:
        case 0x02:
            break;
        case 0x04:
        case 0x08:
        case 0x40:
        case 0x80:
            pte_flags |= mm::kPageWritable;
            break;
        case 0x10:
        case 0x20:
            pte_flags &= ~mm::kPageNoExecute;
            break;
        default:
            frame->rax = kStatusInvalidParameter;
            return;
        }
        const u64 page_size = mm::kPageSize;
        const u64 aligned_size = (size + page_size - 1) & ~(page_size - 1);
        const u64 aligned_base = base & ~(page_size - 1);
        // Same gate as SYS_VM_ALLOCATE: AddressSpaceProtectUserPage
        // panics on a kernel-half virt, so refuse out-of-range inputs
        // here instead of letting an unprivileged caller DoS the kernel.
        constexpr u64 kVmUserMax = 0x00007FFFFFFFFFFFULL;
        if (aligned_base > kVmUserMax || aligned_size == 0 || (aligned_size - 1) > (kVmUserMax - aligned_base))
        {
            frame->rax = kStatusInvalidParameter;
            return;
        }
        u32 first_old_protect = 0x04; // best-effort: PAGE_READWRITE
        for (u64 va = aligned_base; va < aligned_base + aligned_size; va += page_size)
        {
            (void)mm::AddressSpaceProtectUserPage(target->as, va, pte_flags | mm::kPagePresent);
        }
        if (user_old != 0)
        {
            (void)mm::CopyToUser(reinterpret_cast<void*>(user_old), &first_old_protect, sizeof(first_old_protect));
        }
        frame->rax = kStatusSuccess;
        return;
    }

    case SYS_EXECVE:
    {
        // In-place image replacement. Read the file, tear down
        // the AS user mappings, ElfLoad into the same AS, reset
        // the trap frame's RIP/RSP. The syscall return path's
        // iretq picks up the new RIP via the trap frame, so we
        // don't return into the caller — we return into the new
        // program.
        // kCapFsRead + kCapSpawnThread are gated centrally by
        // `SyscallGate` (cap_table.def) — a process missing either
        // cap returns -1 from the gate before reaching this handler.
        Process* caller = CurrentProcess();
        if (caller == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 user_path = frame->rdi;
        const u64 path_len = frame->rsi;
        if (path_len == 0 || path_len >= 256)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        char kpath[256];
        if (!mm::CopyUserCString(kpath, path_len + 1, reinterpret_cast<const void*>(user_path)).ok())
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

        // Path lookup — fat32-only (matches §11.18 stat). Parse
        // /disk/<idx>/<rest> inline (the routing-side helper is
        // file-local in fs/file_route.cpp).
        u32 disk_idx = 0;
        const char* leaf = nullptr;
        {
            constexpr const char* kPrefix = "/disk/";
            constexpr u32 kPrefixLen = 6;
            if (path_len <= kPrefixLen)
            {
                frame->rax = static_cast<u64>(-1);
                return;
            }
            for (u32 i = 0; i < kPrefixLen; ++i)
            {
                if (kpath[i] != kPrefix[i])
                {
                    frame->rax = static_cast<u64>(-1);
                    return;
                }
            }
            u32 i = kPrefixLen;
            while (i < path_len && kpath[i] >= '0' && kpath[i] <= '9')
            {
                disk_idx = disk_idx * 10 + static_cast<u32>(kpath[i] - '0');
                ++i;
            }
            if (i == kPrefixLen || i >= path_len || kpath[i] != '/')
            {
                frame->rax = static_cast<u64>(-1);
                return;
            }
            leaf = &kpath[i + 1];
        }
        if (disk_idx >= fs::fat32::kMaxVolumes)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        char mount_point[16] = {};
        if (!fs::VfsFormatDiskMountPoint(disk_idx, mount_point, sizeof(mount_point)) ||
            !fs::VfsMountVisibleFromRoot(caller->root, mount_point))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

        const fs::fat32::Volume* v = fs::fat32::Fat32Volume(disk_idx);
        if (v == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        fs::fat32::DirEntry e;
        if (!fs::fat32::Fat32LookupPath(v, leaf, &e))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        // Cap the image at 1 MiB to bound the kheap allocation.
        // Bigger binaries need a streaming load; sub-GAP.
        constexpr u64 kExecveMaxImage = 1ULL << 20;
        if (e.size_bytes == 0 || e.size_bytes > kExecveMaxImage)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        u8* buf = static_cast<u8*>(mm::KMalloc(e.size_bytes));
        if (buf == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const i64 nread = fs::fat32::Fat32ReadFile(v, &e, buf, e.size_bytes);
        if (nread != static_cast<i64>(e.size_bytes))
        {
            mm::KFree(buf);
            frame->rax = static_cast<u64>(-1);
            return;
        }

        // Tear down the AS user mappings, then ElfLoad into the
        // same AS. Past this point any failure is fatal — the
        // caller's address space is already gone.
        mm::AddressSpaceClearUserMappings(caller->as);
        const core::ElfLoadResult r = core::ElfLoad(buf, e.size_bytes, caller->as);
        mm::KFree(buf);
        if (!r.ok)
        {
            // No way back — terminate the calling task.
            arch::SerialWrite("[execve] ElfLoad failed; terminating task pid=");
            arch::SerialWriteHex(caller->pid);
            arch::SerialWrite("\n");
            sched::SchedExit();
        }

        // Reset the trap frame so iretq lands at the new entry.
        // Sanitise rflags (IF=1, no IOPL/TF/NT) + cs/ss to
        // ring-3 selectors, same shape as §11.7's SetContext
        // path. Argv/envp are ignored in v0 — static ELFs that
        // don't read them work; sub-GAP for everyone else.
        frame->rip = r.entry_va;
        frame->rsp = r.stack_top;
        frame->rax = 0;
        frame->rbx = 0;
        frame->rcx = 0;
        frame->rdx = 0;
        frame->rsi = 0;
        frame->rdi = 0;
        frame->rbp = 0;
        frame->r8 = 0;
        frame->r9 = 0;
        frame->r10 = 0;
        frame->r11 = 0;
        frame->r12 = 0;
        frame->r13 = 0;
        frame->r14 = 0;
        frame->r15 = 0;
        // cs/ss/rflags from a known-good user state.
        frame->cs = 0x2B;
        frame->ss = 0x33;
        frame->rflags = 0x202;
        arch::SerialWrite("[execve] task pid=");
        arch::SerialWriteHex(caller->pid);
        arch::SerialWrite(" -> ");
        arch::SerialWrite(kpath);
        arch::SerialWrite(" entry=");
        arch::SerialWriteHex(r.entry_va);
        arch::SerialWrite(" rsp=");
        arch::SerialWriteHex(r.stack_top);
        arch::SerialWrite("\n");
        return;
    }

    case SYS_SOCKET_OP:
    {
        // Win32 ws2_32 + native socket userland → kernel socket
        // pool. kCapNet is gated centrally by `SyscallGate`
        // (cap_table.def); a process missing the cap returns -1
        // from the gate before reaching this handler.
        Process* caller = CurrentProcess();
        if (caller == nullptr)
        {
            frame->rax = static_cast<u64>(-13); // -EACCES
            return;
        }
        const u64 op = frame->rdi;
        struct LinuxSockaddrIn
        {
            u16 sin_family;
            u16 sin_port_be;
            u8 sin_addr[4];
            u8 sin_zero[8];
        };
        auto read_sa = [](u64 user_addr, u64 len, ::duetos::net::Ipv4Address& ip, u16& port) -> bool
        {
            if (len < sizeof(LinuxSockaddrIn))
                return false;
            LinuxSockaddrIn sa;
            if (!mm::CopyFromUser(&sa, reinterpret_cast<const void*>(user_addr), sizeof(sa)))
                return false;
            if (sa.sin_family != 2)
                return false;
            port = (u16(sa.sin_port_be & 0xFF) << 8) | u16(sa.sin_port_be >> 8);
            for (u32 i = 0; i < 4; ++i)
                ip.octets[i] = sa.sin_addr[i];
            return true;
        };
        auto write_sa = [](u64 user_addr, u64 user_addrlen_ptr, ::duetos::net::Ipv4Address ip, u16 port) -> bool
        {
            if (user_addr == 0)
                return true;
            u32 cap = 0;
            if (user_addrlen_ptr != 0 &&
                !mm::CopyFromUser(&cap, reinterpret_cast<const void*>(user_addrlen_ptr), sizeof(cap)))
                return false;
            if (user_addrlen_ptr == 0)
                cap = sizeof(LinuxSockaddrIn);
            LinuxSockaddrIn sa = {};
            sa.sin_family = 2;
            sa.sin_port_be = u16(((port & 0xFF) << 8) | (port >> 8));
            for (u32 i = 0; i < 4; ++i)
                sa.sin_addr[i] = ip.octets[i];
            const u32 to_write = (cap < sizeof(sa)) ? cap : sizeof(sa);
            if (to_write > 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_addr), &sa, to_write))
                return false;
            if (user_addrlen_ptr != 0)
            {
                const u32 truth = sizeof(sa);
                if (!mm::CopyToUser(reinterpret_cast<void*>(user_addrlen_ptr), &truth, sizeof(truth)))
                    return false;
            }
            return true;
        };
        i64 rv = -22; // -EINVAL default
        switch (op)
        {
        case kSockOpCreate:
        {
            const i32 idx = ::duetos::net::SocketAlloc(static_cast<u16>(frame->rsi), static_cast<u16>(frame->rdx));
            rv = (idx < 0) ? -23 /* -ENFILE */ : static_cast<i64>(idx);
            break;
        }
        case kSockOpBind:
        {
            ::duetos::net::Ipv4Address ip;
            u16 port;
            if (!read_sa(frame->rdx, frame->r10, ip, port))
            {
                rv = -22;
                break;
            }
            rv = ::duetos::net::SocketBind(static_cast<u32>(frame->rsi), ip, port) ? 0 : -98 /* -EADDRINUSE */;
            break;
        }
        case kSockOpConnect:
        {
            ::duetos::net::Ipv4Address ip;
            u16 port;
            if (!read_sa(frame->rdx, frame->r10, ip, port))
            {
                rv = -22;
                break;
            }
            rv = ::duetos::net::SocketConnect(static_cast<u32>(frame->rsi), ip, port) ? 0 : -100 /* -ENETDOWN */;
            break;
        }
        case kSockOpListen:
            rv = ::duetos::net::SocketListen(static_cast<u32>(frame->rsi), static_cast<u32>(frame->rdx)) ? 0 : -22;
            break;
        case kSockOpAccept:
        {
            // Polling-style accept (matches Linux ABI shape).
            const u32 listen_idx = static_cast<u32>(frame->rsi);
            while (true)
            {
                const auto snap = ::duetos::net::NetTcpActiveSnapshot();
                if (snap.in_use && snap.response_len > 0)
                    break;
                sched::SchedYield();
            }
            const i32 new_idx =
                ::duetos::net::SocketAlloc(::duetos::net::kSocketDomainInet, ::duetos::net::kSocketTypeStream);
            if (new_idx < 0)
            {
                rv = -23;
                break;
            }
            ::duetos::net::Ipv4Address peer_ip;
            u16 peer_port;
            ::duetos::net::SocketGetPeer(listen_idx, &peer_ip, &peer_port);
            ::duetos::net::SocketConnect(static_cast<u32>(new_idx), peer_ip, peer_port);
            (void)write_sa(frame->rdx, frame->r10, peer_ip, peer_port);
            rv = static_cast<i64>(new_idx);
            break;
        }
        case kSockOpSendto:
        {
            constexpr u64 kStageCap = 1500;
            u64 len = frame->r10;
            if (len > kStageCap)
                len = kStageCap;
            u8 stage[kStageCap];
            if (len > 0 && !mm::CopyFromUser(stage, reinterpret_cast<const void*>(frame->rdx), len))
            {
                rv = -14; // -EFAULT
                break;
            }
            ::duetos::net::Ipv4Address dst_ip = {};
            u16 dst_port = 0;
            if (frame->r8 != 0)
            {
                if (!read_sa(frame->r8, frame->r9, dst_ip, dst_port))
                {
                    rv = -22;
                    break;
                }
            }
            const auto* s = ::duetos::net::SocketGet(static_cast<u32>(frame->rsi));
            if (s == nullptr)
            {
                rv = -9; // -EBADF
                break;
            }
            if (s->type == ::duetos::net::kSocketTypeDgram)
                rv = ::duetos::net::SocketSendDgram(static_cast<u32>(frame->rsi), dst_ip, dst_port, stage,
                                                    static_cast<u32>(len));
            else
                rv = ::duetos::net::SocketSendStream(static_cast<u32>(frame->rsi), stage, static_cast<u32>(len));
            break;
        }
        case kSockOpRecvfrom:
        {
            constexpr u64 kStageCap = 1500;
            u64 cap = frame->r10;
            if (cap > kStageCap)
                cap = kStageCap;
            u8 stage[kStageCap];
            const auto* s = ::duetos::net::SocketGet(static_cast<u32>(frame->rsi));
            if (s == nullptr)
            {
                rv = -9;
                break;
            }
            if (s->type == ::duetos::net::kSocketTypeDgram)
            {
                ::duetos::net::Ipv4Address src_ip = {};
                u16 src_port = 0;
                u32 truth = 0;
                rv = ::duetos::net::SocketRecvDgram(static_cast<u32>(frame->rsi), stage, static_cast<u32>(cap), &truth,
                                                    &src_ip, &src_port);
                if (rv > 0 && !mm::CopyToUser(reinterpret_cast<void*>(frame->rdx), stage, static_cast<u64>(rv)))
                {
                    rv = -14;
                    break;
                }
                (void)write_sa(frame->r8, frame->r9, src_ip, src_port);
            }
            else
            {
                rv = ::duetos::net::SocketRecvStream(static_cast<u32>(frame->rsi), stage, static_cast<u32>(cap));
                if (rv > 0 && !mm::CopyToUser(reinterpret_cast<void*>(frame->rdx), stage, static_cast<u64>(rv)))
                    rv = -14;
            }
            break;
        }
        case kSockOpShutdown:
            rv = ::duetos::net::SocketShutdown(static_cast<u32>(frame->rsi), static_cast<u32>(frame->rdx)) ? 0 : -22;
            break;
        case kSockOpClose:
            ::duetos::net::SocketRelease(static_cast<u32>(frame->rsi));
            rv = 0;
            break;
        case kSockOpGetSock:
        {
            ::duetos::net::Ipv4Address ip;
            u16 port;
            ::duetos::net::SocketGetLocal(static_cast<u32>(frame->rsi), &ip, &port);
            rv = write_sa(frame->rdx, frame->r10, ip, port) ? 0 : -14;
            break;
        }
        case kSockOpGetPeer:
        {
            ::duetos::net::Ipv4Address ip;
            u16 port;
            ::duetos::net::SocketGetPeer(static_cast<u32>(frame->rsi), &ip, &port);
            rv = write_sa(frame->rdx, frame->r10, ip, port) ? 0 : -14;
            break;
        }
        case kSockOpResolveA:
        {
            char host[257] = {};
            const auto host_copy = mm::CopyUserCString(host, sizeof(host), reinterpret_cast<const void*>(frame->rsi));
            if (!host_copy.ok())
            {
                rv = (host_copy.status == mm::UserStringCopyStatus::NoTerminator) ? -36 : -14;
                break;
            }
            const auto lease = ::duetos::net::DhcpLeaseRead();
            if (!lease.valid)
            {
                rv = -100;
                break;
            }
            if (!::duetos::net::NetDnsQueryA(/*iface_index=*/0, lease.dns, host))
            {
                rv = -22;
                break;
            }
            ::duetos::net::DnsResult dns{};
            for (u32 i = 0; i < 300; ++i)
            {
                ::duetos::sched::SchedSleepTicks(1);
                dns = ::duetos::net::NetDnsResultRead();
                if (dns.resolved)
                    break;
            }
            if (!dns.resolved)
            {
                rv = -110;
                break;
            }
            const u32 be = (u32(dns.ip.octets[0])) | (u32(dns.ip.octets[1]) << 8) | (u32(dns.ip.octets[2]) << 16) |
                           (u32(dns.ip.octets[3]) << 24);
            if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rdx), &be, sizeof(be)))
            {
                rv = -14;
                break;
            }
            rv = 0;
            break;
        }
        case kSockOpGetLease:
        {
            // Snapshot the kernel's DHCP lease state into the
            // user-supplied SocketLeaseInfo buffer (40 bytes).
            // See syscall.h for the field layout.
            struct SocketLeaseInfo
            {
                u32 valid;
                u32 ip_be;
                u32 netmask_be;
                u32 gateway_be;
                u32 dns_be;
                u32 lease_seconds;
                u8 mac[6];
                u8 iface_index;
                u8 reserved0;
                u8 reserved1[8];
            };
            static_assert(sizeof(SocketLeaseInfo) == 40, "SocketLeaseInfo must be 40 bytes");
            const u64 cap = frame->rdx;
            if (cap < sizeof(SocketLeaseInfo))
            {
                rv = -34; // ERANGE
                break;
            }
            SocketLeaseInfo info{};
            const auto lease = ::duetos::net::DhcpLeaseRead();
            info.valid = lease.valid ? 1u : 0u;
            const auto pack_be = [](const ::duetos::net::Ipv4Address& a) -> u32 {
                return (u32(a.octets[0])) | (u32(a.octets[1]) << 8) | (u32(a.octets[2]) << 16) |
                       (u32(a.octets[3]) << 24);
            };
            info.ip_be = pack_be(lease.ip);
            info.gateway_be = pack_be(lease.router);
            info.dns_be = pack_be(lease.dns);
            info.lease_seconds = lease.lease_secs;
            // No netmask in DhcpLease; default to /24 when valid so
            // iphlpapi consumers don't see a 0.0.0.0 mask.
            info.netmask_be = lease.valid ? 0x00FFFFFFu : 0u; // 255.255.255.0 in network byte order
            info.iface_index = 0;
            const auto mac = ::duetos::net::InterfaceMac(0);
            for (u32 i = 0; i < 6; ++i)
                info.mac[i] = mac.octets[i];
            if (!mm::CopyToUser(reinterpret_cast<void*>(frame->rsi), &info, sizeof(info)))
            {
                rv = -14;
                break;
            }
            rv = 0;
            break;
        }
        }
        frame->rax = static_cast<u64>(rv);
        return;
    }

    case SYS_DIR_OPEN:
    {
        const i64 rv = ::duetos::subsystems::win32::SysDirOpen(frame->rdi);
        frame->rax = static_cast<u64>(rv);
        return;
    }

    case SYS_DIR_NEXT:
    {
        const i64 rv = ::duetos::subsystems::win32::SysDirNext(frame->rdi, frame->rsi);
        frame->rax = static_cast<u64>(rv);
        return;
    }

    case SYS_DIR_REWIND:
    {
        const i64 rv = ::duetos::subsystems::win32::SysDirRewind(frame->rdi);
        frame->rax = static_cast<u64>(rv);
        return;
    }

    case SYS_DIR_NOTIFY:
    {
        const i64 rv =
            ::duetos::subsystems::win32::SysDirNotify(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        frame->rax = static_cast<u64>(rv);
        return;
    }

    case SYS_PROCESS_SPAWN:
    {
        const i64 rv = ::duetos::subsystems::win32::SysProcessSpawn(frame->rdi, frame->rsi);
        frame->rax = static_cast<u64>(rv);
        return;
    }

    case SYS_IOCP_CREATE:
        frame->rax = static_cast<u64>(::duetos::subsystems::win32::SysIocpCreate());
        return;
    case SYS_IOCP_SET:
        frame->rax = static_cast<u64>(
            ::duetos::subsystems::win32::SysIocpSet(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8));
        return;
    case SYS_IOCP_REMOVE:
        frame->rax = static_cast<u64>(
            ::duetos::subsystems::win32::SysIocpRemove(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8));
        return;
    case SYS_IOCP_CLOSE:
        frame->rax = static_cast<u64>(::duetos::subsystems::win32::SysIocpClose(frame->rdi));
        return;
    case SYS_JOB_CREATE:
        frame->rax = static_cast<u64>(::duetos::subsystems::win32::SysJobCreate());
        return;
    case SYS_JOB_ASSIGN:
        frame->rax = static_cast<u64>(::duetos::subsystems::win32::SysJobAssign(frame->rdi, frame->rsi));
        return;
    case SYS_JOB_IS_IN:
        frame->rax =
            static_cast<u64>(::duetos::subsystems::win32::SysJobIsProcessIn(frame->rdi, frame->rsi, frame->rdx));
        return;
    case SYS_JOB_TERMINATE:
        frame->rax = static_cast<u64>(::duetos::subsystems::win32::SysJobTerminate(frame->rdi, frame->rsi));
        return;
    case SYS_JOB_QUERY:
        frame->rax =
            static_cast<u64>(::duetos::subsystems::win32::SysJobQuery(frame->rdi, frame->rsi, frame->rdx, frame->r10));
        return;
    case SYS_JOB_CLOSE:
        frame->rax = static_cast<u64>(::duetos::subsystems::win32::SysJobClose(frame->rdi));
        return;

    case SYS_TOKEN_ADJUST:
    {
        const i64 rv =
            ::duetos::subsystems::win32::SysTokenAdjust(frame->rdi, frame->rsi, frame->rdx, frame->r10, frame->r8);
        frame->rax = static_cast<u64>(rv);
        return;
    }

    case SYS_FILE_QUERY_ATTRIBUTES:
    {
        // Path-based file stat. Wires through fs::routing's
        // StatPathForProcess (fat32-only in v0).
        const u64 user_path = frame->rdi;
        const u64 path_len = frame->rsi;
        const u64 user_out = frame->rdx;
        const u64 buf_cap = frame->r10;
        constexpr u64 kFileBasicInfoBytes = 56;
        if (buf_cap < kFileBasicInfoBytes || user_out == 0)
        {
            frame->rax = kStatusInvalidParameter;
            return;
        }
        if (path_len == 0 || path_len >= 256)
        {
            frame->rax = kStatusInvalidParameter;
            return;
        }
        char kpath[256];
        if (!mm::CopyUserCString(kpath, path_len + 1, reinterpret_cast<const void*>(user_path)).ok())
        {
            frame->rax = kStatusAccessViolation;
            return;
        }
        u64 size = 0;
        bool is_dir = false;
        Process* caller = CurrentProcess();
        if (!fs::routing::StatPathForProcess(caller, kpath, &size, &is_dir))
        {
            constexpr u64 kStatusObjectNameNotFound = 0xC0000034ULL;
            frame->rax = kStatusObjectNameNotFound;
            return;
        }
        // Pack FILE_NETWORK_OPEN_INFORMATION (56 bytes):
        //   [0..8)   CreationTime    — 0 (no metadata)
        //   [8..16)  LastAccessTime  — 0
        //   [16..24) LastWriteTime   — 0
        //   [24..32) ChangeTime      — 0
        //   [32..40) AllocationSize  — page-rounded size
        //   [40..48) EndOfFile       — file size
        //   [48..52) FileAttributes  — 0x10 directory, else 0x80 normal
        //   [52..56) Reserved        — 0
        u8 buf[kFileBasicInfoBytes];
        for (u32 i = 0; i < kFileBasicInfoBytes; ++i)
            buf[i] = 0;
        const u64 alloc_size = (size + 4095) & ~4095ULL;
        for (u32 i = 0; i < 8; ++i)
            buf[32 + i] = static_cast<u8>((alloc_size >> (i * 8)) & 0xFF);
        for (u32 i = 0; i < 8; ++i)
            buf[40 + i] = static_cast<u8>((size >> (i * 8)) & 0xFF);
        const u32 attrs = is_dir ? 0x10u : 0x80u;
        for (u32 i = 0; i < 4; ++i)
            buf[48 + i] = static_cast<u8>((attrs >> (i * 8)) & 0xFF);
        if (!mm::CopyToUser(reinterpret_cast<void*>(user_out), buf, kFileBasicInfoBytes))
        {
            frame->rax = kStatusAccessViolation;
            return;
        }
        frame->rax = kStatusSuccess;
        return;
    }

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

    case SYS_SECTION_CREATE:
    {
        // NtCreateSection(MaximumSize, PageProtection): allocate
        // a pagefile-backed section pool entry + frames + plant
        // a handle in the calling Process. Caller can then
        // NtMapViewOfSection it into self or a foreign target.
        Process* caller = CurrentProcess();
        if (caller == nullptr)
        {
            frame->rax = 0;
            return;
        }
        const u64 size_bytes = frame->rdi;
        const u32 page_protect = static_cast<u32>(frame->rsi);
        const i32 pool_idx = subsystems::win32::section::SectionCreate(size_bytes, page_protect);
        if (pool_idx < 0)
        {
            frame->rax = 0;
            return;
        }
        u64 handle_idx = Process::kWin32SectionCap;
        for (u64 i = 0; i < Process::kWin32SectionCap; ++i)
        {
            if (!caller->win32_section_handles[i].in_use)
            {
                handle_idx = i;
                break;
            }
        }
        if (handle_idx == Process::kWin32SectionCap)
        {
            // Section allocated but no handle slot; release it
            // so we don't leak the frames + pool entry.
            subsystems::win32::section::SectionRelease(static_cast<u32>(pool_idx));
            frame->rax = 0;
            return;
        }
        caller->win32_section_handles[handle_idx].in_use = true;
        caller->win32_section_handles[handle_idx].pool_index = static_cast<u32>(pool_idx);
        frame->rax = Process::kWin32SectionBase + handle_idx;
        return;
    }

    case SYS_SECTION_MAP:
    {
        // NtMapViewOfSection(SectionHandle, ProcessHandle,
        //   inout BaseAddress*, inout ViewSize*, ViewProtect)
        // — install a borrowed-page view of `section` into
        // either the caller's AS (process_handle == -1, the
        // NtCurrentProcess pseudo-handle) or a foreign target's
        // AS (cap-gated on kCapDebug).
        Process* caller = CurrentProcess();
        if (caller == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        const u64 section_handle = frame->rdi;
        const u64 process_handle = frame->rsi;
        const u64 base_user_ptr = frame->rdx;
        const u64 size_user_ptr = frame->r10;
        const u32 view_protect = static_cast<u32>(frame->r8);

        const i32 pool_idx = subsystems::win32::section::LookupSectionHandle(caller, section_handle);
        if (pool_idx < 0)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }

        Process* target = caller;
        constexpr u64 kCurrentProcess = static_cast<u64>(-1);
        if (process_handle != kCurrentProcess)
        {
            if (!CapSetHas(caller->caps, kCapDebug))
            {
                RecordSandboxDenial(kCapDebug);
                frame->rax = kStatusAccessDenied;
                return;
            }
            target = LookupProcessHandle(caller, process_handle);
            if (target == nullptr)
            {
                frame->rax = kStatusInvalidHandle;
                return;
            }
        }

        u64 hint_va = 0;
        if (base_user_ptr != 0 &&
            !mm::CopyFromUser(&hint_va, reinterpret_cast<const void*>(base_user_ptr), sizeof(hint_va)))
        {
            frame->rax = kStatusAccessViolation;
            return;
        }

        // Pick a base VA. v0: caller-supplied hint must be
        // page-aligned and non-overlapping; if 0 (or hint
        // collides), bump-allocate from the calling process's
        // mmap arena. Cross-process maps with hint == 0 use
        // the TARGET's mmap cursor.
        u64 base_va = (hint_va & ~0xFFFULL);
        if (base_va == 0)
        {
            base_va = target->linux_mmap_cursor;
        }

        // Reject out-of-range base_va before SectionMap drives
        // AddressSpaceMapBorrowedPage past its kUserMax panic gate.
        // Without this an unprivileged caller with a section handle
        // could DoS the kernel by passing a kernel-half hint.
        const u64 view_size_pre = subsystems::win32::section::SectionViewSize(static_cast<u32>(pool_idx));
        constexpr u64 kSectionUserMax = 0x00007FFFFFFFFFFFULL;
        if (view_size_pre == 0 || base_va > kSectionUserMax || (view_size_pre - 1) > (kSectionUserMax - base_va))
        {
            frame->rax = kStatusInvalidParameter;
            return;
        }

        if (!subsystems::win32::section::SectionMap(static_cast<u32>(pool_idx), target->as, base_va, view_protect))
        {
            frame->rax = kStatusConflictingAddresses;
            return;
        }
        subsystems::win32::section::SectionRetain(static_cast<u32>(pool_idx));

        const u64 view_size = subsystems::win32::section::SectionViewSize(static_cast<u32>(pool_idx));
        if (base_va == target->linux_mmap_cursor)
        {
            target->linux_mmap_cursor += view_size;
        }

        if (base_user_ptr != 0 && !mm::CopyToUser(reinterpret_cast<void*>(base_user_ptr), &base_va, sizeof(base_va)))
        {
            // Map installed but caller can't see the base —
            // tear it down so we don't leak the view.
            subsystems::win32::section::SectionUnmap(static_cast<u32>(pool_idx), target->as, base_va);
            subsystems::win32::section::SectionRelease(static_cast<u32>(pool_idx));
            frame->rax = kStatusAccessViolation;
            return;
        }
        if (size_user_ptr != 0 &&
            !mm::CopyToUser(reinterpret_cast<void*>(size_user_ptr), &view_size, sizeof(view_size)))
        {
            subsystems::win32::section::SectionUnmap(static_cast<u32>(pool_idx), target->as, base_va);
            subsystems::win32::section::SectionRelease(static_cast<u32>(pool_idx));
            frame->rax = kStatusAccessViolation;
            return;
        }
        frame->rax = kStatusSuccess;
        return;
    }

    case SYS_SECTION_UNMAP:
    {
        // NtUnmapViewOfSection(ProcessHandle, BaseAddress).
        // v0 unmaps every section view that starts exactly at
        // `base_va` in the target's AS — we don't track which
        // section a given VA belongs to, so the unmap walks
        // every live section pool entry and asks each one to
        // unmap (the borrowed-PTE clear is idempotent on
        // already-unmapped pages, and SectionUnmap returns
        // false if any page was missing → we accept the first
        // one whose every page WAS mapped).
        Process* caller = CurrentProcess();
        if (caller == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        const u64 process_handle = frame->rdi;
        const u64 base_va = frame->rsi;
        if ((base_va & 0xFFF) != 0)
        {
            frame->rax = kStatusInvalidParameter;
            return;
        }
        Process* target = caller;
        constexpr u64 kCurrentProcess = static_cast<u64>(-1);
        if (process_handle != kCurrentProcess)
        {
            if (!CapSetHas(caller->caps, kCapDebug))
            {
                RecordSandboxDenial(kCapDebug);
                frame->rax = kStatusAccessDenied;
                return;
            }
            target = LookupProcessHandle(caller, process_handle);
            if (target == nullptr)
            {
                frame->rax = kStatusInvalidHandle;
                return;
            }
        }
        const i32 hit = subsystems::win32::section::SectionUnmapAtVa(target->as, base_va);
        if (hit < 0)
        {
            frame->rax = kStatusInvalidParameter;
            return;
        }
        subsystems::win32::section::SectionRelease(static_cast<u32>(hit));
        frame->rax = kStatusSuccess;
        return;
    }

    case SYS_THREAD_OPEN:
    {
        // NtOpenThread: TID in rdi → kernel handle in rax (or 0
        // on any failure). Cap-gated on kCapDebug — same threat
        // class as NtOpenProcess, since the produced handle
        // unlocks SUSPEND / RESUME / GET / SET_CONTEXT on a
        // task in another process. Refuses kernel-only tasks
        // (target->process == nullptr — those have no NT
        // identity and no Process to refcount).
        Process* caller = CurrentProcess();
        if (caller == nullptr || !CapSetHas(caller->caps, kCapDebug))
        {
            if (caller != nullptr)
            {
                RecordSandboxDenial(kCapDebug);
            }
            frame->rax = 0;
            return;
        }
        const u64 target_tid = frame->rdi;
        sched::Task* target_task = sched::SchedFindTaskByTid(target_tid);
        if (target_task == nullptr)
        {
            frame->rax = 0;
            return;
        }
        Process* owner = sched::TaskProcess(target_task);
        if (owner == nullptr)
        {
            frame->rax = 0;
            return;
        }
        u64 idx = Process::kWin32ForeignThreadCap;
        for (u64 i = 0; i < Process::kWin32ForeignThreadCap; ++i)
        {
            if (!caller->win32_foreign_threads[i].in_use)
            {
                idx = i;
                break;
            }
        }
        if (idx == Process::kWin32ForeignThreadCap)
        {
            frame->rax = 0; // table full
            return;
        }
        ProcessRetain(owner);
        caller->win32_foreign_threads[idx].in_use = true;
        caller->win32_foreign_threads[idx].task = target_task;
        caller->win32_foreign_threads[idx].owner = owner;
        frame->rax = Process::kWin32ForeignThreadBase + idx;
        return;
    }

    case SYS_THREAD_SUSPEND:
    case SYS_THREAD_RESUME:
    {
        Process* caller = CurrentProcess();
        sched::Task* target = LookupThreadHandle(caller, frame->rdi);
        if (target == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        u32 prev_count = 0;
        const sched::SuspendResult rc = (num == SYS_THREAD_SUSPEND) ? sched::SchedSuspendTask(target, &prev_count)
                                                                    : sched::SchedResumeTask(target, &prev_count);
        if (rc != sched::SuspendResult::Signaled)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        frame->rax = prev_count;
        return;
    }

    case SYS_THREAD_GET_CONTEXT:
    case SYS_THREAD_SET_CONTEXT:
    {
        // Cap-gate: same threat class as cross-AS VM ops.
        Process* caller = CurrentProcess();
        if (caller == nullptr || !CapSetHas(caller->caps, kCapDebug))
        {
            if (caller != nullptr)
            {
                RecordSandboxDenial(kCapDebug);
            }
            frame->rax = kStatusAccessDenied;
            return;
        }
        sched::Task* target = LookupThreadHandle(caller, frame->rdi);
        if (target == nullptr)
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        // Get/SetContext is only well-defined on a suspended target.
        // A running target's TrapFrame is being actively pushed/
        // popped; reading or writing it would race.
        if (sched::TaskIsDead(target))
        {
            frame->rax = kStatusInvalidHandle;
            return;
        }
        arch::TrapFrame* tf = sched::SchedFindUserTrapFrame(target);
        if (tf == nullptr)
        {
            // No user trap frame — target hasn't entered user mode
            // yet, or the stack is corrupt.
            frame->rax = kStatusInvalidParameter;
            return;
        }
        const u64 user_ctx_va = frame->rsi;
        if (user_ctx_va == 0)
        {
            frame->rax = kStatusInvalidParameter;
            return;
        }

        // The caller-supplied flags filter selects which classes
        // the kernel touches. v0 honours INTEGER + CONTROL fully;
        // SEGMENTS partial (we sanitise on SET regardless because
        // a malicious value here is the privilege-escalation path);
        // FLOATING_POINT + DEBUG_REGISTERS deferred. Microsoft's
        // contract is "the kernel only writes the parts you asked
        // for" — we honour that for GET, and on SET we apply the
        // requested classes plus the always-on cs/ss sanitisation.
        const u32 caller_flags = static_cast<u32>(frame->rdx);
        const bool want_integer = (caller_flags & kContextInteger) == kContextInteger;
        const bool want_control = (caller_flags & kContextControl) == kContextControl;

        if (num == SYS_THREAD_GET_CONTEXT)
        {
            Win32Context ctx;
            __builtin_memset(&ctx, 0, sizeof(ctx));
            ctx.ContextFlags = caller_flags;
            if (want_integer)
            {
                ctx.Rax = tf->rax;
                ctx.Rcx = tf->rcx;
                ctx.Rdx = tf->rdx;
                ctx.Rbx = tf->rbx;
                ctx.Rbp = tf->rbp;
                ctx.Rsi = tf->rsi;
                ctx.Rdi = tf->rdi;
                ctx.R8 = tf->r8;
                ctx.R9 = tf->r9;
                ctx.R10 = tf->r10;
                ctx.R11 = tf->r11;
                ctx.R12 = tf->r12;
                ctx.R13 = tf->r13;
                ctx.R14 = tf->r14;
                ctx.R15 = tf->r15;
            }
            if (want_control)
            {
                ctx.Rip = tf->rip;
                ctx.Rsp = tf->rsp;
                ctx.EFlags = static_cast<u32>(tf->rflags);
                ctx.SegCs = static_cast<u16>(tf->cs);
                ctx.SegSs = static_cast<u16>(tf->ss);
            }
            if (!mm::CopyToUser(reinterpret_cast<void*>(user_ctx_va), &ctx, sizeof(ctx)))
            {
                frame->rax = kStatusAccessViolation;
                return;
            }
            frame->rax = kStatusSuccess;
            return;
        }

        // SYS_THREAD_SET_CONTEXT
        Win32Context ctx;
        if (!mm::CopyFromUser(&ctx, reinterpret_cast<const void*>(user_ctx_va), sizeof(ctx)))
        {
            frame->rax = kStatusAccessViolation;
            return;
        }
        if (want_integer)
        {
            tf->rax = ctx.Rax;
            tf->rcx = ctx.Rcx;
            tf->rdx = ctx.Rdx;
            tf->rbx = ctx.Rbx;
            tf->rbp = ctx.Rbp;
            tf->rsi = ctx.Rsi;
            tf->rdi = ctx.Rdi;
            tf->r8 = ctx.R8;
            tf->r9 = ctx.R9;
            tf->r10 = ctx.R10;
            tf->r11 = ctx.R11;
            tf->r12 = ctx.R12;
            tf->r13 = ctx.R13;
            tf->r14 = ctx.R14;
            tf->r15 = ctx.R15;
        }
        if (want_control)
        {
            tf->rip = ctx.Rip;
            tf->rsp = ctx.Rsp;
            // RFLAGS sanitisation: keep IF on (otherwise the
            // target wakes with interrupts disabled and the
            // kernel deadlocks at the next timer tick), force
            // IOPL = 0 (no port-IO privilege gift), clear NT
            // and TF (no nested-task chains, no single-step
            // surprises). The caller's choice of arithmetic /
            // comparison flags is preserved.
            constexpr u64 kRflagsIf = 1ULL << 9;
            constexpr u64 kRflagsTf = 1ULL << 8;
            constexpr u64 kRflagsNt = 1ULL << 14;
            constexpr u64 kRflagsIoplMask = 0x3ULL << 12;
            u64 new_flags = static_cast<u64>(ctx.EFlags);
            new_flags |= kRflagsIf;
            new_flags &= ~(kRflagsTf | kRflagsNt | kRflagsIoplMask);
            tf->rflags = new_flags;
            // Force ring-3 selectors. A malicious caller passing
            // kernel selectors would otherwise iretq into ring 0.
            tf->cs = 0x2B; // kUserCodeSelector
            tf->ss = 0x33; // kUserDataSelector
        }
        frame->rax = kStatusSuccess;
        return;
    }

    case SYS_NT_INVOKE:
    {
        // Forward to the NT→Linux translator. The handler reads
        // frame->rdi for the NT number + frame->rsi..r9 for NT-
        // ABI arguments; its return value is the final NTSTATUS
        // that goes back to the caller.
        const auto t = subsystems::translation::NtTranslateToLinux(frame);
        frame->rax = static_cast<u64>(t.rv);
        return;
    }

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

        // Bounce buffer on kernel stack, +1 for the hard terminator.
        // This diagnostic ABI is intentionally truncating: we copy at
        // most kSyscallDebugPrintMax bytes and append a kernel NUL, but
        // we do not require the page after a short user string to be
        // mapped just because the ceiling is larger than the string.
        char kbuf[kSyscallDebugPrintMax + 1];
        const auto copy = mm::CopyUserCStringTruncating(kbuf, sizeof(kbuf), reinterpret_cast<const void*>(frame->rdi));
        if (copy.status == mm::UserStringCopyStatus::BadArgument || copy.status == mm::UserStringCopyStatus::Fault)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

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
            for (u16 i = 0; i < proc->as->region_count; ++i)
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

        // Read up to kSyscallDebugPrintMax wide-chars (2 bytes each)
        // with the same truncating/page-boundary semantics as
        // SYS_DEBUG_PRINT.
        u16 wbuf[kSyscallDebugPrintMax + 1];
        const auto copy =
            mm::CopyUserString16Truncating(wbuf, kSyscallDebugPrintMax + 1, reinterpret_cast<const void*>(frame->rdi));
        if (copy.status == mm::UserStringCopyStatus::BadArgument || copy.status == mm::UserStringCopyStatus::Fault)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

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

    case SYS_SEM_CREATE:
        subsystems::win32::DoSemCreate(frame);
        return;
    case SYS_SEM_RELEASE:
        subsystems::win32::DoSemRelease(frame);
        return;
    case SYS_SEM_WAIT:
        subsystems::win32::DoSemWait(frame);
        return;

    case SYS_THREAD_EXIT_CODE:
    {
        // Win32 contract: GetExitCodeThread on an unknown or
        // foreign handle (e.g. a process pseudo-handle passed by
        // mistake) should still succeed with BOOL TRUE and a
        // benign STILL_ACTIVE (0x103) payload — that's what the
        // stub did before this set, and the
        // hello_winapi test pins this behavior. So: return
        // STILL_ACTIVE for any handle outside our own thread
        // range, return the real exit_code only for handles we
        // actually own.
        constexpr u64 kStillActive = 0x103;
        const u64 handle = frame->rdi;
        Process* proc = CurrentProcess();
        if (proc == nullptr || handle < Process::kWin32ThreadBase ||
            handle >= Process::kWin32ThreadBase + Process::kWin32ThreadCap)
        {
            frame->rax = kStillActive;
            return;
        }
        const u64 slot = handle - Process::kWin32ThreadBase;
        if (!proc->win32_threads[slot].in_use)
        {
            frame->rax = kStillActive;
            return;
        }
        frame->rax = static_cast<u64>(proc->win32_threads[slot].exit_code);
        return;
    }

    case SYS_THREAD_WAIT:
    {
        const u64 handle = frame->rdi;
        const u64 timeout_ms = frame->rsi & 0xFFFFFFFFu;
        Process* proc = CurrentProcess();
        if (proc == nullptr || handle < Process::kWin32ThreadBase ||
            handle >= Process::kWin32ThreadBase + Process::kWin32ThreadCap)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 slot = handle - Process::kWin32ThreadBase;
        const auto& th = proc->win32_threads[slot];
        if (!th.in_use)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        // Use exit_code != STILL_ACTIVE as the authoritative
        // "thread is done" signal instead of dereferencing
        // th.task, which the reaper may have KFree'd already
        // after the task died. The SYS_EXIT path writes the
        // real exit code into this slot before SchedExit runs,
        // so the slot is valid as long as in_use remains true.
        constexpr u64 kStillActive = 0x103;
        constexpr u64 kInfinite = 0xFFFFFFFFu;
        const u64 start = sched::SchedNowTicks();
        const u64 deadline = (timeout_ms == kInfinite) ? u64(-1) : start + ((timeout_ms + 9) / 10);
        for (;;)
        {
            if (th.exit_code != kStillActive)
            {
                frame->rax = 0; // WAIT_OBJECT_0
                return;
            }
            if (timeout_ms != kInfinite && sched::SchedNowTicks() >= deadline)
            {
                frame->rax = 0x102; // WAIT_TIMEOUT
                return;
            }
            if (timeout_ms == kInfinite)
                sched::SchedYield();
            else
                sched::SchedSleepTicks(1);
        }
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
                        // Look up the KEvent through the unified
                        // handle table and peek at signaled state.
                        // Auto-reset: clear only when we're ACTUALLY
                        // going to wake (handled in the consume
                        // pass below, after the whole wait is known
                        // to be satisfied).
                        const ipc::Handle ipc_h = static_cast<ipc::Handle>(h - Process::kWin32EventBase);
                        ipc::KObject* obj = ipc::HandleTableLookup(proc->kobj_handles, ipc_h, ipc::KObjectType::Event);
                        if (obj != nullptr)
                        {
                            auto* e = reinterpret_cast<ipc::KEvent*>(obj);
                            if (ipc::KEventIsSignaled(e))
                                sig = true;
                        }
                    }
                    else if (h >= Process::kWin32ThreadBase && h < Process::kWin32ThreadBase + Process::kWin32ThreadCap)
                    {
                        // Use exit_code (set by SYS_EXIT) instead
                        // of TaskIsDead (th.task may be a reaped
                        // pointer). Valid as long as in_use holds.
                        const u64 slot = h - Process::kWin32ThreadBase;
                        const auto& th = proc->win32_threads[slot];
                        if (th.in_use && th.exit_code != 0x103)
                            sig = true;
                    }
                    else if (h >= Process::kWin32SemaphoreBase &&
                             h < Process::kWin32SemaphoreBase + Process::kWin32SemaphoreCap)
                    {
                        // Semaphores are signaled iff count > 0.
                        // Wait-all via poll doesn't consume the
                        // count — a fully race-free multi-wait is
                        // a future slice. Look up via the unified
                        // handle table.
                        const ipc::Handle ipc_h = static_cast<ipc::Handle>(h - Process::kWin32SemaphoreBase);
                        ipc::KObject* obj =
                            ipc::HandleTableLookup(proc->kobj_handles, ipc_h, ipc::KObjectType::Semaphore);
                        if (obj != nullptr)
                        {
                            auto* s = reinterpret_cast<ipc::KSemaphore*>(obj);
                            if (ipc::KSemaphoreCount(s) > 0)
                                sig = true;
                        }
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
                // Manual-reset events stay signaled (Win32 contract)
                // — `KEventClearAutoReset` is a no-op on those.
                if (proc != nullptr)
                {
                    for (u64 i = 0; i < count; ++i)
                    {
                        const u64 h = handles[i];
                        if (h < Process::kWin32EventBase || h >= Process::kWin32EventBase + Process::kWin32EventCap)
                            continue;
                        if (wait_all == 0 && i != first_signaled)
                            continue;
                        const ipc::Handle ipc_h = static_cast<ipc::Handle>(h - Process::kWin32EventBase);
                        ipc::KObject* obj = ipc::HandleTableLookup(proc->kobj_handles, ipc_h, ipc::KObjectType::Event);
                        if (obj != nullptr)
                        {
                            auto* e = reinterpret_cast<ipc::KEvent*>(obj);
                            ipc::KEventClearAutoReset(e);
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
        // convert to ticks and call SchedSleepTicks. Caller wakes
        // when the timer has advanced past the deadline; spurious
        // early wakes are not a thing in v0.
        //
        // Win32 Sleep contract: "at least N ms, never less". The
        // 100 Hz tick is 10 ms wide, and the request lands at an
        // arbitrary point inside the current tick — so an N-tick
        // sleep can fire as soon as (N - 1) full ticks have elapsed
        // in wall time. Round-up alone (`(ms + 9) / 10`) therefore
        // undershoots for any ms that's already an exact multiple
        // of the tick (Sleep(50) → 5 ticks → wakes in [40, 50) ms).
        // Add one extra tick to absorb the partial first tick and
        // make the bound "at least ms" hold for every input.
        const u64 ms = frame->rdi;
        if (ms == 0)
        {
            sched::SchedYield();
        }
        else
        {
            constexpr u64 kMsPerTick = 10;
            const u64 ticks = (ms + (kMsPerTick - 1)) / kMsPerTick + 1;
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
        // Same cap + jail composition as SYS_STAT: kCapFsRead is
        // gated centrally by `SyscallGate` (cap_table.def);
        // Process::root bounds what can be named. The leaf-node
        // check also rejects reading a directory — "read a dir
        // entry by entry" is a future getdents-style syscall.
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

        char kpath[kSyscallPathMax];
        if (!mm::CopyUserCString(kpath, sizeof(kpath), reinterpret_cast<const void*>(frame->rdi)).ok())
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

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
        // kCapFsRead is gated centrally by `SyscallGate`
        // (cap_table.def) — a process without the cap returns -1
        // from the gate before reaching this handler.
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

        // Bounce the user path onto the kernel stack. CopyUserCString
        // validates/probes via the active AS and requires an in-bounds
        // NUL terminator; namespace jail checks happen during lookup.
        char kpath[kSyscallPathMax];
        if (!mm::CopyUserCString(kpath, sizeof(kpath), reinterpret_cast<const void*>(frame->rdi)).ok())
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }

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
        // child. kCapFsRead is gated centrally by `SyscallGate`
        // (cap_table.def): the observable primitive is "the caller
        // named a file path"; without it, even the lookup is not
        // something the process is authorised to perform.
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
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
        if (!mm::CopyUserCString(kpath, plen + 1, reinterpret_cast<const void*>(frame->rdi)).ok())
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
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
        arch::SerialWrite("(");
        SerialWriteCapBits(drop_mask);
        arch::SerialWrite(") caps=");
        arch::SerialWriteHex(before);
        arch::SerialWrite("(");
        SerialWriteCapBits(before);
        arch::SerialWrite(")->");
        arch::SerialWriteHex(proc->caps.bits);
        arch::SerialWrite("(");
        SerialWriteCapBits(proc->caps.bits);
        arch::SerialWrite(")\n");
        frame->rax = 0;
        return;
    }

    // Windowing family — ring-3 bridge to the kernel compositor.
    case SYS_WIN_CREATE:
        subsystems::win32::DoWinCreate(frame);
        return;
    case SYS_WIN_DESTROY:
        subsystems::win32::DoWinDestroy(frame);
        return;
    case SYS_WIN_SHOW:
        subsystems::win32::DoWinShow(frame);
        return;
    case SYS_WIN_MSGBOX:
        subsystems::win32::DoWinMsgBox(frame);
        return;
    case SYS_WIN_PEEK_MSG:
        subsystems::win32::DoWinPeekMsg(frame);
        return;
    case SYS_WIN_GET_MSG:
        subsystems::win32::DoWinGetMsg(frame);
        return;
    case SYS_WIN_POST_MSG:
        subsystems::win32::DoWinPostMsg(frame);
        return;
    case SYS_GDI_FILL_RECT:
        subsystems::win32::DoGdiFillRect(frame);
        return;
    case SYS_GDI_TEXT_OUT:
        subsystems::win32::DoGdiTextOut(frame);
        return;
    case SYS_GDI_RECTANGLE:
        subsystems::win32::DoGdiRectangle(frame);
        return;
    case SYS_GDI_CLEAR:
        subsystems::win32::DoGdiClear(frame);
        return;
    case SYS_WIN_MOVE:
        subsystems::win32::DoWinMove(frame);
        return;
    case SYS_WIN_GET_RECT:
        subsystems::win32::DoWinGetRect(frame);
        return;
    case SYS_WIN_SET_TEXT:
        subsystems::win32::DoWinSetText(frame);
        return;
    case SYS_WIN_TIMER_SET:
        subsystems::win32::DoWinTimerSet(frame);
        return;
    case SYS_WIN_TIMER_KILL:
        subsystems::win32::DoWinTimerKill(frame);
        return;
    case SYS_GDI_LINE:
        subsystems::win32::DoGdiLine(frame);
        return;
    case SYS_GDI_ELLIPSE:
        subsystems::win32::DoGdiEllipse(frame);
        return;
    case SYS_GDI_SET_PIXEL:
        subsystems::win32::DoGdiSetPixel(frame);
        return;
    case SYS_WIN_GET_KEYSTATE:
        subsystems::win32::DoWinGetKeyState(frame);
        return;
    case SYS_WIN_GET_CURSOR:
        subsystems::win32::DoWinGetCursor(frame);
        return;
    case SYS_WIN_GET_MOUSE_DELTA:
        subsystems::win32::DoWinGetMouseDelta(frame);
        return;

    case SYS_STDIN_READ:
    {
        // rdi = user dst buffer, rsi = capacity. Blocks until at
        // least one byte is available; returns the byte count or
        // (u64)-1 on a bad parameter.
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 user_dst = frame->rdi;
        const u64 cap = frame->rsi;
        if (user_dst == 0 || cap == 0)
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const i64 rv = ProcessReadStdinBlocking(proc, reinterpret_cast<void*>(user_dst), cap);
        frame->rax = static_cast<u64>(rv);
        return;
    }

    case SYS_DLL_BASE_BY_NAME:
    {
        // rdi = user pointer to ASCII name, rsi = name length.
        // Empty / zero-length name returns the EXE image base
        // (Win32 GetModuleHandleW(NULL) semantics).
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = 0;
            return;
        }
        const u64 user_name = frame->rdi;
        const u64 name_len = frame->rsi;
        if (name_len >= 64)
        {
            frame->rax = 0;
            return;
        }
        if (name_len == 0 || user_name == 0)
        {
            // Empty name → EXE base.
            frame->rax = ProcessFindDllBaseByName(proc, "");
            return;
        }
        char kname[64];
        if (!mm::CopyUserCString(kname, name_len + 1, reinterpret_cast<const void*>(user_name)).ok())
        {
            frame->rax = 0;
            return;
        }
        frame->rax = ProcessFindDllBaseByName(proc, kname);
        return;
    }
    case SYS_WIN_TRACK_POPUP:
        subsystems::win32::DoWinTrackPopup(frame);
        return;
    case SYS_GDI_SET_CURSOR:
    {
        // PE cursor request. Map the GdiCursorShape ABI value
        // to the kernel's CursorShape enum and return the
        // previous shape so user32 can implement the standard
        // SetCursor "previous handle" return.
        const u32 req = static_cast<u32>(frame->rdi);
        using duetos::drivers::video::CursorGetShape;
        using duetos::drivers::video::CursorSetShape;
        using duetos::drivers::video::CursorSetShapeCustom;
        using duetos::drivers::video::CursorShape;
        using duetos::drivers::video::kCustomCursorIdBase;
        using duetos::drivers::video::kCustomCursorMax;
        const CursorShape prev = CursorGetShape();
        // Custom HCURSOR (slot id ≥ 256) routes through the
        // CursorSetShapeCustom path; the previous-shape return
        // collapses to Arrow because the kernel doesn't track
        // which custom id was active before.
        if (req >= kCustomCursorIdBase && req < kCustomCursorIdBase + kCustomCursorMax)
        {
            CursorSetShapeCustom(req);
            frame->rax = static_cast<u64>(prev);
            return;
        }
        CursorShape want = CursorShape::Arrow;
        switch (req)
        {
        case kGdiCursorIBeam:
            want = CursorShape::IBeam;
            break;
        case kGdiCursorHand:
            want = CursorShape::Hand;
            break;
        case kGdiCursorWait:
            want = CursorShape::Wait;
            break;
        case kGdiCursorResizeNS:
            want = CursorShape::ResizeNS;
            break;
        case kGdiCursorResizeEW:
            want = CursorShape::ResizeEW;
            break;
        case kGdiCursorResizeNESW:
            want = CursorShape::ResizeNESW;
            break;
        case kGdiCursorResizeNWSE:
            want = CursorShape::ResizeNWSE;
            break;
        case kGdiCursorArrow:
        default:
            want = CursorShape::Arrow;
            break;
        }
        // Skip the change if Wait is currently active — long-op
        // holders own the shape; the PE's request is parked
        // until the wait pops.
        if (prev != CursorShape::Wait)
        {
            CursorSetShape(want);
        }
        frame->rax = static_cast<u64>(prev);
        return;
    }
    case SYS_GDI_CREATE_CURSOR:
    {
        // PE registers a custom 12×20 cursor. rdi = mask_ptr,
        // rsi = size (must == 240), rdx packs (y_hot<<8)|x_hot.
        const u64 mask_va = frame->rdi;
        const u32 size = static_cast<u32>(frame->rsi);
        const u64 hot_packed = frame->rdx;
        constexpr u32 kExpected = 12 * 20;
        if (size != kExpected || mask_va == 0)
        {
            frame->rax = 0;
            return;
        }
        u8 mask_buf[kExpected];
        // mm::CopyFromUser validates the source range against
        // the calling Process's address space ledger + gates
        // SMAP — same pattern every other byte-buffer syscall
        // uses.
        if (!mm::CopyFromUser(mask_buf, reinterpret_cast<const void*>(mask_va), kExpected))
        {
            frame->rax = 0;
            return;
        }
        const u8 x_hot = static_cast<u8>(hot_packed & 0xFFU);
        const u8 y_hot = static_cast<u8>((hot_packed >> 8) & 0xFFU);
        const u32 id = duetos::drivers::video::CursorRegisterCustom(mask_buf, x_hot, y_hot);
        frame->rax = id;
        return;
    }
    case SYS_WIN_SET_CURSOR:
        subsystems::win32::DoWinSetCursor(frame);
        return;
    case SYS_WIN_SET_CAPTURE:
        subsystems::win32::DoWinSetCapture(frame);
        return;
    case SYS_WIN_RELEASE_CAPTURE:
        subsystems::win32::DoWinReleaseCapture(frame);
        return;
    case SYS_WIN_GET_CAPTURE:
        subsystems::win32::DoWinGetCapture(frame);
        return;
    case SYS_WIN_CLIP_SET_TEXT:
        subsystems::win32::DoWinClipSetText(frame);
        return;
    case SYS_WIN_CLIP_GET_TEXT:
        subsystems::win32::DoWinClipGetText(frame);
        return;
    case SYS_WIN_GET_LONG:
        subsystems::win32::DoWinGetLong(frame);
        return;
    case SYS_WIN_SET_LONG:
        subsystems::win32::DoWinSetLong(frame);
        return;
    case SYS_WIN_INVALIDATE:
        subsystems::win32::DoWinInvalidate(frame);
        return;
    case SYS_WIN_VALIDATE:
        subsystems::win32::DoWinValidate(frame);
        return;
    case SYS_WIN_GET_ACTIVE:
        subsystems::win32::DoWinGetActive(frame);
        return;
    case SYS_WIN_SET_ACTIVE:
        subsystems::win32::DoWinSetActive(frame);
        return;
    case SYS_WIN_GET_METRIC:
        subsystems::win32::DoWinGetMetric(frame);
        return;
    case SYS_WIN_ENUM:
        subsystems::win32::DoWinEnum(frame);
        return;
    case SYS_WIN_FIND:
        subsystems::win32::DoWinFind(frame);
        return;
    case SYS_WIN_SET_PARENT:
        subsystems::win32::DoWinSetParent(frame);
        return;
    case SYS_WIN_GET_PARENT:
        subsystems::win32::DoWinGetParent(frame);
        return;
    case SYS_WIN_GET_RELATED:
        subsystems::win32::DoWinGetRelated(frame);
        return;
    case SYS_WIN_SET_FOCUS:
        subsystems::win32::DoWinSetFocus(frame);
        return;
    case SYS_WIN_GET_FOCUS:
        subsystems::win32::DoWinGetFocus(frame);
        return;
    case SYS_WIN_CARET:
        subsystems::win32::DoWinCaret(frame);
        return;
    case SYS_WIN_BEEP:
        subsystems::win32::DoWinBeep(frame);
        return;

    case SYS_GDI_BITBLT:
        subsystems::win32::DoGdiBitBlt(frame);
        return;
    case SYS_WIN_BEGIN_PAINT:
        subsystems::win32::DoWinBeginPaint(frame);
        return;
    case SYS_WIN_END_PAINT:
        subsystems::win32::DoWinEndPaint(frame);
        return;
    case SYS_GDI_FILL_RECT_USER:
        subsystems::win32::DoGdiFillRectUser(frame);
        return;
    case SYS_GDI_CREATE_COMPAT_DC:
        subsystems::win32::DoGdiCreateCompatibleDC(frame);
        return;
    case SYS_GDI_CREATE_COMPAT_BITMAP:
        subsystems::win32::DoGdiCreateCompatibleBitmap(frame);
        return;
    case SYS_GDI_CREATE_SOLID_BRUSH:
        subsystems::win32::DoGdiCreateSolidBrush(frame);
        return;
    case SYS_GDI_GET_STOCK_OBJECT:
        subsystems::win32::DoGdiGetStockObject(frame);
        return;
    case SYS_GDI_SELECT_OBJECT:
        subsystems::win32::DoGdiSelectObject(frame);
        return;
    case SYS_GDI_DELETE_DC:
        subsystems::win32::DoGdiDeleteDC(frame);
        return;
    case SYS_GDI_DELETE_OBJECT:
        subsystems::win32::DoGdiDeleteObject(frame);
        return;
    case SYS_GDI_BITBLT_DC:
        subsystems::win32::DoGdiBitBltDC(frame);
        return;
    case SYS_GDI_STRETCH_BLT_DC:
        subsystems::win32::DoGdiStretchBltDC(frame);
        return;
    case SYS_GDI_CREATE_PEN:
        subsystems::win32::DoGdiCreatePen(frame);
        return;
    case SYS_GDI_MOVE_TO_EX:
        subsystems::win32::DoGdiMoveToEx(frame);
        return;
    case SYS_GDI_LINE_TO:
        subsystems::win32::DoGdiLineTo(frame);
        return;
    case SYS_GDI_DRAW_TEXT_USER:
        subsystems::win32::DoGdiDrawText(frame);
        return;
    case SYS_GDI_RECTANGLE_FILLED:
        subsystems::win32::DoGdiRectangleFilled(frame);
        return;
    case SYS_GDI_ELLIPSE_FILLED:
        subsystems::win32::DoGdiEllipseFilled(frame);
        return;
    case SYS_GDI_PAT_BLT:
        subsystems::win32::DoGdiPatBlt(frame);
        return;
    case SYS_GDI_TEXT_OUT_W:
        subsystems::win32::DoGdiTextOutW(frame);
        return;
    case SYS_GDI_DRAW_TEXT_W:
        subsystems::win32::DoGdiDrawTextW(frame);
        return;
    case SYS_GDI_GET_SYS_COLOR:
        subsystems::win32::DoGdiGetSysColor(frame);
        return;
    case SYS_GDI_GET_SYS_COLOR_BRUSH:
        subsystems::win32::DoGdiGetSysColorBrush(frame);
        return;
    case SYS_GDI_SET_TEXT_COLOR:
        subsystems::win32::DoGdiSetTextColor(frame);
        return;
    case SYS_GDI_SET_BK_COLOR:
        subsystems::win32::DoGdiSetBkColor(frame);
        return;
    case SYS_GDI_SET_BK_MODE:
        subsystems::win32::DoGdiSetBkMode(frame);
        return;

    case SYS_GFX_D3D_STUB:
    {
        // rdi = kind. Forward to the graphics ICD's counter-backed
        // stubs so the `gfx` shell command sees per-API activity;
        // each bumps a counter and returns HRESULT E_FAIL (real DLL
        // implementations ignore this return — the userland DLL
        // produced its own object).
        //
        // Kinds:
        //   1 = D3D11           5 = DInput8
        //   2 = D3D12           6 = XInput
        //   3 = DXGI            7 = XAudio2
        //   4 = D3D9            8 = DSound
        //                       9 = DDraw
        //                      10 = D2D1
        //                      11 = DWrite
        u32 hr = 0;
        switch (frame->rdi)
        {
        case 1:
            hr = subsystems::graphics::D3D11CreateDeviceStub();
            break;
        case 2:
            hr = subsystems::graphics::D3D12CreateDeviceStub();
            break;
        case 3:
            hr = subsystems::graphics::DxgiCreateFactoryStub();
            break;
        case 4:
            hr = subsystems::graphics::D3d9CreateStub();
            break;
        case 5:
            hr = subsystems::graphics::Dinput8CreateStub();
            break;
        case 6:
            hr = subsystems::graphics::XinputCreateStub();
            break;
        case 7:
            hr = subsystems::graphics::Xaudio2CreateStub();
            break;
        case 8:
            hr = subsystems::graphics::DsoundCreateStub();
            break;
        case 9:
            hr = subsystems::graphics::DdrawCreateStub();
            break;
        case 10:
            hr = subsystems::graphics::D2d1CreateStub();
            break;
        case 11:
            hr = subsystems::graphics::DwriteCreateStub();
            break;
        default:
            hr = 0; // bad kind = S_OK surface would confuse callers; leave 0
            break;
        }
        frame->rax = hr;
        return;
    }

    case SYS_DLL_PROC_ADDRESS:
    {
        // rdi = HMODULE (DLL base VA; 0 = any registered DLL).
        // rsi = user VA of NUL-terminated ASCII function name.
        //
        // Returns the exported function's VA on hit, 0 on miss
        // (module not registered, name not exported, forwarder).
        // Returning 0 matches Win32 GetProcAddress's miss
        // semantics exactly.
        Process* proc = CurrentProcess();
        if (proc == nullptr)
        {
            frame->rax = 0;
            return;
        }
        // Bounded copy-in for the function name. 256 chars is
        // comfortably above the longest C++-mangled export name
        // we've seen in MSVCP140 (~180 chars).
        constexpr u64 kDllFuncNameMax = 256;
        char name_buf[kDllFuncNameMax + 1];
        if (frame->rsi == 0 ||
            !mm::CopyUserCString(name_buf, sizeof(name_buf), reinterpret_cast<const void*>(frame->rsi)).ok())
        {
            frame->rax = 0;
            return;
        }
        const u64 va = ProcessResolveDllExportByBase(proc, frame->rdi, name_buf);
        frame->rax = va;
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
        // Record the gap in the fix journal before logging — dedup
        // collapses repeat hits of the same number, so a workload
        // calling syscall 999 in a tight loop generates one record
        // not thousands. The reviewer wants to know which numbers
        // are getting hit, with a sample caller rip for triage.
        {
            // Encode the syscall number into source_pin so dedup
            // groups by (UnknownSyscall, num). 24 chars max is
            // plenty for "syscall#" + a 16-digit hex.
            char pin[32];
            const char* hex = "0123456789abcdef";
            pin[0] = 's';
            pin[1] = 'y';
            pin[2] = 's';
            pin[3] = 'c';
            pin[4] = 'a';
            pin[5] = 'l';
            pin[6] = 'l';
            pin[7] = '#';
            u64 n = num;
            // Render up to 16 hex nibbles; trim leading zeros.
            char raw[16];
            for (int i = 15; i >= 0; --i)
            {
                raw[i] = hex[(n >> (i * 4)) & 0xF];
            }
            int first = 0;
            while (first < 15 && raw[first] == '0')
                ++first;
            int p = 8;
            for (int i = first; i < 16; ++i)
                pin[p++] = raw[i];
            pin[p] = '\0';
            (void)::duetos::diag::FixJournalRecord(::duetos::diag::FixDetector::UnknownSyscall, pin,
                                                   "implement or route this syscall number", num, frame->rip);
        }
        ReportUnknownSyscall(num, frame->rip);
        // Convention: -ENOSYS back to the caller for a bad syscall
        // number. Two's-complement cast keeps the rax payload
        // machine-visible as a negative errno in rax.
        frame->rax = static_cast<u64>(kSysErrnoENOSYS);
        return;
    }
    }
}

} // namespace duetos::core
