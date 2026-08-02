#include "subsystems/win32/thread_syscall.h"

#include "subsystems/win32/custom.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/traps.h"
#include "arch/x86_64/usermode.h"
#include "cpu/percpu.h"
#include "log/klog.h"
#include "core/panic.h"
#include "proc/process.h"
#include "syscall/syscall.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "subsystems/win32/thunks.h"
#include "util/nospec.h"

namespace duetos::subsystems::win32
{

namespace
{

// Handed from DoThreadCreate to Ring3ThreadEntry via the Task's
// `arg`. Kernel-heap allocated; the entry function reads and
// frees it before iretq. Frees on the same path on any early-
// return too (the Task is then flagged dead).
struct ThreadDesc
{
    u64 start_va;     // ring-3 RIP
    u64 param;        // goes into rcx (Win32 x64 first arg)
    u64 user_rsp;     // ring-3 RSP (stack_top - 8 for shadow alignment)
    u64 user_gs_base; // usually the Process's shared TEB VA (v0 scope)
};

struct ThreadPrepareContext
{
    core::Process* process;
    u64 slot;
    u64 generation;
    core::UserStackRange user_stack;
    mm::AddressSpaceReservationToken stack_reservation;
    u64 user_gs_base;
    u64 tid;
};

void PrepareWin32ThreadTask(sched::Task* task, void* raw_context)
{
    auto* context = static_cast<ThreadPrepareContext*>(raw_context);
    KASSERT(task != nullptr && context != nullptr && context->process != nullptr, "win32/thread",
            "invalid prepared-task context");

    // Stack ownership must exist before scheduler publication: the new
    // Task may fault, exit and reach the reaper on another CPU as soon as
    // this callback returns.
    sched::SchedPrepareOwnedUserStack(task, context->user_stack, context->stack_reservation);

    if (context->user_gs_base != 0)
        sched::SchedSetUserGsOverride(task, context->user_gs_base);

    core::Process* process = context->process;
    context->tid = sched::TaskId(task);
    KASSERT(context->tid != 0, "win32/thread", "prepared task has invalid TID");
    const sync::IrqFlags flags = sync::SpinLockAcquire(process->win32_thread_lock);
    auto& row = process->win32_threads[context->slot];
    KASSERT(row.in_use && row.creating && row.generation == context->generation && row.tid == 0, "win32/thread",
            "prepared task lost reserved handle slot");
    row.tid = context->tid;
    row.user_stack_va = context->user_stack.reserve_lo;
    sync::SpinLockRelease(process->win32_thread_lock, flags);
}

} // namespace

[[noreturn]] void Ring3ThreadEntry(void* arg)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    const u64 kstack_top = sched::SchedCurrentKernelStackTop();
    if (kstack_top == 0)
    {
        // Debug: panic — kernel-stack bookkeeping is broken before
        // we even get to ring 3. Release: terminate just this
        // task. The SchedExit/KFree below is dead code in debug
        // (Panic is [[noreturn]]); in release it cleans up the
        // descriptor heap allocation and routes to the reaper.
        ::duetos::core::DebugPanicOrWarn("win32/thread", "SchedCurrentKernelStackTop returned 0");
        if (arg != nullptr)
        {
            mm::KFree(arg);
        }
        sched::SchedExit();
    }
    arch::TssSetRsp0(kstack_top);
    cpu::CurrentCpu()->kernel_rsp = kstack_top;

    if (arg == nullptr)
    {
        // Same shape as above: in release, exit this task instead
        // of the whole kernel. Nothing to free — arg is already
        // null.
        ::duetos::core::DebugPanicOrWarn("win32/thread", "Ring3ThreadEntry called with null desc");
        sched::SchedExit();
    }

    // Copy onto the stack then free the heap allocation — the
    // iretq below doesn't return, so deferring the free to the
    // task's teardown would leak.
    ThreadDesc d;
    d.start_va = static_cast<ThreadDesc*>(arg)->start_va;
    d.param = static_cast<ThreadDesc*>(arg)->param;
    d.user_rsp = static_cast<ThreadDesc*>(arg)->user_rsp;
    d.user_gs_base = static_cast<ThreadDesc*>(arg)->user_gs_base;
    mm::KFree(arg);

    SerialWrite("[thread] task pid=");
    SerialWriteHex(sched::CurrentTaskId());
    SerialWrite(" entering ring 3 rip=");
    SerialWriteHex(d.start_va);
    SerialWrite(" rsp=");
    SerialWriteHex(d.user_rsp);
    SerialWrite(" param(rcx)=");
    SerialWriteHex(d.param);
    if (d.user_gs_base != 0)
    {
        SerialWrite(" gs_base=");
        SerialWriteHex(d.user_gs_base);
    }
    SerialWrite("\n");

    // Hand off to the 4-arg asm entry that preserves rcx through
    // the iretq (SYS_THREAD_CREATE contract: thread proc sees the
    // caller-supplied param in rcx per Win32 x64 ABI).
    arch::EnterUserModeThread(d.start_va, d.user_rsp, d.user_gs_base, d.param);
}

namespace
{

// Per-thread static-TLS region (T6-01 per-thread half). Each
// win32 thread slot gets a private 1 MiB window — well clear of
// the thread-stack arena (0x68000000), the main-thread TEB/TLS
// fixed VAs (0x70-0x73000000), and the main stack (0x7fff0000).
constexpr u64 kPerThreadTlsBase = 0x74000000ULL;
constexpr u64 kPerThreadTlsStride = 0x100000ULL; // 1 MiB / slot
constexpr u64 kPerThreadTebOff = 0x00000;
constexpr u64 kPerThreadArrOff = 0x01000;
constexpr u64 kPerThreadBlkOff = 0x02000;
constexpr u64 kPerThreadTrampOff = 0x20000;
constexpr u64 kPerThreadBlkMaxPages = 8; // 32 KiB static-TLS cap / thread
constexpr u32 kDllThreadAttach = 2;
constexpr u64 kTebOffSelf = 0x30;
constexpr u64 kTebOffTlsPtr = 0x58;

// Demand-grown secondary stacks occupy disjoint [guard,reservation]
// windows below the main TEB at 0x70000000. The legacy cursor remains the
// process-wide allocator, but each published Task owns only its own range.
constexpr u64 kThreadStackArenaLimit = 0x70000000ULL;
constexpr u64 kThreadStackReserveBytes = core::kUserStackReserveMin;
constexpr u64 kThreadStackInitialCommitBytes = core::kUserStackCommitMinPages * mm::kPageSize;
constexpr u64 kThreadStackFootprint = kThreadStackReserveBytes + core::kUserStackGuardPages * mm::kPageSize;

constexpr u64 kUserMaxExclusive = 0x0000800000000000ULL;

bool UserRangeIsValid(u64 user_va, u64 len)
{
    return len == 0 || (user_va < kUserMaxExclusive && len <= kUserMaxExclusive - user_va);
}

// Copy an arbitrary bounded user range a page at a time. Each individual
// transaction pins the resolved mapping against concurrent unmap/remap and
// never lets a physical-frame receipt or direct-map pointer escape.
bool ReadUserRange(mm::AddressSpace* as, u64 user_va, void* kernel_dst, u64 len)
{
    if (len == 0)
        return true;
    if (as == nullptr || kernel_dst == nullptr || !UserRangeIsValid(user_va, len))
        return false;

    auto* destination = static_cast<u8*>(kernel_dst);
    while (len != 0)
    {
        u64 chunk = mm::kPageSize - (user_va & (mm::kPageSize - 1));
        if (chunk > len)
            chunk = len;
        if (!mm::AddressSpaceReadUserMemory(as, user_va, destination, chunk))
            return false;
        user_va += chunk;
        destination += chunk;
        len -= chunk;
    }
    return true;
}

// Return an owned frame receipt whose direct-map alias is used only before
// the frame can become visible in an AddressSpace. The caller must either
// transfer the frame to a successful map transaction or FreeFrame it.
mm::PhysAddr AllocateInitializedFrame(const u8* initial, u64 initial_len)
{
    if (initial_len > mm::kPageSize || (initial_len != 0 && initial == nullptr))
        return mm::kNullFrame;

    const mm::PhysAddr frame = mm::AllocateFrame().value_or(mm::kNullFrame);
    if (frame == mm::kNullFrame)
        return mm::kNullFrame;
    {
        auto* private_page = static_cast<u8*>(mm::PhysToVirt(frame));
        for (u64 index = 0; index < mm::kPageSize; ++index)
            private_page[index] = 0;
        for (u64 index = 0; index < initial_len; ++index)
            private_page[index] = initial[index];
    }
    return frame;
}

// Replace one subsystem-owned TLS page without ever retaining an AS frame
// snapshot. The old per-slot page belongs to a completed thread;
// borrowed/colliding mappings are not detached and make the new map fail
// closed. Once mapping succeeds, ownership transfers to the AddressSpace.
bool ReplaceOwnedUserPageFromKernel(mm::AddressSpace* as, u64 user_va, u64 flags, const u8* initial, u64 initial_len)
{
    if (as == nullptr || (user_va & (mm::kPageSize - 1)) != 0)
        return false;

    const mm::PhysAddr frame = AllocateInitializedFrame(initial, initial_len);
    if (frame == mm::kNullFrame)
        return false;

    // Slots are recycled only after task death. Removing an old owned page
    // is therefore safe; a borrowed or absent page simply remains untouched.
    (void)mm::AddressSpaceUnmapUserPage(as, user_va);
    if (!mm::AddressSpaceMapUserPage(as, user_va, frame, flags))
    {
        mm::FreeFrame(frame);
        return false;
    }
    return true;
}

void ZeroPage(u8* page)
{
    for (u64 index = 0; index < mm::kPageSize; ++index)
        page[index] = 0;
}

// Give thread `slot` its own TEB + static-TLS block (a fresh copy
// of the process template) and, if the image registers TLS
// callbacks, an R-X trampoline that invokes each with
// DLL_THREAD_ATTACH before jumping to the real thread proc.
// out_teb_va  -> the thread's GSBASE (TEB.ThreadLocalStoragePointer
//                at +0x58 points at its private TLS slot array).
// out_entry_va -> trampoline (callbacks) or real_start (none).
bool SetupPerThreadTls(core::Process* proc, u32 slot, u64 real_start_va, u64 thread_param, u64* out_teb_va,
                       u64* out_entry_va)
{
    if (proc == nullptr || proc->as == nullptr || out_teb_va == nullptr || out_entry_va == nullptr)
        return false;

    const u64 region = kPerThreadTlsBase + static_cast<u64>(slot) * kPerThreadTlsStride;
    const u64 teb_va = region + kPerThreadTebOff;
    const u64 arr_va = region + kPerThreadArrOff;
    const u64 blk_va = region + kPerThreadBlkOff;
    const u64 tr_va = region + kPerThreadTrampOff;
    constexpr u64 kTlsTemplateMaxBytes = kPerThreadBlkMaxPages * mm::kPageSize;
    if (proc->tls_tmpl_raw > kTlsTemplateMaxBytes ||
        proc->tls_tmpl_zerofill > kTlsTemplateMaxBytes - proc->tls_tmpl_raw ||
        !UserRangeIsValid(proc->tls_tmpl_src_va, proc->tls_tmpl_raw))
    {
        arch::SerialWrite("[thread-tls] FAIL template too large\n");
        return false;
    }
    const u64 total = proc->tls_tmpl_raw + proc->tls_tmpl_zerofill;
    constexpr u64 rw = mm::kPagePresent | mm::kPageUser | mm::kPageWritable | mm::kPageNoExecute;
    u8 page_image[mm::kPageSize]{};

    // 1. TEB: clone the main-thread TEB page (inherits the PEB /
    //    PEB_LDR scaffold a CRT thread-attach may walk), then
    //    repoint NT_TIB.Self and TLS pointer at this thread's.
    if (!ReadUserRange(proc->as, proc->user_gs_base, page_image, mm::kPageSize))
    {
        arch::SerialWrite("[thread-tls] FAIL main-TEB read\n");
        return false;
    }
    for (u64 b = 0; b < 8; ++b)
    {
        page_image[kTebOffSelf + b] = static_cast<u8>((teb_va >> (b * 8)) & 0xFF);
        page_image[kTebOffTlsPtr + b] = static_cast<u8>((arr_va >> (b * 8)) & 0xFF);
    }
    if (!ReplaceOwnedUserPageFromKernel(proc->as, teb_va, rw, page_image, sizeof(page_image)))
        return false;

    // 2. Per-thread TLS slot array: slot[_tls_index(=0)] = block.
    ZeroPage(page_image);
    for (u64 b = 0; b < 8; ++b)
        page_image[b] = static_cast<u8>((blk_va >> (b * 8)) & 0xFF);
    if (!ReplaceOwnedUserPageFromKernel(proc->as, arr_va, rw, page_image, sizeof(page_image)))
        return false;

    // 3. Per-thread TLS data block: fresh copy of the template +
    //    zero-fill tail (so each thread's __declspec(thread) data
    //    is independent).
    const u64 npages = total == 0 ? 1 : ((total + mm::kPageSize - 1) / mm::kPageSize);
    for (u64 p = 0; p < npages; ++p)
    {
        ZeroPage(page_image);
        const u64 page_offset = p * mm::kPageSize;
        u64 raw_on_page = 0;
        if (page_offset < proc->tls_tmpl_raw)
        {
            raw_on_page = proc->tls_tmpl_raw - page_offset;
            if (raw_on_page > mm::kPageSize)
                raw_on_page = mm::kPageSize;
        }
        if (raw_on_page != 0 && !ReadUserRange(proc->as, proc->tls_tmpl_src_va + page_offset, page_image, raw_on_page))
        {
            arch::SerialWrite("[thread-tls] FAIL template read\n");
            return false;
        }
        if (!ReplaceOwnedUserPageFromKernel(proc->as, blk_va + page_offset, rw, page_image, sizeof(page_image)))
            return false;
    }

    *out_teb_va = teb_va;

    // 4. No callbacks -> run the real thread proc directly.
    if (proc->tls_cb_count == 0)
    {
        *out_entry_va = real_start_va;
        return true;
    }

    // 5. DLL_THREAD_ATTACH trampoline. Entry state (per
    //    EnterUserModeThread + DoThreadCreate stack setup):
    //    rcx=param, rsp%16==8, [rsp]=thread-exit trampoline.
    ZeroPage(page_image);
    u64 n = 0;
    bool emit_ok = true;
    auto emit = [&](u8 b)
    {
        if (n >= sizeof(page_image))
        {
            emit_ok = false;
            return;
        }
        page_image[n++] = b;
    };
    auto emit_u64 = [&](u64 v)
    {
        for (int i = 0; i < 8; ++i)
            emit(static_cast<u8>((v >> (i * 8)) & 0xFF));
    };
    emit(0x49);
    emit(0x89);
    emit(0xCF); // mov r15, rcx  (save thread param; r15 nonvolatile)
    emit(0x48);
    emit(0x83);
    emit(0xEC);
    emit(0x28); // sub rsp,0x28  (align for the Win64 calls)
    for (u32 i = 0; i < proc->tls_cb_count && i < core::Process::kTlsMaxCallbacks; ++i)
    {
        emit(0x48);
        emit(0xB9);
        emit_u64(proc->pe_image_base); // mov rcx, hinstDLL
        emit(0x31);
        emit(0xD2); // xor edx,edx
        emit(0xB2);
        emit(static_cast<u8>(kDllThreadAttach)); // mov dl,2
        emit(0x45);
        emit(0x31);
        emit(0xC0); // xor r8d,r8d
        emit(0x48);
        emit(0xB8);
        emit_u64(proc->tls_callbacks[i]); // mov rax, cb
        emit(0xFF);
        emit(0xD0); // call rax
    }
    emit(0x48);
    emit(0x83);
    emit(0xC4);
    emit(0x28); // add rsp,0x28  (restore rsp; [rsp]=exit-tramp intact)
    emit(0x4C);
    emit(0x89);
    emit(0xF9); // mov rcx, r15  (restore thread param)
    emit(0x48);
    emit(0xB8);
    emit_u64(real_start_va); // mov rax, real thread proc
    emit(0xFF);
    emit(0xE0); // jmp rax
    if (!emit_ok || !ReplaceOwnedUserPageFromKernel(proc->as, tr_va, mm::kPagePresent | mm::kPageUser, page_image, n))
    {
        return false;
    }
    (void)thread_param;
    *out_entry_va = tr_va;
    arch::SerialWrite("[thread-tls] per-thread TLS armed slot=");
    arch::SerialWriteHex(slot);
    arch::SerialWrite(" teb=");
    arch::SerialWriteHex(teb_va);
    arch::SerialWrite(" cbs=");
    arch::SerialWriteHex(proc->tls_cb_count);
    arch::SerialWrite("\n");
    return true;
}

} // namespace

void DoThreadCreate(arch::TrapFrame* frame)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using ::duetos::core::Process;

    // kCapSpawnThread is gated centrally by `SyscallGate`
    // (cap_table.def) — a process missing the cap never reaches
    // this handler.
    core::Process* proc = core::CurrentProcess();
    if (proc == nullptr)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    const u64 start_va = frame->rdi;
    const u64 param = frame->rsi;

    // Basic input validation. start_va must be non-zero and in
    // the user half of the canonical VA range (we enforce the
    // latter by requiring the high bit unset — the full
    // canonical-form check is the paging layer's problem and
    // would catch any truly wild value on the first #PF).
    if (start_va == 0 || (start_va & (1ULL << 63)) != 0)
    {
        SerialWrite("[thread] create FAIL invalid rip pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" rip=");
        SerialWriteHex(start_va);
        SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Find and CLAIM a free thread-table slot. The scan + claim must
    // be a single process-wide critical section: KMalloc /
    // AllocateFrame / SchedCreateUser further down can sleep or
    // yield, and a concurrent SYS_THREAD_CREATE on another CPU must
    // not pick the same slot. Disabling local interrupts alone does
    // not serialize that peer.
    // The handle metadata (tid, user_stack_va) gets filled in further
    // down once SchedCreateUser succeeds.
    u32 slot = Process::kWin32ThreadCap;
    u64 claim_generation = 0;
    core::UserStackRange user_stack{};
    bool stack_arena_exhausted = false;
    {
        const sync::IrqFlags flags = sync::SpinLockAcquire(proc->win32_thread_lock);
        const u64 stack_guard_lo = proc->thread_stack_cursor;
        if ((stack_guard_lo & (mm::kPageSize - 1)) != 0 ||
            stack_guard_lo > kThreadStackArenaLimit - kThreadStackFootprint)
        {
            stack_arena_exhausted = true;
        }
        else
        {
            user_stack = core::UserStackPlanAt(stack_guard_lo + kThreadStackFootprint, kThreadStackReserveBytes,
                                               kThreadStackInitialCommitBytes, nullptr);
            if (!core::UserStackRangeIsValid(user_stack) || user_stack.guard_lo != stack_guard_lo)
            {
                stack_arena_exhausted = true;
            }
        }
        if (!stack_arena_exhausted)
        {
            for (u32 i = 0; i < Process::kWin32ThreadCap; ++i)
            {
                if (!proc->win32_threads[i].in_use)
                {
                    slot = i;
                    proc->win32_threads[i].in_use = true;
                    proc->win32_threads[i].creating = true;
                    proc->win32_threads[i].handle_open = false;
                    proc->win32_threads[i].exited = false;
                    proc->win32_threads[i].exit_code = 0x103; // STILL_ACTIVE for this generation
                    ++proc->win32_threads[i].generation;
                    if (proc->win32_threads[i].generation == 0)
                        ++proc->win32_threads[i].generation;
                    claim_generation = proc->win32_threads[i].generation;
                    proc->win32_threads[i].tid = 0;
                    proc->win32_threads[i].user_stack_va = 0;
                    proc->thread_stack_cursor = user_stack.top;
                    break;
                }
            }
        }
        sync::SpinLockRelease(proc->win32_thread_lock, flags);
    }
    if (slot == Process::kWin32ThreadCap)
    {
        SerialWrite(stack_arena_exhausted ? "[thread] create stack-arena exhausted pid="
                                          : "[thread] create out-of-handles pid=");
        SerialWriteHex(proc->pid);
        SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }
    auto release_claimed_slot = [&]()
    {
        const sync::IrqFlags flags = sync::SpinLockAcquire(proc->win32_thread_lock);
        auto& th = proc->win32_threads[slot];
        if (th.in_use && th.creating && th.generation == claim_generation)
        {
            th.in_use = false;
            th.creating = false;
            th.handle_open = false;
            th.exited = false;
            th.exit_code = 0x103;
            th.tid = 0;
            th.user_stack_va = 0;
        }
        sync::SpinLockRelease(proc->win32_thread_lock, flags);
    };

    // The spin-protected cursor claim makes the VA choice unique among
    // peer creators. The address-space reservation is acquired only after
    // dropping that spinlock: it takes the AS mutation mutex and may grow
    // its ledger. From this point every stack PTE requires the exact token.
    // The cursor is deliberately not rolled back on failure because a peer
    // may already have claimed a later window.
    mm::AddressSpaceReservationToken stack_reservation{};
    if (!mm::AddressSpaceReserveUserRange(proc->as, user_stack.guard_lo, user_stack.top, &stack_reservation))
    {
        SerialWrite("[thread] create FAIL stack reservation conflict/exhaustion pid=");
        SerialWriteHex(proc->pid);
        SerialWrite("\n");
        release_claimed_slot();
        frame->rax = static_cast<u64>(-1);
        return;
    }
    auto unwind_stack = [&]() { core::UserStackReleaseOwnedMappings(proc->as, user_stack, stack_reservation); };

    // Commit only the bounded initial top pages as RW + user + NX;
    // page faults grow the current Task's descriptor downward.
    const u64 stack_pages = (user_stack.top - user_stack.commit_lo) / mm::kPageSize;
    for (u64 p = 0; p < stack_pages; ++p)
    {
        const mm::PhysAddr frame_phys = AllocateInitializedFrame(nullptr, 0);
        if (frame_phys == mm::kNullFrame)
        {
            SerialWrite("[thread] create FAIL stack frame alloc pid=");
            SerialWriteHex(proc->pid);
            SerialWrite(" idx=");
            SerialWriteHex(p);
            SerialWrite("/");
            SerialWriteHex(stack_pages);
            SerialWrite("\n");
            unwind_stack();
            // Release the slot we claimed above; no task ever attaches.
            release_claimed_slot();
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 page_va = user_stack.commit_lo + p * mm::kPageSize;
        if (!mm::AddressSpaceMapReservedUserPage(proc->as, stack_reservation, page_va, frame_phys,
                                                 mm::kPagePresent | mm::kPageUser | mm::kPageWritable |
                                                     mm::kPageNoExecute))
        {
            mm::FreeFrame(frame_phys);
            unwind_stack();
            release_claimed_slot();
            frame->rax = static_cast<u64>(-1);
            return;
        }
    }
    const u64 stack_top = user_stack.top;
    // Microsoft x64 ABI at function entry:
    //   rsp % 16 == 8                — `call` pushed 8 bytes
    //   [rsp]                         — return address
    //   [rsp+8..rsp+0x28)             — 32-byte shadow space the
    //                                   callee may freely spill
    //                                   register args into
    // If we set rsp = stack_top - 8 the shadow space spans
    // [stack_top..stack_top+0x20) — entirely OUTSIDE the mapped
    // stack page. The very first prolog instruction that touches
    // a shadow slot (`mov [rsp+8], rcx`, etc.) takes a #PF and the
    // task is killed before it can run, leaving the matching
    // win32_threads slot's exit_code stuck at STILL_ACTIVE forever.
    //
    // Bias rsp down by 0x28 so the shadow space lands at
    // [stack_top-0x20..stack_top), well inside the mapped page.
    // 0x28 mod 16 == 8, so the 16n+8 alignment requirement still
    // holds. The matching trampoline VA is planted at the new
    // [rsp] location (page offset 0x1000-0x28 = 0xfd8) instead of
    // the old page-end - 8 slot.
    constexpr u64 kShadowReserve = 0x28;
    const u64 user_rsp = stack_top - kShadowReserve;

    const u64 thread_exit_va = ::duetos::win32::kWin32ThreadExitTrampVa;
    if (!mm::AddressSpaceWriteUserMemory(proc->as, user_rsp, &thread_exit_va, sizeof(thread_exit_va)))
    {
        SerialWrite("[thread] create FAIL stack return-address write pid=");
        SerialWriteHex(proc->pid);
        SerialWrite("\n");
        unwind_stack();
        release_claimed_slot();
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Build the kernel-heap ThreadDesc that Ring3ThreadEntry
    // will consume. Heap-allocated so the ring-0 stack frame
    // for this syscall can be freed before the new Task runs.
    auto* desc = static_cast<ThreadDesc*>(mm::KMalloc(sizeof(ThreadDesc)));
    if (desc == nullptr)
    {
        SerialWrite("[thread] create FAIL heap alloc for ThreadDesc\n");
        unwind_stack();
        release_claimed_slot();
        frame->rax = static_cast<u64>(-1);
        return;
    }
    desc->start_va = start_va;
    desc->param = param;
    desc->user_rsp = user_rsp;
    desc->user_gs_base = proc->user_gs_base;

    // T6-01 per-thread half: a TLS-using PE's worker thread gets
    // its OWN TEB + static-TLS block (independent
    // __declspec(thread) storage) and DLL_THREAD_ATTACH callbacks
    // before its proc. On any failure fall back to the shared-TEB
    // path (callbacks skipped, shared TLS) rather than failing the
    // create — degraded but not fatal.
    u64 per_thread_teb = 0;
    if (proc->tls_present)
    {
        u64 teb_va = 0;
        u64 entry_va = 0;
        if (SetupPerThreadTls(proc, slot, start_va, param, &teb_va, &entry_va))
        {
            desc->user_gs_base = teb_va;
            desc->start_va = entry_va;
            per_thread_teb = teb_va;
        }
        else
        {
            SerialWrite("[thread] per-thread TLS setup failed — shared-TEB fallback\n");
        }
    }

    // Retain the process so the new Task can share it. The
    // scheduler Task will release on death via the reaper — same
    // contract as SchedCreateUser's documented caller discipline.
    core::ProcessRetain(proc);

    // Name: short thread label. Pin to the process's pid + slot
    // for debugging; a real Win32 caller would pass a name via
    // SetThreadDescription, which is a future syscall.
    char thread_name[32] = {};
    // Open-coded "thread-<pid>-<slot>" — avoid dragging a
    // full sprintf in just for this.
    u32 nlen = 0;
    const char* prefix = "thread-";
    for (u32 i = 0; prefix[i] != '\0' && nlen < sizeof(thread_name) - 1; ++i, ++nlen)
        thread_name[nlen] = prefix[i];
    // lowercase hex digits for pid + slot, 2 hex each — the
    // debugger + logs only need to disambiguate small counts.
    auto hexd = [&](u8 v)
    {
        const char table[] = "0123456789abcdef";
        if (nlen < sizeof(thread_name) - 1)
            thread_name[nlen++] = table[(v >> 4) & 0xF];
        if (nlen < sizeof(thread_name) - 1)
            thread_name[nlen++] = table[v & 0xF];
    };
    hexd(static_cast<u8>(proc->pid & 0xFF));
    if (nlen < sizeof(thread_name) - 1)
        thread_name[nlen++] = '-';
    hexd(static_cast<u8>(slot));
    thread_name[nlen] = '\0';

    ThreadPrepareContext prepare_context{proc,           slot, claim_generation, user_stack, stack_reservation,
                                         per_thread_teb, 0};
    const sched::TaskCreateResult result = sched::SchedCreateUserPrepared(&Ring3ThreadEntry, desc, thread_name, proc,
                                                                          &PrepareWin32ThreadTask, &prepare_context);
    if (!result.created)
    {
        SerialWrite("[thread] create FAIL SchedCreateUser\n");
        unwind_stack();
        mm::KFree(desc);
        // ProcessRetain was consumed by SchedCreateUser's
        // gate-denial branch (ProcessRelease there) on nullptr
        // return. No manual release here — see sched.cpp.
        release_claimed_slot();
        frame->rax = static_cast<u64>(-1);
        return;
    }
    KASSERT(result.tid == prepare_context.tid, "win32/thread", "Task receipt disagrees with prepared handle TID");

    const u64 handle = Process::kWin32ThreadBase + slot;
    SerialWrite("[thread] create ok pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" slot=");
    SerialWriteHex(slot);
    SerialWrite(" handle=");
    SerialWriteHex(handle);
    SerialWrite(" start=");
    SerialWriteHex(start_va);
    SerialWrite(" stack=[");
    SerialWriteHex(user_stack.reserve_lo);
    SerialWrite("..");
    SerialWriteHex(user_stack.top);
    SerialWrite(") guard=");
    SerialWriteHex(user_stack.guard_lo);
    SerialWrite("\n");
    custom::OnHandleAlloc(proc, handle, static_cast<u32>(core::SYS_THREAD_CREATE), frame->rip);
    {
        const sync::IrqFlags flags = sync::SpinLockAcquire(proc->win32_thread_lock);
        auto& th = proc->win32_threads[slot];
        KASSERT(th.in_use && th.creating && th.generation == claim_generation && th.tid == prepare_context.tid &&
                    th.tid != 0,
                "win32/thread", "published task lost reserved handle slot");
        th.handle_open = true;
        th.creating = false;
        frame->rax = handle;
        sync::SpinLockRelease(proc->win32_thread_lock, flags);
    }
}

namespace
{

constexpr u64 kThreadWaitObject0 = 0;
constexpr u64 kThreadWaitTimeout = 0x102;
constexpr u64 kThreadWaitInfiniteMs = 0xFFFFFFFFULL;
constexpr u64 kThreadWaitMsPerTick = 10;

struct ThreadWaitSnapshot
{
    bool exited;
    u64 generation;
    u64 tid;
    u64 event_sequence;
};

bool SnapshotThreadWait(core::Process* process, u64 slot, u64 expected_generation, u64 expected_tid,
                        ThreadWaitSnapshot* snapshot)
{
    KASSERT(process != nullptr && snapshot != nullptr && slot < core::Process::kWin32ThreadCap, "win32/thread",
            "invalid thread wait snapshot request");

    bool valid = false;
    const sync::IrqFlags flags = sync::SpinLockAcquire(process->win32_thread_lock);
    const auto& row = process->win32_threads[slot];
    if (row.in_use && row.handle_open && !row.creating && row.generation != 0 && row.tid != 0 &&
        (expected_generation == 0 ||
         (row.generation == expected_generation && row.tid == expected_tid)))
    {
        snapshot->exited = row.exited;
        snapshot->generation = row.generation;
        snapshot->tid = row.tid;
        snapshot->event_sequence = __atomic_load_n(&row.event_sequence, __ATOMIC_ACQUIRE);
        valid = true;
    }
    sync::SpinLockRelease(process->win32_thread_lock, flags);
    return valid;
}

u64 ThreadWaitDeadlineFromNow(u64 now, u64 ticks)
{
    return ticks > (~u64{0} - now) ? ~u64{0} : now + ticks;
}

bool ThreadWaitDeadlineReached(u64 now, u64 deadline)
{
    return static_cast<i64>(now - deadline) >= 0;
}

} // namespace

void DoThreadWait(arch::TrapFrame* frame)
{
    core::Process* process = core::CurrentProcess();
    const u64 handle = frame->rdi;
    if (process == nullptr || handle < core::Process::kWin32ThreadBase ||
        handle >= core::Process::kWin32ThreadBase + core::Process::kWin32ThreadCap)
    {
        frame->rax = static_cast<u64>(-1);
        return;
    }

    const u64 slot = util::MaskedIndex(handle - core::Process::kWin32ThreadBase,
                                       core::Process::kWin32ThreadCap);
    const u64 timeout_ms = frame->rsi & 0xFFFFFFFFULL;
    const bool infinite = timeout_ms == kThreadWaitInfiniteMs;
    const u64 timeout_ticks = infinite ? 0 : (timeout_ms + (kThreadWaitMsPerTick - 1)) / kThreadWaitMsPerTick;
    const u64 deadline = infinite ? 0 : ThreadWaitDeadlineFromNow(sched::SchedNowTicks(), timeout_ticks);
    u64 expected_generation = 0;
    u64 expected_tid = 0;

    for (;;)
    {
        ThreadWaitSnapshot snapshot{};
        if (!SnapshotThreadWait(process, slot, expected_generation, expected_tid, &snapshot))
        {
            frame->rax = static_cast<u64>(-1);
            return;
        }
        if (expected_generation == 0)
        {
            expected_generation = snapshot.generation;
            expected_tid = snapshot.tid;
        }
        if (snapshot.exited)
        {
            frame->rax = kThreadWaitObject0;
            return;
        }

        u64 remaining_ticks = 0;
        if (!infinite)
        {
            const u64 now = sched::SchedNowTicks();
            if (ThreadWaitDeadlineReached(now, deadline))
            {
                frame->rax = kThreadWaitTimeout;
                return;
            }
            remaining_ticks = deadline - now;
        }

        sched::WaitQueueBlockResult block_result;
        auto* waiters = &process->win32_threads[slot].waiters;
        const auto* sequence = &process->win32_threads[slot].event_sequence;
        if (snapshot.event_sequence == ~u64{0})
        {
            // A stable sequence never wraps onto an old observation. Once it
            // saturates, bounded cancellable waits guarantee a rescan even if
            // an exit wake races just before enqueue.
            const u64 fallback_ticks = infinite || remaining_ticks > 1 ? 1 : remaining_ticks;
            block_result = sched::WaitQueueBlockTimeoutCancellable(waiters, fallback_ticks);
        }
        else if (infinite)
        {
            block_result = sched::WaitQueueBlockIfSequenceUnchangedCancellable(
                waiters, sequence, snapshot.event_sequence);
        }
        else
        {
            block_result = sched::WaitQueueBlockIfSequenceUnchangedTimeoutCancellable(
                waiters, sequence, snapshot.event_sequence, remaining_ticks);
        }

        if (block_result == sched::WaitQueueBlockResult::Cancelled)
        {
            // Internal unwind sentinel only. The syscall dispatcher's outer
            // cancellation guard exits the task before ring 3 observes it.
            frame->rax = static_cast<u64>(-1);
            return;
        }
        // Woken, SequenceChanged, and TimedOut all rescan exact generation,
        // TID, and terminal state before selecting the public wait result.
    }
}

} // namespace duetos::subsystems::win32
