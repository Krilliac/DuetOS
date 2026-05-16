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

// Map `va` in `proc->as` if unmapped, else reuse the existing
// frame (slots are recycled across thread create/exit, so the
// per-slot region may already be mapped from a prior thread —
// reusing avoids an AddressSpaceMapUserPage "virt already mapped"
// panic without needing exit-time teardown). Returns the
// kernel-direct pointer to the page, or nullptr on OOM.
u8* MapOrReuse(core::Process* proc, u64 va, u64 flags)
{
    mm::PhysAddr fr = mm::AddressSpaceLookupUserFrame(proc->as, va & ~0xFFFULL);
    if (fr == mm::kNullFrame)
    {
        fr = mm::AllocateFrame();
        if (fr == mm::kNullFrame)
            return nullptr;
        mm::AddressSpaceMapUserPage(proc->as, va, fr, flags);
    }
    return static_cast<u8*>(mm::PhysToVirt(fr));
}

// Copy `len` bytes from `proc->as` VA `src` into `dst`. Returns
// false if any source page is unmapped.
bool AsReadInto(core::Process* proc, u64 src, u8* dst, u64 len)
{
    for (u64 i = 0; i < len; ++i)
    {
        const u64 cur = src + i;
        const mm::PhysAddr fr = mm::AddressSpaceLookupUserFrame(proc->as, cur & ~0xFFFULL);
        if (fr == mm::kNullFrame)
            return false;
        dst[i] = static_cast<const u8*>(mm::PhysToVirt(fr))[cur & 0xFFFULL];
    }
    return true;
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
    const u64 region = kPerThreadTlsBase + static_cast<u64>(slot) * kPerThreadTlsStride;
    const u64 teb_va = region + kPerThreadTebOff;
    const u64 arr_va = region + kPerThreadArrOff;
    const u64 blk_va = region + kPerThreadBlkOff;
    const u64 tr_va = region + kPerThreadTrampOff;
    const u64 total = proc->tls_tmpl_raw + proc->tls_tmpl_zerofill;
    if (total > kPerThreadBlkMaxPages * mm::kPageSize)
    {
        arch::SerialWrite("[thread-tls] FAIL template too large\n");
        return false;
    }
    constexpr u64 rw = mm::kPagePresent | mm::kPageUser | mm::kPageWritable | mm::kPageNoExecute;

    // 1. TEB: clone the main-thread TEB page (inherits the PEB /
    //    PEB_LDR scaffold a CRT thread-attach may walk), then
    //    repoint NT_TIB.Self and TLS pointer at this thread's.
    u8* teb = MapOrReuse(proc, teb_va, rw);
    if (teb == nullptr)
        return false;
    if (!AsReadInto(proc, proc->user_gs_base, teb, mm::kPageSize))
    {
        arch::SerialWrite("[thread-tls] FAIL main-TEB read\n");
        return false;
    }
    for (u64 b = 0; b < 8; ++b)
    {
        teb[kTebOffSelf + b] = static_cast<u8>((teb_va >> (b * 8)) & 0xFF);
        teb[kTebOffTlsPtr + b] = static_cast<u8>((arr_va >> (b * 8)) & 0xFF);
    }

    // 2. Per-thread TLS slot array: slot[_tls_index(=0)] = block.
    u8* arr = MapOrReuse(proc, arr_va, rw);
    if (arr == nullptr)
        return false;
    for (u64 i = 0; i < mm::kPageSize; ++i)
        arr[i] = 0;
    for (u64 b = 0; b < 8; ++b)
        arr[b] = static_cast<u8>((blk_va >> (b * 8)) & 0xFF);

    // 3. Per-thread TLS data block: fresh copy of the template +
    //    zero-fill tail (so each thread's __declspec(thread) data
    //    is independent).
    const u64 npages = total == 0 ? 1 : ((total + mm::kPageSize - 1) / mm::kPageSize);
    for (u64 p = 0; p < npages; ++p)
    {
        u8* pg = MapOrReuse(proc, blk_va + p * mm::kPageSize, rw);
        if (pg == nullptr)
            return false;
        for (u64 i = 0; i < mm::kPageSize; ++i)
            pg[i] = 0;
    }
    for (u64 done = 0; done < proc->tls_tmpl_raw;)
    {
        u8 tmp[256];
        u64 chunk = proc->tls_tmpl_raw - done;
        if (chunk > sizeof(tmp))
            chunk = sizeof(tmp);
        if (!AsReadInto(proc, proc->tls_tmpl_src_va + done, tmp, chunk))
        {
            arch::SerialWrite("[thread-tls] FAIL template read\n");
            return false;
        }
        for (u64 i = 0; i < chunk; ++i)
        {
            const u64 off = done + i;
            u8* pg = MapOrReuse(proc, blk_va + (off & ~0xFFFULL), rw);
            if (pg == nullptr)
                return false;
            pg[off & 0xFFFULL] = tmp[i];
        }
        done += chunk;
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
    u8* code = MapOrReuse(proc, tr_va, mm::kPagePresent | mm::kPageUser); // R-X
    if (code == nullptr)
        return false;
    u64 n = 0;
    auto emit = [&](u8 b) { code[n++] = b; };
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
    // be a single critical section: KMalloc / AllocateFrame /
    // SchedCreateUser further down can sleep or yield, and a
    // concurrent SYS_THREAD_CREATE on this same process must not
    // pick the same slot. Mark `in_use = true` while still under the
    // IRQ-off window so the second caller's scan sees this slot busy.
    // The handle metadata (task, user_stack_va) gets filled in further
    // down once SchedCreateUser succeeds.
    u32 slot = Process::kWin32ThreadCap;
    {
        arch::Cli();
        for (u32 i = 0; i < Process::kWin32ThreadCap; ++i)
        {
            if (!proc->win32_threads[i].in_use)
            {
                slot = i;
                proc->win32_threads[i].in_use = true;
                proc->win32_threads[i].task = nullptr;
                break;
            }
        }
        arch::Sti();
    }
    if (slot == Process::kWin32ThreadCap)
    {
        SerialWrite("[thread] create out-of-handles pid=");
        SerialWriteHex(proc->pid);
        SerialWrite("\n");
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Carve a fresh stack range off the process's thread-stack
    // cursor. N pages, writable + NX + user. Stack grows down,
    // so rsp starts at (base + N*4096 - 8).
    //
    // On partial-OOM we bump the cursor by the FULL requested range
    // even though only `p` pages made it in — same pattern as
    // vmap_syscall's partial-OOM path. Without this the next
    // DoThreadCreate would try to re-map the successfully-allocated
    // pages' VAs and AddressSpaceMapUserPage would panic on
    // "virt already mapped". Leak is bounded; frames get reclaimed
    // when the process dies (AS destructor walks regions).
    const u64 stack_base_va = proc->thread_stack_cursor;
    const u64 stack_pages = Process::kV0ThreadStackPages;
    mm::PhysAddr top_frame_phys = mm::kNullFrame;
    for (u64 p = 0; p < stack_pages; ++p)
    {
        const mm::PhysAddr frame_phys = mm::AllocateFrame();
        if (frame_phys == mm::kNullFrame)
        {
            SerialWrite("[thread] create FAIL stack frame alloc pid=");
            SerialWriteHex(proc->pid);
            SerialWrite(" idx=");
            SerialWriteHex(p);
            SerialWrite("/");
            SerialWriteHex(stack_pages);
            SerialWrite("\n");
            proc->thread_stack_cursor += stack_pages * mm::kPageSize;
            // Release the slot we claimed above; no task ever attaches.
            proc->win32_threads[slot].in_use = false;
            frame->rax = static_cast<u64>(-1);
            return;
        }
        const u64 page_va = stack_base_va + p * mm::kPageSize;
        mm::AddressSpaceMapUserPage(proc->as, page_va, frame_phys,
                                    mm::kPagePresent | mm::kPageUser | mm::kPageWritable | mm::kPageNoExecute);
        if (p == stack_pages - 1)
            top_frame_phys = frame_phys;
    }
    proc->thread_stack_cursor += stack_pages * mm::kPageSize;
    const u64 stack_top = stack_base_va + stack_pages * mm::kPageSize;
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

    auto* top_page_kva = static_cast<u8*>(mm::PhysToVirt(top_frame_phys));
    auto* retaddr_slot = reinterpret_cast<u64*>(top_page_kva + mm::kPageSize - kShadowReserve);
    *retaddr_slot = ::duetos::win32::kWin32ThreadExitTrampVa;

    // Build the kernel-heap ThreadDesc that Ring3ThreadEntry
    // will consume. Heap-allocated so the ring-0 stack frame
    // for this syscall can be freed before the new Task runs.
    auto* desc = static_cast<ThreadDesc*>(mm::KMalloc(sizeof(ThreadDesc)));
    if (desc == nullptr)
    {
        SerialWrite("[thread] create FAIL heap alloc for ThreadDesc\n");
        proc->win32_threads[slot].in_use = false;
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
    static char s_name[32] = {};
    // Open-coded "thread-<pid>-<slot>" — avoid dragging a
    // full sprintf in just for this.
    u32 nlen = 0;
    const char* prefix = "thread-";
    for (u32 i = 0; prefix[i] != '\0' && nlen < sizeof(s_name) - 1; ++i, ++nlen)
        s_name[nlen] = prefix[i];
    // lowercase hex digits for pid + slot, 2 hex each — the
    // debugger + logs only need to disambiguate small counts.
    auto hexd = [&](u8 v)
    {
        const char table[] = "0123456789abcdef";
        if (nlen < sizeof(s_name) - 1)
            s_name[nlen++] = table[(v >> 4) & 0xF];
        if (nlen < sizeof(s_name) - 1)
            s_name[nlen++] = table[v & 0xF];
    };
    hexd(static_cast<u8>(proc->pid & 0xFF));
    if (nlen < sizeof(s_name) - 1)
        s_name[nlen++] = '-';
    hexd(static_cast<u8>(slot));
    s_name[nlen] = '\0';

    sched::Task* t = sched::SchedCreateUser(&Ring3ThreadEntry, desc, s_name, proc);
    if (t == nullptr)
    {
        SerialWrite("[thread] create FAIL SchedCreateUser\n");
        mm::KFree(desc);
        // ProcessRetain was consumed by SchedCreateUser's
        // gate-denial branch (ProcessRelease there) on nullptr
        // return. No manual release here — see sched.cpp.
        proc->win32_threads[slot].in_use = false;
        frame->rax = static_cast<u64>(-1);
        return;
    }

    // Pin the per-thread TEB as this Task's GSBASE override so the
    // scheduler restores IT (not the process's shared TEB) into
    // KERNEL_GS_BASE on every resume — without this the worker's
    // return-to-user swapgs would load the main thread's TEB and
    // its __declspec(thread) reads would hit the wrong block.
    if (per_thread_teb != 0)
        sched::SchedSetUserGsOverride(t, per_thread_teb);

    // The pre-claim above already set in_use=true; the (slot,task)
    // pair is now finalised so future Lookup hits this row.
    proc->win32_threads[slot].in_use = true;
    proc->win32_threads[slot].task = t;
    proc->win32_threads[slot].user_stack_va = stack_base_va;

    const u64 handle = Process::kWin32ThreadBase + slot;
    SerialWrite("[thread] create ok pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" slot=");
    SerialWriteHex(slot);
    SerialWrite(" handle=");
    SerialWriteHex(handle);
    SerialWrite(" start=");
    SerialWriteHex(start_va);
    SerialWrite(" stack_base=");
    SerialWriteHex(stack_base_va);
    SerialWrite("\n");
    custom::OnHandleAlloc(proc, handle, static_cast<u32>(core::SYS_THREAD_CREATE), frame->rip);
    frame->rax = handle;
}

} // namespace duetos::subsystems::win32
