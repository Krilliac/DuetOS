#include "ring3_smoke.h"

#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/usermode.h"
#include "../mm/frame_allocator.h"
#include "../mm/page.h"
#include "../mm/paging.h"
#include "../sched/sched.h"
#include "klog.h"
#include "panic.h"

/*
 * First ring-3 slice — see ring3_smoke.h for the design contract.
 *
 * Chosen user VA layout:
 *
 *   0x0000000040000000 : one 4 KiB code page  (U | P, exec)
 *   0x0000000040010000 : one 4 KiB stack page (U | P | W | NX)
 *
 * Why 1 GiB (0x40000000), not the traditional 0x400000: the first 1 GiB
 * of virtual address space is paved by boot.S with 2 MiB PS-mapped
 * identity entries, and the v0 paging API explicitly panics if asked
 * to install a 4 KiB mapping inside a PS region (it would have to
 * split the PS page). 0x40000000 lives in PDPT[1], which boot.S left
 * empty — the walker creates fresh PD + PT tables on the first MapPage
 * call, and we get the clean 4 KiB granularity we need for W^X. The
 * stack sits 64 KiB above so there's obvious headroom between the two
 * regions if the payload ever grows.
 *
 * Payload exercises two independent things in order:
 *
 *     user_entry:
 *         pause                 ; F3 90 ─┐
 *         pause                 ; F3 90  │ Four `pause` iterations give
 *         pause                 ; F3 90  │ the 100 Hz timer a few ticks'
 *         pause                 ; F3 90 ─┘ worth of chance to preempt us
 *                                          at least once while ring-3.
 *         xor eax, eax          ; 31 C0    rax = 0 (SYS_EXIT)
 *         xor edi, edi          ; 31 FF    rdi = 0 (exit code)
 *         int 0x80              ; CD 80    trap into the kernel syscall gate
 *         hlt                   ; F4       unreachable — a syscall return
 *                                          here would be a bug
 *
 * 13 bytes. No privileged instructions on the happy path: all four
 * pauses are ring-3-legal, `int 0x80` is explicitly what the DPL=3
 * gate allows, and the trailing `hlt` only executes if the syscall
 * returns (which SYS_EXIT promises never to). If the gate were
 * misconfigured (DPL=0) the `int 0x80` would #GP on delivery, which
 * is the clean failure mode we want — the trap dispatcher prints
 * a record rather than a silent misbehaviour.
 */

namespace customos::core
{

namespace
{

constexpr u64 kUserCodeVirt = 0x0000000040000000ULL;
constexpr u64 kUserStackVirt = 0x0000000040010000ULL;
constexpr u64 kUserStackTop = kUserStackVirt + mm::kPageSize;

// 13-byte user payload: four pauses (so the timer gets a chance to
// preempt us in ring 3 at least once), then SYS_EXIT via int 0x80.
// Emitted as raw bytes rather than a .S file so the user-mode VA
// layout, the bytes, and the "hands-off: this runs in ring 3"
// context all stay in one place.
constexpr u8 kUserPayload[] = {
    0xF3, 0x90, // pause
    0xF3, 0x90, // pause
    0xF3, 0x90, // pause
    0xF3, 0x90, // pause
    0x31, 0xC0, // xor eax, eax  -> rax = 0  (SYS_EXIT)
    0x31, 0xFF, // xor edi, edi  -> rdi = 0  (exit code)
    0xCD, 0x80, // int 0x80
    0xF4,       // hlt (unreachable)
};

[[noreturn]] void Ring3SmokeMain(void*)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace customos::mm;

    SerialWrite("[ring3] smoke task starting\n");

    // ---- 1) Allocate + map the user code page. -----------------------------

    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "failed to allocate user code frame");
    }

    // Write the payload via the direct-map alias — the MapPage below
    // flips on kPageUser but ordinary kernel code still reaches the
    // frame through the higher-half direct map. Doing the write
    // before the user-mode install order lets us verify byte values
    // before any ring-3 entry is even possible.
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < sizeof(kUserPayload); ++i)
    {
        code_direct[i] = kUserPayload[i];
    }

    // kPagePresent + kPageUser only — no kPageWritable (W^X for user
    // code) and no kPageNoExecute (exec is exactly what we want).
    MapPage(kUserCodeVirt, code_frame, kPagePresent | kPageUser);

    // ---- 2) Allocate + map the user stack page. ----------------------------

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "failed to allocate user stack frame");
    }

    MapPage(kUserStackVirt, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // ---- 3) Publish kernel stack top to the TSS so user→kernel traps land. -

    const u64 kstack_top = sched::SchedCurrentKernelStackTop();
    if (kstack_top == 0)
    {
        // CurrentTask()'s kernel stack must exist — this function runs as
        // an entry fn of a SchedCreate'd task, which always has one.
        Panic("core/ring3", "SchedCurrentKernelStackTop returned 0");
    }
    arch::TssSetRsp0(kstack_top);

    SerialWrite("[ring3] user rip=");
    SerialWriteHex(kUserCodeVirt);
    SerialWrite(" user rsp=");
    SerialWriteHex(kUserStackTop);
    SerialWrite(" rsp0=");
    SerialWriteHex(kstack_top);
    SerialWrite("\n");

    LogWithValue(LogLevel::Info, "core/ring3", "entering user mode at rip", kUserCodeVirt);

    // ---- 4) Enter ring 3. Never returns. -----------------------------------

    arch::EnterUserMode(kUserCodeVirt, kUserStackTop);
}

} // namespace

void StartRing3SmokeTask()
{
    sched::SchedCreate(&Ring3SmokeMain, nullptr, "ring3-smoke");
    Log(LogLevel::Info, "core/ring3", "ring3 smoke thread queued");
}

} // namespace customos::core
