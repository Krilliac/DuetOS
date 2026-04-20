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
 * Payload exercises the full user→kernel ABI in order:
 *
 *     user_entry:                  ; at 0x40000000
 *         pause                    ; F3 90   give the timer a tick
 *         pause                    ; F3 90
 *         mov eax, 2               ; B8 02 00 00 00   rax = SYS_WRITE
 *         mov edi, 1               ; BF 01 00 00 00   rdi = 1 (stdout)
 *         mov esi, 0x40000080      ; BE 80 00 00 40   rsi = msg ptr
 *         mov edx, <msg_len>       ; BA nn 00 00 00   rdx = length
 *         int 0x80                 ; CD 80
 *         mov eax, 3               ; B8 03 00 00 00   rax = SYS_YIELD
 *         int 0x80                 ; CD 80   cooperative yield
 *         xor eax, eax             ; 31 C0   rax = 0 (SYS_EXIT)
 *         xor edi, edi             ; 31 FF   rdi = 0 (exit code)
 *         int 0x80                 ; CD 80
 *         hlt                      ; F4      unreachable
 *
 *     msg:                         ; at 0x40000080
 *         "Hello from ring 3!\n"   ; 19 bytes
 *
 * Wiring the string at a fixed offset (0x80 = 128 bytes into the
 * code page) keeps the immediates in the instruction stream
 * constant — without that, a `lea rsi, [rip+N]` would pin the
 * string's address to the instruction's position, turning every
 * future code tweak into a chase through the encoding. 128 bytes
 * is well past the 24-byte instruction block; the gap between
 * them is zeroed at install time so a mis-jump lands on `add
 * [rax], al` (`00 00`) forever and is harmless.
 *
 * The pause/pause prefix gives the 100 Hz timer at least one chance
 * to preempt us while we're genuinely in ring 3 — the evidence that
 * the scheduler handles a user-mode-interrupted context correctly.
 * Everything after the prefix is a linear walk through SYS_WRITE →
 * SYS_EXIT, with no control flow back to user mode.
 */

namespace customos::core
{

namespace
{

constexpr u64 kUserCodeVirt = 0x0000000040000000ULL;
constexpr u64 kUserStackVirt = 0x0000000040010000ULL;
constexpr u64 kUserStackTop = kUserStackVirt + mm::kPageSize;

// Fixed offset of the "Hello from ring 3!\n" string inside the user
// code page. Encoded as the low-32 immediate in the user's
// `mov esi, 0x40000080` instruction below; changing this value
// requires updating BOTH the constant AND the instruction byte
// at the same time (the test below enforces that they match).
constexpr u64 kUserMessageOffset = 0x80;

constexpr char kUserMessage[] = "Hello from ring 3!\n";
// sizeof includes the trailing NUL; the user syscall passes
// sizeof - 1 so the NUL isn't written to COM1.
constexpr u64 kUserMessageLen = sizeof(kUserMessage) - 1;

// 31-byte user code: pause x2, SYS_WRITE(1, 0x40000080, len),
// SYS_YIELD, SYS_EXIT(0), hlt. Emitted as raw bytes rather than
// a .S file so the user-mode VA layout, the bytes, and the
// "hands-off: this runs in ring 3" context all stay in one place.
// clang-format off
constexpr u8 kUserCodeBytes[] = {
    0xF3, 0x90,                                                       // pause
    0xF3, 0x90,                                                       // pause
    0xB8, 0x02, 0x00, 0x00, 0x00,                                     // mov eax, 2         (SYS_WRITE)
    0xBF, 0x01, 0x00, 0x00, 0x00,                                     // mov edi, 1         (fd=1)
    0xBE, 0x80, 0x00, 0x00, 0x40,                                     // mov esi, 0x40000080 (msg ptr)
    0xBA, static_cast<u8>(kUserMessageLen), 0x00, 0x00, 0x00,         // mov edx, len
    0xCD, 0x80,                                                       // int 0x80   (SYS_WRITE)
    0xB8, 0x03, 0x00, 0x00, 0x00,                                     // mov eax, 3         (SYS_YIELD)
    0xCD, 0x80,                                                       // int 0x80   (yield)
    0x31, 0xC0,                                                       // xor eax, eax       (SYS_EXIT)
    0x31, 0xFF,                                                       // xor edi, edi       (rc=0)
    0xCD, 0x80,                                                       // int 0x80   (exit)
    0xF4,                                                             // hlt (unreachable)
};
// clang-format on
static_assert(sizeof(kUserCodeBytes) <= kUserMessageOffset, "user code runs into the fixed message offset");

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
    //
    // Layout inside the page:
    //   [0 .. sizeof(kUserCodeBytes)]   : instructions
    //   [sizeof(..) .. kUserMessageOffset) : zero-fill (so mis-jumps
    //                                        land on `add [rax], al`
    //                                        == harmless)
    //   [kUserMessageOffset .. +N)      : the "Hello…\n" bytes
    //   [rest of page]                  : zero-fill
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kUserCodeBytes); ++i)
    {
        code_direct[i] = kUserCodeBytes[i];
    }
    for (u64 i = 0; i < kUserMessageLen; ++i)
    {
        code_direct[kUserMessageOffset + i] = static_cast<u8>(kUserMessage[i]);
    }

    // kPagePresent + kPageUser only — no kPageWritable (W^X for user
    // code) and no kPageNoExecute (exec is exactly what we want).
    MapPage(kUserCodeVirt, code_frame, kPagePresent | kPageUser);
    sched::RegisterUserVmRegion(kUserCodeVirt, code_frame);

    // ---- 2) Allocate + map the user stack page. ----------------------------

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "failed to allocate user stack frame");
    }

    MapPage(kUserStackVirt, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);
    sched::RegisterUserVmRegion(kUserStackVirt, stack_frame);

    // ---- 3) Publish kernel stack top to the TSS so user→kernel traps land. -
    //
    // Belt-and-braces: the scheduler's switch-in path already updated
    // TSS.RSP0 on the way into this task, so the value is correct by
    // the time we reach here. Writing it again here is harmless (same
    // value) and documents the invariant at the exact point the next
    // iretq will consume it. If the scheduler ever stops owning this
    // invariant, the manual write below keeps this task working while
    // the breakage is investigated.
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
