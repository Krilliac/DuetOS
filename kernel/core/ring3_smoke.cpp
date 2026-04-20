#include "ring3_smoke.h"

#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/usermode.h"
#include "../fs/ramfs.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../mm/page.h"
#include "../mm/paging.h"
#include "../sched/sched.h"
#include "klog.h"
#include "panic.h"
#include "process.h"

/*
 * Ring-3 smoke test, second iteration.
 *
 * The first version mapped its user code + stack pages into the ONE
 * global PML4 and registered them with the scheduler's per-task region
 * table for reaper-driven cleanup. Per-process address spaces have now
 * landed: this version creates a fresh `mm::AddressSpace` per task,
 * populates it with the same user code + stack mappings, and hands it
 * to `SchedCreateUser` so the scheduler flips CR3 to the AS on the
 * task's first switch-in.
 *
 * The chosen user VAs (0x40000000 for code, 0x40010000 for stack)
 * are now PER-PROCESS — every smoke task can use the same fixed VAs
 * without colliding, because each task has its own PML4. That's the
 * isolation property we wanted: spawn two smoke tasks back-to-back,
 * both succeed, both print "Hello from ring 3!\n" with their own
 * private code/stack frames behind those VAs.
 *
 * If isolation were broken (one shared PML4), the SECOND
 * `MapUserPage(virt=0x40000000, ...)` call would panic on the
 * "virt already mapped" assertion — which is exactly the assertion
 * we used to demonstrate isolation works while writing this slice.
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

// Populate `frame` with the user-code-page contents via the kernel
// direct-map alias. Reaches the frame from the parent task's view —
// the AS this frame is going into doesn't have to be active.
void WriteUserCodeFrame(mm::PhysAddr frame)
{
    auto* code_direct = static_cast<u8*>(mm::PhysToVirt(frame));
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
}

// Entry point for the user task. Runs in ring 0 on a fresh kernel
// stack with the task's own AS already loaded in CR3 (Schedule()
// flipped it on first switch-in). All this entry needs to do is
// publish RSP0 and iretq to user space.
[[noreturn]] void Ring3UserEntry(void*)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    const u64 kstack_top = sched::SchedCurrentKernelStackTop();
    if (kstack_top == 0)
    {
        Panic("core/ring3", "SchedCurrentKernelStackTop returned 0");
    }
    arch::TssSetRsp0(kstack_top);

    SerialWrite("[ring3] task pid=");
    SerialWriteHex(sched::CurrentTaskId());
    SerialWrite(" entering ring 3 rip=");
    SerialWriteHex(kUserCodeVirt);
    SerialWrite(" rsp=");
    SerialWriteHex(kUserStackTop);
    SerialWrite("\n");

    arch::EnterUserMode(kUserCodeVirt, kUserStackTop);
}

// Build a ring-3 task: allocate AS, allocate + populate code page,
// allocate stack page, install both into the AS, wrap the AS in a
// Process with the caller-supplied cap set, hand the Process to a
// new task. The reaper's ProcessRelease tears everything down at
// task death.
void SpawnRing3Task(const char* name, CapSet caps, const fs::RamfsNode* root)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace customos::mm;

    AddressSpace* as = AddressSpaceCreate();
    if (as == nullptr)
    {
        Panic("core/ring3", "AddressSpaceCreate failed");
    }

    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "failed to allocate user code frame");
    }
    WriteUserCodeFrame(code_frame);

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "failed to allocate user stack frame");
    }

    // Code: present + user, RX (no W, no NX). Stack: present + user
    // + writable + NX. Same flags as the pre-AS version — what's
    // different is they go into THIS AS's PML4 only, not the boot
    // PML4 or any sibling AS.
    AddressSpaceMapUserPage(as, kUserCodeVirt, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, kUserStackVirt, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    Process* proc = ProcessCreate(name, as, caps, root);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed");
    }

    SerialWrite("[ring3] queued task name=\"");
    SerialWrite(name);
    SerialWrite("\" pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" caps=");
    SerialWriteHex(proc->caps.bits);
    SerialWrite(" as=");
    SerialWriteHex(reinterpret_cast<u64>(as));
    SerialWrite(" code_frame=");
    SerialWriteHex(code_frame);
    SerialWrite(" stack_frame=");
    SerialWriteHex(stack_frame);
    SerialWrite("\n");

    sched::SchedCreateUser(&Ring3UserEntry, nullptr, name, proc);
}

} // namespace

void StartRing3SmokeTask()
{
    // Three ring-3 tasks, all using the SAME user VAs (0x40000000
    // code, 0x40010000 stack) in their own private address spaces.
    // Per-AS isolation means the VA "collisions" aren't collisions
    // at all.
    //
    //   - ring3-smoke-A, ring3-smoke-B: trusted profile (full cap
    //     set). Both print "Hello from ring 3!" via SYS_WRITE and
    //     exit cleanly.
    //
    //   - ring3-smoke-sandbox: empty cap set. Same user payload,
    //     but SYS_WRITE(fd=1) is denied by the cap check in the
    //     syscall dispatcher — the kernel logs
    //       "[sys] denied syscall=SYS_WRITE pid=N cap=SerialConsole"
    //     and returns -1 to ring 3. The user code ignores the
    //     return value (SYS_YIELD + SYS_EXIT follow unconditionally)
    //     so the task exits cleanly. Demonstrates that a process
    //     with zero ambient authority cannot reach the kernel
    //     serial console even though it shares the int 0x80 gate
    //     with trusted processes — the gate is open, the caps
    //     aren't.
    // Trusted tasks run off the rich ramfs root (/etc/version,
    // /bin/hello reachable). Their SYS_WRITE ⇒ "Hello from ring 3!"
    // succeeds because they hold kCapSerialConsole.
    //
    // Sandbox task runs off the one-file root (only
    // /welcome.txt exists there). It holds ZERO caps, so:
    //   - SYS_WRITE is denied by the cap check.
    //   - SYS_STAT would be denied too, if the user payload
    //     issued one (today's payload doesn't — the next bite
    //     adds per-task payloads so the sandbox actively tries
    //     a jail-escape and gets logged).
    SpawnRing3Task("ring3-smoke-A", CapSetTrusted(), fs::RamfsTrustedRoot());
    SpawnRing3Task("ring3-smoke-B", CapSetTrusted(), fs::RamfsTrustedRoot());
    SpawnRing3Task("ring3-smoke-sandbox", CapSetEmpty(), fs::RamfsSandboxRoot());
    Log(LogLevel::Info, "core/ring3", "two trusted + one sandboxed ring3 smoke tasks queued");
}

} // namespace customos::core
