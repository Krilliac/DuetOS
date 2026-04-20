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

// Fixed offsets of string constants inside the user code page.
// Every offset below is encoded as a 32-bit immediate in the
// machine code — changing any of them here requires updating the
// matching byte in kUserCodeBytes too. The static_assert at the
// bottom bounds the instruction region so a new instruction byte
// can't silently overrun the first string.
constexpr u64 kUserMessageOffset = 0x80; // "Hello from ring 3!\n"
constexpr u64 kUserStatPath1Offset = 0xA0; // "/etc/version"
constexpr u64 kUserStatPath2Offset = 0xB0; // "/welcome.txt"

constexpr char kUserMessage[] = "Hello from ring 3!\n";
constexpr char kUserStatPath1[] = "/etc/version";
constexpr char kUserStatPath2[] = "/welcome.txt";
constexpr u64 kUserMessageLen = sizeof(kUserMessage) - 1;

// SYS_STAT writes a u64 size to the user-provided buffer. The
// user stack page is mapped writable (NX), so point the buffer
// near the top of the stack — comfortably below where any stack
// frames would grow for this payload.
constexpr u64 kUserStatOutVa = kUserStackVirt + 0xFF0;

// SYS_READ destination buffer. 256 bytes, centred in the stack
// page. Deliberately non-overlapping with kUserStatOutVa.
constexpr u64 kUserReadBufVa = kUserStackVirt + 0x800;
constexpr u64 kUserReadBufCap = 128;

// User code. Order:
//   pause, pause,
//   SYS_STAT("/etc/version",  &stat_out),
//   SYS_STAT("/welcome.txt",  &stat_out),
//   SYS_READ("/etc/version",  read_buf, 128),
//     rax <- bytes_read (or -1)
//     rdx <- rax        (preserve length for the write that follows)
//   SYS_WRITE(1, read_buf, rdx),                  ; echoes the file
//   SYS_WRITE(1, "Hello from ring 3!\n", 19),     ; existing banner
//   SYS_YIELD,
//   SYS_EXIT(0), hlt.
//
// Same bytes in every task. Trusted pid gets:
//   - stat ok /etc/version (size=0x1b)
//   - stat miss /welcome.txt
//   - read ok /etc/version (bytes=0x1b) → /etc/version content echoed
//   - write "Hello from ring 3!"
// Sandbox pid gets:
//   - stat miss /etc/version        <- namespace jail
//   - stat ok /welcome.txt (size=0x30)
//   - read miss /etc/version        <- jail again, on the read path
//   - SYS_WRITE denied by cap check (sandbox lacks kCapSerialConsole)
//
// For the sandbox, after the failed read rax=-1 and the follow-up
// mov rdx, rax puts 0xFFFF_FFFF_FFFF_FFFF in rdx. The subsequent
// SYS_WRITE never touches that length because the cap check fires
// first and returns -1 — so even an invalid length is harmless.
// clang-format off
constexpr u8 kUserCodeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0xF3, 0x90,                                                   // pause

    // SYS_STAT /etc/version
    0xB8, 0x04, 0x00, 0x00, 0x00,                                 // mov eax, 4    (SYS_STAT)
    0xBF, 0xA0, 0x00, 0x00, 0x40,                                 // mov edi, 0x400000A0 (path1)
    0xBE, 0xF0, 0x0F, 0x01, 0x40,                                 // mov esi, 0x40010FF0 (stat_out)
    0xCD, 0x80,                                                   // int 0x80

    // SYS_STAT /welcome.txt
    0xB8, 0x04, 0x00, 0x00, 0x00,                                 // mov eax, 4    (SYS_STAT)
    0xBF, 0xB0, 0x00, 0x00, 0x40,                                 // mov edi, 0x400000B0 (path2)
    0xBE, 0xF0, 0x0F, 0x01, 0x40,                                 // mov esi, 0x40010FF0 (stat_out)
    0xCD, 0x80,                                                   // int 0x80

    // SYS_READ /etc/version into read_buf (rax <- bytes_read or -1)
    0xB8, 0x05, 0x00, 0x00, 0x00,                                 // mov eax, 5    (SYS_READ)
    0xBF, 0xA0, 0x00, 0x00, 0x40,                                 // mov edi, 0x400000A0 (path1)
    0xBE, 0x00, 0x08, 0x01, 0x40,                                 // mov esi, 0x40010800 (read_buf)
    0xBA, 0x80, 0x00, 0x00, 0x00,                                 // mov edx, 128  (cap)
    0xCD, 0x80,                                                   // int 0x80

    // Preserve read length for the write below.
    0x48, 0x89, 0xC2,                                             // mov rdx, rax

    // SYS_WRITE(1, read_buf, rdx)
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2    (SYS_WRITE)
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xBE, 0x00, 0x08, 0x01, 0x40,                                 // mov esi, 0x40010800 (read_buf)
    0xCD, 0x80,                                                   // int 0x80

    // SYS_WRITE(1, msg, kUserMessageLen)
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2    (SYS_WRITE)
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xBE, 0x80, 0x00, 0x00, 0x40,                                 // mov esi, 0x40000080 (msg)
    0xBA, static_cast<u8>(kUserMessageLen), 0x00, 0x00, 0x00,     // mov edx, len
    0xCD, 0x80,                                                   // int 0x80

    // SYS_YIELD
    0xB8, 0x03, 0x00, 0x00, 0x00,                                 // mov eax, 3
    0xCD, 0x80,                                                   // int 0x80

    // SYS_EXIT(0)
    0x31, 0xC0,                                                   // xor eax, eax
    0x31, 0xFF,                                                   // xor edi, edi
    0xCD, 0x80,                                                   // int 0x80
    0xF4,                                                         // hlt (unreachable)
};
// clang-format on
static_assert(sizeof(kUserCodeBytes) <= kUserMessageOffset, "user code runs into the first string region");
static_assert(kUserMessageOffset + sizeof(kUserMessage) <= kUserStatPath1Offset, "msg overruns stat-path-1 region");
static_assert(kUserStatPath1Offset + sizeof(kUserStatPath1) <= kUserStatPath2Offset,
              "stat-path-1 overruns stat-path-2 region");

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
    // Stat paths: include the terminating NUL so VfsLookup has a
    // clean stop. The initial zero-fill guarantees every byte past
    // the string is 0, but writing the NUL explicitly keeps the
    // layout self-documenting.
    for (u64 i = 0; i < sizeof(kUserStatPath1); ++i)
    {
        code_direct[kUserStatPath1Offset + i] = static_cast<u8>(kUserStatPath1[i]);
    }
    for (u64 i = 0; i < sizeof(kUserStatPath2); ++i)
    {
        code_direct[kUserStatPath2Offset + i] = static_cast<u8>(kUserStatPath2[i]);
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
void SpawnRing3Task(const char* name, CapSet caps, const fs::RamfsNode* root, u64 frame_budget)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace customos::mm;

    AddressSpace* as = AddressSpaceCreate(frame_budget);
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

// Dedicated NX-probe payload: jumps into its own NX stack page at
// 0x40010000. The stack is mapped with kPageNoExecute; instruction
// fetch from there triggers #PF with the "instruction fetch" bit
// (err_code bit 4) set. The kernel's ring-3 trap path turns the
// fault into a [task-kill] and reschedules. This is the DEP /
// NX-exec enforcement proof: we can directly observe "the CPU
// refused to execute bytes on a writable page." Without EFER.NXE
// being honored or without kPageNoExecute on the stack, the jump
// would succeed and the CPU would start executing random stack
// bytes.
//
// clang-format off
constexpr u8 kNxProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    // mov rax, 0x40010000
    0x48, 0xB8, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xE0,                                                   // jmp rax
    0x0F, 0x0B,                                                   // ud2 (belt-and-braces)
};
// clang-format on

void SpawnNxProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace customos::mm;

    AddressSpace* as = AddressSpaceCreate(kFrameBudgetSandbox);
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for nx probe");
    }

    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for nx probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kNxProbeBytes); ++i)
    {
        code_direct[i] = kNxProbeBytes[i];
    }

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for nx probe");
    }

    AddressSpaceMapUserPage(as, kUserCodeVirt, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, kUserStackVirt, stack_frame,
                            kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    Process* proc = ProcessCreate("ring3-nx-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot());
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for nx probe");
    }

    SerialWrite("[ring3] queued nx-probe task pid=");
    SerialWriteHex(proc->pid);
    SerialWrite("\n");

    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-nx-probe", proc);
}

// Dedicated jail-probe payload: immediately attempts to write into
// its own R-X code page at 0x40000000. The code page is mapped
// kPagePresent | kPageUser — no kPageWritable — so the store #PFs.
// The kernel's ring-3 exception path logs [task-kill] and calls
// SchedExit, terminating the task cleanly. The ud2 at the tail is
// belt-and-braces — if, impossibly, the write succeeded, ud2 raises
// #UD and the task still dies.
//
// clang-format off
constexpr u8 kJailProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    // mov dword ptr [0x40000000], 0xDEADBEEF
    0xC7, 0x04, 0x25, 0x00, 0x00, 0x00, 0x40, 0xEF, 0xBE, 0xAD, 0xDE,
    0x0F, 0x0B,                                                   // ud2
};
// clang-format on

void SpawnJailProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace customos::mm;

    AddressSpace* as = AddressSpaceCreate(kFrameBudgetSandbox);
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for jail probe");
    }

    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for jail probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kJailProbeBytes); ++i)
    {
        code_direct[i] = kJailProbeBytes[i];
    }

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for jail probe");
    }

    AddressSpaceMapUserPage(as, kUserCodeVirt, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, kUserStackVirt, stack_frame,
                            kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Empty cap set — the jail probe never gets a chance to issue
    // a syscall (it faults first), but if the fault path ever
    // regressed and the task reached int 0x80, denying caps
    // defence-in-depths that path too.
    Process* proc = ProcessCreate("ring3-jail-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot());
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for jail probe");
    }

    SerialWrite("[ring3] queued jail-probe task pid=");
    SerialWriteHex(proc->pid);
    SerialWrite("\n");

    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-jail-probe", proc);
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
    // Sandbox gets kCapFsRead so SYS_STAT reaches the namespace
    // layer — with an empty cap set, the cap check would short-
    // circuit and we'd never exercise VfsLookup against the
    // sandbox root. Granting the cap lets the demo prove that
    // EVEN WITH the cap, Process::root bounds what the process
    // can name: "/etc/version" in the sandbox root simply does
    // not exist.
    CapSet sandbox_caps = CapSetEmpty();
    CapSetAdd(sandbox_caps, kCapFsRead);

    SpawnRing3Task("ring3-smoke-A", CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted);
    SpawnRing3Task("ring3-smoke-B", CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted);
    SpawnRing3Task("ring3-smoke-sandbox", sandbox_caps, fs::RamfsSandboxRoot(), mm::kFrameBudgetSandbox);

    // Jail-probe task: writes to its own RX code page. Expected
    // outcome is the kernel's ring-3 trap handler terminating the
    // task via SchedExit and emitting [task-kill] on COM1. If the
    // kernel instead panics / halts here, the sandboxing contract
    // is broken: a user-mode fault must never bring down the OS.
    SpawnJailProbeTask();
    SpawnNxProbeTask();
    Log(LogLevel::Info, "core/ring3", "trusted+sandbox+jail-probe+nx-probe ring3 tasks queued");
}

} // namespace customos::core
