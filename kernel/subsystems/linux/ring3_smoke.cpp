#include "ring3_smoke.h"

#include "../../arch/x86_64/gdt.h"
#include "../../arch/x86_64/serial.h"
#include "../../arch/x86_64/usermode.h"
#include "../../core/klog.h"
#include "../../core/panic.h"
#include "../../core/process.h"
#include "../../core/ring3_smoke.h"
#include "../../cpu/percpu.h"
#include "../../fs/ramfs.h"
#include "../../mm/address_space.h"
#include "../../mm/frame_allocator.h"
#include "../../mm/page.h"
#include "../../mm/paging.h"
#include "../../sched/sched.h"

namespace customos::subsystems::linux
{

namespace
{

using customos::core::CurrentProcess;
using customos::core::kAbiLinux;
using customos::core::Process;
using customos::core::ProcessCreate;
using customos::mm::AddressSpace;
using customos::mm::AddressSpaceCreate;
using customos::mm::AddressSpaceMapUserPage;
using customos::mm::AllocateFrame;
using customos::mm::PhysAddr;

// Raw machine code for the smoke task. RIP-relative LEA is used
// to address the inline "hello linux!\n" string, so we still don't
// need ASLR patching — the displacement is position-independent.
//
//   mov  eax, 1                  ; sys_write
//   mov  edi, 1                  ; fd = stdout
//   lea  rsi, [rip + msg]        ; buf
//   mov  edx, 13                 ; count
//   syscall
//   mov  eax, 231                ; sys_exit_group
//   mov  edi, 0x42               ; exit code
//   syscall
//   ud2                          ; unreachable
//   msg: db "hello linux!\n"
//
// 51 bytes total. Fits comfortably in the 4 KiB code page.
constexpr u8 kPayload[] = {
    // write(1, msg, 13)
    0xB8,
    0x01,
    0x00,
    0x00,
    0x00, // mov eax, 1
    0xBF,
    0x01,
    0x00,
    0x00,
    0x00, // mov edi, 1
    0x48,
    0x8D,
    0x35,
    0x15,
    0x00,
    0x00,
    0x00, // lea rsi, [rip + 0x15]
    0xBA,
    0x0D,
    0x00,
    0x00,
    0x00, // mov edx, 13
    0x0F,
    0x05, // syscall
    // exit_group(0x42)
    0xB8,
    0xE7,
    0x00,
    0x00,
    0x00, // mov eax, 231
    0xBF,
    0x42,
    0x00,
    0x00,
    0x00, // mov edi, 0x42
    0x0F,
    0x05, // syscall
    0x0F,
    0x0B, // ud2 (unreachable guard)
    // msg — starts at offset 38; LEA's disp32 above = 21 = 0x15
    // because RIP after the LEA points at offset 17, and 38-17 = 21.
    'h',
    'e',
    'l',
    'l',
    'o',
    ' ',
    'l',
    'i',
    'n',
    'u',
    'x',
    '!',
    '\n',
};

// Hard-coded VAs — simpler than ASLR for a smoke. Chosen to avoid
// collision with the native smoke's randomised range. Ring-3
// user-only code+stack pair sits at 0x68_xxxxxxxx, well within
// the user half.
constexpr u64 kCodeVa = 0x0000'6800'0000'0000ull;
constexpr u64 kStackVa = kCodeVa + 0x10000;

} // namespace

void SpawnRing3LinuxSmoke()
{
    KLOG_TRACE_SCOPE("linux/smoke", "SpawnRing3LinuxSmoke");
    using arch::SerialWrite;

    AddressSpace* as = AddressSpaceCreate(/*frame_budget=*/16);
    if (as == nullptr)
    {
        core::Panic("linux/smoke", "AddressSpaceCreate failed");
    }
    const PhysAddr code_frame = AllocateFrame();
    const PhysAddr stack_frame = AllocateFrame();
    if (code_frame == mm::kNullFrame || stack_frame == mm::kNullFrame)
    {
        core::Panic("linux/smoke", "frame allocation failed");
    }

    // Populate the code page directly via the phys→direct-map alias.
    // The page starts zeroed (AllocateFrame guarantees this — see
    // the frame allocator); copy the payload bytes in at offset 0.
    auto* code_direct = static_cast<u8*>(mm::PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
        code_direct[i] = 0;
    for (u64 i = 0; i < sizeof(kPayload); ++i)
        code_direct[i] = kPayload[i];

    // Same page flags as the native smoke: code is RX + User,
    // stack is RW + User + NX.
    AddressSpaceMapUserPage(as, kCodeVa, code_frame, mm::kPagePresent | mm::kPageUser);
    AddressSpaceMapUserPage(as, kStackVa, stack_frame,
                            mm::kPagePresent | mm::kPageWritable | mm::kPageUser | mm::kPageNoExecute);

    // Minimal caps — smoke doesn't need filesystem / networking.
    const core::CapSet caps = core::CapSetEmpty();
    Process* proc =
        ProcessCreate("linux-smoke", as, caps, fs::RamfsSandboxRoot(), kCodeVa, kStackVa, core::kTickBudgetSandbox);
    if (proc == nullptr)
    {
        core::Panic("linux/smoke", "ProcessCreate failed");
    }
    // Flip ABI flavor — this tells the syscall entry plumbing the
    // task's `syscall` instruction should route through the Linux
    // dispatcher rather than (hypothetically) falling back to the
    // native int-0x80 path.
    proc->abi_flavor = kAbiLinux;

    arch::SerialWrite("[linux] queued ring3 smoke: exit_group(0x42) via syscall\n");
    sched::SchedCreateUser(&core::Ring3UserEntry, nullptr, "linux-smoke", proc);
}

} // namespace customos::subsystems::linux
