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

// Raw machine code for the smoke task. Tests the full Linux-ABI
// I/O + memory path in one ring-3 task:
//
//   1. mmap(NULL, 4096, RW, MAP_PRIVATE|MAP_ANON, -1, 0)
//      -> rax = new VA. Stored in r12.
//   2. Write "MOK\n" into the fresh page via r12-relative stores.
//      If mmap didn't actually map the page, these writes #PF and
//      the task-kill log appears — a visible failure signal.
//   3. write(1, r12, 4)  -> prints "MOK\n" to COM1.
//   4. write(1, msg, 13) -> prints "hello linux!\n".
//   5. exit_group(0x42)
//   6. ud2 (unreachable guard)
//
// Everything is position-independent:
//   - mmap/write/exit_group arguments are pure immediates.
//   - The "hello linux!\n" buffer is addressed via RIP-relative LEA.
//
// R12 addressing requires SIB bytes (r12's encoding collides with
// "SIB follows" in the ModRM rm field), which is why the stores
// into *r12 are 5-6 bytes each instead of 3-4.
constexpr u8 kPayload[] = {
    // mmap(NULL, 4096, 3, 0x22, -1, 0)
    0xB8,
    0x09,
    0x00,
    0x00,
    0x00, // mov eax, 9         ; sys_mmap
    0x31,
    0xFF, // xor edi, edi       ; addr=NULL
    0xBE,
    0x00,
    0x10,
    0x00,
    0x00, // mov esi, 0x1000    ; len=4096
    0xBA,
    0x03,
    0x00,
    0x00,
    0x00, // mov edx, 3         ; prot=RW
    0x41,
    0xBA,
    0x22,
    0x00,
    0x00,
    0x00, // mov r10d, 0x22     ; flags=PRIVATE|ANON
    0x41,
    0xB8,
    0xFF,
    0xFF,
    0xFF,
    0xFF, // mov r8d, -1        ; fd=-1
    0x45,
    0x31,
    0xC9, // xor r9d, r9d       ; offset=0
    0x0F,
    0x05, // syscall
    0x49,
    0x89,
    0xC4, // mov r12, rax       ; save mmap'd VA
    // Write "MOK\n" to the mapped page. If mmap failed silently
    // (returned an errno-encoded value), these writes will #PF.
    0x41,
    0xC6,
    0x04,
    0x24,
    0x4D, // mov byte [r12],    'M'
    0x41,
    0xC6,
    0x44,
    0x24,
    0x01,
    0x4F, // mov byte [r12+1],  'O'
    0x41,
    0xC6,
    0x44,
    0x24,
    0x02,
    0x4B, // mov byte [r12+2],  'K'
    0x41,
    0xC6,
    0x44,
    0x24,
    0x03,
    0x0A, // mov byte [r12+3],  '\n'
    // write(1, r12, 4)
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
    0x4C,
    0x89,
    0xE6, // mov rsi, r12
    0xBA,
    0x04,
    0x00,
    0x00,
    0x00, // mov edx, 4
    0x0F,
    0x05, // syscall
    // write(1, msg, 13) — "hello linux!\n"
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
    0x00, // lea rsi, [rip+0x15]
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
    0x0B, // ud2
    // msg — LEA's disp32 (0x15 = 21) resolves relative to the
    // instruction FOLLOWING the lea. Keep this comment honest
    // if you edit the payload above — the displacement needs
    // to equal (offset_of_msg - offset_after_lea).
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

// Linux-ABI heap + mmap anchors. Brk heap sits just past the
// code+stack, mmap region above that. Must not collide with
// kCodeVa / kStackVa. The ELF loader (future) will set these
// from the loaded image's end-of-data + TASK_SIZE analogues.
constexpr u64 kBrkBase = kCodeVa + 0x100'0000ull; // 16 MiB past code
constexpr u64 kMmapBase = 0x0000'7000'0000'0000ull;

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
    proc->linux_brk_base = kBrkBase;
    proc->linux_brk_current = kBrkBase;
    proc->linux_mmap_cursor = kMmapBase;

    arch::SerialWrite("[linux] queued ring3 smoke: mmap + write + exit_group via syscall\n");
    sched::SchedCreateUser(&core::Ring3UserEntry, nullptr, "linux-smoke", proc);
}

} // namespace customos::subsystems::linux
