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

namespace
{

// ELF64 field layout: ehdr (64 B) then one phdr (56 B) then the
// payload. We cheat on alignment by choosing p_vaddr = 0x400078
// so the segment's (vaddr % kPageSize) matches p_offset (120) —
// the ElfLoader validates this equivalence. Keeps the ELF tiny
// (one 4 KiB page instead of padding to a real 4 KiB offset).
constexpr u64 kSmokeElfVaddr = 0x0000'0000'0040'0078ull;
constexpr u64 kSmokeElfPhdrSize = 56;
constexpr u64 kSmokeElfEhdrSize = 64;

// Build a valid ELF64 image into `out_buf` with the Linux smoke
// payload inline. Returns total bytes written. Caller sizes the
// buffer at kSmokeElfEhdrSize + kSmokeElfPhdrSize + sizeof(kPayload)
// (= 64 + 56 + payload = ~260 bytes for our current payload).
u64 BuildLinuxElf(u8* out_buf, u64 buf_cap)
{
    const u64 total = kSmokeElfEhdrSize + kSmokeElfPhdrSize + sizeof(kPayload);
    if (buf_cap < total)
    {
        return 0;
    }
    // Zero everything first so reserved fields / e_flags read as 0.
    for (u64 i = 0; i < total; ++i)
        out_buf[i] = 0;

    auto put_u16 = [&](u64 off, u16 v)
    {
        out_buf[off + 0] = static_cast<u8>(v);
        out_buf[off + 1] = static_cast<u8>(v >> 8);
    };
    auto put_u32 = [&](u64 off, u32 v)
    {
        out_buf[off + 0] = static_cast<u8>(v);
        out_buf[off + 1] = static_cast<u8>(v >> 8);
        out_buf[off + 2] = static_cast<u8>(v >> 16);
        out_buf[off + 3] = static_cast<u8>(v >> 24);
    };
    auto put_u64 = [&](u64 off, u64 v)
    {
        for (u64 i = 0; i < 8; ++i)
            out_buf[off + i] = static_cast<u8>(v >> (i * 8));
    };

    // --- ehdr ---
    out_buf[0] = 0x7F;
    out_buf[1] = 'E';
    out_buf[2] = 'L';
    out_buf[3] = 'F';
    out_buf[4] = 2; // EI_CLASS = ELFCLASS64
    out_buf[5] = 1; // EI_DATA = ELFDATA2LSB
    out_buf[6] = 1; // EI_VERSION = EV_CURRENT
    out_buf[7] = 0; // EI_OSABI = ELFOSABI_SYSV — our loader doesn't check
    // bytes 8..15 already zeroed.
    put_u16(16, 2);                 // e_type = ET_EXEC
    put_u16(18, 0x3E);              // e_machine = EM_X86_64
    put_u32(20, 1);                 // e_version = EV_CURRENT
    put_u64(24, kSmokeElfVaddr);    // e_entry — points at payload byte 0
    put_u64(32, kSmokeElfEhdrSize); // e_phoff = 64
    put_u64(40, 0);                 // e_shoff = 0, no sections
    put_u32(48, 0);                 // e_flags
    put_u16(52, static_cast<u16>(kSmokeElfEhdrSize));
    put_u16(54, static_cast<u16>(kSmokeElfPhdrSize));
    put_u16(56, 1); // e_phnum = 1
    put_u16(58, 0); // e_shentsize
    put_u16(60, 0); // e_shnum
    put_u16(62, 0); // e_shstrndx

    // --- phdr[0] at offset 64 ---
    const u64 phdr = kSmokeElfEhdrSize;
    const u64 p_offset = kSmokeElfEhdrSize + kSmokeElfPhdrSize; // = 120
    put_u32(phdr + 0, 1);                                       // p_type = PT_LOAD
    put_u32(phdr + 4, 0x05);                                    // p_flags = PF_R | PF_X — RX code
    put_u64(phdr + 8, p_offset);
    put_u64(phdr + 16, kSmokeElfVaddr);
    put_u64(phdr + 24, kSmokeElfVaddr);
    put_u64(phdr + 32, sizeof(kPayload)); // p_filesz
    put_u64(phdr + 40, sizeof(kPayload)); // p_memsz
    put_u64(phdr + 48, 0x1000);           // p_align
    // 120 % 0x1000 == 120 and 0x400078 % 0x1000 == 120, so the
    // ElfLoader's "p_offset % p_align == p_vaddr % p_align" check
    // passes.

    // --- payload at offset 120 ---
    for (u64 i = 0; i < sizeof(kPayload); ++i)
        out_buf[p_offset + i] = kPayload[i];

    return total;
}

} // namespace

// File-I/O smoke payload: open("HELLO.TXT", O_RDONLY, 0) ->
// mmap a 4 KiB buf -> read(fd, buf, 32) -> write(1, buf, n) ->
// close(fd) -> write(1, "done\n", 5) -> exit_group(0x42). Expected
// stdout on boot: "hello from fat32\ndone\n".
//
// Byte layout:
//   0..144  : instructions
//   145..154: "HELLO.TXT\0"   (path, 10 bytes)
//   155..159: "done\n"         (ok marker, 5 bytes)
//
// Both LEA displacements (0x85 and 0x1F) are RIP-relative so this
// is position-independent — loader can place it at any VA.
constexpr u8 kFilePayload[] = {
    // open("HELLO.TXT", 0, 0)
    0xB8,
    0x02,
    0x00,
    0x00,
    0x00, // mov eax, 2
    0x48,
    0x8D,
    0x3D,
    0x85,
    0x00,
    0x00,
    0x00, // lea rdi, [rip+0x85] (path)
    0x31,
    0xF6, // xor esi, esi   (flags=0)
    0x31,
    0xD2, // xor edx, edx   (mode=0)
    0x0F,
    0x05, // syscall
    0x49,
    0x89,
    0xC5, // mov r13, rax   (save fd)
    // mmap(NULL, 4096, 3, 0x22, -1, 0)
    0xB8,
    0x09,
    0x00,
    0x00,
    0x00, // mov eax, 9
    0x31,
    0xFF, // xor edi, edi
    0xBE,
    0x00,
    0x10,
    0x00,
    0x00, // mov esi, 0x1000
    0xBA,
    0x03,
    0x00,
    0x00,
    0x00, // mov edx, 3
    0x41,
    0xBA,
    0x22,
    0x00,
    0x00,
    0x00, // mov r10d, 0x22
    0x41,
    0xB8,
    0xFF,
    0xFF,
    0xFF,
    0xFF, // mov r8d, -1
    0x45,
    0x31,
    0xC9, // xor r9d, r9d
    0x0F,
    0x05, // syscall
    0x49,
    0x89,
    0xC4, // mov r12, rax (buf)
    // read(fd, buf, 32)
    0xB8,
    0x00,
    0x00,
    0x00,
    0x00, // mov eax, 0  (sys_read)
    0x44,
    0x89,
    0xEF, // mov edi, r13d (fd)
    0x4C,
    0x89,
    0xE6, // mov rsi, r12
    0xBA,
    0x20,
    0x00,
    0x00,
    0x00, // mov edx, 32
    0x0F,
    0x05, // syscall
    0x49,
    0x89,
    0xC6, // mov r14, rax (n bytes)
    // write(1, buf, r14)
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
    0x4C,
    0x89,
    0xF2, // mov rdx, r14
    0x0F,
    0x05, // syscall
    // close(fd)
    0xB8,
    0x03,
    0x00,
    0x00,
    0x00, // mov eax, 3  (sys_close)
    0x44,
    0x89,
    0xEF, // mov edi, r13d
    0x0F,
    0x05, // syscall
    // write(1, "done\n", 5)
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
    0x1F,
    0x00,
    0x00,
    0x00, // lea rsi, [rip+0x1F] (done)
    0xBA,
    0x05,
    0x00,
    0x00,
    0x00, // mov edx, 5
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
    // path: "HELLO.TXT\0"
    'H',
    'E',
    'L',
    'L',
    'O',
    '.',
    'T',
    'X',
    'T',
    0,
    // done: "done\n"
    'd',
    'o',
    'n',
    'e',
    '\n',
};

void SpawnRing3LinuxFileSmoke()
{
    KLOG_TRACE_SCOPE("linux/smoke", "SpawnRing3LinuxFileSmoke");

    AddressSpace* as = AddressSpaceCreate(/*frame_budget=*/16);
    if (as == nullptr)
    {
        core::Panic("linux/smoke", "AddressSpaceCreate failed");
    }
    const PhysAddr code_frame = AllocateFrame();
    const PhysAddr stack_frame = AllocateFrame();
    if (code_frame == mm::kNullFrame || stack_frame == mm::kNullFrame)
    {
        core::Panic("linux/smoke", "frame alloc failed");
    }
    auto* code_direct = static_cast<u8*>(mm::PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
        code_direct[i] = 0;
    for (u64 i = 0; i < sizeof(kFilePayload); ++i)
        code_direct[i] = kFilePayload[i];

    // Different VA pair so this task doesn't collide with the
    // existing hand-crafted Linux smoke.
    const u64 code_va = 0x0000'6900'0000'0000ull;
    const u64 stack_va = code_va + 0x10000;
    AddressSpaceMapUserPage(as, code_va, code_frame, mm::kPagePresent | mm::kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame,
                            mm::kPagePresent | mm::kPageWritable | mm::kPageUser | mm::kPageNoExecute);

    Process* proc = ProcessCreate("linux-file-smoke", as, core::CapSetEmpty(), fs::RamfsSandboxRoot(), code_va,
                                  stack_va, core::kTickBudgetSandbox);
    if (proc == nullptr)
    {
        core::Panic("linux/smoke", "ProcessCreate failed");
    }
    proc->abi_flavor = kAbiLinux;
    proc->linux_brk_base = code_va + 0x100'0000ull;
    proc->linux_brk_current = proc->linux_brk_base;
    proc->linux_mmap_cursor = 0x0000'7100'0000'0000ull;

    arch::SerialWrite("[linux] queued ring3 file smoke: open+read+write+close\n");
    sched::SchedCreateUser(&core::Ring3UserEntry, nullptr, "linux-file-smoke", proc);
}

void SpawnRing3LinuxElfSmoke()
{
    KLOG_TRACE_SCOPE("linux/smoke", "SpawnRing3LinuxElfSmoke");

    // Construct the ELF in a static scratch buffer. One call at a
    // time (boot-sequence-only); SpawnElfLinux copies the bytes it
    // needs into user pages, so the buffer can be reused after.
    static u8 scratch[512];
    const u64 n = BuildLinuxElf(scratch, sizeof(scratch));
    if (n == 0)
    {
        core::Panic("linux/smoke", "BuildLinuxElf scratch too small");
    }
    const u64 pid = core::SpawnElfLinux("linux-elf-smoke", scratch, n, core::CapSetEmpty(), fs::RamfsSandboxRoot(),
                                        /*frame_budget=*/16, core::kTickBudgetSandbox);
    if (pid == 0)
    {
        arch::SerialWrite("[linux] SpawnElfLinux FAILED for linux-elf-smoke\n");
    }
}

// Translation-unit exerciser. Two syscalls that the primary Linux
// dispatcher doesn't handle, so the TU gets a chance:
//   sys_madvise(0x7f000000, 4096, 0)  -> no-op translation
//   sys_rseq(0, 0, 0, 0)              -> deliberate -ENOSYS
//   exit_group(0x42)
// The boot log shows both [translate] lines; re-run shows the
// same lines, making it easy to grep "[translate]" for the full
// story of what's translated vs. missing.
constexpr u8 kTranslatePayload[] = {
    // sys_madvise(0x7F000000, 0x1000, 0)
    0xB8, 0x1C, 0x00, 0x00, 0x00, // mov eax, 28
    0xBF, 0x00, 0x00, 0x00, 0x7F, // mov edi, 0x7F000000
    0xBE, 0x00, 0x10, 0x00, 0x00, // mov esi, 0x1000
    0x31, 0xD2,                   // xor edx, edx
    0x0F, 0x05,                   // syscall
    // sys_rseq(0, 0, 0, 0)
    0xB8, 0x4E, 0x01, 0x00, 0x00, // mov eax, 334
    0x31, 0xFF,                   // xor edi, edi
    0x31, 0xF6,                   // xor esi, esi
    0x31, 0xD2,                   // xor edx, edx
    0x0F, 0x05,                   // syscall
    // exit_group(0x42)
    0xB8, 0xE7, 0x00, 0x00, 0x00, // mov eax, 231
    0xBF, 0x42, 0x00, 0x00, 0x00, // mov edi, 0x42
    0x0F, 0x05,                   // syscall
    0x0F, 0x0B,                   // ud2
};

void SpawnRing3LinuxTranslateSmoke()
{
    KLOG_TRACE_SCOPE("linux/smoke", "SpawnRing3LinuxTranslateSmoke");

    AddressSpace* as = AddressSpaceCreate(/*frame_budget=*/16);
    if (as == nullptr)
        core::Panic("linux/smoke", "AddressSpaceCreate failed");
    const PhysAddr code_frame = AllocateFrame();
    const PhysAddr stack_frame = AllocateFrame();
    if (code_frame == mm::kNullFrame || stack_frame == mm::kNullFrame)
        core::Panic("linux/smoke", "frame alloc failed");
    auto* code_direct = static_cast<u8*>(mm::PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
        code_direct[i] = 0;
    for (u64 i = 0; i < sizeof(kTranslatePayload); ++i)
        code_direct[i] = kTranslatePayload[i];

    // Dedicated VA so this task doesn't collide with the others.
    const u64 code_va = 0x0000'6A00'0000'0000ull;
    const u64 stack_va = code_va + 0x10000;
    AddressSpaceMapUserPage(as, code_va, code_frame, mm::kPagePresent | mm::kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame,
                            mm::kPagePresent | mm::kPageWritable | mm::kPageUser | mm::kPageNoExecute);
    Process* proc = ProcessCreate("linux-translate-smoke", as, core::CapSetEmpty(), fs::RamfsSandboxRoot(), code_va,
                                  stack_va, core::kTickBudgetSandbox);
    if (proc == nullptr)
        core::Panic("linux/smoke", "ProcessCreate failed");
    proc->abi_flavor = kAbiLinux;
    proc->linux_brk_base = code_va + 0x100'0000ull;
    proc->linux_brk_current = proc->linux_brk_base;
    proc->linux_mmap_cursor = 0x0000'7200'0000'0000ull;
    arch::SerialWrite("[linux] queued ring3 translate smoke: madvise + rseq + exit\n");
    sched::SchedCreateUser(&core::Ring3UserEntry, nullptr, "linux-translate-smoke", proc);
}

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
