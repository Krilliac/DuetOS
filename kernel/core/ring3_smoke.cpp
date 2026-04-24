#include "ring3_smoke.h"

#include "../arch/x86_64/gdt.h"
#include "../arch/x86_64/serial.h"
#include "../arch/x86_64/usermode.h"
#include "../cpu/percpu.h"
#include "../debug/inspect.h"
#include "../fs/ramfs.h"
#include "generated_advapi32_dll.h"
#include "generated_bcrypt_dll.h"
#include "generated_comctl32_dll.h"
#include "generated_comdlg32_dll.h"
#include "generated_crypt32_dll.h"
#include "generated_dwmapi_dll.h"
#include "generated_customdll.h"
#include "generated_customdll2.h"
#include "generated_customdll_test.h"
#include "generated_d3d11_dll.h"
#include "generated_d3d12_dll.h"
#include "generated_d3d9_dll.h"
#include "generated_dbghelp_dll.h"
#include "generated_dxgi_dll.h"
#include "generated_gdi32_dll.h"
#include "generated_kernel32_dll.h"
#include "generated_kernelbase_dll.h"
#include "generated_msvcp140_dll.h"
#include "generated_msvcrt_dll.h"
#include "generated_ntdll_dll.h"
#include "generated_ole32_dll.h"
#include "generated_oleaut32_dll.h"
#include "generated_psapi_dll.h"
#include "generated_reg_fopen_test.h"
#include "generated_shell32_dll.h"
#include "generated_shlwapi_dll.h"
#include "generated_iphlpapi_dll.h"
#include "generated_secur32_dll.h"
#include "generated_setupapi_dll.h"
#include "generated_ucrtbase_dll.h"
#include "generated_user32_dll.h"
#include "generated_userenv_dll.h"
#include "generated_uxtheme_dll.h"
#include "generated_vcruntime140_dll.h"
#include "generated_version_dll.h"
#include "generated_winhttp_dll.h"
#include "generated_wininet_dll.h"
#include "generated_winmm_dll.h"
#include "generated_ws2_32_dll.h"
#include "generated_wtsapi32_dll.h"
#include "generated_hello_pe.h"
#include "generated_hello_winapi.h"
#include "generated_syscall_stress.h"
#include "generated_thread_stress.h"
#include "generated_winkill_pe.h"
#include "../mm/address_space.h"
#include "../mm/frame_allocator.h"
#include "../mm/page.h"
#include "../mm/paging.h"
#include "../sched/sched.h"
#include "../subsystems/win32/heap.h"
#include "dll_loader.h"
#include "elf_loader.h"
#include "klog.h"
#include "random.h"
#include "panic.h"
#include "pe_loader.h"
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

namespace duetos::core
{

namespace
{

// ASLR: per-process randomised base for the user code page. The
// stack sits 64 KiB above, and both fit in 32 bits (so the
// payload's imm32 fields can still encode absolute VAs).
//
// Range: [0x01000000, 0xEF000000), 16 MiB-aligned — 238 candidate
// bases, ~7.9 bits of entropy. Small, but each sandboxed process
// has its own layout and an attacker observing one process's
// layout learns nothing about a sibling's. The range is deliberately
// kept below 4 GiB so we don't need REX.W-imm64 forms in the
// payload — everything encodes as `mov r32, imm32` (which zero-
// extends to r64 for free on x86-64).
//
// The boot.S direct map at PDPT[0] covers [0, 1 GiB) as 2 MiB PS
// pages — we must NOT try to install 4 KiB user pages inside that
// range (MapPage panics on PS regions). So the lower bound is
// 0x40000000 in practice — but the AddressSpaceMapUserPage walker
// is on a per-process PML4 whose PDPT[0] is empty (we zero the
// user half at create), so the walker happily creates a fresh
// PD + PT and the 2 MiB-PS panic doesn't apply. Starting at
// 0x01000000 is safe.
constexpr u64 kAslrMinBase = 0x0000000001000000ULL;
constexpr u64 kAslrMaxBase = 0x00000000EF000000ULL;
constexpr u64 kAslrAlign = 0x0000000001000000ULL; // 16 MiB
constexpr u64 kStackOffsetFromCode = 0x10000;

// Offsets WITHIN the 4 KiB code page for string constants. Identical
// layout across processes — only the PAGE base is randomised.
constexpr u64 kMsgOffsetInCode = 0x80;
constexpr u64 kPath1OffsetInCode = 0xA0;
constexpr u64 kPath2OffsetInCode = 0xB0;

// Offsets WITHIN the 4 KiB stack page for scratch buffers.
constexpr u64 kReadBufOffsetInStack = 0x800;
constexpr u64 kStatOutOffsetInStack = 0xFF0;

// Pick a fresh 16 MiB-aligned base in [kAslrMinBase, kAslrMaxBase).
// Draws from the shared kernel entropy pool (RDSEED → RDRAND →
// splitmix) rather than the old per-file TSC-seeded splitmix —
// all consumers now share a single entropy source with
// observable stats via `rand -s`.
u64 AslrPickBase()
{
    const u64 range = (kAslrMaxBase - kAslrMinBase) / kAslrAlign;
    const u64 r = duetos::core::RandomU64() % range;
    return kAslrMinBase + r * kAslrAlign;
}

// Fixed offsets of string constants inside the user code page.
// Every offset below is encoded as a 32-bit immediate in the
// machine code — changing any of them here requires updating the
// matching byte in kUserCodeBytes too. The static_assert at the
// bottom bounds the instruction region so a new instruction byte
// can't silently overrun the first string.
constexpr u64 kUserMessageOffset = 0x80;   // "Hello from ring 3!\n"
constexpr u64 kUserStatPath1Offset = 0xA0; // "/etc/version"
constexpr u64 kUserStatPath2Offset = 0xB0; // "/welcome.txt"

constexpr char kUserMessage[] = "Hello from ring 3!\n";
constexpr char kUserStatPath1[] = "/etc/version";
constexpr char kUserStatPath2[] = "/welcome.txt";
constexpr u64 kUserMessageLen = sizeof(kUserMessage) - 1;

// Stack-page layout (offsets kReadBufOffsetInStack and
// kStatOutOffsetInStack above) is fixed across processes; only
// the stack page's BASE VA is randomised per process. SYS_STAT's
// output slot lives near the top of the stack, the SYS_READ
// destination buffer lives mid-page, and both are patched into
// the payload as absolute (stack_va + offset) values at spawn.

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

// ASLR patch table for the common smoke-task payload. Each entry says
// "at this offset inside the copy of kUserCodeBytes, overwrite the
// 4-byte imm32 with the absolute VA of (either code_base + off_in_code
// OR stack_base + off_in_stack)."
//
// The offsets below are derived from hand-tracing the payload byte
// sequence — see the comment above kUserCodeBytes for the instruction
// ordering. If the payload is ever re-ordered or extended, these
// offsets MUST be re-derived; the static_assert on the payload size
// gives a canary but doesn't protect against reshuffles. Keep them
// in lockstep.
enum class PatchBase : u8
{
    kCode,
    kStack,
};
struct PayloadPatch
{
    u16 bytecode_offset;
    u16 base_offset; // offset within the target page
    PatchBase base;
};

// NOTE: offsets point at the START of each imm32 field (the byte
// AFTER the mov opcode byte). e.g. the "BF A0 00 00 40" at bytecode
// offset 0x09 has imm32 starting at 0x0A.
constexpr PayloadPatch kPayloadPatches[] = {
    {0x0A, kPath1OffsetInCode, PatchBase::kCode},     // SYS_STAT #1: path1
    {0x0F, kStatOutOffsetInStack, PatchBase::kStack}, // SYS_STAT #1: statout
    {0x1B, kPath2OffsetInCode, PatchBase::kCode},     // SYS_STAT #2: path2
    {0x20, kStatOutOffsetInStack, PatchBase::kStack}, // SYS_STAT #2: statout
    {0x2C, kPath1OffsetInCode, PatchBase::kCode},     // SYS_READ: path1
    {0x31, kReadBufOffsetInStack, PatchBase::kStack}, // SYS_READ: readbuf
    {0x4A, kReadBufOffsetInStack, PatchBase::kStack}, // SYS_WRITE (dyn): readbuf
    {0x5B, kMsgOffsetInCode, PatchBase::kCode},       // SYS_WRITE (banner): msg
};

// Write a little-endian u32 into `buf` at byte offset `off`. Asserts
// the 4 bytes fit. Used by all payload patchers.
void WriteImm32LE(u8* buf, u64 off, u32 value)
{
    buf[off + 0] = static_cast<u8>(value & 0xFF);
    buf[off + 1] = static_cast<u8>((value >> 8) & 0xFF);
    buf[off + 2] = static_cast<u8>((value >> 16) & 0xFF);
    buf[off + 3] = static_cast<u8>((value >> 24) & 0xFF);
}

void WriteImm64LE(u8* buf, u64 off, u64 value)
{
    WriteImm32LE(buf, off, static_cast<u32>(value));
    WriteImm32LE(buf, off + 4, static_cast<u32>(value >> 32));
}

// Populate `frame` with the user-code-page contents via the kernel
// direct-map alias. Reaches the frame from the parent task's view —
// the AS this frame is going into doesn't have to be active.
// Patches every ASLR-affected imm32 so absolute VAs in the payload
// match the caller's randomly-chosen code_va / stack_va.
void WriteUserCodeFrame(mm::PhysAddr frame, u64 code_va, u64 stack_va)
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
    for (u64 i = 0; i < sizeof(kUserStatPath1); ++i)
    {
        code_direct[kUserStatPath1Offset + i] = static_cast<u8>(kUserStatPath1[i]);
    }
    for (u64 i = 0; i < sizeof(kUserStatPath2); ++i)
    {
        code_direct[kUserStatPath2Offset + i] = static_cast<u8>(kUserStatPath2[i]);
    }

    // Apply ASLR patches. Each entry rewrites one imm32 field in
    // the payload so its absolute-VA reference targets the right
    // page at this process's chosen layout.
    for (const auto& p : kPayloadPatches)
    {
        const u64 base = (p.base == PatchBase::kCode) ? code_va : stack_va;
        const u64 target = base + p.base_offset;
        KASSERT(target <= 0xFFFFFFFFULL, "core/ring3", "ASLR target overflows imm32");
        WriteImm32LE(code_direct, p.bytecode_offset, static_cast<u32>(target));
    }
}

} // namespace

// Entry point for every ring-3 task created via SchedCreateUser.
// Runs in ring 0 on a fresh kernel stack with the task's own AS
// already loaded in CR3 (Schedule() flipped it on first switch-in).
// Reads user_code_va / user_stack_va from CurrentProcess() so a
// caller-configured layout (ASLR'd smoke tasks, ELF-loaded tasks
// at 0x400000 / 0x7FFFE000, etc.) is picked up automatically.
//
// Exposed via ring3_smoke.h so non-ring3 callers (syscall
// dispatch, shell `exec`) can hand it to SchedCreateUser too.
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
    // Mirror into the per-CPU slot used by the Linux-ABI syscall
    // entry stub. See kernel/cpu/percpu.h for the field; same
    // pattern as the scheduler's context-switch path.
    cpu::CurrentCpu()->kernel_rsp = kstack_top;

    Process* proc = CurrentProcess();
    if (proc == nullptr)
    {
        Panic("core/ring3", "Ring3UserEntry without a Process");
    }
    const u64 code_va = proc->user_code_va;
    // Both SysV and Microsoft x64 ABIs expect rsp % 16 == 8 on
    // function entry — i.e., the caller has already pushed an
    // 8-byte return address before the call. When we iretq
    // into user code, no return address has been pushed, so
    // rsp would be exactly page-aligned (%16 == 0) without
    // this adjustment and any movaps against rsp-relative
    // offsets inside the function prologue would #GP. Bias
    // rsp by -8 once, up front, so the ring-3 entry point
    // sees the same layout it would on a CALL.
    //
    // Linux-ABI tasks override this via proc->user_rsp_init —
    // the loader has pre-populated argc/argv/envp/auxv at the
    // top of the stack page and picked an rsp that lands user
    // _start on `argc` (which satisfies its own 16-alignment
    // requirement without the -8 bias, since the Linux initial
    // stack shape has argc at a 16-aligned boundary).
    const u64 stack_top = (proc->user_rsp_init != 0) ? proc->user_rsp_init : (proc->user_stack_va + mm::kPageSize - 8);

    SerialWrite("[ring3] task pid=");
    SerialWriteHex(sched::CurrentTaskId());
    SerialWrite(" entering ring 3 rip=");
    SerialWriteHex(code_va);
    SerialWrite(" rsp=");
    SerialWriteHex(stack_top);
    if (proc->user_gs_base != 0)
    {
        SerialWrite(" gs_base=");
        SerialWriteHex(proc->user_gs_base);
    }
    SerialWrite("\n");

    arch::EnterUserModeWithGs(code_va, stack_top, proc->user_gs_base);
}

namespace
{ // reopen anon for the rest of the file

// Build a ring-3 task: allocate AS, allocate + populate code page,
// allocate stack page, install both into the AS, wrap the AS in a
// Process with the caller-supplied cap set, hand the Process to a
// new task. The reaper's ProcessRelease tears everything down at
// task death.
void SpawnRing3Task(const char* name, CapSet caps, const fs::RamfsNode* root, u64 frame_budget, u64 tick_budget)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

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
    WriteUserCodeFrame(code_frame, code_va, stack_va);

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "failed to allocate user stack frame");
    }

    // Code: present + user, RX (no W, no NX). Stack: present + user
    // + writable + NX. Same flags as the pre-AS version — what's
    // different is they go into THIS AS's PML4 only, not the boot
    // PML4 or any sibling AS, AND their VAs are randomised per
    // process via ASLR.
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    Process* proc = ProcessCreate(name, as, caps, root, code_va, stack_va, tick_budget);
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
    SerialWrite(" code_va=");
    SerialWriteHex(code_va);
    SerialWrite(" stack_va=");
    SerialWriteHex(stack_va);
    SerialWrite("\n");

    sched::SchedCreateUser(&Ring3UserEntry, nullptr, name, proc);
}

// Deprivilege demo: a trusted task that voluntarily drops its caps
// mid-flight via SYS_DROPCAPS, then attempts SYS_WRITE again.
// Demonstrates that caps can be irreversibly revoked — the
// canonical NO_NEW_PRIVS pattern.
//
// Payload layout:
//   offset 0x00: pause
//   offset 0x02: SYS_WRITE("pre-drop\n")   ; succeeds (trusted caps)
//   offset 0x18: SYS_DROPCAPS(0xFFFFFFFF)  ; drop every bit
//   offset 0x24: SYS_WRITE("post-drop!\n") ; denied by cap check
//   offset 0x3A: SYS_YIELD
//   offset 0x41: SYS_EXIT
//
// Strings:
//   offset 0x80: "pre-drop\n"      (9 bytes)
//   offset 0xA0: "post-drop!\n"    (11 bytes)
//
// clang-format off
constexpr char kDropcapsPreMsg[] = "[dropcaps-demo] pre-drop\n";
constexpr char kDropcapsPostMsg[] = "[dropcaps-demo] post-drop (should never print!)\n";
constexpr u64 kDropcapsPreOffset = 0x80;
constexpr u64 kDropcapsPostOffset = 0xC0;

constexpr u8 kDropcapsProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    // SYS_WRITE pre-drop
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xBE, 0x80, 0x00, 0x00, 0x40,                                 // mov esi, code_va + 0x80 (PATCHED)
    0xBA, static_cast<u8>(sizeof(kDropcapsPreMsg) - 1), 0x00, 0x00, 0x00,  // mov edx, len
    0xCD, 0x80,                                                   // int 0x80
    // SYS_DROPCAPS all caps
    0xB8, 0x06, 0x00, 0x00, 0x00,                                 // mov eax, 6 (SYS_DROPCAPS)
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF,                                 // mov edi, 0xFFFFFFFF (drop everything)
    0xCD, 0x80,                                                   // int 0x80
    // SYS_WRITE post-drop (will be denied)
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xBE, 0xC0, 0x00, 0x00, 0x40,                                 // mov esi, code_va + 0xC0 (PATCHED)
    0xBA, static_cast<u8>(sizeof(kDropcapsPostMsg) - 1), 0x00, 0x00, 0x00,  // mov edx, len
    0xCD, 0x80,                                                   // int 0x80
    // SYS_YIELD
    0xB8, 0x03, 0x00, 0x00, 0x00,                                 // mov eax, 3
    0xCD, 0x80,                                                   // int 0x80
    // SYS_EXIT
    0x31, 0xC0,                                                   // xor eax, eax
    0x31, 0xFF,                                                   // xor edi, edi
    0xCD, 0x80,                                                   // int 0x80
    0xF4,                                                         // hlt
};
// clang-format on

// Offsets of imm32 fields that embed absolute user VAs. Patched
// at spawn against the ASLR-chosen code_va.
struct DropcapsPatch
{
    u16 bytecode_offset;
    u16 code_offset;
};
// imm32 sits at byte offset 13 of the SYS_WRITE #1 block
// (F3 90 pause, then B8 02 00 00 00, BF 01 00 00 00, BE <imm32>).
// SYS_WRITE #2 starts at offset 36 (after SYS_WRITE #1 ends at 24
// and SYS_DROPCAPS takes 12 more bytes), imm32 at 36+11 = 47.
constexpr DropcapsPatch kDropcapsPatches[] = {
    {0x0D, kDropcapsPreOffset},  // SYS_WRITE #1 msg ptr
    {0x2F, kDropcapsPostOffset}, // SYS_WRITE #2 msg ptr
};

void SpawnDropcapsProbe()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;
    KASSERT(code_va <= 0xFFFFFFFFULL, "core/ring3", "dropcaps code_va overflow");

    AddressSpace* as = AddressSpaceCreate(kFrameBudgetTrusted);
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for dropcaps probe");
    }
    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for dropcaps probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    // Zero-on-alloc (slice 18) means the page is already zeroed.
    for (u64 i = 0; i < sizeof(kDropcapsProbeBytes); ++i)
    {
        code_direct[i] = kDropcapsProbeBytes[i];
    }
    // Strings at their fixed offsets (include trailing NUL explicitly
    // though it's not read by SYS_WRITE — keeps the layout self-
    // documenting).
    for (u64 i = 0; i < sizeof(kDropcapsPreMsg); ++i)
    {
        code_direct[kDropcapsPreOffset + i] = static_cast<u8>(kDropcapsPreMsg[i]);
    }
    for (u64 i = 0; i < sizeof(kDropcapsPostMsg); ++i)
    {
        code_direct[kDropcapsPostOffset + i] = static_cast<u8>(kDropcapsPostMsg[i]);
    }
    // ASLR patches.
    for (const auto& p : kDropcapsPatches)
    {
        const u64 target = code_va + p.code_offset;
        WriteImm32LE(code_direct, p.bytecode_offset, static_cast<u32>(target));
    }

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for dropcaps probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Starts with FULL trusted caps — the point is to show
    // that a trusted task can voluntarily deprivilege.
    Process* proc = ProcessCreate("ring3-dropcaps-demo", as, CapSetTrusted(), fs::RamfsTrustedRoot(), code_va, stack_va,
                                  kTickBudgetTrusted);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for dropcaps probe");
    }
    SerialWrite("[ring3] queued dropcaps-demo pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" code_va=");
    SerialWriteHex(code_va);
    SerialWrite("\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-dropcaps-demo", proc);
}

// Dedicated hostile-syscall-spam payload: spins calling SYS_WRITE(fd=1)
// forever. Each iteration fails the kCapSerialConsole cap check and
// bumps the Process's sandbox_denials counter. Once the counter hits
// kSandboxDenialKillThreshold (100 denials ≈ a hundred iterations),
// the cap-check code calls FlagCurrentForKill() and the scheduler
// terminates the task at next resched.
//
// This is the "a malicious EXE retrying a blocked syscall" threat
// model in action. The existing ring3-smoke-sandbox only hits 2
// denials (well under threshold), so it's not a hostile probe
// per-se — just a compliance check. This task is explicitly hostile.
//
// Payload (16 bytes):
//   offset 0x00: pause
//   offset 0x02 loop: mov eax, 2            ; SYS_WRITE (5 bytes)
//   offset 0x07: mov edi, 1                 ; fd=1 (5 bytes)
//                                             — otherwise fd-check short-
//                                             circuits before the cap
//                                             check and we never bump
//                                             the denial counter.
//   offset 0x0C: int 0x80                   ; denied by cap check (2 b)
//   offset 0x0E: jmp loop                   ; rel8 = -14 (2 bytes)
//                                             — targets offset 2, skipping
//                                             the one-off `pause` prefix.
//
// Next_rip after the jmp = 0x10. disp = target(0x02) - next_rip(0x10)
// = -14 = 0xF2 (signed int8).
//
// clang-format off
constexpr u8 kHostileProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2    (SYS_WRITE)
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xCD, 0x80,                                                   // int 0x80
    0xEB, 0xF2,                                                   // jmp -14 (back to mov eax, 2)
};
// clang-format on

void SpawnHostileProbe()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    AddressSpace* as = AddressSpaceCreate(kFrameBudgetSandbox);
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for hostile probe");
    }
    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for hostile probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kHostileProbeBytes); ++i)
    {
        code_direct[i] = kHostileProbeBytes[i];
    }
    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for hostile probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Empty caps — SYS_WRITE is the target, so we want the cap
    // check to reject. Tight tick budget too; denial counter
    // should fire LONG before the tick budget does (100 syscalls
    // in ring 3 is microseconds), but a generous floor protects
    // against a weird schedule.
    Process* proc = ProcessCreate("ring3-hostile-syscall", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for hostile probe");
    }
    SerialWrite("[ring3] queued hostile-syscall probe pid=");
    SerialWriteHex(proc->pid);
    SerialWrite("\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-hostile-syscall", proc);
}

// Dedicated CPU-hog payload: spins in a tight `jmp $` loop so the
// scheduler's tick-budget check eventually triggers. A sandbox with
// a 50-tick budget reaches [sched] tick budget exhausted after
// roughly 500 ms of CPU time (100 Hz timer). Demonstrates the
// resource-quota layer of the sandbox: even if a malicious EXE
// gives up on probing the kernel and just burns CPU forever, the
// scheduler kills it.
//
// clang-format off
constexpr u8 kCpuHogBytes[] = {
    0xEB, 0xFE, // jmp $ (infinite loop)
};
// clang-format on

// Tight per-process budget so the test completes quickly under QEMU.
constexpr u64 kTickBudgetHog = 50;

void SpawnCpuHogProbe()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    AddressSpace* as = AddressSpaceCreate(kFrameBudgetSandbox);
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for cpu-hog probe");
    }
    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for cpu-hog");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kCpuHogBytes); ++i)
    {
        code_direct[i] = kCpuHogBytes[i];
    }
    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for cpu-hog");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);
    Process* proc =
        ProcessCreate("ring3-cpu-hog", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va, kTickBudgetHog);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for cpu-hog");
    }
    SerialWrite("[ring3] queued cpu-hog task pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" tick_budget=");
    SerialWriteHex(kTickBudgetHog);
    SerialWrite("\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-cpu-hog", proc);
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
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

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
    // Patch the "mov rax, 0x40010000" imm64 to match this process's
    // randomised stack VA. Without the patch, the `jmp rax` would
    // land at 0x40010000 — possibly unmapped in this AS (if ASLR
    // chose a different base), producing a not-present #PF rather
    // than the NX #PF we're trying to demonstrate. Imm64 sits 2
    // bytes into the payload (after `pause` + `48 B8` opcode).
    WriteImm64LE(code_direct, 4, stack_va);

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for nx probe");
    }

    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    Process* proc = ProcessCreate("ring3-nx-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for nx probe");
    }

    SerialWrite("[ring3] queued nx-probe task pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" code_va=");
    SerialWriteHex(code_va);
    SerialWrite(" stack_va=");
    SerialWriteHex(stack_va);
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
// mov rax, <imm64 patched to code_va>   ; 48 B8 <8 bytes>
// mov dword ptr [rax], 0xDEADBEEF       ; C7 00 EF BE AD DE
// ud2                                   ; 0F 0B
//
// Uses rax as an unsigned 64-bit base so the store address is
// whatever code_va the ASLR picker chose, with no sign-extension
// gotcha (which `mov [disp32], imm32` has — disp32 is signed
// and anything ≥ 0x80000000 sign-extends into the kernel half).
// That guarantees the fault is "write to a RX page" — #PF
// err=0x7 (P + W + U) — rather than "wild pointer to unmapped
// kernel VA," regardless of which 16 MiB-aligned base ASLR
// picked.
constexpr u8 kJailProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,                           // mov rax, <imm64 patched>
    0xC7, 0x00, 0xEF, 0xBE, 0xAD, 0xDE,                           // mov dword ptr [rax], 0xDEADBEEF
    0x0F, 0x0B,                                                   // ud2
};
// clang-format on

void SpawnJailProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;
    KASSERT(code_va <= 0xFFFFFFFFULL, "core/ring3", "jail-probe code_va overflows imm32");

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
    // Patch the imm64 inside `mov rax, <imm64>`. imm64 starts at
    // byte offset 4:
    //   offset 0: pause F3 90
    //   offset 2: 48 B8 <imm64>  (REX.W mov rax, imm64)
    // imm64 begins at offset 4.
    WriteImm64LE(code_direct, 4, code_va);

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for jail probe");
    }

    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Empty cap set — the jail probe never gets a chance to issue
    // a syscall (it faults first), but if the fault path ever
    // regressed and the task reached int 0x80, denying caps
    // defence-in-depths that path too.
    Process* proc = ProcessCreate("ring3-jail-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for jail probe");
    }

    SerialWrite("[ring3] queued jail-probe task pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" code_va=");
    SerialWriteHex(code_va);
    SerialWrite(" stack_va=");
    SerialWriteHex(stack_va);
    SerialWrite("\n");

    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-jail-probe", proc);
}

// Dedicated privileged-instruction probe: tries to execute `cli` from
// ring 3. IOPL is left at 0 in the iretq frame that runs every ring-3
// task (see usermode.S), so CPL(3) > IOPL(0) — the CPU must raise #GP
// on the `cli` attempt. If it didn't, a sandboxed task could globally
// disable interrupts and spin forever, starving every other process
// plus the reaper, taking the system down. Proving the #GP path kills
// the task (and only the task) is the sandbox invariant in action.
//
// Payload:
//   pause      ; 0xF3 0x90    — gives the scheduler a stable landing
//   cli        ; 0xFA         — privileged; #GP expected
//   ud2        ; 0x0F 0x0B    — belt-and-braces if cli regressed
//
// Expected: "[task-kill] ring-3 task took General protection fault —
// terminating" on COM1, followed by the same reap-and-destroy flow
// every other sandbox probe uses. Other workers (heartbeat, kbd-reader,
// idle) keep running — which they couldn't if `cli` had actually taken
// effect.
//
// clang-format off
constexpr u8 kPrivProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0xFA,                                                         // cli (privileged → #GP from ring 3)
    0x0F, 0x0B,                                                   // ud2
};
// clang-format on

void SpawnPrivProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    AddressSpace* as = AddressSpaceCreate(kFrameBudgetSandbox);
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for priv probe");
    }

    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for priv probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kPrivProbeBytes); ++i)
    {
        code_direct[i] = kPrivProbeBytes[i];
    }
    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for priv probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    Process* proc = ProcessCreate("ring3-priv-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for priv probe");
    }
    SerialWrite("[ring3] queued priv-probe task pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" code_va=");
    SerialWriteHex(code_va);
    SerialWrite(" (expect #GP on cli)\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-priv-probe", proc);
}

// Dedicated bad-int probe: issues `int 0x81` from ring 3. The IDT
// installs vectors 0..47 plus the DPL=3 gate at 0x80; vector 0x81 has
// a zero gate descriptor (present bit clear). Intel SDM Vol. 3A §6.11:
// executing `int N` when IDT[N] is not present raises #NP (vector 11)
// with error-code pointing at the offending gate. The ring-3 trap
// path logs and kills the task. This proves the kernel tolerates a
// user-driven interrupt instruction targeting an unconfigured vector
// — without the trap dispatcher's DPL-agnostic "any vector from
// ring 3 = kill the task" rule, an unhandled vector could triple-
// fault the box.
//
// Payload:
//   pause       ; 0xF3 0x90
//   int 0x81    ; 0xCD 0x81
//   ud2         ; 0x0F 0x0B
//
// clang-format off
constexpr u8 kBadIntProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0xCD, 0x81,                                                   // int 0x81 (gate not present)
    0x0F, 0x0B,                                                   // ud2
};
// clang-format on

void SpawnBadIntProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    AddressSpace* as = AddressSpaceCreate(kFrameBudgetSandbox);
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for bad-int probe");
    }

    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for bad-int probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kBadIntProbeBytes); ++i)
    {
        code_direct[i] = kBadIntProbeBytes[i];
    }
    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for bad-int probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    Process* proc = ProcessCreate("ring3-badint-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for bad-int probe");
    }
    SerialWrite("[ring3] queued bad-int-probe task pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" code_va=");
    SerialWriteHex(code_va);
    SerialWrite(" (expect #GP/#NP on int 0x81)\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-badint-probe", proc);
}

// Dedicated kernel-read probe: tries to load a byte from a kernel-
// half address (0xFFFFFFFF80000000, the higher-half kernel image
// base). The page walker finds a PTE that is Present but lacks the
// U/S bit, so a ring-3 read gets err=5 (P | U-fetch-on-non-U page).
// Kill path identical to every other user-mode fault.
//
// This is the "I have a gadget that leaks kernel addresses to ring 3"
// threat model in action: the attacker already knows a kernel
// symbol, can compute its VA, and tries to dereference it. The
// kernel's user-bit enforcement (set at boot_PML4 time) is the
// firewall between them.
//
// Payload:
//   pause            ; 0xF3 0x90
//   mov rax, <imm64> ; 0x48 0xB8 <8 bytes> — patched to 0xFFFFFFFF80000000
//   mov al,  [rax]   ; 0x8A 0x00
//   ud2              ; 0x0F 0x0B
//
// clang-format off
constexpr u8 kKernelReadProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,                           // mov rax, <imm64 patched>
    0x8A, 0x00,                                                   // mov al, byte ptr [rax]
    0x0F, 0x0B,                                                   // ud2
};
// clang-format on

constexpr u64 kKernelHigherHalfBase = 0xFFFFFFFF80000000ULL;

void SpawnKernelReadProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    AddressSpace* as = AddressSpaceCreate(kFrameBudgetSandbox);
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for kernel-read probe");
    }

    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for kernel-read probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kKernelReadProbeBytes); ++i)
    {
        code_direct[i] = kKernelReadProbeBytes[i];
    }
    // Patch imm64 at byte offset 4 (after `pause` + `48 B8`).
    WriteImm64LE(code_direct, 4, kKernelHigherHalfBase);

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for kernel-read probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    Process* proc = ProcessCreate("ring3-kread-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for kernel-read probe");
    }
    SerialWrite("[ring3] queued kread-probe task pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" code_va=");
    SerialWriteHex(code_va);
    SerialWrite(" (expect #PF on kernel-half read)\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-kread-probe", proc);
}

// Dedicated user-pointer fuzz probe: a TRUSTED ring-3 task that
// hands four deliberately wild user_buf values to SYS_WRITE in
// sequence. Each call must return -1 from `DoWrite` (via the
// `CopyFromUser` rejection path) without the kernel ever touching
// the bogus address. After the four attacks, the task issues one
// CONTROL SYS_WRITE with a valid pointer to a literal string —
// if the kernel survived all four wild attempts, the control
// message reaches COM1; if any of them corrupted state or
// panicked, the control print is missing from the boot log.
//
// Trusted caps are intentional: cap check must pass so the
// `CopyFromUser` machinery is exercised. The probes that send
// ring 3 with empty caps (hostile, jail, nx, ...) short-circuit
// at the cap check and never reach the pointer validators.
//
// Pointer choices:
//   1. NULL                — passes IsUserAddressRange (0 < kUserMax)
//                            but walker finds no PTE → false.
//   2. 0xFFFFFFFF80000000  — kernel image base, > kUserMax →
//                            IsUserAddressRange rejects up front.
//   3. 0xDEADBEEF00000000  — non-canonical hole, > kUserMax →
//                            IsUserAddressRange rejects up front.
//   4. 0x00007FFFFFFFFFFE  — last 2 bytes of user space + len=256
//                            crosses into kernel half →
//                            IsUserAddressRange rejects on the
//                            addr + len - 1 overflow check.
//
// Expected boot log (in this order):
//   [ring3] queued ptrfuzz-probe task pid=N
//   [ring3] task pid=N entering ring 3 ...
//   [ptrfuzz] passed                       <- the control print
//   [ts=...] [I] sys : exit rc val=0
//   [proc] destroy pid=N name="ring3-ptrfuzz-probe"
//
// A panic / triple fault / missing "[ptrfuzz] passed" is the
// failure signal — the kernel didn't survive one of the wild
// pointer attempts.
//
// clang-format off
constexpr char kPtrFuzzMsg[] = "[ptrfuzz] passed\n";
constexpr u64 kPtrFuzzMsgOffset = 0xC0; // string sits at code_va + 0xC0
constexpr u64 kPtrFuzzMsgLen = sizeof(kPtrFuzzMsg) - 1;

constexpr u8 kPtrFuzzProbeBytes[] = {
    0xF3, 0x90,                                                   // pause

    // ---- attack 1: SYS_WRITE(fd=1, buf=NULL, len=1) ---------------
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xBE, 0x00, 0x00, 0x00, 0x00,                                 // mov esi, 0  (NULL)
    0xBA, 0x01, 0x00, 0x00, 0x00,                                 // mov edx, 1
    0xCD, 0x80,                                                   // int 0x80

    // ---- attack 2: SYS_WRITE(1, 0xFFFFFFFF80000000, 1) ------------
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0x48, 0xBE, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFF,   // mov rsi, 0xFFFFFFFF80000000
    0xBA, 0x01, 0x00, 0x00, 0x00,                                 // mov edx, 1
    0xCD, 0x80,                                                   // int 0x80

    // ---- attack 3: SYS_WRITE(1, 0xDEADBEEF00000000, 1) ------------
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE,   // mov rsi, 0xDEADBEEF00000000
    0xBA, 0x01, 0x00, 0x00, 0x00,                                 // mov edx, 1
    0xCD, 0x80,                                                   // int 0x80

    // ---- attack 4: SYS_WRITE(1, 0x7FFFFFFFFFFE, 256) — boundary --
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0x48, 0xBE, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00,   // mov rsi, 0x00007FFFFFFFFFFE
    0xBA, 0x00, 0x01, 0x00, 0x00,                                 // mov edx, 256
    0xCD, 0x80,                                                   // int 0x80

    // ---- control: SYS_WRITE(1, code_va + 0xC0, kPtrFuzzMsgLen) ---
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xBE, 0xC0, 0x00, 0x00, 0x40,                                 // mov esi, <patched: code_va+0xC0>
    0xBA, static_cast<u8>(kPtrFuzzMsgLen), 0x00, 0x00, 0x00,      // mov edx, len
    0xCD, 0x80,                                                   // int 0x80

    // ---- SYS_EXIT(0) ----------------------------------------------
    0x31, 0xC0,                                                   // xor eax, eax
    0x31, 0xFF,                                                   // xor edi, edi
    0xCD, 0x80,                                                   // int 0x80
    0x0F, 0x0B,                                                   // ud2
};
// clang-format on
static_assert(sizeof(kPtrFuzzProbeBytes) <= kPtrFuzzMsgOffset, "ptrfuzz code overruns msg region");
static_assert(kPtrFuzzMsgOffset + sizeof(kPtrFuzzMsg) <= mm::kPageSize, "ptrfuzz msg past end of page");

// Offset of the control SYS_WRITE's `mov esi, imm32` field. The
// payload is a fixed sequence so this is a constant; verify by
// hand if the byte sequence above is ever reordered. The byte at
// `kPtrFuzzCtrlSrcOffset - 1` MUST be 0xBE (the mov-esi-imm32
// opcode) — the spawn helper asserts that before patching.
//
// Hand-traced layout:
//   0x00 .. 0x01   pause                                   (  2)
//   0x02 .. 0x17   attack 1 — NULL ptr,        22 bytes
//   0x18 .. 0x32   attack 2 — kernel-half,     27 bytes
//   0x33 .. 0x4D   attack 3 — non-canonical,   27 bytes
//   0x4E .. 0x68   attack 4 — boundary cross,  27 bytes
//   0x69 .. 0x7E   control SYS_WRITE,          22 bytes
//                    0x69 .. 0x6D  mov eax, 2
//                    0x6E .. 0x72  mov edi, 1
//                    0x73 .. 0x77  mov esi, imm32  <- patched
//                                   ^ 0x73 = opcode 0xBE, imm32 at 0x74
//                    0x78 .. 0x7C  mov edx, len
//                    0x7D .. 0x7E  int 0x80
//   0x7F .. 0x86   SYS_EXIT(0) + ud2                       (  8)
constexpr u16 kPtrFuzzCtrlSrcOffset = 0x74; // imm32 starts at byte 0x74 (116)

void SpawnPtrFuzzProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;
    KASSERT(code_va <= 0xFFFFFFFFULL, "core/ring3", "ptrfuzz code_va overflows imm32");

    AddressSpace* as = AddressSpaceCreate(kFrameBudgetTrusted);
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for ptrfuzz probe");
    }

    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for ptrfuzz probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kPtrFuzzProbeBytes); ++i)
    {
        code_direct[i] = kPtrFuzzProbeBytes[i];
    }
    for (u64 i = 0; i < sizeof(kPtrFuzzMsg); ++i)
    {
        code_direct[kPtrFuzzMsgOffset + i] = static_cast<u8>(kPtrFuzzMsg[i]);
    }
    // Patch control-write source pointer with code_va + msg_offset.
    KASSERT(code_direct[kPtrFuzzCtrlSrcOffset - 1] == 0xBE, "core/ring3",
            "ptrfuzz patch: byte before ctrl-src offset is not the mov-esi-imm32 opcode");
    WriteImm32LE(code_direct, kPtrFuzzCtrlSrcOffset, static_cast<u32>(code_va + kPtrFuzzMsgOffset));

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for ptrfuzz probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Trusted caps: cap check must PASS so the wild user pointers
    // actually reach `CopyFromUser`. With empty caps, every
    // SYS_WRITE would short-circuit at the cap check and the
    // pointer validator would never run.
    Process* proc = ProcessCreate("ring3-ptrfuzz-probe", as, CapSetTrusted(), fs::RamfsTrustedRoot(), code_va, stack_va,
                                  kTickBudgetTrusted);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for ptrfuzz probe");
    }
    SerialWrite("[ring3] queued ptrfuzz-probe task pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" code_va=");
    SerialWriteHex(code_va);
    SerialWrite(" (expect 4× -1 then [ptrfuzz] passed)\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-ptrfuzz-probe", proc);
}

// writefuzz probe — the CopyToUser sibling of ptrfuzz. Ptrfuzz
// covers `SYS_WRITE`, which exercises `CopyFromUser`. This probe
// covers the write-direction of the pointer validator:
// `CopyToUser` inside `SYS_STAT` (writes a `u64` size) and
// `SYS_READ` (writes file bytes). A trusted task with
// `kCapFsRead` issues four syscalls that ALL hit valid lookups
// (so the call actually reaches `CopyToUser`) but supply wild
// DESTINATION pointers:
//
//   1. SYS_STAT(/etc/version, dst=NULL)
//      IsUserAddressRange(0, 8) passes (0 ≤ kUserMax); walker
//      finds no PTE → IsUserRangeAccessible → false → -1.
//   2. SYS_STAT(/etc/version, dst=0xFFFFFFFF80000000)
//      kernel-half, > kUserMax → range-check reject → -1.
//   3. SYS_READ(/etc/version, dst=0xDEADBEEF00000000, cap=128)
//      non-canonical, > kUserMax → range-check reject → -1.
//   4. SYS_READ(/etc/version, dst=0x7FFFFFFFFFFE, cap=256)
//      to_copy clamps to file_size (27 for /etc/version);
//      rsi + 26 = 0x800000000018 > kUserMax →
//      range-check reject → -1.
//
// Each call must return -1 WITHOUT the kernel writing a byte to
// the bogus address. After the four attacks, a control
// SYS_WRITE prints "[writefuzz] passed" — if any CopyToUser
// stumbled and actually attempted the write, the task would
// crash (or worse, the kernel would page-fault in the copy
// routine) and the control print would be missing.
//
// This closes the CopyToUser half of the pointer-validator story
// flagged in .claude/knowledge/pentest-ring3-adversarial-v0.md.

// clang-format off
constexpr char kWriteFuzzPath[] = "/etc/version";
constexpr char kWriteFuzzMsg[] = "[writefuzz] passed\n";
constexpr u64 kWriteFuzzPathOffset = 0x80; // NUL-terminated path in code page
constexpr u64 kWriteFuzzMsgOffset = 0xA0;  // control message in code page
constexpr u64 kWriteFuzzMsgLen = sizeof(kWriteFuzzMsg) - 1;

constexpr u8 kWriteFuzzProbeBytes[] = {
    0xF3, 0x90,                                                   // 0x00 pause

    // attack 1: SYS_STAT(path, NULL) — unmapped user VA
    0xB8, 0x04, 0x00, 0x00, 0x00,                                 // 0x02 mov eax, 4
    0xBF, 0x80, 0x00, 0x00, 0x40,                                 // 0x07 mov edi, path (patched)
    0xBE, 0x00, 0x00, 0x00, 0x00,                                 // 0x0C mov esi, 0 (NULL)
    0xCD, 0x80,                                                   // 0x11 int 0x80

    // attack 2: SYS_STAT(path, 0xFFFFFFFF80000000) — kernel-half
    0xB8, 0x04, 0x00, 0x00, 0x00,                                 // 0x13 mov eax, 4
    0xBF, 0x80, 0x00, 0x00, 0x40,                                 // 0x18 mov edi, path (patched)
    0x48, 0xBE, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFF,   // 0x1D mov rsi, 0xFFFFFFFF80000000
    0xCD, 0x80,                                                   // 0x27 int 0x80

    // attack 3: SYS_READ(path, 0xDEADBEEF00000000, 128) — non-canonical
    0xB8, 0x05, 0x00, 0x00, 0x00,                                 // 0x29 mov eax, 5
    0xBF, 0x80, 0x00, 0x00, 0x40,                                 // 0x2E mov edi, path (patched)
    0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE,   // 0x33 mov rsi, 0xDEADBEEF00000000
    0xBA, 0x80, 0x00, 0x00, 0x00,                                 // 0x3D mov edx, 128
    0xCD, 0x80,                                                   // 0x42 int 0x80

    // attack 4: SYS_READ(path, 0x00007FFFFFFFFFFE, 256) — boundary cross
    0xB8, 0x05, 0x00, 0x00, 0x00,                                 // 0x44 mov eax, 5
    0xBF, 0x80, 0x00, 0x00, 0x40,                                 // 0x49 mov edi, path (patched)
    0x48, 0xBE, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00,   // 0x4E mov rsi, 0x00007FFFFFFFFFFE
    0xBA, 0x00, 0x01, 0x00, 0x00,                                 // 0x58 mov edx, 256
    0xCD, 0x80,                                                   // 0x5D int 0x80

    // control: SYS_WRITE(1, msg, kWriteFuzzMsgLen)
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // 0x5F mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // 0x64 mov edi, 1
    0xBE, 0xA0, 0x00, 0x00, 0x40,                                 // 0x69 mov esi, msg (patched)
    0xBA, static_cast<u8>(kWriteFuzzMsgLen), 0x00, 0x00, 0x00,    // 0x6E mov edx, len
    0xCD, 0x80,                                                   // 0x73 int 0x80

    // SYS_EXIT(0)
    0x31, 0xC0,                                                   // 0x75 xor eax, eax
    0x31, 0xFF,                                                   // 0x77 xor edi, edi
    0xCD, 0x80,                                                   // 0x79 int 0x80
    0x0F, 0x0B,                                                   // 0x7B ud2
};
// clang-format on
static_assert(sizeof(kWriteFuzzProbeBytes) <= kWriteFuzzPathOffset, "writefuzz code overruns path region");
static_assert(kWriteFuzzPathOffset + sizeof(kWriteFuzzPath) <= kWriteFuzzMsgOffset, "writefuzz path overruns msg");
static_assert(kWriteFuzzMsgOffset + sizeof(kWriteFuzzMsg) <= mm::kPageSize, "writefuzz msg past end of page");

// Patch offsets — the imm32 byte in each `mov edi/esi, imm32`
// sits one byte past the opcode. See the hand-traced layout in
// the payload comment block above. Re-derive if the sequence is
// ever reshuffled.
constexpr u16 kWriteFuzzPathPatchOffsets[] = {0x08, 0x19, 0x2F, 0x4A};
constexpr u16 kWriteFuzzMsgPatchOffset = 0x6A;

void SpawnWriteFuzzProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;
    KASSERT(code_va <= 0xFFFFFFFFULL, "core/ring3", "writefuzz code_va overflows imm32");

    AddressSpace* as = AddressSpaceCreate(kFrameBudgetTrusted);
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for writefuzz probe");
    }

    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for writefuzz probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kWriteFuzzProbeBytes); ++i)
    {
        code_direct[i] = kWriteFuzzProbeBytes[i];
    }
    for (u64 i = 0; i < sizeof(kWriteFuzzPath); ++i)
    {
        code_direct[kWriteFuzzPathOffset + i] = static_cast<u8>(kWriteFuzzPath[i]);
    }
    for (u64 i = 0; i < sizeof(kWriteFuzzMsg); ++i)
    {
        code_direct[kWriteFuzzMsgOffset + i] = static_cast<u8>(kWriteFuzzMsg[i]);
    }
    // Patch all four rdi path-pointer slots and the control rsi.
    for (u16 off : kWriteFuzzPathPatchOffsets)
    {
        KASSERT(code_direct[off - 1] == 0xBF, "core/ring3",
                "writefuzz patch: byte before path slot is not mov-edi opcode");
        WriteImm32LE(code_direct, off, static_cast<u32>(code_va + kWriteFuzzPathOffset));
    }
    KASSERT(code_direct[kWriteFuzzMsgPatchOffset - 1] == 0xBE, "core/ring3",
            "writefuzz patch: byte before ctrl-src slot is not mov-esi opcode");
    WriteImm32LE(code_direct, kWriteFuzzMsgPatchOffset, static_cast<u32>(code_va + kWriteFuzzMsgOffset));

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for writefuzz probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Trusted caps: need kCapFsRead to reach the SYS_READ/SYS_STAT
    // implementations. With empty caps the cap gate would
    // short-circuit and CopyToUser would never run.
    Process* proc = ProcessCreate("ring3-writefuzz-probe", as, CapSetTrusted(), fs::RamfsTrustedRoot(), code_va,
                                  stack_va, kTickBudgetTrusted);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for writefuzz probe");
    }
    SerialWrite("[ring3] queued writefuzz-probe task pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" code_va=");
    SerialWriteHex(code_va);
    SerialWrite(" (expect 4× -1 then [writefuzz] passed)\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-writefuzz-probe", proc);
}

// ---- bp-probe: ring-3 exercise of SYS_BP_INSTALL / SYS_BP_REMOVE. -----
//
// A trusted task that installs a HW execute breakpoint on an
// instruction in its own code page, then executes that instruction
// (a `nop` at code_va + kBpProbeTargetOffset), expects the kernel
// to log `HW BP hit` for its pid, then removes the BP and prints
// `[bp-probe] passed via HW BP`. Expected serial log sequence:
//
//   [ring3] queued bp-probe task pid=N
//   [ring3] task pid=N entering ring 3 ...
//   [I] debug/bp : HW BP installed   addr=<target>   id=<id>
//   [I] debug/bp : HW BP hit   addr=<target>   hits=0x1 (1)
//   [I] debug/bp : HW BP removed id   val=<id>
//   [bp-probe] passed via HW BP
//   [I] sys : exit rc val=0x0
//   [proc] destroy pid=N name="ring3-bp-probe"
//
// Failure modes caught:
//   * `SYS_BP_INSTALL` cap-gate bug → rax=-1 → probe still prints
//     the passed-msg but the kernel log lacks the `HW BP hit` line.
//   * Context-switch save/restore bug → BP misses on the specific
//     CPU the task ended up running on → no `HW BP hit` line.
//   * DR7 enable-bit pack bug → BP doesn't arm → no hit.
//
// clang-format off
constexpr char kBpProbeMsg[] = "[bp-probe] passed via HW BP\n";
constexpr u64 kBpProbeMsgOffset = 0x80;
constexpr u64 kBpProbeMsgLen = sizeof(kBpProbeMsg) - 1;
constexpr u64 kBpProbeTargetOffset = 0x19; // byte offset of the BP's `nop`

constexpr u8 kBpProbeBytes[] = {
    // ---- SYS_BP_INSTALL(va=<TARGET>, kind=1, len=1) ---------
    0xB8, 0x26, 0x00, 0x00, 0x00,                                 // 0x00 mov eax, 38 (SYS_BP_INSTALL)
    0xBF, 0x00, 0x00, 0x00, 0x00,                                 // 0x05 mov edi, <TARGET_VA>  (patched)
    0xBE, 0x01, 0x00, 0x00, 0x00,                                 // 0x0A mov esi, 1 (HwExecute)
    0xBA, 0x01, 0x00, 0x00, 0x00,                                 // 0x0F mov edx, 1 (len)
    0xCD, 0x80,                                                   // 0x14 int 0x80 → rax = bp_id
    0x49, 0x89, 0xC4,                                             // 0x16 mov r12, rax (save bp_id)

    // ---- BP target: a single nop at code_va + kBpProbeTargetOffset.
    // The kernel's #DB handler logs the hit; we just keep going.
    0x90,                                                         // 0x19 nop  (HW BP fires here)

    // ---- SYS_BP_REMOVE(id=r12) ------------------------------
    0xB8, 0x27, 0x00, 0x00, 0x00,                                 // 0x1A mov eax, 39 (SYS_BP_REMOVE)
    0x4C, 0x89, 0xE7,                                             // 0x1F mov rdi, r12
    0xCD, 0x80,                                                   // 0x22 int 0x80

    // ---- SYS_WRITE(1, code_va + MSG_OFFSET, MSG_LEN) --------
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // 0x24 mov eax, 2 (SYS_WRITE)
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // 0x29 mov edi, 1 (fd)
    0xBE, 0x00, 0x00, 0x00, 0x00,                                 // 0x2E mov esi, <MSG_VA>  (patched)
    0xBA, static_cast<u8>(kBpProbeMsgLen), 0x00, 0x00, 0x00,      // 0x33 mov edx, len
    0xCD, 0x80,                                                   // 0x38 int 0x80

    // ---- SYS_EXIT(0) ----------------------------------------
    0x31, 0xC0,                                                   // 0x3A xor eax, eax
    0x31, 0xFF,                                                   // 0x3C xor edi, edi
    0xCD, 0x80,                                                   // 0x3E int 0x80
    0x0F, 0x0B,                                                   // 0x40 ud2
};
// clang-format on
static_assert(sizeof(kBpProbeBytes) <= kBpProbeMsgOffset, "bp-probe code overruns msg region");
static_assert(kBpProbeMsgOffset + sizeof(kBpProbeMsg) <= mm::kPageSize, "bp-probe msg past end of page");

// Imm32 patch offsets — hand-verified above. The byte immediately
// preceding each imm32 MUST be the expected opcode (0xBF for
// mov edi, 0xBE for mov esi); asserted in the spawn helper.
constexpr u16 kBpProbeInstallTargetOffset = 0x06; // imm32 at 0x06 (opcode 0xBF at 0x05)
constexpr u16 kBpProbeWriteSrcOffset = 0x2F;      // imm32 at 0x2F (opcode 0xBE at 0x2E)

void SpawnBpProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;
    KASSERT(code_va <= 0xFFFFFFFFULL, "core/ring3", "bp-probe code_va overflows imm32");

    AddressSpace* as = AddressSpaceCreate(kFrameBudgetTrusted);
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for bp-probe");
    }

    const PhysAddr code_frame = AllocateFrame();
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for bp-probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
        code_direct[i] = 0;
    for (u64 i = 0; i < sizeof(kBpProbeBytes); ++i)
        code_direct[i] = kBpProbeBytes[i];
    for (u64 i = 0; i < sizeof(kBpProbeMsg); ++i)
        code_direct[kBpProbeMsgOffset + i] = static_cast<u8>(kBpProbeMsg[i]);

    // Patch the install target and write-source VAs. Opcode
    // sanity checks first — if the byte layout above ever gets
    // shuffled, we want an explicit panic rather than a wrong
    // address silently slipping through.
    KASSERT(code_direct[kBpProbeInstallTargetOffset - 1] == 0xBF, "core/ring3",
            "bp-probe patch: byte before install-target offset is not mov-edi-imm32 opcode");
    KASSERT(code_direct[kBpProbeWriteSrcOffset - 1] == 0xBE, "core/ring3",
            "bp-probe patch: byte before write-src offset is not mov-esi-imm32 opcode");
    WriteImm32LE(code_direct, kBpProbeInstallTargetOffset, static_cast<u32>(code_va + kBpProbeTargetOffset));
    WriteImm32LE(code_direct, kBpProbeWriteSrcOffset, static_cast<u32>(code_va + kBpProbeMsgOffset));

    const PhysAddr stack_frame = AllocateFrame();
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for bp-probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Trusted caps include kCapSerialConsole (for the final
    // SYS_WRITE) and kCapDebug (gating the new BP syscalls).
    Process* proc = ProcessCreate("ring3-bp-probe", as, CapSetTrusted(), fs::RamfsTrustedRoot(), code_va, stack_va,
                                  kTickBudgetTrusted);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for bp-probe");
    }
    SerialWrite("[ring3] queued bp-probe task pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" code_va=");
    SerialWriteHex(code_va);
    SerialWrite(" (expect HW BP hit then [bp-probe] passed)\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-bp-probe", proc);
}

bool LocalStrEq(const char* a, const char* b)
{
    for (u32 i = 0;; ++i)
    {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            return true;
    }
}

} // namespace

u64 SpawnElfFile(const char* name, const u8* elf_bytes, u64 elf_len, CapSet caps, const fs::RamfsNode* root,
                 u64 frame_budget, u64 tick_budget)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    if (elf_bytes == nullptr || elf_len == 0 || root == nullptr)
    {
        return 0;
    }
    // Auto-detect Linux-ABI binaries by EI_OSABI byte at ELF
    // offset 7. ELFOSABI_LINUX = 3. Most gcc/clang output uses
    // ELFOSABI_SYSV = 0 (which we treat as native); only binaries
    // explicitly marked Linux route through SpawnElfLinux so the
    // caller's intent is preserved for ambiguous inputs. When a
    // richer discriminator lands (PT_INTERP sniffing,
    // `.note.ABI-tag` parsing), add it here.
    if (elf_len > 7 && elf_bytes[7] == 3)
    {
        return SpawnElfLinux(name, elf_bytes, elf_len, caps, root, frame_budget, tick_budget);
    }
    // Fire the `inspect arm` latch if the operator armed it
    // before spawning. No-op when unarmed; one-shot when armed.
    duetos::debug::InspectOnSpawn(name, elf_bytes, elf_len);
    AddressSpace* as = AddressSpaceCreate(frame_budget);
    if (as == nullptr)
    {
        return 0;
    }
    const ElfLoadResult r = ElfLoad(elf_bytes, elf_len, as);
    if (!r.ok)
    {
        // ElfLoad may have installed partial mappings; Release
        // walks the AS's user-region table and frees whatever
        // landed.
        AddressSpaceRelease(as);
        return 0;
    }
    Process* proc = ProcessCreate(name, as, caps, root, r.entry_va, r.stack_va, tick_budget);
    if (proc == nullptr)
    {
        AddressSpaceRelease(as);
        return 0;
    }
    SerialWrite("[ring3] elf spawn name=\"");
    SerialWrite(name);
    SerialWrite("\" pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" entry=");
    SerialWriteHex(r.entry_va);
    SerialWrite(" stack_top=");
    SerialWriteHex(r.stack_top);
    SerialWrite("\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, name, proc);
    return proc->pid;
}

u64 SpawnElfLinux(const char* name, const u8* elf_bytes, u64 elf_len, CapSet caps, const fs::RamfsNode* root,
                  u64 frame_budget, u64 tick_budget)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    if (elf_bytes == nullptr || elf_len == 0 || root == nullptr)
    {
        return 0;
    }
    duetos::debug::InspectOnSpawn(name, elf_bytes, elf_len);
    AddressSpace* as = AddressSpaceCreate(frame_budget);
    if (as == nullptr)
    {
        return 0;
    }
    const ElfLoadResult r = ElfLoad(elf_bytes, elf_len, as);
    if (!r.ok)
    {
        AddressSpaceRelease(as);
        return 0;
    }
    Process* proc = ProcessCreate(name, as, caps, root, r.entry_va, r.stack_va, tick_budget);
    if (proc == nullptr)
    {
        AddressSpaceRelease(as);
        return 0;
    }
    // Flip the ABI flavor + seed Linux heap/mmap anchors. The ELF
    // loader doesn't know which ABI the image targets; we decide
    // here. kAbiLinux steers this task's `syscall` instructions
    // through subsystems::linux::LinuxSyscallDispatch instead of
    // the native int-0x80 table.
    //
    // brk base: well past any reasonable static ELF's highest
    // PT_LOAD. Our smokes load at 0x400078; 256 MiB past that is
    // plenty of headroom without poking into the 0x7fffe000
    // stack. A future loader pass will compute this from the
    // max p_vaddr+p_memsz; v0 hard-codes.
    //
    // mmap cursor: 112 TiB up — well clear of everything else
    // in the user half.
    proc->abi_flavor = kAbiLinux;
    proc->linux_brk_base = 0x0000'0000'1000'0000ull; // 256 MiB
    proc->linux_brk_current = proc->linux_brk_base;
    proc->linux_mmap_cursor = 0x0000'7000'0000'0000ull;

    // Populate the top of the user stack with a Linux-ABI initial
    // layout. Musl's _start reads from rsp; the layout is
    // (rsp -> higher addresses):
    //
    //   [rsp_init +  0]: argc = 0
    //   [rsp_init +  8]: argv[0] = NULL
    //   [rsp_init + 16]: envp[0] = NULL
    //   [rsp_init + 24]: AT_PAGESZ  = 6
    //   [rsp_init + 32]: page size  = 4096
    //   [rsp_init + 40]: AT_RANDOM  = 25
    //   [rsp_init + 48]: rand_ptr   = rsp_init + 72
    //   [rsp_init + 56]: AT_NULL    = 0
    //   [rsp_init + 64]: auxv end   = 0
    //   [rsp_init + 72]: 16 bytes of xorshift-mixed rdtsc entropy
    //   [rsp_init + 88]: 8 bytes pad (keep rsp_init 16-aligned)
    //
    // 96 bytes total. musl uses AT_PAGESZ for mmap bookkeeping
    // and AT_RANDOM as a stack-cookie / pointer-mangling seed.
    // AT_PHDR / AT_EXECFN are not supplied; musl skips what it
    // can't find and pulls program-header info from the ELF it
    // loaded itself (works for static binaries).
    const PhysAddr stack_frame = AddressSpaceLookupUserFrame(as, r.stack_va);
    if (stack_frame != kNullFrame)
    {
        auto* stack_direct = static_cast<u8*>(PhysToVirt(stack_frame));
        const u64 off = mm::kPageSize - 96;
        for (u64 i = 0; i < 96; ++i)
            stack_direct[off + i] = 0;
        const u64 rsp_init = r.stack_top - 96;

        auto put_u64 = [&](u64 at, u64 v)
        {
            for (u64 i = 0; i < 8; ++i)
                stack_direct[off + at + i] = static_cast<u8>(v >> (i * 8));
        };
        // argc / argv[0] / envp[0] already zeroed.
        // Aux vector.
        put_u64(24, 6);             // AT_PAGESZ
        put_u64(32, 4096);          // page size
        put_u64(40, 25);            // AT_RANDOM
        put_u64(48, rsp_init + 72); // pointer (user VA) to random block
        put_u64(56, 0);             // AT_NULL
        put_u64(64, 0);             // terminator value
        // Fill the 16-byte AT_RANDOM block from the kernel
        // entropy pool. Linux userland libc (glibc, musl)
        // consumes these bytes for stack-cookie + pointer
        // obfuscation at startup, so real entropy here gives
        // a ported userland the same hardening it expects on
        // bare Linux.
        duetos::core::RandomFillBytes(stack_direct + off + 72, 16);
        proc->user_rsp_init = rsp_init;
    }

    SerialWrite("[ring3] linux elf spawn name=\"");
    SerialWrite(name);
    SerialWrite("\" pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" entry=");
    SerialWriteHex(r.entry_va);
    SerialWrite(" stack_top=");
    SerialWriteHex(r.stack_top);
    SerialWrite("\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, name, proc);
    return proc->pid;
}

// PE twin of SpawnElfFile. Parses a PE/COFF image with the
// v0 loader, maps its sections + a stack page into a fresh
// AddressSpace, and enqueues a ring-3 task to enter it. The
// process-level glue (Process / Ring3UserEntry / EnterUserMode)
// does NOT care whether the image came from an ELF or a PE —
// once the entry_va + stack_top are set, the ring-3 transition
// is identical.
u64 SpawnPeFile(const char* name, const u8* pe_bytes, u64 pe_len, CapSet caps, const fs::RamfsNode* root,
                u64 frame_budget, u64 tick_budget)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    if (pe_bytes == nullptr || pe_len == 0 || root == nullptr)
    {
        return 0;
    }
    duetos::debug::InspectOnSpawn(name, pe_bytes, pe_len);
    // Diagnostic pre-pass — always runs, always logs. A PE we
    // reject below still gets a full report: sections, imports,
    // relocs, TLS. That's how we know what a real Win32
    // subsystem would have to provide.
    SerialWrite("[ring3] pe report name=\"");
    SerialWrite(name);
    SerialWrite("\"\n");
    PeReport(pe_bytes, pe_len);

    // PeLoad handles both Ok and ImportsPresent (the latter
    // by walking the IAT and patching via the Win32 stub
    // table). Any other non-Ok status is fatal — log and
    // bail. For ImportsPresent we don't bail here; PeLoad may
    // still fail if a specific import isn't in the stub
    // table, at which point ok=false and we fall through to
    // the generic "load failed" cleanup below.
    const PeStatus vs = PeValidate(pe_bytes, pe_len);
    if (vs != PeStatus::Ok && vs != PeStatus::ImportsPresent && vs != PeStatus::TlsPresent)
    {
        SerialWrite("[ring3] pe reject name=\"");
        SerialWrite(name);
        SerialWrite("\" reason=");
        SerialWrite(PeStatusName(vs));
        SerialWrite("\n");
        return 0;
    }
    AddressSpace* as = AddressSpaceCreate(frame_budget);
    if (as == nullptr)
    {
        return 0;
    }
    // Per-process ASLR: pick a 64 KiB-aligned delta in [0, 64 MiB).
    // 10 bits of entropy × 64 KiB = 1024 possible positions. Kept
    // modest so the shifted ImageBase can't collide with the
    // fixed-VA subsystem regions (win32 heap at 0x50000000, stubs
    // at 0x60000000, proc-env at 0x65000000, TEB at 0x70000000,
    // stack ending at 0x80000000). A PE's preferred base is
    // typically 0x140000000 — well above those — so adding up to
    // ~64 MiB keeps us safely in the 0x140000000..0x144000000
    // band.
    const u64 entropy = duetos::core::RandomU64();
    const u64 aslr_delta = (entropy & 0x3FF) * (64ULL * 1024);

    // Stage-2 slice 6/9 — pre-load the per-spawn DLL set into
    // `as` BEFORE PeLoad runs so ResolveImports can consult
    // their EATs. Each DllImage lives on this stack frame for
    // the duration of PeLoad; after ProcessCreate we copy them
    // into the Process's permanent dll_images[] table. Only
    // preload when the PE has imports (vs == ImportsPresent) —
    // freestanding PEs don't need DLLs and would pay the frame
    // cost for nothing.
    //
    // The table below is the authoritative list of DLLs that
    // every Win32-imports PE gets pre-loaded. Adding a new DLL
    // here is a one-line append once the blob is embedded via
    // CMake. `kPreloadSlotCap` caps the stack-local array size;
    // bump if the list grows past it.
    constexpr u64 kPreloadSlotCap = 48;
    struct PreloadDllEntry
    {
        const char* label; // diagnostic name for boot-log
        const u8* bytes;   // kernel direct-map pointer to the blob
        u64 len;           // blob size in bytes
    };
    // `static` so the array lives in .rodata and the
    // initializer doesn't compile to a runtime memcpy from a
    // template — the kernel doesn't link libc.
    static const PreloadDllEntry preload_set[] = {
        {"customdll.dll", fs::generated::kBinCustomDllBytes, fs::generated::kBinCustomDllBytes_len},
        {"customdll2.dll", fs::generated::kBinCustomDll2Bytes, fs::generated::kBinCustomDll2Bytes_len},
        // Stage-2 slice 10: kernel32.dll retirement DLL —
        // now 32 exports across slices 10-12 (process/thread
        // identity, pseudo-handles, last-error, terminators,
        // safe-ignore shims, GetStdHandle, Sleep/
        // SwitchToThread / GetTickCount(64), full Interlocked*
        // family 32+64-bit). The via-DLL path in
        // ResolveImports matches kernel32.dll BEFORE falling
        // through to the hand-assembled stubs page. Stubs stay
        // as dead-code fallback; sweep-slice later.
        {"kernel32.dll", fs::generated::kBinKernel32DllBytes, fs::generated::kBinKernel32DllBytes_len},
        // Stage-2 slice 13: vcruntime140.dll — memset / memcpy
        // / memmove. Every MSVC-built PE calls these for
        // struct copy / zero-init / CRT startup. The via-DLL
        // path now fires for each.
        {"vcruntime140.dll", fs::generated::kBinVcruntime140DllBytes, fs::generated::kBinVcruntime140DllBytes_len},
        // Stage-2 slice 14: msvcrt.dll — string intrinsics
        // (strlen / strcmp / strcpy / strchr + wide variants).
        // Retires the batch-7 + 29/31 flat stubs.
        {"msvcrt.dll", fs::generated::kBinMsvcrtDllBytes, fs::generated::kBinMsvcrtDllBytes_len},
        // Stage-2 slice 15: ucrtbase.dll — UCRT runtime: heap
        // (malloc/free/calloc/realloc/_aligned_*), terminators
        // (exit/_exit), CRT startup shims (_initterm,
        // _set_app_type, ...), string intrinsics. Retires the
        // batch-6 / 9 flat stubs.
        {"ucrtbase.dll", fs::generated::kBinUcrtbaseDllBytes, fs::generated::kBinUcrtbaseDllBytes_len},
        // Stage-2 slice 24: ntdll.dll — Nt* / Zw* / Rtl* /
        // Ldr* / __chkstk. 108 exports. Retires the batch-42+
        // ntdll flat stubs. Zw* are same-DLL forwarders to
        // Nt*; STATUS_NOT_IMPLEMENTED aliases centralise on
        // NtReturnNotImpl.
        {"ntdll.dll", fs::generated::kBinNtdllDllBytes, fs::generated::kBinNtdllDllBytes_len},
        // Stage-2 slice 25: dbghelp.dll — 11 Sym* / StackWalk /
        // MiniDumpWriteDump no-ops. Callers check returns; v0
        // has no PDB parser or stack walker.
        {"dbghelp.dll", fs::generated::kBinDbghelpDllBytes, fs::generated::kBinDbghelpDllBytes_len},
        // Stage-2 slice 26: msvcp140.dll — 17 C++ std::
        // throw helpers + ostream stubs via mangled-name .def
        // aliases. Throw paths terminate with SYS_EXIT(3).
        {"msvcp140.dll", fs::generated::kBinMsvcp140DllBytes, fs::generated::kBinMsvcp140DllBytes_len},
        // Stage-2 slice 27: kernelbase.dll — pure forwarders
        // to kernel32.dll (44 entries). Resolved at IAT-patch
        // time via the slice-8 forwarder chaser.
        {"kernelbase.dll", fs::generated::kBinKernelbaseDllBytes, fs::generated::kBinKernelbaseDllBytes_len},
        // Stage-2 slice 27: advapi32.dll — Reg* (not-found),
        // token/privilege (success), GetUserName* (constant),
        // SystemFunction036 (deterministic RNG). 25 exports.
        {"advapi32.dll", fs::generated::kBinAdvapi32DllBytes, fs::generated::kBinAdvapi32DllBytes_len},
        // Stage-2 slice 28: small stub DLLs for misc support
        // surface. Most return "not found" / success sentinels;
        // CoTaskMem* + SysAllocString alias the process heap.
        {"shlwapi.dll", fs::generated::kBinShlwapiDllBytes, fs::generated::kBinShlwapiDllBytes_len},
        {"shell32.dll", fs::generated::kBinShell32DllBytes, fs::generated::kBinShell32DllBytes_len},
        {"ole32.dll", fs::generated::kBinOle32DllBytes, fs::generated::kBinOle32DllBytes_len},
        {"oleaut32.dll", fs::generated::kBinOleaut32DllBytes, fs::generated::kBinOleaut32DllBytes_len},
        {"winmm.dll", fs::generated::kBinWinmmDllBytes, fs::generated::kBinWinmmDllBytes_len},
        {"bcrypt.dll", fs::generated::kBinBcryptDllBytes, fs::generated::kBinBcryptDllBytes_len},
        {"psapi.dll", fs::generated::kBinPsapiDllBytes, fs::generated::kBinPsapiDllBytes_len},
        // Stage-2 slice 29: DirectX + user32/gdi32 return-
        // constant tier. Every DirectX entry returns E_NOTIMPL;
        // GetDC returns a sentinel so windowed programs don't
        // null-check-fail at HDC acquisition. Full GUI/drawing
        // stack remains deferred.
        {"d3d9.dll", fs::generated::kBinD3d9DllBytes, fs::generated::kBinD3d9DllBytes_len},
        {"d3d11.dll", fs::generated::kBinD3d11DllBytes, fs::generated::kBinD3d11DllBytes_len},
        {"d3d12.dll", fs::generated::kBinD3d12DllBytes, fs::generated::kBinD3d12DllBytes_len},
        {"dxgi.dll", fs::generated::kBinDxgiDllBytes, fs::generated::kBinDxgiDllBytes_len},
        {"user32.dll", fs::generated::kBinUser32DllBytes, fs::generated::kBinUser32DllBytes_len},
        {"gdi32.dll", fs::generated::kBinGdi32DllBytes, fs::generated::kBinGdi32DllBytes_len},
        // Stage-2 slice 31: networking / crypto / common UI /
        // version / setup. All stubs — real Windows programs
        // that import these typically check returns and
        // gracefully fall back.
        {"ws2_32.dll", fs::generated::kBinWs2_32DllBytes, fs::generated::kBinWs2_32DllBytes_len},
        {"wininet.dll", fs::generated::kBinWininetDllBytes, fs::generated::kBinWininetDllBytes_len},
        {"winhttp.dll", fs::generated::kBinWinhttpDllBytes, fs::generated::kBinWinhttpDllBytes_len},
        {"crypt32.dll", fs::generated::kBinCrypt32DllBytes, fs::generated::kBinCrypt32DllBytes_len},
        {"comctl32.dll", fs::generated::kBinComctl32DllBytes, fs::generated::kBinComctl32DllBytes_len},
        {"comdlg32.dll", fs::generated::kBinComdlg32DllBytes, fs::generated::kBinComdlg32DllBytes_len},
        {"version.dll", fs::generated::kBinVersionDllBytes, fs::generated::kBinVersionDllBytes_len},
        {"setupapi.dll", fs::generated::kBinSetupapiDllBytes, fs::generated::kBinSetupapiDllBytes_len},
        // Stage-2 slice 33: six more support DLLs — IP helper,
        // user env, terminal services, DWM, theming, SSPI.
        {"iphlpapi.dll", fs::generated::kBinIphlpapiDllBytes, fs::generated::kBinIphlpapiDllBytes_len},
        {"userenv.dll", fs::generated::kBinUserenvDllBytes, fs::generated::kBinUserenvDllBytes_len},
        {"wtsapi32.dll", fs::generated::kBinWtsapi32DllBytes, fs::generated::kBinWtsapi32DllBytes_len},
        {"dwmapi.dll", fs::generated::kBinDwmapiDllBytes, fs::generated::kBinDwmapiDllBytes_len},
        {"uxtheme.dll", fs::generated::kBinUxthemeDllBytes, fs::generated::kBinUxthemeDllBytes_len},
        {"secur32.dll", fs::generated::kBinSecur32DllBytes, fs::generated::kBinSecur32DllBytes_len},
    };
    constexpr u64 kPreloadEntryCount = sizeof(preload_set) / sizeof(preload_set[0]);
    static_assert(kPreloadEntryCount <= kPreloadSlotCap, "Preload DLL list exceeds stack-local cap");

    // Intentionally NOT value-initialised: zero-init of a 4-entry
    // DllImage array (~400 bytes) makes clang emit memset, which
    // the kernel doesn't link. We only ever read entries
    // [0..preloaded_count); each slot we read is fully assigned
    // just above the increment.
    DllImage preloaded_dlls[kPreloadSlotCap];
    u64 preloaded_count = 0;
    if (vs == PeStatus::ImportsPresent)
    {
        for (u64 i = 0; i < kPreloadEntryCount; ++i)
        {
            const DllLoadResult dll = DllLoad(preload_set[i].bytes, preload_set[i].len, as, /*aslr_delta=*/0);
            if (dll.status == DllLoadStatus::Ok)
            {
                preloaded_dlls[preloaded_count] = dll.image;
                ++preloaded_count;
                SerialWrite("[ring3] pre-loaded ");
                SerialWrite(preload_set[i].label);
                SerialWrite(" base=");
                SerialWriteHex(dll.image.base_va);
                SerialWrite(" (pre-PeLoad — visible to ResolveImports)\n");
            }
            else
            {
                SerialWrite("[ring3] ");
                SerialWrite(preload_set[i].label);
                SerialWrite(" DllLoad failed for \"");
                SerialWrite(name);
                SerialWrite("\" status=");
                SerialWrite(DllLoadStatusName(dll.status));
                SerialWrite(" — this DLL's exports won't be resolvable via-DLL\n");
            }
        }
    }

    const DllImage* dll_array = preloaded_count > 0 ? preloaded_dlls : nullptr;
    const PeLoadResult r = PeLoad(pe_bytes, pe_len, as, name, aslr_delta, dll_array, preloaded_count);
    if (!r.ok)
    {
        AddressSpaceRelease(as);
        return 0;
    }
    Process* proc = ProcessCreate(name, as, caps, root, r.entry_va, r.stack_va, tick_budget);
    if (proc == nullptr)
    {
        AddressSpaceRelease(as);
        return 0;
    }
    // PE loader now maps a multi-page stack; Ring3UserEntry's
    // default rsp = user_stack_va + PAGE - 8 would land at the
    // BOTTOM of that range. Override with a Windows-ABI rsp
    // near the top: the x64 Win64 ABI says at function entry
    // rsp is of form `16n + 8` and [rsp] holds the return
    // address with [rsp+8..rsp+0x28] being 32 bytes of caller-
    // reserved shadow space the callee is free to spill argN
    // into. MSVC's entry prolog does exactly that, so an rsp
    // of stack_top - 8 faults immediately because rsp+8 is
    // one byte above the mapped stack. Start at stack_top-0x48
    // (72 bytes = 64 slack + 8) so the whole prolog window fits
    // comfortably inside the top stack page. 0x48 mod 16 = 8,
    // satisfying the 16n+8 rule.
    proc->user_rsp_init = r.stack_top - 0x48;
    proc->user_gs_base = r.teb_va;
    // Transfer any catch-all IAT miss (slot_va -> name) entries
    // the loader queued during ResolveImports. This arms the
    // runtime miss-logger: on the first call to an unstubbed
    // import, SYS_WIN32_MISS_LOG can decode the IAT slot VA back
    // to the function name via this table.
    PeLoadDrainIatMisses(proc);
    // Per-process Win32 heap. Only initialised for PEs that
    // actually imported anything — a freestanding PE like
    // /bin/hello.exe doesn't call HeapAlloc and shouldn't burn
    // the 16 frames the heap region costs.
    if (r.imports_resolved)
    {
        if (!win32::Win32HeapInit(proc))
        {
            SerialWrite("[ring3] win32 heap init failed for \"");
            SerialWrite(name);
            SerialWrite("\"\n");
            AddressSpaceRelease(as);
            return 0;
        }
        // Stage-2 slice 6/9 — the DLLs were pre-loaded BEFORE
        // PeLoad so ResolveImports could consult their EATs. Now
        // that the Process exists, copy each DllImage into its
        // permanent `dll_images[]` table so
        // SYS_DLL_PROC_ADDRESS / ProcessResolveDllExportByBase
        // can reach them too. The pre-PeLoad slots are stack
        // locals about to go out of scope; the per-Process copies
        // are the long-lived record.
        for (u64 i = 0; i < preloaded_count; ++i)
        {
            if (!ProcessRegisterDllImage(proc, preloaded_dlls[i]))
            {
                SerialWrite("[ring3] DLL register failed for \"");
                SerialWrite(name);
                SerialWrite("\" (table full?)\n");
                break;
            }
        }
        if (preloaded_count > 0)
        {
            SerialWrite("[ring3] registered ");
            SerialWriteHex(preloaded_count);
            SerialWrite(" DLL(s) pid=");
            SerialWriteHex(proc->pid);
            SerialWrite("\n");
        }
    }
    SerialWrite("[ring3] pe spawn name=\"");
    SerialWrite(name);
    SerialWrite("\" pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" entry=");
    SerialWriteHex(r.entry_va);
    SerialWrite(" image_base=");
    SerialWriteHex(r.image_base);
    SerialWrite(" stack_top=");
    SerialWriteHex(r.stack_top);
    SerialWrite("\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, name, proc);
    return proc->pid;
}

bool SpawnOnDemand(const char* kind)
{
    if (kind == nullptr || kind[0] == '\0')
        return false;
    if (LocalStrEq(kind, "hello"))
    {
        SpawnRing3Task("ring3-cmd-hello", CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted,
                       kTickBudgetTrusted);
        return true;
    }
    if (LocalStrEq(kind, "sandbox"))
    {
        CapSet caps = CapSetEmpty();
        CapSetAdd(caps, kCapFsRead);
        SpawnRing3Task("ring3-cmd-sandbox", caps, fs::RamfsSandboxRoot(), mm::kFrameBudgetSandbox, kTickBudgetSandbox);
        return true;
    }
    if (LocalStrEq(kind, "jail"))
    {
        SpawnJailProbeTask();
        return true;
    }
    if (LocalStrEq(kind, "nx"))
    {
        SpawnNxProbeTask();
        return true;
    }
    if (LocalStrEq(kind, "hog"))
    {
        SpawnCpuHogProbe();
        return true;
    }
    if (LocalStrEq(kind, "hostile"))
    {
        SpawnHostileProbe();
        return true;
    }
    if (LocalStrEq(kind, "dropcaps"))
    {
        SpawnDropcapsProbe();
        return true;
    }
    if (LocalStrEq(kind, "priv"))
    {
        SpawnPrivProbeTask();
        return true;
    }
    if (LocalStrEq(kind, "badint"))
    {
        SpawnBadIntProbeTask();
        return true;
    }
    if (LocalStrEq(kind, "kread"))
    {
        SpawnKernelReadProbeTask();
        return true;
    }
    if (LocalStrEq(kind, "ptrfuzz"))
    {
        SpawnPtrFuzzProbeTask();
        return true;
    }
    if (LocalStrEq(kind, "writefuzz"))
    {
        SpawnWriteFuzzProbeTask();
        return true;
    }
    if (LocalStrEq(kind, "hellope"))
    {
        SpawnPeFile("ring3-hello-pe", fs::generated::kBinHelloPeBytes, fs::generated::kBinHelloPeBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        return true;
    }
    if (LocalStrEq(kind, "winhello"))
    {
        // First Win32 PE: imports ExitProcess, gets resolved
        // through the kernel-hosted stub page, exits with
        // code 42. "Exit rc=0x2a" in the serial log confirms
        // the full IAT resolution chain worked.
        SpawnPeFile("ring3-hello-winapi", fs::generated::kBinHelloWinapiBytes, fs::generated::kBinHelloWinapiBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        return true;
    }
    if (LocalStrEq(kind, "winkill"))
    {
        // Real-world PE that the v0 loader cannot execute.
        // SpawnPeFile's diagnostic pre-pass still fires
        // (PeReport logs imports/relocs/TLS), then the load is
        // rejected with a typed status code. The point is the
        // serial log, not a running process.
        SpawnPeFile("ring3-winkill", fs::generated::kBinWinKillBytes, fs::generated::kBinWinKillBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        return true;
    }
    if (LocalStrEq(kind, "threads"))
    {
        // thread_stress.exe — exercises CreateThread +
        // CreateEventW + SetEvent + WaitForSingleObject.
        // Expected exit: 0xABCDE on success.
        SpawnPeFile("ring3-thread-stress", fs::generated::kBinThreadStressBytes,
                    fs::generated::kBinThreadStressBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                    mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        return true;
    }
    return false;
}

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

    SpawnRing3Task("ring3-smoke-A", CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted,
                   kTickBudgetTrusted);
    SpawnRing3Task("ring3-smoke-B", CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted,
                   kTickBudgetTrusted);
    SpawnRing3Task("ring3-smoke-sandbox", sandbox_caps, fs::RamfsSandboxRoot(), mm::kFrameBudgetSandbox,
                   kTickBudgetSandbox);

    // Jail-probe task: writes to its own RX code page. Expected
    // outcome is the kernel's ring-3 trap handler terminating the
    // task via SchedExit and emitting [task-kill] on COM1. If the
    // kernel instead panics / halts here, the sandboxing contract
    // is broken: a user-mode fault must never bring down the OS.
    SpawnJailProbeTask();
    SpawnNxProbeTask();
    SpawnCpuHogProbe();
    // Hostile-syscall probe: retries a blocked SYS_WRITE forever.
    // After 100 cap denials, the sandbox-denial threshold kills
    // the task. Boot log shows `[sandbox] pid=N hit 100 denials`.
    SpawnHostileProbe();
    // Dropcaps demo: trusted task drops its caps mid-flight and
    // verifies subsequent SYS_WRITE is denied.
    SpawnDropcapsProbe();
    // Priv-instruction probe: `cli` from ring 3 → #GP → task-kill.
    // Proves CPL(3) > IOPL(0) enforcement is live — a sandboxed
    // process cannot globally mask interrupts.
    SpawnPrivProbeTask();
    // Bad-int probe: `int 0x81` → gate-not-present → task-kill.
    // Proves the trap dispatcher catches any ring-3 vector, not
    // just the architectural 0..31 it installs handlers for.
    SpawnBadIntProbeTask();
    // Kernel-read probe: ring 3 dereferences a higher-half kernel
    // VA → #PF (U/S mismatch) → task-kill. Proves the user-bit
    // firewall between ring 3 and the kernel image.
    SpawnKernelReadProbeTask();
    // Ptrfuzz probe: trusted task hands four wild user pointers
    // to SYS_WRITE in sequence. Proves `CopyFromUser` rejection
    // path is robust — kernel never touches a bad address. Final
    // control message confirms the task survived intact.
    SpawnPtrFuzzProbeTask();
    // Writefuzz probe: trusted task hands four wild DESTINATION
    // pointers to SYS_STAT + SYS_READ. Proves `CopyToUser`
    // rejection path is robust — no byte ever lands at a bad VA.
    SpawnWriteFuzzProbeTask();
    // Bp-probe: trusted task installs a HW execute breakpoint on
    // its own nop via SYS_BP_INSTALL, fires it once, removes via
    // SYS_BP_REMOVE. Proves per-task DR save/restore, the
    // kCapDebug gate, and the syscall surface.
    SpawnBpProbeTask();
    // First PE executable on the system. Freestanding, compiled
    // from userland/apps/hello_pe/hello.c by the host clang +
    // lld-link rule in kernel/CMakeLists.txt. Exercises the v0
    // PE loader: DOS + NT header parse, section map, entry
    // point dispatch. Expected output: "[hello-pe] Hello from a
    // PE executable!" then clean exit.
    SpawnPeFile("ring3-hello-pe", fs::generated::kBinHelloPeBytes, fs::generated::kBinHelloPeBytes_len, CapSetTrusted(),
                fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
    // First Win32 PE that gets RESOLVED (not just reported)
    // by the kernel. Imports kernel32.dll!ExitProcess, hits
    // the stub page, exits with code 42. See
    // .claude/knowledge/win32-subsystem-v0.md.
    SpawnPeFile("ring3-hello-winapi", fs::generated::kBinHelloWinapiBytes, fs::generated::kBinHelloWinapiBytes_len,
                CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
    // Thread-stress PE: CreateThread + CreateEventW + SetEvent +
    // WaitForSingleObject round-trip. Exercises the Win32 →
    // SYS_THREAD_CREATE path. Expected exit: 0xABCDE on success.
    SpawnPeFile("ring3-thread-stress", fs::generated::kBinThreadStressBytes, fs::generated::kBinThreadStressBytes_len,
                CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
    // Syscall-stress PE: batch-51 coverage — OutputDebugStringA,
    // ExitThread, GetProcessTimes/GetThreadTimes/GetSystemTimes,
    // GlobalMemoryStatusEx, WaitForMultipleObjects. Expected exit:
    // 0xCAFE on success.
    SpawnPeFile("ring3-syscall-stress", fs::generated::kBinSyscallStressBytes,
                fs::generated::kBinSyscallStressBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                mm::kFrameBudgetTrusted, kTickBudgetTrusted);
    // Stage-2 slice 6 end-to-end fixture. Imports
    // CustomAdd / CustomMul / CustomVersion from customdll.dll;
    // the kernel DLL loader maps the DLL into the process's AS
    // before PeLoad runs and ResolveImports patches each IAT
    // slot with the DLL's export VA directly. Expected exit:
    // 0x1234 on success (= CustomAdd(0x1000, 0x0234)), 0xBAD0
    // if any of the three DLL call results don't match.
    SpawnPeFile("ring3-customdll-test", fs::generated::kBinCustomDllTestBytes,
                fs::generated::kBinCustomDllTestBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                mm::kFrameBudgetTrusted, kTickBudgetTrusted);
    // Stage-2 slice 34 end-to-end fixture. Exercises the real
    // registry in advapi32.dll + real fopen/fread in ucrtbase.dll.
    SpawnPeFile("ring3-reg-fopen-test", fs::generated::kBinRegFopenTestBytes, fs::generated::kBinRegFopenTestBytes_len,
                CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
    // Real-world Windows PE diagnostic attempt. Expected to
    // reject (most imports unresolved) — the value is the
    // PeReport log line showing the full import / reloc / TLS
    // gap. See .claude/knowledge/pe-subsystem-v0.md.
    SpawnPeFile("ring3-winkill", fs::generated::kBinWinKillBytes, fs::generated::kBinWinKillBytes_len, CapSetTrusted(),
                fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
    Log(LogLevel::Info, "core/ring3",
        "ring3 smoke tasks queued (incl cpu-hog + hostile + dropcaps + priv + badint + kread + "
        "ptrfuzz + writefuzz + hellope + winkill-report + thread-stress + syscall-stress + "
        "customdll-test)");
}

} // namespace duetos::core
