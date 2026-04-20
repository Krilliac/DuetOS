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

// Small, deterministic PRNG seeded from the TSC at boot. Not
// cryptographic — the goal is "layouts differ across processes of
// a single boot"; unpredictability across reboots falls out of
// the TSC seed. splitmix64 per call is 2 arithmetic ops.
u64 Splitmix64(u64& state)
{
    state += 0x9E3779B97F4A7C15ULL;
    u64 z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

u64 g_aslr_state = 0;

void AslrInitIfNeeded()
{
    if (g_aslr_state != 0)
    {
        return;
    }
    u32 lo = 0, hi = 0;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    g_aslr_state = (static_cast<u64>(hi) << 32) | lo;
    if (g_aslr_state == 0)
    {
        g_aslr_state = 0xDEADBEEFCAFEBABEULL; // TSC unavailable? use a
                                              // fixed seed rather than
                                              // 0 (which would skip
                                              // randomisation entirely).
    }
}

// Pick a fresh 16 MiB-aligned base in [kAslrMinBase, kAslrMaxBase).
u64 AslrPickBase()
{
    AslrInitIfNeeded();
    const u64 range = (kAslrMaxBase - kAslrMinBase) / kAslrAlign;
    const u64 r = Splitmix64(g_aslr_state) % range;
    return kAslrMinBase + r * kAslrAlign;
}

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
    {0x0A, kPath1OffsetInCode, PatchBase::kCode},      // SYS_STAT #1: path1
    {0x0F, kStatOutOffsetInStack, PatchBase::kStack},  // SYS_STAT #1: statout
    {0x1B, kPath2OffsetInCode, PatchBase::kCode},      // SYS_STAT #2: path2
    {0x20, kStatOutOffsetInStack, PatchBase::kStack},  // SYS_STAT #2: statout
    {0x2C, kPath1OffsetInCode, PatchBase::kCode},      // SYS_READ: path1
    {0x31, kReadBufOffsetInStack, PatchBase::kStack},  // SYS_READ: readbuf
    {0x4A, kReadBufOffsetInStack, PatchBase::kStack},  // SYS_WRITE (dyn): readbuf
    {0x5B, kMsgOffsetInCode, PatchBase::kCode},        // SYS_WRITE (banner): msg
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

// Entry point for the user task. Runs in ring 0 on a fresh kernel
// stack with the task's own AS already loaded in CR3 (Schedule()
// flipped it on first switch-in). Reads the per-process ASLR
// layout from CurrentProcess() so every task enters ring 3 at
// its own code_va / stack_va.
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

    Process* proc = CurrentProcess();
    if (proc == nullptr)
    {
        Panic("core/ring3", "Ring3UserEntry without a Process");
    }
    const u64 code_va = proc->user_code_va;
    const u64 stack_top = proc->user_stack_va + mm::kPageSize;

    SerialWrite("[ring3] task pid=");
    SerialWriteHex(sched::CurrentTaskId());
    SerialWrite(" entering ring 3 rip=");
    SerialWriteHex(code_va);
    SerialWrite(" rsp=");
    SerialWriteHex(stack_top);
    SerialWrite("\n");

    arch::EnterUserMode(code_va, stack_top);
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

    Process* proc = ProcessCreate(name, as, caps, root, code_va, stack_va);
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

    Process* proc = ProcessCreate("ring3-nx-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va);
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
    using namespace customos::mm;

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
    Process* proc = ProcessCreate("ring3-jail-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va);
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
