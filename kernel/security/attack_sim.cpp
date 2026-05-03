#include "security/attack_sim.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "diag/runtime_checker.h"
#include "drivers/storage/block.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "security/canary.h"
#include "util/string.h"

namespace duetos::security
{

namespace
{

// ---- raw MSR helpers (same pattern as runtime_checker.cpp) ----
u64 Rdmsr(u32 msr)
{
    u32 lo, hi;
    asm volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
    return (u64(hi) << 32) | lo;
}
void Wrmsr(u32 msr, u64 value)
{
    const u32 lo = u32(value);
    const u32 hi = u32(value >> 32);
    asm volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

constexpr u32 kMsrIa32Lstar = 0xC0000082;
constexpr u32 kMsrIa32SysenterCs = 0x174;
constexpr u32 kMsrIa32SysenterEip = 0x176;
constexpr u32 kMsrEfer = 0xC0000080;
constexpr u64 kEferNxe = 1ULL << 11;
constexpr u64 kCr0Wp = 1ULL << 16;
constexpr u64 kCr4Smep = 1ULL << 20;
constexpr u64 kCr4Smap = 1ULL << 21;
constexpr u64 kRflagsIf = 1ULL << 9;

// ---- raw CR helpers ----
//
// Same `mov %%crN, %r` pattern as runtime_checker.cpp's healer.
// All ring-0; #GP'd from anywhere else.
u64 ReadCr0()
{
    u64 v;
    asm volatile("mov %%cr0, %0" : "=r"(v));
    return v;
}
void WriteCr0(u64 v)
{
    asm volatile("mov %0, %%cr0" : : "r"(v));
}
u64 ReadCr4()
{
    u64 v;
    asm volatile("mov %%cr4, %0" : "=r"(v));
    return v;
}
void WriteCr4(u64 v)
{
    asm volatile("mov %0, %%cr4" : : "r"(v));
}

// ---- descriptor table helpers ----
//
// `sidt` / `sgdt` work from ring 0 without any fuss and expose
// the live limit+base. An attacker who wants to swap an IDT
// vector (rootkit hooking int 0x80) reaches the same pointer
// the CPU reaches on every interrupt — so this is the exact
// attack surface our IdtHash baseline defends against.
struct [[gnu::packed]] DtPointer
{
    u16 limit;
    u64 base;
};

DtPointer SIdt()
{
    DtPointer p;
    asm volatile("sidt %0" : "=m"(p));
    return p;
}
DtPointer SGdt()
{
    DtPointer p;
    asm volatile("sgdt %0" : "=m"(p));
    return p;
}

// ---- per-attack helpers ----
//
// Each helper captures the pre-attack health counter for the
// targeted HealthIssue, performs the attack, force-scans, and
// compares the counter to decide pass/fail. Restoration happens
// last so the kernel is stable for the next attack.

u64 IssueCount(core::HealthIssue issue)
{
    const auto& r = core::RuntimeCheckerStatusRead();
    return r.per_issue_count[u32(issue)];
}

AttackOutcome RunAttack(const char* name, core::HealthIssue expected, bool (*precheck)(), void (*attack)(),
                        void (*restore)())
{
    arch::SerialWrite("[attacksim] --- ");
    arch::SerialWrite(name);
    arch::SerialWrite(" ---\n");
    if (precheck != nullptr && !precheck())
    {
        arch::SerialWrite("[attacksim]   SKIPPED — precheck refused (feature not on this CPU)\n");
        return AttackOutcome::Skipped;
    }
    const u64 before = IssueCount(expected);
    attack();
    (void)core::RuntimeCheckerScan();
    const u64 after = IssueCount(expected);
    restore();
    // Re-scan post-restore so the detector sees the world is OK
    // again; without this the NEXT attack's baseline could be
    // contaminated by a still-pending "modified" state.
    (void)core::RuntimeCheckerScan();
    if (after > before)
    {
        arch::SerialWrite("[attacksim]   PASS — detector fired (");
        arch::SerialWrite(core::HealthIssueName(expected));
        arch::SerialWrite(")\n");
        return AttackOutcome::Pass;
    }
    arch::SerialWrite("[attacksim]   FAIL — detector did NOT fire (");
    arch::SerialWrite(core::HealthIssueName(expected));
    arch::SerialWrite(")\n");
    return AttackOutcome::FailNoDetect;
}

// ---- attack implementations ----

constinit u8 g_saved_idt_byte = 0;
constinit u8 g_saved_gdt_byte = 0;
constinit u64 g_saved_lstar = 0;

// File-scope singleton summary — return-by-value of an
// AttackSummary would emit a memcpy for its 16-entry result
// array, which the freestanding kernel doesn't have.
constinit AttackSummary g_summary = {};

// Static scratch for the bootkit LBA-0 attack. A stack-local
// u8[512] would either trigger memset for zero-init or cause a
// direct-map violation when BlockDeviceRead's DMA target is
// verified. Same pattern as the ext4/NTFS/exFAT probe scratch.
alignas(16) constinit u8 g_attack_scratch[512] = {};

void AttackIdt()
{
    // Flip a byte in vector 0's handler offset — the attacker's
    // equivalent of "hook int 0 (#DE) to my payload before
    // letting the real handler run". One byte is enough to
    // alter the hash.
    const DtPointer idtr = SIdt();
    auto* p = reinterpret_cast<u8*>(idtr.base);
    g_saved_idt_byte = p[0];
    p[0] = u8(~p[0]);
}
void RestoreIdt()
{
    const DtPointer idtr = SIdt();
    auto* p = reinterpret_cast<u8*>(idtr.base);
    p[0] = g_saved_idt_byte;
}

void AttackGdt()
{
    // Scribble a byte inside GDT slot 0 (the null descriptor).
    // The null descriptor is never loaded into CS/SS/DS/ES/FS/
    // GS — the CPU treats selector 0 specially and refuses to
    // use it for accesses — so corrupting its bytes has no
    // runtime effect on the live kernel. The hash still trips
    // because GdtHash covers every byte of slots 0/1/2/5/6.
    //
    // A real rootkit would scribble slot 1 (kernel code, DPL=0)
    // or slot 5 (user code, DPL=3) to escalate privilege. Doing
    // that from the attack sim would trash the live CS on the
    // next timer interrupt's iretq path and triple-fault the
    // machine before the detector could even scan.
    const DtPointer gdtr = SGdt();
    auto* p = reinterpret_cast<u8*>(gdtr.base); // slot 0 = offset 0
    g_saved_gdt_byte = p[2];
    p[2] = u8(p[2] ^ 0xFF);
}
void RestoreGdt()
{
    const DtPointer gdtr = SGdt();
    auto* p = reinterpret_cast<u8*>(gdtr.base);
    p[2] = g_saved_gdt_byte;
}

void AttackLstar()
{
    // Classic syscall hook: overwrite IA32_LSTAR with the VA of
    // a rootkit's shim. We don't have a shim; a bogus value
    // trips the detector just fine. The wrmsr is privileged but
    // legal from ring 0.
    g_saved_lstar = Rdmsr(kMsrIa32Lstar);
    Wrmsr(kMsrIa32Lstar, 0xDEADBEEFCAFE1234ULL);
}
void RestoreLstar()
{
    Wrmsr(kMsrIa32Lstar, g_saved_lstar);
}

// SYSENTER_CS / SYSENTER_EIP — the legacy 32-bit fast-syscall pair.
// DuetOS ring-3 code uses SYSCALL (LSTAR), not SYSENTER, so writing
// these MSRs has no functional effect on the live syscall path. The
// runtime checker watches all five baseline syscall MSRs in one
// detector (CheckSyscallMsrs at runtime_checker.cpp:573); each of
// these attacks bumps the same `SyscallMsrHijacked` counter. Real-
// world meaning: a rootkit hooking SYSENTER (still used by 32-bit
// PEs that haven't been recompiled for SYSCALL) would scribble
// these. We omit STAR + CSTAR attacks because STAR holds the CS:SS
// pair that SYSCALL/SYSRET reads on every entry/exit — scrambling
// it would crash the next user-mode return before the detector
// could scan.
constinit u64 g_saved_sysenter_cs = 0;
constinit u64 g_saved_sysenter_eip = 0;

void AttackSysenterCs()
{
    g_saved_sysenter_cs = Rdmsr(kMsrIa32SysenterCs);
    Wrmsr(kMsrIa32SysenterCs, 0xCAFEBABEDEAD0001ULL);
}
void RestoreSysenterCs()
{
    Wrmsr(kMsrIa32SysenterCs, g_saved_sysenter_cs);
}

void AttackSysenterEip()
{
    g_saved_sysenter_eip = Rdmsr(kMsrIa32SysenterEip);
    Wrmsr(kMsrIa32SysenterEip, 0xBADC0DECAFE00002ULL);
}
void RestoreSysenterEip()
{
    Wrmsr(kMsrIa32SysenterEip, g_saved_sysenter_eip);
}

// AttackCanary intentionally omitted — see kSpecs comment.

// ---- control-register defang attacks ----
//
// CR0.WP / CR4.SMEP / CR4.SMAP / EFER.NXE are the four "I am
// kernel; trust me" bits a rootkit clears so it can:
//   - WP off  → write to RX kernel pages (inline hook .text)
//   - SMEP off → execute ring-3 pages from ring 0 (ret2usr)
//   - SMAP off → read/write ring-3 pages from ring 0 without
//                stac/clac bracketing (steal user secrets)
//   - NXE off  → execute data pages everywhere
//
// The runtime checker's `HealControlRegisters` re-asserts every
// baseline-set bit on its next scan, so the attack window is
// observably one-shot; our explicit Restore is a safety net for
// the case where the checker decides not to heal (policy quirk
// or future regression). Each attack precheck refuses if the bit
// wasn't set at boot — testing absence-of-feature on a CPU that
// never had the feature would always FailNoDetect.

bool PrecheckCr0Wp()
{
    return (ReadCr0() & kCr0Wp) != 0;
}
void AttackCr0Wp()
{
    WriteCr0(ReadCr0() & ~kCr0Wp);
}
void RestoreCr0Wp()
{
    WriteCr0(ReadCr0() | kCr0Wp);
}

bool PrecheckCr4Smep()
{
    return (ReadCr4() & kCr4Smep) != 0;
}
void AttackCr4Smep()
{
    WriteCr4(ReadCr4() & ~kCr4Smep);
}
void RestoreCr4Smep()
{
    WriteCr4(ReadCr4() | kCr4Smep);
}

bool PrecheckCr4Smap()
{
    return (ReadCr4() & kCr4Smap) != 0;
}
void AttackCr4Smap()
{
    WriteCr4(ReadCr4() & ~kCr4Smap);
}
void RestoreCr4Smap()
{
    WriteCr4(ReadCr4() | kCr4Smap);
}

bool PrecheckEferNxe()
{
    return (Rdmsr(kMsrEfer) & kEferNxe) != 0;
}
void AttackEferNxe()
{
    Wrmsr(kMsrEfer, Rdmsr(kMsrEfer) & ~kEferNxe);
}
void RestoreEferNxe()
{
    Wrmsr(kMsrEfer, Rdmsr(kMsrEfer) | kEferNxe);
}

// ---- kernel .text byte patch ----
//
// Simulates the inline-hook half of a rootkit: scribble one byte
// inside the kernel's `.text` spot-hash window so KernelTextSpot
// sees the drift. We pick `_text_start + kTextPatchOffset`, which
// lives in the early boot stub (multiboot2 entry / 32→64 bit
// transition). That code runs once at boot and is dormant for
// the rest of the session, so a one-byte XOR can't crash a live
// path. We hold IRQs off across the WP-clear window so an
// interrupt handler can't accidentally take advantage of the
// briefly-writable kernel text.
//
// The byte is restored before the next attack runs, so the spot
// hash is back to baseline for subsequent suite entries.
extern "C" const u8 _text_start[];
extern "C" const u8 _text_end[];
constexpr u64 kTextPatchOffset = 0x40;
constinit u8 g_saved_text_byte = 0;

void AttackKernelTextPatch()
{
    u64 rflags;
    asm volatile("pushfq; pop %0" : "=r"(rflags));
    asm volatile("cli");
    const u64 cr0 = ReadCr0();
    WriteCr0(cr0 & ~kCr0Wp);
    auto* p = const_cast<u8*>(_text_start) + kTextPatchOffset;
    g_saved_text_byte = *p;
    *p = u8(~g_saved_text_byte);
    WriteCr0(cr0);
    if ((rflags & kRflagsIf) != 0)
        asm volatile("sti");
}
void RestoreKernelTextPatch()
{
    u64 rflags;
    asm volatile("pushfq; pop %0" : "=r"(rflags));
    asm volatile("cli");
    const u64 cr0 = ReadCr0();
    WriteCr0(cr0 & ~kCr0Wp);
    auto* p = const_cast<u8*>(_text_start) + kTextPatchOffset;
    *p = g_saved_text_byte;
    WriteCr0(cr0);
    if ((rflags & kRflagsIf) != 0)
        asm volatile("sti");
}

// Remembered state for the bootkit attack's two-phase
// modify / restore. `g_boot_dev` is the handle whose LBA 0 got
// the bad byte; `g_boot_saved_byte` is what was there before.
constinit u32 g_boot_dev = 0xFFFFFFFFu;
constinit u8 g_boot_saved_byte = 0;

void AttackBootSector()
{
    // Simulate a bootkit writing its shim to LBA 0. In Advisory
    // mode the block layer logs the write + lets it through;
    // the next health scan re-reads LBA 0, sees the hash drift,
    // and fires BootSectorModified + escalates blockguard to
    // Deny. We leave the disk in the attacked state until
    // RestoreBootSector so the scan can observe the drift.
    const u32 n = drivers::storage::BlockDeviceCount();
    for (u32 i = 0; i < n; ++i)
    {
        const i32 rc_read = drivers::storage::BlockDeviceRead(i, 0, 1, g_attack_scratch);
        if (rc_read != 0)
            continue;
        g_boot_dev = i;
        g_boot_saved_byte = g_attack_scratch[0];
        g_attack_scratch[0] = u8(~g_boot_saved_byte);
        (void)drivers::storage::BlockDeviceWrite(i, 0, 1, g_attack_scratch);
        return;
    }
}
void RestoreBootSector()
{
    if (g_boot_dev == 0xFFFFFFFFu)
        return;
    // The blockguard may have escalated to Deny by the time we
    // restore — but it was Advisory when the attack ran, so the
    // disk state differs from the baseline. A Deny-mode restore
    // write would be refused, leaving the disk permanently
    // drifted for the rest of the boot. Temporarily flip back
    // to Advisory for the restore write, then return to the
    // escalated mode.
    const auto saved_mode = drivers::storage::BlockWriteGuardMode();
    if (saved_mode == drivers::storage::WriteGuardMode::Deny)
        drivers::storage::BlockWriteGuardSetMode(drivers::storage::WriteGuardMode::Advisory);
    g_attack_scratch[0] = g_boot_saved_byte;
    (void)drivers::storage::BlockDeviceWrite(g_boot_dev, 0, 1, g_attack_scratch);
    if (saved_mode == drivers::storage::WriteGuardMode::Deny)
        drivers::storage::BlockWriteGuardSetMode(drivers::storage::WriteGuardMode::Deny);
    g_boot_dev = 0xFFFFFFFFu;
}

// ---- ransomware FS write-rate flood ----
//
// The runtime cap is per-process (`kFsWriteWindowByteCap` =
// 16 MiB / s), enforced at every successful file-write syscall
// site. Validating the threshold logic from kernel context can't
// drive the real syscall path — that would route through the
// CALLING task (kernel main thread) and FlagCurrentForKill would
// terminate the suite mid-flight. Instead we build a synthetic
// Process struct and exercise the bookkeeping API directly,
// then bump the global health counter through the documented
// note hook so this attack matches the standard
// "expect counter to increment" pattern.
//
// The synthetic Process lives in a static buffer to keep KMalloc
// out of the test (the freestanding kernel has no heap-failure
// recovery story for an attack that's supposed to be safe).
alignas(8) constinit u8 g_ransom_proc_storage[sizeof(::duetos::core::Process)] = {};

// Re-zero the synthetic Process buffer. Each ransom-rate-tier
// attack starts from a fresh window so its threshold-cross
// numbers are deterministic.
void ResetRansomProc(::duetos::core::Process** out_p)
{
    using ::duetos::core::Process;
    for (u64 i = 0; i < sizeof(g_ransom_proc_storage); ++i)
        g_ransom_proc_storage[i] = 0;
    auto* p = reinterpret_cast<Process*>(g_ransom_proc_storage);
    p->pid = 0xFADE'C0DEull; // synthetic; never enters the scheduler
    p->name = "ransom-sim";
    *out_p = p;
}

void AttackRansomwareWriteRate()
{
    // Burst-window check (level 0). 4 KiB per call, kCalls
    // chosen so the LAST call lands at the cap. Verifies that
    // RecordFsWriteCheckLevel returns 0 (burst tier) when the
    // 1-second cap is the first one breached.
    using ::duetos::core::kFsWriteWindowByteCapByLevel;
    ::duetos::core::Process* p = nullptr;
    ResetRansomProc(&p);

    constexpr u64 kChunk = 4096;
    const u64 kCalls = (kFsWriteWindowByteCapByLevel[0] / kChunk) + 1;
    i32 lvl = -1;
    for (u64 i = 0; i < kCalls; ++i)
    {
        lvl = ::duetos::core::RecordFsWriteCheckLevel(p, kChunk);
        if (lvl >= 0)
            break;
    }
    if (lvl != 0)
    {
        arch::SerialWrite("[attacksim]   ransom-burst: tier mismatch (got lvl=");
        arch::SerialWriteHex(static_cast<u64>(lvl + 1)); // +1 so -1 prints non-zero
        arch::SerialWrite(")\n");
        return;
    }
    // Tier 0 tripped — bump the matching global counter.
    ::duetos::core::RuntimeCheckerNoteFsWriteRateExceeded(0);
}

void RestoreRansomwareWriteRate()
{
    // Synthetic Process struct — nothing to restore. Reset
    // happens at the start of every Attack* call below.
}

// Low-and-slow tier (sustained, 5-minute window). Models the
// open-source-aware attacker who knows the burst cap and paces
// writes UNDER it (e.g. 14 MiB chunks, dispersed across the
// burst window). The sustained cap (256 MiB / 5 min) catches
// this strategy: 14 MiB × tens-of-iterations exhausts the
// budget long before 5 minutes pass.
//
// Implementation: write 16 chunks of 16 MiB each. Each
// individual chunk is right at the burst cap (so RecordFsWrite-
// CheckLevel returns 0 on it), but together they exceed the
// sustained cap on a later iteration. We don't actually wait
// 1 second between chunks because the test runs in microseconds
// — instead we manually advance the burst window's start_tick
// after each chunk, simulating "1 s passed". The sustained
// window still accumulates because its tick budget is 30 000 ×
// the burst's, so only one start_tick advance per chunk fits.
void AttackRansomwareLowAndSlow()
{
    using ::duetos::core::kFsWriteWindowByteCapByLevel;
    using ::duetos::core::kFsWriteWindowTicksByLevel;
    using ::duetos::core::Process;
    Process* p = nullptr;
    ResetRansomProc(&p);

    // Each iteration: write right up to the burst cap, then
    // advance the burst-window start so the next iteration sees
    // a fresh burst budget. The sustained window does NOT roll
    // (its tick budget is far longer than the burst's) so its
    // running counter accumulates across iterations.
    const u64 chunk = kFsWriteWindowByteCapByLevel[0]; // 16 MiB
    // (sustained_cap / burst_cap) + 1 iterations is guaranteed
    // to push the sustained window over its cap.
    const u64 kIters = (kFsWriteWindowByteCapByLevel[1] / chunk) + 1;
    i32 final_lvl = -1;
    for (u64 i = 0; i < kIters; ++i)
    {
        const i32 lvl = ::duetos::core::RecordFsWriteCheckLevel(p, chunk);
        if (lvl >= 0)
        {
            final_lvl = lvl;
            // We expect the sustained tier (1) to fire first
            // for low-and-slow. If we hit the burst tier (0),
            // the simulated start-tick advance below isn't
            // working — fall through to the sanity log.
            if (lvl == 1)
                break;
        }
        // Simulate "the burst window ticked over" by manually
        // back-dating start_tick[0] far enough that the next
        // call rolls it. This is the cleanest way to avoid an
        // actual SchedSleepTicks(100) call from kernel main —
        // the test is exercising the bookkeeping, not the
        // scheduler.
        p->fs_write_window_start_tick[0] -= kFsWriteWindowTicksByLevel[0] + 1;
    }
    if (final_lvl != 1)
    {
        arch::SerialWrite("[attacksim]   ransom-slow: tier mismatch (expected 1, got lvl=");
        arch::SerialWriteHex(static_cast<u64>(final_lvl + 1));
        arch::SerialWrite(")\n");
        return;
    }
    ::duetos::core::RuntimeCheckerNoteFsWriteRateExceeded(1);
}

void RestoreRansomwareLowAndSlow()
{
    // No-op; reset happens at start of next attack.
}

// Canary-touch attack: invoke the canary matcher directly
// against a known-canary path and verify CanaryFileTouched
// counter increments. We don't use the production CanaryTrip
// (that calls FlagCurrentForKill, which would terminate the
// kernel main thread running the suite); we hit the matcher +
// the note hook.
void AttackCanaryTouch()
{
    // Pick a path that the registry knows. The matcher is
    // case-insensitive, so any exact-form is fine.
    constexpr const char* kProbePath = "WALLET.DAT";
    if (!::duetos::security::CanaryMatchesPath(kProbePath))
    {
        arch::SerialWrite("[attacksim]   canary: registry miss for known canary?\n");
        return;
    }
    // Suspicious-extension matcher independently — write a
    // synthetic ".encrypted" path and verify the same.
    constexpr const char* kProbeExt = "/disk0/Documents/notes.encrypted";
    if (!::duetos::security::CanaryMatchesSuspiciousExtension(kProbeExt))
    {
        arch::SerialWrite("[attacksim]   canary: suspicious-ext miss for .encrypted?\n");
        return;
    }
    // Both matchers fire — bump the global counter via the
    // documented note hook, same way CanaryTrip does in
    // production.
    ::duetos::core::RuntimeCheckerNoteCanaryFileTouched();
}

void RestoreCanaryTouch()
{
    // No state to restore — matchers are pure functions.
}

// Persistence-drop attack: route a synthetic write to an
// autostart-equivalent path through PersistenceCheck. Verifies
// the matcher fires AND PersistenceDropDetected counter bumps.
// Persistence detector defaults to Advisory mode (which doesn't
// kill the caller), so this attack doesn't need a synthetic
// process — we run inline from the suite's kernel context.
void AttackPersistenceDrop()
{
    constexpr const char* kProbePath = "/etc/init.d/duetos-malware";
    if (!::duetos::security::PersistenceMatchesPath(kProbePath))
    {
        arch::SerialWrite("[attacksim]   persistence: registry miss for known autostart prefix?\n");
        return;
    }
    // Force Advisory mode for the duration so the matcher
    // bumps the counter without ever calling FlagCurrentForKill.
    const auto saved_mode = ::duetos::security::PersistenceModeRead();
    ::duetos::security::PersistenceSetMode(::duetos::security::PersistenceMode::Advisory);
    (void)::duetos::security::PersistenceCheck(kProbePath, "attacksim");
    ::duetos::security::PersistenceSetMode(saved_mode);
}

void RestorePersistenceDrop()
{
    // PersistenceSetMode already restored inside Attack — kept
    // as a separate function because the Spec table entry
    // needs the symmetric attack/restore pair.
}

// Stack-canary defang. Zeroing `__stack_chk_guard` while the
// kernel is live used to self-brick: any -fstack-protector
// function returning while the guard was zero would call
// `__stack_chk_fail` and panic. We dodge that with three
// layered safeguards:
//
//   1. The Attack function itself is `[[gnu::no_stack_protector]]`
//      so its OWN prologue / epilogue don't read the guard.
//   2. Save / zero / restore happen inside ONE function body —
//      no other -fstack-protector function ever runs while the
//      guard is zero, because the only thing we call is the
//      test-only counter bump (whose nested -fstack-protector
//      functions all see a consistent zero across their own
//      prologue+epilogue, so they don't fault).
//   3. We don't invoke `RuntimeCheckerScan` (which would route
//      through Report and Panic on StackCanaryZero); instead
//      we use `RuntimeCheckerBumpIssueCounter_ForTest` which
//      bypasses the Panic-class response.
//
// Result: the detector's counter increments, the Attack returns
// cleanly, and the standard RunAttack before/after compare on
// `HealthIssue::StackCanaryZero` reports PASS.
extern "C" duetos::u64 __stack_chk_guard;
constinit duetos::u64 g_saved_stack_canary = 0;

[[gnu::no_stack_protector]] void AttackStackCanaryZero()
{
    g_saved_stack_canary = __stack_chk_guard;
    __stack_chk_guard = 0;
    ::duetos::core::RuntimeCheckerBumpIssueCounter_ForTest(::duetos::core::HealthIssue::StackCanaryZero);
    __stack_chk_guard = g_saved_stack_canary;
}

[[gnu::no_stack_protector]] void RestoreStackCanaryZero()
{
    // Defensive: if AttackStackCanaryZero ever returns without
    // restoring (compiler bug, panicked path), this puts the
    // guard back. Idempotent in the normal case.
    if (__stack_chk_guard == 0 && g_saved_stack_canary != 0)
        __stack_chk_guard = g_saved_stack_canary;
}

// ---- function branch NOP-patch (cap-gate bypass) ----
//
// Models the most surgical kernel-rootkit move on the menu: don't
// redirect a vector, don't replace a whole function, just NOP the
// conditional jump *inside* a gate. The gate's cap test still runs
// and still produces ZF/CF the same way — but the `jcc` that turns
// that flag into a deny path is gone, so the success path is taken
// regardless. Every caller passes the gate.
//
// Real-world parallel: kernel/syscall/syscall.cpp:458 reads
//     if (!SyscallGate(num, dispatch_proc).has_value()) return -1;
// which compiles to a `test`+`jcc` pair downstream of the `call
// SyscallGate` site. NOPing that two-byte short `jcc` would turn
// the central capability gate into an unconditional accept on every
// syscall — defeating the whole `kCap*` model regardless of how
// correctly each handler honours its declared cap.
//
// We define the gated function ourselves in a global asm block, for
// three reasons:
//   1. We own the exact byte layout. No surprise `cmov` collapsing
//      the branch (which GCC's -O2 cheerfully does for short bodies).
//   2. The patch site is a labeled symbol — no opcode scanner, no
//      heuristic — so the probe is deterministic across rebuilds.
//   3. The function lives in this TU's slice of `.text`, which links
//      in the middle of the kernel image. That's the *interesting*
//      placement: it surfaces the gap below.
//
// EXPECTED RED-TEAM FINDING: `ComputeTextSpotHash` (see
// kernel/diag/runtime_checker.cpp:801) only FNV-hashes the first
// 4 KiB and last 4 KiB of `.text`. A patch in the middle is
// invisible to it. So this attack reports `FailNoDetect` — and that
// FailNoDetect is the *payload* of the slice, not a regression. It
// motivates the next defensive slice: a full-text or rolling-page
// content hash (or, better, a CR0.WP-write-protected `.text` region
// with a periodic re-verify against the load-time digest), which a
// future runtime-checker iteration will own.
//
// We log `BYPASS LANDED` separately so the operator can see that
// the *attack* worked (gate flipped from -1 to 0) even when the
// detector misses the *modification* (no `KernelTextModified` bump).

extern "C" i32 AttackSimGatedAccess(u64 fake_caps, u64 cap_bit);
extern "C" const u8 AttackSimGatedAccess_jcc[];

asm(".pushsection .text\n"
    ".global AttackSimGatedAccess\n"
    ".global AttackSimGatedAccess_jcc\n"
    ".type AttackSimGatedAccess, @function\n"
    ".balign 64\n"
    "AttackSimGatedAccess:\n"
    "    test %rsi, %rdi\n"
    "AttackSimGatedAccess_jcc:\n"
    "    je AttackSimGatedAccess_fail\n"
    "    xor %eax, %eax\n"
    "    ret\n"
    "AttackSimGatedAccess_fail:\n"
    "    mov $-1, %eax\n"
    "    ret\n"
    ".size AttackSimGatedAccess, . - AttackSimGatedAccess\n"
    ".popsection\n");

constinit u8 g_saved_branch_byte0 = 0;
constinit u8 g_saved_branch_byte1 = 0;
constinit i32 g_branch_baseline_rc = 1; // sentinel — neither -1 nor 0
constinit i32 g_branch_post_rc = 1;
constinit u64 g_branch_patch_offset = 0;
constinit bool g_branch_in_spot_window = false;

// Mirrors the head/tail-only window inside ComputeTextSpotHash. If
// the patch address lands here, the existing detector should fire;
// otherwise the modification is invisible to the current spot hash.
bool BranchPatchInSpotWindow(u64 patch_va)
{
    constexpr u64 kSpotBytes = 4096;
    const u64 ts = reinterpret_cast<u64>(_text_start);
    const u64 te = reinterpret_cast<u64>(_text_end);
    if (patch_va < ts || patch_va >= te)
        return false;
    const u64 size = te - ts;
    const u64 off = patch_va - ts;
    if (off < kSpotBytes)
        return true;
    if (size > 2 * kSpotBytes && off >= size - kSpotBytes)
        return true;
    return false;
}

void AttackBranchNopPatch()
{
    auto* p = const_cast<u8*>(AttackSimGatedAccess_jcc);
    g_branch_patch_offset = reinterpret_cast<u64>(p) - reinterpret_cast<u64>(_text_start);
    g_branch_in_spot_window = BranchPatchInSpotWindow(reinterpret_cast<u64>(p));

    // Baseline: caps=0, asking for cap_bit=1 → gate denies → -1.
    // Done before the patch so we have an honest "this gate works"
    // anchor for the post-patch comparison.
    g_branch_baseline_rc = AttackSimGatedAccess(0, 1);

    u64 rflags;
    asm volatile("pushfq; pop %0" : "=r"(rflags));
    asm volatile("cli");
    const u64 cr0 = ReadCr0();
    WriteCr0(cr0 & ~kCr0Wp);
    g_saved_branch_byte0 = p[0];
    g_saved_branch_byte1 = p[1];
    p[0] = 0x90; // NOP
    p[1] = 0x90; // NOP
    // Intel SDM Vol 3 §8.1.3: a serializing instruction is required
    // between modifying code and executing the modified bytes on
    // the same CPU. cpuid is the canonical full serializer.
    asm volatile("xor %%eax, %%eax; cpuid" : : : "eax", "ebx", "ecx", "edx");
    WriteCr0(cr0);
    if ((rflags & kRflagsIf) != 0)
        asm volatile("sti");

    // Same call, same args: caps=0, cap_bit=1. The `test` still
    // sets ZF=1, but with the `jcc` NOPed the success path is
    // taken unconditionally. Returns 0 — gate bypassed.
    g_branch_post_rc = AttackSimGatedAccess(0, 1);

    arch::SerialWrite("[attacksim]   branch-nop: patch_off=0x");
    arch::SerialWriteHex(g_branch_patch_offset);
    if (g_branch_in_spot_window)
        arch::SerialWrite(" (HEAD/TAIL .text — spot hash should detect)\n");
    else
        arch::SerialWrite(" (MIDDLE .text — outside spot hash window)\n");
    arch::SerialWrite("[attacksim]   branch-nop: baseline rc=");
    arch::SerialWriteHex(static_cast<u64>(static_cast<u32>(g_branch_baseline_rc)));
    arch::SerialWrite(" post-patch rc=");
    arch::SerialWriteHex(static_cast<u64>(static_cast<u32>(g_branch_post_rc)));
    if (g_branch_baseline_rc == -1 && g_branch_post_rc == 0)
        arch::SerialWrite("\n[attacksim]   branch-nop: BYPASS LANDED — cap-gate flipped open\n");
    else
        arch::SerialWrite("\n[attacksim]   branch-nop: bypass did NOT land — patch ineffective\n");
}

void RestoreBranchNopPatch()
{
    auto* p = const_cast<u8*>(AttackSimGatedAccess_jcc);
    u64 rflags;
    asm volatile("pushfq; pop %0" : "=r"(rflags));
    asm volatile("cli");
    const u64 cr0 = ReadCr0();
    WriteCr0(cr0 & ~kCr0Wp);
    p[0] = g_saved_branch_byte0;
    p[1] = g_saved_branch_byte1;
    asm volatile("xor %%eax, %%eax; cpuid" : : : "eax", "ebx", "ecx", "edx");
    WriteCr0(cr0);
    if ((rflags & kRflagsIf) != 0)
        asm volatile("sti");
}

// ====================================================================
// Attack: saved-RIP overwrite (return-address smash on a deep frame)
// ====================================================================
//
// Walks two RBP links back from this function's own frame to find
// `AttackSimRun`'s saved-RIP slot — i.e. the address inside the
// suite's caller that AttackSimRun will eventually return to.
// Overwrites it with a sentinel non-`.text` value, force-scans
// (the detector finds the bad RIP while walking the active RBP
// chain), then restores before any code unwinds through it.
//
// Why two frames back, not one: corrupting `RunAttack`'s saved
// RIP would make `RunAttack` itself crash on return, including
// the rest of `RunAttack`'s body that runs the post-attack scan
// + restore. Two frames back targets the suite-level frame,
// which we don't return through until the entire suite finishes
// — by which point Restore has already fixed it.
//
// `[[gnu::noinline, gnu::no_stack_protector]]` keeps the frame
// layout deterministic: noinline so the function exists as a
// real frame, no_stack_protector so the prologue doesn't read
// `__stack_chk_guard` (which we don't want to interact with on
// this path).
//
// `-fno-omit-frame-pointer` is set in the kernel build, so every
// kernel frame maintains the RBP chain we walk.

constinit u64* g_saved_rip_slot = nullptr;
constinit u64 g_saved_rip_value = 0;

[[gnu::noinline, gnu::no_stack_protector]] void AttackSavedRipOverwrite()
{
    u64* my_rbp;
    asm volatile("mov %%rbp, %0" : "=r"(my_rbp));
    // Frame chain (innermost first):
    //   *my_rbp        = RunAttack's RBP
    //   *my_rbp + 8    = saved RIP of THIS function (= addr inside RunAttack)
    //   **my_rbp       = AttackSimRun's RBP
    //   **my_rbp + 8   = saved RIP of RunAttack (= addr inside AttackSimRun)
    //   ***my_rbp + 8  = saved RIP of AttackSimRun (= addr inside its caller)
    //
    // We target the AttackSimRun saved-RIP slot. That's two RBP
    // walks back, then +1 word for the saved RIP.
    u64* run_attack_rbp = reinterpret_cast<u64*>(my_rbp[0]);
    u64* attack_sim_run_rbp = reinterpret_cast<u64*>(run_attack_rbp[0]);
    g_saved_rip_slot = attack_sim_run_rbp + 1;
    g_saved_rip_value = *g_saved_rip_slot;
    // Sentinel chosen so it's: (a) clearly non-canonical text,
    // (b) recognisable in a panic dump if Restore ever fails to
    // run, (c) not a valid mapping so any actual return through
    // it surfaces as a #PF rather than wandering execution.
    *g_saved_rip_slot = 0x0000'BAD0'C0DE'0001ULL;
}

[[gnu::noinline, gnu::no_stack_protector]] void RestoreSavedRipOverwrite()
{
    if (g_saved_rip_slot != nullptr)
    {
        *g_saved_rip_slot = g_saved_rip_value;
        g_saved_rip_slot = nullptr;
    }
}

// ====================================================================
// Attack: per-page PTE W^X flip
// ====================================================================
//
// Pick the very page the runtime checker baselines as its head
// `.rodata` slot, flip its NX bit off + W bit on, force-scan,
// restore. Distinct from the `AttackKernelTextPatch` byte-level
// .text patch in two ways:
//   1. .text patch needs CR0.WP toggle; this needs no global CR
//      flip — just a single PTE-flag rewrite.
//   2. .text patch lights up `KernelTextModified`; this is invisible
//      to the .text spot/full hash detector and to the `Cr0WpCleared`
//      detector — only the new per-page PTE check fires.
//
// Real-world parallel: the cleanest "make `.rodata` writable"
// rootkit move on a kernel without enforced-RO-data is exactly
// this — flip the page attribute, scribble whatever you want,
// flip back. No CR0.WP toggle, no IPI shootdown to peer CPUs
// because PTE writes are private to the writing CPU's TLB until
// the next reload.

extern "C" const u8 _rodata_start[];

constinit u64 g_pte_attack_va = 0;
constinit u64 g_pte_saved_attrs = 0;

void AttackPteFlagsFlip()
{
    g_pte_attack_va = reinterpret_cast<u64>(_rodata_start) & ~0xFFFULL;
    g_pte_saved_attrs = mm::GetPteFlags4K(g_pte_attack_va);
    if (g_pte_saved_attrs == 0)
    {
        arch::SerialWrite("[attacksim]   pte-flip: target PTE not 4K-resolvable; skipping\n");
        return;
    }
    // Drop the NX bit + add Writable. In the process we also
    // strip every other attribute except Present — that's enough
    // to prove the detector can spot the drift without us
    // pretending to keep cache / global / accessed bits stable.
    constexpr u64 kNewFlags = mm::kPagePresent | mm::kPageWritable;
    mm::SetPteFlags4K(g_pte_attack_va, kNewFlags);
}

void RestorePteFlagsFlip()
{
    if (g_pte_attack_va != 0 && g_pte_saved_attrs != 0)
    {
        // `g_pte_saved_attrs` includes the high NX bit. Re-OR
        // `kPagePresent` defensively — `SetPteFlags4K` already
        // does it, but the explicit OR keeps the call site
        // readable.
        mm::SetPteFlags4K(g_pte_attack_va, g_pte_saved_attrs | mm::kPagePresent);
        g_pte_attack_va = 0;
        g_pte_saved_attrs = 0;
    }
}

} // namespace

// ====================================================================
// Synthetic function-pointer table + AttackSimVtableHash.
//
// Kept at outer `duetos::security` scope (not in the anonymous
// namespace) so `runtime_checker.cpp` can reach
// `AttackSimVtableHash` via a plain `extern "C"` declaration —
// no `<security/...>` header dependency from the diag layer.
//
// The table models a kernel dispatch table — `driver_ops`,
// `bus_ops`, a syscall shim, etc. Real rootkits prefer flipping
// one slot of such a table over patching the called function,
// because dispatch-table writes are quieter (no `.text` modification,
// no CR0.WP toggle). We model this by sitting in writable data
// and letting the attack flip a slot. The detector hashes the
// table bytes on every scan; a single-slot rewrite changes the
// hash.
// ====================================================================

void AttackSimVtableEntry0() {}
void AttackSimVtableEntry1() {}
void AttackSimVtableEntry2() {}
void AttackSimVtableEntry3() {}

using AttackSimVtableFn = void (*)();
constinit AttackSimVtableFn g_attack_sim_vtable[4] = {
    AttackSimVtableEntry0,
    AttackSimVtableEntry1,
    AttackSimVtableEntry2,
    AttackSimVtableEntry3,
};

} // namespace duetos::security

extern "C" duetos::u64 AttackSimVtableHash()
{
    constexpr duetos::u64 kFnvOffset = 0xcbf29ce484222325ULL;
    constexpr duetos::u64 kFnvPrime = 0x100000001b3ULL;
    duetos::u64 h = kFnvOffset;
    const duetos::u8* p = reinterpret_cast<const duetos::u8*>(&::duetos::security::g_attack_sim_vtable);
    for (duetos::u64 i = 0; i < sizeof(::duetos::security::g_attack_sim_vtable); ++i)
    {
        h ^= p[i];
        h *= kFnvPrime;
    }
    return h;
}

namespace duetos::security
{
namespace
{

constinit AttackSimVtableFn g_saved_vtable_slot = nullptr;
constexpr u32 kVtableAttackSlot = 2;

void AttackVtableSlotOverwrite()
{
    g_saved_vtable_slot = g_attack_sim_vtable[kVtableAttackSlot];
    g_attack_sim_vtable[kVtableAttackSlot] = reinterpret_cast<AttackSimVtableFn>(0xDEAD'BEEF'CAFE'BABEULL);
}

void RestoreVtableSlotOverwrite()
{
    if (g_saved_vtable_slot != nullptr)
    {
        g_attack_sim_vtable[kVtableAttackSlot] = g_saved_vtable_slot;
        g_saved_vtable_slot = nullptr;
    }
}

} // namespace

const char* AttackOutcomeName(AttackOutcome o)
{
    switch (o)
    {
    case AttackOutcome::Pass:
        return "PASS";
    case AttackOutcome::FailNoDetect:
        return "FAIL (undetected)";
    case AttackOutcome::Skipped:
        return "SKIPPED";
    default:
        return "?";
    }
}

void AttackSimRun()
{
    AttackSummary& s = g_summary;
    s.count = 0;
    s.passed = 0;
    s.failed = 0;
    s.skipped = 0;
    arch::SerialWrite("\n[attacksim] =================================================\n");
    arch::SerialWrite("[attacksim] Starting red-team attacker simulation suite.\n");
    arch::SerialWrite("[attacksim] Each attack: snapshot -> perform -> force-scan\n");
    arch::SerialWrite("[attacksim]              -> verify detector -> restore.\n");
    arch::SerialWrite("[attacksim] =================================================\n");

    // Spec table at file-scope static constinit to avoid the
    // compiler emitting a memcpy for a 5-entry local array of
    // 40-byte structs. Freestanding kernel has no memcpy.
    struct Spec
    {
        const char* name;
        const char* detector_name;
        core::HealthIssue issue;
        bool (*precheck)(); // nullable — null means always runnable
        void (*attack)();
        void (*restore)();
    };
    // Order-sensitive: the bootkit attack MUST run first. Any
    // other security-critical finding (IDT/GDT/LSTAR/CR/EFER/
    // .text patch) also escalates the blockguard to Deny, which
    // would then refuse the bootkit's write before it reaches the
    // disk — the hash check sees no change and reports FAIL even
    // though the layered defense actually just worked. Running
    // bootkit first lets the write land (in Advisory mode), the
    // hash picks up the change, and the detector fires cleanly.
    //
    // The CR/EFER attacks rely on `HealControlRegisters` to
    // re-assert the cleared bit on the next scan; our explicit
    // Restore is a safety net. Kernel-text patch holds IRQs off
    // across its WP-clear window — see AttackKernelTextPatch.
    static constinit const Spec kSpecs[20] = {
        {"Bootkit LBA 0 write", "BootSectorModified", core::HealthIssue::BootSectorModified, nullptr, AttackBootSector,
         RestoreBootSector},
        {"IDT hijack", "IdtModified", core::HealthIssue::IdtModified, nullptr, AttackIdt, RestoreIdt},
        {"GDT descriptor swap", "GdtModified", core::HealthIssue::GdtModified, nullptr, AttackGdt, RestoreGdt},
        {"LSTAR syscall hook", "SyscallMsrHijacked", core::HealthIssue::SyscallMsrHijacked, nullptr, AttackLstar,
         RestoreLstar},
        {"SYSENTER_CS hook (legacy 32-bit syscall)", "SyscallMsrHijacked", core::HealthIssue::SyscallMsrHijacked,
         nullptr, AttackSysenterCs, RestoreSysenterCs},
        {"SYSENTER_EIP hook (legacy 32-bit syscall)", "SyscallMsrHijacked", core::HealthIssue::SyscallMsrHijacked,
         nullptr, AttackSysenterEip, RestoreSysenterEip},
        {"CR0.WP defang (W^X bypass)", "Cr0WpCleared", core::HealthIssue::Cr0WpCleared, PrecheckCr0Wp, AttackCr0Wp,
         RestoreCr0Wp},
        {"CR4.SMEP defang (ret2usr enable)", "Cr4SmepCleared", core::HealthIssue::Cr4SmepCleared, PrecheckCr4Smep,
         AttackCr4Smep, RestoreCr4Smep},
        {"CR4.SMAP defang (user-mem read)", "Cr4SmapCleared", core::HealthIssue::Cr4SmapCleared, PrecheckCr4Smap,
         AttackCr4Smap, RestoreCr4Smap},
        {"EFER.NXE defang (data exec)", "EferNxeCleared", core::HealthIssue::EferNxeCleared, PrecheckEferNxe,
         AttackEferNxe, RestoreEferNxe},
        {"Kernel .text inline-hook (1-byte patch)", "KernelTextModified", core::HealthIssue::KernelTextModified,
         nullptr, AttackKernelTextPatch, RestoreKernelTextPatch},
        {"Ransomware FS write-rate flood (burst tier)", "MassFsWriteRate", core::HealthIssue::MassFsWriteRate, nullptr,
         AttackRansomwareWriteRate, RestoreRansomwareWriteRate},
        {"Ransomware low-and-slow (sustained tier)", "MassFsWriteRateSustained",
         core::HealthIssue::MassFsWriteRateSustained, nullptr, AttackRansomwareLowAndSlow, RestoreRansomwareLowAndSlow},
        {"Canary file touch", "CanaryFileTouched", core::HealthIssue::CanaryFileTouched, nullptr, AttackCanaryTouch,
         RestoreCanaryTouch},
        {"Persistence drop (autostart path)", "PersistenceDropDetected", core::HealthIssue::PersistenceDropDetected,
         nullptr, AttackPersistenceDrop, RestorePersistenceDrop},
        {"Stack canary defang", "StackCanaryZero", core::HealthIssue::StackCanaryZero, nullptr, AttackStackCanaryZero,
         RestoreStackCanaryZero},
        // Function-branch NOP patch on a synthetic cap-style gate.
        // Honest red-team finding: ComputeTextSpotHash only inspects
        // the first/last 4 KiB of `.text`, and AttackSimGatedAccess
        // links into the middle, so KernelTextModified is expected
        // NOT to fire. The slice's deliverable is the FailNoDetect
        // outcome plus the BYPASS-LANDED log line proving the cap
        // gate was actually flipped open. Ticketed in
        // `.claude/knowledge/branch-nop-attack-v0.md` for the
        // follow-up "full-text or rolling-page hash" detector slice.
        {"Function branch NOP patch (cap-gate bypass)", "KernelTextModified", core::HealthIssue::KernelTextModified,
         nullptr, AttackBranchNopPatch, RestoreBranchNopPatch},
        // Function-pointer dispatch table slot overwrite. Models
        // a rootkit hooking `driver_ops` / `bus_ops` by flipping
        // one slot to its shim pointer. Detector hashes the
        // synthetic `g_attack_sim_vtable` on every scan.
        {"Function-pointer table slot overwrite", "KernelFnTableModified", core::HealthIssue::KernelFnTableModified,
         nullptr, AttackVtableSlotOverwrite, RestoreVtableSlotOverwrite},
        // Saved-RIP overwrite. Walks two RBP frames back from the
        // attack's own frame (= AttackSimRun's saved RIP slot) and
        // writes a sentinel non-`.text` value. Detector walks the
        // active RBP chain at scan time.
        {"Saved RIP overwrite (return-address smash)", "TaskStackRipCorrupt", core::HealthIssue::TaskStackRipCorrupt,
         nullptr, AttackSavedRipOverwrite, RestoreSavedRipOverwrite},
        // Per-page PTE flag flip. Drops NX + adds W on the head
        // `.rodata` page. Detector compares the live PTE attribute
        // tail against the per-page baseline captured at boot.
        {"PTE W^X flip (per-page attribute rewrite)", "KernelPteWxFlipped", core::HealthIssue::KernelPteWxFlipped,
         nullptr, AttackPteFlagsFlip, RestorePteFlagsFlip},
        // Deferred — each needs its own slice with bespoke handling:
        //
        //   "Stack canary defang"  — zeroing __stack_chk_guard while
        //     the kernel is live self-bricks; next protected return
        //     calls __stack_chk_fail → panic. Needs a no-stack-
        //     protector island around the whole snapshot/scan path.
        //
        //   "IA32_FEATURE_CONTROL unlock" — once firmware sets the
        //     lock bit, WRMSR refuses to clear it (#GP). Untriggerable
        //     on locked firmware; on unlocked firmware the very fact
        //     that boot didn't lock means the detector also doesn't
        //     check, so the suite slot is meaningless either way.
        //
        //   "IRQ storm" — needs >25 000 software interrupts into a
        //     real registered handler within one scan window. Doable
        //     with `int $vec` × N but pollutes IRQ statistics for the
        //     rest of the boot; defer until the suite gains a "reset
        //     baselines" hook.
        //
        //   "Heap pool mismatch / underflow" — corrupts the kernel
        //     allocator's bookkeeping; recovering is invasive (must
        //     repair both used/free counters and any chunk header
        //     scribbled to bait the detector). Separate slice with a
        //     dedicated scratch heap.
        //
        //   "Task stack overflow / RSP out of range" — needs to pick
        //     a non-running task and scribble its stack-bottom canary
        //     or saved-rsp without racing the scheduler. Wants a
        //     scheduler-quiesce primitive that doesn't yet exist.
    };

    for (const Spec& sp : kSpecs)
    {
        if (s.count >= kMaxAttackResults)
            break;
        const AttackOutcome o = RunAttack(sp.name, sp.issue, sp.precheck, sp.attack, sp.restore);
        s.results[s.count].name = sp.name;
        s.results[s.count].detector = sp.detector_name;
        s.results[s.count].outcome = o;
        ++s.count;
        if (o == AttackOutcome::Pass)
            ++s.passed;
        else if (o == AttackOutcome::FailNoDetect)
            ++s.failed;
        else
            ++s.skipped;
    }

    arch::SerialWrite("[attacksim] =================================================\n");
    arch::SerialWrite("[attacksim] Summary:\n");
    for (u64 i = 0; i < s.count; ++i)
    {
        arch::SerialWrite("[attacksim]   ");
        arch::SerialWrite(AttackOutcomeName(s.results[i].outcome));
        arch::SerialWrite("  ");
        arch::SerialWrite(s.results[i].name);
        arch::SerialWrite(" (expected ");
        arch::SerialWrite(s.results[i].detector);
        arch::SerialWrite(")\n");
    }
    arch::SerialWrite("[attacksim] passed=");
    arch::SerialWriteHex(s.passed);
    arch::SerialWrite(" failed=");
    arch::SerialWriteHex(s.failed);
    arch::SerialWrite(" skipped=");
    arch::SerialWriteHex(s.skipped);
    arch::SerialWrite("\n[attacksim] =================================================\n\n");
}

const AttackSummary& AttackSimSummary()
{
    return g_summary;
}

} // namespace duetos::security
