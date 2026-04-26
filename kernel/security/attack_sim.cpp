#include "security/attack_sim.h"

#include "arch/x86_64/serial.h"
#include "log/klog.h"
#include "diag/runtime_checker.h"
#include "drivers/storage/block.h"

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
    static constinit const Spec kSpecs[11] = {
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
