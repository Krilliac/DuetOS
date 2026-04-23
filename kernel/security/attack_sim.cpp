#include "attack_sim.h"

#include "../arch/x86_64/serial.h"
#include "../core/klog.h"
#include "../core/runtime_checker.h"
#include "../drivers/storage/block.h"

namespace customos::security
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

AttackOutcome RunAttack(const char* name, core::HealthIssue expected, void (*attack)(), void (*restore)())
{
    arch::SerialWrite("[attacksim] --- ");
    arch::SerialWrite(name);
    arch::SerialWrite(" ---\n");
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

// AttackCanary intentionally omitted — see kSpecs comment.

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
        void (*attack)();
        void (*restore)();
    };
    // Order-sensitive: the bootkit attack MUST run first. Any
    // other security-critical finding (IDT/GDT/LSTAR) also
    // escalates the blockguard to Deny, which would then refuse
    // the bootkit's write before it reaches the disk — the hash
    // check sees no change and reports FAIL even though the
    // layered defense actually just worked. Running bootkit
    // first lets the write land (in Advisory mode), the hash
    // picks up the change, and the detector fires cleanly.
    static constinit const Spec kSpecs[4] = {
        {"Bootkit LBA 0 write", "BootSectorModified", core::HealthIssue::BootSectorModified, AttackBootSector,
         RestoreBootSector},
        {"IDT hijack", "IdtModified", core::HealthIssue::IdtModified, AttackIdt, RestoreIdt},
        {"GDT descriptor swap", "GdtModified", core::HealthIssue::GdtModified, AttackGdt, RestoreGdt},
        {"LSTAR syscall hook", "SyscallMsrHijacked", core::HealthIssue::SyscallMsrHijacked, AttackLstar, RestoreLstar},
        // "Stack canary defang" — deliberately NOT in the suite. Zeroing
        // __stack_chk_guard while the kernel is live self-bricks: the
        // very next protected function that returns compares its
        // stashed cookie to 0 and calls __stack_chk_fail → panic. The
        // StackCanaryZero detector is trivially sound (a literal `== 0`
        // check); proving it requires a more careful harness (CLI,
        // no_stack_protector on every callee) than the rest of the
        // suite. Separate slice.
    };

    for (const Spec& sp : kSpecs)
    {
        if (s.count >= kMaxAttackResults)
            break;
        const AttackOutcome o = RunAttack(sp.name, sp.issue, sp.attack, sp.restore);
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

} // namespace customos::security
