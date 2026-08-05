#include "power/suspend.h"

#include "acpi/acpi.h"
#include "arch/x86_64/acpi_wakeup.h"
#include "arch/x86_64/gdt.h"
#include "arch/x86_64/hpet.h"
#include "arch/x86_64/ioapic.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "core/panic.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "log/klog.h"
#include "arch/x86_64/smp.h"

namespace duetos::power
{

namespace
{

// Participant tables. Small fixed arrays rather than a linked list:
// registration happens once at boot from a handful of call sites, and
// a kernel allocation in this path would be one more thing that can
// fail at the worst moment.
constexpr u32 kMaxParticipants = 16;
constexpr u32 kMaxVetoes = 16;

struct Participant
{
    const char* name;
    SuspendVerdict (*prepare)();
    void (*resume)();
};

struct Veto
{
    const char* name;
    const char* reason;
};

constinit Participant g_participants[kMaxParticipants]{};
constinit u32 g_participant_count = 0;
constinit Veto g_vetoes[kMaxVetoes]{};
constinit u32 g_veto_count = 0;

// The S3 SLP_TYP values, resolved once per attempt. Never cached
// across attempts as a "0 means absent" pair — absence is carried by
// the bool return of AcpiSleepTypeFor, because SLP_TYP 0 is legal.
constinit u8 g_s3_typa = 0;
constinit u8 g_s3_typb = 0;

// Written by the trampoline-side context; read after resume to prove
// we came back the way we think we did.
u32 ResumeCount()
{
    return arch::AcpiWakeContextGet().resume_count;
}

// --- Platform participants -----------------------------------------
// These are the pieces the orchestrator itself owns rather than a
// driver: without a working UART there is no resume proof to read, and
// without the PS/2 controller the machine comes back deaf.

void ResumeSerial()
{
    arch::SerialInit();
}

void ResumePs2Keyboard()
{
    drivers::input::Ps2KeyboardResume();
}

void ResumePs2Mouse()
{
    drivers::input::Ps2MouseResume();
}

// Re-establish the interrupt controllers and time sources the CPU lost
// with its power. Runs before any device resume callback: those may
// log, and klog timestamps come from the tick.
//
// Each Resume variant re-PROGRAMS the controller registers (which
// the platform reset wiped) WITHOUT calling mm::MapMmio: the MMIO
// pointers cached at first boot survive S3 in RAM. This was the
// arena-leak bug: the Init functions both mapped AND programmed,
// so every S3 cycle leaked bump-allocator space and stranded the
// old VA.
void ResumePlatform()
{
    arch::LapicResume();
    arch::IoApicResume();
    arch::HpetResume();
    arch::TimerInit();
    arch::LapicTimerStartOnCurrent();
}

// Collect verdicts. Returns the first refusing participant's name, or
// nullptr when every participant is ready.
const char* CollectVerdicts()
{
    for (u32 i = 0; i < g_participant_count; ++i)
    {
        if (g_participants[i].prepare == nullptr)
            continue;
        if (g_participants[i].prepare() != SuspendVerdict::Ready)
            return g_participants[i].name;
    }
    return nullptr;
}

// The C callback AcpiSuspendEnter invokes once the CPU context is
// safely stored. Everything past this point is unrecoverable if it
// throws a fault, so it does exactly two things.
void EnterSleepWrite()
{
    acpi::AcpiSleepWriteControl(g_s3_typa, g_s3_typb);
}

} // namespace

const char* SuspendOutcomeName(SuspendOutcome o)
{
    switch (o)
    {
    case SuspendOutcome::Cycled:
        return "cycled";
    case SuspendOutcome::NoAcpiSleepState:
        return "no-acpi-s3-package";
    case SuspendOutcome::NoWakingVector:
        return "no-waking-vector";
    case SuspendOutcome::DeviceRefused:
        return "device-refused";
    case SuspendOutcome::MultipleCpusOnline:
        return "multiple-cpus-online";
    case SuspendOutcome::PlatformDeclined:
        return "platform-declined";
    }
    return "unknown";
}

bool PowerSuspendRegister(const char* name, SuspendVerdict (*prepare)(), void (*resume)())
{
    if (name == nullptr || resume == nullptr)
        return false;
    if (g_participant_count >= kMaxParticipants)
    {
        KLOG_WARN_S("power/suspend", "participant table full — driver not registered", "name", name);
        return false;
    }
    g_participants[g_participant_count++] = Participant{name, prepare, resume};
    return true;
}

bool PowerSuspendVeto(const char* name, const char* reason)
{
    if (name == nullptr || reason == nullptr)
        return false;
    if (g_veto_count >= kMaxVetoes)
    {
        // A dropped veto would silently ALLOW a suspend that should
        // have been refused, so this is an error, not a warning.
        KLOG_ERROR_S("power/suspend", "veto table full — suspend gating incomplete", "name", name);
        return false;
    }
    g_vetoes[g_veto_count++] = Veto{name, reason};
    return true;
}

SuspendOutcome PowerSuspendCheck()
{
    if (g_veto_count != 0)
        return SuspendOutcome::DeviceRefused;

    // v0 parks no APs and restores no AP context, so a second online
    // CPU would resume into a wild state. Refuse rather than try.
    if (arch::SmpCpusOnline() > 1)
        return SuspendOutcome::MultipleCpusOnline;

    u8 typa = 0;
    u8 typb = 0;
    if (!acpi::AcpiSleepTypeFor(3, &typa, &typb))
        return SuspendOutcome::NoAcpiSleepState;
    if (acpi::FacsAddress() == 0)
        return SuspendOutcome::NoWakingVector;
    return SuspendOutcome::Cycled;
}

SuspendOutcome PowerSuspendToRam()
{
    const SuspendOutcome gate = PowerSuspendCheck();
    if (gate != SuspendOutcome::Cycled)
    {
        KLOG_WARN_S("power/suspend", "suspend refused", "reason", SuspendOutcomeName(gate));
        if (gate == SuspendOutcome::DeviceRefused)
            PowerSuspendReport();
        return gate;
    }

    if (!acpi::AcpiSleepTypeFor(3, &g_s3_typa, &g_s3_typb))
        return SuspendOutcome::NoAcpiSleepState;

    const char* refuser = CollectVerdicts();
    if (refuser != nullptr)
    {
        KLOG_WARN_S("power/suspend", "suspend refused by driver", "name", refuser);
        return SuspendOutcome::DeviceRefused;
    }

    // Arm last, so a refusal above never leaves a live waking vector
    // pointing at a trampoline we then never enter.
    if (!arch::AcpiWakeArm())
        return SuspendOutcome::NoWakingVector;

    // Give firmware its §7 sleep-prep methods before the SLP_TYP
    // write. On QEMU these are absent; on a real laptop the EC will
    // not honour S3 without them.
    acpi::AcpiRunSleepPrep(3);

    const u32 resumes_before = ResumeCount();

    // Structural sentinel: the harness greps for this to know when to
    // deliver the wake event, so it is raw serial, not klog — it has
    // to survive whatever log level the operator picked, and the tick
    // that timestamps klog is about to stop.
    arch::SerialWrite("[suspend] entering S3\n");

    u64 flags = 0;
    asm volatile("pushfq; pop %0; cli" : "=r"(flags)::"memory");

    arch::AcpiWakeContextGet().tss_rsp0 = arch::TssCurrentRsp0();
    const u32 slept = arch::AcpiSuspendEnter(&arch::AcpiWakeContextGet(), &EnterSleepWrite);

    if (slept == 0)
    {
        // The SLP_TYP write returned. Nothing was torn down — the CPU
        // context save is a no-op if we never left — so simply restore
        // interrupts and report the platform declined.
        asm volatile("push %0; popfq" ::"r"(flags) : "memory", "cc");
        arch::SerialWrite("[suspend] S3 declined by platform\n");
        return SuspendOutcome::PlatformDeclined;
    }

    // --- We are on the far side of the power transition. -----------
    // Interrupts are off (the restored RFLAGS carries the pre-cli
    // state, but the trampoline path never re-enabled them). The
    // platform must come back before anything else can log.
    ResumePlatform();

    for (u32 i = 0; i < g_participant_count; ++i)
        g_participants[i].resume();

    asm volatile("push %0; popfq" ::"r"(flags) : "memory", "cc");

    const u32 resumes_after = ResumeCount();
    arch::SerialWrite("[suspend] resumed from S3 resume_count=");
    arch::SerialWriteHex(resumes_after);
    arch::SerialWrite("\n");

    // The resume counter is incremented by the wake trampoline itself.
    // If it did not move we did not come back the way we think we did,
    // and every conclusion drawn from "slept == 1" is unsafe.
    if (resumes_after == resumes_before)
    {
        core::Panic("power/suspend", "resumed without the wake trampoline incrementing resume_count");
    }
    return SuspendOutcome::Cycled;
}

void PowerSuspendReport()
{
    KLOG_INFO_V("power/suspend", "S3 participants", g_participant_count);
    for (u32 i = 0; i < g_participant_count; ++i)
        KLOG_INFO_S("power/suspend", "participant", "name", g_participants[i].name);
    for (u32 i = 0; i < g_veto_count; ++i)
    {
        KLOG_INFO_S("power/suspend", "veto", "name", g_vetoes[i].name);
        KLOG_INFO_S("power/suspend", "veto reason", "reason", g_vetoes[i].reason);
    }
}

void PowerSuspendInit()
{
    // Serial first: it is the only participant whose failure would
    // hide every other participant's failure.
    PowerSuspendRegister("serial", nullptr, &ResumeSerial);
    PowerSuspendRegister("ps2kbd", nullptr, &ResumePs2Keyboard);
    PowerSuspendRegister("ps2mouse", nullptr, &ResumePs2Mouse);
}

void PowerSuspendSelfTest(bool run_live_cycle)
{
    using core::PanicWithValue;

    // Outcome names must all be distinct and non-empty — the shell and
    // the boot log are the only channel a refusal reaches an operator
    // through, and two reasons sharing a name would hide one of them.
    const SuspendOutcome all[] = {
        SuspendOutcome::Cycled,        SuspendOutcome::NoAcpiSleepState,   SuspendOutcome::NoWakingVector,
        SuspendOutcome::DeviceRefused, SuspendOutcome::MultipleCpusOnline, SuspendOutcome::PlatformDeclined,
    };
    for (u32 i = 0; i < sizeof(all) / sizeof(all[0]); ++i)
    {
        const char* a = SuspendOutcomeName(all[i]);
        if (a == nullptr || a[0] == '\0')
            PanicWithValue("power/suspend", "outcome name empty", i);
        for (u32 j = i + 1; j < sizeof(all) / sizeof(all[0]); ++j)
        {
            const char* b = SuspendOutcomeName(all[j]);
            const char* p = a;
            const char* q = b;
            while (*p != '\0' && *p == *q)
            {
                ++p;
                ++q;
            }
            if (*p == '\0' && *q == '\0')
                PanicWithValue("power/suspend", "two outcomes share a name", i);
        }
    }

    // A veto must be BINDING. Register a probe veto, confirm the gate
    // refuses because of it, then withdraw it. If this ever fails, the
    // refusal contract has silently stopped applying and every driver
    // that declared itself unsaveable is being ignored.
    const u32 vetoes_before = g_veto_count;
    if (!PowerSuspendVeto("selftest-probe", "transient veto proving the gate binds"))
        PanicWithValue("power/suspend", "could not register the probe veto", g_veto_count);
    if (PowerSuspendCheck() != SuspendOutcome::DeviceRefused)
        PanicWithValue("power/suspend", "registered veto did not block the gate", g_veto_count);
    g_veto_count = vetoes_before;
    if (g_veto_count != 0 && PowerSuspendCheck() != SuspendOutcome::DeviceRefused)
        PanicWithValue("power/suspend", "pre-existing veto stopped binding", g_veto_count);

    arch::SerialWrite("[suspend-selftest] PASS (outcome names distinct, veto binding)\n");

    if (!run_live_cycle)
        return;

    // Live cycle. This runs from the boot bring-up BEFORE the storage
    // and NIC drivers attach, so no driver that would veto exists yet
    // and no bypass is needed — the gate is consulted for real.
    const SuspendOutcome o = PowerSuspendToRam();

    arch::SerialWrite("[suspend-selftest] live-cycle outcome=");
    arch::SerialWrite(SuspendOutcomeName(o));
    arch::SerialWrite("\n");
}

} // namespace duetos::power
