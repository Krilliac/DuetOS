/*
 * DuetOS — IR runbook: implementation.
 *
 * The runbook table is constexpr; every actionable EventKind has
 * a row, and IrRunbookSelfTest walks the EventKind enum and
 * asserts coverage. Bookkeeping kinds (PolicyChanged, AttackSimRun,
 * IrRunbookEmitted, ...) are explicitly opted out — emitting a
 * runbook for them would be circular.
 */

#include "security/ir_runbook.h"

#include "arch/x86_64/serial.h"
#include "sync/spinlock.h"
#include "time/timekeeper.h"

namespace duetos::security
{

namespace
{

constexpr IrRunbookEntry kEntries[] = {
    {
        EventKind::CanaryTouch,
        "CanaryTouch — caller hit a registered canary or suspicious-extension path",
        "A process attempted to read/write/create a path the kernel marked as a sentinel. "
        "Real workloads do not touch these; ransomware enumeration or honey-file bait did.",
        {
            "Run `secevents 50` to see the cluster of events around this trip.",
            "Run `imagelog pid=<actor>` to identify the binary (path, hash, signer).",
            "Cross-check `guard show` for the image's load-time verdict.",
            "If image was recently installed, treat as untrusted until reviewed.",
            nullptr,
            nullptr,
        },
        "policy set forensic   (if repeat trip from same image)",
    },
    {
        EventKind::PersistenceDrop,
        "PersistenceDrop — caller mutated an autostart-equivalent path",
        "Most malware that wants to survive reboot drops a file in an init.d/Run-key/"
        "autostart equivalent. This trip caught the drop in real time.",
        {
            "Run `secevents kind=PersistenceDrop` to see all related drops.",
            "Inspect the path; if not from a legitimate installer, the writer is suspect.",
            "Check `guard show` for any recent Warn verdicts on the writer.",
            "Switch persistence to Deny if Advisory and the trips repeat.",
            nullptr,
            nullptr,
        },
        "persistence deny",
    },
    {
        EventKind::FsWriteRateBurst,
        "FsWriteRateBurst — process wrote >16 MiB in 1 second",
        "A 16-MiB-in-one-second write burst is the signature shape of mass-encryption "
        "ransomware. Process is already flagged for kill.",
        {
            "Run `secevents 50` for the cluster around this kill.",
            "Run `imagelog pid=<actor>` to identify the binary.",
            "Hash the binary and add to the deny list if not already.",
            "Check for accompanying PersistenceDrop events from same actor.",
            nullptr,
            nullptr,
        },
        "policy set forensic",
    },
    {
        EventKind::FsWriteRateSustained,
        "FsWriteRateSustained — process wrote >256 MiB in 5 minutes (low-and-slow)",
        "Burst-rate evasion: attacker pacing writes under the 16-MiB/s gate, but the "
        "5-minute aggregate reveals them. Process is flagged for kill.",
        {
            "Run `secevents kind=FsWriteRateSustained` for the family.",
            "Correlate with PersistenceDrop in the same window.",
            "Hash the binary; review allow-list eligibility.",
            "Consider freezing other holders of kCapFsWrite as a precaution.",
            nullptr,
            nullptr,
        },
        "policy set forensic",
    },
    {
        EventKind::FsWriteRateLong,
        "FsWriteRateLong — process wrote >2 GiB in 1 hour (persistent attacker)",
        "A determined attacker pacing under the 5-minute gate, but the hour-long "
        "aggregate caught them. Process is flagged for kill.",
        {
            "Escalate immediately — this is patient malware.",
            "Pull `imagelog pid=<actor>` for the binary's full provenance.",
            "Freeze every kCapFsWrite holder until reviewed.",
            "Pull a snapshot of /etc and autostart paths; compare to baseline.",
            nullptr,
            nullptr,
        },
        "policy set forensic",
    },
    {
        EventKind::SandboxDenialKill,
        "SandboxDenialKill — process accumulated 100 cap-denials, reaped",
        "Hostile / buggy process kept hitting cap gates past the threshold. Either a "
        "fuzzer-style malicious workload or a deeply broken binary.",
        {
            "Run `imagelog pid=<actor>` for the binary.",
            "Check for related ImageRejected events with the same image hash.",
            "If accidental, the threshold is the right control to raise via policy.",
            nullptr,
            nullptr,
            nullptr,
        },
        nullptr,
    },
    {
        EventKind::TickBudgetKill,
        "TickBudgetKill — process exhausted CPU-tick budget",
        "Cooperative-scheduling outlier: ran past its quota without yielding. Could "
        "be a runaway loop or a deliberate denial-of-CPU.",
        {
            "Check `secevents` for TickBudgetKill repetition by the same image.",
            "Run `imagelog pid=<actor>` for the binary.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        nullptr,
    },
    {
        EventKind::IdtModified,
        "IdtModified — kernel-mode rootkit indicator (IDT changed since boot baseline)",
        "Nothing legitimate writes to the IDT after boot. A baseline-mismatch is a "
        "rootkit-class signal — investigate before allowing any further untrusted code.",
        {
            "Run `health show` to see the full detector trip inventory.",
            "If repeat trip after self-Heal: active rootkit loop; reboot is the only recovery.",
            "Pull `secevents` for any preceding ImageRejected / ImageWarned events.",
            nullptr,
            nullptr,
            nullptr,
        },
        "reboot (after diagnostic capture)",
    },
    {
        EventKind::GdtModified,
        "GdtModified — kernel-mode rootkit indicator (GDT changed since boot baseline)",
        "Like IdtModified but for the GDT/TSS. RSP0 is excluded from the hash; if this "
        "trip fires it's a real change, not a benign scheduler write.",
        {
            "Run `health show`.",
            "Reboot after diagnostic capture if trip repeats.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        "reboot",
    },
    {
        EventKind::KernelTextModified,
        "KernelTextModified — W^X bypassed, kernel .text spot-check changed",
        "Kernel .text pages are RX-only under W^X. A baseline mismatch means W^X was "
        "bypassed via the direct map or a privilege escalation. Treat as confirmed compromise.",
        {
            "Capture `crashdump` immediately for offline analysis.",
            "Reboot — recovery without reboot is unsafe.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        "reboot (after crashdump)",
    },
    {
        EventKind::SyscallMsrHijacked,
        "SyscallMsrHijacked — IA32_LSTAR / STAR / SYSENTER drift since boot baseline",
        "Modern rootkits hook syscalls by overwriting LSTAR / STAR / SYSENTER_EIP. "
        "Each is set once at boot and never legitimately rewritten.",
        {
            "Run `health show` — the detector reports which MSR drifted.",
            "If drift repeats after Heal: active hook loop; reboot.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        "reboot",
    },
    {
        EventKind::BootSectorModified,
        "BootSectorModified — MBR/GPT changed since boot baseline (bootkit)",
        "Disk-persistence malware overwrote LBA 0 / GPT header. Survives reboot until "
        "the disk image is restored.",
        {
            "Reinstall OS image from clean media.",
            "Audit any process holding kCapBlockWrite around the trip time.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        "reinstall",
    },
    {
        EventKind::Cr0WpCleared,
        "Cr0WpCleared — write-protect bit silently cleared",
        "CR0.WP off lets ring-0 code write through read-only mappings — classic rootkit "
        "preface to a kernel .text patch. Heal restored the bit.",
        {
            "Run `secevents kind=Cr0WpCleared` to spot a clear→Heal→clear loop.",
            "If looped: active rootkit; reboot after `crashdump`.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        nullptr,
    },
    {
        EventKind::Cr4SmepCleared,
        "Cr4SmepCleared — SMEP disabled (kernel can execute user pages)",
        "SMEP off lets the kernel be tricked into executing attacker-controlled pages. "
        "Heal restored the bit; if it clears repeatedly there is an active hook.",
        {
            "Run `secevents kind=Cr4SmepCleared` for repetition.",
            "Reboot if the bit keeps clearing.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        nullptr,
    },
    {
        EventKind::Cr4SmapCleared,
        "Cr4SmapCleared — SMAP disabled (kernel can read user pages without STAC)",
        "SMAP off opens an attacker-controlled-data leak surface. Heal restored.",
        {
            "Run `secevents kind=Cr4SmapCleared` for repetition.",
            "Reboot if the bit keeps clearing.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        nullptr,
    },
    {
        EventKind::EferNxeCleared,
        "EferNxeCleared — NX/no-execute disabled",
        "EFER.NXE off makes every page executable, defeating W^X. Heal restored.",
        {
            "Run `secevents kind=EferNxeCleared` for repetition.",
            "Reboot if the bit keeps clearing.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        nullptr,
    },
    {
        EventKind::StackCanaryZero,
        "StackCanaryZero — __stack_chk_guard zeroed",
        "Active attack on the canary protection itself. Continuing to run is unsafe.",
        {
            "Reboot immediately.",
            "Investigate boot history for the binary that caused this.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        "reboot",
    },
    {
        EventKind::FeatureControlUnlocked,
        "FeatureControlUnlocked — IA32_FEATURE_CONTROL lock bit cleared",
        "Firmware locks this bit at boot to prevent VMX / SMRR re-config. Cleared = "
        "either a buggy firmware or a rogue write setting up VMX-based attack.",
        {
            "If first occurrence on this hardware, file as firmware quirk after reboot.",
            "If repeat or sudden: investigate as VMX-based hook.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        nullptr,
    },
    {
        EventKind::ImageRejected,
        "ImageRejected — loader denied an image at load",
        "Guard's static analysis flagged the image as Deny. The image did not run.",
        {
            "Check `guard show` for the rejection reason.",
            "If false-positive, hash the image and use `guard remember-allow`.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        nullptr,
    },
    {
        EventKind::ImageWarned,
        "ImageWarned — loader emitted Warn verdict on an image",
        "Image had suspicious static-analysis findings but was not denied (Advisory mode "
        "or Warn verdict in Enforce). It is running, monitor for downstream trips.",
        {
            "Check `guard show` for the finding details.",
            "Watch for canary / persistence trips by this image's pid.",
            nullptr,
            nullptr,
            nullptr,
            nullptr,
        },
        nullptr,
    },
};

constexpr u32 kEntryCount = sizeof(kEntries) / sizeof(kEntries[0]);

// EventKinds that intentionally have no runbook entry. Mode-change
// + bookkeeping events do not need follow-up — they're already
// the result of an operator decision OR are bookkeeping for the
// runbook itself.
constexpr EventKind kOptOut[] = {
    EventKind::None,
    EventKind::PolicyChanged,
    EventKind::GuardModeChanged,
    EventKind::PersistenceModeChanged,
    EventKind::BlockguardModeChanged,
    EventKind::AttackSimRun,
    EventKind::IrRunbookEmitted,
};
constexpr u32 kOptOutCount = sizeof(kOptOut) / sizeof(kOptOut[0]);

constinit IrRunbookStats g_stats{};
constinit sync::SpinLock g_stats_lock{};

bool IsOptedOut(EventKind k)
{
    for (u32 i = 0; i < kOptOutCount; ++i)
    {
        if (kOptOut[i] == k)
        {
            return true;
        }
    }
    return false;
}

} // namespace

const IrRunbookEntry* IrRunbookLookup(EventKind kind)
{
    for (u32 i = 0; i < kEntryCount; ++i)
    {
        if (kEntries[i].kind == kind)
        {
            return &kEntries[i];
        }
    }
    return nullptr;
}

void IrRunbookEmit(EventKind kind, u32 actor_pid)
{
    const IrRunbookEntry* entry = IrRunbookLookup(kind);
    {
        sync::SpinLockGuard guard{g_stats_lock};
        ++g_stats.emits_total;
        g_stats.last_kind = kind;
        g_stats.last_uptime_ns = time::MonotonicNs();
        if (entry == nullptr)
        {
            ++g_stats.missing_entries;
        }
    }

    if (entry == nullptr)
    {
        arch::SerialWrite("[ir] no runbook entry for kind=");
        arch::SerialWrite(EventKindName(kind));
        arch::SerialWrite(" — add one in ir_runbook.cpp\n");
        return;
    }

    arch::SerialWrite("[ir] ");
    arch::SerialWrite(entry->one_line_summary);
    arch::SerialWrite("\n");
    arch::SerialWrite("[ir]   ");
    arch::SerialWrite(entry->what_happened);
    arch::SerialWrite("\n");

    u32 step_idx = 1;
    for (u32 i = 0; i < kIrMaxSteps; ++i)
    {
        if (entry->steps[i] == nullptr)
        {
            break;
        }
        arch::SerialWrite("[ir]   ");
        // Render step number as a single ASCII digit (we never have
        // more than 6 steps).
        const char num[3] = {static_cast<char>('0' + step_idx), '.', ' '};
        arch::SerialWriteN(num, sizeof(num));
        arch::SerialWrite(entry->steps[i]);
        arch::SerialWrite("\n");
        ++step_idx;
    }

    if (entry->escalate_to != nullptr)
    {
        arch::SerialWrite("[ir]   escalate: ");
        arch::SerialWrite(entry->escalate_to);
        arch::SerialWrite("\n");
    }

    EventRingPublishKind(EventKind::IrRunbookEmitted, actor_pid, static_cast<u64>(kind), 0, EventKindName(kind));
}

IrRunbookStats IrRunbookStatsRead()
{
    sync::SpinLockGuard guard{g_stats_lock};
    return g_stats;
}

void IrRunbookSelfTest()
{
    u32 missing = 0;
    const u32 kind_count = static_cast<u32>(EventKind::Count);
    for (u32 i = 0; i < kind_count; ++i)
    {
        const EventKind k = static_cast<EventKind>(i);
        if (IsOptedOut(k))
        {
            continue;
        }
        if (IrRunbookLookup(k) == nullptr)
        {
            arch::SerialWrite("[ir] self-test FAIL: no entry for ");
            arch::SerialWrite(EventKindName(k));
            arch::SerialWrite("\n");
            ++missing;
        }
    }
    if (missing == 0)
    {
        arch::SerialWrite("[ir] self-test PASS (entries=");
        arch::SerialWriteHex(kEntryCount);
        arch::SerialWrite(")\n");
    }
    else
    {
        arch::SerialWrite("[ir] self-test FAIL: ");
        arch::SerialWriteHex(missing);
        arch::SerialWrite(" EventKind(s) without a runbook entry\n");
    }
}

} // namespace duetos::security
