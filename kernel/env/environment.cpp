#include "env/environment.h"

#include "acpi/acpi.h"
#include "acpi/acpi_sci.h"
#include "acpi/aml.h"
#include "acpi/aml_eval.h"
#include "acpi/ec.h"
#include "acpi/srat.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "core/panic.h"
#include "cpu/topology.h"
#include "debug/probes.h"
#include "drivers/power/power.h"
#include "env/autonomic.h"
#include "log/klog.h"
#include "mm/frame_allocator.h"
#include "sched/sched.h"
#include "sync/spinlock.h"

namespace duetos::env
{

namespace
{

// The published snapshot and its publish lock. `EnvironmentInit`
// composes the first value; the `env-monitor` task re-publishes on
// every poll. Readers take the lock and copy by value so a read
// never tears against a monitor write.
sync::SpinLock g_env_lock;
SystemEnvironment g_env{};

// The env-monitor blocks here. The ACPI SCI handler
// (`WaitQueueWakeOne`, IRQ-safe) wakes it on a power-management
// event so reaction is immediate instead of poll-latency-bounded.
sched::WaitQueue g_env_wq{};

// Monitor poll period. 100 Hz scheduler tick → 200 ticks ≈ 2 s.
// Power/thermal state does not change faster than a human plugs a
// charger or a fan spins up; a 2 s cadence reacts promptly while
// costing one wakeup every two seconds on an otherwise-idle box.
constexpr u64 kEnvMonitorIntervalTicks = 200;

/// Decimal serial helper. The banner is a structural sentinel
/// written via raw SerialWrite (so it survives klog level demotion
/// and the boot-log analyzer can grep it); serial.h only ships a
/// hex formatter, so a tiny base-10 writer lives here.
void WriteDec(u64 v)
{
    char buf[21]; // 2^64 is 20 digits + NUL
    u32 i = sizeof(buf);
    buf[--i] = '\0';
    if (v == 0)
    {
        buf[--i] = '0';
    }
    while (v != 0 && i != 0)
    {
        buf[--i] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    arch::SerialWrite(&buf[i]);
}

EnvPlatform DerivePlatform(arch::HypervisorKind kind)
{
    if (arch::IsBareMetal())
    {
        return EnvPlatform::BareMetal;
    }
    if (kind == arch::HypervisorKind::QemuTcg || kind == arch::HypervisorKind::Bochs)
    {
        return EnvPlatform::Emulated;
    }
    return EnvPlatform::Virtualized;
}

EnvFormFactor DeriveFormFactor(bool chassis_is_laptop, u32 cpu_total)
{
    if (chassis_is_laptop)
    {
        return EnvFormFactor::Laptop;
    }
    // Coarse heuristic: a non-laptop with a high core count is
    // almost always a server/workstation; everything else is a
    // desktop. Refine only when a consumer needs finer than this
    // (anti-bloat — no SMBIOS chassis-subtype decode until then).
    if (cpu_total >= 8)
    {
        return EnvFormFactor::Server;
    }
    return EnvFormFactor::Desktop;
}

bool AnyHybridCore()
{
    const u32 limit = arch::SmpCpuIdLimit();
    for (u32 id = 0; id < limit; ++id)
    {
        const cpu::Topology* t = cpu::TopologyForCpu(id);
        if (t != nullptr && t->core_class != cpu::kCoreClassUnknown)
        {
            return true;
        }
    }
    return false;
}

// Read every source into `e`. No lock — the underlying accessors
// are either boot-stable (hypervisor / CPU census / RAM / NUMA) or
// process-context-safe re-reads (PowerSnapshotRead re-samples the
// thermal MSRs and re-polls ACPI). Pure w.r.t. env's own state.
void Compose(SystemEnvironment& e)
{
    const arch::HypervisorInfo& hv = arch::HypervisorInfoGet();
    e.hv_kind = hv.kind;
    e.platform = DerivePlatform(hv.kind);

    e.cpu_total = static_cast<u32>(acpi::CpuCount());
    e.cpu_online = static_cast<u32>(arch::SmpCpusOnline());
    if (e.cpu_total == 0)
    {
        // No MADT census (shouldn't happen post-AcpiInit, but keep
        // the banner honest rather than printing 0/0).
        e.cpu_total = e.cpu_online;
    }
    e.cpu_hybrid = AnyHybridCore();

    e.ram_bytes = mm::TotalFrames() * mm::kPageSize;
    e.numa = acpi::srat::SratPresent();
    e.numa_nodes = e.numa ? static_cast<u32>(acpi::srat::SratNodeCount()) : 1u;

    const drivers::power::PowerSnapshot ps = drivers::power::PowerSnapshotRead();
    e.form_factor = DeriveFormFactor(ps.chassis_is_laptop, e.cpu_total);
    e.ac = ps.ac;
    e.battery_state = ps.battery.state;
    e.battery_percent = (ps.battery.state == drivers::power::kBatNotPresent) ? 255 : ps.battery.percent;
    e.lid_present = ps.lid_present;
    e.lid_open = ps.lid_open;
    e.cpu_temp_c = ps.cpu_temp_c;
    e.pkg_temp_c = ps.package_temp_c;
    e.thermal_throttle = ps.thermal_throttle_hit;

    e.power_policy = EnvironmentDerivePolicy(e);
    e.valid = true;
}

// Observable-field equality. A dedicated comparison (rather than a
// memcmp over padding) keeps "what counts as a change" explicit —
// the monitor only logs / probes on a field a consumer can act on.
bool SameObservable(const SystemEnvironment& a, const SystemEnvironment& b)
{
    return a.platform == b.platform && a.cpu_online == b.cpu_online && a.cpu_total == b.cpu_total &&
           a.cpu_hybrid == b.cpu_hybrid && a.ram_bytes == b.ram_bytes && a.numa == b.numa &&
           a.numa_nodes == b.numa_nodes && a.form_factor == b.form_factor && a.ac == b.ac &&
           a.battery_state == b.battery_state && a.battery_percent == b.battery_percent &&
           a.lid_present == b.lid_present && a.lid_open == b.lid_open && a.cpu_temp_c == b.cpu_temp_c &&
           a.pkg_temp_c == b.pkg_temp_c && a.thermal_throttle == b.thermal_throttle && a.power_policy == b.power_policy;
}

void EmitBanner(const SystemEnvironment& e)
{
    arch::SerialWrite("[env] platform=");
    if (e.platform == EnvPlatform::BareMetal)
    {
        arch::SerialWrite("bare-metal");
    }
    else
    {
        arch::SerialWrite(arch::HypervisorName(e.hv_kind));
    }

    arch::SerialWrite(" cpu=");
    WriteDec(e.cpu_online);
    arch::SerialWrite("/");
    WriteDec(e.cpu_total);
    if (e.cpu_hybrid)
    {
        arch::SerialWrite("(hybrid)");
    }

    arch::SerialWrite(" ram=");
    WriteDec(e.ram_bytes >> 20);
    arch::SerialWrite("MiB mem=");
    if (e.numa)
    {
        arch::SerialWrite("NUMA(n");
        WriteDec(e.numa_nodes);
        arch::SerialWrite(")");
    }
    else
    {
        arch::SerialWrite("UMA");
    }

    arch::SerialWrite(" form=");
    arch::SerialWrite(EnvFormFactorName(e.form_factor));

    arch::SerialWrite(" pwr=");
    arch::SerialWrite(drivers::power::AcStateName(e.ac));
    arch::SerialWrite(" batt=");
    if (e.battery_percent == 255)
    {
        arch::SerialWrite("n/a");
    }
    else
    {
        WriteDec(e.battery_percent);
        arch::SerialWrite("%");
    }

    arch::SerialWrite(" temp=");
    if (e.cpu_temp_c == 0)
    {
        arch::SerialWrite("n/a");
    }
    else
    {
        WriteDec(e.cpu_temp_c);
        arch::SerialWrite("C");
    }

    arch::SerialWrite(" policy=");
    arch::SerialWrite(EnvPowerPolicyName(e.power_policy));
    arch::SerialWrite("\n");
}

[[noreturn]] void EnvMonitorMain(void*)
{
    // Install the SCI service now: scheduler is online (we are a
    // task) and the IOAPIC is up by the devices phase. It wakes
    // g_env_wq on a power-management interrupt.
    acpi::AcpiSciInit(&g_env_wq);

    for (;;)
    {
        // Block until the SCI handler wakes us OR the poll period
        // elapses. Same interrupt contract as the reaper: hold
        // interrupts off across the block call, restore after.
        arch::Cli();
        (void)sched::WaitQueueBlockTimeout(&g_env_wq, kEnvMonitorIntervalTicks);
        arch::Sti();

        const acpi::SciPending sp = acpi::AcpiSciTakePending();
        if (sp.power_button)
        {
            // The power/sleep button is a request to shut down.
            // AcpiShutdown evaluates `\_S5` AML — legal here
            // (task/process context). On QEMU this exits the
            // guest; if it returns (no `\_S5`, missing PM1) we
            // keep monitoring rather than spin.
            // Raw structural sentinel (terminal, rare): the
            // boot-log analyzer + the power-button smoke gate on
            // this; a redundant KLOG line would just double it.
            arch::SerialWrite("[env/sci] power button -> ACPI shutdown\n");
            (void)acpi::AcpiShutdown();
        }

        // Any GPE that fired could be the EC's GPE (the firmware
        // maps it; the bit position varies per board). Drain the
        // EC's pending-query queue unconditionally on any GPE
        // status — the EC silently returns "no event pending" if
        // CMD_QUERY had nothing for it, so a spurious drain has
        // no visible effect. Bounded loop (16 iterations) caps
        // worst-case time spent here under a wedged EC that keeps
        // re-arming SCI_EVT. Most boards burst a small handful
        // (lid close + AC unplug at the same instant might emit
        // two or three queries in sequence).
        //
        // Architecturally: this is the v0 stand-in for the full
        // GPE dispatch worker. A proper implementation would
        // (a) consult the per-GPE namespace lookup to identify
        // the EC's GPE bit specifically, and (b) walk every
        // OTHER set bit through `\_GPE._Lxx`/`\_GPE._Exx`
        // evaluation. v0 only handles the EC-routed events
        // because they're the ones a laptop actually depends on
        // (lid, AC, battery); other GPEs are firmware-bug-rare
        // and harmless when not dispatched.
        if (sp.gpe0_status != 0 || sp.gpe1_status != 0)
        {
            for (u32 drain = 0; drain < 16; ++drain)
            {
                if (!acpi::AcpiEcDispatchPendingQuery())
                    break;
            }
            // Per-GPE _Lxx (level-triggered) / _Exx (edge-triggered)
            // dispatch for events not routed through the EC. The
            // status word covers up to 32 GPEs (in each of GPE0
            // and GPE1 blocks); we walk every set bit and try
            // both naming forms. ACPI 6.5 §5.6.4.1 fixes the
            // names: `\_GPE._Lxx` for level-triggered events,
            // `\_GPE._Exx` for edge-triggered. Most boards only
            // emit one or the other per bit; trying both is
            // harmless when one doesn't exist (AmlNamespaceFind
            // returns nullptr and we skip).
            auto dispatch_gpe_bits = [](u32 status, u32 base)
            {
                for (u32 bit = 0; bit < 32u; ++bit)
                {
                    if ((status & (1u << bit)) == 0)
                        continue;
                    const u32 gpe = base + bit;
                    // Build `\_GPE._Lxx` / `\_GPE._Exx`. 2 hex
                    // digits (uppercase) per ACPI naming.
                    char name[12];
                    name[0] = '\\';
                    name[1] = '_';
                    name[2] = 'G';
                    name[3] = 'P';
                    name[4] = 'E';
                    name[5] = '.';
                    name[6] = '_';
                    static const char kHex[] = "0123456789ABCDEF";
                    name[8] = kHex[(gpe >> 4) & 0xFu];
                    name[9] = kHex[gpe & 0xFu];
                    name[10] = '\0';

                    static const char kTriggerForms[2] = {'L', 'E'};
                    for (u32 form = 0; form < 2; ++form)
                    {
                        name[7] = kTriggerForms[form];
                        if (acpi::AmlNamespaceFind(name) == nullptr)
                            continue;
                        acpi::AmlValue r;
                        if (!acpi::AmlEvaluate(name, nullptr, 0, &r).has_value())
                        {
                            KLOG_WARN_V("env/sci", "GPE method evaluation failed; bit", gpe);
                        }
                        // First match wins — a single GPE never
                        // has both _Lxx and _Exx (the firmware
                        // chooses based on the hardware trigger
                        // mode).
                        break;
                    }
                }
            };
            dispatch_gpe_bits(sp.gpe0_status, 0);
            // GPE1 starts at `FADT.Gpe1Base` per ACPI 6.5
            // §5.2.9. The PM1 block does not expose this to us
            // through the existing `acpi.h` accessors; default
            // to 32 (the common "GPE0 holds 0..31, GPE1 holds
            // 32..63" layout). A future slice that wires
            // `FADT.gpe1_base` correctly would replace the
            // constant; for now the worst case is mis-named
            // method lookups that miss in the namespace and
            // are skipped silently.
            dispatch_gpe_bits(sp.gpe1_status, 32);
        }

        // AC / lid / thermal may have moved (the SCI woke us, or
        // the poll period elapsed). Recompose picks it up and
        // republishes + logs/probes on a policy transition.
        (void)EnvironmentRecompose();

        // Sense → decide → ACT. The autonomic engine runs every
        // poll (memory / CPU / security conditions move without an
        // observable env-field change, so it cannot hang off the
        // recompose-changed branch). It reads its own telemetry and
        // the freshly published env snapshot.
        AutonomicTick();
    }
}

} // namespace

EnvPowerPolicy EnvironmentDerivePolicy(const SystemEnvironment& e)
{
    // Thermal pressure trumps everything — back off regardless of
    // power source or form factor.
    if (e.thermal_throttle)
    {
        return EnvPowerPolicy::PowerSave;
    }
    // On battery: conserve.
    if (e.ac == drivers::power::kAcOffline)
    {
        return EnvPowerPolicy::PowerSave;
    }
    // Under a VMM/emulator the host owns real power management; a
    // balanced policy avoids fighting it and avoids spin-heavy
    // perf assumptions that punish a contended host.
    if (e.platform != EnvPlatform::BareMetal)
    {
        return EnvPowerPolicy::Balanced;
    }
    // Bare-metal laptop on AC: balanced (thermals/fan-noise matter
    // even when plugged in). Server/desktop on AC: full performance.
    if (e.form_factor == EnvFormFactor::Laptop)
    {
        return EnvPowerPolicy::Balanced;
    }
    return EnvPowerPolicy::Performance;
}

void EnvironmentInit()
{
    SystemEnvironment e{};
    Compose(e);
    {
        sync::SpinLockGuard g(g_env_lock);
        g_env = e;
    }
    EmitBanner(e);
}

bool EnvironmentRecompose()
{
    SystemEnvironment n{};
    Compose(n);

    SystemEnvironment prev{};
    bool changed;
    {
        sync::SpinLockGuard g(g_env_lock);
        prev = g_env;
        changed = !SameObservable(prev, n);
        g_env = n;
    }

    if (!changed)
    {
        return false;
    }

    // A power-policy transition is a normal, legitimate state
    // change — INFO, not WARN (a WARN here would flood on every
    // unplug; see CLAUDE.md "log-level abuse"). The probe is
    // ArmedLog so a clean boot stays quiet but a real transition
    // leaves a GDB-breakable sentinel.
    if (prev.power_policy != n.power_policy)
    {
        KLOG_INFO_S("env", "power policy changed", "to", EnvPowerPolicyName(n.power_policy));
        KLOG_DEBUG_S("env", "previous power policy", "from", EnvPowerPolicyName(prev.power_policy));
        const u64 packed = (static_cast<u64>(prev.power_policy) << 8) | static_cast<u64>(n.power_policy);
        KBP_PROBE_V(debug::ProbeId::kEnvPolicyChange, packed);
    }
    else
    {
        KLOG_INFO("env", "environment changed (policy unchanged)");
    }
    KLOG_DEBUG_V("env", "ac state", static_cast<u64>(n.ac));
    KLOG_DEBUG_V("env", "cpu temp C", n.cpu_temp_c);
    KLOG_DEBUG_V("env", "battery percent", n.battery_percent);
    return true;
}

void EnvironmentMonitorStart()
{
    {
        sync::SpinLockGuard g(g_env_lock);
        KASSERT(g_env.valid, "env", "EnvironmentMonitorStart before EnvironmentInit");
    }
    sched::SchedCreate(&EnvMonitorMain, nullptr, "env-monitor");
    KLOG_INFO("env", "environment monitor online");
}

SystemEnvironment EnvironmentGet()
{
    sync::SpinLockGuard g(g_env_lock);
    return g_env;
}

EnvPowerPolicy EnvironmentPowerPolicy()
{
    sync::SpinLockGuard g(g_env_lock);
    return g_env.power_policy;
}

const char* EnvPlatformName(EnvPlatform p)
{
    switch (p)
    {
    case EnvPlatform::BareMetal:
        return "bare-metal";
    case EnvPlatform::Virtualized:
        return "virtualized";
    case EnvPlatform::Emulated:
        return "emulated";
    }
    return "unknown";
}

const char* EnvFormFactorName(EnvFormFactor f)
{
    switch (f)
    {
    case EnvFormFactor::Server:
        return "server";
    case EnvFormFactor::Desktop:
        return "desktop";
    case EnvFormFactor::Laptop:
        return "laptop";
    case EnvFormFactor::Unknown:
        return "unknown";
    }
    return "unknown";
}

const char* EnvPowerPolicyName(EnvPowerPolicy p)
{
    switch (p)
    {
    case EnvPowerPolicy::Performance:
        return "performance";
    case EnvPowerPolicy::Balanced:
        return "balanced";
    case EnvPowerPolicy::PowerSave:
        return "powersave";
    }
    return "unknown";
}

void EnvironmentSelfTest()
{
    const SystemEnvironment e = EnvironmentGet();

    KASSERT(e.valid, "env", "EnvironmentInit did not run before self-test");
    KASSERT(e.cpu_online >= 1, "env", "online CPU census is zero");
    KASSERT(e.cpu_total >= e.cpu_online, "env", "total CPUs < online CPUs");

    // The invariant the monitor relies on: the cached policy is
    // exactly what the pure derivation yields for the snapshot.
    KASSERT(EnvironmentPowerPolicy() == EnvironmentDerivePolicy(e), "env",
            "cached power policy diverged from derivation");

    // Exercise the derivation matrix the monitor will drive on
    // every poll, against synthetic snapshots. Start from a known
    // base (bare-metal desktop on AC, no thermal pressure) and
    // perturb one axis at a time.
    SystemEnvironment s{};
    s.platform = EnvPlatform::BareMetal;
    s.form_factor = EnvFormFactor::Desktop;
    s.ac = drivers::power::kAcOnline;
    s.thermal_throttle = false;
    KASSERT(EnvironmentDerivePolicy(s) == EnvPowerPolicy::Performance, "env", "baremetal desktop+AC must be perf");

    s.ac = drivers::power::kAcOffline; // unplug
    KASSERT(EnvironmentDerivePolicy(s) == EnvPowerPolicy::PowerSave, "env", "on-battery must be powersave");

    s.ac = drivers::power::kAcOnline;
    s.thermal_throttle = true; // throttle trumps AC
    KASSERT(EnvironmentDerivePolicy(s) == EnvPowerPolicy::PowerSave, "env", "thermal throttle must be powersave");

    s.thermal_throttle = false;
    s.form_factor = EnvFormFactor::Laptop; // laptop on AC
    KASSERT(EnvironmentDerivePolicy(s) == EnvPowerPolicy::Balanced, "env", "laptop+AC must be balanced");

    s.form_factor = EnvFormFactor::Server;
    s.platform = EnvPlatform::Virtualized; // host owns PM
    KASSERT(EnvironmentDerivePolicy(s) == EnvPowerPolicy::Balanced, "env", "virtualized must be balanced");

    // Recompose end-to-end: it must keep the cached==derived
    // invariant intact regardless of whether anything changed
    // between init and now (no idempotence claim — real hardware
    // temp jitter can legitimately move a field).
    (void)EnvironmentRecompose();
    const SystemEnvironment after = EnvironmentGet();
    KASSERT(EnvironmentPowerPolicy() == EnvironmentDerivePolicy(after), "env",
            "recompose left cached policy inconsistent");

    arch::SerialWrite("[env-selftest] PASS\n");
}

} // namespace duetos::env
