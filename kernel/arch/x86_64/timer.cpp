#include "arch/x86_64/timer.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/ioapic.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/nmi_watchdog.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/traps.h"

#include "acpi/acpi.h"
#include "core/panic.h"
#include "debug/probes.h"
#include "diag/boot_observe.h"
#include "diag/fix_journal.h"
#include "log/klog.h"
#include "sched/sched.h"

namespace duetos::arch
{

namespace
{

// PIT runs at this nominal frequency on every PC since IBM XT.
constexpr u64 kPitHz = 1193182;

// Calibration interval. 10 ms gives a good signal/noise ratio against the
// PIT's 838 ns granularity, and avoids overflowing the 32-bit LAPIC count
// register on any reasonable CPU (would need a 429 GHz LAPIC to overflow).
constexpr u64 kCalibrationMs = 10;
constexpr u64 kCalibrationCount = (kPitHz * kCalibrationMs) / 1000; // 11932

// LAPIC timer divide configuration: bits 0,1,3 form the exponent. 0b0011
// (= 0x3) divides the bus clock by 16 — a good middle ground that keeps
// the count register in a useful range without sacrificing resolution.
constexpr u32 kLapicTimerDivBy16 = 0x3;

// LVT Timer register layout (Intel SDM Vol. 3A §10.5.1):
//   bits 7:0   vector
//   bit  16    mask (1 = masked)
//   bits 18:17 mode (00 one-shot, 01 periodic, 10 TSC-deadline)
constexpr u32 kLvtTimerMaskBit = 1U << 16;
constexpr u32 kLvtTimerPeriodicBit = 1U << 17;

// PIT control / data ports.
constexpr u16 kPitControlPort = 0x43;
constexpr u16 kPitChannel2Port = 0x42;
constexpr u16 kPitGatePort = 0x61;
constexpr u8 kPitChan2Mode0 = 0xB0; // chan 2 | lobyte/hibyte | mode 0 | binary
constexpr u8 kPitGateOut2Mask = 1U << 5;

// Channel 0 — the PIT-tick-fallback source (see
// TimerVerifyDeliveryOrFallback). Channel 0's OUT is hardwired to
// ISA IRQ 0; no gate port. Mode 3 (square wave) is the conventional
// periodic-tick mode. The calibration path above uses channel 2 in
// mode 0 and never touches channel 0, so there is no conflict.
constexpr u16 kPitChannel0Port = 0x40;
constexpr u8 kPitChan0Mode3 = 0x36;                                         // chan 0 | lobyte/hibyte | mode 3 | binary
constexpr u16 kPitCh0Divisor = static_cast<u16>(kPitHz / kTickFrequencyHz); // ~11931 @ 100 Hz

// Single-CPU world: the IRQ handler runs on the same core as any reader,
// so a plain u64 is fine — 8-byte loads are atomic on x86_64 and the
// handler can't race with itself. SMP bring-up will swap this for
// std::atomic<u64> (or __atomic_fetch_add) and the read accessor below
// will become an acquire load.
//
// `volatile` here is load-bearing under LTO + -O3: without it the
// optimizer can hoist `g_ticks` out of any spin loop that doesn't
// otherwise touch state the IRQ handler writes to (e.g. the wireless
// MLME scan-wait loop in `MlmeScanAndWait`). The IRQ handler's
// `++g_ticks;` is the only writer; the volatile keeps every reader
// observing the fresh value across loop iterations.
constinit volatile u64 g_ticks = 0;
constinit u64 g_lapic_ticks_per_period = 0;

// Set true by TimerVerifyDeliveryOrFallback when the LAPIC timer is
// armed but its IRQ is never delivered (observed under VirtualBox:
// the timer counts down but the underflow interrupt is not raised),
// and the scheduler tick has been switched to the IOAPIC-routed PIT
// channel-0 periodic source instead. Read by LapicTimerStartOnCurrent
// to avoid arming a known-dead LVT on APs.
constinit bool g_pit_fallback_active = false;

// Init-wedge watchdog state. The timer IRQ samples the running serial
// byte count at every 5 s heartbeat and compares to the previous
// sample. If the only progress between samples is the heartbeat line
// itself (~50 bytes), `g_silent_heartbeats` ticks up. Three silent
// heartbeats in a row (= ~15 s with no init progress) fires the
// `boot.init_wedge` probe and a one-shot warning so an attached
// debugger / CI grep catches a wedged xHCI bringup, deadlocked spin,
// non-responding MMIO poll, etc.
//
// Disarmed after `g_init_complete` flips to true at the end of
// `RunPhase(Userland)`. Steady-state quiet windows (compositor naps,
// idle loop) shouldn't trip it.
constinit u64 g_last_progress_byte_count = 0;
constinit u32 g_silent_heartbeats = 0;
constinit bool g_init_complete = false;
constinit bool g_wedge_warned = false;
constinit u32 g_wedge_panic_threshold = 0; // 0 = warn-only; >0 = panic after N silent heartbeats
constexpr u32 kWedgeSilentHeartbeatsThreshold = 3;
constexpr u64 kWedgeBytesIgnore = 96; // length of "[tick-irq] g_ticks=0x...\n" plus slack

void TimerHandler()
{
    // C++23 deprecates `++x;` on a volatile object; do the load/add/store
    // explicitly. Single-CPU, IRQ-handler-only writer, so there's no race
    // with a concurrent writer — the volatile is purely to prevent the
    // compiler from caching reads in spin loops elsewhere.
    g_ticks = g_ticks + 1;
    // Pet the NMI watchdog. If this handler ever stops firing,
    // the watchdog's PMU overflow will catch it via NMI even
    // while IF is cleared. Cheap (single store) so it stays in
    // the hot path unconditionally — the watchdog disables
    // itself internally when the PMU is unavailable.
    NmiWatchdogPet();
    sched::OnTimerTick(g_ticks);

    // VirtualBox PIT-tick fallback: the LAPIC timer never delivers, so
    // APs were left with no timer of their own and PIT IRQ0 reaches
    // only the BSP — meaning only the BSP runs this handler. Broadcast
    // a per-CPU tick to every online AP so they get CPU-time accounting
    // (sysmon's per-core bars) and, crucially, preemption. Gated on the
    // fallback flag: on a healthy boot every AP runs its own
    // LAPIC-timer TimerHandler, so broadcasting would double-count.
    if (g_pit_fallback_active && SmpCpusOnline() > 1)
    {
        SmpBroadcastApTimerTick();
    }

    // Liveness heartbeat at 1 Hz. Debug-level so a release preset's
    // kKlogMinLevel filter can drop the per-second spam while still
    // leaving the full trace available during driver-bring-up debug.
    // The kheartbeat thread (every 5 s) gives the richer stats view.
    if ((g_ticks % kTickFrequencyHz) == 0)
    {
        core::LogWithValue(core::LogLevel::Debug, "arch/timer", "tick", g_ticks);
    }
    // ALSO emit an unfiltered direct-serial heartbeat so a CI
    // failure log shows whether the timer kept firing during a
    // wedge. The kheartbeat scheduler thread depends on the
    // scheduler being healthy; this depends only on timer IRQs
    // being delivered. If the smoke task hangs but [tick-irq]
    // keeps printing, the timer is alive and the wedge is in
    // task wakeup. If [tick-irq] also stops, IRQs themselves
    // were disabled or the LAPIC stopped.
    //
    // Period is 5 s rather than 1 s. The UART is the dominant
    // slow path under QEMU TCG (~50 us per character), and 30+
    // bytes/second of heartbeat-only traffic measurably extends
    // boot. 5 s still resolves a wedge well within any
    // human-noticed timeout, and matches the kheartbeat thread's
    // own 5 s cadence so the two complementary signals interleave
    // predictably. Real-hardware boots aren't UART-bound so the
    // lower cadence costs them nothing.
    constexpr u64 kRawHeartbeatPeriodTicks = 5U * kTickFrequencyHz;
    if ((g_ticks % kRawHeartbeatPeriodTicks) == 0)
    {
        // Sample serial-byte progress BEFORE writing the heartbeat
        // so the delta we measure excludes the heartbeat itself.
        const u64 byte_count_before = SerialBytesWritten();

        SerialWrite("[tick-irq] g_ticks=");
        SerialWriteHex(g_ticks);
        SerialWrite("\n");

        // Init-wedge watchdog. Compares the byte count at this
        // heartbeat with the previous heartbeat. If the delta is
        // small enough that ONLY the previous heartbeat itself
        // contributed (i.e. nothing else logged in the past 5 s),
        // count a silent interval. Three consecutive silent
        // intervals fires the boot.init_wedge probe — at that
        // point ~15 s have passed with the timer running but no
        // init progress, which on every driver bring-up path we
        // care about means "wedged, not just slow".
        if (!g_init_complete)
        {
            const u64 delta = byte_count_before - g_last_progress_byte_count;
            if (delta <= kWedgeBytesIgnore)
            {
                ++g_silent_heartbeats;
                if (g_silent_heartbeats >= kWedgeSilentHeartbeatsThreshold && !g_wedge_warned)
                {
                    g_wedge_warned = true;
                    SerialWrite("[init-wedge] WARN: no boot progress for ");
                    SerialWriteHex(g_silent_heartbeats * 5);
                    SerialWrite(" s while timer IRQ kept firing. "
                                "Last progress at byte count=");
                    SerialWriteHex(g_last_progress_byte_count);
                    SerialWrite(", current=");
                    SerialWriteHex(byte_count_before);
                    SerialWrite("\n");
                    duetos::debug::ProbeFire(duetos::debug::ProbeId::kBootInitWedge, 0, g_silent_heartbeats * 5);
                    // Attribute the wedge to the boot phase that was
                    // active and, under a smoke profile, fail fast
                    // with the structured HungInPhase exit code. This
                    // rides the existing, env-independent
                    // no-serial-progress heuristic — no second
                    // watchdog, no wall-clock budget to false-fire on
                    // a chatty-but-slow phase under TCG.
                    ::duetos::diag::BootWatchdogOnWedge();
                }
                // Escalation: if the operator armed the panic path
                // via `init-wedge-panic=<N>` on the kernel cmdline,
                // the watchdog turns from advisory into a hard fault
                // once `N` silent heartbeats have passed. Useful for
                // CI: leave default (warn only), turn on for fuzz
                // / stress runs that need an unambiguous failure.
                if (g_wedge_panic_threshold > 0 && g_silent_heartbeats >= g_wedge_panic_threshold)
                {
                    SerialWrite("[init-wedge] PANIC: silent_heartbeats=");
                    SerialWriteHex(g_silent_heartbeats);
                    SerialWrite(" >= configured panic threshold ");
                    SerialWriteHex(g_wedge_panic_threshold);
                    SerialWrite("\n");
                    duetos::core::Panic("init-wedge", "boot init wedged");
                }
            }
            else
            {
                g_silent_heartbeats = 0;
                g_wedge_warned = false;
            }
            g_last_progress_byte_count = byte_count_before;
        }
    }

    // Request a reschedule on every tick. The IRQ dispatcher consults this
    // flag (and clears it) AFTER sending EOI, so we don't context-switch
    // away with the LAPIC in-service bit still set for this vector.
    sched::SetNeedResched();
}

// Spin until the PIT channel 2 OUT line goes high (terminal count reached
// in mode 0). Returns true on success, false if the bounded TSC budget
// expired before OUT went high.
//
// Real-hardware hardening: many modern UEFI machines (Tiger Lake server
// boards, Apple Mac via Boot Camp, recent Chromebooks) ship with no
// working legacy PIT. Without a bound on this poll the kernel hangs
// indefinitely during LAPIC timer calibration on first boot. We use
// TSC (which is guaranteed by the minimum-feature gate) for the
// deadline rather than HPET, because TimerInit runs before HpetInit,
// and we don't want to add a circular bring-up dependency.
//
// 100 ms is comfortably 10x the expected 10 ms PIT countdown — anything
// over that and the PIT is broken/absent.
bool WaitPitTerminal()
{
    // Read TSC. The minimum-feature gate has confirmed TSC is
    // present on this CPU, so this is safe.
    const u64 tsc_start = TscRead();
    // Worst-case modern CPU is ~5 GHz; pick 1 GHz cycles-per-ms as a
    // floor that won't false-fire on slow CPUs (gives ~500 ms wall
    // time at 1 GHz, ~100 ms at 5 GHz — both safely > the 10 ms PIT
    // calibration window).
    constexpr u64 kPitTimeoutCycles = 500ULL * 1000ULL * 1000ULL;
    while ((Inb(kPitGatePort) & kPitGateOut2Mask) == 0)
    {
        const u64 tsc_now = TscRead();
        if (tsc_now - tsc_start > kPitTimeoutCycles)
        {
            return false;
        }
        // pause hints to the CPU that we're in a spinwait — drops
        // power consumption and reduces memory-ordering pipeline
        // stalls when the loop exits.
        asm volatile("pause" ::: "memory");
    }
    return true;
}

// Drive PIT channel 2 in mode 0 (one-shot, OUT goes high at terminal
// count) so we can poll for a known interval without an IRQ. Returns the
// LAPIC current count at the moment OUT2 went high.
u32 CalibrateLapicTimer()
{
    // Enable channel 2 gate, disable speaker. Bit 0 = gate, bit 1 = speaker.
    const u8 gate = (Inb(kPitGatePort) & 0xFC) | 0x01;
    Outb(kPitGatePort, gate);

    // Program channel 2: mode 0, lobyte/hibyte, binary. Mode 0 holds OUT
    // low after the count is loaded and raises OUT to high at terminal
    // count — exactly what we want to poll on.
    Outb(kPitControlPort, kPitChan2Mode0);

    // Configure LAPIC timer: divide-by-16, masked, periodic-cleared. We
    // start it counting just below by writing the initial-count register.
    LapicWrite(kLapicRegTimerDivide, kLapicTimerDivBy16);
    LapicWrite(kLapicRegLvtTimer, kLvtTimerMaskBit | kTimerVector);

    // Load PIT count low byte, then high byte. Loading the high byte
    // commits the count and (re-)starts the channel.
    Outb(kPitChannel2Port, static_cast<u8>(kCalibrationCount & 0xFF));
    Outb(kPitChannel2Port, static_cast<u8>((kCalibrationCount >> 8) & 0xFF));

    // Start the LAPIC timer immediately by writing a max initial count.
    // From this point on, both clocks are running; the difference between
    // PIT-go and LAPIC-go is one I/O write of latency.
    LapicWrite(kLapicRegTimerInit, 0xFFFFFFFFU);

    const bool pit_ok = WaitPitTerminal();

    // Stop the LAPIC timer ASAP and read the residual count.
    LapicWrite(kLapicRegLvtTimer, kLvtTimerMaskBit);
    const u32 residual = LapicRead(kLapicRegTimerCount);
    if (!pit_ok)
    {
        // The PIT never raised OUT2 within our TSC budget. Either
        // the firmware reports no PIT (FADT IAPC_BOOT_ARCH bit 4 set),
        // the chipset has gated the PIT off, or the gate-port write
        // didn't take. Real-hardware fallback: return a synthetic
        // calibration value derived from a known-safe rate so the
        // LAPIC timer starts ticking at a coarse-but-correct cadence.
        // The downstream tick rate will be wrong by an order of
        // magnitude on some hardware, but the box BOOTS — far better
        // than the previous "hang here forever" behaviour. A future
        // slice should re-calibrate against HPET once HpetInit runs.
        SerialWrite("[arch/timer] WARN: PIT calibration timed out — using fallback estimate\n");
        // 100 MHz bus / 16 divider = 6.25 MHz LAPIC ticks; over 10 ms
        // that's 62500 ticks. Picked to be in the right order of
        // magnitude for any commodity CPU.
        return 62500;
    }
    return 0xFFFFFFFFU - residual;
}

// Switch the scheduler tick off the (non-delivering) LAPIC timer and
// onto PIT channel 0 in periodic mode, routed through the IOAPIC as
// ISA IRQ 0 to kTimerVector — the SAME vector TimerHandler is already
// installed on (TimerInit's IrqInstall), so the handler, LAPIC EOI,
// and preemption path in TrapDispatch are entirely unchanged; only
// the interrupt *source* differs. Order matters: mask the LVT first
// so the two sources can't both target kTimerVector during the
// switch (on the VBox failure path the LVT never delivers anyway,
// but stay correct for any platform).
void StartPitPeriodicTickFallback()
{
    // 1. Silence the LAPIC timer LVT (it was counting but never
    //    delivering; mask it so it's unambiguously not a source).
    LapicWrite(kLapicRegLvtTimer, kLvtTimerMaskBit | kTimerVector);

    // 2. Program PIT channel 0: mode 3 (square wave), lobyte then
    //    hibyte. Writing the high byte commits the count and starts
    //    periodic counting; OUT0 is hardwired to ISA IRQ 0.
    Outb(kPitControlPort, kPitChan0Mode3);
    Outb(kPitChannel0Port, static_cast<u8>(kPitCh0Divisor & 0xFF));
    Outb(kPitChannel0Port, static_cast<u8>((kPitCh0Divisor >> 8) & 0xFF));

    // 3. Route ISA IRQ 0 through the IOAPIC to kTimerVector. Passing
    //    isa_irq=0 lets IoApicRoute honour any MADT "IRQ0→GSI2"
    //    override and pick the right polarity/trigger; it unmasks the
    //    pin itself. Same recipe ps2mouse uses for ISA IRQ 12.
    const u32 gsi = acpi::IsaIrqToGsi(0);
    // IOAPIC RTE physical destination is an 8-bit APIC ID in both
    // xAPIC and x2APIC (the IOAPIC itself is not x2APIC unless
    // interrupt-remapping is on, which we don't use), so take the
    // low 8 bits of the mode-normalised ID.
    const u8 bsp_id = static_cast<u8>(LapicCurrentId());
    IoApicRoute(gsi, kTimerVector, bsp_id, /*isa_irq=*/0);

    g_pit_fallback_active = true;
    KLOG_WARN("arch/timer", "LAPIC timer IRQ not delivered in verify window — "
                            "scheduler tick switched to IOAPIC-routed PIT ch0 periodic");
}

} // namespace

void TimerInit()
{
    KLOG_TRACE_SCOPE("arch/timer", "TimerInit");
    // Calibration must run with interrupts disabled — the PIT poll uses
    // CPU cycles for an accurate window. Caller is responsible for the
    // overall IRQ-disabled bring-up; we assert by checking RFLAGS.IF
    // would be too noisy. Document and trust the call order instead.
    const u32 ticks_per_period = CalibrateLapicTimer();
    g_lapic_ticks_per_period = ticks_per_period;

    // Convert calibration window (10 ms) to the desired period.
    const u64 ticks_per_kernel_tick = (static_cast<u64>(ticks_per_period) * 1000) / (kCalibrationMs * kTickFrequencyHz);

    core::LogWithValue(core::LogLevel::Info, "arch/timer", "calibrated lapic_ticks/10ms", ticks_per_period);
    core::LogWithValue(core::LogLevel::Info, "arch/timer", "ticks_per_kernel_tick", ticks_per_kernel_tick);

    // Install handler before unmasking the LVT — otherwise the very first
    // IRQ would land on a null handler and emit an "unhandled vector"
    // diagnostic at line rate.
    IrqInstall(kTimerVector, TimerHandler);

    // Configure periodic mode at the calibrated count. Writing the initial
    // count register starts the timer counting down; on each underflow it
    // both raises an IRQ and reloads from the initial-count value.
    LapicWrite(kLapicRegTimerDivide, kLapicTimerDivBy16);
    LapicWrite(kLapicRegLvtTimer, kLvtTimerPeriodicBit | kTimerVector);
    LapicWrite(kLapicRegTimerInit, static_cast<u32>(ticks_per_kernel_tick));

    core::LogWithValue(core::LogLevel::Info, "arch/timer", "periodic LAPIC timer armed, vector", kTimerVector);
}

void TimerVerifyDeliveryOrFallback()
{
    // Must run with interrupts LIVE and AFTER TimerInit armed the
    // LAPIC timer (TimerInit itself runs IRQs-off during calibration,
    // so it cannot observe delivery). Snapshot the tick counter, wait
    // a fixed wall window, and re-check: if it never advanced, the
    // LAPIC timer is armed-but-not-delivering (VirtualBox) and we
    // switch the tick to the PIT. No-op on QEMU / real hardware.
    //
    // The wall reference is PIT channel 2 (mode-0 one-shot), NOT the
    // TSC. Under QEMU TCG the TSC is decoupled from wall time, so a
    // TSC-cycle window can elapse in far less than one 10 ms tick
    // period and produce a FALSE fallback on a perfectly healthy
    // timer. The PIT is the one clock proven reliable on every
    // platform we run — LAPIC calibration already depends on it and
    // succeeds on both QEMU and VirtualBox — so it is the correct
    // independent reference here. `WaitPitTerminal` keeps its own
    // large TSC backstop so a (separately-handled) absent PIT can't
    // hang this.
    constexpr u64 kRflagsIf = 1ULL << 9;
    if ((ReadRflags() & kRflagsIf) == 0)
    {
        // Defensive: the documented call site runs with IRQs on, but
        // a dead timer is unrecoverable if we also spin with IF=0.
        Sti();
    }

    const u64 ticks_before = g_ticks;

    // Arm PIT channel 2 (mode 0, one-shot) for ~50 ms — five 100 Hz
    // tick periods, comfortably long for a delivering timer to bump
    // g_ticks at least once. 50 ms = 59659 PIT counts, inside the
    // 16-bit channel. Same gate/control sequence CalibrateLapicTimer
    // uses; calibration has long finished so channel 2 is free.
    constexpr u16 kVerifyPitCount = static_cast<u16>((kPitHz * 50) / 1000); // ~50 ms
    const u8 gate = static_cast<u8>((Inb(kPitGatePort) & 0xFC) | 0x01);
    Outb(kPitGatePort, gate);
    Outb(kPitControlPort, kPitChan2Mode0);
    Outb(kPitChannel2Port, static_cast<u8>(kVerifyPitCount & 0xFF));
    Outb(kPitChannel2Port, static_cast<u8>((kVerifyPitCount >> 8) & 0xFF));

    // Block ~50 ms wall. On the healthy path the LAPIC timer fires
    // during this window (and may even preempt us — fine, the
    // post-wait g_ticks check still observes the advance). On the
    // failing path there is no preemption, so this returns after the
    // full PIT countdown with g_ticks untouched.
    (void)WaitPitTerminal();

    if (g_ticks != ticks_before)
    {
        // LAPIC timer delivers — common path. Silent at Info; one
        // Debug line for driver-bringup tracing.
        core::LogWithValue(core::LogLevel::Debug, "arch/timer", "LAPIC timer delivery verified, ticks", g_ticks);
        return;
    }

    // g_ticks never moved across the whole window: the armed LAPIC
    // timer is not delivering its IRQ. Switch to the PIT tick source.
    StartPitPeriodicTickFallback();
}

u64 TimerTicks()
{
    return g_ticks;
}

void LapicTimerStartOnCurrent()
{
    // If the BSP fell back to the IOAPIC-routed PIT tick
    // (g_pit_fallback_active — VirtualBox: the LVT counts but never
    // delivers its IRQ, and PIT IRQ0 is routed only to the BSP's LAPIC
    // id), arming this AP's LAPIC timer LVT is pointless — it would
    // count but never fire. Don't arm a known-dead LVT; warn once and
    // return. The AP still gets a periodic tick: the BSP's TimerHandler
    // broadcasts one to every online AP each tick via
    // SmpBroadcastApTimerTick (option (a) of the former GAP — chosen
    // over a per-AP TSC-deadline timer, which would re-use the same
    // LVT delivery path VBox fails to raise). So per-CPU accounting and
    // preemption work on APs even on the fallback path.
    if (g_pit_fallback_active)
    {
        KLOG_ONCE_WARN("arch/timer", "AP LAPIC timer skipped — BSP on PIT-tick fallback; "
                                     "AP ticks delivered via IPI broadcast");
        return;
    }
    KASSERT(g_lapic_ticks_per_period != 0, "arch/timer", "LapicTimerStartOnCurrent before TimerInit");
    const u64 ticks_per_kernel_tick = (g_lapic_ticks_per_period * 1000) / (kCalibrationMs * kTickFrequencyHz);
    LapicWrite(kLapicRegTimerDivide, kLapicTimerDivBy16);
    LapicWrite(kLapicRegLvtTimer, kLvtTimerPeriodicBit | kTimerVector);
    LapicWrite(kLapicRegTimerInit, static_cast<u32>(ticks_per_kernel_tick));
}

void MarkInitComplete()
{
    g_init_complete = true;
}

void SetInitWedgePanicThreshold(u32 silent_heartbeats)
{
    g_wedge_panic_threshold = silent_heartbeats;
}

} // namespace duetos::arch
