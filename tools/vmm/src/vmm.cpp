#include "vmm.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <intrin.h> // __debugbreak (used by --break / cfg.breakAtStart)
#include <stdexcept>

#include "debug/host_stop.h"
#include "debug/vmm_dbg.h"

#include "acpi.h"
#include "elf64.h"
#include "host_clock.h"
#include "input/ps2_encode.h"
#include "mmio_emulator.h"
#include "multiboot2.h"

namespace duetos::vmm
{

namespace
{
uint64_t Align2M(uint64_t x) { return (x + 0x1FFFFF) & ~uint64_t(0x1FFFFF); }

// BSP APIC id. The synthesised MADT advertises exactly one LAPIC
// with id 0, so every IOAPIC-routed line targets APIC 0.
constexpr uint32_t kBspApicId = 0;

// Singleton pointer — set in Vmm ctor, cleared in dtor.
Vmm* g_activeVmm = nullptr;
} // namespace

// static
Vmm* Vmm::Active()
{
    return g_activeVmm;
}

bool Vmm::DbgResolveGpa(uint64_t gva, uint64_t& gpa) const
{
    return m_part.TranslateGva(0, gva, gpa);
}

void* Vmm::DbgHostPtr(uint64_t gpa, uint64_t len) const
{
    return m_mem->HostPtr(gpa, len);
}

const ElfSymbols::Sym* Vmm::DbgFindSym(const char* name) const
{
    return m_symbols.Find(name);
}

const ElfSymbols& Vmm::DbgSymbols() const
{
    return m_symbols;
}

Vmm::Vmm(VmConfig cfg)
    : m_cfg(std::move(cfg)),
      m_part(/*cpuCount=*/1, /*debugExits=*/m_cfg.gdbPort != 0)
{
    m_mem = std::make_unique<GuestMemory>(m_part, m_cfg.ramBytes);

    LoadedImage img = LoadElf64(m_cfg.kernelPath, *m_mem);
    std::printf("[vmm] kernel: entry=0x%llx load=[0x%llx,0x%llx)\n",
                (unsigned long long)img.entry,
                (unsigned long long)img.lowPaddr,
                (unsigned long long)img.highPaddr);

    AcpiImage acpi = BuildAcpi(kAcpiGpa, /*lapicCount=*/1);
    m_mem->Write(acpi.baseGpa, acpi.blob.data(), acpi.blob.size());

    const uint64_t reservedEnd =
        Align2M(std::max<uint64_t>(
            {img.highPaddr, kAcpiGpa + acpi.blob.size(),
             kMbInfoGpa + 0x10000}));

    Mb2Params mp;
    // When the GDB stub is enabled, tell the guest kernel that a debugger
    // host owns #BP/#DB so it stands down its boot-time int3 / DR
    // self-tests (TrapsSelfTest's int3, BpSelfTest, WatchSelfTest), which
    // would otherwise collide with our exception intercept and wedge or
    // corrupt the boot. The kernel keys off the "debugstub=1" cmdline
    // token (see kernel/core/boot_cmdline.cpp).
    mp.cmdline     = m_cfg.cmdline;
    if (m_cfg.gdbPort != 0)
    {
        mp.cmdline += " debugstub=1";
    }
    mp.ramBytes    = m_cfg.ramBytes;
    mp.reservedEnd = reservedEnd;
    mp.rsdp        = acpi.rsdp;

    // Reserve framebuffer region BEFORE building the MB2 mmap so the
    // reserved split in BuildMultiboot2Info sees the FB span and marks
    // it reserved (not available RAM). Order is critical: this must
    // precede BuildMultiboot2Info.
    if (!m_cfg.noWindow)
    {
        uint64_t fbGpa  = m_mem->ReserveFramebuffer(m_cfg.fbW, m_cfg.fbH);
        mp.fbAddr       = fbGpa;
        mp.fbWidth      = m_cfg.fbW;
        mp.fbHeight     = m_cfg.fbH;
        mp.fbPitch      = m_cfg.fbW * 4;
        mp.fbBpp        = 32;
        std::printf("[vmm] framebuffer: gpa=0x%llx %ux%u 32bpp "
                    "pitch=%u bytes=%llu\n",
                    (unsigned long long)fbGpa,
                    m_cfg.fbW, m_cfg.fbH,
                    m_cfg.fbW * 4,
                    (unsigned long long)m_mem->FramebufferBytes());
    }

    std::vector<uint8_t> mbi = BuildMultiboot2Info(mp);
    m_mem->Write(kMbInfoGpa, mbi.data(), mbi.size());

    // IOAPIC-routed lines inject into the WHP-emulated LAPIC. This
    // is thread-safe (WHvRequestInterrupt may be called off the vCPU
    // thread), so the stdin/timer threads can raise lines directly.
    m_ioapic.SetInjector(
        [this](uint32_t vec, uint32_t dest, bool level) {
            m_part.RequestInterrupt(vec, dest ? dest : kBspApicId,
                                    level);
        });

    SetupVcpu(img.entry, kMbInfoGpa);

    // Symbols power introspection AND the on-fatal trace dump, so
    // load them whether or not gdb is enabled. Non-fatal if absent.
    if (!m_symbols.Load(m_cfg.kernelPath))
    {
        std::printf("[vmm] no kernel symbols (introspection by "
                    "address only)\n");
    }

    if (m_cfg.gdbPort != 0)
    {
        m_gdb = std::make_unique<GdbServer>(m_part, *m_mem,
                                            m_cfg.gdbPort);
        m_gdb->SetMonitor(
            [this](const std::string& c) { return Monitor(c); });
        // Wire VS Pause / Break-All to a WHP cancellation. The
        // GdbServer watcher thread (started in WaitForConnection)
        // calls this when it sees `\x03` on the gdb socket while the
        // guest is running. CancelRun makes WHvRunVirtualProcessor
        // return with reason=Canceled; the main loop below routes
        // that to a stop-reply + ServeStopped when IrqPending is set,
        // so VS's UI thread gets its expected stop reply instead of
        // freezing the IDE.
        m_gdb->SetOnInterrupt([this] { m_part.CancelRun(0); });
    }

    if (!m_cfg.recordPath.empty())
    {
        if (!m_log.OpenRecord(m_cfg.recordPath))
        {
            throw std::runtime_error("cannot open record file");
        }
        std::printf("[vmm] recording host inputs -> %s\n",
                    m_cfg.recordPath.c_str());
    }
    else if (!m_cfg.replayPath.empty())
    {
        if (!m_log.OpenReplay(m_cfg.replayPath))
        {
            throw std::runtime_error(
                "cannot open/parse replay file");
        }
        m_pit.SetReplay(true);
        std::printf("[vmm] replaying host inputs <- %s "
                    "(exit-seq deterministic)\n",
                    m_cfg.replayPath.c_str());
    }

    // Publish the singleton AFTER all members are constructed (this is the
    // last statement of the ctor body). vmm_dbg::* is only reachable from
    // the VS Immediate window while the vCPU thread is stopped at a
    // native debugger breakpoint — by which time construction has long
    // completed. If a future helper thread ever calls a vmm_dbg:: function
    // before the ctor returns, move this publication to the very end of
    // the function body AND add an std::atomic_thread_fence(release).
    g_activeVmm = this;
}

void Vmm::RaiseGuestLine(uint32_t irq)
{
    if (m_log.mode() == RecMode::Replay)
    {
        return; // the replay pump owns line raises
    }
    if (m_log.mode() == RecMode::Record)
    {
        m_log.Put(m_trace.total(), EvKind::RaiseLine, irq);
    }
    m_ioapic.RaiseLine(irq);
}

void Vmm::DeliverSerial(uint8_t byte)
{
    m_com1.PushRx(byte);
    if (m_log.mode() == RecMode::Record)
    {
        m_log.Put(m_trace.total(), EvKind::SerialRx, byte);
    }
    if (m_com1.RxIrqPending())
    {
        RaiseGuestLine(4); // COM1 = ISA IRQ4
    }
}

void Vmm::PumpReplay()
{
    if (m_log.mode() != RecMode::Replay)
    {
        return;
    }
    Event ev;
    while (m_log.Peek(ev) && ev.seq <= m_trace.total())
    {
        switch (ev.kind)
        {
        case EvKind::SerialRx:
            m_com1.PushRx(static_cast<uint8_t>(ev.a));
            break;
        case EvKind::RaiseLine:
            m_ioapic.RaiseLine(static_cast<uint32_t>(ev.a));
            break;
        case EvKind::Pit2Expire:
            m_pit.ForceExpire();
            break;
        }
        m_log.Pop();
    }
}

void Vmm::SetTrapFlag(bool on)
{
    WHV_REGISTER_NAME n = WHvX64RegisterRflags;
    WHV_REGISTER_VALUE v = {};
    m_part.GetRegisters(0, &n, 1, &v);
    if (on)
    {
        v.Reg64 |= (1ull << 8);  // EFLAGS.TF
    }
    else
    {
        v.Reg64 &= ~(1ull << 8);
    }
    m_part.SetRegisters(0, &n, 1, &v);
}

bool Vmm::ApplyResume(GdbServer::Resume r)
{
    switch (r)
    {
    case GdbServer::Resume::Detach:
        m_gdb.reset();
        SetTrapFlag(false);
        return false;
    case GdbServer::Resume::Step:
        if (m_gdb->RipAtBreakpoint(0))
        {
            m_gdb->StepOffBegin(0); // lift the 0xCC under RIP
        }
        SetTrapFlag(true);
        return true;
    case GdbServer::Resume::Continue:
    default:
        if (m_gdb->RipAtBreakpoint(0))
        {
            // Single-step off the planted 0xCC, then free-run.
            m_gdb->StepOffBegin(0);
            m_continueAfterStepOff = true;
            SetTrapFlag(true);
        }
        else
        {
            SetTrapFlag(false);
        }
        return true;
    }
}

Vmm::~Vmm()
{
    g_activeVmm = nullptr;
    m_stop.store(true);
    m_part.CancelRun(0);
    // Stop the window before guest memory is torn down — FbWindow
    // holds a raw pointer into the guest RAM framebuffer region.
    m_window.Stop();
    // The stdin reader is parked in a blocking getchar() that m_stop
    // can't interrupt; detach it (it dies with the process) rather
    // than hang the dtor on join(). The timer/watchdog threads poll
    // m_stop and exit promptly, so they are joined.
    if (m_stdinThread.joinable())
    {
        m_stdinThread.detach();
    }
    for (std::thread* t : {&m_timerThread, &m_watchdogThread})
    {
        if (t->joinable())
        {
            t->join();
        }
    }
}

void Vmm::SetupVcpu(uint64_t entry, uint64_t mbInfoGpa)
{
    // Multiboot2 machine state: 32-bit protected mode, paging OFF,
    // flat 4 GiB segments, EAX=magic, EBX=&mbi. boot.S takes it from
    // here (its own GDT, long-mode bringup, higher-half map).
    WHV_REGISTER_NAME n[16];
    WHV_REGISTER_VALUE v[16];
    int i = 0;

    auto reg = [&](WHV_REGISTER_NAME name, uint64_t val) {
        n[i] = name;
        v[i] = {};
        v[i].Reg64 = val;
        ++i;
    };
    auto seg = [&](WHV_REGISTER_NAME name, uint16_t sel, bool code) {
        n[i] = name;
        v[i] = {};
        WHV_X64_SEGMENT_REGISTER s = {};
        s.Base = 0;
        s.Limit = 0xFFFFFFFF;
        s.Selector = sel;
        s.SegmentType = code ? 0xB : 0x3; // exec/read vs read/write
        s.NonSystemSegment = 1;
        s.Present = 1;
        s.Default = 1;     // 32-bit
        s.Granularity = 1; // 4 KiB → limit is in pages
        v[i].Segment = s;
        ++i;
    };

    reg(WHvX64RegisterCr0, 0x00000011);  // PE | ET, PG=0
    reg(WHvX64RegisterCr3, 0);
    reg(WHvX64RegisterCr4, 0);
    reg(WHvX64RegisterEfer, 0);
    reg(WHvX64RegisterRflags, 0x2);      // reserved bit, IF=0
    reg(WHvX64RegisterRip, entry);
    reg(WHvX64RegisterRsp, 0x7000);      // boot.S installs its own
    reg(WHvX64RegisterRax, kMultiboot2BootloaderMagic);
    reg(WHvX64RegisterRbx, mbInfoGpa);
    seg(WHvX64RegisterCs, 0x08, true);
    seg(WHvX64RegisterDs, 0x10, false);
    seg(WHvX64RegisterEs, 0x10, false);
    seg(WHvX64RegisterFs, 0x10, false);
    seg(WHvX64RegisterGs, 0x10, false);
    seg(WHvX64RegisterSs, 0x10, false);

    m_part.SetRegisters(0, n, i, v);
}

void Vmm::HandleIoPort(const WHV_RUN_VP_EXIT_CONTEXT& exit)
{
    const auto& io = exit.IoPortAccess;
    const uint16_t port = static_cast<uint16_t>(io.PortNumber);
    const bool isCom1 = m_com1.Handles(port);
    const bool isPit  = m_pit.Handles(port);
    const bool isPs2  = (port == 0x60 || port == 0x64);

    uint64_t rax = io.Rax;
    if (io.AccessInfo.IsWrite)
    {
        const uint32_t val = static_cast<uint32_t>(rax);
        if (isCom1)
        {
            m_com1.Out(port, val);
            if (port == Serial16550::kBase)
            {
                m_lastTxNs.store(HostNanos());
            }
        }
        else if (isPit)
        {
            m_pit.Out(port, val);
        }
        else if (isPs2)
        {
            m_ps2.Out(port, static_cast<uint8_t>(val));
        }
        // Unclaimed port writes are dropped (no bus decoder).
    }
    else
    {
        uint32_t val = 0xFFFFFFFFu;
        if (isCom1)
        {
            val = m_com1.In(port);
        }
        else if (isPit)
        {
            val = m_pit.In(port);
            if (m_log.mode() == RecMode::Record &&
                m_pit.TakeCh2ExpireEdge())
            {
                m_log.Put(m_trace.total(), EvKind::Pit2Expire, 0);
            }
        }
        else if (isPs2)
        {
            val = m_ps2.In(port);
        }
        const uint32_t bytes = io.AccessInfo.AccessSize;
        uint64_t mask = (bytes >= 4) ? 0xFFFFFFFFull
                                     : ((1ull << (bytes * 8)) - 1);
        rax = (rax & ~mask) | (val & mask);
    }

    WHV_REGISTER_NAME n[2] = {WHvX64RegisterRax, WHvX64RegisterRip};
    WHV_REGISTER_VALUE vv[2] = {};
    vv[0].Reg64 = rax;
    vv[1].Reg64 = exit.VpContext.Rip + exit.VpContext.InstructionLength;
    m_part.SetRegisters(0, n, 2, vv);
}

void Vmm::StartHelperThreads()
{
    m_lastTxNs.store(HostNanos());

    // In replay the inputs come from the log, not the host — the
    // pump (in the run loop) feeds them at the recorded exit-seq.
    if (m_log.mode() == RecMode::Replay)
    {
        return;
    }

    // Host stdin -> COM1 RX (DeliverSerial logs the byte + raises
    // IRQ4 through the record-aware funnel).
    m_stdinThread = std::thread([this] {
        while (!m_stop.load())
        {
            int c = std::getchar();
            if (c == EOF)
            {
                break;
            }
            DeliverSerial(static_cast<uint8_t>(c));
        }
    });

    // PIT channel-0 periodic IRQ0 — only live if the kernel fell
    // back from the LAPIC timer (g_pit_fallback_active).
    m_timerThread = std::thread([this] {
        while (!m_stop.load())
        {
            uint64_t periodNs = m_pit.Channel0PeriodNs();
            if (periodNs == 0)
            {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(2));
                continue;
            }
            std::this_thread::sleep_for(
                std::chrono::nanoseconds(periodNs));
            RaiseGuestLine(0); // PIT = ISA IRQ0
        }
    });

    // Idle watchdog (opt-in via --idle, for headless/CI). A healthy
    // guest idle-HLTs between timer ticks but produces serial output
    // as it boots; prolonged COM1 silence in a headless run means
    // wedged. Disabled by default so an interactive shell parked at
    // a prompt is never killed.
    if (m_cfg.idleSecs == 0)
    {
        return;
    }
    m_watchdogThread = std::thread([this] {
        const uint64_t idleNs =
            uint64_t(m_cfg.idleSecs) * 1000000000ull;
        while (!m_stop.load())
        {
            std::this_thread::sleep_for(
                std::chrono::milliseconds(500));
            if (HostNanos() - m_lastTxNs.load() > idleNs)
            {
                std::printf("\n[vmm] COM1 idle %us — breaking run "
                            "(guest wedged or halted)\n",
                            m_cfg.idleSecs);
                std::fflush(stdout);
                m_stop.store(true);
                m_part.CancelRun(0);
                return;
            }
        }
    });
}

int Vmm::Run()
{
    std::printf("[vmm] booting DuetOS guest (1 vCPU, %llu MiB)\n",
                (unsigned long long)(m_cfg.ramBytes >> 20));
    std::fflush(stdout);

    // Open the framebuffer window before the vCPU loop so the kernel
    // can render to it from the first frame. The close callback sets
    // m_stop, which the exit loop checks at the top of each iteration.
    if (!m_cfg.noWindow)
    {
        InputSink sink;
        sink.onKey = [this](uint32_t vk, bool down, bool ext) {
            auto s = VkToSet1(vk, down, ext);
            if (!s.empty())
            {
                m_ps2.PushKey(s.data(), s.size());
            }
        };
        sink.onMouse = [this](int dx, int dy, uint32_t btn, int wheel) {
            auto p = MousePacket(dx, dy, btn, wheel, /*intelliMouse=*/false);
            m_ps2.PushAux(p.data(), p.size());
        };
        m_window.Start(m_mem->FramebufferHost(),
                       m_cfg.fbW * 4,
                       m_cfg.fbW, m_cfg.fbH,
                       "DuetOS - booting",
                       sink,
                       [this] { m_stop.store(true); });
    }

    StartHelperThreads();

    // --break: halt under a native VS attach now that construction is
    // complete and both debug channels are ready — the GDB stub (if
    // --gdb) is already listening so the second VS instance can attach
    // to tcp:<port>, and g_activeVmm is set so the vmm_dbg:: bridge
    // resolves guest symbols (neither was true at the old main()
    // break). For SOURCE-LEVEL kernel debugging via the stub, just
    // continue past this break; do NOT call vmm_dbg::Claim() — Claim()
    // routes #BP/#DB to the host bridge's __debugbreak (VMM host code)
    // and starves the stub. IsDebuggerPresent gates the trap.
    if (m_cfg.breakAtStart)
    {
        if (IsDebuggerPresent())
        {
            std::printf("[vmm] --break: halting after construction "
                        "(GDB stub listening, vmm_dbg:: bridge live)\n");
            std::fflush(stdout);
            __debugbreak();
        }
        else
        {
            std::printf("[vmm] --break: no debugger attached, "
                        "continuing\n");
            std::fflush(stdout);
        }
    }

    if (m_gdb)
    {
        // Stop before the first instruction so the client can plant
        // boot breakpoints (matches the QEMU `-S` flow VS expects).
        m_gdb->WaitForConnection();
        ApplyResume(m_gdb->ServeStopped(5));
    }

    auto dumpFatal = [&] {
        std::string t;
        DumpTrace(t);
        std::printf("[vmm] exit-trace (last <= %u exits):\n%s",
                    ExitTrace::kCap,
                    t.empty() ? "  (none)\n" : t.c_str());
        std::fflush(stdout);
    };

    uint64_t haltSpins = 0;
    for (;;)
    {
        if (m_stop.load())
        {
            return 0;
        }
        WHV_RUN_VP_EXIT_CONTEXT exit = m_part.Run(0);
        RecordExit(exit);
        RefreshGuestView(kernel, *this);
        PumpReplay(); // feed recorded inputs due at this exit-seq
        switch (exit.ExitReason)
        {
        case WHvRunVpExitReasonX64IoPortAccess:
            if (exit.IoPortAccess.AccessInfo.StringOp)
            {
                std::printf("\n[vmm] string I/O port 0x%x "
                            "unimplemented\n",
                            exit.IoPortAccess.PortNumber);
                dumpFatal();
                return 2;
            }
            HandleIoPort(exit);
            haltSpins = 0;
            break;

        case WHvRunVpExitReasonMemoryAccess:
            if (m_ioapic.Handles(exit.MemoryAccess.Gpa))
            {
                EmulateMmio(m_part, 0, exit.MemoryAccess, m_ioapic);
                haltSpins = 0;
                break;
            }
            std::printf("\n[vmm] unhandled MMIO @ 0x%llx rip=%s\n",
                        (unsigned long long)exit.MemoryAccess.Gpa,
                        m_symbols.Symbolize(exit.VpContext.Rip)
                            .c_str());
            dumpFatal();
            return 1;

        case WHvRunVpExitReasonX64Halt:
            // The LAPIC timer (WHP-emulated) or an IOAPIC-routed
            // line wakes the guest; just resume. If nothing is
            // arming interrupts the run spins here — back off so the
            // idle watchdog can fire instead of pinning a core.
            if (++haltSpins > 4096)
            {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(1));
            }
            break;

        case WHvRunVpExitReasonException:
        {
            // Arbiter: if the host-attach session has claimed ownership,
            // give it first crack.  HandleHostStop returns true for #BP/#DB
            // and blocks until the host calls Step() or Run().  Any other
            // exception type returns false, falling through to the GDB stub.
            if (HostAttachOwnsDebug())
            {
                if (HandleHostStop(*this, exit))
                {
                    haltSpins = 0;
                    break;
                }
                // Fall through to legacy handling if arbiter declined.
            }

            const uint8_t et = exit.VpException.ExceptionType;
            if (!m_gdb)
            {
                std::printf("\n[vmm] exception %u with no debugger "
                            "rip=%s\n",
                            et,
                            m_symbols.Symbolize(exit.VpContext.Rip)
                                .c_str());
                dumpFatal();
                return 1;
            }
            SetTrapFlag(false); // the TF single-step has completed
            const bool wasStepOff = m_gdb->stepOffPending();
            if (wasStepOff)
            {
                m_gdb->StepOffEnd(); // re-plant the lifted 0xCC
            }
            if (m_continueAfterStepOff && et == 1)
            {
                // Finished stepping off a breakpoint for `continue`.
                m_continueAfterStepOff = false;
                ApplyResume(GdbServer::Resume::Continue);
                haltSpins = 0;
                break;
            }
            // GAP: a #BP not in m_bps is a guest-originated int3
            // (the kernel's traps self-test, or any in-kernel KBP
            // probe). With a host debugger attached the host owns
            // #BP, so these surface to the client as a one-shot
            // SIGTRAP instead of reaching the kernel handler;
            // pressing Continue in VS skips past the int3. (Before
            // the OnException rewind-fix in gdb_server.cpp these
            // looped forever — boot halted at "[traps] self-test".)
            // Full re-injection into the guest so the kernel #BP
            // handler runs needs the WHP pending-event path —
            // revisit when probe-coverage under gdb matters.
            const int sig = m_gdb->OnException(0, et);
            const GdbServer::Resume r = m_gdb->ServeStopped(sig);
            ApplyResume(r); // Detach drops m_gdb and free-runs
            haltSpins = 0;
            break;
        }

        case WHvRunVpExitReasonX64InterruptWindow:
            break;

        case WHvRunVpExitReasonCanceled:
            // Two callers can drive Canceled:
            //   (1) m_stop.store(true) + CancelRun — clean shutdown
            //       (window close, /quit, helper-thread fatal). Fall
            //       through to the existing return below.
            //   (2) GdbServer's async-interrupt watcher consuming a
            //       `\x03` from gdb (VS Pause / Break-All). The watcher
            //       sets IrqPending before calling CancelRun, so we
            //       can distinguish the two. Send the proactive S05
            //       stop reply gdb is waiting for after `c`, then
            //       enter ServeStopped just like a #BP exit would.
            if (m_gdb && m_gdb->IrqPending())
            {
                m_gdb->ClearIrqPending();
                m_gdb->SendStopReply(5);
                ApplyResume(m_gdb->ServeStopped(5));
                haltSpins = 0;
                break;
            }
            return m_stop.load() ? 0 : 1;

        default:
            std::printf("\n[vmm] unexpected exit %d rip=%s\n",
                        (int)exit.ExitReason,
                        m_symbols.Symbolize(exit.VpContext.Rip)
                            .c_str());
            dumpFatal();
            return 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Keepalive table — prevents MSVC /OPT:REF from stripping vmm_dbg::*
// symbols that are only ever called from the VS Immediate window (i.e.
// never from a normal call-graph edge the linker can see).
// ---------------------------------------------------------------------------
namespace
{
volatile void* const g_vmmDbgKeepalive[] = {
    reinterpret_cast<volatile void*>(&vmm_dbg::ReadQ),
    reinterpret_cast<volatile void*>(&vmm_dbg::ReadD),
    reinterpret_cast<volatile void*>(&vmm_dbg::ReadW),
    reinterpret_cast<volatile void*>(&vmm_dbg::ReadB),
    reinterpret_cast<volatile void*>(&vmm_dbg::WriteQ),
    reinterpret_cast<volatile void*>(&vmm_dbg::WriteD),
    reinterpret_cast<volatile void*>(&vmm_dbg::WriteW),
    reinterpret_cast<volatile void*>(&vmm_dbg::WriteB),
    reinterpret_cast<volatile void*>(&vmm_dbg::Sym),
    reinterpret_cast<volatile void*>(&vmm_dbg::Dump),
    // Layer C — host-attach session control
    reinterpret_cast<volatile void*>(&vmm_dbg::Claim),
    reinterpret_cast<volatile void*>(&vmm_dbg::Release),
    reinterpret_cast<volatile void*>(&vmm_dbg::Bp),
    reinterpret_cast<volatile void*>(&vmm_dbg::Clr),
    reinterpret_cast<volatile void*>(&vmm_dbg::Step),
    reinterpret_cast<volatile void*>(&vmm_dbg::Run),
};
} // namespace

} // namespace duetos::vmm
