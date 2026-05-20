// Top-level VMM: owns the partition, lays out guest RAM, loads the
// kernel + synthesised firmware, brings the vCPU up in the 32-bit
// protected-mode state Multiboot2 mandates, and runs the exit loop.
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

#include "debug/elf_symbols.h"
#include "debug/exit_trace.h"
#include "debug/gdb_server.h"
#include "debug/guest_view.h"
#include "debug/record.h"
#include "devices/ioapic.h"
#include "devices/pit8254.h"
#include "devices/ps2_i8042.h"
#include "devices/serial16550.h"
#include "display/window.h"
#include "guest_memory.h"
#include "whp.h"

namespace duetos::vmm
{

struct VmConfig
{
    std::string kernelPath;
    std::string cmdline   = "console=ttyS0";
    uint64_t    ramBytes  = 512ull * 1024 * 1024;
    // Break the run after this many seconds of COM1 silence. 0
    // disables the watchdog (the default — an interactive shell is
    // legitimately silent while waiting at a prompt). Headless/CI
    // runs pass a positive value to bound a wedged boot.
    uint32_t    idleSecs  = 0;

    // TCP port for the host-side GDB stub. 0 = disabled. When set,
    // the guest stops before the first instruction so the client
    // can plant boot breakpoints; #DB/#BP exits are enabled.
    uint16_t    gdbPort   = 0;

    // Mutually exclusive. recordPath captures host-origin inputs;
    // replayPath feeds them back deterministically (exit-seq
    // granularity — see debug/record.h).
    std::string recordPath;
    std::string replayPath;

    // Framebuffer window. fbW/fbH default to the primary monitor
    // resolution (set by main.cpp after arg-parse). noWindow skips
    // the FB reservation and window entirely (headless/CI path).
    uint32_t    fbW       = 0;
    uint32_t    fbH       = 0;
    bool        noWindow  = false;
};

// Fixed guest-physical homes for the synthesised firmware blobs.
// Both sit below the kernel's 1 MiB load address and inside the
// region the mmap marks reserved, so the frame allocator never
// reclaims them.
constexpr uint64_t kMbInfoGpa = 0x00010000; // 64 KiB
constexpr uint64_t kAcpiGpa   = 0x00080000; // 512 KiB

class Vmm
{
public:
    explicit Vmm(VmConfig cfg);
    ~Vmm();

    // Boots the guest and runs the exit loop until the guest halts,
    // faults, or the idle watchdog fires. Returns a process exit code.
    int Run();

    // Singleton accessor for the vmm_dbg:: layer. Set in ctor, cleared
    // in dtor. Never null while the VMM is running; null before/after.
    static Vmm* Active();

    // Introspection accessors used by vmm_dbg::. These do not lock —
    // callers must only be invoked while the guest is paused (i.e.
    // from the VS Immediate window while the vCPU thread is stopped
    // at a breakpoint in the VMM process).
    bool DbgResolveGpa(uint64_t gva, uint64_t& gpa) const;
    void* DbgHostPtr(uint64_t gpa, uint64_t len) const;
    const ElfSymbols::Sym* DbgFindSym(const char* name) const;
    const ElfSymbols& DbgSymbols() const;
    Partition& DbgPartition() { return m_part; }

    // Typed live view of curated guest kernel globals. Populated
    // lazily on each guest exit via RefreshGuestView(). Inspect in
    // the VS Watch window as `vmm.kernel.g_ticks` — the pointer
    // dereferences directly into WHP-mapped guest RAM, so the value
    // updates every time you step/resume in the debugger.
    GuestKernelView kernel;

private:
    void SetupVcpu(uint64_t entry, uint64_t mbInfoGpa);
    void HandleIoPort(const WHV_RUN_VP_EXIT_CONTEXT& exit);
    void StartHelperThreads();
    void SetTrapFlag(bool on);
    // Applies a GDB resume decision (sets/clears TF, handles the
    // step-off-breakpoint dance). Returns false on detach.
    bool ApplyResume(GdbServer::Resume r);

    void RecordExit(const WHV_RUN_VP_EXIT_CONTEXT& exit);
    std::string Monitor(const std::string& cmd);   // gdb `monitor`
    void DumpTrace(std::string& out) const;         // symbolized ring

    // Central funnels so record/replay can intercept the two
    // host-origin non-deterministic inputs.
    void RaiseGuestLine(uint32_t irq);    // IOAPIC line (record-aware)
    void DeliverSerial(uint8_t byte);     // stdin -> COM1 (record)
    void PumpReplay();                    // feed recorded events

    VmConfig                       m_cfg;
    Partition                      m_part;
    std::unique_ptr<GuestMemory>   m_mem;
    FbWindow                       m_window;
    Serial16550                    m_com1;
    Pit8254                        m_pit;
    IoApic                         m_ioapic;
    Ps2I8042                       m_ps2{[this](uint32_t irq) { RaiseGuestLine(irq); }};

    std::unique_ptr<GdbServer> m_gdb;
    ElfSymbols            m_symbols;
    ExitTrace             m_trace;
    EventLog              m_log;
    bool                  m_continueAfterStepOff = false;

    std::atomic<bool>     m_stop{false};
    std::atomic<uint64_t> m_lastTxNs{0}; // last COM1 output, for watchdog
    std::thread           m_stdinThread;
    std::thread           m_timerThread;
    std::thread           m_watchdogThread;
};

} // namespace duetos::vmm
