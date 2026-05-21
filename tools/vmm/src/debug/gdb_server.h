// Host-side GDB remote-serial-protocol stub. The VMM owns all vCPU
// state via WHP, so — unlike the in-kernel stub — no guest agent is
// needed: gdb (driven by Visual Studio's cppdbg, per launch.vs.json)
// connects over TCP and reads/writes registers + guest memory and
// plants breakpoints entirely from the host.
//
// Supported: qSupported, qXfer:features:read:target.xml (declares
// the amd64 core register set so gdb expects exactly our 164-byte
// 'g' block), ?, g/G, m/M, Z0/z0 (software breakpoints), c, s,
// detach/kill, async ^C interrupt (Pause / Break-All).
// Hardware watchpoints are still a documented GAP.
//
// Async-interrupt design: a background watcher thread (m_irqThread)
// polls the gdb socket while the guest is running. When `\x03`
// arrives, it consumes the byte, sets m_irqPending, and invokes the
// caller-supplied m_onInterrupt callback (Vmm wires this to
// Partition::CancelRun(0)). The blocking WHvRunVirtualProcessor
// returns with Canceled; the main loop sees IrqPending, sends a
// proactive stop reply, and enters ServeStopped.
//
// Thread-safety: all socket I/O on m_conn is serialised by
// m_socketMtx. The watcher uses try_lock so a long RecvPacket /
// SendPacket from the main thread never starves it; it goes dormant
// (via m_inServeStopped) while ServeStopped owns the protocol,
// because while we're stopped the existing in-band `\x03` handler in
// ServeStopped already serves Pause correctly.
#pragma once

#include <winsock2.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>

#include "guest_memory.h"
#include "whp.h"

namespace duetos::vmm
{

class GdbServer
{
public:
    GdbServer(Partition& part, GuestMemory& mem, uint16_t port);
    ~GdbServer();

    enum class Resume
    {
        Continue,
        Step,
        Detach
    };

    // `monitor <cmd>` (gdb qRcmd) handler — the introspection
    // surface. Returns the text to show in the client console.
    using MonitorFn = std::function<std::string(const std::string&)>;
    void SetMonitor(MonitorFn fn) { m_monitor = std::move(fn); }

    // Callback fired from the async-interrupt watcher thread when
    // gdb's `\x03` (Pause / Break-All) arrives while the guest is
    // running. Vmm wires this to Partition::CancelRun(0) so the
    // blocking WHvRunVirtualProcessor returns with Canceled.
    using InterruptFn = std::function<void()>;
    void SetOnInterrupt(InterruptFn fn) { m_onInterrupt = std::move(fn); }

    // Async-interrupt status. Vmm's WHvRunVpExitReasonCanceled
    // handler uses IrqPending() to distinguish a user-initiated
    // Pause (consume + SendStopReply + ServeStopped) from a normal
    // shutdown-driven cancel (which falls through to the m_stop
    // check the way it always has).
    bool IrqPending() const { return m_irqPending.load(); }
    void ClearIrqPending() { m_irqPending.store(false); }

    // Proactively send an `S<sig>` stop reply. Used by Vmm for an
    // async-interrupt-induced stop, where gdb is waiting for a stop
    // reply after a `c` and won't speak first. Standard #BP stops
    // happen to work without this because cppdbg / MIEngine sends
    // `?` after the resume — see comment in vmm.cpp's exception
    // exit handler.
    void SendStopReply(int sig);

    // Blocks until a debugger connects (call before the guest runs
    // so breakpoints can be set at boot). Starts the async-interrupt
    // watcher thread as a side effect.
    void WaitForConnection();

    // Guest is stopped with the given signal (5 = TRAP). Services
    // RSP packets until the client resumes; returns the action.
    // Handles the breakpoint-shadow dance so reads see original
    // bytes and execution steps off a planted 0xCC correctly.
    Resume ServeStopped(int sig);

    // Maps a WHP exception exit to a stop signal and fixes up RIP
    // for a software breakpoint (#BP leaves RIP after the int3).
    int OnException(uint32_t vp, uint8_t exceptionType);

    // Step-off-breakpoint dance: a planted 0xCC at the current RIP
    // must be lifted, single-stepped over, and re-planted before a
    // plain `continue`, else the guest re-traps on it forever.
    bool RipAtBreakpoint(uint32_t vp) const;
    void StepOffBegin(uint32_t vp);   // lift the 0xCC at RIP
    void StepOffEnd();                // re-plant it
    bool stepOffPending() const { return m_haveStepOver; }

    bool attached() const { return m_conn != INVALID_SOCKET; }

private:
    std::string RecvPacket();
    void SendPacket(const std::string& body);
    void SendAck();

    // Background poll loop that consumes a `\x03` from the gdb
    // socket while the guest is running. Runs on m_irqThread.
    void IrqWatcherLoop();

    std::string ReadRegisters(uint32_t vp);
    void WriteRegisters(uint32_t vp, const std::string& hex);
    std::string ReadMem(uint64_t gva, uint64_t len);
    bool WriteMem(uint64_t gva, const std::string& hexData);

    void InsertBreakpoint(uint64_t gva);
    void RemoveBreakpoint(uint64_t gva);
    void ReinsertAll();

    Partition&   m_part;
    GuestMemory& m_mem;
    uint16_t     m_port;
    SOCKET       m_listen = INVALID_SOCKET;
    SOCKET       m_conn   = INVALID_SOCKET;

    MonitorFn m_monitor;
    std::map<uint64_t, uint8_t> m_bps;   // gva -> shadowed orig byte
    uint64_t m_stepOverBp = 0;           // bp lifted for step-off
    bool     m_haveStepOver = false;

    // Async-interrupt state. The watcher reads m_conn while the
    // guest is running; ServeStopped owns m_conn while it doesn't.
    // m_socketMtx serialises ALL recv/send on m_conn so the two
    // paths never race; m_inServeStopped lets the watcher go fully
    // dormant during ServeStopped (avoids ever stealing a byte the
    // protocol's in-band `\x03` handler would otherwise process).
    std::mutex          m_socketMtx;
    std::atomic<bool>   m_inServeStopped{false};
    std::atomic<bool>   m_irqPending{false};
    std::atomic<bool>   m_irqShutdown{false};
    std::thread         m_irqThread;
    InterruptFn         m_onInterrupt;
};

} // namespace duetos::vmm
