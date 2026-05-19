// Host-side GDB remote-serial-protocol stub. The VMM owns all vCPU
// state via WHP, so — unlike the in-kernel stub — no guest agent is
// needed: gdb (driven by Visual Studio's cppdbg, per launch.vs.json)
// connects over TCP and reads/writes registers + guest memory and
// plants breakpoints entirely from the host.
//
// Supported: qSupported, qXfer:features:read:target.xml (declares
// the amd64 core register set so gdb expects exactly our 164-byte
// 'g' block), ?, g/G, m/M, Z0/z0 (software breakpoints), c, s,
// detach/kill. Hardware watchpoints and fully-async ^C interrupt
// are documented GAPs (you can still stop by hitting a breakpoint).
#pragma once

#include <winsock2.h>

#include <cstdint>
#include <functional>
#include <map>
#include <string>

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

    // Blocks until a debugger connects (call before the guest runs
    // so breakpoints can be set at boot).
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
};

} // namespace duetos::vmm
