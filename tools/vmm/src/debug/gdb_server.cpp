#include "debug/gdb_server.h"

#include <ws2tcpip.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

namespace duetos::vmm
{

namespace
{

const char* kTargetXml =
    "<?xml version=\"1.0\"?>"
    "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
    "<target version=\"1.0\">"
    "<architecture>i386:x86-64</architecture>"
    "<feature name=\"org.gnu.gdb.i386.core\"/>"
    "</target>";

char Nyb(uint8_t v) { return "0123456789abcdef"[v & 0xF]; }
uint8_t Unhex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}
void HexByte(std::string& s, uint8_t b)
{
    s += Nyb(b >> 4);
    s += Nyb(b);
}
void HexLE(std::string& s, uint64_t v, int bytes)
{
    for (int i = 0; i < bytes; ++i)
    {
        HexByte(s, static_cast<uint8_t>(v >> (8 * i)));
    }
}

// amd64 'g' block: rax rbx rcx rdx rsi rdi rbp rsp r8..r15 (8B),
// rip (8B), eflags cs ss ds es fs gs (4B). 164 bytes total.
constexpr WHV_REGISTER_NAME kRegs[] = {
    WHvX64RegisterRax, WHvX64RegisterRbx, WHvX64RegisterRcx,
    WHvX64RegisterRdx, WHvX64RegisterRsi, WHvX64RegisterRdi,
    WHvX64RegisterRbp, WHvX64RegisterRsp, WHvX64RegisterR8,
    WHvX64RegisterR9,  WHvX64RegisterR10, WHvX64RegisterR11,
    WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14,
    WHvX64RegisterR15, WHvX64RegisterRip, WHvX64RegisterRflags,
    WHvX64RegisterCs,  WHvX64RegisterSs,  WHvX64RegisterDs,
    WHvX64RegisterEs,  WHvX64RegisterFs,  WHvX64RegisterGs};

} // namespace

GdbServer::GdbServer(Partition& part, GuestMemory& mem, uint16_t port)
    : m_part(part), m_mem(mem), m_port(port)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        throw std::runtime_error("WSAStartup failed");
    }
    m_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listen == INVALID_SOCKET)
    {
        throw std::runtime_error("gdb: socket() failed");
    }
    BOOL yes = TRUE;
    setsockopt(m_listen, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<char*>(&yes), sizeof(yes));
    sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (bind(m_listen, reinterpret_cast<sockaddr*>(&sa),
             sizeof(sa)) != 0 ||
        listen(m_listen, 1) != 0)
    {
        throw std::runtime_error("gdb: bind/listen failed");
    }
}

GdbServer::~GdbServer()
{
    // Tear down the watcher first. Order matters: set the shutdown
    // flag, then shutdown(SD_BOTH) the socket to unblock any
    // WSAPoll/recv the watcher is currently parked in, then join.
    // Only THEN closesocket — closing while another thread is mid-
    // recv on Windows yields WSAENOTSOCK with undefined ordering.
    if (m_irqThread.joinable())
    {
        m_irqShutdown.store(true);
        if (m_conn != INVALID_SOCKET) shutdown(m_conn, SD_BOTH);
        m_irqThread.join();
    }
    if (m_conn != INVALID_SOCKET) closesocket(m_conn);
    if (m_listen != INVALID_SOCKET) closesocket(m_listen);
    WSACleanup();
}

void GdbServer::WaitForConnection()
{
    std::printf("[vmm] gdb: waiting for a client on tcp:%u "
                "(VS: F5 the attach config)\n",
                m_port);
    std::fflush(stdout);
    m_conn = accept(m_listen, nullptr, nullptr);
    if (m_conn == INVALID_SOCKET)
    {
        throw std::runtime_error("gdb: accept() failed");
    }
    BOOL nodelay = TRUE;
    setsockopt(m_conn, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<char*>(&nodelay), sizeof(nodelay));
    std::printf("[vmm] gdb: client attached\n");
    std::fflush(stdout);

    // Spin up the async-interrupt watcher now that the socket is
    // live. It runs until ~GdbServer; the m_inServeStopped flag
    // keeps it dormant while ServeStopped owns the protocol so it
    // never races the main thread's RecvPacket / SendPacket.
    m_irqThread = std::thread(&GdbServer::IrqWatcherLoop, this);
}

std::string GdbServer::RecvPacket()
{
    // Hold m_socketMtx for the whole packet read so a concurrent
    // IrqWatcherLoop iteration can't slice a byte out of the middle.
    // The watcher uses try_lock so this is the back-pressure side of
    // the pair — if main is reading, the watcher waits.
    std::lock_guard<std::mutex> _lk(m_socketMtx);
    // Skip to '$', accumulate to '#', drop the 2 checksum chars.
    char c = 0;
    for (;;)
    {
        int n = recv(m_conn, &c, 1, 0);
        if (n <= 0) return {};
        if (c == 0x03) return "\x03"; // ctrl-C (best-effort)
        if (c == '$') break;
    }
    std::string body;
    for (;;)
    {
        int n = recv(m_conn, &c, 1, 0);
        if (n <= 0) return {};
        if (c == '#') break;
        body += c;
    }
    char cs[2];
    recv(m_conn, &cs[0], 1, 0);
    recv(m_conn, &cs[1], 1, 0);
    SendAck();
    return body;
}

void GdbServer::SendAck()
{
    const char a = '+';
    send(m_conn, &a, 1, 0);
}

void GdbServer::SendPacket(const std::string& body)
{
    // Same locking rationale as RecvPacket — both send + ack-recv
    // need to stay atomic w.r.t. the watcher's peek/consume.
    std::lock_guard<std::mutex> _lk(m_socketMtx);
    uint8_t sum = 0;
    for (char ch : body) sum = static_cast<uint8_t>(sum + ch);
    std::string pkt = "$" + body + "#";
    pkt += Nyb(sum >> 4);
    pkt += Nyb(sum);
    send(m_conn, pkt.data(), static_cast<int>(pkt.size()), 0);
    char ack = 0;
    recv(m_conn, &ack, 1, 0); // consume '+'/'-' (lenient)
}

void GdbServer::SendStopReply(int sig)
{
    char b[8];
    std::snprintf(b, sizeof(b), "S%02x", sig);
    SendPacket(b); // takes m_socketMtx
}

void GdbServer::IrqWatcherLoop()
{
    using namespace std::chrono_literals;
    while (!m_irqShutdown.load())
    {
        // Dormant while ServeStopped owns the protocol. The in-band
        // `\x03` handler inside ServeStopped already handles Pause
        // when we're already stopped; touching the socket from here
        // would only race with it.
        if (m_inServeStopped.load())
        {
            std::this_thread::sleep_for(50ms);
            continue;
        }
        // Cooperative: never block ServeStopped's RecvPacket /
        // SendPacket. If main holds the socket lock, back off.
        std::unique_lock<std::mutex> lk(m_socketMtx, std::try_to_lock);
        if (!lk.owns_lock())
        {
            std::this_thread::sleep_for(10ms);
            continue;
        }
        WSAPOLLFD pfd = {};
        pfd.fd = m_conn;
        pfd.events = POLLRDNORM;
        const int r = WSAPoll(&pfd, 1, 100); // 100 ms wait
        if (m_irqShutdown.load()) return;
        if (r <= 0) continue;
        if (!(pfd.revents & POLLRDNORM)) continue;
        char c = 0;
        const int n = recv(m_conn, &c, 1, MSG_PEEK);
        if (n <= 0) return; // socket dead — let dtor join us
        if (c != '\x03')
        {
            // Stray byte while guest is running. gdb shouldn't send
            // packets while waiting for a stop reply, but if it does
            // we leave the byte for the next ServeStopped read. Drop
            // the lock and yield so main can drain it on the next
            // stop without us spinning here.
            lk.unlock();
            std::this_thread::sleep_for(50ms);
            continue;
        }
        // Consume the \x03 byte so ServeStopped's own \x03 handler
        // doesn't double-fire after we report the stop.
        recv(m_conn, &c, 1, 0);
        m_irqPending.store(true);
        // Drop the lock BEFORE the callback — Partition::CancelRun
        // doesn't touch the socket, but keeping the lock released
        // means a slow callback can't stall main thread I/O.
        lk.unlock();
        if (m_onInterrupt) m_onInterrupt();
    }
}

std::string GdbServer::ReadRegisters(uint32_t vp)
{
    constexpr int kN = static_cast<int>(sizeof(kRegs) /
                                        sizeof(kRegs[0]));
    WHV_REGISTER_VALUE v[kN] = {};
    m_part.GetRegisters(vp, kRegs, kN, v);
    std::string s;
    for (int i = 0; i < 16; ++i) HexLE(s, v[i].Reg64, 8); // GPR
    HexLE(s, v[16].Reg64, 8);                              // rip
    HexLE(s, v[17].Reg64 & 0xFFFFFFFF, 4);                 // eflags
    for (int i = 18; i < kN; ++i)                          // segs
        HexLE(s, v[i].Segment.Selector, 4);
    return s;
}

void GdbServer::WriteRegisters(uint32_t vp, const std::string& hex)
{
    auto rd = [&](size_t off, int bytes) {
        uint64_t x = 0;
        for (int i = 0; i < bytes; ++i)
        {
            uint8_t b = (Unhex(hex[off + i * 2]) << 4) |
                        Unhex(hex[off + i * 2 + 1]);
            x |= uint64_t(b) << (8 * i);
        }
        return x;
    };
    WHV_REGISTER_NAME n[17];
    WHV_REGISTER_VALUE v[17] = {};
    for (int i = 0; i < 16; ++i)
    {
        n[i] = kRegs[i];
        v[i].Reg64 = rd(i * 16, 8);
    }
    n[16] = WHvX64RegisterRip;
    v[16].Reg64 = rd(16 * 16, 8);
    m_part.SetRegisters(vp, n, 17, v);
}

std::string GdbServer::ReadMem(uint64_t gva, uint64_t len)
{
    std::string out;
    for (uint64_t i = 0; i < len; ++i)
    {
        uint64_t gpa = 0;
        if (!m_part.TranslateGva(0, gva + i, gpa)) return "E14";
        uint8_t* p = static_cast<uint8_t*>(m_mem.HostPtr(gpa, 1));
        if (!p) return "E14";
        uint8_t b = *p;
        // Show the shadowed original byte, not the planted 0xCC.
        auto it = m_bps.find(gva + i);
        if (it != m_bps.end()) b = it->second;
        HexByte(out, b);
    }
    return out;
}

bool GdbServer::WriteMem(uint64_t gva, const std::string& hexData)
{
    for (size_t i = 0; i + 1 < hexData.size(); i += 2)
    {
        uint64_t gpa = 0;
        if (!m_part.TranslateGva(0, gva + i / 2, gpa)) return false;
        uint8_t* p = static_cast<uint8_t*>(m_mem.HostPtr(gpa, 1));
        if (!p) return false;
        *p = (Unhex(hexData[i]) << 4) | Unhex(hexData[i + 1]);
    }
    return true;
}

void GdbServer::InsertBreakpoint(uint64_t gva)
{
    if (m_bps.count(gva)) return;
    uint64_t gpa = 0;
    if (!m_part.TranslateGva(0, gva, gpa)) return;
    uint8_t* p = static_cast<uint8_t*>(m_mem.HostPtr(gpa, 1));
    if (!p) return;
    m_bps[gva] = *p;
    *p = 0xCC;
}

void GdbServer::RemoveBreakpoint(uint64_t gva)
{
    auto it = m_bps.find(gva);
    if (it == m_bps.end()) return;
    uint64_t gpa = 0;
    if (m_part.TranslateGva(0, gva, gpa))
    {
        uint8_t* p = static_cast<uint8_t*>(m_mem.HostPtr(gpa, 1));
        if (p) *p = it->second;
    }
    m_bps.erase(it);
}

void GdbServer::ReinsertAll()
{
    for (auto& kv : m_bps)
    {
        uint64_t gpa = 0;
        if (m_part.TranslateGva(0, kv.first, gpa))
        {
            uint8_t* p =
                static_cast<uint8_t*>(m_mem.HostPtr(gpa, 1));
            if (p) *p = 0xCC;
        }
    }
}

int GdbServer::OnException(uint32_t vp, uint8_t exceptionType)
{
    if (exceptionType == 3) // #BP
    {
        // Two flavours of #BP exit here, and the rewind is only
        // correct for one of them:
        //
        // (1) Gdb-planted soft breakpoint. We replaced the original
        //     instruction byte at bp_va with 0xCC. The CPU executed
        //     0xCC and #BP'd; RIP now points just PAST the 0xCC
        //     (= bp_va + 1). Gdb (and the step-off-bp dance in
        //     ApplyResume() → StepOffBegin) both assume the reported
        //     PC equals bp_va, so we rewind by one.
        //
        // (2) Source-hardcoded `int3` not owned by gdb — e.g. the
        //     kernel's traps self-test in kernel/arch/x86_64/traps.cpp
        //     ("[traps] self-test" sentinel) or any in-kernel KBP
        //     probe. The byte at rip-1 IS 0xCC but WE didn't plant
        //     it; we just want the client to see a one-shot SIGTRAP
        //     and resume past it. Rewinding instead loops the int3
        //     forever (each `c` resumes at the same 0xCC, re-traps,
        //     rewinds again — the previous behaviour halted boot
        //     permanently at the traps self-test under any attached
        //     debugger).
        //
        // Distinguish by membership in m_bps. If rip-1 is one we
        // planted, it's ours; otherwise hands off.
        const uint64_t rip = m_part.GetRip(vp);
        if (m_bps.count(rip - 1) != 0)
        {
            m_part.SetRip(vp, rip - 1);
        }
    }
    return 5; // SIGTRAP for both #BP and #DB(single-step)
}

bool GdbServer::RipAtBreakpoint(uint32_t vp) const
{
    return m_bps.count(m_part.GetRip(vp)) != 0;
}

void GdbServer::StepOffBegin(uint32_t vp)
{
    const uint64_t rip = m_part.GetRip(vp);
    auto it = m_bps.find(rip);
    if (it == m_bps.end()) return;
    uint64_t gpa = 0;
    if (m_part.TranslateGva(0, rip, gpa))
    {
        uint8_t* p = static_cast<uint8_t*>(m_mem.HostPtr(gpa, 1));
        if (p) *p = it->second; // restore original; keep shadow
    }
    m_stepOverBp = rip;
    m_haveStepOver = true;
}

void GdbServer::StepOffEnd()
{
    if (!m_haveStepOver) return;
    uint64_t gpa = 0;
    if (m_part.TranslateGva(0, m_stepOverBp, gpa))
    {
        uint8_t* p = static_cast<uint8_t*>(m_mem.HostPtr(gpa, 1));
        if (p) *p = 0xCC;
    }
    m_haveStepOver = false;
}

GdbServer::Resume GdbServer::ServeStopped(int sig)
{
    // Park the async-interrupt watcher for the duration. While we're
    // stopped, gdb's in-band `\x03` is handled by the cmd == "\x03"
    // arm in this function — the watcher would only race for the
    // same byte. RAII so every return path clears the flag.
    struct InServeStoppedGuard
    {
        std::atomic<bool>& flag;
        explicit InServeStoppedGuard(std::atomic<bool>& f) : flag(f)
        {
            flag.store(true);
        }
        ~InServeStoppedGuard() { flag.store(false); }
    } _guard(m_inServeStopped);

    for (;;)
    {
        std::string pkt = RecvPacket();
        if (pkt.empty()) return Resume::Detach;

        const char cmd = pkt[0];
        if (pkt == "\x03")
        {
            SendPacket("S05");
            continue;
        }
        if (cmd == '?')
        {
            char b[8];
            std::snprintf(b, sizeof(b), "S%02x", sig);
            SendPacket(b);
        }
        else if (pkt.rfind("qSupported", 0) == 0)
        {
            SendPacket("PacketSize=4000;qXfer:features:read+");
        }
        else if (pkt.rfind("qXfer:features:read:target.xml:", 0) == 0)
        {
            SendPacket(std::string("l") + kTargetXml);
        }
        else if (pkt.rfind("qRcmd,", 0) == 0)
        {
            std::string rcmd;
            for (size_t i = 6; i + 1 < pkt.size(); i += 2)
            {
                rcmd += static_cast<char>(
                    (Unhex(pkt[i]) << 4) | Unhex(pkt[i + 1]));
            }
            std::string out =
                m_monitor ? m_monitor(rcmd)
                          : std::string("no introspector\n");
            std::string hexed;
            for (unsigned char ch : out) HexByte(hexed, ch);
            SendPacket("O" + hexed); // console output
            SendPacket("OK");
        }
        else if (cmd == 'g')
        {
            SendPacket(ReadRegisters(0));
        }
        else if (cmd == 'G')
        {
            WriteRegisters(0, pkt.substr(1));
            SendPacket("OK");
        }
        else if (cmd == 'm')
        {
            uint64_t a = 0, l = 0;
            std::sscanf(pkt.c_str() + 1, "%llx,%llx",
                        (unsigned long long*)&a,
                        (unsigned long long*)&l);
            SendPacket(ReadMem(a, l));
        }
        else if (cmd == 'M')
        {
            uint64_t a = 0, l = 0;
            int off = 0;
            std::sscanf(pkt.c_str() + 1, "%llx,%llx:%n",
                        (unsigned long long*)&a,
                        (unsigned long long*)&l, &off);
            bool ok = WriteMem(a, pkt.substr(1 + off));
            SendPacket(ok ? "OK" : "E14");
        }
        else if (cmd == 'Z' && pkt[1] == '0')
        {
            uint64_t a = 0;
            std::sscanf(pkt.c_str() + 3, "%llx",
                        (unsigned long long*)&a);
            InsertBreakpoint(a);
            SendPacket("OK");
        }
        else if (cmd == 'z' && pkt[1] == '0')
        {
            uint64_t a = 0;
            std::sscanf(pkt.c_str() + 3, "%llx",
                        (unsigned long long*)&a);
            RemoveBreakpoint(a);
            SendPacket("OK");
        }
        else if (cmd == 'c')
        {
            ReinsertAll();
            return Resume::Continue;
        }
        else if (cmd == 's')
        {
            ReinsertAll();
            return Resume::Step;
        }
        else if (cmd == 'D' || cmd == 'k')
        {
            SendPacket("OK");
            return Resume::Detach;
        }
        else
        {
            SendPacket(""); // unsupported -> empty (gdb convention)
        }
    }
}

} // namespace duetos::vmm
