/*
 * DuetOS — GDB remote serial protocol stub v0 (plan D7).
 *
 * See `gdb_stub.h` for the public contract. v0 is the framing
 * + checksum + a minimal handler table; the live register /
 * memory paths return zeros / ACKs so a future wiring slice
 * can attach a real GDB session against this scaffold.
 */

#include "diag/gdb_stub.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"

namespace duetos::diag::gdb
{

namespace
{

// Parser state machine.
enum class State : u8
{
    Idle,  ///< Waiting for `$` packet-start.
    Body,  ///< Accumulating packet body until `#`.
    Csum1, ///< Reading first checksum hex digit.
    Csum2, ///< Reading second checksum hex digit.
};

constinit State g_state = State::Idle;
constinit u8 g_packet[kPacketMax];
constinit u32 g_packet_len = 0;
constinit u8 g_csum_calc = 0;
constinit u8 g_csum_recv = 0;

constinit GdbStubWriteByte g_sink = nullptr;
constinit const GdbRegSnapshot* g_regs = nullptr;
constinit GdbRegSnapshot* g_regs_writable = nullptr;

constinit u64 g_packets_received = 0;
constinit u64 g_packets_bad_csum = 0;
constinit u64 g_packets_handled = 0;

bool IsHexDigit(u8 c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

u8 HexDigitValue(u8 c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return 0;
}

u8 HexDigitChar(u8 v)
{
    return (v < 10) ? u8('0' + v) : u8('a' + (v - 10));
}

void EmitByte(u8 b)
{
    if (g_sink != nullptr)
    {
        g_sink(b);
    }
}

bool MatchPrefix(const u8* body, u32 len, const char* prefix)
{
    for (u32 i = 0; prefix[i] != '\0'; ++i)
    {
        if (i >= len || body[i] != static_cast<u8>(prefix[i]))
            return false;
    }
    return true;
}

// Send a `$<payload>#<csum>` reply. The caller passes the raw
// payload bytes + length; the function frames + checksums.
void SendReply(const char* payload, u32 len)
{
    EmitByte('$');
    u8 csum = 0;
    for (u32 i = 0; i < len; ++i)
    {
        const u8 b = static_cast<u8>(payload[i]);
        EmitByte(b);
        csum = static_cast<u8>(csum + b);
    }
    EmitByte('#');
    EmitByte(HexDigitChar((csum >> 4) & 0xF));
    EmitByte(HexDigitChar(csum & 0xF));
}

void SendCStr(const char* payload)
{
    u32 len = 0;
    while (payload[len] != '\0')
        ++len;
    SendReply(payload, len);
}

void HandlePacket()
{
    ++g_packets_handled;
    if (g_packet_len == 0)
    {
        SendCStr("");
        return;
    }
    if (MatchPrefix(g_packet, g_packet_len, "qSupported"))
    {
        // Advertise the v0 capability set. Keep it short — GDB
        // only needs to know the packet size + that we don't
        // support the optional features.
        SendCStr("PacketSize=400");
        return;
    }
    if (g_packet[0] == '?')
    {
        // Halt reason — SIGTRAP (5).
        SendCStr("S05");
        return;
    }
    if (g_packet[0] == 'g')
    {
        // 16 × u64 GPRs + rip + rflags + 6 × u32 segments, in
        // GDB's canonical x86_64 order. Each u64 = 16 hex chars
        // little-endian; each u32 = 8 hex chars. Size:
        //   16*16 (GPRs) + 16 (rip) + 16 (rflags) + 6*8 (segs)
        //   = 256 + 16 + 16 + 48 = 336 hex chars.
        constexpr u32 kReplyChars = 16 * 16 + 16 + 16 + 6 * 8;
        char buf[kReplyChars + 1];
        u32 off = 0;
        auto put_u64 = [&](u64 v)
        {
            // Little-endian byte order: GDB expects the LSB first.
            for (u32 i = 0; i < 8; ++i)
            {
                const u8 b = static_cast<u8>(v >> (i * 8));
                buf[off++] = HexDigitChar((b >> 4) & 0xF);
                buf[off++] = HexDigitChar(b & 0xF);
            }
        };
        auto put_u32 = [&](u32 v)
        {
            for (u32 i = 0; i < 4; ++i)
            {
                const u8 b = static_cast<u8>(v >> (i * 8));
                buf[off++] = HexDigitChar((b >> 4) & 0xF);
                buf[off++] = HexDigitChar(b & 0xF);
            }
        };
        const GdbRegSnapshot z{};
        const GdbRegSnapshot& r = (g_regs != nullptr) ? *g_regs : z;
        put_u64(r.rax);
        put_u64(r.rbx);
        put_u64(r.rcx);
        put_u64(r.rdx);
        put_u64(r.rsi);
        put_u64(r.rdi);
        put_u64(r.rbp);
        put_u64(r.rsp);
        put_u64(r.r8);
        put_u64(r.r9);
        put_u64(r.r10);
        put_u64(r.r11);
        put_u64(r.r12);
        put_u64(r.r13);
        put_u64(r.r14);
        put_u64(r.r15);
        put_u64(r.rip);
        put_u64(r.rflags);
        put_u32(r.cs);
        put_u32(r.ss);
        put_u32(r.ds);
        put_u32(r.es);
        put_u32(r.fs);
        put_u32(r.gs);
        buf[off] = '\0';
        SendReply(buf, off);
        return;
    }
    if (g_packet[0] == 'G')
    {
        // G<hex> — parse the same little-endian byte order the
        // 'g' handler emits and copy back into the writable
        // snapshot. Silently OK when no writable snapshot is
        // published.
        if (g_regs_writable != nullptr)
        {
            const u32 body_off = 1;
            auto take_u64 = [&](u32 idx) -> u64
            {
                u64 v = 0;
                const u32 base = body_off + idx * 16;
                for (u32 i = 0; i < 8; ++i)
                {
                    if (base + i * 2 + 1 >= g_packet_len)
                        return v;
                    const u8 hi = HexDigitValue(g_packet[base + i * 2]);
                    const u8 lo = HexDigitValue(g_packet[base + i * 2 + 1]);
                    v |= static_cast<u64>((hi << 4) | lo) << (i * 8);
                }
                return v;
            };
            auto take_u32 = [&](u32 hex_off) -> u32
            {
                u32 v = 0;
                for (u32 i = 0; i < 4; ++i)
                {
                    if (hex_off + i * 2 + 1 >= g_packet_len)
                        return v;
                    const u8 hi = HexDigitValue(g_packet[hex_off + i * 2]);
                    const u8 lo = HexDigitValue(g_packet[hex_off + i * 2 + 1]);
                    v |= static_cast<u32>((hi << 4) | lo) << (i * 8);
                }
                return v;
            };
            g_regs_writable->rax = take_u64(0);
            g_regs_writable->rbx = take_u64(1);
            g_regs_writable->rcx = take_u64(2);
            g_regs_writable->rdx = take_u64(3);
            g_regs_writable->rsi = take_u64(4);
            g_regs_writable->rdi = take_u64(5);
            g_regs_writable->rbp = take_u64(6);
            g_regs_writable->rsp = take_u64(7);
            g_regs_writable->r8 = take_u64(8);
            g_regs_writable->r9 = take_u64(9);
            g_regs_writable->r10 = take_u64(10);
            g_regs_writable->r11 = take_u64(11);
            g_regs_writable->r12 = take_u64(12);
            g_regs_writable->r13 = take_u64(13);
            g_regs_writable->r14 = take_u64(14);
            g_regs_writable->r15 = take_u64(15);
            g_regs_writable->rip = take_u64(16);
            g_regs_writable->rflags = take_u64(17);
            const u32 seg_off = body_off + 18 * 16;
            g_regs_writable->cs = take_u32(seg_off + 0 * 8);
            g_regs_writable->ss = take_u32(seg_off + 1 * 8);
            g_regs_writable->ds = take_u32(seg_off + 2 * 8);
            g_regs_writable->es = take_u32(seg_off + 3 * 8);
            g_regs_writable->fs = take_u32(seg_off + 4 * 8);
            g_regs_writable->gs = take_u32(seg_off + 5 * 8);
        }
        SendCStr("OK");
        return;
    }
    if (g_packet[0] == 'm')
    {
        // m<addr>,<len> — parse the two hex args separated by
        // ',', then read up to `len` bytes from `addr` and reply
        // hex-encoded. Bounds the read at half the packet
        // capacity (each byte costs 2 hex chars + framing). The
        // kernel-VA read is direct — extable-protected access
        // is a future D7-followup.
        u64 addr = 0;
        u64 len = 0;
        u32 i = 1;
        while (i < g_packet_len && g_packet[i] != ',')
        {
            if (!IsHexDigit(g_packet[i]))
                break;
            addr = (addr << 4) | HexDigitValue(g_packet[i]);
            ++i;
        }
        if (i >= g_packet_len || g_packet[i] != ',')
        {
            SendCStr("E01");
            return;
        }
        ++i;
        while (i < g_packet_len)
        {
            if (!IsHexDigit(g_packet[i]))
                break;
            len = (len << 4) | HexDigitValue(g_packet[i]);
            ++i;
        }
        constexpr u64 kMaxLen = (kPacketMax / 2) - 8; // leave room for framing
        if (len > kMaxLen)
            len = kMaxLen;
        // Refuse non-canonical addresses to keep a typo from
        // walking off into a non-mapped half of the AS.
        const u64 high = addr >> 47;
        if (high != 0 && high != 0x1FFFF)
        {
            SendCStr("E14"); // GDB's EFAULT-style code
            return;
        }
        char buf[kPacketMax];
        u32 off = 0;
        const u8* p = reinterpret_cast<const u8*>(addr);
        for (u64 k = 0; k < len && off + 2 <= sizeof(buf); ++k)
        {
            const u8 b = p[k];
            buf[off++] = HexDigitChar((b >> 4) & 0xF);
            buf[off++] = HexDigitChar(b & 0xF);
        }
        if (off == 0)
        {
            SendCStr("00");
        }
        else
        {
            SendReply(buf, off);
        }
        return;
    }
    if (g_packet[0] == 'M')
    {
        // M<addr>,<len>:<hex> — write `len` bytes from the hex
        // payload to `addr`. Same canonical-address bound as
        // the `m` handler; per-byte direct kernel write.
        u64 addr = 0;
        u64 len = 0;
        u32 i = 1;
        while (i < g_packet_len && g_packet[i] != ',')
        {
            if (!IsHexDigit(g_packet[i]))
                break;
            addr = (addr << 4) | HexDigitValue(g_packet[i]);
            ++i;
        }
        if (i >= g_packet_len || g_packet[i] != ',')
        {
            SendCStr("E01");
            return;
        }
        ++i;
        while (i < g_packet_len && g_packet[i] != ':')
        {
            if (!IsHexDigit(g_packet[i]))
                break;
            len = (len << 4) | HexDigitValue(g_packet[i]);
            ++i;
        }
        if (i >= g_packet_len || g_packet[i] != ':')
        {
            SendCStr("E01");
            return;
        }
        ++i;
        const u64 high = addr >> 47;
        if (high != 0 && high != 0x1FFFF)
        {
            SendCStr("E14");
            return;
        }
        u8* p = reinterpret_cast<u8*>(addr);
        for (u64 k = 0; k < len; ++k)
        {
            if (i + 1 >= g_packet_len)
                break;
            const u8 hi = HexDigitValue(g_packet[i]);
            const u8 lo = HexDigitValue(g_packet[i + 1]);
            p[k] = static_cast<u8>((hi << 4) | lo);
            i += 2;
        }
        SendCStr("OK");
        return;
    }
    if (g_packet[0] == 'H')
    {
        SendCStr("OK");
        return;
    }
    if (g_packet[0] == 'k')
    {
        // Detach. No reply expected.
        return;
    }
    // Unsupported — empty packet means "I don't recognise this".
    SendCStr("");
}

void ResetParser()
{
    g_state = State::Idle;
    g_packet_len = 0;
    g_csum_calc = 0;
    g_csum_recv = 0;
}

} // namespace

void GdbStubSetSink(GdbStubWriteByte sink)
{
    g_sink = sink;
}

void GdbStubPublishRegisters(const GdbRegSnapshot* snap)
{
    g_regs = snap;
}

void GdbStubPublishWritableRegisters(GdbRegSnapshot* snap)
{
    g_regs_writable = snap;
}

void GdbStubReceiveByte(u8 byte)
{
    switch (g_state)
    {
    case State::Idle:
        if (byte == '$')
        {
            g_packet_len = 0;
            g_csum_calc = 0;
            g_state = State::Body;
        }
        // ACK / NAK from GDB just dropped on the floor in v0;
        // we don't track our own retransmits.
        break;
    case State::Body:
        if (byte == '#')
        {
            g_state = State::Csum1;
        }
        else if (g_packet_len < kPacketMax)
        {
            g_packet[g_packet_len++] = byte;
            g_csum_calc = static_cast<u8>(g_csum_calc + byte);
        }
        else
        {
            // Overrun — abort the packet.
            ResetParser();
        }
        break;
    case State::Csum1:
        if (IsHexDigit(byte))
        {
            g_csum_recv = static_cast<u8>(HexDigitValue(byte) << 4);
            g_state = State::Csum2;
        }
        else
        {
            ResetParser();
        }
        break;
    case State::Csum2:
        if (IsHexDigit(byte))
        {
            g_csum_recv = static_cast<u8>(g_csum_recv | HexDigitValue(byte));
            ++g_packets_received;
            if (g_csum_recv == g_csum_calc)
            {
                EmitByte('+');
                HandlePacket();
            }
            else
            {
                ++g_packets_bad_csum;
                EmitByte('-');
            }
            ResetParser();
        }
        else
        {
            ResetParser();
        }
        break;
    default:
        // Unknown / corrupted parser state — reset to a safe baseline.
        ResetParser();
        break;
    }
}

u64 GdbStubPacketsReceived()
{
    return g_packets_received;
}

u64 GdbStubPacketsBadChecksum()
{
    return g_packets_bad_csum;
}

u64 GdbStubPacketsHandled()
{
    return g_packets_handled;
}

namespace
{

// Capturing sink for the self-test — appends every emitted
// byte into a fixed buffer so the test can assert reply shape.
constinit u8 g_capture[256];
constinit u32 g_capture_len = 0;

void CaptureSink(u8 b)
{
    if (g_capture_len < sizeof(g_capture))
    {
        g_capture[g_capture_len++] = b;
    }
}

void FeedString(const char* s)
{
    for (u32 i = 0; s[i] != '\0'; ++i)
    {
        GdbStubReceiveByte(static_cast<u8>(s[i]));
    }
}

bool CaptureContains(const char* needle)
{
    const u32 nlen = [&]
    {
        u32 n = 0;
        while (needle[n] != '\0')
            ++n;
        return n;
    }();
    if (nlen == 0 || nlen > g_capture_len)
        return false;
    for (u32 i = 0; i + nlen <= g_capture_len; ++i)
    {
        bool match = true;
        for (u32 j = 0; j < nlen; ++j)
        {
            if (g_capture[i + j] != static_cast<u8>(needle[j]))
            {
                match = false;
                break;
            }
        }
        if (match)
            return true;
    }
    return false;
}

} // namespace

void GdbStubSelfTest()
{
    arch::SerialWrite("[gdb-stub] self-test: framing + checksum + qSupported handler\n");

    // Save existing state so the self-test is re-runnable.
    GdbStubWriteByte saved_sink = g_sink;
    ResetParser();
    g_capture_len = 0;
    GdbStubSetSink(CaptureSink);

    // qSupported: "$qSupported#" + checksum.
    // Sum of "qSupported" = 0x71+0x53+0x75+0x70+0x70+0x6f+0x72+0x74+0x65+0x64
    //                    = 1079 = 0x437 → low byte 0x37 = "37".
    g_capture_len = 0;
    FeedString("$qSupported#37");
    if (g_packets_received == 0)
    {
        core::Panic("diag/gdb-stub", "self-test: parser did not complete a packet");
    }
    if (!CaptureContains("PacketSize"))
    {
        core::Panic("diag/gdb-stub", "self-test: qSupported reply missing PacketSize");
    }

    // Halt-reason: "$?#3f" — sum of '?' = 0x3F = "3f".
    g_capture_len = 0;
    FeedString("$?#3f");
    if (!CaptureContains("S05"))
    {
        core::Panic("diag/gdb-stub", "self-test: halt-reason reply missing S05");
    }

    // Bad checksum: "$g#00" (real csum = 0x67 = "67"). Should
    // emit '-' (NAK) and bump the bad-csum counter.
    const u64 baseline_bad = g_packets_bad_csum;
    g_capture_len = 0;
    FeedString("$g#00");
    if (g_packets_bad_csum != baseline_bad + 1)
    {
        core::Panic("diag/gdb-stub", "self-test: bad-checksum counter did not advance");
    }
    bool saw_nak = false;
    for (u32 i = 0; i < g_capture_len; ++i)
    {
        if (g_capture[i] == '-')
        {
            saw_nak = true;
            break;
        }
    }
    if (!saw_nak)
    {
        core::Panic("diag/gdb-stub", "self-test: bad-csum path did not emit NAK");
    }

    // Restore the original sink.
    GdbStubSetSink(saved_sink);
    ResetParser();
    g_capture_len = 0;

    arch::SerialWrite("[gdb-stub] self-test OK (framing + qSupported + halt-reason + bad-csum NAK).\n");
}

} // namespace duetos::diag::gdb
