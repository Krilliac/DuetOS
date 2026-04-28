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
    Idle,         ///< Waiting for `$` packet-start.
    Body,         ///< Accumulating packet body until `#`.
    Csum1,        ///< Reading first checksum hex digit.
    Csum2,        ///< Reading second checksum hex digit.
};

constinit State g_state = State::Idle;
constinit u8 g_packet[kPacketMax];
constinit u32 g_packet_len = 0;
constinit u8 g_csum_calc = 0;
constinit u8 g_csum_recv = 0;

constinit GdbStubWriteByte g_sink = nullptr;

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
        // 16 × u64 registers, each as 16 hex chars = 256 bytes.
        // v0 returns zeros.
        char zeros[16 * 16 + 1];
        for (u32 i = 0; i < 16 * 16; ++i)
            zeros[i] = '0';
        zeros[16 * 16] = '\0';
        SendReply(zeros, 16 * 16);
        return;
    }
    if (g_packet[0] == 'G')
    {
        SendCStr("OK");
        return;
    }
    if (g_packet[0] == 'm')
    {
        // m<addr>,<len>. v0 ignores the args and returns zeros
        // up to a small cap. Real memory read via mm + extable
        // is a D7-followup.
        SendCStr("00");
        return;
    }
    if (g_packet[0] == 'M')
    {
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
    //                   = 1067 = 0x42B → low byte 0x2B = "2B".
    g_capture_len = 0;
    FeedString("$qSupported#2b");
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
