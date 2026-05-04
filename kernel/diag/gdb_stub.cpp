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
#include "arch/x86_64/traps.h"
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

// RFLAGS.TF — set on `s` (single-step), cleared on `c`.
constexpr u64 kRflagsTf = 1ULL << 8;

// Software-breakpoint table. Each entry holds the patched
// address and the byte we replaced with int3. Bounded — 32
// breakpoints is well above what an interactive session ever
// needs at once. Inserted by the `Z0` handler, removed by `z0`.
struct SwBreakpoint
{
    bool in_use;
    u64 addr;
    u8 original;
};
constexpr u32 kMaxSwBreakpoints = 32;
constinit SwBreakpoint g_breakpoints[kMaxSwBreakpoints]{};

// Set by the `c` / `s` / `D` / `k` handlers; read by the wait
// loop to decide when to exit. The loop clears it on entry.
constinit ResumeAction g_resume_pending = ResumeAction::Continue;
constinit bool g_resume_signalled = false;
constinit ResumeAction g_last_resume = ResumeAction::Continue;

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
        // Advertise our capability set:
        //   PacketSize=1000      — 0x1000 = 4096 matches kPacketMax.
        //   swbreak+             — we report `T05swbreak:;` from the
        //                          stop loop on int3 hits.
        //   qXfer:features:read+ — we serve a custom target.xml
        //                          via the qXfer path. Without
        //                          this GDB defaults to the full
        //                          amd64 register set (~150 regs
        //                          including AVX/AVX-512) and
        //                          rejects our 24-reg `g` reply.
        SendCStr("PacketSize=1000;swbreak+;qXfer:features:read+");
        return;
    }
    if (MatchPrefix(g_packet, g_packet_len, "qXfer:features:read:target.xml:"))
    {
        // Reply with the entire description as a single 'l' chunk
        // (l = last). The target.xml describes a 24-register
        // x86_64 layout matching exactly what the `g` packet emits.
        // GDB then knows our register count, sizes, and
        // semantic types, and asks for nothing more.
        //
        // No FPU / SSE / AVX features advertised — the kernel
        // runs `-mno-sse`. Adding them would let GDB display
        // those regs but their values would all be zero (we
        // don't preserve them across traps), which is misleading.
        // GDB's amd64-tdep validator requires both the
        // `org.gnu.gdb.i386.core` and `org.gnu.gdb.i386.sse`
        // features, AND the SSE feature's xmm regs must
        // reference a `vec128` union type AND the mxcsr must
        // reference an `i386_mxcsr` flags type — otherwise the
        // architecture is rejected and GDB falls back to its
        // built-in default (which today includes AVX-512 = 154
        // registers, which our `g` reply doesn't satisfy →
        // "Truncated register 154").
        //
        // The verbatim type-def + feature blocks below are
        // adapted from `gdb/features/i386/64bit-{core,sse}.xml`
        // in upstream GDB. Trimmed to the minimum
        // amd64-tdep accepts: 24 core regs + the FPU/SSE block
        // (zero-filled in the `g` reply since the kernel runs
        // `-mno-sse`).
        // Trimmed minimum: skip the eflags/mxcsr <flags> and the
        // st0..st7 i387_ext type and put everything inline as
        // bare-typed regs. xmm regs need the vec128 union (GDB
        // amd64-tdep insists). Total ~3500 bytes, fits inside
        // GDB's 4091-byte qXfer chunk.
        static constexpr char kTargetXml[] =
            "l<?xml version=\"1.0\"?>"
            "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">"
            "<target>"
            "<architecture>i386:x86-64</architecture>"
            "<feature name=\"org.gnu.gdb.i386.core\">"
            "<reg name=\"rax\" bitsize=\"64\"/>"
            "<reg name=\"rbx\" bitsize=\"64\"/>"
            "<reg name=\"rcx\" bitsize=\"64\"/>"
            "<reg name=\"rdx\" bitsize=\"64\"/>"
            "<reg name=\"rsi\" bitsize=\"64\"/>"
            "<reg name=\"rdi\" bitsize=\"64\"/>"
            "<reg name=\"rbp\" bitsize=\"64\"/>"
            "<reg name=\"rsp\" bitsize=\"64\"/>"
            "<reg name=\"r8\" bitsize=\"64\"/>"
            "<reg name=\"r9\" bitsize=\"64\"/>"
            "<reg name=\"r10\" bitsize=\"64\"/>"
            "<reg name=\"r11\" bitsize=\"64\"/>"
            "<reg name=\"r12\" bitsize=\"64\"/>"
            "<reg name=\"r13\" bitsize=\"64\"/>"
            "<reg name=\"r14\" bitsize=\"64\"/>"
            "<reg name=\"r15\" bitsize=\"64\"/>"
            "<reg name=\"rip\" bitsize=\"64\" type=\"code_ptr\"/>"
            "<reg name=\"eflags\" bitsize=\"32\"/>"
            "<reg name=\"cs\" bitsize=\"32\"/>"
            "<reg name=\"ss\" bitsize=\"32\"/>"
            "<reg name=\"ds\" bitsize=\"32\"/>"
            "<reg name=\"es\" bitsize=\"32\"/>"
            "<reg name=\"fs\" bitsize=\"32\"/>"
            "<reg name=\"gs\" bitsize=\"32\"/>"
            "<reg name=\"st0\" bitsize=\"64\"/>"
            "<reg name=\"st1\" bitsize=\"64\"/>"
            "<reg name=\"st2\" bitsize=\"64\"/>"
            "<reg name=\"st3\" bitsize=\"64\"/>"
            "<reg name=\"st4\" bitsize=\"64\"/>"
            "<reg name=\"st5\" bitsize=\"64\"/>"
            "<reg name=\"st6\" bitsize=\"64\"/>"
            "<reg name=\"st7\" bitsize=\"64\"/>"
            "<reg name=\"fctrl\" bitsize=\"32\"/>"
            "<reg name=\"fstat\" bitsize=\"32\"/>"
            "<reg name=\"ftag\" bitsize=\"32\"/>"
            "<reg name=\"fiseg\" bitsize=\"32\"/>"
            "<reg name=\"fioff\" bitsize=\"32\"/>"
            "<reg name=\"foseg\" bitsize=\"32\"/>"
            "<reg name=\"fooff\" bitsize=\"32\"/>"
            "<reg name=\"fop\" bitsize=\"32\"/>"
            "</feature>"
            "<feature name=\"org.gnu.gdb.i386.sse\">"
            "<vector id=\"v2d\" type=\"ieee_double\" count=\"2\"/>"
            "<vector id=\"v4f\" type=\"ieee_single\" count=\"4\"/>"
            "<vector id=\"v2i64\" type=\"int64\" count=\"2\"/>"
            "<vector id=\"v4i32\" type=\"int32\" count=\"4\"/>"
            "<vector id=\"v8i16\" type=\"int16\" count=\"8\"/>"
            "<vector id=\"v16i8\" type=\"int8\" count=\"16\"/>"
            "<union id=\"vec128\">"
            "<field name=\"v4_float\" type=\"v4f\"/>"
            "<field name=\"v2_double\" type=\"v2d\"/>"
            "<field name=\"v16_int8\" type=\"v16i8\"/>"
            "<field name=\"v8_int16\" type=\"v8i16\"/>"
            "<field name=\"v4_int32\" type=\"v4i32\"/>"
            "<field name=\"v2_int64\" type=\"v2i64\"/>"
            "<field name=\"uint128\" type=\"uint128\"/>"
            "</union>"
            "<reg name=\"xmm0\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm1\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm2\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm3\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm4\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm5\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm6\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm7\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm8\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm9\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm10\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm11\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm12\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm13\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm14\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"xmm15\" bitsize=\"128\" type=\"vec128\"/>"
            "<reg name=\"mxcsr\" bitsize=\"32\"/>"
            "</feature>"
            "</target>";
        SendReply(kTargetXml, sizeof(kTargetXml) - 1);
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
        // the canonical x86_64 order from our `target.xml`
        // description (sent via the qXfer:features:read path
        // below). Each u64 = 16 hex chars little-endian; each
        // u32 = 8 hex chars. Then the SSE block GDB's
        // amd64-tdep validator demands: 8 × st(80b=10B), 8 ×
        // FPU control (32b each), 16 × xmm (128b=16B each),
        // mxcsr (32b). Total core 336 + SSE 1064 = 1400 hex
        // chars.
        //
        // SSE / FPU bytes are zero — the kernel runs `-mno-sse`
        // so those registers are unused; we can't lie that
        // they're "valid" but reporting zero is the same
        // pattern minidump CONTEXT_X64 uses for FltSave.
        // Core hex: 16 GPR (16) + rip (16) + eflags (8 — u32!) +
        //           6 segs (8 each) = 256 + 16 + 8 + 48 = 328
        // SSE hex:  8 st (16) + 8 fpu_ctrl (8) + 16 xmm (32) + mxcsr (8)
        //         = 128 + 64 + 512 + 8 = 712
        constexpr u32 kCoreHex = 16 * 16 + 16 + 8 + 6 * 8;
        constexpr u32 kSseHex = (8 * 8 + 8 * 4 + 16 * 16 + 4) * 2;
        constexpr u32 kReplyChars = kCoreHex + kSseHex;
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
        // eflags is declared 32-bit in target.xml; emit only 4 bytes
        // (low half of the latched RFLAGS).
        put_u32(static_cast<u32>(r.rflags & 0xFFFFFFFFu));
        put_u32(r.cs);
        put_u32(r.ss);
        put_u32(r.ds);
        put_u32(r.es);
        put_u32(r.fs);
        put_u32(r.gs);
        // SSE pad — zeros for st0..st7 + FPU control + xmm0..15 +
        // mxcsr. Total 1064 hex chars; trips the amd64-tdep
        // requirement without claiming meaningful FPU values.
        for (u32 i = 0; i < kSseHex; ++i)
        {
            buf[off++] = '0';
        }
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
        // Detach. No reply expected. Mark the resume so the wait
        // loop drops out and the trap dispatcher returns instead
        // of waiting for further packets that will never come.
        g_resume_pending = ResumeAction::Killed;
        g_resume_signalled = true;
        return;
    }
    if (g_packet[0] == 'c')
    {
        // Continue. No reply now — the stop loop exits and the
        // trap returns; the *next* stop (breakpoint / step) will
        // send a fresh `T05`.
        if (g_regs_writable != nullptr)
        {
            // Make sure single-step is OFF on a plain continue —
            // a previous `s` may have left RFLAGS.TF set.
            g_regs_writable->rflags &= ~kRflagsTf;
        }
        g_resume_pending = ResumeAction::Continue;
        g_resume_signalled = true;
        return;
    }
    if (g_packet[0] == 's')
    {
        // Single-step. Set RFLAGS.TF so the *next* instruction
        // raises #DB, which re-enters the trap dispatcher and
        // calls GdbStubEnterAndWait again — at which point we
        // send a fresh stop packet to GDB. No reply now.
        if (g_regs_writable != nullptr)
        {
            g_regs_writable->rflags |= kRflagsTf;
        }
        g_resume_pending = ResumeAction::Step;
        g_resume_signalled = true;
        return;
    }
    if (g_packet[0] == 'D')
    {
        // Detach cleanly — reply OK, then the wait loop exits.
        SendCStr("OK");
        g_resume_pending = ResumeAction::Detached;
        g_resume_signalled = true;
        return;
    }
    if (g_packet[0] == 'Z' || g_packet[0] == 'z')
    {
        // Z<type>,<addr>,<kind> — set/clear breakpoint.
        // Z0 is software (int3); Z1..Z4 are hardware. We support
        // Z0 only today; other types fall through to the empty
        // reply, which GDB interprets as "use software-emulated
        // breakpoints" and inserts via the M (write memory)
        // packet instead.
        const bool insert = g_packet[0] == 'Z';
        if (g_packet_len < 4 || g_packet[1] != '0')
        {
            SendCStr(""); // unsupported breakpoint kind
            return;
        }
        if (g_packet[2] != ',')
        {
            SendCStr("E01");
            return;
        }
        u64 addr = 0;
        u32 i = 3;
        while (i < g_packet_len && g_packet[i] != ',')
        {
            if (!IsHexDigit(g_packet[i]))
                break;
            addr = (addr << 4) | HexDigitValue(g_packet[i]);
            ++i;
        }
        // We don't read the kind — int3 is always 1 byte on x86_64.
        const u64 high = addr >> 47;
        if (high != 0 && high != 0x1FFFF)
        {
            SendCStr("E14");
            return;
        }
        if (insert)
        {
            // Find a free slot, save the original byte, patch int3.
            for (u32 s = 0; s < kMaxSwBreakpoints; ++s)
            {
                if (g_breakpoints[s].in_use && g_breakpoints[s].addr == addr)
                {
                    SendCStr("OK"); // already set
                    return;
                }
            }
            for (u32 s = 0; s < kMaxSwBreakpoints; ++s)
            {
                if (!g_breakpoints[s].in_use)
                {
                    u8* p = reinterpret_cast<u8*>(addr);
                    g_breakpoints[s].in_use = true;
                    g_breakpoints[s].addr = addr;
                    g_breakpoints[s].original = *p;
                    *p = 0xCC; // int3
                    SendCStr("OK");
                    return;
                }
            }
            SendCStr("E10"); // no slots
            return;
        }
        else
        {
            for (u32 s = 0; s < kMaxSwBreakpoints; ++s)
            {
                if (g_breakpoints[s].in_use && g_breakpoints[s].addr == addr)
                {
                    u8* p = reinterpret_cast<u8*>(addr);
                    *p = g_breakpoints[s].original;
                    g_breakpoints[s].in_use = false;
                    SendCStr("OK");
                    return;
                }
            }
            SendCStr("OK"); // not set is not an error
            return;
        }
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

// ---------------------------------------------------------------------------
// COM2 wiring + stop loop
// ---------------------------------------------------------------------------

void GdbStubInitCom2()
{
    arch::SerialCom2Init();
    GdbStubSetSink(&arch::SerialCom2WriteByte);
}

namespace
{

// Send a stop packet (`T<sig>...;`) to the attached debugger so
// it knows the kernel has paused. We always send SIGTRAP (5);
// the trailing `swbreak:;` / `hwbreak:;` keys are GDB stop-reason
// hints — important when the same handler covers both int3 and
// single-step.
void SendStop(StopReason reason)
{
    switch (reason)
    {
    case StopReason::SoftBreak:
        SendCStr("T05swbreak:;");
        break;
    case StopReason::SingleStep:
        // No swbreak / hwbreak key — GDB infers single-step from
        // the absence of a breakpoint reason at the current PC.
        SendCStr("T05");
        break;
    case StopReason::UserHalt:
    case StopReason::Trap:
    default:
        SendCStr("S05");
        break;
    }
}

} // namespace

void GdbStubEnterAndWait(StopReason reason)
{
    if (g_sink == nullptr)
    {
        // Stub never had its output sink installed — there's no
        // attached debugger to talk to. Bail silently rather than
        // looping forever waiting for bytes that won't arrive.
        return;
    }
    g_resume_signalled = false;
    g_resume_pending = ResumeAction::Continue;
    SendStop(reason);
    // Pump bytes from COM2 until a resume command lands. The RX
    // path is a blocking poll — there's no useful work for the
    // CPU to do while paused on a breakpoint, so spinning is
    // fine and avoids the IRQ plumbing required for an
    // event-driven RX.
    while (!g_resume_signalled)
    {
        const u8 byte = arch::SerialCom2ReadByteBlocking();
        GdbStubReceiveByte(byte);
    }
    g_last_resume = g_resume_pending;
}

ResumeAction GdbStubLastResume()
{
    return g_last_resume;
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

namespace
{

// One global TrapFrame-shadow. The stop loop blocks the CPU so
// only one is needed; we publish g_regs / g_regs_writable to
// point at it for the duration of EnterAndWait.
constinit GdbRegSnapshot g_trap_snapshot{};

// Mirror trap-frame state into the GdbRegSnapshot the stub reads.
// The CPU pushes data segments only via mov; ds/es/fs/gs are
// sampled live so they reflect the current kernel-mode values.
void TrapFrameToSnapshot(const arch::TrapFrame* f, GdbRegSnapshot& snap)
{
    snap.rax = f->rax;
    snap.rbx = f->rbx;
    snap.rcx = f->rcx;
    snap.rdx = f->rdx;
    snap.rsi = f->rsi;
    snap.rdi = f->rdi;
    snap.rbp = f->rbp;
    snap.rsp = f->rsp;
    snap.r8 = f->r8;
    snap.r9 = f->r9;
    snap.r10 = f->r10;
    snap.r11 = f->r11;
    snap.r12 = f->r12;
    snap.r13 = f->r13;
    snap.r14 = f->r14;
    snap.r15 = f->r15;
    snap.rip = f->rip;
    snap.rflags = f->rflags;
    snap.cs = static_cast<u32>(f->cs);
    snap.ss = static_cast<u32>(f->ss);
    u16 ds = 0, es = 0, fs = 0, gs = 0;
    asm volatile("mov %%ds, %0" : "=r"(ds));
    asm volatile("mov %%es, %0" : "=r"(es));
    asm volatile("mov %%fs, %0" : "=r"(fs));
    asm volatile("mov %%gs, %0" : "=r"(gs));
    snap.ds = ds;
    snap.es = es;
    snap.fs = fs;
    snap.gs = gs;
}

// Inverse: write back any GPR / RIP / RFLAGS the debugger may
// have edited via `G` (or set via `c`/`s` itself for RFLAGS.TF).
// Segment selectors are NOT written back — touching CS/SS during
// trap return would invalidate the iretq frame and is not what
// a debugger session changes anyway.
void SnapshotToTrapFrame(const GdbRegSnapshot& snap, arch::TrapFrame* f)
{
    f->rax = snap.rax;
    f->rbx = snap.rbx;
    f->rcx = snap.rcx;
    f->rdx = snap.rdx;
    f->rsi = snap.rsi;
    f->rdi = snap.rdi;
    f->rbp = snap.rbp;
    f->rsp = snap.rsp;
    f->r8 = snap.r8;
    f->r9 = snap.r9;
    f->r10 = snap.r10;
    f->r11 = snap.r11;
    f->r12 = snap.r12;
    f->r13 = snap.r13;
    f->r14 = snap.r14;
    f->r15 = snap.r15;
    f->rip = snap.rip;
    f->rflags = snap.rflags;
}

bool RouteToStopLoop(arch::TrapFrame* frame, StopReason reason, bool rollback_rip)
{
    if (g_sink == nullptr)
    {
        return false; // GDB never wired up
    }
    TrapFrameToSnapshot(frame, g_trap_snapshot);
    if (rollback_rip)
    {
        // int3 is a TRAP — the saved RIP points to the byte after
        // the 0xCC. GDB expects RIP AT the breakpoint site so the
        // resume + z0-unpatched-byte sequence executes the original
        // instruction. Bias by -1 here; the SnapshotToTrapFrame
        // path then writes the GDB-edited RIP back to the frame.
        g_trap_snapshot.rip -= 1;
    }
    GdbStubPublishRegisters(&g_trap_snapshot);
    GdbStubPublishWritableRegisters(&g_trap_snapshot);
    GdbStubEnterAndWait(reason);
    GdbStubPublishRegisters(nullptr);
    GdbStubPublishWritableRegisters(nullptr);
    SnapshotToTrapFrame(g_trap_snapshot, frame);
    return true;
}

} // namespace

bool HandleSoftwareBreakpoint(arch::TrapFrame* frame)
{
    return RouteToStopLoop(frame, StopReason::SoftBreak, /*rollback_rip=*/true);
}

bool HandleDebugException(arch::TrapFrame* frame)
{
    // #DB (single-step) is a TRAP-class fault: RIP points at the
    // instruction *after* the one that completed. No rollback —
    // GDB wants to see "the previous step finished, here's where
    // we are now" and the next `s` / `c` resumes from this RIP.
    // Clear RFLAGS.TF so the resume doesn't immediately re-step
    // unless GDB explicitly asks (the `s` handler re-sets it).
    frame->rflags &= ~(1ULL << 8);
    return RouteToStopLoop(frame, StopReason::SingleStep, /*rollback_rip=*/false);
}

} // namespace duetos::diag::gdb
