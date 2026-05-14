#include "util/vt_parser.h"

#include "arch/x86_64/serial.h"
#include "util/unicode.h"

namespace duetos::util::vt
{

namespace
{

constexpr u8 kBel = 0x07;
constexpr u8 kBs = 0x08;
constexpr u8 kHt = 0x09;
constexpr u8 kLf = 0x0A;
constexpr u8 kVt = 0x0B;
constexpr u8 kFf = 0x0C;
constexpr u8 kCr = 0x0D;
constexpr u8 kEsc = 0x1B;
constexpr u8 kDel = 0x7F;

bool IsExecutableC0(u8 b)
{
    return b == kBel || b == kBs || b == kHt || b == kLf || b == kVt || b == kFf || b == kCr;
}

bool IsCsiFinal(u8 b)
{
    return b >= 0x40 && b <= 0x7E;
}

bool IsCsiPrivateMarker(u8 b)
{
    return b == '?' || b == '>' || b == '=' || b == '<';
}

void ResetCsi(Parser& p)
{
    for (u32 i = 0; i < kMaxParams; ++i)
        p.params[i] = 0;
    p.nparams = 0;
    p.current_param = 0;
    p.current_param_set = false;
    p.overflow_params = false;
    p.private_marker = 0;
}

void ResetOsc(Parser& p)
{
    p.osc_len = 0;
    p.osc_truncated = false;
}

void ResetUtf8(Parser& p)
{
    p.utf8_bytes_remaining = 0;
    p.utf8_seq_len = 0;
    p.utf8_accum_cp = 0;
    for (u32 i = 0; i < 4; ++i)
        p.utf8_buf[i] = 0;
}

void EmitPrint(Parser& p, u32 cp)
{
    if (p.cb.print)
        p.cb.print(p.cb.cookie, cp);
}

void EmitExecute(Parser& p, u8 ctrl)
{
    if (p.cb.execute)
        p.cb.execute(p.cb.cookie, ctrl);
}

void EmitReplacementAndReset(Parser& p)
{
    EmitPrint(p, kUnicodeReplacement);
    ResetUtf8(p);
}

// Flush a pending partial UTF-8 sequence by emitting U+FFFD.
// Idempotent — no-op if no sequence is in flight. Used both
// internally by FeedUtf8Byte (when an ASCII byte interrupts a
// multi-byte sequence) and externally by the Ground-state control-
// byte path (so a partial sequence is correctly abandoned when
// a C0 byte intervenes).
void FlushPendingUtf8(Parser& p)
{
    if (p.utf8_bytes_remaining != 0)
        EmitReplacementAndReset(p);
}

// UTF-8 byte feeder. Handles single-byte (printable ASCII) inline
// and multi-byte sequences via the accumulator. Returns true if
// the byte was consumed by the UTF-8 layer; false if it should
// be re-dispatched as a control byte (lone ASCII control inside a
// stalled UTF-8 sequence aborts the sequence and is re-handled).
bool FeedUtf8Byte(Parser& p, u8 b)
{
    // Pure 7-bit ASCII: a partial multi-byte sequence in flight
    // must be aborted first (emit U+FFFD); then emit the ASCII
    // codepoint itself.
    if (b < 0x80)
    {
        FlushPendingUtf8(p);
        EmitPrint(p, b);
        return true;
    }

    // 0xC0..0xC1 are always invalid lead bytes (would encode an
    // overlong 2-byte sequence). Same for 0xF5..0xFF (would encode
    // codepoints > U+10FFFF).
    if (b == 0xC0 || b == 0xC1 || b >= 0xF5)
    {
        if (p.utf8_bytes_remaining != 0)
            EmitReplacementAndReset(p);
        EmitPrint(p, kUnicodeReplacement);
        return true;
    }

    if (p.utf8_bytes_remaining == 0)
    {
        // New lead byte.
        if ((b & 0xE0) == 0xC0)
        {
            p.utf8_seq_len = 2;
            p.utf8_bytes_remaining = 1;
        }
        else if ((b & 0xF0) == 0xE0)
        {
            p.utf8_seq_len = 3;
            p.utf8_bytes_remaining = 2;
        }
        else if ((b & 0xF8) == 0xF0)
        {
            p.utf8_seq_len = 4;
            p.utf8_bytes_remaining = 3;
        }
        else
        {
            // Lone continuation byte or other invalid form.
            EmitPrint(p, kUnicodeReplacement);
            return true;
        }
        p.utf8_buf[0] = b;
        return true;
    }

    // Continuation byte expected.
    if ((b & 0xC0) != 0x80)
    {
        // Not a continuation; abandon the partial sequence and
        // re-process this byte as a fresh lead.
        EmitReplacementAndReset(p);
        return FeedUtf8Byte(p, b);
    }

    const u32 idx = p.utf8_seq_len - p.utf8_bytes_remaining;
    if (idx < 4)
        p.utf8_buf[idx] = b;
    --p.utf8_bytes_remaining;

    if (p.utf8_bytes_remaining == 0)
    {
        // Sequence complete — defer to the project-wide decoder so
        // we share its overlong / surrogate rejection rules.
        u32 cp = 0;
        const u32 consumed = Utf8Decode(p.utf8_buf, p.utf8_seq_len, cp);
        if (consumed == p.utf8_seq_len)
            EmitPrint(p, cp);
        else
            EmitPrint(p, kUnicodeReplacement);
        ResetUtf8(p);
    }
    return true;
}

// Append a digit to the current parameter, clamping at u16 max.
void ParamAddDigit(Parser& p, u8 digit)
{
    if (p.overflow_params)
        return;
    if (!p.current_param_set)
    {
        p.current_param_set = true;
        p.current_param = 0;
    }
    const u64 next = static_cast<u64>(p.current_param) * 10 + digit;
    p.current_param = (next > 0xFFFF) ? 0xFFFF : static_cast<u32>(next);
}

void ParamCommit(Parser& p)
{
    if (p.nparams >= kMaxParams)
    {
        p.overflow_params = true;
        return;
    }
    p.params[p.nparams++] = static_cast<u16>(p.current_param);
    p.current_param = 0;
    p.current_param_set = false;
}

void DispatchCsi(Parser& p, char final_byte)
{
    // A CSI with no parameters but a ';' present still produces a
    // single zero param via the commit on the separator. A bare
    // `ESC [ H` (no digits, no semicolons) reports nparams == 0,
    // matching xterm: callbacks treat that as "all defaults".
    if (p.current_param_set || (p.nparams > 0 && !p.current_param_set))
        ParamCommit(p);
    if (p.cb.csi)
        p.cb.csi(p.cb.cookie, final_byte, p.private_marker, p.params, p.nparams);
    ResetCsi(p);
}

void DispatchOsc(Parser& p)
{
    if (!p.cb.osc || p.osc_len == 0)
    {
        ResetOsc(p);
        return;
    }
    // Parse leading numeric command up to the first ';'.
    u32 cmd = 0;
    bool cmd_set = false;
    u32 i = 0;
    while (i < p.osc_len)
    {
        const char c = p.osc_buf[i];
        if (c >= '0' && c <= '9')
        {
            cmd = cmd * 10 + static_cast<u32>(c - '0');
            cmd_set = true;
            ++i;
        }
        else
        {
            break;
        }
    }
    // Skip the ';' separator if present.
    if (i < p.osc_len && p.osc_buf[i] == ';')
        ++i;
    if (!cmd_set)
        cmd = 0;
    p.cb.osc(p.cb.cookie, cmd, p.osc_buf + i, p.osc_len - i);
    ResetOsc(p);
}

void OscAppend(Parser& p, u8 b)
{
    if (p.osc_len < kMaxOscLen)
        p.osc_buf[p.osc_len++] = static_cast<char>(b);
    else
        p.osc_truncated = true;
}

void FeedOneByte(Parser& p, u8 b)
{
    // Bytes other than ESC always re-route via the state machine
    // below. ESC inside any state resets the parser into Escape so
    // a partially-formed sequence doesn't strand the parser.
    switch (p.state)
    {
    case State::Ground:
    {
        if (b == kEsc)
        {
            FlushPendingUtf8(p);
            ResetCsi(p);
            ResetOsc(p);
            p.state = State::Escape;
            return;
        }
        if (b == kDel)
            return; // DEL is ignored everywhere.
        if (b < 0x20)
        {
            // Any control byte ends a partial UTF-8 sequence —
            // emit the replacement glyph first so an aborted
            // codepoint isn't silently absorbed.
            FlushPendingUtf8(p);
            if (IsExecutableC0(b))
                EmitExecute(p, b);
            return;
        }
        // 0x20..0x7E and 0x80+ go through the UTF-8 path.
        (void)FeedUtf8Byte(p, b);
        return;
    }

    case State::Escape:
    {
        if (b == kEsc)
        {
            // Double-ESC: stay in Escape, clear pending data.
            return;
        }
        if (b == '[')
        {
            ResetCsi(p);
            p.state = State::CsiEntry;
            return;
        }
        if (b == ']')
        {
            ResetOsc(p);
            p.state = State::OscString;
            return;
        }
        // Any other byte: drop the escape silently. xterm
        // treats unrecognised ESC <byte> as a no-op for the
        // subset we care about.
        p.state = State::Ground;
        return;
    }

    case State::CsiEntry:
    {
        if (b == kEsc)
        {
            p.state = State::Escape;
            return;
        }
        if (IsCsiPrivateMarker(b))
        {
            p.private_marker = static_cast<char>(b);
            p.state = State::CsiParam;
            return;
        }
        // Fall through to parameter handling.
        p.state = State::CsiParam;
        [[fallthrough]];
    }

    case State::CsiParam:
    {
        if (b == kEsc)
        {
            p.state = State::Escape;
            return;
        }
        if (b >= '0' && b <= '9')
        {
            ParamAddDigit(p, static_cast<u8>(b - '0'));
            return;
        }
        if (b == ';')
        {
            ParamCommit(p);
            return;
        }
        if (IsCsiFinal(b))
        {
            DispatchCsi(p, static_cast<char>(b));
            p.state = State::Ground;
            return;
        }
        // Anything else (intermediates, lingering controls) is
        // dropped silently in v0 — we don't dispatch SGR
        // intermediates and we don't need DCS.
        return;
    }

    case State::OscString:
    {
        if (b == kBel)
        {
            DispatchOsc(p);
            p.state = State::Ground;
            return;
        }
        if (b == kEsc)
        {
            p.state = State::OscEscape;
            return;
        }
        OscAppend(p, b);
        return;
    }

    case State::OscEscape:
    {
        if (b == '\\')
        {
            DispatchOsc(p);
            p.state = State::Ground;
            return;
        }
        // Bare ESC inside OSC — abort, treat as fresh ESC.
        ResetOsc(p);
        p.state = State::Escape;
        FeedOneByte(p, b);
        return;
    }
    }
}

} // namespace

void ParserInit(Parser& p, const Callbacks& cb)
{
    p.cb = cb;
    ParserReset(p);
}

void ParserReset(Parser& p)
{
    p.state = State::Ground;
    ResetUtf8(p);
    ResetCsi(p);
    ResetOsc(p);
}

u32 ParserFeed(Parser& p, const u8* bytes, u32 len)
{
    for (u32 i = 0; i < len; ++i)
        FeedOneByte(p, bytes[i]);
    return len;
}

// --- Self-test ---------------------------------------------------

namespace
{

struct TestCapture
{
    u32 print_count;
    u32 last_cp;
    u32 execute_count;
    u8 last_exec;
    u32 csi_count;
    char last_final;
    char last_private;
    u16 last_params[kMaxParams];
    u32 last_nparams;
    u32 osc_count;
    u32 last_osc_cmd;
    char last_osc_str[kMaxOscLen];
    u32 last_osc_len;
};

void CapturePrint(void* cookie, u32 cp)
{
    auto* t = static_cast<TestCapture*>(cookie);
    t->print_count++;
    t->last_cp = cp;
}

void CaptureExecute(void* cookie, u8 ctrl)
{
    auto* t = static_cast<TestCapture*>(cookie);
    t->execute_count++;
    t->last_exec = ctrl;
}

void CaptureCsi(void* cookie, char final_byte, char private_marker, const u16* params, u32 nparams)
{
    auto* t = static_cast<TestCapture*>(cookie);
    t->csi_count++;
    t->last_final = final_byte;
    t->last_private = private_marker;
    t->last_nparams = (nparams > kMaxParams) ? kMaxParams : nparams;
    for (u32 i = 0; i < t->last_nparams; ++i)
        t->last_params[i] = params[i];
}

void CaptureOsc(void* cookie, u32 cmd, const char* str, u32 str_len)
{
    auto* t = static_cast<TestCapture*>(cookie);
    t->osc_count++;
    t->last_osc_cmd = cmd;
    const u32 n = (str_len > kMaxOscLen) ? kMaxOscLen : str_len;
    for (u32 i = 0; i < n; ++i)
        t->last_osc_str[i] = str[i];
    t->last_osc_len = n;
}

void FeedString(Parser& p, const char* s)
{
    u32 n = 0;
    while (s[n] != '\0')
        ++n;
    ParserFeed(p, reinterpret_cast<const u8*>(s), n);
}

bool Expect(bool cond, const char* tag)
{
    if (!cond)
    {
        arch::SerialWrite("[vt-selftest] FAIL ");
        arch::SerialWrite(tag);
        arch::SerialWrite("\n");
    }
    return cond;
}

} // namespace

void VtParserSelfTest()
{
    TestCapture cap = {};
    Callbacks cb = {};
    cb.cookie = &cap;
    cb.print = &CapturePrint;
    cb.execute = &CaptureExecute;
    cb.csi = &CaptureCsi;
    cb.osc = &CaptureOsc;

    Parser p = {};
    ParserInit(p, cb);

    bool ok = true;

    // 1. Plain ASCII print + LF execute.
    cap = {};
    FeedString(p, "Hi\n");
    ok &= Expect(cap.print_count == 2 && cap.execute_count == 1 && cap.last_exec == kLf, "ascii+lf");

    // 2. CSI cursor-position with two parameters.
    cap = {};
    FeedString(p, "\x1b[5;12H");
    ok &= Expect(cap.csi_count == 1 && cap.last_final == 'H' && cap.last_nparams == 2 && cap.last_params[0] == 5 &&
                     cap.last_params[1] == 12 && cap.last_private == 0,
                 "cup");

    // 3. CSI SGR with no parameters.
    cap = {};
    FeedString(p, "\x1b[m");
    ok &= Expect(cap.csi_count == 1 && cap.last_final == 'm' && cap.last_nparams == 0, "sgr-bare");

    // 4. CSI with private marker.
    cap = {};
    FeedString(p, "\x1b[?25h");
    ok &= Expect(cap.csi_count == 1 && cap.last_final == 'h' && cap.last_private == '?' && cap.last_nparams == 1 &&
                     cap.last_params[0] == 25,
                 "decset");

    // 5. OSC set-title with BEL terminator.
    cap = {};
    FeedString(p, "\x1b]0;hello\x07");
    ok &= Expect(cap.osc_count == 1 && cap.last_osc_cmd == 0 && cap.last_osc_len == 5 && cap.last_osc_str[0] == 'h',
                 "osc-bel");

    // 6. OSC with ST terminator.
    cap = {};
    FeedString(p, "\x1b]2;World\x1b\\");
    ok &= Expect(cap.osc_count == 1 && cap.last_osc_cmd == 2 && cap.last_osc_len == 5, "osc-st");

    // 7. UTF-8 multi-byte: U+00E9 (é) is 0xC3 0xA9.
    cap = {};
    const u8 utf2[] = {0xC3, 0xA9};
    ParserFeed(p, utf2, 2);
    ok &= Expect(cap.print_count == 1 && cap.last_cp == 0xE9, "utf8-2byte");

    // 8. UTF-8 3-byte: U+20AC (€) is 0xE2 0x82 0xAC.
    cap = {};
    const u8 utf3[] = {0xE2, 0x82, 0xAC};
    ParserFeed(p, utf3, 3);
    ok &= Expect(cap.print_count == 1 && cap.last_cp == 0x20AC, "utf8-3byte");

    // 9. Invalid lone continuation byte collapses to U+FFFD.
    cap = {};
    const u8 lone[] = {0x80};
    ParserFeed(p, lone, 1);
    ok &= Expect(cap.print_count == 1 && cap.last_cp == kUnicodeReplacement, "utf8-lone");

    // 10. Truncated multi-byte aborted by a CR — both events seen.
    cap = {};
    const u8 trunc[] = {0xC3, 0x0D};
    ParserFeed(p, trunc, 2);
    ok &= Expect(cap.print_count == 1 && cap.last_cp == kUnicodeReplacement && cap.execute_count == 1 &&
                     cap.last_exec == kCr,
                 "utf8-abort");

    // 11. Param overflow — > kMaxParams entries clamp without
    //     crashing.
    cap = {};
    FeedString(p, "\x1b[");
    for (u32 i = 0; i < kMaxParams + 4; ++i)
        FeedString(p, "1;");
    FeedString(p, "m");
    ok &= Expect(cap.csi_count == 1 && cap.last_nparams == kMaxParams, "param-overflow");

    if (ok)
        arch::SerialWrite("[vt-selftest] PASS\n");
}

} // namespace duetos::util::vt
