#include "util/vt_parser.h"

#include "arch/x86_64/serial.h"
#include "duetos_vt.h"

// The DEC ANSI state machine, UTF-8 decoder, CSI parameter
// accumulator, and OSC string buffer are owned by the `duetos_vt`
// Rust crate (kernel/util/vt_parser_rust/). Untrusted PTY bytes
// from user processes flow through this delegation. The C++ side
// keeps the boot self-test (which exercises the crate via the
// same FFI) and a thin wrapper around the FFI struct so the
// public Parser/Callbacks API in vt_parser.h doesn't change.
//
// Layout note: kernel/util/vt_parser.h declares `Parser` and
// `Callbacks` with the same byte layout as `DuetosVtParser` and
// `DuetosVtCallbacks` in duetos_vt.h. The static_asserts below pin
// the equivalence at compile time so a future refactor on either
// side can't silently desync.

namespace duetos::util::vt
{

static_assert(sizeof(Parser) == sizeof(DuetosVtParser), "Parser layout must match DuetosVtParser");
static_assert(sizeof(Callbacks) == sizeof(DuetosVtCallbacks), "Callbacks layout must match DuetosVtCallbacks");

void ParserInit(Parser& p, const Callbacks& cb)
{
    // The C++ Callbacks struct and the Rust DuetosVtCallbacks
    // struct have identical layouts; cast through the bit-
    // compatible pointer and let the Rust crate copy the fields.
    duetos_vt_parser_init(reinterpret_cast<DuetosVtParser*>(&p), reinterpret_cast<const DuetosVtCallbacks*>(&cb));
}

void ParserReset(Parser& p)
{
    duetos_vt_parser_reset(reinterpret_cast<DuetosVtParser*>(&p));
}

u32 ParserFeed(Parser& p, const u8* bytes, u32 len)
{
    return duetos_vt_parser_feed(reinterpret_cast<DuetosVtParser*>(&p), bytes, len);
}

// --- Self-test ---------------------------------------------------
//
// Exercises the parser through the same FFI a real consumer uses,
// confirming the C++ wrapper + Rust crate together produce the
// expected events on a canned input.

namespace
{

constexpr u32 kSelftestMaxOscLen = 256;

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
    char last_osc_str[kSelftestMaxOscLen];
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
    const u32 n = (str_len > kSelftestMaxOscLen) ? kSelftestMaxOscLen : str_len;
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

    Parser p{};
    ParserInit(p, cb);

    bool ok = true;

    // Printable ASCII.
    cap = {};
    FeedString(p, "hi");
    ok &= Expect(cap.print_count == 2, "print/hi-count");
    ok &= Expect(cap.last_cp == 'i', "print/hi-last");

    // Executable C0.
    cap = {};
    FeedString(p, "\x07");
    ok &= Expect(cap.execute_count == 1 && cap.last_exec == 0x07, "execute/BEL");

    // CSI with two params.
    cap = {};
    FeedString(p, "\x1b[3;5H");
    ok &= Expect(cap.csi_count == 1, "csi/count");
    ok &= Expect(cap.last_final == 'H', "csi/final");
    ok &= Expect(cap.last_nparams == 2, "csi/nparams");
    ok &= Expect(cap.last_params[0] == 3 && cap.last_params[1] == 5, "csi/params");

    // CSI private marker.
    cap = {};
    FeedString(p, "\x1b[?25h");
    ok &= Expect(cap.csi_count == 1, "csi-priv/count");
    ok &= Expect(cap.last_private == '?', "csi-priv/marker");

    // OSC set-title.
    cap = {};
    FeedString(p, "\x1b]0;hello\x07");
    ok &= Expect(cap.osc_count == 1, "osc/count");
    ok &= Expect(cap.last_osc_cmd == 0, "osc/cmd");
    ok &= Expect(cap.last_osc_len == 5 && cap.last_osc_str[0] == 'h', "osc/payload");

    // Multi-byte UTF-8 (U+00E9).
    cap = {};
    const u8 utf8[] = {0xC3, 0xA9};
    ParserFeed(p, utf8, sizeof(utf8));
    ok &= Expect(cap.print_count == 1 && cap.last_cp == 0xE9, "utf8/2byte");

    // DEL is dropped silently.
    cap = {};
    FeedString(p, "a\x7F" "b");
    ok &= Expect(cap.print_count == 2, "del/dropped");

    if (ok)
        arch::SerialWrite("[vt-selftest] PASS (rust-backed)\n");
}

} // namespace duetos::util::vt
