#pragma once

#include "util/types.h"

/*
 * DuetOS — VT/ANSI escape parser (clean-room from-scratch).
 *
 * A byte-fed state machine that decodes the subset of DEC VT /
 * xterm escape sequences needed by a hosted terminal emulator
 * window. Output is delivered through caller-supplied callbacks;
 * the parser holds no buffers larger than a single OSC string
 * staging area, allocates nothing, and is safe to instantiate
 * statically in a single-threaded context (e.g. the kernel's
 * focused-window draw / key dispatch path).
 *
 * Scope (intentional v0):
 *   - C0 controls dispatched as Execute: BEL, BS, HT, LF, VT, FF,
 *     CR. Everything else in 0x00..0x1F is dropped silently.
 *   - CSI dispatched on the final byte (0x40..0x7E). Up to
 *     `kMaxParams` numeric parameters separated by ';' are
 *     decoded as u16; missing slots are returned as 0. The
 *     private-marker byte ('?', '>', '=', '<') is forwarded so
 *     the consumer can branch on DEC private modes.
 *   - OSC dispatched on ST (ESC '\\') or BEL terminator. Up to
 *     `kMaxOscLen` bytes of payload are buffered (overlong OSC
 *     is truncated, not discarded; the consumer sees what fit).
 *     Numeric cmd (the int before the first ';') is parsed out
 *     and passed alongside the remaining string.
 *   - UTF-8 multi-byte sequences are joined into a single
 *     codepoint via util::Utf8Decode; the print callback always
 *     receives a complete codepoint, never a partial sequence.
 *   - Surrogates and overlong encodings collapse to
 *     U+FFFD (REPLACEMENT CHARACTER), matching xterm behaviour.
 *
 * Out of scope (deliberate, recorded so a future slice doesn't
 * resurrect them speculatively):
 *   - DCS / SOS / PM / APC escape forms — terminal apps that
 *     need Sixel, ReGIS, or terminal-keyboard reprogramming are
 *     not the v0 target.
 *   - ESC ( / ESC ) — G0 / G1 character set selection (line
 *     drawing). DuetOS's font is Unicode-native; line drawing
 *     comes through U+2500.. directly.
 *   - VT52 mode.
 *   - Unicode width disambiguation (East-Asian wide vs narrow).
 *     The hosting widget treats every printable codepoint as
 *     one cell. CJK rows will be visually narrow until a
 *     follow-up adds wcwidth-style classification.
 *
 * Studied ToaruOS lib/termemu.c for the escape-grammar shape
 * (CSI parameter accumulation, OSC string termination semantics).
 * No code copied; this implementation is written against the
 * DEC ANSI parser state diagram (vt100.net/emu/dec_ansi_parser)
 * and Paul Williams' state-machine description.
 */

namespace duetos::util::vt
{

/// Maximum numeric parameters per CSI sequence. xterm permits 16;
/// matching that bound is the safe choice for our v0 consumers.
inline constexpr u32 kMaxParams = 16;

/// Bytes of OSC payload buffered before the parser starts
/// dropping characters. 256 covers `set title` payloads with
/// generous headroom; longer strings get truncated.
inline constexpr u32 kMaxOscLen = 256;

/// State value used by the parser's internal state machine.
/// Exposed only so `Parser` can be defined inline; the names are
/// not part of the public contract.
enum class State : u8
{
    Ground,    // Normal input — printables forwarded, C0 executed.
    Escape,    // After 0x1B — next byte selects the sequence kind.
    CsiEntry,  // After `ESC [` — collect optional private marker.
    CsiParam,  // Collecting params + intermediates.
    OscString, // After `ESC ]` — buffering until ST or BEL.
    OscEscape, // Inside OSC, just saw ESC — expecting '\\' for ST.
};

/// Callbacks invoked by the parser. All callbacks may be null;
/// the parser falls back to dropping the event silently. Callbacks
/// run synchronously from within `ParserFeed`; do not call
/// `ParserFeed` from inside a callback (re-entrancy unsupported).
struct Callbacks
{
    /// Opaque pointer passed back to every callback. Owned by the
    /// caller; the parser stores it but never dereferences.
    void* cookie;

    /// Emit a single printable codepoint. The parser has already
    /// stripped C0 controls and joined multi-byte UTF-8 into a
    /// single u32 here, so the callback can treat `cp` as a fully
    /// decoded Unicode scalar value. The replacement character
    /// (U+FFFD) is delivered through this path for invalid input;
    /// callbacks do not need a separate "decode-failed" hook.
    void (*print)(void* cookie, u32 cp);

    /// Dispatch a C0 control byte that the parser deemed
    /// "executable" (BEL/BS/HT/LF/VT/FF/CR). Bytes outside that
    /// set are dropped without invoking this callback.
    void (*execute)(void* cookie, u8 ctrl);

    /// Dispatch a complete CSI sequence. `final_byte` is the
    /// terminator (0x40..0x7E). `private_marker` is the byte that
    /// followed `ESC [` if it was `?`, `>`, `=`, `<` — otherwise 0.
    /// `params` points into the parser's own buffer; the pointer
    /// is valid only for the duration of this callback. `nparams`
    /// is the count of numeric parameters present (missing
    /// trailing slots are still counted: `[;5H` reports nparams=2
    /// with params[0] = 0, params[1] = 5).
    void (*csi)(void* cookie, char final_byte, char private_marker, const u16* params, u32 nparams);

    /// Dispatch an OSC sequence. `cmd` is the leading integer
    /// (e.g. `0` for set-title, `2` for set-window-title, `52`
    /// for clipboard). `str` is the payload after the first ';'
    /// (i.e. the data portion); `str_len` excludes the
    /// terminator. The buffer is valid only for the duration of
    /// this callback.
    void (*osc)(void* cookie, u32 cmd, const char* str, u32 str_len);
};

/// Parser state. Treat as opaque; the fields are documented in
/// vt_parser.cpp but should only be accessed through the helper
/// functions below. Default-constructed (zero-init) is a valid
/// Ground-state parser with all-null callbacks (which means every
/// event is silently dropped — useful for tests that only care
/// about state transitions).
struct Parser
{
    State state;
    u8 utf8_bytes_remaining;
    u8 utf8_seq_len;
    u8 _pad0;

    u32 utf8_accum_cp;
    u8 utf8_buf[4];

    u16 params[kMaxParams];
    u32 nparams;
    u32 current_param;
    bool current_param_set;
    bool overflow_params;
    char private_marker;
    u8 _pad1;

    char osc_buf[kMaxOscLen];
    u32 osc_len;
    bool osc_truncated;
    u8 _pad2[3];

    Callbacks cb;
};

/// Install `cb` into `p` and reset every state field. Safe to
/// call mid-stream to reset the parser between sessions; partial
/// sequences in flight are discarded.
void ParserInit(Parser& p, const Callbacks& cb);

/// Reset state without re-installing callbacks. Useful when a
/// terminal app re-attaches to a fresh shell instance.
void ParserReset(Parser& p);

/// Feed `len` bytes to the parser. Drives callbacks
/// synchronously. Returns the number of bytes consumed, which is
/// always equal to `len` — the parser cannot back-pressure. The
/// signature returns the count for API symmetry with future
/// flow-controlled variants.
u32 ParserFeed(Parser& p, const u8* bytes, u32 len);

/// Single-byte convenience.
inline u32 ParserFeedByte(Parser& p, u8 b)
{
    return ParserFeed(p, &b, 1);
}

/// Self-test, runs at boot. Drives a handful of canned escape
/// sequences through a parser instance with capturing callbacks
/// and asserts the right events fired. Pure compute, no I/O
/// side effects beyond the serial log on failure.
void VtParserSelfTest();

} // namespace duetos::util::vt
