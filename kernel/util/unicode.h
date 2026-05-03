#pragma once

#include "util/types.h"

/*
 * DuetOS — UTF-8 / UTF-16 codepoint conversion (clean room).
 *
 * Specs:
 *   - RFC 3629 (UTF-8) — the only valid lead-byte / continuation
 *     bit patterns; overlong encodings rejected.
 *   - Unicode 15.0 §3.9 (UTF-16) — surrogate pair encoding for
 *     supplementary-plane codepoints (U+10000..U+10FFFF).
 *   - Unicode TR #1 — interchange-form requirements.
 *
 * Consumers in DuetOS today:
 *   - kernel/fs/exfat.cpp, kernel/fs/ntfs.cpp — both decode
 *     UTF-16LE filename buffers down to ASCII for display. Both
 *     used to carry their own private `Utf16ToSafeAscii` helper
 *     that handled only the BMP single-code-unit case (lossy
 *     '?' for any non-ASCII codepoint, surrogates included).
 *     Both now go through `Utf16LeBufferToSafeAscii` which
 *     properly walks surrogate pairs.
 *   - Future Win32 wide-string thunks (`MultiByteToWideChar`,
 *     `WideCharToMultiByte`) will sit on top of the
 *     Utf8Encode / Utf8Decode / Utf16Encode / Utf16Decode
 *     primitives without re-deriving them.
 *
 * Out of scope (deliberate):
 *   - Unicode normalization (NFC / NFD) — punted to a future
 *     slice if a consumer demands it (e.g. exFAT case-folding).
 *   - Case folding — see porting-candidates row, separate slice.
 *   - UTF-32 conversions — every consumer here works in UTF-8
 *     or UTF-16; if a codepoint is required, callers use the
 *     Decode entrypoints which return a u32.
 *
 * No allocation, no global state — every routine operates on
 * caller-provided buffers and returns a length.
 */

namespace duetos::util
{

/// Maximum bytes a single codepoint can occupy in UTF-8 (4).
inline constexpr u32 kUtf8MaxBytes = 4;

/// Maximum 16-bit code units a single codepoint occupies in
/// UTF-16 (2 — surrogate pair for supplementary plane).
inline constexpr u32 kUtf16MaxUnits = 2;

/// Highest valid Unicode codepoint.
inline constexpr u32 kUnicodeMaxCodepoint = 0x10FFFF;

/// Surrogate-half range — never appears as a standalone codepoint.
inline constexpr u32 kUtf16SurrogateLo = 0xD800;
inline constexpr u32 kUtf16SurrogateHi = 0xDFFF;

/// Replacement character for lossy ASCII fallback paths.
inline constexpr u32 kUnicodeReplacement = 0xFFFD;

/// Encode `cp` as UTF-8 into `out`. Returns the byte count
/// written (1..4), or 0 if `cp` is invalid (surrogate, > 0x10FFFF).
u32 Utf8Encode(u32 cp, u8 out[kUtf8MaxBytes]);

/// Decode the UTF-8 sequence at `in` (`in_len` bytes available).
/// On success writes the decoded codepoint to `cp` and returns
/// the byte count consumed (1..4). Returns 0 on truncation,
/// invalid lead byte, invalid continuation byte, overlong
/// encoding, surrogate codepoint, or codepoint > 0x10FFFF.
u32 Utf8Decode(const u8* in, u32 in_len, u32& cp);

/// Encode `cp` as UTF-16 into `out`. Returns 1 (BMP) or 2
/// (surrogate pair) on success, 0 if `cp` is invalid.
u32 Utf16Encode(u32 cp, u16 out[kUtf16MaxUnits]);

/// Decode UTF-16 from `in` (`in_units` code units available).
/// Returns 1 or 2 code units consumed; 0 on lone-surrogate or
/// truncated surrogate pair.
u32 Utf16Decode(const u16* in, u32 in_units, u32& cp);

/// One-codepoint convenience: collapse anything outside printable
/// 7-bit ASCII to '?'. Pass-through for control NUL.
char Utf16CpToSafeAscii(u32 cp);

/// Decode `byte_len` bytes of UTF-16LE from `in`, lossily mapping
/// each codepoint to ASCII via `Utf16CpToSafeAscii`, writing into
/// `out` (capacity `out_cap` including the trailing NUL). Stops
/// at the first NUL codepoint or when input is exhausted. Always
/// NUL-terminates `out` if `out_cap > 0`. Returns the number of
/// ASCII bytes written (excluding terminator).
u32 Utf16LeBufferToSafeAscii(const u8* in, u32 byte_len, char* out, u32 out_cap);

void UnicodeSelfTest();

} // namespace duetos::util
