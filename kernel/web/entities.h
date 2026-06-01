#pragma once

/*
 * DuetOS — HTML character-reference (entity) decoding, used by the
 * tokenizer when emitting Text. Split out of html.cpp so the named-
 * entity table and the numeric/UTF-8 encode helpers stay in one
 * coherent unit rather than bloating the tokenizer TU.
 */

#include "util/types.h"

namespace duetos::web
{

using duetos::u32;

/// Decode the entity beginning at `src[0] == '&'`. On a recognised
/// reference, writes its UTF-8 expansion into `out` (up to `outCap`
/// bytes), sets `*consumed` to the number of source bytes the
/// reference spans (including '&' and any trailing ';'), and returns
/// the number of output bytes written. On an unrecognised sequence
/// returns 0 and sets `*consumed` to 0 — the caller then emits the
/// literal '&'.
u32 DecodeEntity(const char* src, u32 len, char* out, u32 outCap, u32* consumed);

} // namespace duetos::web
