#pragma once

#include "util/types.h"

/*
 * DuetOS — IEEE 802.3 reflected CRC-32 (polynomial 0xEDB88320).
 *
 * Same construction as zlib / gzip / GPT / PKZIP / Ethernet FCS:
 *   - reflected input bytes,
 *   - reflected output,
 *   - 0xFFFFFFFF initial value,
 *   - 0xFFFFFFFF final XOR.
 *
 * The 1 KiB lookup table is built lazily on first use. The compiler
 * could fold this with a constexpr loop — kept runtime-init for now
 * because the table lives in `.data` and only the boot sequence
 * pays the construction cost.
 *
 * Consumers in the tree:
 *   - `fs/gpt.cpp` — header CRC + entry-array CRC.
 *   - Future: PNG chunk CRCs, ZIP local-file headers, gzip footer,
 *     ext4 metadata checksums (with seed = ~0).
 *
 * If a future caller wants seedable CRC (for streaming chunks
 * without re-running over already-consumed data), add an
 * `_Update` overload that takes a running CRC; v0 callers all
 * have the full buffer in memory.
 */

namespace duetos::util
{

/// One-shot CRC-32 over a contiguous buffer. Returns 0 for a
/// zero-length input (matches the reflected-CRC convention used
/// by zlib + GPT).
u32 Crc32(const u8* data, u64 len);

void Crc32SelfTest();

} // namespace duetos::util
