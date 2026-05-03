#pragma once

#include "util/types.h"

/*
 * DuetOS — TZif (Olson zoneinfo) binary parser (RFC 8536, clean room).
 *
 * TZif is the on-disk format every Unix system uses for timezone
 * data: `/usr/share/zoneinfo/America/New_York` etc. Each file
 * carries a list of UTC transition times, the local-time-type
 * each transition selects, and per-type {gmtoff, isdst, abbrind}
 * triples plus a string pool of timezone abbreviations.
 *
 * Spec layout (per RFC 8536 §3):
 *
 *   magic        4 bytes "TZif"
 *   version      1 byte ('\0', '2', '3', '4')
 *   reserved     15 bytes (zero)
 *   tzh_ttisutcnt   u32 BE
 *   tzh_ttisstdcnt  u32 BE
 *   tzh_leapcnt     u32 BE
 *   tzh_timecnt     u32 BE
 *   tzh_typecnt     u32 BE
 *   tzh_charcnt     u32 BE
 *   then six body sections...
 *
 * Version '2' adds a second (post-2038-safe) data block with
 * 8-byte transition times. Version '3' adds extended POSIX TZ
 * string handling. v0 here parses only the v1 (32-bit) block —
 * sufficient for any timestamp 1901-2038. The v2/v3 trailing
 * blocks are skipped if present.
 *
 * Eventual consumers:
 *   - Linux ABI strftime / strptime / mktime / localtime when
 *     paired with the existing POSIX-TZ string parser.
 *   - Future userland `date` / `cron` thunks.
 *
 * Out of scope (deliberate):
 *   - Leap-second table (parsed past, not exposed).
 *   - v2/v3 64-bit transition tables.
 *   - The trailing POSIX-TZ string in v2+.
 *
 * No allocation, no global state — caller provides the parse
 * buffer + a fixed-size record table.
 */

namespace duetos::util
{

inline constexpr u32 kTzifMaxTransitions = 256;
inline constexpr u32 kTzifMaxTypes = 32;
inline constexpr u32 kTzifAbbrPool = 256;

struct TzifLocalType
{
    i32 gmtoff_secs; // east-of-UTC offset (Linux convention)
    bool isdst;
    u8 abbr_index; // index into the abbreviation pool
};

struct TzifData
{
    u32 transition_count;
    i64 transitions[kTzifMaxTransitions];    // UTC seconds-since-epoch
    u8 transition_type[kTzifMaxTransitions]; // index into types[]

    u32 type_count;
    TzifLocalType types[kTzifMaxTypes];

    char abbr_pool[kTzifAbbrPool];
    u32 abbr_pool_bytes;

    bool ok;
};

/// Parse a TZif file into `out`. Returns true on success.
/// On failure `out.ok = false` and the other fields are zero.
bool TzifParse(const u8* src, u32 src_len, TzifData& out);

void TzifSelfTest();

} // namespace duetos::util
