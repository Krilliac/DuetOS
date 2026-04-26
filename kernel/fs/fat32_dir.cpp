/*
 * DuetOS — FAT32 filesystem driver: directory walk + decode.
 *
 * Sibling to fat32.cpp (probe / accessors / block primitives) and
 * fat32_lookup.cpp / fat32_read.cpp / fat32_write.cpp / fat32_selftest.cpp.
 *
 * Holds every primitive that decodes an on-disk directory entry
 * and walks the cluster chain that backs a directory:
 *
 *   internal::FormatShortName    — render 11-byte 8.3 to "NAME.EXT\0"
 *   internal::IsDotEntry         — predicate for "." / ".." synthetic entries
 *   internal::NameIEqual         — case-insensitive ASCII compare
 *   internal::DecodeEntry        — 32-byte on-disk record -> DirEntry
 *   internal::DecodeLfnChars     — pull 13 UTF-16 codepoints out of an LFN frag
 *   internal::ComputeLfnChecksum — FAT32 SFN-checksum (spec §7.2)
 *   internal::WalkDirChain       — full cluster-chain iterator with LFN stitching
 *   internal::WalkRootIntoSnapshot — fill Volume::root_entries[] cache
 *
 * Plus the two public dir-shaped APIs:
 *
 *   Fat32ListDirByCluster — enumerate a directory's entries
 *   Fat32FindInRoot       — case-insensitive lookup in cached root snapshot
 *
 * Cross-TU declarations live in fat32_internal.h. Public fat32.h API
 * is unchanged.
 */

#include "fs/fat32.h"

#include "fs/fat32_internal.h"

namespace duetos::fs::fat32
{

using namespace internal;

namespace internal
{

// Populate `out` with "NAME.EXT\0" given an 11-byte FAT 8.3 name.
// `name` is caller-owned; `out` must be at least 13 bytes. Trailing
// spaces in the base or extension are stripped.
void FormatShortName(const u8* name, char* out)
{
    u32 w = 0;
    // Base (bytes 0..7).
    for (u32 i = 0; i < 8; ++i)
    {
        if (name[i] == ' ')
            break;
        out[w++] = static_cast<char>(name[i]);
    }
    // Extension (bytes 8..10). Only emit the '.' if there's an ext.
    bool has_ext = false;
    for (u32 i = 8; i < 11; ++i)
    {
        if (name[i] != ' ')
        {
            has_ext = true;
            break;
        }
    }
    if (has_ext)
    {
        out[w++] = '.';
        for (u32 i = 8; i < 11; ++i)
        {
            if (name[i] == ' ')
                break;
            out[w++] = static_cast<char>(name[i]);
        }
    }
    out[w] = 0;
}
// True if the formatted name is exactly "." or "..". Used by the
// enumerators to suppress the self / parent pseudo-entries that
// every non-root directory carries.
bool IsDotEntry(const char* n)
{
    if (n[0] != '.')
        return false;
    if (n[1] == 0)
        return true;
    if (n[1] == '.' && n[2] == 0)
        return true;
    return false;
}

// Case-insensitive ASCII compare of two NUL-terminated strings.
bool NameIEqual(const char* a, const char* b)
{
    u32 i = 0;
    for (; a[i] != 0 && b[i] != 0; ++i)
    {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'a' && ca <= 'z')
            ca = static_cast<char>(ca - 32);
        if (cb >= 'a' && cb <= 'z')
            cb = static_cast<char>(cb - 32);
        if (ca != cb)
            return false;
    }
    return a[i] == 0 && b[i] == 0;
}

// Fill one DirEntry from the 32-byte on-disk record.
void DecodeEntry(const u8* e, DirEntry& out)
{
    VZero(&out, sizeof(out));
    FormatShortName(e, out.name);
    out.attributes = e[11];
    const u16 cl_lo = LeU16(e + 26);
    const u16 cl_hi = LeU16(e + 20);
    out.first_cluster = (u32(cl_hi) << 16) | u32(cl_lo);
    out.size_bytes = LeU32(e + 28);
}

// Visitor type for the directory-cluster walker. Return true to
// keep walking, false to short-circuit. `ctx` is caller-opaque.
using DirVisitor = bool (*)(const DirEntry& e, void* ctx);

// Extract the 13 UTF-16 code units from a single LFN entry into
// `out_chars` at offsets [0..12]. Stops writing on the first
// 0x0000 terminator; `*did_terminate` reports whether the NUL was
// hit inside this fragment. Non-ASCII codepoints collapse to '?'
// — v0 is ASCII-friendly only.
void DecodeLfnChars(const u8* e, char* out_chars, bool* did_terminate)
{
    *did_terminate = false;
    // 13 positions: entry bytes (1..10) = 5 chars, (14..25) = 6 chars,
    // (28..31) = 2 chars. Each char is a little-endian u16.
    static constexpr u32 kLfnOffsets[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
    for (u32 i = 0; i < 13; ++i)
    {
        const u32 o = kLfnOffsets[i];
        const u16 wc = static_cast<u16>(e[o] | (u16(e[o + 1]) << 8));
        if (wc == 0x0000)
        {
            out_chars[i] = 0;
            *did_terminate = true;
            // Don't break — zero out remaining positions explicitly
            // so the caller's concatenator sees a clean tail.
            for (u32 j = i + 1; j < 13; ++j)
                out_chars[j] = 0;
            return;
        }
        if (wc > 0x7F)
            out_chars[i] = '?';
        else
            out_chars[i] = static_cast<char>(wc);
    }
}

// FAT32 short-name checksum, per the spec: rotate-right one bit and
// add each of the 11 SFN bytes. All LFN fragments in a sequence
// carry this checksum at offset 13 — when it mismatches the SFN
// that follows, the LFN is orphaned (typical after a partial
// rename) and we must fall back to the 8.3 name.
u8 ComputeLfnChecksum(const u8* sfn11)
{
    u8 sum = 0;
    for (u32 i = 0; i < 11; ++i)
        sum = static_cast<u8>(((sum & 1) ? 0x80 : 0) + static_cast<u8>(sum >> 1) + sfn11[i]);
    return sum;
}

// Walk a directory's cluster chain, decode each in-use entry, and
// feed it to `visit`. LFN sequences are assembled into the DirEntry's
// `name` field before the visitor is called on the SFN. Deleted /
// volume-label / dot entries are filtered. Returns true on clean
// completion (end-of-dir or EOC), false on I/O error. A visitor
// returning false also ends the walk (still not an error).
//
// Reuses g_scratch for cluster data; the visitor MUST copy any
// DirEntry fields it wants to keep before returning.
bool WalkDirChain(const Volume& v, u32 first_cluster, DirVisitor visit, void* ctx)
{
    // LFN accumulator. FAT32 spec allows up to 20 LFN fragments ×
    // 13 UTF-16 chars = 260 chars; we truncate to DirEntry::name's
    // 128-byte budget at copy-out time.
    char pending_long[260];
    bool pending_any = false;
    u8 pending_checksum = 0;
    bool pending_checksum_set = false;
    bool pending_checksum_consistent = true;
    VZero(pending_long, sizeof(pending_long));

    u32 cluster = first_cluster;
    for (u32 step = 0; step < 64; ++step)
    {
        if (cluster < 2 || cluster >= 0x0FFFFFF8u)
            break;
        if (!ReadCluster(v, cluster))
            return false;

        const u32 bytes = v.sectors_per_cluster * v.bytes_per_sector;
        for (u32 off = 0; off + 32 <= bytes; off += 32)
        {
            const u8* e = g_scratch + off;
            if (e[0] == 0x00)
                return true; // end of dir
            if (e[0] == 0xE5)
            {
                pending_any = false;
                pending_checksum_set = false;
                pending_checksum_consistent = true;
                continue;
            }
            const u8 attr = e[11];
            if ((attr & kAttrLongName) == kAttrLongName)
            {
                // LFN fragment. Ordinal low 6 bits = 1..20; bit 6
                // set on the LAST (first-in-physical-order) entry.
                const u8 ord = static_cast<u8>(e[0] & 0x3F);
                if (ord == 0 || ord > 20)
                {
                    pending_any = false;
                    pending_checksum_set = false;
                    pending_checksum_consistent = true;
                    continue;
                }
                const u8 frag_chk = e[13];
                if (!pending_checksum_set)
                {
                    pending_checksum = frag_chk;
                    pending_checksum_set = true;
                    pending_checksum_consistent = true;
                }
                else if (frag_chk != pending_checksum)
                {
                    pending_checksum_consistent = false;
                }
                char chars[13];
                for (u32 i = 0; i < 13; ++i)
                    chars[i] = 0;
                bool terminated = false;
                DecodeLfnChars(e, chars, &terminated);
                const u32 base = u32(ord - 1) * 13;
                for (u32 i = 0; i < 13; ++i)
                    pending_long[base + i] = chars[i];
                pending_any = true;
                continue;
            }
            if (attr & kAttrVolumeId)
            {
                pending_any = false;
                pending_checksum_set = false;
                pending_checksum_consistent = true;
                continue;
            }

            DirEntry decoded;
            DecodeEntry(e, decoded);
            if (IsDotEntry(decoded.name))
            {
                pending_any = false;
                pending_checksum_set = false;
                pending_checksum_consistent = true;
                continue;
            }
            if (pending_any)
            {
                // Replace the 8.3 name with the assembled LFN, but
                // only if every fragment carried the same checksum
                // AND that checksum matches the trailing SFN's
                // 11-byte computation. Otherwise the LFN is
                // orphaned — fall back to the SFN.
                bool lfn_ok = pending_checksum_set && pending_checksum_consistent;
                if (lfn_ok && ComputeLfnChecksum(e) != pending_checksum)
                    lfn_ok = false;
                if (lfn_ok)
                {
                    u32 n = 0;
                    while (n + 1 < sizeof(decoded.name) && pending_long[n] != 0)
                    {
                        decoded.name[n] = pending_long[n];
                        ++n;
                    }
                    decoded.name[n] = 0;
                }
            }
            pending_any = false;
            pending_checksum_set = false;
            pending_checksum_consistent = true;
            VZero(pending_long, sizeof(pending_long));

            if (!visit(decoded, ctx))
                return true;
        }
        cluster = ReadFatEntry(v, cluster);
    }
    return true;
}

// Probe-time root snapshot filler. Uses the generic walker with a
// cookie that appends into v.root_entries[].
bool WalkRootIntoSnapshot(Volume& v, u32 first_cluster)
{
    v.root_entry_count = 0;
    struct Ctx
    {
        Volume* v;
    };
    Ctx ctx{&v};
    return WalkDirChain(
        v, first_cluster,
        [](const DirEntry& e, void* cx) -> bool
        {
            auto* c = static_cast<Ctx*>(cx);
            if (c->v->root_entry_count >= kMaxDirEntries)
                return false;
            CopyEntry(c->v->root_entries[c->v->root_entry_count++], e);
            return true;
        },
        &ctx);
}

} // namespace internal

u32 Fat32ListDirByCluster(const Volume* v, u32 first_cluster, DirEntry* out, u32 cap)
{
    if (v == nullptr || out == nullptr || cap == 0)
        return 0;
    struct Ctx
    {
        DirEntry* out;
        u32 cap;
        u32 n;
    };
    Ctx ctx{out, cap, 0};
    WalkDirChain(
        *v, first_cluster,
        [](const DirEntry& e, void* cx) -> bool
        {
            auto* c = static_cast<Ctx*>(cx);
            if (c->n >= c->cap)
                return false;
            CopyEntry(c->out[c->n++], e);
            return true;
        },
        &ctx);
    return ctx.n;
}


const DirEntry* Fat32FindInRoot(const Volume* v, const char* name)
{
    if (v == nullptr || name == nullptr)
        return nullptr;
    for (u32 i = 0; i < v->root_entry_count; ++i)
    {
        const DirEntry& e = v->root_entries[i];
        bool match = true;
        u32 k = 0;
        for (; e.name[k] != 0 && name[k] != 0; ++k)
        {
            // Case-insensitive over ASCII A-Z.
            char a = e.name[k];
            char b = name[k];
            if (a >= 'a' && a <= 'z')
                a = static_cast<char>(a - 32);
            if (b >= 'a' && b <= 'z')
                b = static_cast<char>(b - 32);
            if (a != b)
            {
                match = false;
                break;
            }
        }
        if (match && e.name[k] == 0 && name[k] == 0)
        {
            return &e;
        }
    }
    return nullptr;
}

} // namespace duetos::fs::fat32
