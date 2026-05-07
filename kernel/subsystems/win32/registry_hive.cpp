#include "subsystems/win32/registry.h"

#include "arch/x86_64/serial.h"
#include "fs/fat32.h"

/*
 * Registry hive persistence — REGISTRY.HIV on the FAT32 root.
 *
 * The kernel-side sidecar mutable-value pool (registry.cpp's
 * g_sidecar) was RAM-only. SetValueKey / DeleteValueKey writes
 * disappeared on every reboot. This file mirrors the live pool
 * to a text file so values survive across boots while the
 * static .rodata-backed key tree stays the source of truth for
 * built-in defaults.
 *
 * On-disk format (line-oriented ASCII; comment lines start `#`):
 *   v|<root_hex>|<path>|<name>|<type_dec>|<data_hex>
 *   t|<root_hex>|<path>|<name>
 *
 * Field separator is `|`. Constraints:
 *   - <root_hex>  : 8 hex chars (kHkey* sentinel)
 *   - <path>      : verbatim from kRegKeys[].path; must NOT contain
 *                   `|` or `\n`. The static tree's paths satisfy
 *                   this by inspection (only ASCII identifier chars
 *                   plus `\` and ` `).
 *   - <name>      : sidecar value name. Same constraints. Names
 *                   that violate them are skipped on save with a
 *                   serial warning — a future slice can switch to
 *                   length-prefixed binary if a real PE wants
 *                   exotic names.
 *   - <type_dec>  : decimal REG_* code (1..4)
 *   - <data_hex>  : 0..2*kSidecarDataMax hex chars, two per byte.
 *
 * Throttle: RegistryHiveSave formats the payload, byte-compares
 * against the last successful write, and skips the FAT32 op when
 * the payload is identical. Mirrors core::SessionRestoreSave's
 * approach.
 *
 * Context: kernel. RegistryHiveLoad must run AFTER FAT32 is mounted
 * AND AFTER RegistrySelfTest, so the consistency probes don't
 * observe a half-applied hive.
 */

namespace duetos::subsystems::win32::registry
{

namespace
{

namespace fat = duetos::fs::fat32;

constexpr const char kHivePath[] = "REGISTRY.HIV";

// Worst case per entry:
//   "v|XXXXXXXX|<path:128>|<name:64>|<type:10>|<data: 2*256>\n"
// Round up to 1024 bytes per entry; 32 entries -> 32 KiB cap.
// Header line + a few comment bytes -> 33 KiB scratch.
constexpr u64 kPayloadCap = 33 * 1024;

constinit char g_last_payload[kPayloadCap] = {};
constinit u64 g_last_len = 0;

// Re-entrancy guard. The FAT32 write path may emit Trace logs;
// those go through the persistent klog sink which writes to
// FAT32 too. If a log emitted from inside our save raced through
// to a registry-modifying handler somehow, we'd recurse — drop
// the call instead.
constinit bool g_in_save = false;

bool ContainsForbidden(const char* s)
{
    if (s == nullptr)
    {
        return false;
    }
    for (const char* p = s; *p != '\0'; ++p)
    {
        if (*p == '|' || *p == '\n' || *p == '\r')
        {
            return true;
        }
    }
    return false;
}

void AppendStr(char* dst, u64* pos, u64 cap, const char* s)
{
    while (*s != '\0' && *pos + 1 < cap)
    {
        dst[(*pos)++] = *s++;
    }
}

void AppendChar(char* dst, u64* pos, u64 cap, char c)
{
    if (*pos + 1 < cap)
    {
        dst[(*pos)++] = c;
    }
}

constexpr char kHexUpper[] = "0123456789ABCDEF";

void AppendHex32(char* dst, u64* pos, u64 cap, u32 v)
{
    for (i32 i = 7; i >= 0; --i)
    {
        AppendChar(dst, pos, cap, kHexUpper[(v >> (i * 4)) & 0xF]);
    }
}

void AppendU32Dec(char* dst, u64* pos, u64 cap, u32 v)
{
    char tmp[12];
    u32 n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    while (v != 0)
    {
        tmp[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    while (n > 0)
    {
        AppendChar(dst, pos, cap, tmp[--n]);
    }
}

void AppendBytesHex(char* dst, u64* pos, u64 cap, const u8* bytes, u32 len)
{
    for (u32 i = 0; i < len; ++i)
    {
        AppendChar(dst, pos, cap, kHexUpper[(bytes[i] >> 4) & 0xF]);
        AppendChar(dst, pos, cap, kHexUpper[bytes[i] & 0xF]);
    }
}

bool HexNibble(char c, u8* out)
{
    if (c >= '0' && c <= '9')
    {
        *out = static_cast<u8>(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f')
    {
        *out = static_cast<u8>(10 + (c - 'a'));
        return true;
    }
    if (c >= 'A' && c <= 'F')
    {
        *out = static_cast<u8>(10 + (c - 'A'));
        return true;
    }
    return false;
}

bool ParseHex32(const char* s, u32 len, u32* out)
{
    if (len == 0 || len > 8)
    {
        return false;
    }
    u32 v = 0;
    for (u32 i = 0; i < len; ++i)
    {
        u8 nib = 0;
        if (!HexNibble(s[i], &nib))
        {
            return false;
        }
        v = (v << 4) | nib;
    }
    *out = v;
    return true;
}

bool ParseU32Dec(const char* s, u32 len, u32* out)
{
    if (len == 0)
    {
        return false;
    }
    u32 v = 0;
    for (u32 i = 0; i < len; ++i)
    {
        const char c = s[i];
        if (c < '0' || c > '9')
        {
            return false;
        }
        const u32 n = v * 10 + static_cast<u32>(c - '0');
        if (n < v)
        {
            return false;
        }
        v = n;
    }
    *out = v;
    return true;
}

bool ParseBytesHex(const char* s, u32 len, u8* out, u32 cap, u32* size_out)
{
    if ((len & 1) != 0)
    {
        return false;
    }
    const u32 nbytes = len / 2;
    if (nbytes > cap)
    {
        return false;
    }
    for (u32 i = 0; i < nbytes; ++i)
    {
        u8 hi = 0;
        u8 lo = 0;
        if (!HexNibble(s[i * 2], &hi) || !HexNibble(s[i * 2 + 1], &lo))
        {
            return false;
        }
        out[i] = static_cast<u8>((hi << 4) | lo);
    }
    *size_out = nbytes;
    return true;
}

bool BytewiseEqual(const char* a, u64 la, const char* b, u64 lb)
{
    if (la != lb)
    {
        return false;
    }
    for (u64 i = 0; i < la; ++i)
    {
        if (a[i] != b[i])
        {
            return false;
        }
    }
    return true;
}

// Format the live sidecar pool into `dst[..cap)`. Returns the
// number of bytes written. Skips entries whose path/name would
// break the file format (ContainsForbidden) — those entries
// stay in RAM but don't make it to disk.
u64 FormatPayload(char* dst, u64 cap)
{
    u64 pos = 0;
    AppendStr(dst, &pos, cap, "# DuetOS registry sidecar v1\n");
    AppendStr(dst, &pos, cap, "# v|root|path|name|type|hex-data\n");
    AppendStr(dst, &pos, cap, "# t|root|path|name\n");
    for (u32 i = 0; i < detail::kSidecarPoolSize; ++i)
    {
        detail::HiveSnapshot s{};
        if (!detail::SidecarSnapshotAt(i, &s) || !s.active)
        {
            continue;
        }
        if (ContainsForbidden(s.path) || ContainsForbidden(s.name))
        {
            arch::SerialWrite("[reg-hive] skipping entry with reserved chars in path/name\n");
            continue;
        }
        AppendChar(dst, &pos, cap, s.tombstone ? 't' : 'v');
        AppendChar(dst, &pos, cap, '|');
        AppendHex32(dst, &pos, cap, static_cast<u32>(s.root));
        AppendChar(dst, &pos, cap, '|');
        AppendStr(dst, &pos, cap, s.path);
        AppendChar(dst, &pos, cap, '|');
        AppendStr(dst, &pos, cap, s.name);
        if (!s.tombstone)
        {
            AppendChar(dst, &pos, cap, '|');
            AppendU32Dec(dst, &pos, cap, s.type);
            AppendChar(dst, &pos, cap, '|');
            AppendBytesHex(dst, &pos, cap, s.data, s.size);
        }
        AppendChar(dst, &pos, cap, '\n');
    }
    return pos;
}

// Walk one already-trimmed line. Returns true on a recognised
// `v|...` or `t|...` line (regardless of whether the apply
// succeeded — unknown keys are silently skipped per the
// forward-compat policy). Comments and blank lines are also
// "recognised" as no-ops.
bool ApplyLine(const char* line, u64 len)
{
    if (len == 0 || line[0] == '#')
    {
        return true;
    }
    if (line[0] != 'v' && line[0] != 't')
    {
        return false;
    }
    if (len < 2 || line[1] != '|')
    {
        return false;
    }
    detail::HiveSnapshot s{};
    s.active = true;
    s.tombstone = (line[0] == 't');

    // Walk fields separated by '|'. We need 4 fields for `t|...`,
    // 6 fields for `v|...`. Track field starts and lengths.
    u64 starts[6] = {0};
    u32 lens[6] = {0};
    u32 nfields = 0;
    u64 cur = 2;
    starts[0] = cur;
    while (cur < len)
    {
        if (line[cur] == '|')
        {
            lens[nfields] = static_cast<u32>(cur - starts[nfields]);
            ++nfields;
            if (nfields >= 6)
            {
                return false; // too many fields
            }
            starts[nfields] = cur + 1;
        }
        ++cur;
    }
    lens[nfields] = static_cast<u32>(cur - starts[nfields]);
    ++nfields;

    const u32 want = s.tombstone ? 3u : 5u;
    if (nfields != want)
    {
        return false;
    }
    u32 root32 = 0;
    if (!ParseHex32(line + starts[0], lens[0], &root32))
    {
        return false;
    }
    s.root = static_cast<u64>(root32);

    if (lens[1] >= sizeof(s.path))
    {
        return false;
    }
    for (u32 i = 0; i < lens[1]; ++i)
    {
        s.path[i] = line[starts[1] + i];
    }
    s.path[lens[1]] = '\0';

    if (lens[2] >= sizeof(s.name))
    {
        return false;
    }
    for (u32 i = 0; i < lens[2]; ++i)
    {
        s.name[i] = line[starts[2] + i];
    }
    s.name[lens[2]] = '\0';

    if (!s.tombstone)
    {
        u32 type32 = 0;
        if (!ParseU32Dec(line + starts[3], lens[3], &type32))
        {
            return false;
        }
        s.type = type32;
        u32 size32 = 0;
        if (!ParseBytesHex(line + starts[4], lens[4], s.data, sizeof(s.data), &size32))
        {
            return false;
        }
        s.size = size32;
    }

    detail::SidecarRestoreOne(&s);
    return true;
}

void ApplyPayload(const char* buf, u64 len)
{
    u64 i = 0;
    while (i < len)
    {
        const u64 line_start = i;
        while (i < len && buf[i] != '\n' && buf[i] != '\r')
        {
            ++i;
        }
        ApplyLine(buf + line_start, i - line_start);
        // Skip the line terminator(s).
        while (i < len && (buf[i] == '\n' || buf[i] == '\r'))
        {
            ++i;
        }
    }
}

} // namespace

void RegistryHiveLoad()
{
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        return;
    }
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, kHivePath, &e))
    {
        return; // first boot — file doesn't exist yet
    }
    if (e.size_bytes == 0 || e.size_bytes > kPayloadCap)
    {
        arch::SerialWrite("[reg-hive] REGISTRY.HIV size out of range, ignoring\n");
        return;
    }
    static char buf[kPayloadCap];
    const i64 n = fat::Fat32ReadAt(v, &e, 0, buf, e.size_bytes);
    if (n <= 0)
    {
        arch::SerialWrite("[reg-hive] REGISTRY.HIV read failed\n");
        return;
    }
    detail::SidecarReset();
    ApplyPayload(buf, static_cast<u64>(n));
    // Seed g_last_payload so the first SetValueKey-driven save
    // doesn't write a no-op file. Recompute from the live pool —
    // round-tripping through FormatPayload normalises whitespace.
    g_last_len = FormatPayload(g_last_payload, kPayloadCap);
    arch::SerialWrite("[reg-hive] REGISTRY.HIV applied\n");
}

void RegistryHiveSave()
{
    if (g_in_save)
    {
        return;
    }
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        return;
    }
    static char buf[kPayloadCap];
    g_in_save = true;
    const u64 len = FormatPayload(buf, kPayloadCap);
    if (len == 0)
    {
        g_in_save = false;
        return;
    }
    if (BytewiseEqual(buf, len, g_last_payload, g_last_len))
    {
        g_in_save = false;
        return;
    }
    fat::DirEntry pre;
    if (fat::Fat32LookupPath(v, kHivePath, &pre))
    {
        fat::Fat32DeleteAtPath(v, kHivePath);
    }
    if (fat::Fat32CreateAtPath(v, kHivePath, buf, static_cast<u32>(len)) < 0)
    {
        arch::SerialWrite("[reg-hive] REGISTRY.HIV create failed\n");
        g_in_save = false;
        return;
    }
    for (u64 i = 0; i < len; ++i)
    {
        g_last_payload[i] = buf[i];
    }
    g_last_len = len;
    g_in_save = false;
}

void RegistryHiveSelfTest()
{
    using arch::SerialWrite;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[reg-hive] self-test SKIP: no FAT32 volume\n");
        return;
    }

    // Round-trip a synthetic snapshot through FormatPayload +
    // ApplyPayload entirely in memory. Doesn't touch the on-disk
    // hive — the operator's saved values are preserved.

    // Snapshot the current pool so we can restore it after the
    // round-trip. The probe value stays in slot 0..N-1 only for
    // the duration of the test.
    detail::HiveSnapshot saved[detail::kSidecarPoolSize];
    for (u32 i = 0; i < detail::kSidecarPoolSize; ++i)
    {
        detail::SidecarSnapshotAt(i, &saved[i]);
    }
    detail::SidecarReset();

    // Plant a known probe — a REG_DWORD (type=4, 4 bytes) under
    // the always-present HKLM CurrentVersion key. The data is a
    // distinctive bit pattern so a memcmp gap stands out in
    // failure mode logs.
    detail::HiveSnapshot probe{};
    probe.active = true;
    probe.tombstone = false;
    probe.root = kHkeyLocalMachine;
    {
        const char* p = "Software\\Microsoft\\Windows NT\\CurrentVersion";
        u32 i = 0;
        for (; p[i] != '\0' && i + 1 < sizeof(probe.path); ++i)
        {
            probe.path[i] = p[i];
        }
        probe.path[i] = '\0';
    }
    {
        const char* n = "DuetOSHiveProbe";
        u32 i = 0;
        for (; n[i] != '\0' && i + 1 < sizeof(probe.name); ++i)
        {
            probe.name[i] = n[i];
        }
        probe.name[i] = '\0';
    }
    probe.type = kRegDword;
    probe.size = 4;
    probe.data[0] = 0xDE;
    probe.data[1] = 0xAD;
    probe.data[2] = 0xBE;
    probe.data[3] = 0xEF;
    const bool restored = detail::SidecarRestoreOne(&probe);

    bool ok = restored;
    if (!ok)
    {
        SerialWrite("[reg-hive] self-test FAILED: SidecarRestoreOne refused probe\n");
    }

    char scratch[2048];
    const u64 fmt_len = FormatPayload(scratch, sizeof(scratch));
    if (fmt_len == 0)
    {
        ok = false;
        SerialWrite("[reg-hive] self-test FAILED: FormatPayload empty\n");
    }

    // Wipe the pool again, then re-apply the payload — the probe
    // slot should come back identically.
    detail::SidecarReset();
    ApplyPayload(scratch, fmt_len);

    detail::HiveSnapshot back{};
    bool found_probe = false;
    for (u32 i = 0; i < detail::kSidecarPoolSize; ++i)
    {
        detail::HiveSnapshot s{};
        if (!detail::SidecarSnapshotAt(i, &s) || !s.active)
        {
            continue;
        }
        if (s.root != kHkeyLocalMachine)
        {
            continue;
        }
        // Match by name only — there's just one probe.
        bool name_match = true;
        for (u32 k = 0; k < sizeof(probe.name); ++k)
        {
            if (s.name[k] != probe.name[k])
            {
                name_match = false;
                break;
            }
            if (probe.name[k] == '\0')
            {
                break;
            }
        }
        if (!name_match)
        {
            continue;
        }
        back = s;
        found_probe = true;
        break;
    }
    if (!found_probe)
    {
        ok = false;
        SerialWrite("[reg-hive] self-test FAILED: probe missing after round-trip\n");
    }
    else if (back.type != probe.type || back.size != probe.size || back.data[0] != 0xDE || back.data[1] != 0xAD ||
             back.data[2] != 0xBE || back.data[3] != 0xEF)
    {
        ok = false;
        SerialWrite("[reg-hive] self-test FAILED: probe payload mismatch after round-trip\n");
    }

    // Restore the original pool.
    detail::SidecarReset();
    for (u32 i = 0; i < detail::kSidecarPoolSize; ++i)
    {
        if (saved[i].active)
        {
            detail::SidecarRestoreOne(&saved[i]);
        }
    }

    SerialWrite(ok ? "[reg-hive] self-test OK (sidecar round-trip via REGISTRY.HIV format)\n"
                   : "[reg-hive] self-test FAILED\n");
}

} // namespace duetos::subsystems::win32::registry
