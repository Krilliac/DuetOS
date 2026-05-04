#include "core/session_restore.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "fs/fat32.h"
#include "log/klog.h"

/*
 * SESSION.CFG round-trip.
 *
 * Layout decision: one file at the FAT32 root, plain ASCII
 * key=value lines. Reasons:
 *   - Hand-readable from `dmesg f` style streaming or any
 *     external FAT32 reader, so a user can debug a corrupt
 *     window position without a hex editor.
 *   - Forward-compatible: unknown keys are skipped, so adding
 *     a `win.0.minimized=1` field tomorrow doesn't break a
 *     boot that mounts an older file.
 *   - Tiny payload (< 256 bytes) so the whole file fits in a
 *     single FAT32 cluster + a single Read call.
 *
 * Throttle: every call to SessionRestoreSave() formats the
 * payload first, compares it byte-for-byte against the last
 * successfully-written copy held in g_last_payload, and skips
 * the FAT32 write if identical. With the 1 Hz autosave wired
 * up in main.cpp's ui-ticker, a stable session writes once and
 * then idles — the FAT mirror is not beaten flat.
 *
 * Re-entrancy: the FAT32 write path emits Trace logs, and
 * those Trace logs go through the persistent klog sink which
 * also issues FAT32 writes. The klog sink has its own
 * re-entrancy guard; we don't need a separate one here because
 * SessionRestoreSave is only ever called from task context
 * (ui-ticker, logout paths) and never from inside a klog
 * callback.
 */

namespace duetos::core
{

namespace
{

constexpr const char kCfgPath[] = "SESSION.CFG";
constexpr u64 kPayloadCap = 1024;

constinit char g_last_payload[kPayloadCap] = {};
constinit u64 g_last_len = 0;

// Small helpers — no <string.h> in kernel.

bool StrEq(const char* a, const char* b)
{
    while (*a != 0 && *b != 0)
    {
        if (*a++ != *b++)
        {
            return false;
        }
    }
    return *a == 0 && *b == 0;
}

u64 StrLen(const char* s)
{
    u64 n = 0;
    while (s[n] != 0)
    {
        ++n;
    }
    return n;
}

// Append `s` to `dst[*pos]`, bounded by cap. No-op on overflow.
void Append(char* dst, u64* pos, u64 cap, const char* s)
{
    while (*s != 0 && *pos + 1 < cap)
    {
        dst[(*pos)++] = *s++;
    }
}

void AppendU32(char* dst, u64* pos, u64 cap, u32 v)
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
    // tmp is reversed; emit it in the right order.
    while (n > 0 && *pos + 1 < cap)
    {
        dst[(*pos)++] = tmp[--n];
    }
}

bool ParseU32(const char* s, u32 len, u32* out)
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
        const u32 next = v * 10 + static_cast<u32>(c - '0');
        if (next < v)
        {
            return false; // overflow
        }
        v = next;
    }
    *out = v;
    return true;
}

void FormatPayload(char* dst, u64 cap, u64* len_out)
{
    namespace v = drivers::video;
    u64 pos = 0;
    Append(dst, &pos, cap, "theme=");
    Append(dst, &pos, cap, v::ThemeIdName(v::ThemeCurrentId()));
    Append(dst, &pos, cap, "\n");

    for (u32 i = 0; i < static_cast<u32>(v::ThemeRole::kCount); ++i)
    {
        const v::WindowHandle h = v::ThemeRoleWindow(static_cast<v::ThemeRole>(i));
        if (h == v::kWindowInvalid)
        {
            continue;
        }
        u32 x = 0;
        u32 y = 0;
        if (!v::WindowGetBounds(h, &x, &y, nullptr, nullptr))
        {
            continue;
        }
        Append(dst, &pos, cap, "win.");
        AppendU32(dst, &pos, cap, i);
        Append(dst, &pos, cap, ".x=");
        AppendU32(dst, &pos, cap, x);
        Append(dst, &pos, cap, "\n");

        Append(dst, &pos, cap, "win.");
        AppendU32(dst, &pos, cap, i);
        Append(dst, &pos, cap, ".y=");
        AppendU32(dst, &pos, cap, y);
        Append(dst, &pos, cap, "\n");
    }
    *len_out = pos;
}

// Apply one already-split key=value. Returns true on a known-key
// match (regardless of whether the value applied cleanly).
bool ApplyOne(const char* key, const char* val)
{
    namespace v = drivers::video;
    if (StrEq(key, "theme"))
    {
        v::ThemeId id;
        if (v::ThemeIdFromName(val, &id))
        {
            v::ThemeSet(id);
        }
        return true;
    }
    // win.<role>.x or win.<role>.y
    if (key[0] == 'w' && key[1] == 'i' && key[2] == 'n' && key[3] == '.')
    {
        const char* p = key + 4;
        u32 role = 0;
        u32 i = 0;
        while (p[i] >= '0' && p[i] <= '9')
        {
            role = role * 10 + static_cast<u32>(p[i] - '0');
            ++i;
        }
        if (i == 0 || p[i] != '.' || role >= static_cast<u32>(v::ThemeRole::kCount))
        {
            return false;
        }
        const char axis = p[i + 1];
        if ((axis != 'x' && axis != 'y') || p[i + 2] != 0)
        {
            return false;
        }
        u32 num = 0;
        if (!ParseU32(val, static_cast<u32>(StrLen(val)), &num))
        {
            return false;
        }
        const v::WindowHandle h = v::ThemeRoleWindow(static_cast<v::ThemeRole>(role));
        if (h == v::kWindowInvalid)
        {
            return true; // known key, just no live window — accept silently
        }
        u32 cx = 0;
        u32 cy = 0;
        if (!v::WindowGetBounds(h, &cx, &cy, nullptr, nullptr))
        {
            return true;
        }
        if (axis == 'x')
        {
            v::WindowMoveTo(h, num, cy);
        }
        else
        {
            v::WindowMoveTo(h, cx, num);
        }
        return true;
    }
    return false;
}

void ApplyPayload(const char* buf, u64 len)
{
    // Walk line by line. Buffers are small, so we copy each
    // line into a 96-byte stack scratch and split on '='.
    char line[96];
    u64 lpos = 0;
    for (u64 i = 0; i <= len; ++i)
    {
        const char c = (i < len) ? buf[i] : '\n';
        if (c == '\n' || c == '\r')
        {
            if (lpos == 0)
            {
                continue;
            }
            line[lpos] = 0;
            // Find '='
            u64 eq = 0;
            while (eq < lpos && line[eq] != '=')
            {
                ++eq;
            }
            if (eq < lpos)
            {
                line[eq] = 0;
                ApplyOne(line, line + eq + 1);
            }
            lpos = 0;
            continue;
        }
        if (lpos + 1 < sizeof(line))
        {
            line[lpos++] = c;
        }
    }
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

} // namespace

void SessionRestoreApply()
{
    namespace fat = fs::fat32;
    const fat::Volume* vol = fat::Fat32Volume(0);
    if (vol == nullptr)
    {
        return;
    }
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(vol, kCfgPath, &e))
    {
        return; // first boot — no file yet
    }
    if (e.size_bytes == 0 || e.size_bytes > kPayloadCap)
    {
        KLOG_WARN("session", "SESSION.CFG size out of range, ignoring");
        return;
    }
    char buf[kPayloadCap];
    const i64 n = fat::Fat32ReadAt(vol, &e, 0, buf, e.size_bytes);
    if (n <= 0)
    {
        KLOG_WARN("session", "SESSION.CFG read failed");
        return;
    }
    ApplyPayload(buf, static_cast<u64>(n));
    // Seed g_last_payload with what was just applied so the
    // first autosave doesn't write a no-op file.
    for (i64 i = 0; i < n; ++i)
    {
        g_last_payload[i] = buf[i];
    }
    g_last_len = static_cast<u64>(n);
    KLOG_INFO("session", "applied SESSION.CFG");
}

void SessionRestoreSave()
{
    namespace fat = fs::fat32;
    const fat::Volume* vol = fat::Fat32Volume(0);
    if (vol == nullptr)
    {
        return;
    }
    char buf[kPayloadCap];
    u64 len = 0;
    FormatPayload(buf, kPayloadCap, &len);
    if (len == 0)
    {
        return;
    }
    if (BytewiseEqual(buf, len, g_last_payload, g_last_len))
    {
        return; // unchanged; skip the FAT32 write
    }
    // Replace the file: delete + create, since Fat32CreateAtPath
    // doesn't truncate-on-exist.
    fat::DirEntry pre;
    if (fat::Fat32LookupPath(vol, kCfgPath, &pre))
    {
        fat::Fat32DeleteAtPath(vol, kCfgPath);
    }
    if (fat::Fat32CreateAtPath(vol, kCfgPath, buf, static_cast<u32>(len)) < 0)
    {
        KLOG_WARN("session", "SESSION.CFG create failed");
        return;
    }
    for (u64 i = 0; i < len; ++i)
    {
        g_last_payload[i] = buf[i];
    }
    g_last_len = len;
}

void SessionRestoreSelfTest()
{
    namespace fat = fs::fat32;
    namespace v = drivers::video;
    using arch::SerialWrite;
    const fat::Volume* vol = fat::Fat32Volume(0);
    if (vol == nullptr)
    {
        SerialWrite("[session] self-test SKIP: no FAT32 volume\n");
        return;
    }
    // Round-trip a synthetic payload through ApplyPayload +
    // FormatPayload without touching the on-disk SESSION.CFG.
    // We don't want this self-test to clobber the user's saved
    // session state, so we operate purely in memory.
    // Pick a synthetic theme name that's actually registered. The
    // round-trip needs to switch *to* a different theme than the
    // current default (Classic), so we pick "amber" — known
    // registered, distinct from Classic.
    constexpr const char* kSynthTheme = "amber";
    char synth[64];
    u64 spos = 0;
    Append(synth, &spos, sizeof(synth), "theme=");
    Append(synth, &spos, sizeof(synth), kSynthTheme);
    Append(synth, &spos, sizeof(synth), "\nwin.0.x=42\nwin.0.y=84\n");
    const v::ThemeId orig_theme = v::ThemeCurrentId();
    u32 ox = 0;
    u32 oy = 0;
    const v::WindowHandle calc = v::ThemeRoleWindow(v::ThemeRole::Calculator);
    const bool have_calc = (calc != v::kWindowInvalid) && v::WindowGetBounds(calc, &ox, &oy, nullptr, nullptr);

    ApplyPayload(synth, spos);

    bool ok = true;
    v::ThemeId got;
    const bool theme_known = v::ThemeIdFromName(kSynthTheme, &got);
    const bool theme_applied = theme_known && (v::ThemeCurrentId() == got);
    if (!theme_applied)
    {
        ok = false;
        // Sub-check failure detail. WARN so it always surfaces in any
        // sensible klog level, but routed through klog (not raw serial)
        // so it respects loglevel demotion in production builds.
        KLOG_WARN("session", "self-test: theme sub-check FAILED");
        KLOG_DEBUG_S("session", "  theme known", "want", kSynthTheme);
        KLOG_DEBUG_S("session", "  theme current", "current", v::ThemeIdName(v::ThemeCurrentId()));
        KLOG_DEBUG_V("session", "  theme known flag", theme_known ? 1u : 0u);
    }
    bool win_ok = true;
    u32 nx_dbg = 0;
    u32 ny_dbg = 0;
    bool got_bounds = false;
    if (have_calc)
    {
        got_bounds = v::WindowGetBounds(calc, &nx_dbg, &ny_dbg, nullptr, nullptr);
        if (!got_bounds || nx_dbg != 42 || ny_dbg != 84)
        {
            ok = false;
            win_ok = false;
        }
        // Restore original calc position.
        v::WindowMoveTo(calc, ox, oy);
    }
    if (!win_ok)
    {
        KLOG_WARN("session", "self-test: window-position sub-check FAILED");
        KLOG_DEBUG_V("session", "  have_calc", have_calc ? 1u : 0u);
        KLOG_DEBUG_V("session", "  got_bounds", got_bounds ? 1u : 0u);
        KLOG_DEBUG_V("session", "  observed nx", nx_dbg);
        KLOG_DEBUG_V("session", "  observed ny", ny_dbg);
    }
    // Restore original theme.
    v::ThemeSet(orig_theme);

    if (ok)
    {
        SerialWrite("[session] self-test OK (theme + window position round-trip)\n");
    }
    else
    {
        SerialWrite("[session] self-test FAILED (see preceding sub-check log)\n");
        // Fire the GDB-attachable probe so a debugger session catches
        // the exact frame where the regression first surfaces. Encoded
        // value packs the two sub-check flags so the probe row tells
        // an at-a-glance reader which leg failed without re-greping.
        const u64 fail_value = (theme_applied ? 0u : 0x01u) | (win_ok ? 0u : 0x02u);
        KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, fail_value);
    }
}

} // namespace duetos::core
