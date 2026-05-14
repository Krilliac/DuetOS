#include "core/session_restore.h"

#include "apps/calculator.h"
#include "apps/imageview.h"
#include "apps/settings.h"
#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/sound_cue.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "fs/fat32.h"
#include "log/klog.h"
#include "time/timezone.h"
#include "util/string.h"

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
// Sized for: theme + every role window (two lines each) + the
// system-knob keys (mouse / kbd / sound / tz / calc / imageview).
// The 12-role window block alone is ~600 bytes; the knob block
// adds ~250. 2 KiB leaves headroom for new keys without forcing
// a per-add bump.
constexpr u64 kPayloadCap = 2048;

constinit char g_last_payload[kPayloadCap] = {};
constinit u64 g_last_len = 0;

// Pull the canonical NUL-string helpers into scope so the
// session-restore parser code below can call them unqualified —
// previously this TU rolled its own near-identical copies of
// each (since retired into util/string.h).
using duetos::core::StrEqual;
using duetos::core::StrLen;

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

void AppendI32(char* dst, u64* pos, u64 cap, i32 v)
{
    if (v < 0)
    {
        if (*pos + 1 < cap)
        {
            dst[(*pos)++] = '-';
        }
        // -INT32_MIN can't be represented; promote to u32 abs.
        const u32 abs_v = (v == static_cast<i32>(0x80000000)) ? 0x80000000u : static_cast<u32>(-v);
        AppendU32(dst, pos, cap, abs_v);
        return;
    }
    AppendU32(dst, pos, cap, static_cast<u32>(v));
}

bool ParseI32(const char* s, u32 len, i32* out)
{
    if (len == 0)
    {
        return false;
    }
    bool neg = false;
    u32 i = 0;
    if (s[0] == '-')
    {
        neg = true;
        i = 1;
    }
    else if (s[0] == '+')
    {
        i = 1;
    }
    if (i >= len)
    {
        return false;
    }
    u32 mag = 0;
    if (!ParseU32(s + i, len - i, &mag))
    {
        return false;
    }
    if (neg)
    {
        // Allow magnitude up to 2^31 (so INT32_MIN parses).
        if (mag > 0x80000000u)
        {
            return false;
        }
        *out = (mag == 0x80000000u) ? static_cast<i32>(0x80000000) : -static_cast<i32>(mag);
    }
    else
    {
        if (mag > 0x7FFFFFFFu)
        {
            return false;
        }
        *out = static_cast<i32>(mag);
    }
    return true;
}

void AppendI64(char* dst, u64* pos, u64 cap, i64 v)
{
    bool neg = false;
    u64 mag;
    if (v < 0)
    {
        neg = true;
        // i64 min has no representable positive — handle it as
        // the unsigned 0x80000000'00000000 magnitude, identical to
        // -static_cast<u64>(v) under two's-complement semantics.
        mag = static_cast<u64>(-(v + 1)) + 1;
    }
    else
    {
        mag = static_cast<u64>(v);
    }
    char tmp[24];
    u32 n = 0;
    if (mag == 0)
    {
        tmp[n++] = '0';
    }
    while (mag != 0)
    {
        tmp[n++] = static_cast<char>('0' + (mag % 10));
        mag /= 10;
    }
    if (neg && *pos + 1 < cap)
    {
        dst[(*pos)++] = '-';
    }
    while (n > 0 && *pos + 1 < cap)
    {
        dst[(*pos)++] = tmp[--n];
    }
}

bool ParseI64(const char* s, u32 len, i64* out)
{
    if (len == 0)
    {
        return false;
    }
    bool neg = false;
    u32 i = 0;
    if (s[0] == '-')
    {
        neg = true;
        i = 1;
    }
    else if (s[0] == '+')
    {
        i = 1;
    }
    if (i >= len)
    {
        return false;
    }
    u64 v = 0;
    for (u32 j = i; j < len; ++j)
    {
        const char c = s[j];
        if (c < '0' || c > '9')
        {
            return false;
        }
        const u64 next = v * 10 + static_cast<u64>(c - '0');
        if (next < v)
        {
            return false; // overflow
        }
        v = next;
    }
    if (neg)
    {
        if (v > 0x8000000000000000ULL)
        {
            return false;
        }
        *out = (v == 0x8000000000000000ULL) ? static_cast<i64>(0x8000000000000000LL) : -static_cast<i64>(v);
    }
    else
    {
        if (v > 0x7FFFFFFFFFFFFFFFULL)
        {
            return false;
        }
        *out = static_cast<i64>(v);
    }
    return true;
}

const char* KeyboardLayoutName(drivers::input::KeyboardLayout l)
{
    using drivers::input::KeyboardLayout;
    switch (l)
    {
    case KeyboardLayout::US:
        return "us";
    case KeyboardLayout::UK:
        return "uk";
    case KeyboardLayout::Dvorak:
        return "dvorak";
    case KeyboardLayout::DE:
        return "de";
    case KeyboardLayout::FR:
        return "fr";
    case KeyboardLayout::Colemak:
        return "colemak";
    }
    return "us";
}

bool KeyboardLayoutFromName(const char* name, drivers::input::KeyboardLayout* out)
{
    using drivers::input::KeyboardLayout;
    if (StrEqual(name, "us"))
    {
        *out = KeyboardLayout::US;
        return true;
    }
    if (StrEqual(name, "uk"))
    {
        *out = KeyboardLayout::UK;
        return true;
    }
    if (StrEqual(name, "dvorak"))
    {
        *out = KeyboardLayout::Dvorak;
        return true;
    }
    if (StrEqual(name, "de"))
    {
        *out = KeyboardLayout::DE;
        return true;
    }
    if (StrEqual(name, "fr"))
    {
        *out = KeyboardLayout::FR;
        return true;
    }
    if (StrEqual(name, "colemak"))
    {
        *out = KeyboardLayout::Colemak;
        return true;
    }
    return false;
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
        u32 w = 0;
        u32 hgt = 0;
        if (!v::WindowGetBounds(h, &x, &y, &w, &hgt))
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

        // Width/height — captures user-driven resizes (e.g. the
        // ImageView Ctrl+wheel / +/- zoom path, which mutates
        // the window dimensions rather than a separate zoom
        // factor). Only emitted when the bounds query succeeds;
        // the apply side tolerates either field being absent.
        Append(dst, &pos, cap, "win.");
        AppendU32(dst, &pos, cap, i);
        Append(dst, &pos, cap, ".w=");
        AppendU32(dst, &pos, cap, w);
        Append(dst, &pos, cap, "\n");

        Append(dst, &pos, cap, "win.");
        AppendU32(dst, &pos, cap, i);
        Append(dst, &pos, cap, ".h=");
        AppendU32(dst, &pos, cap, hgt);
        Append(dst, &pos, cap, "\n");
    }

    // Mouse — double-click threshold (in compositor ticks) and
    // sensitivity (0..255, identity = 128).
    Append(dst, &pos, cap, "mouse.dblclick=");
    AppendU32(dst, &pos, cap, v::WindowDoubleClickTicks());
    Append(dst, &pos, cap, "\n");
    Append(dst, &pos, cap, "mouse.sens=");
    AppendU32(dst, &pos, cap, v::WindowMouseSensitivity());
    Append(dst, &pos, cap, "\n");

    // Keyboard — typematic indices + active layout.
    Append(dst, &pos, cap, "kbd.rate=");
    AppendU32(dst, &pos, cap, apps::settings::KeyboardTypematicRateIdx());
    Append(dst, &pos, cap, "\n");
    Append(dst, &pos, cap, "kbd.delay=");
    AppendU32(dst, &pos, cap, apps::settings::KeyboardTypematicDelayIdx());
    Append(dst, &pos, cap, "\n");
    Append(dst, &pos, cap, "kbd.layout=");
    Append(dst, &pos, cap, KeyboardLayoutName(drivers::input::Ps2KeyboardLayout()));
    Append(dst, &pos, cap, "\n");

    // Sound cues enable flag — drives the M-key toggle on the
    // Sound sub-panel.
    Append(dst, &pos, cap, "sound.cues=");
    AppendU32(dst, &pos, cap, v::SoundCueIsEnabled() ? 1u : 0u);
    Append(dst, &pos, cap, "\n");

    // Timezone offset in minutes (signed; range -720..+840).
    Append(dst, &pos, cap, "tz.minutes=");
    AppendI32(dst, &pos, cap, time::TimezoneOffsetMinutes());
    Append(dst, &pos, cap, "\n");

    // Calculator memory register — only emit when the user has
    // an active stash. The `memset` flag is what drives the M
    // indicator; on a fresh boot with no stash we don't bother
    // round-tripping a zero pair.
    if (apps::calculator::CalculatorMemorySet())
    {
        Append(dst, &pos, cap, "calc.mem=");
        AppendI64(dst, &pos, cap, apps::calculator::CalculatorMemoryValue());
        Append(dst, &pos, cap, "\ncalc.memset=1\n");
    }

    // ImageView last-loaded filename — empty string means "no
    // selection on the most recent boot", which the Apply path
    // ignores (no point selecting "" through SelectByName).
    const char* iv_name = apps::imageview::ImageViewCurrentName();
    if (iv_name != nullptr && iv_name[0] != '\0')
    {
        Append(dst, &pos, cap, "imageview.last=");
        Append(dst, &pos, cap, iv_name);
        Append(dst, &pos, cap, "\n");
    }

    *len_out = pos;
}

// Apply one already-split key=value. Returns true on a known-key
// match (regardless of whether the value applied cleanly).
bool ApplyOne(const char* key, const char* val)
{
    namespace v = drivers::video;
    if (StrEqual(key, "theme"))
    {
        v::ThemeId id;
        if (v::ThemeIdFromName(val, &id))
        {
            v::ThemeSet(id);
        }
        return true;
    }
    if (StrEqual(key, "mouse.dblclick"))
    {
        u32 num = 0;
        if (ParseU32(val, static_cast<u32>(StrLen(val)), &num))
        {
            v::WindowSetDoubleClickTicks(num);
        }
        return true;
    }
    if (StrEqual(key, "mouse.sens"))
    {
        u32 num = 0;
        if (ParseU32(val, static_cast<u32>(StrLen(val)), &num) && num <= 0xFF)
        {
            v::WindowSetMouseSensitivity(static_cast<u8>(num));
        }
        return true;
    }
    if (StrEqual(key, "kbd.rate") || StrEqual(key, "kbd.delay"))
    {
        u32 num = 0;
        if (!ParseU32(val, static_cast<u32>(StrLen(val)), &num))
        {
            return true; // known key, malformed value — ignore
        }
        // Read the current pair, replace just the field this key
        // names, then push both. Avoids depending on which of the
        // two keys the parser sees first.
        u8 rate = apps::settings::KeyboardTypematicRateIdx();
        u8 delay = apps::settings::KeyboardTypematicDelayIdx();
        if (StrEqual(key, "kbd.rate") && num <= 31)
        {
            rate = static_cast<u8>(num);
        }
        else if (StrEqual(key, "kbd.delay") && num <= 3)
        {
            delay = static_cast<u8>(num);
        }
        apps::settings::KeyboardSetTypematicIdx(rate, delay);
        return true;
    }
    if (StrEqual(key, "kbd.layout"))
    {
        drivers::input::KeyboardLayout l;
        if (KeyboardLayoutFromName(val, &l))
        {
            drivers::input::Ps2KeyboardSetLayout(l);
        }
        return true;
    }
    if (StrEqual(key, "sound.cues"))
    {
        u32 num = 0;
        if (ParseU32(val, static_cast<u32>(StrLen(val)), &num))
        {
            v::SoundCueSetEnabled(num != 0);
        }
        return true;
    }
    if (StrEqual(key, "tz.minutes"))
    {
        i32 num = 0;
        if (ParseI32(val, static_cast<u32>(StrLen(val)), &num))
        {
            time::SetTimezoneOffsetMinutes(num);
        }
        return true;
    }
    if (StrEqual(key, "calc.mem"))
    {
        i64 num = 0;
        if (ParseI64(val, static_cast<u32>(StrLen(val)), &num))
        {
            // Tentatively stash the value. The matching memset=1
            // line that follows will lock in the M indicator. If
            // calc.memset never arrives (stripped file), the
            // value sits as a zeroed register from boot defaults
            // — exactly the no-stash state.
            apps::calculator::CalculatorMemoryRestore(num, true);
        }
        return true;
    }
    if (StrEqual(key, "calc.memset"))
    {
        u32 num = 0;
        if (ParseU32(val, static_cast<u32>(StrLen(val)), &num))
        {
            // Honor the explicit clear: memset=0 wipes whatever
            // calc.mem put in place (defensive; keeps the M flag
            // and the value coherent on a partially-written file).
            if (num == 0)
            {
                apps::calculator::CalculatorMemoryRestore(0, false);
            }
        }
        return true;
    }
    if (StrEqual(key, "imageview.last"))
    {
        if (val[0] != '\0')
        {
            apps::imageview::ImageViewSelectByName(val);
        }
        return true;
    }
    // win.<role>.x | win.<role>.y | win.<role>.w | win.<role>.h
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
        if ((axis != 'x' && axis != 'y' && axis != 'w' && axis != 'h') || p[i + 2] != 0)
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
        else if (axis == 'y')
        {
            v::WindowMoveTo(h, cx, num);
        }
        else if (axis == 'w')
        {
            // WindowResizeTo treats 0 as "leave unchanged" — pass
            // num for the width axis, 0 for height. The matching
            // .h line (if present) lands the height in a follow-up
            // call. WindowResizeTo clamps against the framebuffer
            // so a stale-config height bigger than the screen is
            // a no-op rather than a corruption.
            v::WindowResizeTo(h, num, 0);
        }
        else
        {
            v::WindowResizeTo(h, 0, num);
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
    char synth[256];
    u64 spos = 0;
    Append(synth, &spos, sizeof(synth), "theme=");
    Append(synth, &spos, sizeof(synth), kSynthTheme);
    Append(synth, &spos, sizeof(synth), "\nwin.0.x=42\nwin.0.y=84\nwin.0.w=320\nwin.0.h=240\n");
    // Synthetic system-knob block. Each of these values is
    // distinguishable from the boot defaults so a sub-check that
    // fails to apply leaves an observable gap.
    Append(synth, &spos, sizeof(synth),
           "mouse.dblclick=77\nmouse.sens=200\n"
           "kbd.rate=7\nkbd.delay=2\n"
           "sound.cues=0\n"
           "tz.minutes=-330\n"
           "calc.mem=-12345\ncalc.memset=1\n");
    const v::ThemeId orig_theme = v::ThemeCurrentId();
    u32 ox = 0;
    u32 oy = 0;
    u32 ow = 0;
    u32 oh = 0;
    const v::WindowHandle calc = v::ThemeRoleWindow(v::ThemeRole::Calculator);
    const bool have_calc = (calc != v::kWindowInvalid) && v::WindowGetBounds(calc, &ox, &oy, &ow, &oh);

    // Snapshot the live system-knob state so we can restore it
    // after the round-trip — this self-test must not perturb
    // what the user / boot defaults left behind.
    const u32 orig_dblclick = v::WindowDoubleClickTicks();
    const u8 orig_sens = v::WindowMouseSensitivity();
    const u8 orig_kbd_rate = apps::settings::KeyboardTypematicRateIdx();
    const u8 orig_kbd_delay = apps::settings::KeyboardTypematicDelayIdx();
    const bool orig_sound = v::SoundCueIsEnabled();
    const i32 orig_tz = time::TimezoneOffsetMinutes();
    const i64 orig_mem = apps::calculator::CalculatorMemoryValue();
    const bool orig_memset = apps::calculator::CalculatorMemorySet();

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
    u32 nw_dbg = 0;
    u32 nh_dbg = 0;
    bool got_bounds = false;
    if (have_calc)
    {
        got_bounds = v::WindowGetBounds(calc, &nx_dbg, &ny_dbg, &nw_dbg, &nh_dbg);
        if (!got_bounds || nx_dbg != 42 || ny_dbg != 84 || nw_dbg != 320 || nh_dbg != 240)
        {
            ok = false;
            win_ok = false;
        }
        // Restore the original calc geometry — both position
        // and size, so the test leaves no observable drift.
        v::WindowMoveTo(calc, ox, oy);
        v::WindowResizeTo(calc, ow, oh);
    }
    if (!win_ok)
    {
        KLOG_WARN("session", "self-test: window-geometry sub-check FAILED");
        KLOG_DEBUG_V("session", "  have_calc", have_calc ? 1u : 0u);
        KLOG_DEBUG_V("session", "  got_bounds", got_bounds ? 1u : 0u);
        KLOG_DEBUG_V("session", "  observed nx", nx_dbg);
        KLOG_DEBUG_V("session", "  observed ny", ny_dbg);
        KLOG_DEBUG_V("session", "  observed nw", nw_dbg);
        KLOG_DEBUG_V("session", "  observed nh", nh_dbg);
    }

    // System-knob round-trip checks. Each compares the live value
    // against the synthetic line above. A failure points to a
    // missing handler in ApplyOne or a parser regression.
    bool knob_ok = true;
    const u32 got_dblclick = v::WindowDoubleClickTicks();
    if (got_dblclick != 77)
    {
        knob_ok = false;
        KLOG_DEBUG_V("session", "  dblclick mismatch", got_dblclick);
    }
    const u32 got_sens = v::WindowMouseSensitivity();
    if (got_sens != 200)
    {
        knob_ok = false;
        KLOG_DEBUG_V("session", "  mouse sens mismatch", got_sens);
    }
    const u8 got_kbd_rate = apps::settings::KeyboardTypematicRateIdx();
    const u8 got_kbd_delay = apps::settings::KeyboardTypematicDelayIdx();
    if (got_kbd_rate != 7 || got_kbd_delay != 2)
    {
        knob_ok = false;
        KLOG_DEBUG_V("session", "  kbd rate idx mismatch", got_kbd_rate);
        KLOG_DEBUG_V("session", "  kbd delay idx mismatch", got_kbd_delay);
    }
    if (v::SoundCueIsEnabled())
    {
        knob_ok = false;
        KLOG_WARN("session", "  sound.cues=0 line did not disable cues");
    }
    const i32 got_tz = time::TimezoneOffsetMinutes();
    if (got_tz != -330)
    {
        knob_ok = false;
        KLOG_DEBUG_V("session", "  tz.minutes mismatch (expected -330)", static_cast<u32>(got_tz));
    }
    const i64 got_mem = apps::calculator::CalculatorMemoryValue();
    const bool got_memset = apps::calculator::CalculatorMemorySet();
    if (got_mem != -12345 || !got_memset)
    {
        knob_ok = false;
        KLOG_WARN("session", "  calc.mem / calc.memset round-trip mismatch");
    }
    if (!knob_ok)
    {
        ok = false;
        KLOG_WARN("session", "self-test: system-knob sub-check FAILED");
    }

    // Restore the original system-knob state so this test leaves
    // no observable side effects.
    v::WindowSetDoubleClickTicks(orig_dblclick);
    v::WindowSetMouseSensitivity(orig_sens);
    apps::settings::KeyboardSetTypematicIdx(orig_kbd_rate, orig_kbd_delay);
    v::SoundCueSetEnabled(orig_sound);
    time::SetTimezoneOffsetMinutes(orig_tz);
    apps::calculator::CalculatorMemoryRestore(orig_mem, orig_memset);

    // Restore original theme.
    v::ThemeSet(orig_theme);

    if (ok)
    {
        SerialWrite("[session] self-test OK (theme + window xy/wh + knob round-trip)\n");
    }
    else
    {
        SerialWrite("[session] self-test FAILED (see preceding sub-check log)\n");
        // Fire the GDB-attachable probe so a debugger session catches
        // the exact frame where the regression first surfaces. Encoded
        // value packs the three sub-check flags so the probe row tells
        // an at-a-glance reader which leg failed without re-greping.
        const u64 fail_value = (theme_applied ? 0u : 0x01u) | (win_ok ? 0u : 0x02u) | (knob_ok ? 0u : 0x04u);
        KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, fail_value);
    }
}

} // namespace duetos::core
