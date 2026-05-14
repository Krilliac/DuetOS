#include "drivers/video/start_menu_apps.h"

#include "arch/x86_64/serial.h"
#include "fs/fat32.h"
#include "log/klog.h"
#include "util/string.h"

/*
 * /APPS shortcut enumeration.
 *
 * Storage: a static pool of 16 (label, role) entries. Labels
 * live in a parallel 32-byte buffer so the menu can hold raw
 * `const char*` pointers that outlive the scan — re-scanning
 * just rewrites the same buffer in place.
 *
 * Parser is intentionally tiny: each manifest is read whole
 * (capped at 256 bytes), then walked once line-by-line. We
 * only recognise `name=` and `target=`; everything else is
 * skipped silently for forward compatibility.
 *
 * Why the SAMPLE.MNF seed: the directory enumeration would
 * otherwise look identical to "FAT32 isn't mounted" from a
 * user perspective. Planting one example file makes /APPS
 * discoverable and gives users a working template to copy.
 */

namespace duetos::drivers::video
{

namespace
{

constexpr u32 kLabelCap = 32;
constexpr u32 kPathCap = 96;
constexpr const char kAppsDir[] = "APPS";
constexpr const char kSamplePath[] = "APPS/SAMPLE.MNF";
constexpr const char kSampleBody[] = "; sample shortcut — copy as APPS/<NAME>.MNF\n"
                                     "name=DuetOS Notes\n"
                                     "target=notes\n"
                                     "; alternative form for a PE binary on disk:\n"
                                     ";   name=My PE App\n"
                                     ";   kind=pe path=APPS/MYAPP.EXE\n";

struct Slot
{
    char label[kLabelCap];
    ShortcutKind kind;
    ThemeRole role;      // valid iff kind == Role
    char path[kPathCap]; // valid iff kind == Pe / Elf — FAT32 path, NUL-terminated
    bool used;
};

constinit Slot g_slots[kStartMenuAppsMax] = {};
constinit u32 g_slot_count = 0;

using duetos::core::StrEqualCaseInsensitive;

bool CharEqIgnoreCase(char a, char b)
{
    if (a >= 'A' && a <= 'Z')
    {
        a = static_cast<char>(a + ('a' - 'A'));
    }
    if (b >= 'A' && b <= 'Z')
    {
        b = static_cast<char>(b + ('a' - 'A'));
    }
    return a == b;
}

bool ResolveTargetName(const char* s, ThemeRole* out)
{
    if (StrEqualCaseInsensitive(s, "calculator"))
    {
        *out = ThemeRole::Calculator;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "notes") || StrEqualCaseInsensitive(s, "notepad"))
    {
        *out = ThemeRole::Notes;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "files"))
    {
        *out = ThemeRole::Files;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "clock"))
    {
        *out = ThemeRole::Clock;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "settings"))
    {
        *out = ThemeRole::Settings;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "gfxdemo"))
    {
        *out = ThemeRole::GfxDemo;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "taskmanager"))
    {
        *out = ThemeRole::TaskManager;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "logview"))
    {
        *out = ThemeRole::LogView;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "imageview") || StrEqualCaseInsensitive(s, "imageviewer"))
    {
        *out = ThemeRole::ImageView;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "about") || StrEqualCaseInsensitive(s, "sysinfo"))
    {
        *out = ThemeRole::About;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "help") || StrEqualCaseInsensitive(s, "shortcuts"))
    {
        *out = ThemeRole::Help;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "browser") || StrEqualCaseInsensitive(s, "web"))
    {
        *out = ThemeRole::Browser;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "calendar") || StrEqualCaseInsensitive(s, "cal"))
    {
        *out = ThemeRole::Calendar;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "sysmon") || StrEqualCaseInsensitive(s, "monitor"))
    {
        *out = ThemeRole::Sysmon;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "hex") || StrEqualCaseInsensitive(s, "hexview") ||
        StrEqualCaseInsensitive(s, "hexviewer"))
    {
        *out = ThemeRole::HexView;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "charmap") || StrEqualCaseInsensitive(s, "characters"))
    {
        *out = ThemeRole::CharMap;
        return true;
    }
    if (StrEqualCaseInsensitive(s, "terminal") || StrEqualCaseInsensitive(s, "term") ||
        StrEqualCaseInsensitive(s, "console"))
    {
        *out = ThemeRole::Terminal;
        return true;
    }
    return false;
}

void CopyLabel(char* dst, const char* src)
{
    u32 i = 0;
    while (src[i] != 0 && i < kLabelCap - 1)
    {
        char c = src[i];
        // Upper-case the label so it matches the existing
        // start-menu items' visual style.
        if (c >= 'a' && c <= 'z')
        {
            c = static_cast<char>(c - ('a' - 'A'));
        }
        dst[i] = c;
        ++i;
    }
    dst[i] = 0;
}

struct ParsedManifest
{
    char label[kLabelCap];
    ShortcutKind kind;
    ThemeRole role;      // valid iff kind == Role
    char path[kPathCap]; // valid iff kind == Pe / Elf
};

// Copy a value into a destination buffer, truncating at cap-1 chars
// and NUL-terminating. Caller-owned bounded write.
void CopyTo(char* dst, u32 dst_cap, const char* src)
{
    u32 j = 0;
    while (src[j] != 0 && j < dst_cap - 1)
    {
        dst[j] = src[j];
        ++j;
    }
    dst[j] = 0;
}

// Parse one manifest payload. Recognises:
//   name=<label>
//   target=<role>          (Role kind)
//   kind=pe|elf
//   path=<fat32 path>      (Pe / Elf kinds)
// Returns true if name + (target | (kind + path)) all resolved.
bool ParseManifest(const char* buf, u64 len, ParsedManifest* out)
{
    char name[kLabelCap] = {};
    char target[kLabelCap] = {};
    char kind_str[kLabelCap] = {};
    char path[kPathCap] = {};
    bool have_name = false;
    bool have_target = false;
    bool have_kind = false;
    bool have_path = false;
    char line[160];
    u64 lpos = 0;
    for (u64 i = 0; i <= len; ++i)
    {
        const char c = (i < len) ? buf[i] : '\n';
        if (c == '\n' || c == '\r')
        {
            if (lpos == 0 || line[0] == ';')
            {
                lpos = 0;
                continue;
            }
            line[lpos] = 0;
            u64 eq = 0;
            while (eq < lpos && line[eq] != '=')
            {
                ++eq;
            }
            if (eq < lpos)
            {
                line[eq] = 0;
                const char* k = line;
                const char* val = line + eq + 1;
                if (StrEqualCaseInsensitive(k, "name"))
                {
                    CopyTo(name, kLabelCap, val);
                    have_name = true;
                }
                else if (StrEqualCaseInsensitive(k, "target"))
                {
                    CopyTo(target, kLabelCap, val);
                    have_target = true;
                }
                else if (StrEqualCaseInsensitive(k, "kind"))
                {
                    CopyTo(kind_str, kLabelCap, val);
                    have_kind = true;
                }
                else if (StrEqualCaseInsensitive(k, "path"))
                {
                    CopyTo(path, kPathCap, val);
                    have_path = true;
                }
            }
            lpos = 0;
            continue;
        }
        if (lpos + 1 < sizeof(line))
        {
            line[lpos++] = c;
        }
    }
    if (!have_name)
    {
        return false;
    }
    if (have_kind && have_path)
    {
        if (StrEqualCaseInsensitive(kind_str, "pe"))
            out->kind = ShortcutKind::Pe;
        else if (StrEqualCaseInsensitive(kind_str, "elf"))
            out->kind = ShortcutKind::Elf;
        else
            return false;
        out->role = ThemeRole::Notes; // unused for PE/ELF; sentinel
        CopyTo(out->path, kPathCap, path);
    }
    else if (have_target)
    {
        if (!ResolveTargetName(target, &out->role))
            return false;
        out->kind = ShortcutKind::Role;
        out->path[0] = 0;
    }
    else
    {
        // Neither target= nor (kind=+path=) — manifest is missing
        // its launch directive.
        return false;
    }
    CopyLabel(out->label, name);
    return true;
}

bool EndsWithMnf(const char* name)
{
    u32 n = 0;
    while (name[n] != 0)
    {
        ++n;
    }
    if (n < 4)
    {
        return false;
    }
    return CharEqIgnoreCase(name[n - 4], '.') && CharEqIgnoreCase(name[n - 3], 'M') &&
           CharEqIgnoreCase(name[n - 2], 'N') && CharEqIgnoreCase(name[n - 1], 'F');
}

void ResetSlots()
{
    for (u32 i = 0; i < kStartMenuAppsMax; ++i)
    {
        g_slots[i].used = false;
        g_slots[i].label[0] = 0;
        g_slots[i].path[0] = 0;
        g_slots[i].kind = ShortcutKind::Role;
    }
    g_slot_count = 0;
}

} // namespace

void StartMenuAppsScan()
{
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        return;
    }
    ResetSlots();

    // Ensure /APPS exists. Fat32MkdirAtPath rejects collisions,
    // so check first.
    fat::DirEntry probe;
    if (!fat::Fat32LookupPath(v, kAppsDir, &probe))
    {
        if (!fat::Fat32MkdirAtPath(v, kAppsDir))
        {
            KLOG_WARN("startapps", "mkdir /APPS failed");
            return;
        }
    }

    // Plant the sample manifest if absent so users have a copy-
    // paste template the moment they open the directory.
    if (!fat::Fat32LookupPath(v, kSamplePath, &probe))
    {
        const u32 n = static_cast<u32>(sizeof(kSampleBody) - 1);
        fat::Fat32CreateAtPath(v, kSamplePath, kSampleBody, n);
    }

    // Re-look-up /APPS to get its first cluster, then enumerate.
    if (!fat::Fat32LookupPath(v, kAppsDir, &probe))
    {
        return;
    }
    fat::DirEntry entries[kStartMenuAppsMax + 4];
    const u32 listed =
        fat::Fat32ListDirByCluster(v, probe.first_cluster, entries, sizeof(entries) / sizeof(entries[0]));

    for (u32 i = 0; i < listed && g_slot_count < kStartMenuAppsMax; ++i)
    {
        const fat::DirEntry& e = entries[i];
        if ((e.attributes & 0x10) != 0 || !EndsWithMnf(e.name))
        {
            continue;
        }
        if (e.size_bytes == 0 || e.size_bytes > 256)
        {
            continue;
        }
        char buf[256];
        const i64 n = fat::Fat32ReadAt(v, &e, 0, buf, e.size_bytes);
        if (n <= 0)
        {
            continue;
        }
        ParsedManifest pm{};
        if (!ParseManifest(buf, static_cast<u64>(n), &pm))
        {
            arch::SerialWrite("[startapps] skipping malformed ");
            arch::SerialWrite(e.name);
            arch::SerialWrite("\n");
            continue;
        }
        Slot& s = g_slots[g_slot_count];
        for (u32 j = 0; j < kLabelCap; ++j)
            s.label[j] = pm.label[j];
        s.kind = pm.kind;
        s.role = pm.role;
        for (u32 j = 0; j < kPathCap; ++j)
            s.path[j] = pm.path[j];
        s.used = true;
        ++g_slot_count;
    }

    if (g_slot_count > 0)
    {
        KLOG_INFO("startapps", "scanned /APPS, found shortcuts");
    }
}

void StartMenuAppsAppendTo(MenuItem* items, u32* count, u32 max)
{
    if (items == nullptr || count == nullptr)
    {
        return;
    }
    bool dropped = false;
    for (u32 i = 0; i < g_slot_count; ++i)
    {
        if (!g_slots[i].used)
        {
            continue;
        }
        if (*count >= max)
        {
            dropped = true;
            break;
        }
        items[*count].label = g_slots[i].label;
        items[*count].action_id = kStartMenuAppsActionBase + i;
        ++*count;
    }
    if (dropped)
    {
        KLOG_WARN("startapps", "menu cap reached, some shortcuts dropped");
    }
}

bool StartMenuAppsResolve(u32 action_id, ThemeRole* out)
{
    if (action_id < kStartMenuAppsActionBase || action_id >= kStartMenuAppsActionBase + kStartMenuAppsMax)
    {
        return false;
    }
    const u32 slot = action_id - kStartMenuAppsActionBase;
    if (!g_slots[slot].used || g_slots[slot].kind != ShortcutKind::Role)
    {
        return false;
    }
    if (out != nullptr)
    {
        *out = g_slots[slot].role;
    }
    return true;
}

bool StartMenuAppsResolveLaunch(u32 action_id, ShortcutKind* out_kind, ThemeRole* out_role, const char** out_path)
{
    if (action_id < kStartMenuAppsActionBase || action_id >= kStartMenuAppsActionBase + kStartMenuAppsMax)
    {
        return false;
    }
    const u32 slot = action_id - kStartMenuAppsActionBase;
    if (!g_slots[slot].used)
    {
        return false;
    }
    if (out_kind != nullptr)
        *out_kind = g_slots[slot].kind;
    if (out_role != nullptr)
        *out_role = g_slots[slot].role;
    if (out_path != nullptr)
        *out_path = g_slots[slot].path;
    return true;
}

void StartMenuAppsSelfTest()
{
    namespace fat = fs::fat32;
    using arch::SerialWrite;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[startapps] self-test SKIP: no FAT32 volume\n");
        return;
    }
    constexpr const char kSynth[] = "name=TestApp\ntarget=Calculator\n";
    ParsedManifest pm{};
    const bool role_ok = ParseManifest(kSynth, sizeof(kSynth) - 1, &pm) && pm.kind == ShortcutKind::Role &&
                         pm.role == ThemeRole::Calculator && pm.label[0] == 'T' && pm.label[1] == 'E' &&
                         pm.label[2] == 'S' && pm.label[3] == 'T';
    constexpr const char kPeSynth[] = "name=PeApp\nkind=pe\npath=APPS/FOO.EXE\n";
    ParsedManifest pmpe{};
    const bool pe_ok = ParseManifest(kPeSynth, sizeof(kPeSynth) - 1, &pmpe) && pmpe.kind == ShortcutKind::Pe &&
                       pmpe.path[0] == 'A' && pmpe.path[1] == 'P' && pmpe.path[2] == 'P' && pmpe.path[3] == 'S' &&
                       pmpe.path[4] == '/';
    constexpr const char kBadSynth[] = "name=NoLaunch\n"; // missing both target= and kind=
    ParsedManifest pmbad{};
    const bool reject_ok = !ParseManifest(kBadSynth, sizeof(kBadSynth) - 1, &pmbad);
    if (role_ok && pe_ok && reject_ok)
    {
        SerialWrite("[startapps] self-test OK (role + PE + reject-no-launch round-trip)\n");
    }
    else
    {
        SerialWrite(role_ok ? "[startapps] self-test FAIL (PE or reject branch)\n"
                            : "[startapps] self-test FAIL (role branch)\n");
    }
}

} // namespace duetos::drivers::video
