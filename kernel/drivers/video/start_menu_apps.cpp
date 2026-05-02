#include "drivers/video/start_menu_apps.h"

#include "arch/x86_64/serial.h"
#include "fs/fat32.h"
#include "log/klog.h"

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
constexpr const char kAppsDir[] = "APPS";
constexpr const char kSamplePath[] = "APPS/SAMPLE.MNF";
constexpr const char kSampleBody[] = "; sample shortcut — copy as APPS/<NAME>.MNF\n"
                                     "name=DuetOS Notes\n"
                                     "target=notes\n";

struct Slot
{
    char label[kLabelCap];
    ThemeRole role;
    bool used;
};

constinit Slot g_slots[kStartMenuAppsMax] = {};
constinit u32 g_slot_count = 0;

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

bool StrEqI(const char* a, const char* b)
{
    while (*a != 0 && *b != 0)
    {
        if (!CharEqIgnoreCase(*a, *b))
        {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == 0 && *b == 0;
}

bool ResolveTargetName(const char* s, ThemeRole* out)
{
    if (StrEqI(s, "calculator"))
    {
        *out = ThemeRole::Calculator;
        return true;
    }
    if (StrEqI(s, "notes") || StrEqI(s, "notepad"))
    {
        *out = ThemeRole::Notes;
        return true;
    }
    if (StrEqI(s, "files"))
    {
        *out = ThemeRole::Files;
        return true;
    }
    if (StrEqI(s, "clock"))
    {
        *out = ThemeRole::Clock;
        return true;
    }
    if (StrEqI(s, "settings"))
    {
        *out = ThemeRole::Settings;
        return true;
    }
    if (StrEqI(s, "gfxdemo"))
    {
        *out = ThemeRole::GfxDemo;
        return true;
    }
    if (StrEqI(s, "taskmanager"))
    {
        *out = ThemeRole::TaskManager;
        return true;
    }
    if (StrEqI(s, "logview"))
    {
        *out = ThemeRole::LogView;
        return true;
    }
    if (StrEqI(s, "imageview") || StrEqI(s, "imageviewer"))
    {
        *out = ThemeRole::ImageView;
        return true;
    }
    if (StrEqI(s, "about") || StrEqI(s, "sysinfo"))
    {
        *out = ThemeRole::About;
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

// Parse one manifest payload. Returns true if both name and
// target resolved. `label_out` and `role_out` are populated on
// success; on failure they're untouched.
bool ParseManifest(const char* buf, u64 len, char* label_out, ThemeRole* role_out)
{
    char name[kLabelCap] = {};
    char target[kLabelCap] = {};
    bool have_name = false;
    bool have_target = false;
    char line[96];
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
                if (StrEqI(k, "name"))
                {
                    u32 j = 0;
                    while (val[j] != 0 && j < kLabelCap - 1)
                    {
                        name[j] = val[j];
                        ++j;
                    }
                    name[j] = 0;
                    have_name = true;
                }
                else if (StrEqI(k, "target"))
                {
                    u32 j = 0;
                    while (val[j] != 0 && j < kLabelCap - 1)
                    {
                        target[j] = val[j];
                        ++j;
                    }
                    target[j] = 0;
                    have_target = true;
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
    if (!have_name || !have_target)
    {
        return false;
    }
    if (!ResolveTargetName(target, role_out))
    {
        return false;
    }
    CopyLabel(label_out, name);
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
        Slot& s = g_slots[g_slot_count];
        if (!ParseManifest(buf, static_cast<u64>(n), s.label, &s.role))
        {
            arch::SerialWrite("[startapps] skipping malformed ");
            arch::SerialWrite(e.name);
            arch::SerialWrite("\n");
            continue;
        }
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
    if (!g_slots[slot].used)
    {
        return false;
    }
    if (out != nullptr)
    {
        *out = g_slots[slot].role;
    }
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
    char label[kLabelCap] = {};
    ThemeRole role = ThemeRole::Notes;
    const bool ok = ParseManifest(kSynth, sizeof(kSynth) - 1, label, &role) && role == ThemeRole::Calculator &&
                    label[0] == 'T' && label[1] == 'E' && label[2] == 'S' && label[3] == 'T';
    SerialWrite(ok ? "[startapps] self-test OK (manifest parser round-trip)\n" : "[startapps] self-test FAILED\n");
}

} // namespace duetos::drivers::video
