#include "apps/files.h"

#include "apps/imageview.h"
#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"
#include "fs/fat32.h"
#include "fs/ramfs.h"

namespace duetos::apps::files
{

namespace
{

constexpr u32 kMaxDepth = 8;
constexpr u32 kFatMax = 64;
constexpr u32 kGlyphW = 8;
constexpr u32 kRowH = 10;
constexpr u32 kInkFg = 0x00D0D8E0;
constexpr u32 kInkDim = 0x00707880;
constexpr u32 kInkSel = 0x00101020;
constexpr u32 kBg = 0x00101828;
constexpr u32 kSelBg = 0x00C0C888;

enum class Mode : u8
{
    Ramfs = 0,
    Fat32 = 1,
};

struct State
{
    duetos::drivers::video::WindowHandle handle;
    Mode mode;

    // Ramfs view: stack of directory nodes from root down to the
    // current view. ramfs_depth == 1 at init (just the trusted root).
    const duetos::fs::RamfsNode* ramfs_stack[kMaxDepth];
    u32 ramfs_depth;
    u32 ramfs_selection;

    // Fat32 view (root only in v0). entries cached on entry to
    // disk mode; refreshed via 'r' / on every mode toggle so newly
    // written files (e.g. a fresh screenshot) appear without
    // reboot.
    duetos::fs::fat32::DirEntry fat_entries[kFatMax];
    u32 fat_count;
    u32 fat_selection;
};

constinit State g_state = {duetos::drivers::video::kWindowInvalid, Mode::Ramfs, {}, 0, 0, {}, 0, 0};

u32 CountChildren(const duetos::fs::RamfsNode* dir)
{
    if (dir == nullptr || dir->children == nullptr)
        return 0;
    u32 n = 0;
    while (dir->children[n] != nullptr)
        ++n;
    return n;
}

const duetos::fs::RamfsNode* RamfsCur()
{
    if (g_state.ramfs_depth == 0)
        return nullptr;
    return g_state.ramfs_stack[g_state.ramfs_depth - 1];
}

void RescanFat32()
{
    namespace fat = fs::fat32;
    g_state.fat_count = 0;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return;
    fat::DirEntry tmp[fat::kMaxDirEntries];
    const u32 n = fat::Fat32ListDirByCluster(v, v->root_cluster, tmp, fat::kMaxDirEntries);
    for (u32 i = 0; i < n && g_state.fat_count < kFatMax; ++i)
    {
        g_state.fat_entries[g_state.fat_count++] = tmp[i];
    }
}

u32 ModeCount()
{
    if (g_state.mode == Mode::Fat32)
        return g_state.fat_count;
    return CountChildren(RamfsCur());
}

u32 ModeSelection()
{
    return (g_state.mode == Mode::Fat32) ? g_state.fat_selection : g_state.ramfs_selection;
}

void ModeSelectionSet(u32 v)
{
    if (g_state.mode == Mode::Fat32)
        g_state.fat_selection = v;
    else
        g_state.ramfs_selection = v;
}

bool EndsWithCi(const char* name, const char* ext)
{
    auto up = [](char c) { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - ('a' - 'A')) : c; };
    u32 nlen = 0;
    while (name[nlen] != '\0')
        ++nlen;
    u32 elen = 0;
    while (ext[elen] != '\0')
        ++elen;
    if (nlen < elen)
        return false;
    for (u32 i = 0; i < elen; ++i)
    {
        if (up(name[nlen - elen + i]) != up(ext[i]))
            return false;
    }
    return true;
}

void WriteU64Dec(char* dst, u32 cap, u64 v)
{
    if (cap < 2)
    {
        if (cap == 1)
            dst[0] = '\0';
        return;
    }
    char tmp[24];
    u32 n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    else
    {
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    }
    if (n > cap - 1)
        n = cap - 1;
    for (u32 i = 0; i < n; ++i)
        dst[i] = tmp[n - 1 - i];
    dst[n] = '\0';
}

// Generic row painter — takes the type tag, name, and size; the
// per-mode draw paths assemble these from their entry types.
void DrawRowGeneric(u32 x, u32 y, u32 w, bool is_dir, const char* name, u64 size_bytes, bool selected)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    if (selected)
        FramebufferFillRect(x, y, w, kRowH, kSelBg);
    else
        FramebufferFillRect(x, y, w, kRowH, kBg);
    const u32 fg = selected ? kInkSel : kInkFg;
    const u32 bg = selected ? kSelBg : kBg;
    const char* tag = is_dir ? "[D] " : "[F] ";
    FramebufferDrawString(x + 4, y + 1, tag, fg, bg);
    const char* dn = (name != nullptr && name[0] != '\0') ? name : "(root)";
    FramebufferDrawString(x + 4 + 4 * kGlyphW, y + 1, dn, fg, bg);
    if (!is_dir)
    {
        char num[24];
        WriteU64Dec(num, sizeof(num), size_bytes);
        u32 len = 0;
        while (num[len] != '\0')
            ++len;
        const u32 bytes_len = 6;
        const u32 right = x + w - 4;
        if (right > (len + bytes_len) * kGlyphW + 8)
        {
            const u32 nx = right - (len + bytes_len) * kGlyphW;
            FramebufferDrawString(nx, y + 1, num, fg, bg);
            FramebufferDrawString(nx + len * kGlyphW, y + 1, " BYTES", selected ? kInkSel : kInkDim, bg);
        }
    }
}

void DrawRamfs(u32 cx, u32 cy, u32 cw, u32 ch)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);
    const duetos::fs::RamfsNode* cur = RamfsCur();
    if (cur == nullptr)
    {
        FramebufferDrawString(cx + 4, cy + 4, "(no root)", kInkDim, kBg);
        return;
    }

    char header[40];
    u32 h_off = 0;
    const char* prefix = "RAM:/";
    for (u32 i = 0; prefix[i] != '\0' && h_off + 1 < sizeof(header); ++i)
        header[h_off++] = prefix[i];
    if (g_state.ramfs_depth > 1)
    {
        for (u32 i = 1; i < g_state.ramfs_depth; ++i)
        {
            const char* nm = g_state.ramfs_stack[i]->name;
            if (nm == nullptr)
                continue;
            for (u32 j = 0; nm[j] != '\0' && h_off + 1 < sizeof(header); ++j)
                header[h_off++] = nm[j];
            if (h_off + 1 < sizeof(header))
                header[h_off++] = '/';
        }
    }
    header[h_off] = '\0';
    FramebufferDrawString(cx + 4, cy + 2, header, 0x0080F088, kBg);

    const u32 list_top = cy + 2 + kRowH + 2;
    const u32 n = CountChildren(cur);
    const u32 max_rows = (ch > (list_top - cy) + kRowH) ? (ch - (list_top - cy)) / kRowH : 0;
    u32 first = 0;
    if (n > max_rows && g_state.ramfs_selection >= max_rows)
        first = g_state.ramfs_selection - (max_rows - 1);
    for (u32 i = 0; i < max_rows && first + i < n; ++i)
    {
        const u32 idx = first + i;
        const duetos::fs::RamfsNode* child = cur->children[idx];
        if (child == nullptr)
            break;
        const bool is_dir = (child->type == duetos::fs::RamfsNodeType::kDir);
        DrawRowGeneric(cx, list_top + i * kRowH, cw, is_dir, child->name, is_dir ? 0 : child->file_size,
                       idx == g_state.ramfs_selection);
    }
    if (ch > kRowH + 2)
    {
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "UP/DN ENTER:OPEN B:BACK D:DISK", kInkDim, kBg);
    }
}

void DrawFat32(u32 cx, u32 cy, u32 cw, u32 ch)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    char header[40];
    u32 h_off = 0;
    const char* prefix = "DISK:/";
    for (u32 i = 0; prefix[i] != '\0' && h_off + 1 < sizeof(header); ++i)
        header[h_off++] = prefix[i];
    header[h_off] = '\0';
    FramebufferDrawString(cx + 4, cy + 2, header, 0x0080F088, kBg);

    if (g_state.fat_count == 0)
    {
        FramebufferDrawString(cx + 4, cy + 2 + kRowH + 4, "(no FAT32 volume mounted)", kInkDim, kBg);
        if (ch > kRowH + 2)
        {
            FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "M:RAM  R:RESCAN", kInkDim, kBg);
        }
        return;
    }

    const u32 list_top = cy + 2 + kRowH + 2;
    const u32 n = g_state.fat_count;
    const u32 max_rows = (ch > (list_top - cy) + kRowH) ? (ch - (list_top - cy)) / kRowH : 0;
    u32 first = 0;
    if (n > max_rows && g_state.fat_selection >= max_rows)
        first = g_state.fat_selection - (max_rows - 1);
    for (u32 i = 0; i < max_rows && first + i < n; ++i)
    {
        const u32 idx = first + i;
        const auto& e = g_state.fat_entries[idx];
        const bool is_dir = (e.attributes & 0x10) != 0;
        DrawRowGeneric(cx, list_top + i * kRowH, cw, is_dir, e.name, e.size_bytes, idx == g_state.fat_selection);
    }
    if (ch > kRowH + 2)
    {
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "UP/DN ENTER:OPEN R:RESCAN M:RAM", kInkDim, kBg);
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    if (g_state.mode == Mode::Fat32)
        DrawFat32(cx, cy, cw, ch);
    else
        DrawRamfs(cx, cy, cw, ch);
}

bool OpenFat32Selected()
{
    if (g_state.fat_selection >= g_state.fat_count)
        return false;
    const auto& e = g_state.fat_entries[g_state.fat_selection];
    if ((e.attributes & 0x10) != 0)
    {
        // v0: no FAT32 directory descent. Log + notify.
        duetos::arch::SerialWrite("[files] (fat32 dir descent not supported in v0): ");
        duetos::arch::SerialWrite(e.name);
        duetos::arch::SerialWrite("\n");
        duetos::drivers::video::NotifyShow("subdir descent not in v0");
        return true;
    }
    if (EndsWithCi(e.name, ".BMP"))
    {
        if (duetos::apps::imageview::ImageViewSelectByName(e.name))
        {
            const duetos::drivers::video::WindowHandle iv =
                duetos::drivers::video::ThemeRoleWindow(duetos::drivers::video::ThemeRole::ImageView);
            if (iv != duetos::drivers::video::kWindowInvalid)
            {
                duetos::drivers::video::WindowRaise(iv);
            }
            duetos::drivers::video::NotifyShow("opened in image viewer");
            duetos::arch::SerialWrite("[files] open BMP -> ImageView: ");
            duetos::arch::SerialWrite(e.name);
            duetos::arch::SerialWrite("\n");
        }
        return true;
    }
    duetos::arch::SerialWrite("[files] open file (no handler): ");
    duetos::arch::SerialWrite(e.name);
    duetos::arch::SerialWrite("\n");
    return true;
}

} // namespace

void FilesInit(duetos::drivers::video::WindowHandle handle)
{
    g_state.handle = handle;
    g_state.mode = Mode::Ramfs;
    g_state.ramfs_depth = 0;
    g_state.ramfs_selection = 0;
    g_state.fat_count = 0;
    g_state.fat_selection = 0;
    const duetos::fs::RamfsNode* root = duetos::fs::RamfsTrustedRoot();
    if (root != nullptr)
    {
        g_state.ramfs_stack[0] = root;
        g_state.ramfs_depth = 1;
    }
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
}

duetos::drivers::video::WindowHandle FilesWindow()
{
    return g_state.handle;
}

bool FilesFeedArrow(bool up)
{
    const u32 n = ModeCount();
    if (n == 0)
        return true;
    u32 sel = ModeSelection();
    if (up)
    {
        if (sel > 0)
            ModeSelectionSet(sel - 1);
    }
    else
    {
        if (sel + 1 < n)
            ModeSelectionSet(sel + 1);
    }
    return true;
}

bool FilesFeedChar(char c)
{
    if (c == 'j' || c == 'J')
        return FilesFeedArrow(false);
    if (c == 'k' || c == 'K')
        return FilesFeedArrow(true);
    if (c == 'd' || c == 'D')
    {
        if (g_state.mode != Mode::Fat32)
        {
            g_state.mode = Mode::Fat32;
            g_state.fat_selection = 0;
            RescanFat32();
            duetos::drivers::video::NotifyShow("files: disk view");
        }
        return true;
    }
    if (c == 'm' || c == 'M')
    {
        if (g_state.mode != Mode::Ramfs)
        {
            g_state.mode = Mode::Ramfs;
            duetos::drivers::video::NotifyShow("files: ram view");
        }
        return true;
    }
    if (c == 'r' || c == 'R')
    {
        if (g_state.mode == Mode::Fat32)
        {
            const u32 prev_sel = g_state.fat_selection;
            RescanFat32();
            if (prev_sel >= g_state.fat_count)
            {
                g_state.fat_selection = (g_state.fat_count > 0) ? (g_state.fat_count - 1) : 0;
            }
            else
            {
                g_state.fat_selection = prev_sel;
            }
            duetos::drivers::video::NotifyShow("files: rescan");
            return true;
        }
        return false;
    }
    if (c == 'b' || c == 'B' || static_cast<u8>(c) == 0x08) // Back / Backspace
    {
        if (g_state.mode == Mode::Ramfs)
        {
            if (g_state.ramfs_depth > 1)
            {
                --g_state.ramfs_depth;
                g_state.ramfs_selection = 0;
            }
            return true;
        }
        // Fat32 mode: Back is a no-op in v0 (root only).
        return true;
    }
    if (static_cast<u8>(c) == 0x0A) // Enter
    {
        if (g_state.mode == Mode::Ramfs)
        {
            const duetos::fs::RamfsNode* cur = RamfsCur();
            if (cur == nullptr || cur->children == nullptr)
                return true;
            if (g_state.ramfs_selection >= CountChildren(cur))
                return true;
            const duetos::fs::RamfsNode* sel = cur->children[g_state.ramfs_selection];
            if (sel == nullptr)
                return true;
            if (sel->type == duetos::fs::RamfsNodeType::kDir)
            {
                if (g_state.ramfs_depth < kMaxDepth)
                {
                    g_state.ramfs_stack[g_state.ramfs_depth++] = sel;
                    g_state.ramfs_selection = 0;
                }
            }
            else
            {
                duetos::arch::SerialWrite("[files] open file name=");
                duetos::arch::SerialWrite(sel->name ? sel->name : "(unnamed)");
                duetos::arch::SerialWrite("\n");
            }
            return true;
        }
        // Fat32 mode.
        return OpenFat32Selected();
    }
    return false;
}

void FilesSelfTest()
{
    using duetos::arch::SerialWrite;
    const duetos::fs::RamfsNode* root = duetos::fs::RamfsTrustedRoot();
    const u32 root_n = CountChildren(root);
    bool pass = (root != nullptr && root_n > 0);
    const u32 saved_depth = g_state.ramfs_depth;
    const u32 saved_sel = g_state.ramfs_selection;
    const Mode saved_mode = g_state.mode;
    const duetos::fs::RamfsNode* saved_top = RamfsCur();
    if (pass)
    {
        for (u32 i = 0; i < root_n; ++i)
        {
            if (root->children[i]->type == duetos::fs::RamfsNodeType::kDir)
            {
                g_state.ramfs_selection = i;
                FilesFeedChar('\n'); // Enter -> descend
                if (g_state.ramfs_depth != saved_depth + 1 || RamfsCur() != root->children[i])
                    pass = false;
                FilesFeedChar('b'); // Back -> pop
                if (g_state.ramfs_depth != saved_depth || RamfsCur() != saved_top)
                    pass = false;
                break;
            }
        }
    }

    // Mode toggle round-trip. Disk mode is reachable iff a FAT32
    // volume is mounted; either way, switching back to ram mode
    // must succeed.
    FilesFeedChar('d');
    if (g_state.mode != Mode::Fat32)
        pass = false;
    FilesFeedChar('m');
    if (g_state.mode != Mode::Ramfs)
        pass = false;

    // Extension-match helper sanity (used by Files->ImageView dispatch).
    if (!EndsWithCi("SHOT0001.BMP", ".bmp"))
        pass = false;
    if (!EndsWithCi("readme.BMP", ".bmp"))
        pass = false;
    if (EndsWithCi("notes.txt", ".bmp"))
        pass = false;

    g_state.ramfs_depth = saved_depth;
    g_state.ramfs_selection = saved_sel;
    g_state.mode = saved_mode;
    SerialWrite(pass ? "[files] self-test OK (ramfs descend+back, mode toggle, ext match)\n"
                     : "[files] self-test FAILED\n");
}

} // namespace duetos::apps::files
