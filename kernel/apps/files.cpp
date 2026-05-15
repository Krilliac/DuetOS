#include "apps/files.h"

#include "apps/imageview.h"
#include "apps/notes.h"
#include "apps/trash.h"
#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/cursor.h"
#include "drivers/video/dialog.h"
#include "drivers/video/dnd.h"
#include "drivers/video/menu.h"
#include "drivers/video/notify.h"
#include "drivers/video/scrollbar.h"
#include "drivers/video/sound_cue.h"
#include "drivers/video/theme.h"
#include "fs/duetfs.h"
#include "fs/fat32.h"
#include "fs/ramfs.h"
#include "mm/address_space.h"
#include "mm/kheap.h"
#include "proc/process.h"
#include "proc/spawn.h"

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
    Trash = 2,
    DuetFs = 3, // the native DuetFS "main drive", browsable + nested
};

// Pending two-step prompt. The X-then-Y convention generalises
// across "delete" (in disk view), "permanent delete" (in trash
// view), and "empty trash". Each arms a different verb on the
// same state slot.
enum class Pending : u8
{
    None = 0,
    DeleteToTrash = 1,       // disk: X arms; Y -> TrashMove
    PermDeleteFromTrash = 2, // trash: X arms; Y -> TrashPermDelete
    EmptyTrash = 3,          // trash: E arms; Y -> TrashEmpty
};

// Sort orders for the FAT32 + Trash listings. Cycled with 's' /
// 'S'. Default Name (case-insensitive ascending) matches what
// every commodity file manager opens with.
enum class SortMode : u8
{
    Name = 0,
    Size = 1,
    Type = 2, // dirs first, then files; alphabetical within each
    kCount = 3,
};

const char* SortModeName(SortMode m)
{
    switch (m)
    {
    case SortMode::Name:
        return "name";
    case SortMode::Size:
        return "size";
    case SortMode::Type:
        return "type";
    default:
        return "?";
    }
}

struct State
{
    duetos::drivers::video::WindowHandle handle;
    Mode mode;
    SortMode sort;

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

    // Trash view — same shape as the Fat32 view but populated
    // from /TRASH instead of root. Separate selection so a
    // T-toggle round-trip preserves where the user was.
    duetos::fs::fat32::DirEntry trash_entries[kFatMax];
    u32 trash_count;
    u32 trash_selection;

    // DuetFS "main drive" view — a node-id navigation stack
    // mirroring the ramfs view, populated through the
    // duetfs_readdir FFI. duet_depth == 0 until the view is first
    // entered, then >= 1 (stack[0] = root). duet_names carries the
    // breadcrumb component per level for the header path.
    duetos::fs::duetfs::DirEntry duet_entries[kFatMax];
    u32 duet_count;
    u32 duet_selection;
    u32 duet_stack[kMaxDepth];
    char duet_names[kMaxDepth][64];
    u32 duet_depth;

    // Pending two-step prompt. `pending_idx` records the row the
    // arm targeted so a subsequent navigate / mode-switch can
    // disarm cleanly.
    Pending pending;
    u32 pending_idx;
};

constinit State g_state = {duetos::drivers::video::kWindowInvalid,
                           Mode::Ramfs,
                           SortMode::Name,
                           {},
                           0,
                           0,
                           {},
                           0,
                           0,
                           {},
                           0,
                           0,
                           {},
                           0,
                           0,
                           {},
                           {},
                           0,
                           Pending::None,
                           0};

// Case-insensitive ASCII strcmp used by the Name + Type sort
// comparators. Returns the standard <0 / 0 / >0 trichotomy.
int FilesNameCmpCi(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0')
    {
        char ca = *a;
        char cb = *b;
        if (ca >= 'a' && ca <= 'z')
            ca = static_cast<char>(ca - 32);
        if (cb >= 'a' && cb <= 'z')
            cb = static_cast<char>(cb - 32);
        if (ca != cb)
            return static_cast<int>(static_cast<unsigned char>(ca)) - static_cast<int>(static_cast<unsigned char>(cb));
        ++a;
        ++b;
    }
    if (*a == *b)
        return 0;
    return *a == '\0' ? -1 : 1;
}

bool FilesEntryLess(const duetos::fs::fat32::DirEntry& a, const duetos::fs::fat32::DirEntry& b, SortMode m)
{
    const bool a_dir = (a.attributes & 0x10) != 0;
    const bool b_dir = (b.attributes & 0x10) != 0;
    switch (m)
    {
    case SortMode::Name:
        return FilesNameCmpCi(a.name, b.name) < 0;
    case SortMode::Size:
        if (a.size_bytes != b.size_bytes)
            return a.size_bytes < b.size_bytes;
        return FilesNameCmpCi(a.name, b.name) < 0;
    case SortMode::Type:
        if (a_dir != b_dir)
            return a_dir; // dirs first
        return FilesNameCmpCi(a.name, b.name) < 0;
    default:
        return FilesNameCmpCi(a.name, b.name) < 0;
    }
}

// Insertion sort over the entries array. Both fat_entries and
// trash_entries cap at kFatMax = 64; insertion sort is O(n^2)
// worst case but trivially correct, allocator-free, and fast on
// already-sorted-or-near input (which dominates after a rescan
// followed by a sort-mode toggle).
void SortFat32Array(duetos::fs::fat32::DirEntry* arr, u32 count, SortMode m)
{
    for (u32 i = 1; i < count; ++i)
    {
        duetos::fs::fat32::DirEntry tmp = arr[i];
        u32 j = i;
        while (j > 0 && FilesEntryLess(tmp, arr[j - 1], m))
        {
            arr[j] = arr[j - 1];
            --j;
        }
        arr[j] = tmp;
    }
}

void SortFat32Entries()
{
    SortFat32Array(g_state.fat_entries, g_state.fat_count, g_state.sort);
}

void SortTrashEntries()
{
    SortFat32Array(g_state.trash_entries, g_state.trash_count, g_state.sort);
}

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
        // Hide the TRASH directory from the Fat32 view — users
        // reach it through the T-toggle, and showing it here
        // would let them descend into the bin via Enter (which
        // v0 doesn't support for any subdir).
        const auto& e = tmp[i];
        if ((e.attributes & 0x10) != 0)
        {
            const char* name = e.name;
            if (name[0] == 'T' && name[1] == 'R' && name[2] == 'A' && name[3] == 'S' && name[4] == 'H' &&
                name[5] == '\0')
                continue;
        }
        g_state.fat_entries[g_state.fat_count++] = e;
    }
    SortFat32Entries();
}

void RescanTrash()
{
    namespace fat = fs::fat32;
    g_state.trash_count = 0;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return;
    g_state.trash_count = duetos::apps::trash::TrashList(v, g_state.trash_entries, kFatMax);
    SortTrashEntries();
}

// Page the current DuetFS directory (the node on top of the
// navigation stack) into the entry cache via duetfs_readdir. The
// boot DuetFS volume is mounted at /duetfs; we talk to it through
// its boot block handle so the view tracks the same bytes the
// shell's `ls /duetfs` sees.
void RescanDuetFs()
{
    namespace df = duetos::fs::duetfs;
    g_state.duet_count = 0;
    if (g_state.duet_depth == 0)
    {
        g_state.duet_stack[0] = df::kRootNodeId;
        g_state.duet_names[0][0] = '\0';
        g_state.duet_depth = 1;
    }
    const df::Device dev = df::DeviceForMountHandle(df::BootHandle());
    const u32 node = g_state.duet_stack[g_state.duet_depth - 1];
    u32 start = 0;
    for (;;)
    {
        df::DirEntry batch[16];
        duetos::usize got = 0;
        if (df::duetfs_readdir(&dev, node, start, batch, sizeof(batch) / sizeof(batch[0]), &got) != df::kStatusOk)
            break;
        if (got == 0)
            break;
        for (duetos::usize i = 0; i < got && g_state.duet_count < kFatMax; ++i)
            g_state.duet_entries[g_state.duet_count++] = batch[i];
        start += static_cast<u32>(got);
    }
}

u32 ModeCount()
{
    if (g_state.mode == Mode::Fat32)
        return g_state.fat_count;
    if (g_state.mode == Mode::Trash)
        return g_state.trash_count;
    if (g_state.mode == Mode::DuetFs)
        return g_state.duet_count;
    return CountChildren(RamfsCur());
}

u32 ModeSelection()
{
    if (g_state.mode == Mode::Fat32)
        return g_state.fat_selection;
    if (g_state.mode == Mode::Trash)
        return g_state.trash_selection;
    if (g_state.mode == Mode::DuetFs)
        return g_state.duet_selection;
    return g_state.ramfs_selection;
}

void ModeSelectionSet(u32 v)
{
    if (g_state.mode == Mode::Fat32)
        g_state.fat_selection = v;
    else if (g_state.mode == Mode::Trash)
        g_state.trash_selection = v;
    else if (g_state.mode == Mode::DuetFs)
        g_state.duet_selection = v;
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
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "UP/DN ENTER:OPEN B:BACK D:DISK F:DRIVE", kInkDim, kBg);
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
    const u32 list_w =
        (cw > duetos::drivers::video::kScrollbarWidth + 2) ? cw - duetos::drivers::video::kScrollbarWidth - 2 : cw;
    for (u32 i = 0; i < max_rows && first + i < n; ++i)
    {
        const u32 idx = first + i;
        const auto& e = g_state.fat_entries[idx];
        const bool is_dir = (e.attributes & 0x10) != 0;
        DrawRowGeneric(cx, list_top + i * kRowH, list_w, is_dir, e.name, e.size_bytes, idx == g_state.fat_selection);
    }
    // Scrollbar at the right edge of the row area.
    if (max_rows > 0 && cw > duetos::drivers::video::kScrollbarWidth)
    {
        const duetos::u32 sb_x = cx + cw - duetos::drivers::video::kScrollbarWidth;
        const duetos::u32 sb_y = list_top;
        const duetos::u32 sb_w = duetos::drivers::video::kScrollbarWidth;
        const duetos::u32 sb_h = max_rows * kRowH;
        duetos::drivers::video::ScrollbarPaint(sb_x, sb_y, sb_w, sb_h, {n, max_rows, first});
        // Register the bar with the kernel so the mouse loop
        // can hit-test against it for click-on-track and
        // drag-the-thumb without re-deriving the geometry.
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = true;
        s.x = sb_x;
        s.y = sb_y;
        s.w = sb_w;
        s.h = sb_h;
        s.total = n;
        s.visible = max_rows;
        s.first = first;
        duetos::drivers::video::WindowSetScrollbar(g_state.handle, s);
    }
    else
    {
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = false;
        duetos::drivers::video::WindowSetScrollbar(g_state.handle, s);
    }
    // Delete-to-trash prompt overlays the footer row when armed.
    // Painted in red ink so a confirmation step is visually
    // unmistakable.
    if (g_state.pending == Pending::DeleteToTrash && g_state.pending_idx < g_state.fat_count && ch > kRowH + 2)
    {
        const auto& e = g_state.fat_entries[g_state.pending_idx];
        char prompt[80];
        u32 p = 0;
        const char* lead = "TO TRASH: ";
        for (u32 i = 0; lead[i] != '\0' && p + 1 < sizeof(prompt); ++i)
            prompt[p++] = lead[i];
        for (u32 i = 0; e.name[i] != '\0' && p + 1 < sizeof(prompt); ++i)
            prompt[p++] = e.name[i];
        const char* tail = " ? Y:CONFIRM ANY:CANCEL";
        for (u32 i = 0; tail[i] != '\0' && p + 1 < sizeof(prompt); ++i)
            prompt[p++] = tail[i];
        prompt[p] = '\0';
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, prompt, 0x00FF8080, kBg);
    }
    else if (ch > kRowH + 2)
    {
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "ENTER:OPEN R:RESCAN X:TRASH T:TRASH M:RAM F:DRIVE", kInkDim,
                              kBg);
    }
}

void DrawTrash(u32 cx, u32 cy, u32 cw, u32 ch)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);
    FramebufferDrawString(cx + 4, cy + 2, "TRASH:/", 0x00FFA060, kBg);

    if (g_state.trash_count == 0)
    {
        FramebufferDrawString(cx + 4, cy + 2 + kRowH + 4, "(trash is empty)", kInkDim, kBg);
        if (ch > kRowH + 2)
        {
            FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "D:DISK  M:RAM", kInkDim, kBg);
        }
        return;
    }

    const u32 list_top = cy + 2 + kRowH + 2;
    const u32 n = g_state.trash_count;
    const u32 max_rows = (ch > (list_top - cy) + kRowH) ? (ch - (list_top - cy)) / kRowH : 0;
    u32 first = 0;
    if (n > max_rows && g_state.trash_selection >= max_rows)
        first = g_state.trash_selection - (max_rows - 1);
    for (u32 i = 0; i < max_rows && first + i < n; ++i)
    {
        const u32 idx = first + i;
        const auto& e = g_state.trash_entries[idx];
        DrawRowGeneric(cx, list_top + i * kRowH, cw, false, e.name, e.size_bytes, idx == g_state.trash_selection);
    }

    // Two distinct prompts share the footer slot: per-item
    // permanent delete vs whole-bin empty. Paint the right one
    // for the active arm.
    if (g_state.pending == Pending::PermDeleteFromTrash && g_state.pending_idx < g_state.trash_count && ch > kRowH + 2)
    {
        const auto& e = g_state.trash_entries[g_state.pending_idx];
        char prompt[96];
        u32 p = 0;
        const char* lead = "PERM-DELETE ";
        for (u32 i = 0; lead[i] != '\0' && p + 1 < sizeof(prompt); ++i)
            prompt[p++] = lead[i];
        for (u32 i = 0; e.name[i] != '\0' && p + 1 < sizeof(prompt); ++i)
            prompt[p++] = e.name[i];
        const char* tail = " ? Y:CONFIRM ANY:CANCEL";
        for (u32 i = 0; tail[i] != '\0' && p + 1 < sizeof(prompt); ++i)
            prompt[p++] = tail[i];
        prompt[p] = '\0';
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, prompt, 0x00FF6060, kBg);
    }
    else if (g_state.pending == Pending::EmptyTrash && ch > kRowH + 2)
    {
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "EMPTY ALL? Y:CONFIRM ANY:CANCEL", 0x00FF6060, kBg);
    }
    else if (ch > kRowH + 2)
    {
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "R:RESTORE  X:PERM-DEL  E:EMPTY  D:DISK  M:RAM", kInkDim,
                              kBg);
    }
}

void DrawDuetFs(u32 cx, u32 cy, u32 cw, u32 ch)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    // Header breadcrumb: "DRIVE:/a/b/" from the name stack.
    char header[80];
    u32 h = 0;
    const char* prefix = "DRIVE:/";
    for (u32 i = 0; prefix[i] != '\0' && h + 1 < sizeof(header); ++i)
        header[h++] = prefix[i];
    for (u32 d = 1; d < g_state.duet_depth && h + 1 < sizeof(header); ++d)
    {
        for (u32 i = 0; g_state.duet_names[d][i] != '\0' && h + 1 < sizeof(header); ++i)
            header[h++] = g_state.duet_names[d][i];
        if (h + 1 < sizeof(header))
            header[h++] = '/';
    }
    header[h] = '\0';
    FramebufferDrawString(cx + 4, cy + 2, header, 0x0080F088, kBg);

    if (g_state.duet_count == 0)
    {
        FramebufferDrawString(cx + 4, cy + 2 + kRowH + 4, "(empty directory)", kInkDim, kBg);
        if (ch > kRowH + 2)
            FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "B:BACK  M:RAM  D:DISK", kInkDim, kBg);
        return;
    }

    const u32 list_top = cy + 2 + kRowH + 2;
    const u32 n = g_state.duet_count;
    const u32 max_rows = (ch > (list_top - cy) + kRowH) ? (ch - (list_top - cy)) / kRowH : 0;
    u32 first = 0;
    if (n > max_rows && g_state.duet_selection >= max_rows)
        first = g_state.duet_selection - (max_rows - 1);
    const u32 list_w =
        (cw > duetos::drivers::video::kScrollbarWidth + 2) ? cw - duetos::drivers::video::kScrollbarWidth - 2 : cw;
    for (u32 i = 0; i < max_rows && first + i < n; ++i)
    {
        const u32 idx = first + i;
        const auto& e = g_state.duet_entries[idx];
        const bool is_dir = e.kind == duetos::fs::duetfs::kKindDir;
        char nm[65];
        const u32 nl = e.name_len < 64 ? e.name_len : 64;
        for (u32 k = 0; k < nl; ++k)
            nm[k] = static_cast<char>(e.name[k]);
        nm[nl] = '\0';
        DrawRowGeneric(cx, list_top + i * kRowH, list_w, is_dir, nm, e.size_bytes, idx == g_state.duet_selection);
    }
    if (max_rows > 0 && cw > duetos::drivers::video::kScrollbarWidth)
    {
        const duetos::u32 sb_x = cx + cw - duetos::drivers::video::kScrollbarWidth;
        const duetos::u32 sb_y = list_top;
        const duetos::u32 sb_w = duetos::drivers::video::kScrollbarWidth;
        const duetos::u32 sb_h = max_rows * kRowH;
        duetos::drivers::video::ScrollbarPaint(sb_x, sb_y, sb_w, sb_h, {n, max_rows, first});
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = true;
        s.x = sb_x;
        s.y = sb_y;
        s.w = sb_w;
        s.h = sb_h;
        s.total = n;
        s.visible = max_rows;
        s.first = first;
        duetos::drivers::video::WindowSetScrollbar(g_state.handle, s);
    }
    else
    {
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = false;
        duetos::drivers::video::WindowSetScrollbar(g_state.handle, s);
    }
    if (ch > kRowH + 2)
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "UP/DN ENTER:OPEN B:BACK M:RAM D:DISK", kInkDim, kBg);
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    if (g_state.mode == Mode::Fat32)
        DrawFat32(cx, cy, cw, ch);
    else if (g_state.mode == Mode::Trash)
        DrawTrash(cx, cy, cw, ch);
    else if (g_state.mode == Mode::DuetFs)
        DrawDuetFs(cx, cy, cw, ch);
    else
        DrawRamfs(cx, cy, cw, ch);
}

// Spawn a PE / ELF directly from a ramfs node's embedded bytes.
// Returns true if the file was an executable and a spawn was
// attempted (regardless of whether the spawn ultimately
// succeeded — caller doesn't need to retry).
bool MaybeLaunchRamfsExe(const duetos::fs::RamfsNode* sel)
{
    if (sel == nullptr || sel->name == nullptr || sel->file_bytes == nullptr || sel->file_size == 0)
        return false;
    const bool is_exe = EndsWithCi(sel->name, ".exe");
    const bool is_elf = EndsWithCi(sel->name, ".elf");
    if (!is_exe && !is_elf)
        return false;
    char tag[40];
    duetos::u32 ti = 0;
    const char* prefix = "ramfs-launch:";
    while (prefix[ti] != '\0' && ti < sizeof(tag) - 1)
    {
        tag[ti] = prefix[ti];
        ++ti;
    }
    duetos::u32 ni = 0;
    while (sel->name[ni] != '\0' && ti < sizeof(tag) - 1)
    {
        tag[ti++] = sel->name[ni++];
    }
    tag[ti] = '\0';
    const duetos::u64 pid =
        is_exe ? duetos::core::SpawnPeFile(tag, sel->file_bytes, sel->file_size, duetos::core::CapSetTrusted(),
                                           duetos::fs::RamfsTrustedRoot(), duetos::mm::kFrameBudgetTrusted,
                                           duetos::core::kTickBudgetTrusted)
               : duetos::core::SpawnElfFile(tag, sel->file_bytes, sel->file_size, duetos::core::CapSetTrusted(),
                                            duetos::fs::RamfsTrustedRoot(), duetos::mm::kFrameBudgetTrusted,
                                            duetos::core::kTickBudgetTrusted);
    duetos::arch::SerialWrite("[files] launch ");
    duetos::arch::SerialWrite(is_exe ? "PE" : "ELF");
    duetos::arch::SerialWrite(" name=");
    duetos::arch::SerialWrite(sel->name);
    duetos::arch::SerialWrite(pid != 0 ? " spawn=OK pid=" : " spawn=FAIL");
    if (pid != 0)
    {
        char hex[20];
        duetos::u32 hi = 0;
        for (int i = 60; i >= 0; i -= 4)
        {
            const auto nib = (pid >> i) & 0xF;
            hex[hi++] = static_cast<char>(nib < 10 ? '0' + nib : 'a' + nib - 10);
        }
        hex[hi] = '\0';
        duetos::arch::SerialWrite(hex);
    }
    duetos::arch::SerialWrite("\n");
    duetos::drivers::video::NotifyShow(pid != 0 ? "launched" : "launch failed");
    return true;
}

// FAT32 counterpart: read the selected file into a heap buffer,
// hand it to SpawnPeFile / SpawnElfFile. Same end-to-end shape
// the start-menu launcher already uses (kernel/core/menu_dispatch.cpp).
// Returns true iff the entry was an executable and a spawn was
// attempted.
bool MaybeLaunchFat32Entry(const duetos::fs::fat32::DirEntry& e)
{
    const bool is_exe = EndsWithCi(e.name, ".EXE");
    const bool is_elf = EndsWithCi(e.name, ".ELF");
    if (!is_exe && !is_elf)
        return false;
    constexpr duetos::u64 kMaxLaunchSize = 8 * 1024 * 1024;
    if (e.size_bytes == 0 || e.size_bytes > kMaxLaunchSize)
    {
        duetos::drivers::video::NotifyShow("file too large to launch");
        return true;
    }
    const auto* vol = duetos::fs::fat32::Fat32Volume(0);
    if (vol == nullptr)
    {
        duetos::drivers::video::NotifyShow("no fat32 volume");
        return true;
    }
    auto* staging = static_cast<duetos::u8*>(duetos::mm::KMalloc(e.size_bytes));
    if (staging == nullptr)
    {
        duetos::drivers::video::NotifyShow("OOM staging exe");
        return true;
    }
    const auto got = duetos::fs::fat32::Fat32ReadFile(vol, &e, staging, e.size_bytes);
    if (got != static_cast<duetos::i64>(e.size_bytes))
    {
        duetos::mm::KFree(staging);
        duetos::drivers::video::NotifyShow("read failed");
        return true;
    }
    char tag[40];
    duetos::u32 ti = 0;
    const char* prefix = "fat32-launch:";
    while (prefix[ti] != '\0' && ti < sizeof(tag) - 1)
    {
        tag[ti] = prefix[ti];
        ++ti;
    }
    for (duetos::u32 i = 0; e.name[i] != '\0' && ti < sizeof(tag) - 1; ++i)
        tag[ti++] = e.name[i];
    tag[ti] = '\0';
    const duetos::u64 pid =
        is_exe ? duetos::core::SpawnPeFile(tag, staging, e.size_bytes, duetos::core::CapSetTrusted(),
                                           duetos::fs::RamfsTrustedRoot(), duetos::mm::kFrameBudgetTrusted,
                                           duetos::core::kTickBudgetTrusted)
               : duetos::core::SpawnElfFile(tag, staging, e.size_bytes, duetos::core::CapSetTrusted(),
                                            duetos::fs::RamfsTrustedRoot(), duetos::mm::kFrameBudgetTrusted,
                                            duetos::core::kTickBudgetTrusted);
    // SpawnPeFile/SpawnElfFile copies the bytes into the new
    // process's AS during PeLoad / ElfLoad, so the staging buffer
    // can be freed immediately after the call returns regardless
    // of whether the spawn succeeded.
    duetos::mm::KFree(staging);
    duetos::arch::SerialWrite("[files] launch ");
    duetos::arch::SerialWrite(is_exe ? "PE" : "ELF");
    duetos::arch::SerialWrite(" name=");
    duetos::arch::SerialWrite(e.name);
    duetos::arch::SerialWrite(pid != 0 ? " spawn=OK\n" : " spawn=FAIL\n");
    duetos::drivers::video::NotifyShow(pid != 0 ? "launched" : "launch failed");
    return true;
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
    if (MaybeLaunchFat32Entry(e))
    {
        return true;
    }
    if (EndsWithCi(e.name, ".TXT"))
    {
        if (duetos::apps::notes::NotesLoadFile(e.name))
        {
            const duetos::drivers::video::WindowHandle nh =
                duetos::drivers::video::ThemeRoleWindow(duetos::drivers::video::ThemeRole::Notes);
            if (nh != duetos::drivers::video::kWindowInvalid)
            {
                duetos::drivers::video::WindowRaise(nh);
            }
            duetos::drivers::video::NotifyShow("opened in notes");
            duetos::arch::SerialWrite("[files] open TXT -> Notes: ");
            duetos::arch::SerialWrite(e.name);
            duetos::arch::SerialWrite("\n");
        }
        else
        {
            duetos::drivers::video::NotifyShow("notes: load failed");
        }
        return true;
    }
    duetos::arch::SerialWrite("[files] open file (no handler): ");
    duetos::arch::SerialWrite(e.name);
    duetos::arch::SerialWrite("\n");
    return true;
}

// Helper: copy a directory entry's name into a 16-byte buffer
// safely. Avoids the previous `kMaxDirEntries > 0 ? 16 : 16`
// expression that only existed to suppress an unused-constant
// warning — the buffer cap is just kNameCap.
void CopyEntryName(char (&out)[16], const char* name)
{
    u32 i = 0;
    for (; i + 1 < sizeof(out) && name[i] != '\0'; ++i)
        out[i] = name[i];
    out[i] = '\0';
}

// Soft-delete the selected disk-view item by moving it to the
// trash bin (`/TRASH/<name>`). On collision (a trash entry with
// the same name), reports a notify so the user can empty first.
// Used by the Pending::DeleteToTrash path — what was previously
// a permanent Fat32DeleteAtPath.
bool TrashSelectedFat32()
{
    namespace fat = fs::fat32;
    if (g_state.fat_selection >= g_state.fat_count)
        return false;
    const auto& e = g_state.fat_entries[g_state.fat_selection];
    if ((e.attributes & 0x10) != 0)
    {
        duetos::drivers::video::NotifyShow("cannot trash directories");
        return true;
    }
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return false;
    char saved_name[16];
    CopyEntryName(saved_name, e.name);
    const auto rc = duetos::apps::trash::TrashMove(v, saved_name);
    if (rc == duetos::apps::trash::MoveResult::Ok)
    {
        duetos::drivers::video::NotifyShow("moved to trash");
        const u32 prev = g_state.fat_selection;
        RescanFat32();
        if (prev >= g_state.fat_count)
        {
            g_state.fat_selection = (g_state.fat_count > 0) ? (g_state.fat_count - 1) : 0;
        }
    }
    else if (rc == duetos::apps::trash::MoveResult::Collision)
    {
        duetos::drivers::video::NotifyShowKind("trash: name collision (empty first)",
                                               duetos::drivers::video::NotifyKind::Warning);
    }
    else
    {
        duetos::drivers::video::NotifyShowKind("trash: move failed", duetos::drivers::video::NotifyKind::Error);
    }
    return true;
}

bool RestoreSelectedTrash()
{
    namespace fat = fs::fat32;
    if (g_state.trash_selection >= g_state.trash_count)
        return false;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return false;
    char saved_name[16];
    CopyEntryName(saved_name, g_state.trash_entries[g_state.trash_selection].name);
    const bool ok = duetos::apps::trash::TrashRestore(v, saved_name);
    if (ok)
    {
        duetos::drivers::video::NotifyShow("restored");
        const u32 prev = g_state.trash_selection;
        RescanTrash();
        if (prev >= g_state.trash_count)
        {
            g_state.trash_selection = (g_state.trash_count > 0) ? (g_state.trash_count - 1) : 0;
        }
        // The restored file is now back in the Fat32 view; refresh
        // it too so the user sees it on a subsequent T->D toggle.
        RescanFat32();
    }
    else
    {
        duetos::drivers::video::NotifyShowKind("restore failed", duetos::drivers::video::NotifyKind::Error);
    }
    return true;
}

bool PermDeleteSelectedTrash()
{
    namespace fat = fs::fat32;
    if (g_state.trash_selection >= g_state.trash_count)
        return false;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return false;
    char saved_name[16];
    CopyEntryName(saved_name, g_state.trash_entries[g_state.trash_selection].name);
    const bool ok = duetos::apps::trash::TrashPermDelete(v, saved_name);
    if (ok)
    {
        duetos::drivers::video::NotifyShow("permanently deleted");
        const u32 prev = g_state.trash_selection;
        RescanTrash();
        if (prev >= g_state.trash_count)
        {
            g_state.trash_selection = (g_state.trash_count > 0) ? (g_state.trash_count - 1) : 0;
        }
    }
    else
    {
        duetos::drivers::video::NotifyShowKind("perm-delete failed", duetos::drivers::video::NotifyKind::Error);
    }
    return true;
}

void EmptyTrashAll()
{
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        duetos::drivers::video::NotifyShow("no FAT32 volume");
        return;
    }
    const u32 deleted = duetos::apps::trash::TrashEmpty(v);
    if (deleted > 0)
    {
        duetos::drivers::video::NotifyShow("trash emptied");
    }
    else
    {
        duetos::drivers::video::NotifyShow("trash already empty");
    }
    RescanTrash();
    g_state.trash_selection = 0;
}

} // namespace

void FilesInit(duetos::drivers::video::WindowHandle handle)
{
    namespace fat = fs::fat32;
    g_state.handle = handle;
    g_state.ramfs_depth = 0;
    g_state.ramfs_selection = 0;
    g_state.fat_count = 0;
    g_state.fat_selection = 0;
    g_state.trash_count = 0;
    g_state.trash_selection = 0;
    g_state.pending = Pending::None;
    const duetos::fs::RamfsNode* root = duetos::fs::RamfsTrustedRoot();
    if (root != nullptr)
    {
        g_state.ramfs_stack[0] = root;
        g_state.ramfs_depth = 1;
    }
    // Default mode: if a FAT32 volume is mounted, open straight
    // into the disk view so the user immediately sees what's
    // actually saved on disk. Without a disk, fall back to the
    // RAM tree (the historical default).
    if (fat::Fat32Volume(0) != nullptr)
    {
        g_state.mode = Mode::Fat32;
        RescanFat32();
    }
    else
    {
        g_state.mode = Mode::Ramfs;
    }
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
    duetos::drivers::video::WindowSetWheelHandler(handle, FilesOnWheel);
    duetos::drivers::video::WindowSetScrollHandler(handle,
                                                   [](duetos::u32 first)
                                                   {
                                                       // The list selection drives `first` in DrawFn —
                                                       // setting `first` directly via the bar means
                                                       // moving the selection so it lands at the new
                                                       // top. Clamp to the listing.
                                                       if (g_state.mode != Mode::Fat32)
                                                           return;
                                                       if (first >= g_state.fat_count)
                                                           first = g_state.fat_count > 0 ? g_state.fat_count - 1 : 0;
                                                       g_state.fat_selection = first;
                                                   });
    // Drop target: a FileEntry dropped onto Files moves the
    // file into the FAT32 trash. Useful for "drag a row out
    // of FAT32 mode and drop it back" without arming the
    // X-then-Y prompt.
    duetos::drivers::video::DndRegisterDropTarget(
        handle,
        [](const duetos::drivers::video::DndPayload& p, duetos::u32 /*cx*/, duetos::u32 /*cy*/) -> bool
        {
            if (p.kind != duetos::drivers::video::DndKind::FileEntry)
                return false;
            namespace fat = duetos::fs::fat32;
            const fat::Volume* v = fat::Fat32Volume(0);
            if (v == nullptr)
            {
                duetos::drivers::video::NotifyShow("trash: no FAT32 volume");
                duetos::drivers::video::SoundCueError();
                return false;
            }
            const auto rc = duetos::apps::trash::TrashMove(v, p.text);
            if (rc == duetos::apps::trash::MoveResult::Ok)
            {
                RescanFat32();
                RescanTrash();
                duetos::drivers::video::NotifyShow("moved to trash");
                return true;
            }
            if (rc == duetos::apps::trash::MoveResult::Collision)
            {
                duetos::drivers::video::NotifyShowKind("trash: name collision",
                                                       duetos::drivers::video::NotifyKind::Warning);
                duetos::drivers::video::SoundCueError();
                return false;
            }
            duetos::drivers::video::NotifyShowKind("trash: failed", duetos::drivers::video::NotifyKind::Error);
            duetos::drivers::video::SoundCueError();
            return false;
        },
        1u << static_cast<duetos::u32>(duetos::drivers::video::DndKind::FileEntry));
}

void FilesOnWheel(duetos::i32 dz, duetos::u8 modifiers)
{
    (void)modifiers;
    if (dz == 0)
        return;
    const bool up = (dz > 0);
    const duetos::i32 steps = (dz > 0) ? dz : -dz;
    for (duetos::i32 i = 0; i < steps; ++i)
    {
        FilesFeedArrow(up);
    }
}

duetos::drivers::video::WindowHandle FilesWindow()
{
    return g_state.handle;
}

void FilesPromoteToDisk()
{
    namespace fat = fs::fat32;
    if (g_state.mode != Mode::Ramfs)
        return; // user already switched, don't override
    if (fat::Fat32Volume(0) == nullptr)
        return;
    g_state.mode = Mode::Fat32;
    g_state.fat_selection = 0;
    RescanFat32();
}

bool FilesFeedArrow(bool up)
{
    // Any navigation cancels a pending prompt — keeps every
    // confirmation flow strictly modal at the caret.
    g_state.pending = Pending::None;
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
    // Pending two-step prompts. 'Y' confirms whatever was armed,
    // anything else cancels. This branch comes first so a stale
    // arm followed by an unrelated key cleanly disarms.
    if (g_state.pending != Pending::None)
    {
        const Pending p = g_state.pending;
        g_state.pending = Pending::None;
        if (c == 'y' || c == 'Y')
        {
            switch (p)
            {
            case Pending::DeleteToTrash:
                TrashSelectedFat32();
                break;
            case Pending::PermDeleteFromTrash:
                PermDeleteSelectedTrash();
                break;
            case Pending::EmptyTrash:
                EmptyTrashAll();
                break;
            default:
                break;
            }
        }
        else
        {
            duetos::drivers::video::NotifyShow("cancelled");
        }
        return true;
    }
    if (c == 'j' || c == 'J')
        return FilesFeedArrow(false);
    if (c == 'k' || c == 'K')
        return FilesFeedArrow(true);
    // X — two distinct semantics by mode: Fat32 view soft-
    // deletes (move to trash); Trash view perm-deletes the
    // selected item.
    if (c == 'x' || c == 'X')
    {
        if (g_state.mode == Mode::Fat32 && g_state.fat_selection < g_state.fat_count)
        {
            const auto& e = g_state.fat_entries[g_state.fat_selection];
            if ((e.attributes & 0x10) != 0)
            {
                duetos::drivers::video::NotifyShow("cannot trash directories");
                return true;
            }
            g_state.pending = Pending::DeleteToTrash;
            g_state.pending_idx = g_state.fat_selection;
            duetos::drivers::video::NotifyShow("press Y to move to trash");
        }
        else if (g_state.mode == Mode::Trash && g_state.trash_selection < g_state.trash_count)
        {
            g_state.pending = Pending::PermDeleteFromTrash;
            g_state.pending_idx = g_state.trash_selection;
            duetos::drivers::video::NotifyShow("press Y to perm-delete");
        }
        return true;
    }
    if (c == 'e' || c == 'E')
    {
        // Empty trash — only meaningful in trash mode.
        if (g_state.mode == Mode::Trash && g_state.trash_count > 0)
        {
            g_state.pending = Pending::EmptyTrash;
            g_state.pending_idx = 0;
            duetos::drivers::video::NotifyShow("press Y to empty trash");
        }
        return true;
    }
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
    if (c == 't' || c == 'T')
    {
        if (g_state.mode != Mode::Trash)
        {
            g_state.mode = Mode::Trash;
            g_state.trash_selection = 0;
            RescanTrash();
            duetos::drivers::video::NotifyShow("files: trash view");
        }
        return true;
    }
    if (c == 'f' || c == 'F')
    {
        if (g_state.mode != Mode::DuetFs)
        {
            g_state.mode = Mode::DuetFs;
            g_state.duet_selection = 0;
            g_state.duet_depth = 0; // RescanDuetFs re-seeds root
            RescanDuetFs();
            duetos::drivers::video::NotifyShow("files: main drive");
        }
        return true;
    }
    if (c == 'r' || c == 'R')
    {
        // Disk view: rescan. Trash view: restore selected item.
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
        if (g_state.mode == Mode::Trash)
        {
            return RestoreSelectedTrash();
        }
        return false;
    }
    if (c == 's' || c == 'S')
    {
        // Cycle sort mode: name -> size -> type -> name. Re-sort
        // both arrays so a subsequent T-toggle into Trash also
        // shows the new order. Selection follows the previously-
        // selected entry by name match where possible — better
        // UX than "selection randomly jumps because the array
        // reordered."
        const auto next = static_cast<u8>(g_state.sort) + 1;
        g_state.sort = (next >= static_cast<u8>(SortMode::kCount)) ? SortMode::Name : static_cast<SortMode>(next);
        // Capture the selected name BEFORE re-sorting so we can
        // find it again after the order changes.
        char saved_name[128] = {};
        u32 nlen = 0;
        if (g_state.mode == Mode::Fat32 && g_state.fat_selection < g_state.fat_count)
        {
            const char* s = g_state.fat_entries[g_state.fat_selection].name;
            for (; nlen + 1 < sizeof(saved_name) && s[nlen] != '\0'; ++nlen)
                saved_name[nlen] = s[nlen];
        }
        else if (g_state.mode == Mode::Trash && g_state.trash_selection < g_state.trash_count)
        {
            const char* s = g_state.trash_entries[g_state.trash_selection].name;
            for (; nlen + 1 < sizeof(saved_name) && s[nlen] != '\0'; ++nlen)
                saved_name[nlen] = s[nlen];
        }
        SortFat32Entries();
        SortTrashEntries();
        // Re-anchor selection to the named entry.
        if (nlen > 0)
        {
            if (g_state.mode == Mode::Fat32)
            {
                for (u32 i = 0; i < g_state.fat_count; ++i)
                {
                    if (FilesNameCmpCi(g_state.fat_entries[i].name, saved_name) == 0)
                    {
                        g_state.fat_selection = i;
                        break;
                    }
                }
            }
            else if (g_state.mode == Mode::Trash)
            {
                for (u32 i = 0; i < g_state.trash_count; ++i)
                {
                    if (FilesNameCmpCi(g_state.trash_entries[i].name, saved_name) == 0)
                    {
                        g_state.trash_selection = i;
                        break;
                    }
                }
            }
        }
        char msg[32];
        u32 mo = 0;
        const char* lead = "files: sort by ";
        for (u32 i = 0; lead[i] != '\0' && mo + 1 < sizeof(msg); ++i)
            msg[mo++] = lead[i];
        const char* sn = SortModeName(g_state.sort);
        for (u32 i = 0; sn[i] != '\0' && mo + 1 < sizeof(msg); ++i)
            msg[mo++] = sn[i];
        msg[mo] = '\0';
        duetos::drivers::video::NotifyShow(msg);
        return true;
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
        if (g_state.mode == Mode::DuetFs)
        {
            if (g_state.duet_depth > 1)
            {
                --g_state.duet_depth;
                g_state.duet_selection = 0;
                RescanDuetFs();
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
                // First chance: launchable PE / ELF — spawn it like
                // a real installed app. MaybeLaunchRamfsExe handles
                // .exe / .elf and reports the result; if it returns
                // true we are done. Anything else falls through to
                // the legacy "open file" log line so the user gets a
                // breadcrumb even when no handler matches.
                if (!MaybeLaunchRamfsExe(sel))
                {
                    duetos::arch::SerialWrite("[files] open file name=");
                    duetos::arch::SerialWrite(sel->name ? sel->name : "(unnamed)");
                    duetos::arch::SerialWrite("\n");
                }
            }
            return true;
        }
        if (g_state.mode == Mode::DuetFs)
        {
            if (g_state.duet_selection >= g_state.duet_count)
                return true;
            const auto& e = g_state.duet_entries[g_state.duet_selection];
            const u32 nl = e.name_len < 63 ? e.name_len : 63;
            if (e.kind == duetos::fs::duetfs::kKindDir)
            {
                if (g_state.duet_depth < kMaxDepth)
                {
                    g_state.duet_stack[g_state.duet_depth] = e.node_id;
                    u32 k = 0;
                    for (; k < nl; ++k)
                        g_state.duet_names[g_state.duet_depth][k] = static_cast<char>(e.name[k]);
                    g_state.duet_names[g_state.duet_depth][k] = '\0';
                    ++g_state.duet_depth;
                    g_state.duet_selection = 0;
                    RescanDuetFs();
                }
            }
            else
            {
                char nm[64];
                u32 k = 0;
                for (; k < nl; ++k)
                    nm[k] = static_cast<char>(e.name[k]);
                nm[k] = '\0';
                duetos::arch::SerialWrite("[files] open duetfs file name=");
                duetos::arch::SerialWrite(nm);
                duetos::arch::SerialWrite("\n");
                duetos::drivers::video::NotifyShow(nm);
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

    // DuetFS "main drive" view round-trip. The boot volume is
    // mounted at /duetfs and seeded with /etc, so entering the
    // view, descending into the first directory, and backing out
    // must all hold. duet_depth tracks the navigation stack.
    FilesFeedChar('f');
    if (g_state.mode != Mode::DuetFs || g_state.duet_depth != 1)
        pass = false;
    {
        u32 dir_row = kFatMax;
        for (u32 i = 0; i < g_state.duet_count; ++i)
        {
            if (g_state.duet_entries[i].kind == duetos::fs::duetfs::kKindDir)
            {
                dir_row = i;
                break;
            }
        }
        if (dir_row != kFatMax)
        {
            g_state.duet_selection = dir_row;
            FilesFeedChar('\n'); // descend
            if (g_state.duet_depth != 2)
                pass = false;
            FilesFeedChar('b'); // back to root
            if (g_state.duet_depth != 1)
                pass = false;
        }
    }
    FilesFeedChar('m');
    if (g_state.mode != Mode::Ramfs)
        pass = false;

    // Extension-match helper sanity (used by Files->ImageView dispatch
    // and Files->Notes dispatch).
    if (!EndsWithCi("SHOT0001.BMP", ".bmp"))
        pass = false;
    if (!EndsWithCi("readme.BMP", ".bmp"))
        pass = false;
    if (EndsWithCi("notes.txt", ".bmp"))
        pass = false;
    if (!EndsWithCi("README.TXT", ".txt"))
        pass = false;
    if (!EndsWithCi("session.cfg", ".CFG"))
        pass = false;
    if (EndsWithCi("AB", ".bmp"))
        pass = false;

    // Pending-prompt disarm flow: arming any of the three two-
    // step prompts and then navigating must clear it. Touch-
    // test only (no FAT32 write involved).
    g_state.pending = Pending::DeleteToTrash;
    g_state.pending_idx = 0;
    FilesFeedArrow(true);
    if (g_state.pending != Pending::None)
        pass = false;
    g_state.pending = Pending::PermDeleteFromTrash;
    g_state.pending_idx = 0;
    FilesFeedArrow(false);
    if (g_state.pending != Pending::None)
        pass = false;
    g_state.pending = Pending::EmptyTrash;
    FilesFeedArrow(true);
    if (g_state.pending != Pending::None)
        pass = false;

    g_state.ramfs_depth = saved_depth;
    g_state.ramfs_selection = saved_sel;
    g_state.mode = saved_mode;
    SerialWrite(pass ? "[files] self-test OK (ramfs descend+back, mode toggle, duetfs descend+back, ext match, "
                       "delete-disarm)\n"
                     : "[files] self-test FAILED\n");
}

namespace
{

// Per-row context menu items. Static so the menu primitive can
// hold a borrowed pointer for the open lifetime.
constinit duetos::drivers::video::MenuItem kFilesContextMenuItems[] = {
    {"OPEN", 30, 0, nullptr, 0},       {"RENAME", 31, 0, nullptr, 0},        {"DELETE", 32, 0, nullptr, 0},
    {"PROPERTIES", 33, 0, nullptr, 0}, {"NEW TEXT FILE", 35, 0, nullptr, 0}, {"NEW FOLDER", 36, 0, nullptr, 0},
    {"REFRESH", 34, 0, nullptr, 0},
};
// Sentinel ctx for a right-click on empty space (no row under the
// cursor): row-specific actions (OPEN/RENAME/DELETE/PROPERTIES)
// no-op on it; the create/refresh actions still work.
constexpr duetos::u32 kFilesNoRow = 0xFFFFFFFFu;
constexpr duetos::u32 kFilesContextMenuItemsN = sizeof(kFilesContextMenuItems) / sizeof(kFilesContextMenuItems[0]);

// DuetFS "main drive" view context menu. Read-only set for v0 —
// the native FS write path is the shell's job; the GUI mirrors
// what every file manager offers for a browse-only mount.
constinit duetos::drivers::video::MenuItem kFilesDuetMenuItems[] = {
    {"OPEN", 37, 0, nullptr, 0},
    {"PROPERTIES", 38, 0, nullptr, 0},
    {"REFRESH", 39, 0, nullptr, 0},
};
constexpr duetos::u32 kFilesDuetMenuItemsN = sizeof(kFilesDuetMenuItems) / sizeof(kFilesDuetMenuItems[0]);

} // namespace

duetos::i32 FilesRowAt(duetos::u32 sx, duetos::u32 sy)
{
    if (g_state.mode != Mode::Fat32 || g_state.fat_count == 0)
        return -1;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return -1;
    if (ww < 4 || wh < 26)
        return -1;
    // Content area starts at (wx+2, wy+22+2) — title bar 22 px +
    // 2-px borders. Mirror the geometry in DrawFat32: list_top is
    // 2 + kRowH + 2 below the content origin.
    const duetos::u32 content_x = wx + 2;
    const duetos::u32 content_y = wy + 22 + 2;
    const duetos::u32 content_w = ww - 4;
    const duetos::u32 content_h = wh - 22 - 4;
    if (sx < content_x || sx >= content_x + content_w)
        return -1;
    const duetos::u32 list_top = content_y + 2 + kRowH + 2;
    if (sy < list_top)
        return -1;
    const duetos::u32 n = g_state.fat_count;
    const duetos::u32 max_rows =
        (content_h > (list_top - content_y) + kRowH) ? (content_h - (list_top - content_y)) / kRowH : 0;
    if (max_rows == 0)
        return -1;
    duetos::u32 first = 0;
    if (n > max_rows && g_state.fat_selection >= max_rows)
        first = g_state.fat_selection - (max_rows - 1);
    const duetos::u32 row_in_view = (sy - list_top) / kRowH;
    if (row_in_view >= max_rows)
        return -1;
    const duetos::u32 idx = first + row_in_view;
    if (idx >= n)
        return -1;
    return static_cast<duetos::i32>(idx);
}

bool FilesBeginDragSelection()
{
    if (g_state.mode != Mode::Fat32 || g_state.fat_selection >= g_state.fat_count)
        return false;
    const auto& e = g_state.fat_entries[g_state.fat_selection];
    duetos::drivers::video::DndPayload p{};
    p.kind = duetos::drivers::video::DndKind::FileEntry;
    u32 i = 0;
    while (i < duetos::drivers::video::kDndPayloadMax && e.name[i] != '\0')
    {
        p.text[i] = e.name[i];
        ++i;
    }
    p.text[i] = '\0';
    duetos::u32 cx = 0, cy = 0;
    duetos::drivers::video::CursorPosition(&cx, &cy);
    if (!duetos::drivers::video::DndBegin(g_state.handle, p, cx, cy))
        return false;
    duetos::drivers::video::NotifyShow("dragging - click target window to drop, Esc to cancel");
    return true;
}

bool FilesOnDoubleClick(duetos::u32 sx, duetos::u32 sy)
{
    // FAT32 mode is the only mode with a click-to-row hit-test
    // today. Trash / ramfs DC could be wired the same way — keep
    // them GAP'd until those modes get a real RowAt helper, so a
    // double-click in those modes simply doesn't open anything
    // (it doesn't misfire).
    if (g_state.mode != Mode::Fat32)
        return false;
    const duetos::i32 row = FilesRowAt(sx, sy);
    if (row < 0)
        return false;
    g_state.fat_selection = static_cast<duetos::u32>(row);
    OpenFat32Selected();
    duetos::arch::SerialWrite("[files] double-click open row=");
    duetos::arch::SerialWriteHex(static_cast<duetos::u64>(row));
    duetos::arch::SerialWrite("\n");
    return true;
}

bool FilesOnRightClick(duetos::u32 sx, duetos::u32 sy)
{
    // DuetFS "main drive" view gets its own context menu so the
    // everyday Open / Properties gestures work on the native
    // volume — not just on the FAT32 disk. GAP: acts on the
    // highlighted row (FilesRowAt is FAT32-geometry only); precise
    // DuetFS hit-testing waits on a shared row-geometry helper.
    if (g_state.mode == Mode::DuetFs)
    {
        duetos::drivers::video::MenuOpen(kFilesDuetMenuItems, kFilesDuetMenuItemsN, sx, sy, g_state.duet_selection);
        duetos::arch::SerialWrite("[files] duetfs context menu opened sel=");
        duetos::arch::SerialWriteHex(g_state.duet_selection);
        duetos::arch::SerialWrite("\n");
        return true;
    }
    // Only FAT32 mode has a v0 row context menu beyond this. Trash
    // and ramfs fall through; caller uses the default window menu.
    if (g_state.mode != Mode::Fat32)
        return false;
    const duetos::i32 row = FilesRowAt(sx, sy);
    // Empty space still gets the menu so NEW TEXT FILE / NEW FOLDER
    // are reachable without aiming at an existing entry — the
    // everyday "right-click to create" gesture.
    const duetos::u32 ctx = (row < 0) ? kFilesNoRow : static_cast<duetos::u32>(row);
    duetos::drivers::video::MenuOpen(kFilesContextMenuItems, kFilesContextMenuItemsN, sx, sy, ctx);
    duetos::arch::SerialWrite("[files] context menu opened row=");
    duetos::arch::SerialWriteHex(static_cast<duetos::u64>(row));
    duetos::arch::SerialWrite(" name=");
    if (static_cast<duetos::u32>(row) < g_state.fat_count)
        duetos::arch::SerialWrite(g_state.fat_entries[row].name);
    duetos::arch::SerialWrite("\n");
    return true;
}

void FilesDispatchContextAction(duetos::u32 action, duetos::u32 ctx)
{
    // DuetFS "main drive" view actions (37..39). Handled before
    // the FAT32 guard since they read g_state.duet_entries.
    if (action == 37 || action == 38 || action == 39)
    {
        if (g_state.mode != Mode::DuetFs)
            return;
        if (action == 39) // REFRESH
        {
            RescanDuetFs();
            if (g_state.duet_selection >= g_state.duet_count && g_state.duet_count > 0)
                g_state.duet_selection = g_state.duet_count - 1;
            duetos::drivers::video::NotifyShow("refreshed");
            return;
        }
        if (ctx >= g_state.duet_count)
            return;
        const auto& e = g_state.duet_entries[ctx];
        if (action == 37) // OPEN — descend dir / breadcrumb file
        {
            g_state.duet_selection = ctx;
            FilesFeedChar('\n');
            return;
        }
        // action == 38: PROPERTIES — info dialog (static body must
        // outlive this scope; single-instance dialog makes it safe).
        static char s_dprops[160];
        u32 p = 0;
        auto put = [&](const char* s)
        {
            for (u32 i = 0; s[i] != '\0' && p + 1 < sizeof(s_dprops); ++i)
                s_dprops[p++] = s[i];
        };
        const u32 nl = e.name_len < 63 ? e.name_len : 63;
        char nm[64];
        for (u32 i = 0; i < nl; ++i)
            nm[i] = static_cast<char>(e.name[i]);
        nm[nl] = '\0';
        put("Name: ");
        put(nm);
        put("\nType: ");
        put(e.kind == duetos::fs::duetfs::kKindDir ? "Folder" : "File");
        put("\nSize: ");
        char num[24];
        u32 ni = 0;
        duetos::u64 v = e.size_bytes;
        char tmp[24];
        u32 ti = 0;
        if (v == 0)
            tmp[ti++] = '0';
        while (v != 0)
        {
            tmp[ti++] = static_cast<char>('0' + v % 10);
            v /= 10;
        }
        while (ti > 0)
            num[ni++] = tmp[--ti];
        num[ni] = '\0';
        put(num);
        put(" bytes (DuetFS main drive)");
        s_dprops[p] = '\0';
        duetos::arch::SerialWrite("[files] duetfs properties: ");
        duetos::arch::SerialWrite(s_dprops);
        duetos::arch::SerialWrite("\n");
        duetos::drivers::video::MessageBoxOpen(
            "PROPERTIES", s_dprops, [](duetos::drivers::video::DialogResult, const char*, void*) {}, nullptr);
        return;
    }
    // ctx is the row index captured at MenuOpen time. Validate
    // against the current fat_count — the listing could have
    // re-scanned between right-click and click-on-item.
    if (g_state.mode != Mode::Fat32)
        return;
    // Row-specific actions need a valid row; create/refresh do
    // not (ctx may be kFilesNoRow from an empty-space right-click).
    if (action == 30 || action == 31 || action == 32 || action == 33)
    {
        if (ctx >= g_state.fat_count)
            return;
    }
    switch (action)
    {
    case 30: // OPEN
    {
        // Restore selection to the right-clicked row so the
        // existing OpenFat32Selected helper opens the correct
        // file. Save + restore would be over-engineered for v0.
        g_state.fat_selection = ctx;
        OpenFat32Selected();
        break;
    }
    case 31: // RENAME — InputBox prompt -> Fat32RenameAtPath
    {
        // Stash the row in a static so the callback knows which
        // entry the user was renaming. The dialog primitive is
        // single-instance + the callback fires synchronously
        // from the kbd-reader once OK is chosen, so a single
        // slot is enough; a future multi-dialog primitive would
        // make this state per-callback.
        static u32 s_rename_row = 0;
        s_rename_row = ctx;
        const auto& e = g_state.fat_entries[ctx];
        duetos::drivers::video::InputBoxOpen(
            "RENAME", "Enter new name (8.3 form):", e.name,
            [](duetos::drivers::video::DialogResult r, const char* text, void* /*user*/)
            {
                if (r != duetos::drivers::video::DialogResult::Ok || text == nullptr || text[0] == '\0')
                {
                    duetos::drivers::video::NotifyShow("rename cancelled");
                    return;
                }
                if (s_rename_row >= g_state.fat_count)
                    return;
                namespace fat = duetos::fs::fat32;
                const fat::Volume* v = fat::Fat32Volume(0);
                if (v == nullptr)
                {
                    duetos::drivers::video::NotifyShow("rename: no FAT32 volume");
                    return;
                }
                char src[20];
                src[0] = '/';
                u32 si = 1;
                const auto& cur = g_state.fat_entries[s_rename_row];
                for (u32 i = 0; cur.name[i] != '\0' && si + 1 < sizeof(src); ++i)
                    src[si++] = cur.name[i];
                src[si] = '\0';
                char dst[20];
                dst[0] = '/';
                u32 di = 1;
                for (u32 i = 0; text[i] != '\0' && di + 1 < sizeof(dst); ++i)
                    dst[di++] = text[i];
                dst[di] = '\0';
                const bool ok = fat::Fat32RenameAtPath(v, src, dst);
                if (ok)
                {
                    RescanFat32();
                    duetos::drivers::video::NotifyShow("renamed");
                    duetos::arch::SerialWrite("[files] rename ok: ");
                    duetos::arch::SerialWrite(src);
                    duetos::arch::SerialWrite(" -> ");
                    duetos::arch::SerialWrite(dst);
                    duetos::arch::SerialWrite("\n");
                }
                else
                {
                    duetos::drivers::video::NotifyShowKind("rename failed", duetos::drivers::video::NotifyKind::Error);
                    duetos::drivers::video::SoundCueError();
                    duetos::arch::SerialWrite("[files] rename FAILED: ");
                    duetos::arch::SerialWrite(src);
                    duetos::arch::SerialWrite(" -> ");
                    duetos::arch::SerialWrite(dst);
                    duetos::arch::SerialWrite("\n");
                }
            },
            nullptr);
        break;
    }
    case 32: // DELETE — re-arm the existing X-then-Y prompt.
    {
        g_state.fat_selection = ctx;
        g_state.pending = Pending::DeleteToTrash;
        g_state.pending_idx = ctx;
        duetos::drivers::video::NotifyShow("press Y to confirm delete");
        duetos::arch::SerialWrite("[files] delete-to-trash armed via context menu\n");
        break;
    }
    case 33: // PROPERTIES — real info dialog (name / size / type / attr)
    {
        const auto& e = g_state.fat_entries[ctx];
        const bool is_dir = (e.attributes & 0x10) != 0;
        // MessageBoxOpen stores the body by reference until the
        // callback fires, so it must outlive this scope — a
        // file-scope static is safe given the dialog primitive is
        // single-instance.
        static char s_props[160];
        u32 p = 0;
        auto put = [&](const char* s)
        {
            for (u32 i = 0; s[i] != '\0' && p + 1 < sizeof(s_props); ++i)
                s_props[p++] = s[i];
        };
        put("Name: ");
        put(e.name);
        put("\nType: ");
        put(is_dir ? "Folder" : "File");
        put("\nSize: ");
        char num[24];
        u32 ni = 0;
        duetos::u64 v = e.size_bytes;
        char tmp[24];
        u32 ti = 0;
        if (v == 0)
            tmp[ti++] = '0';
        while (v != 0)
        {
            tmp[ti++] = static_cast<char>('0' + v % 10);
            v /= 10;
        }
        while (ti > 0)
            num[ni++] = tmp[--ti];
        num[ni] = '\0';
        put(num);
        put(" bytes\nAttr: 0x");
        const char* hexd = "0123456789ABCDEF";
        char ah[3] = {hexd[(e.attributes >> 4) & 0xF], hexd[e.attributes & 0xF], '\0'};
        put(ah);
        s_props[p] = '\0';
        duetos::arch::SerialWrite("[files] properties: ");
        duetos::arch::SerialWrite(s_props);
        duetos::arch::SerialWrite("\n");
        duetos::drivers::video::MessageBoxOpen(
            "PROPERTIES", s_props, [](duetos::drivers::video::DialogResult, const char*, void*) {}, nullptr);
        break;
    }
    case 35: // NEW TEXT FILE — prompt for a name, create empty file
    {
        duetos::drivers::video::InputBoxOpen(
            "NEW TEXT FILE", "Enter file name (8.3 form):", "NEW.TXT",
            [](duetos::drivers::video::DialogResult r, const char* text, void*)
            {
                if (r != duetos::drivers::video::DialogResult::Ok || text == nullptr || text[0] == '\0')
                {
                    duetos::drivers::video::NotifyShow("new file cancelled");
                    return;
                }
                namespace fat = duetos::fs::fat32;
                const fat::Volume* v = fat::Fat32Volume(0);
                if (v == nullptr)
                {
                    duetos::drivers::video::NotifyShow("new file: no FAT32 volume");
                    return;
                }
                char path[24];
                path[0] = '/';
                u32 pi = 1;
                for (u32 i = 0; text[i] != '\0' && pi + 1 < sizeof(path); ++i)
                    path[pi++] = text[i];
                path[pi] = '\0';
                const bool ok = fat::Fat32CreateAtPath(v, path, nullptr, 0) >= 0;
                if (ok)
                {
                    RescanFat32();
                    duetos::drivers::video::NotifyShow("file created");
                }
                else
                {
                    duetos::drivers::video::NotifyShowKind("create failed", duetos::drivers::video::NotifyKind::Error);
                    duetos::drivers::video::SoundCueError();
                }
                duetos::arch::SerialWrite("[files] new file ");
                duetos::arch::SerialWrite(ok ? "ok: " : "FAILED: ");
                duetos::arch::SerialWrite(path);
                duetos::arch::SerialWrite("\n");
            },
            nullptr);
        break;
    }
    case 36: // NEW FOLDER — prompt for a name, mkdir
    {
        duetos::drivers::video::InputBoxOpen(
            "NEW FOLDER", "Enter folder name (8.3 form):", "NEWDIR",
            [](duetos::drivers::video::DialogResult r, const char* text, void*)
            {
                if (r != duetos::drivers::video::DialogResult::Ok || text == nullptr || text[0] == '\0')
                {
                    duetos::drivers::video::NotifyShow("new folder cancelled");
                    return;
                }
                namespace fat = duetos::fs::fat32;
                const fat::Volume* v = fat::Fat32Volume(0);
                if (v == nullptr)
                {
                    duetos::drivers::video::NotifyShow("new folder: no FAT32 volume");
                    return;
                }
                char path[24];
                path[0] = '/';
                u32 pi = 1;
                for (u32 i = 0; text[i] != '\0' && pi + 1 < sizeof(path); ++i)
                    path[pi++] = text[i];
                path[pi] = '\0';
                const bool ok = fat::Fat32MkdirAtPath(v, path);
                if (ok)
                {
                    RescanFat32();
                    duetos::drivers::video::NotifyShow("folder created");
                }
                else
                {
                    duetos::drivers::video::NotifyShowKind("mkdir failed", duetos::drivers::video::NotifyKind::Error);
                    duetos::drivers::video::SoundCueError();
                }
                duetos::arch::SerialWrite("[files] new folder ");
                duetos::arch::SerialWrite(ok ? "ok: " : "FAILED: ");
                duetos::arch::SerialWrite(path);
                duetos::arch::SerialWrite("\n");
            },
            nullptr);
        break;
    }
    case 34: // REFRESH — re-scan FAT32 root, clamp selection.
    {
        RescanFat32();
        if (g_state.fat_selection >= g_state.fat_count && g_state.fat_count > 0)
            g_state.fat_selection = g_state.fat_count - 1;
        duetos::drivers::video::NotifyShow("refreshed");
        duetos::arch::SerialWrite("[files] refresh via context menu, count=");
        duetos::arch::SerialWriteHex(g_state.fat_count);
        duetos::arch::SerialWrite("\n");
        break;
    }
    default:
        break;
    }
}

} // namespace duetos::apps::files
