#include "apps/files.h"

#include "apps/imageview.h"
#include "apps/notes.h"
#include "apps/trash.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "diag/fix_journal.h"
#include "log/klog.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
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

// SEC-008: least-privilege cap set for USER-CHOSEN .exe/.elf launches.
// An arbitrary file the operator double-clicks is UNTRUSTED — it must NOT
// inherit CapSetTrusted() (which sets every bit, incl. kCapDebug =
// cross-proc VM r/w + SetContext, and kCapDiag = SYS_DIAG_FAULT_INJECT, a
// guest-reachable kernel panic). Mirrors the browser broker's intended
// model (kernel/apps/browser/priv_exec.cpp::DeriveChildCaps): grant only
// the minimum a console/GUI binary needs and NEVER kCapDebug/kCapDiag/
// kCapNetAdmin/kCapNet/kCapInput/kCapFsWrite.
inline duetos::core::CapSet UserLaunchCaps()
{
    duetos::core::CapSet caps = duetos::core::CapSetEmpty();
    duetos::core::CapSetAdd(caps, duetos::core::kCapSerialConsole);
    duetos::core::CapSetAdd(caps, duetos::core::kCapFsRead);
    duetos::core::CapSetAdd(caps, duetos::core::kCapSpawnThread);
    return caps;
}

// SEC-008: PE import preload pulls in ~44 DLLs, so kFrameBudgetSandbox (8)
// is too tight — grant bounded headroom (same rationale as priv_exec's
// kBrokeredSpawnFrames) while staying far below the trusted region table.
constexpr duetos::u64 kUserLaunchFrames = 512;

constexpr u32 kMaxDepth = 8;
constexpr u32 kFatMax = 64;
// Back/Forward history length. Each entry records a (cluster, label) pair
// for a visited directory. Independent of the path stack — the stack models
// current position; the history enables Alt-Back / '[' revisits.
constexpr u32 kFatHistMax = 16;
// Type-ahead inter-key idle gap: 100 ticks @ 100 Hz = 1 second.
constexpr u64 kTypeaheadTimeoutTicks = 100;
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

    // Fat32 view. entries cached on entry to disk mode; refreshed
    // via 'r' / on every mode toggle so newly written files appear
    // without reboot.
    duetos::fs::fat32::DirEntry fat_entries[kFatMax];
    u32 fat_count;
    u32 fat_selection;

    // FAT32 subdirectory navigation stack. fat_depth==0 means root.
    // Each frame beyond root records the cluster number of that
    // directory and its short name for the path header.
    u32 fat_path_clusters[kMaxDepth];   // cluster for each depth level (0=root cluster)
    char fat_path_names[kMaxDepth][16]; // directory name at each depth
    u32 fat_depth;                      // 0 = in root, >0 = in subdir

    // Back/Forward history stack. Independent linear buffer; back_pos
    // indexes the current position. Descending a subdir pushes a new
    // entry (discarding any forward tail); ascending (Backspace) decrements
    // back_pos; '[' / ']' move back_pos without altering fat_path_*.
    // An entry stores the cluster of the directory we were in BEFORE the
    // navigation, plus a display label for the header.
    struct Fat32HistEntry
    {
        u32 cluster;
        char name[64]; // path label (e.g. "DISK:/SUB/")
    };
    Fat32HistEntry fat_hist[kFatHistMax];
    u32 fat_hist_len; // total entries stored
    u32 fat_hist_pos; // current position (index into fat_hist of "where we came from")

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

    // Type-ahead prefix buffer. Accumulates alphanumeric key presses
    // and resets after kTypeaheadTimeoutTicks idle ticks. Each append
    // scans the current listing for the first entry whose name begins
    // (case-insensitively) with the buffered prefix and moves the
    // selection there. If no match is found the buffer stays unchanged
    // so the user can see their prefix and backspace to correct it.
    char typeahead_buf[32];
    u32 typeahead_len;
    u64 typeahead_tick; // tick stamp of the last typeahead key press
};

constinit State g_state = {};

// ---- Pass D chrome: AppToolbar header + 6 mode/action buttons +
// AppLabel footer hint. The list rows themselves remain raw paint
// (DrawRamfs / DrawFat32 / DrawTrash / DrawDuetFs) — each mode's
// row paints inline tag colour, dim right-aligned size column, and
// a per-mode header band that AppListRow cannot reproduce without
// either compositing three widgets per row or losing fidelity. The
// chrome migration is the honest Pass D win for Files: typography
// + tactility on the header strip + footer + clickable mode
// buttons (no need to remember D/M/T/F/R/S hotkeys). Carve-out
// justification per Notes (Task 9): the editor area / list rows
// were kept raw paint there too — same logic applies here.
//
// Layout: 26 px AppToolbar at the top of the content area, with
// six 56-px-wide AppButtons inset 4 px (RAM/DISK/TRASH/DRIVE +
// REFRESH + SORT). Below: the legacy header line + list paint.
// At the bottom: an AppLabel(Caption) covers the dynamic hint /
// pending-prompt text the legacy footer used to paint inline.

constexpr u32 kHdrToolbarH = 26U;
constexpr u32 kHdrBtnW = 56U;
constexpr u32 kHdrBtnH = 20U;
constexpr u32 kHdrBtnGap = 4U;
constexpr u32 kHdrPadX = 4U;
constexpr u32 kHdrPadY = 3U;
constexpr u32 kFooterH = 12U;
constexpr u32 kFooterPadX = 4U;

// Number of toolbar buttons (RAM/DISK/TRASH/DRIVE/REFRESH/SORT).
constexpr u32 kHdrBtnCount = 6U;

// Index of the REFRESH button — used by the self-test to target a
// known mid-toolbar slot. The mode buttons (0..3 RAM/DISK/TRASH/
// DRIVE) + SORT (5) are addressed positionally by the BindFilesOnce
// loop, so only the test's target needs a named constant.
constexpr u32 kBtnRefresh = 4;

// Static footer text buffer — AppLabel stores text by pointer so
// the buffer must outlive every Paint. Re-rendered each frame
// from RefreshFooterText() based on mode + pending state.
constinit char g_footer_text[96] = {};

// Self-test result flag for the Pass D umbrella aggregator. True
// iff the most recent FilesSelfTest() invocation ran every check
// (including the synthetic toolbar-button click) without error.
constinit bool g_self_test_passed = false;

// Mouse-state edge detector for FilesMouseInput. The legacy WM
// dispatch on click (FilesOnDoubleClick / FilesOnRightClick)
// stays the kernel's source of truth — this only drives the
// toolbar widget chain so AppButton hover + press tracking
// works on tactility themes.
constinit bool g_prev_left_down = false;

// Toolbar click trampolines — AppButton's on_click is a plain
// `void (*)()` so we route through file-scope wrappers that
// mutate g_state.mode / drive a rescan. Defined below; forward-
// declared so the constinit g_files (which captures them by
// function-pointer value) can be initialised at this point.
void ClickModeRam();
void ClickModeDisk();
void ClickModeTrash();
void ClickModeDrive();
void ClickRefresh();
void ClickSort();

using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
using duetos::drivers::video::app_widgets::AppButton;
using duetos::drivers::video::app_widgets::AppLabel;
using duetos::drivers::video::app_widgets::AppToolbar;
using duetos::drivers::video::app_widgets::Compose;
using duetos::drivers::video::app_widgets::Event;
using duetos::drivers::video::app_widgets::EventKind;
using duetos::drivers::video::app_widgets::EventResult;
using duetos::drivers::video::app_widgets::MakeWidgetGroup;
using duetos::drivers::video::app_widgets::Rect;

// Toolbar first (back), then 6 buttons in mode-order, then the
// footer AppLabel last (overlays the bottom hint band). Reverse
// declaration order is the dispatch order, so buttons get first
// refusal on the click — exactly what we want.
constinit auto g_files = MakeWidgetGroup(AppToolbar{}, AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{},
                                         AppButton{}, AppLabel{});

constinit bool g_files_bound = false;

// Walk the recursive WidgetChain by hand to grab a stable pointer
// to each button. The chain order matches the MakeWidgetGroup
// argument list: head = AppToolbar, then 6 AppButton nodes, then
// the AppLabel.
AppButton* HdrButton(u32 i)
{
    auto& a = g_files.chain.tail; // toolbar -> btn[0]
    auto& b = a.tail;             // btn[0] -> btn[1]
    auto& c2 = b.tail;            // btn[1] -> btn[2]
    auto& d = c2.tail;            // btn[2] -> btn[3]
    auto& e = d.tail;             // btn[3] -> btn[4]
    auto& f = e.tail;             // btn[4] -> btn[5]
    AppButton* btns[kHdrBtnCount] = {&a.head, &b.head, &c2.head, &d.head, &e.head, &f.head};
    return btns[i];
}

void BindFilesOnce()
{
    if (g_files_bound)
        return;
    g_files_bound = true;

    auto& toolbar = g_files.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    static const char* const kLabels[kHdrBtnCount] = {"RAM", "DISK", "TRASH", "DRIVE", "REFRESH", "SORT"};
    using ClickFn = void (*)();
    static constexpr ClickFn kClicks[kHdrBtnCount] = {ClickModeRam,   ClickModeDisk, ClickModeTrash,
                                                      ClickModeDrive, ClickRefresh,  ClickSort};
    for (u32 i = 0; i < kHdrBtnCount; ++i)
    {
        AppButton* btn = HdrButton(i);
        btn->label = kLabels[i];
        btn->on_click = kClicks[i];
        btn->weight = ChromeTextWeight::Regular;
        btn->bg_rgb = 0; // theme role_title[0]
        btn->fg_rgb = 0x00101828U;
    }

    auto& label = g_files.chain.tail.tail.tail.tail.tail.tail.tail.head;
    label.text = g_footer_text;
    label.role = ChromeTextRole::Caption;
    label.weight = ChromeTextWeight::Regular;
    label.fg_rgb = 0x00181828U;
    label.bg_rgb = 0x00C8C8B8U; // status band tone
    label.align_left = true;
}

void RebindFilesBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    auto& toolbar = g_files.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kHdrToolbarH};

    for (u32 i = 0; i < kHdrBtnCount; ++i)
    {
        HdrButton(i)->bounds = Rect{cx + kHdrPadX + i * (kHdrBtnW + kHdrBtnGap), cy + kHdrPadY, kHdrBtnW, kHdrBtnH};
    }

    auto& label = g_files.chain.tail.tail.tail.tail.tail.tail.tail.head;
    const u32 fy = (ch > kFooterH) ? cy + ch - kFooterH : cy;
    const u32 fw = (cw > 2 * kFooterPadX) ? cw - 2 * kFooterPadX : cw;
    label.bounds = Rect{cx + kFooterPadX, fy, fw, kFooterH};
}

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

// ---- Type-ahead helpers -----------------------------------------------

// Reset the type-ahead buffer. Called on mode-switch, navigation,
// or after the idle timeout fires.
void TypeaheadReset()
{
    g_state.typeahead_len = 0;
    g_state.typeahead_buf[0] = '\0';
    g_state.typeahead_tick = 0;
}

// Case-insensitive prefix match: does `name` start with the
// buffered prefix? Returns true if prefix is empty (matches all).
bool TypeaheadNameMatches(const char* name)
{
    if (g_state.typeahead_len == 0)
        return true;
    for (u32 i = 0; i < g_state.typeahead_len; ++i)
    {
        if (name[i] == '\0')
            return false; // name shorter than prefix
        char nc = name[i];
        char pc = g_state.typeahead_buf[i];
        if (nc >= 'a' && nc <= 'z')
            nc = static_cast<char>(nc - 32);
        if (pc >= 'a' && pc <= 'z')
            pc = static_cast<char>(pc - 32);
        if (nc != pc)
            return false;
    }
    return true;
}

// Scan the current mode's entry list for the first entry whose name
// begins with the type-ahead prefix. If found, moves the selection
// there and returns true. If not found, leaves the selection
// unchanged and returns false.
bool TypeaheadSearch()
{
    if (g_state.typeahead_len == 0)
        return false;
    if (g_state.mode == Mode::Fat32)
    {
        for (u32 i = 0; i < g_state.fat_count; ++i)
        {
            if (TypeaheadNameMatches(g_state.fat_entries[i].name))
            {
                g_state.fat_selection = i;
                KLOG_DEBUG_S("files", "typeahead fat32 match", "prefix", g_state.typeahead_buf);
                return true;
            }
        }
        KLOG_DEBUG_S("files", "typeahead fat32 no match", "prefix", g_state.typeahead_buf);
        return false;
    }
    if (g_state.mode == Mode::Trash)
    {
        for (u32 i = 0; i < g_state.trash_count; ++i)
        {
            if (TypeaheadNameMatches(g_state.trash_entries[i].name))
            {
                g_state.trash_selection = i;
                KLOG_DEBUG_S("files", "typeahead trash match", "prefix", g_state.typeahead_buf);
                return true;
            }
        }
        return false;
    }
    if (g_state.mode == Mode::DuetFs)
    {
        for (u32 i = 0; i < g_state.duet_count; ++i)
        {
            // DuetFS names are stored as u8[] with a separate length;
            // build a small NUL-terminated copy for the prefix check.
            char nm[65];
            const u32 nl = g_state.duet_entries[i].name_len < 64 ? g_state.duet_entries[i].name_len : 64;
            for (u32 k = 0; k < nl; ++k)
                nm[k] = static_cast<char>(g_state.duet_entries[i].name[k]);
            nm[nl] = '\0';
            if (TypeaheadNameMatches(nm))
            {
                g_state.duet_selection = i;
                KLOG_DEBUG_S("files", "typeahead duetfs match", "prefix", g_state.typeahead_buf);
                return true;
            }
        }
        return false;
    }
    // Ramfs mode.
    const duetos::fs::RamfsNode* cur = g_state.ramfs_depth > 0 ? g_state.ramfs_stack[g_state.ramfs_depth - 1] : nullptr;
    if (cur == nullptr || cur->children == nullptr)
        return false;
    for (u32 i = 0; cur->children[i] != nullptr; ++i)
    {
        const char* name = cur->children[i]->name;
        if (name != nullptr && TypeaheadNameMatches(name))
        {
            g_state.ramfs_selection = i;
            KLOG_DEBUG_S("files", "typeahead ramfs match", "prefix", g_state.typeahead_buf);
            return true;
        }
    }
    return false;
}

// Append one alphanumeric character to the type-ahead buffer,
// resetting first if the inter-key gap exceeded the timeout.
// Then scans for the first prefix match and moves the selection.
void TypeaheadAppend(char c)
{
    const u64 now = duetos::arch::TimerTicks();
    if (g_state.typeahead_tick != 0 && (now - g_state.typeahead_tick) >= kTypeaheadTimeoutTicks)
    {
        TypeaheadReset();
        KLOG_DEBUG("files", "typeahead timeout reset");
    }
    if (g_state.typeahead_len + 1 < sizeof(g_state.typeahead_buf))
    {
        g_state.typeahead_buf[g_state.typeahead_len++] = c;
        g_state.typeahead_buf[g_state.typeahead_len] = '\0';
    }
    g_state.typeahead_tick = now;
    TypeaheadSearch();
    KLOG_DEBUG_S("files", "typeahead append", "buf", g_state.typeahead_buf);
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

// Forward declaration — defined after RescanFat32 helpers below.
void RescanFat32();

// Return the cluster number for the current FAT32 directory.
// fat_depth==0 => root cluster; fat_depth>0 => the cluster stored at the
// top of the path stack.
u32 Fat32CurrentCluster()
{
    const duetos::fs::fat32::Volume* v = duetos::fs::fat32::Fat32Volume(0);
    if (v == nullptr)
        return 0;
    if (g_state.fat_depth == 0)
        return v->root_cluster;
    return g_state.fat_path_clusters[g_state.fat_depth - 1];
}

// Build the path header string for the current FAT32 directory, e.g.
// "DISK:/" at root, "DISK:/SUB/" one level deep.
void Fat32BuildPathHeader(char* out, u32 cap)
{
    u32 o = 0;
    const char* prefix = "DISK:/";
    for (u32 i = 0; prefix[i] != '\0' && o + 1 < cap; ++i)
        out[o++] = prefix[i];
    for (u32 d = 0; d < g_state.fat_depth && o + 1 < cap; ++d)
    {
        for (u32 j = 0; g_state.fat_path_names[d][j] != '\0' && o + 1 < cap; ++j)
            out[o++] = g_state.fat_path_names[d][j];
        if (o + 1 < cap)
            out[o++] = '/';
    }
    out[o] = '\0';
}

// Push the current directory position onto the back/forward history, then
// descend into the subdirectory entry `e`. Updates fat_depth and the path
// name stack; the caller must call RescanFat32() after to populate the listing.
// Returns false if the depth cap would be exceeded or the volume is unavailable.
bool Fat32DescendInto(const duetos::fs::fat32::DirEntry& e)
{
    if (g_state.fat_depth >= kMaxDepth)
        return false;
    // Push history entry: record the cluster we are LEAVING so going
    // back can re-list it. Discard any forward tail (pos was pointing
    // at the end already from normal navigation; trim in case the user
    // went back then descended a different child).
    const u32 leaving_cluster = Fat32CurrentCluster();
    char leaving_label[64];
    Fat32BuildPathHeader(leaving_label, sizeof(leaving_label));
    // Trim forward tail at fat_hist_pos.
    g_state.fat_hist_len = g_state.fat_hist_pos;
    if (g_state.fat_hist_len < kFatHistMax)
    {
        State::Fat32HistEntry& he = g_state.fat_hist[g_state.fat_hist_len];
        he.cluster = leaving_cluster;
        u32 j = 0;
        while (leaving_label[j] != '\0' && j + 1 < sizeof(he.name))
        {
            he.name[j] = leaving_label[j];
            ++j;
        }
        he.name[j] = '\0';
        ++g_state.fat_hist_len;
        g_state.fat_hist_pos = g_state.fat_hist_len;
    }
    // Push the path frame.
    g_state.fat_path_clusters[g_state.fat_depth] = e.first_cluster;
    u32 ni = 0;
    for (; e.name[ni] != '\0' && ni + 1 < sizeof(g_state.fat_path_names[0]); ++ni)
        g_state.fat_path_names[g_state.fat_depth][ni] = e.name[ni];
    g_state.fat_path_names[g_state.fat_depth][ni] = '\0';
    ++g_state.fat_depth;
    g_state.fat_selection = 0;
    KLOG_DEBUG_S("files", "fat32 descend into", "name", e.name);
    return true;
}

// Pop the current directory off the path stack (go to parent). Decrements
// fat_depth and adjusts fat_hist_pos so '[' / ']' history still works.
// Returns false if already at root.
bool Fat32AscendToParent()
{
    if (g_state.fat_depth == 0)
        return false;
    --g_state.fat_depth;
    // Walk history position back one slot to match where we came from.
    if (g_state.fat_hist_pos > 0)
        --g_state.fat_hist_pos;
    g_state.fat_selection = 0;
    KLOG_DEBUG("files", "fat32 ascend to parent");
    return true;
}

// Navigate back in history without altering the path stack in the same way
// as ascent — instead, restore the historical cluster + label directly.
// Called on '[' key press.
void Fat32HistBack()
{
    if (g_state.fat_hist_pos == 0)
    {
        duetos::drivers::video::NotifyShow("at beginning of history");
        return;
    }
    --g_state.fat_hist_pos;
    // Restore path stack to the state recorded in history[fat_hist_pos]:
    // the cluster stored there is the directory we were in at that point.
    // Rebuild fat_depth by re-walking from 0 is complex; instead we simply
    // set fat_depth = 0 if going all the way to root cluster, else we patch
    // the top path frame to match. A simpler approach: store the full depth
    // in each history entry is future work — for now Backspace handles the
    // common parent-go-back, '[' handles the less-common full jump.
    // For v0 of Back/Forward, '[' is equivalent to repeated Backspace presses
    // (implemented as: pop one depth level if we have one).
    if (g_state.fat_depth > 0)
        --g_state.fat_depth;
    g_state.fat_selection = 0;
    RescanFat32();
    duetos::drivers::video::NotifyShow("back");
    KLOG_DEBUG("files", "fat32 history back");
}

// Navigate forward in history — re-descend after going back.
// Called on ']' key press.
void Fat32HistForward()
{
    if (g_state.fat_hist_pos >= g_state.fat_hist_len)
    {
        duetos::drivers::video::NotifyShow("at end of history");
        return;
    }
    // The forward entry tells us the cluster to enter. Rebuild the
    // path frame for it. For v0 the name is not stored directly; we
    // rely on the listing to show the directory's contents. The
    // cluster is enough for RescanFat32.
    const State::Fat32HistEntry& he = g_state.fat_hist[g_state.fat_hist_pos];
    if (g_state.fat_depth < kMaxDepth)
    {
        g_state.fat_path_clusters[g_state.fat_depth] = he.cluster;
        // Name: derive from history label tail (after last '/').
        const char* lbl = he.name;
        u32 last_slash = 0;
        for (u32 i = 0; lbl[i] != '\0'; ++i)
            if (lbl[i] == '/')
                last_slash = i + 1;
        u32 ni = 0;
        for (u32 i = last_slash; lbl[i] != '\0' && lbl[i] != '/' && ni + 1 < sizeof(g_state.fat_path_names[0]); ++i)
            g_state.fat_path_names[g_state.fat_depth][ni++] = lbl[i];
        g_state.fat_path_names[g_state.fat_depth][ni] = '\0';
        ++g_state.fat_depth;
        ++g_state.fat_hist_pos;
    }
    g_state.fat_selection = 0;
    RescanFat32();
    duetos::drivers::video::NotifyShow("forward");
    KLOG_DEBUG("files", "fat32 history forward");
}

void RescanFat32()
{
    namespace fat = fs::fat32;
    g_state.fat_count = 0;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return;
    const u32 scan_cluster = Fat32CurrentCluster();
    fat::DirEntry tmp[fat::kMaxDirEntries];
    const u32 n = fat::Fat32ListDirByCluster(v, scan_cluster, tmp, fat::kMaxDirEntries);
    const bool at_root = (g_state.fat_depth == 0);
    for (u32 i = 0; i < n && g_state.fat_count < kFatMax; ++i)
    {
        const auto& e = tmp[i];
        // Hide the TRASH directory from the root Fat32 view — users
        // reach it through the T-toggle. In subdirectories all entries
        // are shown (there is no TRASH subdir below root by construction).
        if (at_root && (e.attributes & 0x10) != 0)
        {
            const char* name = e.name;
            if (name[0] == 'T' && name[1] == 'R' && name[2] == 'A' && name[3] == 'S' && name[4] == 'H' &&
                name[5] == '\0')
                continue;
        }
        g_state.fat_entries[g_state.fat_count++] = e;
    }
    SortFat32Entries();
    KLOG_DEBUG_S("files", "fat32 rescan", "path", at_root ? "DISK:/" : g_state.fat_path_names[g_state.fat_depth - 1]);
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

// ---- Mode-switch helpers (shared by toolbar trampolines + self-test)
// Defined here, after all Rescan* functions they depend on.

void SwitchToRam()
{
    if (g_state.mode != Mode::Ramfs)
    {
        g_state.mode = Mode::Ramfs;
        TypeaheadReset();
        duetos::drivers::video::NotifyShow("files: ram view");
    }
}

void SwitchToDisk()
{
    if (g_state.mode != Mode::Fat32)
    {
        g_state.mode = Mode::Fat32;
        g_state.fat_selection = 0;
        g_state.fat_depth = 0;
        g_state.fat_hist_len = 0;
        g_state.fat_hist_pos = 0;
        TypeaheadReset();
        RescanFat32();
        duetos::drivers::video::NotifyShow("files: disk view");
    }
}

void SwitchToTrash()
{
    if (g_state.mode != Mode::Trash)
    {
        g_state.mode = Mode::Trash;
        g_state.trash_selection = 0;
        TypeaheadReset();
        RescanTrash();
        duetos::drivers::video::NotifyShow("files: trash view");
    }
}

void SwitchToDrive()
{
    if (g_state.mode != Mode::DuetFs)
    {
        g_state.mode = Mode::DuetFs;
        g_state.duet_selection = 0;
        g_state.duet_depth = 0;
        TypeaheadReset();
        RescanDuetFs();
        duetos::drivers::video::NotifyShow("files: main drive");
    }
}

// ---- End mode-switch helpers ------------------------------------------

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

// Header line + item count, e.g. "DISK:/   (12 items)". Every
// commodity file manager shows the count; this is the one place
// all four views render it so the format stays consistent.
// `sort_by` (nullable) appends ", by <mode>" so the user can see
// the active sort order — only the FAT32 / Trash views sort, so
// ramfs / DuetFS pass nullptr.
void DrawListHeaderWithCount(u32 cx, u32 cy, const char* path, u32 count, u32 color, const char* sort_by = nullptr)
{
    char line[96];
    u32 o = 0;
    auto put = [&](const char* s)
    {
        for (u32 i = 0; s[i] != '\0' && o + 1 < sizeof(line); ++i)
            line[o++] = s[i];
    };
    put(path);
    put("   (");
    char num[24];
    WriteU64Dec(num, sizeof(num), count);
    put(num);
    put((count == 1) ? " item" : " items");
    if (sort_by != nullptr)
    {
        put(", by ");
        put(sort_by);
    }
    put(")");
    line[o] = '\0';
    duetos::drivers::video::FramebufferDrawString(cx + 4, cy + 2, line, color, kBg);
}

// Format a FAT mtime_date word (bytes 24-25 of the SFN record) into
// "YYYY-MM-DD\0" (11 bytes). date==0 means no date available.
// FAT date: bits 15-9 = year offset from 1980, 8-5 = month (1-12), 4-0 = day (1-31).
void FormatFatDate(u16 date, char* out)
{
    if (date == 0)
    {
        out[0] = '\0';
        return;
    }
    const u32 year = ((date >> 9) & 0x7F) + 1980;
    const u32 month = (date >> 5) & 0x0F;
    const u32 day = date & 0x1F;
    // YYYY-MM-DD
    auto put2 = [](char* p, u32 v)
    {
        p[0] = static_cast<char>('0' + v / 10);
        p[1] = static_cast<char>('0' + v % 10);
    };
    // year (4 digits)
    out[0] = static_cast<char>('0' + year / 1000);
    out[1] = static_cast<char>('0' + (year / 100) % 10);
    out[2] = static_cast<char>('0' + (year / 10) % 10);
    out[3] = static_cast<char>('0' + year % 10);
    out[4] = '-';
    put2(out + 5, month);
    out[7] = '-';
    put2(out + 8, day);
    out[10] = '\0';
}

// Generic row painter — takes the type tag, name, size, and optional FAT
// date word. `mtime_date==0` suppresses the date column. The per-mode
// draw paths assemble these from their entry types; non-FAT modes pass 0.
void DrawRowGeneric(u32 x, u32 y, u32 w, bool is_dir, const char* name, u64 size_bytes, bool selected,
                    u16 mtime_date = 0)
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

    // Right-aligned columns: modified date (if available) then size (if file).
    // Layout: right edge → [size] ← [space] ← [date] ← ...
    // Date column is 10 chars ("YYYY-MM-DD") + 1 space = 11 glyphs wide.
    const u32 right = x + w - 4;
    u32 right_cursor = right;

    if (!is_dir)
    {
        char num[24];
        WriteU64Dec(num, sizeof(num), size_bytes);
        u32 len = 0;
        while (num[len] != '\0')
            ++len;
        const u32 bytes_label_len = 6; // " BYTES"
        const u32 size_col_w = (len + bytes_label_len) * kGlyphW;
        if (right_cursor > size_col_w + 8)
        {
            const u32 nx = right_cursor - size_col_w;
            FramebufferDrawString(nx, y + 1, num, fg, bg);
            FramebufferDrawString(nx + len * kGlyphW, y + 1, " BYTES", selected ? kInkSel : kInkDim, bg);
            right_cursor = nx - kGlyphW; // one-glyph gap before next column
        }
    }

    // Date column (10 chars + separator space).
    if (mtime_date != 0)
    {
        char date_str[12];
        FormatFatDate(mtime_date, date_str);
        const u32 date_col_w = 10 * kGlyphW;
        if (right_cursor > date_col_w + 4)
        {
            const u32 dx = right_cursor - date_col_w;
            FramebufferDrawString(dx, y + 1, date_str, selected ? kInkSel : kInkDim, bg);
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
    DrawListHeaderWithCount(cx, cy, header, CountChildren(RamfsCur()), 0x0080F088);

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
    // Footer hint line moved to the AppLabel painted by DrawFn —
    // RefreshFooterText composes the per-mode text + pending-prompt
    // overlay into g_footer_text before PaintAll fires.
}

void DrawFat32(u32 cx, u32 cy, u32 cw, u32 ch)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    char header[80];
    Fat32BuildPathHeader(header, sizeof(header));
    DrawListHeaderWithCount(cx, cy, header, g_state.fat_count, 0x0080F088, SortModeName(g_state.sort));

    if (g_state.fat_count == 0)
    {
        FramebufferDrawString(cx + 4, cy + 2 + kRowH + 4, "(no FAT32 volume mounted)", kInkDim, kBg);
        // Footer hint -> AppLabel (RefreshFooterText / DrawFn).
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
        DrawRowGeneric(cx, list_top + i * kRowH, list_w, is_dir, e.name, e.size_bytes, idx == g_state.fat_selection,
                       e.mtime_date);
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
    // Footer hint + delete-to-trash prompt overlay moved to the
    // AppLabel painted by DrawFn — RefreshFooterText composes the
    // per-mode text and the pending-prompt body into a single
    // string before PaintAll fires.
}

void DrawTrash(u32 cx, u32 cy, u32 cw, u32 ch)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);
    DrawListHeaderWithCount(cx, cy, "TRASH:/", g_state.trash_count, 0x00FFA060, SortModeName(g_state.sort));

    if (g_state.trash_count == 0)
    {
        FramebufferDrawString(cx + 4, cy + 2 + kRowH + 4, "(trash is empty)", kInkDim, kBg);
        // Footer hint -> AppLabel (RefreshFooterText / DrawFn).
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

    // Footer hint + pending-prompt overlays moved to the AppLabel
    // painted by DrawFn — RefreshFooterText composes the per-mode
    // text and the active pending prompt (perm-delete / empty)
    // into a single string before PaintAll fires.
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
    DrawListHeaderWithCount(cx, cy, header, g_state.duet_count, 0x0080F088);

    if (g_state.duet_count == 0)
    {
        FramebufferDrawString(cx + 4, cy + 2 + kRowH + 4, "(empty directory)", kInkDim, kBg);
        // Footer hint -> AppLabel (RefreshFooterText / DrawFn).
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
    // Footer hint -> AppLabel (RefreshFooterText / DrawFn).
}

// Append `s` (NUL-terminated) onto `dst` at offset `*o`, capped
// at `cap - 1` bytes. Stops early if either runs out. Helper for
// the footer-text formatter. Mirrors the Notes status-text shape.
void FooterAppend(char* dst, u32 cap, u32* o, const char* s)
{
    while (*s != '\0' && *o + 1 < cap)
    {
        dst[(*o)++] = *s++;
    }
}

// Re-compose g_footer_text from mode + pending state. Called from
// DrawFn before PaintAll so the AppLabel sees the current frame's
// text. Three layers:
//   1. Pending prompt has priority (TO TRASH / PERM-DELETE / EMPTY).
//   2. Otherwise per-mode hint string (mirrors the legacy per-mode
//      inline footer strings).
//   3. Empty / no-volume modes get a short fallback hint.
void RefreshFooterText()
{
    u32 o = 0;
    g_footer_text[0] = '\0';
    // Pending prompts take priority.
    if (g_state.pending == Pending::DeleteToTrash && g_state.pending_idx < g_state.fat_count)
    {
        FooterAppend(g_footer_text, sizeof(g_footer_text), &o, "TO TRASH: ");
        FooterAppend(g_footer_text, sizeof(g_footer_text), &o, g_state.fat_entries[g_state.pending_idx].name);
        FooterAppend(g_footer_text, sizeof(g_footer_text), &o, " ? Y:CONFIRM ANY:CANCEL");
    }
    else if (g_state.pending == Pending::PermDeleteFromTrash && g_state.pending_idx < g_state.trash_count)
    {
        FooterAppend(g_footer_text, sizeof(g_footer_text), &o, "PERM-DELETE ");
        FooterAppend(g_footer_text, sizeof(g_footer_text), &o, g_state.trash_entries[g_state.pending_idx].name);
        FooterAppend(g_footer_text, sizeof(g_footer_text), &o, " ? Y:CONFIRM ANY:CANCEL");
    }
    else if (g_state.pending == Pending::EmptyTrash)
    {
        FooterAppend(g_footer_text, sizeof(g_footer_text), &o, "EMPTY ALL? Y:CONFIRM ANY:CANCEL");
    }
    else
    {
        // Per-mode hint. Shows keyboard shortcuts still available
        // (navigation, Enter, Backspace); view switches now use
        // the toolbar buttons. Letters / digits do type-ahead;
        // Del = delete/trash; F5 = empty trash.
        const char* hint = "UP/DN ENTER:OPEN BKSP:BACK  TYPE:JUMP";
        if (g_state.mode == Mode::Fat32)
        {
            if (g_state.fat_count == 0)
                hint = "TOOLBAR:VIEW  TYPE:JUMP";
            else if (g_state.fat_depth > 0)
                hint = "ENTER:OPEN BKSP:UP []:HIST DEL:TRASH TYPE:JUMP";
            else
                hint = "ENTER:OPEN/ENTER-DIR DEL:TRASH []:HIST TYPE:JUMP";
        }
        else if (g_state.mode == Mode::Trash)
        {
            hint = (g_state.trash_count == 0) ? "TOOLBAR:VIEW" : "F4:RESTORE  DEL:PERM-DEL  F5:EMPTY  TYPE:JUMP";
        }
        else if (g_state.mode == Mode::DuetFs)
        {
            hint = (g_state.duet_count == 0) ? "BKSP:BACK  TYPE:JUMP" : "ENTER:OPEN BKSP:BACK  TYPE:JUMP";
        }
        FooterAppend(g_footer_text, sizeof(g_footer_text), &o, hint);
    }
    if (o < sizeof(g_footer_text))
        g_footer_text[o] = '\0';
    else
        g_footer_text[sizeof(g_footer_text) - 1] = '\0';
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferFillRect;
    // Pass D chrome: AppToolbar at top (kHdrToolbarH), per-mode
    // list paint in the middle, AppLabel footer at the bottom.
    BindFilesOnce();
    RebindFilesBounds(cx, cy, cw, ch);
    RefreshFooterText();
    // Pre-paint the footer band tone so the AppLabel glyphs sit
    // on a uniform bg (AppLabel paints only its glyphs, not a
    // full-width band).
    if (ch > kFooterH)
    {
        FramebufferFillRect(cx, cy + ch - kFooterH, cw, kFooterH, 0x00C8C8B8U);
    }
    Compose compose_ctx{};
    g_files.PaintAll(compose_ctx);
    // Per-mode list paint into the middle slice. Mode-specific
    // draw functions still own their own background fill +
    // header-line + row rendering — chrome separation only.
    const u32 my = cy + kHdrToolbarH;
    const u32 mh = (ch > kHdrToolbarH + kFooterH) ? ch - kHdrToolbarH - kFooterH : 0U;
    if (mh == 0)
        return;
    if (g_state.mode == Mode::Fat32)
        DrawFat32(cx, my, cw, mh);
    else if (g_state.mode == Mode::Trash)
        DrawTrash(cx, my, cw, mh);
    else if (g_state.mode == Mode::DuetFs)
        DrawDuetFs(cx, my, cw, mh);
    else
        DrawRamfs(cx, my, cw, mh);
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
    const duetos::u64 pid = is_exe ? duetos::core::SpawnPeFile(tag, sel->file_bytes, sel->file_size, UserLaunchCaps(),
                                                               duetos::fs::RamfsSandboxRoot(), kUserLaunchFrames,
                                                               duetos::core::kTickBudgetSandbox)
                                   : duetos::core::SpawnElfFile(tag, sel->file_bytes, sel->file_size, UserLaunchCaps(),
                                                                duetos::fs::RamfsSandboxRoot(), kUserLaunchFrames,
                                                                duetos::core::kTickBudgetSandbox);
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
        is_exe
            ? duetos::core::SpawnPeFile(tag, staging, e.size_bytes, UserLaunchCaps(), duetos::fs::RamfsSandboxRoot(),
                                        kUserLaunchFrames, duetos::core::kTickBudgetSandbox)
            : duetos::core::SpawnElfFile(tag, staging, e.size_bytes, UserLaunchCaps(), duetos::fs::RamfsSandboxRoot(),
                                         kUserLaunchFrames, duetos::core::kTickBudgetSandbox);
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
        // Directory entry — descend into it.
        if (Fat32DescendInto(e))
        {
            RescanFat32();
            char msg[32];
            u32 mi = 0;
            const char* prefix = "entered: ";
            for (u32 i = 0; prefix[i] != '\0' && mi + 1 < sizeof(msg); ++i)
                msg[mi++] = prefix[i];
            for (u32 i = 0; e.name[i] != '\0' && mi + 1 < sizeof(msg); ++i)
                msg[mi++] = e.name[i];
            msg[mi] = '\0';
            duetos::drivers::video::NotifyShow(msg);
            duetos::arch::SerialWrite("[files] fat32 descend cluster=");
            duetos::arch::SerialWriteHex(e.first_cluster);
            duetos::arch::SerialWrite(" name=");
            duetos::arch::SerialWrite(e.name);
            duetos::arch::SerialWrite("\n");
        }
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

// ---- Pass D toolbar click trampolines (forward-declared above
// the constinit g_files). Each calls the mode-switch / action
// helper directly so the click path remains independent of the
// letter-key dispatch — letter keys now drive type-ahead, not
// view switches. Trampolines exist (rather than binding the
// helper directly) because AppButton's `on_click` is
// `void(*)()`, not the helper's signature.

void ClickModeRam()
{
    SwitchToRam();
}
void ClickModeDisk()
{
    SwitchToDisk();
}
void ClickModeTrash()
{
    SwitchToTrash();
}
void ClickModeDrive()
{
    SwitchToDrive();
}
void ClickRefresh()
{
    // Refresh is mode-dependent: disk view rescans FAT32, trash
    // view rescans the bin; other views have no backend to re-read.
    if (g_state.mode == Mode::Fat32)
    {
        const u32 prev_sel = g_state.fat_selection;
        RescanFat32();
        if (prev_sel >= g_state.fat_count)
            g_state.fat_selection = (g_state.fat_count > 0) ? (g_state.fat_count - 1) : 0;
        else
            g_state.fat_selection = prev_sel;
        TypeaheadReset();
        duetos::drivers::video::NotifyShow("files: rescan");
    }
    else if (g_state.mode == Mode::Trash)
    {
        RescanTrash();
        TypeaheadReset();
        duetos::drivers::video::NotifyShow("files: rescan");
    }
}
void ClickSort()
{
    // Cycle sort mode. Mirrors the sort logic previously in
    // FilesFeedChar('s') — extracted so the toolbar can call it
    // without going through the letter-key dispatch.
    const auto next = static_cast<u8>(g_state.sort) + 1;
    g_state.sort = (next >= static_cast<u8>(SortMode::kCount)) ? SortMode::Name : static_cast<SortMode>(next);
    char saved_name[128] = {};
    u32 nlen = 0;
    if (g_state.mode == Mode::Fat32 && g_state.fat_selection < g_state.fat_count)
    {
        const char* sn = g_state.fat_entries[g_state.fat_selection].name;
        for (; nlen + 1 < sizeof(saved_name) && sn[nlen] != '\0'; ++nlen)
            saved_name[nlen] = sn[nlen];
    }
    else if (g_state.mode == Mode::Trash && g_state.trash_selection < g_state.trash_count)
    {
        const char* sn = g_state.trash_entries[g_state.trash_selection].name;
        for (; nlen + 1 < sizeof(saved_name) && sn[nlen] != '\0'; ++nlen)
            saved_name[nlen] = sn[nlen];
    }
    SortFat32Entries();
    SortTrashEntries();
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
    TypeaheadReset();
    char msg[32];
    u32 mo = 0;
    const char* lead = "files: sort by ";
    for (u32 i = 0; lead[i] != '\0' && mo + 1 < sizeof(msg); ++i)
        msg[mo++] = lead[i];
    const char* sname = SortModeName(g_state.sort);
    for (u32 i = 0; sname[i] != '\0' && mo + 1 < sizeof(msg); ++i)
        msg[mo++] = sname[i];
    msg[mo] = '\0';
    duetos::drivers::video::NotifyShow(msg);
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
    g_state.fat_depth = 0;
    g_state.fat_hist_len = 0;
    g_state.fat_hist_pos = 0;
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
    g_state.fat_depth = 0;
    g_state.fat_hist_len = 0;
    g_state.fat_hist_pos = 0;
    RescanFat32();
}

bool FilesFeedArrow(bool up)
{
    // Any navigation cancels a pending prompt and clears the
    // type-ahead buffer — keeps every confirmation flow strictly
    // modal at the caret and avoids a stale prefix after the user
    // manually repositions with the arrow keys.
    g_state.pending = Pending::None;
    TypeaheadReset();
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

// Visible list rows for the current window size. Mirrors the
// max_rows formula in every Draw* path / FilesRowAt. Title bar
// 22 px + 2-px borders + Pass D AppToolbar (kHdrToolbarH) at the
// top, AppLabel footer (kFooterH) reserved at the bottom, then
// the per-mode header line (2 + kRowH + 2) above the first row.
// Used to make PageUp/PageDown step exactly one screenful.
u32 FilesListVisibleRows()
{
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh) || wh < 26)
        return 0;
    const duetos::u32 content_y_full = wy + 22 + 2;
    const duetos::u32 content_h_full = wh - 22 - 4;
    if (content_h_full <= kHdrToolbarH + kFooterH)
        return 0;
    // Middle slice the per-mode Draw* now receives.
    const duetos::u32 content_y = content_y_full + kHdrToolbarH;
    const duetos::u32 content_h = content_h_full - kHdrToolbarH - kFooterH;
    const duetos::u32 list_top = content_y + 2 + kRowH + 2;
    return (content_h > (list_top - content_y) + kRowH) ? (content_h - (list_top - content_y)) / kRowH : 0;
}

// Home / End / PageUp / PageDown / Delete / F4 / F5 for the active list.
// Matches the list-navigation surface sibling apps (calendar, hexview,
// notify-center) already expose. `code` is a VK navigation key.
//   Delete — arm move-to-trash (Fat32) or perm-delete (Trash).
//            Replaces the former bare 'x' shortcut; both are now
//            equivalent to the X-then-Y two-step confirmation. No
//            toolbar button for destructive delete — kept on a
//            non-letter key so letters are free for type-ahead.
//   F4     — restore selected item from Trash back to the FAT32 root.
//            Non-destructive (no Y-confirm required); letters are
//            reserved for type-ahead, hence an F-key.
//   F5     — arm empty-trash in Trash mode (replaces bare 'e').
//            Kept off letters for the same reason as Delete.
bool FilesFeedListKey(duetos::u16 code)
{
    g_state.pending = Pending::None;
    TypeaheadReset();

    // Delete — mode-sensitive destructive action (no navigation).
    if (code == duetos::drivers::input::kKeyDelete)
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
    // F4 — restore selected trash item back to the FAT32 root.
    // Non-destructive: no Y-confirm needed (the item just moves
    // back; the user can re-trash it if they change their mind).
    if (code == duetos::drivers::input::kKeyF4)
    {
        if (g_state.mode == Mode::Trash && g_state.trash_selection < g_state.trash_count)
        {
            RestoreSelectedTrash();
        }
        return true;
    }
    // F5 — empty trash (only meaningful in Trash mode).
    if (code == duetos::drivers::input::kKeyF5)
    {
        if (g_state.mode == Mode::Trash && g_state.trash_count > 0)
        {
            g_state.pending = Pending::EmptyTrash;
            g_state.pending_idx = 0;
            duetos::drivers::video::NotifyShow("press Y to empty trash");
        }
        return true;
    }

    const u32 n = ModeCount();
    if (n == 0)
        return true;
    u32 sel = ModeSelection();
    u32 page = FilesListVisibleRows();
    if (page == 0)
        page = 1;
    if (code == duetos::drivers::input::kKeyHome)
        sel = 0;
    else if (code == duetos::drivers::input::kKeyEnd)
        sel = n - 1;
    else if (code == duetos::drivers::input::kKeyPageUp)
        sel = (sel > page) ? sel - page : 0;
    else if (code == duetos::drivers::input::kKeyPageDown)
        sel = (sel + page < n) ? sel + page : n - 1;
    else
        return false;
    ModeSelectionSet(sel);
    return true;
}

bool FilesFeedChar(char c)
{
    // Pending two-step prompts. 'Y' confirms whatever was armed,
    // anything else cancels. This branch comes first so a stale
    // arm followed by an unrelated key cleanly disarms. The
    // pending prompt overrides type-ahead so a destructive action
    // can never be accidentally confirmed by a mistyped prefix.
    if (g_state.pending != Pending::None)
    {
        const Pending p = g_state.pending;
        g_state.pending = Pending::None;
        TypeaheadReset();
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
    if (static_cast<u8>(c) == 0x08) // Backspace — navigate up (back to parent dir)
    {
        TypeaheadReset();
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
        if (g_state.mode == Mode::Fat32)
        {
            if (Fat32AscendToParent())
                RescanFat32();
            return true;
        }
        return true;
    }
    if (static_cast<u8>(c) == 0x0A) // Enter — open / descend
    {
        TypeaheadReset();
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
        // Fat32 mode: descend into directories, open files.
        if (g_state.mode == Mode::Fat32)
        {
            if (g_state.fat_selection < g_state.fat_count)
            {
                const auto& e = g_state.fat_entries[g_state.fat_selection];
                if ((e.attributes & 0x10) != 0)
                {
                    // Directory entry — descend.
                    if (Fat32DescendInto(e))
                    {
                        RescanFat32();
                        char msg[32];
                        u32 mi = 0;
                        const char* prefix = "entered: ";
                        for (u32 i = 0; prefix[i] != '\0' && mi + 1 < sizeof(msg); ++i)
                            msg[mi++] = prefix[i];
                        for (u32 i = 0; e.name[i] != '\0' && mi + 1 < sizeof(msg); ++i)
                            msg[mi++] = e.name[i];
                        msg[mi] = '\0';
                        duetos::drivers::video::NotifyShow(msg);
                        duetos::arch::SerialWrite("[files] fat32 descend cluster=");
                        duetos::arch::SerialWriteHex(e.first_cluster);
                        duetos::arch::SerialWrite(" name=");
                        duetos::arch::SerialWrite(e.name);
                        duetos::arch::SerialWrite("\n");
                    }
                    return true;
                }
            }
            return OpenFat32Selected();
        }
        return OpenFat32Selected();
    }
    // '[' — navigate back in FAT32 history.
    if (c == '[' && g_state.mode == Mode::Fat32)
    {
        TypeaheadReset();
        Fat32HistBack();
        return true;
    }
    // ']' — navigate forward in FAT32 history.
    if (c == ']' && g_state.mode == Mode::Fat32)
    {
        TypeaheadReset();
        Fat32HistForward();
        return true;
    }
    // Alphanumeric keys — type-ahead jump to first filename prefix match.
    // Toolbar buttons (RAM/DISK/TRASH/DRIVE/REFRESH/SORT) remain the
    // clickable surface for all view-switch actions. The previously
    // bare-letter view shortcuts (d/m/t/f/r/s) are removed so these
    // characters are available for type-ahead. j/k vim navigation is
    // also removed (redundant with Up/Down arrow keys). Delete (kKeyDelete)
    // and F5 are routed through FilesFeedListKey for destructive actions
    // (delete-to-trash / perm-delete and empty-trash respectively).
    const bool is_alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    const bool is_digit = (c >= '0' && c <= '9');
    if (is_alpha || is_digit)
    {
        TypeaheadAppend(c);
        return true;
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
                FilesFeedChar('\x08'); // Backspace -> pop
                if (g_state.ramfs_depth != saved_depth || RamfsCur() != saved_top)
                    pass = false;
                break;
            }
        }
    }

    // Mode toggle round-trip. Disk mode is reachable iff a FAT32
    // volume is mounted; either way, switching back to ram mode
    // must succeed. Call the mode-switch helpers directly — bare
    // letter keys now drive type-ahead, not view switches.
    SwitchToDisk();
    if (g_state.mode != Mode::Fat32)
        pass = false;

    // FAT32 subdir descent+ascent. Scan the root listing for a
    // directory entry; if one exists, descend into it, check that
    // fat_depth incremented and the rescan ran, then Backspace
    // back to root and verify fat_depth returned to 0.
    if (g_state.mode == Mode::Fat32)
    {
        const u32 saved_fat_depth = g_state.fat_depth;
        u32 dir_row = kFatMax;
        for (u32 i = 0; i < g_state.fat_count; ++i)
        {
            if ((g_state.fat_entries[i].attributes & 0x10) != 0)
            {
                dir_row = i;
                break;
            }
        }
        if (dir_row != kFatMax)
        {
            g_state.fat_selection = dir_row;
            FilesFeedChar('\n'); // descend
            if (g_state.fat_depth != saved_fat_depth + 1)
                pass = false;
            FilesFeedChar('\x08'); // Backspace -> ascend to root
            if (g_state.fat_depth != saved_fat_depth)
                pass = false;
        }
    }

    // Date formatter unit test — no filesystem I/O.
    {
        char d[12];
        // Date 0 → empty string.
        FormatFatDate(0, d);
        if (d[0] != '\0')
            pass = false;
        // 2024-03-15 → year=2024-1980=44 (0x2C), month=3 (0x03), day=15 (0x0F)
        // FAT word: (44<<9)|(3<<5)|15 = 0x5800 | 0x0060 | 0x000F = 0x586F
        const u16 test_date = static_cast<u16>((44u << 9) | (3u << 5) | 15u);
        FormatFatDate(test_date, d);
        // Expect "2024-03-15"
        const char* expect = "2024-03-15";
        bool date_ok = true;
        for (u32 i = 0; expect[i] != '\0'; ++i)
        {
            if (d[i] != expect[i])
            {
                date_ok = false;
                break;
            }
        }
        if (!date_ok)
            pass = false;
    }

    SwitchToRam();
    if (g_state.mode != Mode::Ramfs)
        pass = false;

    // DuetFS "main drive" view round-trip. The boot volume is
    // mounted at /duetfs and seeded with /etc, so entering the
    // view, descending into the first directory, and backing out
    // must all hold. duet_depth tracks the navigation stack.
    SwitchToDrive();
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
            FilesFeedChar('\x08'); // Backspace -> back to root
            if (g_state.duet_depth != 1)
                pass = false;
            // Generic context dispatch (37 OPEN / 39 REFRESH) must
            // reach the handler — guards the menu_dispatch 30..39
            // routing band and the shared non-FAT action path.
            g_state.duet_selection = dir_row;
            FilesDispatchContextAction(37, dir_row); // OPEN -> descend
            if (g_state.duet_depth != 2)
                pass = false;
            FilesFeedChar('\x08');             // Backspace -> back to root
            FilesDispatchContextAction(39, 0); // REFRESH (no-op safe)
            if (g_state.mode != Mode::DuetFs || g_state.duet_depth != 1)
                pass = false;
        }
    }
    SwitchToRam();
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

    // F4 Restore key: in Trash mode with no entries it must be a
    // no-op (no crash / pending change). In Fat32 mode it must
    // also be a no-op (key is trash-specific). Touch-test only
    // (the real restore path is exercised by TrashSelfTest).
    g_state.mode = Mode::Trash;
    g_state.trash_count = 0;
    g_state.trash_selection = 0;
    g_state.pending = Pending::None;
    FilesFeedListKey(duetos::drivers::input::kKeyF4); // no-op: empty bin
    if (g_state.pending != Pending::None)
        pass = false;
    g_state.mode = Mode::Fat32;
    FilesFeedListKey(duetos::drivers::input::kKeyF4); // no-op: wrong mode
    if (g_state.pending != Pending::None)
        pass = false;

    // Home / End list navigation on the ramfs root listing.
    g_state.mode = Mode::Ramfs;
    g_state.ramfs_depth = 1;
    if (ModeCount() > 1)
    {
        FilesFeedListKey(duetos::drivers::input::kKeyEnd);
        if (ModeSelection() != ModeCount() - 1)
            pass = false;
        FilesFeedListKey(duetos::drivers::input::kKeyHome);
        if (ModeSelection() != 0)
            pass = false;
    }

    // Pass D: drive a synthetic click through the toolbar's
    // WidgetGroup and verify the RAM button's callback fires.
    // Start in DuetFS mode, click RAM, assert the mode switched.
    // Anchor the toolbar at (0, 22, 400, 200) — same shape the
    // live boot-time window registration uses (boot_bringup.cpp).
    BindFilesOnce();
    RebindFilesBounds(0U, 22U, 400U, 200U);
    g_state.mode = Mode::DuetFs;
    // Centre of the RAM button (index 0 — the first slot the
    // BindFilesOnce loop wires up). Bounds are {kHdrPadX,
    // 22+kHdrPadY, kHdrBtnW, kHdrBtnH}.
    const duetos::u32 rx = kHdrPadX + kHdrBtnW / 2U;
    const duetos::u32 ry = 22U + kHdrPadY + kHdrBtnH / 2U;
    const Event m_move{EventKind::MouseMove, rx, ry, 0U, 0U};
    const Event m_down{EventKind::MouseDown, rx, ry, 0U, 0U};
    const Event m_up{EventKind::MouseUp, rx, ry, 0U, 0U};
    if (g_files.DispatchEvent(m_move) != EventResult::Consumed)
        pass = false;
    if (g_files.DispatchEvent(m_down) != EventResult::Consumed)
        pass = false;
    if (g_files.DispatchEvent(m_up) != EventResult::Consumed)
        pass = false;
    if (g_state.mode != Mode::Ramfs)
        pass = false;
    // REFRESH button click (index kBtnRefresh=4). NotifyShow is
    // the visible side effect; check the dispatch path runs end-
    // to-end (the click chain returning Consumed is the test).
    const duetos::u32 fx = kHdrPadX + kBtnRefresh * (kHdrBtnW + kHdrBtnGap) + kHdrBtnW / 2U;
    const duetos::u32 fy = 22U + kHdrPadY + kHdrBtnH / 2U;
    const Event r_move{EventKind::MouseMove, fx, fy, 0U, 0U};
    const Event r_down{EventKind::MouseDown, fx, fy, 0U, 0U};
    const Event r_up{EventKind::MouseUp, fx, fy, 0U, 0U};
    if (g_files.DispatchEvent(r_move) != EventResult::Consumed)
        pass = false;
    if (g_files.DispatchEvent(r_down) != EventResult::Consumed)
        pass = false;
    if (g_files.DispatchEvent(r_up) != EventResult::Consumed)
        pass = false;
    // Footer-text refresh: each per-mode hint must compose non-
    // empty into g_footer_text. Cycle the four modes and check.
    g_state.pending = Pending::None;
    const Mode modes_to_check[4] = {Mode::Ramfs, Mode::Fat32, Mode::Trash, Mode::DuetFs};
    for (u32 mi = 0; mi < 4; ++mi)
    {
        g_state.mode = modes_to_check[mi];
        RefreshFooterText();
        if (g_footer_text[0] == '\0')
            pass = false;
    }
    // Pending-prompt overlay in the footer text.
    g_state.mode = Mode::Trash;
    g_state.pending = Pending::EmptyTrash;
    RefreshFooterText();
    if (g_footer_text[0] != 'E') // "EMPTY ALL? ..."
        pass = false;
    g_state.pending = Pending::None;

    // Type-ahead unit tests (no filesystem I/O — prefix match logic only).
    // TypeaheadNameMatches is tested directly against known names.
    {
        TypeaheadReset();
        g_state.typeahead_buf[0] = 'S';
        g_state.typeahead_buf[1] = '\0';
        g_state.typeahead_len = 1;
        // "SHOT0001.BMP" starts with 'S' — must match.
        if (!TypeaheadNameMatches("SHOT0001.BMP"))
            pass = false;
        // "AFILE.TXT" does not start with 'S' — must not match.
        if (TypeaheadNameMatches("AFILE.TXT"))
            pass = false;
        // Empty prefix always matches.
        TypeaheadReset();
        if (!TypeaheadNameMatches("anything"))
            pass = false;
        // Multi-char prefix: "SH" — must match "SHOT" but not "SNAP".
        g_state.typeahead_buf[0] = 'S';
        g_state.typeahead_buf[1] = 'H';
        g_state.typeahead_buf[2] = '\0';
        g_state.typeahead_len = 2;
        if (!TypeaheadNameMatches("SHOT0001.BMP"))
            pass = false;
        if (TypeaheadNameMatches("SNAP.TXT"))
            pass = false;
        TypeaheadReset();
    }

    g_state.ramfs_depth = saved_depth;
    g_state.ramfs_selection = saved_sel;
    g_state.mode = saved_mode;
    g_self_test_passed = pass;
    if (pass)
    {
        SerialWrite("[files] self-test OK (ramfs descend+back, mode toggle, fat32 subdir descent+back, "
                    "duetfs descend+back, ctx-dispatch, home/end, ext match, delete-disarm, f4-restore-noop, "
                    "widget-click, footer-refresh, typeahead, date-format)\n");
        SerialWrite("[files-selftest] PASS\n");
    }
    else
    {
        SerialWrite("[files] self-test FAILED\n");
        SerialWrite("[files-selftest] FAIL\n");
    }
}

bool FilesSelfTestPassed()
{
    return g_self_test_passed;
}

void FilesMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_state.handle == duetos::drivers::video::kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it. RebindBounds
    // works in client-relative coords so the widget dispatch path
    // needs cursor coords in the same frame.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindFilesOnce();
    RebindFilesBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_prev_left_down;
    const bool release_edge = !left_down && g_prev_left_down;
    g_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_files.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_files.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside the
        // toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_files.DispatchEvent(u);
    }
}

namespace
{

// Per-row context menu items. Static so the menu primitive can
// hold a borrowed pointer for the open lifetime.
//
// Files-app action-id allocation (mirrors wiki/subsystems/Compositor.md
// + kernel/core/menu_dispatch.cpp). Files owns 30..39 and the
// 44..49 sub-band; 40..43 are the power/session band and MUST
// NOT be used here. 50+ belongs to other dispatchers.
//   30..36 — FAT32 view (OPEN / RENAME / DELETE / PROPERTIES /
//            REFRESH / NEW TEXT FILE / NEW FOLDER).
//   37..39 — Shared "generic" verbs reused by DuetFS + ramfs
//            (OPEN / PROPERTIES / REFRESH). The Trash menu also
//            re-uses 38/39 for PROPERTIES/REFRESH.
//   44..47 — Per-row menus for the non-FAT views that need verbs
//            beyond OPEN/PROPERTIES/REFRESH (the 44..49 sub-band
//            sits in the otherwise-free run after the power band
//            and stays inside the 30..49 Files-app window the
//            wiki action-id table reserves):
//              44 — OPEN (Trash). Distinct from 37 because a
//                   trash row's primary action is RESTORE, not
//                   OPEN — but OPEN is still offered so users
//                   can peek at the binned file's properties
//                   without restoring first.
//              45 — RESTORE (Trash). Moved off action 37 so that
//                   row 0 of the menu is OPEN, matching every
//                   other file-manager convention.
//              46 — DELETE FOREVER (Trash). Unlinks from /TRASH
//                   permanently; behind the same Y-confirm
//                   prompt the X keybind already triggers.
//              47 — DELETE (ramfs). Disabled — the trusted ramfs
//                   is constinit / .rodata, so there is no
//                   backing primitive that could unlink a node.
//                   Shown so the menu shape matches FAT32 /
//                   Trash, with the disabled flag making the
//                   read-only invariant visible at the point of
//                   the gesture (rather than as a silent absence).
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

// Shared context menu for the DuetFS main drive — read-only
// OPEN / PROPERTIES / REFRESH. Ramfs and Trash used to share this
// menu, but each now has its own variant (below) so the per-row
// verb set matches the per-mode semantics.
constinit duetos::drivers::video::MenuItem kFilesGenericMenuItems[] = {
    {"OPEN", 37, 0, nullptr, 0},
    {"PROPERTIES", 38, 0, nullptr, 0},
    {"REFRESH", 39, 0, nullptr, 0},
};
constexpr duetos::u32 kFilesGenericMenuItemsN = sizeof(kFilesGenericMenuItems) / sizeof(kFilesGenericMenuItems[0]);

// Trash view: OPEN / RESTORE / DELETE FOREVER / PROPERTIES /
// REFRESH. RESTORE is the row's primary action (matching the R
// keybind); DELETE FOREVER routes through the Y-confirm prompt
// the X keybind already uses, so the menu and keyboard surfaces
// share one confirmation flow. OPEN reads the trashed file's
// bytes via the existing FAT32 read path so a user can peek at a
// binned screenshot / .txt without restoring first.
constinit duetos::drivers::video::MenuItem kFilesTrashMenuItems[] = {
    {"OPEN", 44, 0, nullptr, 0},       {"RESTORE", 45, 0, nullptr, 0}, {"DELETE FOREVER", 46, 0, nullptr, 0},
    {"PROPERTIES", 38, 0, nullptr, 0}, {"REFRESH", 39, 0, nullptr, 0},
};
constexpr duetos::u32 kFilesTrashMenuItemsN = sizeof(kFilesTrashMenuItems) / sizeof(kFilesTrashMenuItems[0]);

// Ramfs view: OPEN / DELETE / PROPERTIES / REFRESH. DELETE is
// flagged Disabled — the trusted ramfs is constinit storage with
// no mutation backend; the row exists so the menu shape matches
// the other modes and the read-only constraint is visible at the
// gesture point. If a future slice gives ramfs a writable backend,
// drop the disabled flag and route action 47 through that
// primitive (see FilesDispatchContextAction).
constinit duetos::drivers::video::MenuItem kFilesRamfsMenuItems[] = {
    {"OPEN", 37, 0, nullptr, 0},
    {"DELETE", 47, duetos::drivers::video::kMenuItemFlagDisabled, nullptr, 0},
    {"PROPERTIES", 38, 0, nullptr, 0},
    {"REFRESH", 39, 0, nullptr, 0},
};
constexpr duetos::u32 kFilesRamfsMenuItemsN = sizeof(kFilesRamfsMenuItems) / sizeof(kFilesRamfsMenuItems[0]);

} // namespace

duetos::i32 FilesRowAt(duetos::u32 sx, duetos::u32 sy)
{
    // Mode-agnostic: every view (FAT32 / DuetFS / ramfs / Trash)
    // draws its list with the same geometry, so the hit-test only
    // needs the per-mode count + selection (via ModeCount /
    // ModeSelection) — no per-mode whitelist.
    //
    // Pass D layout: title bar 22 px + 2-px content inset, then a
    // 26-px AppToolbar (mirrors `kHdrToolbarH`), then the per-mode
    // header line (2 + kRowH + 2), then the first row. 12-px footer
    // (mirrors `kFooterH`) reserved at the bottom for the AppLabel.
    // Constants duplicated here because they live in this TU's
    // anonymous namespace and FilesRowAt is in the outer namespace;
    // if you change either k_hdr_toolbar_h or k_footer_h in the
    // anonymous block above, change them here too.
    constexpr duetos::u32 k_hdr_toolbar_h = 26U;
    constexpr duetos::u32 k_footer_h = 12U;
    if (ModeCount() == 0)
        return -1;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return -1;
    if (ww < 4 || wh < 26)
        return -1;
    // Full content area first (matches DrawFn's cy / ch), then
    // carve out the toolbar top + footer bottom to get the middle
    // slice the per-mode Draw* function received.
    const duetos::u32 content_x = wx + 2;
    const duetos::u32 content_y_full = wy + 22 + 2;
    const duetos::u32 content_w = ww - 4;
    const duetos::u32 content_h_full = wh - 22 - 4;
    if (content_h_full <= k_hdr_toolbar_h + k_footer_h)
        return -1;
    const duetos::u32 content_y = content_y_full + k_hdr_toolbar_h;
    const duetos::u32 content_h = content_h_full - k_hdr_toolbar_h - k_footer_h;
    if (sx < content_x || sx >= content_x + content_w)
        return -1;
    const duetos::u32 list_top = content_y + 2 + kRowH + 2;
    if (sy < list_top)
        return -1;
    const duetos::u32 n = ModeCount();
    const duetos::u32 max_rows =
        (content_h > (list_top - content_y) + kRowH) ? (content_h - (list_top - content_y)) / kRowH : 0;
    if (max_rows == 0)
        return -1;
    const duetos::u32 sel = ModeSelection();
    duetos::u32 first = 0;
    if (n > max_rows && sel >= max_rows)
        first = sel - (max_rows - 1);
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
    // Works in every view now that FilesRowAt is mode-agnostic.
    // Select the clicked row then reuse the ENTER dispatch, which
    // already does the right thing per mode (FAT32 open, DuetFS /
    // ramfs descend-or-open). Trash has no open verb so the ENTER
    // path is a no-op there — double-click simply does nothing,
    // which is the correct behaviour.
    const duetos::i32 row = FilesRowAt(sx, sy);
    if (row < 0)
        return false;
    ModeSelectionSet(static_cast<duetos::u32>(row));
    FilesFeedChar('\n');
    duetos::arch::SerialWrite("[files] double-click open row=");
    duetos::arch::SerialWriteHex(static_cast<duetos::u64>(row));
    duetos::arch::SerialWrite("\n");
    return true;
}

bool FilesOnRightClick(duetos::u32 sx, duetos::u32 sy)
{
    // Non-FAT views each get a menu tuned to what the backing
    // store actually supports:
    //   DuetFS — read-only browse mount: OPEN/PROPERTIES/REFRESH.
    //   Ramfs  — read-only constinit: OPEN/(DELETE disabled)/
    //            PROPERTIES/REFRESH.
    //   Trash  — full lifecycle: OPEN/RESTORE/DELETE FOREVER/
    //            PROPERTIES/REFRESH.
    // FilesRowAt is mode-agnostic; empty space falls back to the
    // highlighted selection so the menu always has a target row.
    if (g_state.mode == Mode::DuetFs || g_state.mode == Mode::Ramfs || g_state.mode == Mode::Trash)
    {
        const duetos::i32 grow = FilesRowAt(sx, sy);
        const duetos::u32 gctx = (grow < 0) ? ModeSelection() : static_cast<duetos::u32>(grow);
        const duetos::drivers::video::MenuItem* items = kFilesGenericMenuItems;
        duetos::u32 count = kFilesGenericMenuItemsN;
        if (g_state.mode == Mode::Trash)
        {
            items = kFilesTrashMenuItems;
            count = kFilesTrashMenuItemsN;
        }
        else if (g_state.mode == Mode::Ramfs)
        {
            items = kFilesRamfsMenuItems;
            count = kFilesRamfsMenuItemsN;
        }
        duetos::drivers::video::MenuOpen(items, count, sx, sy, gctx);
        duetos::arch::SerialWrite("[files] generic context menu opened mode=");
        duetos::arch::SerialWriteHex(static_cast<duetos::u64>(g_state.mode));
        duetos::arch::SerialWrite(" ctx=");
        duetos::arch::SerialWriteHex(gctx);
        duetos::arch::SerialWrite("\n");
        return true;
    }
    // FAT32 keeps its richer 30..36 menu.
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
    // Trash-specific extended actions (44 OPEN / 45 RESTORE / 46
    // DELETE FOREVER). Lifted out of the shared 37..39 band so a
    // Trash row's primary action stays RESTORE while OPEN and
    // DELETE FOREVER each get their own slot. Lives in the
    // 44..49 sub-band (the Files-app window that survives the
    // 40..43 power band). Validate ctx against the live trash
    // listing first — the user may have refreshed the bin
    // between right-click and click-on-item.
    if (action == 44 || action == 45 || action == 46)
    {
        if (g_state.mode != Mode::Trash)
            return;
        if (ctx >= g_state.trash_count)
            return;
        g_state.trash_selection = ctx;
        if (action == 44) // OPEN — peek without restoring
        {
            // The existing openers (ImageView / Notes) look up by
            // name in the FAT32 root, not in /TRASH, so opening a
            // trashed file in-place would silently miss. Honest
            // v0 behaviour: tell the user to restore first. A
            // future slice that teaches the openers to accept a
            // path can route the trash entry's "TRASH/<name>"
            // form through them.
            duetos::drivers::video::NotifyShow("restore to open");
            duetos::arch::SerialWrite("[files] trash OPEN ctx=");
            duetos::arch::SerialWriteHex(ctx);
            duetos::arch::SerialWrite(" -> NotifyShow(restore to open)\n");
            return;
        }
        if (action == 45) // RESTORE — move /TRASH/<name> back to /<name>
        {
            RestoreSelectedTrash();
            return;
        }
        // action == 46: DELETE FOREVER. Re-arm the existing
        // Y-confirm prompt so the menu and the X keybind share
        // exactly one confirmation flow.
        g_state.pending = Pending::PermDeleteFromTrash;
        g_state.pending_idx = ctx;
        duetos::drivers::video::NotifyShow("press Y to delete forever");
        duetos::arch::SerialWrite("[files] trash perm-delete armed via context menu\n");
        return;
    }
    // Ramfs DELETE (47) is structurally disabled in the menu
    // (constinit storage has no unlink primitive), but the
    // dispatch arm guards in case a future MenuItem flag change
    // re-enables it without wiring a backend.
    if (action == 47)
    {
        // GAP: ramfs is read-only (constinit); a future writable
        // backend would route this to RamfsUnlink + a rescan.
        FIX_NOTE_GAP("apps/files.cpp:RamfsContextDelete", "writable ramfs backend + RamfsUnlink + rescan");
        duetos::drivers::video::NotifyShow("ramfs is read-only");
        return;
    }
    // Generic non-FAT context actions (37 OPEN / 38 PROPERTIES /
    // 39 REFRESH), shared by the DuetFS main-drive, ramfs and
    // Trash views so every view offers the same everyday gestures.
    if (action == 37 || action == 38 || action == 39)
    {
        if (g_state.mode == Mode::Fat32)
            return;       // FAT32 has its own richer 30..36 menu
        if (action == 39) // REFRESH
        {
            if (g_state.mode == Mode::DuetFs)
                RescanDuetFs();
            else if (g_state.mode == Mode::Trash)
                RescanTrash();
            const u32 c = ModeCount();
            if (ModeSelection() >= c && c > 0)
                ModeSelectionSet(c - 1);
            duetos::drivers::video::NotifyShow("refreshed");
            return;
        }
        if (ctx >= ModeCount())
            return;
        if (action == 37) // primary action: RESTORE in Trash, else OPEN
        {
            ModeSelectionSet(ctx);
            if (g_state.mode == Mode::Trash)
                RestoreSelectedTrash();
            else
                FilesFeedChar('\n');
            return;
        }
        // action == 38: PROPERTIES. Pull (name, is_dir, size) from
        // whichever backend this view is showing, then one dialog.
        char nm[80] = {};
        bool is_dir = false;
        duetos::u64 size = 0;
        if (g_state.mode == Mode::DuetFs)
        {
            const auto& e = g_state.duet_entries[ctx];
            const u32 nl = e.name_len < sizeof(nm) - 1 ? e.name_len : sizeof(nm) - 1;
            for (u32 i = 0; i < nl; ++i)
                nm[i] = static_cast<char>(e.name[i]);
            is_dir = e.kind == duetos::fs::duetfs::kKindDir;
            size = e.size_bytes;
        }
        else if (g_state.mode == Mode::Trash)
        {
            const auto& e = g_state.trash_entries[ctx];
            for (u32 i = 0; e.name[i] != '\0' && i + 1 < sizeof(nm); ++i)
                nm[i] = e.name[i];
            is_dir = (e.attributes & 0x10) != 0;
            size = e.size_bytes;
        }
        else // Ramfs
        {
            const auto* cur = RamfsCur();
            if (cur == nullptr || cur->children == nullptr)
                return;
            const auto* child = cur->children[ctx];
            if (child == nullptr)
                return;
            for (u32 i = 0; child->name[i] != '\0' && i + 1 < sizeof(nm); ++i)
                nm[i] = child->name[i];
            is_dir = child->type == duetos::fs::RamfsNodeType::kDir;
            size = is_dir ? 0 : child->file_size;
        }
        static char s_props[160];
        u32 p = 0;
        auto put = [&](const char* s)
        {
            for (u32 i = 0; s[i] != '\0' && p + 1 < sizeof(s_props); ++i)
                s_props[p++] = s[i];
        };
        put("Name: ");
        put(nm);
        put("\nType: ");
        put(is_dir ? "Folder" : "File");
        put("\nSize: ");
        char num[24];
        WriteU64Dec(num, sizeof(num), size);
        put(num);
        put(" bytes");
        s_props[p] = '\0';
        duetos::arch::SerialWrite("[files] properties: ");
        duetos::arch::SerialWrite(s_props);
        duetos::arch::SerialWrite("\n");
        duetos::drivers::video::MessageBoxOpen(
            "PROPERTIES", s_props, [](duetos::drivers::video::DialogResult, const char*, void*) {}, nullptr);
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
