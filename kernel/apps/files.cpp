#include "apps/files.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "fs/ramfs.h"

namespace duetos::apps::files
{

namespace
{

constexpr u32 kMaxDepth = 8;
constexpr u32 kGlyphW = 8;
constexpr u32 kRowH = 10;
constexpr u32 kInkFg = 0x00D0D8E0;
constexpr u32 kInkDim = 0x00707880;
constexpr u32 kInkSel = 0x00101020;
constexpr u32 kBg = 0x00101828;
constexpr u32 kSelBg = 0x00C0C888;

struct State
{
    duetos::drivers::video::WindowHandle handle;
    // Stack of directory nodes from root down to the current
    // view. depth == 1 at init (just the trusted root).
    const duetos::fs::RamfsNode* stack[kMaxDepth];
    u32 depth;
    // Selection index within the current directory's children
    // (the node at stack[depth-1]).
    u32 selection;
};

constinit State g_state = {duetos::drivers::video::kWindowInvalid, {}, 0, 0};

// Count children of a directory node. Children list is
// nullptr-terminated.
u32 CountChildren(const duetos::fs::RamfsNode* dir)
{
    if (dir == nullptr || dir->children == nullptr)
        return 0;
    u32 n = 0;
    while (dir->children[n] != nullptr)
        ++n;
    return n;
}

const duetos::fs::RamfsNode* Cur()
{
    if (g_state.depth == 0)
        return nullptr;
    return g_state.stack[g_state.depth - 1];
}

const duetos::fs::RamfsNode* SelectedChild()
{
    const duetos::fs::RamfsNode* cur = Cur();
    if (cur == nullptr || cur->children == nullptr)
        return nullptr;
    const u32 n = CountChildren(cur);
    if (g_state.selection >= n)
        return nullptr;
    return cur->children[g_state.selection];
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

void DrawRow(u32 x, u32 y, u32 w, const duetos::fs::RamfsNode* n, bool selected)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    if (selected)
        FramebufferFillRect(x, y, w, kRowH, kSelBg);
    else
        FramebufferFillRect(x, y, w, kRowH, kBg);
    const u32 fg = selected ? kInkSel : kInkFg;
    const u32 bg = selected ? kSelBg : kBg;
    const bool is_dir = (n->type == duetos::fs::RamfsNodeType::kDir);
    // "[D] " or "[F] " tag.
    const char* tag = is_dir ? "[D] " : "[F] ";
    FramebufferDrawString(x + 4, y + 1, tag, fg, bg);
    // Name.
    const char* name = (n->name != nullptr && n->name[0] != '\0') ? n->name : "(root)";
    FramebufferDrawString(x + 4 + 4 * kGlyphW, y + 1, name, fg, bg);
    // Size column for files. 10 columns right-aligned from the
    // right edge — rough, but fine for 8x8 fixed-width glyphs.
    if (!is_dir)
    {
        char num[24];
        WriteU64Dec(num, sizeof(num), n->file_size);
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

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);
    const duetos::fs::RamfsNode* cur = Cur();
    if (cur == nullptr)
    {
        FramebufferDrawString(cx + 4, cy + 4, "(no root)", kInkDim, kBg);
        return;
    }

    // Header line showing depth dots + "<dir>" or "<root>".
    char header[32];
    u32 h_off = 0;
    header[h_off++] = '/';
    if (g_state.depth > 1)
    {
        // Show the last directory name after a trailing slash.
        for (u32 i = 1; i < g_state.depth; ++i)
        {
            const char* nm = g_state.stack[i]->name;
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

    // List rows starting below the header.
    const u32 list_top = cy + 2 + kRowH + 2;
    const u32 n = CountChildren(cur);
    const u32 max_rows = (ch > (list_top - cy) + kRowH) ? (ch - (list_top - cy)) / kRowH : 0;
    // Window the list around the selection so it stays in view.
    u32 first = 0;
    if (n > max_rows && g_state.selection >= max_rows)
        first = g_state.selection - (max_rows - 1);
    for (u32 i = 0; i < max_rows && first + i < n; ++i)
    {
        const u32 idx = first + i;
        const duetos::fs::RamfsNode* child = cur->children[idx];
        if (child == nullptr)
            break;
        DrawRow(cx, list_top + i * kRowH, cw, child, idx == g_state.selection);
    }
    // Footer hint.
    if (ch > kRowH + 2)
    {
        FramebufferDrawString(cx + 4, cy + ch - kRowH - 1, "UP/DN  ENTER:OPEN  B:BACK", kInkDim, kBg);
    }
}

} // namespace

void FilesInit(duetos::drivers::video::WindowHandle handle)
{
    g_state.handle = handle;
    g_state.depth = 0;
    g_state.selection = 0;
    const duetos::fs::RamfsNode* root = duetos::fs::RamfsTrustedRoot();
    if (root != nullptr)
    {
        g_state.stack[0] = root;
        g_state.depth = 1;
    }
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
}

duetos::drivers::video::WindowHandle FilesWindow()
{
    return g_state.handle;
}

bool FilesFeedArrow(bool up)
{
    const duetos::fs::RamfsNode* cur = Cur();
    if (cur == nullptr)
        return true;
    const u32 n = CountChildren(cur);
    if (n == 0)
        return true;
    if (up)
    {
        if (g_state.selection > 0)
            --g_state.selection;
    }
    else
    {
        if (g_state.selection + 1 < n)
            ++g_state.selection;
    }
    return true;
}

bool FilesFeedChar(char c)
{
    if (c == 'j' || c == 'J')
        return FilesFeedArrow(false);
    if (c == 'k' || c == 'K')
        return FilesFeedArrow(true);
    if (c == 'b' || c == 'B' || static_cast<u8>(c) == 0x08) // Back / Backspace
    {
        if (g_state.depth > 1)
        {
            --g_state.depth;
            g_state.selection = 0;
        }
        return true;
    }
    if (static_cast<u8>(c) == 0x0A) // Enter
    {
        const duetos::fs::RamfsNode* sel = SelectedChild();
        if (sel == nullptr)
            return true;
        if (sel->type == duetos::fs::RamfsNodeType::kDir)
        {
            if (g_state.depth < kMaxDepth)
            {
                g_state.stack[g_state.depth++] = sel;
                g_state.selection = 0;
            }
        }
        else
        {
            // File — log selection. Preview is a future slice.
            duetos::arch::SerialWrite("[files] open file name=");
            duetos::arch::SerialWrite(sel->name ? sel->name : "(unnamed)");
            duetos::arch::SerialWrite("\n");
        }
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
    // Try to enter the first directory child (if any) and verify
    // Cur() advances + depth grows. Uses DispatchKey-equivalents
    // directly to exercise the navigation path.
    u32 saved_depth = g_state.depth;
    u32 saved_sel = g_state.selection;
    const duetos::fs::RamfsNode* saved_top = Cur();
    if (pass)
    {
        // Pick the first child that is a directory.
        for (u32 i = 0; i < root_n; ++i)
        {
            if (root->children[i]->type == duetos::fs::RamfsNodeType::kDir)
            {
                g_state.selection = i;
                FilesFeedChar('\n'); // Enter -> descend
                if (g_state.depth != saved_depth + 1 || Cur() != root->children[i])
                    pass = false;
                FilesFeedChar('b'); // Back -> pop
                if (g_state.depth != saved_depth || Cur() != saved_top)
                    pass = false;
                break;
            }
        }
    }
    g_state.depth = saved_depth;
    g_state.selection = saved_sel;
    SerialWrite(pass ? "[files] self-test OK (root has children, descend+back works)\n" : "[files] self-test FAILED\n");
}

} // namespace duetos::apps::files
