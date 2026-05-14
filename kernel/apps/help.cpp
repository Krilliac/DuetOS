#include "apps/help.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"

namespace duetos::apps::help
{

namespace
{

using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::ThemeRole;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kRowH = 11;
constexpr u32 kSectionGap = 6;

// One row in the help table. `is_section` flips the formatter to
// paint the line as a section header (banner-fg colour, no
// indentation) instead of a normal binding row (indented + dim).
struct Row
{
    const char* text;
    bool is_section;
};

// Reference list. Must stay in lock-step with PrintShortcutHelp
// in kernel/core/menu_dispatch.cpp — both surfaces document the
// same bindings; if one drifts the other is wrong.
constexpr Row kRows[] = {
    {"GETTING STARTED", true},
    {"  CLICK [START] (BOTTOM-LEFT) TO LAUNCH APPS", false},
    {"  CLICK A TASKBAR TAB TO RAISE THAT WINDOW", false},
    {"  DRAG A TITLE BAR TO MOVE A WINDOW", false},
    {"  [X] OR ALT+F4 TO CLOSE", false},
    {"WINDOWS", true},
    {"  ALT+TAB           CYCLE ACTIVE WINDOW", false},
    {"  CTRL+ALT+UP       MAXIMISE / RESTORE", false},
    {"  CTRL+ALT+DOWN     RESTORE / MINIMISE", false},
    {"  CTRL+ALT+LEFT/R   SNAP HALF-SCREEN", false},
    {"  CTRL+ALT+, / .    OPACITY DOWN / UP", false},
    {"DESKTOP / SYSTEM", true},
    {"  F1                THIS HELP", false},
    {"  CTRL+ALT+T        TOGGLE DESKTOP / TTY", false},
    {"  CTRL+ALT+L        LOCK / UNLOCK TASKBAR", false},
    {"  CTRL+ALT+K        LOCK SCREEN", false},
    {"  CTRL+ALT+Y        CYCLE THEME", false},
    {"  CTRL+ALT+1..9     PICK THEME DIRECTLY", false},
    {"  CTRL+ALT+P        SCREENSHOT TO SHOTNNNN.BMP", false},
    {"  CTRL+ALT+M        TOGGLE MAGNIFIER", false},
    {"  CTRL+C            INTERRUPT SHELL CMD", false},
    {"  CTRL+SHIFT+V      ROTATE CLIP HISTORY", false},
    {"NOTES", true},
    {"  CTRL+C / CTRL+V   COPY / PASTE CLIPBOARD", false},
    {"  CTRL+S / CTRL+O   SAVE / LOAD NOTES.TXT", false},
    {"  CTRL+F            FIND (case-insensitive)", false},
    {"  F3                FIND NEXT (wraps to start)", false},
    {"  CTRL+H            FIND-AND-REPLACE (two prompts)", false},
    {"  CTRL+A            SELECT ALL", false},
    {"  CTRL+G            GO TO LINE", false},
    {"  STATUS FOOTER     L:line C:col + word/char count", false},
    {"  *MOD              UNSAVED CHANGES", false},
    {"FILES", true},
    {"  UP / DN           MOVE SELECTION", false},
    {"  ENTER             OPEN (DESCEND / DISPATCH)", false},
    {"  B                 UP ONE LEVEL (RAM MODE)", false},
    {"  D / M / T         DISK / RAM / TRASH VIEW", false},
    {"  R                 RESCAN (DISK) / RESTORE (TRASH)", false},
    {"  S                 CYCLE SORT (NAME -> SIZE -> TYPE)", false},
    {"  X THEN Y          DISK: TO TRASH; TRASH: PERM-DEL", false},
    {"  E THEN Y          EMPTY TRASH (TRASH VIEW ONLY)", false},
    {"IMAGE VIEWER", true},
    {"  N / P / LEFT/RT   NEXT / PREV IMAGE", false},
    {"  R                 RESCAN DISK FOR IMAGES", false},
    {"  + / -             ZOOM IN / OUT (resize window)", false},
    {"  CTRL+WHEEL        ZOOM IN / OUT (mouse)", false},
    {"CALCULATOR", true},
    {"  0..9 + - * / =    BASIC ARITHMETIC", false},
    {"  C                 CLEAR", false},
    {"  %                 PERCENT", false},
    {"  N / _             SIGN TOGGLE", false},
    {"  BACKSPACE         REMOVE LAST DIGIT", false},
    {"  M / S             MEMORY RECALL / STORE", false},
    {"  A / B             MEMORY ADD / SUBTRACT", false},
    {"  L                 MEMORY CLEAR", false},
    {"  Q / X / Y / R / ! SQRT / SQUARE / ABS / 1OVERN / FACTORIAL", false},
    {"  & | ^             BITWISE AND / OR / XOR (binary)", false},
    {"  < / >             SHIFT LEFT / RIGHT (binary)", false},
    {"  ~                 BITWISE NOT (unary)", false},
    {"  HEX / BIN / OCT   shown live below decimal display", false},
    {"TASK MANAGER", true},
    {"  TAB               CYCLE PROCESSES / PERFORMANCE", false},
    {"  UP / DN PG/PG     MOVE SELECTION (PROCESSES TAB)", false},
    {"  S                 CYCLE SORT (CPU/PID/NAME/STATE)", false},
    {"  K / DEL           KILL SELECTED PROCESS (CONFIRM)", false},
    {"  R                 FORCE SNAPSHOT REBUILD", false},
    {"BROWSER", true},
    {"  U / TAB           URL EDIT", false},
    {"  ENTER             FETCH (in URL edit)", false},
    {"  B / F             BACK / FORWARD", false},
    {"  R                 RELOAD", false},
    {"  H / L             HISTORY / BOOKMARKS LIST", false},
    {"  M                 BOOKMARK CURRENT", false},
    {"  S                 SAVE TO DLNNNN.HTM", false},
    {"  J / K / UP / DN   SCROLL", false},
    {"CALENDAR", true},
    {"  [ ] LEFT/RT       PREV / NEXT MONTH", false},
    {"  { } UP / DN       PREV / NEXT YEAR", false},
    {"  T                 JUMP TO TODAY", false},
    {"  SHIFT+LEFT/RT     STEP SELECTION 1 DAY", false},
    {"  SHIFT+UP/DN       STEP SELECTION 7 DAYS", false},
    {"  ENTER             ADD EVENT (selected date)", false},
    {"  DEL               REMOVE EVENT (selected date)", false},
    {"  CTRL+S / CTRL+O   SAVE / LOAD CALENDAR.TXT", false},
    {"  *DOT*             cell carries an event", false},
    {"SETTINGS", true},
    {"  THEME / OPACITY / TZ / LOG OUT", false},
    {"  REBOOT / SHUTDOWN", false},
};

constexpr u32 kRowCount = sizeof(kRows) / sizeof(kRows[0]);

struct State
{
    WindowHandle handle;
};

constinit State g_state = {kWindowInvalid};

// Live filter — appended to by HelpFeedChar. Section headers
// pass through whenever at least one of their following rows
// matches, so the rendered output stays grouped.
constexpr u32 kFilterCap = 31;
constinit char g_filter[kFilterCap + 1] = {};
constinit u32 g_filter_len = 0;

char ToUpperAscii(char c)
{
    if (c >= 'a' && c <= 'z')
        return static_cast<char>(c - 32);
    return c;
}

// Case-insensitive substring search. Returns true iff `hay`
// contains `needle`. Empty needle matches everything.
bool ContainsCi(const char* hay, const char* needle)
{
    if (needle == nullptr || needle[0] == '\0')
        return true;
    if (hay == nullptr)
        return false;
    u32 nlen = 0;
    while (needle[nlen] != '\0')
        ++nlen;
    u32 hlen = 0;
    while (hay[hlen] != '\0')
        ++hlen;
    if (nlen > hlen)
        return false;
    for (u32 i = 0; i + nlen <= hlen; ++i)
    {
        bool ok = true;
        for (u32 j = 0; j < nlen; ++j)
        {
            if (ToUpperAscii(hay[i + j]) != ToUpperAscii(needle[j]))
            {
                ok = false;
                break;
            }
        }
        if (ok)
            return true;
    }
    return false;
}

// Resolve "should this row be drawn under the active filter?"
// for index `i`. Section headers (kRows[i].is_section) survive
// when at least one row following them (until the next section)
// matches; non-section rows must match directly.
bool ShouldRenderRow(u32 i)
{
    if (g_filter_len == 0)
        return true;
    if (kRows[i].is_section)
    {
        for (u32 j = i + 1; j < kRowCount && !kRows[j].is_section; ++j)
        {
            if (ContainsCi(kRows[j].text, g_filter))
                return true;
        }
        return false;
    }
    return ContainsCi(kRows[i].text, g_filter);
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(ThemeRole::Help)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    FramebufferFillRect(cx, cy, cw, ch, bg);

    if (cw < 220 || ch < 60)
    {
        FramebufferDrawString(cx + 4, cy + 4, "(window too small)", dim, bg);
        return;
    }

    // Title row + live filter readout. Filter sits on the right
    // half of the title line; ESC / BACKSPACE manage it via the
    // HelpFeedChar path.
    FramebufferDrawString(cx + 8, cy + 6, "DUETOS QUICK REFERENCE", dim, bg);
    {
        char fline[kFilterCap + 16];
        u32 o = 0;
        const char* lead = (g_filter_len > 0) ? "FIND: " : "TYPE TO FILTER";
        for (u32 i = 0; lead[i] != '\0' && o + 1 < sizeof(fline); ++i)
            fline[o++] = lead[i];
        for (u32 i = 0; i < g_filter_len && o + 1 < sizeof(fline); ++i)
            fline[o++] = g_filter[i];
        fline[o] = '\0';
        const u32 fw = o * 8;
        const u32 fx = (cw > fw + 16) ? cx + cw - fw - 8 : cx + 8;
        const u32 ffg = (g_filter_len > 0) ? fg : dim;
        FramebufferDrawString(fx, cy + 6, fline, ffg, bg);
    }

    u32 y = cy + 6 + kRowH + 4;
    bool any_drawn = false;
    for (u32 i = 0; i < kRowCount; ++i)
    {
        if (!ShouldRenderRow(i))
            continue;
        any_drawn = true;
        if (y + kRowH > cy + ch)
        {
            // Truncate cleanly — paint a "..." tail so the user
            // knows they're missing rows. v0 doesn't paginate.
            FramebufferDrawString(cx + 8, y, "...", dim, bg);
            break;
        }
        if (kRows[i].is_section)
        {
            // Small gap before each section header so the list
            // groups visually.
            if (i != 0)
                y += kSectionGap;
            if (y + kRowH > cy + ch)
                break;
            FramebufferDrawString(cx + 6, y, kRows[i].text, dim, bg);
        }
        else
        {
            FramebufferDrawString(cx + 8, y, kRows[i].text, fg, bg);
        }
        y += kRowH;
    }
    if (!any_drawn)
    {
        FramebufferDrawString(cx + 8, y, "(no match — Backspace to clear)", dim, bg);
    }
}

} // namespace

void HelpInit(WindowHandle handle)
{
    g_state.handle = handle;
    WindowSetContentDraw(handle, DrawFn, nullptr);
}

bool HelpFeedChar(char c)
{
    const u8 uc = static_cast<u8>(c);
    if (uc == 0x08) // Backspace — drop a char, or clear at zero
    {
        if (g_filter_len > 0)
        {
            --g_filter_len;
            g_filter[g_filter_len] = '\0';
        }
        return true;
    }
    // Accept printable ASCII (letters / digits / space /
    // punctuation), reject control codes including Enter /
    // Tab — those collide with global / per-app behaviours.
    if (c >= 0x20 && c <= 0x7E)
    {
        if (g_filter_len < kFilterCap)
        {
            g_filter[g_filter_len++] = c;
            g_filter[g_filter_len] = '\0';
        }
        return true;
    }
    return false;
}

WindowHandle HelpWindow()
{
    return g_state.handle;
}

void HelpSelfTest()
{
    using arch::SerialWrite;
    bool pass = (kRowCount > 0);
    // Every section header must be followed by at least one
    // non-section row. Catches a regression where the list grew
    // a stray "TITLE\n" with no bindings underneath.
    for (u32 i = 0; pass && i < kRowCount; ++i)
    {
        if (!kRows[i].is_section)
            continue;
        if (i + 1 >= kRowCount || kRows[i + 1].is_section)
        {
            pass = false;
            break;
        }
    }
    SerialWrite(pass ? "[help] self-test OK (sections non-empty)\n" : "[help] self-test FAILED\n");
}

} // namespace duetos::apps::help
