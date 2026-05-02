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
// in kernel/core/main.cpp — both surfaces document the same
// bindings; if one drifts the other is wrong.
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
    {"NOTES", true},
    {"  CTRL+C / CTRL+V   COPY / PASTE CLIPBOARD", false},
    {"  CTRL+S / CTRL+O   SAVE / LOAD NOTES.TXT", false},
    {"FILES", true},
    {"  UP / DN           MOVE SELECTION", false},
    {"  ENTER             OPEN (DESCEND / DISPATCH)", false},
    {"  B                 UP ONE LEVEL (RAM MODE)", false},
    {"  D / M / T         DISK / RAM / TRASH VIEW", false},
    {"  R                 RESCAN (DISK) / RESTORE (TRASH)", false},
    {"  X THEN Y          DISK: TO TRASH; TRASH: PERM-DEL", false},
    {"  E THEN Y          EMPTY TRASH (TRASH VIEW ONLY)", false},
    {"IMAGE VIEWER", true},
    {"  N / P / LEFT/RT   NEXT / PREV BMP", false},
    {"  R                 RESCAN DISK FOR BMPS", false},
    {"CALCULATOR", true},
    {"  0..9 + - * / =    BASIC ARITHMETIC", false},
    {"  C                 CLEAR", false},
    {"  %                 PERCENT", false},
    {"  N / _             SIGN TOGGLE", false},
    {"  BACKSPACE         REMOVE LAST DIGIT", false},
    {"BROWSER", true},
    {"  U / TAB           URL EDIT", false},
    {"  ENTER             FETCH (in URL edit)", false},
    {"  B / F             BACK / FORWARD", false},
    {"  R                 RELOAD", false},
    {"  H / L             HISTORY / BOOKMARKS LIST", false},
    {"  M                 BOOKMARK CURRENT", false},
    {"  S                 SAVE TO DLNNNN.HTM", false},
    {"  J / K / UP / DN   SCROLL", false},
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

    // Title row.
    FramebufferDrawString(cx + 8, cy + 6, "DUETOS QUICK REFERENCE", dim, bg);

    u32 y = cy + 6 + kRowH + 4;
    for (u32 i = 0; i < kRowCount; ++i)
    {
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
}

} // namespace

void HelpInit(WindowHandle handle)
{
    g_state.handle = handle;
    WindowSetContentDraw(handle, DrawFn, nullptr);
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
