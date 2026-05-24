#include "drivers/video/dialog.h"

#include "drivers/input/ps2kbd.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/shadow.h"
#include "drivers/video/sound_cue.h"
#include "drivers/video/theme.h"

namespace duetos::drivers::video
{

namespace
{

enum class DialogKind : u8
{
    None = 0,
    Message = 1,
    Input = 2,
};

constexpr u32 kPanelW = 400;
constexpr u32 kPanelH = 140;
constexpr u32 kBtnW = 80;
constexpr u32 kBtnH = 22;
constexpr u32 kBtnGap = 16;
constexpr u32 kBtnYOffset = 22; // distance from panel bottom
constexpr u32 kPad = 12;
constexpr u32 kGlyphW = 8;
constexpr u32 kGlyphH = 10;

struct State
{
    DialogKind kind;
    const char* title;
    const char* body;
    DialogResultFn cb;
    void* user;
    char input_buf[kDialogInputMax];
    u32 input_len;
    bool reentry_lock;           // set while firing the callback so the cb can't reopen
    bool pending;                // resolved, callback not yet fired
    DialogResult pending_result; // result captured at Resolve(), fired at drain
};

constinit State g_state = {};

void ResetState()
{
    g_state.kind = DialogKind::None;
    g_state.title = nullptr;
    g_state.body = nullptr;
    g_state.cb = nullptr;
    g_state.user = nullptr;
    g_state.input_buf[0] = '\0';
    g_state.input_len = 0;
    g_state.reentry_lock = false;
    g_state.pending = false;
    g_state.pending_result = DialogResult::Cancel;
}

// Centre coordinates of the panel inside the framebuffer.
// Recomputed every paint pass so a runtime resolution change
// just re-centres the panel without any extra plumbing.
void PanelOrigin(u32* px, u32* py)
{
    const auto fb = FramebufferGet();
    *px = (fb.width > kPanelW) ? (fb.width - kPanelW) / 2 : 0;
    *py = (fb.height > kPanelH) ? (fb.height - kPanelH) / 2 : 0;
}

// Geometry of OK / Cancel buttons in screen coords. Anchored to
// the panel-centre helper so a future resolution / panel-size
// shift doesn't desync paint and hit-test.
void ButtonBounds(bool ok, u32* x, u32* y, u32* w, u32* h)
{
    u32 px = 0, py = 0;
    PanelOrigin(&px, &py);
    *w = kBtnW;
    *h = kBtnH;
    *y = py + kPanelH - kBtnYOffset - kBtnH;
    if (ok)
    {
        *x = px + kPanelW / 2 - kBtnW - kBtnGap / 2;
    }
    else
    {
        *x = px + kPanelW / 2 + kBtnGap / 2;
    }
}

bool PointInButton(bool ok, u32 cx, u32 cy)
{
    u32 x = 0, y = 0, w = 0, h = 0;
    ButtonBounds(ok, &x, &y, &w, &h);
    return cx >= x && cx < x + w && cy >= y && cy < y + h;
}

bool PointInPanel(u32 cx, u32 cy)
{
    u32 px = 0, py = 0;
    PanelOrigin(&px, &py);
    return cx >= px && cx < px + kPanelW && cy >= py && cy < py + kPanelH;
}

void FireCallback(DialogResult r)
{
    if (g_state.cb == nullptr)
        return;
    DialogResultFn cb = g_state.cb;
    void* user = g_state.user;
    const char* text = (r == DialogResult::Ok && g_state.kind == DialogKind::Input) ? g_state.input_buf : nullptr;
    g_state.reentry_lock = true;
    cb(r, text, user);
    g_state.reentry_lock = false;
    ResetState();
}

// Record the resolution but DO NOT fire the callback here. The
// input handlers that call this (DialogFeedKey / DialogFeedChar /
// DialogOnPress) run under the caller's CompositorLock; the
// callback can do arbitrary work (e.g. FAT32 file I/O, which
// takes g_fat32_mutex). Firing it here would nest fat32 under
// compositor and form the compositor<->fat32 lockdep cycle.
// `DialogDrainResolved` fires it later, outside any lock.
void Resolve(DialogResult r)
{
    if (g_state.kind == DialogKind::None || g_state.pending)
        return;
    g_state.pending = true;
    g_state.pending_result = r;
}

} // namespace

bool MessageBoxOpen(const char* title, const char* body, DialogResultFn cb, void* user)
{
    if (g_state.kind != DialogKind::None || g_state.reentry_lock)
        return false;
    g_state.kind = DialogKind::Message;
    g_state.title = title;
    g_state.body = body;
    g_state.cb = cb;
    g_state.user = user;
    g_state.input_buf[0] = '\0';
    g_state.input_len = 0;
    // Non-intrusive attention chime so an unattended operator hears
    // a dialog appear. Matches the existing screenshot / files
    // convention of pairing user-visible state changes with a cue;
    // SoundCueChime is no-op when the master mute is off.
    SoundCueChime();
    return true;
}

bool InputBoxOpen(const char* title, const char* prompt, const char* default_text, DialogResultFn cb, void* user)
{
    if (g_state.kind != DialogKind::None || g_state.reentry_lock)
        return false;
    g_state.kind = DialogKind::Input;
    g_state.title = title;
    g_state.body = prompt;
    g_state.cb = cb;
    g_state.user = user;
    g_state.input_len = 0;
    if (default_text != nullptr)
    {
        for (u32 i = 0; default_text[i] != '\0' && g_state.input_len + 1 < kDialogInputMax; ++i)
        {
            g_state.input_buf[g_state.input_len++] = default_text[i];
        }
    }
    g_state.input_buf[g_state.input_len] = '\0';
    // InputBox opens with the same attention chime as MessageBox.
    SoundCueChime();
    return true;
}

bool DialogIsActive()
{
    return g_state.kind != DialogKind::None;
}

// Fire the deferred callback for a dialog that Resolve() marked
// pending. MUST be called with NO global lock held (in
// particular not CompositorLock) — the callback may take any
// lock, including g_fat32_mutex. Idempotent / cheap when there
// is nothing pending. Returns true if a callback was fired.
bool DialogDrainResolved()
{
    if (!g_state.pending)
        return false;
    const DialogResult r = g_state.pending_result;
    const DialogKind k = g_state.kind;
    g_state.pending = false;
    // Reject buzz on MessageBox cancel — operator dismissed an
    // attention prompt without confirming. InputBox cancel is a
    // normal escape (the user is just abandoning a rename / edit)
    // so no cue there. This branch runs with NO compositor lock
    // held per the contract above, so the 150 ms blocking beep
    // doesn't stall any compose pass.
    if (k == DialogKind::Message && r == DialogResult::Cancel)
        SoundCueError();
    FireCallback(r); // reads input_buf, invokes cb, then ResetState()
    return true;
}

bool DialogFeedKey(u16 keycode, bool is_release, u8 /*modifiers*/)
{
    if (g_state.kind == DialogKind::None || is_release)
        return g_state.kind != DialogKind::None;
    using namespace duetos::drivers::input;
    if (keycode == kKeyEnter || keycode == 0x0A || keycode == '=')
    {
        // '=' here covers the rare case of an unmapped Enter on a
        // bare-bones layout. Enter / numpad-Enter both arrive as
        // kKeyEnter on the PS/2 path.
        Resolve(DialogResult::Ok);
        return true;
    }
    if (keycode == kKeyEsc || keycode == 0x1B)
    {
        Resolve(DialogResult::Cancel);
        return true;
    }
    if (g_state.kind == DialogKind::Input)
    {
        if (keycode == kKeyBackspace || keycode == 0x08)
        {
            if (g_state.input_len > 0)
            {
                --g_state.input_len;
                g_state.input_buf[g_state.input_len] = '\0';
            }
            return true;
        }
    }
    // Swallow every other key while a dialog is up — input is
    // modal-locked. Returning true here matches that contract.
    return true;
}

bool DialogFeedChar(char c)
{
    if (g_state.kind != DialogKind::Input)
        return g_state.kind != DialogKind::None;
    const u8 uc = static_cast<u8>(c);
    if (uc == 0x08)
    {
        if (g_state.input_len > 0)
        {
            --g_state.input_len;
            g_state.input_buf[g_state.input_len] = '\0';
        }
        return true;
    }
    if (uc == 0x0A || uc == 0x0D)
    {
        Resolve(DialogResult::Ok);
        return true;
    }
    if (uc == 0x1B)
    {
        Resolve(DialogResult::Cancel);
        return true;
    }
    if (uc >= 0x20 && uc <= 0x7E && g_state.input_len + 1 < kDialogInputMax)
    {
        g_state.input_buf[g_state.input_len++] = c;
        g_state.input_buf[g_state.input_len] = '\0';
        return true;
    }
    return true;
}

bool DialogOnPress(u32 cx, u32 cy)
{
    if (g_state.kind == DialogKind::None)
        return false;
    if (PointInButton(true, cx, cy))
    {
        Resolve(DialogResult::Ok);
        return true;
    }
    if (PointInButton(false, cx, cy))
    {
        Resolve(DialogResult::Cancel);
        return true;
    }
    // Click in the panel body — eat it (modal). Click outside
    // the panel — also eat it; clicking off-panel doesn't
    // dismiss because real users tend to lose dialog state
    // that way.
    return PointInPanel(cx, cy) || true;
}

namespace
{

// Wrap-aware multi-line draw. Splits `text` at '\n' and at the
// caller's column cap so a long body string still reads inside
// the panel. Stops painting when it runs out of vertical room.
void DrawWrappedText(u32 x0, u32 y0, u32 max_w, u32 max_h, const char* text, u32 fg, u32 bg)
{
    if (text == nullptr || max_w < kGlyphW || max_h < kGlyphH)
        return;
    const u32 max_col = max_w / kGlyphW;
    const u32 max_row = max_h / kGlyphH;
    u32 row = 0, col = 0;
    for (u32 i = 0; text[i] != '\0' && row < max_row; ++i)
    {
        const char c = text[i];
        if (c == '\n')
        {
            ++row;
            col = 0;
            continue;
        }
        if (col >= max_col)
        {
            ++row;
            col = 0;
            if (row >= max_row)
                break;
        }
        FramebufferDrawChar(x0 + col * kGlyphW, y0 + row * kGlyphH, c, fg, bg);
        ++col;
    }
}

void PaintButton(bool ok, bool focused, u32 fg, u32 fill_normal, u32 fill_focus, u32 border)
{
    u32 x = 0, y = 0, w = 0, h = 0;
    ButtonBounds(ok, &x, &y, &w, &h);
    const u32 fill = focused ? fill_focus : fill_normal;
    FramebufferFillRect(x, y, w, h, fill);
    FramebufferDrawRect(x, y, w, h, border, 1);
    const char* label = ok ? "OK" : "CANCEL";
    u32 lw = 0;
    while (label[lw] != '\0')
        ++lw;
    const u32 lx = (lw * kGlyphW < w) ? x + (w - lw * kGlyphW) / 2 : x + 4;
    const u32 ly = y + (h > kGlyphH ? (h - kGlyphH) / 2 : 2);
    FramebufferDrawString(lx, ly, label, fg, fill);
}

} // namespace

void DialogCompose()
{
    if (g_state.kind == DialogKind::None)
        return;
    const auto fb = FramebufferGet();
    if (fb.virt == nullptr)
        return;
    const auto& th = ThemeCurrent();

    // Dim the desktop with a smooth alpha-blended overlay so the
    // panel reads as the only interactive surface, mirroring the
    // macOS / KDE / GNOME convention. The overlay tints the
    // surface toward near-black at ~40 % opacity — strong enough
    // to deemphasise the chrome behind it without making titles
    // unreadable in case a user wants to glance at context.
    // Replaces the older "every-other-pixel dotted" approximation
    // that used the chrome's no-alpha era primitives.
    constexpr u32 kDimArgb = (0x66U << 24) | 0x00080810U;
    FramebufferBlendFill(0, 0, fb.width, fb.height, kDimArgb);

    u32 px = 0, py = 0;
    PanelOrigin(&px, &py);
    const u32 panel_bg = th.role_client[0]; // first role's client
    const u32 title_bg = th.taskbar_accent;
    const u32 ink = 0x00101020;
    const u32 dim_ink = 0x00606078;
    const u32 border = th.window_border;

    // Tactility lift: paint a 50% larger soft shadow than the
    // window's 24-active radius (40 here) at 75% of the active
    // shadow intensity. Modals already command attention via the
    // 40% scrim above, but the stronger shadow makes the panel
    // physically read as floating on top of the dim, not painted
    // onto it. No-op for tactility=off themes / runtime override.
    if (ThemeTactilityEffective() && th.shadow_intensity_active > 0)
    {
        const u8 opacity = static_cast<u8>((static_cast<u32>(th.shadow_intensity_active) * 3U) / 4U);
        if (opacity > 0)
        {
            RenderSoftShadow(static_cast<i32>(px), static_cast<i32>(py), kPanelW, kPanelH, 40U, opacity, 0x00000000U);
        }
    }

    // Body fill + 1-px border.
    FramebufferFillRect(px, py, kPanelW, kPanelH, panel_bg);
    FramebufferDrawRect(px, py, kPanelW, kPanelH, border, 2);

    // Title bar.
    constexpr u32 kTitleH = 18;
    FramebufferFillRect(px + 2, py + 2, kPanelW - 4, kTitleH, title_bg);
    if (g_state.title != nullptr)
    {
        FramebufferDrawString(px + 6, py + 4, g_state.title, ink, title_bg);
    }

    // Body text.
    const u32 body_y = py + 2 + kTitleH + kPad;
    const u32 body_h = kPanelH - 2 - kTitleH - kPad - kBtnH - kBtnYOffset - kPad;
    DrawWrappedText(px + kPad, body_y, kPanelW - 2 * kPad, body_h, g_state.body, ink, panel_bg);

    if (g_state.kind == DialogKind::Input)
    {
        // Edit field below the prompt. One row of glyphs at
        // 8x10, framed by a 1-px border. Caret is the trailing
        // underscore — no blink for v0; the dialog is brief.
        constexpr u32 kEditH = kGlyphH + 4;
        const u32 ey = py + kPanelH - kBtnH - kBtnYOffset - kPad - kEditH;
        FramebufferFillRect(px + kPad, ey, kPanelW - 2 * kPad, kEditH, 0x00FFFFFF);
        FramebufferDrawRect(px + kPad, ey, kPanelW - 2 * kPad, kEditH, border, 1);
        FramebufferDrawString(px + kPad + 4, ey + 2, g_state.input_buf, ink, 0x00FFFFFF);
        const u32 cx_caret = px + kPad + 4 + g_state.input_len * kGlyphW;
        FramebufferDrawChar(cx_caret, ey + 2, '_', ink, 0x00FFFFFF);
    }

    PaintButton(true, true, ink, title_bg, th.taskbar_accent, border);
    PaintButton(false, false, ink, panel_bg, dim_ink, border);
}

void DialogDismiss()
{
    if (g_state.kind == DialogKind::None)
        return;
    ResetState();
}

} // namespace duetos::drivers::video
