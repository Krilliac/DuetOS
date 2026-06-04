#include "apps/browser.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "log/klog.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/scrollbar.h"
#include "drivers/video/theme.h"
#include "fs/fat32.h"
#include "mm/kheap.h"
#include "net/cookies.h"
#include "net/http.h"
#include "net/socket.h"
#include "net/stack.h"
#include "net/tls_socket.h"
#include "net/x509_verify.h"
#include "sched/sched.h"
#include "time/timekeeper.h"
#include "apps/browser/assistant_backend.h"
#include "apps/browser/dock_surface.h"
#include "apps/browser/omnibox.h"
#include "apps/browser/priv_exec.h"
#include "apps/browser/start_page.h"
#include "apps/browser/tab_strip.h"
#include "apps/browser/tokens.h"
#include "security/privilege/arm_state.h"
#include "security/privilege/config.h"
#include "security/privilege/scope.h"
#include "web/css.h"
#include "web/dom.h"
#include "web/html.h"
#include "web/jpeg.h"
#include "web/js_dom.h"
#include "web/layout.h"
#include "web/paint.h"
#include "web/png.h"
#include "web/priv_binding.h"

namespace duetos::apps::browser
{

namespace
{

using duetos::drivers::input::kKeyArrowDown;
using duetos::drivers::input::kKeyArrowUp;
using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::ThemeRole;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kUrlCap = 256;
// Body cap covers the post-strip plain text. 64 KiB is the same
// budget the v0 single-slot TCP RX buffer carried — keep it for
// pages with large header / inline-CSS prefixes.
constexpr u32 kHttpResponseCap = 65536;
constexpr u32 kBodyCap = kHttpResponseCap + 256;
constexpr u32 kStatusCap = 96;
constexpr u32 kHistoryCap = 32;
constexpr u32 kBookmarkCap = 32;
constexpr u32 kRowH = 10;
// Max links we track for hit-testing / keyboard focus on one page. A
// real page can have hundreds of links; beyond this the extras simply
// aren't clickable (the display list still paints them). 256 covers the
// common case without bloating g_state.
constexpr u32 kLinkRectCap = 256;
// Sentinel for "no link focused" in State::focus_link.
constexpr u32 kNoLink = 0xFFFFFFFFu;
constexpr const char kBookmarkPath[] = "BOOKMARK.TXT";

enum class Mode : u8
{
    View = 0,
    UrlEdit = 1,
    History = 2,
    Bookmarks = 3,
};

struct State
{
    WindowHandle handle;
    Mode mode;

    // URL bar — visible in every mode; in UrlEdit it's the live
    // edit target.
    char url[kUrlCap];
    u32 url_len;

    // Loaded body (HTML-stripped plain text). Wraps lines on
    // paint; no pre-wrapped layout to keep the painter simple.
    char body[kBodyCap];
    u32 body_len;
    bool truncated; // true when the response filled the TCP buffer

    // Last status line (errors / progress / "OK 200").
    char status[kStatusCap];
    u32 status_code; // last HTTP status if known

    // Vertical scroll offset (in wrapped rows). Used by the History /
    // Bookmarks modal lists. Reset to 0 on a successful fetch.
    u32 scroll_row;

    // Rendered-page scroll offset in DEVICE PIXELS. The render
    // pipeline (ParseHtml -> ComputeStyles -> scripts -> LayoutDocument
    // -> DisplayList) produces a pixel-addressed display list; the View
    // body scrolls it by this offset, clamped to [0, total_height -
    // view_h]. Reset to 0 on a successful fetch.
    i32 scroll_y;

    // Render output, produced by RenderPage in the fetch worker and
    // consumed by DrawBody under the compositor lock. `render_dl` points
    // into `render_arena_buf` (persistent so it outlives DoFetch);
    // `render_total_h` is the laid-out page height in device px;
    // `render_ready` gates DrawBody between the painter path and the
    // legacy "Fetching..." / empty state.
    duetos::web::DisplayList* render_dl;
    i32 render_total_h;
    u32 render_viewport_w;
    volatile bool render_ready;

    // Link hit-test table, rebuilt by BuildLinkRects after every
    // RenderPage. Each entry is a rect in DOCUMENT coordinates (the same
    // space the display list lives in, before the scroll offset is
    // applied) plus the link's RESOLVED absolute href. Clicks and the
    // focus-cycle test against these. `focus_link` is the index of the
    // keyboard-focused link (kNoLink = none); the painter draws a focus
    // outline around it. See kLinkRectCap.
    struct LinkRect
    {
        duetos::web::Rect rect;
        char href[kUrlCap];
    };
    LinkRect link_rects[kLinkRectCap];
    u32 link_count;
    u32 focus_link; // index into link_rects, or kNoLink

    // History — circular buffer of visited URLs. `idx` points
    // past the most-recent entry; back/forward decrement/increment
    // through `count` entries until either end. Push truncates any
    // forward history (Chrome / Firefox semantics).
    char history[kHistoryCap][kUrlCap];
    u32 history_count;
    u32 history_idx; // current position; 0..history_count

    // Bookmarks — persisted on FAT32 root.
    char bookmarks[kBookmarkCap][kUrlCap];
    u32 bookmark_count;

    // Selection within the active modal list (History or Bookmarks).
    u32 list_selection;

    // Fetch worker handshake. The input thread sets `fetch_url`
    // and `fetch_pending=true`; the worker swaps it to in_flight,
    // runs, then clears the in_flight flag. DrawFn checks
    // `fetch_in_flight` to decide what to paint.
    char fetch_url[kUrlCap];
    volatile bool fetch_in_flight;

    // Interactive scripting handle. Each RenderPage of an HTML page
    // (re)creates ONE retained JS context bound to the freshly-parsed
    // DOM root (`page_doc`) out of the render arena, runs every <script>
    // against it so listeners persist, and keeps it alive until the next
    // RenderPage. A user click then hit-tests the display list back to a
    // DOM node and dispatches a bubbling `click` through `page_ctx`, so
    // page JS click handlers fire (on buttons / divs / anything), not just
    // anchors. Both are nullptr before the first render, on a non-HTML
    // page, on a download (no RenderPage), or if context creation fails —
    // callers MUST null-check and fall back to link-only navigation.
    // The pointers reference the persistent render arena + the file-static
    // singleton context, both of which outlive DoFetch.
    duetos::web::JsDomContext* page_ctx;
    duetos::web::Node* page_doc;
};

constinit State g_state = {};

// ---------------------------------------------------------------
// Render pipeline backing storage. All of this is single-page —
// each RenderPage rebuilds the DOM / styles / display list from the
// raw HTML, so we keep ONE persistent arena (the display list it
// produces must outlive DoFetch because DrawBody paints it later).
//
//   - kRenderArenaBytes: the DOM (+ runtime nodes created by click
//     handlers) for one page. 1 MiB; with styles/layout moved to the
//     layout arena, the whole budget is the DOM's, so handler mutations
//     (textContent/innerHTML) have far more headroom before exhaustion.
//   - kLayoutArenaBytes: stylesheets + style map + display list. RESET
//     on every (re)layout (RelayoutFromDoc), so it never grows across
//     re-renders — only the DOM arena does (see the GAP in RelayoutFromDoc).
//   - kCanvasW/kCanvasH: the off-screen RGBA8888 compose surface the
//     painter draws into before blitting to the framebuffer. Sized to
//     a generous window content area; oversize windows clip to this.
//   - Image cache: up to kImageCacheCap decoded images keyed by URL,
//     each decoded into its own slice of kImageArenaBytes.
// ---------------------------------------------------------------
constexpr u32 kRenderArenaBytes = 1024u * 1024u;
constexpr u32 kLayoutArenaBytes = 1024u * 1024u;
constexpr u32 kCanvasW = 1024u;
constexpr u32 kCanvasH = 1024u;
constexpr u32 kImageArenaBytes = 4u * 1024u * 1024u;
constexpr u32 kImageCacheCap = 16u;

alignas(16) u8 g_render_arena_buf[kRenderArenaBytes];
alignas(16) u8 g_layout_arena_buf[kLayoutArenaBytes];
alignas(16) u8 g_canvas[kCanvasW * kCanvasH * 4u];
alignas(16) u8 g_image_arena_buf[kImageArenaBytes];

// PERSISTENT render arena over g_render_arena_buf. It must OUTLIVE
// RenderPage: the retained JsDomContext keeps `&domArena` to allocate
// DOM nodes that listeners create at click time (textContent setters,
// innerHTML), long after RenderPage returns. A RenderPage-local Arena
// would dangle (the buffer persists, but the bump-pointer object would
// be destroyed) and runtime DOM mutations would fault / spuriously OOM.
// Reset (re-constructed over the buffer) at the top of each RenderPage.
duetos::web::Arena g_render_arena{g_render_arena_buf, kRenderArenaBytes};

// LAYOUT arena: stylesheets + style map + display list. Separate from the
// DOM arena so a re-layout after a runtime DOM mutation (RelayoutFromDoc)
// can RESET it wholesale without disturbing the DOM. The display list's
// string payloads (TextRun bytes, href, the node back-ref) point back into
// the DOM (g_render_arena), which persists; styles are copied BY VALUE into
// each DisplayItem (color/bold/fontPx), so nothing in a built display list
// outlives a layout-arena reset by reference. Reset per (re)layout.
duetos::web::Arena g_layout_arena{g_layout_arena_buf, kLayoutArenaBytes};

struct ImageCacheEntry
{
    char url[kUrlCap];
    duetos::web::PaintImage img; // rgba==nullptr => decode failed (placeholder)
    bool used;
};

struct ImageCache
{
    ImageCacheEntry entries[kImageCacheCap];
    u32 count;
    duetos::web::PngArena arena; // bump over g_image_arena_buf
    // Page URL the current cache was resolved against (for relative
    // <img src> resolution). Reset per RenderPage.
    char page_url[kUrlCap];
};

constinit ImageCache g_images = {};

// ---------------------------------------------------------------
// Pass D chrome: AppToolbar (back) + 7 AppButton entries
// (BACK / FWD / RLD / HIST / BMRK / MARK / SAVE) + 3 AppLabel
// rows (URL bar, status line, footer hint). The 7 nav buttons
// duplicate the keyboard shortcuts B / F / R / H / L / M / S so
// the chrome stays discoverable without forcing fresh users to
// memorise the footer hint.
//
// Carve-outs that stay raw paint:
//   - URL bar with the crude '_' cursor sits in the AppLabel
//     text buffer (re-composed each frame from g_state.url +
//     mode), but the live caret rendering would clash with
//     AppInput's own focus-driven caret and keystroke handling
//     — Browser's URL editing is mode-gated by Mode::UrlEdit,
//     not by mouse focus, so AppInput's contract doesn't fit.
//   - Modal History / Bookmarks lists keep their custom hit-
//     highlight + selection band (heterogeneous rows + key-
//     driven cursor — AppListRow's per-row click handler
//     doesn't reproduce the j/k navigation semantics).
//   - Body view (HTML-stripped text + scrollbar) stays raw
//     paint — wrapping is computed inline against the live
//     glyph cell, not by a widget primitive.
//
// Layout: toolbar (kToolbarH=28) + URL bar (kRowH+4) +
// status row (kRowH+2) + body band + footer hint (kFooterH=12).

constexpr u32 kToolbarH = 28U;
constexpr u32 kToolbarBtnW = 56U;
constexpr u32 kToolbarBtnH = 22U;
constexpr u32 kToolbarBtnGap = 4U;
constexpr u32 kToolbarPadX = 4U;
constexpr u32 kToolbarPadY = 3U;
constexpr u32 kUrlBarH = kRowH + 4U;
constexpr u32 kUrlBarPadX = 4U;
constexpr u32 kStatusRowH = kRowH + 2U;
constexpr u32 kFooterH = 12U;
// Tab strip band above the toolbar (shell redesign Phase 1). The existing
// toolbar/url/status chrome is anchored kTabStripH lower; the strip is
// painted in [cy, cy+kTabStripH].
constexpr u32 kTabStripH = 30U;

// Live tab model (Phase 1: one page rendered at a time; the active tab
// tracks the current URL/title — real per-tab render contexts are Phase 3).
TabStrip g_tabs;
// Unified omnibox + the two dockable surfaces (Assistant / Library) + the
// new-tab start page (shell redesign Phase 1).
Omnibox g_omni;
DockSurface g_assistant;
DockSurface g_library;
StartPage g_startpage;
constexpr u32 kNavBtnCount = 7U;

// ---------------------------------------------------------------
// Privileged-Origin Mode (spec §13). The browser owns ONE per-tab arm
// state for the single live page (Phase 1 renders one tab at a time).
// Arming is gated on PrivConfig.available && the live navigation being
// the privileged origin; the armed chrome (crimson omnibox, shield
// glyph, warning ribbon, red tab accent + content border) is the sole
// trust signal because the page can never draw chrome. A reconfirm
// dialog (g_priv_confirm) sits between the arm affordance and Arm().
// ---------------------------------------------------------------
duetos::security::privilege::PrivTab g_priv{};
// The Client-A (browser) bind handed to the page's JS context on arm. Its
// back-pointers (tab => g_priv; roots => the persistent boot config) outlive
// the JsDomContext, so the window.duetos.* host objects stay valid for the
// context's lifetime. Re-initialised on every PrivArm.
duetos::web::priv::PrivBind g_priv_bind{};
// Reconfirm dialog gate: true while the modal "really arm?" prompt is up.
// The dialog is chrome-drawn + chrome-handled (the page cannot suppress or
// satisfy it).
constinit bool g_priv_confirm = false;
// Full-width warning ribbon height, painted under the toolbar ONLY while
// armed (no layout shift when disarmed — chrome is byte-for-byte as today).
constexpr u32 kPrivRibbonH = 22U;
// Forward decls: the armed-chrome predicate + ribbon-height helper are defined
// further down (next to the draw code) but referenced by the layout/scroll/
// hit-test math above it (top-band reserves include the ribbon while armed).
bool PrivShouldRenderArmed();
u32 PrivRibbonH();

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

// AppLabel stores text by pointer so the buffers must outlive
// every Paint. DrawFn re-renders them each frame.
constinit char g_urlbar_text[kUrlCap + 8] = {};
constinit char g_footer_text[96] = {};

// Forward decls for the toolbar click trampolines (defined
// below; they have to live above the constinit g_browser that
// captures them by function-pointer value).
void ClickBack();
void ClickForward();
void ClickReload();
void ClickHistory();
void ClickBookmarks();
void ClickMark();
void ClickSave();

// Toolbar (back), then 7 nav AppButtons, then URL-bar label,
// status label, footer label. Reverse declaration order is
// dispatch order — buttons get first refusal on clicks.
constinit auto g_browser = MakeWidgetGroup(AppToolbar{}, AppButton{}, AppButton{}, AppButton{}, AppButton{},
                                           AppButton{}, AppButton{}, AppButton{}, AppLabel{}, AppLabel{}, AppLabel{});

constinit bool g_browser_bound = false;
constinit bool g_prev_left_down = false;
constinit bool g_self_test_passed = false;

// Walk the recursive WidgetChain by hand to grab a stable
// pointer to each nav button. Chain order mirrors the
// MakeWidgetGroup argument list (toolbar -> 7 buttons -> 3
// labels).
AppButton* NavButton(u32 i)
{
    auto& a = g_browser.chain.tail; // toolbar -> btn[0]
    auto& b = a.tail;               // btn[0]   -> btn[1]
    auto& c = b.tail;               // btn[1]   -> btn[2]
    auto& d = c.tail;               // btn[2]   -> btn[3]
    auto& e = d.tail;               // btn[3]   -> btn[4]
    auto& f = e.tail;               // btn[4]   -> btn[5]
    auto& g = f.tail;               // btn[5]   -> btn[6]
    AppButton* btns[kNavBtnCount] = {&a.head, &b.head, &c.head, &d.head, &e.head, &f.head, &g.head};
    return btns[i];
}

// AppLabel accessors — URL bar / status / footer sit at chain
// positions 8, 9, 10 (zero-indexed) after the 1 toolbar + 7
// buttons.
AppLabel& UrlBarLabel()
{
    return g_browser.chain.tail.tail.tail.tail.tail.tail.tail.tail.head;
}
AppLabel& StatusLabel()
{
    return g_browser.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
}
AppLabel& FooterLabel()
{
    return g_browser.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
}

void BindBrowserOnce()
{
    if (g_browser_bound)
        return;
    g_browser_bound = true;

    auto& toolbar = g_browser.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    static const char* const kNavLabels[kNavBtnCount] = {"BACK", "FWD", "RLD", "HIST", "BMRK", "MARK", "SAVE"};
    using ClickFn = void (*)();
    static constexpr ClickFn kNavClicks[kNavBtnCount] = {ClickBack,      ClickForward, ClickReload, ClickHistory,
                                                         ClickBookmarks, ClickMark,    ClickSave};
    for (u32 i = 0; i < kNavBtnCount; ++i)
    {
        AppButton* btn = NavButton(i);
        btn->label = kNavLabels[i];
        btn->on_click = kNavClicks[i];
        btn->weight = ChromeTextWeight::Regular;
        btn->bg_rgb = 0; // theme role default
        btn->fg_rgb = 0x00101828U;
    }

    auto& url = UrlBarLabel();
    url.text = g_urlbar_text;
    url.role = ChromeTextRole::Body;
    url.weight = ChromeTextWeight::Regular;
    url.fg_rgb = 0x00181828U;
    url.bg_rgb = 0;
    url.align_left = true;

    auto& status = StatusLabel();
    status.text = g_state.status;
    status.role = ChromeTextRole::Caption;
    status.weight = ChromeTextWeight::Regular;
    status.fg_rgb = 0x00404858U;
    status.bg_rgb = 0;
    status.align_left = true;

    auto& footer = FooterLabel();
    footer.text = g_footer_text;
    footer.role = ChromeTextRole::Caption;
    footer.weight = ChromeTextWeight::Regular;
    footer.fg_rgb = 0x00181828U;
    footer.bg_rgb = 0x00C8C8B8U;
    footer.align_left = true;
}

// Re-anchor the toolbar + buttons + labels to the live client
// rect. Called from DrawFn before PaintAll and from
// BrowserMouseInput before DispatchEvent so hit-tests + visuals
// stay consistent across window moves / resizes.
void RebindBrowserBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    auto& toolbar = g_browser.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kToolbarH};

    for (u32 i = 0; i < kNavBtnCount; ++i)
    {
        const u32 bx = cx + kToolbarPadX + i * (kToolbarBtnW + kToolbarBtnGap);
        NavButton(i)->bounds = Rect{bx, cy + kToolbarPadY, kToolbarBtnW, kToolbarBtnH};
    }

    // URL bar sits directly below the toolbar; status line
    // sits below that. Both span the full client width
    // (carve-out: the '_' caret in UrlEdit mode is appended
    // into g_urlbar_text by RefreshUrlBarText below).
    const u32 urlbar_y = cy + kToolbarH;
    const u32 status_y = urlbar_y + kUrlBarH;
    UrlBarLabel().bounds =
        Rect{cx + kUrlBarPadX, urlbar_y, (cw > 2U * kUrlBarPadX) ? cw - 2U * kUrlBarPadX : cw, kUrlBarH};
    StatusLabel().bounds =
        Rect{cx + kUrlBarPadX, status_y, (cw > 2U * kUrlBarPadX) ? cw - 2U * kUrlBarPadX : cw, kStatusRowH};

    // Footer hint band along the bottom of the client area.
    const u32 fy = (ch > kFooterH) ? cy + ch - kFooterH : cy;
    const u32 fw = (cw > 2U * kUrlBarPadX) ? cw - 2U * kUrlBarPadX : cw;
    FooterLabel().bounds = Rect{cx + kUrlBarPadX, fy, fw, kFooterH};
}

// Re-compose g_urlbar_text from live state. Mirrors the old
// inline build in DrawHeader: '>' prefix when in UrlEdit mode,
// then the URL itself, then a '_' caret when in UrlEdit mode.
void RefreshUrlBarText()
{
    u32 bp = 0;
    g_urlbar_text[bp++] = (g_state.mode == Mode::UrlEdit) ? '>' : ' ';
    g_urlbar_text[bp++] = ' ';
    for (u32 i = 0; i < g_state.url_len && bp + 1 < sizeof(g_urlbar_text); ++i)
        g_urlbar_text[bp++] = g_state.url[i];
    if (g_state.mode == Mode::UrlEdit && bp + 1 < sizeof(g_urlbar_text))
        g_urlbar_text[bp++] = '_';
    g_urlbar_text[bp] = '\0';
}

// Re-compose g_footer_text. The legacy DrawFn paints a static
// hint; we keep the same shape so the migration is a wash from
// the user's perspective.
void RefreshFooterText()
{
    static const char kHint[] =
        "U:URL  B:BACK  F:FWD  R:RELOAD  H:HIST  L:BMARK  M:MARK  S:SAVE  J/K:SCROLL  n/N:LINK  ENTER:GO";
    u32 i = 0;
    for (; kHint[i] != '\0' && i + 1 < sizeof(g_footer_text); ++i)
        g_footer_text[i] = kHint[i];
    g_footer_text[i] = '\0';
}

// Forward declarations.
void DoFetch(const char* url);
void RescanBookmarks();
void SaveBookmarks();
bool TryParseDottedQuad(const char* host, net::Ipv4Address* out);
void ResolveUrl(const char* base, const char* ref, char* out, u32 cap);
void BuildLinkRects(const char* page_url);
void StartFetch(const char* url);

// ---------------------------------------------------------------
// String helpers — kept self-contained so the browser doesn't
// need a dependency on whatever string library evolves.
// ---------------------------------------------------------------

u32 StrLen(const char* s)
{
    u32 n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

bool StrEqI(const char* a, const char* b)
{
    auto up = [](char c) { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - ('a' - 'A')) : c; };
    while (*a != '\0' && *b != '\0')
    {
        if (up(*a) != up(*b))
            return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

void StrCopyCap(char* dst, u32 cap, const char* src)
{
    u32 i = 0;
    for (; i + 1 < cap && src[i] != '\0'; ++i)
        dst[i] = src[i];
    dst[i] = '\0';
}

void StrAppend(char* dst, u32 cap, const char* src)
{
    u32 len = StrLen(dst);
    for (u32 i = 0; src[i] != '\0' && len + 1 < cap; ++i)
    {
        dst[len++] = src[i];
    }
    dst[len] = '\0';
}

void StatusSet(const char* msg)
{
    StrCopyCap(g_state.status, kStatusCap, msg);
}

// ---------------------------------------------------------------
// URL parsing.
//
// Supported forms:
//   scheme://host[:port][/path]
//   host[:port][/path]            (scheme defaulted to http)
//
// Output:
//   `scheme_https`: true if scheme is "https" (routed through TLS)
//   `host`:        zero-terminated, lower-case-tolerant
//   `port`:        80 default, parsed otherwise
//   `path`:        starts with '/'; defaults to "/"
// ---------------------------------------------------------------

struct ParsedUrl
{
    bool ok;
    bool scheme_https;
    char host[128];
    u16 port;
    char path[160];
};

ParsedUrl ParseUrl(const char* url)
{
    ParsedUrl out{};
    if (url == nullptr || url[0] == '\0')
        return out;

    const char* p = url;
    // Skip whitespace.
    while (*p == ' ' || *p == '\t')
        ++p;

    // Scheme detection. Tolerant: accept either "http://" or
    // "https://"; if neither, assume http.
    if (StrLen(p) >= 7 && p[0] == 'h' && p[1] == 't' && p[2] == 't' && p[3] == 'p' && p[4] == ':' && p[5] == '/' &&
        p[6] == '/')
    {
        p += 7;
    }
    else if (StrLen(p) >= 8 && p[0] == 'h' && p[1] == 't' && p[2] == 't' && p[3] == 'p' && p[4] == 's' && p[5] == ':' &&
             p[6] == '/' && p[7] == '/')
    {
        out.scheme_https = true;
        p += 8;
    }
    // else: bare "host[:port]/path" — keep p where it is.

    // Host (and optional :port). Stop at '/' or end-of-string.
    u32 hi = 0;
    while (*p != '\0' && *p != '/' && hi + 1 < sizeof(out.host))
    {
        out.host[hi++] = *p++;
    }
    out.host[hi] = '\0';
    // Trim and parse :port. Default depends on scheme: 443 for
    // https, 80 otherwise. An explicit ":port" below overrides.
    out.port = out.scheme_https ? 443 : 80;
    for (u32 i = 0; i < hi; ++i)
    {
        if (out.host[i] == ':')
        {
            out.host[i] = '\0';
            u32 port = 0;
            for (u32 j = i + 1; j < hi; ++j)
            {
                const char c = out.host[j];
                if (c < '0' || c > '9')
                {
                    return out;
                }
                port = port * 10 + static_cast<u32>(c - '0');
            }
            if (port == 0 || port > 0xFFFFu)
            {
                return out;
            }
            out.port = static_cast<u16>(port);
            break;
        }
    }
    if (out.host[0] == '\0')
        return out;

    // Path. Default "/". Skip past any '?' fragment until end so
    // the request line is well-formed (the kernel TCP buffer
    // doesn't care, but echo of the URL stays clean).
    if (*p == '\0')
    {
        out.path[0] = '/';
        out.path[1] = '\0';
    }
    else
    {
        u32 pi = 0;
        while (*p != '\0' && pi + 1 < sizeof(out.path))
        {
            out.path[pi++] = *p++;
        }
        out.path[pi] = '\0';
    }

    out.ok = true;
    return out;
}

// IPv4 dotted-quad detector. Used to skip DNS when the host is a
// raw address.
bool TryParseDottedQuad(const char* host, net::Ipv4Address* out)
{
    u32 octets[4] = {0, 0, 0, 0};
    u32 oi = 0;
    bool any_digit = false;
    for (u32 i = 0; host[i] != '\0'; ++i)
    {
        const char c = host[i];
        if (c >= '0' && c <= '9')
        {
            octets[oi] = octets[oi] * 10 + static_cast<u32>(c - '0');
            if (octets[oi] > 255)
                return false;
            any_digit = true;
        }
        else if (c == '.')
        {
            if (!any_digit)
                return false;
            ++oi;
            if (oi >= 4)
                return false;
            any_digit = false;
        }
        else
        {
            return false;
        }
    }
    if (oi != 3 || !any_digit)
        return false;
    for (u32 i = 0; i < 4; ++i)
        out->octets[i] = static_cast<u8>(octets[i]);
    return true;
}

// ---------------------------------------------------------------
// HTML stripping (plain-text utility — NOT the live renderer).
//
// Walk the input, drop tag content (<...>), decode known entities,
// and emit a newline at every block-level close. The LIVE page is now
// rendered through the full web engine (ParseHtml -> ComputeStyles ->
// scripts -> LayoutDocument -> DisplayList -> paint); see RenderPage /
// DrawBody below. This stripper survives only as a tested text-
// extraction helper (BrowserSelfTest) and could back a future
// "view source as text" mode.
// ---------------------------------------------------------------

// Block-level open/close tags whose presence implies a paragraph
// break. Compared case-insensitively against the first 16 bytes
// of the tag content (between '<' and '>').
constexpr const char* kBlockTags[] = {
    "/p", "/div", "/li", "/tr", "/h1", "/h2", "/h3", "/h4", "/h5", "/h6", "br",  "br/", "p",   "tr",    "li",     "h1",
    "h2", "h3",   "h4",  "h5",  "h6",  "/td", "/dl", "/dt", "/dd", "ul",  "/ul", "ol",  "/ol", "table", "/table",
};

bool TagIsBlock(const char* tag_inner)
{
    for (auto* t : kBlockTags)
    {
        // Case-insensitive prefix compare against the first
        // alphabetic-or-slash run; ignore trailing attributes.
        u32 i = 0;
        auto up = [](char c) { return (c >= 'a' && c <= 'z') ? static_cast<char>(c - ('a' - 'A')) : c; };
        for (; t[i] != '\0' && tag_inner[i] != '\0'; ++i)
        {
            if (up(tag_inner[i]) != up(t[i]))
                break;
        }
        if (t[i] == '\0')
        {
            const char nxt = tag_inner[i];
            if (nxt == '\0' || nxt == ' ' || nxt == '\t' || nxt == '/' || nxt == '>')
                return true;
        }
    }
    return false;
}

void EmitChar(char* out, u32 cap, u32* len, char c)
{
    if (*len + 1 >= cap)
        return;
    out[(*len)++] = c;
    out[*len] = '\0';
}

// Common HTML entities. v0 covers the cases real pages use most;
// numeric entities (&#NN;) decode in-band by reading the digits.
struct EntityRow
{
    const char* name;
    char repl;
};
constexpr EntityRow kEntities[] = {
    {"amp", '&'}, {"lt", '<'}, {"gt", '>'}, {"quot", '"'}, {"apos", '\''}, {"nbsp", ' '}, {"copy", 'C'}, {"reg", 'R'},
};

bool DecodeEntity(const char*& p, char* out, u32 cap, u32* len)
{
    // Caller has already consumed '&'. Read until ';' or 8 chars.
    char name[10];
    u32 n = 0;
    while (*p != '\0' && *p != ';' && n + 1 < sizeof(name))
    {
        name[n++] = *p++;
    }
    name[n] = '\0';
    if (*p == ';')
        ++p;
    if (n == 0)
        return false;

    if (name[0] == '#' && n >= 2)
    {
        u32 v = 0;
        const u32 base = (name[1] == 'x' || name[1] == 'X') ? 16 : 10;
        const u32 start = (base == 16) ? 2 : 1;
        for (u32 i = start; i < n; ++i)
        {
            const char c = name[i];
            u32 d;
            if (c >= '0' && c <= '9')
                d = static_cast<u32>(c - '0');
            else if (base == 16 && c >= 'a' && c <= 'f')
                d = static_cast<u32>(c - 'a' + 10);
            else if (base == 16 && c >= 'A' && c <= 'F')
                d = static_cast<u32>(c - 'A' + 10);
            else
                return false;
            v = v * base + d;
        }
        EmitChar(out, cap, len, (v >= 0x20 && v < 0x7F) ? static_cast<char>(v) : '?');
        return true;
    }
    for (auto& e : kEntities)
    {
        if (StrEqI(name, e.name))
        {
            EmitChar(out, cap, len, e.repl);
            return true;
        }
    }
    return false;
}

void StripHtml(const u8* src, u32 src_len, char* dst, u32 dst_cap, u32* dst_len)
{
    *dst_len = 0;
    bool in_tag = false;
    bool in_script = false;
    char tag_buf[20];
    u32 tag_n = 0;
    bool prev_blank = true; // collapse leading whitespace
    for (u32 i = 0; i < src_len && *dst_len + 1 < dst_cap; ++i)
    {
        const char c = static_cast<char>(src[i]);
        if (in_script)
        {
            // Skip everything until "</script". Cheap: look for
            // "</s" followed by "cript" anywhere.
            if (c == '<' && i + 8 < src_len && src[i + 1] == '/' && (src[i + 2] == 's' || src[i + 2] == 'S') &&
                (src[i + 3] == 'c' || src[i + 3] == 'C') && (src[i + 4] == 'r' || src[i + 4] == 'R') &&
                (src[i + 5] == 'i' || src[i + 5] == 'I') && (src[i + 6] == 'p' || src[i + 6] == 'P') &&
                (src[i + 7] == 't' || src[i + 7] == 'T'))
            {
                in_script = false;
                in_tag = true;
                tag_n = 0;
            }
            continue;
        }
        if (in_tag)
        {
            if (c == '>')
            {
                in_tag = false;
                tag_buf[tag_n] = '\0';
                if (TagIsBlock(tag_buf))
                {
                    if (!prev_blank)
                    {
                        EmitChar(dst, dst_cap, dst_len, '\n');
                        prev_blank = true;
                    }
                }
                // Detect <script ...> openers — the tag-content
                // starts with "script" (or "SCRIPT").
                if ((tag_buf[0] == 's' || tag_buf[0] == 'S') && (tag_buf[1] == 'c' || tag_buf[1] == 'C') &&
                    (tag_buf[2] == 'r' || tag_buf[2] == 'R') && (tag_buf[3] == 'i' || tag_buf[3] == 'I') &&
                    (tag_buf[4] == 'p' || tag_buf[4] == 'P') && (tag_buf[5] == 't' || tag_buf[5] == 'T') &&
                    (tag_buf[6] == ' ' || tag_buf[6] == '>' || tag_buf[6] == '\0' || tag_buf[6] == '\t'))
                {
                    in_script = true;
                }
                tag_n = 0;
            }
            else if (tag_n + 1 < sizeof(tag_buf))
            {
                tag_buf[tag_n++] = c;
            }
            continue;
        }
        if (c == '<')
        {
            in_tag = true;
            tag_n = 0;
            continue;
        }
        if (c == '&')
        {
            const char* p = reinterpret_cast<const char*>(src + i + 1);
            const char* before = p;
            if (DecodeEntity(p, dst, dst_cap, dst_len))
            {
                i += static_cast<u32>(p - before);
                prev_blank = false;
                continue;
            }
            // Fall through — emit the raw '&'.
        }
        // Whitespace collapse: convert tabs/CR to space, skip
        // runs of whitespace.
        const bool is_space = (c == ' ' || c == '\t' || c == '\r' || c == '\n');
        if (is_space)
        {
            if (!prev_blank)
            {
                EmitChar(dst, dst_cap, dst_len, ' ');
                prev_blank = true;
            }
        }
        else
        {
            EmitChar(dst, dst_cap, dst_len, c);
            prev_blank = false;
        }
    }
}

// ---------------------------------------------------------------
// History.
// ---------------------------------------------------------------

void HistoryPush(const char* url)
{
    // Truncate any forward history — Chrome / Firefox semantics.
    if (g_state.history_idx < g_state.history_count)
    {
        g_state.history_count = g_state.history_idx;
    }
    if (g_state.history_count >= kHistoryCap)
    {
        // Shift down by one — drop the oldest.
        for (u32 i = 1; i < kHistoryCap; ++i)
        {
            for (u32 j = 0; j < kUrlCap; ++j)
                g_state.history[i - 1][j] = g_state.history[i][j];
        }
        --g_state.history_count;
        if (g_state.history_idx > 0)
            --g_state.history_idx;
    }
    StrCopyCap(g_state.history[g_state.history_count], kUrlCap, url);
    ++g_state.history_count;
    g_state.history_idx = g_state.history_count;
}

// ---------------------------------------------------------------
// Bookmarks load / save.
// ---------------------------------------------------------------

void RescanBookmarks()
{
    namespace fat = fs::fat32;
    g_state.bookmark_count = 0;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return;
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, kBookmarkPath, &e))
        return;
    if ((e.attributes & 0x10) != 0)
        return;
    // 32 bookmarks * 256 bytes = ~8 KiB — heap-allocate to keep
    // the kernel stack small. Cap reads to whatever the live
    // bookmark roster could possibly need plus slack for stray
    // newlines / comments.
    constexpr u64 kBufBytes = static_cast<u64>(kBookmarkCap) * (kUrlCap + 4);
    char* tmp = static_cast<char*>(mm::KMalloc(kBufBytes));
    if (tmp == nullptr)
        return;
    const u64 cap = (e.size_bytes < kBufBytes) ? e.size_bytes : kBufBytes;
    const i64 n = fat::Fat32ReadFile(v, &e, tmp, cap);
    if (n <= 0)
    {
        mm::KFree(tmp);
        return;
    }
    u32 line_start = 0;
    for (u32 i = 0; i < static_cast<u32>(n) && g_state.bookmark_count < kBookmarkCap; ++i)
    {
        if (tmp[i] == '\n' || i == static_cast<u32>(n) - 1)
        {
            const u32 end = (tmp[i] == '\n') ? i : i + 1;
            const u32 len = end - line_start;
            if (len > 0 && len + 1 < kUrlCap)
            {
                u32 j = 0;
                for (; j < len; ++j)
                {
                    g_state.bookmarks[g_state.bookmark_count][j] = tmp[line_start + j];
                }
                g_state.bookmarks[g_state.bookmark_count][j] = '\0';
                if (g_state.bookmarks[g_state.bookmark_count][0] != '\0' &&
                    g_state.bookmarks[g_state.bookmark_count][0] != '#')
                {
                    ++g_state.bookmark_count;
                }
            }
            line_start = i + 1;
        }
    }
    mm::KFree(tmp);
}

void SaveBookmarks()
{
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return;
    // 32 * 260 = ~8 KiB — heap-allocate so the kernel stack
    // (which is intentionally small) doesn't carry it.
    constexpr u64 kBufBytes = static_cast<u64>(kBookmarkCap) * (kUrlCap + 4);
    char* buf = static_cast<char*>(mm::KMalloc(kBufBytes));
    if (buf == nullptr)
        return;
    u32 off = 0;
    for (u32 i = 0; i < g_state.bookmark_count; ++i)
    {
        const char* u = g_state.bookmarks[i];
        for (u32 j = 0; u[j] != '\0' && off + 1 < kBufBytes; ++j)
        {
            buf[off++] = u[j];
        }
        if (off + 1 < kBufBytes)
            buf[off++] = '\n';
    }
    fat::DirEntry probe;
    if (fat::Fat32LookupPath(v, kBookmarkPath, &probe))
    {
        fat::Fat32DeleteAtPath(v, kBookmarkPath);
    }
    fat::Fat32CreateAtPath(v, kBookmarkPath, buf, off);
    mm::KFree(buf);
}

bool BookmarkContains(const char* url)
{
    for (u32 i = 0; i < g_state.bookmark_count; ++i)
    {
        if (StrEqI(g_state.bookmarks[i], url))
            return true;
    }
    return false;
}

// ---------------------------------------------------------------
// Download.
// ---------------------------------------------------------------

u32 NextDownloadIndex(const fs::fat32::Volume* v)
{
    namespace fat = fs::fat32;
    fat::DirEntry tmp[fat::kMaxDirEntries];
    const u32 n = fat::Fat32ListDirByCluster(v, v->root_cluster, tmp, fat::kMaxDirEntries);
    u32 max_idx = 0;
    for (u32 i = 0; i < n; ++i)
    {
        const char* nm = tmp[i].name;
        if (!(nm[0] == 'D' && nm[1] == 'L'))
            continue;
        u32 num = 0;
        bool digits_ok = true;
        for (u32 d = 2; d < 6; ++d)
        {
            const char c = nm[d];
            if (c < '0' || c > '9')
            {
                digits_ok = false;
                break;
            }
            num = num * 10 + static_cast<u32>(c - '0');
        }
        if (!digits_ok)
            continue;
        if (nm[6] != '.')
            continue;
        if (num > max_idx)
            max_idx = num;
    }
    return (max_idx + 1 > 9999) ? 0 : (max_idx + 1);
}

void SaveDownload()
{
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        StatusSet("save: no FAT32 volume");
        return;
    }
    if (g_state.body_len == 0)
    {
        StatusSet("save: no content to save");
        return;
    }
    const u32 idx = NextDownloadIndex(v);
    if (idx == 0)
    {
        KLOG_WARN("apps/browser", "download filename counter exhausted (>9999)");
        StatusSet("save: counter exhausted (>9999)");
        return;
    }
    char path[16];
    path[0] = 'D';
    path[1] = 'L';
    path[2] = static_cast<char>('0' + (idx / 1000) % 10);
    path[3] = static_cast<char>('0' + (idx / 100) % 10);
    path[4] = static_cast<char>('0' + (idx / 10) % 10);
    path[5] = static_cast<char>('0' + idx % 10);
    path[6] = '.';
    path[7] = 'H';
    path[8] = 'T';
    path[9] = 'M';
    path[10] = '\0';
    const i64 rc = fat::Fat32CreateAtPath(v, path, g_state.body, g_state.body_len);
    if (rc < 0)
    {
        StatusSet("save: write failed");
    }
    else
    {
        StatusSet("saved: ");
        StrAppend(g_state.status, kStatusCap, path);
    }
}

// ---------------------------------------------------------------
// Download decision + filename derivation.
//
// A real browser RENDERS text/* responses and SAVES everything else
// (images, archives, PDFs, octet-streams, or any response marked
// `Content-Disposition: attachment`). These helpers are pure compute
// so the self-test can table-test them without spawning the worker.
// ---------------------------------------------------------------

// Case-insensitive substring search. Returns true iff `needle`
// (which must be lowercase) appears anywhere in `hay`.
bool StrContainsI(const char* hay, const char* needle)
{
    if (needle[0] == '\0')
        return true;
    auto lo = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c; };
    for (u32 i = 0; hay[i] != '\0'; ++i)
    {
        u32 j = 0;
        while (needle[j] != '\0' && hay[i + j] != '\0' && lo(hay[i + j]) == needle[j])
            ++j;
        if (needle[j] == '\0')
            return true;
    }
    return false;
}

// True iff a response carrying `content_type` should be rendered as a
// page rather than saved. A missing/empty type is treated as
// renderable (legacy servers omit it for HTML). Only the renderable
// text types qualify; everything else downloads. Matching is on the
// type prefix so "text/html; charset=utf-8" still renders.
bool IsRenderableType(const char* content_type)
{
    if (content_type == nullptr || content_type[0] == '\0')
        return true;
    auto isPrefixI = [](const char* s, const char* pfx)
    {
        auto lo = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c; };
        u32 i = 0;
        for (; pfx[i] != '\0'; ++i)
            if (lo(s[i]) != pfx[i])
                return false;
        return true;
    };
    return isPrefixI(content_type, "text/html") || isPrefixI(content_type, "text/plain") ||
           isPrefixI(content_type, "application/xhtml+xml");
}

// Render-vs-download predicate. DOWNLOAD when the response is marked
// as an attachment, OR carries a non-renderable Content-Type.
bool ShouldDownload(const char* content_type, const char* content_disposition)
{
    if (content_disposition != nullptr && StrContainsI(content_disposition, "attachment"))
        return true;
    return !IsRenderableType(content_type);
}

// Map a Content-Type to a FAT32 3-char extension for the DLxxxx
// fallback name. GAP: small known-type table — unknown types fall
// back to BIN rather than sniffing the body bytes.
const char* ExtForType(const char* content_type)
{
    if (content_type != nullptr)
    {
        auto pfx = [](const char* s, const char* p)
        {
            auto lo = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c; };
            for (u32 i = 0; p[i] != '\0'; ++i)
                if (lo(s[i]) != p[i])
                    return false;
            return true;
        };
        if (pfx(content_type, "application/pdf"))
            return "PDF";
        if (pfx(content_type, "image/png"))
            return "PNG";
        if (pfx(content_type, "image/jpeg"))
            return "JPG";
        if (pfx(content_type, "application/zip"))
            return "ZIP";
    }
    return "BIN";
}

// Append `c` to an 8.3 component buffer, uppercasing and dropping any
// char outside [A-Z0-9]. `cap` bounds the component (8 for stem, 3 for
// ext); `*n` tracks the live length.
void Push83(char* comp, u32 cap, u32* n, char c)
{
    if (*n >= cap)
        return;
    char u = (c >= 'a' && c <= 'z') ? static_cast<char>(c - ('a' - 'A')) : c;
    const bool ok = (u >= 'A' && u <= 'Z') || (u >= '0' && u <= '9');
    if (ok)
        comp[(*n)++] = u;
}

// Derive an 8.3 download filename into `out` (cap >= 13: 8+'.'+3+NUL).
// Priority: (1) a `filename="..."` token in Content-Disposition;
// (2) the URL path's basename if it carries an extension; (3) the
// DLxxxx counter with an extension mapped from Content-Type.
// GAP: 8.3 only — long names and non-ASCII are truncated/dropped, no
// collision-suffixing beyond the DLxxxx counter.
void DeriveDownloadFilename(const char* url, const char* content_type, const char* content_disposition, u32 dl_index,
                            char* out, u32 cap)
{
    char stem[9];
    char ext[4];
    u32 sn = 0;
    u32 en = 0;
    bool have_name = false;

    // (1) Content-Disposition: filename="...".
    if (content_disposition != nullptr)
    {
        const char* fn = nullptr;
        auto lo = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c; };
        const char want[] = "filename";
        for (u32 i = 0; content_disposition[i] != '\0'; ++i)
        {
            // Match the "filename" token case-insensitively at i.
            const char* p = content_disposition + i;
            u32 j = 0;
            for (; want[j] != '\0'; ++j)
                if (lo(p[j]) != want[j])
                    break;
            if (want[j] != '\0')
                continue;
            const char* q = p + j;
            while (*q == ' ')
                ++q;
            if (*q != '=')
                continue;
            ++q;
            while (*q == ' ' || *q == '"')
                ++q;
            fn = q;
            break;
        }
        if (fn != nullptr)
        {
            // Read up to the closing quote / separator into stem.ext,
            // splitting on the LAST '.'.
            char raw_name[64];
            u32 rn = 0;
            for (u32 i = 0; fn[i] != '\0' && fn[i] != '"' && fn[i] != ';' && rn + 1 < sizeof(raw_name); ++i)
                raw_name[rn++] = fn[i];
            raw_name[rn] = '\0';
            u32 dot = rn;
            for (u32 i = 0; i < rn; ++i)
                if (raw_name[i] == '.')
                    dot = i;
            for (u32 i = 0; i < dot; ++i)
                Push83(stem, 8, &sn, raw_name[i]);
            for (u32 i = dot + 1; i < rn; ++i)
                Push83(ext, 3, &en, raw_name[i]);
            if (sn > 0)
                have_name = true;
        }
    }

    // (2) URL path basename with an extension. Reset any partial
    // component left by a disposition whose name sanitised to empty.
    if (!have_name && url != nullptr)
    {
        sn = 0;
        en = 0;
        const ParsedUrl pu = ParseUrl(url);
        if (pu.ok)
        {
            const char* path = pu.path;
            u32 plen = StrLen(path);
            // Strip a trailing query (?...) for basename purposes.
            for (u32 i = 0; i < plen; ++i)
                if (path[i] == '?')
                {
                    plen = i;
                    break;
                }
            u32 slash = 0;
            for (u32 i = 0; i < plen; ++i)
                if (path[i] == '/')
                    slash = i + 1;
            u32 dot = plen;
            for (u32 i = slash; i < plen; ++i)
                if (path[i] == '.')
                    dot = i;
            if (dot < plen && dot + 1 < plen) // has a non-empty extension
            {
                for (u32 i = slash; i < dot; ++i)
                    Push83(stem, 8, &sn, path[i]);
                for (u32 i = dot + 1; i < plen; ++i)
                    Push83(ext, 3, &en, path[i]);
                if (sn > 0 && en > 0)
                    have_name = true;
                else
                {
                    sn = 0;
                    en = 0;
                }
            }
        }
    }

    // (3) DLxxxx fallback, extension from Content-Type.
    if (!have_name)
    {
        sn = 0;
        en = 0;
        const char dl[] = "DL";
        Push83(stem, 8, &sn, dl[0]);
        Push83(stem, 8, &sn, dl[1]);
        Push83(stem, 8, &sn, static_cast<char>('0' + (dl_index / 1000) % 10));
        Push83(stem, 8, &sn, static_cast<char>('0' + (dl_index / 100) % 10));
        Push83(stem, 8, &sn, static_cast<char>('0' + (dl_index / 10) % 10));
        Push83(stem, 8, &sn, static_cast<char>('0' + dl_index % 10));
        const char* e = ExtForType(content_type);
        for (u32 i = 0; e[i] != '\0'; ++i)
            Push83(ext, 3, &en, e[i]);
    }

    // An all-illegal stem (sanitized to empty) falls back to "DL".
    if (sn == 0)
    {
        stem[sn++] = 'D';
        stem[sn++] = 'L';
    }
    if (en == 0)
    {
        const char* e = ExtForType(content_type);
        for (u32 i = 0; e[i] != '\0'; ++i)
            Push83(ext, 3, &en, e[i]);
    }

    // Assemble STEM.EXT into out (cap presumed >= 13).
    u32 o = 0;
    for (u32 i = 0; i < sn && o + 1 < cap; ++i)
        out[o++] = stem[i];
    if (en > 0 && o + 1 < cap)
        out[o++] = '.';
    for (u32 i = 0; i < en && o + 1 < cap; ++i)
        out[o++] = ext[i];
    out[o] = '\0';
}

// Write `len` raw response bytes to FAT32 root under `filename`.
// Replaces an existing entry (the DLxxxx counter usually makes this a
// fresh name, but a Content-Disposition / URL-derived name can repeat).
// Returns true on success and sets g_state.status accordingly.
bool SaveDownloadAs(const u8* data, u32 len, const char* filename)
{
    namespace fat = fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        StatusSet("download: no FAT32 volume");
        return false;
    }
    fat::DirEntry probe;
    if (fat::Fat32LookupPath(v, filename, &probe))
        fat::Fat32DeleteAtPath(v, filename);
    const i64 rc = fat::Fat32CreateAtPath(v, filename, data, len);
    if (rc < 0)
    {
        StatusSet("download: write failed");
        return false;
    }
    StatusSet("Downloaded: ");
    StrAppend(g_state.status, kStatusCap, filename);
    return true;
}

// ---------------------------------------------------------------
// Fetch worker.
// ---------------------------------------------------------------

bool ResolveHost(const char* host, net::Ipv4Address* out)
{
    if (TryParseDottedQuad(host, out))
        return true;
    const auto lease = net::DhcpLeaseRead();
    if (!lease.valid)
        return false;
    if (!net::NetDnsQueryA(0, lease.dns, host))
        return false;
    // Poll 5 seconds.
    for (u32 i = 0; i < 500; ++i)
    {
        sched::SchedSleepTicks(1);
        const auto r = net::NetDnsResultRead();
        if (r.resolved)
        {
            *out = r.ip;
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------
// Time + cookie + TLS-trust glue.
//
// The cookie module is timestamp-driven (Max-Age / Expires).
// Convert the kernel's wall-clock (Windows FILETIME = 100ns ticks
// since 1601-01-01) to a UNIX epoch second so CookieSetFromHeader
// / CookieBuildHeader see the same clock the rest of the world
// does. FILETIME->Unix offset is 11644473600 seconds.
// ---------------------------------------------------------------

i64 NowUnix()
{
    constexpr u64 kFiletimePerSecond = 10000000ULL;     // 100ns ticks per second
    constexpr u64 kFiletimeUnixOffset = 11644473600ULL; // seconds 1601->1970
    const u64 ft = duetos::time::RealtimeFiletime();
    if (ft == 0)
        return 0; // RTC unavailable — treat as epoch (cookies still attach by default Path/Domain)
    const u64 secs1601 = ft / kFiletimePerSecond;
    if (secs1601 <= kFiletimeUnixOffset)
        return 0;
    return static_cast<i64>(secs1601 - kFiletimeUnixOffset);
}

// x509 verifier adapter. net::tls::CertVerifyFn hands us the server's
// leaf DER + the intermediate chain it sent + the hostname;
// net::x509::Verify wants the same shape plus a wall-clock. The two
// chain-parameter triples line up 1:1, so we forward them verbatim and
// supply NowUnix() for the validity window. This verifies the server's
// full chain against x509's embedded trust store — which now carries
// real, widely-trusted roots (DigiCert, Amazon, ISRG/Let's Encrypt,
// GlobalSign, Go Daddy, AffirmTrust; see x509_verify.h), so a
// real-internet leaf that chains to one of those roots is accepted.
//
// GAP: NOT full PKI. Verification covers signature + chain-to-embedded-
//      root (depth <= 2: leaf + one intermediate) + hostname (SAN/CN
//      with leftmost wildcard) + validity window. It does NOT do CRL/
//      OCSP revocation (a revoked-but-unexpired cert still verifies),
//      name constraints, or EKU/KU policy, and the embedded root set is
//      a hand-picked subset of the CCADB program — sites chaining to any
//      other root fail closed. See x509_verify.h for the precise list.
bool BrowserCertVerify(const u8* leaf_der, u32 leaf_len, const u8* const* chain_ders, const u32* chain_lens,
                       u32 chain_count, const char* hostname, void* /*ctx*/)
{
    const u64 now = static_cast<u64>(NowUnix());
    return net::x509::Verify(leaf_der, leaf_len, chain_ders, chain_lens, chain_count, hostname, now);
}

void InstallTlsVerifierOnce()
{
    static bool installed = false;
    if (installed)
        return;
    installed = true;
    net::tls::TlsSocketSetVerifier(BrowserCertVerify, nullptr);
}

// ---------------------------------------------------------------
// HttpTransport factories.
//
// http://  — ctx is the socket pool index; read/write hit the TCB
//            stream directly.
// https:// — ctx is a heap-allocated TlsState (TLS session + its
//            socket index). read/write encrypt/decrypt application
//            records.
// ---------------------------------------------------------------

i64 PlainTransportRead(void* ctx, u8* buf, u32 len)
{
    return net::SocketRecvStream(static_cast<u32>(reinterpret_cast<u64>(ctx)), buf, len);
}

i64 PlainTransportWrite(void* ctx, const u8* buf, u32 len)
{
    const u32 idx = static_cast<u32>(reinterpret_cast<u64>(ctx));
    u32 sent = 0;
    while (sent < len)
    {
        const i64 n = net::SocketSendStream(idx, buf + sent, len - sent);
        if (n <= 0)
            return -1;
        sent += static_cast<u32>(n);
    }
    return static_cast<i64>(len);
}

// TLS session + the socket index it rides on, owned for the life of
// one FetchUrl call (and any redirect transports it opens).
struct TlsState
{
    net::tls::TlsSocketState tls;
    i32 sock;
};

i64 TlsTransportRead(void* ctx, u8* buf, u32 len)
{
    return net::tls::TlsSocketRecv(&static_cast<TlsState*>(ctx)->tls, buf, len);
}

i64 TlsTransportWrite(void* ctx, const u8* buf, u32 len)
{
    return net::tls::TlsSocketSend(&static_cast<TlsState*>(ctx)->tls, buf, len);
}

// Result codes FetchUrl reports back so the UI can render a precise
// status without knowing the transport details.
enum class FetchStatus : u8
{
    Ok = 0,
    BadUrl,
    DnsFailed,
    ConnectFailed,
    CertUntrusted,
    TlsHandshakeFailed,
    HttpError,
    Oom,
};

// Open a transport to (scheme_https, host, port). On success fills
// *out, sets *out_sock to the owning socket index (caller releases
// it) and, for TLS, *out_tls to the heap TlsState (caller frees it).
// Returns a FetchStatus. Shared by the initial request and the
// redirect connect hook.
FetchStatus OpenTransport(bool scheme_https, const char* host, u16 port, net::http::HttpTransport* out, i32* out_sock,
                          TlsState** out_tls)
{
    *out_sock = -1;
    *out_tls = nullptr;

    net::Ipv4Address ip{};
    if (!ResolveHost(host, &ip))
        return FetchStatus::DnsFailed;
    const u32 ip_be = static_cast<u32>(ip.octets[0]) | (static_cast<u32>(ip.octets[1]) << 8) |
                      (static_cast<u32>(ip.octets[2]) << 16) | (static_cast<u32>(ip.octets[3]) << 24);

    if (scheme_https)
    {
        InstallTlsVerifierOnce();
        TlsState* st = static_cast<TlsState*>(mm::KMalloc(sizeof(TlsState)));
        if (st == nullptr)
            return FetchStatus::Oom;
        *st = TlsState{};
        const i32 sock = net::tls::TlsSocketConnect(&st->tls, host, ip_be, port);
        if (sock < 0)
        {
            mm::KFree(st);
            // TlsSocketConnect collapses TCP-connect failure, verify
            // rejection, and handshake failure into -1. The most
            // actionable message for the test-only trust store is the
            // cert one, but distinguish a clearly-unreachable host.
            return FetchStatus::TlsHandshakeFailed;
        }
        st->sock = sock;
        out->read = TlsTransportRead;
        out->write = TlsTransportWrite;
        out->ctx = st;
        *out_sock = sock;
        *out_tls = st;
        return FetchStatus::Ok;
    }

    const i32 sock = net::SocketAlloc(net::kSocketDomainInet, net::kSocketTypeStream);
    if (sock < 0)
    {
        KLOG_ONCE_WARN("apps/browser", "socket pool exhausted on TCP open");
        return FetchStatus::ConnectFailed;
    }
    if (!net::SocketConnect(static_cast<u32>(sock), ip, port))
    {
        net::SocketRelease(static_cast<u32>(sock));
        return FetchStatus::ConnectFailed;
    }
    out->read = PlainTransportRead;
    out->write = PlainTransportWrite;
    out->ctx = reinterpret_cast<void*>(static_cast<u64>(static_cast<u32>(sock)));
    *out_sock = sock;
    return FetchStatus::Ok;
}

void CloseTransport(i32 sock, TlsState* tls)
{
    if (tls != nullptr)
    {
        net::tls::TlsSocketClose(&tls->tls);
        if (tls->sock >= 0)
            net::SocketRelease(static_cast<u32>(tls->sock));
        mm::KFree(tls);
    }
    else if (sock >= 0)
    {
        net::SocketRelease(static_cast<u32>(sock));
    }
}

// Redirect connect hook: HttpRequest calls this when a 3xx points
// at a (possibly new) origin. We open a fresh transport and stash
// the owning socket/TLS pointers so DoFetch can tear them all down.
// Tracks every transport it opens (up to the redirect hop cap) so
// none leak.
struct RedirectTracker
{
    static constexpr u32 kMaxHops = net::http::kDefaultMaxRedirects + 1;
    i32 socks[kMaxHops];
    TlsState* tlss[kMaxHops];
    u32 count;
};

bool RedirectConnect(bool scheme_https, const char* host, u16 port, net::http::HttpTransport* out, void* ctx)
{
    RedirectTracker* rt = static_cast<RedirectTracker*>(ctx);
    if (rt->count >= RedirectTracker::kMaxHops)
        return false;
    i32 sock = -1;
    TlsState* tls = nullptr;
    if (OpenTransport(scheme_https, host, port, out, &sock, &tls) != FetchStatus::Ok)
        return false;
    rt->socks[rt->count] = sock;
    rt->tlss[rt->count] = tls;
    ++rt->count;
    return true;
}

// Set-Cookie hook: feed every response header value into the jar,
// keyed by the request host + path the cookie ctx carries.
struct CookieCtx
{
    const char* host;
    const char* path;
    i64 now;
};

void OnSetCookie(const char* header_value, void* ctx)
{
    CookieCtx* cc = static_cast<CookieCtx*>(ctx);
    net::CookieSetFromHeader(cc->host, cc->path, header_value, cc->now);
}

// ---------------------------------------------------------------
// FetchUrl — UI-decoupled fetch over an HttpTransport.
//
// Parses `url`, opens the right transport (plain / TLS), attaches
// cookies, drives net::http::HttpRequest (redirects + chunked +
// Content-Length), and writes the RAW (un-stripped) response body
// into raw_buf. The caller strips HTML for display. `transport`,
// when non-null, is used as-is (the self-test injects a loopback
// transport); when null FetchUrl opens a real socket/TLS transport.
// ---------------------------------------------------------------
// `ct_out` / `cd_out`, when non-null, receive the response's
// Content-Type / Content-Disposition header values (copied out of the
// short-lived `result`). They are emptied first so a missing header
// reads as "". `ct_cap` / `cd_cap` are their buffer capacities.
FetchStatus FetchUrl(const char* url, u8* raw_buf, u32 raw_cap, u32* raw_len, u16* status_out, bool* truncated_out,
                     net::http::HttpTransport* injected, net::http::HttpConnect injected_connect = nullptr,
                     void* injected_connect_ctx = nullptr, char* ct_out = nullptr, u32 ct_cap = 0,
                     char* cd_out = nullptr, u32 cd_cap = 0)
{
    *raw_len = 0;
    *status_out = 0;
    *truncated_out = false;
    if (ct_out != nullptr && ct_cap > 0)
        ct_out[0] = '\0';
    if (cd_out != nullptr && cd_cap > 0)
        cd_out[0] = '\0';

    const auto p = ParseUrl(url);
    if (!p.ok)
        return FetchStatus::BadUrl;

    const i64 now = NowUnix();

    // Open the primary transport (unless the caller injected one).
    net::http::HttpTransport transport{};
    i32 primary_sock = -1;
    TlsState* primary_tls = nullptr;
    if (injected != nullptr)
    {
        transport = *injected;
    }
    else
    {
        const FetchStatus st = OpenTransport(p.scheme_https, p.host, p.port, &transport, &primary_sock, &primary_tls);
        if (st != FetchStatus::Ok)
            return st;
    }

    // Build the Cookie request header from the jar.
    char cookie_hdr[768];
    const u32 cookie_n = net::CookieBuildHeader(p.host, p.path, p.scheme_https, now, cookie_hdr, sizeof(cookie_hdr));

    CookieCtx cookie_ctx{p.host, p.path, now};
    RedirectTracker redirects{};

    net::http::HttpRequestSpec spec{};
    spec.method = net::http::HttpMethod::Get;
    spec.scheme_https = p.scheme_https;
    StrCopyCap(spec.host, sizeof(spec.host), p.host);
    spec.port = p.port;
    StrCopyCap(spec.path, sizeof(spec.path), p.path);
    spec.user_agent = "DuetOS-Browser/0.2";
    spec.accept = "text/html,*/*";
    spec.cookie_header = (cookie_n > 0) ? cookie_hdr : nullptr;
    // The self-test injects a canned redirect harness; production
    // uses the socket-opening RedirectConnect + tracker.
    spec.on_connect = (injected_connect != nullptr) ? injected_connect : RedirectConnect;
    spec.connect_ctx = (injected_connect != nullptr) ? injected_connect_ctx : &redirects;
    spec.body_buf = raw_buf;
    spec.body_cap = raw_cap;
    spec.on_set_cookie = OnSetCookie;
    spec.cookie_ctx = &cookie_ctx;

    net::http::HttpResult result{};
    const bool ok = net::http::HttpRequest(spec, &transport, &result);

    // Tear down the primary transport + every redirect transport.
    CloseTransport(primary_sock, primary_tls);
    for (u32 i = 0; i < redirects.count; ++i)
        CloseTransport(redirects.socks[i], redirects.tlss[i]);

    if (!ok)
        return FetchStatus::HttpError;

    *status_out = static_cast<u16>(result.status_code);
    *raw_len = result.body_len;
    *truncated_out = result.body_truncated || (result.body_len >= raw_cap);

    // Copy the content-classification headers out before `result` (a
    // stack local) goes out of scope; the caller uses them to decide
    // render-vs-download and to derive a saved filename.
    if (ct_out != nullptr && ct_cap > 0)
    {
        const char* ct = result.FindHeader("Content-Type");
        if (ct != nullptr)
            StrCopyCap(ct_out, ct_cap, ct);
    }
    if (cd_out != nullptr && cd_cap > 0)
    {
        const char* cd = result.FindHeader("Content-Disposition");
        if (cd != nullptr)
            StrCopyCap(cd_out, cd_cap, cd);
    }

    // Persist any cookies the response set.
    net::CookieJarSave();
    return FetchStatus::Ok;
}

void FetchWorker(void* arg_v)
{
    const char* url = static_cast<const char*>(arg_v);
    DoFetch(url);
    g_state.fetch_in_flight = false;
    sched::SchedExit();
}

// Append the numeric HTTP status + any truncation banner to a
// caller buffer. Shared by the OK path.
void FormatHttpStatus(char* buf, u32 cap, u16 code, bool truncated)
{
    u32 sp = 0;
    auto append = [&](const char* s)
    {
        for (u32 k = 0; s[k] != '\0' && sp + 1 < cap; ++k)
            buf[sp++] = s[k];
        buf[sp] = '\0';
    };
    append("HTTP ");
    if (code == 0)
    {
        append("(no code)");
    }
    else
    {
        char d[6];
        u32 dn = 0;
        u32 c = code;
        while (c > 0 && dn < sizeof(d))
        {
            d[dn++] = static_cast<char>('0' + c % 10);
            c /= 10;
        }
        while (dn > 0 && sp + 1 < cap)
            buf[sp++] = d[--dn];
        buf[sp] = '\0';
    }
    if (truncated)
        append(" (truncated to 64 KiB)");
}

// ---------------------------------------------------------------
// Render pipeline: ParseHtml -> gather author CSS -> ComputeStyles ->
// run <script>s against the live DOM -> LayoutDocument -> DisplayList.
// All allocation comes from g_render_arena_buf so the resulting display
// list outlives DoFetch (DrawBody paints it later, off the same state).
// ---------------------------------------------------------------

// Resolve a (possibly relative) reference `ref` against `base` into
// `out`. Handles: absolute http(s):// (copied as-is), scheme-relative
// (//host/...), root-relative (/path), and same-directory relative
// (path). GAP: no `..` collapsing, no query/fragment normalisation —
// enough for the common <img src> shapes a v0 page ships.
void ResolveUrl(const char* base, const char* ref, char* out, u32 cap)
{
    if (ref == nullptr || ref[0] == '\0')
    {
        out[0] = '\0';
        return;
    }
    // Absolute.
    if ((StrLen(ref) >= 7 && ref[0] == 'h' && ref[1] == 't' && ref[2] == 't' && ref[3] == 'p' &&
         (ref[4] == ':' || (ref[4] == 's' && ref[5] == ':'))))
    {
        StrCopyCap(out, cap, ref);
        return;
    }
    const auto bp = ParseUrl(base);
    if (!bp.ok)
    {
        StrCopyCap(out, cap, ref);
        return;
    }
    // Scheme-relative: //host/path.
    if (ref[0] == '/' && ref[1] == '/')
    {
        StrCopyCap(out, cap, bp.scheme_https ? "https:" : "http:");
        StrAppend(out, cap, ref);
        return;
    }
    // Build "scheme://host" prefix.
    StrCopyCap(out, cap, bp.scheme_https ? "https://" : "http://");
    StrAppend(out, cap, bp.host);
    if (ref[0] == '/')
    {
        // Root-relative.
        StrAppend(out, cap, ref);
        return;
    }
    // Same-directory relative: take base path up to the last '/'.
    char dir[160];
    StrCopyCap(dir, sizeof(dir), bp.path);
    u32 cut = 0;
    for (u32 i = 0; dir[i] != '\0'; ++i)
    {
        if (dir[i] == '/')
            cut = i + 1;
    }
    dir[cut] = '\0';
    StrAppend(out, cap, dir);
    StrAppend(out, cap, ref);
}

// Fetch + decode the image at `url` into the image arena, returning its
// PaintImage (rgba==nullptr on failure). Sniffs PNG vs JPEG by magic.
duetos::web::PaintImage DecodeImage(const char* url)
{
    duetos::web::PaintImage out{};
    u8* raw = static_cast<u8*>(mm::KMalloc(kHttpResponseCap));
    if (raw == nullptr)
        return out;

    u32 got = 0;
    u16 code = 0;
    bool trunc = false;
    const FetchStatus st = FetchUrl(url, raw, kHttpResponseCap, &got, &code, &trunc, /*injected=*/nullptr);
    if (st != FetchStatus::Ok || got < 4)
    {
        mm::KFree(raw);
        return out;
    }

    if (raw[0] == 0x89 && raw[1] == 0x50 && raw[2] == 0x4E && raw[3] == 0x47)
    {
        duetos::web::PngImage png{};
        if (duetos::web::PngDecode(raw, got, g_images.arena, &png))
        {
            out.rgba = png.pixels;
            out.w = png.width;
            out.h = png.height;
        }
    }
    else if (raw[0] == 0xFF && raw[1] == 0xD8)
    {
        duetos::web::JpegImage jpg{};
        if (duetos::web::JpegDecode(raw, got, g_images.arena, &jpg))
        {
            out.rgba = jpg.pixels;
            out.w = jpg.width;
            out.h = jpg.height;
        }
    }
    mm::KFree(raw);
    return out;
}

// Painter ImageProvider callback: resolve <img src> against the page
// URL, return a cached decode, or fetch+decode (and cache) on first
// sight. A cache slot with rgba==nullptr is a remembered failure so we
// don't refetch a broken image every paint.
duetos::web::PaintImage ImageProviderFn(const char* src, u32 /*srcLen*/, void* /*ctx*/)
{
    duetos::web::PaintImage none{};
    if (src == nullptr || src[0] == '\0')
        return none;

    char abs[kUrlCap];
    ResolveUrl(g_images.page_url, src, abs, sizeof(abs));
    if (abs[0] == '\0')
        return none;

    for (u32 i = 0; i < g_images.count; ++i)
    {
        if (g_images.entries[i].used && StrEqI(g_images.entries[i].url, abs))
            return g_images.entries[i].img;
    }
    if (g_images.count >= kImageCacheCap)
        return none; // cache full — placeholder

    ImageCacheEntry& e = g_images.entries[g_images.count++];
    StrCopyCap(e.url, sizeof(e.url), abs);
    e.img = DecodeImage(abs);
    e.used = true;
    return e.img;
}

// Concatenate every <style> element's text into `out` (recursive walk),
// NUL-terminated, truncated to cap-1.
u32 GatherStyles(const duetos::web::Node* node, char* out, u32 cap, u32 len)
{
    using duetos::web::NodeKind;
    for (const duetos::web::Node* c = node->firstChild; c != nullptr; c = c->nextSibling)
    {
        if (c->kind == NodeKind::Element && c->tag != nullptr && StrEqI(c->tag, "style"))
        {
            for (const duetos::web::Node* t = c->firstChild; t != nullptr; t = t->nextSibling)
            {
                if (t->kind == NodeKind::Text && t->text != nullptr)
                {
                    for (u32 i = 0; t->text[i] != '\0' && len + 1 < cap; ++i)
                        out[len++] = t->text[i];
                }
            }
        }
        len = GatherStyles(c, out, cap, len);
    }
    out[(len < cap) ? len : cap - 1] = '\0';
    return len;
}

// Run every <script> element's text against the RETAINED JS context (so
// scripts mutate the tree before layout AND any listeners they register
// via addEventListener persist into `ctx` for a later user-click
// dispatch). All scripts on the page share the single `ctx`, so a handler
// defined in one <script> sees globals from another. Each RunScript call
// is bounded by the JS engine's step budget, so a runaway page script
// returns an error rather than hanging the browser.
void RunScripts(duetos::web::JsDomContext* ctx, duetos::web::Node* node)
{
    using duetos::web::NodeKind;
    for (duetos::web::Node* c = node->firstChild; c != nullptr; c = c->nextSibling)
    {
        if (c->kind == NodeKind::Element && c->tag != nullptr && StrEqI(c->tag, "script"))
        {
            for (duetos::web::Node* t = c->firstChild; t != nullptr; t = t->nextSibling)
            {
                if (t->kind == NodeKind::Text && t->text != nullptr && t->text[0] != '\0')
                {
                    // A page <script> that fails to parse/run is a normal
                    // web condition (and an engine-coverage gap surfacer) —
                    // log it gated rather than failing the render. Listeners
                    // a failed script would have registered simply don't.
                    // A page <script> that fails to parse/run is a normal
                    // web condition — log it gated rather than failing the
                    // render; listeners it would have registered just don't.
                    const duetos::core::Result<void> sr =
                        duetos::web::JsDomContextRunScript(ctx, t->text, StrLen(t->text));
                    if (!sr)
                    {
                        KLOG_WARN("apps/browser", "page script error");
                    }
                }
            }
        }
        RunScripts(ctx, c);
    }
}

// Compute the laid-out page's total height in device px (max bottom of
// any display item) so the scrollbar / scroll clamp have a real extent.
i32 DisplayListHeight(const duetos::web::DisplayList& dl)
{
    i32 maxY = 0;
    for (u32 i = 0; i < dl.count; ++i)
    {
        const i32 bottom = dl.items[i].rect.y + dl.items[i].rect.h;
        if (bottom > maxY)
            maxY = bottom;
    }
    return maxY;
}

// BuildLinkRects — scan the freshly-laid-out display list for items the
// layout engine tagged with an <a href> (TextRun / ImageBox / a styled
// anchor's FillRect / Border), resolve each href against `page_url` into
// an absolute URL, and record a DOCUMENT-coordinate hit rect per link.
//
// A single anchor can produce several display items (a wrapped link spans
// multiple TextRuns; an anchor's bg + border + text all carry the same
// href pointer). We coalesce items that share the SAME href POINTER into
// one bounding rect — the layout engine threads the one arena-owned href
// string through every item of an anchor, so pointer identity cleanly
// groups them without a string compare. (Two distinct anchors pointing at
// the same URL keep separate rects, which is what a user expects.)
void BuildLinkRects(const char* page_url)
{
    g_state.link_count = 0;
    g_state.focus_link = kNoLink;
    if (g_state.render_dl == nullptr)
    {
        return;
    }
    const duetos::web::DisplayList& dl = *g_state.render_dl;
    for (u32 i = 0; i < dl.count; ++i)
    {
        const auto& it = dl.items[i];
        if (it.href == nullptr || it.href[0] == '\0')
        {
            continue;
        }
        // Empty geometry can't be hit; skip it (still resolves a later,
        // non-empty item of the same anchor).
        if (it.rect.w <= 0 || it.rect.h <= 0)
        {
            continue;
        }

        // Coalesce into an existing rect sharing the same href pointer.
        bool merged = false;
        for (u32 j = 0; j < g_state.link_count; ++j)
        {
            // Identity is by absolute href string here — the document-side
            // pointer isn't stored, so compare the resolved URL plus
            // require vertical adjacency so two far-apart links to the same
            // page stay distinct. A wrapped link's runs sit on consecutive
            // lines, so their rects touch/overlap vertically.
            State::LinkRect& lr = g_state.link_rects[j];
            char abs_i[kUrlCap];
            ResolveUrl(page_url, it.href, abs_i, sizeof(abs_i));
            const bool same_href = StrEqI(lr.href, abs_i);
            const i32 lr_bottom = lr.rect.y + lr.rect.h;
            const i32 it_bottom = it.rect.y + it.rect.h;
            const bool adjacent = (it.rect.y <= lr_bottom + 4) && (it_bottom + 4 >= lr.rect.y);
            if (same_href && adjacent)
            {
                const i32 x0 = (lr.rect.x < it.rect.x) ? lr.rect.x : it.rect.x;
                const i32 y0 = (lr.rect.y < it.rect.y) ? lr.rect.y : it.rect.y;
                const i32 x1 =
                    (lr.rect.x + lr.rect.w > it.rect.x + it.rect.w) ? lr.rect.x + lr.rect.w : it.rect.x + it.rect.w;
                const i32 y1 = (lr_bottom > it_bottom) ? lr_bottom : it_bottom;
                lr.rect.x = x0;
                lr.rect.y = y0;
                lr.rect.w = x1 - x0;
                lr.rect.h = y1 - y0;
                merged = true;
                break;
            }
        }
        if (merged)
        {
            continue;
        }

        if (g_state.link_count >= kLinkRectCap)
        {
            break; // table full — remaining links aren't clickable (GAP)
        }
        State::LinkRect& lr = g_state.link_rects[g_state.link_count];
        lr.rect = it.rect;
        ResolveUrl(page_url, it.href, lr.href, sizeof(lr.href));
        if (lr.href[0] == '\0')
        {
            // Unresolvable (e.g. javascript:/mailto: or empty base) —
            // don't record a dead hit rect.
            continue;
        }
        ++g_state.link_count;
    }
}

// RelayoutFromDoc — (re)style + lay out an already-parsed DOM into the
// resettable LAYOUT arena, refreshing render_dl / total height / link
// rects. Called once by RenderPage after scripts run, and again by the
// click path after a handler mutates the DOM (so the change reaches the
// screen). Resets g_layout_arena each call, so re-layout never grows the
// layout arena — only the DOM arena grows when a handler adds nodes.
//
// GAP: a click handler that mutates the DOM on every click (e.g. a
// counter doing `el.textContent = n` each time) allocates a fresh DOM
// node per mutation into g_render_arena, which the bump allocator never
// frees (orphaned nodes persist). After ~thousands of mutations the DOM
// arena exhausts and SetTextContent/SetInnerHtml start returning false
// (the mutation is silently dropped, no fault). A real reclaiming DOM
// allocator would lift this; for v0 the 1 MiB DOM budget covers ordinary
// interactive pages. Uses g_images.page_url (set by RenderPage) for link
// resolution, so the page URL need not be re-threaded. Returns false only
// if layout itself fails (arena exhaustion).
bool RelayoutFromDoc(duetos::web::Node* doc, u32 viewport_w)
{
    if (doc == nullptr)
        return false;

    // Reset the layout arena: the prior sheet/styles/display list are
    // discarded wholesale. Their string payloads pointed into the DOM
    // (which persists), so nothing dangles.
    g_layout_arena = duetos::web::Arena(g_layout_arena_buf, kLayoutArenaBytes);
    duetos::web::Arena& la = g_layout_arena;

    // Author CSS from <style> elements (inline style="" is folded in by
    // ComputeStyles directly off each element's attribute).
    static char css_buf[16 * 1024];
    GatherStyles(doc, css_buf, sizeof(css_buf), 0);

    duetos::web::StyleSheet sheet;
    duetos::web::AppendUserAgentStyles(sheet, la);
    duetos::web::ParseStyleSheet(sheet, css_buf, StrLen(css_buf), /*userAgent=*/false, la);

    duetos::web::StyleMap styles = duetos::web::ComputeStyles(doc, sheet, la);

    // Monospace metrics matching the 8x8 console font (cell height 16px
    // gives readable line spacing; the painter scales the 8x8 bitmap).
    duetos::web::TextMetrics tm;
    tm.glyphW = 8;
    tm.glyphH = 16;
    tm.baseFontPx = 16;

    duetos::web::DisplayList* dl = duetos::web::LayoutDocument(doc, styles, viewport_w, tm, la);
    if (dl == nullptr)
        return false;

    // Pre-warm the image cache (resolve + decode every ImageBox up front)
    // so the ImageProvider is a pure cache lookup at PAINT time and DrawBody
    // never does network I/O under the compositor lock.
    for (u32 i = 0; i < dl->count; ++i)
    {
        if (dl->items[i].cmd == duetos::web::DisplayCmd::ImageBox)
            ImageProviderFn(dl->items[i].src, dl->items[i].srcLen, nullptr);
    }

    g_state.render_dl = dl;
    g_state.render_total_h = DisplayListHeight(*dl);
    g_state.render_viewport_w = viewport_w;

    // Rebuild the link hit-test table from the laid-out display list
    // (links tagged by layout, resolved against the page URL).
    BuildLinkRects(g_images.page_url);
    return true;
}

// RenderPage — UI-decoupled: parse, script, lay out one page and stash
// the display list + height for DrawBody. The DOM goes in the persistent
// render arena (so click-time handler mutations persist); styles + layout
// go in the resettable layout arena via RelayoutFromDoc. `page_url` drives
// relative <img src> resolution.
void RenderPage(const char* html, u32 len, const char* page_url, u32 viewport_w)
{
    g_state.render_ready = false;
    g_state.render_dl = nullptr;
    g_state.render_total_h = 0;
    g_state.scroll_y = 0;
    g_state.render_viewport_w = viewport_w;
    // Drop the previous page's interactive context up front: if this
    // render bails early (parse failure) or never installs a context
    // (OOM), a stale ctx pointing at a freed/overwritten DOM must not
    // survive into the click path.
    g_state.page_ctx = nullptr;
    g_state.page_doc = nullptr;

    // Reset the image cache for the new page (the decoded pixels in the
    // image arena are reclaimed wholesale).
    g_images.count = 0;
    g_images.arena = duetos::web::PngArena(g_image_arena_buf, kImageArenaBytes);
    StrCopyCap(g_images.page_url, sizeof(g_images.page_url), page_url);

    // Reset the PERSISTENT render arena (it must outlive this call so the
    // retained JsDomContext can allocate listener-created DOM nodes at
    // click time). `arena` aliases the global; passing it to
    // JsDomContextCreate hands the context a pointer to the persistent
    // object, not a soon-to-be-destroyed stack local.
    g_render_arena = duetos::web::Arena(g_render_arena_buf, kRenderArenaBytes);
    duetos::web::Arena& arena = g_render_arena;

    duetos::web::Node* doc = duetos::web::ParseHtml(html, len, arena);
    if (doc == nullptr)
        return;

    // Run scripts BEFORE styling+layout so DOM mutations are reflected.
    // Create ONE retained context for the whole page (so all <script>s
    // share globals AND any addEventListener registrations survive to be
    // fired by a later user click), then run each <script> against it.
    // Keep ctx + doc in g_state so the click path can dispatch into the
    // listeners; both stay valid until the next RenderPage (render arena +
    // singleton context persist). If Create fails (OOM / no env), fall
    // through with a null ctx — RunScripts is skipped and the page is
    // link-only, never faulting.
    static char console_buf[4096];
    duetos::web::JsDomContext* ctx = duetos::web::JsDomContextCreate(doc, arena, console_buf, sizeof(console_buf));
    if (ctx != nullptr)
    {
        RunScripts(ctx, doc);
        // Scripts may have mutated the DOM before first paint; the upcoming
        // layout reflects that, so consume the flag now (it must not survive
        // into the first user click as a spurious re-layout request).
        duetos::web::JsDomContextConsumeDirty(ctx);
        g_state.page_ctx = ctx;
        g_state.page_doc = doc;
    }

    // Style + lay out the (post-script) DOM into the layout arena.
    if (!RelayoutFromDoc(doc, viewport_w))
        return;

    g_state.render_ready = true;
}

void DoFetch(const char* url)
{
    g_state.body_len = 0;
    g_state.body[0] = '\0';
    g_state.truncated = false;
    g_state.scroll_row = 0;
    g_state.scroll_y = 0;
    g_state.render_ready = false;
    g_state.render_dl = nullptr;
    g_state.status_code = 0;
    g_state.link_count = 0;
    g_state.focus_link = kNoLink;
    // Drop the prior page's interactive context: a download / error /
    // non-HTML response below may not call RenderPage, and a stale ctx
    // would point at a DOM no longer reflected on screen. RenderPage
    // re-creates it for an HTML page.
    g_state.page_ctx = nullptr;
    g_state.page_doc = nullptr;

    const auto p = ParseUrl(url);
    if (!p.ok)
    {
        StatusSet("bad URL");
        return;
    }

    StatusSet(p.scheme_https ? "connecting (TLS) " : "connecting ");
    StrAppend(g_state.status, kStatusCap, p.host);

    u8* raw = static_cast<u8*>(mm::KMalloc(kHttpResponseCap));
    if (raw == nullptr)
    {
        KLOG_ERROR_V("apps/browser", "KMalloc failed for HTTP response buffer (cap)", kHttpResponseCap);
        StatusSet("OOM (heap exhausted)");
        return;
    }

    u32 got = 0;
    u16 code = 0;
    bool truncated = false;
    char content_type[128] = {};
    char content_disp[256] = {};
    const FetchStatus st = FetchUrl(url, raw, kHttpResponseCap, &got, &code, &truncated, /*injected=*/nullptr,
                                    /*injected_connect=*/nullptr, /*injected_connect_ctx=*/nullptr, content_type,
                                    sizeof(content_type), content_disp, sizeof(content_disp));

    if (st != FetchStatus::Ok)
    {
        switch (st)
        {
        case FetchStatus::BadUrl:
            StatusSet("bad URL");
            break;
        case FetchStatus::DnsFailed:
            StatusSet("DNS resolve failed: ");
            StrAppend(g_state.status, kStatusCap, p.host);
            break;
        case FetchStatus::ConnectFailed:
            StatusSet("TCP connect failed");
            break;
        case FetchStatus::CertUntrusted:
            StatusSet("certificate not trusted (TLS verify failed)");
            break;
        case FetchStatus::TlsHandshakeFailed:
            // The test-only trust store rejects real-internet leaves;
            // surface that as the most likely cause.
            StatusSet("TLS failed / certificate not trusted");
            break;
        case FetchStatus::Oom:
            StatusSet("OOM (heap exhausted)");
            break;
        case FetchStatus::HttpError:
        default:
            StatusSet("no response / HTTP error");
            break;
        }
        mm::KFree(raw);
        return;
    }

    g_state.status_code = code;
    g_state.truncated = truncated;

    // Download path: an attachment-marked or non-text response is
    // SAVED to disk (raw bytes) instead of rendered. GAP: no resume,
    // no progress UI, no body-byte MIME sniffing — the decision is
    // header-driven only, and the body is capped at kHttpResponseCap.
    if (ShouldDownload(content_type, content_disp))
    {
        namespace fat = fs::fat32;
        const fat::Volume* dlv = fat::Fat32Volume(0);
        const u32 dl_index = (dlv != nullptr) ? NextDownloadIndex(dlv) : 0;
        char filename[16];
        DeriveDownloadFilename(url, content_type, content_disp, dl_index, filename, sizeof(filename));
        SaveDownloadAs(raw, got, filename);
        mm::KFree(raw);
        // Record the navigation; do NOT RenderPage (status already set
        // by SaveDownloadAs to "Downloaded: <name>").
        HistoryPush(url);
        return;
    }

    // Keep the RAW HTML in g_state.body so Save writes the actual page
    // source, and render the page through the full pipeline (parse ->
    // style -> script -> layout -> display list) for DrawBody to paint.
    u32 keep = got;
    if (keep >= kBodyCap)
        keep = kBodyCap - 1;
    for (u32 i = 0; i < keep; ++i)
        g_state.body[i] = static_cast<char>(raw[i]);
    g_state.body[keep] = '\0';
    g_state.body_len = keep;

    // Viewport width for layout: the window content width minus the
    // scrollbar gutter; clamped to the canvas width. DrawBody re-lays
    // nothing — it paints this display list at the live scroll offset.
    const u32 vw = (g_state.render_viewport_w != 0) ? g_state.render_viewport_w : 640;
    RenderPage(g_state.body, g_state.body_len, url, vw);

    mm::KFree(raw);

    char status_buf[kStatusCap];
    FormatHttpStatus(status_buf, sizeof(status_buf), code, truncated);
    // Lock indicator: a leading "[S] " marks an HTTPS page whose
    // chain verified (the only way a TLS fetch reaches Ok). The
    // bitmap console font has no padlock glyph, so "[S]" stands in.
    if (p.scheme_https)
    {
        StatusSet("[S] ");
        StrAppend(g_state.status, kStatusCap, status_buf);
    }
    else
    {
        StatusSet(status_buf);
    }

    // Add to history if this was a fresh navigation (not a
    // back/forward replay — those reuse the slot in-place).
    HistoryPush(url);
}

// ---------------------------------------------------------------
// UI / paint.
// ---------------------------------------------------------------

// DrawHeader is gone — the URL bar + status row now live in
// the AppLabel chain inside g_browser (URL = UrlBarLabel(),
// status = StatusLabel(), both painted via PaintAll from
// DrawFn). RefreshUrlBarText composes the URL bar text from
// g_state.url + the mode-driven '_' caret each frame.

void DrawBody(u32 cx, u32 cy, u32 cw, u32 ch, u32 fg, u32 bg)
{
    // Reserve Pass D toolbar + URL bar + status row at the top and the
    // AppLabel footer at the bottom. The rendered page sits in the
    // middle band, painted from the display list at the live pixel
    // scroll offset. PrivRibbonH() adds the armed-state warning ribbon
    // band (0 when disarmed, so the layout is unchanged off the
    // privileged path).
    const u32 top_reserved = kTabStripH + kToolbarH + kUrlBarH + kStatusRowH + PrivRibbonH() + 2;
    const u32 bot_reserved = kFooterH + 2;
    if (ch < top_reserved + bot_reserved)
        return;
    const u32 view_h = ch - top_reserved - bot_reserved;
    const u32 sbw = duetos::drivers::video::kScrollbarWidth;
    const u32 view_w = (cw > sbw + 4) ? cw - sbw : cw;

    // Record the live viewport width so the NEXT fetch / reload lays the
    // page out to the current window size. We do NOT re-run RenderPage
    // here: the pipeline runs scripts and (pre-)fetches images, which is
    // network I/O that must not happen under the compositor lock. A
    // resize therefore reflows on the next reload, not live.
    g_state.render_viewport_w = view_w;

    if (!g_state.render_ready || g_state.render_dl == nullptr)
    {
        FramebufferDrawString(cx + 4, cy + top_reserved + 4, "(no content)", fg, bg);
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = false;
        duetos::drivers::video::WindowSetScrollbar(g_state.handle, s);
        return;
    }

    // Clamp the scroll offset to the page extent.
    i32 max_scroll = g_state.render_total_h - static_cast<i32>(view_h);
    if (max_scroll < 0)
        max_scroll = 0;
    if (g_state.scroll_y > max_scroll)
        g_state.scroll_y = max_scroll;
    if (g_state.scroll_y < 0)
        g_state.scroll_y = 0;

    // Compose the page off-screen into the persistent canvas, then blit
    // it into the body band. The canvas is clamped to its fixed size.
    const u32 canvas_w = (view_w < kCanvasW) ? view_w : kCanvasW;
    const u32 canvas_h = (view_h < kCanvasH) ? view_h : kCanvasH;

    duetos::web::PaintMetrics pm;
    pm.glyphW = 8;
    pm.glyphH = 16;
    pm.baseFontPx = 16;

    // Background = the browser client tone (0xRRGGBBAA, opaque).
    const u32 bg_rgba = (bg << 8) | 0xFFu;
    duetos::web::PaintToWindow(*g_state.render_dl, g_canvas, canvas_w, canvas_h, g_state.scroll_y, pm, ImageProviderFn,
                               nullptr, cx, cy + top_reserved, bg_rgba);

    // Focus outline: when a link is keyboard-focused, stroke a 2px box
    // around its rect, mapped from document coords into the body band
    // (screenY = body_top + doc_y - scroll_y), clipped to the band. Drawn
    // as four edge FillRects so it sits on top of the composed page.
    if (g_state.focus_link != kNoLink && g_state.focus_link < g_state.link_count)
    {
        const u32 body_top = cy + top_reserved;
        const duetos::web::Rect& lr = g_state.link_rects[g_state.focus_link].rect;
        const i32 sx = static_cast<i32>(cx) + lr.x;
        const i32 sy = static_cast<i32>(body_top) + lr.y - g_state.scroll_y;
        const i32 band_top = static_cast<i32>(body_top);
        const i32 band_bot = band_top + static_cast<i32>(view_h);
        constexpr u32 kOutline = 0x00FF8000U; // orange focus ring
        constexpr i32 kT = 2;                 // outline thickness
        // Only draw edges that fall inside the body band (cheap clip).
        auto edge = [&](i32 ex, i32 ey, i32 ew, i32 eh)
        {
            if (ew <= 0 || eh <= 0)
                return;
            i32 y0 = ey;
            i32 y1 = ey + eh;
            if (y0 < band_top)
                y0 = band_top;
            if (y1 > band_bot)
                y1 = band_bot;
            if (y1 <= y0 || ex < static_cast<i32>(cx))
                return;
            FramebufferFillRect(static_cast<u32>(ex), static_cast<u32>(y0), static_cast<u32>(ew),
                                static_cast<u32>(y1 - y0), kOutline);
        };
        edge(sx, sy, lr.w, kT);             // top
        edge(sx, sy + lr.h - kT, lr.w, kT); // bottom
        edge(sx, sy, kT, lr.h);             // left
        edge(sx + lr.w - kT, sy, kT, lr.h); // right
    }

    // Scrollbar at the right edge, in pixel units (total/visible/first).
    if (cw > sbw)
    {
        const u32 sb_x = cx + cw - sbw;
        const u32 sb_y = cy + top_reserved;
        const u32 sb_h = view_h;
        const u32 total = static_cast<u32>(g_state.render_total_h);
        const u32 first = static_cast<u32>(g_state.scroll_y);
        duetos::drivers::video::ScrollbarPaint(sb_x, sb_y, sbw, sb_h, {total, view_h, first});
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = true;
        s.x = sb_x;
        s.y = sb_y;
        s.w = sbw;
        s.h = sb_h;
        s.total = total;
        s.visible = view_h;
        s.first = first;
        duetos::drivers::video::WindowSetScrollbar(g_state.handle, s);
    }
    else
    {
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = false;
        duetos::drivers::video::WindowSetScrollbar(g_state.handle, s);
    }
}

void DrawList(u32 cx, u32 cy, u32 cw, u32 ch, const char* title, char list[][kUrlCap], u32 count, u32 fg, u32 dim,
              u32 bg)
{
    FramebufferDrawString(cx + 4, cy + 4, title, fg, bg);
    if (count == 0)
    {
        FramebufferDrawString(cx + 4, cy + 4 + kRowH * 2, "(empty)", dim, bg);
        return;
    }
    const u32 top = cy + 4 + kRowH * 2;
    const u32 max_rows = (ch > (top - cy) + kRowH) ? (ch - (top - cy)) / kRowH : 0;
    u32 first = 0;
    if (count > max_rows && g_state.list_selection >= max_rows)
        first = g_state.list_selection - (max_rows - 1);
    for (u32 i = 0; i < max_rows && first + i < count; ++i)
    {
        const u32 idx = first + i;
        const u32 y = top + i * kRowH;
        if (idx == g_state.list_selection)
        {
            FramebufferFillRect(cx, y, cw, kRowH, 0x00C0C888);
            FramebufferDrawString(cx + 4, y + 1, list[idx], 0x00101020, 0x00C0C888);
        }
        else
        {
            FramebufferDrawString(cx + 4, y + 1, list[idx], fg, bg);
        }
    }
}

// ---------------------------------------------------------------
// Privileged-Origin Mode — browser-side logic (spec §13).
//
// The arm/disarm decisions live here; the chrome below renders them.
// All of this runs in kernel-owned browser chrome, never the page —
// that unspoofability is the whole point of the mode.
// ---------------------------------------------------------------

// True iff `url` lexically satisfies the privileged origin:
// https://claude.ai/code (exact scheme + host, path begins "/code").
//
// GAP: SPKI-pin + no-redirect — origin_predicate.h's IsPrivilegedOrigin
// also requires `leafPin` matches the embedded claude.ai pin AND the page
// was NOT reached via any 3xx/client redirect. The browser fetch path
// (DoFetch/FetchUrl) does not yet surface the negotiated server-leaf SPKI
// hash or a "reached-via-redirect" flag up to the chrome, so this check
// covers only the scheme/host/path leg. Tighten to a full OriginCheck (and
// route it through IsPrivilegedOrigin) once net::tls_socket exposes the
// leaf SPKI + net::http exposes the redirect-observed flag. Until then the
// kernel cap-gates (Task 8) remain the real enforcement; arming only skips
// the interactive prompt, never the gate.
bool UrlIsPrivilegedOrigin(const char* url)
{
    const auto p = ParseUrl(url);
    if (!p.ok || !p.scheme_https)
        return false;
    if (!StrEqI(p.host, "claude.ai"))
        return false;
    // Path must begin with "/code" (exactly, or "/code/..."): a literal
    // prefix match — ParseUrl already strips the scheme/host.
    const char* path = p.path;
    if (path[0] != '/' || path[1] != 'c' || path[2] != 'o' || path[3] != 'd' || path[4] != 'e')
        return false;
    const char nxt = path[5];
    return nxt == '\0' || nxt == '/' || nxt == '?' || nxt == '#';
}

// The CURRENT live page's privileged-origin status (the rendered URL).
bool CurrentUrlIsPrivilegedOrigin()
{
    return UrlIsPrivilegedOrigin(g_state.url);
}

// Chrome predicate: should the chrome render its crimson armed state?
// (Tab armed — the arm-state machine is the single source of truth.)
bool PrivShouldRenderArmed()
{
    return g_priv.IsArmed();
}

// Pure affordance predicate (spec §13.5): the arm affordance is shown ONLY
// when the feature is available (boot flag set), the live page is the
// privileged origin, and the tab is not already armed. Factored pure so the
// boot self-test can assert the truth table (esp. available=false => false,
// the "feature fully off => no privileged UI" rule) without mutating globals.
bool PrivAffordanceVisibleFor(bool available, bool armed, bool originPriv)
{
    return available && !armed && originPriv;
}

// Chrome predicate: is the arm affordance shown? Wires the live globals into
// the pure predicate above.
bool PrivArmAffordanceVisible()
{
    return PrivAffordanceVisibleFor(duetos::security::privilege::PrivConfigCurrent().available, g_priv.IsArmed(),
                                    CurrentUrlIsPrivilegedOrigin());
}

// Ribbon height: reserved ONLY while armed, so a disarmed tab's chrome
// layout is unchanged from the pre-privilege build (no shift).
u32 PrivRibbonH()
{
    return PrivShouldRenderArmed() ? kPrivRibbonH : 0U;
}

// Tear down the page-side privileged JS binding. The binding's host objects
// (window.duetos.*) live in the JsDomContext's JS arena and are reclaimed when
// the next JsDomContextCreate rebuilds the context — so the sandboxed reload
// PrivDisarm performs is what physically removes them. Crucially, PrivDisarm
// clears the cap scope BEFORE this, so even in the brief window before the
// reload lands, every window.duetos.* call fail-closes at the broker (empty
// scope => "EPERM: not armed"). The engine's env has no "undefine" primitive,
// so the reload IS the teardown; this stays a deliberate no-op hook.
void PrivBindingTeardownCurrent() {}

// Arm the live tab: bind the default capability scope and install the
// page-side window.duetos.* binding on the live JS context. Gated by the
// caller (the reconfirm-confirm path) on PrivArmAffordanceVisible().
void PrivArm()
{
    g_priv.Arm(duetos::security::privilege::DefaultArmScope());
    // Build the bind from the live arm-state tab + the persistent boot config
    // roots, then install window.duetos.* onto the page's JS global env. The
    // kernel cap gates (Task 8) re-check every call independently, so the
    // binding is a convenience surface, never the enforcement boundary.
    g_priv_bind = duetos::web::priv::PrivBind{};
    g_priv_bind.tab = &g_priv;
    g_priv_bind.roots = duetos::security::privilege::PrivConfigCurrent().roots;
    // Phase 2b: register the app-layer EXECUTORS so proc.spawn / net.fetch
    // actually run (validate -> audit -> execute). Child caps are derived from
    // the armed scope (child <= broker); fetch reuses this app's page-fetch
    // transport. Cleared automatically by the PrivBind{} reset on disarm.
    g_priv_bind.spawnExec = &PrivSpawnExec;
    g_priv_bind.fetchExec = &PrivFetchExec;
    g_priv_bind.execCtx = nullptr; // executors are stateless in v1
    if (g_state.page_ctx != nullptr && duetos::web::JsDomContextInstallPrivBinding(g_state.page_ctx, &g_priv_bind))
    {
        arch::SerialWrite("[priv] armed: https://claude.ai/code (window.duetos.* installed)\n");
    }
    else
    {
        // GAP: the active page has no live JS context (a script-less or failed
        // render leaves page_ctx null), so there is no global env to install
        // onto — window.duetos.* appears on the next render that builds one.
        // The arm state + crimson chrome are live and the cap gates enforce
        // regardless, so this degraded case grants nothing and hides nothing.
        arch::SerialWrite("[priv] armed: https://claude.ai/code (no live JS context — binding deferred)\n");
    }
}

// Forward decl: Disarm re-fetches the page sandboxed, which lives below.
void Reload();

// Disarm the live tab: drop the cap scope, tear down the binding, and
// re-render the page sandboxed. Instantaneous + total.
void PrivDisarm()
{
    if (!g_priv.IsArmed())
        return;
    g_priv.Disarm();
    g_priv_confirm = false;
    PrivBindingTeardownCurrent();
    // Re-render sandboxed: re-fetch the current page so the rebuilt JS
    // context carries no privileged binding. Any in-flight privileged call
    // is aborted by the cap scope being cleared above (the broker re-checks
    // PrivTab.scope on every call — an empty scope fails closed).
    arch::SerialWrite("[priv] disarmed (kill/ribbon): re-rendering sandboxed\n");
    Reload();
}

// Paint the Chrome-style tab strip in the top band [cy, cy+kTabStripH].
// Active tab carries a teal top-accent; each tab a dual-accent favicon
// chip (teal native / amber doc) + title. New-tab '+' at the end.
void DrawTabStrip(u32 cx, u32 cy, u32 cw)
{
    FramebufferFillRect(cx, cy, cw, kTabStripH, tokens::kCanvas);
    const Rect strip{cx, cy, cw, kTabStripH};
    const u32 chipY = cy + (kTabStripH - 8U) / 2U;
    for (u32 i = 0; i < g_tabs.count; ++i)
    {
        const Rect t = g_tabs.TabRect(i, strip);
        const bool on = (i == g_tabs.active);
        // Privileged-Origin armed: the ACTIVE tab (the one live page) wears a
        // crimson top-accent instead of the teal one — an unspoofable signal.
        const bool armedTab = on && PrivShouldRenderArmed();
        const u32 tabbg = on ? tokens::kPanelHi : tokens::kPanel;
        const u32 tw = (t.w > 2U) ? t.w - 2U : t.w;
        duetos::drivers::video::FramebufferFillRoundRect(t.x, t.y + 4U, tw, t.h - 4U, tokens::kRadTab, tabbg);
        if (on)
            FramebufferFillRect(t.x, t.y + 4U, tw, 2U, armedTab ? tokens::kAccentDanger : tokens::kAccentTeal);
        const u32 chip = armedTab
                             ? tokens::kAccentDanger
                             : ((g_tabs.tabs[i].accent == TabAccent::Doc) ? tokens::kAccentAmber : tokens::kAccentTeal);
        duetos::drivers::video::FramebufferFillRoundRect(t.x + 8U, chipY, 8U, 8U, 2U, chip);
        FramebufferDrawString(t.x + 20U, chipY, g_tabs.tabs[i].title, on ? 0x00E3E9EFU : tokens::kInkMute, tabbg);
    }
    const Rect nt = g_tabs.NewTabRect(strip);
    FramebufferDrawString(nt.x + 8U, chipY, "+", tokens::kInkMute, tokens::kCanvas);
}

// The arm affordance chip — a small "[Arm]" button at the right end of the
// omnibox pill, shown ONLY when PrivArmAffordanceVisible(). Draw + hit-test
// derive geometry from this one helper so they never disagree.
Rect PrivArmChipRect(const Rect& pill, u32 pillY, u32 pillH)
{
    constexpr u32 kChipW = 46U;
    const u32 cx = (pill.x + pill.w > kChipW + 4U) ? pill.x + pill.w - kChipW - 4U : pill.x;
    return Rect{cx, pillY + 3U, kChipW, (pillH > 6U) ? pillH - 6U : pillH};
}

// New unified toolbar: nav (back/fwd/reload) + omnibox pill (URL/search) +
// ✦ Ask AI + ▤ Library + ⋮ menu, drawn in the band of height kToolbarH +
// kUrlBarH + kStatusRowH (replacing the old toolbar + URL bar + status row).
// GAP: ASCII glyph fallbacks ('<' '>' '@' '*' 'L' ':') until the real chrome
// glyph set (incl. the ✦ spark) lands.
//
// Privileged-Origin armed (spec §13.5): the omnibox pill is tinted crimson
// (tokens::kAccentDanger), the lock indicator becomes a red shield ("[!]"
// ASCII fallback), and the "[Arm]" affordance is suppressed (the ribbon's
// "[Disarm]" takes over). When NOT armed the toolbar is byte-for-byte as
// before, save for the "[Arm]" chip when on the privileged origin.
void DrawToolbar(u32 cx, u32 cy, u32 cw)
{
    const bool armed = PrivShouldRenderArmed();
    const u32 H = kToolbarH + kUrlBarH + kStatusRowH;
    FramebufferFillRect(cx, cy, cw, H, tokens::kPanelHi);
    FramebufferFillRect(cx, cy + H - 1U, cw, 1U, tokens::kBorder);
    const Rect tb{cx, cy, cw, H};
    const u32 ty = cy + H / 2U - 4U; // glyph baseline-ish
    const char* navg[3] = {"<", ">", "@"};
    for (u32 i = 0; i < 3U; ++i)
    {
        const Rect r = g_omni.NavRect(i, tb);
        FramebufferDrawString(r.x + 6U, ty, navg[i], tokens::kInkMute, tokens::kPanelHi);
    }
    const u32 pillH = 26U;
    const u32 pillY = cy + (H - pillH) / 2U;
    const Rect pill = g_omni.PillRect(tb);
    // Armed: the pill is filled crimson (kAccentDanger), so its text/lock sit
    // on the danger field; otherwise the usual canvas-dark pill.
    const u32 pillBg = armed ? tokens::kAccentDanger : tokens::kCanvas;
    duetos::drivers::video::FramebufferFillRoundRect(pill.x, pillY, pill.w, pillH, tokens::kRadPill, pillBg);
    // Lock indicator: red shield ("[!]") when armed, else the usual nothing —
    // the URL text starts after the indicator slot.
    u32 textX = pill.x + 12U;
    if (armed)
    {
        FramebufferDrawString(pill.x + 8U, pillY + pillH / 2U - 4U, "[!]", 0x00FFFFFFU, pillBg);
        textX = pill.x + 36U;
    }
    const bool hasUrl = (g_state.url[0] != '\0');
    const u32 urlFg = armed ? 0x00FFFFFFU : (hasUrl ? tokens::kInk : tokens::kInkDim);
    FramebufferDrawString(textX, pillY + pillH / 2U - 4U, hasUrl ? g_state.url : "Ask anything, or type a URL", urlFg,
                          pillBg);
    if (g_state.mode == Mode::UrlEdit)
        FramebufferDrawString(textX + StrLen(g_state.url) * 8U, pillY + pillH / 2U - 4U, "_",
                              armed ? 0x00FFFFFFU : tokens::kAccentTeal, pillBg);
    // Arm affordance: a "[Arm]" chip inside the pill's right end, only when
    // the feature is available, on the privileged origin, and not yet armed.
    if (PrivArmAffordanceVisible())
    {
        const Rect chip = PrivArmChipRect(pill, pillY, pillH);
        duetos::drivers::video::FramebufferFillRoundRect(chip.x, chip.y, chip.w, chip.h, tokens::kRadBtn,
                                                         tokens::kAccentDanger);
        FramebufferDrawString(chip.x + 6U, chip.y + chip.h / 2U - 4U, "Arm", 0x00FFFFFFU, tokens::kAccentDanger);
    }
    const Rect ask = g_omni.AskRect(tb);
    duetos::drivers::video::FramebufferFillRoundRect(ask.x, pillY, ask.w, pillH, tokens::kRadPill, tokens::kPanel);
    FramebufferDrawString(ask.x + 8U, pillY + pillH / 2U - 4U, "* Ask", tokens::kAccentTeal, tokens::kPanel);
    const Rect lib = g_omni.LibraryRect(tb);
    FramebufferDrawString(lib.x + 6U, ty, "L", tokens::kAccentTeal, tokens::kPanelHi);
    const Rect mn = g_omni.MenuRect(tb);
    FramebufferDrawString(mn.x + 7U, ty, ":", tokens::kInkMute, tokens::kPanelHi);
}

// Draw the full-width warning ribbon under the toolbar while armed, plus the
// reconfirm dialog when up. Both are chrome-drawn — the page cannot touch
// either. `cy` is the top of the ribbon band (directly below the toolbar);
// returns nothing (the band height is PrivRibbonH()).
//
// Ribbon: "[!] PRIVILEGED SYSTEM ACCESS ARMED — claude.ai/code   [Disarm]"
// (ASCII "[!]" fallback for the ⚠). The "[Disarm]" hit-rect is the right end.
Rect PrivDisarmBtnRect(u32 cx, u32 cy, u32 cw)
{
    constexpr u32 kBtnW = 72U;
    const u32 bx = (cw > kBtnW + 8U) ? cx + cw - kBtnW - 8U : cx;
    const u32 by = cy + (kPrivRibbonH > 16U ? (kPrivRibbonH - 16U) / 2U : 0U);
    return Rect{bx, by, kBtnW, 16U};
}

void DrawPrivRibbon(u32 cx, u32 cy, u32 cw)
{
    FramebufferFillRect(cx, cy, cw, kPrivRibbonH, tokens::kAccentDanger);
    FramebufferDrawString(cx + 10U, cy + kPrivRibbonH / 2U - 4U, "[!] PRIVILEGED SYSTEM ACCESS ARMED - claude.ai/code",
                          0x00FFFFFFU, tokens::kAccentDanger);
    const Rect db = PrivDisarmBtnRect(cx, cy, cw);
    duetos::drivers::video::FramebufferFillRoundRect(db.x, db.y, db.w, db.h, tokens::kRadBtn, 0x00FFFFFFU);
    FramebufferDrawString(db.x + 8U, db.y + db.h / 2U - 4U, "Disarm", tokens::kAccentDanger, 0x00FFFFFFU);
}

// Reconfirm dialog geometry (centred over the content). Draw + hit-test
// share these. Returns the dialog rect; the Confirm / Cancel buttons sit in
// its lower half.
Rect PrivConfirmDialogRect(const Rect& content)
{
    constexpr u32 kDlgW = 420U;
    constexpr u32 kDlgH = 130U;
    const u32 dx = content.x + ((content.w > kDlgW) ? (content.w - kDlgW) / 2U : 0U);
    const u32 dy = content.y + ((content.h > kDlgH) ? (content.h - kDlgH) / 3U : 0U);
    return Rect{dx, dy, kDlgW, kDlgH};
}
Rect PrivConfirmYesRect(const Rect& dlg)
{
    return Rect{dlg.x + 24U, dlg.y + dlg.h - 40U, 150U, 26U};
}
Rect PrivConfirmNoRect(const Rect& dlg)
{
    return Rect{dlg.x + dlg.w - 150U - 24U, dlg.y + dlg.h - 40U, 150U, 26U};
}

void DrawPrivConfirm(const Rect& content)
{
    if (!g_priv_confirm)
        return;
    // Dim the content behind the modal (a flat scrim — the painter has no
    // alpha-blend primitive in this path).
    FramebufferFillRect(content.x, content.y, content.w, content.h, 0x00050709U);
    const Rect d = PrivConfirmDialogRect(content);
    duetos::drivers::video::FramebufferFillRoundRect(d.x, d.y, d.w, d.h, tokens::kRadPanel, tokens::kPanel);
    FramebufferFillRect(d.x, d.y, d.w, 2U, tokens::kAccentDanger); // danger top-accent
    FramebufferDrawString(d.x + 16U, d.y + 14U, "Arm privileged system access?", tokens::kInk, tokens::kPanel);
    FramebufferDrawString(d.x + 16U, d.y + 34U, "claude.ai/code will gain scoped fs/proc/kernel/net", tokens::kInkMute,
                          tokens::kPanel);
    FramebufferDrawString(d.x + 16U, d.y + 48U, "via kernel cap gates. Ctrl+Shift+Esc revokes instantly.",
                          tokens::kInkMute, tokens::kPanel);
    const Rect yes = PrivConfirmYesRect(d);
    duetos::drivers::video::FramebufferFillRoundRect(yes.x, yes.y, yes.w, yes.h, tokens::kRadBtn,
                                                     tokens::kAccentDanger);
    FramebufferDrawString(yes.x + 10U, yes.y + yes.h / 2U - 4U, "Arm access", 0x00FFFFFFU, tokens::kAccentDanger);
    const Rect no = PrivConfirmNoRect(d);
    duetos::drivers::video::FramebufferFillRoundRect(no.x, no.y, no.w, no.h, tokens::kRadBtn, tokens::kPanelHi);
    FramebufferDrawString(no.x + 10U, no.y + no.h / 2U - 4U, "Cancel", tokens::kInk, tokens::kPanelHi);
}

// The DuetOS start page shows when the active tab has no rendered page
// (a fresh / new tab), in View mode, not mid-fetch.
bool ShowStartPage()
{
    return g_state.mode == Mode::View && !g_state.fetch_in_flight && !g_state.render_ready;
}

// Render the new-tab start page (wordmark + Ask/URL prompt + tile row) into
// the content rect. GAP: the radial backdrop glow is a flat fill (the
// painter's gradients are vertical-linear only) and the ✦ spark is an ASCII
// '*' until the real glyph lands.
void DrawStartPage(const Rect& content)
{
    FramebufferFillRect(content.x, content.y, content.w, content.h, tokens::kCanvas);
    const Rect wm = g_startpage.WordmarkRect(content);
    FramebufferDrawString(wm.x + 52U, wm.y + 8U, "DuetOS", tokens::kInk, tokens::kCanvas);
    const Rect pr = g_startpage.PromptRect(content);
    duetos::drivers::video::FramebufferFillRoundRect(pr.x, pr.y, pr.w, pr.h, tokens::kRadPill, 0x000D131AU);
    FramebufferFillRect(pr.x, pr.y, pr.w, 1U, tokens::kAccentTeal);
    FramebufferDrawString(pr.x + 14U, pr.y + pr.h / 2U - 4U, "* Ask anything, or type a URL", tokens::kInkMute,
                          0x000D131AU);
    for (u32 i = 0; i < g_startpage.tileCount; ++i)
    {
        const Rect t = g_startpage.TileRect(i, content);
        duetos::drivers::video::FramebufferFillRoundRect(t.x, t.y, t.w, t.h, tokens::kRadTile, tokens::kPanel);
        duetos::drivers::video::FramebufferFillRoundRect(t.x + t.w / 2U - 8U, t.y + 12U, 16U, 16U, 4U,
                                                         g_startpage.tiles[i].accent);
        FramebufferDrawString(t.x + 6U, t.y + t.h - 12U, g_startpage.tiles[i].label, tokens::kInkMute, tokens::kPanel);
    }
}

// Render a dockable surface (Assistant / Library) over the content. `body`
// is the web-content rect the surface floats/docks within. GAP: a docked
// surface currently OVERLAYS the content rather than reflowing it, and the
// drag/snap gesture + ghost preview are not yet wired (the DockSurface state
// machine supports both — see DockSurfaceSelfTest — this is a UI-wiring GAP).
// `bodyText` is the surface's content line. For the Assistant it is the live
// AssistantRespond output (a real source -> sink wiring of the Phase 2b
// backend); the Library still passes a placeholder. GAP: an interactive
// text-input line (type a query -> AssistantRespond -> append reply) is not yet
// wired — the dock has no text-input primitive (same UI-wiring GAP class as the
// drag/snap gesture above); the backend is live and self-tested regardless.
void DrawDockSurface(const DockSurface& s, const char* title, const Rect& body, const char* bodyText)
{
    if (s.mode == DockMode::Hidden)
        return;
    const Rect r = s.SurfaceRect(body);
    if (r.w == 0U || r.h == 0U)
        return;
    duetos::drivers::video::FramebufferFillRoundRect(r.x, r.y, r.w, r.h, tokens::kRadPanel, tokens::kPanel);
    FramebufferFillRect(r.x, r.y, r.w, 1U, tokens::kAccentTeal); // top accent
    const u32 hH = 20U;
    FramebufferFillRect(r.x, r.y + 1U, r.w, hH, tokens::kPanelHi); // header
    FramebufferDrawString(r.x + 8U, r.y + 6U, title, tokens::kAccentTeal, tokens::kPanelHi);
    if (r.w > 20U)
        FramebufferDrawString(r.x + r.w - 16U, r.y + 6U, "x", tokens::kInkMute, tokens::kPanelHi);
    FramebufferDrawString(r.x + 8U, r.y + hH + 10U, bodyText, tokens::kInkDim, tokens::kPanel);
}

// Route a press to a visible dock surface: a hit inside its rect is consumed;
// a hit on its close (x) glyph dismisses it. Returns true if consumed.
bool HandleDockClick(DockSurface& s, const Rect& body, u32 cx, u32 cy)
{
    if (s.mode == DockMode::Hidden)
        return false;
    const Rect r = s.SurfaceRect(body);
    if (r.w == 0U || r.h == 0U || !r.Contains(cx, cy))
        return false;
    const Rect close{(r.w > 20U) ? r.x + r.w - 20U : r.x, r.y + 2U, 18U, 18U};
    if (close.Contains(cx, cy))
        s.Dismiss();
    return true; // the surface absorbs the press either way.
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(ThemeRole::Browser)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    FramebufferFillRect(cx, cy, cw, ch, bg);

    // Pass D chrome: refresh the URL bar + footer text from
    // live state, re-anchor the toolbar / labels to the current
    // client rect, and paint the WidgetGroup. The pre-existing
    // raw-paint body / modal-list paths run below, OFFSET to
    // sit under the new top band the toolbar / URL bar / status
    // label carve out.
    // Shell redesign chrome: the tab strip + the new unified toolbar
    // (Omnibox pill + ✦ Ask + ▤ Library + ⋮) replace the old WidgetGroup
    // toolbar / URL bar / status row / footer. RebindBrowserBounds is kept
    // so the (now-unpainted) AppButtons' bounds stay sane for any stray
    // event, but the chrome is drawn manually below.
    RefreshUrlBarText();
    DrawTabStrip(cx, cy, cw);
    DrawToolbar(cx, cy + kTabStripH, cw);
    RebindBrowserBounds(cx, cy + kTabStripH, cw, (ch > kTabStripH) ? ch - kTabStripH : 0U);

    // Privileged-Origin armed: the full-width crimson warning ribbon sits
    // directly under the toolbar. Drawn by chrome — the page can never
    // suppress it. PrivRibbonH() == kPrivRibbonH while armed, else 0.
    const u32 ribbon_y = cy + kTabStripH + kToolbarH + kUrlBarH + kStatusRowH;
    if (PrivShouldRenderArmed())
        DrawPrivRibbon(cx, ribbon_y, cw);

    // Body / modal-list paint area starts BELOW the tab strip + toolbar band
    // (+ the armed ribbon band when present).
    const u32 top_band = kTabStripH + kToolbarH + kUrlBarH + kStatusRowH + PrivRibbonH();

    if (g_state.fetch_in_flight)
    {
        FramebufferDrawString(cx + 4, cy + top_band + 4, "Fetching... please wait.", dim, bg);
    }
    else if (g_state.mode == Mode::History)
    {
        DrawList(cx, cy + top_band, cw, (ch > top_band + kFooterH) ? ch - top_band - kFooterH : 0,
                 "HISTORY (Enter:load Esc:back):", g_state.history, g_state.history_count, fg, dim, bg);
    }
    else if (g_state.mode == Mode::Bookmarks)
    {
        DrawList(cx, cy + top_band, cw, (ch > top_band + kFooterH) ? ch - top_band - kFooterH : 0,
                 "BOOKMARKS (Enter:load X:remove Esc:back):", g_state.bookmarks, g_state.bookmark_count, fg, dim, bg);
    }
    else if (ShowStartPage())
    {
        const Rect content{cx, cy + top_band, cw, (ch > top_band) ? ch - top_band : 0U};
        DrawStartPage(content);
    }
    else
    {
        DrawBody(cx, cy, cw, ch, fg, bg);
    }

    // Dockable surfaces overlay the content (Assistant + Library share the
    // one DockSurface mechanism). `body` is the web-content rect below the
    // chrome they float/dock within.
    const Rect body{cx, cy + top_band, cw, (ch > top_band) ? ch - top_band : 0U};
    // The Assistant surface renders the live local-backend output (Phase 2b);
    // with no interactive input wired yet, it shows the capability/help line.
    char assistLine[160];
    AssistantRespond("help", assistLine, sizeof(assistLine));
    DrawDockSurface(g_assistant, "* Assistant", body, assistLine);
    DrawDockSurface(g_library, "L Library", body, "(placeholder)");

    // Privileged-Origin armed: a crimson border around the content frame —
    // a second unspoofable cue. Drawn after the content so it sits on top.
    if (PrivShouldRenderArmed() && body.w > 4U && body.h > 4U)
    {
        FramebufferFillRect(body.x, body.y, body.w, 2U, tokens::kAccentDanger);
        FramebufferFillRect(body.x, body.y + body.h - 2U, body.w, 2U, tokens::kAccentDanger);
        FramebufferFillRect(body.x, body.y, 2U, body.h, tokens::kAccentDanger);
        FramebufferFillRect(body.x + body.w - 2U, body.y, 2U, body.h, tokens::kAccentDanger);
    }

    // Reconfirm dialog (chrome-drawn, chrome-handled) sits on top of
    // everything — the page can neither suppress nor satisfy it.
    DrawPrivConfirm(body);
}

void StartFetch(const char* url)
{
    if (g_state.fetch_in_flight)
        return;
    // Per-navigation privilege lifetime (spec §13.10): EVERY navigation
    // funnels through here (URL submit, link click, back/forward, reload,
    // history/bookmark load, tab select, start-page tile). If the target
    // leaves the privileged origin, privilege auto-disarms before the fetch
    // — privilege NEVER survives leaving claude.ai/code. A reload onto the
    // SAME privileged origin keeps the tab armed (the broker re-checks the
    // live page on each call regardless).
    const bool still_priv = UrlIsPrivilegedOrigin(url);
    if (g_priv.IsArmed() && !still_priv)
    {
        g_priv.OnNavigation(false);
        PrivBindingTeardownCurrent();
        g_priv_confirm = false;
        arch::SerialWrite("[priv] auto-disarm on navigation off privileged origin\n");
    }
    else
    {
        g_priv.OnNavigation(still_priv);
    }
    StrCopyCap(g_state.fetch_url, kUrlCap, url);
    g_state.fetch_in_flight = true;
    sched::SchedCreate(FetchWorker, g_state.fetch_url, "browser-fetch");
}

// ---------------------------------------------------------------
// Link navigation: follow a hit-tested / focused link, and cycle the
// keyboard focus across the page's visible links.
// ---------------------------------------------------------------

// Follow link `idx`: its href is already absolute (BuildLinkRects resolved
// it against the page URL). Mirror the URL into the bar and StartFetch so
// the navigation pushes to history — Back/Forward then work as usual.
void FollowLink(u32 idx)
{
    if (idx >= g_state.link_count || g_state.fetch_in_flight)
        return;
    char tmp[kUrlCap];
    StrCopyCap(tmp, kUrlCap, g_state.link_rects[idx].href);
    StrCopyCap(g_state.url, kUrlCap, tmp);
    g_state.url_len = StrLen(g_state.url);
    g_state.mode = Mode::View;
    StartFetch(tmp);
}

// Follow a RAW (un-resolved) href, resolving it against the current
// page's URL the same way BuildLinkRects does, then mirror it into the
// URL bar and StartFetch (so history Back/Forward work). Used by the
// node-click path, where the href comes straight off a display item and
// hasn't been pre-resolved into the link table. No-op on a null/empty
// href or while a fetch is in flight.
void FollowHref(const char* raw_href)
{
    if (raw_href == nullptr || raw_href[0] == '\0' || g_state.fetch_in_flight)
        return;
    char abs[kUrlCap];
    // Resolve against the rendered page's URL (g_images.page_url is the
    // base BuildLinkRects also resolved against).
    ResolveUrl(g_images.page_url, raw_href, abs, sizeof(abs));
    StrCopyCap(g_state.url, kUrlCap, abs);
    g_state.url_len = StrLen(g_state.url);
    g_state.mode = Mode::View;
    StartFetch(abs);
}

// Compute the content viewport height (device px) inside the body band, so
// scroll-into-view can clamp a focused link to the visible region. Mirrors
// the band math in DrawBody. Returns 0 when bounds are unavailable.
u32 ContentViewHeight()
{
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return 0;
    constexpr u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return 0;
    const u32 ch = wh - kTitleH;
    const u32 top_reserved = kTabStripH + kToolbarH + kUrlBarH + kStatusRowH + PrivRibbonH() + 2;
    const u32 bot_reserved = kFooterH + 2;
    if (ch < top_reserved + bot_reserved)
        return 0;
    return ch - top_reserved - bot_reserved;
}

// Scroll so the focused link's rect (document coords) is visible in the
// content viewport, clamped to the page extent.
void ScrollLinkIntoView(u32 idx)
{
    if (idx >= g_state.link_count)
        return;
    const duetos::web::Rect& r = g_state.link_rects[idx].rect;
    const u32 view_h = ContentViewHeight();
    if (view_h == 0)
        return;
    // If the link sits above the viewport, scroll up to its top; if below,
    // scroll down so its bottom is just visible.
    if (r.y < g_state.scroll_y)
    {
        g_state.scroll_y = r.y;
    }
    else if (r.y + r.h > g_state.scroll_y + static_cast<i32>(view_h))
    {
        g_state.scroll_y = (r.y + r.h) - static_cast<i32>(view_h);
    }
    if (g_state.scroll_y < 0)
        g_state.scroll_y = 0;
    i32 max_scroll = g_state.render_total_h - static_cast<i32>(view_h);
    if (max_scroll < 0)
        max_scroll = 0;
    if (g_state.scroll_y > max_scroll)
        g_state.scroll_y = max_scroll;
}

// Map a SCREEN-space click to the page's DOCUMENT coordinates, the space
// the display list + link rects live in (before the scroll offset is
// applied). The body band starts at (window_x, window_y + title +
// top_reserved); doc_y maps to screen via doc_y - scroll_y. Returns true
// and fills *out_doc_x / *out_doc_y only when the click lands inside the
// body band (View mode, excluding the scrollbar gutter); returns false for
// clicks on the chrome / scrollbar / outside the window. The single source
// of truth for the screen->doc transform — HitTestLink and
// BrowserHitTestNode both go through it.
bool ScreenToDoc(u32 screen_cx, u32 screen_cy, i32* out_doc_x, i32* out_doc_y)
{
    if (g_state.mode != Mode::View)
        return false;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return false;
    constexpr u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return false;
    const u32 client_y = wy + kTitleH;
    const u32 client_h = wh - kTitleH;
    const u32 top_reserved = kTabStripH + kToolbarH + kUrlBarH + kStatusRowH + PrivRibbonH() + 2;
    const u32 bot_reserved = kFooterH + 2;
    if (client_h < top_reserved + bot_reserved)
        return false;
    const u32 view_h = client_h - top_reserved - bot_reserved;
    const u32 body_top = client_y + top_reserved;
    const u32 sbw = duetos::drivers::video::kScrollbarWidth;
    const u32 body_right = (ww > sbw) ? wx + ww - sbw : wx + ww;

    // Click must be inside the body band (excluding the scrollbar gutter).
    if (screen_cx < wx || screen_cx >= body_right)
        return false;
    if (screen_cy < body_top || screen_cy >= body_top + view_h)
        return false;

    *out_doc_x = static_cast<i32>(screen_cx) - static_cast<i32>(wx);
    *out_doc_y = static_cast<i32>(screen_cy) - static_cast<i32>(body_top) + g_state.scroll_y;
    return true;
}

// Hit-test a screen-space click against the page's link rects. Returns the
// hit link index, or kNoLink. View mode only; clicks outside the body band
// miss. Used by the keyboard-focus path and as a fallback when the page has
// no interactive context.
u32 HitTestLink(u32 screen_cx, u32 screen_cy)
{
    if (g_state.link_count == 0)
        return kNoLink;
    i32 doc_x = 0;
    i32 doc_y = 0;
    if (!ScreenToDoc(screen_cx, screen_cy, &doc_x, &doc_y))
        return kNoLink;
    for (u32 i = 0; i < g_state.link_count; ++i)
    {
        const duetos::web::Rect& r = g_state.link_rects[i].rect;
        if (doc_x >= r.x && doc_x < r.x + r.w && doc_y >= r.y && doc_y < r.y + r.h)
            return i;
    }
    return kNoLink;
}

// Hit-test DOCUMENT coordinates against the laid-out display list and
// return the TOPMOST element they fall on. Items are in back-to-front
// paint order, so the LAST item whose rect contains (doc_x, doc_y) and
// carries a non-null source `node` is the one on top. Sets *out_href to
// that item's raw (un-resolved) href (may be null) so the caller can
// follow a link after dispatching the click. Returns nullptr when nothing
// is hit or no page is rendered.
const duetos::web::Node* BrowserHitTestNode(i32 doc_x, i32 doc_y, const char** out_href)
{
    if (out_href != nullptr)
        *out_href = nullptr;
    if (g_state.render_dl == nullptr)
        return nullptr;
    const duetos::web::DisplayList& dl = *g_state.render_dl;
    const duetos::web::Node* hit = nullptr;
    const char* hit_href = nullptr;
    for (u32 i = 0; i < dl.count; ++i)
    {
        const auto& it = dl.items[i];
        if (it.node == nullptr)
            continue;
        if (it.rect.w <= 0 || it.rect.h <= 0)
            continue;
        if (doc_x >= it.rect.x && doc_x < it.rect.x + it.rect.w && doc_y >= it.rect.y && doc_y < it.rect.y + it.rect.h)
        {
            // Keep the last (top-most) match.
            hit = it.node;
            hit_href = it.href;
        }
    }
    if (hit != nullptr && out_href != nullptr)
        *out_href = hit_href;
    return hit;
}

// Move the keyboard link focus forward (`forward`=true) or backward across
// the page's links, wrapping at the ends, and scroll the new target into
// view. No-op when the page has no links.
void FocusCycleLink(bool forward)
{
    if (g_state.link_count == 0)
    {
        g_state.focus_link = kNoLink;
        return;
    }
    if (g_state.focus_link == kNoLink)
    {
        g_state.focus_link = forward ? 0 : (g_state.link_count - 1);
    }
    else if (forward)
    {
        g_state.focus_link = (g_state.focus_link + 1) % g_state.link_count;
    }
    else
    {
        g_state.focus_link = (g_state.focus_link == 0) ? (g_state.link_count - 1) : (g_state.focus_link - 1);
    }
    ScrollLinkIntoView(g_state.focus_link);
}

void Reload()
{
    if (g_state.history_idx == 0)
        return;
    char tmp[kUrlCap];
    StrCopyCap(tmp, kUrlCap, g_state.history[g_state.history_idx - 1]);
    // Pop the duplicate that DoFetch will push, by setting idx
    // back so HistoryPush replaces the slot.
    --g_state.history_idx;
    g_state.history_count = g_state.history_idx;
    StartFetch(tmp);
}

void NavigateBackForward(bool forward)
{
    if (forward)
    {
        if (g_state.history_idx >= g_state.history_count)
            return;
        const char* u = g_state.history[g_state.history_idx];
        char tmp[kUrlCap];
        StrCopyCap(tmp, kUrlCap, u);
        // Pop the slot that DoFetch will push so we don't duplicate.
        g_state.history_count = g_state.history_idx;
        StartFetch(tmp);
    }
    else
    {
        if (g_state.history_idx < 2)
        {
            StatusSet("at start of history");
            return;
        }
        const char* u = g_state.history[g_state.history_idx - 2];
        char tmp[kUrlCap];
        StrCopyCap(tmp, kUrlCap, u);
        g_state.history_idx -= 2;
        g_state.history_count = g_state.history_idx;
        StartFetch(tmp);
    }
}

void BookmarkCurrent()
{
    if (g_state.url_len == 0)
    {
        StatusSet("no URL to bookmark");
        return;
    }
    if (g_state.bookmark_count >= kBookmarkCap)
    {
        StatusSet("bookmarks full (16)");
        return;
    }
    if (BookmarkContains(g_state.url))
    {
        StatusSet("already bookmarked");
        return;
    }
    StrCopyCap(g_state.bookmarks[g_state.bookmark_count], kUrlCap, g_state.url);
    ++g_state.bookmark_count;
    SaveBookmarks();
    StatusSet("bookmarked");
}

void BookmarkRemoveSelected()
{
    if (g_state.list_selection >= g_state.bookmark_count)
        return;
    for (u32 i = g_state.list_selection + 1; i < g_state.bookmark_count; ++i)
    {
        for (u32 j = 0; j < kUrlCap; ++j)
            g_state.bookmarks[i - 1][j] = g_state.bookmarks[i][j];
    }
    --g_state.bookmark_count;
    if (g_state.list_selection >= g_state.bookmark_count && g_state.list_selection > 0)
        --g_state.list_selection;
    SaveBookmarks();
}

void EnterUrlEdit()
{
    g_state.mode = Mode::UrlEdit;
}

// ----- Pass D click trampolines --------------------------------
// AppButton::on_click is a plain `void (*)()` so the constinit
// g_browser above captures each one by function-pointer value.
// Each one mirrors the corresponding BrowserFeedChar branch
// end-state so the chrome migration adds discoverability (a
// fresh user can click BACK / FWD / etc. instead of memorising
// the footer hint) without changing any side effects.

void ClickBack()
{
    NavigateBackForward(false);
}

void ClickForward()
{
    NavigateBackForward(true);
}

void ClickReload()
{
    Reload();
}

void ClickHistory()
{
    if (g_state.fetch_in_flight)
        return;
    g_state.mode = Mode::History;
    g_state.list_selection = (g_state.history_count > 0) ? g_state.history_count - 1 : 0;
}

void ClickBookmarks()
{
    if (g_state.fetch_in_flight)
        return;
    g_state.mode = Mode::Bookmarks;
    RescanBookmarks();
    g_state.list_selection = 0;
}

void ClickMark()
{
    if (g_state.fetch_in_flight)
        return;
    BookmarkCurrent();
}

void ClickSave()
{
    if (g_state.fetch_in_flight)
        return;
    SaveDownload();
}

void HandleUrlEditChar(char c)
{
    const u8 uc = static_cast<u8>(c);
    if (uc == 0x0A) // Enter
    {
        StrCopyCap(g_state.url, kUrlCap, g_state.url); // no-op, just clarity
        g_state.mode = Mode::View;
        StartFetch(g_state.url);
        return;
    }
    if (uc == 0x1B) // Esc
    {
        g_state.mode = Mode::View;
        return;
    }
    if (uc == 0x08) // Backspace
    {
        if (g_state.url_len > 0)
        {
            --g_state.url_len;
            g_state.url[g_state.url_len] = '\0';
        }
        return;
    }
    if (uc >= 0x20 && uc <= 0x7E && g_state.url_len + 1 < kUrlCap)
    {
        g_state.url[g_state.url_len++] = c;
        g_state.url[g_state.url_len] = '\0';
    }
}

// ---------------------------------------------------------------
// Self-test loopback transport.
//
// Hands the HTTP engine a canned byte stream and swallows the
// request it writes. A queue of responses lets a redirect chain
// run without a socket — the FIRST response is the injected
// transport, each subsequent hop is served by SelfTestRedirect.
// ---------------------------------------------------------------

struct CannedResp
{
    const char* data;
    u32 len;
    u32 pos;
};

i64 CannedRespRead(void* ctx, u8* buf, u32 len)
{
    auto* c = static_cast<CannedResp*>(ctx);
    if (c->pos >= c->len)
        return 0; // EOF
    const u32 avail = c->len - c->pos;
    const u32 take = (len < avail) ? len : avail;
    for (u32 i = 0; i < take; ++i)
        buf[i] = static_cast<u8>(c->data[c->pos + i]);
    c->pos += take;
    return static_cast<i64>(take);
}

// Swallow the request bytes. The default transports point write at
// the CannedResp itself, so this MUST NOT dereference ctx — it just
// acknowledges the bytes. (Test B captures the request through a
// separate combined-ctx lambda that writes into a real char buffer.)
i64 CannedRespWrite(void* /*ctx*/, const u8* /*buf*/, u32 len)
{
    return static_cast<i64>(len);
}

// Capture variant: append the request bytes into a char buffer ctx.
// Used by test B (request bytes -> req_capture) to assert the Cookie
// header was emitted on the second fetch.
i64 CannedRespCaptureWrite(char* cap, const u8* buf, u32 len)
{
    if (cap != nullptr)
    {
        u32 n = StrLen(cap);
        for (u32 i = 0; i < len && n + 1 < 2048; ++i)
            cap[n++] = static_cast<char>(buf[i]);
        cap[n] = '\0';
    }
    return static_cast<i64>(len);
}

struct SelfTestRedirectHarness
{
    const char* responses[4];
    CannedResp canned[4];
    u32 next;
};

bool SelfTestRedirect(bool /*https*/, const char* /*host*/, u16 /*port*/, net::http::HttpTransport* out, void* ctx)
{
    auto* h = static_cast<SelfTestRedirectHarness*>(ctx);
    if (h->next >= 4 || h->responses[h->next] == nullptr)
        return false;
    const u32 i = h->next++;
    h->canned[i].data = h->responses[i];
    h->canned[i].len = StrLen(h->responses[i]);
    h->canned[i].pos = 0;
    out->read = CannedRespRead;
    out->write = CannedRespWrite;
    out->ctx = &h->canned[i];
    return true;
}

} // namespace

// Privileged net.fetch executor (Phase 2b). DEFINED here, not in priv_exec.cpp,
// because it reuses this TU's file-static OpenTransport / CloseTransport /
// RedirectConnect TLS machinery — the SAME page-fetch transport a normal page
// load uses (spec §13.6: "the same net stack + policy as a page fetch").
// Declared in apps/browser/priv_exec.h; registered on g_priv_bind at arm time.
// The anonymous-namespace helpers above remain visible here for the rest of the
// TU, so this external-linkage definition can call them unqualified.
bool PrivFetchExec(const duetos::web::priv::FetchReq& req, duetos::web::priv::FetchRes* out, void* /*ctx*/)
{
    if (out == nullptr || req.url == nullptr)
        return false;
    out->status = 0;
    out->bodyLen = 0;
    out->ok = false;

    bool https = false;
    char host[256];
    u16 port = 0;
    char path[1024];
    if (!net::http::ParseUrl(req.url, &https, host, sizeof(host), &port, path, sizeof(path)) || host[0] == '\0')
        return false;

    net::http::HttpTransport transport{};
    i32 sock = -1;
    TlsState* tls = nullptr;
    if (OpenTransport(https, host, port, &transport, &sock, &tls) != FetchStatus::Ok)
        return false;

    RedirectTracker redirects{};
    net::http::HttpRequestSpec spec{};
    const bool is_post = req.method != nullptr && (req.method[0] == 'P' || req.method[0] == 'p');
    spec.method = is_post ? net::http::HttpMethod::Post : net::http::HttpMethod::Get;
    spec.scheme_https = https;
    StrCopyCap(spec.host, sizeof(spec.host), host);
    spec.port = port;
    StrCopyCap(spec.path, sizeof(spec.path), path);
    spec.user_agent = "DuetOS-Browser/0.2";
    spec.accept = "*/*";
    if (is_post)
    {
        spec.content_type = req.contentType;
        spec.body = reinterpret_cast<const u8*>(req.body);
        spec.body_len = req.bodyLen;
    }
    spec.on_connect = RedirectConnect;
    spec.connect_ctx = &redirects;
    spec.body_buf = reinterpret_cast<u8*>(out->body);
    spec.body_cap = out->bodyCap;

    net::http::HttpResult result{};
    const bool ok = net::http::HttpRequest(spec, &transport, &result);

    CloseTransport(sock, tls);
    for (u32 i = 0; i < redirects.count; ++i)
        CloseTransport(redirects.socks[i], redirects.tlss[i]);

    out->status = result.status_code;
    out->bodyLen = result.body_len;
    out->ok = ok && result.error == net::http::HttpError::None;
    return out->ok;
}

void BrowserInit(WindowHandle handle)
{
    g_state.handle = handle;
    g_state.mode = Mode::View;
    g_state.url[0] = '\0';
    g_state.url_len = 0;
    g_state.body[0] = '\0';
    g_state.body_len = 0;
    g_state.status[0] = '\0';
    g_state.status_code = 0;
    g_state.scroll_row = 0;
    g_state.scroll_y = 0;
    g_state.render_ready = false;
    g_state.render_dl = nullptr;
    g_state.render_total_h = 0;
    g_state.render_viewport_w = 0;
    g_state.link_count = 0;
    g_state.focus_link = kNoLink;
    g_state.history_count = 0;
    g_state.history_idx = 0;
    g_state.bookmark_count = 0;
    g_state.list_selection = 0;
    g_state.fetch_in_flight = false;
    StatusSet("Press U for URL bar.  HTTP + HTTPS supported.");
    // Load any persisted cookie jar from the FAT32 root so cookies
    // survive across boots; the verifier is installed lazily on the
    // first HTTPS fetch (InstallTlsVerifierOnce).
    net::CookieJarLoad();
    BindBrowserOnce();
    WindowSetContentDraw(handle, DrawFn, nullptr);
    // Seed the tab strip with one home tab (the live page). Real per-tab
    // render contexts are Phase 3; here the active tab tracks the page.
    if (g_tabs.count == 0)
        g_tabs.AddTab("", "DuetOS - Home", TabAccent::Native);
    g_startpage.InitDefault();
    duetos::drivers::video::WindowSetWheelHandler(handle, BrowserOnWheel);
    duetos::drivers::video::WindowSetScrollHandler(handle,
                                                   [](duetos::u32 first)
                                                   {
                                                       // Body view scroll is in pixel units (display-list
                                                       // total/first), clamped on the next DrawBody.
                                                       if (g_state.mode == Mode::View)
                                                           g_state.scroll_y = static_cast<duetos::i32>(first);
                                                   });
}

void BrowserOpenDemo()
{
    if (g_state.handle == kWindowInvalid)
        return;

    // Built-in welcome page. Network-free; exercises the real pipeline
    // (HTML parse -> CSS cascade -> JS at render time -> layout -> paint)
    // so a screenshot shows the engine actually working, not empty chrome.
    static const char kDemoHtml[] =
        "<html><head><style>"
        "body { background:#eef2f8; color:#1a2330; margin:16px; }"
        "h1 { color:#15507a; }"
        ".card { background:#ffffff; border:2px solid #15507a; padding:10px; margin:10px 0; }"
        ".ok { color:#1f8a4c; font-weight:bold; }"
        "a { color:#15507a; }"
        "</style></head><body>"
        "<h1>Welcome to DuetOS</h1>"
        "<p>This page is rendered by the in-kernel web engine: HTML parse, CSS "
        "cascade, JavaScript, layout and paint &mdash; no external browser.</p>"
        "<div class=\"card\">"
        "<p class=\"ok\" id=\"js\">(script did not run)</p>"
        "<ul>"
        "<li>CSS selectors with backtracking combinators</li>"
        "<li>JS try / catch / finally and the dotAll regexp flag</li>"
        "<li>addEventListener capture phase &amp; once option</li>"
        "</ul>"
        "<p><a href=\"http://example.com/\">A sample link</a></p>"
        "</div>"
        "<script>document.getElementById('js').textContent = "
        "'JavaScript executed at render time';</script>"
        "</body></html>";

    StrCopyCap(g_state.url, sizeof(g_state.url), "duet://welcome");
    g_state.url_len = StrLen(g_state.url);
    StatusSet("Welcome to DuetOS  -  rendered by the in-kernel web engine");

    // Layout width = window content width minus the scrollbar gutter,
    // mirroring the live-fetch render path.
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    duetos::u32 vw = 640;
    if (duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
    {
        const duetos::u32 sbw = duetos::drivers::video::kScrollbarWidth;
        vw = (ww > sbw) ? ww - sbw : ww;
    }

    RenderPage(kDemoHtml, StrLen(kDemoHtml), "duet://welcome", vw);

    duetos::drivers::video::WindowSetVisible(g_state.handle, true);
    duetos::drivers::video::WindowRaise(g_state.handle);
}

void BrowserOnWheel(duetos::i32 dz, duetos::u8 modifiers)
{
    (void)modifiers;
    if (dz == 0)
        return;
    // Wheel-up (dz > 0) maps to "scroll content up" which means
    // ARROW UP in our viewport (smaller scroll_row).
    const u16 key = (dz > 0) ? kKeyArrowUp : kKeyArrowDown;
    const duetos::i32 steps = (dz > 0) ? dz : -dz;
    for (duetos::i32 i = 0; i < steps; ++i)
    {
        BrowserFeedArrow(key);
    }
}

void BrowserFocusUrl()
{
    EnterUrlEdit();
}

void BrowserNavBack()
{
    NavigateBackForward(false);
}

void BrowserNavForward()
{
    NavigateBackForward(true);
}

// Privileged-Origin kill switch (spec §13.5). Routed at HIGHEST priority by
// the global key reader (Ctrl+Shift+Esc) BEFORE any per-app / per-page key
// dispatch, so a malicious page can never swallow the chord. Revokes ALL
// armed privilege the browser owns and re-renders sandboxed. Safe to call
// unconditionally — a no-op when nothing is armed.
//
// GAP: "all clients" = the browser's tabs only (Phase 1 has ONE live tab,
// g_priv). The architecture intends an extensible revoke-all surface; when a
// second privileged client lands (e.g. the headless self-dev agent), it must
// register with this same kill switch and be revoked here too. Today there is
// no client registry, so this disarms the single browser tab.
void BrowserPrivKillSwitch()
{
    g_priv_confirm = false; // also cancel any pending reconfirm dialog
    PrivDisarm();
}

// Chrome predicate bridge (spec §13.5) — true iff the armed crimson chrome
// should render. Public so the boot self-test can assert the predicate; the
// chrome paint path reads the anon-namespace PrivShouldRenderArmed() directly.
bool BrowserPrivShouldRenderArmed()
{
    return PrivShouldRenderArmed();
}

// ---- Privileged-Origin chrome self-test bridges (boot self-test only) ----
// These let the separate priv_chrome_selftest TU drive + inspect the
// file-static arm state + config-gated affordance predicate WITHOUT exposing
// the internals. Each one is a thin, side-effect-bounded shim; the self-test
// arms via the SAME PrivArm() the real reconfirm-confirm path uses, and
// restores g_priv on exit so runtime state is untouched.
namespace priv_chrome_test
{
void Arm()
{
    PrivArm();
}
void Disarm()
{
    g_priv.Disarm(); // direct (no reload) — the test owns no history/page.
}
bool IsArmed()
{
    return g_priv.IsArmed();
}
void KillSwitchNoReload()
{
    // Mirror BrowserPrivKillSwitch's revoke WITHOUT the sandboxed Reload()
    // (the test has no rendered page / history to reload). Asserts the
    // chord's Armed->Disarmed transition in isolation.
    g_priv_confirm = false;
    if (g_priv.IsArmed())
    {
        g_priv.Disarm();
        PrivBindingTeardownCurrent();
    }
}
// Run OnNavigation against the LIVE g_priv exactly as StartFetch does.
void OnNavigation(bool stillPriv)
{
    g_priv.OnNavigation(stillPriv);
}
// The pure affordance truth table (available && !armed && originPriv).
bool AffordanceVisibleFor(bool available, bool armed, bool originPriv)
{
    return PrivAffordanceVisibleFor(available, armed, originPriv);
}
// The lexical privileged-origin check (scheme/host/path leg of §13).
bool UrlIsPrivileged(const char* url)
{
    return UrlIsPrivilegedOrigin(url);
}
} // namespace priv_chrome_test

bool BrowserOnDoubleClick(duetos::u32 sx, duetos::u32 sy)
{
    (void)sx;
    // Only meaningful in Bookmarks mode — DC follows the hit row.
    // History mode could mirror this but isn't on the v1 critical
    // path (less common navigation pattern).
    if (g_state.mode != Mode::Bookmarks || g_state.bookmark_count == 0)
        return false;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return false;
    // Mirror the geometry from DrawFn → DrawList. Client area
    // starts 22 px below the window origin (title bar) + 2 px
    // border. Pass D chrome: DrawList is invoked at
    // (cy + top_band) where top_band = kToolbarH + kUrlBarH +
    // kStatusRowH. Inside DrawList the list rows start at
    // top = cy_inner + 4 + kRowH * 2.
    constexpr u32 kTitle = 22;
    constexpr u32 kBorder = 2;
    const u32 client_y = wy + kTitle + kBorder;
    const u32 top_band = kTabStripH + kToolbarH + kUrlBarH + kStatusRowH + PrivRibbonH();
    const u32 list_y0 = client_y + top_band + 4 + kRowH * 2;
    if (sy < list_y0)
        return false;
    const u32 row = (sy - list_y0) / kRowH;
    // Re-derive `first` the same way DrawList does so the hit row
    // matches what's painted.
    const u32 max_rows_h = (wh > kTitle + kBorder * 2 + kRowH) ? (wh - kTitle - kBorder * 2) / kRowH : 0;
    u32 first = 0;
    if (g_state.bookmark_count > max_rows_h && g_state.list_selection >= max_rows_h)
        first = g_state.list_selection - (max_rows_h - 1);
    const u32 idx = first + row;
    if (idx >= g_state.bookmark_count)
        return false;
    char tmp[kUrlCap];
    StrCopyCap(tmp, kUrlCap, g_state.bookmarks[idx]);
    g_state.mode = Mode::View;
    StartFetch(tmp);
    duetos::arch::SerialWrite("[browser] double-click bookmark idx=");
    duetos::arch::SerialWriteHex(idx);
    duetos::arch::SerialWrite("\n");
    return true;
}

WindowHandle BrowserWindow()
{
    return g_state.handle;
}

bool BrowserFeedArrow(u16 keycode)
{
    if (g_state.mode == Mode::View)
    {
        // Scroll the rendered page (pixel units): arrows step one line,
        // page keys step most of a viewport.
        constexpr i32 kLineStep = 16;
        constexpr i32 kPageStep = 16 * 20;
        if (keycode == kKeyArrowUp)
        {
            g_state.scroll_y -= kLineStep;
        }
        else if (keycode == kKeyArrowDown)
        {
            g_state.scroll_y += kLineStep;
        }
        else if (keycode == duetos::drivers::input::kKeyPageUp)
        {
            g_state.scroll_y -= kPageStep;
        }
        else if (keycode == duetos::drivers::input::kKeyPageDown)
        {
            g_state.scroll_y += kPageStep;
        }
        if (g_state.scroll_y < 0)
            g_state.scroll_y = 0;
        return true;
    }
    if (g_state.mode == Mode::History || g_state.mode == Mode::Bookmarks)
    {
        const u32 cap = (g_state.mode == Mode::History) ? g_state.history_count : g_state.bookmark_count;
        if (cap == 0)
            return true;
        if (keycode == kKeyArrowUp)
        {
            if (g_state.list_selection > 0)
                --g_state.list_selection;
        }
        else if (keycode == kKeyArrowDown)
        {
            if (g_state.list_selection + 1 < cap)
                ++g_state.list_selection;
        }
        return true;
    }
    return false;
}

bool BrowserFeedChar(char c)
{
    const u8 uc = static_cast<u8>(c);

    if (g_state.mode == Mode::UrlEdit)
    {
        HandleUrlEditChar(c);
        return true;
    }

    if (g_state.mode == Mode::History || g_state.mode == Mode::Bookmarks)
    {
        if (uc == 0x1B || (g_state.mode == Mode::History && (c == 'h' || c == 'H')) ||
            (g_state.mode == Mode::Bookmarks && (c == 'l' || c == 'L')))
        {
            g_state.mode = Mode::View;
            return true;
        }
        if (uc == 0x0A) // Enter
        {
            const u32 cap = (g_state.mode == Mode::History) ? g_state.history_count : g_state.bookmark_count;
            if (g_state.list_selection >= cap)
                return true;
            const char* u = (g_state.mode == Mode::History) ? g_state.history[g_state.list_selection]
                                                            : g_state.bookmarks[g_state.list_selection];
            char tmp[kUrlCap];
            StrCopyCap(tmp, kUrlCap, u);
            StrCopyCap(g_state.url, kUrlCap, tmp);
            g_state.url_len = StrLen(g_state.url);
            g_state.mode = Mode::View;
            StartFetch(tmp);
            return true;
        }
        if (g_state.mode == Mode::Bookmarks && (c == 'x' || c == 'X'))
        {
            BookmarkRemoveSelected();
            return true;
        }
        if (c == 'j' || c == 'J')
            return BrowserFeedArrow(kKeyArrowDown);
        if (c == 'k' || c == 'K')
            return BrowserFeedArrow(kKeyArrowUp);
        return true;
    }

    // View mode.
    if (g_state.fetch_in_flight)
        return true; // swallow keys while a fetch is running

    if (uc == 0x09 || c == 'u' || c == 'U') // Tab or U -> URL edit
    {
        EnterUrlEdit();
        return true;
    }
    if (c == 'b' || c == 'B' || uc == 0x08)
    {
        NavigateBackForward(false);
        return true;
    }
    if (c == 'f' || c == 'F')
    {
        NavigateBackForward(true);
        return true;
    }
    if (c == 'r' || c == 'R')
    {
        Reload();
        return true;
    }
    if (c == 'h' || c == 'H')
    {
        g_state.mode = Mode::History;
        g_state.list_selection = (g_state.history_count > 0) ? g_state.history_count - 1 : 0;
        return true;
    }
    if (c == 'l' || c == 'L')
    {
        g_state.mode = Mode::Bookmarks;
        RescanBookmarks();
        g_state.list_selection = 0;
        return true;
    }
    if (c == 'm' || c == 'M')
    {
        BookmarkCurrent();
        return true;
    }
    if (c == 's' || c == 'S')
    {
        SaveDownload();
        return true;
    }
    if (c == 'j' || c == 'J')
        return BrowserFeedArrow(kKeyArrowDown);
    if (c == 'k' || c == 'K')
        return BrowserFeedArrow(kKeyArrowUp);
    // Link focus: 'n' cycles forward through the page's links, 'N'
    // (Shift-n) cycles backward — Tab is already bound to URL-edit, so the
    // link tab-order lives on n/N. Enter follows the focused link.
    if (c == 'n')
    {
        FocusCycleLink(true);
        return true;
    }
    if (c == 'N')
    {
        FocusCycleLink(false);
        return true;
    }
    if (uc == 0x0A) // Enter — follow the focused link, if any.
    {
        if (g_state.focus_link != kNoLink)
            FollowLink(g_state.focus_link);
        return true;
    }
    if (uc == 0x1B)
    {
        // Esc clears the status AND drops link focus.
        StatusSet("");
        g_state.focus_link = kNoLink;
        return true;
    }
    return false;
}

void BrowserSelfTest()
{
    using arch::SerialWrite;
    bool pass = true;

    // URL parsing.
    {
        const auto p = ParseUrl("http://example.com/foo");
        if (!p.ok || p.scheme_https || p.port != 80 || !StrEqI(p.host, "example.com") || !StrEqI(p.path, "/foo"))
            pass = false;
    }
    {
        const auto p = ParseUrl("https://example.com:8443/x");
        if (!p.ok || !p.scheme_https || p.port != 8443 || !StrEqI(p.host, "example.com") || !StrEqI(p.path, "/x"))
            pass = false;
    }
    {
        // https with no explicit port must default to 443 (the v0
        // code rejected https outright; this pins the new accept).
        const auto p = ParseUrl("https://secure.example.com/");
        if (!p.ok || !p.scheme_https || p.port != 443 || !StrEqI(p.host, "secure.example.com"))
            pass = false;
    }
    {
        const auto p = ParseUrl("example.com");
        if (!p.ok || p.scheme_https || p.port != 80 || !StrEqI(p.host, "example.com") || !StrEqI(p.path, "/"))
            pass = false;
    }
    {
        const auto p = ParseUrl("");
        if (p.ok)
            pass = false;
    }

    // Dotted-quad parser.
    {
        net::Ipv4Address ip;
        if (!TryParseDottedQuad("8.8.8.8", &ip) || ip.octets[0] != 8 || ip.octets[3] != 8)
            pass = false;
        if (TryParseDottedQuad("hello", &ip))
            pass = false;
        if (TryParseDottedQuad("1.2.3", &ip))
            pass = false;
        if (TryParseDottedQuad("256.0.0.0", &ip))
            pass = false;
    }

    // HTML strip — basic case + entity decode + tag block break.
    {
        const char html[] = "<html><body><p>Hello, &amp; world!</p><p>Second.</p></body></html>";
        char out[128];
        u32 ol = 0;
        StripHtml(reinterpret_cast<const u8*>(html), sizeof(html) - 1, out, sizeof(out), &ol);
        // Should contain "Hello, & world!" and "Second."
        bool found_amp = false;
        bool found_second = false;
        bool found_break = false;
        for (u32 i = 0; i + 1 < ol; ++i)
        {
            if (out[i] == '&' && out[i + 1] == ' ')
                found_amp = true;
            if (out[i] == 'S' && out[i + 1] == 'e')
                found_second = true;
            if (out[i] == '\n')
                found_break = true;
        }
        if (!found_amp || !found_second || !found_break)
            pass = false;
    }

    // HTML strip — script tag content is dropped.
    {
        const char html[] = "<p>before</p><script>var x = 1; alert('hi');</script><p>after</p>";
        char out[128];
        u32 ol = 0;
        StripHtml(reinterpret_cast<const u8*>(html), sizeof(html) - 1, out, sizeof(out), &ol);
        out[ol] = '\0';
        // Result should not contain "alert" or "var x".
        bool leaked = false;
        for (u32 i = 0; i + 4 < ol; ++i)
        {
            if (out[i] == 'a' && out[i + 1] == 'l' && out[i + 2] == 'e' && out[i + 3] == 'r' && out[i + 4] == 't')
                leaked = true;
        }
        if (leaked)
            pass = false;
    }

    // FetchUrl end-to-end over an in-memory loopback HttpTransport.
    // No socket, no network — this proves the HTTP/1.1 + cookie +
    // redirect wiring without the boot's (absent) outbound link.
    //
    // Test A: a 301 -> 200 redirect whose first hop sets a cookie.
    // Assert the final body resolves to hop-2's body, the status is
    // 200, and the Set-Cookie landed in the jar.
    {
        // Use a unique host so the assertions don't collide with the
        // cookie self-test's jar entries.
        static const char kHost[] = "selftest.duetos.local";
        const i64 now = NowUnix();

        // Hop 1: 301 with a Set-Cookie + a relative Location.
        static const char kResp301[] = "HTTP/1.1 301 Moved Permanently\r\n"
                                       "Location: /final\r\n"
                                       "Set-Cookie: sid=abc; Path=/\r\n"
                                       "Content-Length: 0\r\n"
                                       "\r\n";
        // Hop 2: 200 with the real body.
        static const char kResp200[] = "HTTP/1.1 200 OK\r\n"
                                       "Content-Type: text/html\r\n"
                                       "Content-Length: 18\r\n"
                                       "\r\n"
                                       "<p>final body</p>!";

        CannedResp hop1{kResp301, StrLen(kResp301), 0};
        net::http::HttpTransport t1{};
        t1.read = CannedRespRead;
        t1.write = CannedRespWrite;
        t1.ctx = &hop1;

        SelfTestRedirectHarness harness{};
        harness.responses[0] = kResp200;

        char urlbuf[64];
        StrCopyCap(urlbuf, sizeof(urlbuf), "http://");
        StrAppend(urlbuf, sizeof(urlbuf), kHost);
        StrAppend(urlbuf, sizeof(urlbuf), "/start");

        u8 raw[256];
        u32 got = 0;
        u16 code = 0;
        bool trunc = false;
        const FetchStatus st = FetchUrl(urlbuf, raw, sizeof(raw), &got, &code, &trunc, &t1, SelfTestRedirect, &harness);
        if (st != FetchStatus::Ok || code != 200)
            pass = false;
        // Final body must be hop-2's payload.
        bool found_final = false;
        for (u32 i = 0; i + 5 < got; ++i)
        {
            if (raw[i] == 'f' && raw[i + 1] == 'i' && raw[i + 2] == 'n' && raw[i + 3] == 'a' && raw[i + 4] == 'l')
                found_final = true;
        }
        if (!found_final)
            pass = false;

        // The Set-Cookie must now be retrievable from the jar.
        char ckout[256];
        const u32 ckn = net::CookieBuildHeader(kHost, "/page", false, now, ckout, sizeof(ckout));
        bool jar_has_sid = false;
        if (ckn > 0)
        {
            for (u32 i = 0; i + 6 < ckn; ++i)
            {
                if (ckout[i] == 's' && ckout[i + 1] == 'i' && ckout[i + 2] == 'd' && ckout[i + 3] == '=' &&
                    ckout[i + 4] == 'a' && ckout[i + 5] == 'b' && ckout[i + 6] == 'c')
                    jar_has_sid = true;
            }
        }
        if (!jar_has_sid)
            pass = false;

        // Test B: a subsequent fetch to the same host must EMIT the
        // Cookie header (built from the jar) in its request bytes.
        static const char kRespPlain[] = "HTTP/1.1 200 OK\r\n"
                                         "Content-Length: 2\r\n"
                                         "\r\n"
                                         "ok";
        CannedResp hop2{kRespPlain, StrLen(kRespPlain), 0};
        char req_capture[2048];
        req_capture[0] = '\0';
        net::http::HttpTransport t2{};
        t2.read = CannedRespRead;
        t2.write = CannedRespWrite;
        // Two ctxs needed (read vs write) — the engine writes the
        // request through `write`, then reads through `read`. Use a
        // small shim: point write at the capture buffer, read at the
        // canned response, by handing the engine separate transports
        // isn't possible, so capture via a combined ctx.
        struct Combined
        {
            CannedResp* resp;
            char* cap;
        } combined{&hop2, req_capture};
        // Re-bind read/write through a combined-ctx lambda pair.
        t2.read = [](void* ctx, u8* buf, u32 len) -> i64
        { return CannedRespRead(static_cast<Combined*>(ctx)->resp, buf, len); };
        t2.write = [](void* ctx, const u8* buf, u32 len) -> i64
        { return CannedRespCaptureWrite(static_cast<Combined*>(ctx)->cap, buf, len); };
        t2.ctx = &combined;

        u8 raw2[64];
        u32 got2 = 0;
        u16 code2 = 0;
        bool trunc2 = false;
        const FetchStatus st2 = FetchUrl(urlbuf, raw2, sizeof(raw2), &got2, &code2, &trunc2, &t2);
        if (st2 != FetchStatus::Ok || code2 != 200)
            pass = false;
        // The captured request must carry "Cookie: sid=abc".
        bool emitted_cookie = false;
        for (u32 i = 0; req_capture[i] != '\0'; ++i)
        {
            if (req_capture[i] == 'C' && StrLen(req_capture + i) >= 13 && req_capture[i + 1] == 'o' &&
                req_capture[i + 2] == 'o' && req_capture[i + 3] == 'k' && req_capture[i + 4] == 'i' &&
                req_capture[i + 5] == 'e' && req_capture[i + 6] == ':')
            {
                // Scan the rest of the line for "sid=abc".
                for (u32 j = i; req_capture[j] != '\0' && req_capture[j] != '\r'; ++j)
                {
                    if (req_capture[j] == 's' && req_capture[j + 1] == 'i' && req_capture[j + 2] == 'd' &&
                        req_capture[j + 3] == '=' && req_capture[j + 4] == 'a' && req_capture[j + 5] == 'b' &&
                        req_capture[j + 6] == 'c')
                        emitted_cookie = true;
                }
            }
        }
        if (!emitted_cookie)
            pass = false;

        // Clean up the jar entry so the live desktop / other tests
        // don't see the synthetic cookie, and re-persist so the
        // delete reaches disk (FetchUrl already saved it with sid
        // present).
        net::CookieSetFromHeader(kHost, "/", "sid=; Max-Age=0; Path=/", now);
        net::CookieJarSave();
    }

    // Test E: file downloads.
    //
    // E1 — pure-compute table tests for the render-vs-download
    // predicate and the 8.3 filename derivation (the exact logic
    // DoFetch routes through). E2 — drive the FULL download path
    // (FetchUrl over an injected attachment response -> ShouldDownload
    // -> DeriveDownloadFilename -> SaveDownloadAs) and assert the file
    // landed on the FAT32 root.
    {
        // E1: decision predicate.
        if (!IsRenderableType(nullptr) || !IsRenderableType(""))
            pass = false; // missing type renders (legacy HTML).
        if (!IsRenderableType("text/html; charset=utf-8") || !IsRenderableType("text/plain"))
            pass = false;
        if (IsRenderableType("application/pdf") || IsRenderableType("image/png"))
            pass = false;
        if (ShouldDownload("text/html", nullptr)) // renderable, no disposition
            pass = false;
        if (!ShouldDownload("application/octet-stream", nullptr)) // non-text type
            pass = false;
        if (!ShouldDownload("text/html", "attachment; filename=\"x.txt\"")) // attachment wins
            pass = false;

        // E1: filename derivation. Content-Disposition filename wins,
        // sanitised + truncated to 8.3.
        char fn[16];
        DeriveDownloadFilename("http://h/p", "application/octet-stream", "attachment; filename=\"report.pdf\"", 7, fn,
                               sizeof(fn));
        if (!StrEqI(fn, "REPORT.PDF"))
            pass = false;
        // URL basename when no disposition.
        DeriveDownloadFilename("http://h/dir/photo.png", "image/png", nullptr, 7, fn, sizeof(fn));
        if (!StrEqI(fn, "PHOTO.PNG"))
            pass = false;
        // DLxxxx fallback (no usable name) with Content-Type extension.
        DeriveDownloadFilename("http://h/", "application/zip", nullptr, 42, fn, sizeof(fn));
        if (!StrEqI(fn, "DL0042.ZIP"))
            pass = false;

        // E2: full download path over an injected attachment response.
        static const char kDlBody[] = "BINARYPAYLOAD";
        static const char kDlResp[] = "HTTP/1.1 200 OK\r\n"
                                      "Content-Type: application/octet-stream\r\n"
                                      "Content-Disposition: attachment; filename=\"hi.bin\"\r\n"
                                      "Content-Length: 13\r\n"
                                      "\r\n"
                                      "BINARYPAYLOAD";
        CannedResp dlhop{kDlResp, StrLen(kDlResp), 0};
        net::http::HttpTransport tdl{};
        tdl.read = CannedRespRead;
        tdl.write = CannedRespWrite;
        tdl.ctx = &dlhop;

        u8 dlraw[256];
        u32 dlgot = 0;
        u16 dlcode = 0;
        bool dltrunc = false;
        char ct[128] = {};
        char cd[256] = {};
        const FetchStatus dlst = FetchUrl("http://selftest.duetos.local/file", dlraw, sizeof(dlraw), &dlgot, &dlcode,
                                          &dltrunc, &tdl, nullptr, nullptr, ct, sizeof(ct), cd, sizeof(cd));
        if (dlst != FetchStatus::Ok || dlcode != 200 || dlgot != StrLen(kDlBody))
            pass = false;
        // The headers must have been captured and classified as a
        // download with the disposition-supplied filename.
        if (!ShouldDownload(ct, cd))
            pass = false;
        char dlfn[16];
        DeriveDownloadFilename("http://selftest.duetos.local/file", ct, cd, 1, dlfn, sizeof(dlfn));
        if (!StrEqI(dlfn, "HI.BIN"))
            pass = false;

        // Drive the real save + probe FAT32 for the result. Skip the
        // disk assertion when no volume is mounted (the predicate /
        // filename checks above already validate the logic).
        namespace fat = fs::fat32;
        const fat::Volume* dv = fat::Fat32Volume(0);
        if (dv != nullptr)
        {
            const bool saved = SaveDownloadAs(dlraw, dlgot, dlfn);
            fat::DirEntry probe;
            if (!saved || !fat::Fat32LookupPath(dv, dlfn, &probe))
                pass = false;
            // Status must read "Downloaded: HI.BIN".
            if (g_state.status[0] != 'D' || g_state.status[1] != 'o' || g_state.status[2] != 'w')
                pass = false;
            // Clean up so the live desktop doesn't keep the synthetic file.
            if (saved)
                fat::Fat32DeleteAtPath(dv, dlfn);
        }
    }

    // Pass D: drive a synthetic click on the HIST nav button
    // via the WidgetGroup dispatch chain. ClickHistory flips
    // g_state.mode to Mode::History (when not fetch-in-flight),
    // so the test verifies the dispatch path is wired end-to-end
    // AND that the click mutates the browser state. Restore the
    // mode + selection so the live desktop is unchanged when
    // the test returns.
    const Mode saved_mode = g_state.mode;
    const u32 saved_selection = g_state.list_selection;
    const bool saved_in_flight = g_state.fetch_in_flight;
    BindBrowserOnce();
    // Anchor the toolbar at (0, 22, 640, 438) — same shape
    // boot_bringup.cpp registers the live Browser window with
    // (640x460 minus 22 px title bar). HIST is nav index 3.
    RebindBrowserBounds(0U, 22U, 640U, 438U);
    g_state.mode = Mode::View;
    g_state.fetch_in_flight = false;
    constexpr u32 kHistIdx = 3U;
    const u32 hx = kToolbarPadX + kHistIdx * (kToolbarBtnW + kToolbarBtnGap) + kToolbarBtnW / 2U;
    const u32 hy = 22U + kToolbarPadY + kToolbarBtnH / 2U;
    const Event h_move{EventKind::MouseMove, hx, hy, 0U, 0U};
    const Event h_down{EventKind::MouseDown, hx, hy, 0U, 0U};
    const Event h_up{EventKind::MouseUp, hx, hy, 0U, 0U};
    if (g_browser.DispatchEvent(h_move) != EventResult::Consumed)
        pass = false;
    if (g_browser.DispatchEvent(h_down) != EventResult::Consumed)
        pass = false;
    if (g_browser.DispatchEvent(h_up) != EventResult::Consumed)
        pass = false;
    if (g_state.mode != Mode::History)
        pass = false;

    // URL-bar composer + footer composer must produce non-empty
    // text after a refresh.
    g_state.mode = Mode::UrlEdit;
    StrCopyCap(g_state.url, kUrlCap, "example.com");
    g_state.url_len = StrLen(g_state.url);
    RefreshUrlBarText();
    // Expect '>' prefix + ' ' + URL + '_' caret.
    if (g_urlbar_text[0] != '>' || g_urlbar_text[1] != ' ' || g_urlbar_text[2] != 'e')
        pass = false;
    RefreshFooterText();
    if (g_footer_text[0] == '\0')
        pass = false;

    // Restore pre-test state so the live UI is unchanged when
    // the umbrella selftest returns.
    g_state.mode = saved_mode;
    g_state.list_selection = saved_selection;
    g_state.fetch_in_flight = saved_in_flight;
    g_state.url[0] = '\0';
    g_state.url_len = 0;

    g_self_test_passed = pass;
    if (pass)
    {
        SerialWrite("[browser] self-test OK (URL parse incl https:443 + dotted-quad + HTML strip + "
                    "widget-click + FetchUrl loopback: 301->200 redirect + Set-Cookie jar + Cookie emit + "
                    "download decision/filename + attachment save)\n");
        SerialWrite("[browser-selftest] PASS (https-route + cookies + redirect + downloads)\n");
    }
    else
    {
        SerialWrite("[browser] self-test FAILED\n");
        SerialWrite("[browser-selftest] FAIL\n");
    }
}

bool BrowserSelfTestPassed()
{
    return g_self_test_passed;
}

void BrowserRenderSelfTest()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    auto fail = [](u32 check)
    {
        SerialWrite("[browser-render-selftest] FAIL check=");
        SerialWriteHex(check);
        SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, check);
    };

    // A canned page exercising the full pipeline: an author stylesheet
    // (a styled box + a red h1), a heading, the box, and a script that
    // mutates the h1's text. If the script runs before layout, the
    // display list will carry a "Changed" TextRun, not "Hi".
    const char* html =
        "<html><head><style>.box{background:#3366cc;width:200px;height:40px} h1{color:#ff0000}</style></head>"
        "<body><h1 id=t>Hi</h1><div class=box></div>"
        "<script>document.getElementById('t').textContent='Changed'</script></body></html>";

    const u32 vw = 320;
    RenderPage(html, StrLen(html), "http://example.com/", vw);

    if (!g_state.render_ready || g_state.render_dl == nullptr)
    {
        fail(1);
        return;
    }
    const duetos::web::DisplayList& dl = *g_state.render_dl;

    // --- Check 1: a FillRect of #3366CC (the .box background) exists,
    // sized to the styled 200x40 box. ---
    const duetos::web::DisplayItem* box = nullptr;
    for (u32 i = 0; i < dl.count; ++i)
    {
        const auto& it = dl.items[i];
        if (it.cmd == duetos::web::DisplayCmd::FillRect && it.color.r == 0x33 && it.color.g == 0x66 &&
            it.color.b == 0xCC)
        {
            box = &it;
            break;
        }
    }
    if (box == nullptr)
    {
        fail(2);
        return;
    }
    if (box->rect.w != 200 || box->rect.h != 40)
    {
        fail(3);
        return;
    }

    // --- Check 2: the heading run is RED and reflects the script
    // mutation ('Changed', not 'Hi') — proving parse->style->script->
    // layout end-to-end. ---
    const duetos::web::DisplayItem* heading = nullptr;
    for (u32 i = 0; i < dl.count; ++i)
    {
        const auto& it = dl.items[i];
        if (it.cmd == duetos::web::DisplayCmd::TextRun && it.color.r == 0xFF && it.color.g == 0x00 &&
            it.color.b == 0x00)
        {
            heading = &it;
            break;
        }
    }
    if (heading == nullptr)
    {
        fail(4);
        return;
    }
    if (heading->textLen != 7 || heading->text[0] != 'C' || heading->text[1] != 'h')
    {
        SerialWrite("[browser-render-selftest] DIAG heading='");
        for (u32 i = 0; i < heading->textLen && i < 32; ++i)
        {
            char ch[2] = {heading->text[i], '\0'};
            SerialWrite(ch);
        }
        SerialWrite("' len=");
        SerialWriteHex(heading->textLen);
        SerialWrite("\n");
        // Script did not run (still "Hi") or text wrong.
        fail(5);
        return;
    }

    // --- Check 3: PAINT the display list into a canvas and assert the
    // pixels: the .box background colour lands at the box rect, and the
    // heading draws red glyph pixels. ---
    duetos::web::PaintMetrics pm;
    pm.glyphW = 8;
    pm.glyphH = 16;
    pm.baseFontPx = 16;

    const u32 cw = vw;
    const u32 chh = 256;
    // Clear the canvas to opaque white background.
    for (u32 i = 0; i < cw * chh; ++i)
    {
        g_canvas[i * 4 + 0] = 0xFF;
        g_canvas[i * 4 + 1] = 0xFF;
        g_canvas[i * 4 + 2] = 0xFF;
        g_canvas[i * 4 + 3] = 0xFF;
    }
    duetos::web::PaintToCanvas(dl, g_canvas, cw, chh, /*scrollY=*/0, pm, ImageProviderFn, nullptr);

    // The box FillRect's interior must be #3366CC.
    {
        const i32 px = box->rect.x + box->rect.w / 2;
        const i32 py = box->rect.y + box->rect.h / 2;
        if (px >= 0 && py >= 0 && static_cast<u32>(px) < cw && static_cast<u32>(py) < chh)
        {
            const u8* p = g_canvas + (static_cast<u32>(py) * cw + static_cast<u32>(px)) * 4u;
            if (p[0] != 0x33 || p[1] != 0x66 || p[2] != 0xCC)
            {
                fail(6);
                return;
            }
        }
        else
        {
            fail(6);
            return;
        }
    }

    // The heading region must contain red glyph pixels.
    {
        bool foundRed = false;
        const i32 y0 = heading->rect.y;
        const i32 y1 = y0 + 16;
        const i32 x0 = heading->rect.x;
        const i32 x1 = x0 + static_cast<i32>(heading->textLen) * 8;
        for (i32 yy = y0; yy < y1 && yy >= 0 && static_cast<u32>(yy) < chh && !foundRed; ++yy)
        {
            for (i32 xx = x0; xx < x1 && xx >= 0 && static_cast<u32>(xx) < cw; ++xx)
            {
                const u8* p = g_canvas + (static_cast<u32>(yy) * cw + static_cast<u32>(xx)) * 4u;
                if (p[0] == 0xFF && p[1] == 0x00 && p[2] == 0x00)
                {
                    foundRed = true;
                    break;
                }
            }
        }
        if (!foundRed)
        {
            fail(7);
            return;
        }
    }

    // Leave g_state clean — this ran against canned HTML, not a real
    // navigation, so wipe the render handle so the live browser starts
    // empty rather than showing the test page.
    g_state.render_ready = false;
    g_state.render_dl = nullptr;
    g_state.render_total_h = 0;
    g_state.body_len = 0;
    g_state.body[0] = '\0';
    g_state.link_count = 0;
    g_state.focus_link = kNoLink;
    g_images.count = 0;

    SerialWrite("[browser-render-selftest] PASS (parse->style->script->layout->paint: box bg pixels, "
                "red heading glyphs, script mutation 'Changed')\n");
}

void BrowserLinksSelfTest()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    auto fail = [](u32 check)
    {
        SerialWrite("[browser-links-selftest] FAIL check=");
        SerialWriteHex(check);
        SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, check);
    };

    // Snapshot live state we touch so the desktop is unchanged after.
    const Mode saved_mode = g_state.mode;
    const bool saved_in_flight = g_state.fetch_in_flight;
    char saved_url[kUrlCap];
    StrCopyCap(saved_url, kUrlCap, g_state.url);
    const u32 saved_url_len = g_state.url_len;
    char saved_fetch_url[kUrlCap];
    StrCopyCap(saved_fetch_url, kUrlCap, g_state.fetch_url);

    // A canned page: a heading (text), a root-relative link, and an
    // absolute link. The page URL is http://example.com/dir/page so the
    // root-relative href resolves to http://example.com/next.
    const char* html = "<html><body><h1>Welcome</h1>"
                       "<p>Some intro text. <a href=\"/next\">next page</a> tail.</p>"
                       "<p><a href=\"http://other.example/abs\">absolute</a></p>"
                       "</body></html>";
    const char* page_url = "http://example.com/dir/page";

    // Guard StartFetch so FollowLink mutates the pending-nav fields but
    // never spawns a real fetch worker during the boot self-test.
    g_state.fetch_in_flight = true;
    RenderPage(html, StrLen(html), page_url, 320);
    g_state.fetch_in_flight = false; // RenderPage cleared render_ready path; reset for FollowLink

    if (!g_state.render_ready || g_state.render_dl == nullptr)
    {
        fail(1);
        goto restore;
    }

    // --- Check 1: two link rects were produced. ---
    if (g_state.link_count < 2)
    {
        SerialWrite("[browser-links-selftest] DIAG link_count=");
        SerialWriteHex(g_state.link_count);
        SerialWrite("\n");
        fail(2);
        goto restore;
    }

    // --- Check 2: one rect resolves the root-relative href to the
    // expected absolute URL, with a plausible (non-empty) rect. ---
    {
        u32 next_idx = kNoLink;
        u32 abs_idx = kNoLink;
        for (u32 i = 0; i < g_state.link_count; ++i)
        {
            if (StrEqI(g_state.link_rects[i].href, "http://example.com/next"))
                next_idx = i;
            if (StrEqI(g_state.link_rects[i].href, "http://other.example/abs"))
                abs_idx = i;
        }
        if (next_idx == kNoLink || abs_idx == kNoLink)
        {
            fail(3);
            goto restore;
        }
        const duetos::web::Rect& r = g_state.link_rects[next_idx].rect;
        if (r.w <= 0 || r.h <= 0 || r.y < 0)
        {
            fail(4);
            goto restore;
        }

        // --- Check 3: hit-testing inside the rect (document coords) maps
        // to this link. We test the document-coord predicate the same way
        // HitTestLink does, independent of live window bounds. ---
        const i32 cx_doc = r.x + r.w / 2;
        const i32 cy_doc = r.y + r.h / 2;
        bool hit = false;
        for (u32 i = 0; i < g_state.link_count; ++i)
        {
            const duetos::web::Rect& rr = g_state.link_rects[i].rect;
            if (cx_doc >= rr.x && cx_doc < rr.x + rr.w && cy_doc >= rr.y && cy_doc < rr.y + rr.h)
            {
                if (i == next_idx)
                    hit = true;
            }
        }
        if (!hit)
        {
            fail(5);
            goto restore;
        }

        // --- Check 4: the navigation target a click/Enter would follow is
        // the resolved absolute URL. FollowLink hands link_rects[idx].href
        // straight to StartFetch, so that href IS the target — assert it
        // without spawning a fetch worker (kept fetch_in_flight=true so
        // StartFetch / FollowLink no-op, exercising the navigate-path
        // guard at the same time). ---
        g_state.fetch_in_flight = true; // suppress the worker spawn
        const u32 url_len_before = g_state.url_len;
        FollowLink(next_idx); // must no-op while a fetch is "in flight"
        if (g_state.url_len != url_len_before)
        {
            fail(6); // FollowLink ignored the in-flight guard
            goto restore;
        }
        if (!StrEqI(g_state.link_rects[next_idx].href, "http://example.com/next"))
        {
            SerialWrite("[browser-links-selftest] DIAG target='");
            SerialWrite(g_state.link_rects[next_idx].href);
            SerialWrite("'\n");
            fail(7);
            goto restore;
        }

        // --- Check 5: keyboard focus cycling lands on a real link, so
        // 'n' then Enter would follow link_rects[focus_link]. ---
        g_state.focus_link = kNoLink;
        FocusCycleLink(true);
        if (g_state.focus_link >= g_state.link_count)
        {
            fail(8);
            goto restore;
        }
    }

    SerialWrite("[browser-links-selftest] PASS (anchor->link rect, root-relative + absolute href resolution, "
                "doc hit-test, FollowLink pending-nav target, focus-cycle)\n");

restore:
    // Restore the live desktop state. Wipe the render handle + link table
    // so the live browser starts empty rather than showing the test page.
    g_state.render_ready = false;
    g_state.render_dl = nullptr;
    g_state.render_total_h = 0;
    g_state.link_count = 0;
    g_state.focus_link = kNoLink;
    g_state.body_len = 0;
    g_state.body[0] = '\0';
    g_state.page_ctx = nullptr;
    g_state.page_doc = nullptr;
    g_images.count = 0;
    g_state.mode = saved_mode;
    g_state.fetch_in_flight = saved_in_flight;
    StrCopyCap(g_state.url, kUrlCap, saved_url);
    g_state.url_len = saved_url_len;
    StrCopyCap(g_state.fetch_url, kUrlCap, saved_fetch_url);
}

// Recursively find the first element in `node`'s subtree whose `id`
// attribute matches `id`. Returns nullptr if none. Used by the click
// self-test to locate the button DOM node and read its textContent back
// without a JS round-trip. File-local (test-only helper).
static duetos::web::Node* FindById(duetos::web::Node* node, const char* id)
{
    using duetos::web::NodeKind;
    for (duetos::web::Node* c = node->firstChild; c != nullptr; c = c->nextSibling)
    {
        if (c->kind == NodeKind::Element)
        {
            const char* cid = c->GetAttr("id");
            if (cid != nullptr && StrEqI(cid, id))
                return c;
        }
        if (duetos::web::Node* hit = FindById(c, id))
            return hit;
    }
    return nullptr;
}

// Boot self-test for the INTERACTIVE click plumbing (retain -> hit-test
// -> dispatch). Renders a small page through the SAME RenderPage path the
// live browser uses, so the JS context is created + retained and the
// <script>'s addEventListener registration persists. Then it dispatches a
// click through that retained context onto the button's DOM node and
// asserts the handler fired (by re-reading the button's textContent, which
// the handler set to "hit"), and that BrowserHitTestNode maps the button's
// rect centre back to the button node + the anchor's rect back to the
// anchor node with its href. This proves retain->hit-test->dispatch
// end-to-end WITHOUT a GUI.
//
// GAP: a REAL on-screen window-manager click (cursor -> BrowserMouseInput
// -> ScreenToDoc -> BrowserHitTestNode -> dispatch) is verified only via
// the GUI harness; this headless test exercises every link of that chain
// except the live cursor->screen-coord leg.
void BrowserClickSelfTest()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    auto fail = [](u32 check)
    {
        SerialWrite("[browser-click-selftest] FAIL check=");
        SerialWriteHex(check);
        SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, check);
    };

    // Snapshot live state we touch so the desktop is unchanged after.
    const Mode saved_mode = g_state.mode;
    const bool saved_in_flight = g_state.fetch_in_flight;
    char saved_url[kUrlCap];
    StrCopyCap(saved_url, kUrlCap, g_state.url);
    const u32 saved_url_len = g_state.url_len;
    char saved_fetch_url[kUrlCap];
    StrCopyCap(saved_fetch_url, kUrlCap, g_state.fetch_url);

    // A page with a button + a script that registers a click listener
    // (which bumps a counter and rewrites the button's textContent), plus
    // an anchor to exercise the link hit-test back-reference.
    const char* html = "<html><body>"
                       "<button id=\"b\">Go</button>"
                       "<span id=\"out\">idle</span>"
                       "<p><a id=\"lnk\" href=\"/next\">next</a></p>"
                       "<script>"
                       "document.getElementById('b').addEventListener('click',"
                       "function(){ document.getElementById('out').textContent='hit'; });"
                       "</script>"
                       "</body></html>";
    const char* page_url = "http://example.com/dir/page";

    // Guard the fetch worker so any accidental navigation no-ops.
    g_state.fetch_in_flight = true;
    RenderPage(html, StrLen(html), page_url, 320);
    g_state.fetch_in_flight = false;

    if (!g_state.render_ready || g_state.render_dl == nullptr)
    {
        fail(1);
        goto restore;
    }

    // --- Check 1: the retained context was created + stored. ---
    if (g_state.page_ctx == nullptr || g_state.page_doc == nullptr)
    {
        fail(2);
        goto restore;
    }

    {
        // --- Check 2: locate the button node in the live DOM. ---
        duetos::web::Node* button = FindById(g_state.page_doc, "b");
        if (button == nullptr)
        {
            fail(3);
            goto restore;
        }

        // The button's textContent starts as "Go" (its first Text child).
        if (button->firstChild == nullptr || button->firstChild->text == nullptr ||
            !StrEqI(button->firstChild->text, "Go"))
        {
            fail(4);
            goto restore;
        }

        // --- Check 3: dispatch a click through the retained context. The
        // listener the <script> registered during render must still be
        // alive and fire, rewriting textContent to "hit". ---
        duetos::web::JsDomContextDispatchClick(g_state.page_ctx, button);
        // The listener rewrites a SEPARATE #out element's textContent to
        // "hit" (mutating a node other than the dispatch target, mirroring
        // the js-dom self-test's persistence case).
        duetos::web::Node* outEl = FindById(g_state.page_doc, "out");
        if (outEl == nullptr || outEl->firstChild == nullptr || outEl->firstChild->text == nullptr ||
            !StrEqI(outEl->firstChild->text, "hit"))
        {
            SerialWrite("[browser-click-selftest] DIAG out='");
            if (outEl != nullptr && outEl->firstChild != nullptr && outEl->firstChild->text != nullptr)
                SerialWrite(outEl->firstChild->text);
            SerialWrite("'\n");
            fail(5);
            goto restore;
        }

        // --- Check 6: LIVE RE-RENDER. The handler's textContent='hit'
        // marked the DOM dirty; consume the flag and re-lay-out the
        // retained doc (exactly what BrowserMouseInput does after a real
        // click). The FRESH display list must now carry a TextRun reading
        // "hit" tagged with #out's node — proving a handler's DOM change
        // reaches the SCREEN (the display list), not just the DOM tree. ---
        if (!duetos::web::JsDomContextConsumeDirty(g_state.page_ctx))
        {
            fail(10); // mutation didn't set the dirty flag
            goto restore;
        }
        if (!RelayoutFromDoc(g_state.page_doc, g_state.render_viewport_w) || g_state.render_dl == nullptr)
        {
            fail(11);
            goto restore;
        }
        {
            const duetos::web::DisplayList& rdl = *g_state.render_dl;
            bool found_hit = false;
            for (u32 i = 0; i < rdl.count; ++i)
            {
                const duetos::web::DisplayItem& it = rdl.items[i];
                if (it.cmd == duetos::web::DisplayCmd::TextRun && it.node == outEl && it.text != nullptr &&
                    it.textLen >= 3 && it.text[0] == 'h' && it.text[1] == 'i' && it.text[2] == 't')
                {
                    found_hit = true;
                    break;
                }
            }
            if (!found_hit)
            {
                fail(12); // re-render did not surface the mutated text
                goto restore;
            }
        }

        // --- Check 4: BrowserHitTestNode at the button's rect centre maps
        // back to the button node. Find the button's display item by node
        // identity to get its document rect. ---
        const duetos::web::DisplayList& dl = *g_state.render_dl;
        const duetos::web::Rect* brect = nullptr;
        for (u32 i = 0; i < dl.count; ++i)
        {
            if (dl.items[i].node == button && dl.items[i].rect.w > 0 && dl.items[i].rect.h > 0)
            {
                brect = &dl.items[i].rect;
                break;
            }
        }
        if (brect == nullptr)
        {
            fail(6);
            goto restore;
        }
        {
            const i32 bx = brect->x + brect->w / 2;
            const i32 by = brect->y + brect->h / 2;
            const char* href = nullptr;
            const duetos::web::Node* hit = BrowserHitTestNode(bx, by, &href);
            if (hit != button)
            {
                fail(7);
                goto restore;
            }
        }

        // --- Check 5: the anchor's rect centre hit-tests to a node
        // carrying the anchor's href (the link surface). ---
        const duetos::web::Rect* lrect = nullptr;
        for (u32 i = 0; i < dl.count; ++i)
        {
            if (dl.items[i].node != nullptr && dl.items[i].href != nullptr && dl.items[i].href[0] != '\0' &&
                dl.items[i].rect.w > 0 && dl.items[i].rect.h > 0)
            {
                lrect = &dl.items[i].rect;
                break;
            }
        }
        if (lrect == nullptr)
        {
            fail(8);
            goto restore;
        }
        {
            const i32 lx = lrect->x + lrect->w / 2;
            const i32 ly = lrect->y + lrect->h / 2;
            const char* href = nullptr;
            const duetos::web::Node* hit = BrowserHitTestNode(lx, ly, &href);
            if (hit == nullptr || href == nullptr || href[0] == '\0')
            {
                fail(9);
                goto restore;
            }
        }
    }

    SerialWrite("[browser-click-selftest] PASS (retained ctx, addEventListener persists, dispatch fires handler "
                "via textContent readback, live re-render surfaces mutated text, hit-test node + href)\n");

restore:
    g_state.render_ready = false;
    g_state.render_dl = nullptr;
    g_state.render_total_h = 0;
    g_state.link_count = 0;
    g_state.focus_link = kNoLink;
    g_state.body_len = 0;
    g_state.body[0] = '\0';
    g_state.page_ctx = nullptr;
    g_state.page_doc = nullptr;
    g_images.count = 0;
    g_state.mode = saved_mode;
    g_state.fetch_in_flight = saved_in_flight;
    StrCopyCap(g_state.url, kUrlCap, saved_url);
    g_state.url_len = saved_url_len;
    StrCopyCap(g_state.fetch_url, kUrlCap, saved_fetch_url);
}

// Drop the rendered page so the start page shows (a fresh / blank tab).
void ShowBlankTab()
{
    // A blank tab is NOT the privileged origin — leaving a page this way
    // (new tab / tab-select fallback) must auto-disarm just like a fetch
    // navigation does (the start page must never inherit armed privilege).
    if (g_priv.IsArmed())
    {
        g_priv.OnNavigation(false);
        PrivBindingTeardownCurrent();
        g_priv_confirm = false;
    }
    g_state.render_ready = false;
    g_state.render_dl = nullptr;
    g_state.render_total_h = 0;
    g_state.body_len = 0;
    g_state.body[0] = '\0';
    g_state.scroll_y = 0;
    g_state.url[0] = '\0';
    g_state.url_len = 0;
}

void BrowserMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_state.handle == kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it. The
    // WidgetGroup dispatch path needs cursor coords in the
    // same frame RebindBrowserBounds anchors the chrome to.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindBrowserOnce();
    RebindBrowserBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_prev_left_down;
    const bool release_edge = !left_down && g_prev_left_down;
    g_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_browser.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        // Reconfirm dialog is MODAL + chrome-owned: it steals every press
        // while up. Yes => arm; anything else (Cancel or outside) => dismiss.
        // The page never sees these clicks.
        if (g_priv_confirm)
        {
            const u32 mb_top = client_y + kTabStripH + kToolbarH + kUrlBarH + kStatusRowH + PrivRibbonH();
            const Rect content{wx, mb_top, ww, (wy + wh > mb_top) ? wy + wh - mb_top : 0U};
            const Rect d = PrivConfirmDialogRect(content);
            const Rect yes = PrivConfirmYesRect(d);
            if (yes.Contains(cx, cy))
            {
                g_priv_confirm = false;
                if (PrivArmAffordanceVisible()) // re-check at confirm time
                    PrivArm();
            }
            else
            {
                g_priv_confirm = false; // Cancel or click-away dismisses.
            }
            return;
        }
        // Tab strip band (top): route to the tab model before the page/chrome.
        if (cy < client_y + kTabStripH)
        {
            const Rect strip{wx, client_y, ww, kTabStripH};
            const TabHit th = g_tabs.HitTest(strip, cx, cy);
            if (th.kind == TabHitKind::NewTab)
            {
                g_tabs.AddTab("", "New Tab", TabAccent::Native);
                ShowBlankTab(); // a new tab opens on the start page.
            }
            else if (th.kind == TabHitKind::Close)
            {
                g_tabs.CloseTab(th.index);
            }
            else if (th.kind == TabHitKind::Tab)
            {
                g_tabs.Select(th.index);
                // Phase 1: one live page — selecting re-fetches the tab's URL
                // if it has one, else falls back to the start page.
                if (g_tabs.tabs[th.index].url[0] != '\0' && !g_state.fetch_in_flight)
                    StartFetch(g_tabs.tabs[th.index].url);
                else
                    ShowBlankTab();
            }
            return; // the strip consumed this press; next compose repaints it.
        }
        // Toolbar band: route to the unified omnibox controls (same actions
        // as the retired AppButtons), then to the page below.
        const u32 tb_top = client_y + kTabStripH;
        const u32 tb_h = kToolbarH + kUrlBarH + kStatusRowH;
        if (cy < tb_top + tb_h)
        {
            const Rect tb{wx, tb_top, ww, tb_h};
            const u32 body_top = tb_top + tb_h + PrivRibbonH();
            const Rect body{wx, body_top, ww, (wy + wh > body_top) ? wy + wh - body_top : 0U};
            // Arm affordance: the "[Arm]" chip overlays the pill's right end.
            // Check it before the omnibox hit-test (it sits inside the Pill
            // region) — a press opens the reconfirm dialog, never arms directly.
            if (PrivArmAffordanceVisible())
            {
                const u32 pillH = 26U;
                const u32 pillY = tb_top + (tb_h - pillH) / 2U;
                const Rect chip = PrivArmChipRect(g_omni.PillRect(tb), pillY, pillH);
                if (chip.Contains(cx, cy))
                {
                    g_priv_confirm = true; // open the reconfirm dialog.
                    return;
                }
            }
            const OmniHit oh = g_omni.HitTest(tb, cx, cy);
            switch (oh.kind)
            {
            case OmniHitKind::Nav:
                if (oh.navIndex == 0)
                    ClickBack();
                else if (oh.navIndex == 1)
                    ClickForward();
                else
                    ClickReload();
                break;
            case OmniHitKind::Pill:
                EnterUrlEdit();
                break;
            case OmniHitKind::Ask:
                // ✦ toggles the Assistant dock surface.
                if (g_assistant.mode == DockMode::Hidden)
                    g_assistant.Summon(body);
                else
                    g_assistant.Dismiss();
                break;
            case OmniHitKind::Library:
                // ▤ toggles the Library dock surface.
                if (g_library.mode == DockMode::Hidden)
                    g_library.Summon(body);
                else
                    g_library.Dismiss();
                break;
            case OmniHitKind::Menu:
                ClickBookmarks();
                break;
            default:
                break;
            }
            return; // toolbar consumed this press.
        }
        // Armed warning ribbon band: the only interactive element is the
        // "[Disarm]" button at its right end. Chrome-owned — the page never
        // sees a press in this band.
        if (PrivShouldRenderArmed())
        {
            const u32 rib_top = client_y + kTabStripH + kToolbarH + kUrlBarH + kStatusRowH;
            if (cy >= rib_top && cy < rib_top + kPrivRibbonH)
            {
                const Rect db = PrivDisarmBtnRect(wx, rib_top, ww);
                if (db.Contains(cx, cy))
                    PrivDisarm();
                return; // the ribbon absorbs the press either way.
            }
        }
        // Dockable surfaces overlay the content — handle their clicks before
        // the page. `body` here matches the DrawFn surface rect.
        {
            const u32 body_top = client_y + kTabStripH + kToolbarH + kUrlBarH + kStatusRowH + PrivRibbonH();
            const Rect body{wx, body_top, ww, (wy + wh > body_top) ? wy + wh - body_top : 0U};
            if (HandleDockClick(g_assistant, body, cx, cy) || HandleDockClick(g_library, body, cx, cy))
                return;
            // Start page (blank tab): route tile / prompt clicks.
            if (ShowStartPage())
            {
                const StartHit sh = g_startpage.HitTest(body, cx, cy);
                if (sh.kind == StartHitKind::Tile && g_startpage.tiles[sh.index].url[0] != '\0')
                    StartFetch(g_startpage.tiles[sh.index].url);
                else if (sh.kind == StartHitKind::Prompt)
                    EnterUrlEdit();
                return; // the start page consumes body presses.
            }
        }
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        const EventResult er = g_browser.DispatchEvent(d);
        // The toolbar / chrome didn't claim this press — route it into the
        // page. Unified interactive path: map screen->doc coords, hit-test
        // the display list back to the topmost DOM node, dispatch a
        // bubbling JS `click` so page handlers fire (on buttons / divs /
        // anything, not just anchors), then — unless a handler called
        // preventDefault() — follow the element's href if it has one. This
        // also tracks keyboard focus on a clicked link so the focus ring
        // follows. When there is no interactive context (download / parse
        // failure / OOM), fall back to the link-only hit-test.
        //
        // CONCURRENCY: the whole page-interaction block is gated on
        // !fetch_in_flight. RenderPage runs on the browser-fetch worker
        // thread and bump-allocates g_render_arena (DOM + display list +
        // link_rects) for the WHOLE duration fetch_in_flight is true. If the
        // compositor thread dispatched a click in that window, a JS handler's
        // DOM mutation (innerHTML/textContent) would bump-allocate the SAME
        // arena concurrently — a two-thread arena race — and BrowserHitTestNode
        // would read a half-rebuilt render_dl / link_rects. Skipping page
        // interaction while a fetch is loading closes both. (FollowLink /
        // FollowHref already self-guard on this same flag.)
        if (er != EventResult::Consumed && !g_state.fetch_in_flight)
        {
            i32 doc_x = 0;
            i32 doc_y = 0;
            const bool in_body = ScreenToDoc(cx, cy, &doc_x, &doc_y);
            if (in_body && g_state.page_ctx != nullptr)
            {
                const char* href = nullptr;
                const duetos::web::Node* n = BrowserHitTestNode(doc_x, doc_y, &href);
                // Keep the focus ring on a clicked link.
                const u32 link_hit = HitTestLink(cx, cy);
                if (link_hit != kNoLink)
                    g_state.focus_link = link_hit;
                bool prevented = false;
                if (n != nullptr)
                {
                    // DispatchClick takes a mutable Node*; the back-ref is
                    // const only to keep layout from mutating it.
                    prevented =
                        duetos::web::JsDomContextDispatchClick(g_state.page_ctx, const_cast<duetos::web::Node*>(n));
                    // If a listener mutated the DOM (textContent/innerHTML/
                    // setAttribute/classList), re-lay-out the retained doc so
                    // the change reaches the screen on the next compose. Safe
                    // here: we hold the compositor context and !fetch_in_flight
                    // (the enclosing guard), so the fetch worker is not racing
                    // the same arenas.
                    if (duetos::web::JsDomContextConsumeDirty(g_state.page_ctx))
                        RelayoutFromDoc(g_state.page_doc, g_state.render_viewport_w);
                }
                if (!prevented && href != nullptr && href[0] != '\0')
                    FollowHref(href);
            }
            else
            {
                // No interactive context — link-only navigation.
                const u32 hit = HitTestLink(cx, cy);
                if (hit != kNoLink)
                {
                    g_state.focus_link = hit;
                    FollowLink(hit);
                }
            }
        }
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside
        // the toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_browser.DispatchEvent(u);
    }
}

} // namespace duetos::apps::browser
