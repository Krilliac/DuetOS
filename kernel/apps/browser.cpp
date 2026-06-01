#include "apps/browser.h"

#include "arch/x86_64/serial.h"
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

    // Vertical scroll offset (in wrapped rows). Reset to 0 on a
    // successful fetch.
    u32 scroll_row;

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
};

constinit State g_state = {};

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
constexpr u32 kNavBtnCount = 7U;

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
    static const char kHint[] = "U:URL  B:BACK  F:FWD  R:RELOAD  H:HIST  L:BMARK  M:MARK  S:SAVE  J/K:SCROLL";
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
// HTML stripping.
//
// Walk the input, drop tag content (<...>), decode known entities,
// and emit a newline at every block-level close. The output is a
// plaintext stream the painter line-wraps on the fly.
//
// GAP: CSS / JavaScript / images / layout — the renderer is a tag
//      stripper, not a layout engine. Styling, scripting, and inline
//      media are deferred to future swarms; <script> bodies are
//      dropped, <style>/CSS is treated as text, <img> is ignored.
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

// x509 verifier adapter. net::tls::CertVerifyFn hands us only the
// leaf DER + hostname; net::x509::Verify wants the (empty here)
// intermediate chain + a wall-clock. We supply no intermediates —
// the test trust store issues the leaf directly — and NowUnix().
//
// GAP: production CA roots — x509's embedded trust store is
//      test-only, so a real-internet leaf fails this check and the
//      handshake aborts (the browser surfaces "certificate not
//      trusted"). Wiring the Mozilla root program in is the seam.
bool BrowserCertVerify(const u8* leaf_der, u32 leaf_len, const char* hostname, void* /*ctx*/)
{
    const u64 now = static_cast<u64>(NowUnix());
    return net::x509::Verify(leaf_der, leaf_len, nullptr, nullptr, 0, hostname, now);
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
FetchStatus FetchUrl(const char* url, u8* raw_buf, u32 raw_cap, u32* raw_len, u16* status_out, bool* truncated_out,
                     net::http::HttpTransport* injected, net::http::HttpConnect injected_connect = nullptr,
                     void* injected_connect_ctx = nullptr)
{
    *raw_len = 0;
    *status_out = 0;
    *truncated_out = false;

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

void DoFetch(const char* url)
{
    g_state.body_len = 0;
    g_state.body[0] = '\0';
    g_state.truncated = false;
    g_state.scroll_row = 0;
    g_state.status_code = 0;

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
    const FetchStatus st = FetchUrl(url, raw, kHttpResponseCap, &got, &code, &truncated, /*injected=*/nullptr);

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
    StripHtml(raw, got, g_state.body, kBodyCap, &g_state.body_len);
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
    // Reserve Pass D toolbar + URL bar + status row at the top
    // and the AppLabel footer at the bottom. Body view sits in
    // the middle band.
    const u32 top_reserved = kToolbarH + kUrlBarH + kStatusRowH + 2;
    const u32 bot_reserved = kFooterH + 2;
    if (ch < top_reserved + bot_reserved)
        return;
    const u32 view_h = ch - top_reserved - bot_reserved;
    const u32 chars_per_row = (cw > 12) ? (cw - 8) / 8 : 1;
    const u32 rows_visible = view_h / kRowH;

    // Wrap body on the fly. Maintain a row counter so we can skip
    // ahead by `scroll_row` and stop after `rows_visible` rows.
    u32 row = 0;
    u32 col = 0;
    char line[200];
    u32 line_n = 0;

    auto flush_line = [&]()
    {
        line[line_n] = '\0';
        if (row >= g_state.scroll_row && row < g_state.scroll_row + rows_visible)
        {
            const u32 y = cy + top_reserved + (row - g_state.scroll_row) * kRowH;
            FramebufferDrawString(cx + 4, y, line, fg, bg);
        }
        ++row;
        line_n = 0;
        col = 0;
    };

    for (u32 i = 0; i < g_state.body_len; ++i)
    {
        const char c = g_state.body[i];
        if (c == '\n')
        {
            flush_line();
            continue;
        }
        if (col >= chars_per_row)
        {
            flush_line();
        }
        if (line_n + 1 < sizeof(line))
        {
            line[line_n++] = c;
        }
        ++col;
        // Don't break early — keep counting rows past the
        // visible range so the scrollbar's "total" reflects the
        // full body. The flush_line bounds-check above already
        // prevents writes outside the visible window.
    }
    if (line_n > 0)
        flush_line();
    // Scrollbar at the right edge of the body view. `total` is
    // the final row count; `visible` is rows_visible; `first`
    // is scroll_row.
    if (rows_visible > 0 && cw > duetos::drivers::video::kScrollbarWidth)
    {
        const u32 sb_x = cx + cw - duetos::drivers::video::kScrollbarWidth;
        const u32 sb_y = cy + top_reserved;
        const u32 sb_w = duetos::drivers::video::kScrollbarWidth;
        const u32 sb_h = rows_visible * kRowH;
        duetos::drivers::video::ScrollbarPaint(sb_x, sb_y, sb_w, sb_h, {row, rows_visible, g_state.scroll_row});
        duetos::drivers::video::WindowScrollbarSurface s{};
        s.present = true;
        s.x = sb_x;
        s.y = sb_y;
        s.w = sb_w;
        s.h = sb_h;
        s.total = row;
        s.visible = rows_visible;
        s.first = g_state.scroll_row;
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
    BindBrowserOnce();
    RefreshUrlBarText();
    RefreshFooterText();
    RebindBrowserBounds(cx, cy, cw, ch);

    // Pre-paint a status-band tone behind the footer label so
    // the Caption-role glyphs sit on a uniform backdrop —
    // mirrors the Notes status band.
    if (ch > kFooterH)
        FramebufferFillRect(cx, cy + ch - kFooterH, cw, kFooterH, 0x00C8C8B8U);

    Compose compose_ctx{};
    g_browser.PaintAll(compose_ctx);

    // Body / modal-list paint area starts BELOW the toolbar +
    // URL bar + status row the AppToolbar / labels just painted.
    const u32 top_band = kToolbarH + kUrlBarH + kStatusRowH;

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
    else
    {
        DrawBody(cx, cy, cw, ch, fg, bg);
    }
    // Footer hint is now painted by the AppLabel inside
    // g_browser — see RefreshFooterText.
}

void StartFetch(const char* url)
{
    if (g_state.fetch_in_flight)
        return;
    StrCopyCap(g_state.fetch_url, kUrlCap, url);
    g_state.fetch_in_flight = true;
    sched::SchedCreate(FetchWorker, g_state.fetch_url, "browser-fetch");
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
    duetos::drivers::video::WindowSetWheelHandler(handle, BrowserOnWheel);
    duetos::drivers::video::WindowSetScrollHandler(handle,
                                                   [](duetos::u32 first)
                                                   {
                                                       // Body view binds directly; modal lists clamp.
                                                       if (g_state.mode == Mode::View)
                                                           g_state.scroll_row = first;
                                                   });
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
    const u32 top_band = kToolbarH + kUrlBarH + kStatusRowH;
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
        if (keycode == kKeyArrowUp)
        {
            if (g_state.scroll_row > 0)
                --g_state.scroll_row;
        }
        else if (keycode == kKeyArrowDown)
        {
            ++g_state.scroll_row;
        }
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
    if (uc == 0x1B)
    {
        StatusSet("");
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
                    "widget-click + FetchUrl loopback: 301->200 redirect + Set-Cookie jar + Cookie emit)\n");
        SerialWrite("[browser-selftest] PASS (https-route + cookies + redirect)\n");
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
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_browser.DispatchEvent(d);
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
