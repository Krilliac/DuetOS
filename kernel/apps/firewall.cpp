#include "apps/firewall.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"
#include "net/firewall.h"
#include "net/stack.h"

namespace duetos::apps::firewall
{

namespace
{

constexpr u32 kRowH = 14;
constexpr u32 kMargin = 16;
constexpr u32 kPad = 4;
constexpr u32 kHeaderFg = 0x00FFD040;
constexpr u32 kFg = 0x00C8D0DA;
constexpr u32 kFgDim = 0x00808890;
constexpr u32 kAllowFg = 0x0040E060;
constexpr u32 kDenyFg = 0x00E04040;
constexpr u32 kBg = 0x00181020;

constinit duetos::drivers::video::WindowHandle g_handle = duetos::drivers::video::kWindowInvalid;

void Append(char* line, u32& pos, u32 cap, const char* s)
{
    while (*s != '\0' && pos + 1 < cap)
    {
        line[pos++] = *s++;
    }
}

void AppendU(char* line, u32& pos, u32 cap, u64 v)
{
    char buf[24];
    u32 t = 0;
    if (v == 0)
    {
        buf[t++] = '0';
    }
    while (v != 0)
    {
        buf[t++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    while (t != 0 && pos + 1 < cap)
    {
        line[pos++] = buf[--t];
    }
}

void AppendIp(char* line, u32& pos, u32 cap, duetos::net::Ipv4Address ip, u8 mask)
{
    for (u32 i = 0; i < 4; ++i)
    {
        AppendU(line, pos, cap, ip.octets[i]);
        if (i < 3 && pos + 1 < cap)
        {
            line[pos++] = '.';
        }
    }
    if (pos + 1 < cap)
    {
        line[pos++] = '/';
    }
    AppendU(line, pos, cap, mask);
}

const char* DirName(duetos::net::firewall::Direction d)
{
    return d == duetos::net::firewall::Direction::Ingress ? "IN " : "OUT";
}

const char* ProtoName(duetos::net::firewall::Proto p)
{
    using duetos::net::firewall::Proto;
    switch (p)
    {
    case Proto::Icmp:
        return "ICMP";
    case Proto::Tcp:
        return "TCP ";
    case Proto::Udp:
        return "UDP ";
    case Proto::Any:
    default:
        return "ANY ";
    }
}

// ---------------------------------------------------------------
// Pass D chrome: AppToolbar (back) + 1 AppButton (RFRSH) + 2
// AppLabels (header "DUETOS FIREWALL", footer hint). The toolbar
// surfaces a read-only refresh trigger so a fresh user has a
// discoverable affordance without memorising the kernel-shell
// `firewall` subcommands.
//
// Carve-outs that stay raw paint:
//   - DEFAULTS line: "DEFAULT IN=ALLOW OUT=ALLOW" — single
//     coloured row composed from FwDefaultPolicy() calls.
//   - STATS line: dim-coloured aggregated counters from
//     FwStatsRead().
//   - RULES table: variable-length multi-column block (IDX / DIR /
//     PROTO / SRC / DST / ACTION / HITS) with a section heading
//     and a dim column-header subline. Per-row colour varies
//     (ALLOW=green, DENY=red). AppListRow has no multi-column /
//     per-row colour model.
//   - CONNTRACK table: variable-length multi-column block (PROTO
//     STATE LOCAL PEER) with its own heading + column-header.
//   - RECENT DENIALS: variable-length list of dim-coloured deny
//     records (DIR PROTO SRC -> DST) with its own heading.
//   - EDIT HINT: dim-coloured footer-band caption pointing at the
//     kernel-shell `firewall` subcommand surface.
//   AppPanel / AppListRow / AppLabel have no multi-column /
//   section-header / per-row colour model and would lose the
//   tabular alignment + colour cues. The lists paint inside the
//   band DrawFn carves out between the (toolbar + header) at the
//   top and the AppLabel footer at the bottom.

constexpr u32 kFwToolbarH = 22U;
constexpr u32 kFwToolbarBtnW = 52U;
constexpr u32 kFwToolbarBtnH = 18U;
constexpr u32 kFwToolbarBtnGap = 4U;
constexpr u32 kFwToolbarPadX = 4U;
constexpr u32 kFwToolbarPadY = 2U;
constexpr u32 kFwHeaderH = kRowH + 6U; // matches legacy header drop
constexpr u32 kFwFooterH = kRowH;

using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
using duetos::drivers::video::ThemeCurrent;
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
constinit char g_header_text[40] = {};
constinit char g_footer_text[80] = {};

// Forward decl for the toolbar click trampoline (defined below;
// it has to live above the constinit g_firewall that captures it
// by function-pointer value).
void ClickRefresh();

// Toolbar (back), then 1 action AppButton, then 2 AppLabels
// (header, footer). Reverse declaration order is dispatch order
// — buttons get first refusal on clicks.
constinit auto g_firewall = MakeWidgetGroup(AppToolbar{}, AppButton{}, AppLabel{}, AppLabel{});

constinit bool g_firewall_bound = false;
constinit bool g_firewall_prev_left_down = false;
constinit bool g_firewall_self_test_passed = false;

// Walk the recursive WidgetChain by hand to grab a stable
// pointer to the action button. Chain order mirrors the
// MakeWidgetGroup argument list (toolbar -> 1 button -> 2
// labels).
AppButton* FwActionButton()
{
    return &g_firewall.chain.tail.head; // toolbar -> btn[0]
}

// AppLabel accessors — header / footer sit at chain positions
// 2, 3 (zero-indexed) after the 1 toolbar + 1 button.
AppLabel& FwHeaderLabel()
{
    return g_firewall.chain.tail.tail.head;
}
AppLabel& FwFooterLabel()
{
    return g_firewall.chain.tail.tail.tail.head;
}

void BindFirewallOnce()
{
    if (g_firewall_bound)
        return;
    g_firewall_bound = true;

    auto& toolbar = g_firewall.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    AppButton* btn = FwActionButton();
    btn->label = "RFRSH";
    btn->on_click = ClickRefresh;
    btn->weight = ChromeTextWeight::Regular;
    btn->bg_rgb = 0; // theme role default
    btn->fg_rgb = 0x00101828U;

    const auto& th = ThemeCurrent();
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;

    auto& header = FwHeaderLabel();
    header.text = g_header_text;
    header.role = ChromeTextRole::Body;
    header.weight = ChromeTextWeight::Bold;
    header.fg_rgb = fg;
    header.bg_rgb = kBg;
    header.align_left = true;

    auto& footer = FwFooterLabel();
    footer.text = g_footer_text;
    footer.role = ChromeTextRole::Caption;
    footer.weight = ChromeTextWeight::Regular;
    footer.fg_rgb = dim;
    footer.bg_rgb = kBg;
    footer.align_left = true;
}

// Re-anchor the toolbar + button + labels to the live client
// rect. Called from DrawFn before PaintAll and from
// FirewallMouseInput before DispatchEvent so hit-tests + visuals
// stay consistent across window moves / resizes.
void RebindFirewallBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    auto& toolbar = g_firewall.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kFwToolbarH};

    {
        constexpr u32 i = 0U;
        const u32 bx = cx + kFwToolbarPadX + i * (kFwToolbarBtnW + kFwToolbarBtnGap);
        FwActionButton()->bounds = Rect{bx, cy + kFwToolbarPadY, kFwToolbarBtnW, kFwToolbarBtnH};
    }

    // Header sits directly below the toolbar. Spans the client
    // width with kMargin x-pad to match the legacy raw-paint
    // x-offset ("cx + kMargin").
    const u32 header_y = cy + kFwToolbarH;
    const u32 header_x_pad = kMargin;
    FwHeaderLabel().bounds =
        Rect{cx + header_x_pad, header_y, (cw > header_x_pad) ? cw - header_x_pad : cw, kFwHeaderH};

    // Footer hint band along the bottom of the client area.
    const u32 fy = (ch > kFwFooterH) ? cy + ch - kFwFooterH : cy;
    const u32 fw = (cw > kPad) ? cw - kPad : cw;
    FwFooterLabel().bounds = Rect{cx + kPad, fy, fw, kFwFooterH};
}

void RefreshFirewallHeader()
{
    static const char kHeader[] = "DUETOS FIREWALL";
    u32 i = 0;
    for (; kHeader[i] != '\0' && i + 1 < sizeof(g_header_text); ++i)
        g_header_text[i] = kHeader[i];
    g_header_text[i] = '\0';
}

void RefreshFirewallFooter()
{
    static const char kHint[] = "EDIT via kernel shell: firewall add/del/toggle/default/log/conntrack";
    u32 i = 0;
    for (; kHint[i] != '\0' && i + 1 < sizeof(g_footer_text); ++i)
        g_footer_text[i] = kHint[i];
    g_footer_text[i] = '\0';
}

// ----- Pass D click trampoline ---------------------------------
// AppButton::on_click is a plain `void (*)()` so the constinit
// g_firewall above captures it by function-pointer value. RFRSH
// is intentionally read-only: it touches FwStatsRead +
// FwSnapshot (both read-only) so the snapshot the next paint
// reads is current, and posts a notify so the user gets visual
// confirmation. We deliberately do NOT bind destructive actions
// (FwRemove / FwReset / FwSetDefaultPolicy) to the toolbar —
// rule editing is gated behind the kernel shell with
// `kCapNetAdmin`, and the toolbar must never grant unprivileged
// rule edits.

void ClickRefresh()
{
    // Touch the read-only snapshot APIs so any lazy backing
    // store warms up before the next paint. Both calls are
    // side-effect-free at the firewall module's contract.
    (void)duetos::net::firewall::FwStatsRead();
    duetos::net::firewall::Rule snap_unused[duetos::net::firewall::kFwMaxRules];
    (void)duetos::net::firewall::FwSnapshot(snap_unused, duetos::net::firewall::kFwMaxRules);
    duetos::drivers::video::NotifyShow("firewall: refreshed");
}

// Paint the raw firewall content (defaults / stats / rules /
// conntrack / recent denials / edit hint) inside the band DrawFn
// carves out between the (toolbar + header) at the top and the
// AppLabel footer at the bottom.
void PaintFirewallContent(u32 cx, u32 cy, u32 cw, u32 ch)
{
    (void)cw;
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    u32 y = cy;
    char line[120];
    u32 pos = 0;

    Append(line, pos, sizeof(line), "DEFAULT IN=");
    Append(line, pos, sizeof(line),
           duetos::net::firewall::FwDefaultPolicy(duetos::net::firewall::Direction::Ingress) ==
                   duetos::net::firewall::Action::Allow
               ? "ALLOW"
               : "DENY");
    Append(line, pos, sizeof(line), " OUT=");
    Append(line, pos, sizeof(line),
           duetos::net::firewall::FwDefaultPolicy(duetos::net::firewall::Direction::Egress) ==
                   duetos::net::firewall::Action::Allow
               ? "ALLOW"
               : "DENY");
    line[pos] = '\0';
    FramebufferDrawString(cx + kMargin, y, line, kFg, kBg);
    y += kRowH;

    const duetos::net::firewall::Stats stats = duetos::net::firewall::FwStatsRead();
    pos = 0;
    Append(line, pos, sizeof(line), "STATS    IN: ");
    AppendU(line, pos, sizeof(line), stats.ingress_checked);
    Append(line, pos, sizeof(line), " checked, ");
    AppendU(line, pos, sizeof(line), stats.ingress_denied);
    Append(line, pos, sizeof(line), " denied   OUT: ");
    AppendU(line, pos, sizeof(line), stats.egress_checked);
    Append(line, pos, sizeof(line), " checked, ");
    AppendU(line, pos, sizeof(line), stats.egress_denied);
    Append(line, pos, sizeof(line), " denied");
    line[pos] = '\0';
    FramebufferDrawString(cx + kMargin, y, line, kFgDim, kBg);
    y += kRowH + 4;

    FramebufferDrawString(cx + kMargin, y, "RULES (first match wins)", kHeaderFg, kBg);
    y += kRowH;
    FramebufferDrawString(cx + kMargin, y, "IDX  DIR PROTO SRC                DST                ACTION HITS", kFgDim,
                          kBg);
    y += kRowH;

    duetos::net::firewall::Rule snap[duetos::net::firewall::kFwMaxRules];
    const u32 n = duetos::net::firewall::FwSnapshot(snap, duetos::net::firewall::kFwMaxRules);
    bool any = false;
    for (u32 i = 0; i < n && y + kRowH < cy + ch; ++i)
    {
        if (!snap[i].active)
        {
            continue;
        }
        any = true;
        pos = 0;
        if (i < 10)
        {
            line[pos++] = ' ';
        }
        AppendU(line, pos, sizeof(line), i);
        Append(line, pos, sizeof(line), "   ");
        Append(line, pos, sizeof(line), DirName(snap[i].dir));
        line[pos++] = ' ';
        Append(line, pos, sizeof(line), ProtoName(snap[i].proto));
        line[pos++] = ' ';
        const u32 src_start = pos;
        AppendIp(line, pos, sizeof(line), snap[i].src.addr, snap[i].src.mask_bits);
        while (pos - src_start < 18 && pos + 1 < sizeof(line))
        {
            line[pos++] = ' ';
        }
        line[pos++] = ' ';
        const u32 dst_start = pos;
        AppendIp(line, pos, sizeof(line), snap[i].dst.addr, snap[i].dst.mask_bits);
        while (pos - dst_start < 18 && pos + 1 < sizeof(line))
        {
            line[pos++] = ' ';
        }
        line[pos++] = ' ';
        const bool allow = snap[i].action == duetos::net::firewall::Action::Allow;
        Append(line, pos, sizeof(line), allow ? "ALLOW " : "DENY  ");
        line[pos++] = ' ';
        AppendU(line, pos, sizeof(line), snap[i].hits);
        line[pos] = '\0';
        FramebufferDrawString(cx + kMargin, y, line, allow ? kAllowFg : kDenyFg, kBg);
        y += kRowH;
    }
    if (!any)
    {
        FramebufferDrawString(cx + kMargin, y, "  (no active rules - only defaults apply)", kFgDim, kBg);
        y += kRowH;
    }

    // ---------- Active conntrack ----------
    y += kRowH / 2;
    if (y + kRowH < cy + ch)
    {
        FramebufferDrawString(cx + kMargin, y, "CONNTRACK (recent / active)", kHeaderFg, kBg);
        y += kRowH;
    }
    if (y + kRowH < cy + ch)
    {
        FramebufferDrawString(cx + kMargin, y, "PROTO STATE LOCAL                   PEER", kFgDim, kBg);
        y += kRowH;
    }
    duetos::net::firewall::ConntrackEntry ct[duetos::net::firewall::kConntrackCap];
    const u32 ct_n = duetos::net::firewall::ConntrackSnapshot(ct, duetos::net::firewall::kConntrackCap);
    if (ct_n == 0 && y + kRowH < cy + ch)
    {
        FramebufferDrawString(cx + kMargin, y, "  (no active conntrack entries)", kFgDim, kBg);
        y += kRowH;
    }
    // Show up to 4 most-recent entries; the kernel shell's
    // `firewall conntrack` is the full surface.
    const u32 ct_show = (ct_n < 4) ? ct_n : 4;
    for (u32 i = 0; i < ct_show && y + kRowH < cy + ch; ++i)
    {
        const auto& e = ct[i];
        pos = 0;
        Append(line, pos, sizeof(line), ProtoName(e.proto));
        line[pos++] = ' ';
        Append(line, pos, sizeof(line), duetos::net::firewall::TcpStateName(e.tcp_state));
        Append(line, pos, sizeof(line), "    ");
        const u32 lstart = pos;
        AppendIp(line, pos, sizeof(line), e.local_ip, 32);
        if (pos < sizeof(line) - 1)
        {
            line[pos++] = ':';
        }
        AppendU(line, pos, sizeof(line), e.local_port);
        while (pos - lstart < 21 && pos + 1 < sizeof(line))
        {
            line[pos++] = ' ';
        }
        line[pos++] = ' ';
        AppendIp(line, pos, sizeof(line), e.peer_ip, 32);
        if (pos < sizeof(line) - 1)
        {
            line[pos++] = ':';
        }
        AppendU(line, pos, sizeof(line), e.peer_port);
        line[pos] = '\0';
        FramebufferDrawString(cx + kMargin, y, line, kFg, kBg);
        y += kRowH;
    }

    // ---------- Recent denials ----------
    y += kRowH / 2;
    if (y + kRowH < cy + ch)
    {
        FramebufferDrawString(cx + kMargin, y, "RECENT DENIALS", kHeaderFg, kBg);
        y += kRowH;
    }
    duetos::net::firewall::DenialRecord dl[duetos::net::firewall::kFwLogCap];
    const u32 dl_n = duetos::net::firewall::FwLogSnapshot(dl, duetos::net::firewall::kFwLogCap);
    if (dl_n == 0 && y + kRowH < cy + ch)
    {
        FramebufferDrawString(cx + kMargin, y, "  (no denials recorded)", kFgDim, kBg);
        y += kRowH;
    }
    // Show the four most-recent denials (newest at the bottom).
    const u32 dl_show = (dl_n < 4) ? dl_n : 4;
    const u32 dl_start = dl_n - dl_show;
    for (u32 i = dl_start; i < dl_n && y + kRowH < cy + ch; ++i)
    {
        const auto& r = dl[i];
        pos = 0;
        Append(line, pos, sizeof(line), DirName(r.dir));
        line[pos++] = ' ';
        Append(line, pos, sizeof(line), ProtoName(r.proto));
        line[pos++] = ' ';
        AppendIp(line, pos, sizeof(line), r.src_ip, 32);
        if (pos < sizeof(line) - 1)
        {
            line[pos++] = ':';
        }
        AppendU(line, pos, sizeof(line), r.src_port);
        Append(line, pos, sizeof(line), " -> ");
        AppendIp(line, pos, sizeof(line), r.dst_ip, 32);
        if (pos < sizeof(line) - 1)
        {
            line[pos++] = ':';
        }
        AppendU(line, pos, sizeof(line), r.dst_port);
        line[pos] = '\0';
        FramebufferDrawString(cx + kMargin, y, line, kDenyFg, kBg);
        y += kRowH;
    }
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferFillRect;
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    // Pass D chrome: refresh the header / footer text from live
    // state (constant for firewall — no per-state variation),
    // re-anchor the toolbar / labels to the current client rect,
    // and paint the WidgetGroup. The raw firewall content (carve-
    // out) sits in the band between the header row and the
    // AppLabel footer.
    BindFirewallOnce();
    RefreshFirewallHeader();
    RefreshFirewallFooter();
    RebindFirewallBounds(cx, cy, cw, ch);

    Compose compose_ctx{};
    g_firewall.PaintAll(compose_ctx);

    // Content band — between (toolbar + header) at the top and
    // the AppLabel footer at the bottom.
    const u32 top_band = kFwToolbarH + kFwHeaderH;
    const u32 bot_band = kFwFooterH + kPad;
    const u32 list_x = cx;
    const u32 list_y = cy + top_band;
    const u32 list_w = cw;
    const u32 list_h = (ch > top_band + bot_band) ? (ch - top_band - bot_band) : 0;
    if (list_h > 0)
    {
        PaintFirewallContent(list_x, list_y, list_w, list_h);
    }
}

} // namespace

void FirewallInit(duetos::drivers::video::WindowHandle handle)
{
    g_handle = handle;
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
}

duetos::drivers::video::WindowHandle FirewallWindow()
{
    return g_handle;
}

void FirewallSelfTest()
{
    using arch::SerialWrite;
    bool ok = true;

    // Compute checks on the line composers the content band
    // depends on.
    char line[64];
    u32 pos = 0;
    Append(line, pos, sizeof(line), "DEFAULT IN=");
    Append(line, pos, sizeof(line), "ALLOW");
    line[pos] = '\0';
    ok = ok && line[0] == 'D' && line[8] == 'I' && line[11] == 'A';

    pos = 0;
    AppendU(line, pos, sizeof(line), 0u);
    AppendU(line, pos, sizeof(line), 12345u);
    line[pos] = '\0';
    ok = ok && line[0] == '0' && line[1] == '1' && line[2] == '2' && line[3] == '3' && line[4] == '4' && line[5] == '5';

    pos = 0;
    duetos::net::Ipv4Address ip{};
    ip.octets[0] = 192;
    ip.octets[1] = 168;
    ip.octets[2] = 1;
    ip.octets[3] = 7;
    AppendIp(line, pos, sizeof(line), ip, 24);
    line[pos] = '\0';
    // Expect "192.168.1.7/24"
    ok = ok && line[0] == '1' && line[1] == '9' && line[2] == '2' && line[3] == '.';
    ok = ok && line[pos - 3] == '/' && line[pos - 2] == '2' && line[pos - 1] == '4';

    // Direction / proto name table sanity.
    ok = ok && DirName(duetos::net::firewall::Direction::Ingress)[0] == 'I';
    ok = ok && DirName(duetos::net::firewall::Direction::Egress)[0] == 'O';
    ok = ok && ProtoName(duetos::net::firewall::Proto::Tcp)[0] == 'T';
    ok = ok && ProtoName(duetos::net::firewall::Proto::Udp)[0] == 'U';
    ok = ok && ProtoName(duetos::net::firewall::Proto::Icmp)[0] == 'I';
    ok = ok && ProtoName(duetos::net::firewall::Proto::Any)[0] == 'A';

    // Pass D: drive a synthetic click on the RFRSH toolbar button
    // via the WidgetGroup dispatch chain. ClickRefresh only calls
    // read-only firewall snapshot APIs + NotifyShow — it never
    // mutates the rule table, default policies, or conntrack
    // state, so this self-test is safe to run unconditionally at
    // boot.
    BindFirewallOnce();
    // Anchor the toolbar at (0, 22, 440, 218) — same shape
    // boot_bringup.cpp registers the live Firewall window with
    // (440x240 minus 22 px title bar). RFRSH is action index 0.
    RebindFirewallBounds(0U, 22U, 440U, 218U);
    constexpr u32 kRfrshIdx = 0U;
    const u32 nx = kFwToolbarPadX + kRfrshIdx * (kFwToolbarBtnW + kFwToolbarBtnGap) + kFwToolbarBtnW / 2U;
    const u32 ny = 22U + kFwToolbarPadY + kFwToolbarBtnH / 2U;
    const Event n_move{EventKind::MouseMove, nx, ny, 0U, 0U};
    const Event n_down{EventKind::MouseDown, nx, ny, 0U, 0U};
    const Event n_up{EventKind::MouseUp, nx, ny, 0U, 0U};

    // Capture the pre-click stats counters. RFRSH must NOT
    // mutate them — read-only snapshot reads only.
    const duetos::net::firewall::Stats stats_before = duetos::net::firewall::FwStatsRead();
    const u64 log_before = duetos::net::firewall::FwLogTotalCount();

    if (g_firewall.DispatchEvent(n_move) != EventResult::Consumed)
        ok = false;
    if (g_firewall.DispatchEvent(n_down) != EventResult::Consumed)
        ok = false;
    if (g_firewall.DispatchEvent(n_up) != EventResult::Consumed)
        ok = false;

    const duetos::net::firewall::Stats stats_after = duetos::net::firewall::FwStatsRead();
    const u64 log_after = duetos::net::firewall::FwLogTotalCount();
    // Read-only contract: RFRSH must not have touched any
    // mutable counter.
    if (stats_before.ingress_checked != stats_after.ingress_checked)
        ok = false;
    if (stats_before.ingress_denied != stats_after.ingress_denied)
        ok = false;
    if (stats_before.egress_checked != stats_after.egress_checked)
        ok = false;
    if (stats_before.egress_denied != stats_after.egress_denied)
        ok = false;
    if (log_before != log_after)
        ok = false;

    // Header / footer composers must produce non-empty text
    // after a refresh.
    RefreshFirewallHeader();
    if (g_header_text[0] == '\0')
        ok = false;
    RefreshFirewallFooter();
    if (g_footer_text[0] == '\0')
        ok = false;

    g_firewall_self_test_passed = ok;
    SerialWrite(ok ? "[firewall-selftest] PASS\n" : "[firewall-selftest] FAIL\n");
}

bool FirewallSelfTestPassed()
{
    return g_firewall_self_test_passed;
}

void FirewallMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_handle == duetos::drivers::video::kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it. The
    // WidgetGroup dispatch path needs cursor coords in the same
    // frame RebindFirewallBounds anchors the chrome to.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindFirewallOnce();
    RebindFirewallBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_firewall_prev_left_down;
    const bool release_edge = !left_down && g_firewall_prev_left_down;
    g_firewall_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_firewall.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        // Carve-out: the raw firewall content (defaults / stats /
        // rules / conntrack / denials) sits below the toolbar /
        // header rows the WidgetGroup owns. DispatchEvent's
        // hit-test naturally short-circuits when the click misses
        // the toolbar bounds — the content tables have no per-row
        // click semantics in v0 (selection / detail is not
        // implemented; rule editing is gated to the kernel shell
        // with kCapNetAdmin). MouseDown still fires for the
        // toolbar Pressed-state visual.
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_firewall.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside the
        // toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_firewall.DispatchEvent(u);
    }
}

} // namespace duetos::apps::firewall
