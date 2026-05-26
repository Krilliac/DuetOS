#include "apps/devicemgr.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/pci/pci.h"
#include "drivers/usb/usb.h"
#include "drivers/usb/xhci.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_toolbar.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/notify.h"
#include "drivers/video/theme.h"

namespace duetos::apps::devicemgr
{

namespace
{

using duetos::drivers::video::FramebufferDrawString;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kRowH = 12;
constexpr u32 kMargin = 12;
constexpr u32 kPad = 4;
constexpr u32 kFg = 0x00C8D0DA;
constexpr u32 kFgDim = 0x00808890;
constexpr u32 kSection = 0x00FFD040;
constexpr u32 kBg = 0x00101820;

constinit WindowHandle g_handle = kWindowInvalid;

void HexN(char* out, u32 v, u32 nibbles)
{
    static const char kHex[] = "0123456789ABCDEF";
    for (u32 i = 0; i < nibbles; ++i)
    {
        out[nibbles - 1 - i] = kHex[v & 0xF];
        v >>= 4;
    }
}

// Brief class-code labels for the most common PCI base classes.
// Anything else falls through to "OTHER".
const char* ClassLabel(u8 base, u8 sub)
{
    switch (base)
    {
    case 0x00:
        return "UNCLASS";
    case 0x01:
        switch (sub)
        {
        case 0x06:
            return "AHCI";
        case 0x08:
            return "NVME";
        default:
            return "STORAGE";
        }
    case 0x02:
        return "NET";
    case 0x03:
        return "DISPLAY";
    case 0x04:
        return "MULTIMEDIA";
    case 0x05:
        return "MEMORY";
    case 0x06:
        return "BRIDGE";
    case 0x07:
        return "COMM";
    case 0x08:
        return "SYS";
    case 0x09:
        return "INPUT";
    case 0x0C:
        return (sub == 0x03) ? "USB" : "SERBUS";
    default:
        return "OTHER";
    }
}

// Translate a USB device class byte to a short label. Codes
// per USB.org Class Code Reference. 0x00 indicates the device
// defers class declaration to the interface descriptor, which
// the v0 enumerator records on the configuration descriptor
// path (PortRecord.hid_keyboard / hid_mouse). Anything we
// don't recognise prints the raw hex via the caller's fallback.
const char* UsbClassLabel(u8 cls)
{
    switch (cls)
    {
    case 0x00:
        return "PER-IFACE";
    case 0x01:
        return "AUDIO";
    case 0x02:
        return "CDC";
    case 0x03:
        return "HID";
    case 0x05:
        return "PHYS";
    case 0x06:
        return "IMAGE";
    case 0x07:
        return "PRINT";
    case 0x08:
        return "MSC";
    case 0x09:
        return "HUB";
    case 0x0A:
        return "CDC-DATA";
    case 0x0B:
        return "SMARTCARD";
    case 0x0E:
        return "VIDEO";
    case 0x0F:
        return "PHDC";
    case 0xDC:
        return "DIAG";
    case 0xE0:
        return "WIRELESS";
    case 0xEF:
        return "MISC";
    case 0xFE:
        return "APPLIC";
    case 0xFF:
        return "VENDOR";
    default:
        return "OTHER";
    }
}

// Decode the 4-bit PORTSC speed indicator into a short label
// matching xHCI 1.1 §5.4.8. "?" for the unknown / power-off
// states the v0 enumerator never sets.
const char* UsbSpeedLabel(u8 speed)
{
    switch (speed)
    {
    case 1:
        return "FS";
    case 2:
        return "LS";
    case 3:
        return "HS";
    case 4:
        return "SS";
    case 5:
        return "SS+";
    default:
        return "?";
    }
}

void DrawPciSection(u32 cx, u32& y, u32 cy, u32 ch)
{
    FramebufferDrawString(cx + kMargin, y, "PCI DEVICES", kSection, kBg);
    y += kRowH + 4;
    FramebufferDrawString(cx + kMargin, y, "BUS:DV.F  VEND:DEV   CLASS", kFgDim, kBg);
    y += kRowH;

    const u64 n = duetos::drivers::pci::PciDeviceCount();
    if (n == 0)
    {
        FramebufferDrawString(cx + kMargin, y, "  (NO DEVICES — PCI ENUMERATION DID NOT RUN)", kFgDim, kBg);
        y += kRowH;
        return;
    }

    for (u64 i = 0; i < n && y + kRowH < cy + ch; ++i)
    {
        const auto& d = duetos::drivers::pci::PciDevice(i);

        char line[64];
        u32 o = 0;
        HexN(line + o, d.addr.bus, 2);
        o += 2;
        line[o++] = ':';
        HexN(line + o, d.addr.device, 2);
        o += 2;
        line[o++] = '.';
        line[o++] = static_cast<char>('0' + (d.addr.function & 0x7));
        line[o++] = ' ';
        line[o++] = ' ';

        HexN(line + o, d.vendor_id, 4);
        o += 4;
        line[o++] = ':';
        HexN(line + o, d.device_id, 4);
        o += 4;
        line[o++] = ' ';
        line[o++] = ' ';
        line[o++] = ' ';

        const char* cls = ClassLabel(d.class_code, d.subclass);
        u32 c = 0;
        while (cls[c] != '\0' && o < sizeof(line) - 1)
            line[o++] = cls[c++];
        line[o] = '\0';

        FramebufferDrawString(cx + kMargin, y, line, kFg, kBg);
        y += kRowH;
    }
}

void DrawUsbSection(u32 cx, u32& y, u32 cy, u32 ch)
{
    if (y + kRowH >= cy + ch)
    {
        return;
    }
    y += kRowH / 2;
    FramebufferDrawString(cx + kMargin, y, "USB DEVICES", kSection, kBg);
    y += kRowH + 4;
    FramebufferDrawString(cx + kMargin, y, "CTL PORT  VID:PID    SPEED CLASS    HID", kFgDim, kBg);
    y += kRowH;

    const u32 hc = duetos::drivers::usb::xhci::XhciCount();
    if (hc == 0)
    {
        FramebufferDrawString(cx + kMargin, y, "  (NO USB HOST CONTROLLERS)", kFgDim, kBg);
        y += kRowH;
        return;
    }

    bool any_attached = false;
    for (u32 c = 0; c < hc && y + kRowH < cy + ch; ++c)
    {
        const auto* ci = duetos::drivers::usb::xhci::XhciControllerAt(c);
        if (ci == nullptr)
        {
            continue;
        }
        for (u32 p = 0; p < duetos::drivers::usb::xhci::kMaxXhciPortsPerController && y + kRowH < cy + ch; ++p)
        {
            const auto& port = ci->ports[p];
            if (!port.connected)
            {
                continue;
            }
            any_attached = true;

            char line[80];
            u32 o = 0;
            line[o++] = static_cast<char>('0' + (c & 0x7));
            line[o++] = ' ';
            line[o++] = ' ';
            line[o++] = static_cast<char>('0' + ((port.port_num / 10) % 10));
            line[o++] = static_cast<char>('0' + (port.port_num % 10));
            line[o++] = ' ';
            line[o++] = ' ';

            if (port.descriptor_ok)
            {
                HexN(line + o, port.vendor_id, 4);
                o += 4;
                line[o++] = ':';
                HexN(line + o, port.product_id, 4);
                o += 4;
            }
            else
            {
                const char* na = "----:----";
                for (u32 i = 0; na[i] != '\0'; ++i)
                {
                    line[o++] = na[i];
                }
            }
            line[o++] = ' ';
            line[o++] = ' ';

            const char* spd = UsbSpeedLabel(port.speed);
            for (u32 i = 0; spd[i] != '\0'; ++i)
            {
                line[o++] = spd[i];
            }
            while (o < 28 && o < sizeof(line) - 1)
            {
                line[o++] = ' ';
            }

            const char* cls = UsbClassLabel(port.device_class);
            for (u32 i = 0; cls[i] != '\0' && o < sizeof(line) - 1; ++i)
            {
                line[o++] = cls[i];
            }
            while (o < 37 && o < sizeof(line) - 1)
            {
                line[o++] = ' ';
            }

            const char* hid_label = "";
            if (port.hid_keyboard)
            {
                hid_label = "KBD";
            }
            else if (port.hid_mouse)
            {
                hid_label = "MOUSE";
            }
            for (u32 i = 0; hid_label[i] != '\0' && o < sizeof(line) - 1; ++i)
            {
                line[o++] = hid_label[i];
            }
            line[o] = '\0';

            FramebufferDrawString(cx + kMargin, y, line, kFg, kBg);
            y += kRowH;
        }
    }
    if (!any_attached && y + kRowH < cy + ch)
    {
        FramebufferDrawString(cx + kMargin, y, "  (NO USB DEVICES ATTACHED)", kFgDim, kBg);
        y += kRowH;
    }
}

// ---------------------------------------------------------------
// Pass D chrome: AppToolbar (back) + 1 AppButton (RSCN) + 2
// AppLabels (header "DEVICE MANAGER", footer controls hint). The
// toolbar duplicates the only available action (re-walk the PCI
// bus + XHCI ports) so a fresh user has a discoverable trigger
// without memorising any keyboard shortcut.
//
// Carve-out that stays raw paint:
//   - PCI device list: variable-length tabular block led by a
//     "PCI DEVICES" section heading and a column-header subline
//     ("BUS:DV.F VEND:DEV CLASS"), then one row per cached
//     PciDevice. Empty-state path is its own dim-text line.
//   - USB device list: parallel block ("USB DEVICES" heading +
//     "CTL PORT VID:PID SPEED CLASS HID" subline), then one row
//     per connected XHCI port. Two empty-state lines (no
//     controllers, no devices attached).
//   AppListRow has no multi-column / section-header / dim-column-
//   subline model and would lose the fixed-width tabular
//   alignment + section grouping. AppPanel / AppLabel have no
//   per-row model at all. The lists paint inside the band DrawFn
//   carves out between the (toolbar + header) at the top and the
//   AppLabel footer at the bottom.

constexpr u32 kDmToolbarH = 22U;
constexpr u32 kDmToolbarBtnW = 52U;
constexpr u32 kDmToolbarBtnH = 18U;
constexpr u32 kDmToolbarBtnGap = 4U;
constexpr u32 kDmToolbarPadX = 4U;
constexpr u32 kDmToolbarPadY = 2U;
constexpr u32 kDmActionBtnCount = 1U;
constexpr u32 kDmHeaderH = kRowH + 6U; // matches legacy header drop
constexpr u32 kDmFooterH = kRowH;

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
constinit char g_header_text[40] = {};
constinit char g_footer_text[64] = {};

// Forward decl for the toolbar click trampoline (defined below;
// it has to live above the constinit g_devicemgr that captures it
// by function-pointer value).
void ClickRescan();

// Toolbar (back), then 1 action AppButton, then 2 AppLabels
// (header, footer). Reverse declaration order is dispatch order
// — buttons get first refusal on clicks.
constinit auto g_devicemgr = MakeWidgetGroup(AppToolbar{}, AppButton{}, AppLabel{}, AppLabel{});

constinit bool g_devicemgr_bound = false;
constinit bool g_devicemgr_prev_left_down = false;
constinit bool g_devicemgr_self_test_passed = false;

// Walk the recursive WidgetChain by hand to grab a stable
// pointer to the action button. Chain order mirrors the
// MakeWidgetGroup argument list (toolbar -> 1 button -> 2
// labels).
AppButton* DmActionButton()
{
    return &g_devicemgr.chain.tail.head; // toolbar -> btn[0]
}

// AppLabel accessors — header / footer sit at chain positions
// 2, 3 (zero-indexed) after the 1 toolbar + 1 button.
AppLabel& DmHeaderLabel()
{
    return g_devicemgr.chain.tail.tail.head;
}
AppLabel& DmFooterLabel()
{
    return g_devicemgr.chain.tail.tail.tail.head;
}

void BindDevicemgrOnce()
{
    if (g_devicemgr_bound)
        return;
    g_devicemgr_bound = true;

    auto& toolbar = g_devicemgr.chain.head;
    toolbar.bg_rgb = 0; // theme.taskbar_bg

    AppButton* btn = DmActionButton();
    btn->label = "RSCN";
    btn->on_click = ClickRescan;
    btn->weight = ChromeTextWeight::Regular;
    btn->bg_rgb = 0; // theme role default
    btn->fg_rgb = 0x00101828U;

    const auto& th = ThemeCurrent();
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;

    auto& header = DmHeaderLabel();
    header.text = g_header_text;
    header.role = ChromeTextRole::Body;
    header.weight = ChromeTextWeight::Bold;
    header.fg_rgb = fg;
    header.bg_rgb = kBg;
    header.align_left = true;

    auto& footer = DmFooterLabel();
    footer.text = g_footer_text;
    footer.role = ChromeTextRole::Caption;
    footer.weight = ChromeTextWeight::Regular;
    footer.fg_rgb = dim;
    footer.bg_rgb = kBg;
    footer.align_left = true;
}

// Re-anchor the toolbar + button + labels to the live client
// rect. Called from DrawFn before PaintAll and from
// DeviceMgrMouseInput before DispatchEvent so hit-tests + visuals
// stay consistent across window moves / resizes.
void RebindDevicemgrBounds(u32 cx, u32 cy, u32 cw, u32 ch)
{
    auto& toolbar = g_devicemgr.chain.head;
    toolbar.bounds = Rect{cx, cy, cw, kDmToolbarH};

    {
        constexpr u32 i = 0U;
        const u32 bx = cx + kDmToolbarPadX + i * (kDmToolbarBtnW + kDmToolbarBtnGap);
        DmActionButton()->bounds = Rect{bx, cy + kDmToolbarPadY, kDmToolbarBtnW, kDmToolbarBtnH};
    }

    // Header sits directly below the toolbar. Spans the client
    // width with kMargin x-pad to match the legacy raw-paint
    // x-offset ("cx + kMargin").
    const u32 header_y = cy + kDmToolbarH;
    const u32 header_x_pad = kMargin;
    DmHeaderLabel().bounds =
        Rect{cx + header_x_pad, header_y, (cw > header_x_pad) ? cw - header_x_pad : cw, kDmHeaderH};

    // Footer hint band along the bottom of the client area.
    const u32 fy = (ch > kDmFooterH) ? cy + ch - kDmFooterH : cy;
    const u32 fw = (cw > kPad) ? cw - kPad : cw;
    DmFooterLabel().bounds = Rect{cx + kPad, fy, fw, kDmFooterH};
}

void RefreshDevicemgrHeader()
{
    static const char kHeader[] = "DEVICE MANAGER";
    u32 i = 0;
    for (; kHeader[i] != '\0' && i + 1 < sizeof(g_header_text); ++i)
        g_header_text[i] = kHeader[i];
    g_header_text[i] = '\0';
}

void RefreshDevicemgrFooter()
{
    static const char kHint[] = "RSCN=RESCAN PCI + USB  (READ-ONLY)";
    u32 i = 0;
    for (; kHint[i] != '\0' && i + 1 < sizeof(g_footer_text); ++i)
        g_footer_text[i] = kHint[i];
    g_footer_text[i] = '\0';
}

// ----- Pass D click trampoline ---------------------------------
// AppButton::on_click is a plain `void (*)()` so the constinit
// g_devicemgr above captures it by function-pointer value. RSCN
// tears down the cached PCI device list + ECAM aperture, then
// re-walks the bus so the in-window list reflects any hot-plug
// state since boot. XHCI port records are refreshed on the next
// XhciControllerAt() read so no explicit re-probe is needed.

void ClickRescan()
{
    duetos::drivers::pci::PciTeardown();
    duetos::drivers::pci::PciEnumerate();
    duetos::drivers::video::NotifyShow("devicemgr: rescanned");
}

// Paint the raw PCI + USB section list inside the band DrawFn
// carves out between the (toolbar + header) at the top and the
// AppLabel footer at the bottom. The two sections share a single
// running `y` cursor so the USB block flows directly under the
// PCI block.
void PaintDeviceLists(u32 cx, u32 cy, u32 cw, u32 ch)
{
    (void)cw;
    FramebufferFillRect(cx, cy, cw, ch, kBg);
    u32 y = cy;
    DrawPciSection(cx, y, cy, ch);
    DrawUsbSection(cx, y, cy, ch);
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    FramebufferFillRect(cx, cy, cw, ch, kBg);

    // Pass D chrome: refresh the header / footer text from live
    // state (constant for devicemgr — no per-state variation),
    // re-anchor the toolbar / labels to the current client rect,
    // and paint the WidgetGroup. The raw PCI + USB list (carve-
    // out) sits in the band between the header row and the
    // AppLabel footer.
    BindDevicemgrOnce();
    RefreshDevicemgrHeader();
    RefreshDevicemgrFooter();
    RebindDevicemgrBounds(cx, cy, cw, ch);

    Compose compose_ctx{};
    g_devicemgr.PaintAll(compose_ctx);

    // List band — between (toolbar + header) at the top and the
    // AppLabel footer at the bottom.
    const u32 top_band = kDmToolbarH + kDmHeaderH;
    const u32 bot_band = kDmFooterH + kPad;
    const u32 list_x = cx;
    const u32 list_y = cy + top_band;
    const u32 list_w = cw;
    const u32 list_h = (ch > top_band + bot_band) ? (ch - top_band - bot_band) : 0;
    if (list_h > 0)
    {
        PaintDeviceLists(list_x, list_y, list_w, list_h);
    }
}

} // namespace

void DeviceMgrInit(WindowHandle handle)
{
    g_handle = handle;
    WindowSetContentDraw(handle, DrawFn, nullptr);
}

WindowHandle DeviceMgrWindow()
{
    return g_handle;
}

void DeviceMgrSelfTest()
{
    using arch::SerialWrite;
    bool ok = true;

    // Legacy compute check: HexN round-trip on the formatter the
    // PCI rows depend on (bus:dev.fn + vend:dev hex).
    char hex[5] = {};
    HexN(hex, 0xABCD, 4);
    ok = ok && hex[0] == 'A' && hex[1] == 'B' && hex[2] == 'C' && hex[3] == 'D';
    HexN(hex, 0x07, 2);
    ok = ok && hex[0] == '0' && hex[1] == '7';

    // Class-label lookup table sanity — verify the most common
    // PCI base classes resolve to non-empty stable labels.
    ok = ok && ClassLabel(0x01, 0x06)[0] == 'A';      // AHCI
    ok = ok && ClassLabel(0x01, 0x08)[0] == 'N';      // NVME
    ok = ok && ClassLabel(0x02, 0x00)[0] == 'N';      // NET
    ok = ok && ClassLabel(0x0C, 0x03)[0] == 'U';      // USB
    ok = ok && UsbSpeedLabel(3)[0] == 'H';            // HS
    ok = ok && UsbClassLabel(0x03)[0] == 'H';         // HID

    // PCI device-count walk: every cached PciDevice(idx) is
    // dereferenceable up to PciDeviceCount(). This mirrors the
    // legacy v0 self-test contract. The count may legitimately
    // be 0 — BootBringupDesktop runs BEFORE BootBringupDevices in
    // main.cpp's bring-up sequence, so PciEnumerate has not run
    // yet when this self-test fires. The synthetic RSCN click
    // below is the v0 path's first enumeration trigger.
    const u64 n = duetos::drivers::pci::PciDeviceCount();
    for (u64 i = 0; i < n; ++i)
    {
        const auto& d = duetos::drivers::pci::PciDevice(i);
        // vendor_id == 0xFFFF would indicate an empty slot the
        // enumerator should have skipped — treat it as a probe
        // failure.
        if (d.vendor_id == 0xFFFF)
            ok = false;
    }

    // Pass D: drive a synthetic click on the RSCN toolbar button
    // via the WidgetGroup dispatch chain. ClickRescan calls
    // PciTeardown + PciEnumerate; the test verifies the dispatch
    // path is wired end-to-end. PCI re-enumeration is idempotent
    // (same bus walk runs at boot), so the device count is stable
    // across the synthetic click.
    BindDevicemgrOnce();
    // Anchor the toolbar at (0, 22, 460, 298) — same shape
    // boot_bringup.cpp registers the live Device Manager window
    // with (460x320 minus 22 px title bar). RSCN is action index 0.
    RebindDevicemgrBounds(0U, 22U, 460U, 298U);
    constexpr u32 kRscnIdx = 0U;
    const u32 nx = kDmToolbarPadX + kRscnIdx * (kDmToolbarBtnW + kDmToolbarBtnGap) + kDmToolbarBtnW / 2U;
    const u32 ny = 22U + kDmToolbarPadY + kDmToolbarBtnH / 2U;
    const Event n_move{EventKind::MouseMove, nx, ny, 0U, 0U};
    const Event n_down{EventKind::MouseDown, nx, ny, 0U, 0U};
    const Event n_up{EventKind::MouseUp, nx, ny, 0U, 0U};
    if (g_devicemgr.DispatchEvent(n_move) != EventResult::Consumed)
        ok = false;
    if (g_devicemgr.DispatchEvent(n_down) != EventResult::Consumed)
        ok = false;
    if (g_devicemgr.DispatchEvent(n_up) != EventResult::Consumed)
        ok = false;
    // ClickRescan ran PciTeardown + PciEnumerate; n_after may be
    // 0 (no PCI hardware) or some positive number (QEMU's 12,
    // a real box's actual count). We do NOT assert n_after == n
    // because BootBringupDesktop runs BEFORE BootBringupDevices'
    // PciEnumerate — the click is the path's FIRST enumeration
    // trigger, so n is typically 0 here while n_after is >= 0.
    // Empty-slot probe failure is still flagged below.
    const u64 n_after = duetos::drivers::pci::PciDeviceCount();
    for (u64 i = 0; i < n_after; ++i)
    {
        const auto& d = duetos::drivers::pci::PciDevice(i);
        if (d.vendor_id == 0xFFFF)
            ok = false;
    }

    // Header / footer composers must produce non-empty text
    // after a refresh.
    RefreshDevicemgrHeader();
    if (g_header_text[0] == '\0')
        ok = false;
    RefreshDevicemgrFooter();
    if (g_footer_text[0] == '\0')
        ok = false;

    g_devicemgr_self_test_passed = ok;

    // Report the post-click count — n was likely 0 (see comment
    // above), but n_after reflects the rescan result and matches
    // the live-window PCI list.
    SerialWrite("[apps/devicemgr] selftest: pci_count=");
    char buf[8];
    u32 v = static_cast<u32>(n_after);
    u32 o = 0;
    if (v == 0)
        buf[o++] = '0';
    else
    {
        char tmp[8];
        u32 t = 0;
        while (v != 0)
        {
            tmp[t++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (t != 0)
            buf[o++] = tmp[--t];
    }
    buf[o] = '\0';
    SerialWrite(buf);
    SerialWrite(ok ? " OK\n" : " FAIL\n");
    SerialWrite(ok ? "[devicemgr-selftest] PASS\n" : "[devicemgr-selftest] FAIL\n");
}

bool DeviceMgrSelfTestPassed()
{
    return g_devicemgr_self_test_passed;
}

void DeviceMgrMouseInput(duetos::u32 cx, duetos::u32 cy, duetos::u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_handle == kWindowInvalid)
        return;
    duetos::u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_handle, &wx, &wy, &ww, &wh))
        return;
    // Title bar is 22 px; client origin sits below it. The
    // WidgetGroup dispatch path needs cursor coords in the same
    // frame RebindDevicemgrBounds anchors the chrome to.
    constexpr duetos::u32 kTitleH = 22U;
    if (wh <= kTitleH)
        return;
    const duetos::u32 client_y = wy + kTitleH;
    const duetos::u32 client_h = wh - kTitleH;
    BindDevicemgrOnce();
    RebindDevicemgrBounds(wx, client_y, ww, client_h);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_devicemgr_prev_left_down;
    const bool release_edge = !left_down && g_devicemgr_prev_left_down;
    g_devicemgr_prev_left_down = left_down;

    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= client_y && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, cx, cy, 0U, 0U};
        g_devicemgr.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        // Carve-out: the raw PCI + USB list sits below the
        // toolbar / header rows the WidgetGroup owns. The
        // DispatchEvent path's hit-test naturally short-circuits
        // when the click misses the toolbar bounds — the device
        // list has no per-row click semantics in v0 (selection /
        // detail is not implemented). MouseDown still fires for
        // the toolbar Pressed-state visual.
        const Event d{EventKind::MouseDown, cx, cy, 0U, 0U};
        g_devicemgr.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always dispatch MouseUp so a button pressed inside the
        // toolbar and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, cx, cy, 0U, 0U};
        g_devicemgr.DispatchEvent(u);
    }
}

} // namespace duetos::apps::devicemgr
