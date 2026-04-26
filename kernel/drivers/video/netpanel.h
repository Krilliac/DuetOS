#pragma once

#include "util/types.h"

/*
 * Network flyout panel — v0.
 *
 * The bottom-right "Wi-Fi icon flyout" you'd recognise from
 * Windows / macOS / GNOME. Anchors against the NET tray cell on
 * the taskbar; opens in two modes:
 *
 *   1. Preview (hover): a compact one-line status — IP + link
 *      state, no buttons. Auto-closes when the cursor leaves the
 *      tray cell + the panel.
 *
 *   2. Full (click): a tall popup listing wireless adapters, the
 *      networks scanned (today: "no driver"), every wired
 *      adapter with its IP / gateway / DNS / lease, plus a
 *      "RENEW" button that kicks DHCP. Stays open until clicked
 *      outside or until the NET cell is clicked again.
 *
 * Same paint chrome as the calendar popup (sibling-look). The
 * mouse reader is responsible for the open/close state machine —
 * this module just paints the panel, hit-tests its rect, and
 * dispatches a click on the RENEW button.
 *
 * Context: kernel. Redraw from DesktopCompose after the taskbar.
 * Toggle from the mouse reader on hover/click of the NET cell.
 */

namespace duetos::drivers::video
{

enum class NetPanelMode : u8
{
    Closed = 0,
    Preview = 1,
    Full = 2,
};

/// Open the panel in the requested mode anchored with `ax, ay` as
/// the upper-left corner. Re-opening with a new mode is allowed
/// (preview → full when the user clicks while the preview is up).
void NetPanelOpen(u32 ax, u32 ay, NetPanelMode mode);

/// Close the panel. Idempotent.
void NetPanelClose();

/// Currently-open mode (or NetPanelMode::Closed).
NetPanelMode NetPanelCurrentMode();

bool NetPanelIsOpen();

/// Render the panel if open. Safe any time. Re-reads NIC + DHCP
/// state every call so a fresh DHCP ACK or lease change shows up
/// on the next compose.
void NetPanelRedraw();

/// Hit-test the panel's rect (whole-popup, including chrome).
bool NetPanelContains(u32 x, u32 y);

/// Hit-test the RENEW button specifically. Only meaningful when
/// the panel is in Full mode; returns false otherwise. The mouse
/// reader passes a press event here BEFORE the generic click-
/// outside-to-close path so a press on the button doesn't dismiss.
bool NetPanelRenewButtonContains(u32 x, u32 y);

/// Called by the mouse reader when the user clicks RENEW. Kicks a
/// fresh DHCP DISCOVER on iface 0; safe no-op if no iface is
/// bound. Returns true iff DHCP was successfully started.
bool NetPanelDoRenew();

/// Width / height of the panel in its current mode. Layout is
/// fixed per mode; callers use these to anchor the popup so its
/// bottom edge sits flush against the taskbar's top.
u32 NetPanelWidth();
u32 NetPanelHeight();

} // namespace duetos::drivers::video
