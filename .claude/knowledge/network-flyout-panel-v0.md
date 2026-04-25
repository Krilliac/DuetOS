# Network flyout panel v0 — bottom-right Wi-Fi-style popup

**Last updated:** 2026-04-25
**Type:** Observation + Decision
**Status:** Active

## Description

The bottom-right "click the Wi-Fi icon" flyout that every modern OS
ships. Anchors against the NET tray cell ("N" badge) on the
taskbar; opens in two modes:

1. **Preview** (hover): compact one-line status — IP + link
   state, no buttons. Auto-closes when the cursor leaves the
   tray cell + the panel.
2. **Full** (click): tall popup listing wireless adapters, the
   networks "scanned" (today: "no driver"), every wired adapter
   with its IP / gateway / DNS / lease, plus a **RENEW** button
   that kicks DHCP. Stays open until clicked outside or until the
   NET cell is clicked again.

Same paint chrome as the calendar popup — the popups look like
siblings.

## Wi-Fi driver-gap honesty

DuetOS has no wireless driver online. Building one (iwlwifi /
rtl88xx / bcm43xx) is a months-long firmware-and-PHY effort and
out of scope for this slice. Instead, the discovery layer is
honest:

- `drivers::net::NicIsWireless(index)` discriminates by PCI
  subclass 0x80 (the "other / wireless" subclass) plus family-
  string heuristics (`iwlwifi`, `rtl8821`, `rtl88`, `bcm43`,
  `bcm4331`).
- `drivers::net::WirelessStatusRead()` returns
  `{adapters_detected, drivers_online}`. Today `drivers_online`
  is hard-coded 0; landing an actual wireless driver bumps it.
- The flyout's WIRELESS section reads:
  - "no wireless adapter" if none detected
  - "N adapter(s) detected / no wireless driver online" otherwise

When an iwlwifi slice eventually lands, the same panel grows an
SSID list under the WIRELESS header without restructuring.

## Hover state machine

The mouse reader runs the state machine inside the existing
mouse-packet loop in `main.cpp`. Logic per packet:

| Cursor over NET cell? | Click? | Current mode | Action               |
|-----------------------|--------|--------------|----------------------|
| Yes                   | No     | Closed       | Open Preview         |
| Yes                   | Yes    | (any)        | Toggle Full          |
| No                    | No     | Preview      | Close (if not over panel) |
| No                    | Yes    | Full         | Close (click outside) |
| Yes (RENEW button)    | Yes    | Full         | Kick DHCP, keep open |

Full mode is sticky — hover-out doesn't close it. Only an
explicit click outside (or another click on the NET cell) closes
it. Matches the Windows / GNOME behaviour the user expects.

## Files touched

| File                                       | Role                                     |
|--------------------------------------------|------------------------------------------|
| `kernel/drivers/net/net.h`                 | `NicIsWireless` / `WirelessStatusRead` decls |
| `kernel/drivers/net/net.cpp`               | Implementation + family heuristics       |
| `kernel/drivers/video/taskbar.h`           | `TaskbarNetCellBounds` decl              |
| `kernel/drivers/video/taskbar.cpp`         | Bounds capture + amber/green tray colour |
| `kernel/drivers/video/netpanel.h` (new)    | Panel API (Open / Close / Redraw / hit-test) |
| `kernel/drivers/video/netpanel.cpp` (new)  | Preview + Full layouts; renders DHCP lease + per-NIC details |
| `kernel/drivers/video/widget.cpp`          | `NetPanelRedraw` added to DesktopCompose paint stack |
| `kernel/CMakeLists.txt`                    | netpanel.cpp added to shared sources     |
| `kernel/core/main.cpp`                     | Mouse-loop hover/click handlers          |

## NET tray cell colour code

The tray cell now reflects three states:
- **Green (`0x0040803C`)**: NIC up + DHCP lease bound (online).
- **Amber (`0x00C0A040`)**: NIC up but DHCP lease pending.
- **Grey (`0x00505058`)**: no NIC discovered.

This makes the boot transition from "amber" → "green" visible at
a glance once DHCP completes.

## Edge cases

- **Panel anchor clamp.** `NetPanelOpen` is called twice on the
  Full path — once with `(0,0)` to compute height, once with the
  final clamped anchor. Cheap and avoids exposing a separate
  `MeasureFullHeight` helper.
- **Click-outside doesn't eat the click.** Closing on click-
  outside intentionally does NOT set `menu_handled = true`, so
  the click can still pass through to a window underneath.
- **DesktopCompose paint order.** Panel painted AFTER the
  taskbar + calendar so it overlays them. Caret stays last so it
  blinks over everything.

## Future work

- Real wireless driver (iwlwifi or rtl88xx). Slot lands in
  `WirelessStatusRead().drivers_online` and the WIRELESS section
  grows an SSID list with signal-strength bars.
- "Connect to SSID" button (post-driver).
- Connection-history persistence across reboots (post-driver +
  post-disk-write story).
- Dark/light theme awareness — netpanel currently hard-codes the
  same palette as the calendar; piggy-backing the theme module's
  tokens would make this consistent across themes.

## Observable

```
(hover over the N cell on the bottom-right)
  ┌─────────────────────────────────┐
  │ ● CONNECTED                     │
  │   IP 10.0.2.15                  │
  │   click to expand               │
  └─────────────────────────────────┘

(click the cell, or click "click to expand")
  ┌──────────────────────────────────┐
  │ NETWORK                          │
  │                                  │
  │ ● CONNECTED                      │
  │   IP 10.0.2.15                   │
  │                                  │
  │ WIRELESS                         │
  │   no wireless adapter            │
  │   (use wired below)              │
  │                                  │
  │ WIRED                            │
  │   net0 Intel              UP     │
  │      ip  10.0.2.15               │
  │      gw  10.0.2.2                │
  │      dns 10.0.2.3                │
  │                                  │
  │ click outside to close [RENEW]   │
  └──────────────────────────────────┘
```
