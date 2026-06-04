#pragma once

#include "drivers/video/app_widgets/widget.h" // Rect
#include "util/types.h"

/*
 * DuetOS browser — TabStrip: the Chrome-style tab model + layout math +
 * hit-testing for the shell redesign (Phase 1). Real multi-tab (a live
 * render context per tab) is Phase 3; here a Tab stores url/title/scroll
 * and only the active tab's page is live at a time.
 *
 * Pure model + geometry — boot-self-tested, no rendering.
 */

namespace duetos::apps::browser
{
using duetos::drivers::video::app_widgets::Rect;

constexpr duetos::u32 kTabUrlCap = 256;
constexpr duetos::u32 kTabTitleCap = 64;
constexpr duetos::u32 kMaxTabs = 16;
constexpr duetos::u32 kTabMin = 120; // shrink floor; beyond this the strip clips (GAP: no scroll)
constexpr duetos::u32 kTabMax = 160;
constexpr duetos::u32 kNewBtnW = 26;
constexpr duetos::u32 kTabCloseW = 16;

// Identity accent (dual-accent DuetOS touch): teal = native, amber = doc.
enum class TabAccent : duetos::u8
{
    Native = 0,
    Doc = 1,
};

// GAP: live favicon fetch — until then the accent tints a placeholder chip.
struct Tab
{
    char url[kTabUrlCap] = {};
    char title[kTabTitleCap] = {};
    TabAccent accent = TabAccent::Native;
    duetos::i32 scrollY = 0;
    bool live = false; // is this tab's page currently rendered? (one at a time, Phase 1)
};

enum class TabHitKind : duetos::u8
{
    None = 0,
    Tab = 1,
    NewTab = 2,
    Close = 3,
};

struct TabHit
{
    TabHitKind kind = TabHitKind::None;
    duetos::u32 index = 0; // tab index for Tab/Close
};

struct TabStrip
{
    Tab tabs[kMaxTabs] = {};
    duetos::u32 count = 0;
    duetos::u32 active = 0;

    // Append a tab; becomes active. Returns the new index, or `count` (no-op)
    // when full. A null/empty url is allowed (a new-tab/start-page tab).
    duetos::u32 AddTab(const char* url, const char* title, TabAccent accent);
    // Close tab i; never drops below one tab (closing the last is a no-op).
    void CloseTab(duetos::u32 i);
    // Make tab i active (no-op if out of range).
    void Select(duetos::u32 i);

    // Per-tab width given the strip rect: shrink-to-fit between [kTabMin,kTabMax].
    duetos::u32 TabWidth(const Rect& strip) const;
    Rect TabRect(duetos::u32 i, const Rect& strip) const;
    Rect NewTabRect(const Rect& strip) const;
    Rect CloseRect(duetos::u32 i, const Rect& strip) const;
    TabHit HitTest(const Rect& strip, duetos::u32 cx, duetos::u32 cy) const;
};

void TabStripSelfTest();

} // namespace duetos::apps::browser
