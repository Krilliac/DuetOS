#pragma once

#include "drivers/video/app_widgets/widget.h" // Rect
#include "util/types.h"

/*
 * DuetOS browser — Omnibox: the unified URL/search field + the toolbar
 * control geometry (nav buttons, the pill, the ✦ Ask AI button, the
 * Library button, the overflow menu). Shell redesign Phase 1.
 *
 * Pure state + geometry — boot-self-tested, no rendering.
 */

namespace duetos::apps::browser
{
using duetos::drivers::video::app_widgets::Rect;

constexpr duetos::u32 kOmniCap = 256;

// Toolbar control metrics.
constexpr duetos::u32 kOmniNavW = 24;
constexpr duetos::u32 kOmniNavCount = 3; // back / forward / reload
constexpr duetos::u32 kOmniAskW = 72;    // "✦ Ask AI"
constexpr duetos::u32 kOmniLibW = 24;    // ▤ library
constexpr duetos::u32 kOmniMenuW = 24;   // ⋮ overflow
constexpr duetos::u32 kOmniGap = 7;
constexpr duetos::u32 kOmniPad = 9;

enum class OmniHitKind : duetos::u8
{
    None = 0,
    Nav = 1, // navIndex: 0=back 1=fwd 2=reload
    Pill = 2,
    Ask = 3,
    Library = 4,
    Menu = 5,
};

struct OmniHit
{
    OmniHitKind kind = OmniHitKind::None;
    duetos::u32 navIndex = 0;
};

struct Omnibox
{
    char text[kOmniCap] = {};
    duetos::u32 len = 0;
    duetos::u32 caret = 0;
    bool editing = false;

    void BeginEdit();
    void EndEdit();
    void SetText(const char* s);
    void InsertChar(char c);
    void Backspace();

    // Geometry (given the toolbar rect).
    Rect NavRect(duetos::u32 i, const Rect& toolbar) const; // i in [0,kOmniNavCount)
    Rect PillRect(const Rect& toolbar) const;
    Rect AskRect(const Rect& toolbar) const;
    Rect LibraryRect(const Rect& toolbar) const;
    Rect MenuRect(const Rect& toolbar) const;
    OmniHit HitTest(const Rect& toolbar, duetos::u32 cx, duetos::u32 cy) const;
};

void OmniboxSelfTest();

} // namespace duetos::apps::browser
