#pragma once

#include "drivers/video/app_widgets/widget.h" // Rect
#include "util/types.h"

/*
 * DuetOS browser — StartPage: the new-tab command-center model (wordmark,
 * the centered Ask/URL prompt, dual-accent shortcut tiles). Shell redesign
 * Phase 1. Pure layout model — boot-self-tested; rendering is wired in the
 * chrome-integration task.
 */

namespace duetos::apps::browser
{
using duetos::drivers::video::app_widgets::Rect;

constexpr duetos::u32 kStartUrlCap = 256;
constexpr duetos::u32 kStartLabelCap = 24;
constexpr duetos::u32 kMaxTiles = 8;
constexpr duetos::u32 kTileW = 58;
constexpr duetos::u32 kTileH = 58;
constexpr duetos::u32 kTileGap = 11;

struct StartTile
{
    char label[kStartLabelCap] = {};
    char url[kStartUrlCap] = {};
    duetos::u32 accent = 0; // 0x00RRGGBB tint
};

enum class StartHitKind : duetos::u8
{
    None = 0,
    Prompt = 1,
    Tile = 2,
};

struct StartHit
{
    StartHitKind kind = StartHitKind::None;
    duetos::u32 index = 0;
};

struct StartPage
{
    StartTile tiles[kMaxTiles] = {};
    duetos::u32 tileCount = 0;

    // Seed the default shortcut row (Home / Docs / GitHub / Wiki / + Pin).
    void InitDefault();

    Rect WordmarkRect(const Rect& content) const;
    Rect PromptRect(const Rect& content) const;
    Rect TileRect(duetos::u32 i, const Rect& content) const;
    StartHit HitTest(const Rect& content, duetos::u32 cx, duetos::u32 cy) const;
};

void StartPageSelfTest();

} // namespace duetos::apps::browser
