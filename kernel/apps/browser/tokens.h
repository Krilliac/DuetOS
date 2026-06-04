#pragma once

#include "util/types.h"

/*
 * DuetOS browser — shell design tokens (the "DuetOS touch"). The motif
 * set the redesign applies across the new chrome: corner radii, soft-
 * shadow elevation tiers, and the dual-accent identity colours. See
 * docs/superpowers/specs/2026-06-04-browser-ui-redesign-design.md §5.
 *
 * Colours are 0x00RRGGBB (the framebuffer's packed format).
 */

namespace duetos::apps::browser::tokens
{
using duetos::u32;

// Corner radii (FramebufferFillRoundRect).
constexpr u32 kRadPill = 13;  // omnibox, Ask AI, citation chips
constexpr u32 kRadTab = 7;    // tab top corners
constexpr u32 kRadPanel = 10; // dock surfaces, cards
constexpr u32 kRadTile = 13;  // start-page tiles
constexpr u32 kRadBtn = 6;    // toolbar buttons

// Soft-shadow elevation tiers (RenderSoftShadow radius).
constexpr u32 kShadowChrome = 8; // tab strip / toolbar
constexpr u32 kShadowCard = 10;  // tiles / cards
constexpr u32 kShadowFloat = 16; // a floating dock surface (elevated)

// Dual-accent identity + danger.
constexpr u32 kAccentTeal = 0x002DD4BF;   // interactive · AI · native · focus · CTA
constexpr u32 kAccentAmber = 0x00E0A33A;  // secondary identity (docs/bookmarks) — never a CTA
constexpr u32 kAccentDanger = 0x00E0564A; // Privileged-Origin armed state (Phase 2)

// Neutrals (dark Duet — the default theme).
constexpr u32 kCanvas = 0x000B0E13;
constexpr u32 kPanel = 0x00141A22;
constexpr u32 kPanelHi = 0x001A212A;
constexpr u32 kBorder = 0x002B3440;
constexpr u32 kInk = 0x00C2CCD6;
constexpr u32 kInkMute = 0x009AA6B2;
constexpr u32 kInkDim = 0x006B7682;

} // namespace duetos::apps::browser::tokens
