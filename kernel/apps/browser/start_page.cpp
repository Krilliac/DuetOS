#include "apps/browser/start_page.h"

#include "apps/browser/tokens.h"

namespace duetos::apps::browser
{
using duetos::u32;

namespace
{
void CopyZ(char* dst, u32 cap, const char* src)
{
    u32 i = 0;
    for (; src[i] != '\0' && i + 1 < cap; ++i)
        dst[i] = src[i];
    dst[i] = '\0';
}

void AddTile(StartPage& p, const char* label, const char* url, u32 accent)
{
    if (p.tileCount >= kMaxTiles)
        return;
    StartTile& t = p.tiles[p.tileCount];
    CopyZ(t.label, kStartLabelCap, label);
    CopyZ(t.url, kStartUrlCap, url);
    t.accent = accent;
    ++p.tileCount;
}
} // namespace

void StartPage::InitDefault()
{
    tileCount = 0;
    AddTile(*this, "Home", "https://duetos.dev", tokens::kAccentTeal);
    AddTile(*this, "Docs", "https://duetos.dev/docs", tokens::kAccentAmber);
    AddTile(*this, "GitHub", "https://github.com/Krilliac/DuetOS", 0x005B8DEF);
    AddTile(*this, "Wiki", "https://duetos.dev/wiki", 0x002F9E78);
    AddTile(*this, "+ Pin", "", tokens::kInkDim);
}

Rect StartPage::WordmarkRect(const Rect& content) const
{
    const u32 w = 160;
    const u32 h = 28;
    return Rect{content.x + (content.w > w ? (content.w - w) / 2 : 0), content.y + content.h * 22 / 100, w, h};
}

Rect StartPage::PromptRect(const Rect& content) const
{
    const u32 w = content.w * 62 / 100;
    const u32 h = 38;
    return Rect{content.x + (content.w - w) / 2, content.y + content.h * 38 / 100, w, h};
}

Rect StartPage::TileRect(u32 i, const Rect& content) const
{
    const u32 n = tileCount ? tileCount : 1;
    const u32 total = n * kTileW + (n - 1) * kTileGap;
    const u32 startX = content.x + (content.w > total ? (content.w - total) / 2 : 0);
    const u32 y = content.y + content.h * 60 / 100;
    return Rect{startX + i * (kTileW + kTileGap), y, kTileW, kTileH};
}

StartHit StartPage::HitTest(const Rect& content, u32 cx, u32 cy) const
{
    if (PromptRect(content).Contains(cx, cy))
        return StartHit{StartHitKind::Prompt, 0};
    for (u32 i = 0; i < tileCount; ++i)
        if (TileRect(i, content).Contains(cx, cy))
            return StartHit{StartHitKind::Tile, i};
    return StartHit{StartHitKind::None, 0};
}

} // namespace duetos::apps::browser
