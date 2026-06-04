#include "apps/browser/omnibox.h"

namespace duetos::apps::browser
{
using duetos::u32;

void Omnibox::BeginEdit()
{
    editing = true;
    caret = len;
}

void Omnibox::EndEdit()
{
    editing = false;
}

void Omnibox::SetText(const char* s)
{
    u32 i = 0;
    if (s != nullptr)
        for (; s[i] != '\0' && i + 1 < kOmniCap; ++i)
            text[i] = s[i];
    text[i] = '\0';
    len = i;
    caret = i;
    editing = false;
}

void Omnibox::InsertChar(char c)
{
    if (len + 1 >= kOmniCap)
        return;
    if (caret > len)
        caret = len;
    for (u32 i = len; i > caret; --i)
        text[i] = text[i - 1];
    text[caret] = c;
    ++len;
    ++caret;
    text[len] = '\0';
}

void Omnibox::Backspace()
{
    if (caret == 0 || len == 0)
        return;
    for (u32 i = caret - 1; i < len; ++i)
        text[i] = text[i + 1];
    --len;
    --caret;
    text[len] = '\0';
}

Rect Omnibox::NavRect(u32 i, const Rect& toolbar) const
{
    const u32 x = toolbar.x + kOmniPad + i * (kOmniNavW + kOmniGap);
    return Rect{x, toolbar.y, kOmniNavW, toolbar.h};
}

Rect Omnibox::MenuRect(const Rect& toolbar) const
{
    const u32 x = toolbar.x + toolbar.w - kOmniPad - kOmniMenuW;
    return Rect{x, toolbar.y, kOmniMenuW, toolbar.h};
}

Rect Omnibox::LibraryRect(const Rect& toolbar) const
{
    const u32 x = MenuRect(toolbar).x - kOmniGap - kOmniLibW;
    return Rect{x, toolbar.y, kOmniLibW, toolbar.h};
}

Rect Omnibox::AskRect(const Rect& toolbar) const
{
    const u32 x = LibraryRect(toolbar).x - kOmniGap - kOmniAskW;
    return Rect{x, toolbar.y, kOmniAskW, toolbar.h};
}

Rect Omnibox::PillRect(const Rect& toolbar) const
{
    const u32 left = toolbar.x + kOmniPad + kOmniNavCount * (kOmniNavW + kOmniGap);
    const u32 askX = AskRect(toolbar).x;
    const u32 right = (askX > left + kOmniGap) ? (askX - kOmniGap) : left;
    return Rect{left, toolbar.y, right - left, toolbar.h};
}

OmniHit Omnibox::HitTest(const Rect& toolbar, u32 cx, u32 cy) const
{
    for (u32 i = 0; i < kOmniNavCount; ++i)
        if (NavRect(i, toolbar).Contains(cx, cy))
            return OmniHit{OmniHitKind::Nav, i};
    if (AskRect(toolbar).Contains(cx, cy))
        return OmniHit{OmniHitKind::Ask, 0};
    if (LibraryRect(toolbar).Contains(cx, cy))
        return OmniHit{OmniHitKind::Library, 0};
    if (MenuRect(toolbar).Contains(cx, cy))
        return OmniHit{OmniHitKind::Menu, 0};
    if (PillRect(toolbar).Contains(cx, cy))
        return OmniHit{OmniHitKind::Pill, 0};
    return OmniHit{OmniHitKind::None, 0};
}

} // namespace duetos::apps::browser
