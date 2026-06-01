/*
 * DuetOS — boot self-test for the block + inline layout engine.
 *
 * Parses a small HTML document, computes styles (UA sheet + an author
 * sheet), lays it out at a fixed viewport width + deterministic glyph
 * metrics (glyph_w=8, glyph_h=16), and asserts the resulting DISPLAY
 * LIST:
 *   1. a styled <div> emits a FillRect of the expected color at the
 *      expected rect (origin + size including padding);
 *   2. a heading text run sits at the expected y with bold set;
 *   3. a long paragraph WRAPS to >= 2 TextRuns (lines) at the chosen
 *      width;
 *   4. two stacked blocks have the expected y offsets (box heights
 *      stack);
 *   5. display:none produces NO commands for that subtree;
 *   6. text-align:center shifts a run's x rightward.
 *
 * On success emits one grep-able `[layout-selftest] PASS (...)` line; on
 * the first failed sub-check fires KBP_PROBE_V(kBootSelftestFail, <#>)
 * and emits a FAIL line. Wired via DUETOS_BOOT_SELFTEST in
 * boot_bringup.cpp after the existing web (html/png/js/css) self-tests.
 */

#include "web/layout.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "util/string.h"
#include "web/css.h"
#include "web/html.h"

namespace duetos::web
{

namespace
{

void Fail(u32 check)
{
    arch::SerialWrite("[layout-selftest] FAIL check=");
    arch::SerialWriteHex(check);
    arch::SerialWrite("\n");
    KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, check);
}

// Count TextRun commands whose bytes start with `prefix` (so the test
// can find "the heading run" / "the paragraph's runs" without depending
// on exact wrapping points).
u32 CountTextRunsStarting(const DisplayList& dl, const char* prefix)
{
    const u32 plen = static_cast<u32>(duetos::core::StrLen(prefix));
    u32 n = 0;
    for (u32 i = 0; i < dl.count; ++i)
    {
        const DisplayItem& it = dl.items[i];
        if (it.cmd != DisplayCmd::TextRun || it.textLen < plen)
        {
            continue;
        }
        bool match = true;
        for (u32 j = 0; j < plen; ++j)
        {
            if (it.text[j] != prefix[j])
            {
                match = false;
                break;
            }
        }
        if (match)
        {
            ++n;
        }
    }
    return n;
}

// Find the first TextRun whose bytes start with `prefix`, or nullptr.
const DisplayItem* FindTextRun(const DisplayList& dl, const char* prefix)
{
    const u32 plen = static_cast<u32>(duetos::core::StrLen(prefix));
    for (u32 i = 0; i < dl.count; ++i)
    {
        const DisplayItem& it = dl.items[i];
        if (it.cmd != DisplayCmd::TextRun || it.textLen < plen)
        {
            continue;
        }
        bool match = true;
        for (u32 j = 0; j < plen; ++j)
        {
            if (it.text[j] != prefix[j])
            {
                match = false;
                break;
            }
        }
        if (match)
        {
            return &it;
        }
    }
    return nullptr;
}

// Find the first FillRect of the given exact color, or nullptr.
const DisplayItem* FindFillRect(const DisplayList& dl, u8 r, u8 g, u8 b)
{
    for (u32 i = 0; i < dl.count; ++i)
    {
        const DisplayItem& it = dl.items[i];
        if (it.cmd == DisplayCmd::FillRect && it.color.r == r && it.color.g == g && it.color.b == b)
        {
            return &it;
        }
    }
    return nullptr;
}

} // namespace

void LayoutSelfTest()
{
    // A generous shared arena: DOM + sheets + style map + display list
    // all live here. ~256 KiB covers this small document comfortably.
    static u8 buffer[256 * 1024];
    Arena arena(buffer, sizeof(buffer));

    // Document. Notes on the shapes each check leans on:
    //   - #box: a 200px-wide block with 10px padding + a known bg color.
    //   - h1: bold (UA default) heading, first block -> known y.
    //   - p#long: a long paragraph that must wrap at a 160px width.
    //   - two stacked <div>s with explicit heights to test y stacking.
    //   - .gone: display:none -> no commands.
    //   - .ctr: text-align:center -> shifted run x.
    const char* html = "<body>"
                       "<h1>Title</h1>"
                       "<div id=box>Boxed</div>"
                       "<p id=long>wwww wwww wwww wwww wwww wwww wwww wwww wwww wwww</p>"
                       "<div class=a>AAAA</div>"
                       "<div class=b>BBBB</div>"
                       "<div class=gone>HIDDEN</div>"
                       "<p class=ctr>mid</p>"
                       "</body>";

    const char* css = "#box { background-color: #112233; padding: 10px; width: 200px; }"
                      ".a { height: 30px; }"
                      ".b { height: 40px; }"
                      ".gone { display: none; }"
                      ".ctr { text-align: center; }"
                      // Make geometry deterministic: drop the UA body margin
                      // (8px) so child boxes start at the viewport origin, and
                      // pin line-height == cell height everywhere.
                      "body { margin: 0; line-height: 16px; }"
                      // Zero the UA heading/paragraph margins so block y
                      // offsets are driven purely by box heights.
                      "h1 { margin: 0; line-height: 16px; }"
                      "p { margin: 0; line-height: 16px; }"
                      "div { line-height: 16px; }";

    Node* doc = ParseHtml(html, static_cast<u32>(duetos::core::StrLen(html)), arena);
    if (doc == nullptr)
    {
        Fail(1);
        return;
    }

    StyleSheet sheet;
    AppendUserAgentStyles(sheet, arena);
    ParseStyleSheet(sheet, css, static_cast<u32>(duetos::core::StrLen(css)), false, arena);
    StyleMap styles = ComputeStyles(doc, sheet, arena);

    // Deterministic 8x16 monospace cell at a 16px base.
    TextMetrics tm;
    tm.glyphW = 8;
    tm.glyphH = 16;
    tm.baseFontPx = 16;

    // Lay out at 160px viewport so the long paragraph must wrap.
    const u32 viewportW = 160;
    DisplayList* dl = LayoutDocument(doc, styles, viewportW, tm, arena);
    if (dl == nullptr || dl->items == nullptr)
    {
        Fail(2);
        return;
    }

    // --- Check 1: #box FillRect color + rect (padding box). ---
    // #box has width:200px content + 10px padding each side; the body's
    // content box starts at x=0, and #box's content x = padding-left.
    // The padding box origin is the border box origin (no border): the
    // box top-left x = cb-left margin (0). Padding box = {0, y, 220, 36}.
    // (content 200 + 2*10 padding width = 220; height: "Boxed" is one
    // 16px line + 2*10 padding = 36.)
    const DisplayItem* bg = FindFillRect(*dl, 0x11, 0x22, 0x33);
    if (bg == nullptr)
    {
        Fail(3);
        return;
    }
    if (bg->rect.w != 220 || bg->rect.h != 36 || bg->rect.x != 0)
    {
        arch::SerialWrite("[layout-selftest] bg rect x=");
        arch::SerialWriteHex(static_cast<u64>(static_cast<u32>(bg->rect.x)));
        arch::SerialWrite(" w=");
        arch::SerialWriteHex(static_cast<u64>(static_cast<u32>(bg->rect.w)));
        arch::SerialWrite(" h=");
        arch::SerialWriteHex(static_cast<u64>(static_cast<u32>(bg->rect.h)));
        arch::SerialWrite("\n");
        Fail(4);
        return;
    }

    // --- Check 2: the h1 run is bold and sits at the top (y == 0). ---
    const DisplayItem* h1run = FindTextRun(*dl, "Title");
    if (h1run == nullptr)
    {
        Fail(5);
        return;
    }
    if (!h1run->bold)
    {
        Fail(6);
        return;
    }
    if (h1run->rect.y != 0)
    {
        Fail(7);
        return;
    }

    // --- Check 3: the long paragraph wraps to >= 2 TextRuns. ---
    // 50 "w" words at 8px each + spaces vastly exceed the 160px content
    // width, so they must break across multiple lines.
    if (CountTextRunsStarting(*dl, "wwww") < 2)
    {
        Fail(8);
        return;
    }

    // --- Check 4: the two stacked .a / .b divs stack by their heights. ---
    // .a has height:30px, .b height:40px. .b's "BBBB" run must sit 30px
    // below .a's "AAAA" run.
    const DisplayItem* aRun = FindTextRun(*dl, "AAAA");
    const DisplayItem* bRun = FindTextRun(*dl, "BBBB");
    if (aRun == nullptr || bRun == nullptr)
    {
        Fail(9);
        return;
    }
    if (bRun->rect.y - aRun->rect.y != 30)
    {
        Fail(10);
        return;
    }

    // --- Check 5: display:none subtree emits nothing. ---
    if (FindTextRun(*dl, "HIDDEN") != nullptr)
    {
        Fail(11);
        return;
    }

    // --- Check 6: text-align:center shifts the run's x. ---
    // ".ctr" is a <p> filling the 160px viewport; "mid" is 3 glyphs ->
    // 24px wide; centered shift = (160 - 24) / 2 = 68. Left-aligned the
    // run would sit at x=0, so a centered run's x must be > 0.
    const DisplayItem* ctr = FindTextRun(*dl, "mid");
    if (ctr == nullptr)
    {
        Fail(12);
        return;
    }
    if (ctr->rect.x <= 0)
    {
        Fail(13);
        return;
    }
    // And precisely the expected centered offset.
    if (ctr->rect.x != 68)
    {
        Fail(14);
        return;
    }

    arch::SerialWrite("[layout-selftest] PASS (block+inline display list: bg-rect, bold heading, wrap, "
                      "stacked-y, display:none, center-align)\n");
}

} // namespace duetos::web
