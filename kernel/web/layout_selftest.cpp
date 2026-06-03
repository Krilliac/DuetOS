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
                       // Mixed block + inline children: the loose text
                       // "alpha" and "omega" must each be wrapped in an
                       // anonymous block box around the real <p> block.
                       "<div class=mix>alpha<p>blockmid</p>omega</div>"
                       // Block-in-inline split: a <span> (inline) wrapping a
                       // block <div> must be split into three stacked block
                       // pieces — inline "pre", block "MID", inline "post".
                       "<div class=mix2><span>pre<div class=inblk>MID</div>post</span></div>"
                       // Adjacent-sibling margin collapsing: .mc1's 20px
                       // bottom margin and .mc2's 30px top margin collapse to
                       // max(20,30)=30, NOT 20+30=50.
                       "<div class=mc1>MCONE</div>"
                       "<div class=mc2>MCTWO</div>"
                       "</body>";

    const char* css = "#box { background-color: #112233; padding: 10px; width: 200px; }"
                      ".a { height: 30px; }"
                      ".b { height: 40px; }"
                      ".gone { display: none; }"
                      ".ctr { text-align: center; }"
                      ".mix { margin: 0; }"
                      ".mix2 { margin: 0; }"
                      ".mc1 { margin-bottom: 20px; line-height: 16px; }"
                      ".mc2 { margin-top: 30px; line-height: 16px; }"
                      ".inblk { margin: 0; line-height: 16px; }"
                      "span { line-height: 16px; }"
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

    // --- Check 7: anonymous-block wrapping of loose inline content. ---
    // ".mix" is a <div> whose children are: loose text "alpha", a block
    // <p>blockmid</p>, then loose text "omega". Box generation must wrap
    // "alpha" and "omega" each in an anonymous block box, stacking three
    // block-level boxes vertically: anon("alpha"), p("blockmid"),
    // anon("omega"). All three text runs must exist and their y-ranges
    // (each one 16px line tall) must be strictly increasing and
    // non-overlapping, with the real <p> sandwiched between the two
    // anonymous blocks.
    const DisplayItem* aAnon = FindTextRun(*dl, "alpha");
    const DisplayItem* pBlock = FindTextRun(*dl, "blockmid");
    const DisplayItem* oAnon = FindTextRun(*dl, "omega");
    if (aAnon == nullptr || pBlock == nullptr || oAnon == nullptr)
    {
        Fail(15);
        return;
    }
    // Each run is exactly one 16px line tall (deterministic metrics).
    if (aAnon->rect.h != 16 || pBlock->rect.h != 16 || oAnon->rect.h != 16)
    {
        Fail(16);
        return;
    }
    // Strict vertical stacking: the <p> sits one line below the leading
    // anonymous block, and the trailing anonymous block one line below the
    // <p>. This proves the loose text was wrapped into stacked block boxes
    // (not dropped, and not flowed inline into a single line).
    if (pBlock->rect.y - aAnon->rect.y != 16)
    {
        Fail(17);
        return;
    }
    if (oAnon->rect.y - pBlock->rect.y != 16)
    {
        Fail(18);
        return;
    }
    // Non-overlap: each box's [y, y+h) range must end at or before the
    // next box's top (here exactly abutting at 16px steps).
    if (aAnon->rect.y + aAnon->rect.h > pBlock->rect.y || pBlock->rect.y + pBlock->rect.h > oAnon->rect.y)
    {
        Fail(19);
        return;
    }

    // --- Check 8: block-in-inline split (anonymous-inline-box gen). ---
    // ".mix2" is <div><span>pre<div>MID</div>post</span></div>. The <span>
    // is inline but contains a block <div>, so box generation must SPLIT
    // the span around the block: inline "pre" becomes an anonymous block,
    // the <div>MID</div> stays a block, and inline "post" becomes another
    // anonymous block — three boxes stacked vertically. (Without the split
    // the three would flow inline onto one line at the same y, or "MID"
    // would be flowed inline instead of pulled out as a block.)
    const DisplayItem* preRun = FindTextRun(*dl, "pre");
    const DisplayItem* midRun = FindTextRun(*dl, "MID");
    const DisplayItem* postRun = FindTextRun(*dl, "post");
    if (preRun == nullptr || midRun == nullptr || postRun == nullptr)
    {
        Fail(20);
        return;
    }
    // Each piece is exactly one 16px line tall.
    if (preRun->rect.h != 16 || midRun->rect.h != 16 || postRun->rect.h != 16)
    {
        Fail(21);
        return;
    }
    // Strict vertical stacking at 16px steps: pre, then MID one line below,
    // then post one line below MID.
    if (midRun->rect.y - preRun->rect.y != 16)
    {
        Fail(22);
        return;
    }
    if (postRun->rect.y - midRun->rect.y != 16)
    {
        Fail(23);
        return;
    }
    // Non-overlap: each piece's [y, y+h) ends at or before the next's top.
    if (preRun->rect.y + preRun->rect.h > midRun->rect.y || midRun->rect.y + midRun->rect.h > postRun->rect.y)
    {
        Fail(24);
        return;
    }

    // --- Check 9: adjacent-sibling vertical margin collapsing. ---
    // ".mc1" (one 16px line, margin-bottom:20px) is immediately followed by
    // ".mc2" (margin-top:30px). The two touching margins collapse to
    // max(20,30)=30, so .mc2's run sits 16 (mc1 content height) + 30
    // (collapsed gap) = 46px below .mc1's run — NOT 16 + (20+30)=66px, which
    // is what summing the margins would give.
    const DisplayItem* mc1Run = FindTextRun(*dl, "MCONE");
    const DisplayItem* mc2Run = FindTextRun(*dl, "MCTWO");
    if (mc1Run == nullptr || mc2Run == nullptr)
    {
        Fail(25);
        return;
    }
    if (mc2Run->rect.y - mc1Run->rect.y != 46)
    {
        arch::SerialWrite("[layout-selftest] mc gap=");
        arch::SerialWriteHex(static_cast<u64>(static_cast<u32>(mc2Run->rect.y - mc1Run->rect.y)));
        arch::SerialWrite("\n");
        Fail(26);
        return;
    }

    arch::SerialWrite("[layout-selftest] PASS (block+inline display list: bg-rect, bold heading, wrap, "
                      "stacked-y, display:none, center-align, anon-block-wrap, block-in-inline, "
                      "margin-collapse)\n");
}

} // namespace duetos::web
