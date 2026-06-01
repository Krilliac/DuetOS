/*
 * DuetOS — built-in User-Agent default stylesheet. See css.h.
 *
 * This is the browser's baked-in baseline: the rules every HTML
 * document gets before any author CSS. It is expressed as one embedded
 * CSS string and fed through the normal ParseStyleSheet path tagged
 * userAgent=true, so author rules with equal specificity win on origin.
 *
 * The sheet is a practical subset matching what the layout swarm will
 * render: block/inline display defaults, heading sizes + weights +
 * margins, paragraph/list/quote margins, link color + underline, bold/
 * italic emphasis, monospace pre/code, and a thin hr rule. Pixel font
 * sizes stand in for the spec's em-relative ones (em units are a GAP);
 * they track the usual 16px-base heading scale.
 */

#include "web/css.h"

namespace duetos::web
{

namespace
{

// The default sheet. Kept compact but readable; one selector group per
// concern. Comments inside are stripped by the CSS comment skipper.
constexpr const char* kUserAgentCss =
    "html, body, div, p, h1, h2, h3, h4, h5, h6, ul, ol, li, blockquote,"
    "section, article, header, footer, nav, main, aside, figure, hr, table,"
    "form, pre { display: block; }"
    "head, title, script, style, meta, link { display: none; }"
    "span, a, b, strong, i, em, u, small, code, label, abbr, cite,"
    "sub, sup, mark { display: inline; }"
    "img, button, input, select, textarea { display: inline-block; }"

    "body { margin: 8px; color: black; font-size: 16px; line-height: 19px; }"

    "h1 { font-size: 32px; font-weight: bold; margin-top: 21px; margin-bottom: 21px; }"
    "h2 { font-size: 24px; font-weight: bold; margin-top: 19px; margin-bottom: 19px; }"
    "h3 { font-size: 18px; font-weight: bold; margin-top: 18px; margin-bottom: 18px; }"
    "h4 { font-size: 16px; font-weight: bold; margin-top: 21px; margin-bottom: 21px; }"
    "h5 { font-size: 13px; font-weight: bold; margin-top: 22px; margin-bottom: 22px; }"
    "h6 { font-size: 11px; font-weight: bold; margin-top: 24px; margin-bottom: 24px; }"

    "p { margin-top: 16px; margin-bottom: 16px; }"
    "blockquote { margin-top: 16px; margin-bottom: 16px; margin-left: 40px; margin-right: 40px; }"

    "ul, ol { margin-top: 16px; margin-bottom: 16px; padding-left: 40px; }"
    "li { display: block; }"

    "a { color: #0000ee; text-decoration: underline; }"
    "b, strong { font-weight: bold; }"
    "i, em, cite { font-style: italic; }"
    "u { text-decoration: underline; }"
    "small { font-size: 13px; }"

    "pre { white-space: pre; margin-top: 13px; margin-bottom: 13px; }"
    "pre, code { font-size: 13px; }"

    "hr { margin-top: 8px; margin-bottom: 8px; border: 1px solid gray; }";

} // namespace

void AppendUserAgentStyles(StyleSheet& sheet, Arena& arena)
{
    u32 len = 0;
    while (kUserAgentCss[len] != '\0')
    {
        ++len;
    }
    ParseStyleSheet(sheet, kUserAgentCss, len, /*userAgent=*/true, arena);
}

} // namespace duetos::web
