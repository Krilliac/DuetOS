/*
 * DuetOS — boot self-test for the HTML tokenizer + tree builder.
 *
 * Parses a handful of representative fragments into a DOM and asserts
 * the resulting tree shape: nested elements + attributes, void-element
 * handling, entity decoding in text, <p>/<li> mis-nesting recovery,
 * comment skipping, and whole-document text extraction. On success it
 * emits one grep-able PASS line; on the first failed sub-check it fires
 * KBP_PROBE_V(kBootSelftestFail, <check#>) and emits a FAIL line.
 *
 * Wired into the boot path via DUETOS_BOOT_SELFTEST in boot_bringup.cpp
 * (after the browser/net self-tests).
 */

#include "web/html.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "util/string.h"

namespace duetos::web
{

namespace
{

bool StrEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
    {
        return false;
    }
    return duetos::core::StrEqual(a, b);
}

// Does `hay` contain `needle` as a substring?
bool Contains(const char* hay, const char* needle)
{
    if (hay == nullptr || needle == nullptr)
    {
        return false;
    }
    for (u32 i = 0; hay[i] != '\0'; ++i)
    {
        u32 k = 0;
        while (needle[k] != '\0' && hay[i + k] == needle[k])
        {
            ++k;
        }
        if (needle[k] == '\0')
        {
            return true;
        }
    }
    return false;
}

void Fail(u32 check)
{
    arch::SerialWrite("[html-dom-selftest] FAIL check=");
    arch::SerialWriteHex(check);
    arch::SerialWrite("\n");
    KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, check);
}

// Count direct element children of a node.
u32 CountElementChildren(const Node* n)
{
    u32 c = 0;
    for (const Node* k = n->firstChild; k != nullptr; k = k->nextSibling)
    {
        if (k->kind == NodeKind::Element)
        {
            ++c;
        }
    }
    return c;
}

} // namespace

void HtmlDomSelfTest()
{
    // One shared arena buffer reused across the sub-parses. 64 KiB is
    // ample for these tiny fragments and stays off the kernel stack
    // via a function-local static (single-threaded boot path).
    static u8 s_arenaBuf[64 * 1024];

    // --- Check 1: nested elements + attributes -----------------------
    {
        Arena arena(s_arenaBuf, sizeof(s_arenaBuf));
        const char* html = "<div id=\"main\" class='wrap'><a href=https://x>hi</a></div>";
        Node* doc = ParseHtml(html, static_cast<u32>(duetos::core::StrLen(html)), arena);
        if (doc == nullptr)
        {
            Fail(1);
            return;
        }
        Node* div = doc->FirstChildByTag("div");
        if (div == nullptr || !StrEq(div->GetAttr("id"), "main") || !StrEq(div->GetAttr("class"), "wrap"))
        {
            Fail(1);
            return;
        }
        Node* a = div->FirstChildByTag("a");
        if (a == nullptr || !StrEq(a->GetAttr("href"), "https://x"))
        {
            Fail(1);
            return;
        }
        char text[64];
        CollectText(a, text, sizeof(text));
        if (!StrEq(text, "hi"))
        {
            Fail(1);
            return;
        }
    }

    // --- Check 2: void element handling ------------------------------
    {
        Arena arena(s_arenaBuf, sizeof(s_arenaBuf));
        const char* html = "<p>a<br>b<img src=\"x.png\">c</p>";
        Node* doc = ParseHtml(html, static_cast<u32>(duetos::core::StrLen(html)), arena);
        Node* p = (doc != nullptr) ? doc->FirstChildByTag("p") : nullptr;
        if (p == nullptr)
        {
            Fail(2);
            return;
        }
        // <br> and <img> must be direct children of <p>, not nested,
        // and must have no children themselves.
        Node* br = p->FirstChildByTag("br");
        Node* img = p->FirstChildByTag("img");
        if (br == nullptr || img == nullptr || br->firstChild != nullptr || img->firstChild != nullptr)
        {
            Fail(2);
            return;
        }
        if (!StrEq(img->GetAttr("src"), "x.png"))
        {
            Fail(2);
            return;
        }
        char text[64];
        CollectText(p, text, sizeof(text));
        if (!StrEq(text, "abc"))
        {
            Fail(2);
            return;
        }
    }

    // --- Check 3: entity decoding in text ----------------------------
    {
        Arena arena(s_arenaBuf, sizeof(s_arenaBuf));
        const char* html = "<span>5 &lt; 10 &amp;&amp; 10 &gt; 5 &#65;&#x42;&copy;</span>";
        Node* doc = ParseHtml(html, static_cast<u32>(duetos::core::StrLen(html)), arena);
        Node* span = (doc != nullptr) ? doc->FirstChildByTag("span") : nullptr;
        if (span == nullptr)
        {
            Fail(3);
            return;
        }
        char text[128];
        CollectText(span, text, sizeof(text));
        // "5 < 10 && 10 > 5 AB" followed by the UTF-8 for U+00A9 (©).
        if (!Contains(text, "5 < 10 && 10 > 5 AB"))
        {
            Fail(3);
            return;
        }
        // © is 0xC2 0xA9 in UTF-8.
        bool sawCopy = false;
        for (u32 i = 0; text[i] != '\0'; ++i)
        {
            if (static_cast<u8>(text[i]) == 0xC2 && static_cast<u8>(text[i + 1]) == 0xA9)
            {
                sawCopy = true;
                break;
            }
        }
        if (!sawCopy)
        {
            Fail(3);
            return;
        }
    }

    // --- Check 4: <p>/<li> mis-nesting recovery ----------------------
    {
        Arena arena(s_arenaBuf, sizeof(s_arenaBuf));
        // Unclosed <p> then a <div> block start must auto-close the <p>;
        // unclosed <li> then another <li> must auto-close the first.
        const char* html = "<p>one<div>two</div><ul><li>a<li>b</ul>";
        Node* doc = ParseHtml(html, static_cast<u32>(duetos::core::StrLen(html)), arena);
        if (doc == nullptr)
        {
            Fail(4);
            return;
        }
        Node* p = doc->FirstChildByTag("p");
        Node* div = doc->FirstChildByTag("div");
        // <div> must be a sibling of <p> under the document, not nested
        // inside it (the open <p> was auto-closed by the block start).
        if (p == nullptr || div == nullptr || div->parent != doc)
        {
            Fail(4);
            return;
        }
        if (p->FirstChildByTag("div") != nullptr)
        {
            Fail(4); // div wrongly nested inside p
            return;
        }
        Node* ul = doc->FirstChildByTag("ul");
        if (ul == nullptr || CountElementChildren(ul) != 2)
        {
            Fail(4); // both <li> must be direct, sibling children
            return;
        }
        // The first <li> must not contain the second.
        Node* li1 = ul->FirstChildByTag("li");
        if (li1 == nullptr || li1->FirstChildByTag("li") != nullptr)
        {
            Fail(4);
            return;
        }
    }

    // --- Check 5: comment skipping -----------------------------------
    {
        Arena arena(s_arenaBuf, sizeof(s_arenaBuf));
        const char* html = "<div>before<!-- a comment <not a tag> -->after</div>";
        Node* doc = ParseHtml(html, static_cast<u32>(duetos::core::StrLen(html)), arena);
        Node* div = (doc != nullptr) ? doc->FirstChildByTag("div") : nullptr;
        if (div == nullptr)
        {
            Fail(5);
            return;
        }
        // A Comment node must exist among the children, and the comment
        // body must not leak into the extracted text.
        bool sawComment = false;
        for (const Node* k = div->firstChild; k != nullptr; k = k->nextSibling)
        {
            if (k->kind == NodeKind::Comment)
            {
                sawComment = true;
            }
        }
        char text[64];
        CollectText(div, text, sizeof(text));
        if (!sawComment || !StrEq(text, "beforeafter"))
        {
            Fail(5);
            return;
        }
    }

    // --- Check 6: small-document text extraction + EOF recovery ------
    {
        Arena arena(s_arenaBuf, sizeof(s_arenaBuf));
        // No closing </body>/</html>; EOF recovery must close them.
        const char* html = "<!doctype html><html><body><h1>Title</h1>"
                           "<p>Hello <b>world</b>!";
        Node* doc = ParseHtml(html, static_cast<u32>(duetos::core::StrLen(html)), arena);
        if (doc == nullptr)
        {
            Fail(6);
            return;
        }
        char text[128];
        CollectText(doc, text, sizeof(text));
        if (!StrEq(text, "TitleHello world!"))
        {
            Fail(6);
            return;
        }
        // Walk doc->html->body->h1 to prove the tree nested correctly.
        Node* htmlEl = doc->FirstChildByTag("html");
        Node* body = (htmlEl != nullptr) ? htmlEl->FirstChildByTag("body") : nullptr;
        Node* h1 = (body != nullptr) ? body->FirstChildByTag("h1") : nullptr;
        if (h1 == nullptr)
        {
            Fail(6);
            return;
        }
    }

    arch::SerialWrite("[html-dom-selftest] PASS (6 checks: nesting, void, entities, p/li recovery, "
                      "comments, doc-text)\n");
}

} // namespace duetos::web
