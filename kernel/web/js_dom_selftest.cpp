#include "web/js_dom.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "util/string.h"
#include "web/html.h"

/*
 * DuetOS — kernel/web: JS ⇄ DOM bindings boot self-test.
 *
 * Parses a small HTML document, runs a battery of scripts through
 * JsRunOnDocument, and asserts the JS↔DOM effects TWO ways: against the
 * captured console buffer, and by an independent re-walk of the live DOM
 * (proving a mutation actually landed in the Node tree, not just in a JS
 * copy). Emits one structural sentinel on success:
 *     [js-dom-selftest] PASS (N/N)
 * On any failure fires KBP_PROBE_V(kBootSelftestFail, idx) and emits a
 * FAIL line naming the failing check.
 */

namespace duetos::web
{

using namespace duetos::core;

namespace
{

// DOM arena for the self-test document + script mutations.
alignas(16) u8 g_selftestDomArena[256 * 1024];

void WriteDec(u32 v, char* out)
{
    char tmp[12];
    u32 t = 0;
    if (v == 0)
        tmp[t++] = '0';
    while (v)
    {
        tmp[t++] = char('0' + (v % 10));
        v /= 10;
    }
    u32 o = 0;
    while (t)
        out[o++] = tmp[--t];
    out[o] = '\0';
}

// Run `script` against `doc`, compare the captured console buffer to
// `wantConsole` (when non-null).
bool RunExpectConsole(Document* doc, Arena& dom, const char* script, const char* wantConsole)
{
    char console[512];
    JsDomResult r = JsRunOnDocument(doc, script, u32(duetos::core::StrLen(script)), dom, console, sizeof(console));
    if (!r.status)
        return false;
    if (wantConsole && !duetos::core::StrEqual(console, wantConsole))
        return false;
    return true;
}

// Re-walk for the independent DOM assertions: find an element by id
// using only the public Node API (mirrors what the binding does, but
// keeps the self-test from depending on js_dom.cpp internals).
Node* FindElementById(Node* n, const char* id)
{
    for (Node* c = n->firstChild; c; c = c->nextSibling)
    {
        if (c->kind == NodeKind::Element)
        {
            const char* cid = c->GetAttr("id");
            if (cid && duetos::core::StrEqual(cid, id))
                return c;
        }
        Node* hit = FindElementById(c, id);
        if (hit)
            return hit;
    }
    return nullptr;
}

} // namespace

void JsDomSelfTest()
{
    int total = 0;
    int failIdx = -1;
    auto run = [&](bool ok)
    {
        if (failIdx < 0 && !ok)
            failIdx = total;
        ++total;
    };

    Arena dom(g_selftestDomArena, sizeof(g_selftestDomArena));
    const char* html = "<html><body>"
                       "<h1 id='title'>Hello</h1>"
                       "<p class='lead'>First</p>"
                       "<p>Second</p>"
                       "<div id='box'></div>"
                       "</body></html>";
    Document* doc = ParseHtml(html, u32(duetos::core::StrLen(html)), dom);

    // 0. read textContent via getElementById.
    run(RunExpectConsole(doc, dom, "console.log(document.getElementById('title').textContent);", "Hello\n"));

    // 1. setAttribute then read it back via getAttribute.
    run(RunExpectConsole(doc, dom,
                         "var t=document.getElementById('title');"
                         "t.setAttribute('data-x','42');"
                         "console.log(t.getAttribute('data-x'));",
                         "42\n"));

    // 2. set textContent, verify via re-read AND a fresh DOM walk below.
    run(RunExpectConsole(doc, dom,
                         "var t=document.getElementById('title');"
                         "t.textContent='Changed';"
                         "console.log(t.textContent);",
                         "Changed\n"));

    // Re-walk the DOM independently of JS to prove the mutation landed.
    {
        Node* title = FindElementById(doc, "title");
        char buf[64];
        u32 n = title ? web::CollectText(title, buf, sizeof(buf)) : 0;
        run(title && n == 7 && duetos::core::StrEqual(buf, "Changed"));
    }

    // 3. createElement + appendChild grows childNodes; check tagName.
    run(RunExpectConsole(doc, dom,
                         "var box=document.getElementById('box');"
                         "var before=box.childNodes.length;"
                         "var span=document.createElement('span');"
                         "box.appendChild(span);"
                         "console.log(before + ',' + box.childNodes.length + ',' + box.children[0].tagName);",
                         "0,1,SPAN\n"));

    // Confirm via DOM walk that #box now has an element child <span>.
    {
        Node* box = FindElementById(doc, "box");
        Node* child = box ? box->firstChild : nullptr;
        run(child && child->kind == NodeKind::Element && duetos::core::StrEqual(child->tag, "span"));
    }

    // 4. getElementsByTagName('p').length.
    run(RunExpectConsole(doc, dom, "console.log(document.getElementsByTagName('p').length);", "2\n"));

    // 5. querySelector lite: #id, .class, tag.
    run(RunExpectConsole(doc, dom,
                         "console.log(document.querySelector('#box').tagName + ',' +"
                         " document.querySelector('.lead').textContent + ',' +"
                         " document.querySelector('h1').id);",
                         "DIV,First,title\n"));

    // 6. console.log of a DOM value (element id reflects to string).
    run(RunExpectConsole(doc, dom,
                         "var p=document.getElementsByTagName('p')[0];"
                         "p.id='lead-p';"
                         "console.log(document.getElementById('lead-p').className);",
                         "lead\n"));

    // 7. id/className setter reflects into the attribute (host set hook).
    run(RunExpectConsole(doc, dom,
                         "var box=document.getElementById('box');"
                         "box.className='panel';"
                         "console.log(box.getAttribute('class'));",
                         "panel\n"));

    // 8. removeAttribute / hasAttribute round-trip.
    run(RunExpectConsole(doc, dom,
                         "var t=document.getElementById('title');"
                         "t.setAttribute('hidden','1');"
                         "var had=t.hasAttribute('hidden');"
                         "t.removeAttribute('hidden');"
                         "console.log(had + ',' + t.hasAttribute('hidden'));",
                         "true,false\n"));

    // 9. innerHTML get serializes children.
    run(RunExpectConsole(doc, dom,
                         "var box=document.getElementById('box');"
                         "console.log(box.innerHTML.indexOf('<span') >= 0);",
                         "true\n"));

    // 10. innerHTML SET (parse-and-replace): assigning markup parses it
    // into a fragment and swaps in the new children. Assert via JS that
    // the element now has exactly 2 element children with the parsed tag
    // names, and that reading innerHTML back reflects the new subtree.
    run(RunExpectConsole(doc, dom,
                         "var box=document.getElementById('box');"
                         "box.innerHTML='<b>hi</b><i>x</i>';"
                         "console.log(box.children.length + ',' +"
                         " box.children[0].tagName + ',' + box.children[1].tagName + ',' +"
                         " (box.innerHTML.indexOf('<b>') >= 0) + ',' +"
                         " (box.innerHTML.indexOf('<i>') >= 0));",
                         "2,B,I,true,true\n"));

    // Independent DOM walk: #box's children are now <b>hi</b><i>x</i>,
    // proving the parse-and-replace landed in the live Node tree (not
    // just a JS-side view), and that the old <span> child is gone.
    {
        Node* box = FindElementById(doc, "box");
        Node* first = box ? box->firstChild : nullptr;
        Node* second = first ? first->nextSibling : nullptr;
        char fbuf[8];
        char sbuf[8];
        u32 fn = first ? web::CollectText(first, fbuf, sizeof(fbuf)) : 0;
        u32 sn = second ? web::CollectText(second, sbuf, sizeof(sbuf)) : 0;
        run(first && first->kind == NodeKind::Element && duetos::core::StrEqual(first->tag, "b") && second &&
            second->kind == NodeKind::Element && duetos::core::StrEqual(second->tag, "i") &&
            second->nextSibling == nullptr && fn == 2 && duetos::core::StrEqual(fbuf, "hi") && sn == 1 &&
            duetos::core::StrEqual(sbuf, "x"));
    }

    // 11. innerHTML SET in an element-specific fragment context: assigning
    // table-cell markup to a <tr> element must parse the bare <td>s in the
    // "in row" context and yield two <td> element children (not text, not
    // dropped). Build the <tr> via createElement so its tag drives the
    // fragment context, attach it to #box so a DOM re-walk can find it.
    run(RunExpectConsole(doc, dom,
                         "var box=document.getElementById('box');"
                         "var tr=document.createElement('tr');"
                         "tr.id='row';"
                         "box.appendChild(tr);"
                         "tr.innerHTML='<td>hi</td><td>x</td>';"
                         "console.log(tr.children.length + ',' +"
                         " tr.children[0].tagName + ',' + tr.children[1].tagName);",
                         "2,TD,TD\n"));

    // Independent DOM walk: the <tr> now has exactly two <td> element
    // children with the expected text, proving the table-context fragment
    // parse landed real <td> nodes in the live tree.
    {
        Node* row = FindElementById(doc, "row");
        Node* first = row ? row->firstChild : nullptr;
        Node* second = first ? first->nextSibling : nullptr;
        char fbuf[8];
        char sbuf[8];
        u32 fn = first ? web::CollectText(first, fbuf, sizeof(fbuf)) : 0;
        u32 sn = second ? web::CollectText(second, sbuf, sizeof(sbuf)) : 0;
        run(first && first->kind == NodeKind::Element && duetos::core::StrEqual(first->tag, "td") && second &&
            second->kind == NodeKind::Element && duetos::core::StrEqual(second->tag, "td") &&
            second->nextSibling == nullptr && fn == 2 && duetos::core::StrEqual(fbuf, "hi") && sn == 1 &&
            duetos::core::StrEqual(sbuf, "x"));
    }

    char numBuf[12];
    if (failIdx >= 0)
    {
        KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, u64(failIdx));
        ::duetos::arch::SerialWrite("[js-dom-selftest] FAIL (check ");
        WriteDec(u32(failIdx), numBuf);
        ::duetos::arch::SerialWrite(numBuf);
        ::duetos::arch::SerialWrite(")\n");
        return;
    }

    ::duetos::arch::SerialWrite("[js-dom-selftest] PASS (");
    WriteDec(u32(total), numBuf);
    ::duetos::arch::SerialWrite(numBuf);
    ::duetos::arch::SerialWrite("/");
    ::duetos::arch::SerialWrite(numBuf);
    ::duetos::arch::SerialWrite(")\n");
}

} // namespace duetos::web
