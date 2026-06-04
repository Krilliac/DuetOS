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

// Second DOM arena for the retained-context cases (their own small pages,
// kept separate from the main battery's document so a re-walk is clean).
alignas(16) u8 g_selftestDomArena2[64 * 1024];

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
                       "<ul id='list'>"
                       "<li class='item'>A</li>"
                       "<li class='item active'>B</li>"
                       "<li>C</li>"
                       "</ul>"
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

    // 12. getElementsByTagName('li').length over the whole document.
    run(RunExpectConsole(doc, dom, "console.log(document.getElementsByTagName('li').length);", "3\n"));

    // 13. getElementsByClassName('item').length (two of the three <li>).
    run(RunExpectConsole(doc, dom, "console.log(document.getElementsByClassName('item').length);", "2\n"));

    // 14. querySelector('.lead') returns the right element (the <p class=lead>),
    // and querySelector('li.active') matches the compound (tag + class).
    run(RunExpectConsole(doc, dom,
                         "console.log(document.querySelector('.lead').textContent + ',' +"
                         " document.querySelector('li.active').textContent + ',' +"
                         " document.querySelector('#list').tagName);",
                         "First,B,UL\n"));

    // 15. querySelectorAll('.item') returns a JS array of both matches; the
    // first carries text 'A'. Also exercise '*' via getElementsByTagName on
    // a scoped element below.
    run(RunExpectConsole(doc, dom,
                         "var all=document.querySelectorAll('.item');"
                         "console.log(all.length + ',' + all[0].textContent + ',' + all[1].textContent);",
                         "2,A,B\n"));

    // 16. Element-scoped querySelectorAll / getElementsByTagName: rooted at
    // <ul id=list>, 'li' finds the three list items (and only those).
    run(RunExpectConsole(doc, dom,
                         "var ul=document.getElementById('list');"
                         "console.log(ul.querySelectorAll('li').length + ',' +"
                         " ul.getElementsByTagName('li').length + ',' +"
                         " ul.getElementsByClassName('item').length);",
                         "3,3,2\n"));

    // 17. classList.add / contains: add a token, observe membership flips to
    // true and the className attribute reflects it.
    run(RunExpectConsole(doc, dom,
                         "var li=document.querySelector('li');" // the first <li class='item'>
                         "var before=li.classList.contains('x');"
                         "li.classList.add('x');"
                         "console.log(before + ',' + li.classList.contains('x') + ',' + li.className);",
                         "false,true,item x\n"));

    // 18. classList.remove: removing 'x' drops it but keeps 'item'.
    run(RunExpectConsole(doc, dom,
                         "var li=document.querySelector('li');"
                         "li.classList.remove('x');"
                         "console.log(li.classList.contains('x') + ',' + li.className);",
                         "false,item\n"));

    // 19. classList.toggle: toggling 'on' adds it (returns true), toggling
    // again removes it (returns false).
    run(RunExpectConsole(doc, dom,
                         "var li=document.querySelector('li');"
                         "var a=li.classList.toggle('on');"
                         "var hasAfterAdd=li.classList.contains('on');"
                         "var b=li.classList.toggle('on');"
                         "console.log(a + ',' + hasAfterAdd + ',' + b + ',' + li.classList.contains('on'));",
                         "true,true,false,false\n"));

    // Independent DOM walk: after the add/remove/toggle churn the first
    // <li>'s class attribute is back to exactly 'item' (no leftover tokens).
    {
        Node* list = FindElementById(doc, "list");
        Node* li = list ? list->firstChild : nullptr;
        const char* cls = li ? li->GetAttr("class") : nullptr;
        run(li && li->kind == NodeKind::Element && duetos::core::StrEqual(li->tag, "li") && cls &&
            duetos::core::StrEqual(cls, "item"));
    }

    // 20. addEventListener + click(): a click listener fires on el.click(),
    // mutating a closure-captured counter. Listeners live only for the
    // duration of one JsRunOnDocument call (the DomCtx — and its listener
    // table — is per-eval), so register AND dispatch in one script.
    run(RunExpectConsole(doc, dom,
                         "var n=0;"
                         "var t=document.getElementById('title');"
                         "t.addEventListener('click', function(e){ n=n+1; });"
                         "t.click();"
                         "console.log(n);",
                         "1\n"));

    // 21. event.target is the clicked element (its id reflects through the
    // event object passed to the handler).
    run(RunExpectConsole(doc, dom,
                         "var who='';"
                         "var t=document.getElementById('title');"
                         "t.addEventListener('click', function(e){ who=e.target.id + ',' + e.type; });"
                         "t.click();"
                         "console.log(who);",
                         "title,click\n"));

    // 22. Bubbling: a listener on an ANCESTOR fires when a descendant is
    // clicked. Click the first <li> (child of <ul id=list>); a listener on
    // the <ul> must also run. Order is target-then-ancestor.
    run(RunExpectConsole(doc, dom,
                         "var log='';"
                         "var ul=document.getElementById('list');"
                         "var li=ul.querySelector('li');"
                         "li.addEventListener('click', function(e){ log=log+'li'; });"
                         "ul.addEventListener('click', function(e){ log=log+'ul'; });"
                         "li.click();"
                         "console.log(log);",
                         "liul\n"));

    // 23. stopPropagation() halts bubbling: the target listener calls it,
    // so the ancestor listener never runs.
    run(RunExpectConsole(doc, dom,
                         "var log='';"
                         "var ul=document.getElementById('list');"
                         "var li=ul.querySelector('li');"
                         "li.addEventListener('click', function(e){ log=log+'li'; e.stopPropagation(); });"
                         "ul.addEventListener('click', function(e){ log=log+'ul'; });"
                         "li.click();"
                         "console.log(log);",
                         "li\n"));

    // 24. removeEventListener prevents the handler from firing: register a
    // named handler, remove it, then click — the counter stays 0.
    run(RunExpectConsole(doc, dom,
                         "var n=0;"
                         "var t=document.getElementById('title');"
                         "function h(e){ n=n+1; }"
                         "t.addEventListener('click', h);"
                         "t.removeEventListener('click', h);"
                         "t.click();"
                         "console.log(n);",
                         "0\n"));

    // 25. preventDefault() sets event.defaultPrevented, observable inside a
    // later (bubbling) listener on the same event.
    run(RunExpectConsole(doc, dom,
                         "var seen='';"
                         "var ul=document.getElementById('list');"
                         "var li=ul.querySelector('li');"
                         "li.addEventListener('click', function(e){ e.preventDefault(); });"
                         "ul.addEventListener('click', function(e){ seen=e.defaultPrevented; });"
                         "li.click();"
                         "console.log(seen);",
                         "true\n"));

    // 26. dispatchEvent with a custom type only fires listeners for that
    // type (a 'click' listener must NOT run for a dispatched 'tap').
    run(RunExpectConsole(doc, dom,
                         "var log='';"
                         "var t=document.getElementById('title');"
                         "t.addEventListener('click', function(e){ log=log+'c'; });"
                         "t.addEventListener('tap', function(e){ log=log+'t'; });"
                         "t.dispatchEvent('tap');"
                         "console.log(log);",
                         "t\n"));

    // 27. Capture phase ordering: a CAPTURE-phase listener on an ANCESTOR
    // must fire BEFORE the target's (bubble-phase) listener. Register the
    // ancestor listener with capture=true (boolean 3rd arg) and the target
    // listener with the default (bubble) form; clicking the target yields
    // ancestor-then-target order (the reverse of plain bubbling).
    run(RunExpectConsole(doc, dom,
                         "var log='';"
                         "var ul=document.getElementById('list');"
                         "var li=ul.querySelector('li');"
                         "ul.addEventListener('click', function(e){ log=log+'ulCap'; }, true);"
                         "li.addEventListener('click', function(e){ log=log+'li'; });"
                         "li.click();"
                         "console.log(log);",
                         "ulCapli\n"));

    // 28. `once` fires exactly once across TWO dispatches: a once listener
    // increments a counter, then two clicks leave the counter at 1 (the
    // listener auto-removed itself after the first fire). Uses the options
    // object form { once: true }.
    run(RunExpectConsole(doc, dom,
                         "var n=0;"
                         "var t=document.getElementById('title');"
                         "t.addEventListener('click', function(e){ n=n+1; }, { once: true });"
                         "t.click();"
                         "t.click();"
                         "console.log(n);",
                         "1\n"));

    // 29. removeEventListener with a MISMATCHED capture flag does NOT
    // remove: register a capture-phase listener, then attempt to remove it
    // with the default (bubble) form — the listener survives and still
    // fires. (type, fn, capture) is the identity key per the DOM spec.
    run(RunExpectConsole(doc, dom,
                         "var n=0;"
                         "var t=document.getElementById('title');"
                         "function h(e){ n=n+1; }"
                         "t.addEventListener('click', h, true);"
                         "t.removeEventListener('click', h);"
                         "t.click();"
                         "console.log(n);",
                         "1\n"));

    // ----------------------------------------------------------------
    // RETAINED CONTEXT: the listener a script registers must survive to
    // a LATER dispatch (the run→click gap). JsRunOnDocument is one-shot,
    // so these cases drive the JsDomContext API directly: Create once,
    // RunScript to register a listener, THEN DispatchClick — and assert
    // (by an independent DOM re-walk) that the listener fired across the
    // boundary. This is the whole point of the retained context.
    // ----------------------------------------------------------------
    {
        Arena dom2(g_selftestDomArena2, sizeof(g_selftestDomArena2));
        const char* html2 = "<html><body>"
                            "<button id='btn'>Click</button>"
                            "<span id='out'>idle</span>"
                            "</body></html>";
        Document* doc2 = ParseHtml(html2, u32(duetos::core::StrLen(html2)), dom2);

        // 30. Create + RunScript registers a click listener that, when
        // fired, mutates #out.textContent. The listener does NOT run yet.
        char console2[256];
        JsDomContext* ctx = JsDomContextCreate(doc2, dom2, console2, sizeof(console2));
        const char* reg = "var n=0;"
                          "document.getElementById('btn').addEventListener('click', function(e){"
                          " n=n+1;"
                          " document.getElementById('out').textContent='clicked';"
                          "});";
        bool ran = ctx && bool(JsDomContextRunScript(ctx, reg, u32(duetos::core::StrLen(reg))));
        run(ctx != nullptr && ran);

        // Before the click, #out is still 'idle' — the listener registered
        // but has not fired (proving registration alone does not mutate).
        {
            Node* out = FindElementById(doc2, "out");
            char buf[16];
            u32 n = out ? web::CollectText(out, buf, sizeof(buf)) : 0;
            run(out && n == 4 && duetos::core::StrEqual(buf, "idle"));
        }

        // 31. THE persistence check: dispatch a click to #btn THROUGH the
        // retained context (the listener was registered in a PRIOR
        // RunScript call). Re-walk the DOM and assert #out became
        // 'clicked' — proving the listener survived the run→dispatch gap.
        Node* btn = FindElementById(doc2, "btn");
        bool prevented = JsDomContextDispatchClick(ctx, btn);
        run(btn != nullptr && !prevented); // no preventDefault → false
        {
            Node* out = FindElementById(doc2, "out");
            char buf[16];
            u32 n = out ? web::CollectText(out, buf, sizeof(buf)) : 0;
            run(out && n == 7 && duetos::core::StrEqual(buf, "clicked"));
        }
    }

    // 32. preventDefault round-trip: a listener registered in one
    // RunScript that calls event.preventDefault() makes DispatchClick
    // return true; a fresh page whose listener does NOT call it returns
    // false. Two independent Create/RunScript/DispatchClick cycles.
    {
        Arena dom3(g_selftestDomArena2, sizeof(g_selftestDomArena2));
        const char* html3 = "<html><body><a id='lnk'>go</a></body></html>";
        Document* doc3 = ParseHtml(html3, u32(duetos::core::StrLen(html3)), dom3);
        char console3[128];

        // With preventDefault → DispatchClick returns true.
        JsDomContext* ctxP = JsDomContextCreate(doc3, dom3, console3, sizeof(console3));
        const char* regP = "document.getElementById('lnk').addEventListener('click',"
                           " function(e){ e.preventDefault(); });";
        bool okP = ctxP && bool(JsDomContextRunScript(ctxP, regP, u32(duetos::core::StrLen(regP))));
        Node* lnkP = FindElementById(doc3, "lnk");
        run(okP && JsDomContextDispatchClick(ctxP, lnkP) == true);

        // Re-create over the SAME page (resets the listener table) with a
        // listener that does NOT preventDefault → DispatchClick is false.
        JsDomContext* ctxN = JsDomContextCreate(doc3, dom3, console3, sizeof(console3));
        const char* regN = "document.getElementById('lnk').addEventListener('click',"
                           " function(e){ });";
        bool okN = ctxN && bool(JsDomContextRunScript(ctxN, regN, u32(duetos::core::StrLen(regN))));
        Node* lnkN = FindElementById(doc3, "lnk");
        run(okN && JsDomContextDispatchClick(ctxN, lnkN) == false);
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
