#include "web/priv_binding.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "web/js/object.h" // EnvNew

namespace duetos::web::priv
{
namespace
{
namespace sp = duetos::security::privilege;

duetos::u32 Len(const char* s)
{
    duetos::u32 n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}
bool StrEq(const char* a, const char* b)
{
    duetos::u32 i = 0;
    for (; a[i] != '\0' && b[i] != '\0'; ++i)
        if (a[i] != b[i])
            return false;
    return a[i] == b[i];
}
bool Has(const char* hay, const char* needle)
{
    for (duetos::u32 i = 0; hay[i] != '\0'; ++i)
    {
        duetos::u32 j = 0;
        for (; needle[j] != '\0' && hay[i + j] == needle[j]; ++j)
        {
        }
        if (needle[j] == '\0')
            return true;
    }
    return false;
}

alignas(16) unsigned char g_arena_buf[96 * 1024];
} // namespace

void PrivBindingSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[priv-binding-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    js::Arena arena(g_arena_buf, sizeof(g_arena_buf));
    char conbuf[256];
    js::ConsoleBuf con{conbuf, static_cast<duetos::u32>(sizeof(conbuf)), 0};
    js::Interp I(arena, con);
    I.global = js::EnvNew(arena, nullptr);
    if (I.global == nullptr)
    {
        fail(0);
        return;
    }

    sp::PrivTab tab;
    tab.Arm(sp::DefaultArmScope());
    sp::Roots roots;
    roots.root[0] = "/home/user";
    roots.count = 1;
    PrivBind bind{&tab, roots, "https://claude.ai/code", "browser"};

    char s[256];
    auto str = [&](const js::JsValue& v) -> const char*
    {
        // ValueToChars writes the string form and returns its length but does
        // NOT NUL-terminate — terminate at the returned length before reading.
        const duetos::u32 n = js::ValueToChars(v, s, sizeof(s) - 1);
        s[n] = '\0';
        return s;
    };
    auto get = [&](js::JsObject* o, const char* k)
    {
        auto r = o->hostGet(I, o, k, Len(k));
        return r.take();
    };

    js::JsValue dv = BuildDuetosObject(I, &bind);
    js::JsObject* duetos = dv.as.obj;

    // 1: window.duetos.armed === true on an armed bind.
    if (!StrEq(str(get(duetos, "armed")), "true"))
    {
        fail(1);
        return;
    }
    // 2: origin is the exact privileged origin.
    if (!StrEq(str(get(duetos, "origin")), "https://claude.ai/code"))
    {
        fail(2);
        return;
    }
    // 3: scope array enumerates the granted caps.
    if (!Has(str(get(duetos, "scope")), "fs.write"))
    {
        fail(3);
        return;
    }
    // 4: the fs / kernel sub-objects exist.
    if (StrEq(str(get(duetos, "fs")), "undefined"))
    {
        fail(4);
        return;
    }
    js::JsValue kv = get(duetos, "kernel");
    if (StrEq(str(kv), "undefined"))
    {
        fail(5);
        return;
    }
    js::JsObject* kobj = kv.as.obj;
    // 6: kernel.read is present.
    if (StrEq(str(get(kobj, "read")), "undefined"))
    {
        fail(6);
        return;
    }
    // 7: kernel.installHandler is ABSENT (never built in v1).
    if (!StrEq(str(get(kobj, "installHandler")), "undefined"))
    {
        fail(7);
        return;
    }
    // 8: a DISARMED bind reports armed === false (gating).
    sp::PrivTab off;
    PrivBind boff{&off, roots, "https://claude.ai/code", "browser"};
    js::JsValue dv2 = BuildDuetosObject(I, &boff);
    if (!StrEq(str(get(dv2.as.obj, "armed")), "false"))
    {
        fail(8);
        return;
    }
    // 9: invoking fs.writeFile marshals to the broker (armed + in-scope path =>
    //    ok) and fires a [priv/audit] line (visible in the boot log). The call
    //    returns a result object, not undefined.
    js::JsValue fsv = get(duetos, "fs");
    js::JsValue wf = get(fsv.as.obj, "writeFile");
    js::JsFunction* fn = wf.as.fn;
    js::JsValue cargs[2] = {js::JsValue::Str(js::MakeString(arena, "/home/user/x", 12)),
                            js::JsValue::Str(js::MakeString(arena, "data", 4))};
    auto rr = fn->nativeCall(I, js::JsValue::Undefined(), cargs, 2, fn->nativeCtx);
    js::JsValue res = rr.take();
    if (StrEq(str(res), "undefined"))
    {
        fail(9);
        return;
    }

    arch::SerialWrite("[priv-binding-selftest] PASS (armed/disarmed gate, origin, scope caps, fs/kernel subs, "
                      "kernel.read present, installHandler absent, brokered fs.writeFile invoke+audit)\n");
}

} // namespace duetos::web::priv
