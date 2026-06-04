#include "web/priv_binding.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "security/privilege/audit.h"
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

// Mock executors (Phase 2b): record invocation so the test can assert the
// validate -> audit -> EXECUTE path reaches them on an ALLOW and is NEVER
// reached on a DENY — without a live process table or net stack.
int g_mock_spawn_calls = 0;
duetos::i64 MockSpawn(const char*, const char* const*, duetos::u32, const sp::CapSet&, void*)
{
    ++g_mock_spawn_calls;
    return 4242;
}
int g_mock_fetch_calls = 0;
bool MockFetch(const FetchReq&, FetchRes* out, void*)
{
    ++g_mock_fetch_calls;
    if (out != nullptr)
    {
        out->status = 200;
        out->bodyLen = 0;
        out->ok = true;
    }
    return true;
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

    // 10: a DISARMED bind's fs.writeFile FAILS CLOSED — validate denies, no
    //     mutation, result carries ok:false (gating, not just origin display).
    //     Runs without a mounted volume: a denied call never touches fs.
    js::JsValue fsoff = get(dv2.as.obj, "fs");
    js::JsValue wfoff = get(fsoff.as.obj, "writeFile");
    js::JsFunction* fnoff = wfoff.as.fn;
    auto rroff = fnoff->nativeCall(I, js::JsValue::Undefined(), cargs, 2, fnoff->nativeCtx);
    js::JsValue resoff = rroff.take();
    if (resoff.type != js::JsType::Object || resoff.as.obj == nullptr)
    {
        fail(10);
        return;
    }
    js::JsValue okoff{};
    if (!js::ObjGet(resoff.as.obj, "ok", 2, okoff) || !StrEq(str(okoff), "false"))
    {
        fail(10);
        return;
    }

    // 11: the ISO-8601 stamp is well-formed: "YYYY-MM-DDTHH:MM:SSZ" — 20 chars,
    //     digits + the fixed separators in the right positions. Volume-free.
    char iso[24];
    PrivBindingFormatIso8601(iso, sizeof(iso));
    bool isoOk = Len(iso) == 20 && iso[4] == '-' && iso[7] == '-' && iso[10] == 'T' && iso[13] == ':' &&
                 iso[16] == ':' && iso[19] == 'Z';
    for (duetos::u32 i = 0; isoOk && i < 20; ++i)
    {
        if (i == 4 || i == 7 || i == 10 || i == 13 || i == 16 || i == 19)
            continue; // separator positions
        if (iso[i] < '0' || iso[i] > '9')
            isoOk = false;
    }
    if (!isoOk)
    {
        fail(11);
        return;
    }

    // 12: AuditAppend no-ops cleanly with no FAT32 volume mounted (the boot
    //     order may run this before fs is up). It must not crash; the serial
    //     mirror still fires. We exercise the path to assert it returns.
    sp::AuditEntry probe{iso, "browser", "https://claude.ai/code", 0, "fs.read", "path=/home/user/x", false};
    sp::AuditAppend(probe);

    // ---- Phase 2b: proc.spawn / net.fetch execution via the executor hooks ----
    // Register mock executors so we can observe the validate -> audit -> EXECUTE
    // path WITHOUT a real process table or net stack.
    bind.spawnExec = &MockSpawn;
    bind.fetchExec = &MockFetch;
    g_mock_spawn_calls = 0;
    g_mock_fetch_calls = 0;

    // 13: armed + in-root proc.spawn reaches the executor and returns {ok,pid}.
    js::JsValue procv = get(duetos, "proc");
    js::JsValue spawnf = get(procv.as.obj, "spawn");
    js::JsFunction* spfn = spawnf.as.fn;
    js::JsValue spArgsOk[1] = {js::JsValue::Str(js::MakeString(arena, "/home/user/t.elf", 16))};
    js::JsValue spRes = spfn->nativeCall(I, js::JsValue::Undefined(), spArgsOk, 1, spfn->nativeCtx).take();
    {
        js::JsValue okv{};
        js::JsValue pidv{};
        if (g_mock_spawn_calls != 1 || spRes.type != js::JsType::Object || !js::ObjGet(spRes.as.obj, "ok", 2, okv) ||
            !StrEq(str(okv), "true") || !js::ObjGet(spRes.as.obj, "pid", 3, pidv) || !StrEq(str(pidv), "4242"))
        {
            fail(13);
            return;
        }
    }

    // 14: an out-of-root spawn target is DENIED before the executor (count steady).
    js::JsValue spArgsBad[1] = {js::JsValue::Str(js::MakeString(arena, "/etc/shadow", 11))};
    js::JsValue spBad = spfn->nativeCall(I, js::JsValue::Undefined(), spArgsBad, 1, spfn->nativeCtx).take();
    {
        js::JsValue okv{};
        if (g_mock_spawn_calls != 1 || spBad.type != js::JsType::Object || !js::ObjGet(spBad.as.obj, "ok", 2, okv) ||
            !StrEq(str(okv), "false"))
        {
            fail(14);
            return;
        }
    }

    // 15: a DISARMED bind's proc.spawn fails closed — even WITH an executor wired,
    //     the not-armed check gates first, so the executor is never reached.
    boff.spawnExec = &MockSpawn;
    {
        js::JsValue pv2 = get(dv2.as.obj, "proc");
        js::JsValue sf2 = get(pv2.as.obj, "spawn");
        js::JsFunction* spfn2 = sf2.as.fn;
        js::JsValue r2 = spfn2->nativeCall(I, js::JsValue::Undefined(), spArgsOk, 1, spfn2->nativeCtx).take();
        js::JsValue okv{};
        if (g_mock_spawn_calls != 1 || r2.type != js::JsType::Object || !js::ObjGet(r2.as.obj, "ok", 2, okv) ||
            !StrEq(str(okv), "false"))
        {
            fail(15);
            return;
        }
    }

    // 16: armed + well-formed net.fetch reaches the executor and returns {ok,status}.
    js::JsValue netv = get(duetos, "net");
    js::JsValue fetchf = get(netv.as.obj, "fetch");
    js::JsFunction* ffn = fetchf.as.fn;
    js::JsValue fArgsOk[1] = {js::JsValue::Str(js::MakeString(arena, "https://x.test/y", 16))};
    js::JsValue fRes = ffn->nativeCall(I, js::JsValue::Undefined(), fArgsOk, 1, ffn->nativeCtx).take();
    {
        js::JsValue okv{};
        js::JsValue stv{};
        if (g_mock_fetch_calls != 1 || fRes.type != js::JsType::Object || !js::ObjGet(fRes.as.obj, "ok", 2, okv) ||
            !StrEq(str(okv), "true") || !js::ObjGet(fRes.as.obj, "status", 6, stv) || !StrEq(str(stv), "200"))
        {
            fail(16);
            return;
        }
    }

    // 17: a malformed-URL net.fetch is DENIED before the executor (count steady).
    js::JsValue fArgsBad[1] = {js::JsValue::Str(js::MakeString(arena, "ftp://nope", 10))};
    js::JsValue fBad = ffn->nativeCall(I, js::JsValue::Undefined(), fArgsBad, 1, ffn->nativeCtx).take();
    {
        js::JsValue okv{};
        if (g_mock_fetch_calls != 1 || fBad.type != js::JsType::Object || !js::ObjGet(fBad.as.obj, "ok", 2, okv) ||
            !StrEq(str(okv), "false"))
        {
            fail(17);
            return;
        }
    }

    arch::SerialWrite("[priv-binding-selftest] PASS (armed/disarmed gate, origin, scope caps, fs/kernel subs, "
                      "kernel.read present, installHandler absent, brokered fs.writeFile invoke+audit, disarmed "
                      "fs.write fail-closed, ISO-8601 shape, AuditAppend volume-absent no-op, proc.spawn "
                      "exec+deny+disarm-gate, net.fetch exec+malformed-deny)\n");
}

} // namespace duetos::web::priv
