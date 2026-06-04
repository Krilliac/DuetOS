#include "web/priv_binding.h"

#include "security/privilege/broker.h"
#include "web/js/builtins.h"
#include "web/js/object.h"

namespace duetos::web::priv
{
using namespace duetos::web::js;
using duetos::core::Result;
namespace sp = duetos::security::privilege;

namespace
{
duetos::u32 Len(const char* s)
{
    duetos::u32 n = 0;
    while (s != nullptr && s[n] != '\0')
        ++n;
    return n;
}

bool KeyIs(const char* k, duetos::u32 kl, const char* lit)
{
    duetos::u32 i = 0;
    for (; i < kl && lit[i] != '\0'; ++i)
        if (k[i] != lit[i])
            return false;
    return i == kl && lit[i] == '\0';
}

// Build a { ok: bool, error: string } result object.
JsValue MakeResult(Interp& I, bool ok, const char* err)
{
    JsObject* o = ObjNew(I.arena, false);
    if (o == nullptr)
        return JsValue::Undefined();
    ObjSet(o, I.arena, "ok", 2, JsValue::Bool(ok));
    if (err != nullptr && err[0] != '\0')
    {
        JsString* s = MakeString(I.arena, err, Len(err));
        if (s != nullptr)
            ObjSet(o, I.arena, "error", 5, JsValue::Str(s));
    }
    return JsValue::Obj(o);
}

JsValue MakeMethod(Interp& I, JsNativeCall cb, const char* name, void* nctx)
{
    JsFunction* fn = I.arena.New<JsFunction>();
    if (fn == nullptr)
        return JsValue::Undefined();
    fn->nativeId = kNativeCallback;
    fn->name = name;
    fn->nativeCall = cb;
    fn->nativeCtx = nctx;
    return JsValue::Fn(fn);
}

// ---- methods: each marshals to the kernel Privilege Engine validator ----
// GAP (Task 8): on a yes verdict, EXECUTE the matching cap-gated syscall
// (fs::fat32 / net / proc) + AuditAppend. Here we return the verdict so the
// page sees the structured allow/deny.
JsValue FsValidate(Interp& I, sp::Cap cap, const JsValue* args, duetos::u32 argc, PrivBind* b)
{
    if (b == nullptr || b->tab == nullptr)
        return MakeResult(I, false, "EPERM: no context");
    char path[512];
    if (argc > 0)
        ValueToChars(args[0], path, sizeof(path));
    else
        path[0] = '\0';
    duetos::u32 byteLen = 0;
    if (cap == sp::Cap::FsWrite && argc > 1)
    {
        char data[256];
        byteLen = ValueToChars(args[1], data, sizeof(data));
    }
    char canon[512];
    const sp::PrivRequest req{cap, (argc > 0) ? path : nullptr, byteLen};
    const sp::Verdict v = sp::ValidateRequest(*b->tab, b->roots, req, canon, sizeof(canon));
    return MakeResult(I, v.ok, v.error);
}

JsValue CapValidate(Interp& I, sp::Cap cap, PrivBind* b)
{
    if (b == nullptr || b->tab == nullptr)
        return MakeResult(I, false, "EPERM: no context");
    char canon[8];
    const sp::PrivRequest req{cap, nullptr, 0};
    const sp::Verdict v = sp::ValidateRequest(*b->tab, b->roots, req, canon, sizeof(canon));
    return MakeResult(I, v.ok, v.error);
}

Result<JsValue> MFsWrite(Interp& I, const JsValue&, const JsValue* a, duetos::u32 n, void* c)
{
    return FsValidate(I, sp::Cap::FsWrite, a, n, static_cast<PrivBind*>(c));
}
Result<JsValue> MFsRead(Interp& I, const JsValue&, const JsValue* a, duetos::u32 n, void* c)
{
    return FsValidate(I, sp::Cap::FsRead, a, n, static_cast<PrivBind*>(c));
}
Result<JsValue> MProcSpawn(Interp& I, const JsValue&, const JsValue*, duetos::u32, void* c)
{
    return CapValidate(I, sp::Cap::ProcSpawn, static_cast<PrivBind*>(c));
}
Result<JsValue> MNetFetch(Interp& I, const JsValue&, const JsValue*, duetos::u32, void* c)
{
    return CapValidate(I, sp::Cap::Net, static_cast<PrivBind*>(c));
}
Result<JsValue> MKernelRead(Interp& I, const JsValue&, const JsValue*, duetos::u32, void* c)
{
    return CapValidate(I, sp::Cap::KernelRead, static_cast<PrivBind*>(c));
}

Result<JsValue> FsHostGet(Interp& I, JsObject* self, const char* k, duetos::u32 kl)
{
    PrivBind* b = static_cast<PrivBind*>(self->hostData);
    if (KeyIs(k, kl, "writeFile"))
        return MakeMethod(I, MFsWrite, "writeFile", b);
    if (KeyIs(k, kl, "readFile"))
        return MakeMethod(I, MFsRead, "readFile", b);
    return JsValue::Undefined();
}
Result<JsValue> ProcHostGet(Interp& I, JsObject* self, const char* k, duetos::u32 kl)
{
    PrivBind* b = static_cast<PrivBind*>(self->hostData);
    if (KeyIs(k, kl, "spawn"))
        return MakeMethod(I, MProcSpawn, "spawn", b);
    return JsValue::Undefined();
}
Result<JsValue> NetHostGet(Interp& I, JsObject* self, const char* k, duetos::u32 kl)
{
    PrivBind* b = static_cast<PrivBind*>(self->hostData);
    if (KeyIs(k, kl, "fetch"))
        return MakeMethod(I, MNetFetch, "fetch", b);
    return JsValue::Undefined();
}
Result<JsValue> KernelHostGet(Interp& I, JsObject* self, const char* k, duetos::u32 kl)
{
    PrivBind* b = static_cast<PrivBind*>(self->hostData);
    if (KeyIs(k, kl, "read"))
        return MakeMethod(I, MKernelRead, "read", b);
    // installHandler is intentionally ABSENT (spec §13.6 — not built in v1).
    return JsValue::Undefined();
}

JsValue MakeSub(Interp& I, PrivBind* b, JsHostGet hg)
{
    JsObject* o = ObjNew(I.arena, false);
    if (o == nullptr)
        return JsValue::Undefined();
    o->hostData = b;
    o->hostGet = hg;
    return JsValue::Obj(o);
}

JsValue BuildScope(Interp& I, PrivBind* b)
{
    JsObject* arr = ObjNew(I.arena, true);
    if (arr == nullptr || b == nullptr || b->tab == nullptr)
        return JsValue::Undefined();
    const sp::CapSet& s = b->tab->scope;
    const struct
    {
        sp::Cap c;
        const char* n;
    } tbl[5] = {{sp::Cap::FsRead, "fs.read"},
                {sp::Cap::FsWrite, "fs.write"},
                {sp::Cap::ProcSpawn, "proc.spawn"},
                {sp::Cap::KernelRead, "kernel.read"},
                {sp::Cap::Net, "net"}};
    for (const auto& e : tbl)
        if (s.Has(e.c))
        {
            JsString* js = MakeString(I.arena, e.n, Len(e.n));
            if (js != nullptr)
                ArrPush(arr, I.arena, JsValue::Str(js));
        }
    return JsValue::Obj(arr);
}

Result<JsValue> DuetosHostGet(Interp& I, JsObject* self, const char* k, duetos::u32 kl)
{
    PrivBind* b = static_cast<PrivBind*>(self->hostData);
    if (KeyIs(k, kl, "armed"))
        return JsValue::Bool(b != nullptr && b->tab != nullptr && b->tab->IsArmed());
    if (KeyIs(k, kl, "origin"))
    {
        const char* o = (b != nullptr) ? b->origin : "";
        JsString* s = MakeString(I.arena, o, Len(o));
        return s != nullptr ? JsValue::Str(s) : JsValue::Undefined();
    }
    if (KeyIs(k, kl, "scope"))
        return BuildScope(I, b);
    if (KeyIs(k, kl, "fs"))
        return MakeSub(I, b, FsHostGet);
    if (KeyIs(k, kl, "proc"))
        return MakeSub(I, b, ProcHostGet);
    if (KeyIs(k, kl, "net"))
        return MakeSub(I, b, NetHostGet);
    if (KeyIs(k, kl, "kernel"))
        return MakeSub(I, b, KernelHostGet);
    // installHandler intentionally absent.
    return JsValue::Undefined();
}

Result<JsValue> WindowHostGet(Interp& I, JsObject* self, const char* k, duetos::u32 kl)
{
    PrivBind* b = static_cast<PrivBind*>(self->hostData);
    if (KeyIs(k, kl, "duetos"))
        return BuildDuetosObject(I, b);
    return JsValue::Undefined();
}
} // namespace

JsValue BuildDuetosObject(Interp& I, PrivBind* bind)
{
    JsObject* o = ObjNew(I.arena, false);
    if (o == nullptr)
        return JsValue::Undefined();
    o->hostData = bind;
    o->hostGet = DuetosHostGet;
    return JsValue::Obj(o);
}

bool PrivBindingInstall(Interp& I, PrivBind* bind)
{
    if (I.global == nullptr)
        return false;
    EnvDefine(I.global, I.arena, "duetos", 6, BuildDuetosObject(I, bind));
    JsObject* win = ObjNew(I.arena, false);
    if (win != nullptr)
    {
        win->hostData = bind;
        win->hostGet = WindowHostGet;
        EnvDefine(I.global, I.arena, "window", 6, JsValue::Obj(win));
    }
    return true;
}

} // namespace duetos::web::priv
