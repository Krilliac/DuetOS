#include "web/priv_binding.h"

#include "fs/fat32.h"
#include "mm/kheap.h"
#include "security/privilege/audit.h"
#include "security/privilege/broker.h"
#include "security/privilege/scope.h"
#include "time/timekeeper.h"
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
const char* CapName(sp::Cap c)
{
    switch (c)
    {
    case sp::Cap::FsRead:
        return "fs.read";
    case sp::Cap::FsWrite:
        return "fs.write";
    case sp::Cap::ProcSpawn:
        return "proc.spawn";
    case sp::Cap::KernelRead:
        return "kernel.read";
    case sp::Cap::Net:
        return "net";
    }
    return "?";
}

// Largest single privileged read/write we marshal through the JS binding. The
// broker independently rejects > kMaxPrivWriteBytes; this is the binding-local
// bounce buffer ceiling (well under that) so a page can't ask us to heap-alloc
// 16 MiB per call. 64 KiB covers config/state files a privileged page edits.
constexpr duetos::u32 k_MaxFsBounceBytes = 64u * 1024u;

// Two-digit zero-padded append helper for the ISO-8601 stamp.
duetos::u32 Put2(char* out, duetos::u32 pos, duetos::u32 v)
{
    out[pos++] = static_cast<char>('0' + (v / 10) % 10);
    out[pos++] = static_cast<char>('0' + v % 10);
    return pos;
}

// Format the current wall clock as "YYYY-MM-DDTHH:MM:SSZ" into out (>= 21 B,
// incl. NUL). Sampled from the CMOS RTC via the timekeeper. Always succeeds.
void FormatIso8601(char* out, duetos::u32 cap)
{
    if (out == nullptr || cap < 21)
    {
        if (out != nullptr && cap > 0)
            out[0] = '\0';
        return;
    }
    duetos::time::BrokenDownTime t{};
    duetos::time::RealtimeBrokenDown(&t);
    duetos::u32 p = 0;
    p = Put2(out, p, t.year / 100);
    p = Put2(out, p, t.year % 100);
    out[p++] = '-';
    p = Put2(out, p, t.month);
    out[p++] = '-';
    p = Put2(out, p, t.day);
    out[p++] = 'T';
    p = Put2(out, p, t.hour);
    out[p++] = ':';
    p = Put2(out, p, t.minute);
    out[p++] = ':';
    p = Put2(out, p, t.second);
    out[p++] = 'Z';
    out[p] = '\0';
}

// Audit EVERY brokered call (allow AND deny), tagged with the client identity.
// The caller owns `iso8601` storage (it must outlive this synchronous call).
void Audit(PrivBind* b, const char* iso8601, sp::Cap cap, const char* args, bool ok)
{
    const sp::AuditEntry e{iso8601, b->client, b->origin, 0, CapName(cap), args, ok};
    sp::AuditAppend(e);
}

// Build a { ok:true, data:"<contents>" } result for a successful read. The
// payload is JSON/string-escaped through the arena's MakeString path.
JsValue MakeReadResult(Interp& I, const char* data, duetos::u32 dataLen)
{
    JsObject* o = ObjNew(I.arena, false);
    if (o == nullptr)
        return JsValue::Undefined();
    ObjSet(o, I.arena, "ok", 2, JsValue::Bool(true));
    JsString* s = MakeString(I.arena, data, dataLen);
    if (s != nullptr)
        ObjSet(o, I.arena, "data", 4, JsValue::Str(s));
    return JsValue::Obj(o);
}

// Execute the validated fs.write of `canon`: delete-then-create (the proven
// SaveBookmarks pattern). `data`/`dataLen` are the bounded content bytes.
JsValue ExecFsWrite(Interp& I, const char* canon, const char* data, duetos::u32 dataLen)
{
    namespace fat = duetos::fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return MakeResult(I, false, "EIO: no volume");
    fat::DirEntry probe;
    if (fat::Fat32LookupPath(v, canon, &probe))
        fat::Fat32DeleteAtPath(v, canon);
    const duetos::i64 rc = fat::Fat32CreateAtPath(v, canon, data, dataLen);
    if (rc < 0)
        return MakeResult(I, false, "EIO: write failed");
    return MakeResult(I, true, nullptr);
}

// Execute the validated fs.read of `canon`: lookup + bounded read.
JsValue ExecFsRead(Interp& I, const char* canon)
{
    namespace fat = duetos::fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
        return MakeResult(I, false, "EIO: no volume");
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, canon, &e) || (e.attributes & 0x10) != 0)
        return MakeResult(I, false, "ENOENT: not found");
    const duetos::u32 want = (e.size_bytes < k_MaxFsBounceBytes) ? e.size_bytes : k_MaxFsBounceBytes;
    if (want == 0)
        return MakeReadResult(I, "", 0);
    char* buf = static_cast<char*>(mm::KMalloc(want));
    if (buf == nullptr)
        return MakeResult(I, false, "EIO: no memory");
    const duetos::i64 n = fat::Fat32ReadFile(v, &e, buf, want);
    if (n < 0)
    {
        mm::KFree(buf);
        return MakeResult(I, false, "EIO: read failed");
    }
    const JsValue out = MakeReadResult(I, buf, static_cast<duetos::u32>(n));
    mm::KFree(buf);
    return out;
}

JsValue FsValidate(Interp& I, sp::Cap cap, const JsValue* args, duetos::u32 argc, PrivBind* b)
{
    if (b == nullptr || b->tab == nullptr)
        return MakeResult(I, false, "EPERM: no context");
    char path[512];
    const duetos::u32 plen = (argc > 0) ? ValueToChars(args[0], path, sizeof(path) - 1) : 0;
    path[plen] = '\0'; // ValueToChars does not NUL-terminate.

    // Capture the actual write payload (bounded) — not just its length. The
    // broker independently rejects oversize against kMaxPrivWriteBytes; this
    // bounce buffer caps what the binding will heap-carry per call.
    char* data = nullptr;
    duetos::u32 byteLen = 0;
    if (cap == sp::Cap::FsWrite && argc > 1)
    {
        data = static_cast<char*>(mm::KMalloc(k_MaxFsBounceBytes));
        if (data == nullptr)
            return MakeResult(I, false, "EIO: no memory");
        byteLen = ValueToChars(args[1], data, k_MaxFsBounceBytes);
    }

    char canon[512];
    const sp::PrivRequest req{cap, (argc > 0) ? path : nullptr, byteLen};
    const sp::Verdict v = sp::ValidateRequest(*b->tab, b->roots, req, canon, sizeof(canon));

    // Build a bounded args summary (path only — never payload) and audit, with
    // a real ISO-8601 timestamp. `iso` outlives the synchronous AuditAppend.
    char iso[24];
    FormatIso8601(iso, sizeof(iso));
    char summ[560];
    duetos::u32 so = 0;
    for (const char* p = "path="; *p != '\0'; ++p)
        summ[so++] = *p;
    for (const char* p = v.ok ? canon : path; *p != '\0' && so + 1 < sizeof(summ); ++p)
        summ[so++] = *p;
    summ[so] = '\0';
    Audit(b, iso, cap, summ, v.ok);

    if (!v.ok)
    {
        if (data != nullptr)
            mm::KFree(data);
        return MakeResult(I, false, v.error); // denied: NEVER execute.
    }

    // Symlink-TOCTOU re-check: re-confirm `canon` is STILL within `roots`
    // immediately before the fs syscall, closing the validate→execute window.
    // GAP: FAT32 has no symlinks so string containment is sufficient here; real
    // symlink resolution must be re-enforced by the fs layer AFTER path
    // resolution on symlink-capable backends — revisit when ext4 write lands.
    char recheck[512];
    if (!sp::CanonicalizeAndContain(canon, b->roots, recheck, sizeof(recheck)))
    {
        if (data != nullptr)
            mm::KFree(data);
        return MakeResult(I, false, "EPERM: containment re-check failed");
    }

    JsValue result = JsValue::Undefined();
    if (cap == sp::Cap::FsWrite)
        result = ExecFsWrite(I, recheck, (data != nullptr) ? data : "", byteLen);
    else
        result = ExecFsRead(I, recheck);

    if (data != nullptr)
        mm::KFree(data);
    return result;
}

Result<JsValue> MFsWrite(Interp& I, const JsValue&, const JsValue* a, duetos::u32 n, void* c)
{
    return FsValidate(I, sp::Cap::FsWrite, a, n, static_cast<PrivBind*>(c));
}
Result<JsValue> MFsRead(Interp& I, const JsValue&, const JsValue* a, duetos::u32 n, void* c)
{
    return FsValidate(I, sp::Cap::FsRead, a, n, static_cast<PrivBind*>(c));
}
// proc.spawn(path[, args]): validate the target against the exec roots, audit,
// then — on allow and with a spawn executor registered — load+spawn the image
// with caps derived from the armed scope (child <= broker; see priv_exec.cpp).
// Returns { ok:true, pid } | { ok:false, error }. With no executor (self-test /
// mid-bring-up) it degrades to validate+audit-only, returning { ok, error }.
Result<JsValue> MProcSpawn(Interp& I, const JsValue&, const JsValue* a, duetos::u32 n, void* c)
{
    PrivBind* b = static_cast<PrivBind*>(c);
    if (b == nullptr || b->tab == nullptr)
        return MakeResult(I, false, "EPERM: no context");
    char path[512];
    const duetos::u32 plen = (n > 0) ? ValueToChars(a[0], path, sizeof(path) - 1) : 0;
    path[plen] = '\0'; // ValueToChars does not NUL-terminate.

    char canon[512];
    const sp::PrivRequest req{sp::Cap::ProcSpawn, (n > 0) ? path : nullptr, 0, nullptr};
    const sp::Verdict v = sp::ValidateRequest(*b->tab, b->roots, req, canon, sizeof(canon));

    // Audit the canonical target (path only — never argv contents), with a real
    // ISO-8601 timestamp. `iso` outlives the synchronous AuditAppend.
    char iso[24];
    FormatIso8601(iso, sizeof(iso));
    char summ[560];
    duetos::u32 so = 0;
    for (const char* p = "path="; *p != '\0'; ++p)
        summ[so++] = *p;
    for (const char* p = v.ok ? canon : path; *p != '\0' && so + 1 < sizeof(summ); ++p)
        summ[so++] = *p;
    summ[so] = '\0';
    Audit(b, iso, sp::Cap::ProcSpawn, summ, v.ok);

    if (!v.ok)
        return MakeResult(I, false, v.error); // denied: NEVER execute.
    if (b->spawnExec == nullptr)
        return MakeResult(I, v.ok, v.error); // no executor: validate+audit only.

    // Symlink-TOCTOU re-check (symmetry with FsValidate): re-confirm `canon` is
    // STILL contained immediately before the spawn, closing the validate->execute
    // window, and hand the re-validated path to the executor. GAP: FAT32 has no
    // symlinks so containment is string-stable here; a symlink-capable exec
    // backend (ext4) must re-enforce scope in the fs layer after path resolution.
    char recheck[512];
    if (!sp::CanonicalizeAndContain(canon, b->roots, recheck, sizeof(recheck)))
        return MakeResult(I, false, "EPERM: spawn containment re-check failed");

    // argv is validated/audited as a count only; the executor drops it (GAP:
    // the spawn ABI carries no argv vector yet — see priv_exec.cpp).
    const duetos::i64 pid = b->spawnExec(recheck, nullptr, 0, b->tab->scope, b->execCtx);
    if (pid < 0)
        return MakeResult(I, false, "EIO: spawn failed");
    JsObject* o = ObjNew(I.arena, false);
    if (o == nullptr)
        return JsValue::Undefined();
    ObjSet(o, I.arena, "ok", 2, JsValue::Bool(true));
    ObjSet(o, I.arena, "pid", 3, JsValue::Int(pid));
    return JsValue::Obj(o);
}

// net.fetch(url[, opts]): validate the URL shape, audit (url+method — NEVER the
// body), then — on allow and with a fetch executor registered — run the request
// over the browser's page-fetch transport. Returns { ok:true, status, body } |
// { ok:false, error }. `opts` = { method:"GET"|"POST", body, contentType };
// POST carries body + contentType to the executor (which already supports both).
Result<JsValue> MNetFetch(Interp& I, const JsValue&, const JsValue* a, duetos::u32 n, void* c)
{
    PrivBind* b = static_cast<PrivBind*>(c);
    if (b == nullptr || b->tab == nullptr)
        return MakeResult(I, false, "EPERM: no context");
    char url[1024];
    const duetos::u32 ulen = (n > 0) ? ValueToChars(a[0], url, sizeof(url) - 1) : 0;
    url[ulen] = '\0'; // ValueToChars does not NUL-terminate.

    // Method comes from opts.method (default GET); parsed up front so the audit
    // records the real verb. Body/contentType are read later, only for POST.
    char method[8] = "GET";
    JsObject* opts = (n > 1 && a[1].type == JsType::Object) ? a[1].as.obj : nullptr;
    if (opts != nullptr)
    {
        JsValue mv{};
        if (ObjGet(opts, "method", 6, mv))
        {
            const duetos::u32 ml = ValueToChars(mv, method, sizeof(method) - 1);
            method[ml] = '\0';
        }
    }
    const bool isPost = method[0] == 'P' || method[0] == 'p';

    char canon[8];
    const sp::PrivRequest req{sp::Cap::Net, nullptr, 0, (n > 0) ? url : nullptr};
    const sp::Verdict v = sp::ValidateRequest(*b->tab, b->roots, req, canon, sizeof(canon));

    char iso[24];
    FormatIso8601(iso, sizeof(iso));
    char summ[1080];
    duetos::u32 so = 0;
    for (const char* p = "url="; *p != '\0'; ++p)
        summ[so++] = *p;
    for (const char* p = url; *p != '\0' && so + 16 < sizeof(summ); ++p)
        summ[so++] = *p;
    for (const char* p = ",method="; *p != '\0'; ++p)
        summ[so++] = *p;
    for (const char* p = method; *p != '\0' && so + 1 < sizeof(summ); ++p)
        summ[so++] = *p;
    summ[so] = '\0';
    Audit(b, iso, sp::Cap::Net, summ, v.ok);

    if (!v.ok)
        return MakeResult(I, false, v.error); // denied: NEVER execute.
    if (b->fetchExec == nullptr)
        return MakeResult(I, v.ok, v.error); // no executor: validate+audit only.

    // 256 KiB response bounce — intentionally larger than the page-fetch path's
    // 64 KiB ceiling: a brokered fetch services API/JSON responses (the LLM seam)
    // that legitimately run bigger. The executor caps the copy at this size.
    constexpr duetos::u32 kFetchBodyCap = 256u * 1024u;
    char* body = static_cast<char*>(mm::KMalloc(kFetchBodyCap));
    if (body == nullptr)
        return MakeResult(I, false, "EIO: no memory");

    // For POST, capture body + contentType from opts into a bounded request
    // buffer. Freed immediately after the synchronous executor call below.
    char ctype[128] = {};
    char* reqBody = nullptr;
    duetos::u32 reqLen = 0;
    if (isPost && opts != nullptr)
    {
        JsValue cv{};
        if (ObjGet(opts, "contentType", 11, cv))
        {
            const duetos::u32 cl = ValueToChars(cv, ctype, sizeof(ctype) - 1);
            ctype[cl] = '\0';
        }
        JsValue bv{};
        if (ObjGet(opts, "body", 4, bv))
        {
            reqBody = static_cast<char*>(mm::KMalloc(kFetchBodyCap));
            if (reqBody != nullptr)
                reqLen = ValueToChars(bv, reqBody, kFetchBodyCap);
        }
    }

    FetchReq fr{};
    fr.url = url;
    fr.method = isPost ? "POST" : "GET";
    fr.body = reqBody;
    fr.bodyLen = reqLen;
    fr.contentType = (ctype[0] != '\0') ? ctype : nullptr;
    FetchRes fres{};
    fres.body = body;
    fres.bodyCap = kFetchBodyCap;
    const bool ok = b->fetchExec(fr, &fres, b->execCtx);
    if (reqBody != nullptr)
        mm::KFree(reqBody); // request body consumed synchronously by the executor

    JsValue out;
    if (!ok)
    {
        out = MakeResult(I, false, "EIO: fetch failed");
    }
    else
    {
        JsObject* o = ObjNew(I.arena, false);
        if (o == nullptr)
        {
            mm::KFree(body);
            return JsValue::Undefined();
        }
        ObjSet(o, I.arena, "ok", 2, JsValue::Bool(true));
        ObjSet(o, I.arena, "status", 6, JsValue::Int(static_cast<duetos::i64>(fres.status)));
        JsString* s = MakeString(I.arena, fres.body, fres.bodyLen);
        if (s != nullptr)
            ObjSet(o, I.arena, "body", 4, JsValue::Str(s));
        out = JsValue::Obj(o);
    }
    mm::KFree(body);
    return out;
}
// kernel.read(): read-only introspection. Validates + audits the KernelRead
// cap, then — on allow — returns a trivially-safe, already-available kernel
// datum: monotonic uptime in nanoseconds (a number a privileged page can read
// without any capability to mutate state). No path, no side effect.
Result<JsValue> MKernelRead(Interp& I, const JsValue&, const JsValue*, duetos::u32, void* c)
{
    PrivBind* b = static_cast<PrivBind*>(c);
    if (b == nullptr || b->tab == nullptr)
        return MakeResult(I, false, "EPERM: no context");
    const sp::PrivRequest req{sp::Cap::KernelRead, nullptr, 0};
    char canon[8];
    const sp::Verdict v = sp::ValidateRequest(*b->tab, b->roots, req, canon, sizeof(canon));
    char iso[24];
    FormatIso8601(iso, sizeof(iso));
    Audit(b, iso, sp::Cap::KernelRead, "datum=uptimeNs", v.ok);
    if (!v.ok)
        return MakeResult(I, false, v.error);
    JsObject* o = ObjNew(I.arena, false);
    if (o == nullptr)
        return JsValue::Undefined();
    ObjSet(o, I.arena, "ok", 2, JsValue::Bool(true));
    ObjSet(o, I.arena, "uptimeNs", 8, JsValue::Int(static_cast<duetos::i64>(duetos::time::MonotonicNs())));
    return JsValue::Obj(o);
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

void PrivBindingFormatIso8601(char* out, duetos::u32 cap)
{
    FormatIso8601(out, cap);
}

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
