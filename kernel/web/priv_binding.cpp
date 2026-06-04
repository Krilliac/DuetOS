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

JsValue CapValidate(Interp& I, sp::Cap cap, PrivBind* b)
{
    if (b == nullptr || b->tab == nullptr)
        return MakeResult(I, false, "EPERM: no context");
    char canon[8];
    const sp::PrivRequest req{cap, nullptr, 0};
    const sp::Verdict v = sp::ValidateRequest(*b->tab, b->roots, req, canon, sizeof(canon));
    char iso[24];
    FormatIso8601(iso, sizeof(iso));
    Audit(b, iso, cap, "-", v.ok);
    // GAP: proc.spawn / net.fetch validate + audit but do not yet EXECUTE — the
    // JS methods carry no actionable arguments (a spawn target, a fetch URL).
    // Fabricating one from nothing would be speculative; execution awaits these
    // methods gaining real arguments in Phase 2b. The validate + audit is
    // correct and load-bearing today. (kernel.read DOES execute — see MKernelRead.)
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
