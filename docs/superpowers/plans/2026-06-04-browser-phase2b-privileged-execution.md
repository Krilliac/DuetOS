# Browser Phase 2b — Privileged Execution + Assistant Backend — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `window.duetos.proc.spawn` / `net.fetch` from validate+audit-only into real execution behind the unchanged broker validator, and give the Assistant dock a deterministic local backend with inert LLM transport plumbing.

**Architecture:** An executor-hook — the browser app registers `spawnExec`/`fetchExec` function-pointers on `PrivBind`; the engine validates + audits, then delegates. Validator stays the pure keystone; new `ProcSpawn`/`Net` branches reuse the existing `CanonicalizeAndContain` + `ParseUrl`. Child processes inherit the armed scope's caps (never trusted).

**Tech Stack:** C++23 freestanding kernel; build via `wsl-build` skill (WSL `x86_64-debug`); verification via boot self-tests emitting grep-able `PASS` sentinels (no host test framework — `DUETOS_TIMEOUT=40 tools/qemu/run.sh` headless smoke).

**Dependency graph (parallelization):**
```
Task 0 (shared headers/interfaces)  ── done first, single owner
        │
        ├──> Task A (broker validator)      ┐
        ├──> Task C (priv_exec executors)   ├─ PARALLEL, disjoint files
        └──> Task D (assistant heuristic)    ┘
                    │
                    └──> Task B (binding execution + selftest)  ── integrates A+C
                              │
                              └──> Task E (browser.cpp wiring + build + boot)  ── integrate, single owner
```

---

## Task 0: Shared interfaces (single owner — do first)

**Files:**
- Modify: `kernel/security/privilege/broker.h` (add `url` to `PrivRequest`)
- Modify: `kernel/web/priv_binding.h` (add executor hooks + Fetch req/res structs to `PrivBind`)
- Create: `kernel/apps/browser/assistant_backend.h`

- [ ] **Step 1: Add `url` field to `PrivRequest`** in `broker.h`, after `byteLen`:

```cpp
struct PrivRequest
{
    Cap cap;
    const char* path = nullptr; // required for fs caps; spawn target for ProcSpawn
    duetos::u32 byteLen = 0;    // for fs.write
    const char* url = nullptr;  // required for Net (fetch target)
};
```

- [ ] **Step 2: Add executor hooks to `PrivBind`** in `priv_binding.h`. Add a forward `#include "security/privilege/scope.h"` is already present. Insert above `struct PrivBind`:

```cpp
// Fetch request/response marshalled across the executor hook. The binding owns
// `body` storage in both directions (a bounded bounce buffer); the executor
// fills `out->body` (up to `out->bodyCap`) and sets bodyLen/status/ok.
struct FetchReq
{
    const char* url = nullptr;
    const char* method = "GET";      // "GET" | "POST"
    const char* body = nullptr;      // POST body (may be null)
    duetos::u32 bodyLen = 0;
    const char* contentType = nullptr;
};
struct FetchRes
{
    char* body = nullptr;            // caller-owned buffer (binding provides)
    duetos::u32 bodyCap = 0;         // capacity of body
    duetos::u32 bodyLen = 0;         // bytes the executor wrote
    duetos::u32 status = 0;          // HTTP status
    bool ok = false;
};

// Spawn executor: read+load `canonPath` from an exec root, spawn with caps
// derived from `armedScope` (child <= broker). Returns child pid (>0) or -errno.
using SpawnExec = duetos::i64 (*)(const char* canonPath, const char* const* argv, duetos::u32 argc,
                                  const duetos::security::privilege::CapSet& armedScope, void* ctx);
// Fetch executor: run `req` over the browser's page-fetch transport. Returns true on
// transport success (out->status/body filled); false on transport/connect failure.
using FetchExec = bool (*)(const FetchReq& req, FetchRes* out, void* ctx);
```

  Then add three fields to `struct PrivBind` (after `client`):

```cpp
    SpawnExec spawnExec = nullptr; // null => proc.spawn validate+audit only (no exec)
    FetchExec fetchExec = nullptr; // null => net.fetch  validate+audit only (no exec)
    void* execCtx = nullptr;       // opaque ctx passed to the executors
```

- [ ] **Step 3: Create `assistant_backend.h`** — the one-method backend interface:

```cpp
#pragma once
#include "util/types.h"

/*
 * DuetOS browser — Assistant dock backend (spec Phase 2b §7). One method:
 * map a user message to a reply string. v1 ships a deterministic LocalHeuristic
 * (assistant_heuristic.cpp); a RemoteLlm seam routes through the privileged
 * net.fetch executor but is inert in v1 (no secret-store for an API key).
 */
namespace duetos::apps::browser
{
// Write a reply for `userMsg` into `out` (NUL-terminated, <= cap). Returns true
// if a reply was produced (always true for LocalHeuristic — it has a fallback).
bool AssistantRespond(const char* userMsg, char* out, duetos::u32 cap);

void AssistantHeuristicSelfTest();
} // namespace duetos::apps::browser
```

- [ ] **Step 4: Commit**

```bash
git add kernel/security/privilege/broker.h kernel/web/priv_binding.h kernel/apps/browser/assistant_backend.h
git commit -m "feat(browser/priv): Phase 2b shared interfaces — PrivRequest.url, PrivBind executor hooks, AssistantBackend"
```

---

## Task A: Broker validator extension (PARALLEL — owns `broker.cpp`, `broker_selftest.cpp`)

**Files:**
- Modify: `kernel/security/privilege/broker.cpp` (add `ProcSpawn` + `Net` branches)
- Modify: `kernel/security/privilege/broker_selftest.cpp` (new cases)

Reference: `ParseUrl` is declared in `kernel/net/http.h` (`bool ParseUrl(const char* url, bool* scheme_https, char* host, u32 host_cap, u16* port, char* path, u32 path_cap)`). `CanonicalizeAndContain` is in `scope.h`.

- [ ] **Step 1: Add the two branches** to `ValidateRequest` in `broker.cpp`, after the existing fs block (before `return Verdict{true, ""}`):

```cpp
    // 5: proc.spawn — the target must canonicalise + contain within the exec
    //    roots (v1: exec-roots == scoped-roots, spec §13.6). Reuses the fs keystone.
    if (r.cap == Cap::ProcSpawn)
    {
        if (r.path == nullptr)
            return Verdict{false, "EINVAL: null spawn path"};
        if (!CanonicalizeAndContain(r.path, roots, canonOut, cap))
            return Verdict{false, "EPERM: spawn target outside exec roots"};
    }

    // 6: net.fetch — the URL must parse as http/https with a non-empty host.
    //    Arbitrary hosts are allowed (same policy as a page fetch, §13.6); the
    //    kernel firewall remains the final net authority.
    if (r.cap == Cap::Net)
    {
        if (r.url == nullptr || r.url[0] == '\0')
            return Verdict{false, "EINVAL: null url"};
        bool https = false;
        char host[256];
        duetos::u16 port = 0;
        char path[1024];
        if (!duetos::net::http::ParseUrl(r.url, &https, host, sizeof(host), &port, path, sizeof(path)) ||
            host[0] == '\0')
            return Verdict{false, "EINVAL: malformed url"};
    }
```

  Add `#include "net/http.h"` at the top of `broker.cpp`.

- [ ] **Step 2: Extend `broker_selftest.cpp`** with the new cases. Find the existing test harness pattern (armed `PrivTab` + `Roots` with a known root like `/home/user`) and add:

```cpp
    // proc.spawn containment
    {
        const PrivRequest ok{Cap::ProcSpawn, "/home/user/bin/t.elf", 0, nullptr};
        char canon[512];
        if (!ValidateRequest(armed, roots, ok, canon, sizeof(canon)).ok)
            STFAIL("spawn-inroot-allow");
        const PrivRequest esc{Cap::ProcSpawn, "/home/user/../etc/x", 0, nullptr};
        if (ValidateRequest(armed, roots, esc, canon, sizeof(canon)).ok)
            STFAIL("spawn-escape-deny");
        const PrivRequest dev{Cap::ProcSpawn, "/dev/sda", 0, nullptr};
        if (ValidateRequest(armed, roots, dev, canon, sizeof(canon)).ok)
            STFAIL("spawn-devnode-deny");
    }
    // net.fetch url shape
    {
        char canon[8];
        const PrivRequest good{Cap::Net, nullptr, 0, "https://api.example.com/x"};
        if (!ValidateRequest(armed, roots, good, canon, sizeof(canon)).ok)
            STFAIL("net-https-allow");
        const PrivRequest bad{Cap::Net, nullptr, 0, "ftp://nope"};
        if (ValidateRequest(armed, roots, bad, canon, sizeof(canon)).ok)
            STFAIL("net-nonhttp-deny");
        const PrivRequest empty{Cap::Net, nullptr, 0, ""};
        if (ValidateRequest(armed, roots, empty, canon, sizeof(canon)).ok)
            STFAIL("net-empty-deny");
    }
```

  (Match the file's actual `STFAIL`/assert macro and `armed`/`roots` fixture names — read the file first. Emit the existing `PASS` sentinel line unchanged.)

- [ ] **Step 3: Commit**

```bash
git add kernel/security/privilege/broker.cpp kernel/security/privilege/broker_selftest.cpp
git commit -m "feat(browser/priv): broker validator — ProcSpawn exec-root containment + Net url-shape checks"
```

---

## Task C: Privileged executors (PARALLEL — owns `kernel/apps/browser/priv_exec.{h,cpp}`)

**Files:**
- Create: `kernel/apps/browser/priv_exec.h`
- Create: `kernel/apps/browser/priv_exec.cpp`

Reference patterns: `kernel/apps/files.cpp:1040-1056` (Fat32 read into staging → `SpawnPeFile`/`SpawnElfFile`); `kernel/apps/browser.cpp:1700-1745` (`OpenTransport` → `HttpRequestSpec` → `HttpRequest` → `CloseTransport`). Cap bits: `core::CapSet`, `kCapFsRead/kCapFsWrite/kCapSpawnThread/kCapNet` (grep `kCap` in `kernel/proc/process.h`).

- [ ] **Step 1: `priv_exec.h`** — declare the two executors matching the Task 0 hook signatures:

```cpp
#pragma once
#include "util/types.h"
#include "web/priv_binding.h" // FetchReq/FetchRes, SpawnExec/FetchExec signatures

namespace duetos::apps::browser
{
// Matches web::priv::SpawnExec. Reads canonPath from FAT32, sniffs PE/ELF, spawns
// with caps derived from armedScope (child <= broker). Returns pid (>0) or -errno.
duetos::i64 PrivSpawnExec(const char* canonPath, const char* const* argv, duetos::u32 argc,
                          const duetos::security::privilege::CapSet& armedScope, void* ctx);

// Matches web::priv::FetchExec. Runs req over the browser page-fetch transport.
bool PrivFetchExec(const duetos::web::priv::FetchReq& req, duetos::web::priv::FetchRes* out, void* ctx);
} // namespace duetos::apps::browser
```

- [ ] **Step 2: `priv_exec.cpp` — spawn executor.** Map caps (child ⊆ broker), read FAT32, sniff magic, spawn:

```cpp
#include "apps/browser/priv_exec.h"
#include "fs/fat32.h"
#include "mm/kheap.h"
#include "proc/spawn.h"

namespace duetos::apps::browser
{
namespace sp = duetos::security::privilege;

namespace
{
// armed scope (sp::CapSet) -> kernel CapSet. Child is never more capable than the
// broker: only bits present in armedScope are granted.
duetos::core::CapSet MapCaps(const sp::CapSet& s)
{
    duetos::core::CapSet c{}; // empty
    if (s.Has(sp::Cap::FsRead))    c.Add(duetos::core::kCapFsRead);
    if (s.Has(sp::Cap::FsWrite))   c.Add(duetos::core::kCapFsWrite);
    if (s.Has(sp::Cap::ProcSpawn)) c.Add(duetos::core::kCapSpawnThread);
    if (s.Has(sp::Cap::Net))       c.Add(duetos::core::kCapNet);
    return c;
}
constexpr duetos::u32 kMaxSpawnImageBytes = 8u * 1024u * 1024u;
} // namespace

duetos::i64 PrivSpawnExec(const char* canonPath, const char* const* /*argv*/, duetos::u32 /*argc*/,
                          const sp::CapSet& armedScope, void* /*ctx*/)
{
    namespace fat = duetos::fs::fat32;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr) return -5; // -EIO
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, canonPath, &e) || (e.attributes & 0x10) != 0)
        return -2; // -ENOENT
    if (e.size_bytes == 0 || e.size_bytes > kMaxSpawnImageBytes)
        return -22; // -EINVAL
    duetos::u8* buf = static_cast<duetos::u8*>(mm::KMalloc(e.size_bytes));
    if (buf == nullptr) return -12; // -ENOMEM
    const duetos::i64 n = fat::Fat32ReadFile(v, &e, buf, e.size_bytes);
    if (n < 0) { mm::KFree(buf); return -5; }
    const duetos::core::CapSet caps = MapCaps(armedScope);
    // GAP: argv not delivered to child — SpawnPe/ElfFile carry no argv vector yet;
    // revisit when the spawn ABI gains one.
    duetos::u64 pid = 0;
    if (n >= 2 && buf[0] == 'M' && buf[1] == 'Z')
        pid = duetos::core::SpawnPeFile(canonPath, buf, static_cast<duetos::u64>(n), caps, nullptr, 0, 0);
    else if (n >= 4 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F')
        pid = duetos::core::SpawnElfFile(canonPath, buf, static_cast<duetos::u64>(n), caps, nullptr, 0, 0);
    else { mm::KFree(buf); return -22; }
    mm::KFree(buf);
    return (pid == 0) ? -8 : static_cast<duetos::i64>(pid); // -ENOEXEC on spawn failure
}
```

  (Confirm `SpawnPeFile`/`SpawnElfFile` exact arg order against `kernel/proc/spawn.h` — the `nullptr` is the `RamfsNode* root`, `0,0` are frame/tick budgets; copy the working call from `files.cpp` if budgets must be non-zero.)

- [ ] **Step 3: `priv_exec.cpp` — fetch executor.** Reuse the page-fetch transport. **Read `browser.cpp:1700-1745` and copy the real `OpenTransport`/`CloseTransport` calls** — if `OpenTransport` is file-static in `browser.cpp`, this executor must live in `browser.cpp` instead (note that in the implementation and move the function there). Skeleton:

```cpp
#include "net/http.h"
// ... (transport open/close helpers — see browser.cpp)

bool PrivFetchExec(const duetos::web::priv::FetchReq& req, duetos::web::priv::FetchRes* out, void* /*ctx*/)
{
    if (out == nullptr || req.url == nullptr) return false;
    bool https = false; char host[256]; duetos::u16 port = 0; char path[1024];
    if (!net::http::ParseUrl(req.url, &https, host, sizeof(host), &port, path, sizeof(path)))
        return false;
    net::http::HttpTransport transport{};
    /* OpenTransport(https, host, port, &transport, &sock, &tls) — see browser.cpp */
    net::http::HttpRequestSpec spec{};
    spec.method = (req.method != nullptr && req.method[0] == 'P') ? net::http::HttpMethod::Post
                                                                  : net::http::HttpMethod::Get;
    spec.scheme_https = https;
    StrCopyCap(spec.host, sizeof(spec.host), host);
    spec.port = port;
    StrCopyCap(spec.path, sizeof(spec.path), path);
    spec.user_agent = "DuetOS-Browser/0.2";
    if (spec.method == net::http::HttpMethod::Post)
    {
        spec.content_type = req.contentType;
        spec.body = reinterpret_cast<const duetos::u8*>(req.body);
        spec.body_len = req.bodyLen;
    }
    spec.body_buf = reinterpret_cast<duetos::u8*>(out->body);
    spec.body_cap = out->bodyCap;
    net::http::HttpResult result{};
    const bool ok = net::http::HttpRequest(spec, &transport, &result);
    /* CloseTransport(...) */
    out->status = result.status_code;
    out->bodyLen = result.body_len;
    out->ok = ok && result.error == net::http::HttpError::None;
    return out->ok;
}
```

  Mark every reused-but-not-yet-verified call site; do NOT invent a parallel transport — reuse browser.cpp's. If reuse forces the executor into `browser.cpp`, do that and have `priv_exec.h` just declare it.

- [ ] **Step 4: Commit**

```bash
git add kernel/apps/browser/priv_exec.h kernel/apps/browser/priv_exec.cpp
git commit -m "feat(browser/priv): privileged spawn + fetch executors (child<=broker caps; reuses page-fetch transport)"
```

---

## Task D: Assistant heuristic backend (PARALLEL — owns assistant files)

**Files:**
- Create: `kernel/apps/browser/assistant_heuristic.cpp`
- Create: `kernel/apps/browser/assistant_heuristic_selftest.cpp` (or append to an existing browser selftest TU — check first)

- [ ] **Step 1: `assistant_heuristic.cpp`** — deterministic responder, small fixed intent set + fallback:

```cpp
#include "apps/browser/assistant_backend.h"

namespace duetos::apps::browser
{
namespace
{
bool Eq(const char* a, const char* b) { while (*a && *b) { if (*a++ != *b++) return false; } return *a == *b; }
bool StartsWith(const char* s, const char* p) { while (*p) { if (*s++ != *p++) return false; } return true; }
duetos::u32 Copy(char* out, duetos::u32 cap, const char* s)
{
    duetos::u32 i = 0; for (; s[i] && i + 1 < cap; ++i) out[i] = s[i]; out[i] = '\0'; return i;
}
} // namespace

bool AssistantRespond(const char* userMsg, char* out, duetos::u32 cap)
{
    if (out == nullptr || cap == 0) return false;
    if (userMsg == nullptr || userMsg[0] == '\0' || Eq(userMsg, "help"))
    {
        Copy(out, cap, "I can: open <url>, report page status. (local mode — no LLM yet)");
        return true;
    }
    if (StartsWith(userMsg, "open "))
    {
        // Emit a navigate intent; the dock host performs the navigation.
        Copy(out, cap, "navigate:");
        const char* url = userMsg + 5;
        duetos::u32 n = 0; while (out[n]) ++n;
        Copy(out + n, cap - n, url);
        return true;
    }
    if (Eq(userMsg, "status") || Eq(userMsg, "arm?"))
    {
        Copy(out, cap, "status:requested"); // host fills live page/arm state on render
        return true;
    }
    Copy(out, cap, "I can't do that locally yet. Try `help`.");
    return true;
}
```

- [ ] **Step 2: `assistant_heuristic_selftest.cpp`** — assert each intent:

```cpp
#include "apps/browser/assistant_backend.h"
#include "arch/x86_64/serial.h" // arch::SerialWrite — match the project's selftest pattern

namespace duetos::apps::browser
{
namespace
{
bool Has(const char* s, const char* sub)
{
    for (; *s; ++s) { const char* a = s; const char* b = sub; while (*a && *b && *a == *b) { ++a; ++b; } if (!*b) return true; }
    return false;
}
} // namespace

void AssistantHeuristicSelfTest()
{
    char buf[128];
    bool ok = true;
    AssistantRespond("help", buf, sizeof(buf));      ok = ok && Has(buf, "open");
    AssistantRespond("", buf, sizeof(buf));           ok = ok && Has(buf, "open");
    AssistantRespond("open https://x.test", buf, sizeof(buf)); ok = ok && Has(buf, "navigate:");
    AssistantRespond("zzz", buf, sizeof(buf));        ok = ok && Has(buf, "Try");
    if (ok)
        arch::SerialWrite("[assistant-heuristic-selftest] PASS\n");
    else
        arch::SerialWrite("[assistant-heuristic-selftest] FAIL\n");
}
} // namespace duetos::apps::browser
```

  (Match the real serial-write/selftest idiom used by `priv_chrome_selftest.cpp` — read it first for the exact include + sentinel format.)

- [ ] **Step 3: Commit**

```bash
git add kernel/apps/browser/assistant_heuristic.cpp kernel/apps/browser/assistant_heuristic_selftest.cpp
git commit -m "feat(browser): local heuristic Assistant backend + selftest"
```

---

## Task B: Binding execution (integrates A + C — owns `priv_binding.cpp`, `priv_binding_selftest.cpp`)

**Files:**
- Modify: `kernel/web/priv_binding.cpp` (`MProcSpawn`/`MNetFetch` → real)
- Modify: `kernel/web/priv_binding_selftest.cpp` (mock executors)

- [ ] **Step 1: Rewrite `MProcSpawn`** to plumb args + call the executor. Replace the `CapValidate(...)` body for spawn:

```cpp
Result<JsValue> MProcSpawn(Interp& I, const JsValue&, const JsValue* a, duetos::u32 n, void* c)
{
    PrivBind* b = static_cast<PrivBind*>(c);
    if (b == nullptr || b->tab == nullptr) return MakeResult(I, false, "EPERM: no context");
    char path[512];
    const duetos::u32 plen = (n > 0) ? ValueToChars(a[0], path, sizeof(path) - 1) : 0;
    path[plen] = '\0';
    char canon[512];
    const sp::PrivRequest req{sp::Cap::ProcSpawn, (n > 0) ? path : nullptr, 0, nullptr};
    const sp::Verdict v = sp::ValidateRequest(*b->tab, b->roots, req, canon, sizeof(canon));
    char iso[24]; FormatIso8601(iso, sizeof(iso));
    char summ[80]; /* "path=<canon>,argc=0" */ /* build bounded summary */
    Audit(b, iso, sp::Cap::ProcSpawn, summ, v.ok);
    if (!v.ok) return MakeResult(I, false, v.error);
    if (b->spawnExec == nullptr) return MakeResult(I, v.ok, v.error); // validate-only fallback
    const duetos::i64 pid = b->spawnExec(canon, nullptr, 0, b->tab->scope, b->execCtx);
    if (pid < 0) return MakeResult(I, false, "EIO: spawn failed");
    JsObject* o = ObjNew(I.arena, false);
    if (o == nullptr) return JsValue::Undefined();
    ObjSet(o, I.arena, "ok", 2, JsValue::Bool(true));
    ObjSet(o, I.arena, "pid", 3, JsValue::Int(pid));
    return JsValue::Obj(o);
}
```

- [ ] **Step 2: Rewrite `MNetFetch`** to plumb url + opts + call the executor:

```cpp
Result<JsValue> MNetFetch(Interp& I, const JsValue&, const JsValue* a, duetos::u32 n, void* c)
{
    PrivBind* b = static_cast<PrivBind*>(c);
    if (b == nullptr || b->tab == nullptr) return MakeResult(I, false, "EPERM: no context");
    char url[1024];
    const duetos::u32 ulen = (n > 0) ? ValueToChars(a[0], url, sizeof(url) - 1) : 0;
    url[ulen] = '\0';
    char canon[8];
    const sp::PrivRequest req{sp::Cap::Net, nullptr, 0, (n > 0) ? url : nullptr};
    const sp::Verdict v = sp::ValidateRequest(*b->tab, b->roots, req, canon, sizeof(canon));
    char iso[24]; FormatIso8601(iso, sizeof(iso));
    Audit(b, iso, sp::Cap::Net, "url=<redacted-in-summary>,method=GET", v.ok);
    if (!v.ok) return MakeResult(I, false, v.error);
    if (b->fetchExec == nullptr) return MakeResult(I, v.ok, v.error); // validate-only fallback
    constexpr duetos::u32 kFetchBodyCap = 256u * 1024u;
    char* body = static_cast<char*>(mm::KMalloc(kFetchBodyCap));
    if (body == nullptr) return MakeResult(I, false, "EIO: no memory");
    FetchReq fr{}; fr.url = url; fr.method = "GET"; // POST opts parsed from a[1] in a follow-up
    FetchRes res{}; res.body = body; res.bodyCap = kFetchBodyCap;
    const bool ok = b->fetchExec(fr, &res, b->execCtx);
    JsValue out;
    if (!ok) out = MakeResult(I, false, "EIO: fetch failed");
    else
    {
        JsObject* o = ObjNew(I.arena, false);
        if (o == nullptr) { mm::KFree(body); return JsValue::Undefined(); }
        ObjSet(o, I.arena, "ok", 2, JsValue::Bool(true));
        ObjSet(o, I.arena, "status", 6, JsValue::Int(static_cast<duetos::i64>(res.status)));
        JsString* s = MakeString(I.arena, res.body, res.bodyLen);
        if (s != nullptr) ObjSet(o, I.arena, "body", 4, JsValue::Str(s));
        out = JsValue::Obj(o);
    }
    mm::KFree(body);
    return out;
}
```

  Keep the `CapValidate` helper for any remaining argless caps, or delete it if now unused (it is — `kernel.read` has `MKernelRead`; `proc`/`net` now have real impls). Remove the now-stale GAP comment at lines 272-277. Add `#include "mm/kheap.h"` if not present (it is).

- [ ] **Step 3: Add mock-executor cases to `priv_binding_selftest.cpp`.** Define file-static mocks that record being called, register them on a test `PrivBind`, and assert reach/no-reach:

```cpp
static int g_spawn_calls = 0;
static duetos::i64 MockSpawn(const char*, const char* const*, duetos::u32,
                             const sp::CapSet&, void*) { ++g_spawn_calls; return 4242; }
static int g_fetch_calls = 0;
static bool MockFetch(const FetchReq&, FetchRes* o, void*)
{ ++g_fetch_calls; o->status = 200; o->bodyLen = 0; o->ok = true; return true; }
```

  Assertions (match the file's existing harness + sentinel):
  - armed + in-scope `proc.spawn("/home/user/x.elf")` → `g_spawn_calls == 1`, result `ok` with `pid == 4242`.
  - **disarm the tab**, repeat → `g_spawn_calls` unchanged (executor NOT reached), result `EPERM`.
  - out-of-root spawn path while armed → executor NOT reached, `EPERM`.
  - armed `net.fetch("https://x.test")` → `g_fetch_calls == 1`, `ok`.
  - malformed-url fetch → executor NOT reached, `EINVAL`.

- [ ] **Step 4: Commit**

```bash
git add kernel/web/priv_binding.cpp kernel/web/priv_binding_selftest.cpp
git commit -m "feat(browser/priv): proc.spawn + net.fetch execute via executor hooks (validate->audit->exec); mock-executor selftests"
```

---

## Task E: Wiring + build + boot (integrate — single owner)

**Files:**
- Modify: `kernel/apps/browser.cpp` (register executors on arm; clear on disarm; dock input → AssistantRespond)
- Modify: CMake (add `priv_exec.cpp`, `assistant_heuristic.cpp`, selftests to the kernel sources list)
- Modify: boot self-test hook list (call `AssistantHeuristicSelfTest` where the other browser selftests are invoked)
- Modify: `wiki/kernel/Privileged-Origin.md` (GAP→real)

- [ ] **Step 1: Register executors on arm.** In `browser.cpp` near line 2647 (where `g_priv_bind.tab`/`.roots` are set), add:

```cpp
    g_priv_bind.spawnExec = &duetos::apps::browser::PrivSpawnExec;
    g_priv_bind.fetchExec = &duetos::apps::browser::PrivFetchExec;
    g_priv_bind.execCtx = nullptr; // executors are stateless v1
```

  `#include "apps/browser/priv_exec.h"`. They are cleared automatically by the existing `g_priv_bind = PrivBind{};` reset on disarm.

- [ ] **Step 2: Wire the Assistant dock input** to `AssistantRespond` (find where `g_assistant` text is rendered / where the omnibox/dock input events arrive). Minimal: on Enter in the assistant input, call `AssistantRespond(input, reply, cap)` and append `reply` to the surface body. If `reply` starts with `navigate:` perform the navigation via the existing nav entrypoint.

- [ ] **Step 3: Add the new TUs to CMake.** Grep the kernel `CMakeLists.txt` for `priv_binding.cpp` / `priv_chrome_selftest.cpp` and add the four new files alongside. Add `AssistantHeuristicSelfTest()` to the boot self-test invocation list (grep for `PrivBindingSelfTest()` call site).

- [ ] **Step 4: Build via wsl-build skill.** Expect zero warnings, zero errors.

- [ ] **Step 5: Boot smoke.** `DUETOS_TIMEOUT=40 tools/qemu/run.sh` headless. Assert all selftest PASS sentinels present: `broker-selftest`, `priv-binding ... selftest`, `assistant-heuristic-selftest PASS`. Assert no `PANIC`/`[E]`/`FAIL`. Run `tools/test/boot-log-analyze.sh` on the log.

- [ ] **Step 6: Update wiki** `Privileged-Origin.md` — flip the proc.spawn/net.fetch rows from "validate+audit only (GAP)" to "executes via executor-hook"; document the child-caps rule and the carried GAPs (argv, RemoteLlm inert).

- [ ] **Step 7: Final commit**

```bash
git add -A
git commit -m "feat(browser/priv): wire executors on arm + Assistant dock backend; CMake + boot selftests + wiki"
```

---

## Self-review notes

- **Spec coverage:** §4 validator→Task A; §5 binding→Task B; §6 executors→Task C; §7 assistant→Task D; §3 hooks→Task 0; wiring/§8 tests→Tasks B/E; §9 security asserted in B+A selftests; §10 GAPs pinned in C (argv) + D (RemoteLlm). All covered.
- **Type consistency:** `SpawnExec`/`FetchExec`/`FetchReq`/`FetchRes` defined once in Task 0 `priv_binding.h`; Tasks C/B/E reference them unchanged. `AssistantRespond` signature identical in Task 0 header and Tasks D/E.
- **RemoteLlm:** Spec §7 names a `RemoteLlm` seam; v1 keeps it inert — the seam is the `fetchExec` plumbing already built in C, so no separate dead class is created (anti-bloat). The GAP marker lives where the seam would activate. Documented, not stubbed-as-dead-code.
- **POST opts:** `net.fetch` v1 wires GET end-to-end; POST body/contentType parsing from `a[1]` is a one-method follow-up noted in Task B step 2 — the executor (C) already accepts POST so the seam is complete on the transport side.
