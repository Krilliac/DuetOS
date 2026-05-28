#pragma once

#include "util/types.h"

/*
 * DuetOS — DUETOS_DEFER / ScopeGuard.
 *
 * The "cleanup on early return" gap left by `-fno-exceptions`.
 * RAII destructors fire on scope exit, but a sequence of fallible
 * acquisitions threaded through RESULT_TRY needs each acquired
 * resource released only if a LATER step fails — and if every
 * step succeeds, the resources should be HANDED OFF, not released.
 *
 *     Result<KFile*> AttachKFile(...)
 *     {
 *         RESULT_TRY_ASSIGN(KFile* kf, KFileCreate(...));
 *         DUETOS_DEFER(KObjectRelease(&kf->base)); // fires on any
 *                                                  // failure exit
 *                                                  // from here
 *         RESULT_TRY_ASSIGN(Handle h, HandleTableInsert(table, &kf->base));
 *         DUETOS_DEFER(HandleTableRemove(table, h));
 *
 *         // ... more fallible work ...
 *
 *         // Success — disarm both guards so the caller owns the
 *         // KFile + handle they were promised.
 *         _defer_<line>.dismiss();
 *         _defer_<line>.dismiss();
 *         return kf;
 *     }
 *
 * The macro shape mirrors Go's `defer` and Rust's `scopeguard::guard`.
 * A bare `DUETOS_DEFER(stmt)` produces a uniquely-named local
 * `ScopeGuard` whose destructor fires `stmt`; `DUETOS_DEFER_NAMED(g,
 * stmt)` lets the caller pick a stable name for the `g.dismiss()`
 * call.
 *
 * Context: usable in kernel and userland C++23. Lambda capture is
 * `[&]` — the deferred statement sees the surrounding scope by
 * reference, so it can release the exact pointer that was just
 * acquired. The guard is non-copyable, non-movable; it lives in
 * place on the stack from its declaration to scope exit.
 *
 * Cost: one bool + one lambda. The lambda is typically inlined
 * away on release builds; the bool sits in a single byte. Empty
 * if the guard is just `dismiss()`-ed before scope exit.
 */

namespace duetos::util
{

template <typename F> class ScopeGuard
{
  public:
    explicit ScopeGuard(F fn) : m_fn(fn), m_active(true) {}

    ~ScopeGuard()
    {
        if (m_active)
            m_fn();
    }

    // Disarm the guard — the deferred action will NOT fire when the
    // guard goes out of scope. Call this on the success path after
    // every fallible step has succeeded.
    void dismiss() { m_active = false; }

    // Non-copyable, non-movable: the guard owns one cleanup
    // commitment and that commitment lives at exactly one stack
    // address. Moving it would create two guards or transfer
    // ownership in a way that the macro-driven naming convention
    // can't track at the call site.
    ScopeGuard(const ScopeGuard&) = delete;
    ScopeGuard& operator=(const ScopeGuard&) = delete;
    ScopeGuard(ScopeGuard&&) = delete;
    ScopeGuard& operator=(ScopeGuard&&) = delete;

  private:
    F m_fn;
    bool m_active;
};

// Factory used by the macro — lets CTAD deduce F without the caller
// spelling out the lambda type.
template <typename F> ScopeGuard<F> MakeScopeGuard(F fn)
{
    return ScopeGuard<F>(fn);
}

} // namespace duetos::util

// Token-paste helpers — the inner DUETOS_DEFER_CONCAT2 forces the
// __LINE__ expansion before the ## glues the pieces. Without the
// double-indirection the result is `_defer___LINE__` literally.
#define DUETOS_DEFER_CONCAT2(a, b) a##b
#define DUETOS_DEFER_CONCAT(a, b) DUETOS_DEFER_CONCAT2(a, b)

// `DUETOS_DEFER(stmt)` — declares an anonymous (line-unique)
// ScopeGuard whose destructor runs `stmt` on scope exit unless a
// later `dismiss()` retires it. Use the named form below if you
// need to dismiss it.
#define DUETOS_DEFER(...)                                                                                              \
    auto DUETOS_DEFER_CONCAT(_defer_, __LINE__) = ::duetos::util::MakeScopeGuard([&]() { __VA_ARGS__; })

// `DUETOS_DEFER_NAMED(name, stmt)` — same as DUETOS_DEFER but
// binds the guard to `name` so the caller can `name.dismiss()`
// on the success path. Pick names that read as "what I'd undo":
// `release_kf`, `unmap_window`, `drop_ref`.
#define DUETOS_DEFER_NAMED(name, ...) auto name = ::duetos::util::MakeScopeGuard([&]() { __VA_ARGS__; })
