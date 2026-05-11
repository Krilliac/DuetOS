#pragma once

#include "util/types.h"

/*
 * DuetOS — saturating integer arithmetic, v0.
 *
 * WHY THIS EXISTS
 *   wiki/security/Linux-CVE-Audit.md classes M (AML pkg_end wrap),
 *   N (Spectre-v1 OOB after bypassed bounds check), and O (refcount
 *   wraps to UAF) are all rooted in integer overflow / underflow.
 *   The general defensive position is "every arithmetic operation
 *   that touches an attacker-influenced value should be checked,"
 *   but C++ has no operator-overload way to intercept the built-in
 *   `+ - * / % ++` on primitive integer types. The realistic shape
 *   is opt-in:
 *
 *     u64 size = util::SatMul(n_entries, sizeof(Entry));   // clamps
 *     util::SatU32 refcount;
 *     ++refcount;                                          // clamps
 *     refcount -= 1;                                       // clamps to 0
 *
 *   Wrap any size / count / index / refcount in `SatU8/16/32/64`
 *   (or call the explicit `SatAdd/Sub/Mul`) and the value is
 *   clamped instead of wrapping, with a klog warning emitted on
 *   every clamp event including the caller RIP (via
 *   `__builtin_return_address(0)`).
 *
 * WHAT IT GUARANTEES
 *   - Add overflow → clamp to type max, log WARN with caller RIP.
 *   - Sub underflow → clamp to 0 (for unsigned) / type min (signed
 *     not in v0), log WARN with caller RIP.
 *   - Mul overflow → clamp to type max, log WARN with caller RIP.
 *   - Inc / Dec via `++` / `--` route through the same paths.
 *
 * WHAT IT DOES NOT
 *   - Intercept raw `u32 x = a + b;` — caller has to use the
 *     helper or the wrapper type.
 *   - Provide signed semantics in v0 (every consumer in the audit
 *     was unsigned; signed is a follow-on if/when needed).
 *   - Detect *all* overflows kernel-wide; UBSAN does that and is
 *     wired separately (`kernel/diag/ubsan.cpp`).
 *
 * COMPLEMENTS, NOT REPLACES:
 *   - UBSAN traps (already in tree) — they panic; this clamps and
 *     keeps going with a log. Use UBSAN for "must never happen"
 *     paths, Sat for "could happen, recover and warn."
 *   - `util::nospec.h::RefcountIncSaturating` — that one is
 *     branchless and lock-protected. SatU32 here is the
 *     general-purpose version for non-refcount values.
 *
 * CONTEXT
 *   Kernel. Safe in any context — no allocation, no locks. The
 *   warning emit uses klog, which itself is IRQ-safe.
 */

namespace duetos::util
{

// Forward decl of the diagnostic helper. Defined in saturating.cpp.
// Logs one klog WARN line including the symbol of the calling
// function (resolved via util/symbols.h). `tag` is one of "add",
// "sub", "mul", "inc", "dec"; `attempted` is the value before
// clamping; `clamped` is the value after.
void SatLogClamp(const char* tag, u64 attempted, u64 clamped, void* caller_rip);

// ---------------------------------------------------------------
// Free-function operations on plain primitives.
// ---------------------------------------------------------------

template <typename T> [[nodiscard]] inline T SatAdd(T a, T b)
{
    static_assert(sizeof(T) <= 8, "SatAdd: T too wide");
    T result;
    if (__builtin_add_overflow(a, b, &result))
    {
        const T maxv = static_cast<T>(~static_cast<T>(0));
        SatLogClamp("add", static_cast<u64>(a) + static_cast<u64>(b), static_cast<u64>(maxv),
                    __builtin_return_address(0));
        return maxv;
    }
    return result;
}

template <typename T> [[nodiscard]] inline T SatSub(T a, T b)
{
    static_assert(sizeof(T) <= 8, "SatSub: T too wide");
    T result;
    if (__builtin_sub_overflow(a, b, &result))
    {
        SatLogClamp("sub", static_cast<u64>(a), 0, __builtin_return_address(0));
        return 0;
    }
    return result;
}

template <typename T> [[nodiscard]] inline T SatMul(T a, T b)
{
    static_assert(sizeof(T) <= 8, "SatMul: T too wide");
    T result;
    if (__builtin_mul_overflow(a, b, &result))
    {
        const T maxv = static_cast<T>(~static_cast<T>(0));
        SatLogClamp("mul", static_cast<u64>(a) * static_cast<u64>(b), static_cast<u64>(maxv),
                    __builtin_return_address(0));
        return maxv;
    }
    return result;
}

// ---------------------------------------------------------------
// SMP-safe saturating increment for atomically-shared counters.
//
// WHY THIS EXISTS
//   The wrapper Saturating<T> + the free SatAdd helpers above are
//   single-threaded — wrapping a counter that real kernel code
//   touches with `__atomic_add_fetch` would silently strip the
//   atomicity. Wrap with SatAtomicAdd instead: a CAS loop loads
//   the current value, computes the saturated sum, and commits
//   atomically. On overflow it clamps to type-max and emits the
//   same SatLogClamp WARN as the single-threaded path.
//
// USE WHEN
//   - The counter is shared across CPUs / IRQ context, AND
//   - The semantics tolerate stalling at the cap (every event
//     past the cap registers as "still at max"; loss of finer
//     count is the price of not-wrapping).
//
// DO NOT USE WHEN
//   - The counter participates in modular arithmetic (ring
//     write/read indices, ticket-lock counters, sequence numbers
//     used as `idx % cap`) — those need plain wrap.
//   - You need fetch-then-CAS semantics for some other reason.
//
// MEMORY ORDER
//   RELAXED on both load and store. Saturating counters are
//   diagnostic / liveness — the only invariant is "monotonic and
//   bounded." If a future caller needs ordering against unrelated
//   memory, take SEQ_CST locally around it.
template <typename T> inline T SatAtomicAdd(T* p, T n)
{
    static_assert(sizeof(T) <= 8, "SatAtomicAdd: T too wide");
    const T maxv = static_cast<T>(~static_cast<T>(0));
    T cur = __atomic_load_n(p, __ATOMIC_RELAXED);
    while (true)
    {
        T next;
        const bool overflow = __builtin_add_overflow(cur, n, &next);
        if (overflow)
        {
            next = maxv;
        }
        // CAS publishes `next`; on failure `cur` reloads with
        // the actual value seen and we retry. The single-shot
        // overflow log fires only on the iteration that actually
        // commits, so SMP contention can't multiply the WARN
        // count.
        if (__atomic_compare_exchange_n(p, &cur, next, /*weak=*/false, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        {
            if (overflow)
            {
                SatLogClamp("atom-add", static_cast<u64>(cur) + static_cast<u64>(n), static_cast<u64>(maxv),
                            __builtin_return_address(0));
            }
            return next;
        }
    }
}

// ---------------------------------------------------------------
// Wrapper types — drop-in replacement for plain unsigned ints
// that auto-clamp on every operator. Trivially constructible
// and copyable; lays out as the underlying type so SatU32 in a
// struct is wire-compatible with u32.
// ---------------------------------------------------------------

template <typename T> struct Saturating
{
    T value;

    constexpr Saturating() = default;
    constexpr Saturating(T v) : value(v) {}
    constexpr operator T() const { return value; }

    Saturating& operator+=(T rhs)
    {
        value = SatAdd<T>(value, rhs);
        return *this;
    }
    Saturating& operator-=(T rhs)
    {
        value = SatSub<T>(value, rhs);
        return *this;
    }
    Saturating& operator*=(T rhs)
    {
        value = SatMul<T>(value, rhs);
        return *this;
    }
    Saturating& operator++()
    {
        if (value == static_cast<T>(~static_cast<T>(0)))
        {
            SatLogClamp("inc", static_cast<u64>(value) + 1, static_cast<u64>(value), __builtin_return_address(0));
        }
        else
        {
            ++value;
        }
        return *this;
    }
    Saturating operator++(int)
    {
        Saturating old = *this;
        ++(*this);
        return old;
    }
    Saturating& operator--()
    {
        if (value == 0)
        {
            SatLogClamp("dec", 0, 0, __builtin_return_address(0));
        }
        else
        {
            --value;
        }
        return *this;
    }
    Saturating operator--(int)
    {
        Saturating old = *this;
        --(*this);
        return old;
    }
};

using SatU8 = Saturating<u8>;
using SatU16 = Saturating<u16>;
using SatU32 = Saturating<u32>;
using SatU64 = Saturating<u64>;

/// Boot-time self-test. Asserts add/sub/mul clamp correctly for
/// u32 and u64 edges, ++ saturates at max, -- saturates at 0,
/// no spurious clamp warnings on operations safely in range.
void SaturatingSelfTest();

} // namespace duetos::util
