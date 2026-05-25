#pragma once

#include "drivers/video/app_widgets/widget.h"

/*
 * Compile-time-known widget collection for DuetOS apps.
 *
 * Apps declare `WidgetGroup<W1, W2, ...> group{w1, w2, ...};` with their
 * widget set as direct value members. PaintAll iterates back-to-front
 * (declaration order); DispatchEvent iterates front-to-back (reverse
 * declaration order) with first-Consumed-wins semantics.
 *
 * Storage model: recursive inheritance, not std::tuple. The kernel is
 * built -ffreestanding -nostdinc; libc++ headers (<tuple>, <utility>,
 * std::index_sequence) are unreachable. Recursive composition gives us
 * the same compile-time fold without dragging in a tuple primitive we
 * don't have. Each instantiated WidgetGroup<Ws...> is a chain of bases,
 * each holding one widget as a value member — no heap, no virtual
 * dispatch, no per-element overhead beyond the widget itself.
 *
 * Iteration is fold-like via recursive method calls; the compiler
 * inlines the chain at -O1 and above (every Paint / OnEvent call is
 * statically dispatched through the CRTP Self pointer).
 *
 * See docs/superpowers/specs/2026-05-25-duetos-pass-d-design.md.
 */

namespace duetos::drivers::video::app_widgets
{

namespace detail
{

// Recursive-inheritance widget chain. Each node stores ONE widget as
// a public `head` member and recurses into a Tail that holds the rest.
// The empty specialization terminates both the Paint and the dispatch
// folds.
template <typename... Ws> struct WidgetChain;

template <> struct WidgetChain<>
{
    constexpr void PaintEach(Compose&) const
    {
        // Empty fold — nothing to paint.
    }

    constexpr EventResult DispatchReverse(const Event&)
    {
        // Empty fold — no widget interested.
        return EventResult::NotInterested;
    }
};

template <typename Head, typename... Tail> struct WidgetChain<Head, Tail...>
{
    Head head;
    WidgetChain<Tail...> tail;

    constexpr WidgetChain() = default;

    // Pack-expanded constructor: take Head by value, forward the
    // remaining args to the recursive tail.
    constexpr explicit WidgetChain(Head h, Tail... rest)
        : head(static_cast<Head&&>(h)), tail(static_cast<Tail&&>(rest)...)
    {
    }

    constexpr void PaintEach(Compose& c) const
    {
        // Back-to-front: declaration order. `head` is the earliest
        // widget in the parameter pack, so paint it FIRST (it sits
        // visually at the back), then recurse so subsequent widgets
        // land on top.
        head.Paint(c);
        tail.PaintEach(c);
    }

    constexpr EventResult DispatchReverse(const Event& e)
    {
        // Front-to-back with first-Consumed-wins: ask the TAIL first
        // (later-declared widgets are visually on top, so they get
        // first refusal on the event), then fall back to head.
        const EventResult fromTail = tail.DispatchReverse(e);
        if (fromTail == EventResult::Consumed)
        {
            return EventResult::Consumed;
        }
        return head.OnEvent(e);
    }
};

} // namespace detail

/// Compile-time widget collection. Construct with the widgets in
/// back-to-front declaration order:
///
///   WidgetGroup<AppPanel, AppLabel, AppButton> group{
///       AppPanel{...}, AppLabel{...}, AppButton{...}};
///
/// Then call `group.PaintAll(compose)` from the app's draw routine
/// and `group.DispatchEvent(event)` from the app's input routine.
template <typename... Ws> struct WidgetGroup
{
    detail::WidgetChain<Ws...> chain;

    // The variadic constructor IS the default constructor when Ws...
    // is empty, so we do not write `WidgetGroup() = default` — that
    // would collide with the empty-pack instantiation of the variadic
    // form. Likewise we do not mark this `explicit`: when `Ws...` has
    // exactly one element, `explicit` would forbid copy-list-init from
    // a brace pair (which apps will use for the static instance).
    constexpr WidgetGroup(Ws... ws) : chain(static_cast<Ws&&>(ws)...) {}

    /// Paint every widget in declaration (back-to-front) order.
    /// `const` because Paint must not mutate widget state — only
    /// OnEvent does.
    constexpr void PaintAll(Compose& c) const { chain.PaintEach(c); }

    /// Dispatch one input event in reverse declaration (front-to-back)
    /// order. Returns Consumed if any widget claimed the event;
    /// otherwise NotInterested. Non-const because OnEvent may mutate
    /// widget state (hover, pressed, focus).
    constexpr EventResult DispatchEvent(const Event& e) { return chain.DispatchReverse(e); }
};

/// Deduction helper so callers don't have to spell the template
/// parameters: `auto g = MakeWidgetGroup(w1, w2, w3);`.
template <typename... Ws> constexpr auto MakeWidgetGroup(Ws... ws)
{
    return WidgetGroup<Ws...>(static_cast<Ws&&>(ws)...);
}

} // namespace duetos::drivers::video::app_widgets
