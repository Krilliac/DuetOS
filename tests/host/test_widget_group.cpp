// tests/host/test_widget_group.cpp
//
// Pass D Task 6 — WidgetGroup fold-order + first-consumed-wins.
//
// The kernel WidgetGroup is a recursive-inheritance variadic
// template (the freestanding kernel lacks <tuple>), which makes it
// awkward to link against from a host test. Re-derives the
// iteration contract inline against a simple array-backed mock:
//
//   - PaintAll iterates in declaration order (back-to-front), so
//     later siblings appear visually ON TOP of earlier ones.
//   - DispatchEvent iterates in REVERSE declaration order
//     (front-to-back) and short-circuits the moment any widget
//     returns EventResult::Consumed. The visually-topmost widget
//     therefore gets first crack at the event, which matches user
//     expectation for click-to-z-front semantics.
//
// A regression that flips either order, or that walks past a
// Consumed return, will fire here.

#include "host_test_helper.h"

#include <cstdint>
#include <vector>

enum class EventResult : uint8_t
{
    NotInterested = 0U,
    Consumed = 1U,
};

struct PaintTrace
{
    std::vector<int> paint_order;
    std::vector<int> event_order;
};

struct FakeWidget
{
    int id;
    bool consumes;

    void Paint(PaintTrace& t) const
    {
        t.paint_order.push_back(id);
    }

    EventResult OnEvent(PaintTrace& t)
    {
        t.event_order.push_back(id);
        return consumes ? EventResult::Consumed : EventResult::NotInterested;
    }
};

// Mirror the WidgetGroup contract: PaintAll iterates declaration
// order, DispatchEvent iterates REVERSE declaration order with
// first-Consumed-wins short-circuit. The kernel template walks a
// recursive-inheritance chain; the array here is a behavioural
// stand-in only.
struct FakeGroup
{
    std::vector<FakeWidget> widgets;

    void PaintAll(PaintTrace& t) const
    {
        for (const FakeWidget& w : widgets)
        {
            w.Paint(t);
        }
    }

    EventResult DispatchEvent(PaintTrace& t)
    {
        for (auto it = widgets.rbegin(); it != widgets.rend(); ++it)
        {
            const EventResult r = it->OnEvent(t);
            if (r == EventResult::Consumed)
            {
                return EventResult::Consumed;
            }
        }
        return EventResult::NotInterested;
    }
};

int main()
{
    // ----- PaintAll fold order: declaration order 1, 2, 3. -----
    PaintTrace t;
    FakeGroup g{{{1, false}, {2, false}, {3, false}}};

    g.PaintAll(t);
    EXPECT_TRUE(t.paint_order.size() == 3U);
    EXPECT_TRUE(t.paint_order[0] == 1);
    EXPECT_TRUE(t.paint_order[1] == 2);
    EXPECT_TRUE(t.paint_order[2] == 3);

    // ----- DispatchEvent fold order: reverse order 3, 2, 1 when
    //       no widget consumes the event. -----
    const EventResult r1 = g.DispatchEvent(t);
    EXPECT_TRUE(r1 == EventResult::NotInterested);
    EXPECT_TRUE(t.event_order.size() == 3U);
    EXPECT_TRUE(t.event_order[0] == 3);
    EXPECT_TRUE(t.event_order[1] == 2);
    EXPECT_TRUE(t.event_order[2] == 1);

    // ----- First-Consumed-wins short-circuit: widget id=2 consumes,
    //       so the walk stops at 2 and id=1 is NEVER visited. -----
    PaintTrace t2;
    FakeGroup g2{{{1, false}, {2, true}, {3, false}}};
    const EventResult r2 = g2.DispatchEvent(t2);
    EXPECT_TRUE(r2 == EventResult::Consumed);
    EXPECT_TRUE(t2.event_order.size() == 2U); // walked 3 (no), 2 (yes — stop)
    EXPECT_TRUE(t2.event_order[0] == 3);
    EXPECT_TRUE(t2.event_order[1] == 2);

    // ----- Topmost-consumes shortcut: the frontmost widget claims
    //       it, so only one OnEvent fires. -----
    PaintTrace t3;
    FakeGroup g3{{{1, false}, {2, false}, {3, true}}};
    const EventResult r3 = g3.DispatchEvent(t3);
    EXPECT_TRUE(r3 == EventResult::Consumed);
    EXPECT_TRUE(t3.event_order.size() == 1U);
    EXPECT_TRUE(t3.event_order[0] == 3);

    // ----- Empty group is a no-op (both fold paths). -----
    PaintTrace t4;
    FakeGroup empty;
    empty.PaintAll(t4);
    EXPECT_TRUE(t4.paint_order.empty());
    const EventResult r4 = empty.DispatchEvent(t4);
    EXPECT_TRUE(r4 == EventResult::NotInterested);
    EXPECT_TRUE(t4.event_order.empty());

    return ::duetos_host_test::finish_main("tests/host/test_widget_group.cpp");
}
