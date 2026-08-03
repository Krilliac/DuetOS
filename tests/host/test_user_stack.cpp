// test_user_stack.cpp — hosted unit test for the demand-grown ring-3
// stack reservation planner + page-fault classifier.
//
// Covers:
//   kernel/proc/user_stack.h
//     (UserStackPlan — SizeOfStackReserve / SizeOfStackCommit
//      clamping; UserStackClassify — the growth-vs-guard-vs-wild
//      decision the ring-3 #PF handler in kernel/arch/x86_64/traps.cpp
//      acts on)
//
// Both are freestanding by construction (the header includes only
// util/types.h and neither function allocates, maps or locks), which
// is why the decision that gates committing memory on behalf of an
// untrusted PE can be exercised exhaustively here rather than only
// observed in a boot log.
//
// The bar this test enforces: a mis-classified fault that silently
// commits memory is worse than a crash. So every case that is NOT
// exactly "a not-present fault on the page immediately below the
// committed edge, taken by the thread whose rsp is inside this
// reservation, above the guard" must come back NotStack.

#include "host_test_helper.h"

#include "proc/user_stack.h"

#include <cstdio>

using duetos::u64;
using duetos::core::kUserStackCommitMaxPages;
using duetos::core::kUserStackCommitMinPages;
using duetos::core::kUserStackGuardPages;
using duetos::core::kUserStackReserveMax;
using duetos::core::kUserStackReserveMin;
using duetos::core::kUserStackTopVa;
using duetos::core::UserStackClassify;
using duetos::core::UserStackFault;
using duetos::core::UserStackPlan;
using duetos::core::UserStackPlanAt;
using duetos::core::UserStackRange;
using duetos::core::UserStackRangeIsValid;
using duetos::core::UserStackRangesDisjoint;

namespace
{

constexpr u64 kPage = 4096;

// #PF error-code bits (Intel SDM Vol 3 Table 4-15).
constexpr u64 kErrNotPresentRead = 0x0;  // not present, read, user
constexpr u64 kErrNotPresentWrite = 0x2; // not present, write, user
constexpr u64 kErrProtectionWrite = 0x3; // present + write => protection fault

const char* Name(UserStackFault f)
{
    switch (f)
    {
    case UserStackFault::NotStack:
        return "NotStack";
    case UserStackFault::Grow:
        return "Grow";
    case UserStackFault::Grew:
        return "Grew";
    case UserStackFault::Guard:
        return "Guard";
    case UserStackFault::Failed:
        return "Failed";
    }
    return "unknown";
}

void ExpectVerdict(const char* what, UserStackFault got, UserStackFault want)
{
    if (got != want)
    {
        std::fprintf(stderr, "FAIL: %s: got %s, want %s\n", what, Name(got), Name(want));
    }
    EXPECT_TRUE(got == want);
}

// ---------------------------------------------------------------
// UserStackPlan — clamping the image's untrusted request.
// ---------------------------------------------------------------
void TestPlanHonoursTypicalMsvcDefaults()
{
    // /STACK:1048576,4096 — what link.exe emits unless told otherwise.
    bool clamped = true;
    const UserStackRange s = UserStackPlan(1024 * 1024, 4096, &clamped);

    EXPECT_EQ(s.top, kUserStackTopVa);
    EXPECT_EQ(s.top - s.reserve_lo, 1024u * 1024u);
    EXPECT_EQ(s.reserve_lo - s.guard_lo, kUserStackGuardPages * kPage);
    EXPECT_TRUE(!clamped);

    // SizeOfStackCommit of 4096 is below the 2-page floor, so the
    // floor wins — ring-3 entry lands rsp near `top` and the first
    // prologue writes below it.
    EXPECT_EQ((s.top - s.commit_lo) / kPage, kUserStackCommitMinPages);
    EXPECT_TRUE(s.guard_taken == false);
}

void TestPlanClampsAbsurdReserve()
{
    bool clamped = false;
    const UserStackRange s = UserStackPlan(4ull * 1024 * 1024 * 1024, 0, &clamped);
    EXPECT_TRUE(clamped);
    EXPECT_EQ(s.top - s.reserve_lo, kUserStackReserveMax);
}

void TestPlanFloorsTinyReserve()
{
    // A PE declaring 0 (or a few KiB) still gets at least what the
    // pre-growth fixed 64 KiB stack handed every image, so nothing
    // that used to run regresses.
    bool clamped = false;
    const UserStackRange zero = UserStackPlan(0, 0, &clamped);
    EXPECT_TRUE(clamped);
    EXPECT_EQ(zero.top - zero.reserve_lo, kUserStackReserveMin);

    const UserStackRange tiny = UserStackPlan(4096, 0, nullptr);
    EXPECT_EQ(tiny.top - tiny.reserve_lo, kUserStackReserveMin);
}

void TestPlanClampsCommitToWindow()
{
    // An image cannot demand its whole reserve at spawn under the
    // guise of "commit" — that is exactly the frame-cost multiplier
    // demand growth exists to avoid.
    const UserStackRange greedy = UserStackPlan(1024 * 1024, 1024 * 1024, nullptr);
    EXPECT_EQ((greedy.top - greedy.commit_lo) / kPage, kUserStackCommitMaxPages);

    // Commit is never larger than the reservation itself.
    const UserStackRange small = UserStackPlan(kUserStackReserveMin, 1024 * 1024, nullptr);
    EXPECT_TRUE(small.commit_lo >= small.reserve_lo);

    // A mid-window request is honoured verbatim.
    const UserStackRange mid = UserStackPlan(1024 * 1024, 8 * kPage, nullptr);
    EXPECT_EQ((mid.top - mid.commit_lo) / kPage, 8u);
}

void TestPlanRoundsUpToPages()
{
    const UserStackRange s = UserStackPlan(kUserStackReserveMin + 1, kPage * 3 + 1, nullptr);
    EXPECT_EQ((s.top - s.reserve_lo) % kPage, 0u);
    EXPECT_EQ((s.top - s.commit_lo) % kPage, 0u);
    EXPECT_EQ((s.top - s.commit_lo) / kPage, 4u);
}

void TestCustomTopPlansDisjointTaskStacks()
{
    constexpr u64 kArenaBase = 0x68000000ull;
    constexpr u64 kReserve = kUserStackReserveMin;
    constexpr u64 kFootprint = kReserve + kUserStackGuardPages * kPage;

    const UserStackRange first = UserStackPlanAt(kArenaBase + kFootprint, kReserve, 0, nullptr);
    const UserStackRange second = UserStackPlanAt(first.top + kFootprint, kReserve, 0, nullptr);

    EXPECT_TRUE(UserStackRangeIsValid(first));
    EXPECT_TRUE(UserStackRangeIsValid(second));
    EXPECT_EQ(first.guard_lo, kArenaBase);
    EXPECT_EQ(second.guard_lo, first.top);
    EXPECT_TRUE(first.top <= second.guard_lo);
    EXPECT_TRUE(UserStackRangesDisjoint(first, second));
    EXPECT_EQ((first.top - first.commit_lo) / kPage, kUserStackCommitMinPages);
    EXPECT_EQ((second.top - second.commit_lo) / kPage, kUserStackCommitMinPages);
}

void TestDescriptorValidationBoundsTeardownWalk()
{
    UserStackRange s = UserStackPlanAt(0x68014000ull, kUserStackReserveMin, 0, nullptr);
    EXPECT_TRUE(UserStackRangeIsValid(s));

    UserStackRange bad = s;
    bad.top += 1;
    EXPECT_TRUE(!UserStackRangeIsValid(bad));

    bad = s;
    bad.guard_lo -= kPage;
    EXPECT_TRUE(!UserStackRangeIsValid(bad));

    bad = s;
    bad.commit_lo = bad.reserve_lo - kPage;
    EXPECT_TRUE(!UserStackRangeIsValid(bad));

    // Once the one-shot guard has fired, commit_lo may legitimately
    // enter the guard region, but never below its hard floor.
    bad.guard_taken = true;
    EXPECT_TRUE(UserStackRangeIsValid(bad));
    bad.commit_lo = bad.guard_lo - kPage;
    EXPECT_TRUE(!UserStackRangeIsValid(bad));

    EXPECT_TRUE(!UserStackRangeIsValid(UserStackRange{}));
    EXPECT_TRUE(!UserStackRangesDisjoint(s, s));
    EXPECT_EQ(UserStackPlanAt(0x68014001ull, kUserStackReserveMin, 0, nullptr).top, 0u);
}

// ---------------------------------------------------------------
// UserStackClassify — the decision that gates committing memory.
// ---------------------------------------------------------------

// A 1 MiB reservation with 2 pages committed — the state a freshly
// spawned MSVC PE is in.
UserStackRange FreshPlan()
{
    return UserStackPlan(1024 * 1024, 4096, nullptr);
}

void TestGrowsOnTheAdjacentPage()
{
    const UserStackRange s = FreshPlan();
    const u64 rsp = s.commit_lo + 0x40; // thread is on the lowest committed page

    // The classic __chkstk / push probe: one word below the edge.
    ExpectVerdict("classify: word below the commit edge grows",
                  UserStackClassify(s, s.commit_lo - 8, kErrNotPresentWrite, rsp), UserStackFault::Grow);
    // Anywhere inside that one page grows.
    ExpectVerdict("classify: base of the adjacent page grows",
                  UserStackClassify(s, s.commit_lo - kPage, kErrNotPresentWrite, rsp), UserStackFault::Grow);
    // Reads grow too — a prologue can read before it writes.
    ExpectVerdict("classify: read fault on the adjacent page grows",
                  UserStackClassify(s, s.commit_lo - 0x100, kErrNotPresentRead, rsp), UserStackFault::Grow);
}

void TestRefusesToSkipPages()
{
    const UserStackRange s = FreshPlan();
    const u64 rsp = s.commit_lo + 0x40;

    // One byte past the one-page step. A fault that skips over
    // uncommitted pages is a wild pointer, not a stack probe.
    ExpectVerdict("classify: fault one byte past the grow step is not stack",
                  UserStackClassify(s, s.commit_lo - kPage - 1, kErrNotPresentWrite, rsp), UserStackFault::NotStack);
    ExpectVerdict("classify: fault deep inside the reservation is not stack",
                  UserStackClassify(s, s.reserve_lo + kPage, kErrNotPresentWrite, rsp), UserStackFault::NotStack);
}

void TestRefusesProtectionFaults()
{
    const UserStackRange s = FreshPlan();
    const u64 rsp = s.commit_lo + 0x40;
    // Present-bit set => a protection violation on an already-
    // committed page. Real error, never growth.
    ExpectVerdict("classify: protection fault on the adjacent page is not stack",
                  UserStackClassify(s, s.commit_lo - 8, kErrProtectionWrite, rsp), UserStackFault::NotStack);
}

void TestOnlyTheThreadRunningOnThisStackCanGrowIt()
{
    const UserStackRange s = FreshPlan();

    // The service path selects the current Task's descriptor. The pure
    // classifier additionally refuses an rsp from a different stack,
    // even if a caller accidentally hands it the wrong descriptor.
    const u64 other_thread_rsp = 0x68001000ull;
    ExpectVerdict("classify: wild pointer from another thread is not stack",
                  UserStackClassify(s, s.commit_lo - 8, kErrNotPresentWrite, other_thread_rsp),
                  UserStackFault::NotStack);
    ExpectVerdict("classify: rsp above the reservation top is not stack",
                  UserStackClassify(s, s.commit_lo - 8, kErrNotPresentWrite, s.top + kPage), UserStackFault::NotStack);

    // The access itself may be at or ABOVE rsp — that is what a real
    // prologue does after `sub rsp, N`, and refusing it would refuse
    // every growth a normal recursion asks for. Observed live: cr2
    // exactly equal to rsp on the first frame of a recursing PE.
    ExpectVerdict("classify: fault exactly at rsp still grows",
                  UserStackClassify(s, s.commit_lo - 8, kErrNotPresentWrite, s.commit_lo - 8), UserStackFault::Grow);
    ExpectVerdict("classify: fault above rsp inside the same page still grows",
                  UserStackClassify(s, s.commit_lo - 8, kErrNotPresentWrite, s.commit_lo - 0x800),
                  UserStackFault::Grow);
}

void TestGuardPageIsFatalNotGrowable()
{
    const UserStackRange s = FreshPlan();
    // A runaway that walked the whole reservation down: commit edge
    // is at reserve_lo, the next probe lands in the guard page.
    UserStackRange exhausted = s;
    exhausted.commit_lo = s.reserve_lo;
    const u64 rsp = s.reserve_lo + 0x40;

    ExpectVerdict("classify: first fault below the reservation is Guard, never Grow",
                  UserStackClassify(exhausted, s.reserve_lo - 8, kErrNotPresentWrite, rsp), UserStackFault::Guard);
    ExpectVerdict("classify: base of the guard region is Guard",
                  UserStackClassify(exhausted, s.guard_lo, kErrNotPresentWrite, rsp), UserStackFault::Guard);
    ExpectVerdict("classify: middle of the guard region is Guard",
                  UserStackClassify(exhausted, s.guard_lo + 2 * kPage, kErrNotPresentWrite, rsp),
                  UserStackFault::Guard);
    // Guard wins over every other condition — the verdict does not
    // depend on the error code or on rsp, because landing there means
    // the thread is off the bottom of its own reservation whatever it
    // was doing.
    ExpectVerdict("classify: guard verdict ignores the error code",
                  UserStackClassify(exhausted, s.guard_lo, kErrProtectionWrite, rsp), UserStackFault::Guard);
    ExpectVerdict("classify: guard verdict ignores rsp",
                  UserStackClassify(exhausted, s.guard_lo, kErrNotPresentWrite, 0), UserStackFault::Guard);
}

void TestBelowTheGuardIsAnOrdinaryWildPointer()
{
    const UserStackRange s = FreshPlan();
    UserStackRange exhausted = s;
    exhausted.commit_lo = s.reserve_lo;
    // One byte below the guard page: outside everything this
    // reservation owns, so the ordinary task-kill path applies.
    ExpectVerdict("classify: below the guard region is not stack",
                  UserStackClassify(exhausted, s.guard_lo - 1, kErrNotPresentWrite, s.reserve_lo + 0x40),
                  UserStackFault::NotStack);
}

void TestNoReservationClassifiesEverythingAsNotStack()
{
    // ELF tasks and the native ring-3 smoke payloads never get a
    // reservation; their faults must behave exactly as they did
    // before demand growth existed.
    const UserStackRange none{};
    ExpectVerdict("classify: zero reservation is always NotStack",
                  UserStackClassify(none, 0x7FFDF000ull, kErrNotPresentWrite, 0x7FFE0000ull), UserStackFault::NotStack);
    ExpectVerdict("classify: zero reservation ignores a zero fault va",
                  UserStackClassify(none, 0, kErrNotPresentWrite, 0), UserStackFault::NotStack);
}

void TestFaultsAboveTheReservationAreNotStack()
{
    const UserStackRange s = FreshPlan();
    // Inside the committed region (would not fault not-present in
    // reality, but the classifier must still refuse it) and above the
    // reservation top.
    ExpectVerdict("classify: inside the committed region is not stack",
                  UserStackClassify(s, s.commit_lo + kPage, kErrNotPresentWrite, s.top - 8), UserStackFault::NotStack);
    ExpectVerdict("classify: above the reservation top is not stack",
                  UserStackClassify(s, s.top + kPage, kErrNotPresentWrite, s.top - 8), UserStackFault::NotStack);
}

// Walk a whole 1 MiB reservation down one page at a time the way a
// deep recursion does, asserting every step grows and the step after
// the last one hits the guard. This is the property the live
// stackgrow_smoke fixture exercises for real.
void TestFullWalkGrowsThenGuards()
{
    UserStackRange s = FreshPlan();
    u64 steps = 0;
    while (s.commit_lo > s.reserve_lo)
    {
        const u64 fault_va = s.commit_lo - 8;
        const u64 rsp = s.commit_lo + 0x40;
        ExpectVerdict("classify: every step of the walk grows",
                      UserStackClassify(s, fault_va, kErrNotPresentWrite, rsp), UserStackFault::Grow);
        s.commit_lo -= kPage; // what UserStackServiceFault does on Grow
        ++steps;
    }
    EXPECT_EQ(steps, (1024u * 1024u) / kPage - kUserStackCommitMinPages);
    ExpectVerdict("classify: the step after the last grow is Guard",
                  UserStackClassify(s, s.reserve_lo - 8, kErrNotPresentWrite, s.reserve_lo + 0x40),
                  UserStackFault::Guard);
}

} // namespace

int main()
{
    TestPlanHonoursTypicalMsvcDefaults();
    TestPlanClampsAbsurdReserve();
    TestPlanFloorsTinyReserve();
    TestPlanClampsCommitToWindow();
    TestPlanRoundsUpToPages();
    TestCustomTopPlansDisjointTaskStacks();
    TestDescriptorValidationBoundsTeardownWalk();

    TestGrowsOnTheAdjacentPage();
    TestRefusesToSkipPages();
    TestRefusesProtectionFaults();
    TestOnlyTheThreadRunningOnThisStackCanGrowIt();
    TestGuardPageIsFatalNotGrowable();
    TestBelowTheGuardIsAnOrdinaryWildPointer();
    TestNoReservationClassifiesEverythingAsNotStack();
    TestFaultsAboveTheReservationAreNotStack();
    TestFullWalkGrowsThenGuards();

    return ::duetos_host_test::finish_main("user_stack");
}
