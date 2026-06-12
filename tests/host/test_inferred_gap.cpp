// Hosted unit test for Phase A runtime gap inference decision logic.
// Verifies InferredGapShouldRecord: only the not-implemented sentinel records;
// success and correct-error return values do not.
#include "syscall/inferred_gap_decide.h"

#include <cassert>
#include <cstdio>

using duetos::syscall::InferredGapShouldRecord;
using duetos::syscall::kInferredGapSentinel;

int main()
{
    // The not-implemented sentinel -> record.
    assert(InferredGapShouldRecord(kInferredGapSentinel) == true);
    assert(InferredGapShouldRecord(0xC0000002ULL) == true);

    // Success (0) -> no record.
    assert(InferredGapShouldRecord(0) == false);

    // STATUS_ACCESS_DENIED (0xC0000022) is a CORRECT denial, not a gap.
    assert(InferredGapShouldRecord(0xC0000022ULL) == false);

    // STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034) is correct, not a gap.
    assert(InferredGapShouldRecord(0xC0000034ULL) == false);

    // A normal small success-ish handle value -> no record.
    assert(InferredGapShouldRecord(1) == false);

    std::printf("[inferred-gap-host] PASS\n");
    return 0;
}
