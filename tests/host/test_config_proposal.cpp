// Hosted unit test for Phase B learner config-proposal decision logic.
// Covers: below-threshold -> no proposal; at/above threshold -> a bounded
// raise (never more than 2x, never past the ceiling) with evidence recorded.
// DD#016: this header has no FS/codegen path — it only computes numbers.
#include "env/config_proposal_decide.h"

#include <cassert>
#include <cstdio>

using namespace duetos::env;

int main()
{
    // Below the evidence threshold -> no proposal.
    auto below = ConfigProposalDecide(ConfigKnob::InferredGapPinCap, 2);
    assert(below.emit == false);
    assert(below.proposed_value == below.current_value);

    // At/above threshold -> a proposal with a bounded raise.
    auto d = ConfigProposalDecide(ConfigKnob::InferredGapPinCap, kConfigEvidenceThreshold);
    assert(d.emit == true);
    assert(d.proposed_value > d.current_value);
    assert(d.proposed_value <= d.current_value * 2); // stability bound
    assert(d.evidence_count == kConfigEvidenceThreshold);

    // The raise is exactly one step for InferredGapPinCap (128 -> 256).
    assert(d.current_value == 128ull);
    assert(d.proposed_value == 256ull);

    // A large observed count still never exceeds 2x in one proposal.
    auto big = ConfigProposalDecide(ConfigKnob::InferredGapPinCap, 1000);
    assert(big.proposed_value <= big.current_value * 2);

    std::printf("[config-proposal-host] PASS\n");
    return 0;
}
