#pragma once

// Freestanding decision logic for learner-driven config proposals (Phase B of
// the dynamic fix-discovery system —
// docs/superpowers/specs/2026-06-11-dynamic-fix-discovery-design.md).
//
// DD#016 boundary: this produces a *proposal* (which knob, current value,
// bounded proposed value, evidence count) as DATA. It NEVER writes source. The
// kernel-side emitter (config_proposal.cpp) turns the decision into an
// AutonomicProposal journal record; the offline generator renders the diff; a
// human flips the `#if 0`. No kernel dependency so the hosted unit test
// (tests/host/test_config_proposal.cpp) links it directly.

namespace duetos::env
{

// The allow-list of tunable config symbols the learner may propose changes to.
// Deliberately tiny — the learner proposes only over symbols whose runtime
// pressure it can actually observe. Add a knob by extending this enum AND the
// ConfigKnobInfo table below; nothing else may be proposed.
enum class ConfigKnob : unsigned
{
    // kInferredGapPinCap (kernel/syscall/inferred_gap.cpp). When InferredGap
    // discovery drops new pins because the per-boot cap is reached, that drop
    // count is the evidence to raise it.
    InferredGapPinCap = 0,
    Count
};

struct ConfigKnobInfo
{
    unsigned long long current_value;
    unsigned long long max_value; // hard ceiling — a proposal never exceeds this
    unsigned long long step;      // additive step per proposal
    const char* symbol;           // the source constant name (for the patch)
};

// Current values mirror the live constants. Kept here so the decision is pure
// and testable; config_proposal.cpp static_asserts the InferredGapPinCap entry
// against the real constant so they cannot drift.
inline constexpr ConfigKnobInfo kConfigKnobTable[static_cast<unsigned>(ConfigKnob::Count)] = {
    /* InferredGapPinCap */ {128ull, 1024ull, 128ull, "kInferredGapPinCap"},
};

// Evidence needed before any proposal is emitted (matches the action-gate
// learner's conservative bias — a one-off blip is not a proposal).
inline constexpr unsigned kConfigEvidenceThreshold = 4;

struct ConfigProposalDecision
{
    bool emit;
    unsigned long long current_value;
    unsigned long long proposed_value;
    unsigned evidence_count;
    const char* symbol;
};

inline constexpr const ConfigKnobInfo& ConfigKnobInfoFor(ConfigKnob knob)
{
    return kConfigKnobTable[static_cast<unsigned>(knob)];
}

// Pure decision: given a knob and how many times its pressure was observed,
// decide whether to propose and to what (bounded) value. A proposal raises by
// one `step`, capped at `max_value` and never more than 2x the current value
// (the stability bound). Below the evidence threshold: no proposal.
constexpr ConfigProposalDecision ConfigProposalDecide(ConfigKnob knob, unsigned observed)
{
    const ConfigKnobInfo& info = ConfigKnobInfoFor(knob);
    ConfigProposalDecision d{};
    d.current_value = info.current_value;
    d.evidence_count = observed;
    d.symbol = info.symbol;
    if (observed < kConfigEvidenceThreshold)
    {
        d.emit = false;
        d.proposed_value = info.current_value;
        return d;
    }
    unsigned long long proposed = info.current_value + info.step;
    const unsigned long long two_x = info.current_value * 2ull;
    if (proposed > two_x)
        proposed = two_x; // stability: never more than double in one proposal
    if (proposed > info.max_value)
        proposed = info.max_value; // hard ceiling
    d.emit = proposed > info.current_value;
    d.proposed_value = proposed;
    return d;
}

} // namespace duetos::env
