#pragma once

#include "env/config_proposal_decide.h"
#include "util/types.h"

// Phase B of dynamic fix-discovery: the autonomic learner emits a bounded,
// evidence-backed CONFIG proposal as DATA (an AutonomicProposal journal
// record). DD#016: no source is written here — the offline generator renders
// the diff and a human flips the `#if 0`. See
// docs/superpowers/specs/2026-06-11-dynamic-fix-discovery-design.md.

namespace duetos::env
{

// If `observed` evidence crosses the threshold for `knob`, record one
// AutonomicProposal journal entry (`config:<symbol>`) proposing the bounded
// new value. No-op below threshold or if already emitted for this knob this
// boot (dedup is also enforced by the journal per source_pin). Returns true if
// a proposal was recorded.
bool EmitConfigProposal(ConfigKnob knob, u32 observed);

} // namespace duetos::env
