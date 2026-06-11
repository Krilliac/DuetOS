#pragma once

#include "env/autonomic.h"

/*
 * DuetOS — learned autonomic policy (the "neural / synaptic" decide step).
 *
 * The fixed-point neural policy that, once trained, proposes the action
 * set for the current sensed inputs. It sits behind the `PolicyDecide`
 * seam (env/autonomic.cpp) alongside the hand-written rule table, and
 * its proposal is reconciled with the rule floor by the shield
 * (env/policy_shield.h) before anything reaches an actuator.
 *
 * Slice 1 (this commit) is a no-op placeholder: `NeuralPolicyDecide`
 * returns an empty set, so the shield passes the rule floor through and
 * the engine behaves byte-identically to the pre-seam rule table — the
 * strangler-fig "delegate first, grow the new organism later" step. The
 * fixed-point MLP (feature extraction + forward pass + imitation-by-
 * construction init) lands in Slice 2; online three-factor-Hebbian
 * learning in Slice 3. See
 * docs/superpowers/specs/2026-06-10-autonomic-neural-policy-design.md.
 *
 * Subsystem isolation: freestanding kernel engine. Issues no syscalls
 * and grants no privilege — it only proposes actions the kernel already
 * owns, exactly like the rule table it will eventually replace.
 *
 * Threading: kernel task context only (the env-monitor poll). The
 * weights (Slice 2+) are owned by that single task, so there is no SMP
 * contention by construction.
 */

namespace duetos::env
{

/// The learned policy's proposed action set for `in`. Slice 1 returns an
/// empty set (no learner yet); Slice 2+ returns the net's gated actions.
/// A pure read of `in` — touches no actuator and mutates no kernel state.
AutoActionSet NeuralPolicyDecide(const AutoInputs& in);

} // namespace duetos::env
