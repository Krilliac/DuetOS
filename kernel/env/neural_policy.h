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

// ---------------------------------------------------------------------
// Fixed-point network (no FPU). Features/activations are Q16
// (65536 = 1.0); weights are Q12 (4096 = 1.0). Each layer accumulates
// products in i64 and requantizes by >> kQWeight, with a ReLU hidden
// layer. The net governs the LEVEL-predicate discretionary actions; the
// edge rule (SecurityEscalate <= health rose) and the deterministic
// policy->bias map stay rule-driven (a stateless net cannot reproduce a
// delta, and a fixed mapping has nothing to learn).
// ---------------------------------------------------------------------

inline constexpr int kQWeight = 12;  // weight fixed-point fractional bits
inline constexpr int kQFeature = 16; // feature/activation fractional bits

inline constexpr int kNetIn = 3;     // free-fraction, thermal, load-per-cpu
inline constexpr int kNetHidden = 3; // mem / thermal / cpu detectors
inline constexpr int kNetOut = 3;    // MemReclaim, FootprintTrim, ForceHealthScan

struct NetParams
{
    i16 w1[kNetIn][kNetHidden];  // input  -> hidden, Q12
    i32 b1[kNetHidden];          // hidden bias, Q16
    i16 w2[kNetHidden][kNetOut]; // hidden -> output, Q12
    i32 b2[kNetOut];             // output bias, Q16
};

/// Fixed-point forward pass: `feat` (Q16, length kNetIn) -> `logits`
/// (Q16, length kNetOut). ReLU hidden layer, i64 accumulators,
/// requantize each layer by >> kQWeight. Pure — no state, no kernel
/// calls, deterministic.
void NetForward(const NetParams& p, const i32 feat[kNetIn], i32 logits[kNetOut]);

/// Extract the Q16 feature vector (free-fraction, thermal, load-per-cpu)
/// from sensed inputs. Degenerate inputs (`total_frames==0` /
/// `cpu_online==0`) map to the "no pressure" value so the net never
/// false-fires on them; load-per-cpu is capped so a runaway loadavg
/// cannot overflow downstream arithmetic.
void ExtractFeatures(const AutoInputs& in, i32 feat[kNetIn]);

/// The learned policy's proposed action set for `in`. Slice 1 returned an
/// empty set; Slice 2+ returns the imitation net's gated actions. A pure
/// read of `in` — touches no actuator and mutates no kernel state.
AutoActionSet NeuralPolicyDecide(const AutoInputs& in);

/// Boot self-test: drives the imitation net on a known vector and asserts
/// the expected proposal — the on-target echo of the host test's coverage.
/// Emits `[neural-policy] selftest pass`; panics on mismatch. Defined in a
/// separate TU (neural_policy_selftest.cpp) so neural_policy.cpp stays
/// freestanding and host-linkable.
void NeuralPolicySelfTest();

} // namespace duetos::env
