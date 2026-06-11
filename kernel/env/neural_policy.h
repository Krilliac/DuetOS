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
 * Threading (Slice 3): the learner's mutable state — the learned output
 * layer (g_net.w2/b2), the decision-context ring, and the per-action
 * circuit breakers — is touched by TWO task-context kthreads:
 *   - `env-monitor` runs the decide (NeuralPolicyDecide / DecideLive):
 *     writes the ctx ring, reads the weights.
 *   - `kselfthink` runs the delayed reward (feedback::Tick ->
 *     NeuralPolicyReward): writes the weights, reads the ctx ring.
 * No lock is taken — matching the lock-free best-effort contract of the
 * feedback ring this learner is driven by. On x86_64 every shared field
 * is naturally aligned and <=8 bytes, so reads/writes are word-atomic
 * (no torn values, no UB); the only cross-task hazard is a transiently
 * stale weight read for a single decision, which the decay regularizer +
 * repeated rewards absorb by design. A kernel spinlock would break this
 * TU's host-linkability and is unnecessary for a noise-tolerant learner.
 * IRQ context must never call in (it never does — both sites are tasks).
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

// ---------------------------------------------------------------------
// Slice 3 — online learning (three-factor reward-modulated Hebbian).
//
// Only the output layer (w2/b2) adapts online; the hidden detectors
// (w1/b1) stay the fixed imitation feature map. The update is gated by
// the delayed feedback reward and credit-assigned to the synapses of the
// action that fired, weighted by the decision's hidden activations:
//   dW2_jk = (reward * h_j) >> kLearnShiftW   (then decay toward prior)
// Every constant below doubles as a stability shield — bounded step,
// weight clamp, decay toward the imitation prior, capped exploration.
// ---------------------------------------------------------------------

inline constexpr int kLearnShiftW = 8;   // w2 step = (reward * h_j) >> this (Q12 nudge)
inline constexpr i32 kLearnStepB = 256;  // b2 step per reward (Q16, ~0.0039)
inline constexpr i16 kW2Clamp = 32767;   // |w2| bound — i16 max; the stability clamp
inline constexpr i32 kB2Clamp = 1 << 20; // |b2| bound — 16.0 (Q16)
inline constexpr int kDecayShift = 6;    // decay toward prior: w += (prior - w) >> this
inline constexpr u32 kLearnCtxRing = 16; // retained decisions (hidden activations)

inline constexpr u64 kBreakerTrip = 3;            // consecutive Worsened that opens a breaker
inline constexpr u64 kBreakerCooldownTicks = 200; // ticks a tripped breaker stays open

/// Reset the learned output layer to the imitation prior and clear all
/// learning state (decision-context ring + circuit breakers). The boot
/// state needs no call (g_net is constinit to the prior); this exists for
/// the `autonomic weights reset` shell command (recover a diverged learner
/// without a reboot) and to give host tests a clean slate between cases.
void NeuralPolicyResetWeights();

/// Live-mode decide: forward pass through the *learned* net, gate per
/// action, AND retain this decision's hidden activations keyed by `tick`
/// so a later reward (delayed feedback outcome) can credit-assign the
/// update. `tick` must be the same tick the feedback entry is stamped
/// with — the engine captures it once per poll.
AutoActionSet NeuralPolicyDecideLive(const AutoInputs& in, u64 tick);

/// Apply one reward-modulated update for the action that fired at
/// `decision_tick`. `reward` is +1 (Improved), 0 (NoChange), -1
/// (Worsened); the caller maps the feedback Outcome (Diagnostic / Pending
/// are not rewards and must not be passed). No-op if `action` is not a
/// learned output, or the decision's hidden context has aged out of the
/// ring — though the circuit breaker still tracks the outcome run.
void NeuralPolicyReward(u64 decision_tick, AutoAction action, int reward);

/// Bounded epsilon-greedy exploration: when `rand_q16 < epsilon_q16`
/// (probability epsilon_q16/65536) toggle one learned action's membership
/// in `set`, so the engine occasionally samples an off-policy move.
/// `epsilon_q16 == 0` never perturbs the set. Pure — the randomness is
/// injected by the caller so it is host-test reproducible.
void NeuralPolicyExplore(AutoActionSet& set, u32 epsilon_q16, u32 rand_q16);

/// Circuit breaker: true while `action`'s breaker is open — it Worsened
/// `NeuralPolicyBreakerTrip()` times in a row, so the shield vetoes the
/// net's proposal of it (the rule floor still covers any safety action)
/// until `NeuralPolicyBreakerCooldownTicks()` have elapsed. `now` = the
/// current tick.
bool NeuralPolicyActionBreakerTripped(AutoAction action, u64 now);

/// Snapshot the live learned parameters (for the `autonomic weights`
/// shell view + host-test assertions). By-value copy.
NetParams NeuralPolicyWeightsSnapshot();

/// A reviewable proposal the learner surfaces from its own weights: a gate
/// it has LEARNED TO SUPPRESS — a synapse the imitation prior made positive
/// (action fires when detector j is active) that online reward drove to or
/// below zero (action no longer fires there). This is evidence a rule may
/// be wrong; it is recorded to the fix journal as DATA (DD#016 — the kernel
/// never patches its own .text), for an offline reviewer to act on.
/// `detector` is the hidden unit (0=mem, 1=thermal, 2=cpu-load); `learned`
/// / `prior` are that synapse's Q12 weights.
struct PolicyProposal
{
    AutoAction action;
    int detector;
    i32 learned;
    i32 prior;
};

/// Scan the learned weights for proposals and fill up to `cap` into `out`,
/// returning the count. `aggressive=false` (shielded) reports only durable
/// proposals — prior-positive gates driven fully non-positive. `aggressive
/// =true` (the master-off firehose) ALSO reports gates merely trending
/// toward suppression (any downward drift from the prior), capturing the
/// learner's in-progress experiments, not just settled patterns. Pure read
/// of the weights — no side effects; host-testable.
u32 NeuralPolicyProposalScan(PolicyProposal* out, u32 cap, bool aggressive);

/// Boot self-test: drives the imitation net on a known vector and asserts
/// the expected proposal — the on-target echo of the host test's coverage.
/// Emits `[neural-policy] selftest pass`; panics on mismatch. Defined in a
/// separate TU (neural_policy_selftest.cpp) so neural_policy.cpp stays
/// freestanding and host-linkable.
void NeuralPolicySelfTest();

} // namespace duetos::env
