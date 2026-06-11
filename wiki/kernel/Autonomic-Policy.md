# Autonomic Policy (the learned "decide" step)

> **Audience:** Kernel hackers working the autonomic-OS arc.
>
> **Execution context:** Kernel — the env-monitor poll (~2 s cadence),
> task context only.
>
> **Maturity:** v1 (all 4 slices landed) — the decision **seam**, the
> toggleable safety **shield**, the **fixed-point imitation net**, **online
> three-factor reward-modulated learning** with **Live mode**, the
> scheduler **load-balance actuator**, and **reviewable fix-journal
> proposals** (with a master-off **firehose**) are all wired into boot.

## Overview

The autonomic engine ([`Environment.md`](Environment.md#autonomic-rule-engine))
runs a **sense → decide → act** loop. Today *decide* is five hand-written
rules (`env::AutonomicEvaluate`). This subsystem is replacing that decision
with a learned, fixed-point, online-adapting neural policy — without
disturbing the actuators, which the kernel still owns.

Full design + the 4-slice plan:
[`docs/superpowers/specs/2026-06-10-autonomic-neural-policy-design.md`](../../docs/superpowers/specs/2026-06-10-autonomic-neural-policy-design.md).

```
env-monitor tick → SenseInputs() → PolicyDecide(state, in, now) → AutonomicApply → Enqueue(feedback)
                                       │                                                    │
                 rule floor ──────────┤  AutonomicEvaluate (safety floor + teacher)        │ (delayed ~10 ticks)
                 learned proposal ────┤  NeuralPolicyDecideLive (forward + explore + breaker)
                 reconcile ───────────┘  ShieldReconcile (Off/Shadow→floor; Live→net∪floor)
                                                                                            ▼
kselfthink tick → feedback::Tick() → classify outcome → NeuralPolicyReward(tick, action, r)  [Live only]
```

## What's landed (Slices 1–2)

- **The `PolicyDecide` seam** (`env/autonomic.cpp`). `AutonomicTick` now
  routes through it: evaluate the rule floor, ask the (Slice-1 no-op)
  learner, reconcile through the shield, trace, return. With an empty net
  proposal the shield passes the rule floor straight through, so behaviour
  is **byte-identical** to the pre-seam engine — a strangler-fig
  "delegate first" step.
- **The toggleable shield** (`env/policy_shield.h`, host-tested). A
  `ShieldConfig` of per-safeguard booleans (`rule_floor_veto`,
  `action_clamp`, `circuit_breaker`, `explore_cap`, `forbidden_actions`),
  all default ON, plus a master `shields_enabled`. `ShieldSetMaster(cfg,
  false)` clears the whole envelope in one call.
- **The toggle surface.** Boot cmdline `autonomic=off|shadow|live` and
  `shields=on|off` (parsed by `PolicyConfigInitFromCmdline` at bringup);
  runtime `ShieldMasterSet` / `PolicyModeSet` for the shell. `shields=off`
  boots straight into un-shielded data collection.
- **The imitation net** (`env/neural_policy.{h,cpp}`, Slice 2). A
  fixed-point MLP (3→3→3; Q16 activations, Q12 `int16` weights, `i64`
  accumulators, ReLU) whose hand-initialised weights reproduce the rule
  **level**-predicates — `MemReclaim ⟸ free<10%`, `FootprintTrim ⟸
  thermal`, `ForceHealthScan ⟸ thermal∨load>1`. It runs every tick in
  **shadow mode** (computed + traced; the rule floor still actuates), so
  its proposals are pure data until Slice 3 flips it live. The net governs
  only these LEVEL-predicate discretionary actions; the *edge* rule
  (SecurityEscalate ⟸ health **rose**) and the deterministic policy→bias
  map stay rule-driven (a stateless net can't reproduce a delta).
- **Boot self-tests** `[policy-shield] selftest pass` + `[neural-policy]
  selftest pass`; the pure logic is covered host-side by
  `tests/host/test_policy_shield.cpp` and `test_neural_policy.cpp`.

## What's landed (Slices 3–4)

- **Online learning — three-factor reward-modulated Hebbian** (Slice 3,
  `neural_policy.cpp`). Only the output layer (`w2`/`b2`) adapts; the hidden
  detectors stay the fixed imitation map. The update
  `dW2_jk = (reward · h_j) >> kLearnShiftW` is credit-assigned to the
  synapses of the action that fired, weighted by that decision's hidden
  activations. **Reward** is the delayed `feedback` outcome
  (Improved=+1, NoChange=0, Worsened=−1; Diagnostic/Pending skipped).
  Stability shields: bounded step, weight **clamp** (`±kW2Clamp`), **decay**
  toward the imitation prior every update, and bounded **ε-greedy
  exploration** (`NeuralPolicyExplore`, widened when `explore_cap` is off).
- **Live mode** (`ShieldReconcile`, `policy_shield.h`, host-tested). In Live
  the net **drives** the actuators; `rule_floor_veto` unions the floor's
  safety actions back in so nothing the rules demand is dropped;
  `forbidden_actions` keeps `SecurityEscalate` rule-only; **master-off**
  yields the **raw** net set. A per-action **circuit breaker** vetoes an
  action that Worsened `kBreakerTrip` times in a row (cooldown-bounded).
  The decision is recorded under the poll's tick so the delayed reward
  credit-assigns the right synapses; the feedback entry carries the same
  tick.
- **Load-balance actuator** (Slice 4). `SchedRebalanceNow` →
  `sched::SchedRequestActiveBalance()` — a one-shot out-of-band active
  balance, fired by the CpuSaturation rule (alongside the health scan).
  Self-test `[sched-activebalance-selftest] PASS`. (Balance **cadence** is
  *not* a separate actuator — it is the existing `PowerBias` lever, to keep
  one source of truth per scheduler knob; see Design-Decisions 2026-06-11.)
- **Reviewable proposals** (Slice 4, `NeuralPolicyProposalScan` →
  `FixDetector::AutonomicProposal`). The learner surfaces gates it has
  **learned to suppress** (a prior-positive synapse driven non-positive) to
  the fix journal as **data** — never a code mutation (DD#016). Shielded
  reports only durable flips; the **master-off firehose** also reports gates
  merely *trending* toward suppression (one record per experiment). Flows
  ring → FAT32 `KERNEL.FIX` → offline patch generator → human/Claude review.
- **Shell surface.** `autonomic mode <off|shadow|live>`, `autonomic shields
  <on|off>`, `autonomic weights` (the learned output layer), `autonomic
  proposals` (current learned-away gates). No-arg `autonomic` shows
  `policy=` and `shields=` state.
- **Boot self-tests** still green end-to-end under `autonomic=live`:
  `[sched-activebalance-selftest] PASS` + the env/policy quartet; host tests
  cover the learning dynamics (reward moves weights, clamp/decay hold,
  breaker trips, exploration bounded, proposal scan).

### Threading (two tasks, lock-free)

The learner's mutable state (`g_net.w2/b2`, the decision-context ring, the
breakers) is touched by **two** task-context kthreads: `env-monitor` runs the
decide (writes the ctx ring, reads weights) and `kselfthink` runs the delayed
reward (writes weights, reads the ctx ring). **No lock** — matching the
lock-free best-effort contract of the feedback ring it is driven by. On
x86_64 every shared field is naturally aligned ≤8 bytes, so reads/writes are
word-atomic; the only cross-task hazard is a transiently stale weight for one
decision, which the decay regularizer + repeated rewards absorb by design.

## Policy modes

| Mode | Meaning |
|------|---------|
| `Off` | Learner disabled; the rule table alone decides. |
| `Shadow` | (default) Net infers and is traced, but actuators stay rule-driven — pure data collection, no consequences. |
| `Live` | Net's gated actions drive the actuators (behind the shield) and learn online from the delayed feedback reward. |

## Why the shield is removable (and why that matters)

This is **shielded reinforcement learning**: a policy that must explore to
learn, but whose exploration is bounded by a shield that overrides unsafe
actions. The master-off is deliberate — you cannot validate that the policy
*itself* got good (vs. the shield merely masking a bad learner) unless you
can measure the **raw** policy. A shield that can't be removed can't be
trusted. See [Design-Decisions](../reference/Design-Decisions.md) (2026-06-10).

## The self-improvement boundary

The learner rewrites its **weights** (data) and **proposes** source patches
as reviewable `fix_journal` records (`AutonomicProposal`) — it never patches
kernel `.text`. That upholds Design-Decision #016 and stays consistent with
the `runtime_checker`, which treats any code/fn-table drift as an attack.
Runtime owns learning; the offline patch generator owns committing source.

Beyond action-gate proposals, the learner also emits bounded **config**
proposals (`kernel/env/config_proposal.cpp`): when runtime pressure on an
allow-listed tunable crosses an evidence threshold (e.g. inferred-gap discovery
dropping pins because `kInferredGapPinCap` is too low), it records an
`AutonomicProposal` `config:<symbol>` with the current value, a bounded
proposed value (never more than 2× current, never past a hard ceiling), and the
evidence count. Still pure data — see the
[Fix Journal](../security/Fix-Journal.md) dynamic-discovery section.

## Files

- [`kernel/env/policy_shield.h`](../../kernel/env/policy_shield.h) — pure
  config + `ShieldApply`/`ShieldReconcile` + cmdline parse (host-tested).
- [`kernel/env/policy_shield.cpp`](../../kernel/env/policy_shield.cpp) —
  live config singletons, cmdline init, self-test.
- [`kernel/env/neural_policy.{h,cpp}`](../../kernel/env/neural_policy.h) —
  the learner: forward pass, online reward update, exploration, breakers,
  proposal scan.
- The seam (`PolicyDecide`/`PolicyTrace`/`EmitPolicyProposals`) lives in
  [`kernel/env/autonomic.cpp`](../../kernel/env/autonomic.cpp); the delayed
  reward is wired from
  [`kernel/env/autonomic_feedback.cpp`](../../kernel/env/autonomic_feedback.cpp).
- The actuator primitive `SchedRequestActiveBalance()` lives in
  [`kernel/sched/sched.cpp`](../../kernel/sched/sched.cpp).
