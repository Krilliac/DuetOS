# Autonomic Policy (the learned "decide" step)

> **Audience:** Kernel hackers working the autonomic-OS arc.
>
> **Execution context:** Kernel — the env-monitor poll (~2 s cadence),
> task context only.
>
> **Maturity:** v0 (Slices 1–2 of 4) — the decision **seam**, the
> toggleable safety **shield**, and the **fixed-point imitation net**
> (running in **shadow mode**) are landed and wired into boot. Online
> learning (Slice 3) and the load-balance actuators + fix-journal proposal
> tie-in (Slice 4) are deferred.

## Overview

The autonomic engine ([`Environment.md`](Environment.md#autonomic-rule-engine))
runs a **sense → decide → act** loop. Today *decide* is five hand-written
rules (`env::AutonomicEvaluate`). This subsystem is replacing that decision
with a learned, fixed-point, online-adapting neural policy — without
disturbing the actuators, which the kernel still owns.

Full design + the 4-slice plan:
[`docs/superpowers/specs/2026-06-10-autonomic-neural-policy-design.md`](../../docs/superpowers/specs/2026-06-10-autonomic-neural-policy-design.md).

```
env-monitor tick → SenseInputs() → PolicyDecide(state, in) → AutonomicApply
                                       │
                 rule floor ──────────┤  AutonomicEvaluate (safety floor + teacher)
                 learned proposal ────┤  NeuralPolicyDecide (Slice 1: no-op → empty)
                 reconcile ───────────┘  ShieldApply (toggleable; Slice 1: passthrough)
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

## Policy modes

| Mode | Meaning |
|------|---------|
| `Off` | Learner disabled; the rule table alone decides. |
| `Shadow` | (default) Net infers and is traced, but actuators stay rule-driven — pure data collection, no consequences. |
| `Live` | Net's gated actions drive the actuators and learn online (Slice 3). |

## Why the shield is removable (and why that matters)

This is **shielded reinforcement learning**: a policy that must explore to
learn, but whose exploration is bounded by a shield that overrides unsafe
actions. The master-off is deliberate — you cannot validate that the policy
*itself* got good (vs. the shield merely masking a bad learner) unless you
can measure the **raw** policy. A shield that can't be removed can't be
trusted. See [Design-Decisions](../reference/Design-Decisions.md) (2026-06-10).

## The self-improvement boundary

The learner may rewrite its **weights** (data) and may **propose** source
patches as reviewable `fix_journal` records (Slice 4) — it never patches
kernel `.text`. That upholds Design-Decision #016 and stays consistent with
the `runtime_checker`, which treats any code/fn-table drift as an attack.
Runtime owns learning; the offline patch generator owns committing source.

## Files

- [`kernel/env/policy_shield.h`](../../kernel/env/policy_shield.h) — pure
  config + `ShieldApply` + cmdline parse (host-tested).
- [`kernel/env/policy_shield.cpp`](../../kernel/env/policy_shield.cpp) —
  live config singletons, cmdline init, self-test.
- [`kernel/env/neural_policy.{h,cpp}`](../../kernel/env/neural_policy.h) —
  the learner (Slice 1: no-op).
- The seam (`PolicyDecide`/`PolicyTrace`) lives in
  [`kernel/env/autonomic.cpp`](../../kernel/env/autonomic.cpp).
