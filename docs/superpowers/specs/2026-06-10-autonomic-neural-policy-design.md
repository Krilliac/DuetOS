# Autonomic Neural Policy — Design Spec

- **Date:** 2026-06-10
- **Status:** LANDED 2026-06-11 — all 4 slices implemented, host-tested, and
  verified on a live `autonomic=live` QEMU boot. See
  [`wiki/kernel/Autonomic-Policy.md`](../../../wiki/kernel/Autonomic-Policy.md)
  and the 2026-06-11 entry in
  [`wiki/reference/Design-Decisions.md`](../../../wiki/reference/Design-Decisions.md).
- **Branch:** `claude/autonomic-neural-policy`
- **Owning wiki:** `wiki/drivers/Neural-Engine.md` (arc step 3), new `wiki/kernel/Autonomic-Policy.md`

## Goal

Replace the hand-written rule table in the autonomic engine's *decide* step
(`env::AutonomicEvaluate`) with a learned, **fixed-point** neural policy that
improves **online** from the system's own feedback signal, expands the action
surface to scheduler **load-balancing**, emits **verbose** decision/outcome
traces, and surfaces **reviewable patch proposals** through the fix journal —
all behind a **toggleable safety shield** with a single **master-off** for
un-shielded data collection during testing.

## Context — the substrate already exists (MAPE-K loop)

| Stage | Existing code | Role |
|---|---|---|
| Sense | `RuntimeCheckerScan`, `ResmonSnapshot`, `SystemEnvironment` | telemetry + ~35 health invariants |
| Decide | `env::AutonomicEvaluate` (pure fn, 5 rules) | **the seam we replace** |
| Act | `env::AutonomicApply` | real kernel levers |
| Measure | `env::feedback` (Improved/NoChange/Worsened) | **the reward signal** |
| Reflect | `diag::selfthink` (`SelfPortrait` + `CausalChain`) | verbose trace sink |
| Fix | `diag::fix_journal` (`FixRecord` → FAT32/NVMe) | reviewable-proposal sink |

## Architecture — the `PolicyDecide` seam

`AutonomicTick` today calls `AutonomicEvaluate` directly. We insert one
indirection (zero behavior change in Slice 1):

```
AutonomicTick: SenseInputs() -> PolicyDecide(state, in) -> AutonomicApply(set)

PolicyDecide(state, in):
    rule_set = AutonomicEvaluate(state, in)             // rules = the floor + teacher
    net_set  = NeuralPolicyDecide(in)                   // empty in Slice 1
    final    = ShieldApply(cfg, in, rule_set, net_set)  // Slice 1: returns rule_set
    PolicyTrace(in, rule_set, net_set, final)           // KLOG_DEBUG + causal chain
    return final
```

- New TUs (extend the `env` subsystem, **not** a new `kernel/ml/`):
  - `kernel/env/neural_policy.{h,cpp}` — the learner core.
  - `kernel/env/policy_shield.{h,cpp}` — toggleable safeguards + config + master-off.

## The learner (fixed-point, no FPU)

- **Features** (`AutoInputs` -> ~6 normalized Q16 features; the same quantities
  the rules threshold on): free%, heap%, thermal, health-delta, loadavg/cpu,
  power-policy.
- **Network:** `6 -> 8 (ReLU) -> 10 logits`. **Multi-label** (each logit is an
  independent "fire action k?" gate, threshold `tau_k`) — the engine already
  fires action *sets*. `int16` (Q4.12) weights, `i64` accumulator, requantize
  by shift. ~256 bytes of `.bss`. No `kmalloc`.
- **Imitation by construction:** weights are hand-initialized so the net
  reproduces the rules (features *are* the rule predicates). No offline training
  pipeline in v1; shadow-mode self-test proves `net == rules`.
- **Online learning — three-factor reward-modulated Hebbian** (the "synaptic"
  rule): reward = delayed `env::feedback` outcome (Improved=+1, NoChange=0,
  Worsened=-1, Diagnostic=skip). `dW2_jk = eta * r * h_j * fired_k`. Only the
  output layer learns online (hidden layer = fixed imitation feature map). Only
  synapses for actions that *actually fired* update (credit assignment).
- **Stability bounds = shields:** bounded reward, small fixed `eta`, weight
  clamp `|W| <= W_max`, decay toward the imitation prior, capped `epsilon`-greedy
  exploration (kernel `util/random`).

## Shadow vs live

- **Shadow (Slice 2):** net infers; trace logs net-vs-rule agreement;
  **actuators stay rule-driven.** Pure data collection.
- **Live (Slice 3):** net gates drive `AutonomicApply`; feedback reward updates
  weights. Real online RL begins here, behind the shield, master-off available.

## Actuators (Slice 4) — system grain only

- New `AutoAction`s: `SchedRebalanceNow` (needs a thin new public
  `SchedRequestActiveBalance()` wrapper) and `SchedBalanceCadence(fast|normal|slow)`.
- **Excluded:** per-task affinity (wrong grain for a system-level policy).
- **Deferred** (each own slice, each needs a safety argument): runtime-tunable
  `kStealScanCap` / `kClusterPlacementMargin` (hot-path constexprs).

## Fix-journal proposal tie-in (Slice 4) — honest "generate patches"

- New stable detector `FixDetector::AutonomicProposal = 11`. Records a
  **reviewable record, never a code mutation** (DD#016): rule the net learned to
  avoid; net/rule persistent disagreement where net scored Improved; a weight
  pinned at its clamp. Flows ring -> FAT32 `KERNEL.FIX` -> **offline** patch
  generator -> brief -> human/Claude commits the source patch.
- **Under master-off flag:** the brain switches to an **aggressive proposal
  firehose** — one record per divergence/experiment, not just durable patterns —
  for full data capture. Still no code mutation.

## Toggle surface (your hard requirement)

- `ShieldConfig`: `constinit` bool per safeguard (`rule_floor_veto`,
  `action_clamp`, `circuit_breaker`, `explore_cap`, `forbidden_actions`), all
  **default ON**, + master `shields_enabled` (ON).
- `ShieldSetMaster(bool)` flips *all* in one call (easy master-off).
- Boot cmdline via `CmdlineMatches`: `autonomic=shadow|live|off`, `shields=on|off`.
- Shell: `autonomic mode <m>`, `autonomic shields <on|off>`, `autonomic weights`,
  `autonomic proposals`.

## Security decisions (append to Design-Decisions.md)

- **DD#016 upheld.** Runtime owns *learning* (weights = data in `.bss`); offline
  owns *committing code*. The kernel proposes from evidence; a reviewer disposes
  with authority. Rationale: self-modifying `.text` would trip the kernel's own
  `runtime_checker` (`KernelTextModified` -> Panic) and is a rootkit primitive;
  in-kernel code-gen can't produce a reviewable source patch anyway.

## Slice plan + verification

Each slice: `-Werror`, clang-format clean, a `[...] selftest pass` line, a
**freestanding hosted test** (QEMU CI skips bare-metal smokes), clean boot.

| Slice | Delivers | Key verification |
|---|---|---|
| **1** | `PolicyDecide` seam + shield + toggles + master-off + cmdline + verbose trace; net = no-op | `PolicyDecide == rules`; `PolicyShieldSelfTest`; host test for config/cmdline; boot unchanged |
| **2** | Fixed-point MLP forward pass + imitation init + shadow mode | `test_neural_policy.cpp`: forward determinism, `net == rules`, overflow bounds; shadow agreement ~100% |
| **3** | Three-factor online learning + reward wiring + epsilon-greedy + clamps/decay + live mode | host test: synthetic reward moves weights, clamp/decay hold, shield veto overrides; shielded + un-shielded boots |
| **4** | Load-balance actuators + `AutonomicProposal` records + firehose mode | sched wrapper self-test; proposal round-trips fix_journal; boot smoke |

## Cross-cutting (by construction)

- **No SMP contention:** weights owned by the single env-monitor/kselfthink task
  that already owns `g_state`/`g_report`; shell reads use existing lock-free
  snapshots.
- **No allocation:** fixed-size `.bss`.
- **Deterministic** with `epsilon=0` + shields-off given (weights, inputs) —
  reproducible host tests.
