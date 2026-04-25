# docs/knowledge

Living strategy + decisions documents. Day-to-day "what shipped"
notes live in `.claude/knowledge/`; this directory is for the
longer-lived material that survives across many slices.

## Contents

### Planning (forward-looking)

- `security-malware-hard-stop-plan.md` — initial architecture and
  planning notes for malware prevention, execution gating, and
  hard-stop containment.
- `smp-ap-bringup-scope.md` — staged plan for bringing up the APs on
  top of the existing SMP foundations (spinlock + PerCpu + MADT
  LAPIC enum + IPI helper). What's landed vs. the trampoline work
  still ahead.
- `runtime-recovery-strategy.md` — the **halt vs. restart vs. retry
  vs. reject** taxonomy. Source of truth for "when X happens, what
  does the kernel do?" Every subsystem defers to this and records
  any deviation in the design-decisions log.
- `linux-networking-port-opportunities-2026-04-25.md` — survey of
  Linux's `drivers/usb/host`, `drivers/net/usb`,
  `drivers/net/ethernet/intel/e1000e`, and `net/core` for things we
  could lift into DuetOS. Dated 2026-04-25; treat as a one-shot
  research log rather than a perpetual living doc.

### Implementation ground-truth (append-only)

- `design-decisions-log.md` — **living log** of concrete decisions
  made while implementing the roadmap. One entry per committed
  slice; each includes rationale, what it defers, and a "Revisit
  when" trigger so the decision can be refined with new context
  (SMP, userland, first real peripheral, etc.). The forward-looking
  planning docs above describe **intent**; this log describes
  **what actually shipped**, flagging any divergence.

## How the two relate

When a planning doc says "do X one day" and the implementation log
says "shipped Y as a simpler first step" — that's expected. The
planning docs should be updated only when the divergence is
deliberate and long-term (e.g. "we decided against X in favour of
Y"). Transient deferrals stay in the log's "Revisit when" markers
and don't churn the planning docs.

## Note on deleted planning docs

`roadmap-to-gui-desktop.md`, `track-2-platform-foundation-implementation-plan.md`,
`implementation-backlog-gates.md`, and `usb-xhci-scope-estimate.md`
were all retired on 2026-04-25 once the work they planned for had
shipped (windowed Win32 + live network + xHCI + storage). The
historical versions remain in git history if needed.
