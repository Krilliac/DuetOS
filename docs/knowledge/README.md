# docs/knowledge

Planning and living-decisions documents intended to capture long-range execution strategy for CustomOS.

## Contents

### Planning (forward-looking)

- `roadmap-to-gui-desktop.md` — end-to-end 13-track roadmap from current kernel state to native GUI desktop + Win32 app support.
- `security-malware-hard-stop-plan.md` — initial architecture and planning notes for malware prevention, execution gating, and hard-stop containment.
- `track-2-platform-foundation-implementation-plan.md` — detailed implementation plan for Track 2 (UEFI/ACPI/SMP/PCIe/diagnostics), including ordered work items, acceptance tests, and embedded security constraints.
- `implementation-backlog-gates.md` — execution backlog and gate framework translating roadmap tracks into epics, streams, and next-session checklist.
- `usb-xhci-scope-estimate.md` — scope estimate + staged plan for the USB HID path (PCI enumeration → xHCI → USB core → HID class). Explains why USB is deferred past the v0 PS/2 driver.

### Implementation ground-truth (append-only)

- `design-decisions-log.md` — **living log** of concrete decisions made while implementing the roadmap. One entry per committed slice; each includes rationale, what it defers, and a "Revisit when" trigger so the decision can be refined with new context (SMP, userland, first real peripheral, etc.). The forward-looking planning docs above describe **intent**; this log describes **what actually shipped**, flagging any divergence.

## How the two relate

When a planning doc says "do X one day" and the implementation log says "shipped Y as a simpler first step" — that's expected. The planning docs should be updated only when the divergence is deliberate and long-term (e.g. "we decided against X in favour of Y"). Transient deferrals stay in the log's "Revisit when" markers and don't churn the planning docs.

