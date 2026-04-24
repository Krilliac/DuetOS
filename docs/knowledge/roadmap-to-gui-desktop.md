# DuetOS Roadmap — From Current Kernel Bring-up to Full GUI Desktop

_Last updated: 2026-04-20_

## Purpose

This document is the **single source roadmap** for taking DuetOS from the current early kernel state to a usable graphical desktop that can run:

- native DuetOS applications, and
- Windows PE applications via the first-class Win32 subsystem.

This is intentionally thorough and front-loads decisions so implementation work can execute quickly and in sequence.

---

## 0) Current Baseline (assumed complete)

Based on current repo context and `.claude/index.md` quick reference:

- x86_64 kernel boots in higher-half.
- GDT/IDT, paging, frame allocator, kernel heap are online.
- LAPIC timer + preemptive scheduler v0 are online.
- Basic kernel threading and idle loop exist.

This roadmap starts from that baseline.

---

## 1) Master Delivery Plan (13 Program Tracks)

> We previously discussed “13 things needed.” This plan formalizes those as tracks with explicit outputs and dependencies.

### Track 1 — Build, Tooling, CI, and Deterministic Artifacts

**Goal:** Reliable daily development loop.

**Deliverables:**

- Stable CMake presets (`debug/release/sanitized`) for host + target tools.
- Reproducible kernel image build (pinned toolchain versions).
- ISO/image builder with deterministic metadata.
- CI matrix (format, build, hosted tests, image boot smoke).
- Artifact promotion policy (only signed, reproducible outputs).

**Exit criteria:** One-command local + CI build that emits bootable images consistently.

---

### Track 2 — Boot/Platform Foundation (UEFI-first, hardware discovery)

**Goal:** Production-grade platform bring-up path.

**Deliverables:**

- UEFI boot path finalized (memory map, framebuffer handoff, ACPI roots).
- ACPI parser (MADT, MCFG, FADT essentials).
- AP startup sequence and per-CPU init hardening.
- PCIe enumeration core with resource allocation.
- Early panic diagnostics with serial + framebuffer output.

**Exit criteria:** Boot succeeds across target QEMU profiles and at least 1 real machine profile.

---

### Track 3 — Memory Management Hardening

**Goal:** Secure and scalable VM model.

**Deliverables:**

- Full process address-space abstraction.
- User/kernel split enforcement, guard pages, copy-on-write.
- Demand paging scaffolding + page-fault policy engine.
- Kernel/user allocator strategy and fragmentation metrics.
- Strict W^X and NX enforcement pipeline.

**Exit criteria:** Isolated user processes with stable memory semantics and fault containment.

---

### Track 4 — Process Model, IPC, and Syscall ABI

**Goal:** Stable kernel contract for userland and subsystems.

**Deliverables:**

- Process lifecycle (`spawn/exec/exit/wait`) primitives.
- Handle/object model and namespace policy.
- Capability-based IPC channels/ports + shared memory.
- Syscall table governance + versioning rules.
- Audit-friendly syscall logging mode.

**Exit criteria:** Multi-process userland running under explicit ABI rules.

---

### Track 5 — Storage + VFS + Mount Model

**Goal:** Persistent and safe data plane.

**Deliverables:**

- VFS interfaces with mount manager.
- Native FS MVP (journaling policy + crash consistency).
- FAT/exFAT/NTFS/ext interoperability tiers (read-only first).
- Cache layers (page cache, dentry/inode cache).
- Permission model + future ACL hooks.

**Exit criteria:** Reliable boot volume + user data volume handling with recovery semantics.

---

### Track 6 — Device Driver Platform and Core Devices

**Goal:** Practical hardware support envelope.

**Deliverables:**

- Driver model (probe/bind/power/interrupt contract).
- Storage drivers (NVMe first, AHCI second).
- USB host + HID path for keyboard/mouse.
- NIC baseline (e1000/rtl8169) + net stack integration.
- Driver crash containment policy and telemetry.

**Exit criteria:** Interactive system on commodity hardware with persistent IO + input.

---

### Track 7 — Userland Runtime and Service Management

**Goal:** Boot to managed userland environment.

**Deliverables:**

- `init` (PID 1) service supervision graph.
- Core libc and runtime primitives.
- Logging, config, and service restart policy.
- Shell + diagnostic tools.
- Crash dump pipeline for kernel + user services.

**Exit criteria:** Text-mode multi-service OS session with recoverable failures.

---

### Track 8 — Graphics Foundation (Kernel + User-space)

**Goal:** GPU path suitable for desktop composition.

**Deliverables:**

- Display manager abstraction (modeset, planes, vblank).
- GPU memory manager + command submission path (tiered by vendor).
- Buffer allocation API for compositor + apps.
- Software renderer fallback.
- Vulkan ICD bootstrap path.

**Exit criteria:** Stable display output with compositable surfaces and basic acceleration.

---

### Track 9 — Windowing System + Desktop Shell

**Goal:** Usable GUI desktop session.

**Deliverables:**

- Window server protocol (surfaces, events, focus, z-order).
- Compositor (damage tracking, frame scheduling).
- Input routing (pointer/keyboard/IME hooks).
- Core desktop shell (taskbar/launcher/window controls/settings).
- Accessibility and DPI policy baseline.

**Exit criteria:** Daily-usable GUI desktop for native apps.

---

### Track 10 — Audio + Multimedia Stack

**Goal:** Low-latency audio and timing for desktop/apps.

**Deliverables:**

- Audio service (mixer graph, session routing, volume policy).
- Driver backend integration (Intel HDA first).
- Timer model for multimedia sync.
- WAV/PCM pipeline first, compressed codecs later.

**Exit criteria:** System sounds + app playback/recording in GUI session.

---

### Track 11 — Win32/NT Subsystem (Core Compatibility)

**Goal:** Run real PE user applications in supported profile.

**Deliverables:**

- PE loader (imports, relocations, TLS, SEH basics).
- `ntdll` + NT syscall surface mapping.
- `kernel32` process/thread/file/time/environment APIs.
- `user32` bridge into native window manager.
- `gdi32` software path then accelerated path.

**Exit criteria:** Meaningful Win32 test apps launch and operate in desktop session.

---

### Track 12 — 3D API Translation and App Compatibility Growth

**Goal:** Real-world app support growth.

**Deliverables:**

- DXGI + D3D11 translation to Vulkan.
- D3D12 feasibility tier and staged implementation.
- Compatibility test corpus + telemetry-driven prioritization.
- Per-title shims policy (minimize; document every shim).

**Exit criteria:** Curated Windows app set runs with acceptable performance.

---

### Track 13 — Security, Defense, Reliability, and Update Trust

**Goal:** System that is difficult to exploit and easy to trust.

**Deliverables:**

- Secure boot chain + measured boot attestation plan.
- Code-signing and executable trust policy engine.
- Runtime exploit mitigations (CFI, canaries, W^X, SMEP/SMAP).
- Anti-malware execution control architecture (hard-stop path).
- Update signing + rollback protection + incident response playbook.

**Exit criteria:** Security posture documented, enforced, and continuously tested.

---

## 2) Phasing Strategy

### Phase A — Platform Stabilization (Tracks 1–4)

Outcome: robust kernel + process foundation.

### Phase B — IO & Userland Maturity (Tracks 5–7)

Outcome: stable text-mode OS with services and persistence.

### Phase C — Desktop Bring-up (Tracks 8–10)

Outcome: native GUI desktop with input/audio/graphics.

### Phase D — Windows Compatibility Layer (Tracks 11–12)

Outcome: practical PE/Win32 app execution.

### Phase E — Security Hardening & Productization (Track 13 across all)

Outcome: defensible, maintainable, shippable platform profile.

---

## 3) Milestones (operational checkpoints)

- **M1:** Reproducible image + CI green path.
- **M2:** AP bring-up + stable process model.
- **M3:** VFS + storage + service-managed userland.
- **M4:** GPU/display baseline + window server online.
- **M5:** Desktop shell daily-usable.
- **M6:** First Win32 app class stable.
- **M7:** Security hardening gates mandatory for release builds.

---

## 4) Dependency Highlights (critical order constraints)

- Win32 GUI viability depends on native window manager/compositor maturity.
- D3D translation viability depends on Vulkan + GPU memory stability.
- Anti-malware hard-stop depends on executable trust hooks in loader + syscall/object policy.
- Update trust model must exist before broad hardware rollout.

---

## 5) Definition of Done (DoD) — per major subsystem

A subsystem is not done until all are true:

1. Implemented and wired into real boot/runtime path.
2. Negative tests exist (error/fault paths).
3. Metrics/telemetry points defined.
4. Security review checklist completed.
5. Documentation updated in `docs/knowledge/`.

---

## 6) Risks to Manage Early

- Driver complexity explosion across vendors.
- ABI drift in syscall/Win32 surfaces.
- Hidden global state in early subsystems causing race bugs later.
- Compatibility pressure creating short-term hacks that become permanent.
- Malware/threat modeling deferred too late.

---

## 7) Immediate Next Work (to resume from broken session)

Because earlier work stopped around “part 2 of 13,” proceed with:

1. Finalize Track 2 design docs (UEFI, ACPI, SMP, PCIe init order).
2. Draft executable trust pipeline requirements (Track 13 dependency).
3. Create implementation issue list per Track 2 component with ownership and test cases.
4. Define exact milestone acceptance tests for M1–M3.

---

## 8) Open Questions for Upcoming Review Sessions

- Exact executable trust policy: permissive/dev mode vs strict/signed-only mode defaults?
- Initial hardware certification set for desktop target (which GPU/NIC/storage combos)?
- Minimum Win32 compatibility target for first public preview (API subset + app categories)?
- Virtualization/sandbox boundary strategy for untrusted apps in early releases?
- Telemetry/privacy defaults and user control model?

---

## 9) Governance Notes

- No subsystem lands without owner + backup owner.
- No ABI-affecting change without written rationale.
- No “temporary” compatibility hacks without expiration condition.
- Security exceptions must be time-limited and tracked.

