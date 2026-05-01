# Persistence Context — Index

_Read this at every session start (after git sync). Each row links to a detailed knowledge file._

## Knowledge Index

| Topic | File | Type | Status | Last Updated |
|-------|------|------|--------|--------------|
| AI bloat pattern and countermeasures | [knowledge/ai-bloat-pattern.md](knowledge/ai-bloat-pattern.md) | Observation | Active | 2026-04-20 |
| clang-format — CI-matching invocation | [knowledge/clang-format.md](knowledge/clang-format.md) | Pattern | Active | 2026-04-20 |
| Git rebase conflict resolution | [knowledge/git-rebase-conflicts.md](knowledge/git-rebase-conflicts.md) | Pattern | Active | 2026-04-20 |
| GitHub API / PR checks diagnosis | [knowledge/github-api-pr-checks.md](knowledge/github-api-pr-checks.md) | Pattern | Active | 2026-04-20 |
| Build and CI workflow speedups | [knowledge/build-optimizations.md](knowledge/build-optimizations.md) | Optimization | Active | 2026-04-20 |
| Lifetime download tally — survives rolling-channel asset re-uploads | [knowledge/lifetime-downloads-tally-v0.md](knowledge/lifetime-downloads-tally-v0.md) | Issue + Decision + Pattern | Active | 2026-04-29 |
| Effective dev workflows | [knowledge/workflow-patterns.md](knowledge/workflow-patterns.md) | Pattern | Active | 2026-04-20 |
| **Subsystems status — Win32/NT + Linux ABI (consolidated)** | [knowledge/subsystems-status.md](knowledge/subsystems-status.md) | Decision + Observation | Active — single source of truth for the subsystems work | 2026-04-29 |
| Registry static-tree v0 — terminal + prefix tier + nested OpenKey + KEY_FULL_INFORMATION | [knowledge/registry-prefix-tree-v0.md](knowledge/registry-prefix-tree-v0.md) | Decision + Observation | Active | 2026-04-29 |
| Kernel breakpoint subsystem v0 + phase 2a (per-task DR, syscall, kCapDebug) + phase 3 (suspend/inspect/resume/step) + phase 4 (static KBP_PROBE macros) | [knowledge/breakpoints-v0.md](knowledge/breakpoints-v0.md) | Observation | Active | 2026-04-23 |
| Hardware target matrix (CPU/GPU/IO tiers) | [knowledge/hardware-target-matrix.md](knowledge/hardware-target-matrix.md) | Decision | Active | 2026-04-20 |
| UEFI hybrid-ISO boot path — same ISO boots SeaBIOS + OVMF | [knowledge/uefi-hybrid-iso-v0.md](knowledge/uefi-hybrid-iso-v0.md) | Observation | Active | 2026-04-23 |
| Result<T, E> — kernel exception-handling primitive (software side) | [knowledge/result-type-v0.md](knowledge/result-type-v0.md) | Decision + Pattern | Active | 2026-04-23 |
| DebugPanicOrWarn — release-stable variant of Panic (debug-panic / release-warn-and-recover) — 58 sites converted across 6 passes | [knowledge/debug-panic-or-warn-v0.md](knowledge/debug-panic-or-warn-v0.md) | Decision + Pattern | Active | 2026-05-01 |
| Kernel-stack guard pages v0 — unmapped low-edge page per task | [knowledge/kernel-stack-guard-v0.md](knowledge/kernel-stack-guard-v0.md) | Observation + Decision | Active | 2026-04-23 |
| Kernel isolation v0 — extable + fault domains | [knowledge/kernel-isolation-v0.md](knowledge/kernel-isolation-v0.md) | Decision + Pattern | Active | 2026-04-23 |
| Rust bring-up plan — trigger, layout, toolchain, CI | [knowledge/rust-bringup-plan.md](knowledge/rust-bringup-plan.md) | Decision | Active | 2026-04-21 |
| Storage + Filesystem roadmap — block layer → NVMe/AHCI → GPT → FS | [knowledge/storage-and-filesystem-roadmap.md](knowledge/storage-and-filesystem-roadmap.md) | Decision | Active (stages 1–2, 4 landed) | 2026-04-21 |
| NVMe driver v0 — polling admin + I/O queue, marker self-test | [knowledge/nvme-driver-v0.md](knowledge/nvme-driver-v0.md) | Observation | Active | 2026-04-21 |
| GPT parser v0 — PMBR + primary header + entries, CRC-validated | [knowledge/gpt-parser-v0.md](knowledge/gpt-parser-v0.md) | Observation | Active | 2026-04-21 |
| klog overhaul — Trace + scopes + metrics + sinks + colour | [knowledge/klog-overhaul.md](knowledge/klog-overhaul.md) | Observation | Active | 2026-04-21 |
| Security guard — image-load protection | [knowledge/security-guard.md](knowledge/security-guard.md) | Decision | Active | 2026-04-21 |
| `inspect` umbrella v0 — `syscalls` / `opcodes` / `arm` subcommands | [knowledge/inspect-umbrella-v0.md](knowledge/inspect-umbrella-v0.md) | Observation | Active | 2026-04-23 |
| Native DuetOS apps v0 — pattern for in-kernel applications | [knowledge/native-apps-v0.md](knowledge/native-apps-v0.md) | Pattern | Active | 2026-04-21 |
| gfxdemo multi-mode v0 — six animated effects (plasma/mandelbrot/cube/particles/starfield/fire) + key dispatch + self-tests | [knowledge/gfxdemo-multimode-v0.md](knowledge/gfxdemo-multimode-v0.md) | Observation + Pattern | Active | 2026-04-26 |
| Desktop chrome polish v0 — fb line/circle/round-rect-outline/drop-shadow + window gradient titles + X-glyph close + taskbar gradient strip + rounded START/tabs + active-tab accent | [knowledge/desktop-chrome-polish-v0.md](knowledge/desktop-chrome-polish-v0.md) | Observation + Decision | Active | 2026-04-29 |
| End-user onboarding v0 — Start menu app launchers + ThemeRoleWindow + F1 shortcut help + post-login banner | [knowledge/end-user-onboarding-v0.md](knowledge/end-user-onboarding-v0.md) | Observation + Decision | Active | 2026-05-01 |
| End-user feature gaps v0 — prioritized inventory of what an ordinary user notices is missing (audio / Wi-Fi / save-to-disk / Settings panel / accessibility) | [knowledge/feature-gaps-end-user-v0.md](knowledge/feature-gaps-end-user-v0.md) | Observation + Decision | Active — 13 of 27 fully landed + P0 #4 Wi-Fi data-decode tier complete 2026-05-01 (all three vendor envelope parsers + 802.11 beacon walker); control tier (upload + MLME) gated on real-HW verification | 2026-05-01 |
| iwlwifi TLV firmware parser v0 — Intel microcode envelope walker (zero/magic preamble, 64-byte name, ver/build, INST/DATA/INIT/INIT_DATA/SEC_RT capture, length-overflow bounds check) wired into IwlwifiBringUp + boot self-test (synthetic 7-record blob + 3 negative cases) | [knowledge/iwl-fw-tlv-parser-v0.md](knowledge/iwl-fw-tlv-parser-v0.md) | Observation + Decision | Active — parser only; microcode upload + MLME still deferred | 2026-05-01 |
| Wireless firmware parsers v0 (rtl88xx + bcm43xx + iwlwifi consolidated) — clean-room envelope walkers across all three wireless vendors: Realtek 32-byte rtlwifi/rtw88/rtw89 header (signature classification + tolerant ramcodesize) + Broadcom b43 record stream (`'u'`/`'p'`/`'i'` types, big-endian 8-byte headers, bounded 8-record table), wired into respective BringUp paths + boot self-tests for each | [knowledge/wireless-fw-parsers-v0.md](knowledge/wireless-fw-parsers-v0.md) | Observation + Decision | Active — parsers only; microcode upload + MLME still deferred (real-HW gated) | 2026-05-01 |
| IEEE 802.11 frame headers + beacon parser v0 — `kernel/net/wireless/ieee80211.h` (frame-control bits, type/subtype, capability bits, 35 IE IDs + 4 ID extensions, 12 cipher suites, 12 AKM suites) + `beacon.{h,cpp}` (BeaconParse → BeaconParsed with SSID/channel/rates/RSN-derived security taxonomy across Open/WEP/WPA/WPA2/WPA3/Wpa2Ent/Wpa3Ent + boot self-test exercising 5 frame variants) | [knowledge/ieee80211-beacon-parser-v0.md](knowledge/ieee80211-beacon-parser-v0.md) | Observation + Decision | Active — beacon/probe-resp decode only; TX, RX dispatch, MLME still deferred | 2026-05-01 |
| Disk installer plan (P2 #16) — GPT write + FAT32 mkfs prerequisites, verification ladder (RAM-disk → QEMU → hardware), risk notes for the destructive-write paths | [knowledge/disk-installer-plan.md](knowledge/disk-installer-plan.md) | Plan | Pending — strictly blocked on infra (gpt.cpp is probe-only, no Fat32Format yet) | 2026-05-01 |
| Kernel bring-up v0 (Multiboot2 → long mode → `kernel_main`) | [knowledge/kernel-bringup-v0.md](knowledge/kernel-bringup-v0.md) | Observation | Active | 2026-04-20 |
| ISO build & end-to-end boot verification | [knowledge/iso-build-and-boot.md](knowledge/iso-build-and-boot.md) | Pattern | Active | 2026-04-20 |
| GDT + IDT v0 — canonical descriptors and trap path | [knowledge/gdt-idt-v0.md](knowledge/gdt-idt-v0.md) | Observation | Active | 2026-04-20 |
| Physical frame allocator v0 — bitmap over Multiboot2 map | [knowledge/frame-allocator-v0.md](knowledge/frame-allocator-v0.md) | Observation | Active | 2026-04-20 |
| Higher-half kernel move v0 — `0xFFFFFFFF80000000` | [knowledge/higher-half-kernel-v0.md](knowledge/higher-half-kernel-v0.md) | Observation | Active | 2026-04-20 |
| Boot stack high-VMA alias — fixes #DF on first boot→user CR3 switch under load | [knowledge/boot-stack-high-vma-fix.md](knowledge/boot-stack-high-vma-fix.md) | Issue + Pattern | Active | 2026-04-26 |
| Debug tooling — `addr2sym` shell command + `tools/debug/disasm-at.sh` + `tools/debug/decode-panic.sh` | [knowledge/debug-tooling-symbol-disasm.md](knowledge/debug-tooling-symbol-disasm.md) | Pattern | Active | 2026-04-26 |
| Kernel heap v0 — first-fit + coalescing over direct map | [knowledge/kernel-heap-v0.md](knowledge/kernel-heap-v0.md) | Observation | Active | 2026-04-20 |
| Managed page-table API v0 — 4-level walker over boot PML4 | [knowledge/paging-v0.md](knowledge/paging-v0.md) | Observation | Active | 2026-04-20 |
| LAPIC + periodic timer v0 — PIT-calibrated 100 Hz tick | [knowledge/lapic-timer-v0.md](knowledge/lapic-timer-v0.md) | Observation | Active | 2026-04-20 |
| Scheduler v0 — round-robin kernel threads with preemption | [knowledge/scheduler-v0.md](knowledge/scheduler-v0.md) | Observation | Active | 2026-04-20 |
| Scheduler blocking primitives v0 — sleep, wait queues, mutex | [knowledge/sched-blocking-primitives-v0.md](knowledge/sched-blocking-primitives-v0.md) | Observation | Active | 2026-04-20 |
| ACPI MADT discovery v0 — RSDP → XSDT/RSDT → APIC table | [knowledge/acpi-madt-v0.md](knowledge/acpi-madt-v0.md) | Observation | Active | 2026-04-20 |
| IOAPIC driver v0 — MMIO redirection table + ACPI override routing | [knowledge/ioapic-v0.md](knowledge/ioapic-v0.md) | Observation | Active | 2026-04-20 |
| PS/2 keyboard v0 — first end-to-end IRQ-driven driver | [knowledge/ps2-keyboard-v0.md](knowledge/ps2-keyboard-v0.md) | Observation | Active | 2026-04-20 |
| Boot verification v0 — end-to-end QEMU boot baseline | [knowledge/boot-verification-v0.md](knowledge/boot-verification-v0.md) | Observation | Active | 2026-04-20 |
| Per-process address space v0 — `mm::AddressSpace`, per-task PML4, isolation | [knowledge/per-process-address-space-v0.md](knowledge/per-process-address-space-v0.md) | Observation | Active | 2026-04-20 |
| Process + capability model v0 — `core::Process`, `CapSet`, cap-gated syscalls | [knowledge/process-capabilities-v0.md](knowledge/process-capabilities-v0.md) | Observation | Active | 2026-04-20 |
| VFS namespace + per-process root v0 — ramfs + `Process::root` + SYS_STAT | [knowledge/vfs-namespace-v0.md](knowledge/vfs-namespace-v0.md) | Observation | Active | 2026-04-20 |
| Sandboxing overview v0 — consolidated 5-wall story across AS/caps/VFS/W^X/budget | [knowledge/sandbox-overview-v0.md](knowledge/sandbox-overview-v0.md) | Decision | Active | 2026-04-20 |
| DEP / NX / W^X v0 — EFER.NXE, map-time gate, kernel-image split, live probes | [knowledge/dep-nx-v0.md](knowledge/dep-nx-v0.md) | Observation | Active | 2026-04-20 |
| Detour / hook hardening v0 — threat-model table + every wall mapped | [knowledge/detour-hook-hardening-v0.md](knowledge/detour-hook-hardening-v0.md) | Decision | Active | 2026-04-20 |
| SMP foundations v0 — spinlocks + per-CPU data | [knowledge/smp-foundations-v0.md](knowledge/smp-foundations-v0.md) | Observation | Active | 2026-04-20 |
| Runtime recovery strategy — halt/restart/retry/reject taxonomy | [../docs/knowledge/runtime-recovery-strategy.md](../docs/knowledge/runtime-recovery-strategy.md) | Decision | Active | 2026-04-20 |
| PCI enumeration v0 — legacy port-IO walk | [knowledge/pci-enum-v0.md](knowledge/pci-enum-v0.md) | Observation | Active | 2026-04-20 |
| GPU discovery v0 — PCI classification + BAR map | [knowledge/gpu-discovery-v0.md](knowledge/gpu-discovery-v0.md) | Observation | Active | 2026-04-22 |
| Driver shells v0 — net / usb / audio / gpu-probes | [knowledge/driver-shells-v0.md](knowledge/driver-shells-v0.md) | Observation | Active | 2026-04-22 |
| Render / drivers — current state (through v6) | [knowledge/render-drivers-v6.md](knowledge/render-drivers-v6.md) | Observation + Decision | Active | 2026-04-25 |
| xHCI enumeration v0 — Address Device + GET_DESCRIPTOR(Device) | [knowledge/xhci-enumeration-v0.md](knowledge/xhci-enumeration-v0.md) | Observation | Active | 2026-04-23 |
| xHCI HID boot keyboard — end-to-end USB keyboard input | [knowledge/xhci-hid-keyboard-v0.md](knowledge/xhci-hid-keyboard-v0.md) | Observation | Active | 2026-04-23 |
| Intel e1000 NIC driver — real packet I/O on commodity wired gigabit | [knowledge/e1000-driver-v0.md](knowledge/e1000-driver-v0.md) | Observation | Active | 2026-04-23 |
| Network shell commands — ifconfig / dhcp / route / netscan / net | [knowledge/network-shell-commands-v0.md](knowledge/network-shell-commands-v0.md) | Observation | Active | 2026-04-25 |
| Network flyout panel — bottom-right Wi-Fi-style popup with hover preview | [knowledge/network-flyout-panel-v0.md](knowledge/network-flyout-panel-v0.md) | Observation + Decision | Active | 2026-04-25 |
| Wireless driver shells v0 — iwlwifi / rtl88xx / bcm43xx chip-id bring-up | [knowledge/wireless-drivers-v0.md](knowledge/wireless-drivers-v0.md) | Observation + Decision | Active | 2026-04-25 |
| Live Internet connectivity v0 — DuetOS reaches Google over real DNS + TCP | [knowledge/live-internet-connectivity-v0.md](knowledge/live-internet-connectivity-v0.md) | Observation + Pattern | Active | 2026-04-25 |
| Live Internet QEMU SLIRP — `netsmoke=force` flag + e1000e RX-poll bounded wait fix | [knowledge/live-internet-qemu-slirp-v0.md](knowledge/live-internet-qemu-slirp-v0.md) | Observation + Issue + Pattern | Active | 2026-04-30 |
| mini_browser — real Windows PE on DuetOS reaches google.com (WSAStartup→gethostbyname→socket→connect→send→recv→close) end-to-end | [knowledge/mini-browser-runs-on-duetos-v0.md](knowledge/mini-browser-runs-on-duetos-v0.md) | Observation + Issue + Pattern | Active | 2026-04-30 |
| Smoke PE suite v0 — 6 PE apps (mini_browser/crypto/paths/time/iphlpapi/wininet) covering 28 PASS Win32 APIs + gap inventory | [knowledge/smoke-pe-suite-v0.md](knowledge/smoke-pe-suite-v0.md) | Observation + Pattern | Superseded by v1 | 2026-04-30 |
| Smoke PE suite v1 — expanded to 13 apps (+string/mem/fs/registry/handle/process/module) covering 80 PASS Win32 APIs | [knowledge/smoke-pe-suite-v1.md](knowledge/smoke-pe-suite-v1.md) | Observation + Pattern + Issue | Superseded by v2 | 2026-04-30 |
| Smoke PE suite v2 — expanded to 22 apps (+env/debug/codepage/rng/version/psapi/com/dbghelp/winhttp) covering 112 PASS Win32 APIs | [knowledge/smoke-pe-suite-v2.md](knowledge/smoke-pe-suite-v2.md) | Observation + Pattern + Issue | Superseded by v3 | 2026-04-30 |
| Smoke PE suite v3 — expanded to 30 apps (+crt/critsec/tls/atom/console/datetime/locale/gdi) covering 143 PASS Win32 APIs | [knowledge/smoke-pe-suite-v3.md](knowledge/smoke-pe-suite-v3.md) | Observation + Pattern + Issue | Superseded by v4 | 2026-04-30 |
| Smoke PE suite v4 — expanded to 36 apps (+msg/pipe/resource/ntdll/shell/userenv) + msvcrt-exports/locale/atom impls covering 177 PASS Win32 APIs | [knowledge/smoke-pe-suite-v4.md](knowledge/smoke-pe-suite-v4.md) | Observation + Pattern + Issue | Superseded by v5 | 2026-04-30 |
| Smoke PE suite v5 — expanded to 44 apps (+interlock/fiber/profile/clipboard/windowclass/wow64/mathlib/stdio) + psapi/timezone/console-SBI/fs impls covering 213 PASS Win32 APIs | [knowledge/smoke-pe-suite-v5.md](knowledge/smoke-pe-suite-v5.md) | Observation + Pattern + Issue | Superseded by v6 | 2026-04-30 |
| Smoke PE suite v6 — expanded to 52 apps (+nls/services/eventlog/sound/multimon/power/heap/thread2) + wininet/winhttp sentinel handles covering 242 PASS Win32 APIs | [knowledge/smoke-pe-suite-v6.md](knowledge/smoke-pe-suite-v6.md) | Observation + Pattern + Issue | Superseded by v7 | 2026-04-30 |
| Smoke PE suite v7 — expanded to 60 apps (+ipc/jobobj/console2/dns/network2/dxgi/dwm/uxtheme) covering 259 PASS Win32 APIs | [knowledge/smoke-pe-suite-v7.md](knowledge/smoke-pe-suite-v7.md) | Observation + Pattern + Issue | Superseded by v8 | 2026-04-30 |
| Smoke PE suite v8 — expanded to 68 apps (+token/security/perf/accel/wts/winerr/sleep/nt) + console-cursor + jobobj + filemapping impls covering 284 PASS Win32 APIs | [knowledge/smoke-pe-suite-v8.md](knowledge/smoke-pe-suite-v8.md) | Observation + Pattern + Issue | Superseded by v9 | 2026-04-30 |
| Smoke PE suite v9 — expanded to 76 apps (+vol/drive/conio/mbcs/fpcontrol/locale2/gdiplus/dde) covering 294 PASS Win32 APIs | [knowledge/smoke-pe-suite-v9.md](knowledge/smoke-pe-suite-v9.md) | Observation + Pattern + Issue | Superseded by v10 | 2026-04-30 |
| Smoke PE suite v10 — expanded to 84 apps (+stream/setupapi/asyn/wndmsg/scrap/trace/wmi/enviro) covering 313 PASS Win32 APIs | [knowledge/smoke-pe-suite-v10.md](knowledge/smoke-pe-suite-v10.md) | Observation + Pattern + Issue | Superseded by v11 | 2026-04-30 |
| Smoke PE suite v11 — expanded to 91 apps (+select/proc2/find/iocp2/signal/timer/winsock_ext) covering 325 PASS Win32 APIs | [knowledge/smoke-pe-suite-v11.md](knowledge/smoke-pe-suite-v11.md) | Observation + Pattern + Issue | Superseded by v12 | 2026-04-30 |
| Smoke PE suite v12 — expanded to 97 apps (+key/reg2/paths2/advapi/heap3/thread3) + IOCP/timer/power impls covering 357 PASS Win32 APIs | [knowledge/smoke-pe-suite-v12.md](knowledge/smoke-pe-suite-v12.md) | Observation + Pattern + Issue | Superseded by v13 | 2026-04-30 |
| Smoke PE suite v13 — expanded to 105 apps (+wstr/intl/disp/svc_ctrl/sysinfo/mem2/fs2/console3) covering 374 PASS Win32 APIs | [knowledge/smoke-pe-suite-v13.md](knowledge/smoke-pe-suite-v13.md) | Observation + Pattern + Issue | Superseded by v14 | 2026-04-30 |
| Smoke PE suite v14 — expanded to 112 apps (+xml/reg3/proc3/com2/advmem/wstr2/fs3) + GeoInfo/CalInfo/DpiForSystem impls covering 394 PASS Win32 APIs | [knowledge/smoke-pe-suite-v14.md](knowledge/smoke-pe-suite-v14.md) | Observation + Pattern + Issue | Superseded by v15 | 2026-04-30 |
| Smoke PE suite v15 — expanded to 118 apps (+cap/utf16/handle2/sock_opt/prio/debug2) + SD/ACL/SID impls covering 411 PASS Win32 APIs | [knowledge/smoke-pe-suite-v15.md](knowledge/smoke-pe-suite-v15.md) | Observation + Pattern + Issue | Superseded by v16 | 2026-04-30 |
| Smoke PE suite v16 — pass-rate lift to 81.4%: iphlpapi tables/NLS-formats/profile-INI/volume-info impls covering 421 PASS Win32 APIs (118 apps) | [knowledge/smoke-pe-suite-v16.md](knowledge/smoke-pe-suite-v16.md) | Observation + Pattern + Issue | Superseded by v17 | 2026-04-30 |
| Smoke PE suite v17 — pass-rate lift to 83.4%: multimon/gdi/dde/userenv impls covering 432 PASS Win32 APIs (118 apps) | [knowledge/smoke-pe-suite-v17.md](knowledge/smoke-pe-suite-v17.md) | Observation + Pattern + Issue | Superseded by v18 | 2026-04-30 |
| Smoke PE suite v18 — pass-rate lift to **87.3%**: 21 new kernel32 + 8 new msvcrt exports covering 452 PASS Win32 APIs (118 apps) | [knowledge/smoke-pe-suite-v18.md](knowledge/smoke-pe-suite-v18.md) | Observation + Pattern + Issue | Superseded by v19 | 2026-04-30 |
| Smoke PE suite v19 — pass-rate lift to **89.5%**: shell/uxtheme/select/winsock-ext/token/vol/proc2/winerr/enviro/accel impls covering 469 PASS Win32 APIs (118 apps) | [knowledge/smoke-pe-suite-v19.md](knowledge/smoke-pe-suite-v19.md) | Observation + Pattern + Issue | Superseded by v20 | 2026-04-30 |
| Smoke PE suite v20 — **broke 90% (91.3%)**: SystemTimeToFileTime/fopen/aligned-malloc/CreatePipe/SCM impls covering 493 PASS Win32 APIs (118 apps) | [knowledge/smoke-pe-suite-v20.md](knowledge/smoke-pe-suite-v20.md) | Observation + Pattern + Issue | Superseded by v21 | 2026-04-30 |
| Smoke PE suite v21 — pass-rate **92.4%**: GetProcessId/ThreadId pseudo-handle + VEH + shlwapi PathCanonicalize/Rename/Quote impls covering 502 PASS Win32 APIs (118 apps) | [knowledge/smoke-pe-suite-v21.md](knowledge/smoke-pe-suite-v21.md) | Observation + Pattern + Issue | Superseded by v22 | 2026-04-30 |
| Smoke PE suite v22 — pass-rate **93.2%**: ole32 StringFromGUID2 + user32 GetDpiFor* + kernel32 GetMaxProcCount + advapi32 CryptGenRandom bridge covering 505 PASS Win32 APIs (118 apps) | [knowledge/smoke-pe-suite-v22.md](knowledge/smoke-pe-suite-v22.md) | Observation + Pattern + Issue | Superseded by v23 | 2026-04-30 |
| Smoke PE suite v23 — pass-rate **93.7%**: msvcrt memcpy/memmove/memset re-exports (mingw-w64 imports them via msvcrt) covering 505 PASS Win32 APIs (118 apps) | [knowledge/smoke-pe-suite-v23.md](knowledge/smoke-pe-suite-v23.md) | Observation + Pattern | Active | 2026-04-30 |
| **DirectX v0 — full COM-vtable surface across 11 DLLs (d3d{9,11,12}/dxgi pre-existing + dinput8/xinput1_4/xaudio2_8/dsound/ddraw/d2d1/dwrite new) + 10 smoke PEs walking real Clear+Present pipelines** | [knowledge/directx-v0.md](knowledge/directx-v0.md) | Observation + Decision + Pattern | Active | 2026-04-30 |
| DirectX gap-fill v0 — DirectInput keyboard/mouse → SYS_WIN_GET_KEYSTATE/CURSOR; D2D1 FillEllipse/DrawEllipse/DrawRectangle/DrawLine; DWrite GetMetrics monospace approximation | [knowledge/directx-input-d2d-dwrite-wire-v0.md](knowledge/directx-input-d2d-dwrite-wire-v0.md) | Observation + Pattern | Active | 2026-04-30 |
| USB CDC-ECM driver + xHCI bulk-transfer API v0 | [knowledge/usb-cdc-ecm-driver-v0.md](knowledge/usb-cdc-ecm-driver-v0.md) | Observation + Decision | Active (probe not auto-called) | 2026-04-25 |
| USB RNDIS driver + bulk-poll serialization v0 | [knowledge/usb-rndis-driver-v0.md](knowledge/usb-rndis-driver-v0.md) | Observation + Decision | Active (control plane works; bulk concurrency gap) | 2026-04-25 |
| KPTI / Meltdown — investigation v0 | [knowledge/kpti-meltdown-investigation-v0.md](knowledge/kpti-meltdown-investigation-v0.md) | Decision + Observation | Active — answer "no, deferred" recorded; trigger conditions for re-eval listed | 2026-04-27 |
| Kernel & debug design recommendations — 18-item leverage-ordered plan | [knowledge/kernel-debug-recommendations-plan.md](knowledge/kernel-debug-recommendations-plan.md) | Plan | Closed 2026-04-28 — every numbered recommendation landed v0; remaining large items (B2 SMP, KPTI/CET enable, real per-zone allocator, slab+KASAN, ABI handle migration, GDB stub completion, more driver-domain registrations) graduated to post-debug-recommendations-plan.md | 2026-04-28 |
| Post-recommendations follow-on plan — graduated large items from the closed recommendations plan | [knowledge/post-debug-recommendations-plan.md](knowledge/post-debug-recommendations-plan.md) | Plan | Active — captures B2 SMP, CET enable, KPTI enable, per-zone allocator, slab+KASAN, ABI handle migration, GDB stub completion, more driver fault-domain registrations | 2026-04-28 |
| Kernel entropy pool — RDSEED/RDRAND/splitmix tier | [knowledge/kernel-entropy-v0.md](knowledge/kernel-entropy-v0.md) | Observation | Active | 2026-04-22 |
| Runtime invariant checker — heap/frames/sched/CRx/canary/stack-overflow | [knowledge/runtime-invariant-checker-v0.md](knowledge/runtime-invariant-checker-v0.md) | Observation | Active | 2026-04-22 |
| Crash dump v0 — embedded symbol table + bracketed dump file (+ register-bit decoders + GPR symbolization + readable uptime/task labels + tree-wide hex log readability pass: PCI/NVMe/AHCI/xHCI/USB/PE/GPT/ext4/FAT32/Linux-signals/Win32-NTSTATUS + VA-region tags on cr2/rsp/rbp/rip + boot-time mm-map anchor + peer-CPU NMI snapshots + per-CPU held-locks dump) | [knowledge/crash-dump-v0.md](knowledge/crash-dump-v0.md) | Observation | Active | 2026-04-25 |
| Ring 3 first slice — GDT user segments + iretq entry + smoke task | [knowledge/ring3-first-slice-v0.md](knowledge/ring3-first-slice-v0.md) | Observation | Active | 2026-04-20 |
| Ring-3 adversarial test suite — jail / nx / priv / badint / kread probes | [knowledge/pentest-ring3-adversarial-v0.md](knowledge/pentest-ring3-adversarial-v0.md) | Pattern | Active | 2026-04-21 |
| GUI pentest runner v0 — live login + shell attack findings | [knowledge/pentest-gui-findings-v0.md](knowledge/pentest-gui-findings-v0.md) | Observation | Active | 2026-04-24 |
| Kernel attacker simulation suite v1 — 11 active attacks (bootkit, IDT, GDT, LSTAR, SYSENTER_CS/EIP, CR0.WP, SMEP, SMAP, NXE, .text patch) + deferred catalogue | [knowledge/attack-sim-kernel-v1.md](knowledge/attack-sim-kernel-v1.md) | Observation + Pattern | Active | 2026-04-26 |
| Redteam coverage matrix v0 — full malware-technique map vs. existing probes / attacks / detectors + gap analysis + slice-order roadmap | [knowledge/redteam-coverage-matrix-v0.md](knowledge/redteam-coverage-matrix-v0.md) | Observation + Decision | Active | 2026-04-26 |
| Cleanroom-trace boot survey v0 — first live read of the trace ring buffer | [knowledge/cleanroom-trace-boot-survey-v0.md](knowledge/cleanroom-trace-boot-survey-v0.md) | Observation | Active | 2026-04-25 |
| qemu-smoke profile-matrix redesign — split monolith into per-profile parallel jobs + isa-debug-exit + serial spinlock + hosted unit tests | [knowledge/qemu-smoke-profile-matrix-v0.md](knowledge/qemu-smoke-profile-matrix-v0.md) | Decision + Pattern | Active | 2026-04-28 |
| qemu-smoke #DE flake at PicDisable — held legacy IRQ delivered to master 8259 pre-init vector base 0; fixed via mask-first + CLI-around in PicDisable; smoke retry-on-flake tier removed so future crashes always fail | [knowledge/qemu-smoke-pic-de-flake-v0.md](knowledge/qemu-smoke-pic-de-flake-v0.md) | Issue + Pattern | Fixed | 2026-04-30 |
| KMalloc-zero-init pattern — every kernel struct with embedded sync primitives must memset before use | [knowledge/kmalloc-zero-init-pattern.md](knowledge/kmalloc-zero-init-pattern.md) | Pattern + Issue | Active | 2026-04-28 |
| Deferred-task batches (2026-04-25 + 2026-04-26 follow-up) — PE ordinal forwarders + by-ord IAT + binary-search EAT, ext4 multi-block dirs, ext4 depth>0 extent tree walk, GDI ellipse fill/outline parity, RNDIS multi-record RX, FAT32 LFN-checksum, window-DC SetTextColor explicit-black | [knowledge/deferred-task-batch-2026-04-25.md](knowledge/deferred-task-batch-2026-04-25.md) | Observation | Active | 2026-04-26 |
| Build flavors v0 — central debug/release configuration (build_config.h + DEBUG_ASSERT + cap-audit + boot banner + new presets) | [knowledge/build-flavors-v0.md](knowledge/build-flavors-v0.md) | Decision + Pattern | Active | 2026-04-29 |

## Quick Reference

### Current Project State (2026-04-25)

The system boots end-to-end on QEMU `-vga virtio` and exercises every
landed subsystem on its way to the desktop. Headline capabilities:

- **PE / Win32**: Real-world MSVC PEs (e.g. `windows-kill.exe`, ~80 KB,
  52 imports across 6 DLLs, SEH + TLS + resources) load and exit
  cleanly. Stage-2 PE loader chases forwarders (name + ordinal) through
  the per-process DLL table; ordinal-form `Dll.#N` forwarders are
  parsed; by-ordinal IAT entries resolve against preloaded EATs;
  `PeExportLookupName` is binary-search.
- **Win32 windowing**: `windowed_hello` paints with GDI primitives,
  pumps `WM_TIMER`s, dispatches `WM_PAINT` through a user-registered
  WndProc, round-trips `SendMessage`, queries focus / styles / palette,
  exits cleanly. `text_color_set` flag honors explicit-black
  `SetTextColor`. Filled-ellipse compositor prim parity between
  window-HDC and memDC paths.
- **Storage / FS**: NVMe + GPT + FAT32 + ext4 read paths. FAT32 LFN
  walker validates the per-fragment checksum against the trailing SFN
  (orphaned LFN runs fall back to the 8.3 name). ext4 root-dir walk
  iterates every leaf-extent block; depth>0 still deferred.
- **Net**: e1000 wired NIC + USB CDC-ECM + USB RNDIS for live
  Internet. RNDIS RX delivers every `RNDIS_PACKET_MSG` per bulk
  transfer (was: only the first).
- **Render**: virtio-gpu 2D scanout cycle as the kernel framebuffer;
  Classic-theme system palette; 8×8 font.
- **Security**: SMEP / SMAP / NX / W^X / KASLR / CFI all on; image-load
  guard; per-process address spaces; sandbox 5-wall story.

Branch convention: each Claude-driven slice runs on its own
`claude/<slug>` feature branch. Merge target is `main`. The active
branch for any given session is whatever the harness checked out;
session-start git sync rebases on `origin/main` first.

- **Default branch**: `main`.
- **Platforms**: x86_64 first (Multiboot2 → long mode + UEFI hybrid
  ISO). ARM64 planned, not started.
- **Toolchain**: clang 18.1.3, lld 18, cmake 3.28, GNU assembler via
  clang (`.S` files with Intel syntax). NASM not required yet.
- **Build**: `cmake --preset x86_64-debug` / `x86_64-release`. Output:
  `build/<preset>/kernel/duetos-kernel.elf`.
- **Live-test tooling on demand**: `qemu-system-x86_64`, `ovmf`,
  `grub-mkrescue`, `xorriso`, `mtools` are NOT pre-installed on the
  dev host. CLAUDE.md → "Live-test runtime tooling — install on
  demand" lists when to install (runtime-behaviour deltas, not pure
  refactors) and the apt line.
- **CI**: not yet wired. When it lands, mirror locally with the
  commands in CLAUDE.md → "Pre-commit checks".

### Project Pillars (one-liners)

- PE executables run as a **native ABI**, not through an emulator shell.
- Kernel is a **hybrid** (microkernel IPC shape, monolithic hot paths).
- **Direct GPU drivers** for Intel / AMD / NVIDIA; Vulkan is the primary user-mode API.
- **Capability-based IPC**; no setuid.
- **W^X, ASLR, SMEP/SMAP, KASLR, CFI** enforced from day one.

### Before Writing Code

1. Check file size — if over 500 lines (`.cpp`/`.c`/`.rs`) or 300 lines (`.h`/`.hpp`), consider splitting.
2. Search for existing implementations before adding new ones — especially low-level primitives (spinlocks, allocators, list helpers).
3. Be explicit about kernel vs. user space. Kernel has no `malloc`, no `printf`, no exceptions.
4. Run `clang-format -i` on modified files before committing.
5. If adding a syscall number, remember: **once published, it's ABI forever.**

### CI Quick Reference

- Once CI is online, treat `check-format` as the canonical formatter check. Mirror it locally using the full command in `.claude/knowledge/clang-format.md`.
- Use GitHub MCP tools in this environment (not `gh`) for PR polling. See `.claude/knowledge/github-api-pr-checks.md`.
- Pre-push order: format → configure → build → tests → QEMU smoke.

---

_To add a new entry: create a file in `knowledge/`, add a row to the table above, then commit both. Delete completed single-shot session logs — the code is in the repo and the history is in git._
