# Persistence Context — Index

_Read this at every session start (after git sync). Each row links to a detailed knowledge file._

## Knowledge Index

| Topic | File | Type | Status | Last Updated |
|-------|------|------|--------|--------------|
| Live security-testing pass — deflate canary, PBKDF2 boot DoS, VM-syscall+PE/DLL ImageBase user-range pre-checks | [knowledge/security-testing-fixes-2026-05-03.md](knowledge/security-testing-fixes-2026-05-03.md) | Issue + Pattern + Decision | Active | 2026-05-03 |
| AI bloat pattern and countermeasures | [knowledge/ai-bloat-pattern.md](knowledge/ai-bloat-pattern.md) | Observation | Active | 2026-04-20 |
| clang-format — CI-matching invocation | [knowledge/clang-format.md](knowledge/clang-format.md) | Pattern | Active | 2026-04-20 |
| Git rebase conflict resolution | [knowledge/git-rebase-conflicts.md](knowledge/git-rebase-conflicts.md) | Pattern | Active | 2026-04-20 |
| GitHub API / PR checks diagnosis | [knowledge/github-api-pr-checks.md](knowledge/github-api-pr-checks.md) | Pattern | Active | 2026-04-20 |
| Build and CI workflow speedups | [knowledge/build-optimizations.md](knowledge/build-optimizations.md) | Optimization | Active | 2026-04-20 |
| Lifetime download tally — survives rolling-channel asset re-uploads | [knowledge/lifetime-downloads-tally-v0.md](knowledge/lifetime-downloads-tally-v0.md) | Issue + Decision + Pattern | Active | 2026-04-29 |
| Effective dev workflows | [knowledge/workflow-patterns.md](knowledge/workflow-patterns.md) | Pattern | Active | 2026-04-20 |
| **Subsystems status — Win32/NT + Linux ABI (consolidated)** | [knowledge/subsystems-status.md](knowledge/subsystems-status.md) | Decision + Observation | Active — single source of truth for the subsystems work | 2026-04-29 |
| Linux ABI app coverage — synxtest + synfs + synet + synfull pipelines + slice findings (build flags inc. -mno-sse, -mno-mmx; getpid Process::pid bug; getdents64 -ENOTDIR errno; 2 dead-on-arrival smokes fixed; openat O_CREAT pending-create flag; mkdir/rmdir errno restoration; copy_file_range kernel-VA bypass; recvfrom MSG_DONTWAIT propagation; dense kSysEnosys_* ABI table for all 374 spec syscalls; gen-linux-syscall-table.py multi-TU scan + tri-state classifier showing 96% effective coverage; syscall_aux.cpp 70-handler fill-in 51%->70% primary; -EOPNOTSUPP-vs-ENOSYS doc for xattr; xattr+alarm+itimer+legacy-getdents+fallocate REAL impls + relocate aux; synfull bug-hunt: wait4/waitid -ECHILD, fchdir -ENOTDIR, vhangup -EPERM, pidfd_open -EINVAL, utimensat -EFAULT, time CMOS-RTC-seed; recvmmsg+sendmmsg+clone3; LinuxGapFill removal; POSIX timers + clone-fork-via-DoFork + mq_notify; fcntl+prctl extensions; getppid/setsid/getpgid/getsid/getpriority Linux-convention fixes; capget/capset header validation) | [knowledge/linux-app-coverage-pattern-v0.md](knowledge/linux-app-coverage-pattern-v0.md) | Pattern + Observation + Issue | Active | 2026-05-02 |
| Registry static-tree v0 — terminal + prefix tier + nested OpenKey + KEY_FULL_INFORMATION | [knowledge/registry-prefix-tree-v0.md](knowledge/registry-prefix-tree-v0.md) | Decision + Observation | Active | 2026-04-29 |
| Kernel breakpoint subsystem v0 + phase 2a (per-task DR, syscall, kCapDebug) + phase 3 (suspend/inspect/resume/step) + phase 4 (static KBP_PROBE macros) | [knowledge/breakpoints-v0.md](knowledge/breakpoints-v0.md) | Observation | Active | 2026-04-23 |
| Hardware target matrix (CPU/GPU/IO tiers) | [knowledge/hardware-target-matrix.md](knowledge/hardware-target-matrix.md) | Decision | Active | 2026-04-20 |
| UEFI hybrid-ISO boot path — same ISO boots SeaBIOS + OVMF | [knowledge/uefi-hybrid-iso-v0.md](knowledge/uefi-hybrid-iso-v0.md) | Observation | Active | 2026-04-23 |
| Result<T, E> — kernel exception-handling primitive (software side) | [knowledge/result-type-v0.md](knowledge/result-type-v0.md) | Decision + Pattern | Active | 2026-04-23 |
| DebugPanicOrWarn — release-stable variant of Panic (debug-panic / release-warn-and-recover) — 58 sites converted across 6 passes | [knowledge/debug-panic-or-warn-v0.md](knowledge/debug-panic-or-warn-v0.md) | Decision + Pattern | Active | 2026-05-01 |
| Kernel-stack guard pages v0 — unmapped low-edge page per task | [knowledge/kernel-stack-guard-v0.md](knowledge/kernel-stack-guard-v0.md) | Observation + Decision | Active | 2026-04-23 |
| Kernel isolation v0 — extable + fault domains | [knowledge/kernel-isolation-v0.md](knowledge/kernel-isolation-v0.md) | Decision + Pattern | Active | 2026-04-23 |
| FaultReact v0/v1 — self-defensive fault-reaction dispatcher (per-domain policy + floor + DriverFault + trap-deferred queue + reporter migrations + shell cmd + real `KillProcess`) | [knowledge/fault-react-v0.md](knowledge/fault-react-v0.md) | Decision + Pattern + Observation | Active — v1 shipped; all v0 follow-ups landed | 2026-05-01 |
| Rust bring-up plan — trigger, layout, toolchain, CI | [knowledge/rust-bringup-plan.md](knowledge/rust-bringup-plan.md) | Decision | Active | 2026-04-21 |
| Storage + Filesystem roadmap — block layer → NVMe/AHCI → GPT → FS | [knowledge/storage-and-filesystem-roadmap.md](knowledge/storage-and-filesystem-roadmap.md) | Decision | Active (stages 1–2, 4 landed) | 2026-04-21 |
| NVMe driver v0 — polling admin + I/O queue, marker self-test | [knowledge/nvme-driver-v0.md](knowledge/nvme-driver-v0.md) | Observation | Active | 2026-04-21 |
| GPT parser v0 + write surface (2026-05-03) — PMBR + primary/backup header + entries, CRC-validated, `GptInitDisk` round-trips through `GptProbe` on a RAM-disk fixture | [knowledge/gpt-parser-v0.md](knowledge/gpt-parser-v0.md) | Observation | Active | 2026-05-03 |
| klog overhaul — Trace + scopes + metrics + sinks + colour | [knowledge/klog-overhaul.md](knowledge/klog-overhaul.md) | Observation | Active | 2026-04-21 |
| Security guard — image-load protection | [knowledge/security-guard.md](knowledge/security-guard.md) | Decision | Active | 2026-04-21 |
| `inspect` umbrella v0 — `syscalls` / `opcodes` / `arm` subcommands | [knowledge/inspect-umbrella-v0.md](knowledge/inspect-umbrella-v0.md) | Observation | Active | 2026-04-23 |
| Shell scripting v0 — `exit N` short-circuit + ramfs `/etc/selftest.sh` (gated by `DUETOS_SHELL_SELFTEST`) exercising every control-flow keyword on boot, with mirror-to-COM1 arm/disarm so headless QEMU runs see the markers | [knowledge/shell-scripting-v0-self-test.md](knowledge/shell-scripting-v0-self-test.md) | Decision + Pattern + Observation | Active | 2026-05-03 |
| Native DuetOS apps v0 — pattern for in-kernel applications | [knowledge/native-apps-v0.md](knowledge/native-apps-v0.md) | Pattern | Active | 2026-04-21 |
| gfxdemo multi-mode v0 — six animated effects (plasma/mandelbrot/cube/particles/starfield/fire) + key dispatch + self-tests | [knowledge/gfxdemo-multimode-v0.md](knowledge/gfxdemo-multimode-v0.md) | Observation + Pattern | Active | 2026-04-26 |
| Desktop chrome polish v0 — fb line/circle/round-rect-outline/drop-shadow + window gradient titles + X-glyph close + taskbar gradient strip + rounded START/tabs + active-tab accent | [knowledge/desktop-chrome-polish-v0.md](knowledge/desktop-chrome-polish-v0.md) | Observation + Decision | Active | 2026-04-29 |
| End-user onboarding v0 — Start menu app launchers + ThemeRoleWindow + F1 shortcut help + post-login banner | [knowledge/end-user-onboarding-v0.md](knowledge/end-user-onboarding-v0.md) | Observation + Decision | Active | 2026-05-01 |
| End-user feature gaps v0 — prioritized inventory of what an ordinary user notices is missing (audio / Wi-Fi / save-to-disk / Settings panel / accessibility) | [knowledge/feature-gaps-end-user-v0.md](knowledge/feature-gaps-end-user-v0.md) | Observation + Decision | Active — 19+ of 27 fully landed (BMP viewer + Files FAT32 view + .TXT dispatch + delete + Settings SHUTDOWN/REBOOT + About/SysInfo + help-text refresh + Help window + Calculator polish + git hash in About + Trash bin + Files defaults to disk view + Browser (HTTP only) + TCP-buffer lift 2 KiB→64 KiB + Calendar app + clipboard-history ring (Ctrl+Shift+V) + **Notes status footer + Calculator memory ops, 2026-05-03**) + P0 #4 Wi-Fi data-decode + full control tier; remainder either blocked on driver/FS infra or deferred refactors | 2026-05-03 |
| Image Viewer v0 — BMP-only kernel app pairs with Screenshot, reads 32-bpp top-down + bottom-up DIBs, streaming NN-downsample via Fat32ReadFileStream, aspect-fit no-upscale, 5-case header round-trip self-test, ImageViewSelectByName() entrypoint for cross-app dispatch | [knowledge/imageview-bmp-v0.md](knowledge/imageview-bmp-v0.md) | Observation + Decision | Active — BMP only; 24-bpp / PNG / JPEG / subdir walk deferred | 2026-05-02 |
| Wireless control tier v0 — full Wi-Fi stack landed (HW-untested): wifi-diag ring + SHA-1/SHA-256/HMAC/PBKDF2/PRF (KAT-verified) + EAPOL parse/build + WPA2 4-way handshake (PTK/GTK derivation, MIC, replay) + cfg80211-eq WirelessDevice + MLME (scan/auth/assoc/disconnect frame builders + flow) + iwlwifi/rtl88xx/bcm43xx upload state machines + iwlwifi TFD/RBD ring scaffolds + panic-time diag ring dump + `wifi diag` shell command | [knowledge/wireless-control-tier-v0.md](knowledge/wireless-control-tier-v0.md) | Observation + Decision | Active — 13 boot self-tests pass; runtime correctness gated on real-HW verification cycles | 2026-05-01 |
| Wireless loopback test + fuzz harness v0 — `mac80211_hwsim`-equivalent FakeAp + LoopbackDriver + 4-case boot self-test (success/wrong-psk/replay/tamper, all asserting key match between endpoints) + 5 libFuzzer drivers (beacon/eapol/iwl_fw/rtl_fw/bcm_fw) under ASan+UBSan with ~95M total executions, zero crashes. Caught a wrong PBKDF2 reference value and an M2/M4 send gap during landing | [knowledge/wireless-loopback-and-fuzz-v0.md](knowledge/wireless-loopback-and-fuzz-v0.md) | Observation + Decision + Pattern | Active | 2026-05-01 |
| iwlwifi TLV firmware parser v0 — Intel microcode envelope walker (zero/magic preamble, 64-byte name, ver/build, INST/DATA/INIT/INIT_DATA/SEC_RT capture, length-overflow bounds check) wired into IwlwifiBringUp + boot self-test (synthetic 7-record blob + 3 negative cases) | [knowledge/iwl-fw-tlv-parser-v0.md](knowledge/iwl-fw-tlv-parser-v0.md) | Observation + Decision | Active — parser only; microcode upload + MLME still deferred | 2026-05-01 |
| Wireless firmware parsers v0 (rtl88xx + bcm43xx + iwlwifi consolidated) — clean-room envelope walkers across all three wireless vendors: Realtek 32-byte rtlwifi/rtw88/rtw89 header (signature classification + tolerant ramcodesize) + Broadcom b43 record stream (`'u'`/`'p'`/`'i'` types, big-endian 8-byte headers, bounded 8-record table), wired into respective BringUp paths + boot self-tests for each | [knowledge/wireless-fw-parsers-v0.md](knowledge/wireless-fw-parsers-v0.md) | Observation + Decision | Active — parsers only; microcode upload + MLME still deferred (real-HW gated) | 2026-05-01 |
| IEEE 802.11 frame headers + beacon parser v0 — `kernel/net/wireless/ieee80211.h` (frame-control bits, type/subtype, capability bits, 35 IE IDs + 4 ID extensions, 12 cipher suites, 12 AKM suites) + `beacon.{h,cpp}` (BeaconParse → BeaconParsed with SSID/channel/rates/RSN-derived security taxonomy across Open/WEP/WPA/WPA2/WPA3/Wpa2Ent/Wpa3Ent + boot self-test exercising 5 frame variants) | [knowledge/ieee80211-beacon-parser-v0.md](knowledge/ieee80211-beacon-parser-v0.md) | Observation + Decision | Active — beacon/probe-resp decode only; TX, RX dispatch, MLME still deferred | 2026-05-01 |
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
| EDID 1.3/1.4 base-block parser v0 — clean-room VESA E-EDID decoder (header / vendor / video-input / DTD timings / monitor descriptors / standard timings / established timings) + 5-fixture boot self-test (incl. bad-checksum / bad-header / short-buffer negative cases) + `monitor` shell command | [knowledge/edid-parser-v0.md](knowledge/edid-parser-v0.md) | Observation + Decision | Active — parser only; DDC/I2C transport gated on per-vendor GPU drivers | 2026-05-01 |
| CVT timing generator + CEA-861 extension parser v0 — clean-room VESA CVT 1.1/1.2 RBv1 (Standard + RB modes, aspect-ratio-driven v-sync, integer pixel-clock math) + CEA-861-E/F extension block (Video / Audio / Speaker / HDMI VSDB / HDR Static / Colorimetry data blocks + DTD list) + 9 boot self-test fixtures across both | [knowledge/cvt-cea861-v0.md](knowledge/cvt-cea861-v0.md) | Observation + Decision | Active | 2026-05-01 |
| xHCI enumeration v0 — Address Device + GET_DESCRIPTOR(Device) | [knowledge/xhci-enumeration-v0.md](knowledge/xhci-enumeration-v0.md) | Observation | Active | 2026-04-23 |
| xHCI HID boot keyboard — end-to-end USB keyboard input | [knowledge/xhci-hid-keyboard-v0.md](knowledge/xhci-hid-keyboard-v0.md) | Observation | Active | 2026-04-23 |
| Intel e1000 NIC driver — real packet I/O on commodity wired gigabit | [knowledge/e1000-driver-v0.md](knowledge/e1000-driver-v0.md) | Observation | Active | 2026-04-23 |
| Network shell commands — ifconfig / dhcp / route / netscan / net | [knowledge/network-shell-commands-v0.md](knowledge/network-shell-commands-v0.md) | Observation | Active | 2026-04-25 |
| Network flyout panel — bottom-right Wi-Fi-style popup with hover preview | [knowledge/network-flyout-panel-v0.md](knowledge/network-flyout-panel-v0.md) | Observation + Decision | Active | 2026-04-25 |
| Wireless driver shells v0 — iwlwifi / rtl88xx / bcm43xx chip-id bring-up | [knowledge/wireless-drivers-v0.md](knowledge/wireless-drivers-v0.md) | Observation + Decision | Active | 2026-04-25 |
| Live Internet connectivity v0 — DuetOS reaches Google over real DNS + TCP | [knowledge/live-internet-connectivity-v0.md](knowledge/live-internet-connectivity-v0.md) | Observation + Pattern | Active | 2026-04-25 |
| Live Internet QEMU SLIRP — `netsmoke=force` flag + e1000e RX-poll bounded wait fix | [knowledge/live-internet-qemu-slirp-v0.md](knowledge/live-internet-qemu-slirp-v0.md) | Observation + Issue + Pattern | Active | 2026-04-30 |
| mini_browser — real Windows PE on DuetOS reaches google.com (WSAStartup→gethostbyname→socket→connect→send→recv→close) end-to-end | [knowledge/mini-browser-runs-on-duetos-v0.md](knowledge/mini-browser-runs-on-duetos-v0.md) | Observation + Issue + Pattern | Active | 2026-04-30 |
| Smoke PE suite v23 — pass-rate **93.7%**: msvcrt memcpy/memmove/memset re-exports (mingw-w64 imports them via msvcrt) covering 505 PASS Win32 APIs (118 apps) | [knowledge/smoke-pe-suite-v23.md](knowledge/smoke-pe-suite-v23.md) | Observation + Pattern | Active | 2026-04-30 |
| **DirectX v0 — full COM-vtable surface across 11 DLLs (d3d{9,11,12}/dxgi pre-existing + dinput8/xinput1_4/xaudio2_8/dsound/ddraw/d2d1/dwrite new) + 10 smoke PEs walking real Clear+Present pipelines** | [knowledge/directx-v0.md](knowledge/directx-v0.md) | Observation + Decision + Pattern | Active | 2026-04-30 |
| DirectX gap-fill v0 — DirectInput keyboard/mouse → SYS_WIN_GET_KEYSTATE/CURSOR; D2D1 FillEllipse/DrawEllipse/DrawRectangle/DrawLine; DWrite GetMetrics monospace approximation | [knowledge/directx-input-d2d-dwrite-wire-v0.md](knowledge/directx-input-d2d-dwrite-wire-v0.md) | Observation + Pattern | Active | 2026-04-30 |
| USB CDC-ECM driver + xHCI bulk-transfer API v0 | [knowledge/usb-cdc-ecm-driver-v0.md](knowledge/usb-cdc-ecm-driver-v0.md) | Observation + Decision | Active (probe not auto-called) | 2026-04-25 |
| USB RNDIS driver + bulk-poll serialization v0 | [knowledge/usb-rndis-driver-v0.md](knowledge/usb-rndis-driver-v0.md) | Observation + Decision | Active (control plane works; bulk concurrency gap) | 2026-04-25 |
| KPTI / Meltdown — settled non-implementation decision (loud serial WARN block surfaces on `RDCL_NO=0` boots; runtime probe in `arch::CpuMitigationsGet().needs_kpti`; full KPTI deliberately not built — every targeted CPU has `RDCL_NO=1` in silicon, KPTI would be a 5-30% syscall cost mitigating an attack the hardware already prevents) | [knowledge/kpti-meltdown-decision-v0.md](knowledge/kpti-meltdown-decision-v0.md) | Decision | Settled — closed question; re-open triggers (hardware/workload/spec) recorded | 2026-05-03 |
| Post-recommendations follow-on plan — graduated large items from the closed recommendations plan | [knowledge/post-debug-recommendations-plan.md](knowledge/post-debug-recommendations-plan.md) | Plan | Active — 1/8 landed (C1 per-zone allocator 2026-05-01); pending B2 SMP, CET enable, KPTI enable, slab+KASAN, ABI handle migration, GDB stub completion, more driver fault-domain registrations | 2026-05-01 |
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
| KMalloc-zero-init pattern — every kernel struct with embedded sync primitives must memset before use | [knowledge/kmalloc-zero-init-pattern.md](knowledge/kmalloc-zero-init-pattern.md) | Pattern + Issue | Active | 2026-04-28 |
| Build flavors v0 — central debug/release configuration (build_config.h + DEBUG_ASSERT + cap-audit + boot banner + new presets) | [knowledge/build-flavors-v0.md](knowledge/build-flavors-v0.md) | Decision + Pattern | Active | 2026-04-29 |
| FS write-rate guard + canary wall — v1 ransomware defense (multi-window 1 s/5 min/1 h byte caps + canary-path/suspicious-extension wall + per-boot dynamic canary salt + handle-stamped is_canary on Win32 + Linux fds + persistence-drop detector with autostart path registry; 5 new HealthIssues, 3 new KillReasons; wired into Win32 SYS_FILE_{WRITE,CREATE} + Linux sys_write/copy_file_range/unlink/rename/openat-O_CREAT; 6 attack_sim entries: burst-tier, low-and-slow tier, canary-touch, persistence-drop, stack-canary defang via no-stack-protector island, plus new `crosspid` ring-3 probe verifying cross-PID gate denial) | [knowledge/fs-write-rate-guard-v0.md](knowledge/fs-write-rate-guard-v0.md) | Decision + Pattern + Observation | Active | 2026-05-03 |
| **Security team colors — DuetOS map (Red/Blue/Yellow/Purple/Green/Orange/White)** | [knowledge/security-team-colors-overview.md](knowledge/security-team-colors-overview.md) | Decision + Pattern | Active | 2026-05-03 |
| Blue team — security event ring v0 (256-entry structured event log, 27 EventKind types, spinlock-protected, constinit storage, dropped-oldest accounting) — wired into canary trip, persistence drop, fs-write-rate trip, sandbox-denial kill, image guard Warn/Deny | [knowledge/blue-team-event-ring-v0.md](knowledge/blue-team-event-ring-v0.md) | Decision + Pattern | Active | 2026-05-03 |
| Blue team — IR runbook v0 (per-EventKind follow-up guidance: summary + steps + escalation, 20 entries, boot-time self-test enforces coverage, IrRunbookEmit publishes back to event ring) | [knowledge/blue-team-ir-runbook-v0.md](knowledge/blue-team-ir-runbook-v0.md) | Decision + Pattern | Active | 2026-05-03 |
| White team — policy engine v0 (Default/Lab/Production/Forensic profiles compose Guard/Persistence/Blockguard modes atomically, `policy show/set/diff` shell command, boot-time self-test) | [knowledge/white-team-policy-engine-v0.md](knowledge/white-team-policy-engine-v0.md) | Decision + Pattern | Active | 2026-05-03 |
| Purple team — coverage scorecard v0 (wraps AttackSimRun with event-ring snapshot brackets + coverage % + runbooks-emitted count; replaces direct AttackSimRun call in DUETOS_ATTACK_SIM path) | [knowledge/purple-team-coverage-scorecard-v0.md](knowledge/purple-team-coverage-scorecard-v0.md) | Decision + Pattern | Active | 2026-05-03 |
| AES-128/256 (FIPS 197) + AES Key Wrap (RFC 3394) v0 — clean-room block cipher (S-box / inverse S-box / GF(2^8) MixColumns / Nk-generic key schedule) + RFC 3394 wrap/unwrap on caller buffer with no scratch heap; AES + KW boot KATs (FIPS 197 Appendix B + C.1 + C.3 / RFC 3394 §4.1 + §4.3 + §4.6 + tamper detect + bad-input rejection) | [knowledge/aes-and-keywrap-v0.md](knowledge/aes-and-keywrap-v0.md) | Observation + Decision | Active — unblocks the AES key wrap half of the Wi-Fi M3 GTK encrypted-KeyData path | 2026-05-03 |
| CRC32 hoist + MD5 (RFC 1321) + Base64 (RFC 4648) + EAPOL M3 AES-KW integration v0 — four bounded slices: util/crc32 hoist out of gpt.cpp; MD5 7-vector KAT (legacy interop only); Base64 encode/decode 12-case KAT incl. MIME whitespace + bad-input; FourWayProcessIncoming Encrypted-bit branch decrypts M3 KeyData with KEK + walks unwrapped KDEs + treats integrity failure as a MIC-equivalent fault, plus ciphered-M3 + tamper-detect boot KAT | [knowledge/crc32-md5-base64-and-eapol-keywrap-v0.md](knowledge/crc32-md5-base64-and-eapol-keywrap-v0.md) | Observation + Decision | Active — unblocks real-AP encrypted M3 KeyData on the supplicant | 2026-05-03 |
| Crypto graduates to OS core + password-hash module v0 — `kernel/net/wireless/crypto/` → `kernel/crypto/` (namespace `duetos::crypto`); added Pbkdf2HmacSha256 + RFC 7914 KATs; new `kernel/security/password_hash.{h,cpp}` (PBKDF2-HMAC-SHA256 over 16-byte random salt + 100k default iterations + constant-time verify + 56-byte on-disk PasswordHashRecord struct) — KAT-driven, fail-closed against unknown algorithm/zero-iter, distinct-salts assertion verifies entropy pool is alive. **`kernel/security/auth.cpp` swap landed (2026-05-03)**: account table now stores a `PasswordHashRecord` per row, FNV-1a/64 ripped out, `AuthVerify` runs `PasswordHashVerify` against either the stored record or a decoy, `AuthAddUser`/`AuthChangePassword` call `PasswordHashCreate`, `AuthSelfTest` re-extended to assert the empty-password-guest invariant, init order audited (RandomInit precedes AuthInit). User-table-on-disk is the next bounded slice | [knowledge/crypto-os-core-and-password-hash-v0.md](knowledge/crypto-os-core-and-password-hash-v0.md) | Decision + Pattern + Observation | Active — auth.cpp now hashed; user-table on disk is the next bounded slice | 2026-05-03 |
| Kernel pure-compute utility libraries v0 — 13 clean-room TUs after the 2026-05-03 prune. Survivors: Unicode UTF-8/UTF-16, TGA decoder+encoder, datetime (Gregorian↔Julian-Day + ISO 8601 + Unix-epoch), BMP, CRC32, Adler-32, Base64, DEFLATE, GZIP+zlib, PNG, AES + AES-KW, HMAC-SHA1/SHA256, SHA-1/256+PBKDF2/PRF, DPMS, EDID/CVT/CEA-861. 14 unconsumed TUs (chacha20poly1305, aes_gcm, aes_ccm, sha512, md5, HmacMd5/SHA384/SHA512, posix_tz, tzif, wav, cpio, tar, lz4, psf, gtf) deleted in commit 1a236aa per "fully implement what the OS needs, otherwise trash it" | [knowledge/kernel-util-libraries-v0.md](knowledge/kernel-util-libraries-v0.md) | Observation + Decision | Active | 2026-05-03 |
| **DMA-coherent allocation v0** — `mm::AllocDmaCoherent(bytes, zone)` over zone-clamped contiguous frames + cached direct-map alias on x86_64 (PCIe is HW-coherent so no UC remap or cache flush needed; `DmaSync*` are mfence/lfence). Adds `AllocateContiguousFramesInRange(count, max_phys)` to the frame allocator. Boot self-test asserts Mmio reject + zero-byte reject + per-zone alloc + ceiling + write/read round-trip + reuse-after-free. **First consumer**: iwlwifi TFD/RBD rings — 4 × 32 KiB TX + 1 × 2 KiB RX in Dma32, FH base regs programmed with real phys addrs. Unblocks AHCI / HDA CORB / GPU per-vendor accel as their next-slice prerequisite | [knowledge/dma-coherent-v0.md](knowledge/dma-coherent-v0.md) | Decision + Pattern + Observation | Active | 2026-05-03 |

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
