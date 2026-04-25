# Linux networking port opportunities for DuetOS (surveyed from torvalds/linux master)

**Date:** 2026-04-25  
**Author:** Codex session analysis  
**Scope:** Linux `drivers/usb/host`, `drivers/net/usb`, `drivers/net/ethernet/intel/e1000e`, and `net/core`

## 1) Why this document exists

DuetOS networking is already Internet-capable on wired e1000/e1000e in QEMU, and USB-net class support exists for CDC-ECM and RNDIS. The current blockers are mostly concurrency and robustness issues around xHCI event handling, USB-net coexistence, and a few stack-level v0 shortcuts.

This document maps those DuetOS limitations to concrete Linux patterns that can be ported in DuetOS-native style (not copied code), with implementation slices prioritized for maximum unblock value.

## 2) Current DuetOS limitations (baseline)

From current project knowledge entries, the networking path has the following known constraints:

1. **xHCI event/ring concurrency issues** can deadlock or hang under concurrent USB bulk polling (`runaway-cpu` warning signatures).  
   - Current mitigation uses a global bulk-poll lock and event-consumer pause, which serializes progress but does not solve root-cause routing/state management.
2. **USB-net auto-probe is intentionally disabled** at boot due to interactions that regress wired DHCP or stall USB-net bring-up.
3. **RNDIS v0 gaps:** only first packet in aggregated RX transfer parsed; status indications largely ignored; control plane works but data plane has concurrency hazards.
4. **CDC-ECM v0 gaps:** dependence on paused event consumer and no robust multi-device coexistence model.
5. ~~**ARP behavior in stack remains minimal:** gateway fallback was fixed, but ARP request-on-miss is still intentionally out-of-scope.~~ ✅ **Updated** — v1 now has active ARP request-on-miss with bounded retry/wait; full neighbor queue/state machine is still pending.
6. **TCP stack is single-slot v0**, forcing smoke-test sequencing constraints.
7. **e1000e MSI-X path is gated off** instead of fully configured (IVAR programming follow-up still pending).
8. **Firmware loader backend is scaffold-only** (drivers correctly report `firmware_pending=true`, but no real firmware feed path yet).

## 2.1) Issue closure tracker (live)

Crossing out means the issue has been addressed in-tree (fully or to the stated v1 scope).

- ~~ARP request-on-miss is absent in DNS/TCP/NTP send paths.~~ ✅ **Done (v1)**  
  Implemented active ARP request + bounded wait + retries, with direct-target then gateway fallback in shared L2 resolver.
- ~~DNS/TCP/NTP duplicate ad-hoc L2 fallback code paths.~~ ✅ **Done**  
  Unified through a single shared `ResolveL2Destination` path in `kernel/net/stack.cpp`.
- ~~No ARP TX observability for miss-resolution attempts.~~ ✅ **Done**  
  `ArpStats` now includes `tx_requests` and `tx_failures`.
- ~~Single ARP probe attempt on miss path.~~ ✅ **Done (v1 hardening)**  
  Resolver now performs bounded retries per target before failing.
- **Pending:** bounded pending-packet queue for unresolved peers.
- **Pending:** full neighbor state machine (`INCOMPLETE/REACHABLE/STALE/FAILED`) with retry/backoff timers.
- **Pending:** e1000e IVAR MSI-X programming path.
- **Pending:** xHCI transfer-event router replacing global bulk-poll serialization.
- **Pending:** wireless firmware backend + cfg layer + supplicant-equivalent service.

## 3) Linux net/USB patterns that directly address those limits

Below are the highest-value Linux patterns inspected and what they imply for DuetOS.

---

### A) xHCI event handling ownership + lock discipline

**Linux reference points**
- `drivers/usb/host/xhci-ring.c` (`xhci_irq`, `xhci_handle_events`, `xhci_update_erst_dequeue`)  
  - CodeBrowser: https://codebrowser.dev/linux/linux/drivers/usb/host/xhci-ring.c.html

**What Linux does (relevant behaviors)**
- Uses a clear interrupt ownership path around a controller lock while handling ring dequeue progress.
- Processes all OS-owned event TRBs in an explicit loop and then advances/acks ERDP consistently.
- Maintains a single coherent authority for event-ring dequeue state in normal operation.

**Port insight for DuetOS**
- DuetOS should replace “pause one consumer + opportunistic side cache + global bulk lock” with **a first-class xHCI event router**:
  - One event-consumer context owns dequeue index/cycle transitions.
  - Transfer events are dispatched to waiters by TRB pointer (or endpoint ring + TRB cookie).
  - Synchronous waiters block on per-request completion objects, not by directly racing the global event ring.

**Expected payoff**
- Removes root deadlock/hang class behind CDC/RNDIS contention.
- Unblocks safe USB-net auto-probe and multi-class coexistence (HID + CDC/RNDIS + future USB Wi-Fi dongles).

---

### B) usbnet architecture: completion-driven RX/TX, deferred bottom-half work

**Linux reference points**
- `drivers/net/usb/usbnet.c` (`rx_complete`, `usbnet_bh`, `usbnet_defer_kevent`, queue discipline)
  - CodeBrowser: https://codebrowser.dev/linux/linux/drivers/net/usb/usbnet.c.html

**What Linux does (relevant behaviors)**
- RX URBs complete asynchronously; processing is moved through deferred work queues/bottom-half flow.
- Error handling is converted into explicit deferred events (RX halt, memory pressure, link reset/change).
- State transitions are mediated by flags + queue ownership, not ad-hoc synchronous polling loops.

**Port insight for DuetOS**
- Introduce a **DuetOS usbnet-core** abstraction used by CDC-ECM and RNDIS:
  - Shared RX submission/reap pipeline.
  - Shared TX queue + completion accounting.
  - Shared link/event state machine (`LINK_CHANGE`, `RX_HALT`, `RESET_REQUIRED`, etc.).
- Move class drivers to “protocol glue” only (descriptor parsing + control messages + frame fixups).

**Expected payoff**
- Eliminates duplicate class-driver plumbing.
- Gives consistent recovery behavior across all USB-net classes.
- Makes future CDC-NCM/RTL8152/AX88179 ports much cheaper.

---

### C) RNDIS host handling of control/status edge-cases

**Linux reference points**
- `drivers/net/usb/rndis_host.c` (`rndis_command`, indication handling, keepalive handling, bind path)
  - CodeBrowser: https://codebrowser.dev/linux/linux/drivers/net/usb/rndis_host.c.html

**What Linux does (relevant behaviors)**
- Handles asynchronous indication and keepalive messages in control-response flow.
- Retries and validates response IDs/types/lengths robustly.
- Encapsulates RNDIS negotiation in a reusable bind sequence on top of usbnet core.

**Port insight for DuetOS**
- Expand RNDIS implementation to include:
  - Proper indication/status handling path (media connect/disconnect updates into iface state).
  - Full transfer parsing loop for multi-packet payloads per USB transfer.
  - Hardened response sanity checks with telemetry counters.

**Expected payoff**
- Stabilizes Android/QEMU tethering behavior.
- Reduces silent failure modes and unexplained link stalls.

---

### D) CDC-NCM as a strategic next USB tethering target

**Linux reference points**
- `drivers/net/usb/cdc_ncm.c` (NTB framing, timer-based TX flush logic)
  - CodeBrowser: https://codebrowser.dev/linux/linux/drivers/net/usb/cdc_ncm.c.html

**What Linux does (relevant behaviors)**
- Implements aggregated NTB framing with size/timer thresholds.
- Uses explicit scheduling/timer strategy to balance latency vs throughput.

**Port insight for DuetOS**
- After usbnet-core exists, CDC-NCM becomes practical:
  - Reuse shared RX/TX transport pipeline.
  - Add NCM frame parser/assembler module only.
- This is likely the fastest way to broaden phone/router tether compatibility beyond RNDIS/ECM split.

**Expected payoff**
- Better real-hardware USB tether interoperability.
- Higher throughput potential than simple one-frame-per-transfer ECM paths.

---

### E) Neighbor/ARP request-on-miss state machine

**Linux reference points**
- `net/core/neighbour.c` (`neigh_resolve_output`, `neigh_event_send`, neighbor state transitions)
  - CodeBrowser: https://codebrowser.dev/linux/linux/net/core/neighbour.c.html

**What Linux does (relevant behaviors)**
- On unresolved L2 neighbor, packet path triggers neighbor resolution eventing instead of fail-silent behavior.
- Maintains neighbor entry lifecycle and queueing while resolution is in progress.

**Port insight for DuetOS**
- Add minimal **ARP-neighbor manager v1**:
  - ~~ARP request on cache miss.~~ ✅ **Implemented (v1)** in DNS/TCP/NTP paths.
  - Queue bounded pending packets per unresolved peer. ⏳
  - Retry/backoff + expiry timestamps. ⏳ (currently bounded polling retries only)
  - Promote to RESOLVED on ARP reply; flush queue. ⏳

**Expected payoff**
- Removes same-subnet “first contact fails until traffic appears” behavior.
- Makes TCP/DNS/NTP path behavior deterministic outside QEMU SLIRP assumptions.

---

### F) e1000e MSI-X IVAR programming and interrupt-model hygiene

**Linux reference points**
- `drivers/net/ethernet/intel/e1000e/netdev.c` (`e1000_configure_msix`, NAPI poll + IRQ re-enable paths)
- `drivers/net/ethernet/intel/e1000e/regs.h` (`E1000_IVAR`)
  - CodeBrowser: https://codebrowser.dev/linux/linux/drivers/net/ethernet/intel/e1000e/netdev.c.html  
  - CodeBrowser: https://codebrowser.dev/linux/linux/drivers/net/ethernet/intel/e1000e/regs.h.html

**What Linux does (relevant behaviors)**
- Properly maps causes/vectors via IVAR in MSI-X configurations.
- Couples interrupt moderation and poll/re-enable cadence with NAPI work budget.

**Port insight for DuetOS**
- Implement missing IVAR programming for e1000e in DuetOS MSI-X path.
- Introduce a modest poll-budget API for RX loops (even before full NAPI equivalent).

**Expected payoff**
- Removes current need to hard-gate MSI-X on e1000e variants.
- Better latency/CPU tradeoff under traffic bursts.

---

### G) NAPI-style budgeted polling for DuetOS net RX paths

**Linux reference points**
- Linux NAPI docs: https://docs.kernel.org/networking/napi.html
- Driver usage example in `e1000e_poll`

**What Linux does (relevant behaviors)**
- Uses budgeted poll loops to cap work per scheduling slice.
- Reduces interrupt storms while keeping forward progress and fairness.

**Port insight for DuetOS**
- Add **NetPollBudget** contract:
  - Every NIC `RxDrain(max_packets, max_usecs)`.
  - Scheduler/net softirq drives repeated drains until budget exhausted.
  - Interrupt source masked/unmasked around drain windows.

**Expected payoff**
- Avoids starvation/runaway loops in mixed workloads.
- Creates clean path toward SMP-scaled RX and eventual multiqueue.

## 4) Prioritized DuetOS port roadmap (recommended)

## P0 (immediate unblock: 1-2 weeks)

1. **xHCI event router + per-request completion objects**  
   Replace current global lock/pause workaround with strict event ownership model.
2. **USB-net core extraction (transport/event/state shared layer)**  
   Refactor CDC-ECM and RNDIS drivers to shared pipeline.
3. **RNDIS robustness pass**  
   Multi-packet RX, indications, keepalive handling, stronger response validation.

**Why P0 first:** This directly resolves the concurrency class that is currently blocking auto-probe and stable USB-net operation.

## P1 (network stack correctness/robustness: 1-2 weeks)

4. **ARP request-on-miss + bounded neighbor pending queue**  
   Status: ~~request-on-miss~~ ✅ done, pending-queue ⏳ pending.
5. **e1000e MSI-X IVAR implementation and verification path**.
6. **poll-budgeted RX service loop for e1000/e1000e + USB-net RX tasks**.

**Why P1 next:** Improves correctness and removes tactical workarounds currently in the boot/network smoke path.

## P2 (capability expansion: 2-4 weeks)

7. **CDC-NCM driver on top of usbnet core**.
8. **firmware-loader real backend (VFS path + signature/integrity policy)** for wireless bring-up.
9. **multi-slot TCP progression plan** (small fixed connection table first).

**Why P2:** Expands hardware/real-world compatibility once foundational transport is stable.

## 5) Concrete implementation blueprint (DuetOS-native, not Linux copy)

### 5.1 xHCI event router skeleton

- **Single consumer task** owns `evt_idx/evt_cycle` and ERDP writes.
- On each Transfer Event:
  - decode TRB pointer, slot, endpoint, completion code, transferred length;
  - look up waiter in `pending_map<trb_phys, RequestCtx*>`;
  - publish completion + wake waiter.
- Wait API:
  - `UsbWait(trb_phys, timeout)` sleeps on condition variable / waitqueue tied to RequestCtx;
  - no second thread ever drains event ring directly.

### 5.2 usbnet-core API proposal

- `UsbNetAttach(UsbNetOps* ops, UsbEndpoints eps, MacAddress mac)`
- `UsbNetSubmitRx(n_buffers)` / `UsbNetTxFrame(frame)`
- callback hooks:
  - `ParseRxPayload(span<byte>) -> vector<FrameView>`
  - `BuildTxPayload(frame) -> ByteBuffer`
  - `HandleStatus(message)`
- generic counters: rx_packets, rx_drops, tx_timeouts, ctrl_errors, link_flaps

### 5.3 ARP-neighbor manager minimal state

Status: **Partially implemented** (active request-on-miss is live; queue/state machine remains).

- states: `INCOMPLETE`, `REACHABLE`, `STALE`, `FAILED`
- per-entry:
  - target IP, resolved MAC, last_updated_tick,
  - retry_count, next_retry_tick,
  - bounded pending skb list (e.g., max 8)
- deterministic policy:
  - drop + stat increment on queue overflow
  - clear fail state when new outbound traffic triggers fresh resolution

### 5.4 e1000e MSI-X validation plan

- enable IVAR mapping for RX/TX/other causes
- self-tests:
  1. DHCP under sustained ping flood
  2. DNS burst (10 lookups)
  3. TCP connect/read under background RX traffic
- success criteria: no lost-wakeup stalls, no forced polling fallback

## 6) Wireless connection coverage (Linux patterns to port)

Wireless is a separate subsystem from wired/USB Ethernet and needs an explicit architecture plan. The shortest path to “real Wi-Fi connection” in DuetOS is to mirror Linux’s layering model behaviorally:

- **driver (fullmac/softmac)**
- **cfg layer (scan/auth/assoc policy + regulatory)**
- **userspace control plane (supplicant-equivalent)**
- **IP layer reuse (DHCP/DNS/TCP already in DuetOS net stack)**

### 6.1 Linux wireless layers that matter

**Linux reference points**
- cfg80211 core:
  - https://codebrowser.dev/linux/linux/net/wireless/core.c.html
  - https://codebrowser.dev/linux/linux/include/net/cfg80211.h.html
- mac80211 stack:
  - https://codebrowser.dev/linux/linux/net/mac80211/main.c.html
  - https://codebrowser.dev/linux/linux/include/net/mac80211.h.html
- nl80211 userspace API:
  - https://codebrowser.dev/linux/linux/include/uapi/linux/nl80211.h.html
- iwlwifi (Intel):
  - https://codebrowser.dev/linux/linux/drivers/net/wireless/intel/iwlwifi/mvm/mac80211.c.html
- rtw88 (Realtek softmac family):
  - https://codebrowser.dev/linux/linux/drivers/net/wireless/realtek/rtw88/main.c.html
- brcmfmac (Broadcom fullmac):
  - https://codebrowser.dev/linux/linux/drivers/net/wireless/broadcom/brcm80211/brcmfmac/core.c.html

**What Linux does (relevant behaviors)**
- Separates common 802.11 policy/state handling from chipset specifics.
- Uses explicit firmware + regulatory database dependencies before association attempts.
- Handles WPA2/WPA3 key exchange in user space (`wpa_supplicant`) while kernel handles data path and MLME hooks.

### 6.2 DuetOS wireless constraints and direct fixes

Given current DuetOS state (driver shells present, firmware backend scaffold-only), the key missing pieces for wireless connection are:

1. **Firmware delivery and versioning path**  
   - Required for iwlwifi/rtw/bcm families before scan/auth works.
2. **802.11 control-plane state machine**  
   - Scan results, open/WPA2 association, roam/disconnect events.
3. **EAPOL/4-way handshake integration point**  
   - User-mode security agent equivalent to supplicant.
4. **Regulatory/channel policy**  
   - Basic country/channel/power gate before active scan.
5. **Netdev↔802.11 bridging contract**  
   - Once associated, feed Ethernet-like payloads into existing IP stack.

### 6.3 Recommended wireless port plan (phased)

#### W0 (prerequisite; smallest unblock)

- Implement firmware loader backend (VFS-backed blob lookup + integrity policy).
- Add per-driver firmware telemetry (`fw_version`, `fw_api`, `last_fw_error`).
- Add deterministic failure codes surfaced to shell/UI (`FW_MISSING`, `FW_INCOMPATIBLE`, `REGDOMAIN_BLOCKED`).

#### W1 (first real connection path)

- Build **minimal cfg layer** in kernel:
  - `WifiScanStart(iface)`
  - `WifiJoinOpen(iface, ssid, bssid?)`
  - `WifiJoinWpa2Psk(iface, ssid, psk)`
  - `WifiDisconnect(iface)`
- Driver contract split:
  - fullmac drivers (e.g., brcmfmac-like) implement join directly.
  - softmac drivers (iwlwifi/rtw88-like) report management frame events to cfg layer.
- Keep target narrow: **WPA2-PSK CCMP only** in first slice.

#### W2 (security/control hardening)

- Add user-mode `wifid` (supplicant-equivalent service) owning:
  - PMK/PTK derivation + key rotation policy.
  - reconnect backoff and roaming policy.
  - credentials vault integration.
- Kernel receives derived keys via explicit capability-gated syscall/IPC.

#### W3 (throughput and robustness)

- AMPDU aggregation policy hooks.
- power-save states (U-APSD / DTIM-aware wake policy as hardware allows).
- roaming optimization and background scan cadence.

### 6.4 Why this approach is right for DuetOS

- Preserves clean architecture: avoids coupling Wi-Fi policy into per-vendor drivers.
- Reuses current DuetOS IP stack work (DHCP/DNS/TCP) once L2 association succeeds.
- Keeps first ship target tractable (WPA2-PSK) while leaving clean extension path to WPA3/Enterprise later.

## 7) Additional Linux components worth mining next (high value)

Beyond the immediate fixes above, these Linux areas are strong port candidates:

1. **`drivers/net/mii.c` / PHY helpers** for cleaner PHY/link management abstractions.
2. **`net/core/skbuff.c` design ideas** (not full skb clone) for packet-buffer lifetime discipline.
3. **`net/core/dev.c` softirq-style ingress scheduling concepts** for future SMP scaling.
4. **`drivers/net/ethernet/intel/e1000e` reset/watchdog sequencing** for robust link recovery.
5. **`drivers/net/usb/*` family patterns** (RTL8152/AX88179) once usbnet-core lands.

## 8) Non-goals and caution notes

- Do **not** import Linux code directly due to GPL obligations and architectural mismatch; use behavior-level reimplementation.
- Do **not** attempt “full Linux net stack parity” immediately; maintain narrow, testable slices.
- Keep DuetOS capability/security model explicit when adding firmware paths and USB auto-probe.

## 9) Recommended first execution slice (lowest risk / highest return)

If one slice is picked now, do this first:

1. Introduce xHCI event router with per-request completion.
2. Migrate existing `XhciBulkPoll`/control waiters to router-backed waits.
3. Remove global bulk poll lock and HID consumer pause dependency.
4. Re-enable USB-net probe in controlled boot phase and run net smoke.

This slice attacks the root blocking limitation and unlocks most other networking work.

## 10) References consulted

- Linux xHCI ring handling:
  - https://codebrowser.dev/linux/linux/drivers/usb/host/xhci-ring.c.html
- Linux USB net core:
  - https://codebrowser.dev/linux/linux/drivers/net/usb/usbnet.c.html
- Linux RNDIS host:
  - https://codebrowser.dev/linux/linux/drivers/net/usb/rndis_host.c.html
- Linux CDC-NCM:
  - https://codebrowser.dev/linux/linux/drivers/net/usb/cdc_ncm.c.html
- Linux neighbour core:
  - https://codebrowser.dev/linux/linux/net/core/neighbour.c.html
- Linux e1000e driver + regs:
  - https://codebrowser.dev/linux/linux/drivers/net/ethernet/intel/e1000e/netdev.c.html
  - https://codebrowser.dev/linux/linux/drivers/net/ethernet/intel/e1000e/regs.h.html
- Linux NAPI docs:
  - https://docs.kernel.org/networking/napi.html
- Linux wireless stack:
  - https://codebrowser.dev/linux/linux/net/wireless/core.c.html
  - https://codebrowser.dev/linux/linux/include/net/cfg80211.h.html
  - https://codebrowser.dev/linux/linux/net/mac80211/main.c.html
  - https://codebrowser.dev/linux/linux/include/net/mac80211.h.html
  - https://codebrowser.dev/linux/linux/include/uapi/linux/nl80211.h.html
  - https://codebrowser.dev/linux/linux/drivers/net/wireless/intel/iwlwifi/mvm/mac80211.c.html
  - https://codebrowser.dev/linux/linux/drivers/net/wireless/realtek/rtw88/main.c.html
  - https://codebrowser.dev/linux/linux/drivers/net/wireless/broadcom/brcm80211/brcmfmac/core.c.html
