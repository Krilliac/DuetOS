# DuetOS Usability & Robustness Campaign — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Drive DuetOS through exhaustive real use under max-host parallel orchestration, grade it against a researched bar (peer OSes + documented Win32), then fix what is broken and extend usability to that bar — leaving committed tooling and a recorded evaluation.

**Architecture:** Six sequential phases (bring-up → research → exploration → chaos/stress → triage+fix → synthesis). Each phase fans out parallel subagents, each owning an isolated QEMU guest via `tools/test/desktop-qmp-session.sh INSTANCE DRIVER_PY`. Concurrency scales to host capacity (`MAX_VMS`). The serial log (`boot-log-analyze.sh`) is the correctness channel; QMP screendumps read via vision are the usability channel.

**Tech Stack:** WSL2 build (`x86_64-debug` preset, the only buildable path), QEMU+OVMF (TCG), HMP-monitor Python drivers, `qmp-*.sh` helpers, `make-gpt-image.py` FAT32 staging, libFuzzer (`fuzz-all.sh`), `boot-log-analyze.sh` triage.

**Two kinds of task below:**
- **Tooling tasks (T-)** build/finalize code & scripts — verified by `bash -n` / `python3 -m py_compile` + a smoke invocation. These are TDD-shaped.
- **Execution tasks (E-)** run a phase's discovery loop — they cannot be pre-specified as unit tests because findings are unknown ahead of time, so each carries exact commands + an explicit **Definition of Done** + the record/commit step. This is honest: a discovery phase's "test" is its acceptance gate, not a fabricated assertion.

**Branch:** `claude/usability-campaign` (already created). All work commits here.

**Environment note (read once):** The build CANNOT run over `/mnt/c`. Every code change is made in the Windows checkout, then ported to the WSL checkout (`~/source/DuetOS`) via the `wsl-build` skill; after `cp`, touch the changed TU or ninja won't rebuild. All boot/QMP commands run **inside WSL**. Check host C: free space before long soaks (WSL `EIO` = C: full).

---

## File Structure

| Path | Responsibility | New/Modify |
|------|----------------|------------|
| `docs/usability/rubric.md` | Phase-1 grading bar (peer-OS + Win32 fidelity), per surface | Create |
| `docs/usability/findings.md` | Running findings ledger (id/surface/repro/evidence/expected/severity/fix-status) | Create |
| `docs/usability/2026-06-07-evaluation.md` | Final report (synthesis of findings + verdicts + coverage) | Create |
| `docs/usability/screenshots/` | Captured PPM/PNG evidence, namespaced per surface | Create (dir) |
| `tools/test/drivers/chaos-gui-driver.py` | GUI input-storm fuzzer (exists, staged) | Finalize+commit |
| `tools/test/drivers/chaos-pe-driver.py` | PE spawn/kill + handle-exhaustion driver (exists, staged) | Finalize+commit |
| `tools/test/drivers/chaos-shot-probe.py` | Screendump-path probe (exists, staged) | Finalize+commit |
| `tools/test/drivers/chaos-syscall-driver.py` | In-guest syscall/API abuse driver (terminal-driven) | Create |
| `tools/test/drivers/explore-app-driver.py` | Per-app exploration: open → exercise → screenshot each state | Create |
| `tools/test/usability-campaign.sh` | Master orchestrator: capacity probe, phase runner, parallel instances, combined max-chaos, extreme-load | Create |

---

## Task T-1 (Phase 0): Bring-up — green build, toolbox, golden boot, host-capacity probe

**Files:**
- Run-only (no source edits unless the build is red): WSL checkout `~/source/DuetOS`
- Create: `docs/usability/` directory + `docs/usability/baseline/` for golden screenshots

- [ ] **Step 1: Sync the Windows checkout into WSL and build (debug preset)**

The `wsl-build` skill handles the port + build. Invoke it; it syncs changed files to `~/source/DuetOS` and runs:
```bash
cmake --build ~/source/DuetOS/build/x86_64-debug --parallel "$(nproc)"
```
Expected: build completes, `~/source/DuetOS/build/x86_64-debug/kernel/duetos-kernel.elf` exists.

- [ ] **Step 2: Install the live-boot toolbox (QEMU/OVMF) if absent**

Inside WSL:
```bash
which qemu-system-x86_64 || sudo apt-get install -y qemu-system-x86 ovmf
```
Expected: `qemu-system-x86_64 --version` prints ≥ 6.x; `/usr/share/OVMF/OVMF_CODE_4M.fd` exists.

- [ ] **Step 3: Golden boot — one clean headless boot, capture serial + screendump**

```bash
cd ~/source/DuetOS
# desktop-qmp-session uses chaos-shot-probe to confirm screendump path works
bash tools/test/desktop-qmp-session.sh golden tools/test/drivers/chaos-shot-probe.py 2>&1 | tee /tmp/golden-probe.log
```
Expected: probe prints a non-error `screendump` reply and a `.ppm` is written; session exits 0.

- [ ] **Step 4: Run the verdict tool on the golden boot serial log**

```bash
bash tools/test/boot-log-analyze.sh   # auto-picks newest /tmp/duetos-*.log
echo "rc=$?"
```
Expected: `rc=0` (reached completion sentinel, no non-deliberate failure). **If rc≠0, STOP and fix the boot before any campaign phase** — a red baseline poisons every later grade.

- [ ] **Step 5: Capture the baseline screenshot set (golden desktop + each app first-open)**

```bash
mkdir -p docs/usability/baseline
# Drives the desktop, opens each app once, screendumps to the baseline dir.
# (explore-app-driver.py is built in Task T-4; until then capture desktop only.)
DUETOS_SHOT_DIR=docs/usability/baseline \
  bash tools/test/desktop-qmp-session.sh baseline tools/test/drivers/chaos-shot-probe.py
ls -la docs/usability/baseline/*.ppm
```
Expected: at least the desktop PPM exists; it becomes the visual reference for "did chaos corrupt the compositor."

- [ ] **Step 6: Probe host capacity and record MAX_VMS**

```bash
NPROC=$(nproc); FREE_MIB=$(free -m | awk '/^Mem:/{print $7}')
PER_GUEST_MIB=1024
MAX_VMS=$(( NPROC-2 < FREE_MIB/PER_GUEST_MIB ? NPROC-2 : FREE_MIB/PER_GUEST_MIB ))
echo "MAX_VMS=$MAX_VMS NPROC=$NPROC FREE_MIB=$FREE_MIB"
```
Expected: prints `MAX_VMS=` a value ≥ 4 on the Ryzen 7840HS host. Record it; the orchestrator (T-5) reads the same formula. User has authorized running at this max.

- [ ] **Step 7: Commit the bring-up artifacts**

```bash
git add docs/usability/baseline
git commit -m "usability: phase-0 golden boot baseline + capacity probe"
```

**Definition of Done:** green debug build, QEMU/OVMF present, `boot-log-analyze` rc=0 on a fresh boot, a baseline desktop screenshot committed, `MAX_VMS` known.

---

## Task E-2 (Phase 1): Research — build the grading rubric

**Files:**
- Create: `docs/usability/rubric.md`

This phase fans out **web/research subagents in parallel** (one per surface-family). It produces `rubric.md`: for each surface, the usability bar (peer-OS) + Win32 fidelity contract (docs). No live boot needed.

- [ ] **Step 1: Dispatch parallel research subagents (one per surface-family)**

Surface-families and what each agent answers (use the Agent tool, `general-purpose` or `Explore` for source-diving peer OSes, web search + MS Learn MCP for docs):

| Agent | Surface-family | Must produce |
|-------|----------------|--------------|
| R1 | File mgmt (files, trash, hexview, imageview) | What SerenityOS FileManager / Haiku Tracker / Win32 Explorer minimally do: navigate, select, multi-select, rename, delete, properties, open-with |
| R2 | Productivity (notes, calendar, clock, calculator, charmap) | Calculator operator-precedence + keyboard contract; notes save/load; charmap insert; clock/calendar correctness bar |
| R3 | Settings (display/datetime/keyboard/mouse/sound) | Each panel's apply+persist expectation per Haiku Preferences / Win32 Control Panel |
| R4 | System (sysmon, taskman, devicemgr, terminal) | Task-manager kill/sort bar; terminal line-editing + command set bar |
| R5 | Net/sec (browser, netstatus, firewall) | Browser minimal nav (URL, back, render); firewall rule add/remove bar |
| R6 | PE/Win32 fidelity | Documented NT/Win32 contract (MS Learn) for the syscalls/APIs the embedded System32 exes use; cross-check ReactOS/Wine behavior |

Each agent returns a structured block: `surface · bar(meets/partial/missing/broken criteria) · win32-contract(if applicable) · source URLs`.

- [ ] **Step 2: Assemble `docs/usability/rubric.md` from the agent returns**

Write one section per surface with a checklist of gradable criteria and the cited source. Format each criterion so Phase 2/3 can mark it `meets / partial / missing / broken` (+ `matches / diverges / unimplemented` for Win32).

- [ ] **Step 3: Sanity-gate the rubric**

Every native app from §5 of the spec has ≥3 gradable criteria; the PE surface lists the actual API/syscall contracts (not vague "should work"). Each criterion cites a source.

- [ ] **Step 4: Commit**

```bash
git add docs/usability/rubric.md
git commit -m "usability: phase-1 grading rubric (peer-OS bar + Win32 fidelity)"
```

**Definition of Done:** `rubric.md` exists, every surface has cited, gradable criteria, the PE surface names real Win32 contracts.

---

## Task T-3: Finalize + commit the three staged chaos drivers

The drivers exist (untracked in `tools/test/drivers/`) and already speak the HMP contract. Finalize = syntax-check, smoke against a live guest, fix anything that surfaces, commit.

**Files:**
- Modify/commit: `tools/test/drivers/chaos-gui-driver.py`, `chaos-pe-driver.py`, `chaos-shot-probe.py`

- [ ] **Step 1: Syntax-check all three**

```bash
for d in tools/test/drivers/chaos-gui-driver.py tools/test/drivers/chaos-pe-driver.py tools/test/drivers/chaos-shot-probe.py; do
  python3 -m py_compile "$d" && echo "OK $d" || echo "FAIL $d"
done
```
Expected: each prints `OK`. Fix any `FAIL`.

- [ ] **Step 2: Smoke the screendump probe (shortest, confirms path semantics)**

```bash
cd ~/source/DuetOS
bash tools/test/desktop-qmp-session.sh probe tools/test/drivers/chaos-shot-probe.py 2>&1 | tee /tmp/probe-smoke.log
grep -E "screendump|GREETING" /tmp/probe-smoke.log | head
```
Expected: a successful `screendump` reply (no `Error`), pinning the correct absolute screendump path the other drivers must use.

- [ ] **Step 3: Smoke the GUI chaos driver (short burst)**

```bash
cd ~/source/DuetOS
CHAOS_SECS=20 bash tools/test/desktop-qmp-session.sh guichaos tools/test/drivers/chaos-gui-driver.py
bash tools/test/boot-log-analyze.sh; echo "rc=$?"
```
Expected: session exits 0. **A non-zero `boot-log-analyze` rc is the first real finding — record it in `findings.md` (Task E-6) before fixing.**

- [ ] **Step 4: Smoke the PE chaos driver**

```bash
cd ~/source/DuetOS
CHAOS_SECS=20 bash tools/test/desktop-qmp-session.sh pechaos tools/test/drivers/chaos-pe-driver.py
bash tools/test/boot-log-analyze.sh; echo "rc=$?"
```
Expected: session exits 0; spawn/release tally printed; any crash marker is a recorded finding.

- [ ] **Step 5: Commit the three drivers**

```bash
git add tools/test/drivers/chaos-gui-driver.py tools/test/drivers/chaos-pe-driver.py tools/test/drivers/chaos-shot-probe.py
git commit -m "test: commit finalized GUI/PE/screendump chaos drivers"
```

**Definition of Done:** all three syntax-clean, each smoked against a live guest, committed; screendump path semantics confirmed.

---

## Task T-4: Build the exploration driver + the syscall-abuse driver

Two new drivers fill gaps the staged set doesn't cover: a *structured* per-app exploration driver (Phase 2) and an in-guest *syscall/API abuse* driver (Phase 3 vector 3).

**Files:**
- Create: `tools/test/drivers/explore-app-driver.py`
- Create: `tools/test/drivers/chaos-syscall-driver.py`

- [ ] **Step 1: Write `explore-app-driver.py`** (open one app, exercise it, screenshot each state)

Contract: `python3 explore-app-driver.py <MON_SOCK> <SERIAL_LOG>`; reads `EXPLORE_APP`, `EXPLORE_SHOT_DIR`, `EXPLORE_ICON_X/Y` from env. Opens the target app, runs a scripted interaction, screendumps after each meaningful state. Exits 0; verdict = screenshots + serial log.

```python
#!/usr/bin/env python3
"""explore-app-driver.py - structured single-app exploration for the
usability campaign. Opens EXPLORE_APP, exercises its primary workflow,
screendumps every meaningful state into EXPLORE_SHOT_DIR for vision
grading. Never asserts PASS. Invoked: explore-app-driver.py <MON_SOCK> <SERIAL_LOG>."""
import os, socket, sys, time

mon_p, slog = sys.argv[1], sys.argv[2]
APP = os.environ.get("EXPLORE_APP", "files")
SHOT_DIR = os.environ.get("EXPLORE_SHOT_DIR", "/tmp")
ICON_X = int(os.environ.get("EXPLORE_ICON_X", "48"))
ICON_Y = int(os.environ.get("EXPLORE_ICON_Y", "64"))

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(200):
    try:
        s.connect(mon_p); break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.25)
s.settimeout(0.1)
time.sleep(0.5)

def drain():
    try:
        while s.recv(65536):
            pass
    except Exception:
        pass

def hmp(line):
    s.sendall((line + "\n").encode()); time.sleep(0.05); drain()

def pin_origin():
    hmp("mouse_move -4000 -4000"); time.sleep(0.05)

def move_to(x, y):
    pin_origin()
    sx = 0
    while sx < x:
        d = min(40, x - sx); hmp(f"mouse_move {d} 0"); sx += d
    sy = 0
    while sy < y:
        d = min(40, y - sy); hmp(f"mouse_move 0 {d}"); sy += d

def click(x, y, btn=1):
    move_to(x, y); hmp(f"mouse_button {btn}"); time.sleep(0.05); hmp("mouse_button 0")

def double_click(x, y):
    click(x, y); time.sleep(0.08); click(x, y)

def shot(name):
    path = os.path.join(SHOT_DIR, f"{APP}-{name}.ppm")
    hmp(f"screendump {path}"); time.sleep(0.4); print(f"SHOT {path}")

drain()
os.makedirs(SHOT_DIR, exist_ok=True)
shot("desktop")
double_click(ICON_X, ICON_Y)
time.sleep(1.5); shot("open")
for k in ["t", "e", "s", "t"]:
    hmp(f"sendkey {k}"); time.sleep(0.05)
shot("typed")
hmp("sendkey ret"); time.sleep(0.5); shot("enter")
hmp("sendkey alt-spc"); time.sleep(0.3); shot("sysmenu")
hmp("sendkey esc"); time.sleep(0.2)
hmp("sendkey alt-f4"); time.sleep(0.5); shot("closed")
print("explore-app-driver done for", APP)
sys.exit(0)
```

- [ ] **Step 2: Syntax-check**

```bash
python3 -m py_compile tools/test/drivers/explore-app-driver.py && echo OK
```
Expected: `OK`.

- [ ] **Step 3: Smoke against one app (files)**

```bash
cd ~/source/DuetOS
EXPLORE_APP=files EXPLORE_SHOT_DIR=/tmp/explore-files \
  bash tools/test/desktop-qmp-session.sh expfiles tools/test/drivers/explore-app-driver.py
ls /tmp/explore-files/*.ppm
```
Expected: `files-desktop/open/typed/enter/sysmenu/closed.ppm` exist. Read `files-open.ppm` via vision to confirm the window opened; tune `ICON_X/Y` to the real desktop icon grid if it didn't.

- [ ] **Step 4: Write `chaos-syscall-driver.py`** (live syscall/API abuse via the terminal)

```python
#!/usr/bin/env python3
"""chaos-syscall-driver.py - live syscall/API abuse. Opens the DuetOS
terminal and issues a storm of shell diag/stress commands with malformed
and boundary args, watching the serial log for panic/W^X/OOB markers.
Pairs with the host libFuzzer harness (fuzz-all.sh). Invoked:
chaos-syscall-driver.py <MON_SOCK> <SERIAL_LOG>. Always exits 0."""
import os, socket, sys, time

mon_p, slog = sys.argv[1], sys.argv[2]
DURATION = float(os.environ.get("CHAOS_SECS", "60"))

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(200):
    try:
        s.connect(mon_p); break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.25)
s.settimeout(0.1)
time.sleep(0.5)

def hmp(line):
    s.sendall((line + "\n").encode()); time.sleep(0.04)

def typestr(text):
    for ch in text:
        key = {" ": "spc", "-": "minus", "/": "slash", ".": "dot",
               "\\": "backslash"}.get(ch, ch)
        hmp(f"sendkey {key}")
    hmp("sendkey ret")

tx = int(os.environ.get("TERM_ICON_X", "48"))
ty = int(os.environ.get("TERM_ICON_Y", "352"))
hmp("mouse_move -4000 -4000"); time.sleep(0.05)
sx = 0
while sx < tx:
    d = min(40, tx-sx); hmp(f"mouse_move {d} 0"); sx += d
sy = 0
while sy < ty:
    d = min(40, ty-sy); hmp(f"mouse_move 0 {d}"); sy += d
hmp("mouse_button 1"); hmp("mouse_button 0"); time.sleep(0.1)
hmp("mouse_button 1"); hmp("mouse_button 0"); time.sleep(1.2)

payloads = [
    "help", "mem", "ps", "stress mem 1 999999", "stress cpu -1",
    "cat /../../etc", "ls ////", "kill 999999", "kill -1",
    "alloc 0xffffffffffffffff", "peek 0", "poke 0 0",
    "run X:\\nope.exe", "open " + "A"*4096,
]
end = time.time() + DURATION
i = 0
while time.time() < end:
    typestr(payloads[i % len(payloads)]); i += 1; time.sleep(0.2)
print(f"chaos-syscall-driver issued {i} payloads")
sys.exit(0)
```

- [ ] **Step 5: Syntax-check + smoke the syscall driver**

```bash
python3 -m py_compile tools/test/drivers/chaos-syscall-driver.py && echo OK
cd ~/source/DuetOS
CHAOS_SECS=25 bash tools/test/desktop-qmp-session.sh syschaos tools/test/drivers/chaos-syscall-driver.py
bash tools/test/boot-log-analyze.sh; echo "rc=$?"
```
Expected: `OK`; session exits 0. The shell verb set may differ — grep `kernel/shell/shell_dispatch.cpp` for the real verbs and align `payloads` so the abuse hits real handlers.

- [ ] **Step 6: Commit both drivers**

```bash
git add tools/test/drivers/explore-app-driver.py tools/test/drivers/chaos-syscall-driver.py
git commit -m "test: add exploration + live-syscall-abuse campaign drivers"
```

**Definition of Done:** both drivers syntax-clean and smoked; exploration screenshots show real windows under vision; syscall payloads aligned to the actual shell verbs.

---

## Task T-5: Master orchestrator `usability-campaign.sh`

One entrypoint that runs a phase, scales to `MAX_VMS`, namespaces instances, and supports the combined max-chaos + extreme-load run. It wraps `desktop-qmp-session.sh` (which already namespaces per INSTANCE) — it does **not** reimplement booting.

**Files:**
- Create: `tools/test/usability-campaign.sh`

- [ ] **Step 1: Write the orchestrator**

```bash
#!/usr/bin/env bash
#
# usability-campaign.sh - run a phase of the DuetOS usability campaign at
# host-max parallelism. Wraps desktop-qmp-session.sh (which namespaces
# every per-run artifact by INSTANCE) so N guests run concurrently without
# collision. Verdict per guest = boot-log-analyze on its serial log.
#
# USAGE:
#   usability-campaign.sh capacity
#   usability-campaign.sh explore   APP[:ICONX:ICONY] [APP...]
#   usability-campaign.sh chaos     gui|pe|syscall|resource [SECS]
#   usability-campaign.sh maxchaos  [SECS]     # all vectors at once, MAX_VMS guests
#   usability-campaign.sh extreme   [SECS]     # maxchaos + SMP8 + mem pressure
#
# ENV: DUETOS_PRESET (x86_64-debug)  PER_GUEST_MIB (1024)
set -euo pipefail
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DRV="${SCRIPT_DIR}/drivers"
readonly SESSION="${SCRIPT_DIR}/desktop-qmp-session.sh"
PER_GUEST_MIB="${PER_GUEST_MIB:-1024}"

capacity() {
  local nproc free max
  nproc=$(nproc); free=$(free -m | awk '/^Mem:/{print $7}')
  max=$(( nproc-2 < free/PER_GUEST_MIB ? nproc-2 : free/PER_GUEST_MIB ))
  (( max < 1 )) && max=1
  echo "$max"
}

PRESET="${DUETOS_PRESET:-x86_64-debug}"
# desktop-qmp-session.sh writes the serial log to build/<preset>/sess-<INSTANCE>.serial.log
SERIAL_FOR() { echo "$(cd "${SCRIPT_DIR}/../.." && pwd)/build/${PRESET}/sess-${1}.serial.log"; }

run_one() {  # INSTANCE DRIVER  [extra env already exported]
  local inst="$1" drv="$2"
  bash "${SESSION}" "${inst}" "${drv}" >"/tmp/uc-${inst}.out" 2>&1 || true
  bash "${SCRIPT_DIR}/boot-log-analyze.sh" "$(SERIAL_FOR "${inst}")" \
    >"/tmp/uc-${inst}.verdict" 2>&1; echo "$inst rc=$? -> /tmp/uc-${inst}.verdict"
}

cmd="${1:?usage: see header}"; shift || true
case "$cmd" in
  capacity) capacity ;;
  explore)
    for spec in "$@"; do
      IFS=: read -r app ix iy <<<"$spec"
      EXPLORE_APP="$app" EXPLORE_ICON_X="${ix:-48}" EXPLORE_ICON_Y="${iy:-64}" \
        EXPLORE_SHOT_DIR="$(pwd)/docs/usability/screenshots/${app}" \
        run_one "exp-${app}" "${DRV}/explore-app-driver.py" &
      while (( $(jobs -r | wc -l) >= $(capacity) )); do wait -n; done
    done; wait ;;
  chaos)
    vector="${1:?gui|pe|syscall|resource}"; secs="${2:-75}"
    case "$vector" in
      gui)      drv="${DRV}/chaos-gui-driver.py" ;;
      pe)       drv="${DRV}/chaos-pe-driver.py" ;;
      syscall)  drv="${DRV}/chaos-syscall-driver.py" ;;
      resource) drv="${DRV}/chaos-syscall-driver.py"  # resource payloads live here
                export CHAOS_SECS="$secs" ;;
      *) echo "unknown vector $vector" >&2; exit 2 ;;
    esac
    CHAOS_SECS="$secs" run_one "chaos-${vector}" "$drv" ;;
  maxchaos)
    secs="${1:-90}"
    for v in gui pe syscall resource; do
      drv="${DRV}/chaos-${v}-driver.py"; [[ -f "$drv" ]] || drv="${DRV}/chaos-syscall-driver.py"
      CHAOS_SECS="$secs" run_one "max-${v}" "$drv" &
    done; wait ;;
  extreme)
    secs="${1:-120}"
    # Requires the DUETOS_SMP pass-through added to desktop-qmp-session.sh
    # in Task T-5 Step 4a (the stock script launches single-CPU).
    export DUETOS_SMP="${DUETOS_SMP:-8}"
    "${0}" maxchaos "$secs" ;;
  *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
```

- [ ] **Step 2: Syntax-check**

```bash
bash -n tools/test/usability-campaign.sh && echo OK
```
Expected: `OK`.

- [ ] **Step 3: Capacity dry-run**

```bash
bash tools/test/usability-campaign.sh capacity
```
Expected: prints an integer ≥1 (matches the T-1 Step-6 `MAX_VMS`).

- [ ] **Step 4a: Wire `DUETOS_SMP` into `desktop-qmp-session.sh`** (the stock script launches single-CPU; the `extreme` mode needs SMP)

In `tools/test/desktop-qmp-session.sh`, find the QEMU launch (the line with `-serial "file:${SERIAL_LOG}"`) and add an SMP flag driven by env:
```bash
# near the other readonly env defaults at the top:
SMP="${DUETOS_SMP:-1}"
# in the qemu-system-x86_64 argument list, add:
    -smp "${SMP}" \
```
Verify: `bash -n tools/test/desktop-qmp-session.sh && echo OK`.

- [ ] **Step 4b: One real explore run through the orchestrator**

```bash
cd ~/source/DuetOS
bash tools/test/usability-campaign.sh explore files:48:64
cat /tmp/uc-exp-files.verdict
```
Expected: a verdict line; screenshots under `docs/usability/screenshots/files/`. The verdict reads `build/x86_64-debug/sess-exp-files.serial.log` via `SERIAL_FOR`.

- [ ] **Step 5: Commit**

```bash
git add tools/test/usability-campaign.sh tools/test/desktop-qmp-session.sh
git commit -m "test: usability-campaign orchestrator + DUETOS_SMP pass-through"
```

**Definition of Done:** orchestrator `bash -n` clean, `capacity` matches the probe, `DUETOS_SMP` wired into the session script, one explore run produces verdict + screenshots from the real `sess-<inst>.serial.log` path.

---

## Task E-6 (Phase 2): Exploration — exhaustive, all apps, graded

**Files:**
- Create: `docs/usability/findings.md` (the ledger all later phases append to)
- Create: `docs/usability/screenshots/<app>/*.ppm`

This phase fans out one subagent per app-cluster (spec §5); each owns guests via the orchestrator, drives every app, and grades screenshots against `rubric.md`.

- [ ] **Step 1: Create the findings ledger with its schema header**

```markdown
# DuetOS Usability Findings Ledger
| id | surface | severity | repro | evidence | expected (rubric ref) | fix-status |
|----|---------|----------|-------|----------|-----------------------|------------|
```
Severity: Critical/High/Medium/Low. fix-status: open/fixed/extended/filed.

- [ ] **Step 2: Run exploration for every app, host-max parallel**

```bash
cd ~/source/DuetOS
# ICON_X:ICON_Y per app come from the real desktop icon grid (confirm in T-4 Step-3).
bash tools/test/usability-campaign.sh explore \
  files notes calendar clock calculator charmap trash hexview imageview \
  devicemgr sysmon taskman settings browser netstatus firewall terminal \
  help about screenshot
ls docs/usability/screenshots/*/
```
Expected: each app has a `*-open.ppm` + interaction-state PPMs.

- [ ] **Step 3: Grade each app via vision against the rubric**

For each app's screenshots: read the PPMs, compare observed state to that surface's `rubric.md` criteria. For every criterion that is `partial/missing/broken` (or Win32 `diverges/unimplemented`), append a row to `findings.md` with the screenshot path as evidence and the rubric line as `expected`. Settings: verify each panel applies AND persists (re-open after change).

- [ ] **Step 4: Coverage check**

Every app in spec §5 has ≥1 screenshot set and a grade for every rubric criterion (a criterion graded `meets` is recorded too, as a coverage tick). No app is silently skipped — if an icon never opened, that itself is a Critical/High finding.

- [ ] **Step 5: Commit exploration evidence + findings**

```bash
git add docs/usability/findings.md docs/usability/screenshots
git commit -m "usability: phase-2 exploration evidence + graded findings"
```

**Definition of Done:** every app exercised + graded, findings rows filed with screenshot evidence and rubric refs, no app silently skipped.

---

## Task E-7 (Phase 3): Chaos / stress — all vectors, solo → combined → extreme, loop-until-dry

**Files:**
- Append to: `docs/usability/findings.md`
- Run-only: `tools/test/usability-campaign.sh`, `tools/test/fuzz-all.sh`, `tools/test/mem-stress-sweep.sh`, `tools/test/smp-stress-sweep.sh`

- [ ] **Step 1: Run each vector solo (clean attribution)**

```bash
cd ~/source/DuetOS
for v in gui pe syscall resource; do
  bash tools/test/usability-campaign.sh chaos "$v" 75
  cat /tmp/uc-chaos-${v}.verdict
done
# Host-side parser fuzz in parallel (covers untrusted-input surface):
bash tools/test/fuzz-all.sh 2>&1 | tail -20
```
Expected: a verdict per vector + the fuzz aggregate rc. Each non-zero verdict / fuzz crash artifact → a `findings.md` row (Critical if panic/triple-fault/hang).

- [ ] **Step 2: Combined max-chaos — all four vectors at once, host-max guests**

```bash
cd ~/source/DuetOS
bash tools/test/usability-campaign.sh maxchaos 90
for v in gui pe syscall resource; do cat /tmp/uc-max-${v}.verdict; done
```
Expected: four concurrent guests' verdicts. Combined load is where lost-page/slot collisions and refcount asymmetry surface that solo runs miss — scrutinize any guest that wedged.

- [ ] **Step 3: Extreme load — combined chaos + SMP8 + memory pressure**

```bash
cd ~/source/DuetOS
bash tools/test/usability-campaign.sh extreme 120 &
bash tools/test/smp-stress-sweep.sh 2>&1 | tail -15 &
bash tools/test/mem-stress-sweep.sh 2>&1 | tail -15 &
wait
```
Expected: extreme verdicts + SMP/mem sweep summaries. Any soft-lockup / OOM-non-graceful / race assert → finding.

- [ ] **Step 4: Loop-until-dry on the combined run**

Re-run Step 2 repeatedly. Track findings whose `id` is new each round. Stop after **2 consecutive rounds** that surface nothing new. Confirmed-intermittent findings (crash this round, clean last) re-run ≥3× before classifying — intermittent IS a bug, classify by the class-of-bug shape (collision / refcount / whitelist / sentinel), don't dismiss as flaky.

- [ ] **Step 5: Apply the class-of-bug lens to clustered symptoms**

When N similar verdicts appear, trace ONE to root cause before filing N rows — file the cluster as one finding with N occurrences. Root usually explains the cluster.

- [ ] **Step 6: Commit chaos findings**

```bash
git add docs/usability/findings.md
git commit -m "usability: phase-3 chaos/stress findings (solo+combined+extreme, dry)"
```

**Definition of Done:** every vector run solo + combined + extreme; loop ran to 2 dry rounds; intermittent findings confirmed over ≥3 runs; clustered symptoms traced to single roots; all filed.

---

## Task E-8 (Phase 4): Triage — fix the broken, extend to the bar

**Files:**
- Modify: whatever source the root causes point to (kernel/apps, subsystems, userland libs, WM/compositor)
- Append to: `docs/usability/findings.md` (update fix-status), `wiki/reference/Roadmap.md` (filed items)

This phase fans out one subagent per root-cause cluster (use systematic-debugging). Each: reproduce, root-cause, fix-or-extend, re-verify, update status.

- [ ] **Step 1: Order findings by severity, group by suspected root cause**

Critical/High first. Group rows that likely share a root (same subsystem, same class-of-bug shape) into one investigation each.

- [ ] **Step 2: Per cluster — reproduce with the exact driver that found it**

Re-run the specific `usability-campaign.sh` / driver invocation from the finding's `repro` column inside WSL. Confirm the symptom before touching code (no speculative fixes).

- [ ] **Step 3: Fix the broken / extend to the bar**

- **Broken** (crash/panic/wrong-behavior): fix at the root. Add diagnostic `KLOG_WARN` on the failure summary + `KLOG_DEBUG_*` detail; fire a `KBP_PROBE` on new failure legs (CLAUDE.md diagnostic-logging contract). Keep the diagnostics in.
- **Extend** (finding cites a peer/Win32 bar the app doesn't meet, and it's core to the surface): implement the missing behavior to the bar — no further. Anti-bloat guard: if no finding cites a concrete bar, it is NOT an extension target; file it instead.
- Build via the `wsl-build` skill after every change (port → touch TU → ninja).

- [ ] **Step 4: Re-verify — re-run the finding's signal AND re-scan the others**

```bash
cd ~/source/DuetOS
# the driver that found it:
bash tools/test/usability-campaign.sh chaos <vector> 75   # or the explore/maxchaos cmd
bash tools/test/boot-log-analyze.sh "build/x86_64-debug/sess-chaos-<vector>.serial.log"; echo "rc=$?"
# full signal re-scan (CLAUDE.md: fix anything you surface):
cmake --build build/x86_64-debug --parallel "$(nproc)" 2>&1 | grep -E "warning|error" || echo "build clean"
cd build/x86_64-debug && ctest --output-on-failure 2>&1 | tail -5; cd ../..
find kernel userland \( -name '*.h' -o -name '*.cpp' \) | xargs clang-format --dry-run --Werror 2>&1 | head
bash tools/test/fuzz-all.sh 2>&1 | tail -3
```
Expected: the finding's signal now passes; build clean, ctest green, clang-format clean, fuzz clean. Update the row's `fix-status` to `fixed` or `extended`.

- [ ] **Step 5: File the un-fixable as concrete Roadmap rows**

For each finding needing a real refactor (cyclic dep, change > context window, needs a runtime artifact that doesn't exist), add a `wiki/reference/Roadmap.md` row stating the concrete blocker and what would unblock it — not a vague TODO. Update `fix-status` to `filed`.

- [ ] **Step 6: Commit fixes (one logical commit per root cause)**

```bash
git add -A
git commit -m "usability: fix <root-cause> (<N findings>) + re-verify"
```

**Definition of Done:** every Critical/High either `fixed`/`extended` (signal re-verified, full re-scan clean) or `filed` with a concrete blocker; diagnostics gated and kept; no symptom patched without root-causing its cluster.

---

## Task E-9 (Phase 5): Synthesis — report, tooling, wiki, Definition-of-Done

**Files:**
- Create: `docs/usability/2026-06-07-evaluation.md`
- Modify: `wiki/reference/Win32-Surface-Status.md`, owning subsystem wiki pages, `wiki/reference/Design-Decisions.md`, `wiki/getting-started/History.md` (if a milestone moved)

- [ ] **Step 1: Write the evaluation report**

Sections: per-surface grade table (meets/partial/missing/broken + Win32 matches/diverges/unimplemented), full findings table (final fix-status), what-was-fixed vs what-was-extended vs what-was-filed, coverage map (apps × rubric criteria), comparison verdicts vs SerenityOS/Haiku/ReactOS/Win32, and the campaign re-run instructions (the `usability-campaign.sh` commands).

- [ ] **Step 2: Flip Win32-Surface-Status rows the fixes touched**

For any PE/Win32 surface a fix moved from STUB/MISSING toward REAL, update the row in `wiki/reference/Win32-Surface-Status.md`.

- [ ] **Step 3: Amend owning subsystem wiki pages + Design-Decisions**

Update each subsystem page a fix/extension touched. Append `Design-Decisions.md` where a fix ruled out an alternative a future slice could pick.

- [ ] **Step 4: Run the Definition-of-Done scan (CLAUDE.md checklist)**

```bash
cd ~/source/DuetOS
git grep -nE "// (STUB|GAP):" | wc -l        # markers present on omissions, absent on working code
bash docs/sync-wiki.sh sync 2>&1 | grep -i stale || echo "no stale refs"
bash tools/test/boot-log-analyze.sh "$(ls -t build/x86_64-debug/sess-*.serial.log | head -1)"; echo "final rc=$?"
```
Expected: no stale wiki refs; final boot rc=0; STUB/GAP markers honest.

- [ ] **Step 5: Final commit**

```bash
git add docs/usability wiki
git commit -m "usability: phase-5 evaluation report + wiki/status sync"
```

- [ ] **Step 6: Finish the branch**

Use the `superpowers:finishing-a-development-branch` skill to choose merge/PR. If PR: poll CI to green (GitHub MCP, per CLAUDE.md post-PR checks) and fix anything red before declaring done.

**Definition of Done:** report written; Win32-Surface-Status + subsystem wiki + Design-Decisions synced; DoD scan clean (no stale refs, final boot green, honest markers); branch finished per user's choice.

---

## Self-Review (plan vs spec)

- **Spec §1 outcome (fix + extend + report + tooling + Roadmap):** covered by E-8 (fix/extend/file), E-9 (report/wiki), T-3/T-4/T-5 (tooling). ✓
- **Spec §2 six phases:** T-1=P0, E-2=P1, E-6=P2, E-7=P3, E-8=P4, E-9=P5. ✓
- **Spec §2 max-host concurrency:** T-1 Step-6 probe + T-5 `capacity()`/`MAX_VMS`. ✓
- **Spec §3 interaction loop:** T-4 explore-driver + E-6 grading (screendump→vision + boot-log-analyze). ✓
- **Spec §4 rubric (bar + Win32 fidelity):** E-2 with 6 research agents incl. R6 Win32. ✓
- **Spec §5 exhaustive exploration, all apps + settings panels:** E-6 Step-2/3 (settings apply+persist). ✓
- **Spec §6 four vectors solo+combined+extreme, loop-until-dry, class-of-bug:** E-7 all steps. ✓
- **Spec §7 fix policy + diagnostics gating + Roadmap:** E-8 Steps 3-5. ✓
- **Spec §8 deliverables (report, committed drivers+orchestrator, wiki flips):** T-3/4/5 + E-9. ✓
- **Spec §9 findings/severity schema:** E-6 Step-1 ledger header. ✓
- **Spec §10 risks (WSL-only build, TCG, bare-metal-gated smokes, C: space, determinism):** Environment note + E-7 Step-4 + per-task WSL builds. ✓
- **Spec §11 out-of-scope (no speculative features, no bare-metal/VBox, no rewrites):** E-8 Step-3 anti-bloat guard. ✓
- **Type consistency:** env var names (`EXPLORE_APP/SHOT_DIR/ICON_X/Y`, `CHAOS_SECS`, `MAX_VMS`, `PER_GUEST_MIB`, `DUETOS_SMP`), instance-naming (`exp-<app>`, `chaos-<v>`, `max-<v>`), and the serial-log path (`build/<preset>/sess-<INSTANCE>.serial.log`, via `SERIAL_FOR`) are used consistently across T-5/E-6/E-7/E-8/E-9.

**Two repo assumptions verified during planning (both corrected inline):**
1. `desktop-qmp-session.sh` writes its serial log to `build/<preset>/sess-<INSTANCE>.serial.log` (confirmed at `desktop-qmp-session.sh:50`) — the orchestrator's `SERIAL_FOR`/`run_one` and all verdict reads use this, not `/tmp/duetos-*.log`.
2. The stock session script has **no `-smp`** flag (single-CPU boot). The `extreme` mode's SMP requirement is therefore a concrete edit: T-5 Step-4a adds a `DUETOS_SMP` pass-through to the QEMU launch line.
