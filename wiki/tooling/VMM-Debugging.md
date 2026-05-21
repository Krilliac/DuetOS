# Debugging DuetOS under `duetos-vmm` from Visual Studio

> **Audience:** Anyone debugging the kernel, the VMM itself, or both at once on Windows.
>
> **Execution context:** Windows host running the in-house VMM ([`tools/vmm/`](../../tools/vmm/)) under a hardware hypervisor (WHP).
>
> **Sibling docs:**
> - [In-House Windows VMM](Windows-VMM.md) — what the VMM is, why it exists, build instructions, CLI surface.
> - [Debugger](Debugger.md) — the **in-kernel** debugger (kernel shell, `addr2sym`, KBP probes). Different problem space; complementary.
> - [Debugging](Debugging.md) — general DuetOS debugging toolkit (post-mortem logs, symbol resolution).

## Why this page exists

Debugging an OS that runs as a guest under a hypervisor has a fundamental boundary: the **host CPU** (running the VMM and your debugger) and the **guest CPU** (running the kernel) are different machines. Visual Studio's native debugger only natively understands the host. To inspect or interrupt the guest you need a *bridge* — code in the VMM that translates "set a breakpoint on kernel function `foo`" into "plant `0xCC` at the host-pointer that backs `foo`'s guest VA" and back-translates the resulting trap into something VS can show.

`duetos-vmm` provides **two bridges**, each with different strengths, and a third workflow that runs both at once for full coverage. This page is the complete reference.

## Two debug surfaces, three workflows

| Surface | What VS sees as the debuggee | Best for |
|---|---|---|
| **GDB-stub attach** (via [`launch.vs.json`](../../launch.vs.json)'s *"DuetOS: Attach (in-house VMM, tcp:1234)"* config) | The kernel ELF, source-level — VS uses `cppdbg`/gdb against the VMM's GDB-remote on tcp:1234 | Source-level **kernel** debugging: click in the gutter to plant kernel breakpoints, F10/F11 step kernel C++, browse kernel symbols/locals like any host program. |
| **Native attach + host-side bridge** (F5 the `duetos-vmm` CMake target in Open Folder mode) | `duetos-vmm.exe` itself (the VMM process), and via the bridge surface (`vmm_dbg::`, `Vmm::kernel`, `g_stop_state`) the guest's data | Debugging the **VMM**, or co-inspecting host + guest data in one window. Adds the ability to read/write any kernel global by symbol name and to halt at guest breakpoints planted from VS's Immediate window. |
| **Both at once** | One VS instance per surface; they coexist | Full coverage. Set kernel breakpoints via Path A; peek at VMM internals in Path B; same `duetos-vmm.exe` process backs both. |

## One-time setup

### Prerequisites

- VS 2022 (Community or higher) with the **Desktop development with C++** workload.
- Windows feature **Windows Hypervisor Platform** enabled (Settings → Optional features → "Windows Hypervisor Platform").
- The kernel ELF built in WSL via the project's clang preset: `cmake --preset x86_64-debug && cmake --build build/x86_64-debug`. VS cannot build the freestanding kernel; this stays on the Linux side.
- A **Windows-side gdb** for Path A — on `PATH` so the `"gdb.exe"` placeholder in `launch.vs.json` resolves. **Not** the WSL `/usr/bin/gdb` — WSL2 cannot reach the Windows host's `localhost`, and the VMM's GDB stub is a Windows-side socket. If you don't have one yet, the simplest install (no admin, adds itself to user PATH automatically):
   ```powershell
   winget install BrechtSanders.WinLibs.POSIX.UCRT --source winget
   ```
   Then **relaunch any open VS** instance so it picks up the new PATH. Alternatives: `scoop install gdb`, `choco install gdb` (admin), or `pacman -S mingw-w64-ucrt-x86_64-gdb` inside MSYS2.
- Optional: PowerShell helper [`tools/vmm/vs-start-vmm.ps1`](../../tools/vmm/vs-start-vmm.ps1) for orchestrating the WSL kernel build → VMM build → launch chain.

### Configure VS

1. **Open the repo as an Open-Folder solution** in VS. VS picks up `tools/vmm/CMakeLists.txt` automatically. The default F5 target after CMake configure should be `duetos-vmm` — verify in the toolbar.

2. **Set the Windows gdb path** for the *Attach (in-house VMM, tcp:1234)* config. Open [`launch.vs.json`](../../launch.vs.json), find the entry, and set `miDebuggerPath` to your real Windows gdb.exe (the placeholder `"gdb.exe"` only works if it's on `PATH`). Example:

   ```json
   "miDebuggerPath": "C:\\msys64\\ucrt64\\bin\\gdb.exe"
   ```

3. **(Optional) Wire the preLaunch starter** so F5 builds the kernel via WSL before launching. Drop this snippet into `.vs/tasks.vs.json` (per-user, git-ignored), then add `"preLaunchTask": "start-duetos-vmm"` to the *Attach (in-house VMM)* config:

   ```json
   {
     "version": "0.2.1",
     "tasks": [{
       "taskLabel": "start-duetos-vmm",
       "appliesTo": "launch.vs.json",
       "type": "default",
       "command": "powershell.exe",
       "args": [
         "-ExecutionPolicy", "Bypass", "-File",
         "${workspaceRoot}\\tools\\vmm\\vs-start-vmm.ps1",
         "-BuildKernel"
       ]
     }]
   }
   ```

### Default F5 behaviour

CMake's `VS_DEBUGGER_COMMAND_ARGUMENTS` sets the F5 default launch for the `duetos-vmm` target to:

```
duetos-vmm.exe --kernel <repo>/build/x86_64-debug/kernel/duetos-kernel.elf
               --mem 2048 --gdb 1234 --break
```

That means **a single F5 already opens both bridges**: the GDB stub on tcp:1234 (Path A), and the `__debugbreak()` startup-stop for Path B. To use just one or the other, edit the args in `tools/vmm/CMakeLists.txt`'s `VS_DEBUGGER_COMMAND_ARGUMENTS` (or override via VS's Debug → Options).

---

## Path A — GDB-stub attach (source-level kernel debugging)

This is what you use when you want to debug the **kernel** as if it were a normal program: kernel source open in VS, click breakpoints in `kernel/*.cpp` files, F10/F11 step through kernel code, see kernel variables in Locals.

### How to use — `debug-kernel.ps1` (recommended)

The reliable one-action path. From PowerShell at the repo root:

```powershell
tools\vmm\debug-kernel.ps1
```

The script (see [`tools/vmm/debug-kernel.ps1`](../../tools/vmm/debug-kernel.ps1)) launches the VMM with `--gdb 1234`, polls its stdout for the gdb-stub-ready sentinel (`[vmm] gdb: waiting for a client on tcp:`), then spawns `gdb.exe` in a new console window with the kernel ELF's symbols loaded, WSL→Windows DWARF source-path substitution wired up, and the guest halted pre-first-instruction. Source-level kernel debugging happens in the gdb TUI window — `b kernel_main`, `c`, `bt`, `info reg`, `step`, `next`, `print`. The TUI is more keyboard-driven than a GUI debugger but resolves symbols, sources, and DWARF the same way.

Drop a desktop shortcut on this for genuine one-click:

```
Target:   powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\path\to\DuetOS\tools\vmm\debug-kernel.ps1
Start in: C:\path\to\DuetOS
```

Flags:
- `-NoGdb` — launch only the VMM (gdb stub open, no client attached). Use when you want to attach a different debugger (VS attach below, VS Code, command-line gdb).
- `-GdbPort N` — non-default port.
- `-NoWindow` — headless VMM.
- `-MemMB N` — non-default guest RAM.

**One stop during boot is normal:** the kernel runs a `[traps] self-test` that executes a hardcoded `int3` to exercise its own `#BP` handler. With gdb attached, the host stub catches that `#BP` (the kernel's IDT handler can't run while the host owns exception exits) and reports a one-shot SIGTRAP. Press `c` in gdb and boot proceeds.

### How to use — VS editor attach (when launch.vs.json works)

If you want kernel breakpoints in the VS editor UI instead of the gdb TUI, the [`tools/vmm/launch.vs.json`](../../tools/vmm/launch.vs.json) entry **"DuetOS: Attach (in-house VMM kernel, tcp:1234)"** drives the same gdb-remote attach inside VS's cppdbg debugger:

1. From PowerShell: `tools\vmm\debug-kernel.ps1 -NoGdb` — launches just the VMM, gdb stub open, no client connected.
2. In VS with `tools/vmm/` opened as a folder, pick that entry in the Startup Item dropdown, F5. VS's cppdbg attaches gdb internally to localhost:1234; click breakpoints in the gutter of any kernel `.cpp` file.

> **Known fragility:** VS's launch.vs.json integration in CMake-Open-Folder mode sometimes silently invalidates the entry after CMake configure (entries flash in then vanish from the Startup Item dropdown). If this happens, use the `debug-kernel.ps1` flow above, or fall back to `Debug → Attach to Process...` with `Connection type: Microsoft GDB Adapter` and target `localhost:1234`. Symptom and unsuccessful root-cause hunt documented in commit history.

> Use **Debug → Detach All** to end this session, not Stop Debugging. Stop will pop an E_FAIL "couldn't terminate duetos-kernel.elf" because the kernel is not a local Windows process — only the VMM (started separately) is.

### After connect (either flow)

1. **Set kernel breakpoints.** In the gdb TUI: `b kernel_main`, `b kernel/sched/sched.cpp:42`. In VS editor: click the gutter. They're real breakpoints — the GDB stub plants `0xCC` at the resolved guest VA.
2. Continue: `c` in gdb, F5 in VS. The guest runs until a breakpoint fires.
3. When stopped:
   - **Call stack:** `bt` (gdb) or VS's Call Stack window.
   - **Locals:** `info locals`, `info args`, `print <var>` (gdb) or VS's Locals/Autos.
   - **Registers:** `info reg` (gdb) or VS's Registers window.
   - **Step:** `n` (over), `s` (into), `fin` (out) in gdb. F10/F11/Shift-F11 in VS.

### `monitor` subcommands (gdb-side introspection)

In gdb's prompt (VS exposes this as the Watch window via `-exec` prefix, or use the Debug Console), the VMM responds to several custom `monitor` queries:

```
monitor help              # list available subcommands
monitor sym <hexaddr>     # nearest kernel symbol at this guest address
monitor lookup <name>     # symbol's address + size by exact mangled name
monitor read <name> [n]   # hex-dump n bytes of a named symbol
monitor rip               # current vCPU RIP, symbolized
monitor trace             # last ~256 vmexits with reason/aux/rip
```

These also work without VS — any gdb client (Eclipse, CLion, command-line gdb) sees the same surface.

### Caveats

- **Use Windows gdb, not WSL gdb.** WSL2 can't reach the Windows host via `localhost`.
- **Source-hardcoded `int3` (kernel traps self-test, in-kernel KBP probes)** surface as one-shot SIGTRAPs while gdb is attached — the host stub catches the `#BP` before the guest IDT does, so the kernel's own `#BP` handler can't run under gdb. Press Continue once per stop; the next instruction runs normally. (If you specifically need to validate the in-kernel `#BP` handler path itself, boot without `--gdb`.) Historical note: an earlier unconditional rewind in `OnException` turned these into infinite re-trap loops; that's fixed — see `tools/vmm/src/debug/gdb_server.cpp` `OnException` and `tools/vmm/src/vmm.cpp`'s exception-exit handler.
- **No hardware watchpoints** in v0 of the stub. Software breakpoints (`Z0`/`z0`) only.
- **Async Pause / Break-All works.** A background watcher thread in the stub (`GdbServer::IrqWatcherLoop` in `tools/vmm/src/debug/gdb_server.cpp`) consumes `\x03` from the gdb socket while the guest is running and calls `WHvCancelRunVirtualProcessor` to break the main thread out of the WHP run loop; the main loop sends a proactive `S05` and enters interactive stopped mode. Earlier versions of this stub did NOT implement this — the result was that hitting VS's Pause while the guest was running froze the IDE (UI thread blocked waiting for a stop reply that never came). If you're on an old build and see that symptom, rebuild.

---

## Path B — Native attach + bridge (host VMM + guest data in one window)

This is what you use when you want VS to drive `duetos-vmm.exe` as the debuggee — seeing host VMM C++ (the `Vmm` class, `GuestMemory`, exit handlers) — and ALSO be able to inspect or modify guest kernel state from the same window via the bridge surface.

### What you get

Out of the box (VS sees as host process):
- VMM C++ source, breakpoints in `vmm.cpp` / `gdb_server.cpp` / `host_stop.cpp` / etc.
- F10/F11 over host code.
- All of VS's normal Watch/Locals/Memory/Registers — but these reflect **host** state, not guest.

Through the bridge (added by Slices 1–4 of the debugger-bridge work):

- `Vmm::kernel.g_ticks` in Watch shows the live guest 100 Hz tick counter.
- `duetos::vmm::g_stop_state` shows the guest CPU snapshot (rip, rip_sym, GPRs, rflags, cr2, cr3) when a guest breakpoint has fired.
- The `vmm_dbg::` namespace exposes free functions callable from the Immediate window for read/write/symbolize/breakpoint-by-name against the guest. Full reference below.

### How to use (F5 with `--break`)

1. F5 the `duetos-vmm` CMake target. The default launch args include `--break`, which halts the VMM with `__debugbreak()` immediately after CLI arg parse, BEFORE the `Vmm` constructor. VS halts at `main.cpp`.

2. Open **Debug → Windows → Immediate** (`Ctrl+Alt+I`). The Immediate window evaluates expressions in the debuggee process — this is your control channel for the bridge.

3. Take ownership of guest exception exits (so they route to the bridge, not the GDB stub if it's also enabled):

   ```
   duetos::vmm::vmm_dbg::Claim()
   ```

4. Plant a guest breakpoint by kernel symbol name:

   ```
   duetos::vmm::vmm_dbg::Bp("kernel_main")
   ```

5. F5 again. The startup `__debugbreak` returns; `Vmm vm(...)` constructs; `vm.Run()` enters the WHP loop; the kernel boots until it hits the planted `0xCC`. WHP returns an exception exit → `HandleHostStop()` snapshots regs into `g_stop_state` → `__debugbreak()` halts VS at that exact frame.

6. **Inspect**:
   - Watch `duetos::vmm::g_stop_state` → natvis shows `"guest @ kernel_main+0x0 (reason=3)"`. Expand for full register snapshot.
   - Watch `vmm.kernel.g_ticks` → live value.
   - From Immediate: `duetos::vmm::vmm_dbg::ReadQ("any_kernel_symbol")` to peek any kernel global.

7. **Resume** from Immediate:
   - `duetos::vmm::vmm_dbg::Step()` — single-step one guest instruction. Re-hits HandleHostStop with `reason=1` (#DB).
   - `duetos::vmm::vmm_dbg::Run()` — replant all bridge breakpoints and continue until the next hit.

### Without `--break` (manual entry)

If you've turned off `--break`, you can still enter the bridge: set a host-side C++ breakpoint anywhere in `vmm.cpp` or `host_stop.cpp` (click VS's gutter), or hit **Debug → Break All** (`Ctrl+Alt+Break`) while the VMM is running. Either gives you a stack frame and a live Immediate window. From there the steps above are identical.

---

## Path C — Both at once (full coverage)

This is what the F5 default sets you up for. One `duetos-vmm.exe` process; two VS instances debugging different aspects of it.

### Setup

The F5 default args already include `--gdb 1234 --break`. So:

1. **VS instance #1** — Open the **DuetOS repo root** (`C:\Users\natew\source\repos\DuetOS`), F5 the `duetos-vmm` target (CMake Open Folder mode). The VMM launches, halts at `__debugbreak()` in `main.cpp`. Native-attach session is live.

2. From the Immediate window of instance #1, optionally plant any *host-side* C++ breakpoints you want in VMM code, then F5 to continue past the trap.

3. The VMM constructs `Vmm`, calls `Run()`, and blocks at `m_gdb->WaitForConnection()` waiting for a gdb client. (Console shows `[vmm] gdb: waiting for a client on tcp:1234 (VS: F5 the attach config)`.)

4. **VS instance #2** — open a **new VS window** (`File → New Window`), then **`File → Open → Open a Local Folder…`** and pick **`C:\Users\natew\source\repos\DuetOS\tools\vmm`** (NOT the repo root). This loads the VMM's self-contained CMake project — no root-CMake failure, launch dropdown populates cleanly. Wait for "CMake generation finished" in the status bar.

5. In instance #2's toolbar, click the **▾** arrow next to the green Start button. Pick **"DuetOS: Attach (in-house VMM kernel, tcp:1234)"** (defined in [`tools/vmm/launch.vs.json`](../../tools/vmm/launch.vs.json)). F5.

6. Instance #2's gdb attaches, downloads kernel symbols, halts the guest before its first instruction. From here:
   - Click breakpoints in kernel C++ files (instance #2).
   - Inspect or write any guest global via instance #1's Immediate window using `vmm_dbg::*`.
   - F5 instance #2 to run the guest; if a kernel breakpoint fires, instance #2 halts and shows the kernel call stack with full Locals.
   - At the same time, you can Break-All instance #1 to peek at VMM-host state, then continue.

> **Why open `tools/vmm/` not the repo root in instance #2?**
> The DuetOS repo root's `CMakeLists.txt` is the freestanding kernel's, which intentionally fails to configure on Windows (`clang++ not on PATH`). VS shows "CMake Generation Failed" and can refuse to populate launch entries cleanly. Opening `tools/vmm/` directly bypasses the kernel CMake — its own `CMakeLists.txt` is Windows-MSVC-buildable and configures in under a second. The repo-root `launch.vs.json` also works if you dismiss the CMake error, but `tools/vmm/launch.vs.json` is the recommended clean path.

### Coordination notes

- **The two surfaces don't fight by default.** Slice 3's `g_hostAttachOwns` atomic defaults to `false`, so guest #BP/#DB exits route to the GDB stub (instance #2). The bridge stays passive unless you call `vmm_dbg::Claim()` from instance #1.

- **Claim/Release transfers ownership.** If you call `vmm_dbg::Claim()` from instance #1's Immediate window, subsequent guest exceptions route to `HandleHostStop` instead of the GDB stub. Instance #2's gdb is then *blind* to those traps. Use `vmm_dbg::Release()` to hand back. The intended workflow is **don't Claim** when running Path C — let the GDB stub handle execution control and use the bridge only for inspection / reads / writes.

- **Independent breakpoint shadows.** Each surface keeps its own byte-shadow table. A `Bp` planted via `vmm_dbg::Bp` won't be seen by the GDB stub. A `Z0` planted via gdb won't be seen by `vmm_dbg`. Pick one surface for breakpoint planting and stick to it (in Path C, that's the GDB stub).

### What you can do in Path C

- F9 a kernel function in instance #2 (the GDB-stub-attached one). Continue.
- When it hits, you have full kernel source-level debug in instance #2: stack, locals, registers, source stepping.
- Switch to instance #1 (the native-attach one) — Break-All if not stopped, then in Immediate type `duetos::vmm::vmm_dbg::ReadQ("some_kernel_global")` for an extra peek without disturbing instance #2's session.
- For VMM internals: in instance #1, set a host C++ breakpoint on `Vmm::HandleIoPort` or whatever. Click F5; next time the guest does an MMIO/PIO that lands in that handler, instance #1 halts with the host stack frame.

---

## `vmm_dbg::` reference (Layer B + Layer C)

Namespace: `duetos::vmm::vmm_dbg`. All functions are kept alive by the volatile keepalive table in `vmm.cpp`, so MSVC's `/OPT:REF` cannot strip them — they're always callable from Immediate.

### Memory / symbol access

| Function | Behaviour | Failure return |
|---|---|---|
| `uint64_t ReadQ(const char* name)` | 8-byte read of a kernel symbol's bytes. | `0` |
| `uint32_t ReadD(const char* name)` | 4-byte read. | `0` |
| `uint16_t ReadW(const char* name)` | 2-byte read. | `0` |
| `uint8_t  ReadB(const char* name)` | 1-byte read. | `0` |
| `void WriteQ(const char* name, uint64_t v)` | 8-byte write. No-op on resolution failure. | — |
| `void WriteD/W/B(...)` | Sized writes. | — |
| `const char* Sym(uint64_t guestAddr)` | Symbolize a guest VA → `"sched::Yield+0x42 (0x...)"`. | `"(unknown)"` |
| `const char* Dump(const char* name, size_t n)` | Hex-dump first `n` bytes (capped 256) of a symbol. | `"<symbol not found: …>"` / `"<unmapped: …>"` |

**Symbol resolution order.** Each lookup tries `ElfSymbols::Find(name)` (exact mangled match) first, then `ElfSymbols::FindBySuffix(name)` (Itanium length-prefix suffix match — so `"g_ticks"` resolves to `_ZN6duetos4arch12_GLOBAL__N_17g_ticksE`). Ties prefer non-anonymous-namespace symbols, then smallest address.

**Thread-local buffer warning.** `Sym` and `Dump` return pointers into thread-local scratch buffers that are overwritten on every call. **Do not** evaluate `Sym(a), Dump(b)` in one Immediate expression and dereference both pointers — the second call clobbers the first's buffer.

### Bridge ownership / breakpoints

| Function | Behaviour |
|---|---|
| `const char* Claim()` | Take ownership of WHP exception exits. GDB stub becomes inert until `Release()`. Returns prior owner: `"host"` or `"gdb-or-none"`. Warns to stderr if no debugger attached (avoids hang). |
| `const char* Release()` | Hand exception ownership back. Returns prior owner. **Do this before closing the host-attach session** if you've planted bridge breakpoints — leaving them planted while the GDB stub is the owner makes the GDB stub see "unknown" int3s. |
| `bool Bp(const char* name)` | Plant `0xCC` at the resolved kernel symbol's guest VA. Returns `true` if planted. Logs to `OutputDebugStringA` on symbol-not-found. |
| `bool Clr(const char* name)` | Restore the shadowed byte at a previously-planted symbol. Returns `true` if cleared. |
| `void Step()` | If the guest is stopped (`g_stop_state.stopped == true`), arm RFLAGS.TF, lift the 0xCC under RIP if any, clear `stopped`. vCPU executes one instruction, raises #DB, re-enters `HandleHostStop`. |
| `void Run()` | If stopped, replant all bridge breakpoints (`ReinsertAllLayerC`), clear `stopped`. vCPU resumes until the next hit. |

### Threading contract

- All `vmm_dbg::*` functions are safe to call from the VS Immediate window thread (which is the host process's main thread when VS pauses you).
- The vCPU thread is blocked in `HandleHostStop`'s spin-wait while the guest is stopped — so writes to `g_layerCBps`/`g_stop_state` from Immediate happen with no contention.
- The `g_layerCBps` mutex protects the bridge's breakpoint shadow table from the rare case where the GDB stub thread is also active during a quick Claim/Release sequence.

---

## `Vmm::kernel` (Layer A) reference

Type: `duetos::vmm::GuestKernelView` (declared in [`tools/vmm/src/debug/guest_view.h`](../../tools/vmm/src/debug/guest_view.h)). A `GuestKernelView` is a struct of host pointers that point into mapped guest physical RAM. Each pointer is null until the kernel symbol it tracks has been resolved (after the first guest exit, when paging is up).

Current curated fields (v1):

| Field | Type | Kernel symbol it tracks | Notes |
|---|---|---|---|
| `g_ticks` | `uint64_t*` | `g_ticks` (mangled: `_ZN6duetos4arch12_GLOBAL__N_17g_ticksE`) | The 100 Hz scheduler tick counter. Editing through `*vmm.kernel.g_ticks = 0;` resets it immediately. |

The view is **refilled on every guest exit** via `RefreshGuestView()` so per-CPU / per-process structures that materialise later in boot become visible as they arrive. Already-populated pointers are not re-resolved (idempotency).

**Extending the curated list.** Add a field to `GuestKernelView` in `guest_view.h`, add a `MapSym(view.<field>, vmm, "<symbol>")` line in `guest_view.cpp::RefreshGuestView`, and optionally add a natvis row in `vmm.natvis`. For non-primitive types (mirroring a kernel struct), you also need a layout-mirror header — see the deferred bilateral-drift-guard infrastructure in the slice-2 spec.

---

## `GuestStopState` reference

Type: `duetos::vmm::GuestStopState`, single global in `host_stop.cpp`: `g_stop_state`. Populated by `HandleHostStop()` on every bridge-owned guest stop.

```cpp
struct GuestStopState {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip;
    uint64_t rflags, cr2, cr3;
    char     rip_sym[160];      // "duetos::sched::Yield+0x42 (0x...)"
    uint8_t  stop_reason;       // 3 = #BP, 1 = #DB single-step
    std::atomic<bool> stopped;  // true while halted; cleared by Step()/Run()
};
```

The natvis renders this as `"guest @ <rip_sym> (reason=N)"` when stopped, `"running"` otherwise. Expand for register groups.

---

## CLI flag reference (debugger-relevant)

See [Windows-VMM.md](Windows-VMM.md) for the full flag list. The debugger-relevant ones:

| Flag | Default | Effect |
|---|---|---|
| `--gdb <port>` | `0` (off) | Open the host-side GDB stub on `localhost:<port>`. Stops the guest before its first instruction so a client can plant boot breakpoints (analogous to QEMU `-S`). Required for Path A. |
| `--break` | off | Fire `__debugbreak()` in `main()` after arg parse and `HypervisorPresent()` but BEFORE Vmm construction. Halts the VMM at a known stack frame under VS native attach so the Immediate window is live. `IsDebuggerPresent()` guards the trap — outside a debugger the flag is a no-op (prints `[vmm] --break: no debugger attached, continuing` and proceeds). |
| `--idle <secs>` | `0` (off) | Optional COM1-idle watchdog. Bound a wedged boot in CI; leave off for interactive debugging (a shell parked at a prompt is legitimately silent for long stretches). |
| `--no-window` | off | Headless mode: skip FB reservation and Win32 window. Useful for CI smoke; the debugger flow doesn't require this. |
| `--record <f>` / `--replay <f>` | both off | Deterministic record/replay at exit-seq granularity. Mostly orthogonal to debugging; useful for reproducing flaky bugs once. See [Windows-VMM.md § Record / replay](Windows-VMM.md#record--replay). |

---

## Workflow recipes

### "I want to step through `kernel_main` start to finish."

Path A. F5 the *Attach (in-house VMM)* config, set F9 at the first line of `kernel_main` in the kernel source, F5 to continue from the GDB-stub's auto-halt. When it hits, F10/F11.

### "I want to know what `g_ticks` is right now."

Path B (or path C, doesn't matter). From the native-attach Immediate window:

```
duetos::vmm::vmm_dbg::ReadQ("g_ticks")
```

Or just expand `vmm.kernel.g_ticks` in Watch when paused.

### "Reset the tick counter and watch it advance."

```
duetos::vmm::vmm_dbg::WriteQ("g_ticks", 0)
```

Continue. After a few hundred ms, `vmm.kernel.g_ticks` in Watch should be a small positive number again.

### "I want to halt the guest the moment it tries to spawn the first task."

Path C, instance #2's gdb. Open the kernel source file that owns `Spawn`/`Create` task entry. F9 in the gutter. F5.

If you don't know the function name, in instance #1's Immediate (Path B):

```
duetos::vmm::vmm_dbg::Sym(0xffffffff80100000)  // probe an address
duetos::vmm::vmm_dbg::Dump("g_taskTable", 64)  // peek a known symbol
```

…then go set the F9 in the file you found.

### "I want to investigate why an MMIO handler in the VMM looped."

Path B (no GDB stub needed). F9 in the gutter at `Vmm::HandleIoPort` or `EmulateMmio`. F5. When the next MMIO/PIO occurs, instance #1 halts with the host stack frame and Locals shows the IoAccess / exit context.

### "I want both: kernel-source debug PLUS the ability to inspect the VMM that's hosting it."

Path C. F5 instance #1, continue past `--break`, then F5 instance #2's *Attach (in-house VMM)* config. Both are now live. Use instance #2 (GDB stub) as the primary debugger; switch to instance #1 (native attach) when you need VMM internals or guest-global reads not visible through gdb's view.

---

## Troubleshooting

### Second VS instance shows "CMake Generation Failed" and the launch dropdown is empty

You opened the **DuetOS repo root** in the second VS. The root `CMakeLists.txt` is the freestanding kernel's — it FATAL_ERRORs on Windows by design (`clang++ not on PATH`). VS may refuse to populate `launch.vs.json` entries until the configure failure is dismissed.

Fix:

1. **Close the second VS instance.**
2. Open VS again, `File → Open → Open a Local Folder…`, navigate to **`C:\Users\natew\source\repos\DuetOS\tools\vmm`** (the VMM subfolder, NOT the repo root).
3. VS configures the VMM's own `CMakeLists.txt` cleanly (it's MSVC-buildable). The launch dropdown should now contain **"DuetOS: Attach (in-house VMM kernel, tcp:1234)"** from [`tools/vmm/launch.vs.json`](../../tools/vmm/launch.vs.json).
4. F5 it. gdb attaches to the running first-instance VMM via tcp:1234.

If you really want to use the repo root in instance #2, you can — just dismiss the yellow CMake-failure banner first, then click the **▾** dropdown arrow next to the green Start button. The launch entries should be there alongside the CMake targets.

### Watch / Locals / Memory / Call Stack are all empty after F5

The VMM is **running**, not stopped. VS native attach on a freely-running target legitimately shows empty inspection windows because there's no current stack frame. Fix one of:

- Use the `--break` default — VS halts at `__debugbreak()` in `main()` and everything populates.
- **Debug → Break All** (`Ctrl+Alt+Break`) while running halts wherever the vCPU thread happens to be.
- Set a host-side C++ breakpoint (F9 in the gutter of any `tools/vmm/src/*.cpp` file).
- Or use Path A — its GDB stub halts the guest before its first instruction.

### `vmm_dbg::Bp("foo")` returns `false`

The symbol lookup failed. Try:

- `vmm_dbg::Dump("foo", 1)` — same lookup; if it says `"<symbol not found: foo>"`, the name isn't matching anything (suffix-match also failed).
- Look up the right name in WSL: `nm build/x86_64-debug/kernel/duetos-kernel.elf | grep -i foo`.
- For C++ functions in named namespaces, the bare name often works via FindBySuffix (e.g. `"Yield"` matches `_ZN6duetos5sched5YieldEv`). Anonymous-namespace globals also work.
- For anything that doesn't suffix-match, paste the full mangled name.

### `vmm_dbg::Claim()` warns about no debugger attached

Exactly what it says. Without a debugger, the spin-wait in `HandleHostStop` after a guest BP hits would block forever. The warning is harmless if you're still about to attach VS, but `Claim()` is only useful from inside a debugger session — the warning means you called it from a headless `duetos-vmm.exe` invocation.

### Bridge breakpoints fire while the GDB stub is also attached

This happens if `Claim()` was called and not `Release()`'d before instance #2 (GDB-stub) needed to handle a guest BP. The GDB stub becomes inert under Claim. Fix: from instance #1, type `duetos::vmm::vmm_dbg::Release()` in Immediate. Behaviour returns to "GDB stub owns guest exceptions."

### GDB stub session can't read kernel memory until paging is up

Both the GDB stub's `m`/`M` packets and the bridge's `Bp`/`ReadQ` use `Partition::TranslateGva` which requires guest paging to be set up. Before the kernel enables paging (which happens in the very first instructions of `boot.S` before `kernel_main`), guest VAs don't resolve. The GDB stub will return `E14`; bridge reads return 0. This is normal. Use addresses, not symbols, during pre-paging boot — or just set your breakpoint after `kernel_main`.

### `gdb.exe` not found / can't attach via Path A

`launch.vs.json` ships with `"miDebuggerPath": "gdb.exe"` so VS resolves it from your user PATH. If you don't have a Windows gdb installed, run:

```powershell
winget install BrechtSanders.WinLibs.POSIX.UCRT --source winget
```

That adds `.../mingw64/bin` to your user PATH automatically. **Relaunch VS** so it inherits the new PATH (a running VS won't see env changes). Alternatives: `scoop install gdb`, `choco install gdb` (admin), or `pacman -S mingw-w64-ucrt-x86_64-gdb` from inside MSYS2.

**WSL's `/usr/bin/gdb` does not work** — `localhost` from WSL2 doesn't reach the Windows host. Must be a native Windows gdb.

If your gdb lives at a non-PATH location, edit `tools/vmm/launch.vs.json` locally (don't commit a user-specific absolute path — keep that change out of git).

### `[vmm] gdb: bind/listen failed`

Port `1234` is in use (probably a previous VMM didn't fully exit, or QEMU is also running). Either `Get-Process duetos-vmm | Stop-Process` to reap orphans, or pick another port: `--gdb 1235` and update the `miDebuggerServerAddress` in `launch.vs.json`.

### Windows says "WinHvPlatform.dll not found"

The **Windows Hypervisor Platform** optional feature isn't enabled. Enable it via Settings → Optional features (need admin), reboot, retry. Also requires virtualization on in firmware (BIOS/UEFI) and — if your dev box is itself a VM — nested virt support.

---

## Known limits

Inherited from the v0 bridge:

- **No DWARF type-aware pretty-printing for guest data.** The bridge surfaces raw bytes (`ReadQ`) or POD-mirror types (currently only `g_ticks`). The natvis decorates host-side structs; for kernel structs you typically want Path A (GDB stub) anyway, which DOES have full DWARF.
- **Mixed-mode "see the guest inside the GDB-stub session"** isn't a thing — that's the inverse problem and would need a debugger-side extension. The bridge solves the forward direction (see guest from VS native attach).
- **`Step()` then `Step()` without `Run()`** in between leaves the original BP lifted until the next `Run()` does `ReinsertAllLayerC`. If you really need to step over many instructions, do a `Step()` once then `Run()` with a fresh `Bp` at the next location of interest.
- **`Bp` planted before the kernel reaches the function will hit when the function is reached.** `Bp` planted *after* the kernel has run past the function does nothing visible until a future call. There's no rewind.
- **GDB stub: no hardware watchpoints**, no fully-async `^C` interrupt. Software int3 breakpoints only.

## Source map

- [`tools/vmm/src/debug/vmm_dbg.{h,cpp}`](../../tools/vmm/src/debug/) — `vmm_dbg::` namespace, all Layer B + Layer C functions.
- [`tools/vmm/src/debug/guest_view.{h,cpp}`](../../tools/vmm/src/debug/) — `GuestKernelView`, `MapSym`, refresh loop.
- [`tools/vmm/src/debug/host_stop.{h,cpp}`](../../tools/vmm/src/debug/) — `g_stop_state`, `HandleHostStop`, the bridge arbiter.
- [`tools/vmm/src/debug/gdb_server.{h,cpp}`](../../tools/vmm/src/debug/) — the GDB remote-serial-protocol stub (Path A).
- [`tools/vmm/src/debug/elf_symbols.{h,cpp}`](../../tools/vmm/src/debug/) — ELF symbol table loader; `Find` (exact) + `FindBySuffix` (Itanium-mangled lenient).
- [`tools/vmm/vmm.natvis`](../../tools/vmm/vmm.natvis) — Visual Studio pretty-printers for `GuestKernelView`, `GuestStopState`, `ElfSymbols::Sym`.
- [`tools/vmm/src/main.cpp`](../../tools/vmm/src/main.cpp) — CLI parser, `--break` and `--gdb` wiring.
- [`tools/vmm/CMakeLists.txt`](../../tools/vmm/CMakeLists.txt) — `VS_DEBUGGER_COMMAND_ARGUMENTS` (the F5 default).
- [`launch.vs.json`](../../launch.vs.json) — the GDB-stub attach config (Path A).

## Spec / plan trail

- Design: [`docs/superpowers/specs/2026-05-19-vmm-debugger-bridge-design.md`](../../docs/superpowers/specs/2026-05-19-vmm-debugger-bridge-design.md)
- Plan: [`docs/superpowers/plans/2026-05-19-vmm-debugger-bridge.md`](../../docs/superpowers/plans/2026-05-19-vmm-debugger-bridge.md)
