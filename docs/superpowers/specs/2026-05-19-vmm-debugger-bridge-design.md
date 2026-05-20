# duetos-vmm Host-Attach Guest-Bridge Debugger — Design Spec

**Date:** 2026-05-19
**Status:** Approved (brainstorming) — pending implementation plan
**Scope owner:** `tools/vmm/` (host tooling; outside kernel subsystem-isolation rules)
**Related:** [`2026-05-19-interactive-vmm-design.md`](2026-05-19-interactive-vmm-design.md) (orthogonal feature, same TU tree)

## 1. Problem

`duetos-vmm.exe` exposes a GDB stub on tcp:1234 for VS to attach via
`cppdbg`. That session shows the **guest** kernel only — no host-side
VMM state. Conversely, attaching Visual Studio's native debugger to
`duetos-vmm.exe` shows VMM host C++ data (`Vmm`, `GuestMemory`,
`Partition`) but **nothing about the guest** beyond opaque buffers.

Goal: a single VS Win32-attach session against `duetos-vmm.exe` that
sees **both** — host VMM state AND live, typed guest kernel state —
with read/write/walk/symbolize/breakpoint capabilities, so the
developer can drive the guest from the same Watch + Immediate windows
they already use for host code.

## 2. Root mechanism (verified, see §10 evidence)

WHP requires host-backed memory: `Partition::MapGpaRange` passes a
host VA to `WHvMapGpaRange`. `GuestMemory::HostPtr(gpa)` returns a
host pointer to **the actual bytes the guest CPU reads/writes** at
that GPA. Modifying those bytes from the host has immediate guest
effect with no copy and no synchronisation primitive beyond cache
coherence (x86_64 host vs. x86_64 guest, both little-endian, both on
the same physical CPU).

`tools/vmm/src/debug/elf_symbols.{h,cpp}` already parses
`.symtab/.strtab` from the kernel ELF; `Vmm::Monitor` already
demonstrates `name → guest VA → GPA → host VA` resolution end-to-end
(see `src/debug/introspect.cpp` lines 117-140). The bridge generalises
that path and exposes it to the VS debugger.

**Consequence:** the feature is **VMM-side only — zero kernel
runtime changes** across all four layers. The kernel binary's
behaviour is unchanged. The single kernel-build touch is a
pure-compile-time generated header (`sizeof_report.h`, §5) that
exports `sizeof(T)` constants the VMM `static_assert`s against —
emitted at compile time, not linked into the kernel image, runtime
identical with or without it. Layer C plants `0xCC` software
breakpoints in guest text just as the GDB stub already does (no new
kernel co-operation required).

## 3. Approach (chosen)

**Bridge by mirror** — four layers, each independently useful, all
reachable from one VS native-attach session against `duetos-vmm.exe`:

- **Layer A** Typed view of guest kernel globals as host `T*` members
  of `Vmm::kernel` (pointers into mapped GPA → live in VS Watch
  window, editable inline).
- **Layer B** Read/write/symbolize **by name** via `vmm_dbg::` free
  functions callable from the VS Immediate window.
- **Layer C** Plant guest breakpoints from this same session;
  `DebugBreak()` on hit so VS halts the VMM at the exact host frame
  with `Vmm::g_stop_state` populated.
- **Layer D** `tools/vmm/vmm.natvis` pretty-prints the Layer A view +
  symbolizes guest VAs inline.

Rejected:

- **Build-time DWARF → C++ codegen** of mirror types. Eliminates
  hand-mirroring, but cross-toolchain (clang Itanium DWARF → MSVC
  headers) is real work and ABI differences still bite for non-POD
  types. The `sizeof_report.h` guardrail (§5) gets 90% of the safety
  at 10% of the build complexity.
- **Pure GDB-stub extension** (richer `monitor` commands only).
  Cheap, but every inspection becomes a manual `monitor read foo`
  call — loses the live-watch ergonomics that motivate the bridge.
- **Two debugger windows, no bridge** (status quo). User explicitly
  rejected; eliminates the cognitive cost of context-switching is
  the whole point of the slice.

## 4. v1 scope (locked)

In:
- Layers A, B, C, D as defined in §3, phased per §8.
- Curated initial Layer A exposure: `g_ticks`, `current_task[]`
  per-CPU, `process_table`, scheduler runqueues, vmexit ring header
  (full list locked when slice 2 lands; extensible afterwards).
- Coexistence with existing GDB stub via a `vmm_dbg::Claim()` runtime
  flip — only one debug surface owns the WHP exception-exit path at
  a time. Default: GDB stub owns (today's behaviour).
- `vmm_dbg::` symbols **never stripped**: kept alive by a `volatile`
  keepalive table compiled into `vmm.cpp` so the Immediate window can
  always evaluate them.

Deferred (NOT v1):
- DWARF type generation (manual mirror is good enough; `sizeof`
  guardrails catch drift).
- Hardware breakpoints / watchpoints (software int3 only — same as
  the GDB stub).
- Mixed-mode "see the guest from inside cppdbg/gdb session." That's
  the inverse problem and would need a debugger-side extension; out
  of scope for this slice.
- VS Snippets / debugger visualisers beyond plain natvis.

## 5. Components

### New, under `tools/vmm/src/debug/`

| File | Layer | Responsibility | Depends on |
|------|-------|---------------|-----------|
| `guest_view.{h,cpp}` | A | `GuestKernelView` struct + `Vmm::SetupGuestView()`: walks curated symbol list, populates typed host pointers into mapped GPA. | `ElfSymbols`, `GuestMemory`, `guest_types_mirror.h` |
| `guest_types_mirror.h` | A | Hand-mirrored POD layouts of exposed kernel structs (`KernelTaskMirror`, `ProcessMirror`, …); `static_assert`s vs. kernel-published sizes. | `<kernel>/build/x86_64-debug/kernel/sizeof_report.h` (generated) |
| `vmm_dbg.{h,cpp}` | B, C | Free functions in `vmm_dbg::` namespace: `ReadQ`/`WriteQ` (+ byte/word/dword variants), `Sym`, `Dump`, `Bp`, `Clr`, `Step`, `Run`, `Claim`, `Release`. Resolves names via `ElfSymbols`, accesses memory via `GuestMemory::HostPtr`, breakpoints via the existing shadow-byte machinery. | `Vmm` (singleton accessor) |
| `host_stop.{h,cpp}` | C | `g_stop_state` (registers snapshot, RIP-as-symbol, stop reason). vCPU exit handler routes to either GDB stub OR `DebugBreak()` based on `Claim()` flip. | `Partition`, `<intrin.h>` (`__debugbreak`) |

### New, under `tools/vmm/`

| File | Layer | Responsibility |
|------|-------|---------------|
| `vmm.natvis` | D | Pretty-printers for `GuestKernelView`, RIP fields, `vmm_dbg` cached scratch strings. |

### Modified

| File | Change |
|------|--------|
| `src/vmm.{h,cpp}` | Add `kernel` member (`GuestKernelView`); `SetupGuestView()` call after ELF load; route WHP exception exits through `host_stop.cpp`'s arbiter instead of straight to `GdbServer::OnException`. |
| `src/debug/gdb_server.{h,cpp}` | Gain `IsActive()` predicate; observe `vmm_dbg::Claim()` flag and become inert (returns NotConsumed for exception exits) when host-attach owns the debug surface. |
| `src/debug/elf_symbols.{h,cpp}` | Add `FindAddrToSym(uint64_t)` returning the cached lookup result via a small thread-local scratch buffer so `vmm_dbg::Sym` can return a `const char*` valid through the Immediate-window call. |
| `CMakeLists.txt` | New TUs; embed `vmm.natvis` so VS picks it up. |
| `kernel/CMakeLists.txt` (the **only** kernel-side touch) | Generate `sizeof_report.h` listing `static constexpr size_t kSizeof<Type>` for every mirrored type. Pure compile-time, no behavioural change. |

## 6. Mechanism detail per layer

### Layer A — Typed live view

`GuestKernelView` is a plain struct of host pointers:

```cpp
struct GuestKernelView
{
    uint64_t*           g_ticks         = nullptr;
    KernelTaskMirror*   current_task[8] = {};
    ProcessMirror*      process_table   = nullptr;
    // ... extensible
};
```

Population (`Vmm::SetupGuestView`) reuses the exact `name → GVA →
GPA → host pointer` chain that `Vmm::Monitor`'s `read` handler
already runs (see `src/debug/introspect.cpp:117-140`):

```cpp
template <typename T>
static T* MapSym(Partition& part, const ElfSymbols& s,
                 GuestMemory& m, const char* name)
{
    const auto* sym = s.Find(name);
    if (!sym) return nullptr;
    uint64_t gpa = 0;
    if (!part.TranslateGva(0, sym->addr, gpa)) return nullptr;
    return static_cast<T*>(m.HostPtr(gpa, sizeof(T)));
}
```

This is the same translation path the GDB stub takes for `m`/`M`
packets, so it works exactly when the GDB stub's memory accesses do
(paging set up after the first guest exit). `SetupGuestView` is
therefore called from `Vmm::Run`'s first post-exit point, not at VMM
construction. Symbols that fail to translate at first call leave
their pointers `nullptr`; a periodic `RefreshGuestView()` retries
them on subsequent exits so address-space-lifetime objects (per-CPU
runqueues materialised after AP bringup) become visible as they
arrive.

Mirror header `guest_types_mirror.h` defines POD equivalents:

```cpp
struct alignas(8) KernelTaskMirror
{
    uint64_t pid;
    uint64_t kstack_top;
    uint64_t rip;
    char     name[32];
    // ... only what we expose to debugger
};
static_assert(sizeof(KernelTaskMirror) ==
              ::duetos::sizeof_report::KernelTask,
              "KernelTaskMirror drifted from kernel KernelTask");
```

The generated `sizeof_report.h` lives in the kernel build tree as
`duetos::sizeof_report::<TypeName>` constexpr constants — one entry
per type the VMM mirrors. CMake adds an include path so the VMM
build sees it as `<kernel-build>/include/duetos/sizeof_report.h`.

Layout drift becomes a build break, not a Tuesday-afternoon
"why-is-this-value-garbage" investigation.

### Layer B — `vmm_dbg::` free functions

Signatures (kept stable; this is effectively a debugger ABI):

```cpp
namespace vmm_dbg {
    uint64_t    ReadQ (const char* name);                  // 0 if missing
    uint32_t    ReadD (const char* name);
    uint16_t    ReadW (const char* name);
    uint8_t     ReadB (const char* name);
    void        WriteQ(const char* name, uint64_t v);      // no-op if missing
    void        WriteD(const char* name, uint32_t v);
    void        WriteW(const char* name, uint16_t v);
    void        WriteB(const char* name, uint8_t v);
    const char* Sym   (uint64_t guestAddr);                // tl scratch buf
    const char* Dump  (const char* name, size_t n);        // tl scratch buf
}
```

Keepalive: a `volatile` array of function pointers in `vmm.cpp`
references each `vmm_dbg::*` symbol so the MSVC linker can't
`/OPT:REF` them away.

Each function acquires the singleton `Vmm&` via an accessor set in
`Vmm`'s constructor, then walks `ElfSymbols → GPA → HostPtr` exactly
as `Vmm::Monitor`'s `read`/`lookup` handlers do today.

### Layer C — Host-session breakpoints

State (in `host_stop.cpp`):

```cpp
struct GuestStopState
{
    bool        stopped         = false;
    uint64_t    rip             = 0;
    char        rip_sym[128]    = {};
    uint64_t    rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp;
    uint64_t    r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t    rflags, cr2, cr3;
    uint32_t    stop_reason; // 0=bp 1=step 2=other
} g_stop_state;
```

WHP exit arbiter (replaces direct `m_gdb.OnException` call):

```cpp
case WHvRunVpExitReasonException: {
    if (vmm_dbg::HostAttachOwnsDebug()) {
        if (HandleHostStop(exit)) { /* DebugBreak fired */ }
    } else {
        m_gdb.OnException(0, exit.VpException.ExceptionType);
    }
    break;
}
```

`HandleHostStop` snapshots registers, symbolizes RIP, sets
`g_stop_state.stopped = true`, then:

```cpp
if (IsDebuggerPresent()) __debugbreak();
// Spin until vmm_dbg::Run() or Step() clears the stop.
while (g_stop_state.stopped) std::this_thread::yield();
```

`vmm_dbg::Bp(name)` resolves name → guest VA → GPA → host byte, saves
the original byte in a per-Layer-C shadow table (separate from the
GDB stub's, since they coexist behind the Claim flip), writes `0xCC`.
`vmm_dbg::Clr(name)` restores. `vmm_dbg::Step()` sets RFLAGS.TF on
the stopped vCPU's context and clears `stopped`; the next exception
exit (#DB) flows back through the arbiter. `vmm_dbg::Run()` simply
clears `stopped`; replanting an int3 you just stepped off uses the
same shadow-byte dance `gdb_server.cpp` already documents.

### Layer D — Natvis

`tools/vmm/vmm.natvis`:

```xml
<Type Name="duetos::vmm::GuestKernelView">
  <DisplayString>kernel view ({n_populated} of {n_curated} populated)</DisplayString>
  <Expand>
    <Item Name="g_ticks">*g_ticks</Item>
    <Item Name="current_task[0]">*current_task[0]</Item>
    <!-- ... -->
  </Expand>
</Type>
```

Plus a visualiser that surfaces `g_stop_state.rip_sym` next to the
raw `rip` value when the guest is stopped.

## 7. Threading + coexistence

- vCPU thread is the **only** writer to `g_stop_state` (so no lock
  on the read side from the host debugger; `volatile` reads
  suffice).
- `vmm_dbg::Claim`/`Release` flip an atomic. `gdb_server.cpp`
  checks it at the top of `OnException`; if owned by host-attach,
  returns "not consumed" and lets the arbiter route to
  `HandleHostStop`.
- `vmm_dbg::Bp` / `Clr` take a small mutex shared with
  `gdb_server`'s breakpoint table for the byte-shadow read/modify/
  write — prevents the two stub regimes from corrupting each
  other's shadow bytes during the brief Claim/Release transition.
- `__debugbreak()` is fenced by `IsDebuggerPresent()` so headless
  runs (CI, `--no-window` smoke) never crash on an unhandled
  exception.

## 8. Phasing (commits)

Each slice is independently shippable; the order is steepest-utility
per LOC. Commit messages follow the project's slice convention.

| Slice | Layer | Adds | Removes / Modifies | Est. LOC |
|-------|-------|------|-------------------|----------|
| 1 | B | `vmm_dbg.{h,cpp}` (read/write/sym/dump by name); keepalive table; unit tests against the resolver paths. | None — pure addition. | ~250 |
| 2 | A | `guest_view.{h,cpp}`, `guest_types_mirror.h`; `Vmm::kernel` member + `SetupGuestView()` call; kernel-side `sizeof_report.h` generation. | `kernel/CMakeLists.txt` (new generated header target). | ~400 |
| 3 | C | `host_stop.{h,cpp}`; arbiter rewire in `Vmm::Run`; `Claim`/`Release`/`Bp`/`Clr`/`Step`/`Run` in `vmm_dbg`; coexistence flag in `gdb_server`. | `vmm.cpp` exception-exit case; `gdb_server.cpp` early-return check. | ~350 |
| 4 | D | `vmm.natvis`; `Visualizer` element in `tools/vmm/CMakeLists.txt`. | None. | ~100 |

Total ~1100 LOC across four commits — well within the per-file
threshold; no single TU exceeds the 500-line bloat ceiling.

## 9. Error handling

- Missing symbol in any `vmm_dbg::*` lookup: `ReadQ` returns 0,
  `WriteQ` is a no-op, `Sym`/`Dump` return `"(unknown)"`. No fatal —
  the user is in the debugger and inspects the return.
- Unmapped GPA: same — log via `KLOG_DEBUG_S`-equivalent host-side
  channel (`OutputDebugStringA`), return safe sentinel.
- `Bp` on non-existent symbol: returns `false`, sets
  `OutputDebugStringA("vmm_dbg::Bp: <name> not found")` so it
  surfaces in the VS Output pane.
- `static_assert` failure on a mirror size: build break with a
  message naming both sides (`KernelTaskMirror` vs.
  `duetos::kSizeofKernelTask`); operator updates the mirror or
  re-runs the kernel build, whichever is stale.

## 10. Testing

- **Host unit (no WHP attach):**
  - `vmm_dbg` resolver paths against a fixture ELF (reuse the
    fixture from `tests/test_smoke.cpp` if compatible, else a
    minimal hand-rolled one).
  - `GuestKernelView` population correctness given a stubbed
    `GuestMemory` + `ElfSymbols`.
  - `static_assert` matrix between `guest_types_mirror.h` and
    `sizeof_report.h` (covered by build).
- **Integration (manual — dev tool):**
  - Attach VS native debugger to a running `duetos-vmm.exe`; check
    `vmm.kernel.g_ticks` displays a live, incrementing value.
  - Immediate window: `vmm_dbg::Sym(0xffffffff80100000)` returns the
    expected `kernel_main+0xN`.
  - `vmm_dbg::Bp("kernel_main")` halts the guest at first instruction
    of `kernel_main`; `vmm.g_stop_state.rip` matches.
  - With GDB stub also running, `vmm_dbg::Claim()` quiesces it;
    `vmm_dbg::Release()` hands debug back to GDB.
- **Headless / CI:** `--no-window` runs unchanged; `IsDebuggerPresent`
  guard ensures `__debugbreak` never fires.

## 11. Non-goals / risks

- **Not** a replacement for the GDB-stub flow; complementary.
  Engineers who prefer cppdbg/gdb against the kernel ELF keep that
  workflow.
- **Not** a guest-aware visualiser for the GDB session (the inverse
  problem). Would require a debugger-side extension; out of scope.
- Risk: **mirror drift**. Mitigated by generated `sizeof_report.h` +
  `static_assert` so drift fails the build, never silent.
- Risk: **WHP exit-routing coexistence**. Mitigated by the explicit
  `Claim`/`Release` flip; only one consumer at a time; the inactive
  side returns NotConsumed and never touches state.
- Risk: **`__debugbreak()` in a non-debugger build** would crash the
  process. Mitigated by `IsDebuggerPresent()` guard.
- Risk: **mirror coverage drift** (we add a new kernel field, forget
  to mirror it). Acceptable — the worst outcome is "field invisible
  in debugger," not corruption, and `sizeof` will catch any struct
  growth that changes layout.

## 12. Out-of-scope explicitly

- ARM64 host. (VMM is x86_64-host only today; mirror types assume
  Itanium-ABI x86_64 layout. ARM64 host would need a parallel mirror.)
- Kernel code modification from the debugger (writing `0xCC` is
  inspection, not patching; we don't expose `WriteCode(name, bytes)`
  in v1).
- Snapshot/save-state interaction. Bridge is live-only.
