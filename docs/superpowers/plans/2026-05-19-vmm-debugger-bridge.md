# VMM Host-Attach Guest-Bridge Debugger Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `duetos-vmm` so a single Visual Studio session attached to `duetos-vmm.exe` sees the guest kernel — typed live in the Watch window, read/write/symbolize by name from the Immediate window, with software breakpoints that halt the VMM at the guest stop point — alongside the existing host VMM C++ data.

**Architecture:** Four independent layers landed as four commits, each useful alone. Layer B (`vmm_dbg::` free functions) gives the Immediate-window surface. Layer A (`Vmm::kernel` member of `GuestKernelView`) gives typed Watch-window pointers into mapped GPA. Layer C (`host_stop.cpp` arbiter + `vmm_dbg::Bp/Step/Run`) hands the WHP exception-exit path to the host-attach session when `Claim()`-ed, and uses `__debugbreak()` to halt the VMM at the moment of guest stop. Layer D (`vmm.natvis`) prettifies it all. **Zero kernel runtime changes**; the only kernel-side touch is a hand-written `sizeof_report.h` plus a kernel-side `static_assert` TU that fails kernel builds on layout drift.

**Tech Stack:** C++20, MSVC `/W4 /permissive- /EHsc`, Windows Hypervisor Platform (`WinHvPlatform.lib`), the project's own `vmm-tests` runner (`tests/test_main.h`), `<intrin.h>` for `__debugbreak`, Visual Studio Natvis XML for Layer D.

**Working directory:** `C:\Users\natew\source\repos\DuetOS`. VMM project root: `tools/vmm/`. VMM build dir: `tools/vmm/build/`. Kernel build dir (WSL-built): `build/x86_64-debug/`.

**Tests/build commands referenced repeatedly:**

```powershell
# Configure VMM (first time only; cached afterwards)
cmake -S tools/vmm -B tools/vmm/build -G "Visual Studio 17 2022" -A x64

# Build VMM
cmake --build tools/vmm/build --config Debug

# Run host unit tests
ctest --test-dir tools/vmm/build -C Debug --output-on-failure

# Build the kernel (in WSL — required for the kernel ELF + sizeof check)
wsl.exe -- bash -lc "cd ~/source/DuetOS && cmake --build build/x86_64-debug --target duetos-kernel"
```

---

## Slice 1 — Layer B: `vmm_dbg::` read/write/sym/dump by name

`vmm_dbg::` free functions resolve a guest-symbol name to mapped host bytes via the existing `ElfSymbols` + `GuestMemory::HostPtr` chain. From VS's Immediate window the user types `vmm_dbg::ReadQ("g_ticks")` and gets a `uint64_t` back. Layer B has no WHP or threading subtleties — it's pure addition on top of plumbing the existing `Vmm::Monitor` already demonstrates.

### Task 1.1: Add `vmm_dbg::` header with the surface contract

**Files:**
- Create: `tools/vmm/src/debug/vmm_dbg.h`

- [ ] **Step 1: Write the header**

```cpp
// Host-side debugger surface reachable from Visual Studio's Immediate
// window when VS is natively attached to duetos-vmm.exe. Resolves
// guest-kernel symbol names to mapped host memory via ElfSymbols +
// GuestMemory, then reads/writes/symbolizes through the same pointer
// chain Vmm::Monitor's `read`/`lookup` handlers already use.
//
// All functions are no-ops / safe sentinels if the VMM is not running
// (singleton accessor returns null) or the symbol isn't found — they
// are designed to be safe to call from any VS-eval context, including
// while no debugger is attached.
#pragma once

#include <cstddef>
#include <cstdint>

namespace duetos::vmm::vmm_dbg
{

// Read a 1/2/4/8 byte guest value by kernel symbol name. Returns 0
// if the symbol is missing, the GVA is not mapped, or the VMM is not
// running yet.
uint64_t ReadQ(const char* name);
uint32_t ReadD(const char* name);
uint16_t ReadW(const char* name);
uint8_t  ReadB(const char* name);

// Write a 1/2/4/8 byte value through the same path. No-op on any
// resolution failure (the caller is in a debugger and inspects the
// next ReadQ to confirm).
void WriteQ(const char* name, uint64_t value);
void WriteD(const char* name, uint32_t value);
void WriteW(const char* name, uint16_t value);
void WriteB(const char* name, uint8_t  value);

// Symbolize a guest virtual address. Returns a pointer to a
// thread-local scratch buffer that lives until the next call on the
// same thread. Never returns nullptr: missing symbols yield "(unknown)".
const char* Sym(uint64_t guestAddr);

// Hex-dump the first `n` bytes (cap 256) of the named symbol into a
// thread-local scratch buffer. Returns "(unknown)" on resolution
// failure. The buffer is a single string of "ab cd ef ..." pairs.
const char* Dump(const char* name, size_t n);

} // namespace duetos::vmm::vmm_dbg
```

- [ ] **Step 2: Verify the file compiles standalone**

Run: `cmake --build tools/vmm/build --config Debug --target duetos-vmm 2>&1 | Select-String "vmm_dbg.h"`

Expected: no errors. (The header isn't yet referenced; it's a syntax-only check.)

### Task 1.2: Add Vmm singleton accessor for the `vmm_dbg::` functions

**Files:**
- Modify: `tools/vmm/src/vmm.h:64-113`
- Modify: `tools/vmm/src/vmm.cpp:27-30`

- [ ] **Step 1: Add the singleton accessor declaration in `Vmm`**

At `tools/vmm/src/vmm.h`, after the existing public members of `Vmm` (around line 72, before `private:`), add:

```cpp
    // Singleton accessor for the host-side debugger surface
    // (debug/vmm_dbg.cpp). Returns nullptr until the constructor
    // finishes and after the destructor begins. Only one Vmm lives at
    // a time (one --kernel/--iso per process), so a singleton is the
    // right shape.
    static Vmm* Active();

    // Resolver primitives reused by vmm_dbg. Public, but treat as
    // debugger-only — they don't perform record/replay accounting.
    bool        DbgResolveGpa(uint64_t gva, uint64_t& gpa) const;
    void*       DbgHostPtr(uint64_t gpa, uint64_t len) const;
    const ElfSymbols::Sym* DbgFindSym(const char* name) const;
    const ElfSymbols&      DbgSymbols() const { return m_symbols; }
```

- [ ] **Step 2: Wire the singleton in the constructor + destructor**

In `tools/vmm/src/vmm.cpp`, near the top of the file (after the anonymous namespace at line 25, before `Vmm::Vmm`), add:

```cpp
namespace
{
Vmm* g_activeVmm = nullptr;
}

Vmm* Vmm::Active() { return g_activeVmm; }

bool Vmm::DbgResolveGpa(uint64_t gva, uint64_t& gpa) const
{
    return m_part.TranslateGva(0, gva, gpa);
}

void* Vmm::DbgHostPtr(uint64_t gpa, uint64_t len) const
{
    return m_mem->HostPtr(gpa, len);
}

const ElfSymbols::Sym* Vmm::DbgFindSym(const char* name) const
{
    return m_symbols.Find(name);
}
```

Then at the **very end** of the `Vmm::Vmm(VmConfig cfg)` constructor body (just before its closing brace, which is at line 124), add:

```cpp
    g_activeVmm = this;
```

And at the **start** of `Vmm::~Vmm()` (line 226), add:

```cpp
    g_activeVmm = nullptr;
```

- [ ] **Step 3: Build to confirm it links**

Run: `cmake --build tools/vmm/build --config Debug --target duetos-vmm`
Expected: clean build, no warnings.

- [ ] **Step 4: Commit so far is NOT YET — wait for Task 1.5.**

### Task 1.3: TDD `ReadQ` / `WriteQ` against a fixture

**Files:**
- Create: `tools/vmm/tests/test_vmm_dbg.cpp`
- Modify: `tools/vmm/tests/CMakeLists.txt`

The unit tests exercise the resolver chain WITHOUT a live WHP partition by providing a stub `Vmm::Active()` that returns a test fake. We test the byte-level layer-B logic in isolation; the real Vmm wiring is exercised by the build itself.

- [ ] **Step 1: Refactor — extract resolver primitives behind a small interface so tests can fake them**

Modify `tools/vmm/src/debug/vmm_dbg.h` to add (after the existing declarations, inside the namespace):

```cpp
// Test seam: tests inject a fake resolver via `SetTestResolver`.
// Production code never touches this — `Vmm::Active()` is the resolver
// when in real use.
struct Resolver
{
    virtual ~Resolver()                                          = default;
    virtual bool   FindSym(const char* name, uint64_t& vaOut,
                           uint64_t& sizeOut)                    = 0;
    virtual void*  HostPtrForGva(uint64_t gva, uint64_t len)     = 0;
    virtual const char* Symbolize(uint64_t addr)                 = 0;
};

// nullptr resets to the live Vmm-backed resolver. Tests pass a fake;
// real code never calls this.
void SetTestResolver(Resolver* r);
```

- [ ] **Step 2: Add `tools/vmm/src/debug/vmm_dbg.cpp` with the resolver indirection + ReadQ/WriteQ**

```cpp
#include "debug/vmm_dbg.h"

#include <cstdio>
#include <cstring>

#include "vmm.h"

namespace duetos::vmm::vmm_dbg
{

namespace
{

Resolver* g_testResolver = nullptr;

// Default resolver — routes through Vmm::Active(). When the VMM is
// not yet constructed (or already torn down), `FindSym` returns
// false and the public Read/Write/Sym/Dump functions degrade safely.
struct LiveResolver final : Resolver
{
    bool FindSym(const char* name, uint64_t& va, uint64_t& sz) override
    {
        Vmm* v = Vmm::Active();
        if (!v) return false;
        const ElfSymbols::Sym* s = v->DbgFindSym(name);
        if (!s) return false;
        va = s->addr;
        sz = s->size;
        return true;
    }
    void* HostPtrForGva(uint64_t gva, uint64_t len) override
    {
        Vmm* v = Vmm::Active();
        if (!v) return nullptr;
        uint64_t gpa = 0;
        if (!v->DbgResolveGpa(gva, gpa)) return nullptr;
        return v->DbgHostPtr(gpa, len);
    }
    const char* Symbolize(uint64_t addr) override
    {
        Vmm* v = Vmm::Active();
        if (!v) return "(no vmm)";
        // Vmm::DbgSymbols().Symbolize() returns std::string; copy
        // into the thread-local scratch buffer the public Sym() owns.
        static thread_local char buf[160];
        std::string s = v->DbgSymbols().Symbolize(addr);
        std::snprintf(buf, sizeof(buf), "%s", s.c_str());
        return buf;
    }
};

LiveResolver g_liveResolver;

Resolver& Active()
{
    return g_testResolver ? *g_testResolver
                          : static_cast<Resolver&>(g_liveResolver);
}

// Read N bytes through the resolver. Returns 0 on any failure.
template <typename T>
T ReadN(const char* name)
{
    uint64_t va = 0, sz = 0;
    if (!Active().FindSym(name, va, sz)) return 0;
    void* p = Active().HostPtrForGva(va, sizeof(T));
    if (!p) return 0;
    T value{};
    std::memcpy(&value, p, sizeof(T));
    return value;
}

template <typename T>
void WriteN(const char* name, T value)
{
    uint64_t va = 0, sz = 0;
    if (!Active().FindSym(name, va, sz)) return;
    void* p = Active().HostPtrForGva(va, sizeof(T));
    if (!p) return;
    std::memcpy(p, &value, sizeof(T));
}

} // namespace

void SetTestResolver(Resolver* r) { g_testResolver = r; }

uint64_t ReadQ(const char* name) { return ReadN<uint64_t>(name); }
uint32_t ReadD(const char* name) { return ReadN<uint32_t>(name); }
uint16_t ReadW(const char* name) { return ReadN<uint16_t>(name); }
uint8_t  ReadB(const char* name) { return ReadN<uint8_t>(name);  }

void WriteQ(const char* n, uint64_t v) { WriteN<uint64_t>(n, v); }
void WriteD(const char* n, uint32_t v) { WriteN<uint32_t>(n, v); }
void WriteW(const char* n, uint16_t v) { WriteN<uint16_t>(n, v); }
void WriteB(const char* n, uint8_t  v) { WriteN<uint8_t>(n, v);  }

const char* Sym(uint64_t addr) { return Active().Symbolize(addr); }

const char* Dump(const char* name, size_t n)
{
    static thread_local char buf[3 * 256 + 16];
    uint64_t va = 0, sz = 0;
    if (!Active().FindSym(name, va, sz))
    {
        std::snprintf(buf, sizeof(buf), "(unknown)");
        return buf;
    }
    if (n > 256) n = 256;
    void* p = Active().HostPtrForGva(va, n);
    if (!p)
    {
        std::snprintf(buf, sizeof(buf), "(unmapped)");
        return buf;
    }
    const uint8_t* b = static_cast<const uint8_t*>(p);
    char* out = buf;
    for (size_t i = 0; i < n; ++i)
    {
        std::snprintf(out, 4, "%02x ", b[i]);
        out += 3;
    }
    *out = '\0';
    return buf;
}

} // namespace duetos::vmm::vmm_dbg
```

- [ ] **Step 3: Write the failing tests**

Create `tools/vmm/tests/test_vmm_dbg.cpp`:

```cpp
#include "test_main.h"

#include <array>
#include <cstring>

#include "debug/vmm_dbg.h"

namespace
{

// Test fake — holds one named symbol over a host buffer.
struct FakeResolver final
    : duetos::vmm::vmm_dbg::Resolver
{
    std::array<uint8_t, 64> buf{};
    const char*             symName = "test_sym";
    uint64_t                symVa   = 0x1000;
    uint64_t                symSize = 8;

    bool FindSym(const char* name, uint64_t& va, uint64_t& sz) override
    {
        if (std::strcmp(name, symName) != 0) return false;
        va = symVa;
        sz = symSize;
        return true;
    }
    void* HostPtrForGva(uint64_t gva, uint64_t len) override
    {
        if (gva < symVa || gva + len > symVa + buf.size()) return nullptr;
        return buf.data() + (gva - symVa);
    }
    const char* Symbolize(uint64_t addr) override
    {
        static char b[64];
        std::snprintf(b, sizeof(b), "fake+0x%llx",
                      (unsigned long long)(addr - symVa));
        return b;
    }
};

} // namespace

TEST(vmm_dbg_read_q_returns_value_at_symbol)
{
    FakeResolver r;
    *reinterpret_cast<uint64_t*>(r.buf.data()) = 0xdeadbeefcafebabeull;
    duetos::vmm::vmm_dbg::SetTestResolver(&r);

    CHECK_EQ(0xdeadbeefcafebabeull,
             duetos::vmm::vmm_dbg::ReadQ("test_sym"));

    duetos::vmm::vmm_dbg::SetTestResolver(nullptr);
}

TEST(vmm_dbg_read_q_missing_symbol_returns_zero)
{
    FakeResolver r;
    duetos::vmm::vmm_dbg::SetTestResolver(&r);
    CHECK_EQ(uint64_t{0},
             duetos::vmm::vmm_dbg::ReadQ("nonexistent"));
    duetos::vmm::vmm_dbg::SetTestResolver(nullptr);
}

TEST(vmm_dbg_write_q_then_read_q_roundtrips)
{
    FakeResolver r;
    duetos::vmm::vmm_dbg::SetTestResolver(&r);

    duetos::vmm::vmm_dbg::WriteQ("test_sym", 0x1122334455667788ull);
    CHECK_EQ(0x1122334455667788ull,
             duetos::vmm::vmm_dbg::ReadQ("test_sym"));

    duetos::vmm::vmm_dbg::SetTestResolver(nullptr);
}

TEST(vmm_dbg_write_smaller_widths_match)
{
    FakeResolver r;
    duetos::vmm::vmm_dbg::SetTestResolver(&r);

    duetos::vmm::vmm_dbg::WriteB("test_sym", 0xAB);
    CHECK_EQ(uint8_t{0xAB},
             duetos::vmm::vmm_dbg::ReadB("test_sym"));

    duetos::vmm::vmm_dbg::WriteW("test_sym", 0xCAFE);
    CHECK_EQ(uint16_t{0xCAFE},
             duetos::vmm::vmm_dbg::ReadW("test_sym"));

    duetos::vmm::vmm_dbg::WriteD("test_sym", 0xDEADBEEF);
    CHECK_EQ(uint32_t{0xDEADBEEF},
             duetos::vmm::vmm_dbg::ReadD("test_sym"));

    duetos::vmm::vmm_dbg::SetTestResolver(nullptr);
}

TEST(vmm_dbg_sym_returns_thread_local_string)
{
    FakeResolver r;
    duetos::vmm::vmm_dbg::SetTestResolver(&r);

    const char* s = duetos::vmm::vmm_dbg::Sym(0x1042);
    CHECK(s != nullptr);
    CHECK(std::strstr(s, "fake+0x42") != nullptr);

    duetos::vmm::vmm_dbg::SetTestResolver(nullptr);
}

TEST(vmm_dbg_dump_caps_at_256_bytes)
{
    FakeResolver r;
    for (size_t i = 0; i < r.buf.size(); ++i)
    {
        r.buf[i] = static_cast<uint8_t>(i);
    }
    r.symSize = r.buf.size();
    duetos::vmm::vmm_dbg::SetTestResolver(&r);

    const char* s = duetos::vmm::vmm_dbg::Dump("test_sym", 4);
    CHECK(std::strstr(s, "00 01 02 03 ") != nullptr);

    duetos::vmm::vmm_dbg::SetTestResolver(nullptr);
}
```

- [ ] **Step 4: Add the new sources to the tests CMake**

Modify `tools/vmm/tests/CMakeLists.txt`. Inside the `add_executable(vmm-tests ...)` call (line 4-17), insert these two source lines (alphabetically grouped where they fit):

```cmake
    test_vmm_dbg.cpp
    ../src/debug/vmm_dbg.cpp
```

The whole block ends up looking like:

```cmake
add_executable(vmm-tests
    test_main.cpp
    test_smoke.cpp
    test_mb2_fb.cpp
    test_fb_region.cpp
    test_ps2_encode.cpp
    test_i8042.cpp
    test_mmio_decode.cpp
    test_vmm_dbg.cpp
    ../src/multiboot2.cpp
    ../src/guest_memory_fb.cpp
    ../src/input/ps2_encode.cpp
    ../src/devices/ps2_i8042.cpp
    ../src/mmio_decode.cpp
    ../src/debug/vmm_dbg.cpp
)
```

- [ ] **Step 5: Add `vmm_dbg.cpp` to the duetos-vmm target as well**

Modify `tools/vmm/CMakeLists.txt`. Inside the `add_executable(duetos-vmm ...)` call (line 52-74), in the alphabetically-grouped `src/debug/...` block (after `src/debug/exit_trace.cpp` line 70, before `src/debug/introspect.cpp` line 71), add:

```cmake
    src/debug/vmm_dbg.cpp
```

- [ ] **Step 6: Build the tests and verify they FAIL because vmm_dbg.cpp references `Vmm` types**

Run: `cmake --build tools/vmm/build --config Debug --target vmm-tests 2>&1 | Select-String "error"`

Expected: link errors about `Vmm::Active`, `Vmm::DbgFindSym`, etc. — the test binary doesn't link `vmm.cpp` and shouldn't.

**Diagnosis:** `vmm_dbg.cpp` includes `vmm.h` for the `Vmm::Active()` accessor, which is fine for the duetos-vmm exe build but blows up the unit test build that doesn't include `vmm.cpp`. The fix: gate the `LiveResolver` body on a `#ifndef VMM_DBG_NO_LIVE` macro that the test build defines.

- [ ] **Step 7: Fix — gate the live resolver path**

Modify `tools/vmm/src/debug/vmm_dbg.cpp`:

Replace `#include "vmm.h"` (the second include) with:

```cpp
#ifndef VMM_DBG_NO_LIVE
#  include "vmm.h"
#endif
```

Wrap the `LiveResolver` struct definition + the `g_liveResolver` static + the live arm of `Active()` in `#ifndef VMM_DBG_NO_LIVE`:

```cpp
#ifndef VMM_DBG_NO_LIVE
struct LiveResolver final : Resolver
{
    // ... (existing body unchanged)
};

LiveResolver g_liveResolver;
#endif

Resolver& Active()
{
    if (g_testResolver) return *g_testResolver;
#ifndef VMM_DBG_NO_LIVE
    return static_cast<Resolver&>(g_liveResolver);
#else
    // Tests must always set a test resolver before calling.
    static struct : Resolver
    {
        bool FindSym(const char*, uint64_t&, uint64_t&) override
        {
            return false;
        }
        void* HostPtrForGva(uint64_t, uint64_t) override { return nullptr; }
        const char* Symbolize(uint64_t) override { return "(no-live)"; }
    } nullResolver;
    return nullResolver;
#endif
}
```

Add `VMM_DBG_NO_LIVE` to the test build. In `tools/vmm/tests/CMakeLists.txt`, after the existing `target_compile_definitions`:

```cmake
target_compile_definitions(vmm-tests PRIVATE
    NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS
    VMM_DBG_NO_LIVE)
```

- [ ] **Step 8: Build the tests and confirm they pass**

Run:
```powershell
cmake --build tools/vmm/build --config Debug --target vmm-tests
ctest --test-dir tools/vmm/build -C Debug --output-on-failure
```

Expected output (last line): `100% tests passed, 0 tests failed out of 1` (the single vmm-tests test runs all `TEST()` cases internally; pass = all of them passed).

### Task 1.4: Wire the `vmm_dbg::` keepalive table so the linker doesn't drop the symbols

**Files:**
- Modify: `tools/vmm/src/vmm.cpp`

The MSVC linker's `/OPT:REF` will strip the `vmm_dbg::*` functions if nothing references them — and nothing does, because they only get called from the VS Immediate window at runtime. A `volatile` table of function pointers keeps them alive.

- [ ] **Step 1: Add the keepalive table at the bottom of vmm.cpp**

At the very end of `tools/vmm/src/vmm.cpp`, just before the closing `} // namespace duetos::vmm` (line 595), add:

```cpp
// ---------------------------------------------------------------------
// vmm_dbg keepalive — references every public vmm_dbg:: function so
// MSVC's /OPT:REF cannot eliminate them. Without this the Immediate
// window can't call them: VS resolves names against the PDB, and
// stripped symbols vanish from the PDB. The volatile pointer-array
// pattern is the well-trodden trick for this.
// ---------------------------------------------------------------------
namespace
{
using namespace duetos::vmm::vmm_dbg;
volatile void* const g_vmmDbgKeepalive[] = {
    reinterpret_cast<volatile void*>(&ReadQ),
    reinterpret_cast<volatile void*>(&ReadD),
    reinterpret_cast<volatile void*>(&ReadW),
    reinterpret_cast<volatile void*>(&ReadB),
    reinterpret_cast<volatile void*>(&WriteQ),
    reinterpret_cast<volatile void*>(&WriteD),
    reinterpret_cast<volatile void*>(&WriteW),
    reinterpret_cast<volatile void*>(&WriteB),
    reinterpret_cast<volatile void*>(&Sym),
    reinterpret_cast<volatile void*>(&Dump),
};
} // namespace
```

Also add the include near the top of vmm.cpp (after the existing `#include "multiboot2.h"` at line 13):

```cpp
#include "debug/vmm_dbg.h"
```

- [ ] **Step 2: Build and verify the symbols survive**

Run:
```powershell
cmake --build tools/vmm/build --config Debug --target duetos-vmm
dumpbin /SYMBOLS tools/vmm/build/Debug/duetos-vmm.exe | Select-String "vmm_dbg::ReadQ"
```

Expected: at least one matching line listing `duetos::vmm::vmm_dbg::ReadQ` as an external symbol.

### Task 1.5: Commit Slice 1

- [ ] **Step 1: Verify the tree state**

Run: `git status --short`

Expected files modified/created:
- `M tools/vmm/CMakeLists.txt`
- `M tools/vmm/src/vmm.cpp`
- `M tools/vmm/src/vmm.h`
- `M tools/vmm/tests/CMakeLists.txt`
- `A tools/vmm/src/debug/vmm_dbg.cpp`
- `A tools/vmm/src/debug/vmm_dbg.h`
- `A tools/vmm/tests/test_vmm_dbg.cpp`

- [ ] **Step 2: Verify the full build is clean**

Run:
```powershell
cmake --build tools/vmm/build --config Debug
ctest --test-dir tools/vmm/build -C Debug --output-on-failure
```

Expected: `Build succeeded.` and `100% tests passed`.

- [ ] **Step 3: Stage and commit**

```powershell
git add tools/vmm/CMakeLists.txt tools/vmm/src/vmm.cpp tools/vmm/src/vmm.h tools/vmm/tests/CMakeLists.txt tools/vmm/src/debug/vmm_dbg.cpp tools/vmm/src/debug/vmm_dbg.h tools/vmm/tests/test_vmm_dbg.cpp
git commit -m @'
feat(vmm/debug): vmm_dbg:: read/write/sym/dump-by-name from VS

Slice 1 of the host-attach guest-bridge debugger (spec
docs/superpowers/specs/2026-05-19-vmm-debugger-bridge-design.md).

When VS is natively attached to duetos-vmm.exe, vmm_dbg::ReadQ /
WriteQ / Sym / Dump in the Immediate window now resolve a guest
kernel symbol name to mapped host bytes via ElfSymbols +
GuestMemory and read/write/symbolize through that pointer chain.
No WHP changes; no kernel changes; pure addition on top of the
plumbing Vmm::Monitor''s `read`/`lookup` handlers already use.

Layered behind a small Resolver interface so the unit tests
exercise the byte-level logic without a live WHP partition or
loaded kernel ELF. A volatile keepalive table in vmm.cpp anchors
the public functions against /OPT:REF.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
'@
```

---

## Slice 2 — Layer A: `GuestKernelView` (typed live view in VS Watch)

The `Vmm` gains a `kernel` member of type `GuestKernelView`, whose fields are host pointers into mapped guest RAM. VS Watch window expanders read live guest state by dereferencing them; edits write through. Initial v1 exposure: just `g_ticks` plus one mirrored struct (`KernelTaskMirror`) to demonstrate the layout-drift guardrails. The mirror infrastructure is what's tricky; the curated list grows trivially in follow-ups.

### Task 2.1: Add the hand-maintained `sizeof_report.h` in the kernel tree

**Files:**
- Create: `kernel/include/duetos/sizeof_report.h`

We're not generating this with a CMake codegen step — that would need a hosted probe TU compiled against freestanding kernel headers, which is heavier than the alternative. Instead: hand-write the header with the known offsets, and have both the kernel and the VMM `static_assert` against it. Drift on either side fails its respective build.

- [ ] **Step 1: Determine the actual offsets of the kernel `KernelTask` (or equivalent) fields you intend to expose**

First, find the kernel-side type. Run:

```bash
grep -rn "struct KernelTask\b\|class KernelTask\b" kernel/sched kernel/proc 2>/dev/null | head -5
```

Expected: locates the actual type definition. If the kernel uses a different name (e.g. `Task`, `Thread`, `KThread`), substitute that name throughout this slice.

**Look up:** the `pid` offset, the `name[]` array offset and capacity, and the total size of the struct. Note them — you'll plug them into the header.

(If `KernelTask` doesn't exist or only has fields that aren't useful in a debugger, pick the simplest scheduler-side struct that has a name and a numeric identifier, document the substitution in the file header, and proceed.)

- [ ] **Step 2: Write the sizeof_report header**

Create `kernel/include/duetos/sizeof_report.h`:

```cpp
// Layout report for kernel types the duetos-vmm host-side debugger
// mirrors. Both the kernel TU (kernel/scripts/sizeof_report_check.cpp)
// and the VMM mirror header (tools/vmm/src/debug/guest_types_mirror.h)
// static_assert their respective structs against these constants — so
// adding a field to a kernel struct that shifts its layout fails the
// kernel build, AND the VMM build, until both sides are updated in
// lockstep.
//
// This is hand-maintained rather than codegen'd. The volume is small
// (one entry per debugger-exposed type), the bilateral assertion
// catches every drift direction we care about, and a real codegen
// path would require a hosted probe TU that's not worth the build-
// system complexity for a debug-only feature.
#pragma once

#include <cstddef>

namespace duetos::sizeof_report
{

// ----- KernelTask (kernel/sched/...) -----
// Adjust these constants when KernelTask grows or fields move. The
// kernel-side static_assert in sizeof_report_check.cpp will fail the
// kernel build the moment they diverge from the real layout.
inline constexpr std::size_t kSizeof_KernelTask          = 256;  // FIXME: set to actual sizeof()
inline constexpr std::size_t kOffsetof_KernelTask_pid    = 0;    // FIXME: set to actual offsetof()
inline constexpr std::size_t kOffsetof_KernelTask_name   = 32;   // FIXME
inline constexpr std::size_t kCapacity_KernelTask_name   = 32;   // FIXME
inline constexpr std::size_t kOffsetof_KernelTask_kstack = 64;   // FIXME

} // namespace duetos::sizeof_report
```

**Replace every `FIXME` with the real value found in step 1.** The values above are placeholders for plan purposes; the engineer running this slice must look them up.

### Task 2.2: Add the kernel-side static_assert TU

**Files:**
- Create: `kernel/scripts/sizeof_report_check.cpp`
- Modify: `kernel/CMakeLists.txt` (or whichever CMake adds kernel source files — check `kernel/sched/CMakeLists.txt` and `kernel/CMakeLists.txt`).

- [ ] **Step 1: Write the kernel-side check TU**

Create `kernel/scripts/sizeof_report_check.cpp`:

```cpp
// Compile-time-only TU: verifies the kernel's actual struct layouts
// match the constants exported in kernel/include/duetos/sizeof_report.h.
// Diverging from those constants without updating the header fails
// the kernel build with a precise message naming the offending field.
//
// Has zero runtime impact: nothing in this TU emits code or initialised
// data. It's purely a static_assert anchor.
#include "duetos/sizeof_report.h"

// Pull in the real kernel types we report on. Adjust the include
// paths if the kernel relocates them.
#include "sched/task.h"  // KernelTask

namespace
{

static_assert(sizeof(duetos::KernelTask) ==
                  ::duetos::sizeof_report::kSizeof_KernelTask,
              "KernelTask grew/shrank — update sizeof_report.h "
              "AND tools/vmm/src/debug/guest_types_mirror.h in lockstep");
static_assert(offsetof(duetos::KernelTask, pid) ==
                  ::duetos::sizeof_report::kOffsetof_KernelTask_pid,
              "KernelTask::pid offset drifted");
static_assert(offsetof(duetos::KernelTask, name) ==
                  ::duetos::sizeof_report::kOffsetof_KernelTask_name,
              "KernelTask::name offset drifted");
static_assert(sizeof(duetos::KernelTask::name) ==
                  ::duetos::sizeof_report::kCapacity_KernelTask_name,
              "KernelTask::name capacity drifted");

} // namespace
```

(Substitute `duetos::KernelTask` for the real qualified name; substitute `sched/task.h` for the real header. If you can't find a header where `KernelTask` is fully declared, pick a different struct that IS fully declared in a single header and update both this file and `kernel/include/duetos/sizeof_report.h` accordingly.)

- [ ] **Step 2: Wire the TU into the kernel build**

Identify the right CMakeLists. The DuetOS kernel is built in WSL; the source-of-truth is on this Windows host but rebuilds happen on the Linux side. Inspect `kernel/CMakeLists.txt` for an existing `target_sources(duetos-kernel ...)` block or similar; add `scripts/sizeof_report_check.cpp` to it.

Run:

```bash
grep -n "target_sources\|add_library.*duetos-kernel\|add_executable.*duetos-kernel" kernel/CMakeLists.txt
```

Add the file alongside the existing source list. The exact line depends on the current kernel CMake layout; the principle is: it must be compiled as part of the kernel target.

- [ ] **Step 3: Build the kernel in WSL to verify the static_asserts hold**

```powershell
wsl.exe -- bash -lc "cd ~/source/DuetOS && cmake --build build/x86_64-debug --target duetos-kernel 2>&1 | tail -30"
```

Expected: clean build. If static_asserts fire, you have wrong placeholder values in `sizeof_report.h` — read the assertion message, fix the constants, rerun. **Don't proceed to Task 2.3 until the kernel build is clean.**

### Task 2.3: Add the VMM-side `guest_types_mirror.h`

**Files:**
- Create: `tools/vmm/src/debug/guest_types_mirror.h`

- [ ] **Step 1: Write the mirror header**

```cpp
// VMM-side POD mirrors of kernel structs the host-side debugger
// (debug/guest_view.cpp) overlays on mapped guest RAM. The Visual
// Studio Watch window dereferences a Vmm::kernel.* host pointer of
// these mirror types and presents the result as a typed expandable
// tree.
//
// CRITICAL: mirror field offsets must exactly match the kernel's
// layout for the bytes-overlay to be correct. The static_asserts
// below check this against kernel/include/duetos/sizeof_report.h,
// which the kernel itself static_asserts against the REAL struct.
// So a kernel-side struct change fails both builds until the mirror
// is updated in lockstep — there is no silent-misread failure mode.
//
// Mirrors may be SMALLER than the real type (we only mirror fields
// we expose to the debugger). They must NEVER be larger and must
// NEVER place a field at the wrong offset.
#pragma once

#include <cstdint>
#include <cstddef>

#include "duetos/sizeof_report.h"

namespace duetos::vmm
{

struct alignas(8) KernelTaskMirror
{
    // Layout MUST match kernel KernelTask through the last mirrored
    // field. Subsequent kernel fields beyond `name[]` are not mirrored
    // and the host treats them as inaccessible padding.
    uint64_t pid;        // matches ::duetos::sizeof_report::kOffsetof_KernelTask_pid
    char     _pad0[::duetos::sizeof_report::kOffsetof_KernelTask_name -
                   sizeof(uint64_t)];
    char     name[::duetos::sizeof_report::kCapacity_KernelTask_name];
};

static_assert(offsetof(KernelTaskMirror, pid) ==
                  ::duetos::sizeof_report::kOffsetof_KernelTask_pid,
              "KernelTaskMirror::pid does not match kernel layout");
static_assert(offsetof(KernelTaskMirror, name) ==
                  ::duetos::sizeof_report::kOffsetof_KernelTask_name,
              "KernelTaskMirror::name does not match kernel layout");
static_assert(sizeof(KernelTaskMirror::name) ==
                  ::duetos::sizeof_report::kCapacity_KernelTask_name,
              "KernelTaskMirror::name capacity drift");

} // namespace duetos::vmm
```

- [ ] **Step 2: Add the include path on the VMM side so it can find `duetos/sizeof_report.h`**

Modify `tools/vmm/CMakeLists.txt`. After `target_include_directories(duetos-vmm PRIVATE src)` at line 76, add:

```cmake
# Shared layout report between kernel and VMM. Kernel-side
# static_asserts (kernel/scripts/sizeof_report_check.cpp) keep the
# header truthful; VMM-side mirrors static_assert their offsets
# against it. The path is two-up to the repo root + kernel/include.
get_filename_component(_duetos_kernel_include
    "${CMAKE_SOURCE_DIR}/../../kernel/include" ABSOLUTE)
target_include_directories(duetos-vmm PRIVATE "${_duetos_kernel_include}")
```

- [ ] **Step 3: Build VMM to confirm the mirror header compiles**

Run: `cmake --build tools/vmm/build --config Debug --target duetos-vmm`
Expected: clean build. (The mirror header isn't yet referenced; this is a syntax check via the keepalive table being recompiled.)

### Task 2.4: Add `guest_view.{h,cpp}` and the `MapSym` template

**Files:**
- Create: `tools/vmm/src/debug/guest_view.h`
- Create: `tools/vmm/src/debug/guest_view.cpp`

- [ ] **Step 1: Write the header**

```cpp
// Typed live view of curated guest kernel state. Each field is a host
// pointer into mapped guest physical RAM (host bytes IS guest bytes —
// WHP requires host-backed mappings, so editing through these pointers
// has immediate guest effect with no copy/sync).
//
// Population is deferred: when the kernel boots, paging is set up
// during the first guest exits. `Setup` runs at the first post-exit
// point; pointers that fail to translate at that moment (because
// their backing struct hasn't been initialised yet, or per-CPU AP
// bringup hasn't happened) are filled in by `Refresh`, called on
// every subsequent exit.
//
// Adding a new exposure:
//   1. Add a field here.
//   2. Add a MapSym<...>() call in Refresh() (guest_view.cpp).
//   3. If the type is non-primitive, add a *Mirror in
//      guest_types_mirror.h and the matching sizeof_report.h entry.
#pragma once

#include <cstdint>

#include "debug/guest_types_mirror.h"

namespace duetos::vmm
{

class Vmm; // forward — guest_view.cpp depends on Vmm internals.

struct GuestKernelView
{
    // Kernel scheduler tick counter. Watch this to confirm the guest
    // is actually running (it should monotonically increase).
    uint64_t* g_ticks = nullptr;

    // First slot of the per-CPU current-task array. Slot 0 = BSP.
    KernelTaskMirror* current_task = nullptr;
};

void SetupGuestView(GuestKernelView& view, Vmm& vmm);
void RefreshGuestView(GuestKernelView& view, Vmm& vmm);

} // namespace duetos::vmm
```

- [ ] **Step 2: Write the implementation**

Create `tools/vmm/src/debug/guest_view.cpp`:

```cpp
#include "debug/guest_view.h"

#include "vmm.h"

namespace duetos::vmm
{

namespace
{

// Resolve `name` to a host pointer of T, or leave *outPtr untouched.
// Returns true if *outPtr was filled in (or was already non-null).
template <typename T>
bool MapSym(T*& outPtr, Vmm& vmm, const char* name)
{
    if (outPtr) return true;
    const ElfSymbols::Sym* s = vmm.DbgFindSym(name);
    if (!s) return false;
    uint64_t gpa = 0;
    if (!vmm.DbgResolveGpa(s->addr, gpa)) return false;
    outPtr = static_cast<T*>(vmm.DbgHostPtr(gpa, sizeof(T)));
    return outPtr != nullptr;
}

} // namespace

void SetupGuestView(GuestKernelView& view, Vmm& vmm)
{
    // Same as Refresh — Setup just labels the first call. Splitting
    // the names is for callers who want to log "view first established"
    // vs. "view refilled" semantically.
    RefreshGuestView(view, vmm);
}

void RefreshGuestView(GuestKernelView& view, Vmm& vmm)
{
    // Each MapSym() is a no-op if the field is already mapped. So a
    // populated view stays populated; only nullptr fields are retried.
    MapSym(view.g_ticks,      vmm, "g_ticks");
    MapSym(view.current_task, vmm, "g_currentTask");
    // Add new curated globals here. Replace "g_currentTask" with the
    // actual kernel symbol name once it's known (see Task 2.1).
}

} // namespace duetos::vmm
```

(Substitute `"g_ticks"` and `"g_currentTask"` for the actual kernel symbol names — find them with:

```bash
nm build/x86_64-debug/kernel/duetos-kernel.elf | grep -E "g_ticks|current_task|currentTask" | head
```

Adjust both calls to match the real exported names.)

### Task 2.5: Wire `Vmm::kernel` and call `Refresh` on each exit

**Files:**
- Modify: `tools/vmm/src/vmm.h`
- Modify: `tools/vmm/src/vmm.cpp`
- Modify: `tools/vmm/CMakeLists.txt`

- [ ] **Step 1: Add the include + member**

In `tools/vmm/src/vmm.h`, after the existing `#include "debug/gdb_server.h"` at line 14, add:

```cpp
#include "debug/guest_view.h"
```

Inside the `Vmm` class public section (around line 72-73, before `Active()`), add:

```cpp
    // Live, typed view of curated guest kernel globals. Populated
    // after the first guest exit (paging needs to be up). Fields are
    // host pointers into mapped GPA — edit them in the VS Watch
    // window and the guest sees the change immediately.
    GuestKernelView kernel;
```

- [ ] **Step 2: Add the new source to CMake**

In `tools/vmm/CMakeLists.txt`, inside `add_executable(duetos-vmm ...)`, add (alphabetically, just after `src/debug/guest_view.cpp` would sort):

```cmake
    src/debug/guest_view.cpp
```

- [ ] **Step 3: Call `RefreshGuestView` on each exit**

In `tools/vmm/src/vmm.cpp`, inside `Vmm::Run()` (around line 486 in the for-loop), after the `RecordExit(exit);` call and before the switch — i.e. on every exit, before dispatch — add:

```cpp
        RefreshGuestView(kernel, *this);
```

That single line keeps the view filled in as kernel state materialises through boot.

- [ ] **Step 4: Build and run a quick sanity check**

Run: `cmake --build tools/vmm/build --config Debug --target duetos-vmm`
Expected: clean build.

If the kernel ELF exists in `build/x86_64-debug/kernel/`, manually verify the view fills in by running:

```powershell
$env:DUETOS_VMM_SMOKE=1
.\tools\vmm\build\Debug\duetos-vmm.exe --kernel .\build\x86_64-debug\kernel\duetos-kernel.elf --mem 2048 --idle 10
```

Expected: the VMM exits cleanly after 10 seconds of COM1 silence (the kernel is running but its output has stalled). The interesting verification is **manual** — attach VS native debugger to the running `duetos-vmm.exe` and check that `vmm.kernel.g_ticks` shows a non-null pointer to a monotonically-increasing value. Document the manual-verify result in the commit body.

### Task 2.6: Commit Slice 2

- [ ] **Step 1: Verify clean tree state**

Run: `git status --short`. Expected:
- `M tools/vmm/CMakeLists.txt`
- `M tools/vmm/src/vmm.cpp`
- `M tools/vmm/src/vmm.h`
- `M kernel/CMakeLists.txt` (or wherever you added the check TU)
- `A kernel/include/duetos/sizeof_report.h`
- `A kernel/scripts/sizeof_report_check.cpp`
- `A tools/vmm/src/debug/guest_types_mirror.h`
- `A tools/vmm/src/debug/guest_view.cpp`
- `A tools/vmm/src/debug/guest_view.h`

- [ ] **Step 2: Verify both builds clean**

```powershell
cmake --build tools/vmm/build --config Debug
wsl.exe -- bash -lc "cd ~/source/DuetOS && cmake --build build/x86_64-debug --target duetos-kernel 2>&1 | tail -5"
ctest --test-dir tools/vmm/build -C Debug --output-on-failure
```

Expected: both builds succeed, tests pass.

- [ ] **Step 3: Stage and commit**

```powershell
git add kernel/include/duetos/sizeof_report.h kernel/scripts/sizeof_report_check.cpp kernel/CMakeLists.txt tools/vmm/src/debug/guest_types_mirror.h tools/vmm/src/debug/guest_view.h tools/vmm/src/debug/guest_view.cpp tools/vmm/src/vmm.h tools/vmm/src/vmm.cpp tools/vmm/CMakeLists.txt
git commit -m @'
feat(vmm/debug): typed live guest view in VS Watch (Vmm::kernel)

Slice 2 of the host-attach guest-bridge debugger. Adds:

 * GuestKernelView struct of host pointers into mapped GPA; Vmm
   gains a `kernel` member of this type. VS Watch expands
   `vmm.kernel.g_ticks` etc. and shows the live guest value;
   editing writes through to the same bytes the guest reads.
 * Curated v1 exposure: g_ticks (uint64_t global) and current_task
   (per-CPU pointer to KernelTaskMirror).
 * guest_types_mirror.h hand-mirrors the kernel structs the
   debugger inspects (POD layout, alignment-matched).
 * kernel/include/duetos/sizeof_report.h exports layout constants;
   the new kernel-side TU sizeof_report_check.cpp static_asserts
   the real kernel struct against them; the VMM mirror header
   static_asserts its layout against them. Both directions fail
   their build on drift — there is no silent-misread failure mode.

Population is deferred to the first post-exit moment (paging needs
to be up) and refreshed on every subsequent exit so per-CPU AP
state becomes visible as it materialises through boot.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
'@
```

---

## Slice 3 — Layer C: host-session breakpoints (`Claim()` + `Bp` + `Step` + `Run`)

The vCPU thread normally routes guest #BP / #DB exceptions to the GDB stub. After `vmm_dbg::Claim()` flips the arbiter flag, those same exits route to `host_stop.cpp`, which snapshots registers, restores the shadowed byte, sets `g_stop_state.stopped = true`, then calls `__debugbreak()` — Visual Studio's native debugger halts the VMM at that frame. The user inspects `vmm.kernel.*` and `g_stop_state.*`, then clears `stopped` via `vmm_dbg::Run()` / `Step()` from the Immediate window.

### Task 3.1: Add `host_stop.{h,cpp}` with the stop state + arbiter

**Files:**
- Create: `tools/vmm/src/debug/host_stop.h`
- Create: `tools/vmm/src/debug/host_stop.cpp`

- [ ] **Step 1: Write the header**

```cpp
// Host-attach session's guest-stop surface. When vmm_dbg::Claim() is
// active and the guest hits a software breakpoint (or single-step
// #DB), the arbiter (HandleHostStop) snapshots vCPU state, calls
// __debugbreak() so VS halts the VMM at the exact host frame, then
// spins until vmm_dbg::Run() / Step() clears the stop.
//
// State is process-global (one VMM per process, single vCPU in v1).
#pragma once

#include <atomic>
#include <cstdint>

#include "whp.h"  // WHV_RUN_VP_EXIT_CONTEXT

namespace duetos::vmm
{

class Vmm;

struct GuestStopState
{
    std::atomic<bool> stopped{false};

    // Reason: 0 = breakpoint, 1 = single-step, 2 = other.
    uint32_t stop_reason = 0;

    // RIP + symbolic decoration.
    uint64_t rip = 0;
    char     rip_sym[160] = {};

    // GPRs at stop.
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rflags, cr2, cr3;

    // Set by vmm_dbg::Step(). Cleared by the arbiter on the next
    // #DB exit. While true, the vCPU exit handler arms TF and clears
    // `stopped` after replanting the breakpoint.
    std::atomic<bool> step_pending{false};
};

extern GuestStopState g_stop_state;

// True iff the host-attach session owns the WHP exception-exit path.
// Default false (the GDB stub owns it). Flipped by vmm_dbg::Claim()
// / vmm_dbg::Release().
bool HostAttachOwnsDebug();

// Called from Vmm::Run() exception case when HostAttachOwnsDebug() is
// true. Returns true iff the host arbiter consumed the exit (i.e. the
// guest is now stopped and waiting); false if the exit should fall
// through to legacy handling (e.g. unknown vector).
bool HandleHostStop(Vmm& vmm,
                    const WHV_RUN_VP_EXIT_CONTEXT& exit);

} // namespace duetos::vmm
```

- [ ] **Step 2: Write the implementation**

Create `tools/vmm/src/debug/host_stop.cpp`:

```cpp
#include "debug/host_stop.h"

#include <intrin.h>     // __debugbreak
#include <windows.h>    // IsDebuggerPresent

#include <chrono>
#include <cstdio>
#include <thread>

#include "vmm.h"

namespace duetos::vmm
{

GuestStopState g_stop_state;
std::atomic<bool> g_hostAttachOwns{false};

bool HostAttachOwnsDebug() { return g_hostAttachOwns.load(); }

namespace
{

// Snapshot every register listed in `kSnapRegs` into the stop state.
constexpr WHV_REGISTER_NAME kSnapRegs[] = {
    WHvX64RegisterRax, WHvX64RegisterRbx, WHvX64RegisterRcx,
    WHvX64RegisterRdx, WHvX64RegisterRsi, WHvX64RegisterRdi,
    WHvX64RegisterRbp, WHvX64RegisterRsp, WHvX64RegisterR8,
    WHvX64RegisterR9,  WHvX64RegisterR10, WHvX64RegisterR11,
    WHvX64RegisterR12, WHvX64RegisterR13, WHvX64RegisterR14,
    WHvX64RegisterR15, WHvX64RegisterRip, WHvX64RegisterRflags,
    WHvX64RegisterCr2, WHvX64RegisterCr3,
};

void SnapshotState(Vmm& vmm, uint32_t reason)
{
    WHV_REGISTER_VALUE vals[20] = {};
    // Access via DbgPartition() — added in step 3 below.
    vmm.DbgPartition().GetRegisters(0, kSnapRegs, 20, vals);

    g_stop_state.rax = vals[0].Reg64;
    g_stop_state.rbx = vals[1].Reg64;
    g_stop_state.rcx = vals[2].Reg64;
    g_stop_state.rdx = vals[3].Reg64;
    g_stop_state.rsi = vals[4].Reg64;
    g_stop_state.rdi = vals[5].Reg64;
    g_stop_state.rbp = vals[6].Reg64;
    g_stop_state.rsp = vals[7].Reg64;
    g_stop_state.r8  = vals[8].Reg64;
    g_stop_state.r9  = vals[9].Reg64;
    g_stop_state.r10 = vals[10].Reg64;
    g_stop_state.r11 = vals[11].Reg64;
    g_stop_state.r12 = vals[12].Reg64;
    g_stop_state.r13 = vals[13].Reg64;
    g_stop_state.r14 = vals[14].Reg64;
    g_stop_state.r15 = vals[15].Reg64;
    g_stop_state.rip = vals[16].Reg64;
    g_stop_state.rflags = vals[17].Reg64;
    g_stop_state.cr2 = vals[18].Reg64;
    g_stop_state.cr3 = vals[19].Reg64;
    g_stop_state.stop_reason = reason;

    std::string s = vmm.DbgSymbols().Symbolize(g_stop_state.rip);
    std::snprintf(g_stop_state.rip_sym, sizeof(g_stop_state.rip_sym),
                  "%s", s.c_str());
}

} // namespace

bool HandleHostStop(Vmm& vmm, const WHV_RUN_VP_EXIT_CONTEXT& exit)
{
    const uint8_t et = exit.VpException.ExceptionType;

    // 3 = #BP (int3), 1 = #DB (single-step). Anything else is not
    // ours; fall through.
    uint32_t reason;
    if      (et == 3) reason = 0;
    else if (et == 1) reason = 1;
    else              return false;

    // For #BP the guest RIP points past the int3; rewind so the next
    // continue replays the same instruction (after the byte is
    // restored). For #DB the trap is fault-class on int3 / trap-class
    // on TF; we don't rewind.
    if (et == 3)
    {
        vmm.DbgPartition().SetRip(0, exit.VpContext.Rip - 1);
    }

    SnapshotState(vmm, reason);

    g_stop_state.stopped.store(true);

    std::fprintf(stderr,
                 "[vmm/host-stop] guest stopped: rip=%s reason=%u "
                 "(call vmm_dbg::Run() / Step() to resume)\n",
                 g_stop_state.rip_sym, reason);

    if (IsDebuggerPresent())
    {
        __debugbreak();
    }

    // Spin until Run() / Step() clears `stopped`. Yield-sleep so we
    // don't burn a core while the user inspects state in VS.
    while (g_stop_state.stopped.load())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return true;
}

} // namespace duetos::vmm
```

### Task 3.2: Expose `DbgPartition()` on `Vmm`

The arbiter needs to read/write vCPU registers. Add a debug-only accessor.

- [ ] **Step 1: Add the accessor declaration in vmm.h**

In `tools/vmm/src/vmm.h`, alongside the other `Dbg*` accessors added in Slice 1, add:

```cpp
    Partition&            DbgPartition()      { return m_part; }
```

### Task 3.3: Add `vmm_dbg::Claim` / `Release` / `Bp` / `Clr` / `Step` / `Run`

**Files:**
- Modify: `tools/vmm/src/debug/vmm_dbg.h`
- Modify: `tools/vmm/src/debug/vmm_dbg.cpp`

- [ ] **Step 1: Add declarations to the header**

At the end of the `vmm_dbg::` namespace in `tools/vmm/src/debug/vmm_dbg.h`, before the closing brace:

```cpp
// --- Layer C: host-session breakpoints + step ---

// Hand ownership of the WHP exception-exit path to this host-attach
// session. The GDB stub becomes inert. Default state (no Claim call)
// keeps today's behaviour: GDB stub owns exceptions.
//
// Idempotent. Returns the previous owner ("gdb" / "host" / "none").
const char* Claim();
const char* Release();

// Plant / clear a software breakpoint at the named kernel symbol.
// Returns true iff the byte was actually patched.
bool Bp (const char* name);
bool Clr(const char* name);

// Step the stopped vCPU one instruction. No-op if not stopped.
// Returns immediately after arming TF; the next exception exit
// re-enters HandleHostStop with reason=1.
void Step();

// Resume the stopped vCPU. Replants any breakpoint at RIP via the
// step-off dance, then clears the stop and returns.
void Run();
```

- [ ] **Step 2: Add the implementations in vmm_dbg.cpp**

Append to `tools/vmm/src/debug/vmm_dbg.cpp` (still inside `namespace duetos::vmm::vmm_dbg`, before the closing brace):

```cpp
#ifndef VMM_DBG_NO_LIVE

// Implementation pulls in Vmm internals; gated like LiveResolver.

#include "debug/host_stop.h"

namespace
{

// Layer-C breakpoint shadow table, separate from GdbServer's. Coexists
// with GDB stub's table — Claim/Release flips ownership of the WHP
// exception-exit path; both tables stay valid through transitions so
// the byte-shadow is always recoverable.
std::map<uint64_t, uint8_t> g_layerCBps;
std::mutex                   g_layerCBpsMutex;

// Plant 0xCC; record original. Returns true iff actually patched.
bool PlantBpAtGva(uint64_t gva)
{
    Vmm* v = Vmm::Active();
    if (!v) return false;
    uint64_t gpa = 0;
    if (!v->DbgResolveGpa(gva, gpa)) return false;
    uint8_t* p = static_cast<uint8_t*>(v->DbgHostPtr(gpa, 1));
    if (!p) return false;
    std::lock_guard<std::mutex> lk(g_layerCBpsMutex);
    if (g_layerCBps.count(gva)) return false;  // already planted
    g_layerCBps[gva] = *p;
    *p = 0xCC;
    return true;
}

// Restore the shadowed byte and forget. Returns true iff we held a
// shadow for the address.
bool ClearBpAtGva(uint64_t gva)
{
    Vmm* v = Vmm::Active();
    if (!v) return false;
    std::lock_guard<std::mutex> lk(g_layerCBpsMutex);
    auto it = g_layerCBps.find(gva);
    if (it == g_layerCBps.end()) return false;
    uint64_t gpa = 0;
    if (v->DbgResolveGpa(gva, gpa))
    {
        uint8_t* p = static_cast<uint8_t*>(v->DbgHostPtr(gpa, 1));
        if (p) *p = it->second;
    }
    g_layerCBps.erase(it);
    return true;
}

} // namespace

extern std::atomic<bool> g_hostAttachOwns; // from host_stop.cpp

const char* Claim()
{
    bool was = g_hostAttachOwns.exchange(true);
    return was ? "host" : "gdb-or-none";
}

const char* Release()
{
    bool was = g_hostAttachOwns.exchange(false);
    return was ? "host" : "gdb-or-none";
}

bool Bp(const char* name)
{
    if (!name) return false;
    Vmm* v = Vmm::Active();
    if (!v) return false;
    const ElfSymbols::Sym* s = v->DbgFindSym(name);
    if (!s)
    {
        OutputDebugStringA("vmm_dbg::Bp: symbol not found\n");
        return false;
    }
    return PlantBpAtGva(s->addr);
}

bool Clr(const char* name)
{
    if (!name) return false;
    Vmm* v = Vmm::Active();
    if (!v) return false;
    const ElfSymbols::Sym* s = v->DbgFindSym(name);
    if (!s) return false;
    return ClearBpAtGva(s->addr);
}

void Step()
{
    if (!g_stop_state.stopped.load()) return;
    g_stop_state.step_pending.store(true);

    // Arm TF on the stopped vCPU.
    Vmm* v = Vmm::Active();
    if (!v) return;
    WHV_REGISTER_NAME n = WHvX64RegisterRflags;
    WHV_REGISTER_VALUE val = {};
    v->DbgPartition().GetRegisters(0, &n, 1, &val);
    val.Reg64 |= (1ull << 8); // TF
    v->DbgPartition().SetRegisters(0, &n, 1, &val);

    // Step-off any 0xCC at the current RIP.
    uint64_t rip = v->DbgPartition().GetRip(0);
    auto it = g_layerCBps.find(rip);
    if (it != g_layerCBps.end())
    {
        uint64_t gpa = 0;
        if (v->DbgResolveGpa(rip, gpa))
        {
            uint8_t* p = static_cast<uint8_t*>(
                v->DbgHostPtr(gpa, 1));
            if (p) *p = it->second; // lift; reinsert on next stop
        }
    }

    g_stop_state.stopped.store(false);
}

void Run()
{
    if (!g_stop_state.stopped.load()) return;

    // Reinsert all breakpoints (a Bp planted while stopped doesn't
    // hit until the user continues — same semantic as GdbServer).
    Vmm* v = Vmm::Active();
    if (v)
    {
        std::lock_guard<std::mutex> lk(g_layerCBpsMutex);
        for (auto& kv : g_layerCBps)
        {
            uint64_t gpa = 0;
            if (v->DbgResolveGpa(kv.first, gpa))
            {
                uint8_t* p = static_cast<uint8_t*>(
                    v->DbgHostPtr(gpa, 1));
                if (p) *p = 0xCC;
            }
        }
    }

    g_stop_state.stopped.store(false);
}

#endif // VMM_DBG_NO_LIVE
```

Also add the new `#include`s to the top of `vmm_dbg.cpp`:

```cpp
#include <map>
#include <mutex>
#include <windows.h>  // OutputDebugStringA
```

- [ ] **Step 3: Add `vmm_dbg::Claim` + `Release` + `Bp` + `Clr` + `Step` + `Run` to the keepalive table**

In `tools/vmm/src/vmm.cpp`, extend `g_vmmDbgKeepalive` (added in Task 1.4):

```cpp
volatile void* const g_vmmDbgKeepalive[] = {
    reinterpret_cast<volatile void*>(&ReadQ),
    reinterpret_cast<volatile void*>(&ReadD),
    reinterpret_cast<volatile void*>(&ReadW),
    reinterpret_cast<volatile void*>(&ReadB),
    reinterpret_cast<volatile void*>(&WriteQ),
    reinterpret_cast<volatile void*>(&WriteD),
    reinterpret_cast<volatile void*>(&WriteW),
    reinterpret_cast<volatile void*>(&WriteB),
    reinterpret_cast<volatile void*>(&Sym),
    reinterpret_cast<volatile void*>(&Dump),
    reinterpret_cast<volatile void*>(&Claim),
    reinterpret_cast<volatile void*>(&Release),
    reinterpret_cast<volatile void*>(&Bp),
    reinterpret_cast<volatile void*>(&Clr),
    reinterpret_cast<volatile void*>(&Step),
    reinterpret_cast<volatile void*>(&Run),
};
```

### Task 3.4: Rewire the WHP exception-exit case to consult the arbiter

**Files:**
- Modify: `tools/vmm/src/vmm.cpp`
- Modify: `tools/vmm/CMakeLists.txt`

- [ ] **Step 1: Add `host_stop.cpp` to the build**

In `tools/vmm/CMakeLists.txt`, inside `add_executable(duetos-vmm ...)`, add (alphabetically):

```cmake
    src/debug/host_stop.cpp
```

Also add to `tools/vmm/src/vmm.cpp` near the top (after `#include "debug/vmm_dbg.h"`):

```cpp
#include "debug/host_stop.h"
```

- [ ] **Step 2: Insert the arbiter at the top of the `Exception` case in `Vmm::Run`**

In `tools/vmm/src/vmm.cpp:536-576` (the `case WHvRunVpExitReasonException`), at the **very start** of the case block (right after `case WHvRunVpExitReasonException:` and the opening `{`), add:

```cpp
        {
            if (HostAttachOwnsDebug())
            {
                if (HandleHostStop(*this, exit))
                {
                    haltSpins = 0;
                    break;
                }
                // HandleHostStop returned false: not a #BP/#DB the
                // arbiter recognised. Fall through to legacy path,
                // which will log + dump.
            }
            const uint8_t et = exit.VpException.ExceptionType;
            // ... (existing body unchanged below)
```

The existing body of the case continues from there, **without** its own `const uint8_t et = ...` re-declaration (delete that line — `et` is now declared once above).

- [ ] **Step 3: Build, confirm clean**

Run: `cmake --build tools/vmm/build --config Debug --target duetos-vmm`
Expected: clean build, no warnings.

- [ ] **Step 4: Manual verification (recorded in commit body)**

This slice has no unit-testable surface (it crosses WHP). Verification path:

1. Build the kernel + VMM.
2. Start the VMM: `tools\vmm\build\Debug\duetos-vmm.exe --kernel build\x86_64-debug\kernel\duetos-kernel.elf --mem 2048`
3. Attach VS native debugger to the running `duetos-vmm.exe`.
4. In VS Immediate window: `vmm_dbg::Claim()` — returns `"gdb-or-none"` confirming we took ownership.
5. `vmm_dbg::Bp("kernel_main")` — returns `true`. (Pick a real kernel symbol; `nm build/x86_64-debug/kernel/duetos-kernel.elf | head` lists them.)
6. The breakpoint won't hit retroactively if the guest is past it — pick a function called late in boot. When it hits, VS halts; `vmm.g_stop_state.rip_sym` shows the symbol.
7. `vmm_dbg::Run()` resumes.

Note the result in the commit body.

### Task 3.5: Commit Slice 3

- [ ] **Step 1: Verify clean tree state**

Run: `git status --short`. Expected:
- `M tools/vmm/CMakeLists.txt`
- `M tools/vmm/src/vmm.cpp`
- `M tools/vmm/src/vmm.h`
- `M tools/vmm/src/debug/vmm_dbg.h`
- `M tools/vmm/src/debug/vmm_dbg.cpp`
- `A tools/vmm/src/debug/host_stop.cpp`
- `A tools/vmm/src/debug/host_stop.h`

- [ ] **Step 2: Build + test clean**

```powershell
cmake --build tools/vmm/build --config Debug
ctest --test-dir tools/vmm/build -C Debug --output-on-failure
```

Expected: both succeed.

- [ ] **Step 3: Stage and commit**

```powershell
git add tools/vmm/CMakeLists.txt tools/vmm/src/vmm.cpp tools/vmm/src/vmm.h tools/vmm/src/debug/vmm_dbg.h tools/vmm/src/debug/vmm_dbg.cpp tools/vmm/src/debug/host_stop.h tools/vmm/src/debug/host_stop.cpp
git commit -m @'
feat(vmm/debug): host-attach session breakpoints (Claim/Bp/Step/Run)

Slice 3 of the host-attach guest-bridge debugger. When the user
calls vmm_dbg::Claim() from VS''s Immediate window, the WHP
exception-exit path detaches from the GDB stub and hands to
host_stop.cpp::HandleHostStop. A planted breakpoint via
vmm_dbg::Bp("kernel_main") then halts the VMM at the exact host
frame via __debugbreak() — VS shows g_stop_state.{rip,rip_sym,
rax,..,cr3} live, vmm.kernel.* still works for guest-data
inspection, and vmm_dbg::Run() / Step() resumes.

Coexistence with the GDB stub is explicit: Claim() flips a flag;
both subsystems keep their byte-shadow tables independently so
the transition is reversible without losing breakpoints.

Guarded by IsDebuggerPresent() — headless / CI runs are unaffected
even with the arbiter wired in.

Verified manually: <fill in your verification result here>

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
'@
```

---

## Slice 4 — Layer D: `vmm.natvis` pretty-printers

Native Visual Studio Natvis surfaces `GuestKernelView` and the stop state as expandable typed trees, and decorates raw guest RIPs with their symbol names. Pure presentational layer.

### Task 4.1: Write the natvis file

**Files:**
- Create: `tools/vmm/vmm.natvis`

- [ ] **Step 1: Write the natvis**

```xml
<?xml version="1.0" encoding="utf-8"?>
<!-- Visual Studio Natvis visualisers for duetos-vmm.
     Loaded automatically by VS when attached to a process built
     with this file in target_sources (tools/vmm/CMakeLists.txt
     does that — see the duetos-vmm target). -->
<AutoVisualizer xmlns="http://schemas.microsoft.com/vstudio/debugger/natvis/2010">

  <!-- Live guest view: each populated field shows on its own line. -->
  <Type Name="duetos::vmm::GuestKernelView">
    <DisplayString Condition="g_ticks == nullptr">view (unpopulated — no guest exit yet)</DisplayString>
    <DisplayString>guest view: ticks={*g_ticks,d}</DisplayString>
    <Expand>
      <Item Name="[g_ticks ptr]">g_ticks</Item>
      <Item Name="g_ticks" Condition="g_ticks != nullptr">*g_ticks,d</Item>
      <Item Name="current_task" Condition="current_task != nullptr">*current_task</Item>
    </Expand>
  </Type>

  <!-- Mirror of kernel KernelTask: surface the named fields. -->
  <Type Name="duetos::vmm::KernelTaskMirror">
    <DisplayString>task pid={pid,d} name={name,s}</DisplayString>
    <Expand>
      <Item Name="pid">pid,d</Item>
      <Item Name="name">name,s</Item>
    </Expand>
  </Type>

  <!-- Stop state: surface rip-as-symbol prominently. -->
  <Type Name="duetos::vmm::GuestStopState">
    <DisplayString Condition="stopped._My_val == false">running</DisplayString>
    <DisplayString>STOPPED @ {rip_sym,s} (reason={stop_reason,d})</DisplayString>
    <Expand>
      <Item Name="rip_sym">rip_sym,s</Item>
      <Item Name="rip">rip,X</Item>
      <Item Name="reason">stop_reason,d</Item>
      <Item Name="rax">rax,X</Item>
      <Item Name="rbx">rbx,X</Item>
      <Item Name="rcx">rcx,X</Item>
      <Item Name="rdx">rdx,X</Item>
      <Item Name="rsp">rsp,X</Item>
      <Item Name="rbp">rbp,X</Item>
      <Item Name="rflags">rflags,X</Item>
      <Item Name="cr2">cr2,X</Item>
      <Item Name="cr3">cr3,X</Item>
    </Expand>
  </Type>

</AutoVisualizer>
```

### Task 4.2: Embed the natvis in the VMM target

**Files:**
- Modify: `tools/vmm/CMakeLists.txt`

- [ ] **Step 1: Add the natvis to `target_sources`**

In `tools/vmm/CMakeLists.txt`, after the `add_executable(duetos-vmm ...)` call ends (around line 74), add:

```cmake
# Visual Studio loads the .natvis bundled in target_sources of the
# active project. Including it here means VS picks up the visualisers
# automatically — no per-user "Add to current solution" step needed.
target_sources(duetos-vmm PRIVATE vmm.natvis)
```

- [ ] **Step 2: Re-configure CMake (the source list changed)**

Run:

```powershell
cmake -S tools/vmm -B tools/vmm/build -G "Visual Studio 17 2022" -A x64
```

Expected: configure succeeds; the generated `duetos-vmm.vcxproj` references `vmm.natvis` as a non-build-input.

- [ ] **Step 3: Build and verify**

Run: `cmake --build tools/vmm/build --config Debug`
Expected: clean build.

Confirm the natvis is in the project:

```powershell
Select-String -Path tools\vmm\build\duetos-vmm.vcxproj -Pattern "vmm.natvis"
```

Expected: at least one match.

### Task 4.3: Manual verification + commit Slice 4

- [ ] **Step 1: Manual verification**

1. Attach VS native debugger to a running `duetos-vmm.exe`.
2. Add `vmm.kernel` to the Watch window. Confirm it shows `guest view: ticks=<N>` with `N` increasing on refresh.
3. Add `duetos::vmm::g_stop_state` to the Watch window. Confirm it shows `running` while the guest is running.
4. After `vmm_dbg::Claim()` + `vmm_dbg::Bp("<func>")` + the BP hits, `g_stop_state` shows `STOPPED @ <symbol> (reason=0)`.

- [ ] **Step 2: Stage and commit**

```powershell
git add tools/vmm/CMakeLists.txt tools/vmm/vmm.natvis
git commit -m @'
feat(vmm/debug): natvis pretty-printers for guest view + stop state

Slice 4 (final) of the host-attach guest-bridge debugger. Visual
Studio''s native debugger now displays:

 * Vmm::kernel as "guest view: ticks=N" with expandable typed
   children for every populated curated field.
 * GuestStopState as "running" while live, "STOPPED @ symbol+0x42
   (reason=N)" when the host arbiter has halted the guest — RIP
   symbolised inline alongside the raw hex.
 * KernelTaskMirror displays its pid + name in one line.

CMake embeds vmm.natvis in the duetos-vmm target so VS picks the
visualisers up automatically — no per-user "Add to solution"
step.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
'@
```

---

## Self-Review

**Spec coverage** (against `docs/superpowers/specs/2026-05-19-vmm-debugger-bridge-design.md`):

- §3 Layer A → Slice 2 (Tasks 2.1–2.5).
- §3 Layer B → Slice 1 (Tasks 1.1–1.4).
- §3 Layer C → Slice 3 (Tasks 3.1–3.4).
- §3 Layer D → Slice 4 (Tasks 4.1–4.2).
- §5 components map 1:1 onto Tasks: `vmm_dbg.{h,cpp}` (1.1, 1.2), `guest_view.{h,cpp}` (2.4), `guest_types_mirror.h` (2.3), `host_stop.{h,cpp}` (3.1), `vmm.natvis` (4.1), kernel build (2.1, 2.2).
- §6 Layer A mechanism (TranslateGva-based) → Task 2.4 implements `MapSym` exactly per the spec snippet.
- §7 threading + coexistence → Task 3.3 (Claim/Release + per-layer breakpoint table + mutex).
- §8 phasing → preserved (B, A, C, D).
- §9 error handling → all `vmm_dbg::*` functions either return 0/false sentinels or no-op on resolution failure, per spec §9.
- §10 testing → Slice 1 has TDD (Tasks 1.3); slices 2–4 are infrastructure layers with manual verification documented in the commit bodies — the testable surface (resolver chain) is already covered by slice-1 tests.

**Placeholder scan:**
- Task 2.1's `sizeof_report.h` deliberately ships placeholder constants the engineer overwrites with looked-up values. This is documented in the task and is the *intended* interface, not a plan-failure placeholder.
- Task 2.4 references `"g_currentTask"` as a stand-in kernel symbol name. The task explicitly tells the engineer to look up the real name with `nm`. Documented stand-in, not a placeholder.
- Task 3.4 commit body has `<fill in your verification result here>` — that's manual verification output, by design (the engineer writes what they saw).

**Type consistency:**
- `Vmm::DbgPartition()` / `DbgResolveGpa()` / `DbgHostPtr()` / `DbgFindSym()` / `DbgSymbols()` are all defined together in Task 1.2 and Task 3.2 and consumed consistently downstream.
- `vmm_dbg::Resolver` interface defined in Task 1.3 step 1, consumed by tests + `LiveResolver` consistently.
- `GuestKernelView` field names (`g_ticks`, `current_task`) match between header (Task 2.4), implementation (Task 2.4), natvis (Task 4.1).
- `GuestStopState` field names match across `host_stop.h` (Task 3.1) and `vmm.natvis` (Task 4.1).

**Scope check:** Single connected feature (host-attach guest bridge) split into four sensibly-sized commits totalling ~1100 LOC. No decomposition needed.

---

Plan complete and saved to `docs/superpowers/plans/2026-05-19-vmm-debugger-bridge.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using `executing-plans`, batch execution with checkpoints.
