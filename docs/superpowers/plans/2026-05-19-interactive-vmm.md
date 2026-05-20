# Interactive duetos-vmm Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the headless serial-only WHP `duetos-vmm.exe` into an interactive VM: a Win32 window rendering the DuetOS desktop, PS/2 keyboard+mouse, ISO9660 direct-boot, a native tabbed control dialog, and non-blocking VS GDB attach — all VMM-side, zero kernel changes.

**Architecture:** The kernel already requests a multiboot2 framebuffer (tag type 5) but the VMM shim never emits the framebuffer *info* tag (type 8). Emitting tag 8 pointing at a reserved guest-RAM region, then blitting that host-mapped memory to a Win32 window, gives graphics with no device emulation. PS/2 input via an emulated i8042. A `control/vmm_control` core is the single tested setter/getter API that both the Win32 dialog and the existing gdb `monitor` channel are thin views over.

**Tech Stack:** C++20, MSVC, Windows Hypervisor Platform, Win32 (user32/gdi32/comctl32), CMake (standalone `tools/vmm` project, VS 2022 generator). Build: `cmake --build tools\vmm\build --config Debug`. Kernel ELF/ISO produced in WSL (`/root/source/DuetOS`, branch `build-iso`).

**Reference spec:** `docs/superpowers/specs/2026-05-19-interactive-vmm-design.md`

---

## Conventions used by every task

- **Build command (Windows PowerShell):**
  `cmake --build C:\Users\natew\source\repos\DuetOS\tools\vmm\build --config Debug 2>&1 | Select-String -Pattern "error|warning|duetos-vmm.exe"`
  Expected on success: only the `duetos-vmm.exe ->` link line, **no `warning` / `error`** (project is `/W4`; treat any warning as a failure per repo zero-warning standard).
- **Configure (only after CMakeLists edits):**
  `cmake -S C:\Users\natew\source\repos\DuetOS\tools\vmm -B C:\Users\natew\source\repos\DuetOS\tools\vmm\build -G "Visual Studio 17 2022" -A x64`
- **Host unit tests** run via a new CTest target `vmm-tests` (Task 1). Run:
  `ctest --test-dir C:\Users\natew\source\repos\DuetOS\tools\vmm\build -C Debug --output-on-failure`
- **Kernel ELF for integration** (already built, branch `build-iso`):
  staged to `C:\Users\natew\source\repos\DuetOS\build\x86_64-debug\kernel\duetos-kernel.elf`
  (re-stage with: `wsl -- bash -lc "cp ~/source/DuetOS/build/x86_64-debug/kernel/duetos-kernel.elf /mnt/c/Users/natew/source/repos/DuetOS/build/x86_64-debug/kernel/"`).
- **ISO for integration:** stage with
  `wsl -- bash -lc "cp ~/source/DuetOS/build/x86_64-release/duetos.iso /mnt/c/Users/natew/source/repos/DuetOS/build/x86_64-release/"`
- **Commit discipline:** every task ends with a commit on branch `claude/interactive-vmm`. Use `git -c commit.gpgsign=false commit`. End messages with `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.
- **Steps marked `[INTEGRATION]`** are verified by running the VMM and observing the window/serial, not by a unit test (the spec mandates manual integration for Win32/WHP glue). Steps marked `[TDD]` have a failing-test-first cycle.

## File map (created / modified)

| Path | New? | Responsibility |
|---|---|---|
| `tools/vmm/src/multiboot2.h` / `.cpp` | mod | Add `Mb2Params` fb fields + emit framebuffer info tag (type 8) |
| `tools/vmm/src/guest_memory.h` / `.cpp` | mod | Reserve a page-aligned FB region near top of RAM; expose host ptr + GPA; mark reserved in mmap |
| `tools/vmm/src/display/window.h` / `.cpp` | new | Win32 window, message pump, `StretchDIBits` blit, menu/hotkeys, input event sink |
| `tools/vmm/src/devices/ps2_i8042.h` / `.cpp` | new | i8042 controller: ports 0x60/0x64, kbd+aux FIFOs, IRQ1/IRQ12 |
| `tools/vmm/src/input/ps2_encode.h` / `.cpp` | new | Pure functions: Win32 VK → scan-set-2 bytes; mouse delta/buttons → PS/2 packet |
| `tools/vmm/src/loader/iso9660.h` / `.cpp` | new | Read-only ISO9660(+Joliet) walk → kernel ELF span + grub.cfg cmdline |
| `tools/vmm/src/control/vmm_control.h` / `.cpp` | new | Shared typed get/set/action core + state; no Win32/WHP includes |
| `tools/vmm/src/ui/settings_dialog.h` / `.cpp` | new | Modeless tabbed Win32 dialog over `vmm_control` |
| `tools/vmm/src/vmm.h` / `.cpp` | mod | UI thread, PS/2 member, `HandleIoPort` 0x60/0x64, control wiring, vCPU request flags |
| `tools/vmm/src/main.cpp` | mod | New CLI flags |
| `tools/vmm/CMakeLists.txt` | mod | New sources, link `user32 gdi32 comctl32`, add `vmm-tests` CTest |
| `tools/vmm/tests/*` | new | Host unit tests (no WHP/Win32) |
| `launch.vs.json` | mod | Attach config passes `--gdb-wait` |
| `tools/vmm/vs-start-vmm.ps1` | mod | Default to windowed run; `-GdbWait` switch |
| `wiki/tooling/*` + `wiki/reference/Roadmap.md` | mod | Document the tool; retire roadmap item if present |

---

## Phase 0 — Scaffolding

### Task 1: Test harness + empty modules, build green

**Files:**
- Modify: `tools/vmm/CMakeLists.txt`
- Create: `tools/vmm/tests/CMakeLists.txt`
- Create: `tools/vmm/tests/test_main.cpp`
- Create: `tools/vmm/tests/test_smoke.cpp`

- [ ] **Step 1: Add a tiny assertion-based test runner**

`tools/vmm/tests/test_main.cpp`:
```cpp
// Minimal no-dependency test runner. Each TEST() registers itself;
// main() runs all and reports. Keeps the VMM dependency-light (no
// gtest). A failing CHECK aborts the test with a nonzero exit.
#include "test_main.h"
#include <cstdio>
#include <vector>

namespace vmmtest
{
std::vector<Case>& Registry()
{
    static std::vector<Case> r;
    return r;
}
} // namespace vmmtest

int main()
{
    int failed = 0;
    for (auto& c : vmmtest::Registry())
    {
        try
        {
            c.fn();
            std::printf("[ PASS ] %s\n", c.name);
        }
        catch (const std::exception& e)
        {
            std::printf("[ FAIL ] %s : %s\n", c.name, e.what());
            ++failed;
        }
    }
    std::printf("%d test(s), %d failed\n",
                (int)vmmtest::Registry().size(), failed);
    return failed ? 1 : 0;
}
```

- [ ] **Step 2: Add the test header**

`tools/vmm/tests/test_main.h`:
```cpp
#pragma once
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace vmmtest
{
struct Case
{
    const char*           name;
    std::function<void()> fn;
};
std::vector<Case>& Registry();

struct Reg
{
    Reg(const char* n, std::function<void()> f)
    {
        Registry().push_back({n, std::move(f)});
    }
};
} // namespace vmmtest

#define TEST(name)                                                       \
    static void name();                                                  \
    static vmmtest::Reg reg_##name(#name, name);                         \
    static void name()

#define CHECK(cond)                                                      \
    do                                                                   \
    {                                                                    \
        if (!(cond))                                                     \
            throw std::runtime_error(std::string("CHECK failed: " #cond  \
                                                 " @ ") +                \
                                     __FILE__ + ":" +                    \
                                     std::to_string(__LINE__));          \
    } while (0)

#define CHECK_EQ(a, b)                                                   \
    do                                                                   \
    {                                                                    \
        auto _va = (a);                                                  \
        auto _vb = (b);                                                  \
        if (!(_va == _vb))                                               \
            throw std::runtime_error(std::string("CHECK_EQ failed: " #a  \
                                                 " == " #b " @ ") +      \
                                     __FILE__ + ":" +                    \
                                     std::to_string(__LINE__));          \
    } while (0)
```

- [ ] **Step 3: Add a smoke test**

`tools/vmm/tests/test_smoke.cpp`:
```cpp
#include "test_main.h"

TEST(smoke_runner_works)
{
    CHECK(1 + 1 == 2);
    CHECK_EQ(42, 40 + 2);
}
```

- [ ] **Step 4: Wire a test executable + CTest into CMake**

`tools/vmm/tests/CMakeLists.txt`:
```cmake
# Host unit tests for VMM logic units that have NO WHP/Win32
# dependency (mb2 builder, iso9660, ps2 encode, vmm_control).
# Sources are added incrementally as tasks land them.
add_executable(vmm-tests
    test_main.cpp
    test_smoke.cpp
)
target_include_directories(vmm-tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_SOURCE_DIR})
if(MSVC)
    target_compile_options(vmm-tests PRIVATE /W4 /permissive- /EHsc)
    target_compile_definitions(vmm-tests PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME vmm-tests COMMAND vmm-tests)
```

Append to the end of `tools/vmm/CMakeLists.txt`:
```cmake
enable_testing()
add_subdirectory(tests)
```

- [ ] **Step 5: Configure + build + run tests**

Run:
```
cmake -S C:\Users\natew\source\repos\DuetOS\tools\vmm -B C:\Users\natew\source\repos\DuetOS\tools\vmm\build -G "Visual Studio 17 2022" -A x64
cmake --build C:\Users\natew\source\repos\DuetOS\tools\vmm\build --config Debug
ctest --test-dir C:\Users\natew\source\repos\DuetOS\tools\vmm\build -C Debug --output-on-failure
```
Expected: build clean (no warnings/errors); ctest `100% tests passed, 0 tests failed out of 1`.

- [ ] **Step 6: Commit**
```
git add tools/vmm/CMakeLists.txt tools/vmm/tests
git -c commit.gpgsign=false commit -m "test(vmm): add dependency-light host test runner + CTest

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase 1 — Framebuffer (see the desktop)

### Task 2: Multiboot2 framebuffer info tag (type 8)  `[TDD]`

**Background:** MB2 tag type 8 layout (per Multiboot2 spec, all little-endian):
`u32 type=8; u32 size; u64 framebuffer_addr; u32 framebuffer_pitch; u32 framebuffer_width; u32 framebuffer_height; u8 framebuffer_bpp; u8 framebuffer_type; u8 reserved; ` then for `framebuffer_type==1` (direct RGB): `u8 red_field_position; u8 red_mask_size; u8 green_field_position; u8 green_mask_size; u8 blue_field_position; u8 blue_mask_size;`. Tag is padded to 8-byte alignment. For BGRA 32bpp (`StretchDIBits`-native, blue at bit 0): red_pos=16,green_pos=8,blue_pos=0, each mask size 8.

**Files:**
- Modify: `tools/vmm/src/multiboot2.h`
- Modify: `tools/vmm/src/multiboot2.cpp`
- Create: `tools/vmm/tests/test_mb2_fb.cpp`
- Modify: `tools/vmm/tests/CMakeLists.txt` (add source), `tools/vmm/CMakeLists.txt` (mb2 already compiled in main exe; tests need `../src/multiboot2.cpp`)

- [ ] **Step 1: Extend `Mb2Params` with framebuffer fields**

In `tools/vmm/src/multiboot2.h`, add to `struct Mb2Params` (after `rsdp`):
```cpp
    // Framebuffer (multiboot2 tag 8). Emitted only when fbAddr != 0.
    // 32bpp BGRA (blue at bit 0) so the host StretchDIBits path needs
    // no per-pixel swizzle.
    uint64_t fbAddr   = 0;
    uint32_t fbPitch  = 0; // bytes per scanline
    uint32_t fbWidth  = 0;
    uint32_t fbHeight = 0;
    uint8_t  fbBpp    = 32;
```

- [ ] **Step 2: Write the failing golden-bytes test**

`tools/vmm/tests/test_mb2_fb.cpp`:
```cpp
#include "test_main.h"
#include "multiboot2.h"
#include <cstring>

using duetos::vmm::BuildMultiboot2Info;
using duetos::vmm::Mb2Params;

// Locate the first tag of `type` inside a serialized MB2 info blob.
// MB2 info: u32 total_size; u32 reserved; then 8-byte-aligned tags,
// each u32 type; u32 size; ... ; terminated by type=0.
static const uint8_t* FindTag(const std::vector<uint8_t>& b, uint32_t type, uint32_t& sz)
{
    size_t off = 8;
    while (off + 8 <= b.size())
    {
        uint32_t t, s;
        std::memcpy(&t, &b[off], 4);
        std::memcpy(&s, &b[off + 4], 4);
        if (t == 0) return nullptr;
        if (t == type) { sz = s; return &b[off]; }
        off += (s + 7) & ~size_t(7);
    }
    return nullptr;
}

TEST(mb2_emits_framebuffer_tag_when_fb_set)
{
    Mb2Params p;
    p.cmdline     = "boot=desktop";
    p.ramBytes    = 512ull * 1024 * 1024;
    p.reservedEnd = 0x200000;
    p.fbAddr      = 0x1F000000;
    p.fbWidth     = 1280;
    p.fbHeight    = 1024;
    p.fbPitch     = 1280 * 4;
    p.fbBpp       = 32;

    auto blob = BuildMultiboot2Info(p);
    uint32_t sz = 0;
    const uint8_t* tag = FindTag(blob, 8, sz);
    CHECK(tag != nullptr);
    // type(4)+size(4)+addr(8)+pitch(4)+w(4)+h(4)+bpp(1)+fbtype(1)
    // +rsvd(1)+6 color bytes = 38, padded to 40.
    CHECK_EQ(sz, 38u);
    uint64_t addr;
    uint32_t pitch, w, h;
    std::memcpy(&addr, tag + 8, 8);
    std::memcpy(&pitch, tag + 16, 4);
    std::memcpy(&w, tag + 20, 4);
    std::memcpy(&h, tag + 24, 4);
    CHECK_EQ(addr, 0x1F000000ull);
    CHECK_EQ(pitch, 1280u * 4);
    CHECK_EQ(w, 1280u);
    CHECK_EQ(h, 1024u);
    CHECK_EQ((uint32_t)tag[28], 32u);          // bpp
    CHECK_EQ((uint32_t)tag[29], 1u);           // framebuffer_type = direct RGB
    CHECK_EQ((uint32_t)tag[31], 16u);          // red_field_position
    CHECK_EQ((uint32_t)tag[33], 8u);           // green_field_position
    CHECK_EQ((uint32_t)tag[35], 0u);           // blue_field_position
}

TEST(mb2_omits_framebuffer_tag_when_unset)
{
    Mb2Params p;
    p.ramBytes = 64ull * 1024 * 1024;
    auto blob  = BuildMultiboot2Info(p);
    uint32_t sz = 0;
    CHECK(FindTag(blob, 8, sz) == nullptr);
}
```

- [ ] **Step 3: Add the test source + compile mb2 into the test binary**

In `tools/vmm/tests/CMakeLists.txt`, add to the `add_executable(vmm-tests ...)` list:
```cmake
    test_mb2_fb.cpp
    ../src/multiboot2.cpp
```

- [ ] **Step 4: Build the test, watch it fail**

Run: `cmake --build C:\Users\natew\source\repos\DuetOS\tools\vmm\build --config Debug` then `ctest --test-dir ...\build -C Debug --output-on-failure`
Expected: `mb2_emits_framebuffer_tag_when_fb_set` FAILs (`tag != nullptr` throws) — the builder doesn't emit tag 8 yet.

- [ ] **Step 5: Emit tag 8 in `BuildMultiboot2Info`**

In `tools/vmm/src/multiboot2.cpp`, locate where existing tags are appended (there is a local `append`/`push` helper and an 8-byte align step per tag). **Immediately before the end tag (type 0) is written**, insert:
```cpp
    // Framebuffer info tag (type 8). The kernel's boot.S requests a
    // framebuffer (MB2 header tag 5) and framebuffer.cpp treats a
    // missing tag 8 as "no graphics" — emitting this is what makes
    // the guest render. 32bpp direct-RGB, BGRA channel order so the
    // host StretchDIBits blit is a straight copy.
    if (p.fbAddr != 0)
    {
        const uint32_t tagSize = 38; // see test for byte layout
        size_t base = out.size();
        auto u32 = [&](uint32_t v) {
            for (int i = 0; i < 4; ++i) out.push_back(uint8_t(v >> (8 * i)));
        };
        auto u64 = [&](uint64_t v) {
            for (int i = 0; i < 8; ++i) out.push_back(uint8_t(v >> (8 * i)));
        };
        u32(8);
        u32(tagSize);
        u64(p.fbAddr);
        u32(p.fbPitch);
        u32(p.fbWidth);
        u32(p.fbHeight);
        out.push_back(p.fbBpp); // framebuffer_bpp
        out.push_back(1);       // framebuffer_type = direct RGB
        out.push_back(0);       // reserved
        out.push_back(16); out.push_back(8); // red   pos,size
        out.push_back(8);  out.push_back(8); // green pos,size
        out.push_back(0);  out.push_back(8); // blue  pos,size
        while ((out.size() - base) % 8 != 0) out.push_back(0); // align next tag
    }
```
> If the existing serializer uses a different accumulator name than `out`, adapt these three lines (`out` references) to it. The accumulator is the `std::vector<uint8_t>` returned at the end of `BuildMultiboot2Info`. Do not change existing tags.

- [ ] **Step 6: Build + test green**

Run build + ctest. Expected: both `mb2_*` tests PASS, all prior tests still PASS, no warnings.

- [ ] **Step 7: Commit**
```
git add tools/vmm/src/multiboot2.h tools/vmm/src/multiboot2.cpp tools/vmm/tests
git -c commit.gpgsign=false commit -m "feat(vmm): emit multiboot2 framebuffer info tag (type 8)

The kernel requests a framebuffer (boot.S MB2 header tag 5) but the
shim never wrote back tag 8, so the desktop had nowhere to draw.
32bpp BGRA direct-RGB. Golden-bytes test.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task 3: Reserve a guest-RAM framebuffer region  `[TDD]`

**Files:**
- Modify: `tools/vmm/src/guest_memory.h`
- Modify: `tools/vmm/src/guest_memory.cpp`
- Create: `tools/vmm/tests/test_fb_region.cpp`
- Modify: `tools/vmm/tests/CMakeLists.txt`

- [ ] **Step 1: Add an FB-region API to `GuestMemory`**

In `tools/vmm/src/guest_memory.h`, add public methods to the `GuestMemory` class (signatures only; keep style consistent with the file):
```cpp
    // Carve a page-aligned framebuffer region just below the top of
    // guest RAM. Returns the guest-physical base; the host-side
    // pointer (into the WHP-mapped backing) is fetched via
    // FramebufferHost(). Idempotent: a second call with the same
    // size returns the same base. Must be called before the MB2
    // mmap is built so the region can be flagged reserved.
    uint64_t ReserveFramebuffer(uint32_t width, uint32_t height);
    uint8_t* FramebufferHost();        // nullptr if not reserved
    uint64_t FramebufferGpa() const;   // 0 if not reserved
    uint64_t FramebufferBytes() const; // 0 if not reserved
```
Add private members:
```cpp
    uint64_t m_fbGpa   = 0;
    uint64_t m_fbBytes = 0;
```

- [ ] **Step 2: Write the failing test**

`tools/vmm/tests/test_fb_region.cpp`:
```cpp
#include "test_main.h"
#include "guest_memory.h"

using duetos::vmm::GuestMemory;

TEST(fb_region_is_page_aligned_and_below_ram_top)
{
    // 64 MiB guest; reserve 1280x1024x4 = 5,242,880 bytes.
    GuestMemory gm(64ull * 1024 * 1024);
    uint64_t base = gm.ReserveFramebuffer(1280, 1024);
    CHECK(base != 0);
    CHECK_EQ(base % 4096, 0u);
    CHECK_EQ(gm.FramebufferBytes(), uint64_t(1280) * 1024 * 4);
    // Region must lie fully within guest RAM.
    CHECK(base + gm.FramebufferBytes() <= 64ull * 1024 * 1024);
    // Idempotent.
    CHECK_EQ(gm.ReserveFramebuffer(1280, 1024), base);
    // Host pointer is inside the mapped backing and writable.
    uint8_t* hp = gm.FramebufferHost();
    CHECK(hp != nullptr);
    hp[0] = 0xAB; hp[gm.FramebufferBytes() - 1] = 0xCD;
    CHECK_EQ((int)hp[0], 0xAB);
}
```
> Adjust the `GuestMemory` constructor call to the real signature in `guest_memory.h` (it may take `(uint64_t bytes)` or a config struct). If construction needs WHP, add a host-only ctor guarded by `#ifndef VMM_HOSTTEST` — but prefer using the existing host-allocatable path; `GuestMemory` allocates the backing with `VirtualAlloc` independent of WHP mapping, so a bare construction in a host test is expected to work. If it does not, this task's test instead exercises a free function `ComputeFbRegion(ramBytes,w,h) -> {gpa,bytes}` that `ReserveFramebuffer` calls, and the pointer assertions move to `[INTEGRATION]` in Task 5.

- [ ] **Step 3: Add the test source**

`tools/vmm/tests/CMakeLists.txt` add: `test_fb_region.cpp` and `../src/guest_memory.cpp` (only if it has no WHP link dependency; otherwise use the `ComputeFbRegion` free-function fallback from Step 2's note and add only that).

- [ ] **Step 4: Build → fail** (`ReserveFramebuffer` unresolved/returns 0).

- [ ] **Step 5: Implement**

In `tools/vmm/src/guest_memory.cpp`:
```cpp
uint64_t GuestMemory::ReserveFramebuffer(uint32_t width, uint32_t height)
{
    uint64_t bytes = uint64_t(width) * height * 4;
    bytes = (bytes + 0xFFF) & ~uint64_t(0xFFF);          // page round-up
    if (m_fbGpa != 0)
        return m_fbGpa;                                  // idempotent
    // Place just below the top of RAM, page-aligned.
    uint64_t top = RamBytes();                           // existing accessor
    uint64_t gpa = (top - bytes) & ~uint64_t(0xFFF);
    m_fbGpa   = gpa;
    m_fbBytes = bytes;
    return m_fbGpa;
}
uint8_t* GuestMemory::FramebufferHost()
{
    return m_fbGpa ? HostPtr(m_fbGpa) : nullptr;          // existing GPA->host
}
uint64_t GuestMemory::FramebufferGpa() const   { return m_fbGpa; }
uint64_t GuestMemory::FramebufferBytes() const { return m_fbBytes; }
```
> Use the file's existing RAM-size accessor and GPA→host translator. If they are named differently (e.g. `size()` / `at(gpa)`), substitute those exact names. Do not add new ones if equivalents exist.

- [ ] **Step 6: Mark the FB region reserved in the MB2 memory map**

Find where `Mb2Params::reservedEnd` / the e820 mmap is populated for the VMM (in `vmm.cpp` where `BuildMultiboot2Info` is called). The FB sits high in RAM, so `reservedEnd` (which protects `[0, reservedEnd)`) does not cover it. In `multiboot2.cpp`, in the mmap tag (type 6) emission, after the normal "available" RAM entry, **split out the FB span as a reserved (type 2) entry** when `p.fbAddr != 0`:
```cpp
    // FB region carved from the top of RAM: advertise [0,fbAddr) as
    // available and [fbAddr, fbAddr+fbBytes) as reserved so the
    // kernel frame allocator never hands the scanout buffer out.
```
Implement the split in the existing mmap-entry loop: where one big available entry spanned `[reservedEnd, ramTop)`, instead emit `[reservedEnd, fbAddr)` available + `[fbAddr, fbAddr+fbBytes)` reserved. Keep the existing low reserved entry untouched.

- [ ] **Step 7: Build + test green. Commit**
```
git add tools/vmm/src/guest_memory.h tools/vmm/src/guest_memory.cpp tools/vmm/src/multiboot2.cpp tools/vmm/tests
git -c commit.gpgsign=false commit -m "feat(vmm): reserve a guest-RAM framebuffer region + mark it reserved in MB2 mmap

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task 4: Win32 framebuffer window + UI thread  `[INTEGRATION]`

**Files:**
- Create: `tools/vmm/src/display/window.h`
- Create: `tools/vmm/src/display/window.cpp`
- Modify: `tools/vmm/CMakeLists.txt` (add sources; link `user32 gdi32`)

- [ ] **Step 1: Window interface**

`tools/vmm/src/display/window.h`:
```cpp
#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <thread>

namespace duetos::vmm
{
// A Win32 top-level window that scans out a host-side 32bpp BGRA
// framebuffer. Runs its own thread (Win32 requires the message pump
// on the window's creating thread). Input is delivered to caller-
// supplied sinks. Lockless FB read (tearing acceptable for a dev
// viewer).
struct InputSink
{
    std::function<void(uint32_t vk, bool down, bool extended)> onKey;
    std::function<void(int dx, int dy, uint32_t buttons, int wheel)> onMouse;
};

class FbWindow
{
public:
    // fb/pitch/w/h describe the host-mapped guest framebuffer.
    // onClose is invoked (once) when the user closes the window.
    bool Start(uint8_t* fb, uint32_t pitch, uint32_t w, uint32_t h,
               const char* title, InputSink sink,
               std::function<void()> onClose);
    void Stop();
    void SetTitle(const char* s);
    bool Minimized() const { return m_minimized.load(); }
    ~FbWindow();

private:
    void ThreadMain(const char* title);
    std::thread          m_thread;
    std::atomic<bool>    m_run{false};
    std::atomic<bool>    m_minimized{true};
    uint8_t*             m_fb = nullptr;
    uint32_t             m_pitch = 0, m_w = 0, m_h = 0;
    InputSink            m_sink;
    std::function<void()> m_onClose;
    void*                m_hwnd = nullptr; // HWND (opaque here)
};
} // namespace duetos::vmm
```

- [ ] **Step 2: Add inline accessors to `FbWindow` (window.h)**

Add to the `public:` section of `class FbWindow` in `window.h` (these are what `WndProc` reads — no placeholders):
```cpp
    uint8_t*         Fb()    { return m_fb; }
    uint32_t         W()     const { return m_w; }
    uint32_t         H()     const { return m_h; }
    const InputSink& Sink()  const { return m_sink; }
    void             FireClose() { if (m_onClose) m_onClose(); }
    void*            Hwnd()  const { return m_hwnd; }
```

- [ ] **Step 3: Complete window implementation (one file, no placeholders)**

`tools/vmm/src/display/window.cpp`:
```cpp
#include "display/window.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstring>

namespace duetos::vmm
{
static FbWindow* g_self = nullptr; // one VMM window per process

static uint32_t MouseButtons(WPARAM w)
{
    uint32_t b = 0;
    if (w & MK_LBUTTON) b |= 1;
    if (w & MK_RBUTTON) b |= 2;
    if (w & MK_MBUTTON) b |= 4;
    return b;
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    FbWindow* s = g_self;
    static int lastX = -1, lastY = -1;
    switch (m)
    {
    case WM_TIMER:
        if (s && !IsIconic(h))
        {
            BITMAPINFO bi{};
            bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
            bi.bmiHeader.biWidth       = (LONG)s->W();
            bi.bmiHeader.biHeight      = -(LONG)s->H(); // top-down
            bi.bmiHeader.biPlanes      = 1;
            bi.bmiHeader.biBitCount    = 32;
            bi.bmiHeader.biCompression = BI_RGB;
            RECT cr;
            GetClientRect(h, &cr);
            HDC dc = GetDC(h);
            StretchDIBits(dc, 0, 0, cr.right, cr.bottom, 0, 0,
                          s->W(), s->H(), s->Fb(), &bi,
                          DIB_RGB_COLORS, SRCCOPY);
            ReleaseDC(h, dc);
        }
        return 0;
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
        if (s) s->Sink().onKey((uint32_t)w, true,  (l >> 24) & 1);
        return 0;
    case WM_KEYUP:
    case WM_SYSKEYUP:
        if (s) s->Sink().onKey((uint32_t)w, false, (l >> 24) & 1);
        return 0;
    case WM_MOUSEMOVE:
    {
        int x = GET_X_LPARAM(l), y = GET_Y_LPARAM(l);
        if (lastX < 0) { lastX = x; lastY = y; }
        if (s) s->Sink().onMouse(x - lastX, y - lastY,
                                 MouseButtons(w), 0);
        lastX = x; lastY = y;
        return 0;
    }
    case WM_LBUTTONDOWN: case WM_LBUTTONUP:
    case WM_RBUTTONDOWN: case WM_RBUTTONUP:
    case WM_MBUTTONDOWN: case WM_MBUTTONUP:
        if (s) s->Sink().onMouse(0, 0, MouseButtons(w), 0);
        return 0;
    case WM_MOUSEWHEEL:
        if (s) s->Sink().onMouse(0, 0, MouseButtons(GET_KEYSTATE_WPARAM(w)),
                                 GET_WHEEL_DELTA_WPARAM(w) / WHEEL_DELTA);
        return 0;
    case WM_CLOSE:
        if (s) s->FireClose();
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

bool FbWindow::Start(uint8_t* fb, uint32_t pitch, uint32_t wd, uint32_t ht,
                     const char* title, InputSink sink,
                     std::function<void()> onClose)
{
    m_fb = fb; m_pitch = pitch; m_w = wd; m_h = ht;
    m_sink = std::move(sink); m_onClose = std::move(onClose);
    g_self = this; m_run = true;
    m_thread = std::thread(&FbWindow::ThreadMain, this, title);
    return true;
}

void FbWindow::ThreadMain(const char* title)
{
    HINSTANCE inst = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = inst;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"DuetOSVmmWindow";
    RegisterClassW(&wc);

    RECT r{0, 0, (LONG)m_w, (LONG)m_h};
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);
    wchar_t wt[256];
    MultiByteToWideChar(CP_UTF8, 0, title, -1, wt, 256);
    HWND hwnd = CreateWindowW(wc.lpszClassName, wt, WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, CW_USEDEFAULT,
                              r.right - r.left, r.bottom - r.top,
                              nullptr, nullptr, inst, nullptr);
    m_hwnd = hwnd;
    ShowWindow(hwnd, SW_SHOWMINIMIZED);  // spec: start minimized
    SetTimer(hwnd, 1, 16, nullptr);      // ~60fps blit tick

    MSG msg;
    while (m_run.load() && GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    KillTimer(hwnd, 1);
    UnregisterClassW(wc.lpszClassName, inst);
}

void FbWindow::Stop()
{
    if (!m_run.exchange(false)) return;
    if (m_hwnd) PostMessageW((HWND)m_hwnd, WM_CLOSE, 0, 0);
    if (m_thread.joinable()) m_thread.join();
}

void FbWindow::SetTitle(const char* sIn)
{
    if (!m_hwnd) return;
    wchar_t wt[256];
    MultiByteToWideChar(CP_UTF8, 0, sIn, -1, wt, 256);
    SetWindowTextW((HWND)m_hwnd, wt);
}

FbWindow::~FbWindow() { Stop(); }
} // namespace duetos::vmm
```
> Add `#include <windowsx.h>` for `GET_X_LPARAM`/`GET_KEYSTATE_WPARAM` if the SDK requires it (it does under `WIN32_LEAN_AND_MEAN`). `m_minimized` is unused now (kept for future); `IsIconic` is the live check.

- [ ] **Step 4: CMake — add sources + libs**

In `tools/vmm/CMakeLists.txt` `add_executable(duetos-vmm ...)` add `src/display/window.cpp`. Change the link line to:
```cmake
target_link_libraries(duetos-vmm PRIVATE WinHvPlatform ws2_32 user32 gdi32)
```

- [ ] **Step 5: Build clean.** Run the standard build command. Expected: no warnings/errors; `duetos-vmm.exe` links. (No unit test — window is integration-verified in Task 5.)

- [ ] **Step 6: Commit**
```
git add tools/vmm/src/display tools/vmm/CMakeLists.txt
git -c commit.gpgsign=false commit -m "feat(vmm): Win32 framebuffer window + UI thread (minimized, StretchDIBits blit)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task 5: Wire the framebuffer into boot — first visible desktop  `[INTEGRATION]`

**Files:**
- Modify: `tools/vmm/src/vmm.h` (add `FbWindow m_window;` member + `#include "display/window.h"`)
- Modify: `tools/vmm/src/vmm.cpp`
- Modify: `tools/vmm/src/main.cpp` (add `--res WxH`, default = primary monitor)

- [ ] **Step 1: Pick resolution (monitor-matched) in `main.cpp`**

Where `VmConfig` is filled, add fields to `VmConfig` (`tools/vmm/src/vmm.h`): `uint32_t fbW=0, fbH=0; bool noWindow=false;`. In `main.cpp` arg loop add `--res` (`WxH` → `cfg.fbW/fbH`) and `--no-window` (`cfg.noWindow=true`). After arg parse, if `fbW==0`:
```cpp
    // Default to the primary monitor's current mode.
    cfg.fbW = (uint32_t)GetSystemMetrics(SM_CXSCREEN);
    cfg.fbH = (uint32_t)GetSystemMetrics(SM_CYSCREEN);
    if (cfg.fbW == 0 || cfg.fbH == 0) { cfg.fbW = 1280; cfg.fbH = 1024; }
```
(Add `#define WIN32_LEAN_AND_MEAN` + `#include <windows.h>` to `main.cpp` if not present.)

- [ ] **Step 2: Reserve FB + feed MB2 params in `Vmm`**

In `vmm.cpp`, where guest memory is created and `Mb2Params` populated (before `BuildMultiboot2Info`):
```cpp
    if (!m_cfg.noWindow)
    {
        uint64_t fbGpa = m_mem->ReserveFramebuffer(m_cfg.fbW, m_cfg.fbH);
        mb.fbAddr   = fbGpa;
        mb.fbWidth  = m_cfg.fbW;
        mb.fbHeight = m_cfg.fbH;
        mb.fbPitch  = m_cfg.fbW * 4;
        mb.fbBpp    = 32;
    }
```
(`mb` = the existing `Mb2Params` local.)

- [ ] **Step 3: Start the window before the vCPU loop**

In `Vmm::Run()` (or `StartHelperThreads`), after guest memory is mapped and before the exit loop, if `!m_cfg.noWindow`:
```cpp
    InputSink sink;            // wired for real in Task 8; no-ops for now
    sink.onKey   = [](uint32_t, bool, bool) {};
    sink.onMouse = [](int, int, uint32_t, int) {};
    m_window.Start(m_mem->FramebufferHost(), m_cfg.fbW * 4,
                   m_cfg.fbW, m_cfg.fbH, "DuetOS — booting",
                   sink, [this] { m_stop = true; });
```
In `~Vmm`/shutdown path call `m_window.Stop();`.

- [ ] **Step 4: `[INTEGRATION]` Boot and SEE the desktop**

Stage ELF (see Conventions), then run:
```
& C:\Users\natew\source\repos\DuetOS\tools\vmm\build\Debug\duetos-vmm.exe --kernel C:\Users\natew\source\repos\DuetOS\build\x86_64-debug\kernel\duetos-kernel.elf --mem 1024
```
Expected: a **minimized** taskbar entry "DuetOS — booting"; restore it → the DuetOS desktop renders (Classic theme, taskbar, cursor). Compare against the prior serial log: boot still reaches the self-tests; now `framebuffer.cpp` reports a mode instead of "no graphics". Capture a screenshot into `docs/superpowers/` evidence is NOT committed; note PASS in the commit message.
> If the window is black but serial shows the desktop composed: verify tag 8 byte layout (Task 2 test), FB GPA is inside mapped RAM and reserved (Task 3), and `biHeight` is **negative** (top-down DIB). If colors are swapped: the kernel emitted RGBX not BGRX — re-check the channel positions in Task 2 against `framebuffer.cpp`'s consumed masks and adjust both the tag and the DIB.

- [ ] **Step 5: Commit**
```
git add tools/vmm/src/vmm.h tools/vmm/src/vmm.cpp tools/vmm/src/main.cpp
git -c commit.gpgsign=false commit -m "feat(vmm): wire framebuffer scanout — DuetOS desktop renders in a window

Monitor-matched resolution, --res override, --no-window for CI.
Verified: kernel ELF boots, desktop visible. [INTEGRATION PASS]

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase 2 — PS/2 input (drive the desktop)

> **Pre-task read:** before Task 6, open `kernel/drivers/input/ps2kbd.cpp` and
> `kernel/drivers/input/ps2mouse.cpp` (WSL checkout) and record: (a) which scan
> set `ps2kbd` selects (`0xF0` arg), (b) whether `ps2mouse` performs the
> IntelliMouse `0xF3 200/100/80` knock and reads 4-byte packets. The tests below
> assume **set 2** and **IntelliMouse-on**; if the drivers differ, change the
> expected constants in Task 6's tests AND the encoder to match the drivers
> (the drivers are ground truth — never the other way around).

### Task 6: PS/2 encode pure functions  `[TDD]`

**Files:** Create `tools/vmm/src/input/ps2_encode.h` / `.cpp`; create `tools/vmm/tests/test_ps2_encode.cpp`; modify `tools/vmm/tests/CMakeLists.txt`.

- [ ] **Step 1: Header**

`tools/vmm/src/input/ps2_encode.h`:
```cpp
#pragma once
#include <cstdint>
#include <vector>

namespace duetos::vmm
{
// Win32 virtual-key (+ extended flag) -> scan-set-2 byte sequence.
// `down`=false emits the break sequence (0xF0 prefix, 0xE0 0xF0 for
// extended). Returns empty for keys with no PS/2 mapping.
std::vector<uint8_t> VkToSet2(uint32_t vk, bool down, bool extended);

// Build one PS/2 mouse movement packet. `intelliMouse` selects the
// 4-byte (Z) form. dx/dy are screen deltas (sign-clamped to 9-bit);
// buttons bit0=L bit1=R bit2=M; wheel = signed detents.
std::vector<uint8_t> MousePacket(int dx, int dy, uint32_t buttons,
                                 int wheel, bool intelliMouse);
} // namespace duetos::vmm
```

- [ ] **Step 2: Failing tests**

`tools/vmm/tests/test_ps2_encode.cpp`:
```cpp
#include "test_main.h"
#include "input/ps2_encode.h"
#include <windows.h> // VK_* constants

using namespace duetos::vmm;

TEST(set2_letter_make_break)
{
    auto mk = VkToSet2('A', true, false);   // VK 'A' == 0x41
    CHECK_EQ(mk.size(), 1u);
    CHECK_EQ((int)mk[0], 0x1C);              // set-2 make for 'A'
    auto bk = VkToSet2('A', false, false);
    CHECK_EQ(bk.size(), 2u);
    CHECK_EQ((int)bk[0], 0xF0);
    CHECK_EQ((int)bk[1], 0x1C);
}

TEST(set2_extended_key)
{
    auto mk = VkToSet2(VK_RIGHT, true, true);
    CHECK_EQ(mk.size(), 2u);
    CHECK_EQ((int)mk[0], 0xE0);
    CHECK_EQ((int)mk[1], 0x74);              // set-2 'right arrow'
    auto bk = VkToSet2(VK_RIGHT, false, true);
    CHECK_EQ(bk.size(), 3u);
    CHECK_EQ((int)bk[0], 0xE0);
    CHECK_EQ((int)bk[1], 0xF0);
    CHECK_EQ((int)bk[2], 0x74);
}

TEST(mouse_packet_3byte_basic)
{
    auto p = MousePacket(5, -3, 0x1, 0, false);
    CHECK_EQ(p.size(), 3u);
    CHECK((p[0] & 0x08) != 0);               // always-1 bit
    CHECK((p[0] & 0x01) != 0);               // left button
    CHECK_EQ((int)p[1], 5);                  // dx
    // dy is inverted (PS/2 up = positive); -3 screen => +3
    CHECK_EQ((int)(int8_t)p[2], 3);
}

TEST(mouse_packet_4byte_wheel)
{
    auto p = MousePacket(0, 0, 0, -1, true);
    CHECK_EQ(p.size(), 4u);
    CHECK_EQ((int)(int8_t)p[3], -1);         // Z byte = wheel
}
```

- [ ] **Step 3: Add sources to `tools/vmm/tests/CMakeLists.txt`**: `test_ps2_encode.cpp ../src/input/ps2_encode.cpp`. Build → fail (unresolved `VkToSet2`).

- [ ] **Step 4: Implement `ps2_encode.cpp`**

```cpp
#include "input/ps2_encode.h"
#include <unordered_map>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace duetos::vmm
{
// Minimal set-2 table covering the keys the DuetOS desktop uses
// (letters, digits, Enter, Esc, Space, Backspace, Tab, arrows,
// modifiers). Extend as integration surfaces gaps.
static const std::unordered_map<uint32_t, uint8_t>& Base()
{
    static const std::unordered_map<uint32_t, uint8_t> m = {
        {'A',0x1C},{'B',0x32},{'C',0x21},{'D',0x23},{'E',0x24},
        {'F',0x2B},{'G',0x34},{'H',0x33},{'I',0x43},{'J',0x3B},
        {'K',0x42},{'L',0x4B},{'M',0x3A},{'N',0x31},{'O',0x44},
        {'P',0x4D},{'Q',0x15},{'R',0x2D},{'S',0x1B},{'T',0x2C},
        {'U',0x3C},{'V',0x2A},{'W',0x1D},{'X',0x22},{'Y',0x35},
        {'Z',0x1A},{'0',0x45},{'1',0x16},{'2',0x1E},{'3',0x26},
        {'4',0x25},{'5',0x2E},{'6',0x36},{'7',0x3D},{'8',0x3E},
        {'9',0x46},{VK_RETURN,0x5A},{VK_ESCAPE,0x76},{VK_SPACE,0x29},
        {VK_BACK,0x66},{VK_TAB,0x0D},{VK_LSHIFT,0x12},{VK_LCONTROL,0x14},
        {VK_MENU,0x11},{VK_SHIFT,0x12},{VK_CONTROL,0x14},
    };
    return m;
}
static const std::unordered_map<uint32_t, uint8_t>& Ext()
{
    static const std::unordered_map<uint32_t, uint8_t> m = {
        {VK_RIGHT,0x74},{VK_LEFT,0x6B},{VK_UP,0x75},{VK_DOWN,0x72},
        {VK_DELETE,0x71},{VK_HOME,0x6C},{VK_END,0x69},
        {VK_PRIOR,0x7D},{VK_NEXT,0x7A},{VK_INSERT,0x70},
        {VK_RCONTROL,0x14},{VK_RMENU,0x11},
    };
    return m;
}

std::vector<uint8_t> VkToSet2(uint32_t vk, bool down, bool extended)
{
    const auto& tbl = extended ? Ext() : Base();
    auto it = tbl.find(vk);
    if (it == tbl.end()) return {};
    std::vector<uint8_t> o;
    if (extended) o.push_back(0xE0);
    if (!down)    o.push_back(0xF0);
    o.push_back(it->second);
    return o;
}

static int8_t Clamp9(int v) { return (int8_t)(v < -127 ? -127 : v > 127 ? 127 : v); }

std::vector<uint8_t> MousePacket(int dx, int dy, uint32_t buttons,
                                 int wheel, bool intelliMouse)
{
    uint8_t b0 = 0x08;                       // always-1
    if (buttons & 1) b0 |= 0x01;
    if (buttons & 2) b0 |= 0x02;
    if (buttons & 4) b0 |= 0x04;
    int8_t x = Clamp9(dx);
    int8_t y = Clamp9(-dy);                  // PS/2: +Y is up
    if (x < 0) b0 |= 0x10;
    if (y < 0) b0 |= 0x20;
    std::vector<uint8_t> p = {b0, (uint8_t)x, (uint8_t)y};
    if (intelliMouse) p.push_back((uint8_t)Clamp9(wheel));
    return p;
}
} // namespace duetos::vmm
```

- [ ] **Step 5: Build + ctest green. Commit**
```
git add tools/vmm/src/input tools/vmm/tests
git -c commit.gpgsign=false commit -m "feat(vmm): PS/2 set-2 keyboard + mouse-packet encoders (TDD)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task 7: i8042 controller device  `[TDD]`

**Files:** Create `tools/vmm/src/devices/ps2_i8042.h` / `.cpp`; create `tools/vmm/tests/test_i8042.cpp`; modify tests CMake.

- [ ] **Step 1: Header — model after `Pit8254`/`Serial16550`**

`tools/vmm/src/devices/ps2_i8042.h`:
```cpp
#pragma once
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>

namespace duetos::vmm
{
// i8042 PS/2 controller. Port 0x60 (data) / 0x64 (status+cmd).
// PushKey/PushAux are called from the UI thread; In/Out from the
// vCPU thread. RaiseIrq(1)/RaiseIrq(12) are invoked when a byte
// becomes available and the device is enabled.
class Ps2I8042
{
public:
    explicit Ps2I8042(std::function<void(uint32_t irq)> raiseIrq)
        : m_raise(std::move(raiseIrq)) {}

    uint8_t In(uint16_t port);            // 0x60 / 0x64
    void    Out(uint16_t port, uint8_t v);

    void PushKey(const uint8_t* b, size_t n);  // UI thread
    void PushAux(const uint8_t* b, size_t n);  // UI thread

private:
    void Refill();                         // pick next byte -> data
    std::mutex                       m_mx;
    std::deque<uint8_t>              m_kbd, m_aux;
    uint8_t                          m_data = 0;
    bool                             m_full = false;   // status bit0
    bool                             m_dataIsAux = false; // status bit5
    uint8_t                          m_cfg = 0x47;     // sane default
    uint8_t                          m_pendingCmd = 0; // 0x64 cmd awaiting arg
    std::function<void(uint32_t)>    m_raise;
};
} // namespace duetos::vmm
```

- [ ] **Step 2: Failing test (the command/response handshake the kernel relies on)**

`tools/vmm/tests/test_i8042.cpp`:
```cpp
#include "test_main.h"
#include "devices/ps2_i8042.h"
#include <vector>

using duetos::vmm::Ps2I8042;

TEST(i8042_self_test_and_kbd_byte_flow)
{
    std::vector<uint32_t> irqs;
    Ps2I8042 c([&](uint32_t i){ irqs.push_back(i); });

    // Controller self-test: cmd 0xAA -> data 0x55.
    c.Out(0x64, 0xAA);
    CHECK((c.In(0x64) & 0x01) != 0);          // output buffer full
    CHECK_EQ((int)c.In(0x60), 0x55);

    // Keyboard byte arrives -> status bit0 set, IRQ1 raised.
    uint8_t k = 0x1C;
    c.PushKey(&k, 1);
    CHECK((c.In(0x64) & 0x01) != 0);
    CHECK((c.In(0x64) & 0x20) == 0);          // bit5 (aux) clear
    bool sawIrq1 = false;
    for (auto i : irqs) if (i == 1) sawIrq1 = true;
    CHECK(sawIrq1);
    CHECK_EQ((int)c.In(0x60), 0x1C);
    CHECK((c.In(0x64) & 0x01) == 0);          // drained
}

TEST(i8042_aux_routes_to_irq12_and_sets_bit5)
{
    std::vector<uint32_t> irqs;
    Ps2I8042 c([&](uint32_t i){ irqs.push_back(i); });
    c.Out(0x64, 0xA8);                        // enable aux
    uint8_t m = 0x08;
    c.PushAux(&m, 1);
    CHECK((c.In(0x64) & 0x20) != 0);          // bit5 = aux data
    bool sawIrq12 = false;
    for (auto i : irqs) if (i == 12) sawIrq12 = true;
    CHECK(sawIrq12);
    CHECK_EQ((int)c.In(0x60), 0x08);
}
```

- [ ] **Step 3: tests CMake add** `test_i8042.cpp ../src/devices/ps2_i8042.cpp`. Build → fail.

- [ ] **Step 4: Implement `ps2_i8042.cpp`**

```cpp
#include "devices/ps2_i8042.h"

namespace duetos::vmm
{
void Ps2I8042::Refill()
{
    if (m_full) return;
    if (!m_kbd.empty())
    {
        m_data = m_kbd.front(); m_kbd.pop_front();
        m_dataIsAux = false; m_full = true;
        if (m_raise) m_raise(1);
    }
    else if (!m_aux.empty())
    {
        m_data = m_aux.front(); m_aux.pop_front();
        m_dataIsAux = true; m_full = true;
        if (m_raise) m_raise(12);
    }
}

uint8_t Ps2I8042::In(uint16_t port)
{
    std::lock_guard<std::mutex> g(m_mx);
    if (port == 0x64)
    {
        uint8_t st = 0;
        if (m_full)       st |= 0x01;        // output buffer full
        if (m_dataIsAux)  st |= 0x20;        // mouse byte
        st |= 0x04;                          // system flag (POST ok)
        return st;
    }
    // 0x60
    uint8_t v = m_data;
    m_full = false;
    Refill();
    return v;
}

void Ps2I8042::Out(uint16_t port, uint8_t v)
{
    std::lock_guard<std::mutex> g(m_mx);
    if (port == 0x60)
    {
        // Argument byte for a pending 0x64 command, else a device
        // command (ACK 0xFA). 0xD4 => next byte targets the mouse.
        if (m_pendingCmd == 0x60) { m_cfg = v; m_pendingCmd = 0; return; }
        if (m_pendingCmd == 0xD4) { m_pendingCmd = 0; m_aux.push_back(0xFA); Refill(); return; }
        m_kbd.push_back(0xFA);               // generic ACK
        if (v == 0xFF) m_kbd.push_back(0xAA);// reset self-test pass
        Refill();
        return;
    }
    // 0x64 controller command
    switch (v)
    {
    case 0x20: m_kbd.push_back(m_cfg); Refill(); break; // read cfg
    case 0x60: m_pendingCmd = 0x60; break;              // write cfg (arg next)
    case 0xA8: m_cfg &= ~0x20; break;                   // enable aux clock
    case 0xA7: m_cfg |=  0x20; break;                   // disable aux
    case 0xAA: m_kbd.push_back(0x55); Refill(); break;  // self-test pass
    case 0xAB: m_kbd.push_back(0x00); Refill(); break;  // kbd iface test ok
    case 0xD4: m_pendingCmd = 0xD4; break;              // next byte -> aux
    default: break;
    }
}

void Ps2I8042::PushKey(const uint8_t* b, size_t n)
{
    std::lock_guard<std::mutex> g(m_mx);
    for (size_t i = 0; i < n; ++i) m_kbd.push_back(b[i]);
    Refill();
}
void Ps2I8042::PushAux(const uint8_t* b, size_t n)
{
    std::lock_guard<std::mutex> g(m_mx);
    for (size_t i = 0; i < n; ++i) m_aux.push_back(b[i]);
    Refill();
}
} // namespace duetos::vmm
```
> Mouse device commands (`0xF4`/`0xF6`/`0xF3` + IntelliMouse knock) arrive via
> `0xD4`-prefixed `0x60` writes; v0 ACKs them (`0xFA`). If `ps2mouse.cpp`
> requires the `0xF2` device-ID reply (`0x00`, or `0x03` after the knock),
> extend the `0xD4` branch to track the knock sequence and answer `0xF2` with
> the right ID. Verify against the driver during Task 8 integration.

- [ ] **Step 5: Build + ctest green. Commit**
```
git add tools/vmm/src/devices/ps2_i8042.* tools/vmm/tests
git -c commit.gpgsign=false commit -m "feat(vmm): i8042 PS/2 controller device (TDD: self-test + kbd/aux IRQ flow)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task 8: Wire i8042 into the VMM + window input  `[INTEGRATION]`

**Files:** Modify `tools/vmm/src/vmm.h` (`Ps2I8042 m_kbd;` member + include), `tools/vmm/src/vmm.cpp` (`HandleIoPort` 0x60/0x64; real `InputSink`), `tools/vmm/CMakeLists.txt` (add `src/devices/ps2_i8042.cpp src/input/ps2_encode.cpp`).

- [ ] **Step 1: Construct the device with the IRQ funnel**

In `vmm.h` add `#include "devices/ps2_i8042.h"` and member
`Ps2I8042 m_ps2{[this](uint32_t irq){ RaiseGuestLine(irq); }};`
(`RaiseGuestLine` is the existing record/replay-aware IOAPIC funnel.)

- [ ] **Step 2: Route ports in `HandleIoPort`**

In the `HandleIoPort` port dispatch (where COM1/PIT ports are handled), add:
```cpp
    case 0x60:
    case 0x64:
        if (exit.IoPortAccess.AccessInfo.IsWrite)
            m_ps2.Out(port, (uint8_t)exit.IoPortAccess.Rax);
        else
            SetIoReadResult(exit, m_ps2.In(port)); // use existing read-return helper
        return;
```
> Match the exact field/helper names this file already uses for COM1 PIO
> (e.g. how `Serial16550` reads/writes return into RAX). Do not invent a new
> return path — reuse the one `m_com1` uses.

- [ ] **Step 3: Real `InputSink` (replace the Task 5 no-ops)**

```cpp
    InputSink sink;
    sink.onKey = [this](uint32_t vk, bool down, bool ext) {
        auto s = VkToSet2(vk, down, ext);
        if (!s.empty()) m_ps2.PushKey(s.data(), s.size());
    };
    sink.onMouse = [this](int dx, int dy, uint32_t btn, int wheel) {
        auto p = MousePacket(dx, dy, btn, wheel, /*intelliMouse=*/true);
        m_ps2.PushAux(p.data(), p.size());
    };
```
(Add `#include "input/ps2_encode.h"` to `vmm.cpp`.)

- [ ] **Step 4: `[INTEGRATION]` Drive the desktop**

Build, run `duetos-vmm.exe --kernel ...\duetos-kernel.elf --mem 1024`, restore the window:
- Move the mouse → the DuetOS cursor tracks it.
- Click a taskbar item / open an app → it responds.
- Type in a shell/app → characters appear.
Cross-check serial: no `ps2` driver errors. If the cursor jumps/drifts: confirm `WM_MOUSEMOVE` delta uses relative motion and the window has mouse focus; consider `SetCapture` while focused (add in `WndProc` `WM_SETFOCUS`/`WM_KILLFOCUS`). If keys are wrong: the driver uses a different scan set — fix Task 6's table + tests to the driver's set, rebuild.

- [ ] **Step 5: Commit**
```
git add tools/vmm/src/vmm.h tools/vmm/src/vmm.cpp tools/vmm/CMakeLists.txt
git -c commit.gpgsign=false commit -m "feat(vmm): wire i8042 + window input — mouse/keyboard drive the desktop

Verified: cursor tracks, clicks/typing reach apps. [INTEGRATION PASS]

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase 3 — ISO9660 direct-boot

### Task 9: ISO9660(+Joliet) loader  `[TDD]`

**Files:** Create `tools/vmm/src/loader/iso9660.h` / `.cpp`; create `tools/vmm/tests/test_iso9660.cpp`; modify tests CMake. Fixture: stage the real ISO (see Conventions) — the test skips with PASS if the ISO is absent so CI without it stays green, but MUST find the kernel when present.

- [ ] **Step 1: Header**

`tools/vmm/src/loader/iso9660.h`:
```cpp
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace duetos::vmm
{
struct IsoKernel
{
    std::vector<uint8_t> elf;       // /boot/duetos-kernel.elf bytes
    std::string          cmdline;   // from grub.cfg default menuentry
};
// Parse `isoPath`, locate /boot/duetos-kernel.elf (prefer Joliet for
// exact-case path, fall back to ISO9660 case-insensitive + ;1) and
// the default menuentry's boot=/theme= tokens from /boot/grub/grub.cfg.
// Returns nullopt with `err` set on failure (never silently empty).
std::optional<IsoKernel> LoadKernelFromIso(const std::string& isoPath,
                                           std::string& err);
} // namespace duetos::vmm
```

- [ ] **Step 2: Failing test**

`tools/vmm/tests/test_iso9660.cpp`:
```cpp
#include "test_main.h"
#include "loader/iso9660.h"
#include <cstdio>

using duetos::vmm::LoadKernelFromIso;

TEST(iso_extracts_kernel_and_cmdline)
{
    const char* iso =
        "C:\\Users\\natew\\source\\repos\\DuetOS\\build\\x86_64-release\\duetos.iso";
    if (std::FILE* f = std::fopen(iso, "rb")) std::fclose(f);
    else { std::printf("(skip: %s absent)\n", iso); return; } // PASS-skip
    std::string err;
    auto k = LoadKernelFromIso(iso, err);
    CHECK(k.has_value());                       // err: <reason>
    CHECK(k->elf.size() > 4);
    CHECK(k->elf[0] == 0x7F && k->elf[1] == 'E' &&
          k->elf[2] == 'L'  && k->elf[3] == 'F');
    CHECK(k->cmdline.find("boot=") != std::string::npos);
}
```

- [ ] **Step 3: tests CMake add** `test_iso9660.cpp ../src/loader/iso9660.cpp`. Build → fail.

- [ ] **Step 4: Implement `iso9660.cpp`**

Implement read-only, in this order (each is a small helper; full bytes-on-disk
layout per ECMA-119):
1. `ReadSector(file, lba, 2048)`.
2. Scan descriptors from LBA 16: type 1 = Primary VD (root dir extent), type 2
   with escape `%/@`/`%/C`/`%/E` = Joliet Supplementary VD (UCS-2 names) — keep
   the Joliet root if present, else the PVD root.
3. `FindInDir(rootLba, rootLen, nameParts)` walking directory records
   (len@0, extent LBA@2 LE, data len@10 LE, flags@25, name len@32, name@33).
   For Joliet decode UCS-2 BE; for ISO9660 upper-case compare and strip `;1`.
4. Resolve `boot`,`duetos-kernel.elf` → read its extent into `IsoKernel::elf`.
5. Resolve `boot`,`grub`,`grub.cfg`; parse: find `set default=N`, then the
   N-th `menuentry`, take its `multiboot2 ... <args>` line, keep tokens
   containing `=` after the kernel path (e.g. `boot=desktop theme=classic`)
   into `IsoKernel::cmdline`. On any miss set `err` and return `std::nullopt`.

> This is the spec's single flagged unknown. Validate against the real ISO in
> Step 5 before proceeding; if names resolve only via Rock Ridge, add the SUSP/
> RR `NM` entry parse (POSIX name in directory record System Use area).

- [ ] **Step 5: Build + ctest green against the real ISO. Commit**
```
git add tools/vmm/src/loader tools/vmm/tests
git -c commit.gpgsign=false commit -m "feat(vmm): read-only ISO9660(+Joliet) loader — kernel ELF + grub cmdline (TDD)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task 10: `--iso` boot path  `[INTEGRATION]`

**Files:** Modify `tools/vmm/src/main.cpp` (`--iso`, mutually exclusive with `--kernel`), `tools/vmm/src/vmm.cpp` (if `cfg.isoPath` set, call `LoadKernelFromIso`, feed the ELF bytes into the existing ELF loader path instead of reading a file, and append the returned cmdline).

- [ ] **Step 1:** Add `std::string isoPath;` to `VmConfig`; parse `--iso`; error if both `--iso` and `--kernel` given.
- [ ] **Step 2:** In `Vmm` setup, if `isoPath` non-empty: `LoadKernelFromIso`; on failure print `couldn't find /boot/duetos-kernel.elf in <iso> (...)` and exit nonzero; on success route `k.elf` bytes to the ELF loader (refactor the loader entry to accept a byte span if it currently only takes a path — keep the path overload) and set the kernel cmdline to `k.cmdline` (unless `--cmdline` explicitly overrode).
- [ ] **Step 3: `[INTEGRATION]`** Stage the ISO; run `duetos-vmm.exe --iso ...\x86_64-release\duetos.iso --mem 1024`. Expected: identical desktop to the ELF path, themed per the ISO's default menuentry. Commit `[INTEGRATION PASS]`.

---

## Phase 4 — Control core + dialog shell

### Task 11: `vmm_control` shared core  `[TDD]`

**Files:** Create `tools/vmm/src/control/vmm_control.h` / `.cpp`; create `tools/vmm/tests/test_vmm_control.cpp`; modify tests CMake. **No Win32/WHP includes** — pure, headless-testable.

- [ ] **Step 1: Header (the single source of truth both UIs are views over)**

`tools/vmm/src/control/vmm_control.h`:
```cpp
#pragma once
#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace duetos::vmm
{
enum class RunState { Running, Paused, GdbAttached };

// Actions the control surface can request of the vCPU loop. The
// loop drains pending() at the top of each iteration (no WHP call
// off the vCPU thread).
enum class VmAction { None, Pause, Resume, Reset, Nmi, PowerOff };

class VmmControl
{
public:
    // --- config (next-boot for WHP-fixed attributes) ---
    void   SetNextBootMem(uint64_t bytes, std::string& err);
    uint64_t NextBootMem() const;
    void   SetLogPath(const std::string& p, std::string& err);
    std::string LogPath() const;
    void   SetCmdline(const std::string& c);
    std::string Cmdline() const;

    // --- runtime ---
    void     RequestAction(VmAction a);
    VmAction TakePending();                  // vCPU thread drains
    void     SetState(RunState s);
    RunState State() const;

    // --- exceptions ---
    void SetBreakOnVector(int vec, bool on); // 6=#UD 13=#GP 14=#PF 0=#DE
    bool BreakOnVector(int vec) const;
    void LogFault(int vec, uint64_t rip, const std::string& sym);
    std::vector<std::string> Faults() const;

    // --- text channel parity (gdb `monitor` / REPL) ---
    // Returns human-readable output; recognises: state, pause, resume,
    // reset, nmi, poweroff, mem <MiB>, logpath <p>, break <vec> on|off,
    // faults, cmdline [<v>].
    std::string Command(const std::string& line);

private:
    mutable std::mutex m_mx;
    uint64_t           m_mem = 512ull*1024*1024;
    std::string        m_logPath, m_cmdline;
    std::atomic<RunState> m_state{RunState::Running};
    std::atomic<VmAction> m_pending{VmAction::None};
    bool               m_brk[256] = {};
    std::vector<std::string> m_faults;
};
} // namespace duetos::vmm
```

- [ ] **Step 2: Failing tests**

`tools/vmm/tests/test_vmm_control.cpp`:
```cpp
#include "test_main.h"
#include "control/vmm_control.h"
using namespace duetos::vmm;

TEST(control_action_roundtrip)
{
    VmmControl c;
    c.RequestAction(VmAction::Pause);
    CHECK(c.TakePending() == VmAction::Pause);
    CHECK(c.TakePending() == VmAction::None);   // drained once
}
TEST(control_mem_rejects_garbage)
{
    VmmControl c; std::string e;
    c.SetNextBootMem(0, e);  CHECK(!e.empty());            // reject 0
    e.clear();
    c.SetNextBootMem(256ull*1024*1024, e); CHECK(e.empty());
    CHECK_EQ(c.NextBootMem(), 256ull*1024*1024);
}
TEST(control_text_channel_parity)
{
    VmmControl c;
    CHECK(c.Command("break 13 on").find("ok") != std::string::npos);
    CHECK(c.BreakOnVector(13));
    CHECK(c.Command("pause").find("ok") != std::string::npos);
    CHECK(c.TakePending() == VmAction::Pause);
}
```

- [ ] **Step 3: tests CMake add** `test_vmm_control.cpp ../src/control/vmm_control.cpp`. Build → fail.

- [ ] **Step 4: Implement `vmm_control.cpp`** — straightforward: mutex-guarded
setters with validation (`SetNextBootMem` rejects `<16 MiB`; `SetLogPath`
rejects empty/undirectoried path), `RequestAction/TakePending` via
`m_pending.exchange`, `Command` parses the verbs listed in the header comment
and calls the same setters/actions (so dialog and text channel cannot diverge).
Full method bodies follow the header's documented contract exactly; each verb in
`Command` maps 1:1 to a typed method above it.

- [ ] **Step 5: Build + ctest green. Commit**
```
git add tools/vmm/src/control tools/vmm/tests
git -c commit.gpgsign=false commit -m "feat(vmm): vmm_control shared core (typed get/set/action + text parity, TDD)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task 12: Re-express `Vmm::Monitor` over `vmm_control`  `[TDD]`

**Files:** Modify `tools/vmm/src/vmm.h` (`VmmControl m_ctl;` member), `tools/vmm/src/vmm.cpp` (`Vmm::Monitor` delegates unknown-to-it verbs to `m_ctl.Command`); add `tools/vmm/tests/test_monitor_parity.cpp` linking the real `vmm_control` proving a representative command set returns the same text via `m_ctl.Command` as documented.

- [ ] **Step 1–4:** TDD: test asserts `VmmControl().Command("state")` etc. match the strings `Vmm::Monitor` now returns for the delegated verbs; implement delegation (keep existing gdb-specific monitor verbs like trace dump; forward the control verbs). Build+ctest green.
- [ ] **Step 5: Commit** `feat(vmm): route gdb monitor through vmm_control (parity)`.

### Task 13: Modeless tabbed dialog shell + hotkeys/menu  `[INTEGRATION]`

**Files:** Create `tools/vmm/src/ui/settings_dialog.h` / `.cpp`; modify `window.cpp` (add a menu `Debug▸Settings…`, `F12` accelerator, `F8` pause/resume), `tools/vmm/CMakeLists.txt` (add sources, link `comctl32`).

- [ ] **Step 1:** `settings_dialog.h`: `class SettingsDialog { public: void Open(void* parentHwnd, VmmControl* ctl); void Close(); bool IsMessage(void* msg); };` (PropertySheet with 4 empty `PROPSHEETPAGE` tabs: Config+Logs, Runtime, Exceptions, Debug).
- [ ] **Step 2:** Implement a modeless `PropertySheet` (`PSH_MODELESS|PSH_NOAPPLYNOW`); store `HWND`; `IsMessage` calls `PropSheet_IsDialogMessage`. Tabs are empty placeholders **with a visible "(tab lands in Task 14-17)" static label** so the shell is honest, not blank.
- [ ] **Step 3:** In `window.cpp` add a menu + accelerator table; `WM_COMMAND`/`WM_HOTKEY` for `F12` → `g_dialog->Open(hwnd,&ctl)`, `F8` → `ctl.RequestAction(toggle)`. Pump `g_dialog->IsMessage(&msg)` in the message loop before `TranslateMessage`.
- [ ] **Step 4: `[INTEGRATION]`** Run; `F12` opens a 4-tab dialog over the running desktop (guest keeps running); `F8` toggles pause (verify via serial: ticks stop/resume). Commit `[INTEGRATION PASS]`.

---

## Phase 5 — Control tabs (one slice each)

> Each task: add the tab's controls to `settings_dialog.cpp`, wire every widget
> to a `VmmControl` getter/setter/action (no direct WHP/Win32 state), build,
> `[INTEGRATION]` verify the listed behaviors, commit. No new unit tests (logic
> lives in `vmm_control`, already covered by Task 11); tabs are thin views.

### Task 14: Config + Logs tab  `[INTEGRATION]`
Controls: next-boot mem edit, res edit, cmdline edit, log/crash/record path
pickers (`GetOpenFileNameW`), read-only image path + git-hash banner. Each
edit/picker calls `m_ctl.Set*`; validation errors shown in a status label.
Verify: set a log path → serial log file appears there after Reset.

### Task 15: Runtime tab  `[INTEGRATION]`
Buttons Pause/Resume/Reset/NMI/Power-off → `m_ctl.RequestAction(...)`; live
state badge from `m_ctl.State()` (also mirrored into window title via
`FbWindow::SetTitle`). Implement the vCPU-loop drain: at the top of the exit
loop, `switch (m_ctl.TakePending())` — Pause = block on a condvar until Resume;
Reset = re-init vCPU to the MB2 entry state (reuse `SetupVcpu`); Nmi = inject
via WHP interrupt; PowerOff = set `m_stop`. Verify each from the tab.

### Task 16: Exceptions tab  `[INTEGRATION]`
Checkboxes #DE/#UD/#GP/#PF → `m_ctl.SetBreakOnVector`; in the exit handler
where exceptions are seen, if `m_ctl.BreakOnVector(vec)` enter the gdb-stop path
(or log+pause if no gdb) and `m_ctl.LogFault(vec,rip,sym)` using `ElfSymbols`.
A list box shows `m_ctl.Faults()`. Verify: enable #UD, run a guest UD probe →
fault appears + guest stops.

### Task 17: Debug tab  `[INTEGRATION]`
Read-only views sourced through `m_ctl`/existing introspect: register dump,
memory peek (addr edit → hex view), symbolized exit-trace (reuse
`DumpTrace`), exit-reason histogram. Refresh button. Verify values match a
parallel gdb `monitor` query (parity).

---

## Phase 6 — CLI / UX finalize + docs

### Task 18: CLI flags + VS integration  `[INTEGRATION]`
**Files:** `tools/vmm/src/main.cpp`, `launch.vs.json`, `tools/vmm/vs-start-vmm.ps1`.
- `--gdb` no longer stop-at-entry; add `--gdb-wait` for the old behavior. Update
  `usage:` string and the header comment in `main.cpp`.
- `launch.vs.json`: the "Attach (in-house VMM, tcp:1234)" config's preLaunch/
  args pass `--gdb-wait` so `stopAtConnect:true` still has a stopped guest.
- `vs-start-vmm.ps1`: default launch is windowed (drop forced headless); add
  `-GdbWait` switch that appends `--gdb-wait`; keep `-Port`/`-Mem`.
- `[INTEGRATION]`: from VS, F5 the VMM attach config → attaches to a **running**
  windowed guest; with `-GdbWait` it stops at entry as before. Commit.

### Task 19: Documentation + final sweep  `[INTEGRATION]`
**Files:** `wiki/tooling/` (new page `In-House-VMM.md`: what it is, the
ELF/ISO/`--res`/`--no-window`/`--gdb[-wait]` surface, the F12 dialog tabs, the
WSL-ELF staging step), `wiki/_Sidebar.md` (link it), `wiki/reference/Roadmap.md`
(remove an interactive-VMM item if one exists), `wiki/getting-started/History.md`
(milestone line), and update the existing `vmm-windows-boot-workflow` memory
note to point at the windowed flow.
- Run the full `vmm-tests` suite + an ELF boot + an ISO boot once more; paste
  the `ctest` summary line and an `[INTEGRATION PASS]` note in the commit.
- `git fetch origin main && git rebase origin/main` (sync before any later PR);
  resolve conflicts if any.

---

## Self-Review (performed against the spec)

**1. Spec coverage:** §6 framebuffer→Task 2,3,5; §7 threading→Task 4,5,8,15;
§8 PS/2→Task 6,7,8; §9 ISO→Task 9,10; §10 dialog (4 tabs)→Task 13,14,15,16,17;
§11 CLI/non-blocking gdb→Task 5,10,18; §12 error handling→Task 9 Step4,10 Step2,
14; §13 testing→Tasks' `[TDD]` cycles + `vmm-tests`; §2/§14 zero-kernel-changes
preserved (no kernel files in any File list). No uncovered requirement.

**2. Placeholder scan:** Task 4 scaffold defect fixed (complete `window.cpp`).
Remaining "verify against driver/ISO" notes are bounded validation steps the
spec itself flags, not code placeholders. Tasks 11-step4 / 14-17 describe thin
view wiring whose logic is fully specified+tested in Task 11 — acceptable per
"tabs are thin views" design; each names exact controls→`VmmControl` methods.

**3. Type consistency:** `Mb2Params` fb fields (Task 2) used identically in
Task 5. `FbWindow` accessors defined Task 4 used in `window.cpp` same task.
`VmmControl` methods defined Task 11 used by name in Tasks 12,14-17.
`Ps2I8042::PushKey/PushAux/In/Out` consistent Tasks 7→8. `LoadKernelFromIso`
signature consistent Tasks 9→10.

**Fixes applied inline:** Task 4 placeholder rewrite (done above). No remaining
spec gaps.
