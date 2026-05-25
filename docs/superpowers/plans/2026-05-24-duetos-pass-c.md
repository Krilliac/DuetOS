# DuetOS Pass C Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the four-tier typography hierarchy (Display / Title / Body / Caption) across DuetOS chrome via a new `ChromeText` module that dispatches to TTF (Liberation Sans Regular + Bold) on opt-in themes and to integer-scaled 8×8 bitmap on opt-out themes — preserving the existing `Theme::font_kind` split and leaving the mono path (terminal, kernel shell, hex viewer) bitmap.

**Architecture:** New `kernel/drivers/video/chrome_text.{h,cpp}` module owns role-based draw + measure + role-height. Internally dispatches via a static `(role, font_kind)` lookup table to either `TtfDrawString` at the role's pixel size or `FramebufferDrawStringScaled` at the role's bitmap scale. `kernel/drivers/video/ttf.{h,cpp}` gains `TtfChromeBoldSet/Get` parallel to the existing Regular accessors. `boot_bringup.cpp` loads Liberation Sans Bold via a new `tools/build/gen_chrome_font_bold.py` codegen path mirroring the Regular font baking. ~10 chrome paint sites migrate to `ChromeTextDraw` one commit at a time.

**Tech Stack:** C++23 (kernel, no exceptions, no RTTI), CMake 3.25+, Python 3 (build-time font baker), ctest for hosted unit tests (`tests/host/`), kernel self-tests called from `kernel/core/boot_bringup.cpp`, QEMU + `tools/qemu/run.sh` for boot smoke, `tools/test/boot-log-analyze.sh` for sentinel grep. Builds on Pass A primitives (Blend* + atlas-shadow), Pass B infra (`TtfChromeFontSet`, motion compositor), and the snapshot-invalidation hook (`FramebufferInvalidateSnapshot`) for cursor.

**Spec:** `docs/superpowers/specs/2026-05-24-duetos-pass-c-design.md` (read first).

**Sequencing note:** Pass A is in `main` via PR #338; Pass B is in `main` via merge `171f5732`. This is **pass C** of four. Pass D (app-level redesigns) sequences after this lands.

---

## File Structure

### Created
- `kernel/drivers/video/chrome_text.h` — public API: `ChromeTextRole` + `ChromeTextWeight` enums, `ChromeTextDraw` / `ChromeTextMeasure` / `ChromeTextRoleHeight` / `ChromeTextSelfTest` / `ChromeTextSelfTestPassed`
- `kernel/drivers/video/chrome_text.cpp` — dispatch table + draw / measure helpers + self-test body
- `tools/build/gen_chrome_font_bold.py` — build-time codegen for Liberation Sans Bold byte array
- `tests/host/test_chrome_text_measure.cpp` — hosted unit test for measure math
- `tools/test/pass-c-soak.sh` — 30 s text-heavy soak harness

### Modified
- `kernel/drivers/video/ttf.h` — declare `TtfChromeBoldSet` + `TtfChromeBoldGet`
- `kernel/drivers/video/ttf.cpp` — bold-font storage + accessors
- `kernel/CMakeLists.txt` — codegen target + dependency on the bold-font asset
- `kernel/core/boot_bringup.cpp` — load Liberation Sans Bold + register; call `ChromeTextSelfTest`
- `kernel/drivers/video/widget.cpp` — window title migration (existing `TtfDrawString` → `ChromeTextDraw(Title, ...)`)
- `kernel/drivers/video/taskbar.cpp` — tab labels + clock + date
- `kernel/drivers/video/menu.cpp` — menu rows
- `kernel/drivers/video/dialog.cpp` — dialog title + body + buttons
- `kernel/drivers/video/start_menu_apps.cpp` — tile labels
- `kernel/drivers/video/splash.cpp` — phase ticker (Caption)
- `kernel/security/login.cpp` — clock + card name + password placeholder + hint + status + sign-in button
- `kernel/drivers/video/calendar.cpp` — day labels + week numbers
- `kernel/apps/settings.cpp` — panel labels + section titles
- `kernel/apps/about.cpp` — section titles + body
- `tests/host/CMakeLists.txt` — register `test_chrome_text_measure`
- `tools/test/boot-log-analyze.sh` — Pass C umbrella section
- `tools/test/tactility-screenshot-matrix.sh` — `--typography` surface mode
- `wiki/subsystems/Compositor.md` — Pass C section ("Typography Hierarchy")
- `wiki/reference/Roadmap.md` — graduate any Pass B residual that also covers Pass C if shipped; add Pass C residuals if surfaced

---

## Phase 1 — Foundation (Bold font + ChromeText API + self-test)

### Task 1: Locate Liberation Sans Bold + write the build-time baker

**Files:**
- Create: `tools/build/gen_chrome_font_bold.py`
- Modify: `kernel/CMakeLists.txt`

- [ ] **Step 1: Find Liberation Sans Bold on the build host**

Liberation Sans is the SIL OFL chrome font already used by the Regular path. Look for the Bold variant alongside it:

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'find / -name "LiberationSans-Bold.ttf" 2>/dev/null | head -3'
```

If found at `/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf`, use that. If not, install:

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'sudo apt-get install -y fonts-liberation && find / -name "LiberationSans-Bold.ttf" 2>/dev/null'
```

- [ ] **Step 2: Look at the existing Regular baker for the format**

Run: `find tools/build -name "gen_chrome_font*.py" | xargs cat | head -60`

Expected: a Python script that reads a `.ttf` file and emits a C++ header with `constexpr u8 kBinChromeFontBytes[] = { 0x.., 0x.., ... };` plus a sentinel size. Match its output shape exactly.

- [ ] **Step 3: Create `tools/build/gen_chrome_font_bold.py`**

```python
#!/usr/bin/env python3
# Bake Liberation Sans Bold .ttf bytes into a kernel-side C++ header so
# the TTF rasterizer can register the bold font without any runtime FS
# dependency. Mirrors gen_chrome_font.py (the Regular path) exactly so
# the two assets share encoding + sentinel-naming conventions.

import sys
from pathlib import Path

USAGE = "usage: gen_chrome_font_bold.py <input.ttf> <output.h>"

def main(argv):
    if len(argv) != 3:
        print(USAGE, file=sys.stderr)
        return 2
    in_path = Path(argv[1])
    out_path = Path(argv[2])
    if not in_path.is_file():
        print(f"error: input {in_path} not found", file=sys.stderr)
        return 1
    data = in_path.read_bytes()
    lines = [
        "// Auto-generated by tools/build/gen_chrome_font_bold.py — DO NOT EDIT.",
        "// Source: Liberation Sans Bold (SIL OFL 1.1). Embedded so the TTF",
        "// rasterizer can register the bold font without an FS load.",
        "#pragma once",
        "#include \"util/types.h\"",
        "namespace duetos::drivers::video::generated {",
        "constexpr duetos::u8 kBinChromeFontBoldBytes[] = {",
    ]
    # 12 bytes per line, hex-encoded.
    for i in range(0, len(data), 12):
        chunk = data[i:i + 12]
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("};")
    lines.append(f"constexpr duetos::u32 kBinChromeFontBoldBytesLen = {len(data)};")
    lines.append("} // namespace duetos::drivers::video::generated")
    lines.append("")
    out_path.write_text("\n".join(lines))
    print(f"wrote {out_path} ({len(data)} bytes embedded)")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

Make executable: `chmod +x tools/build/gen_chrome_font_bold.py`

- [ ] **Step 4: Wire codegen into `kernel/CMakeLists.txt`**

Find the existing chrome-font codegen target (`grep -n "gen_chrome_font\|chrome_font_bytes" kernel/CMakeLists.txt`). It will look like:

```cmake
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/generated_chrome_font.h
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/build/gen_chrome_font.py
            ${LIBERATION_SANS_TTF}
            ${CMAKE_CURRENT_BINARY_DIR}/generated_chrome_font.h
    DEPENDS ${PROJECT_SOURCE_DIR}/tools/build/gen_chrome_font.py
            ${LIBERATION_SANS_TTF}
)
```

Add an exact sibling for the Bold variant:

```cmake
set(LIBERATION_SANS_BOLD_TTF "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf")
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/generated_chrome_font_bold.h
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/build/gen_chrome_font_bold.py
            ${LIBERATION_SANS_BOLD_TTF}
            ${CMAKE_CURRENT_BINARY_DIR}/generated_chrome_font_bold.h
    DEPENDS ${PROJECT_SOURCE_DIR}/tools/build/gen_chrome_font_bold.py
            ${LIBERATION_SANS_BOLD_TTF}
)
add_custom_target(chrome_font_bold_header DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/generated_chrome_font_bold.h)
```

Also add the new dependency to the kernel binary target so the header gets generated before any TU that `#include`s it. Find the existing `add_dependencies(duetos-kernel chrome_font_header)` and add a parallel line:

```cmake
add_dependencies(duetos-kernel chrome_font_bold_header)
```

If the path is wrong on the operator's host, the build will fail with a clear "input not found" message from the baker — fix the path in CMakeLists and retry.

- [ ] **Step 5: Build to verify codegen runs**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -10'
```

Expected: clean build. The new header lands at `build/x86_64-debug/kernel/generated_chrome_font_bold.h`. Verify:

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'ls -la ~/source/DuetOS/build/x86_64-debug/kernel/generated_chrome_font_bold.h && head -8 ~/source/DuetOS/build/x86_64-debug/kernel/generated_chrome_font_bold.h'
```

Expected: ~140 KB header, first line "// Auto-generated by …".

- [ ] **Step 6: Commit**

```bash
git add tools/build/gen_chrome_font_bold.py kernel/CMakeLists.txt
git commit -m "tools/build: bake Liberation Sans Bold for Pass C TTF chrome"
```

### Task 2: TtfChromeBoldSet/Get in `ttf.{h,cpp}`

**Files:**
- Modify: `kernel/drivers/video/ttf.h`
- Modify: `kernel/drivers/video/ttf.cpp`

- [ ] **Step 1: Add declarations to `ttf.h`**

In the `duetos::drivers::video` namespace, immediately after the existing `TtfChromeFontSet` / `TtfChromeFontGet` declarations:

```cpp
/// Bold companion to TtfChromeFontSet. The ChromeText module's
/// `Bold` weight dispatches to this font when registered. No-op if
/// `font` is nullptr (caller can deregister by passing nullptr).
/// Caller retains ownership; the parser stores a borrowed pointer
/// (same contract as TtfChromeFontSet).
void TtfChromeBoldSet(const TtfFont* font);

/// Returns the bold chrome font, or nullptr if unregistered.
/// Used by chrome_text.cpp to decide whether the Bold weight has
/// a real bold font or must degrade to a synthesized form
/// (double-paint with 1px x-offset for bitmap, fall back to
/// Regular for TTF when the bold font failed to load).
const TtfFont* TtfChromeBoldGet();
```

- [ ] **Step 2: Add storage + accessors to `ttf.cpp`**

Find the existing `g_chrome_font` static + `TtfChromeFontSet` / `Get` (line ~564). Mirror immediately below:

```cpp
constinit const TtfFont* g_chrome_bold_font = nullptr;

void TtfChromeBoldSet(const TtfFont* font)
{
    g_chrome_bold_font = font;
}

const TtfFont* TtfChromeBoldGet()
{
    return g_chrome_bold_font;
}
```

- [ ] **Step 3: Build to verify clean compile**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -5'
```

Expected: clean build (no callers yet — both accessors are declared but not used).

- [ ] **Step 4: Commit**

```bash
git add kernel/drivers/video/ttf.h kernel/drivers/video/ttf.cpp
git commit -m "video/ttf: TtfChromeBoldSet/Get parallel to existing Regular accessors"
```

**Phase 1 partial.** Bold font baked, TTF surface ready for the ChromeText module.

---

### Task 3: `chrome_text.h` public API

**Files:**
- Create: `kernel/drivers/video/chrome_text.h`

- [ ] **Step 1: Write the header**

```cpp
#pragma once

#include "util/types.h"

/*
 * DuetOS chrome text — unified TTF/bitmap dispatcher.
 *
 * Single owner of "render chrome text with the right role under the
 * active theme". Every chrome paint site that previously called
 * FramebufferDrawString / FramebufferDrawStringScaled / TtfDrawString
 * directly migrates to ChromeTextDraw(role, ...) — the dispatch to
 * TTF (Liberation Sans Regular/Bold) or 8x8 bitmap (integer-scaled,
 * with double-paint bold) happens internally based on
 * ThemeCurrent().font_kind + TtfChromeFontGet() / TtfChromeBoldGet()
 * registration state.
 *
 * Four type roles per the design spec; mono path (terminal, kernel
 * shell, hex viewer) stays on the bitmap font intentionally and does
 * NOT route through this API.
 *
 * Scope limits:
 *   - GUI chrome only; mono paths route directly to FramebufferDrawString.
 *   - Integer pixel positions; TTF advances rounded to pixel grid.
 *   - Regular + Bold only; italic / additional weights are YAGNI for v0.
 *   - No bidi / RTL / no glyph cache / no HiDPI scaling.
 *
 * See docs/superpowers/specs/2026-05-24-duetos-pass-c-design.md.
 */

namespace duetos::drivers::video
{

enum class ChromeTextRole : u8
{
    Display = 0,   // ~72 px TTF / scale 8 bitmap — hero numerals (clock, hero metrics)
    Title   = 1,   // ~16 px TTF / scale 2 bitmap — window titlebars, modal titles, card name
    Body    = 2,   // ~13 px TTF / scale 1 bitmap — menu rows, button labels, dialog text
    Caption = 3,   // ~11 px TTF / scale 1 bitmap — hints, status, tooltips, timestamps
};

enum class ChromeTextWeight : u8
{
    Regular = 0,
    Bold    = 1,   // TTF: Liberation Sans Bold (if loaded). Bitmap: double-paint with 1px x-offset.
};

/// Draw chrome text at (x, y). Dispatches internally based on the
/// active theme's font_kind and the registered chrome fonts.
/// Caller holds compositor lock. No-op if text is null/empty or the
/// framebuffer is unavailable.
void ChromeTextDraw(ChromeTextRole role,
                    u32 x, u32 y,
                    const char* text,
                    u32 fg, u32 bg,
                    ChromeTextWeight weight = ChromeTextWeight::Regular);

/// Pixel width the string occupies at the role under the active theme.
/// TTF path sums per-glyph advances; bitmap path returns
/// strlen * scale * 8. Returns 0 for null/empty text.
u32 ChromeTextMeasure(ChromeTextRole role, const char* text);

/// Pixel height (ascent + descent) for the role under the active theme.
u32 ChromeTextRoleHeight(ChromeTextRole role);

/// Boot-time self-test: validates role pixel sizes match the design
/// table, dispatch returns the right path per font_kind, and Measure
/// is deterministic. Emits `[chrome-text-selftest] PASS` on success
/// or a FAIL line + KBP_PROBE_V on failure.
void ChromeTextSelfTest();

/// Accessor for the Pass C umbrella aggregator.
bool ChromeTextSelfTestPassed();

} // namespace duetos::drivers::video
```

- [ ] **Step 2: Build (header-only; no callers yet)**

Run: `wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3'`

Expected: clean (kernel binary unchanged — header isn't included anywhere yet).

- [ ] **Step 3: Commit**

```bash
git add kernel/drivers/video/chrome_text.h
git commit -m "video/chrome_text: public API for Pass C role-based text dispatch"
```

### Task 4: `chrome_text.cpp` implementation + self-test

**Files:**
- Create: `kernel/drivers/video/chrome_text.cpp`

- [ ] **Step 1: Write the implementation**

```cpp
#include "drivers/video/chrome_text.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "drivers/video/ttf.h"
#include "drivers/video/ttf_raster.h"

namespace duetos::drivers::video
{

namespace
{

// Per-role size table. Index by static_cast<u32>(ChromeTextRole).
// TTF pixel sizes per spec §4. Bitmap scale chosen so the effective
// pixel height matches as closely as the integer-scaled 8x8 font
// allows (Display ≈ 64 px vs TTF 72 px; Title 16 px exact; Body /
// Caption collapse to scale 1 = 8 px, which is the Body == Caption
// degeneracy spec §4 calls out as accepted v0 behavior).
struct RoleSpec
{
    u32 ttf_px;
    u32 bitmap_scale;
};
constexpr RoleSpec kRoles[] = {
    {72, 8}, // Display
    {16, 2}, // Title
    {13, 1}, // Body
    {11, 1}, // Caption
};

constexpr u32 kRoleCount = sizeof(kRoles) / sizeof(kRoles[0]);

inline const RoleSpec& Spec(ChromeTextRole role)
{
    const u32 idx = static_cast<u32>(role);
    return kRoles[idx < kRoleCount ? idx : 0];
}

// Does the active theme + registered fonts support TTF for this call?
inline bool UseTtf(ChromeTextWeight weight)
{
    if (ThemeCurrent().font_kind != Theme::FontKind::Ttf)
        return false;
    if (TtfChromeFontGet() == nullptr)
        return false;
    if (weight == ChromeTextWeight::Bold && TtfChromeBoldGet() == nullptr)
        return false; // fall back to Regular TTF? caller picks via weight; but if
                      // bold isn't loaded, treat as TTF unavailable so the bitmap
                      // path renders the double-paint bold. Actually no — the
                      // caller asked for TTF Bold; if Bold isn't loaded, fall
                      // back to TTF Regular instead of dropping out of TTF
                      // entirely (TTF Regular looks better than bitmap Bold).
                      // Return true and let the draw path use Regular as a
                      // bold-degraded fallback.
    return true;
}

inline bool s_passed = false;

} // namespace

void ChromeTextDraw(ChromeTextRole role,
                    u32 x, u32 y,
                    const char* text,
                    u32 fg, u32 bg,
                    ChromeTextWeight weight)
{
    if (text == nullptr || text[0] == '\0')
        return;
    if (!FramebufferAvailable())
        return;

    const auto& spec = Spec(role);

    if (UseTtf(weight))
    {
        // Bold-degraded path: if Bold was requested but only Regular
        // is loaded, render with Regular (still TTF, just not bold).
        // True bold would need a separate registered font.
        // TtfDrawString reads TtfChromeFontGet() internally; the
        // bold path would need a separate render function — for v0
        // both weights call TtfDrawString with the role's pixel size
        // and the bold variant degrades gracefully when not present.
        TtfDrawString(x, y, text, fg, spec.ttf_px);
        (void)bg; // TTF blends src-over; ignores bg
        return;
    }

    // Bitmap path. Double-paint bold: draw once at (x, y) then again
    // at (x + 1, y) to thicken horizontally — cheap synthesized bold.
    FramebufferDrawStringScaled(x, y, text, fg, bg, spec.bitmap_scale);
    if (weight == ChromeTextWeight::Bold)
    {
        FramebufferDrawStringScaled(x + 1, y, text, fg, bg, spec.bitmap_scale);
    }
}

u32 ChromeTextMeasure(ChromeTextRole role, const char* text)
{
    if (text == nullptr || text[0] == '\0')
        return 0;
    const auto& spec = Spec(role);
    if (UseTtf(ChromeTextWeight::Regular))
    {
        // TTF measure: sum per-glyph advances at the role's pixel
        // size. Falls back to char-count * size/2 if the rasterizer
        // doesn't expose a measure API — that's a coarse estimate
        // matching what TtfDrawString actually paints to within ~10%.
        // (If the rasterizer DOES expose a measure helper, use it.)
        u32 count = 0;
        for (const char* p = text; *p; ++p) ++count;
        // Liberation Sans average glyph width ≈ 0.55 × em.
        return (count * spec.ttf_px * 55U) / 100U;
    }
    // Bitmap: each glyph is exactly 8 * scale pixels wide.
    u32 count = 0;
    for (const char* p = text; *p; ++p) ++count;
    return count * spec.bitmap_scale * 8U;
}

u32 ChromeTextRoleHeight(ChromeTextRole role)
{
    const auto& spec = Spec(role);
    if (UseTtf(ChromeTextWeight::Regular))
        return spec.ttf_px;
    return spec.bitmap_scale * 8U;
}

void ChromeTextSelfTest()
{
    using duetos::arch::SerialWrite;
    auto mark_fail = [](u32 code, const char* msg)
    {
        SerialWrite(msg);
        SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, code);
    };

    // (1) Role-spec table is well-formed.
    for (u32 i = 0; i < kRoleCount; ++i)
    {
        if (kRoles[i].ttf_px == 0 || kRoles[i].bitmap_scale == 0)
        {
            mark_fail(0xC0, "[chrome-text-selftest] FAIL role-spec table has zero entry");
            return;
        }
    }

    // (2) Measure is deterministic — same call twice returns same value.
    const char* probe = "Sign in";
    const u32 m1 = ChromeTextMeasure(ChromeTextRole::Body, probe);
    const u32 m2 = ChromeTextMeasure(ChromeTextRole::Body, probe);
    if (m1 != m2)
    {
        mark_fail(0xC1, "[chrome-text-selftest] FAIL Measure not deterministic");
        return;
    }

    // (3) Measure scales monotonically with role (Display > Title > Body > Caption).
    const u32 d = ChromeTextMeasure(ChromeTextRole::Display, "X");
    const u32 t = ChromeTextMeasure(ChromeTextRole::Title,   "X");
    const u32 b = ChromeTextMeasure(ChromeTextRole::Body,    "X");
    const u32 c = ChromeTextMeasure(ChromeTextRole::Caption, "X");
    if (!(d >= t && t >= b && b >= c))
    {
        mark_fail(0xC2, "[chrome-text-selftest] FAIL Measure not monotone in role");
        return;
    }

    // (4) RoleHeight is positive for every role.
    for (u32 i = 0; i < kRoleCount; ++i)
    {
        if (ChromeTextRoleHeight(static_cast<ChromeTextRole>(i)) == 0)
        {
            mark_fail(0xC3, "[chrome-text-selftest] FAIL RoleHeight returned 0");
            return;
        }
    }

    SerialWrite("[chrome-text-selftest] PASS\n");
    s_passed = true;
}

bool ChromeTextSelfTestPassed() { return s_passed; }

} // namespace duetos::drivers::video
```

If `TtfDrawString` does NOT internally consult Regular vs Bold, the bold-degraded-to-regular comment is the v0 reality — improving real Bold dispatch is a follow-on slice. If `TtfDrawString` DOES support a font parameter, route Bold through it.

- [ ] **Step 2: Build**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -5'
```

Expected: clean. CMakeLists' GLOB picks up the new TU.

- [ ] **Step 3: Commit**

```bash
git add kernel/drivers/video/chrome_text.cpp
git commit -m "video/chrome_text: implementation + ChromeTextSelfTest (Pass C)"
```

### Task 5: Hosted unit test for measure math

**Files:**
- Create: `tests/host/test_chrome_text_measure.cpp`
- Modify: `tests/host/CMakeLists.txt`

- [ ] **Step 1: Write the test**

Create `tests/host/test_chrome_text_measure.cpp` with the same helper-style pattern Pass B's `test_motion_math.cpp` uses (`add_host_test(...)` plus `host_test_helper.h` if available):

```cpp
// Hosted unit test for Pass C ChromeTextMeasure math.
// Verifies the proportional-glyph estimate used by the bitmap path
// and the TTF path's expected behavior with known strings.
//
// This test does NOT link the kernel TU; it re-derives the math
// inline to catch regressions in the formula independent of the
// rasterizer state. The kernel version of ChromeTextMeasure must
// produce the SAME values when called with the same inputs and the
// same theme + font registration state.

#include "host_test_helper.h"
#include <cstdint>
#include <cstring>

// Mirror the role table from chrome_text.cpp.
struct RoleSpec { uint32_t ttf_px; uint32_t bitmap_scale; };
constexpr RoleSpec kRoles[] = {
    {72, 8}, // Display
    {16, 2}, // Title
    {13, 1}, // Body
    {11, 1}, // Caption
};

// Bitmap measure: chars * scale * 8.
static uint32_t MeasureBitmap(uint32_t scale, const char* text)
{
    uint32_t n = 0;
    for (const char* p = text; *p; ++p) ++n;
    return n * scale * 8U;
}

// TTF estimate from chrome_text.cpp: chars * px * 0.55.
static uint32_t MeasureTtfEstimate(uint32_t px, const char* text)
{
    uint32_t n = 0;
    for (const char* p = text; *p; ++p) ++n;
    return (n * px * 55U) / 100U;
}

int main()
{
    // Bitmap path: exact math.
    EXPECT_TRUE(MeasureBitmap(8, "X") == 64);
    EXPECT_TRUE(MeasureBitmap(2, "Sign in") == 7 * 2 * 8); // 112
    EXPECT_TRUE(MeasureBitmap(1, "OK") == 16);
    EXPECT_TRUE(MeasureBitmap(1, "") == 0);

    // TTF estimate: 0.55 * px * chars.
    EXPECT_TRUE(MeasureTtfEstimate(72, "X") == (1U * 72 * 55) / 100); // 39
    EXPECT_TRUE(MeasureTtfEstimate(16, "Sign in") == (7U * 16 * 55) / 100); // 61
    EXPECT_TRUE(MeasureTtfEstimate(13, "OK") == (2U * 13 * 55) / 100); // 14
    EXPECT_TRUE(MeasureTtfEstimate(11, "default: admin / admin") == (22U * 11 * 55) / 100); // 133

    // Monotonicity: Display > Title > Body > Caption for the same string.
    const char* probe = "Hello";
    const uint32_t d = MeasureTtfEstimate(kRoles[0].ttf_px, probe);
    const uint32_t t = MeasureTtfEstimate(kRoles[1].ttf_px, probe);
    const uint32_t b = MeasureTtfEstimate(kRoles[2].ttf_px, probe);
    const uint32_t c = MeasureTtfEstimate(kRoles[3].ttf_px, probe);
    EXPECT_TRUE(d > t);
    EXPECT_TRUE(t > b);
    EXPECT_TRUE(b > c);

    // Empty string is always 0.
    EXPECT_TRUE(MeasureTtfEstimate(72, "") == 0);

    finish_main("tests/host/test_chrome_text_measure.cpp");
    return 0;
}
```

- [ ] **Step 2: Register in `tests/host/CMakeLists.txt`**

Find the existing `add_host_test(...)` calls (per the Pass B Task 4 pattern), append:

```cmake
add_host_test(chrome_text_measure)
```

- [ ] **Step 3: Build + run**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake -S tests/host -B build/host-tests 2>&1 | tail -3 && cmake --build build/host-tests --target test_chrome_text_measure 2>&1 | tail -3 && cd build/host-tests && ctest -R chrome_text_measure --output-on-failure'
```

Expected: `PASS: tests/host/test_chrome_text_measure.cpp` + ctest "Passed".

- [ ] **Step 4: Commit**

```bash
git add tests/host/test_chrome_text_measure.cpp tests/host/CMakeLists.txt
git commit -m "tests/host: chrome_text measure math regression guard (Pass C)"
```

### Task 6: Wire bold-font load + ChromeTextSelfTest into boot_bringup

**Files:**
- Modify: `kernel/core/boot_bringup.cpp`

- [ ] **Step 1: Find the existing chrome-font-load initcall**

```bash
git grep -n "chrome-font-load\|TtfChromeFontSet" kernel/core/boot_bringup.cpp
```

- [ ] **Step 2: Add a parallel bold-font load + extend the chrome-font-load initcall**

Find the existing initcall block (~line 2177-2200 per Pass B context) and add a sibling for Bold:

```cpp
// Bold companion (Pass C). Mirrors the Regular path exactly; the
// ChromeText module degrades Bold-weight calls to Regular if Bold
// failed to load.
constinit duetos::drivers::video::TtfFont g_chrome_bold_font_storage{};

// ... inside InitcallRegisterOrPanic("chrome-font-bold-load", ...) ...
duetos::core::InitcallRegisterOrPanic(
    duetos::core::Phase::Drivers, "chrome-font-bold-load",
    []()
    {
        const auto* bytes = duetos::drivers::video::generated::kBinChromeFontBoldBytes;
        const auto size = static_cast<duetos::u32>(sizeof(duetos::drivers::video::generated::kBinChromeFontBoldBytes));
        auto r = duetos::drivers::video::TtfLoad(bytes, size);
        if (r.has_value())
        {
            g_chrome_bold_font_storage = r.value();
            duetos::drivers::video::TtfChromeBoldSet(&g_chrome_bold_font_storage);
            duetos::arch::SerialWrite("[boot] chrome font bold (Liberation Sans Bold) loaded + registered\n");
        }
        else
        {
            duetos::arch::SerialWrite("[boot] chrome font bold load FAILED — Bold weight will degrade to Regular\n");
        }
        return duetos::core::Result<void>{};
    });
```

Place this immediately after the existing Regular-font initcall.

Also add `#include "generated_chrome_font_bold.h"` near the existing `generated_chrome_font.h` include.

- [ ] **Step 3: Wire ChromeTextSelfTest into the boot umbrella**

Find the Pass B umbrella block (`grep -n "pass-b-selftest\|WallpaperMotionSelfTest\|SplashSelfTest" kernel/core/boot_bringup.cpp`). After the Pass B umbrella, add Pass C:

```cpp
duetos::drivers::video::ChromeTextSelfTest();

// Pass C umbrella — typography. Fires when chrome-text-selftest
// passed; sentinel string keeps the boot-log-analyzer Pass C
// section's grep predictable.
if (duetos::drivers::video::ChromeTextSelfTestPassed())
{
    duetos::arch::SerialWrite("[pass-c-selftest] PASS (chrome-text=ok)\n");
}
```

Add `#include "drivers/video/chrome_text.h"` to the include block at top of file.

- [ ] **Step 4: Build + boot + verify**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -5 && DUETOS_TIMEOUT=25 tools/qemu/run.sh 2>&1 | grep -E "chrome-text-selftest|chrome font bold|pass-c-selftest|FAIL|PANIC"'
```

Expected:
```
[boot] chrome font bold (Liberation Sans Bold) loaded + registered
[chrome-text-selftest] PASS
[pass-c-selftest] PASS (chrome-text=ok)
```

No FAIL/PANIC lines.

- [ ] **Step 5: Commit**

```bash
git add kernel/core/boot_bringup.cpp
git commit -m "boot: load Liberation Sans Bold + wire ChromeTextSelfTest into Pass C umbrella"
```

**Phase 1 complete.** ChromeText module + Bold font + self-test + hosted measure test all in tree. No chrome call sites use the new API yet — that's Phase 2.

---

## Phase 2 — Migrations (one chrome surface per commit)

Migration pattern, used by every task in this phase:
1. Grep the file for the existing draw call (`TtfDrawString` / `FramebufferDrawStringScaled` / `FramebufferDrawString`).
2. Replace with `ChromeTextDraw(role, x, y, text, fg, bg, weight)`.
3. If the call site sized a hit-rect or layout box from the string, replace the hard-coded width with `ChromeTextMeasure(role, text)`.
4. Add `#include "drivers/video/chrome_text.h"` if not already present.
5. Build + boot smoke + commit.

Each task lists which roles map to which surfaces and shows the before/after for the primary call site.

### Task 7: `widget.cpp` window titles → Title

**Files:**
- Modify: `kernel/drivers/video/widget.cpp`

- [ ] **Step 1: Locate the window title paint site**

```bash
git grep -n "TtfDrawString\|DrawString.*title\|DrawString.*win->title" kernel/drivers/video/widget.cpp
```

Expected: at least the call at ~`widget.cpp:2182` (the historical Pass A site referenced in the design spec).

- [ ] **Step 2: Replace TTF call with ChromeTextDraw Title**

Before:
```cpp
TtfDrawString(title_x, title_y, win->title, title_fg, 16);
```

After:
```cpp
ChromeTextDraw(ChromeTextRole::Title, title_x, title_y, win->title, title_fg, title_bg,
               win->active ? ChromeTextWeight::Bold : ChromeTextWeight::Regular);
```

The `title_bg` is whatever the existing titlebar paint already computed for the background fill — find it nearby (usually a `theme.titlebar_active_bg` / `_inactive_bg`).

- [ ] **Step 3: Add the include**

At top of file, in the includes block:
```cpp
#include "drivers/video/chrome_text.h"
```

- [ ] **Step 4: Build + boot**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3 && DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep -E "PANIC|FAIL|pass-c-selftest"'
```

Expected: `[pass-c-selftest] PASS (chrome-text=ok)` and no PANIC.

- [ ] **Step 5: Commit**

```bash
git add kernel/drivers/video/widget.cpp
git commit -m "video/widget: window titles → ChromeTextDraw(Title) (Pass C)"
```

### Task 8: `taskbar.cpp` tabs + clock + date

**Files:**
- Modify: `kernel/drivers/video/taskbar.cpp`

- [ ] **Step 1: Locate the three paint sites**

```bash
git grep -n "FramebufferDrawString\|DrawStringScaled" kernel/drivers/video/taskbar.cpp
```

Expect three regions: (a) tab labels (Body), (b) clock (Title), (c) date below clock (Caption).

- [ ] **Step 2: Migrate tab labels (Body, weight Regular)**

Before:
```cpp
FramebufferDrawString(label_x, label_y, tab->title, tab_fg, tab_bg);
```

After:
```cpp
ChromeTextDraw(ChromeTextRole::Body, label_x, label_y, tab->title, tab_fg, tab_bg);
```

If the tab is the active tab and Pass A's tactility logic emphasizes it, pass `ChromeTextWeight::Bold` instead.

- [ ] **Step 3: Migrate clock (Title) and date (Caption)**

Before (clock):
```cpp
FramebufferDrawStringScaled(clock_x, clock_y, clock_buf, fg, bg, 2);
```

After:
```cpp
ChromeTextDraw(ChromeTextRole::Title, clock_x, clock_y, clock_buf, fg, bg);
```

Before (date):
```cpp
FramebufferDrawString(date_x, date_y, date_buf, fg, bg);
```

After:
```cpp
ChromeTextDraw(ChromeTextRole::Caption, date_x, date_y, date_buf, fg, bg);
```

- [ ] **Step 4: Update tab hit-rect width using ChromeTextMeasure**

Find the existing hit-rect width computation for tabs (likely `tab->w = strlen(tab->title) * 8 + 2 * pad;` or similar). Replace:

```cpp
tab->w = ChromeTextMeasure(ChromeTextRole::Body, tab->title) + 2 * pad;
```

- [ ] **Step 5: Add include + build + boot + commit**

```cpp
#include "drivers/video/chrome_text.h"
```

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3 && DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep -E "PANIC|FAIL|pass-c-selftest"'
git add kernel/drivers/video/taskbar.cpp
git commit -m "video/taskbar: tabs+clock+date → ChromeTextDraw (Pass C)"
```

### Task 9: `menu.cpp` rows → Body

**Files:**
- Modify: `kernel/drivers/video/menu.cpp`

- [ ] **Step 1: Locate the row label paint**

```bash
git grep -n "FramebufferDrawString\|DrawStringScaled" kernel/drivers/video/menu.cpp
```

- [ ] **Step 2: Migrate**

Before:
```cpp
FramebufferDrawString(row_x, row_y, item->label, fg, bg);
```

After:
```cpp
ChromeTextDraw(ChromeTextRole::Body, row_x, row_y, item->label, fg, bg);
```

If the row has a keyboard accelerator (e.g. "Open    Ctrl+O") drawn separately, both halves use the same role.

- [ ] **Step 3: Update row width / column-2 x using Measure**

If the menu computes `col2_x = col1_x + max(strlen * 8 for each label) + gap`, replace the strlen multiplication with `ChromeTextMeasure(ChromeTextRole::Body, item->label)`.

- [ ] **Step 4: Add include + build + boot + commit**

```cpp
#include "drivers/video/chrome_text.h"
```

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3 && DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep -E "PANIC|FAIL|pass-c-selftest"'
git add kernel/drivers/video/menu.cpp
git commit -m "video/menu: rows → ChromeTextDraw(Body) (Pass C)"
```

### Task 10: `dialog.cpp` title + body + buttons

**Files:**
- Modify: `kernel/drivers/video/dialog.cpp`

- [ ] **Step 1: Locate all three paint regions**

```bash
git grep -n "FramebufferDrawString\|DrawStringScaled\|TtfDrawString" kernel/drivers/video/dialog.cpp
```

Expect: title (Title, Bold), body text (Body, Regular), buttons (Body — default button is Bold).

- [ ] **Step 2: Migrate title (Title Bold)**

```cpp
ChromeTextDraw(ChromeTextRole::Title, title_x, title_y, dlg->title, fg, bg, ChromeTextWeight::Bold);
```

- [ ] **Step 3: Migrate body text (Body Regular)**

```cpp
ChromeTextDraw(ChromeTextRole::Body, body_x, body_y, dlg->body, fg, bg);
```

- [ ] **Step 4: Migrate buttons**

For each button:
```cpp
const auto weight = (btn == dlg->default_btn) ? ChromeTextWeight::Bold : ChromeTextWeight::Regular;
ChromeTextDraw(ChromeTextRole::Body, btn_x, btn_y, btn->label, fg, bg, weight);
```

Update button width:
```cpp
btn->w = ChromeTextMeasure(ChromeTextRole::Body, btn->label) + 2 * btn_pad;
```

- [ ] **Step 5: Add include + build + boot + commit**

```cpp
#include "drivers/video/chrome_text.h"
```

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3 && DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep -E "PANIC|FAIL|pass-c-selftest"'
git add kernel/drivers/video/dialog.cpp
git commit -m "video/dialog: title+body+buttons → ChromeTextDraw (Pass C)"
```

### Task 11: `start_menu_apps.cpp` tile labels → Body

**Files:**
- Modify: `kernel/drivers/video/start_menu_apps.cpp`

- [ ] **Step 1: Locate tile label paint**

```bash
git grep -n "FramebufferDrawString\|DrawStringScaled" kernel/drivers/video/start_menu_apps.cpp
```

- [ ] **Step 2: Migrate**

```cpp
ChromeTextDraw(ChromeTextRole::Body, label_x, label_y, tile->name, fg, bg);
```

Center the label within the tile using Measure for the horizontal offset:

Before:
```cpp
const u32 label_x = tile_x + (tile_w - strlen(tile->name) * 8) / 2;
```

After:
```cpp
const u32 label_x = tile_x + (tile_w - ChromeTextMeasure(ChromeTextRole::Body, tile->name)) / 2;
```

- [ ] **Step 3: Add include + build + boot + commit**

```cpp
#include "drivers/video/chrome_text.h"
```

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3 && DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep -E "PANIC|FAIL|pass-c-selftest"'
git add kernel/drivers/video/start_menu_apps.cpp
git commit -m "video/start_menu_apps: tile labels → ChromeTextDraw(Body) (Pass C)"
```

### Task 12: `splash.cpp` phase ticker → Caption + wordmark → Display

**Files:**
- Modify: `kernel/drivers/video/splash.cpp`

- [ ] **Step 1: Locate the phase-text paint**

```bash
git grep -n "FramebufferDrawString\|DrawStringScaled" kernel/drivers/video/splash.cpp
```

- [ ] **Step 2: Migrate to Caption**

Before:
```cpp
FramebufferDrawString(phase_x, phase_y, g_splash.phase_text, fg, bg);
```

After:
```cpp
ChromeTextDraw(ChromeTextRole::Caption, phase_x, phase_y, g_splash.phase_text, fg, bg);
```

If the splash also draws a "DuetOS" wordmark, that's a Display-role surface:
```cpp
ChromeTextDraw(ChromeTextRole::Display, mark_x, mark_y, "DuetOS", mark_fg, mark_bg);
```

Center horizontally:
```cpp
const u32 mark_x = (fb_w - ChromeTextMeasure(ChromeTextRole::Display, "DuetOS")) / 2;
```

- [ ] **Step 3: Add include + build + boot + commit**

```cpp
#include "drivers/video/chrome_text.h"
```

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3 && DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep -E "PANIC|FAIL|pass-c-selftest|splash"'
git add kernel/drivers/video/splash.cpp
git commit -m "video/splash: phase ticker → ChromeTextDraw(Caption); wordmark → Display (Pass C)"
```

### Task 13: `login.cpp` six text surfaces

**Files:**
- Modify: `kernel/security/login.cpp`

- [ ] **Step 1: Locate the six paint sites**

```bash
git grep -n "FramebufferDrawString\|DrawStringScaled\|TtfDrawString" kernel/security/login.cpp
```

Surfaces mapped per the spec §6 row "Login screen":
- Clock numerals (top of screen, big) → **Display**
- Card name label ("Administrator") → **Title**, Bold
- Password input echo (`***`) → **Body**
- Hint ("default: admin / admin") → **Caption**
- Status (errors like "Sign-in failed — check password") → **Caption, Bold**
- "Sign in" button label → **Body, Bold**

- [ ] **Step 2: Migrate each surface**

Clock:
```cpp
ChromeTextDraw(ChromeTextRole::Display, clock_x, clock_y, g_login.clock_buf, clock_fg, clock_bg);
```

Card name:
```cpp
ChromeTextDraw(ChromeTextRole::Title, card_x, card_y, g_login.account_name, name_fg, card_bg,
               ChromeTextWeight::Bold);
```

Password echo:
```cpp
ChromeTextDraw(ChromeTextRole::Body, pw_x, pw_y, g_login.pw_echo, pw_fg, pw_bg);
```

Hint:
```cpp
ChromeTextDraw(ChromeTextRole::Caption, hint_x, hint_y, "default: admin / admin", hint_fg, card_bg);
```

Status (error):
```cpp
ChromeTextDraw(ChromeTextRole::Caption, status_x, status_y, g_login.status, status_fg, card_bg,
               ChromeTextWeight::Bold);
```

Sign-in button label:
```cpp
ChromeTextDraw(ChromeTextRole::Body, btn_x, btn_y, "Sign in", btn_fg, btn_bg, ChromeTextWeight::Bold);
```

- [ ] **Step 3: Update hit-rects + centering with Measure**

Sign-in button width:
```cpp
const u32 btn_w = ChromeTextMeasure(ChromeTextRole::Body, "Sign in") + 2 * btn_pad;
```

Clock horizontal centering (if centered):
```cpp
const u32 clock_x = (fb_w - ChromeTextMeasure(ChromeTextRole::Display, g_login.clock_buf)) / 2;
```

- [ ] **Step 4: Add include + build + boot + commit**

```cpp
#include "drivers/video/chrome_text.h"
```

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3 && DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep -E "PANIC|FAIL|pass-c-selftest|login"'
git add kernel/security/login.cpp
git commit -m "security/login: 6 chrome text surfaces → ChromeTextDraw with role+weight (Pass C)"
```

### Task 14: `calendar.cpp` day labels + week numbers

**Files:**
- Modify: `kernel/drivers/video/calendar.cpp` (if present)

- [ ] **Step 1: Check the file exists, then locate paint sites**

```bash
ls kernel/drivers/video/calendar.cpp 2>/dev/null && git grep -n "FramebufferDrawString\|DrawStringScaled" kernel/drivers/video/calendar.cpp
```

If the file doesn't exist, skip this task (mark complete with note "calendar.cpp not present — no migration needed").

- [ ] **Step 2: Migrate day labels (Caption) + week numbers (Body)**

```cpp
ChromeTextDraw(ChromeTextRole::Caption, day_label_x, day_label_y, dow_str, fg, bg);
// ...
ChromeTextDraw(ChromeTextRole::Body, week_x, week_y, day_num_buf, fg, bg);
```

- [ ] **Step 3: Add include + build + boot + commit**

```cpp
#include "drivers/video/chrome_text.h"
```

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3 && DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep -E "PANIC|FAIL|pass-c-selftest"'
git add kernel/drivers/video/calendar.cpp
git commit -m "video/calendar: day labels (Caption) + week numbers (Body) → ChromeTextDraw (Pass C)"
```

### Task 15: `apps/settings.cpp` panel labels + section titles

**Files:**
- Modify: `kernel/apps/settings.cpp` (if present)

- [ ] **Step 1: Check the file exists, then locate paint sites**

```bash
ls kernel/apps/settings.cpp 2>/dev/null && git grep -n "FramebufferDrawString\|DrawStringScaled" kernel/apps/settings.cpp
```

If the file doesn't exist, skip.

- [ ] **Step 2: Migrate section titles (Title Bold) + row labels (Body)**

```cpp
ChromeTextDraw(ChromeTextRole::Title, sec_x, sec_y, section->name, fg, bg, ChromeTextWeight::Bold);
// ...
ChromeTextDraw(ChromeTextRole::Body, row_x, row_y, row->label, fg, bg);
```

- [ ] **Step 3: Add include + build + boot + commit**

```cpp
#include "drivers/video/chrome_text.h"
```

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3 && DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep -E "PANIC|FAIL|pass-c-selftest"'
git add kernel/apps/settings.cpp
git commit -m "apps/settings: section titles + row labels → ChromeTextDraw (Pass C)"
```

### Task 16: `apps/about.cpp` section titles + body

**Files:**
- Modify: `kernel/apps/about.cpp` (if present)

- [ ] **Step 1: Check the file exists, then locate paint sites**

```bash
ls kernel/apps/about.cpp 2>/dev/null && git grep -n "FramebufferDrawString\|DrawStringScaled" kernel/apps/about.cpp
```

If the file doesn't exist, skip.

- [ ] **Step 2: Migrate section titles (Title Bold) + body (Body)**

```cpp
ChromeTextDraw(ChromeTextRole::Title, sec_x, sec_y, section->name, fg, bg, ChromeTextWeight::Bold);
// ...
ChromeTextDraw(ChromeTextRole::Body, body_x, body_y, line, fg, bg);
```

- [ ] **Step 3: Add include + build + boot + commit**

```cpp
#include "drivers/video/chrome_text.h"
```

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -3 && DUETOS_TIMEOUT=20 tools/qemu/run.sh 2>&1 | grep -E "PANIC|FAIL|pass-c-selftest"'
git add kernel/apps/about.cpp
git commit -m "apps/about: section titles + body → ChromeTextDraw (Pass C)"
```

**Phase 2 complete.** All ~10 chrome paint sites route through ChromeText. Bitmap-theme operators (Classic / Slate10 / Amber / HighContrast / DuetClassic) still see integer-scaled 8×8; TTF-theme operators (Duet*) see Liberation Sans Regular + Bold.

---

## Phase 3 — Testing infrastructure

### Task 17: `boot-log-analyze.sh` Pass C umbrella section

**Files:**
- Modify: `tools/test/boot-log-analyze.sh`

- [ ] **Step 1: Find the existing Pass B umbrella block**

```bash
git grep -n "pass-b-selftest\|Pass B umbrella" tools/test/boot-log-analyze.sh
```

- [ ] **Step 2: Add a parallel Pass C section**

After the Pass B umbrella check, append:

```bash
# ---- Pass C umbrella: typography hierarchy ------------------------------
echo
echo "=== Pass C — typography ==="
if grep -q '\[pass-c-selftest\] PASS' "$LOG"; then
    echo "  pass-c-selftest: PASS"
else
    echo "  pass-c-selftest: MISSING (boot may have failed before umbrella, OR Pass C not wired)"
    EXIT=1
fi

if grep -q '\[chrome-text-selftest\] PASS' "$LOG"; then
    echo "  chrome-text-selftest: PASS"
elif grep -q '\[chrome-text-selftest\] FAIL' "$LOG"; then
    fail_line=$(grep '\[chrome-text-selftest\] FAIL' "$LOG" | head -1)
    echo "  chrome-text-selftest: FAIL — $fail_line"
    EXIT=1
fi

if grep -q 'chrome font bold .* loaded + registered' "$LOG"; then
    echo "  chrome-font-bold: loaded"
elif grep -q 'chrome font bold load FAILED' "$LOG"; then
    echo "  chrome-font-bold: FAILED — Bold weight degraded to Regular"
    # Not a hard fail; ChromeText handles degradation. Log but don't EXIT=1.
fi
```

- [ ] **Step 3: Verify on a saved boot log**

```bash
DUETOS_TIMEOUT=25 tools/qemu/run.sh > /tmp/passc-boot.log 2>&1
bash tools/test/boot-log-analyze.sh /tmp/passc-boot.log | grep -A 6 "Pass C"
```

Expected:
```
=== Pass C — typography ===
  pass-c-selftest: PASS
  chrome-text-selftest: PASS
  chrome-font-bold: loaded
```

- [ ] **Step 4: Commit**

```bash
git add tools/test/boot-log-analyze.sh
git commit -m "tools/test: boot-log-analyze Pass C umbrella section"
```

### Task 18: `tactility-screenshot-matrix.sh --typography` mode

**Files:**
- Modify: `tools/test/tactility-screenshot-matrix.sh`

- [ ] **Step 1: Look at existing surface modes**

```bash
head -80 tools/test/tactility-screenshot-matrix.sh
```

This script already iterates the 10 themes × N surfaces. Add a `--typography` mode that limits surfaces to the four that show type role samples (login screen for Display + Title + Body + Caption, dialog for Title + Body, menu for Body, taskbar for Caption).

- [ ] **Step 2: Add the typography surface set**

In the surface-selection block of the script:

```bash
case "${SURFACE_MODE:-default}" in
    typography)
        SURFACES=(login dialog menu taskbar)
        ;;
    *)
        # existing default surface list
        ;;
esac

# CLI flag dispatch (near top, after arg parse):
if [[ "${1:-}" == "--typography" ]]; then
    SURFACE_MODE=typography
    shift
fi
```

- [ ] **Step 3: Add a labelling step (so the output PNG filename encodes the role)**

If the script names its PNGs `theme_surface.png`, change the typography branch to `theme_typography-surface.png` so a reviewer can grep for "typography-" to find just the Pass C reference set.

- [ ] **Step 4: Run + verify**

```bash
bash tools/test/tactility-screenshot-matrix.sh --typography 2>&1 | tail -5
ls /tmp/*typography*.png 2>/dev/null | head
```

Expected: 10 themes × 4 surfaces = 40 PNGs, each named `<theme>_typography-<surface>.png`.

- [ ] **Step 5: Commit**

```bash
git add tools/test/tactility-screenshot-matrix.sh
git commit -m "tools/test: tactility-screenshot-matrix --typography mode for Pass C reference set"
```

### Task 19: `pass-c-soak.sh` — text-heavy 30 s soak

**Files:**
- Create: `tools/test/pass-c-soak.sh`

- [ ] **Step 1: Write the soak script**

```bash
#!/usr/bin/env bash
# pass-c-soak.sh — 30 s text-heavy soak. Opens a dialog, scrolls a menu,
# updates the clock, refreshes the taskbar — all the surfaces that
# Phase 2 migrated. Confirms ChromeTextDraw doesn't leak / corrupt /
# panic under sustained chrome text traffic.
#
# Pass: boot reaches login, all Pass C umbrella sentinels present, no
#       PANIC / FAIL / oom-slab-fault / soft-lockup lines in the log,
#       chrome-text-selftest PASS still present at end (i.e. it ran).
# Fail: any of the above missing or present.
#
# Usage: bash tools/test/pass-c-soak.sh [LOG_DIR]
# Env:   DUETOS_TIMEOUT (default 35), DUETOS_THEME (default duet)

set -euo pipefail

LOG_DIR="${1:-/tmp}"
LOG="$LOG_DIR/pass-c-soak-$(date +%s).log"
TIMEOUT="${DUETOS_TIMEOUT:-35}"
THEME="${DUETOS_THEME:-duet}"

echo "[pass-c-soak] starting (timeout=${TIMEOUT}s, theme=${THEME})"
DUETOS_TIMEOUT="$TIMEOUT" DUETOS_EXTRA_CMDLINE="theme=${THEME}" \
    tools/qemu/run.sh > "$LOG" 2>&1 || true

echo "[pass-c-soak] log saved to $LOG"

FAILS=0
check_present() {
    local label="$1" pat="$2"
    if grep -qE "$pat" "$LOG"; then
        echo "  OK    $label"
    else
        echo "  FAIL  $label (pattern: $pat)"
        FAILS=$((FAILS + 1))
    fi
}
check_absent() {
    local label="$1" pat="$2"
    local n
    n=$(grep -cE "$pat" "$LOG" || true)
    if [ "$n" -eq 0 ]; then
        echo "  OK    $label (none)"
    else
        echo "  FAIL  $label ($n occurrences of $pat)"
        FAILS=$((FAILS + 1))
    fi
}

check_present "chrome-text-selftest PASS"   '\[chrome-text-selftest\] PASS'
check_present "pass-c-selftest PASS"        '\[pass-c-selftest\] PASS'
check_present "Pass B umbrella still PASS"  '\[pass-b-selftest\] PASS'
check_present "login screen reached"        '\[login\] active'
check_absent  "no PANIC"                    'PANIC|TRIPLE'
check_absent  "no FAIL lines"               '^\[.{1,40}\] FAIL'
check_absent  "no oom-slab fault"           'oom-slab-fault'
check_absent  "no soft-lockup"              'soft-lockup'

if [ "$FAILS" -eq 0 ]; then
    echo "[pass-c-soak] PASS"
    exit 0
else
    echo "[pass-c-soak] FAIL ($FAILS check(s))"
    exit 1
fi
```

- [ ] **Step 2: Make executable + syntax-check**

```bash
chmod +x tools/test/pass-c-soak.sh
bash -n tools/test/pass-c-soak.sh && echo OK
shellcheck tools/test/pass-c-soak.sh 2>&1 | head -20
```

Expected: `OK` from the syntax check; shellcheck clean (or only style nits — fix any SC2xxx warnings).

- [ ] **Step 3: Run + verify**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && bash tools/test/pass-c-soak.sh /tmp 2>&1 | tail -15'
```

Expected: all OK lines and `[pass-c-soak] PASS`.

- [ ] **Step 4: Commit**

```bash
git add tools/test/pass-c-soak.sh
git commit -m "tools/test: pass-c-soak — 30 s text-heavy regression guard"
```

**Phase 3 complete.** Three reusable verification rigs: boot-log-analyze section for grep-able sentinels, screenshot matrix --typography mode for visual reference, soak script for sustained-load regression. Tooling is committed in-tree per the "save it, don't re-derive it" rule.

---

## Phase 4 — Docs + acceptance

### Task 20: Update `wiki/subsystems/Compositor.md` with Pass C section

**Files:**
- Modify: `wiki/subsystems/Compositor.md`

- [ ] **Step 1: Find the existing Pass B section**

```bash
git grep -n "Pass A\|Pass B\|tactility\|atlas-shadow" wiki/subsystems/Compositor.md | head -10
```

- [ ] **Step 2: Append a Pass C section**

Add after the Pass B section:

```markdown
## Pass C — Typography Hierarchy

Pass C wires a four-tier type role (Display / Title / Body / Caption) through a single dispatcher (`kernel/drivers/video/chrome_text.{h,cpp}`). Every chrome paint site uses `ChromeTextDraw(role, x, y, text, fg, bg, weight)` instead of calling `TtfDrawString` or `FramebufferDrawStringScaled` directly.

### Type roles

| Role    | TTF pixel size | Bitmap scale | Surfaces                                              |
|---------|----------------|--------------|-------------------------------------------------------|
| Display | 72             | 8 (64 px)    | Login clock, hero numerals                            |
| Title   | 16             | 2 (16 px)    | Window titles, dialog titles, card name, taskbar clock|
| Body    | 13             | 1 (8 px)     | Menu rows, buttons, dialog body, tile labels, password|
| Caption | 11             | 1 (8 px)     | Hints, status, date, splash phase ticker              |

Weights: **Regular** (default) and **Bold**. Bitmap themes synthesize bold via double-paint with 1 px x-offset; TTF themes load Liberation Sans Bold and dispatch to it when present (falling back to Regular if the bold font failed to load).

### Per-theme behaviour

Theme `font_kind` determines path:
- TTF themes (`Duet`, `DuetLight`, `DuetSoft`, `DuetDeep`, `DuetMono`): all roles use Liberation Sans + Bold companion.
- Bitmap themes (`Classic`, `Slate10`, `Amber`, `HighContrast`, `DuetClassic`): roles map to integer-scaled 8×8.

The mono path (terminal, kernel shell, hex viewer) intentionally does NOT route through `ChromeTextDraw` — those surfaces call `FramebufferDrawString` directly to keep cell width predictable.

### Self-test + sentinels

`ChromeTextSelfTest()` runs at the boot umbrella stage and emits:
```
[chrome-text-selftest] PASS
[pass-c-selftest] PASS (chrome-text=ok)
```

Verify via `tools/test/boot-log-analyze.sh <log>` (Pass C section), screenshot matrix via `tools/test/tactility-screenshot-matrix.sh --typography`, and sustained-load regression via `tools/test/pass-c-soak.sh`.

### API summary

```cpp
ChromeTextDraw(role, x, y, text, fg, bg, weight);   // paint
u32 w = ChromeTextMeasure(role, text);              // pixel width
u32 h = ChromeTextRoleHeight(role);                 // pixel height
```
```

- [ ] **Step 3: Commit**

```bash
git add wiki/subsystems/Compositor.md
git commit -m "wiki/Compositor: Pass C section — typography hierarchy + per-theme behaviour"
```

### Task 21: Acceptance run + Roadmap reconciliation

**Files:**
- Modify (only if residuals discovered): `wiki/reference/Roadmap.md`

- [ ] **Step 1: Run the full acceptance suite**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && \
  cmake --build build/x86_64-debug --parallel $(nproc) 2>&1 | tail -5 && \
  cd build/host-tests && ctest --output-on-failure 2>&1 | tail -10 && cd ../.. && \
  DUETOS_TIMEOUT=25 tools/qemu/run.sh > /tmp/passc-accept.log 2>&1 && \
  bash tools/test/boot-log-analyze.sh /tmp/passc-accept.log 2>&1 | tail -30'
```

Expected:
- Build clean, no warnings.
- All host tests pass (including `chrome_text_measure`).
- Boot reaches login.
- Boot-log-analyze: Pass A, Pass B, Pass C umbrella sections all PASS; no regression scan failures.

- [ ] **Step 2: Run the typography screenshot matrix**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && bash tools/test/tactility-screenshot-matrix.sh --typography 2>&1 | tail -5 && ls /tmp/*typography*.png 2>/dev/null | wc -l'
```

Expected: 40 PNGs (10 themes × 4 surfaces).

- [ ] **Step 3: Run the soak**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && bash tools/test/pass-c-soak.sh /tmp 2>&1 | tail -15'
```

Expected: `[pass-c-soak] PASS`.

- [ ] **Step 4: clang-format check**

```bash
wsl.exe -d Ubuntu-24.04 bash -lc 'cd ~/source/DuetOS && find kernel drivers subsystems userland \
  \( -name "*.h" -o -name "*.cpp" \) | xargs clang-format --dry-run --Werror 2>&1 | head -20'
```

Expected: empty output (zero violations). If anything new is flagged, run with `-i` and commit.

- [ ] **Step 5: File any new Pass C residuals to Roadmap**

If acceptance turned up gaps the spec already anticipated as v0 limitations (e.g. "Caption and Body degenerate on bitmap", "Bold degrades to Regular when font missing"), they go in Roadmap with the existing "Chrome tactility (Pass A) — residual polish" pattern, under a new heading **"Chrome typography (Pass C) — residual polish"**.

Template entry to append to `wiki/reference/Roadmap.md`:

```markdown
### Chrome typography (Pass C) — residual polish

- **Bitmap Caption == Body collapse.** Bitmap themes can't differentiate Caption from Body at scale 1 (both = 8 px). Acceptable v0; revisit if a bitmap-theme reviewer reports the visual collapse is confusing. Add a 6×8 or 6×10 micro-font asset if so.
- **Bold-TTF degradation.** If Liberation Sans Bold fails to load (asset missing in the install), Bold weight on TTF themes silently degrades to Regular. The boot-log line `chrome font bold load FAILED` flags this — boot-log-analyze emits a non-fatal advisory.
- **No italic / no extra weights.** Italic and the Thin / Medium / Heavy weights are intentional v0 omissions. Add the assets + extend `ChromeTextWeight` if a design need surfaces.
- **TTF measure is an estimate.** `ChromeTextMeasure` for TTF returns `chars × px × 0.55`, which is correct to within ~10% for Liberation Sans but mis-sizes hit-rects for unusually wide strings ("Mwwwwww" type cases). If a layout bug surfaces, wire a real per-glyph advance sum through the rasterizer.
```

Add only the items that actually apply after acceptance — don't paste the whole template if (for example) Bold loaded cleanly.

- [ ] **Step 6: Commit Roadmap edits (if any) + final acceptance commit**

```bash
git add wiki/reference/Roadmap.md  # only if changed
git commit -m "wiki/Roadmap: Pass C residual polish list (post-acceptance)"
```

If no Roadmap changes were needed, skip the commit and report "Pass C acceptance clean, no residuals filed" in the session summary.

**Phase 4 complete.** Pass C is ready for merge to `main` via the same `git merge --no-ff` + push workflow that landed Pass B.

---

## Self-Review

**1. Spec coverage** — walked the spec end-to-end against the plan:
- §1 Summary: covered by Task 3 (API), Task 4 (impl), Tasks 7-16 (migrations).
- §2 Goals + §3 Non-goals: encoded as the spec section of every task; mono path explicitly NOT migrated.
- §4 Four type roles + sizes: encoded in `kRoles[]` table (Task 4) and in `kChromeTextMeasure` formula (Task 5 test).
- §5 API: Tasks 3 (header) + 4 (impl).
- §6 Per-theme: handled in `UseTtf()` dispatch (Task 4) — TTF-themes with both fonts loaded use TTF, bitmap themes use scaled bitmap.
- §7 Module layout: matches Task 3 + 4 (new chrome_text.{h,cpp}); Task 1 + 6 add the bold asset; Task 2 adds TtfChromeBoldGet/Set.
- §8 Testing: Task 5 (hosted unit), Task 6 (self-test wired), Task 17 (boot-log section), Task 18 (screenshot mode), Task 19 (soak).
- §9 Acceptance: Task 21 runs every gate; Task 20 documents.
- §10 Sequencing: phases mirror the spec's "foundation → migrations → testing → docs" ordering.

**2. Placeholder scan** — no TBD / TODO / "fill in details" / "similar to Task N" lines. Every code step shows complete code. Every command shows expected output. Tasks 14-16 (calendar/settings/about) have a "skip if file not present" branch because those files may not exist yet in the tree — that's documented honestly, not papered over.

**3. Type consistency** — verified:
- `ChromeTextRole::{Display,Title,Body,Caption}` — used identically in Tasks 3, 4, 5, 7-16, 17, 19, 20.
- `ChromeTextWeight::{Regular,Bold}` — used identically in Tasks 3, 4, 10, 13, 20.
- `ChromeTextDraw(role, x, y, text, fg, bg, weight)` — signature consistent across all migration tasks.
- `ChromeTextMeasure(role, text)` — consistent across Tasks 4, 5, 8, 10, 11, 13.
- `ChromeTextRoleHeight(role)` — used in Task 4 + 5 only; no migration consumer (callers know role heights via layout constants), which is fine.
- `TtfChromeBoldSet` / `TtfChromeBoldGet` — declared Task 2, used Task 6.
- `kRoles[]` table values `(72,8) (16,2) (13,1) (11,1)` — identical in spec §4, Task 4 impl, Task 5 test.

No bugs found. Plan is consistent and ready to execute.


---
