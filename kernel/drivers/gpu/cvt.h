#pragma once

#include "drivers/gpu/edid.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — VESA Coordinated Video Timings (CVT) generator, v0.
 *
 * Clean-room implementation of VESA CVT 1.1 (2003) Standard mode
 * and CVT 1.2 (2013) Reduced-Blanking-v1 mode. Reference material:
 * VESA CVT 1.1 + 1.2 specs, Wikipedia "Coordinated Video Timings",
 * X.Org cvt(1) algorithm description. No code copied from libxcvt
 * (MIT) or the X.Org cvt utility — only the documented algorithm
 * from the VESA spec is used.
 *
 * Why CVT?
 *   EDID established + standard timings carry only (width, height,
 *   refresh, aspect). To actually program a mode on hardware, the
 *   GPU driver needs the pixel clock + h/v blanking + sync offsets.
 *   Reduced Blanking v1 is what every modern flat-panel uses
 *   internally; Standard CVT is what's emitted for backwards-
 *   compatible CRT-style timings. Calling these from a GPU driver's
 *   "set mode 1280x1024" path is what makes the mode-set actually
 *   land on a panel.
 *
 * Scope (v0):
 *   - CVT Reduced-Blanking v1: 160-pixel horizontal blanking,
 *     fixed h-sync (32) + h-front-porch (8) + h-back-porch (120),
 *     v-blanking computed from min v-blank-time (460 μs).
 *   - CVT Standard: variable h-blanking via duty-cycle formula,
 *     v-sync determined by aspect ratio (4..10 lines), v-back-porch
 *     iterated against min vsync+bp time (550 μs).
 *   - Aspect-ratio detection: 4:3 / 16:9 / 16:10 / 5:4 / 15:9.
 *
 * Out of scope:
 *   - CVT Reduced-Blanking v2 (CVT 1.2) — adds 80-pixel blanking
 *     + 1000/1001 ATSC modifier + ±0.001 MHz pixel clock precision;
 *     deferred until a downstream consumer asks.
 *   - Interlaced timings — output remains progressive in v0.
 *   - GTF (Generalized Timing Formula, predecessor to CVT) — only
 *     CVT is generated here; old-CRT GTF can land alongside if a
 *     real workload needs it.
 *
 * Context: kernel. Pure integer math, no floats, no allocations.
 */

namespace duetos::drivers::gpu
{

/// Mode in which to generate a timing.
enum class CvtMode : u8
{
    Standard,         // CVT 1.1 standard (CRT-style, larger blanking)
    ReducedBlankingV1 // CVT 1.2 §3.2 (flat-panel, 160-pixel h-blank)
};

/// Inputs to the CVT generator. Refresh is in milli-hertz so the
/// caller can ask for "59.940 Hz" without dragging in floats.
struct CvtRequest
{
    u16 h_active;
    u16 v_active;
    u32 refresh_mhz; // refresh × 1000 (e.g. 60000 = 60.000 Hz)
    CvtMode mode;
};

/// Generate a timing for the requested resolution + refresh, in the
/// shape of an `EdidDtd` so callers can hand the result straight to
/// a future mode-set syscall (which will accept the same shape EDID
/// would have surfaced).
::duetos::core::Result<EdidDtd> CvtGenerate(const CvtRequest& req);

/// Boot-time self-test: walks 5 well-known modes (640×480@60,
/// 1024×768@60, 1280×1024@60, 1920×1080@60, 2560×1440@60) under
/// both Standard and Reduced-Blanking-v1. Asserts pixel-clock and
/// timing values fall within ±2% of the values that the X.Org cvt
/// utility produces (computed offline). Compiled out when
/// `kBootSelfTests` is false.
void CvtSelfTest();

} // namespace duetos::drivers::gpu
