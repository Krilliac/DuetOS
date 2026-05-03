#pragma once

#include "drivers/gpu/edid.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — VESA Generalized Timing Formula (GTF) generator, v0.
 *
 * Clean-room implementation of VESA GTF 1.1 (1999), the predecessor
 * to CVT for CRT-style timings. Reference material: VESA GTF 1.1
 * spec, X.Org gtf(1) algorithm description (man page formulas, no
 * source code consulted).
 *
 * Why GTF when we already have CVT?
 *   GTF predates CVT and is what older monitors expect when EDID
 *   advertises only "established timings" without a DTD. A few CRT
 *   monitors and some KVM passthroughs still expect GTF-shaped
 *   blanking; CVT-Standard was designed to drop in place of GTF but
 *   subtly different blanking can confuse fixed-frequency monitors.
 *
 *   Practically: this slice exists so the mode-set syscall can
 *   choose CVT for modern panels (already in tree) and GTF for the
 *   legacy fall-back path. CVT remains the default.
 *
 * Algorithm summary:
 *   - h_period_us comes from the requested vertical refresh + a
 *     fixed minimum porch + sync time. GTF uses min_v_porch=3 lines,
 *     min_v_porch_time=550 µs, v_sync=3 lines (constants from the
 *     spec).
 *   - Duty cycle = C - M*(h_period_us / 1000), where C/M are the
 *     "GTF constants" with defaults C=40, M=600. Output blanking is
 *     `(active * duty/100) / (1 - duty/100)`.
 *   - h_sync = active * 8 / 100 (rounded to nearest 8 px).
 *   - Pixel clock derived from h_total / h_period_us.
 *
 * All math is integer, no floats. Operates in micro-units to avoid
 * loss of precision on the duty-cycle subtraction.
 *
 * Scope (v0):
 *   - Standard GTF only (no Reduced-Blanking — CVT-RBv1 covers that
 *     niche).
 *   - Progressive-only (interlaced timings deliberately not
 *     supported).
 *   - All monitors aspect ratios; same shape EdidDtd output as CVT.
 *
 * Out of scope:
 *   - GTF Reduced-Blanking (replaced by CVT-RBv1).
 *   - Custom C/M constants per VESA GTF §3.6 (override knobs); the
 *     default C=40, M=600, K=128, J=20 are baked in.
 */

namespace duetos::drivers::gpu
{

struct GtfRequest
{
    u16 h_active;
    u16 v_active;
    u32 refresh_mhz; // refresh × 1000 (e.g. 60000 = 60.000 Hz)
};

::duetos::core::Result<EdidDtd> GtfGenerate(const GtfRequest& req);

void GtfSelfTest();

} // namespace duetos::drivers::gpu
