#pragma once

// DuetOS — DIB <-> off-screen-surface transfer.
//
// WHAT
//   The two syscalls that move pixel DATA (as opposed to draw
//   commands) between a ring-3 PE and a kernel-owned GDI bitmap:
//   SYS_GDI_SET_DIBITS and SYS_GDI_GET_DIBITS. Between them they back
//   gdi32!CreateBitmap, !CreateDIBitmap, !SetDIBits, !GetDIBits and
//   the flush half of !CreateDIBSection.
//
// WHY A SEPARATE TU
//   gdi_objects.cpp is already the handle registry plus ~25 draw
//   entry points. Device-independent-bitmap format conversion is a
//   different job -- row padding, bit depth, and the bottom-up /
//   top-down origin -- and it is the one part of the GDI surface that
//   reads a guest buffer whose size the guest itself describes.
//
// THE SHAPE OF THE RISK
//   A PE hands us a pointer, a width, a signed height, a bit depth,
//   and a byte count, and asks us to interpret them together. Every
//   one of those is attacker-chosen, and they interact: the byte
//   count that makes a 32bpp buffer safe leaves a 24bpp read of the
//   same rectangle four bytes short on the last row. All the
//   arithmetic therefore goes through gdi_surface_math.h, which is
//   hosted-tested, and the transfer walks ONE row at a time with a
//   bounded staging buffer rather than mapping the guest range.
//
// Context: kernel, process context (CopyFromUser / CopyToUser may
// fault). Not callable from IRQ.

#include "arch/x86_64/traps.h"
#include "util/types.h"

namespace duetos::subsystems::win32
{

// Syscall dispatchers.
void DoGdiSetDiBits(arch::TrapFrame* frame);
void DoGdiGetDiBits(arch::TrapFrame* frame);

} // namespace duetos::subsystems::win32
