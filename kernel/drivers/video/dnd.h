#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * Drag-and-drop infrastructure — v0.
 *
 * Single in-flight DnD payload tracked at the kernel-compositor
 * level. Sources call `DndBegin` from a press-edge handler; the
 * compositor enters a captured-cursor mode where mouse motion
 * updates the ghost-image position; on release the topmost
 * registered drop-target under the cursor (if any) consumes the
 * payload via its callback.
 *
 * Why not a full COM-style IDataObject? v1 ships one payload
 * type — a 16-byte ASCII tag — which covers Files-row drag and
 * any other "name that thing" gesture. A real OLE / Mime
 * payload is a future slice.
 *
 * Context: kernel. State mutated under the compositor lock by
 * the kbd / mouse readers.
 */

namespace duetos::drivers::video
{

constexpr u32 kDndPayloadMax = 31; // bytes (NUL included)

enum class DndKind : u8
{
    None = 0,
    FileEntry = 1, // payload = file basename
    Bookmark = 2,  // payload = URL
    Text = 3,      // payload = arbitrary ASCII
};

struct DndPayload
{
    DndKind kind;
    u8 _pad[3];
    char text[kDndPayloadMax + 1]; // NUL-terminated
};

/// Per-window drop-target callback. `payload` is the in-flight
/// drag's payload (always non-null while a drag is live).
/// Return true to indicate the drop was consumed; false to
/// reject (the kernel logs the rejection but takes no further
/// action — the source has no way to roll back).
using DndDropFn = bool (*)(const DndPayload& payload, u32 cx, u32 cy);

/// Register `h` as a drop target. `cb` fires on release-edge
/// when the cursor is over `h`'s client area AND a drag is
/// live AND the source's payload kind matches `accepted_mask`
/// (bitmask over `1u << static_cast<u32>(DndKind::*)`). Pass
/// `kDndAccceptAny` to accept every kind.
constexpr u32 kDndAcceptAny = 0xFFFFFFFFu;
void DndRegisterDropTarget(WindowHandle h, DndDropFn cb, u32 accepted_mask);

/// Begin a drag with the given payload. Captures the cursor so
/// every motion frame goes to `DndUpdateCursor`. `source_hwnd`
/// records who started the drag so a future "drag back to
/// source" cancel gesture can short-circuit. Returns false if
/// a drag is already in flight.
bool DndBegin(WindowHandle source_hwnd, const DndPayload& payload, u32 grab_x, u32 grab_y);

/// True iff a drag is currently in flight.
bool DndIsActive();

/// Read the active payload. Caller must check `DndIsActive`
/// first. Behaviour is undefined when no drag is live.
const DndPayload& DndCurrentPayload();

/// Update the cursor position during a drag. Called from the
/// mouse loop on every motion frame; the compositor uses this
/// to repaint the ghost image at (cx, cy).
void DndUpdateCursor(u32 cx, u32 cy);

/// Resolve the drag at (cx, cy). Walks alive registered drop
/// targets top-down; the first whose bounds contain (cx, cy)
/// AND whose accepted_mask matches the payload kind has its
/// callback invoked. Returns the cb's verdict, or false if no
/// target matched. Always clears the in-flight state.
bool DndResolveAt(u32 cx, u32 cy);

/// Cancel an in-flight drag without consuming. Used by Esc
/// during drag.
void DndCancel();

/// Paint the ghost image (a small label-on-fill panel) at the
/// current cursor position. Called by `DesktopCompose` after
/// chrome but before tooltips so the ghost reads above
/// windows but below modal dialogs.
void DndCompose();

} // namespace duetos::drivers::video
