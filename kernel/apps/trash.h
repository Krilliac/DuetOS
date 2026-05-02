#pragma once

#include "fs/fat32.h"
#include "util/types.h"

/*
 * DuetOS Trash — v0.
 *
 * A "Recycle Bin" / "Trash" tier for the Files app's disk view.
 * Without this, deleting a file in the disk view was final and a
 * mis-aimed Y-press meant a permanent loss. With it, deletes
 * become a non-destructive move into `/TRASH/`; users can
 * restore an item, drop it permanently, or empty the bin.
 *
 * Storage layout:
 *   - `/TRASH/` is a regular FAT32 subdirectory of the root
 *     volume. Created lazily by `TrashEnsureDir` on first use.
 *   - Each trashed item lives at `/TRASH/<original-name>`. v0
 *     refuses a soft-delete that would collide with an existing
 *     trash item — the user must restore or empty first. Real
 *     filesystems would suffix a timestamp; v0 is intentionally
 *     simple so collisions are visible rather than silent.
 *   - No sidecar metadata, no original-path table — every
 *     trashed item came from the FAT32 root in v0, since that's
 *     the only directory the Files app exposes for delete.
 *
 * Why streaming, not Fat32RenameAtPath:
 *   `Fat32RenameAtPath` caps at 64 KiB (kRenameBounceMax) — a
 *   single-buffer copy. A 1024×768 screenshot is ~3 MiB and
 *   exceeds that cap, which would silently make screenshots
 *   un-trashable. The trash path streams via Fat32ReadFileStream
 *   + Fat32AppendAtPath so any size that fits FAT32 fits the
 *   trash.
 *
 * Safety:
 *   - Move is non-atomic: a power loss between create+append
 *     and delete leaves both copies live. v0 has no journaling;
 *     this matches the existing `// GAP:` discipline elsewhere.
 *   - Empty walks every regular file in /TRASH and tries each
 *     delete; one failure does not stop the rest.
 *
 * Context: kernel. Caller MUST hold the compositor lock when
 * the move runs against the live UI thread (the Files X-then-Y
 * path holds it; same discipline as Notes save).
 */

namespace duetos::apps::trash
{

/// Path of the trash subdirectory on the FAT32 root volume.
inline constexpr const char kTrashDir[] = "TRASH";

/// Ensure `/TRASH` exists on the volume. Returns true if the
/// directory exists at exit (either pre-existing or freshly
/// created), false on any I/O failure. Called lazily — every
/// `TrashMove` invokes this first, and the cost is one
/// directory lookup when the dir already exists.
bool TrashEnsureDir(const fs::fat32::Volume* v);

/// Move `<root>/<name>` into the trash by streaming the bytes
/// to `<root>/TRASH/<name>`, then deleting the source. Returns
/// `Result::Ok` on success. On collision (a trash entry with
/// the same name already exists) returns `Collision`. Other
/// failures (I/O, allocation, no FAT32, source missing) collapse
/// to `Failed`.
enum class MoveResult : u8
{
    Ok = 0,
    Collision = 1,
    Failed = 2,
};
MoveResult TrashMove(const fs::fat32::Volume* v, const char* name);

/// Restore `<root>/TRASH/<name>` back to `<root>/<name>`. Same
/// streaming pattern as TrashMove. Refuses if a file with the
/// same name already exists in the root (no implicit overwrite).
/// Returns true on success; false on collision / I/O / missing
/// source.
bool TrashRestore(const fs::fat32::Volume* v, const char* name);

/// Permanently delete one item from the trash (no streaming —
/// the file simply goes away). Returns true on success; false
/// if the item isn't in the trash or the FAT32 delete fails.
bool TrashPermDelete(const fs::fat32::Volume* v, const char* name);

/// Drop every regular file inside /TRASH. Returns the number of
/// files actually deleted (so a caller can notify the user
/// "emptied N items"). One failure does not stop the rest —
/// the count reflects what landed.
u32 TrashEmpty(const fs::fat32::Volume* v);

/// Snapshot of trash contents. Caller-owned storage; the API
/// is one-shot (no live cursor). Returns the number of regular
/// files (directory / volume-label entries excluded) written
/// into `out[0..cap-1]`.
u32 TrashList(const fs::fat32::Volume* v, fs::fat32::DirEntry* out, u32 cap);

/// Boot self-test. Plants a synthetic file in the FAT32 root,
/// trashes it, verifies it's gone from the root and present in
/// /TRASH, restores it, verifies the round-trip, then deletes
/// it. SKIPped silently if FAT32 isn't mounted. Pure I/O —
/// runs after the FAT32 probe so the on-disk path is real.
void TrashSelfTest();

} // namespace duetos::apps::trash
