#include "apps/notes.h"

#include "apps/notes_internal.h"
#include "arch/x86_64/serial.h"
#include "fs/fat32.h"

/*
 * Notes — FAT32 persistence layer.
 *
 * Reads / writes the live document state defined in notes.cpp via
 * the cross-TU surface in notes_internal.h. The kernel-app context
 * has direct access to the FAT32 driver (no syscall round-trip),
 * so save / load talk to fs::fat32 directly.
 *
 * Path: `NOTES.TXT` on the FAT32 root volume (`Fat32Volume(0)`).
 * 8.3 form so v0 doesn't need LFN emission. Mirrors the convention
 * the shell-mode FAT* commands use.
 *
 * Atomicity: NotesSave is delete-then-create. v0 has no journaling
 * — a power loss between the delete and the create truncates the
 * file. Documented via // GAP marker; revisit when FS journaling
 * lands.
 *
 * Locking: callers (the Ctrl+S / Ctrl+O dispatch in main.cpp, the
 * persist self-test) hold the compositor lock when entering, same
 * discipline as NotesPasteFromClipboard.
 */

namespace duetos::apps::notes
{

bool NotesSave()
{
    namespace fat = duetos::fs::fat32;
    using duetos::arch::SerialWrite;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[notes] save: no FAT32 volume mounted\n");
        return false;
    }
    // GAP: non-atomic save — delete-then-create. v0 has no
    // journaling, and Fat32CreateAtPath rejects duplicate
    // names per its contract. A power loss between the delete
    // and the create truncates the file. Revisit when FS
    // journaling lands.
    fat::DirEntry existing;
    if (fat::Fat32LookupPath(v, detail::kSaveFile, &existing))
    {
        if (!fat::Fat32DeleteAtPath(v, detail::kSaveFile))
        {
            SerialWrite("[notes] save: delete-existing failed\n");
            return false;
        }
    }
    const i64 rc = fat::Fat32CreateAtPath(v, detail::kSaveFile, detail::g_buf, detail::g_len);
    if (rc < 0)
    {
        SerialWrite("[notes] save: create failed\n");
        return false;
    }
    SerialWrite("[notes] save: NOTES.TXT written\n");
    return true;
}

namespace
{

bool LoadFromPath(const char* path)
{
    namespace fat = duetos::fs::fat32;
    using duetos::arch::SerialWrite;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[notes] load: no FAT32 volume mounted\n");
        return false;
    }
    fat::DirEntry e;
    if (!fat::Fat32LookupPath(v, path, &e))
    {
        SerialWrite("[notes] load: file not found\n");
        return false;
    }
    if (e.attributes & 0x10) // ATTR_DIRECTORY
    {
        SerialWrite("[notes] load: target is a directory\n");
        return false;
    }
    char tmp[detail::kBufCap];
    const u64 cap = (e.size_bytes < detail::kBufCap) ? e.size_bytes : detail::kBufCap;
    const i64 n = fat::Fat32ReadFile(v, &e, tmp, cap);
    if (n < 0)
    {
        SerialWrite("[notes] load: read failed\n");
        return false;
    }
    detail::g_len = 0;
    detail::g_cursor = 0;
    for (i64 i = 0; i < n; ++i)
    {
        const char c = tmp[i];
        const u8 uc = static_cast<u8>(c);
        if (c == '\n' || (uc >= 0x20 && uc <= 0x7E))
        {
            if (detail::g_len < detail::kBufCap)
            {
                detail::g_buf[detail::g_len++] = c;
            }
        }
    }
    detail::g_cursor = detail::g_len;
    SerialWrite("[notes] load OK\n");
    return true;
}

} // namespace

bool NotesLoad()
{
    return LoadFromPath(detail::kSaveFile);
}

bool NotesLoadFile(const char* path)
{
    if (path == nullptr || path[0] == '\0')
        return false;
    return LoadFromPath(path);
}

void NotesPersistSelfTest()
{
    namespace fat = duetos::fs::fat32;
    using duetos::arch::SerialWrite;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[notes] persist self-test SKIP: no FAT32 volume\n");
        return;
    }
    fat::DirEntry pre;
    if (fat::Fat32LookupPath(v, detail::kSaveFile, &pre))
    {
        // Don't trample whatever the user has on disk.
        SerialWrite("[notes] persist self-test SKIP: NOTES.TXT exists\n");
        return;
    }

    // Snapshot the live buffer so the round-trip on a known
    // marker doesn't disturb whatever the user (or the boot
    // greeting) seeded into Notes.
    char saved_buf[detail::kBufCap];
    const u32 saved_len = detail::g_len;
    const u32 saved_cursor = detail::g_cursor;
    for (u32 i = 0; i < saved_len; ++i)
    {
        saved_buf[i] = detail::g_buf[i];
    }

    // Plant a known marker → save → clear → load → compare.
    constexpr const char kMark[] = "PERSIST-OK\n";
    constexpr u32 kMarkLen = sizeof(kMark) - 1;
    detail::g_len = 0;
    detail::g_cursor = 0;
    for (u32 i = 0; i < kMarkLen; ++i)
    {
        detail::InsertAtCursor(kMark[i]);
    }

    const bool save_ok = NotesSave();
    detail::g_len = 0;
    detail::g_cursor = 0;
    const bool load_ok = NotesLoad();

    bool match = save_ok && load_ok && (detail::g_len == kMarkLen);
    for (u32 i = 0; match && i < kMarkLen; ++i)
    {
        match = (detail::g_buf[i] == kMark[i]);
    }

    // Clean up the test file regardless of outcome.
    fat::Fat32DeleteAtPath(v, detail::kSaveFile);

    // Restore the pre-test buffer.
    detail::g_len = saved_len;
    detail::g_cursor = saved_cursor;
    for (u32 i = 0; i < saved_len; ++i)
    {
        detail::g_buf[i] = saved_buf[i];
    }

    if (match)
    {
        SerialWrite("[notes] persist self-test OK (save -> load round-trip)\n");
    }
    else
    {
        SerialWrite("[notes] persist self-test FAILED\n");
    }
}

} // namespace duetos::apps::notes
