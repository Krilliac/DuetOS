#include "apps/trash.h"

#include "arch/x86_64/serial.h"
#include "mm/kheap.h"

namespace duetos::apps::trash
{

namespace
{

namespace fat = fs::fat32;

constexpr u32 kPathCap = 64;

// Build "TRASH/<name>" into `out`. Caller-owned `out` must hold
// at least `kPathCap` bytes; truncates silently on overflow so
// the caller's bounded buffer can't overrun. The leading slash
// is omitted — Fat32 path APIs tolerate it but the existing
// trash callers feed paths in slash-less form.
void BuildTrashPath(char* out, const char* name)
{
    u32 i = 0;
    const char* prefix = kTrashDir;
    for (; prefix[i] != '\0' && i + 1 < kPathCap; ++i)
    {
        out[i] = prefix[i];
    }
    if (i + 1 < kPathCap)
    {
        out[i++] = '/';
    }
    for (u32 j = 0; name[j] != '\0' && i + 1 < kPathCap; ++j, ++i)
    {
        out[i] = name[j];
    }
    out[i] = '\0';
}

// Streaming-copy context for Fat32ReadFileStream. The first
// chunk goes through Fat32CreateAtPath (which both creates the
// destination and writes the initial bytes); every subsequent
// chunk goes through Fat32AppendAtPath. On any failure flips
// `failed` to true so the walker stops and the caller knows.
struct CopyCtx
{
    const fat::Volume* v;
    const char* dst_path;
    bool first;
    bool failed;
};

bool CopyChunkCb(const u8* data, u64 len, void* ctx_v)
{
    auto* c = static_cast<CopyCtx*>(ctx_v);
    if (c->failed)
        return false;
    if (c->first)
    {
        if (fat::Fat32CreateAtPath(c->v, c->dst_path, data, len) < 0)
        {
            c->failed = true;
            return false;
        }
        c->first = false;
    }
    else
    {
        if (fat::Fat32AppendAtPath(c->v, c->dst_path, data, len) < 0)
        {
            c->failed = true;
            return false;
        }
    }
    return true;
}

// Stream-copy a regular file from `src_path` to `dst_path`. The
// destination MUST NOT exist (no implicit overwrite — the caller
// is expected to have already screened for collisions). On
// failure deletes any partial destination so the FAT doesn't
// accumulate corrupt entries. Empty source files are handled
// (Fat32CreateAtPath with len==0).
bool StreamCopy(const fat::Volume* v, const char* src_path, const char* dst_path)
{
    fat::DirEntry src;
    if (!fat::Fat32LookupPath(v, src_path, &src))
        return false;
    if ((src.attributes & 0x10) != 0)
        return false; // refuse directory copy

    if (src.size_bytes == 0)
    {
        // Zero-byte file: no chunks fired by ReadFileStream, so
        // do the create directly.
        return fat::Fat32CreateAtPath(v, dst_path, nullptr, 0) >= 0;
    }

    CopyCtx ctx{v, dst_path, true, false};
    const bool stream_ok = fat::Fat32ReadFileStream(v, &src, CopyChunkCb, &ctx);
    if (!stream_ok || ctx.failed)
    {
        // Best-effort cleanup of any partial destination.
        fat::Fat32DeleteAtPath(v, dst_path);
        return false;
    }
    return true;
}

} // namespace

bool TrashEnsureDir(const fat::Volume* v)
{
    if (v == nullptr)
        return false;
    fat::DirEntry probe;
    if (fat::Fat32LookupPath(v, kTrashDir, &probe))
    {
        // Sanity: refuse to use a regular file as the trash dir.
        return (probe.attributes & 0x10) != 0;
    }
    return fat::Fat32MkdirAtPath(v, kTrashDir);
}

MoveResult TrashMove(const fat::Volume* v, const char* name)
{
    using arch::SerialWrite;
    if (v == nullptr || name == nullptr || name[0] == '\0')
        return MoveResult::Failed;
    if (!TrashEnsureDir(v))
    {
        SerialWrite("[trash] move: cannot ensure /TRASH\n");
        return MoveResult::Failed;
    }

    // Source must exist + be a regular file.
    fat::DirEntry src;
    if (!fat::Fat32LookupPath(v, name, &src))
    {
        SerialWrite("[trash] move: source not found: ");
        SerialWrite(name);
        SerialWrite("\n");
        return MoveResult::Failed;
    }
    if ((src.attributes & 0x10) != 0)
        return MoveResult::Failed;

    char dst_path[kPathCap];
    BuildTrashPath(dst_path, name);

    // Collision check — existing trash entry with the same name
    // is the v0 "user must empty first" case.
    fat::DirEntry dst_probe;
    if (fat::Fat32LookupPath(v, dst_path, &dst_probe))
    {
        SerialWrite("[trash] move: collision in /TRASH for ");
        SerialWrite(name);
        SerialWrite("\n");
        return MoveResult::Collision;
    }

    // Try the cheap path first — Fat32RenameAtPath uses a
    // 64 KiB bounce buffer. Skips an extra read+write pass for
    // small files.
    if (src.size_bytes <= 64 * 1024 && fat::Fat32RenameAtPath(v, name, dst_path))
    {
        SerialWrite("[trash] move OK (rename): ");
        SerialWrite(name);
        SerialWrite("\n");
        return MoveResult::Ok;
    }

    // Streaming path. Required for files > 64 KiB (e.g. 1024×768
    // screenshots ~ 3 MiB) and as a fallback when the rename
    // path's bounce-buffer alloc fails.
    if (!StreamCopy(v, name, dst_path))
    {
        SerialWrite("[trash] move FAILED (stream copy): ");
        SerialWrite(name);
        SerialWrite("\n");
        return MoveResult::Failed;
    }
    if (!fat::Fat32DeleteAtPath(v, name))
    {
        // Source delete failed AFTER destination create — leaves
        // both copies live. Caller will see one in trash + one
        // in root; not a loss, but the user must clean up.
        SerialWrite("[trash] move: dest created but source delete FAILED: ");
        SerialWrite(name);
        SerialWrite("\n");
        return MoveResult::Failed;
    }
    SerialWrite("[trash] move OK (stream): ");
    SerialWrite(name);
    SerialWrite("\n");
    return MoveResult::Ok;
}

bool TrashRestore(const fat::Volume* v, const char* name)
{
    using arch::SerialWrite;
    if (v == nullptr || name == nullptr || name[0] == '\0')
        return false;

    char src_path[kPathCap];
    BuildTrashPath(src_path, name);

    fat::DirEntry src;
    if (!fat::Fat32LookupPath(v, src_path, &src))
        return false;
    if ((src.attributes & 0x10) != 0)
        return false;

    // Refuse if a file with the same name already exists in the
    // root — restore must be unambiguous.
    fat::DirEntry root_probe;
    if (fat::Fat32LookupPath(v, name, &root_probe))
    {
        SerialWrite("[trash] restore: name collision in root: ");
        SerialWrite(name);
        SerialWrite("\n");
        return false;
    }

    // Cheap path: small file -> rename.
    if (src.size_bytes <= 64 * 1024 && fat::Fat32RenameAtPath(v, src_path, name))
    {
        SerialWrite("[trash] restore OK (rename): ");
        SerialWrite(name);
        SerialWrite("\n");
        return true;
    }

    if (!StreamCopy(v, src_path, name))
        return false;
    if (!fat::Fat32DeleteAtPath(v, src_path))
    {
        // Rare — leaves both copies live. Same caveat as TrashMove.
        SerialWrite("[trash] restore: root created but trash delete FAILED: ");
        SerialWrite(name);
        SerialWrite("\n");
        return false;
    }
    SerialWrite("[trash] restore OK (stream): ");
    SerialWrite(name);
    SerialWrite("\n");
    return true;
}

bool TrashPermDelete(const fat::Volume* v, const char* name)
{
    if (v == nullptr || name == nullptr || name[0] == '\0')
        return false;
    char path[kPathCap];
    BuildTrashPath(path, name);
    return fat::Fat32DeleteAtPath(v, path);
}

u32 TrashList(const fat::Volume* v, fat::DirEntry* out, u32 cap)
{
    if (v == nullptr || out == nullptr || cap == 0)
        return 0;
    fat::DirEntry probe;
    if (!fat::Fat32LookupPath(v, kTrashDir, &probe))
        return 0;
    if ((probe.attributes & 0x10) == 0)
        return 0;
    fat::DirEntry tmp[fat::kMaxDirEntries];
    const u32 n = fat::Fat32ListDirByCluster(v, probe.first_cluster, tmp, fat::kMaxDirEntries);
    u32 written = 0;
    for (u32 i = 0; i < n && written < cap; ++i)
    {
        // Skip subdirectories. The trash should hold regular
        // files only in v0; if a future slice lets users put a
        // directory in the trash, this filter goes away.
        if ((tmp[i].attributes & 0x10) != 0)
            continue;
        out[written++] = tmp[i];
    }
    return written;
}

u32 TrashEmpty(const fat::Volume* v)
{
    fat::DirEntry list[fat::kMaxDirEntries];
    const u32 n = TrashList(v, list, fat::kMaxDirEntries);
    u32 deleted = 0;
    for (u32 i = 0; i < n; ++i)
    {
        char path[kPathCap];
        BuildTrashPath(path, list[i].name);
        if (fat::Fat32DeleteAtPath(v, path))
            ++deleted;
    }
    return deleted;
}

void TrashSelfTest()
{
    using arch::SerialWrite;
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        SerialWrite("[trash] self-test SKIP: no FAT32 volume\n");
        return;
    }

    constexpr const char kTestName[] = "TRTEST.BIN";
    constexpr u8 kPayload[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x55, 0xAA, 0x42, 0x00};
    constexpr u32 kPayloadLen = sizeof(kPayload);

    // Pre-clean any leftovers from a previous run (in either
    // location). Tests must be idempotent.
    fat::Fat32DeleteAtPath(v, kTestName);
    char trash_path[kPathCap];
    BuildTrashPath(trash_path, kTestName);
    fat::Fat32DeleteAtPath(v, trash_path);

    // Plant the source file.
    if (fat::Fat32CreateAtPath(v, kTestName, kPayload, kPayloadLen) < 0)
    {
        SerialWrite("[trash] self-test FAILED (cannot plant source)\n");
        return;
    }

    // Move to trash.
    bool pass = (TrashMove(v, kTestName) == MoveResult::Ok);
    fat::DirEntry probe;
    if (pass && fat::Fat32LookupPath(v, kTestName, &probe))
        pass = false; // source still present after move
    if (pass && !fat::Fat32LookupPath(v, trash_path, &probe))
        pass = false; // dest missing after move

    // Restore.
    if (pass && !TrashRestore(v, kTestName))
        pass = false;
    if (pass && !fat::Fat32LookupPath(v, kTestName, &probe))
        pass = false; // source missing after restore
    if (pass && fat::Fat32LookupPath(v, trash_path, &probe))
        pass = false; // trash entry still present after restore

    // Verify the restored content matches the original payload.
    if (pass)
    {
        u8 read_buf[kPayloadLen + 4]{};
        const i64 got = fat::Fat32ReadFile(v, &probe, read_buf, sizeof(read_buf));
        if (got != static_cast<i64>(kPayloadLen))
            pass = false;
        for (u32 i = 0; pass && i < kPayloadLen; ++i)
        {
            if (read_buf[i] != kPayload[i])
                pass = false;
        }
    }

    // Re-delete (move to trash) + permanent-delete from trash.
    if (pass && TrashMove(v, kTestName) != MoveResult::Ok)
        pass = false;
    if (pass && !TrashPermDelete(v, kTestName))
        pass = false;
    if (pass && fat::Fat32LookupPath(v, trash_path, &probe))
        pass = false; // trash entry still there after PermDelete

    // Final cleanup — make sure neither name lingers if a step
    // bailed out partway.
    fat::Fat32DeleteAtPath(v, kTestName);
    fat::Fat32DeleteAtPath(v, trash_path);

    SerialWrite(pass ? "[trash] self-test OK (move + restore + perm-delete round-trip)\n"
                     : "[trash] self-test FAILED\n");
}

} // namespace duetos::apps::trash
