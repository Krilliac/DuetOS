#include "fs/vfs.h"

#include "arch/x86_64/serial.h"
#include "fs/mount.h"
#include "log/klog.h"
#include "core/panic.h"

namespace duetos::fs
{

namespace
{

// Byte-wise NUL-terminated string compare with a hard length cap.
// Returns true iff both strings are identical and both terminate
// (either via NUL on `a` within `alen`, or on `b`).
bool StrEqN(const char* a, u64 alen, const char* b)
{
    if (a == nullptr || b == nullptr)
    {
        return false;
    }
    for (u64 i = 0; i < alen; ++i)
    {
        if (b[i] == '\0')
        {
            return false; // b is shorter than a's len
        }
        if (a[i] != b[i])
        {
            return false;
        }
    }
    // a's first `alen` bytes matched. Require b's next byte to be NUL
    // so the strings are actually the same length.
    return b[alen] == '\0';
}

// Locate a child named [name, name+name_len) inside `dir`. O(children)
// linear scan. Returns nullptr if dir is null, not a directory, has
// no children, or no match.
const RamfsNode* FindChild(const RamfsNode* dir, const char* name, u64 name_len)
{
    if (!RamfsIsDir(dir) || dir->children == nullptr)
    {
        return nullptr;
    }
    for (u64 i = 0; dir->children[i] != nullptr; ++i)
    {
        const RamfsNode* c = dir->children[i];
        if (StrEqN(name, name_len, c->name))
        {
            return c;
        }
    }
    return nullptr;
}

} // namespace

const RamfsNode* VfsLookup(const RamfsNode* root, const char* path, u64 path_max)
{
    if (root == nullptr || path == nullptr || path_max == 0)
    {
        return nullptr;
    }

    const RamfsNode* cur = root;

    u64 i = 0;
    while (i < path_max && path[i] != '\0')
    {
        // Skip any run of '/'. Treats "/a//b", "//a/b", "a/b/"
        // identically to "/a/b".
        while (i < path_max && path[i] == '/')
        {
            ++i;
        }
        if (i >= path_max || path[i] == '\0')
        {
            break;
        }

        // Extract the next component [i .. j).
        u64 j = i;
        while (j < path_max && path[j] != '/' && path[j] != '\0')
        {
            ++j;
        }
        const u64 component_len = j - i;

        // "." — stay. ".." — REJECTED (would escape a jail; see
        // the header comment for rationale).
        if (component_len == 1 && path[i] == '.')
        {
            i = j;
            continue;
        }
        if (component_len == 2 && path[i] == '.' && path[i + 1] == '.')
        {
            return nullptr;
        }

        // Cannot walk through a file.
        if (!RamfsIsDir(cur))
        {
            return nullptr;
        }

        const RamfsNode* next = FindChild(cur, path + i, component_len);
        if (next == nullptr)
        {
            return nullptr;
        }
        cur = next;

        i = j;
    }

    return cur;
}

// =====================================================
// Generic VfsNode helpers + cross-mount resolver.
// =====================================================

bool VfsNodeIsValid(const VfsNode& n)
{
    return n.backend != VfsBackend::Invalid;
}

bool VfsNodeIsDir(const VfsNode& n)
{
    if (n.backend == VfsBackend::Ramfs)
    {
        return RamfsIsDir(n.ramfs);
    }
    if (n.backend == VfsBackend::Fat32)
    {
        return (n.fat32_entry.attributes & 0x10) != 0;
    }
    return false;
}

bool VfsNodeIsFile(const VfsNode& n)
{
    if (n.backend == VfsBackend::Ramfs)
    {
        return n.ramfs != nullptr && n.ramfs->type == RamfsNodeType::kFile;
    }
    if (n.backend == VfsBackend::Fat32)
    {
        return (n.fat32_entry.attributes & 0x10) == 0;
    }
    return false;
}

u64 VfsNodeSize(const VfsNode& n)
{
    if (n.backend == VfsBackend::Ramfs)
    {
        return n.ramfs != nullptr ? n.ramfs->file_size : 0;
    }
    if (n.backend == VfsBackend::Fat32)
    {
        return n.fat32_entry.size_bytes;
    }
    return 0;
}

VfsNode VfsResolve(const RamfsNode* root, const char* path, u64 path_max)
{
    VfsNode out{};
    out.backend = VfsBackend::Invalid;
    if (path == nullptr || path_max == 0)
    {
        return out;
    }

    // Mount-registry dispatch only fires when the path is absolute
    // (a leading '/'). Relative paths are always ramfs-from-root —
    // sandbox roots stay sandbox roots. The mount registry is a
    // global namespace; relative paths are anchored to the caller
    // and must not climb out of it.
    if (path[0] == '/')
    {
        const char* sub = nullptr;
        const MountEntry* me = VfsMountResolve(path, &sub);
        if (me != nullptr && me->fs_type != FsType::Ramfs && sub != nullptr)
        {
            const VfsBackendOps* ops = VfsBackendForFsType(me->fs_type);
            if (ops != nullptr && ops->lookup != nullptr)
            {
                if (ops->lookup(me->block_handle, sub, &out))
                {
                    return out;
                }
            }
            // Mount matched but lookup missed / no backend wired —
            // fall through to ramfs is wrong because we're past the
            // mount-point boundary. Return Invalid.
            out.backend = VfsBackend::Invalid;
            return out;
        }
    }

    // Ramfs fall-through: the explicit `root` arg is authoritative.
    const RamfsNode* n = VfsLookup(root, path, path_max);
    if (n == nullptr)
    {
        return out;
    }
    out.backend = VfsBackend::Ramfs;
    out.ramfs = n;
    return out;
}

namespace
{

void Expect(bool cond, const char* what)
{
    if (cond)
    {
        return;
    }
    ::duetos::arch::SerialWrite("[fs/vfs-selftest] FAIL ");
    ::duetos::arch::SerialWrite(what);
    ::duetos::arch::SerialWrite("\n");
    ::duetos::core::Panic("fs/vfs", "VfsSelfTest assertion failed");
}

} // namespace

void VfsSelfTest()
{
    KLOG_TRACE_SCOPE("fs/vfs", "VfsSelfTest");
    arch::SerialWrite("[fs/vfs] self-test start\n");

    const RamfsNode* trusted = RamfsTrustedRoot();
    const RamfsNode* sandbox = RamfsSandboxRoot();
    Expect(trusted != nullptr, "RamfsTrustedRoot non-null");
    Expect(sandbox != nullptr, "RamfsSandboxRoot non-null");
    Expect(RamfsIsDir(trusted), "trusted root is a directory");
    Expect(RamfsIsDir(sandbox), "sandbox root is a directory");

    // ----- Null / zero-length guard rails -----
    Expect(VfsLookup(nullptr, "/etc/version", 64) == nullptr, "null root rejected");
    Expect(VfsLookup(trusted, nullptr, 64) == nullptr, "null path rejected");
    Expect(VfsLookup(trusted, "/etc/version", 0) == nullptr, "path_max=0 rejected");

    // ----- Empty / root-only paths return the root unchanged -----
    Expect(VfsLookup(trusted, "", 64) == trusted, "empty string resolves to root");
    Expect(VfsLookup(trusted, "/", 64) == trusted, "single slash resolves to root");
    Expect(VfsLookup(trusted, "//", 64) == trusted, "double slash resolves to root");
    Expect(VfsLookup(trusted, "///", 64) == trusted, "triple slash resolves to root");
    Expect(VfsLookup(trusted, ".", 64) == trusted, "single dot resolves to root");
    Expect(VfsLookup(trusted, "./", 64) == trusted, "dot-slash resolves to root");
    Expect(VfsLookup(trusted, "/./", 64) == trusted, "slash-dot-slash resolves to root");
    Expect(VfsLookup(trusted, "././.", 64) == trusted, "multiple dots resolve to root");

    // ----- Positive lookups against the trusted tree -----
    const RamfsNode* etc = VfsLookup(trusted, "/etc", 64);
    Expect(etc != nullptr && RamfsIsDir(etc), "/etc resolves to a directory");
    const RamfsNode* version = VfsLookup(trusted, "/etc/version", 64);
    Expect(version != nullptr, "/etc/version resolves");
    Expect(!RamfsIsDir(version), "/etc/version is a file");
    Expect(version->file_size > 0, "/etc/version has bytes");
    Expect(VfsLookup(trusted, "/bin/hello", 64) != nullptr, "/bin/hello resolves");
    Expect(VfsLookup(trusted, "/bin/exit.elf", 64) != nullptr, "/bin/exit.elf resolves");
    Expect(VfsLookup(trusted, "/bin/hello.exe", 64) != nullptr, "/bin/hello.exe resolves");
    Expect(VfsLookup(trusted, "/etc/motd", 64) != nullptr, "/etc/motd resolves");
    Expect(VfsLookup(trusted, "/etc/profile", 64) != nullptr, "/etc/profile resolves");
    Expect(VfsLookup(trusted, "/etc/man/ls", 64) != nullptr, "/etc/man/ls resolves (3-deep)");
    Expect(VfsLookup(trusted, "/etc/man/cat", 64) != nullptr, "/etc/man/cat resolves");

    // ----- Relative lookups (no leading slash) start from root -----
    Expect(VfsLookup(trusted, "etc/version", 64) == version, "relative path matches absolute");
    Expect(VfsLookup(trusted, "bin/hello", 64) != nullptr, "relative /bin/hello resolves");

    // ----- Trailing slash tolerated on both file and dir -----
    Expect(VfsLookup(trusted, "/etc/version/", 64) == version, "trailing slash on file");
    Expect(VfsLookup(trusted, "/etc/", 64) == etc, "trailing slash on directory");
    Expect(VfsLookup(trusted, "/etc//", 64) == etc, "trailing double slash on directory");

    // ----- Empty components / consecutive slashes -----
    Expect(VfsLookup(trusted, "//etc//version", 64) != nullptr, "double-slash mid-path tolerated");
    Expect(VfsLookup(trusted, "///etc///version///", 64) != nullptr, "triple-slash mid-path tolerated");

    // ----- "." mid-path stays put -----
    Expect(VfsLookup(trusted, "/etc/./version", 64) == version, "dot mid-path preserved");
    Expect(VfsLookup(trusted, "/./etc/./version", 64) == version, "dots throughout preserved");

    // ----- ".." rejected at every position (jail invariant) -----
    Expect(VfsLookup(trusted, "..", 64) == nullptr, "bare .. rejected");
    Expect(VfsLookup(trusted, "/..", 64) == nullptr, "/.. rejected");
    Expect(VfsLookup(trusted, "/etc/..", 64) == nullptr, "/etc/.. rejected");
    Expect(VfsLookup(trusted, "/etc/../bin/hello", 64) == nullptr, "/etc/../bin/hello rejected");
    Expect(VfsLookup(trusted, "/etc/man/..", 64) == nullptr, "deep .. rejected");

    // ----- Cannot walk through a file -----
    Expect(VfsLookup(trusted, "/etc/version/foo", 64) == nullptr, "walk through file rejected");
    Expect(VfsLookup(trusted, "/bin/hello/x", 64) == nullptr, "walk through /bin/hello rejected");

    // ----- Missing components fail -----
    Expect(VfsLookup(trusted, "/nope", 64) == nullptr, "missing top-level rejected");
    Expect(VfsLookup(trusted, "/etc/nope", 64) == nullptr, "missing leaf rejected");
    Expect(VfsLookup(trusted, "/nope/version", 64) == nullptr, "missing intermediate rejected");

    // ----- path_max truncation: a short cap stops the scan early -----
    // "/etc/version" = 12 bytes; cap at 4 chars sees "/etc" only and resolves to the dir.
    Expect(VfsLookup(trusted, "/etc/version", 4) == etc, "path_max truncates at /etc");
    // Cap at 1 sees only the leading slash → root.
    Expect(VfsLookup(trusted, "/etc/version", 1) == trusted, "path_max=1 stops at root");

    // ----- Sandbox root: jail containment -----
    const RamfsNode* welcome = VfsLookup(sandbox, "/welcome.txt", 64);
    Expect(welcome != nullptr, "/welcome.txt resolves in sandbox");
    Expect(!RamfsIsDir(welcome), "/welcome.txt is a file");
    Expect(VfsLookup(sandbox, "welcome.txt", 64) == welcome, "relative welcome.txt resolves");
    Expect(VfsLookup(sandbox, "/etc/version", 64) == nullptr, "JAIL: sandbox cannot see /etc/version");
    Expect(VfsLookup(sandbox, "/bin/hello", 64) == nullptr, "JAIL: sandbox cannot see /bin/hello");
    Expect(VfsLookup(sandbox, "/bin", 64) == nullptr, "JAIL: sandbox cannot see /bin");
    Expect(VfsLookup(sandbox, "/etc", 64) == nullptr, "JAIL: sandbox cannot see /etc");
    Expect(VfsLookup(sandbox, "..", 64) == nullptr, "JAIL: sandbox .. rejected");
    Expect(VfsLookup(sandbox, "/welcome.txt/..", 64) == nullptr, "JAIL: sandbox file/.. rejected");

    // ----- Cross-mount resolver (Stage 6 second slice) -----
    //
    // VfsResolve falls back to ramfs when no non-ramfs mount is in
    // the registry; the Fat32-mount path is exercised by the
    // routing self-test that runs after FAT32 auto-mount lands.
    // Here we just verify the ramfs-fall-through and Invalid-miss
    // shapes so a regression in the resolver shows up at this
    // level rather than only at the routing layer above.
    {
        VfsNode r = VfsResolve(trusted, "/etc/version", 64);
        Expect(VfsNodeIsValid(r), "VfsResolve /etc/version valid");
        Expect(r.backend == VfsBackend::Ramfs, "VfsResolve /etc/version is ramfs");
        Expect(r.ramfs == version, "VfsResolve /etc/version matches VfsLookup");
        Expect(VfsNodeIsFile(r), "VfsResolve /etc/version is file");
        Expect(VfsNodeSize(r) == version->file_size, "VfsResolve /etc/version size matches");

        VfsNode d = VfsResolve(trusted, "/etc", 64);
        Expect(VfsNodeIsValid(d), "VfsResolve /etc valid");
        Expect(VfsNodeIsDir(d), "VfsResolve /etc is dir");

        VfsNode m = VfsResolve(trusted, "/nope", 64);
        Expect(!VfsNodeIsValid(m), "VfsResolve /nope misses");
        Expect(m.backend == VfsBackend::Invalid, "VfsResolve /nope backend=Invalid");

        // Sandbox jail still applies to ramfs fall-through.
        VfsNode s = VfsResolve(sandbox, "/etc/version", 64);
        Expect(!VfsNodeIsValid(s), "VfsResolve sandbox-jail still rejects /etc/version");

        // ".." rejection survives the resolver wrapping.
        VfsNode dd = VfsResolve(trusted, "/etc/..", 64);
        Expect(!VfsNodeIsValid(dd), "VfsResolve /etc/.. rejected");

        // Default-constructed node behaves correctly.
        VfsNode z{};
        Expect(!VfsNodeIsValid(z), "default VfsNode invalid");
        Expect(!VfsNodeIsDir(z), "default VfsNode not dir");
        Expect(!VfsNodeIsFile(z), "default VfsNode not file");
        Expect(VfsNodeSize(z) == 0, "default VfsNode size=0");
    }

    arch::SerialWrite("[fs/vfs] self-test OK (lookup + jail + .. + path_max + VfsResolve)\n");
}

void VfsResolveCrossMountSelfTest()
{
    arch::SerialWrite("[fs/vfs] cross-mount self-test\n");

    if (fat32::Fat32VolumeCount() == 0)
    {
        arch::SerialWrite("[fs/vfs] cross-mount self-test SKIP (no fat32 volume)\n");
        return;
    }

    const RamfsNode* root = RamfsTrustedRoot();

    // Resolve `/disk/0` itself. The mount registry has a `/disk/0`
    // → FsType::Fat32 entry pointing at volume 0; VfsResolve must
    // therefore land on the FAT32 backend with a directory-typed
    // node (FAT32 root carries attributes 0x10). The volume root
    // is always present by construction whenever FAT32 mounts —
    // unlike a specific seeded file, which depends on the boot
    // image. This keeps the self-test green across both bare-
    // metal smokes (where HELLO.TXT exists) and emulator runs
    // (where it may not).
    VfsNode rootdir = VfsResolve(root, "/disk/0", 64);
    Expect(VfsNodeIsValid(rootdir), "cross-mount: /disk/0 resolves");
    Expect(rootdir.backend == VfsBackend::Fat32, "cross-mount: /disk/0 lands on fat32 backend");
    Expect(VfsNodeIsDir(rootdir), "cross-mount: /disk/0 is dir");
    Expect(rootdir.fat32_volume_idx == 0, "cross-mount: /disk/0 picked volume 0");

    // Resolving a missing file under the same mount returns Invalid
    // (not a stale ramfs hit, since /disk/0/<unique> doesn't exist
    // in either backend).
    VfsNode miss = VfsResolve(root, "/disk/0/_NONE_TEST_NOT_THERE_.X", 64);
    Expect(!VfsNodeIsValid(miss), "cross-mount: missing fat32 file returns Invalid");
    Expect(miss.backend == VfsBackend::Invalid, "cross-mount: miss has Invalid backend");

    // Optional positive case: try `/disk/0/HELLO.TXT` (the canonical
    // Fat32 self-test artifact). Real bare-metal smokes seed it; QEMU
    // smokes that don't have a populated image just log SKIP. We
    // don't `Expect` on this — it's a bonus check when the file is
    // available.
    VfsNode hello = VfsResolve(root, "/disk/0/HELLO.TXT", 64);
    if (VfsNodeIsValid(hello))
    {
        Expect(hello.backend == VfsBackend::Fat32, "cross-mount: HELLO.TXT lands on fat32");
        Expect(VfsNodeIsFile(hello), "cross-mount: HELLO.TXT is file");
        arch::SerialWrite("[fs/vfs] cross-mount self-test OK (with HELLO.TXT)\n");
    }
    else
    {
        arch::SerialWrite("[fs/vfs] cross-mount self-test OK (HELLO.TXT not seeded — root + miss only)\n");
    }
}

} // namespace duetos::fs
