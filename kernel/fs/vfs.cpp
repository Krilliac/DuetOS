#include "fs/vfs.h"

#include "arch/x86_64/serial.h"
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

    arch::SerialWrite("[fs/vfs] self-test OK (32 cases: lookup + jail + .. + path_max)\n");
}

} // namespace duetos::fs
