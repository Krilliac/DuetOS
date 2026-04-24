#include "vfs.h"

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

} // namespace duetos::fs
