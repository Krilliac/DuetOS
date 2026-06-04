#pragma once

#include "util/types.h"

/*
 * DuetOS browser — Privileged-Origin Mode (spec §13.6 / §13.8): the
 * capability set + the path canonicalisation/containment that is the
 * SECURITY KEYSTONE of the broker. It decides whether a privileged fs
 * request escapes its scoped roots.
 *
 * Adversarial surface this module closes (all boot-self-tested):
 *   - `..`-escapes (resolved, then containment-checked)
 *   - sibling-prefix bypass (`/home/userX` vs root `/home/user`) — boundary check
 *   - audit.log basename injection, incl. case-fold / trailing-dot / `::$DATA`
 *     colon variants
 *   - `/dev` `/proc` `/sys` `/boot` nodes
 *   - backslash separators (FAT/NTFS confusion)
 *   - NUL / control bytes; non-ASCII (conservatively — closes NFD/NFC + homoglyph)
 *
 * Proven a NON-bypass (treated as a literal, NOT decoded): percent / double
 * encoding (`%2e%2e`) — paths are raw bytes, never percent-decoded.
 *
 * NOT closeable by string canonicalisation — symlink races (TOCTOU). A string
 * check can't resolve symlinks; the real defense is the kernel fs layer
 * re-enforcing the scope AFTER path resolution (Task 8 integration). This is a
 * deliberate GAP at THIS layer.
 *
 * Fail-closed: anything ambiguous is refused.
 */

namespace duetos::apps::browser::priv
{
enum class Cap : duetos::u8
{
    FsRead = 0,
    FsWrite = 1,
    ProcSpawn = 2,
    KernelRead = 3,
    Net = 4,
    // NOTE: there is deliberately NO installHandler capability in v1 (spec §13.6).
};

struct CapSet
{
    duetos::u16 bits = 0;
    void Add(Cap c) { bits = static_cast<duetos::u16>(bits | (1u << static_cast<duetos::u32>(c))); }
    bool Has(Cap c) const { return (bits & (1u << static_cast<duetos::u32>(c))) != 0; }
};

// The default-arm set (spec §13.6): fs-read/write, proc-spawn, kernel-read, net.
CapSet DefaultArmScope();

struct Roots
{
    const char* root[4] = {};
    duetos::u32 count = 0;
};

// Canonicalise `in`, refuse structural-invariant paths, and require the result
// lies within one of `roots`. On success writes the NUL-terminated canonical
// path into out[cap] and returns true. Returns false (fail-closed) on any
// sanitisation failure, escape, refused path, out-of-roots path, or overflow.
bool CanonicalizeAndContain(const char* in, const Roots& roots, char* out, duetos::u32 cap);

void ScopeSelfTest();

} // namespace duetos::apps::browser::priv
