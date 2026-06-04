#include "security/privilege/broker.h"

namespace duetos::security::privilege
{
Verdict ValidateRequest(const PrivTab& tab, const Roots& roots, const PrivRequest& r, char* canonOut, duetos::u32 cap)
{
    // 1: the tab must be armed (spec §13.1 — arming skips the prompt, not this).
    if (!tab.IsArmed())
        return Verdict{false, "EPERM: not armed"};

    // 2: the requested capability must be in the armed scope.
    if (!tab.scope.Has(r.cap))
        return Verdict{false, "EPERM: capability not granted"};

    // 3: filesystem caps must reference a path within the scoped roots, with
    //    full canonicalisation + structural-invariant refusals (Task 2).
    if (r.cap == Cap::FsRead || r.cap == Cap::FsWrite)
    {
        if (r.path == nullptr)
            return Verdict{false, "EINVAL: null path"};
        if (!CanonicalizeAndContain(r.path, roots, canonOut, cap))
            return Verdict{false, "EPERM: outside scoped roots"};
        // 4: bound a write.
        if (r.cap == Cap::FsWrite && r.byteLen > kMaxPrivWriteBytes)
            return Verdict{false, "EINVAL: oversize write"};
    }

    return Verdict{true, ""};
}

} // namespace duetos::security::privilege
