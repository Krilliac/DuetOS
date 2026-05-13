#include "loader/compat_shim.h"

#include "core/panic.h"
#include "fs/ramfs.h"
#include "log/klog.h"
#include "proc/process.h"
#include "util/types.h"

namespace duetos::core::compat
{

namespace
{

// ASCII-only case-fold. The sidecar is restricted to ASCII keys
// + values, so a Unicode-aware fold would be wasted complexity.
char Lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c;
}

// Case-insensitive equality for NUL-terminated `a` vs. range
// `[b, b+len)`. Used for both key matching and the sidecar-
// filename suffix check.
bool IEqRange(const char* a, const char* b, u64 len)
{
    u64 i = 0;
    for (; i < len; ++i)
    {
        const char ca = a[i];
        if (ca == '\0')
            return false;
        if (Lower(ca) != Lower(b[i]))
            return false;
    }
    return a[i] == '\0';
}

bool IEq(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0')
    {
        if (Lower(*a) != Lower(*b))
            return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

// Append `suffix` to `base` into `out`, capped at `cap`. Returns
// true on success. Used to derive the sidecar basename from the
// PE program_name. Both inputs are NUL-terminated.
bool JoinSuffix(char* out, u64 cap, const char* base, const char* suffix)
{
    u64 oi = 0;
    for (u64 i = 0; base[i] != '\0'; ++i)
    {
        if (oi + 1 >= cap)
            return false;
        out[oi++] = base[i];
    }
    for (u64 i = 0; suffix[i] != '\0'; ++i)
    {
        if (oi + 1 >= cap)
            return false;
        out[oi++] = suffix[i];
    }
    out[oi] = '\0';
    return true;
}

// Find a Ramfs file child of `root` whose name equals `name`
// (case-insensitive). Returns nullptr on miss. Bounded walk; we
// don't recurse — sidecars live next to the PE.
const fs::RamfsNode* FindChild(const fs::RamfsNode* root, const char* name)
{
    if (root == nullptr || root->children == nullptr)
        return nullptr;
    for (u64 i = 0; root->children[i] != nullptr; ++i)
    {
        const fs::RamfsNode* c = root->children[i];
        if (c->type != fs::RamfsNodeType::kFile)
            continue;
        if (c->name == nullptr)
            continue;
        if (IEq(c->name, name))
            return c;
    }
    return nullptr;
}

bool ParseBool(const char* val_start, u64 val_len, bool* out)
{
    auto match = [&](const char* lit) { return IEqRange(lit, val_start, val_len); };
    if (match("1") || match("true") || match("yes") || match("on"))
    {
        *out = true;
        return true;
    }
    if (match("0") || match("false") || match("no") || match("off"))
    {
        *out = false;
        return true;
    }
    return false;
}

// Walk a single line `[start, end)` and apply it to `policy`.
// `line_no` is the 1-based source line, used in diagnostics.
// Returns 1 if a recognised key was applied, 0 if unknown,
// negative if the line was malformed (no `=`, bad value).
i32 ApplyLine(CompatPolicy* policy, const u8* start, const u8* end, u32 line_no)
{
    // Skip leading whitespace.
    while (start < end && (*start == ' ' || *start == '\t'))
        ++start;
    if (start >= end || *start == '#' || *start == '\n' || *start == '\r')
        return 0;
    // Trim trailing whitespace + CR (LF was the separator).
    while (end > start && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'))
        --end;
    // Find the `=`.
    const u8* eq = nullptr;
    for (const u8* p = start; p < end; ++p)
    {
        if (*p == '=')
        {
            eq = p;
            break;
        }
    }
    if (eq == nullptr)
    {
        KLOG_WARN_V("loader/compat", "malformed sidecar line (no '=')", line_no);
        return -1;
    }
    const u8* key_start = start;
    const u8* key_end = eq;
    while (key_end > key_start && (key_end[-1] == ' ' || key_end[-1] == '\t'))
        --key_end;
    const u8* val_start = eq + 1;
    while (val_start < end && (*val_start == ' ' || *val_start == '\t'))
        ++val_start;
    const u64 key_len = static_cast<u64>(key_end - key_start);
    const u64 val_len = static_cast<u64>(end - val_start);

    struct Entry
    {
        const char* key;
        bool CompatPolicy::*field;
    };
    static const Entry kEntries[] = {
        {"ignore_debugger_present", &CompatPolicy::ignore_debugger_present},
        {"ignore_etw", &CompatPolicy::ignore_etw},
        {"fake_ok_stack_guarantee", &CompatPolicy::fake_ok_stack_guarantee},
    };

    const char* key_bytes_c = reinterpret_cast<const char*>(key_start);
    for (const auto& e : kEntries)
    {
        if (IEqRange(e.key, key_bytes_c, key_len))
        {
            bool parsed = false;
            if (!ParseBool(reinterpret_cast<const char*>(val_start), val_len, &parsed))
            {
                KLOG_WARN_V("loader/compat", "sidecar value not bool-shaped on line", line_no);
                return -1;
            }
            policy->*e.field = parsed;
            return 1;
        }
    }
    KLOG_INFO_V("loader/compat", "sidecar key unknown (ignored) on line", line_no);
    return 0;
}

} // namespace

void Reset(CompatPolicy* policy)
{
    policy->ignore_debugger_present = false;
    policy->ignore_etw = false;
    policy->fake_ok_stack_guarantee = false;
    policy->applied = false;
    policy->keys_applied = 0;
    policy->keys_unknown = 0;
    policy->_pad[0] = 0;
    policy->_pad[1] = 0;
}

namespace
{
bool ApplyBufferToPolicy(CompatPolicy* policy, const u8* buf, u64 buf_len)
{
    if (policy == nullptr || buf == nullptr)
        return false;
    const u8* p = buf;
    const u8* end = buf + buf_len;
    u32 line_no = 0;
    while (p < end)
    {
        ++line_no;
        const u8* line_start = p;
        while (p < end && *p != '\n')
            ++p;
        const i32 r = ApplyLine(policy, line_start, p, line_no);
        if (r > 0)
            ++policy->keys_applied;
        else if (r == 0 && line_start < p && *line_start != '#')
            ++policy->keys_unknown;
        if (p < end)
            ++p;
    }
    policy->applied = true;
    return true;
}
} // namespace

bool ApplyBuffer(Process* proc, const u8* buf, u64 buf_len)
{
    if (proc == nullptr)
        return false;
    CompatPolicy* policy = &proc->compat_policy;
    if (!ApplyBufferToPolicy(policy, buf, buf_len))
        return false;
    KLOG_INFO_2V("loader/compat", "sidecar applied", "keys-applied", static_cast<u64>(policy->keys_applied),
                 "keys-unknown", static_cast<u64>(policy->keys_unknown));
    return true;
}

bool ApplySidecar(Process* proc, const fs::RamfsNode* root, const char* program_name)
{
    if (proc == nullptr || root == nullptr || program_name == nullptr)
        return false;
    char buf[96];
    if (!JoinSuffix(buf, sizeof(buf), program_name, ".duetcompat"))
    {
        // Program name too long to host a sidecar name — skip
        // silently. The PE still loads normally.
        return false;
    }
    const fs::RamfsNode* node = FindChild(root, buf);
    if (node == nullptr)
        return false;
    return ApplyBuffer(proc, node->file_bytes, node->file_size);
}

bool ShouldIgnoreDebugger(const Process* proc)
{
    return proc != nullptr && proc->compat_policy.ignore_debugger_present;
}
bool ShouldIgnoreEtw(const Process* proc)
{
    return proc != nullptr && proc->compat_policy.ignore_etw;
}
bool ShouldFakeOkStackGuarantee(const Process* proc)
{
    return proc != nullptr && proc->compat_policy.fake_ok_stack_guarantee;
}

void SelfTest()
{
    // In-memory sidecar that touches every recognised key + one
    // intentionally-unknown one (to exercise the warn-and-ignore
    // path) + one comment line (to exercise the skip path).
    static const char kSidecar[] = "# duetos-compat self-test\n"
                                   "ignore_debugger_present=1\n"
                                   "ignore_etw=true\n"
                                   "fake_ok_stack_guarantee = YES\n"
                                   "future_key=on\n";

    // Drive the parser directly against a stack-local CompatPolicy
    // instead of a stack-local Process — Process is several KiB
    // and we run during early boot. The parser only touches
    // `compat_policy`, so this exercises the full code path.
    CompatPolicy policy;
    Reset(&policy);
    const bool ok = ApplyBufferToPolicy(&policy, reinterpret_cast<const u8*>(kSidecar), sizeof(kSidecar) - 1);
    if (!ok)
        Panic("loader/compat", "self-test: ApplyBufferToPolicy failed");
    if (!policy.ignore_debugger_present || !policy.ignore_etw || !policy.fake_ok_stack_guarantee)
        Panic("loader/compat", "self-test: a recognised key didn't take effect");
    if (policy.keys_applied != 3)
        Panic("loader/compat", "self-test: keys_applied != 3");
    if (policy.keys_unknown != 1)
        Panic("loader/compat", "self-test: keys_unknown != 1");
}

} // namespace duetos::core::compat
