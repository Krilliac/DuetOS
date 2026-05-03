#include "drivers/gpu/dpms.h"

#include "core/panic.h"

namespace duetos::drivers::gpu
{

namespace
{

DpmsState g_state = DpmsState::On;
DpmsTransitionFn g_hook = nullptr;
void* g_hook_ctx = nullptr;
u64 g_transitions = 0;

bool StateValid(DpmsState s)
{
    const u8 v = u8(s);
    return v <= u8(DpmsState::Off);
}

} // namespace

const char* DpmsStateName(DpmsState s)
{
    switch (s)
    {
    case DpmsState::On:
        return "On";
    case DpmsState::Standby:
        return "Standby";
    case DpmsState::Suspend:
        return "Suspend";
    case DpmsState::Off:
        return "Off";
    }
    return "?";
}

void DpmsInit()
{
    g_state = DpmsState::On;
    g_hook = nullptr;
    g_hook_ctx = nullptr;
    g_transitions = 0;
}

void DpmsRegisterHook(DpmsTransitionFn fn, void* ctx)
{
    g_hook = fn;
    g_hook_ctx = ctx;
}

bool DpmsSetState(DpmsState target)
{
    if (!StateValid(target))
        return false;
    if (target == g_state)
        return true; // idempotent

    if (g_hook != nullptr)
    {
        if (!g_hook(g_state, target, g_hook_ctx))
            return false; // driver vetoed
    }
    g_state = target;
    ++g_transitions;
    return true;
}

DpmsState DpmsGet()
{
    return g_state;
}

u64 DpmsTransitionCount()
{
    return g_transitions;
}

namespace
{

// Self-test scaffolding.
struct TestCtx
{
    u32 calls;
    DpmsState last_from;
    DpmsState last_to;
    bool veto_next;
};

bool RecordHook(DpmsState from, DpmsState to, void* ctx)
{
    auto* tc = static_cast<TestCtx*>(ctx);
    tc->last_from = from;
    tc->last_to = to;
    ++tc->calls;
    if (tc->veto_next)
    {
        tc->veto_next = false;
        return false;
    }
    return true;
}

} // namespace

void DpmsSelfTest()
{
    // Init.
    DpmsInit();
    KASSERT(DpmsGet() == DpmsState::On, "drivers/gpu/dpms", "init state wrong");
    KASSERT(DpmsTransitionCount() == 0, "drivers/gpu/dpms", "init counter wrong");

    // Idempotent transition: On→On returns true and doesn't bump.
    KASSERT(DpmsSetState(DpmsState::On), "drivers/gpu/dpms", "On→On should succeed");
    KASSERT(DpmsTransitionCount() == 0, "drivers/gpu/dpms", "On→On bumped counter");

    // Transition without a hook: bookkeeper-only mode.
    KASSERT(DpmsSetState(DpmsState::Standby), "drivers/gpu/dpms", "On→Standby (no hook) failed");
    KASSERT(DpmsGet() == DpmsState::Standby, "drivers/gpu/dpms", "post-transition state wrong");
    KASSERT(DpmsTransitionCount() == 1, "drivers/gpu/dpms", "transition count wrong (1)");

    // Register a hook + transition through it.
    TestCtx tc = {};
    DpmsRegisterHook(RecordHook, &tc);
    KASSERT(DpmsSetState(DpmsState::Suspend), "drivers/gpu/dpms", "Standby→Suspend (hook) failed");
    KASSERT(tc.calls == 1, "drivers/gpu/dpms", "hook call count wrong");
    KASSERT(tc.last_from == DpmsState::Standby && tc.last_to == DpmsState::Suspend, "drivers/gpu/dpms",
            "hook from/to wrong");
    KASSERT(DpmsTransitionCount() == 2, "drivers/gpu/dpms", "transition count wrong (2)");

    // Hook veto: state stays at Suspend.
    tc.veto_next = true;
    KASSERT(!DpmsSetState(DpmsState::Off), "drivers/gpu/dpms", "veto should block");
    KASSERT(DpmsGet() == DpmsState::Suspend, "drivers/gpu/dpms", "veto must preserve state");
    KASSERT(tc.calls == 2, "drivers/gpu/dpms", "veto-call count wrong");
    KASSERT(DpmsTransitionCount() == 2, "drivers/gpu/dpms", "veto bumped counter");

    // Direct any→any transition is legal per the spec.
    KASSERT(DpmsSetState(DpmsState::Off), "drivers/gpu/dpms", "Suspend→Off failed");
    KASSERT(DpmsSetState(DpmsState::On), "drivers/gpu/dpms", "Off→On failed");
    KASSERT(DpmsGet() == DpmsState::On, "drivers/gpu/dpms", "Off→On state wrong");

    // Detach hook.
    DpmsRegisterHook(nullptr, nullptr);
    KASSERT(DpmsSetState(DpmsState::Suspend), "drivers/gpu/dpms", "post-detach transition failed");
    KASSERT(DpmsGet() == DpmsState::Suspend, "drivers/gpu/dpms", "post-detach state wrong");

    // Reset.
    DpmsInit();
    KASSERT(DpmsGet() == DpmsState::On, "drivers/gpu/dpms", "re-init state wrong");
}

} // namespace duetos::drivers::gpu
