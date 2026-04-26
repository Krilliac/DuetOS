/*
 * DuetOS — kernel shell: cross-TU shell state.
 *
 * Definitions of the long-lived shell tables that need to be
 * visible from more than one shell sibling TU. Currently this is
 * just the environment table (g_env + EnvFind / EnvSet / EnvUnset);
 * the alias table and history ring will follow on subsequent
 * hoist slices.
 *
 * Sized helpers (EnvNameEq / EnvCopy) live inline in
 * shell_internal.h so the alias-table code that still lives in
 * shell.cpp can call them without a TU dependency back here.
 */

#include "shell_internal.h"

namespace duetos::core::shell::internal
{

constinit EnvSlot g_env[kEnvSlotCount] = {};

EnvSlot* EnvFind(const char* name)
{
    for (u32 i = 0; i < kEnvSlotCount; ++i)
    {
        if (g_env[i].in_use && EnvNameEq(g_env[i].name, name))
        {
            return &g_env[i];
        }
    }
    return nullptr;
}

bool EnvSet(const char* name, const char* value)
{
    EnvSlot* s = EnvFind(name);
    if (s == nullptr)
    {
        for (u32 i = 0; i < kEnvSlotCount; ++i)
        {
            if (!g_env[i].in_use)
            {
                s = &g_env[i];
                s->in_use = true;
                break;
            }
        }
    }
    if (s == nullptr)
    {
        return false;
    }
    EnvCopy(s->name, name, kEnvNameMax);
    EnvCopy(s->value, value, kEnvValueMax);
    return true;
}

bool EnvUnset(const char* name)
{
    EnvSlot* s = EnvFind(name);
    if (s == nullptr)
    {
        return false;
    }
    s->in_use = false;
    s->name[0] = '\0';
    s->value[0] = '\0';
    return true;
}

} // namespace duetos::core::shell::internal
