/*
 * DuetOS — kernel shell: cross-TU shell state.
 *
 * Definitions of the long-lived shell tables that need to be
 * visible from more than one shell sibling TU. Currently this
 * houses the environment table (g_env + EnvFind / EnvSet /
 * EnvUnset) and the alias table (g_aliases + AliasFind /
 * AliasSet / AliasUnset). The history ring will follow on a
 * subsequent hoist slice.
 *
 * Sized helpers (EnvNameEq / EnvCopy) live inline in
 * shell_internal.h so callers in either table or any sibling TU
 * reach them through the same header without a back-edge here.
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

constinit AliasSlot g_aliases[kAliasSlotCount] = {};

AliasSlot* AliasFind(const char* name)
{
    for (u32 i = 0; i < kAliasSlotCount; ++i)
    {
        if (g_aliases[i].in_use && EnvNameEq(g_aliases[i].name, name))
        {
            return &g_aliases[i];
        }
    }
    return nullptr;
}

bool AliasSet(const char* name, const char* expansion)
{
    AliasSlot* s = AliasFind(name);
    if (s == nullptr)
    {
        for (u32 i = 0; i < kAliasSlotCount; ++i)
        {
            if (!g_aliases[i].in_use)
            {
                s = &g_aliases[i];
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
    EnvCopy(s->expansion, expansion, kAliasExpansionMax);
    return true;
}

bool AliasUnset(const char* name)
{
    AliasSlot* s = AliasFind(name);
    if (s == nullptr)
    {
        return false;
    }
    s->in_use = false;
    s->name[0] = '\0';
    s->expansion[0] = '\0';
    return true;
}

} // namespace duetos::core::shell::internal
