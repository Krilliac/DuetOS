#pragma once

#include "security/privilege/scope.h"
#include "util/types.h"

/*
 * DuetOS — Privilege Engine (spec §13.3): boot-flag config. The feature is
 * OFF unless the kernel cmdline carries `--allow-claude-system-access`
 * (optionally `=root[:root2…]` to set the scoped roots; bare → a single
 * conservative default). Absent ⇒ no client binding is ever installed.
 * Pure parse — boot-self-tested.
 */

namespace duetos::security::privilege
{
struct PrivConfig
{
    bool available = false; // the master switch (the boot flag was present)
    Roots roots{};          // scoped roots; root[] points into `storage`
    char storage[256] = {}; // backing bytes for the root strings
};

// Parse `cmdline` into `cfg`. Recognises the flag as a whole token; a bare
// flag uses the default root "/home/user"; `=a:b` sets roots a, b (capped).
void PrivConfigParse(const char* cmdline, PrivConfig& cfg);

// The single boot-time config the whole Privilege Engine reads. Boot calls
// PrivConfigSetCurrent once (after parsing the real kernel cmdline); every
// client (browser chrome, the binding installer) reads PrivConfigCurrent().
// Before the boot wire-up runs it reports a default {available=false} — so a
// kernel built without the flag never exposes any privileged surface.
const PrivConfig& PrivConfigCurrent();
void PrivConfigSetCurrent(const PrivConfig& cfg);

void PrivConfigSelfTest();

} // namespace duetos::security::privilege
