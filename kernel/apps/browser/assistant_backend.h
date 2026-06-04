#pragma once

#include "util/types.h"

/*
 * DuetOS browser — Assistant dock backend (Phase 2b §7). One method: map a user
 * message to a reply string. v1 ships a deterministic LocalHeuristic
 * (assistant_heuristic.cpp) — small fixed intent set + graceful fallback,
 * CI-testable with no external dependency. A RemoteLlm direction routes a POST
 * through the privileged net.fetch executor (Part A), but is inert in v1: there
 * is no secret-store for an API key yet, so the heuristic is the only live path.
 */

namespace duetos::apps::browser
{
// Write a reply for `userMsg` into `out` (NUL-terminated, length < cap). Returns
// true if a reply was produced (always true for the LocalHeuristic — it has a
// catch-all fallback). A leading "navigate:<url>" reply is an intent the dock
// host acts on (it performs the navigation); all other replies are display text.
bool AssistantRespond(const char* userMsg, char* out, duetos::u32 cap);

void AssistantHeuristicSelfTest();

} // namespace duetos::apps::browser
