#pragma once

// Private cross-TU surface for the kernel shell. Splits the
// command implementations across multiple sibling translation
// units that share declarations of the per-command Cmd*
// handlers below. Anything in `namespace duetos::core::shell::internal`
// is intended for the shell's own TUs only — never include this
// header from outside kernel/core/.
//
// The dispatcher in shell.cpp pulls every Cmd* name back into
// its outer namespace via `using namespace shell::internal;`,
// so the existing if/else dispatch chain keeps reading like the
// in-TU layout the file used to have.

#include "../core/types.h"

namespace duetos::core::shell::internal
{

// ---------------------------------------------------------------
// Account management commands (shell_security.cpp). Thin wrappers
// around auth.h. Admin-only paths are enforced inside each
// handler so the kernel-side API stays pure data-access.
// ---------------------------------------------------------------
void CmdUsers();
void CmdUseradd(u32 argc, char** argv);
void CmdUserdel(u32 argc, char** argv);
void CmdPasswd(u32 argc, char** argv);
void CmdLogout();
void CmdSu(u32 argc, char** argv);
void CmdLoginCmd(u32 argc, char** argv);

// ---------------------------------------------------------------
// Storage / mount / device-list commands (shell_storage.cpp).
// Thin views over the block layer + GPT parser + mount table.
// (Fat* commands and CmdRead are queued for a follow-up slice.)
// ---------------------------------------------------------------
void CmdMount();
void CmdLsblk();
void CmdLsgpt();
void CmdLsmod();

} // namespace duetos::core::shell::internal
