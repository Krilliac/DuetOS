/*
 * userland/libs/kernelbase/kernelbase.c
 *
 * DuetOS kernelbase.dll — a pure forwarder DLL. Every export
 * is a cross-DLL forwarder (via msvcp140.dll-style .def) to
 * the matching kernel32.dll entry. The forwarder chaser
 * in kernel/core/pe_loader.cpp recurses
 * through these at load time, so an import of
 * `kernelbase.dll!GetCurrentProcessId` ends up pointing at
 * `kernel32.dll!GetCurrentProcessId` via a one-hop chase.
 *
 * lld-link needs at least one symbol to link against even when
 * the EXPORTS are all forwarders; this tiny `kernelbase_unused`
 * symbol satisfies that. It's not itself exported.
 */

void kernelbase_unused(void) {}
