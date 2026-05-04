# Agent Session Bootstrap

Scope: entire repository (`DuetOS`).

For every new session/chat in this repo:

1. Read `CLAUDE.md` first.
2. Then skim the wiki — start at `wiki/Home.md` or `wiki/_Sidebar.md` for the table of contents.
3. Pending and deferred work is tracked in `wiki/reference/Roadmap.md`.
4. Use `CLAUDE.md` plus the relevant wiki pages as persistent project context for workflow, conventions, and task execution.

If `CLAUDE.md` is missing, report that clearly and continue with available context.

## Project summary for agents

DuetOS is a from-scratch x86_64 operating system that runs **Windows PE executables as a native ABI** and targets commodity Intel/AMD/NVIDIA hardware. The Win32 subsystem (PE loader, NT syscall surface, `ntdll`/`kernel32`/`user32`/`gdi32`/`d3d*`) is a peer to the native ABI, not an emulator bolted on top. See `CLAUDE.md` → "What is this?" for the full scope and non-goals.
