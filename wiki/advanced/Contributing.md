# Contributing

> **Audience:** All contributors
>
> **Execution context:** N/A
>
> **Maturity:** Stable

## Overview

This page is the entry point for contributors. It points at the
authoritative coding/anti-bloat/git rules elsewhere in the wiki and
adds the wiki-specific contribution conventions.

## Wiki Authoring Standard

**Every wiki page** should follow the structure in
[`_Template.md`](../_Template.md):

1. **Title** — what the page is about, in noun form.
2. **Audience block** — who should read this (kernel hackers, driver
   authors, PE devs, security folks, etc.).
3. **Execution context** — kernel / userland / both / IRQ-safe /
   sleep-safe / process.
4. **Maturity** — v0 (just landed), active, stable, deprecated.
5. **Overview** — one paragraph stating what the page covers and
   why.
6. **Body sections** — keyed to the topic.
7. **Known Limits / GAPs / STUBs** — itemise what is **not**
   implemented yet. Anything carrying a `// STUB:` or `// GAP:`
   marker in the source belongs here so future audits can find it
   from the wiki side too.
8. **Related Pages** — link to adjacent wiki pages and specs.

## Pre-commit Checklist

| Step | Command |
|------|---------|
| 1. Sync with main | `git fetch origin main && git rebase origin/main` |
| 2. Format check | `find ... | xargs clang-format --dry-run --Werror` |
| 3. Configure | `cmake --preset x86_64-release` |
| 4. Build | `cmake --build build --parallel $(nproc)` |
| 5. Tests | `cd build && ctest --output-on-failure` |
| 6. QEMU smoke | `tools/qemu/run.sh --headless --timeout 30` |
| 7. Wiki sync | `docs/sync-wiki.sh sync` (if you touched code that the auto-blocks track) |
| 8. Wiki nav | `tools/check-wiki-nav.sh` (if you added/removed a wiki page) |
| 9. Wiki quality | `tools/check-wiki-quality.sh --warn-only` |

## When to Add a Wiki Page

Add a page when:

- A new subsystem lands and is wired into the boot path.
- A new driver class is added to `kernel/drivers/`.
- A new Win32 DLL is added to `userland/libs/`.
- A new specification (ABI, file format, protocol) is committed
  to the repo.
- A standalone topic accumulates enough cross-page references that
  inlining everywhere is worse than one canonical page.

Don't add a page when:

- The topic is a one-paragraph addendum to an existing page —
  amend that page instead.
- The topic is a session-specific finding — that goes in
  `.claude/knowledge/`.
- The topic is a transient TODO — that goes in a plan file under
  `.claude/knowledge/<slug>-plan.md`.

## Page Lifecycle

- **Add**: create the file under the right category folder, add
  a row to `_Sidebar.md`, push as part of the same commit as the
  code it documents.
- **Update**: edit in place. The auto-sync blocks
  (`<!-- AUTO:* -->`) refresh from `docs/sync-wiki.sh sync`.
- **Delete**: only when the underlying subsystem is removed.
  Update `_Sidebar.md` in the same commit.

## See Also

- [Coding Standards](../tooling/Coding-Standards.md)
- [Anti-Bloat Guidelines](../tooling/Anti-Bloat-Guidelines.md)
- [Git Workflow](../tooling/Git-Workflow.md)
- [Build System](../tooling/Build-System.md)
- [QEMU Smoke Tests](../tooling/QEMU-Smoke.md)
- [Knowledge Base Index](../reference/Knowledge-Base-Index.md)
