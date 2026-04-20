# GitHub API — PR Checks Diagnosis

**Last updated:** 2026-04-20
**Type:** Pattern
**Status:** Active

## Description

The full workflow for polling PR checks, diagnosing failures, and retriggering jobs **using the GitHub MCP tools available in this environment**. There is no `gh` CLI here — every GitHub interaction goes through the `mcp__github__*` tool family.

Paired with [build-optimizations.md](build-optimizations.md) (which explains *why* the steps below are ordered as they are) and [workflow-patterns.md](workflow-patterns.md) (which shows where this fits in the post-push flow).

---

## 1 — Snapshot the PR state

Use `mcp__github__pull_request_read` to pull the aggregate check state in a single call:

- `method: "get"` — basic PR metadata
- `method: "get_status"` — the aggregate `statusCheckRollup`

Don't poll in a tight loop. CI runs take minutes; a single snapshot per iteration, followed by other work, is enough.

## 2 — Identify the failing job

From the `get_status` response, pull out any check with `conclusion: "failure"`. Record its name and the associated run/check ID.

For a broader view of recent runs on the branch, use `mcp__github__list_commits` on the PR's head ref and correlate with check results.

## 3 — Read only the failed job's log

Never download full logs. Most CI matrices emit tens of MB of output across all jobs, almost none of it relevant. Request only the failed job's logs via whatever the MCP equivalent of `--log-failed` exposes (often via `pull_request_read` extended fields, or by fetching the check run directly).

## 4 — Narrow to the first error line

In the failed log, the relevant failure is almost always the first `error:` or `FAILED` line. When the root cause is buried (e.g., CMake reports a link error but the real issue was a missing symbol upstream), also scan for the first "ninja: build stopped" / "make: *** ... Error" line and read ~40 lines above.

## 5 — Reproduce locally

Pull the matching preset from `.github/workflows/*.yml` (once it exists). Planned presets:

```bash
cmake --preset x86_64-release && cmake --build build --parallel $(nproc)
cmake --preset x86_64-debug   && cmake --build build --parallel $(nproc)
cmake --preset x86_64-kasan   && cmake --build build --parallel $(nproc)
```

Until the build system lands, "reproduce locally" means: trace the failing command back to its source (a shell step in a workflow file, a CMake rule, etc.) and run that command directly.

## 6 — Fix, push, re-poll

Standard flow:

```bash
git add -u && git commit -m "fix: <what>"
git push -u origin <branch>
```

Then wait a moment and re-run step 1. Do not `--amend` to the tip and force-push unless the PR explicitly needs the rewrite — a new commit is clearer in review.

## Notes

- Always fetch (`git fetch origin`) before diagnosing a shared PR; someone else may already have pushed a fix.
- If a failing job is marked `continue-on-error` in the workflow file, the PR can still merge. Don't block on those unless the user explicitly asks.
- **Do not** use the `gh` CLI in this environment — it is not available. Every GitHub action goes through `mcp__github__*`.
- Be frugal with PR comments. Only post when a human reply is genuinely necessary (e.g., explaining why a suggested change won't work). Code replies should land as commits, not comments.

## See also

- [build-optimizations.md](build-optimizations.md) — rationale for downloading only failed logs, parallel builds for rebuilds.
- [workflow-patterns.md](workflow-patterns.md) — post-push verification flow.
- Parent project guide: `CLAUDE.md` → "Post-PR checks" section.
