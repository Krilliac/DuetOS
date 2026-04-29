# Lifetime download tally — survives rolling-channel asset re-uploads

**Last updated:** 2026-04-29
**Type:** Issue + Decision + Pattern
**Status:** Active

## Update 2026-04-29 — badge/state split + idle-run no-op

The first cut of this system put the persistence state inside the
shields.io endpoint JSON under a top-level `_state` key. shields.io
strictly validates the endpoint schema and rejects unknown top-level
properties, returning **`invalid properties: _state`** in place of
the badge. Two-file split fixes it:

- `lifetime-downloads.json` — shields.io envelope ONLY
  (`schemaVersion`, `label`, `message`, `color`, `cacheSeconds`).
  Nothing else. The README badge URL is unchanged.
- `lifetime-downloads-state.json` — persistence (`lifetime_total`,
  `by_asset`, `snapshot_at`, …). Read by the next run.

While there, also fix the spurious-commit problem: the script used to
unconditionally rewrite `snapshot_at`, so every scheduled run pushed
a "stats: lifetime downloads -> 0" no-op commit even when the tally
hadn't moved. Now the script only writes a file when its content
actually differs (badge: when the rendered envelope differs from what
is on disk; state: when `lifetime_total` or `by_asset` changed, or
the state file is missing on the migration run). Idle scheduled runs
become true no-ops that the workflow's `git diff --cached --quiet`
correctly skips.

Migration handling: on the first run after the split, the state file
doesn't exist yet, so `load_prev_state()` falls back to lifting the
`_state` block out of the legacy combined badge file. The state file
is force-written that run (state-missing branch of `state_changed`)
so subsequent runs find the dedicated state file directly and don't
re-bootstrap from a now-clean badge.

## Problem

The README's "lifetime downloads" badge previously used shields.io's
built-in endpoint:

```
https://img.shields.io/github/downloads/krilliac/duetos/total
```

That endpoint sums `download_count` across **currently present**
release assets. Our two rolling channels (`latest-debug`,
`latest-release`) are republished by `softprops/action-gh-release@v2`
on every push to `main` with `overwrite_files: true`. That action
**deletes** the existing asset object and uploads a fresh one whose
`download_count` starts at zero. Net effect: the "total" badge
snapped back to ~0 after every CI run, so a label advertised as
"lifetime" was in fact "current snapshot."

The user-visible symptom: the badge resets every time CI publishes,
contradicting the prose immediately under the badges that promises
"sums every asset download across both channels and never resets."

## Fix

Persist the tally ourselves and have shields.io read it via its
`endpoint` badge type.

### Components

1. **`tools/release/update-lifetime-downloads.py`** — the delta
   arithmetic. Reads a previous snapshot, fetches the current
   GitHub release/asset state, computes per-asset deltas keyed by
   `asset_id` (which is the unique handle that changes when an
   asset is replaced), writes a new snapshot. Output is shaped to
   double as a shields.io endpoint badge response (top-level
   `schemaVersion` / `label` / `message` / `color`) with our state
   parked under `_state`.

2. **`.github/workflows/lifetime-downloads.yml`** — the I/O wrapper.
   Three triggers: `schedule` every 30 minutes (catches organic
   downloads), `workflow_dispatch` (manual reconciliation),
   `workflow_call` (so the publish workflows can request a snapshot
   before they overwrite assets). Concurrency-grouped on
   `lifetime-downloads` so concurrent runs serialize (otherwise
   they'd race on the `stats` branch push). Auto-bootstraps the
   `stats` orphan branch on first run.

3. **`build.yml` / `release.yml` integration** — both publish
   workflows gained a `pre-publish-lifetime-snapshot` job that calls
   `lifetime-downloads.yml` BEFORE the `action-gh-release` step.
   Without that pre-publish snapshot, downloads accrued between
   scheduled snapshots and the next CI publish would be silently
   lost when the asset object is replaced.

4. **`README.md`** — the badge URL switched from
   `/github/downloads/.../total` to
   `https://img.shields.io/endpoint?url=<raw_url_to_stats_branch_json>`.

## Delta arithmetic (the `compute_new_total` core)

Per current asset:
- `asset_id` already in previous snapshot:
  `delta += max(0, current_count - previous_count)`
  (count went up → fold the increase; count went down → asset was
  reset mid-life, ignore so lifetime never decrements)
- `asset_id` not in previous snapshot:
  `delta += current_count`
  (asset is fresh — either a new release or the post-replacement
  successor of a deleted asset; the deleted predecessor's count is
  already in `lifetime_total` from its last snapshot)
- previously-present `asset_id` no longer present:
  no delta — its count was captured at its last snapshot and is
  already part of the running total.

`new_lifetime_total = old_lifetime_total + delta`. Monotonically
non-decreasing by construction.

## Why a `stats` branch (not `main`)

Pushing the JSON to `main` would either trigger CI on every
snapshot (wasteful) or require `paths-ignore` discipline that is
easy to break. An orphan `stats` branch:
- doesn't appear in `branches: [main, claude/**]` triggers
- keeps the JSON out of `main`'s diff history
- has no source code to confuse readers
- can be force-rewritten if needed (the JSON is regenerable from
  the current state plus a one-time review of historical totals)

## Failure modes considered

| Scenario | Behaviour |
|----------|-----------|
| First run, no prior snapshot | Bootstrap from sum of current counters; treat that sum as "previously archived". Subsequent deltas accrue from there. |
| `stats` branch missing | Workflow creates it as an orphan branch with a one-line README and an initial JSON. |
| Snapshot file malformed | `--state` JSONDecodeError → script exits 2; manual intervention needed. |
| GitHub API unavailable | Script exits 1 with a clear error; the workflow run fails but doesn't corrupt state. |
| Two snapshots race | `concurrency: lifetime-downloads` (no cancel-in-progress) serializes. |
| Asset count goes DOWN between snapshots (impossible per GitHub's API but defensive) | Ignored — lifetime never decrements. |
| An asset is renamed but keeps its `asset_id` | Counted correctly — keying by `asset_id` not `name`. |
| `workflow_call` fails inside `release.yml` | Publish jobs gate on `(snapshot.result == 'success' \|\| 'failure')` — a failed snapshot doesn't block the release; the next scheduled run reconciles. |

## Verification

Offline simulation in `/tmp` exercising:

- first run with 15 downloads → total 15
- idle scheduled snapshot → total 15
- +3 downloads → total 18
- pre-publish snapshot, then CI replaces both assets (new IDs,
  count=0) → total stays at 18
- +7 downloads on the new asset → total 25
- new tag release with 100 downloads → total 125

All scenarios produced the expected lifetime total. Real CI
verification will land on first push to `main` after merge.

## Files

- `tools/release/update-lifetime-downloads.py` — delta logic + CLI
  (now takes `--state` and `--badge` as separate paths).
- `.github/workflows/lifetime-downloads.yml` — I/O wrapper, tracks
  both `lifetime-downloads.json` and `lifetime-downloads-state.json`.
- `.github/workflows/build.yml` — `pre-publish-lifetime-snapshot` job
- `.github/workflows/release.yml` — `pre-publish-lifetime-snapshot` job
- `README.md` — badge URL is `https://img.shields.io/endpoint?url=`
  pointing at the badge-only `lifetime-downloads.json` on `stats`.

## Re-derivation (audit cadence)

If we ever doubt the count, regenerate from scratch by:
1. Wiping `lifetime-downloads.json` on the `stats` branch
2. Triggering `lifetime-downloads.yml` via workflow_dispatch
3. Bootstrap path will seed total from current asset counters

That's exactly the badge state we had before the fix, so the worst
case for a blown stats file is "back to the old behaviour for one
CI cycle" — not worse.
