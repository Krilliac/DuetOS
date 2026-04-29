#!/usr/bin/env python3
# Persist a monotonically non-decreasing lifetime download tally for
# DuetOS release assets. The motivating problem: shields.io's
# /github/downloads/{owner}/{repo}/total endpoint sums *currently
# present* asset download counters. Our rolling channels
# (`latest-release`, `latest-debug`) are republished on every push to
# `main` with `softprops/action-gh-release@v2 overwrite_files: true`,
# which deletes the old asset object and uploads a fresh one with
# count = 0. The result: GitHub's "total" snaps back to near-zero on
# every CI run, so the badge advertised as "lifetime" is in fact
# "current snapshot."
#
# This script reconstructs a real lifetime number by:
#   * reading the previous snapshot's persistence state
#   * fetching the current state of every release asset via the
#     GitHub REST API
#   * computing the *delta* per asset since the last snapshot
#     - same asset_id still present:  delta += max(0, new - old)
#     - new asset_id (replaced/added): delta += new
#     - asset_id disappeared:           ignored (its count was already
#       captured as part of the running total when it was last seen)
#   * writing a new snapshot with `lifetime_total = old_total + delta`
#     and a `by_asset` map of currently-live asset counts.
#
# Output is split across two files:
#   * --badge → shields.io endpoint schema (schemaVersion / label /
#     message / color / cacheSeconds). NOTHING ELSE — shields.io
#     rejects unknown top-level properties (it returns "invalid
#     properties: _state" if you give it any).
#   * --state → our persistence dict (lifetime_total, by_asset,
#     snapshot_at, …). Read by the next run; not consumed by
#     shields.io.
#
# Usage:
#   GITHUB_TOKEN=... \
#   GITHUB_REPOSITORY=krilliac/duetos \
#     tools/release/update-lifetime-downloads.py \
#       --state path/to/lifetime-downloads-state.json \
#       --badge path/to/lifetime-downloads.json
#
# Migration: if --state does not exist but --badge does and contains a
# legacy `_state` block (the pre-split shape), the script lifts that
# block as the prev state so no tally is lost on the first run after
# the split.
#
# If neither file exists (first run), the script bootstraps from the
# live counters: lifetime_total = sum(current asset counts).

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

API_ROOT = "https://api.github.com"
USER_AGENT = "duetos-lifetime-downloads/1.0"


def gh_get(url: str, token: str | None) -> object:
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    })
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_all_releases(repo: str, token: str | None) -> list[dict]:
    out: list[dict] = []
    page = 1
    while True:
        data = gh_get(f"{API_ROOT}/repos/{repo}/releases?per_page=100&page={page}", token)
        if not isinstance(data, list) or not data:
            break
        out.extend(data)
        if len(data) < 100:
            break
        page += 1
    return out


def gather_assets(releases: list[dict]) -> list[dict]:
    """Flatten every asset from every release into a single list."""
    assets: list[dict] = []
    for release in releases:
        for asset in release.get("assets", []) or []:
            assets.append({
                "asset_id": asset["id"],
                "name": asset["name"],
                "release_tag": release.get("tag_name"),
                "download_count": int(asset.get("download_count", 0) or 0),
            })
    return assets


def _unwrap_state(prev: dict) -> dict:
    """Pull the persistence block out of an on-disk JSON document.

    Three shapes are accepted:
      * post-split state file: top-level dict with `lifetime_total` /
        `by_asset` directly. Returned as-is.
      * pre-split combined file: top-level dict with `_state` nested.
        The nested block is returned (migration path on first run
        after the badge/state split).
      * empty/missing: returns {}.
    """
    if not prev:
        return {}
    if "_state" in prev and isinstance(prev["_state"], dict):
        return prev["_state"]
    return prev


def load_prev_state(state_path: str, badge_path: str | None) -> dict:
    """Read previous persistence state.

    Tries the dedicated state file first. Falls back to lifting the
    legacy `_state` block out of the badge file so the very first
    run after the badge/state split doesn't lose the tally.
    """
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            return _unwrap_state(json.load(fh))
    except FileNotFoundError:
        pass
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: state file {state_path} is not valid JSON: {exc}")

    if badge_path:
        try:
            with open(badge_path, "r", encoding="utf-8") as fh:
                badge_doc = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
        if isinstance(badge_doc, dict) and isinstance(badge_doc.get("_state"), dict):
            return badge_doc["_state"]
    return {}


def compute_new_total(prev_state: dict, assets: list[dict]) -> tuple[int, dict, int]:
    """Returns (new_lifetime_total, new_by_asset, delta_this_run)."""
    prev_state = _unwrap_state(prev_state)
    prev_total = int(prev_state.get("lifetime_total", 0) or 0)
    prev_by_asset = prev_state.get("by_asset", {}) or {}

    delta = 0
    new_by_asset: dict[str, dict] = {}
    for asset in assets:
        key = str(asset["asset_id"])
        new_count = asset["download_count"]
        prev = prev_by_asset.get(key)
        if prev is None:
            # New asset (fresh upload, possibly replacing a deleted
            # one). Treat its full live count as new downloads — the
            # asset we replaced has already been folded into
            # lifetime_total at its last snapshot.
            delta += new_count
        else:
            prev_count = int(prev.get("count", 0) or 0)
            if new_count > prev_count:
                delta += new_count - prev_count
            # If new_count < prev_count we ignore (asset reset
            # mid-life shouldn't decrement lifetime).
        new_by_asset[key] = {
            "name": asset["name"],
            "release_tag": asset["release_tag"],
            "count": new_count,
        }

    new_total = prev_total + delta
    return new_total, new_by_asset, delta


def render_badge(label: str, total: int, color: str) -> dict:
    """Shape the JSON for shields.io endpoint badges (schemaVersion: 1)."""
    return {
        "schemaVersion": 1,
        "label": label,
        "message": f"{total:,}",
        "color": color,
        "cacheSeconds": 1800,
    }


def _render(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def _write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _read_text(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True,
                        help="Path to persistence state JSON (read + written).")
    parser.add_argument("--badge", required=True,
                        help="Path to shields.io endpoint badge JSON (written).")
    parser.add_argument("--repo",
                        default=os.environ.get("GITHUB_REPOSITORY"),
                        help="owner/repo (defaults to $GITHUB_REPOSITORY).")
    parser.add_argument("--label", default="lifetime downloads (all channels)",
                        help="Badge label.")
    parser.add_argument("--color", default="success",
                        help="Badge color.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print both files to stdout, do not write.")
    args = parser.parse_args()

    if not args.repo or "/" not in args.repo:
        print("error: --repo or $GITHUB_REPOSITORY must be set to owner/repo", file=sys.stderr)
        return 2

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    prev_state = load_prev_state(args.state, args.badge)

    try:
        releases = fetch_all_releases(args.repo, token)
    except urllib.error.HTTPError as exc:
        print(f"error: GitHub API returned {exc.code}: {exc.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"error: could not reach GitHub API: {exc.reason}", file=sys.stderr)
        return 1

    assets = gather_assets(releases)

    # First-run bootstrap: no prev state at all → seed lifetime_total
    # from the current sum so we don't lose what's already counted.
    if not prev_state:
        seed_total = sum(a["download_count"] for a in assets)
        new_total = seed_total
        new_by_asset = {
            str(a["asset_id"]): {
                "name": a["name"],
                "release_tag": a["release_tag"],
                "count": a["download_count"],
            }
            for a in assets
        }
        delta = 0
    else:
        new_total, new_by_asset, delta = compute_new_total(prev_state, assets)

    prev_total = int(prev_state.get("lifetime_total", 0) or 0)
    prev_by_asset = prev_state.get("by_asset", {}) or {}
    nothing_changed = (new_total == prev_total) and (new_by_asset == prev_by_asset)

    badge = render_badge(args.label, new_total, args.color)
    snapshot_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    state_doc = {
        "lifetime_total": new_total,
        "snapshot_at": snapshot_at,
        "delta_this_run": delta,
        "live_assets_total": sum(v["count"] for v in new_by_asset.values()),
        "asset_count": len(new_by_asset),
        "repo": args.repo,
        "by_asset": new_by_asset,
    }

    new_badge_text = _render(badge)
    new_state_text = _render(state_doc)

    if args.dry_run:
        sys.stdout.write("=== badge ===\n" + new_badge_text)
        sys.stdout.write("=== state ===\n" + new_state_text)
        return 0

    # The badge file should match new_badge_text exactly; if not (e.g.
    # the legacy combined badge+state file is still on disk), rewrite
    # it so shields.io stops rejecting the unknown `_state` property.
    badge_dirty = _read_text(args.badge) != new_badge_text
    # State is rewritten when the underlying numbers moved OR when the
    # state file is missing (migration from the legacy combined file —
    # without this we'd lose the carry on the very next run because
    # load_prev_state would fall through to a clean badge file and
    # bootstrap from scratch). snapshot_at intentionally is NOT part
    # of the change signal: otherwise every scheduled run produces a
    # no-op commit whose only diff is the timestamp.
    state_missing = not os.path.exists(args.state)
    state_changed = (not nothing_changed) or state_missing

    if not badge_dirty and not state_changed:
        print(f"lifetime_total unchanged at {new_total:,} "
              f"({len(new_by_asset)} live asset(s)) — skipping write")
        return 0

    if badge_dirty:
        _write_text(args.badge, new_badge_text)
    if state_changed:
        _write_text(args.state, new_state_text)

    print(f"lifetime_total: {new_total:,} (delta this run: +{delta:,}, "
          f"{len(new_by_asset)} live asset(s); "
          f"badge_dirty={badge_dirty} state_changed={state_changed})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
