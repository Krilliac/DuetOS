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
#   * reading the previous snapshot from
#     `lifetime-downloads.json` (shape documented below)
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
# The output JSON also embeds the shields.io endpoint schema
# (schemaVersion / label / message / color) so the README badge can
# point at this file directly via
# https://img.shields.io/endpoint?url=...
#
# Usage:
#   GITHUB_TOKEN=... \
#   GITHUB_REPOSITORY=krilliac/duetos \
#     tools/release/update-lifetime-downloads.py \
#       --state path/to/lifetime-downloads.json
#
# If --state does not exist (first run), the script bootstraps from
# the live counters: lifetime_total = sum(current asset counts).

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
    """Pull the persistence block out of the on-disk JSON.

    The script writes the badge envelope at the top level (so
    shields.io can read it directly) and parks our state under
    `_state`. Older snapshots wrote the state at the top level;
    accept both shapes so a hand-edited file keeps working.
    """
    if not prev:
        return {}
    if "_state" in prev and isinstance(prev["_state"], dict):
        return prev["_state"]
    return prev


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", required=True,
                        help="Path to lifetime-downloads.json (read + written).")
    parser.add_argument("--repo",
                        default=os.environ.get("GITHUB_REPOSITORY"),
                        help="owner/repo (defaults to $GITHUB_REPOSITORY).")
    parser.add_argument("--label", default="lifetime downloads (all channels)",
                        help="Badge label.")
    parser.add_argument("--color", default="success",
                        help="Badge color.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print result to stdout, do not write the file.")
    args = parser.parse_args()

    if not args.repo or "/" not in args.repo:
        print("error: --repo or $GITHUB_REPOSITORY must be set to owner/repo", file=sys.stderr)
        return 2

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    try:
        with open(args.state, "r", encoding="utf-8") as fh:
            prev_state = json.load(fh)
    except FileNotFoundError:
        prev_state = {}
    except json.JSONDecodeError as exc:
        print(f"error: existing state at {args.state} is not valid JSON: {exc}", file=sys.stderr)
        return 2

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
        prev_state = {
            "lifetime_total": seed_total,
            "by_asset": {
                str(a["asset_id"]): {
                    "name": a["name"],
                    "release_tag": a["release_tag"],
                    "count": a["download_count"],
                }
                for a in assets
            },
        }
        delta = 0
        new_total = seed_total
        new_by_asset = prev_state["by_asset"]
    else:
        new_total, new_by_asset, delta = compute_new_total(prev_state, assets)

    snapshot_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    badge = render_badge(args.label, new_total, args.color)
    badge["_state"] = {
        "lifetime_total": new_total,
        "snapshot_at": snapshot_at,
        "delta_this_run": delta,
        "live_assets_total": sum(v["count"] for v in new_by_asset.values()),
        "asset_count": len(new_by_asset),
        "repo": args.repo,
        "by_asset": new_by_asset,
    }

    rendered = json.dumps(badge, indent=2, sort_keys=True) + "\n"

    if args.dry_run:
        sys.stdout.write(rendered)
        return 0

    os.makedirs(os.path.dirname(os.path.abspath(args.state)) or ".", exist_ok=True)
    with open(args.state, "w", encoding="utf-8") as fh:
        fh.write(rendered)

    print(f"lifetime_total: {new_total:,} (delta this run: +{delta:,}, "
          f"{len(new_by_asset)} live asset(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
