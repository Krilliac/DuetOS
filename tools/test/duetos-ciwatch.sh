#!/usr/bin/env bash
# ============================================================================
# duetos-ciwatch.sh — poll a GitHub Actions run for a commit and report
#                      per-job status; pull the log of any failed job.
#
# Why: CLAUDE.md mandates polling CI after every push and fixing failures
# before moving on. The GitHub Actions job-log REST endpoint needs an
# authenticated token even for public repos, so this wraps token discovery
# + the runs/jobs/logs API into one reusable command instead of
# re-deriving the curl incantation every session. `curl -sk` is used
# because the dev environment sits behind an SSL-intercepting proxy (the
# same reason `git fetch` needs `-c http.sslVerify=false` here).
#
# Usage:
#   tools/test/duetos-ciwatch.sh <commit-sha|run-id> [job-name-substr ...]
#     arg1          : commit SHA (latest build.yml run resolved) OR run id
#     extra args    : substrings of job names to assert green; exit 3 if any
#                     named job is not 'success'
#
# Token discovery (first hit wins):
#   $GH_TOKEN / $GITHUB_TOKEN
#   git credential fill (host=github.com)        [5s timeout, non-interactive]
#   ~/.git-credentials
#   $DUETOS_GH_PAT_FILE
#   /mnt/c/Users/*/{,OneDrive/}Desktop/github_pat_*.txt
#
# Env:
#   DUETOS_GH_REPO       default Krilliac/DuetOS
#   DUETOS_GH_PAT_FILE   explicit PAT file path
#   DUETOS_CIWATCH_POLL  seconds between polls while in-progress (0 = once)
#
# Quick analysis:
#   tools/test/duetos-ciwatch.sh <sha> pe-hello pe-winapi
#   DUETOS_CIWATCH_POLL=30 tools/test/duetos-ciwatch.sh <run-id>
#   # failed job logs are saved to /tmp/ciwatch_job_<id>.log
# ============================================================================
set -u
REPO="${DUETOS_GH_REPO:-Krilliac/DuetOS}"
POLL="${DUETOS_CIWATCH_POLL:-0}"
ARG="${1:?usage: duetos-ciwatch.sh <commit-sha|run-id> [job-substr ...]}"
shift || true
GATE_JOBS=("$@")

_curl() {
  curl -sk -H "Accept: application/vnd.github+json" \
    ${TOK:+-H "Authorization: Bearer $TOK"} "$@"
}

find_token() {
  [ -n "${GH_TOKEN:-}" ]     && { printf %s "$GH_TOKEN"; return; }
  [ -n "${GITHUB_TOKEN:-}" ] && { printf %s "$GITHUB_TOKEN"; return; }
  local t
  t=$(printf 'protocol=https\nhost=github.com\n\n' \
        | timeout 5 git credential fill 2>/dev/null | sed -n 's/^password=//p')
  [ -n "$t" ] && { printf %s "$t"; return; }
  if [ -f "$HOME/.git-credentials" ]; then
    t=$(sed -n 's#https://[^:]*:\([^@]*\)@github.com.*#\1#p' \
          "$HOME/.git-credentials" | head -1)
    [ -n "$t" ] && { printf %s "$t"; return; }
  fi
  if [ -n "${DUETOS_GH_PAT_FILE:-}" ] && [ -f "$DUETOS_GH_PAT_FILE" ]; then
    tr -d ' \r\n' < "$DUETOS_GH_PAT_FILE"; return
  fi
  local f
  f=$(ls /mnt/c/Users/*/Desktop/github_pat_*.txt \
         /mnt/c/Users/*/OneDrive/Desktop/github_pat_*.txt 2>/dev/null | head -1)
  [ -n "$f" ] && tr -d ' \r\n' < "$f"
}

TOK="$(find_token)"
[ -z "$TOK" ] && echo "ciwatch: no GitHub token found (set GH_TOKEN or DUETOS_GH_PAT_FILE)" >&2

# Resolve run id (numeric & >=9 digits => treat as run id, else as a SHA).
if [[ "$ARG" =~ ^[0-9]+$ ]] && [ "${#ARG}" -ge 9 ]; then
  RUN_ID="$ARG"
else
  RUN_ID=$(_curl "https://api.github.com/repos/$REPO/actions/runs?head_sha=$ARG&per_page=1" \
    | python3 -c 'import sys,json;r=json.load(sys.stdin).get("workflow_runs") or [];print(r[0]["id"] if r else "")')
fi
[ -z "$RUN_ID" ] && { echo "ciwatch: could not resolve a run for $ARG" >&2; exit 2; }

while :; do
  RUN_JSON=$(_curl "https://api.github.com/repos/$REPO/actions/runs/$RUN_ID")
  read -r STATUS CONCL HEAD < <(printf '%s' "$RUN_JSON" \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("status"),d.get("conclusion"),str(d.get("head_sha"))[:9])')
  echo "run=$RUN_ID head=$HEAD status=$STATUS conclusion=$CONCL"
  [ "$STATUS" = "completed" ] && break
  { [ "$POLL" -le 0 ]; } 2>/dev/null && break
  sleep "$POLL"
done

export JOBS_JSON
JOBS_JSON=$(_curl "https://api.github.com/repos/$REPO/actions/runs/$RUN_ID/jobs?per_page=100")

python3 - "${GATE_JOBS[@]:-}" <<'PY'
import sys, json, os
gates=[g for g in sys.argv[1:] if g]
d=json.loads(os.environ["JOBS_JSON"])
jobs=d.get("jobs",[])
fail_ids={}
for j in jobs:
    c=j["conclusion"]; st=c if c else j["status"]
    print("  %-10s | %s (id=%s)" % (st, j["name"], j["id"]))
    if c not in ("success","skipped",None):
        fail_ids[j["name"]]=j["id"]
        for stp in j.get("steps",[]):
            if stp.get("conclusion") not in ("success","skipped",None):
                print("       FAILED STEP %s: %s" % (stp.get("number"), stp.get("name")))
rc=0
for g in gates:
    matched=[x for x in jobs if g in x["name"]]
    if not matched:
        sys.stderr.write("GATE %s: NO MATCHING JOB\n" % g); rc=3; continue
    for m in matched:
        sys.stderr.write("GATE %s: %s -> %s\n" % (g, m["name"], m["conclusion"]))
        if m["conclusion"] != "success": rc=3
open("/tmp/ciwatch_fail_ids.json","w").write(json.dumps(fail_ids))
sys.exit(rc)
PY
GATE_RC=$?

if [ -s /tmp/ciwatch_fail_ids.json ]; then
  for jid in $(python3 -c 'import json;[print(i) for i in json.load(open("/tmp/ciwatch_fail_ids.json")).values()]'); do
    [ -z "$jid" ] && continue
    out="/tmp/ciwatch_job_${jid}.log"
    code=$(_curl -o "$out" -w "%{http_code}" -L \
      "https://api.github.com/repos/$REPO/actions/jobs/$jid/logs")
    echo "  pulled failed job $jid -> $out (http=$code, $(wc -c <"$out" 2>/dev/null) bytes)"
  done
fi
exit "$GATE_RC"
