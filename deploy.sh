#!/usr/bin/env bash
# Deploy the COMPLETE verifyknot.io site to Cloudflare Pages.
# Pages deploys are FULL SNAPSHOTS — never ship a subset. (incident 2026-06-29)
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"

# ── GUARDRAIL — must run BEFORE anything is staged ───────────────────────────
# This script rsyncs the WORKING DIRECTORY. It does not read a git ref. So the
# thing that gets published is whatever happens to be checked out right now —
# which means "the work is parked on a branch" buys exactly ZERO deploy safety.
#
# That mechanism has already misfired three times (all 2026-07-14):
#   1. `_headers` reached production from an UNTRACKED file, silently.
#   2. A clean `git archive` deploy would have STRIPPED those headers back out
#      (reopening WEB-01) — caught only because someone read this script.
#   3. This repo sat checked out on wip/verify-your-copy-20260714 with this
#      script armed to publish an unmerged feature. Nobody ran it. That was
#      luck, not control.
#
# So: refuse to publish anything that is not committed, reviewed main.
# There is deliberately NO override flag. If you need to ship it, commit it to
# main — that is the entire point. For testing a branch, use a Cloudflare Pages
# preview deployment, not this script.
BRANCH="$(git -C "$SRC" rev-parse --abbrev-ref HEAD)"
if [ "$BRANCH" != "main" ]; then
  echo "ABORT: on branch '$BRANCH', not main."
  echo "       This script publishes the WORKING DIRECTORY, so it would ship"
  echo "       whatever is checked out. Switch to main, or use a Pages preview."
  exit 1
fi

DIRTY="$(git -C "$SRC" status --porcelain)"
if [ -n "$DIRTY" ]; then
  echo "ABORT: working tree is dirty. Pages would publish these uncommitted files:"
  echo "$DIRTY" | sed 's/^/       /'
  echo "       Commit them to main, or stash them. Nothing was deployed."
  exit 1
fi

echo "Guardrail OK: main @ $(git -C "$SRC" rev-parse --short HEAD), tree clean."

# ── Stage ────────────────────────────────────────────────────────────────────
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
rsync -a \
  --exclude='.git' --exclude='*.bak*' --exclude='node_modules' \
  --exclude='deploy*' --exclude='.wrangler' \
  --exclude='*.sh' --exclude='*.py' --exclude='.gitignore' \
  "$SRC"/ "$STAGE"/
# Pre-flight: refuse to deploy a partial site.
for f in index.html verifier.js _redirects sign/index.html start/index.html; do
  [ -f "$STAGE/$f" ] || { echo "ABORT: missing $f in staged tree"; exit 1; }
done
echo "Staged $(find "$STAGE" -type f | wc -l) files."

# ── Deploy ───────────────────────────────────────────────────────────────────
# DRY_RUN=1 runs every check and the full staging, then stops before publishing.
# This exists so the guardrail and the pre-flight can be exercised — including
# their PASSING path — without touching production. A safety check nobody can
# test without deploying is a safety check nobody tests.
if [ "${DRY_RUN:-0}" = "1" ]; then
  echo "DRY_RUN=1 — stopping before deploy. Would have published:"
  (cd "$STAGE" && find . -type f | sed 's|^\./|       |' | sort)
  exit 0
fi

echo "Deploying..."
# --commit-dirty is now redundant (the guardrail already refuses a dirty tree)
# but is kept so wrangler never blocks on an interactive prompt.
npx --yes wrangler pages deploy "$STAGE" --project-name=verifyknot --commit-dirty=true
