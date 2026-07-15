#!/usr/bin/env bash
# Deploy the COMPLETE verifyknot.io site to Cloudflare Pages.
# Pages deploys are FULL SNAPSHOTS — never ship a subset. (incident 2026-06-29)
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"

# ═════════════════════════════════════════════════════════════════════════════
#  THIS SCRIPT IS NOT THE APPROVED PRODUCTION PATH.
#
#  Use:  verifyknot-deploy production --confirm <sha>
#        (~/.local/bin/verifyknot-deploy — lives OUTSIDE every checkout)
#
#  Why: this file is versioned, so it SWITCHES WITH THE BRANCH. A guardrail
#  added here on main is simply ABSENT on any branch that predates it. That is
#  not theory — on 2026-07-15 a `git switch` replaced this guarded script with
#  an older unguarded copy, which ignored DRY_RUN and deployed for real. A guard
#  you can remove by checking out a different branch is not a control.
#  The checks below are a SECONDARY defense only. They are retained because the
#  dirty-tree case is the one real production hazard (see below).
# ═════════════════════════════════════════════════════════════════════════════
#
# GUARDRAIL — must run BEFORE anything is staged.
#
# This script rsyncs the WORKING DIRECTORY. It does not read a git ref, so it
# publishes whatever is checked out right now.
#
# WHAT THE RISK ACTUALLY IS — corrected 2026-07-15 against direct evidence.
# Earlier versions of this comment (and the launch journal, and the readiness
# plan) claimed a feature-branch checkout here "would publish the unmerged
# feature to verifyknot.io". THAT WAS WRONG. It was tested empirically:
# deploying from wip/verify-your-copy-20260714 produced a PREVIEW deployment
# (wip-verify-your-copy-2026071.verifyknot.pages.dev) and production was never
# touched. Cloudflare Pages routes non-production branches to preview.
#
# The real, demonstrated production hazard is narrower and lives right here:
#   publishing an UNCOMMITTED or INCORRECT working tree while ON main.
# That reaches the custom domain. Branch checkout does not.
#
# Note also: Pages branch-routing is Cloudflare's behaviour, not a control we
# own. verifyknot-deploy enforces independently of it. Do not rely on routing.
#
# Two real incidents this file's denylist DID cause (both 2026-07-14):
#   1. `_headers` reached production from an UNTRACKED file, silently — an
#      exclude-list ships whatever nobody remembered to exclude.
#   2. A clean `git archive` deploy would have STRIPPED those headers back out
#      (reopening WEB-01) — caught only because someone read this script.
# verifyknot-deploy replaces the denylist with an explicit allowlist.
#
# No override flag, deliberately. If it should ship, commit it to main.
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
echo ""
echo "WARNING: this script is a SECONDARY defense, not the approved production path."
echo "         It builds from the working directory and lives inside the repo, so it"
echo "         switches with the branch. The approved path builds from a clean"
echo "         detached worktree at a signed, pushed commit:"
echo "           verifyknot-deploy production --confirm $(git -C "$SRC" rev-parse --short HEAD)"
echo ""

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
