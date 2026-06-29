#!/usr/bin/env bash
# Deploy the COMPLETE verifyknot.io site to Cloudflare Pages.
# Pages deploys are FULL SNAPSHOTS — never ship a subset. (incident 2026-06-29)
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
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
echo "Staged $(find "$STAGE" -type f | wc -l) files; deploying..."
npx --yes wrangler pages deploy "$STAGE" --project-name=verifyknot --commit-dirty=true
