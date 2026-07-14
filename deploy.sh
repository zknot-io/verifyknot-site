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
  --exclude='test' --exclude='docs' --exclude='package.json' \
  --exclude='package-lock.json' \
  "$SRC"/ "$STAGE"/
# ^ test/, docs/ and package.json are repo-only: this rsync ships the WORKING DIR,
# so anything not excluded becomes a publicly served URL. The site itself has no
# build step and no runtime deps — package.json exists solely to run node:test.
# Pre-flight: refuse to deploy a partial site.
for f in index.html verifier.js proof-bundle.js flags.js _redirects sign/index.html start/index.html; do
  [ -f "$STAGE/$f" ] || { echo "ABORT: missing $f in staged tree"; exit 1; }
done
echo "Staged $(find "$STAGE" -type f | wc -l) files; deploying..."
npx --yes wrangler pages deploy "$STAGE" --project-name=verifyknot --commit-dirty=true
