# verifyknot.io

The public attestation lookup page for ZKNOT™ products.

## What this serves

A single static HTML file that fetches verification data from
`https://api.zknot.io/v1/verify/{short_code}` and renders the
chain entry, regardless of artifact type.

URL patterns supported:
- `verifyknot.io/` — manual code entry form
- `verifyknot.io/ZK-XXXX-XXX` — auto-verify on page load (used by
  printed QR codes on PowerVerify units)

## Deployment

Cloudflare Pages project `verifyknot` (TBD: connect to this repo
for git-based deploys instead of direct upload).

## What this does NOT serve

- `zknot.io` — marketing site, lives in zknot-io/zknot-site
- `api.zknot.io` — backend API, lives in zknot-io/zknot-api
