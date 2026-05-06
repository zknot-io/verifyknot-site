# verifyknot.io

The public attestation lookup page for ZKNOT™ products.

Serves a single static HTML file that fetches from
`https://api.zknot.io/v1/verify/{short_code}` and renders chain
entries regardless of artifact type.

URL patterns:
- `verifyknot.io/` — manual code entry form
- `verifyknot.io/ZK-XXXX-XXX` — auto-verify on load (used by QR codes)

Deployed via Cloudflare Pages.
