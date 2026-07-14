# HashStamp Portable Proof Bundle — Privacy

Companion to `HASHSTAMP-PROOF-BUNDLE-SPEC-v1.md`. Describes exactly what a
`.hashstamp` file contains, what it can never contain, and what leaves the
browser.

## 1. The mechanism: allowlist, not denylist

`GET /v1/verify/{code}` echoes the artifact's `metadata` blob **unfiltered**
(`zknot-api/app/routers/verify.py:53` — `metadata=artifact.metadata_`, a raw JSON
column passed through with no allowlist and no redaction).

That is not a theoretical hazard. zknot-api's **public** unit-registration route
writes a customer email into that same blob:

```python
# app/routers/units.py:134
md["registration"] = { "email": req.email, "shopify_order_id": ..., ... }
```

An exporter that copied `metadata` wholesale would therefore write a customer
email into a file whose entire purpose is to be emailed to third parties.

So the privacy guarantee here is **structural, not a filter**:

1. `mapApiResponse()` (verifier.js) is an **allowlist** — it names the fields it
   wants and never spreads `api.metadata`.
2. `buildProofBundle()` reads **only named fields off that mapped record**, and
   refuses a raw API body outright (its export gate reads flattened fields that a
   raw body does not have).
3. A field invented in `metadata` tomorrow is **never copied**, because nothing
   copies unknown fields.

The deny-list test suite is a **backstop that proves the property**, not the
mechanism enforcing it.

## 2. What a bundle contains

| Included | Why it is safe / necessary |
|---|---|
| `file_fingerprint.value` | **The evidence subject.** The bundle exists to carry it. A fingerprint is not the file and does not reveal its contents. |
| `signature.*`, `challenge_hash`, `signed_payload` | Required to reproduce the check offline. |
| `signing_key.public_key`, `key_id` | Required to check the signature; already published by the Worker. |
| `record.verification_code` | Already public — it is the code printed on the receipt. |
| `record.public_label` | **Only if the user chose one.** Already public on the record; sanitized on both write and read. |
| `record.artifact_type`, `kind`, `product` | Public, non-identifying record classification. |
| `record.signed_at` / `stamped_at` | Public service timestamps already on the record. |
| `chain.position`, `previous_hash`, `entry_hash`, `artifact_id` | Public chain metadata. `artifact_id` is a deterministic function of `challenge_hash`, so it carries no extra information. |
| `bundle_id`, `exported_at`, `generator` | See §4. |

## 3. What a bundle can never contain

Original file bytes · sender's private filename · recipient's local filename ·
customer email · Stripe session id (`cs_live_`/`cs_test_`) · payment intent
(`pi_`) · secret keys (`sk_`) · webhook secrets (`whsec_`) · price ids ·
`session_id` · IP address · user agent · analytics identifiers · browser
fingerprint · authorization headers / bearer tokens · private internal notes ·
worker secrets · signing private keys · Shopify order ids · any `registration`
block.

### The private filename, specifically

Two independent layers keep it out:

1. **The Worker never publishes it.** Since F2 the browser does not send it, and a
   stray legacy `filename` from an old cached client is deliberately ignored
   (`hashstamp-worker.js:213-217`). `body.filename` is never read.
2. **The exporter never copies it.** `mapApiResponse` *does* map `filename` for
   legacy records (so the live page can still render a historical label), which
   makes it a **real leak vector** — and `buildProofBundle` simply does not read
   it. Verified by the legacy-record export test and by a mutation test:
   injecting `filename: rec.filename` into the builder fails 3 privacy tests.

The suggested download filename is derived only from the stamp date and the
public verification code (`HS-YYYYMMDD-CODE.hashstamp`) — never from the original
filename.

## 4. Tracking resistance

- `bundle_id` = `hsb1_` + hash of **evidence only** (schema, code, fingerprint,
  signature). Deterministic: the same record always yields the same id. It
  contains no exporter entropy — no client id, no random nonce, no timestamp — so
  it cannot function as a tracking token. Tested.
- `exported_at` is the only export-time value. It is honest about being
  non-evidential and feeds nothing.
- No analytics, no telemetry, no beacons anywhere in the feature.

## 5. What leaves the browser

### Export — nothing

The bundle is built with WebCrypto and `Blob`/`URL.createObjectURL` in the page.
**No bundle-generation request is made to any backend.** Tested (download path
with a network trap installed).

### Offline import — nothing

Parsing, schema validation, signature verification, key-pin comparison and
Verify-your-copy are pure computation. The `.hashstamp` file and the selected
local file reach `FileReader`/WebCrypto and nothing else.

Never transmitted: bundle contents, verification result, the selected local file,
its filename, or the computed hash.

Enforced and tested three ways: a **static** assertion that `proof-bundle.js`
contains exactly one `fetch` and that it lives only inside
`checkCurrentStatusOnline`; **dynamic** traps on `fetch`, `XMLHttpRequest`,
`WebSocket`, `EventSource` and `navigator.sendBeacon` around the full path; and a
**mutation test proving the traps fire**, so the first two cannot pass vacuously.

### The optional online check — one GET, one public value

Only on an explicit button press:

```
GET https://api.zknot.io/v1/verify/{verification_code}
```

- **Transmitted:** the verification code — already public — in the URL path. Plus
  whatever any browser request carries (IP, TLS SNI, User-Agent).
- **Not transmitted:** no headers, no cookies, no credentials, no body, no query
  string. The call passes no `init` argument at all. Not the bundle, not the
  fingerprint, not the signature, not the local file or its name or hash, not the
  offline verdict. Tested.
- **Observable side effect:** ZKNOT and any network observer learn *that this
  code is being looked up*, and when. This is stated on the button.

## 6. Local file handling

The selected file only ever reaches WebCrypto. Its name is rendered with
`textContent` for local display and is never transmitted (tested). References are
dropped on remove, on re-import, and on `pagehide`.

## 7. Deploy-time note

`deploy.sh` rsyncs the **working directory**, so anything not excluded becomes a
publicly served URL. `test/`, `docs/`, `package.json`, `package-lock.json` and
`node_modules` are excluded; the staged tree was verified to contain only the 10
site files.
