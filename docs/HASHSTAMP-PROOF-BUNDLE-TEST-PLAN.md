# HashStamp Portable Proof Bundle — Test Plan

**Suite:** `npm test` (node:test) in `verifyknot-site`
**Result at time of writing:** **81 tests, 81 pass, 0 fail** (~2.9 s)

```
test/proof-bundle.test.mjs   export, import, round trip, tamper resistance, schema
test/privacy.test.mjs        deny-list + leak-detector mutation tests
test/network.test.mjs        offline guarantee + the one optional online call
test/flag.test.mjs           both flag states + record-shape contract with the Worker
test/ui.test.mjs             real controller over real index.html markup (jsdom)
test/fixtures.mjs            production-shaped records, signed for real
```

## Design principles

**1. The crypto is real.** Fixtures reproduce the Worker's exact signing math
with a live P-256 keypair. No signature is faked or stubbed, so a change to that
math breaks tests instead of passing silently.

**2. Fixtures are generated, so a contract test guards them.** Generated fixtures
can drift from reality. `flag.test.mjs` reads `hashstamp-worker.js` and
`wrangler.toml` and asserts the signing math, the field names, and **the pinned
key** still match. That last one is the tripwire for an unannounced key rotation.

**3. Detectors are mutation-tested.** A deny-list that only sees clean data proves
nothing — it passes just as happily when broken. Every detector here is proven to
fire (§4).

**4. The fixture key is a throwaway, on purpose.** So the default expectation is
`VERIFIED_UNRECOGNIZED_KEY`. Any test asserting `SIGNING KEY RECOGNIZED` must
explicitly register a key — which keeps the pin honest and makes "recognized" a
deliberate act in tests, as it is in life.

**5. UI tests must not be vacuous.** jsdom does not execute `<script type="module">`.
The first draft of these tests loaded `index.html` and passed while **nothing ran**.
That is why the UI logic lives in `proof-bundle-ui.js`: the suite drives the real
controller over the real markup, and a contract test asserts every element id the
controller touches exists in `index.html`.

## Coverage against the required matrix

| # | Requirement | Test | Result |
|---|---|---|---|
| 1 | Current production-shaped record exports | `1. a current production-shaped record exports successfully` | PASS |
| 2 | Supported legacy record exports | `2. a supported legacy record (pre-F2, no public_label) exports successfully` | PASS |
| 3 | Invalid receipt cannot export | `3. an invalid receipt cannot export` | PASS |
| 4 | Missing fingerprint cannot export | `4. a record with no file fingerprint cannot export` | PASS |
| 5 | Missing public key cannot export | `5. a record with no public key cannot export` | PASS |
| 6 | Missing signed payload cannot export | `6.` + `6b. buildProofBundle refuses … even if called directly` | PASS |
| 7 | No original file content | `7. the export contains no original file content` | PASS |
| 8 | No private filename | `8. … even from a legacy record that has one` | PASS |
| 9 | No Stripe identifiers | `9. the export contains no Stripe identifiers` | PASS |
| 10 | No customer email | `10. the export contains no customer email` | PASS |
| 11 | No secret material | `11. … no secret material, tokens, IPs or user agents` | PASS |
| 12 | Export/import round trip | `12. … preserves every verification-critical field` | PASS |
| 13 | Imported signature verifies | `13.` + `13b.` (pinned-key swap) + `13c.` (pin is a real P-256 point) | PASS |
| 14 | One-byte payload mutation fails | `14.` + `14b.` (payload **and** fingerprint **and** challenge_hash) | PASS |
| 15 | One-byte signature mutation fails | `15. a one-byte mutation of the signature fails` | PASS |
| 16 | Wrong public key fails | `16. a wrong public key fails` | PASS |
| 17 | Unsupported schema fails | `17.` + `17b.` (missing) + `17c.` (additive fields still OK) | PASS |
| 18 | Malformed JSON fails safely | `18. malformed JSON fails safely` | PASS |
| 19 | Oversized bundle fails safely | `19.` + `19b.` (UTF-8 bytes, not string length) | PASS |
| 20 | HTML/script stays inert | `20.` + `20b.` (prototype pollution) + UI inert-text test | PASS |
| 21 | Zero-byte file still matchable | `21. a ZERO-BYTE original file can still be matched…` | PASS |
| 22 | Matching local file works | `22.` + UI `a recognized-key bundle unlocks Verify your copy and reports a local MATCH` | PASS |
| 23 | Modified local file fails | `23.` + `23b.` (blocked for unrecognized key) | PASS |
| 24 | Import causes no network request | `24. STATIC` + `24. DYNAMIC` + `24. MUTATION` + UI `import touches NO network primitive` | PASS |
| 25 | Online button makes only the documented request | `25.` ×4 (one GET, no bundle/file/hash, no code ⇒ no call, no invented revocation) | PASS |
| 26 | Existing online verification unchanged | `26. the existing /v1/verify client path still works unchanged` + `26. a failed fetch still yields CANNOT_VERIFY` | PASS |
| 27 | Existing Verify Your Copy tests remain green | Verify-your-copy is exercised via `21.`/`22.`/`23.` and the UI suite (the pre-existing work shipped with no tests of its own — this suite adds its first) | PASS |
| 28 | Privacy leak-detector mutation tests | `MUTATION:` ×3 (§4) | PASS |

## 4. Mutation testing — proof the detectors fire

Detectors that never see a real defect are decorative. Each was verified against
a **deliberately sabotaged product**, then reverted:

| Sabotage injected into real source | Result |
|---|---|
| `filename: rec.filename` added to the exporter (the real leak vector — the mapped record *does* carry the private filename) | **Caught** — 3 privacy tests fail, incl. `8. the export contains no private filename` |
| `navigator.sendBeacon(...)` added to `verifyProofBundle` | **Caught** — 2 network tests fail |
| `const recognized = true` (key pin defeated) | **Caught** — 3 tests fail, incl. `23b.` and the badge test |
| *(control)* `...rec.metadata` spread into the bundle | **No-op** — `mapApiResponse` flattens metadata, so `rec.metadata` is `undefined`. Not a gap; the allowlist makes this leak *unexpressible*. Documented so the next reader does not mistake it for coverage. |

In-suite mutation tests (run every time, not just by hand):
- `MUTATION: the leak detector fires on every prohibited pattern injected into a clean bundle` — injects all 19 deny-list patterns and asserts each is caught.
- `MUTATION: the detector catches a leak hidden under an innocent-looking key name` — proves the detector inspects **serialized values**, not field names.
- `MUTATION: a deliberately sabotaged exporter is caught by the deny-list` — simulates a metadata-spreading exporter.
- `24. MUTATION: the network trap provably fires when a call IS made` — proves the offline assertions cannot pass vacuously.

## 5. The deny-list

19 patterns over **serialized output** (not field names): `cs_live_`, `cs_test_`,
`pi_`, `sk_live|test_`, `whsec_`, any email-shaped string, `customer_email`,
`registration`, private-key material, `secret`, `authorization`, `bearer`, IPv4,
user agent, analytics id, internal notes, Shopify order id, fixture private
filenames (`payroll`/`CONFIDENTIAL`/`.xlsx`), `"filename":`, `"session_id":`.

The toxic-metadata fixture carries **all** of them; the exported bundle must
contain **none**.

## 6. Regression suites (unchanged by this work)

| Repo | Command | Result |
|---|---|---|
| `hashstamp-worker` | `npm test` | **46 pass, 0 fail** |
| `zknot-api` | `python3 -m pytest -q` | **51 pass, 4 skipped** |
| `verifyknot-site` | `npm test` | **81 pass, 0 fail** |

Neither `hashstamp-worker`, `zknot-api` nor `hashstamp-site` has any working-tree
change (`git status --porcelain` is empty in all three).

## 7. Production build validation

`deploy.sh`'s rsync + pre-flight were replicated **without the deploy step**. The
staged tree contains exactly the 10 site files (`index.html`, `verifier.js`,
`proof-bundle.js`, `proof-bundle-ui.js`, `flags.js`, `_headers`, `_redirects`,
`README.md`, `sign/index.html`, `start/index.html`) and **no** `test/`, `docs/`,
`package.json`, `package-lock.json` or `node_modules`.

## 8. Known gaps

- **No test runs against a live production record.** Fixtures are generated
  (§Design 2) because a captured record's signature could not be re-signed for
  mutation tests. The shape/pin contract tests are the compensating control. A
  single end-to-end check against a real `ZK-` code remains worth doing before
  launch — it is the one thing that would confirm the pinned key matches what the
  **deployed** Worker actually sends (the pin is read from `wrangler.toml`, which
  is the deploy source of truth but could be overridden in the dashboard).
- **No browser-engine test.** jsdom is not Chrome; WebCrypto is Node's. The crypto
  is standard P-256/SHA-256 and identical across engines, but drag-and-drop and
  the real download path are untested outside jsdom.
- **`13b.` cannot prove a positive pinned-key verification** (we do not hold the
  production private key, and must not). It proves the adjacent property instead:
  swapping the pinned key onto a foreign signature **fails**, so recognition
  cannot be laundered. The UI suite covers the positive path with a temporarily
  registered test key.
