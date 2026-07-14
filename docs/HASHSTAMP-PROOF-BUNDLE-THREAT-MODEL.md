# HashStamp Portable Proof Bundle — Threat Model

Scope: the `.hashstamp` v1 format, its exporter, and the offline importer in
verifyknot.io. Companion to `HASHSTAMP-PROOF-BUNDLE-SPEC-v1.md`.

## 1. Assets

| Asset | Why it matters |
|---|---|
| The verdict a stranger reads | The product *is* the verdict. A wrong "verified" is total failure. |
| The HashStamp service private key | Held by the Worker. Compromise forges every past and future stamp. |
| The user's original file | Must never be uploaded, and is not in the bundle. |
| The user's private filenames | Sender's and recipient's. Never published, never transmitted. |
| Customer PII in `metadata` | `/v1/verify` echoes `metadata` unfiltered (see 4.6). |

## 2. Actors

- **Holder** — has a receipt, exports a bundle.
- **Skeptic** — receives a bundle and a file; trusts neither the holder nor ZKNOT.
- **Forger** — wants a bundle that renders as verified for a file ZKNOT never stamped.
- **Snoop** — wants to learn what file the skeptic is checking.
- **ZKNOT** — the issuer. **In scope as a threat**, and the model says so.

## 3. Trust boundaries

1. The bundle file — **fully attacker-controlled**. Every byte is untrusted input.
2. The local file the skeptic selects — untrusted content; only ever hashed.
3. `api.zknot.io` — trusted for *availability of a public record*, never for a verdict.
4. `proof-bundle.js` as delivered by verifyknot.io — **the actual root of trust**
   (see 4.2). Everything rests on this.

## 4. Threats

### 4.1 Forged bundle with an attacker's key — **PRIMARY THREAT**

*Attack:* generate a P-256 keypair, sign any fingerprint, emit a well-formed
bundle carrying that public key. Internal math is flawless.

*Why it is the primary threat:* a naive verifier that checks "signature vs the
key in the file" says **VERIFIED**. This is the failure mode this feature was
most at risk of shipping.

*Mitigation:* key identity is a **separate, decisive check** (BUN-23) against a
pinned key (`KNOWN_SIGNING_KEYS`). Math-passed + key-unrecognized ⇒
`VERIFIED_UNRECOGNIZED_KEY`, rendered **SIGNING KEY NOT RECOGNIZED**, and
Verify-your-copy is **refused** so no green "match" appears next to it.

*Tests:* `13.`, `13b.`, `16.`, `23b.`, UI badge + copy-block tests. Mutation-tested:
forcing `recognized = true` fails 3 tests.

*Residual:* a skeptic who ignores the red badge and the blocked panel.

### 4.2 Substituted verifier — **UNMITIGATED, BY CONSTRUCTION**

*Attack:* serve a modified `proof-bundle.js` (compromised Pages account, hostile
CDN, MITM without HSTS, a hostile fork) whose pin is the attacker's key.

*Mitigation:* none available to a static page verifying itself. TLS + `_headers`
raise the bar; they do not close it.

*Honest consequence:* **the pin is only as good as the copy of the page you are
running.** The spec and the bundle's own `limitations[]` say exactly this and
direct a skeptic to compare `signing_key.public_key` against ZKNOT's published
key obtained independently. We do not claim unforgeability.

### 4.3 Tampered bundle (fingerprint / payload / signature swap)

| Variant | Caught by |
|---|---|
| Mutate fingerprint only | BUN-20 (payload↔fingerprint binding) |
| Mutate payload only | BUN-20 |
| Mutate payload **and** fingerprint **and** recompute `challenge_hash` | BUN-22 (signature) |
| Mutate signature | BUN-22 |
| Swap in a different real key | BUN-22 |
| Swap in the **pinned** key to force recognition | BUN-22 — the foreign signature no longer verifies |

The checks are independent by design: satisfying one breaks another. Tests `14.`,
`14b.`, `15.`, `16.`, `13b.`

### 4.4 Malicious file content (parser / XSS)

*Attacks:* huge file to exhaust memory; deeply nested or malformed JSON; `<script>`
in `public_label`; prototype pollution via `__proto__`/`constructor`.

*Mitigations:* size cap on **UTF-8 bytes** *before* `JSON.parse` (and before the
file is read at all, using `file.size`); `JSON.parse` reviver dropping
prototype keys; strict hex regexes on all crypto fields; length caps on all text;
sanitizer that **removes** angle brackets rather than escaping them; every render
via `textContent`, never `innerHTML`.

*Tests:* `18.`, `19.`, `19b.` (multi-byte size evasion), `20.`, `20b.`, UI inert-text
and oversized-not-read tests.

### 4.5 Exfiltration during "offline" verification

*Attack:* the import path silently beacons the bundle, the local file, its name,
or the verdict.

*Mitigations:* `proof-bundle.js` contains exactly **one** `fetch`, statically
asserted to live only inside `checkCurrentStatusOnline`. The import path is pure
computation.

*Tests, three independent ways:* static source scan (`24. STATIC`), dynamic traps on
`fetch`/`XHR`/`WebSocket`/`EventSource`/`sendBeacon` around the full path
(`24. DYNAMIC`), plus a **mutation test proving the trap fires** (`24. MUTATION`) so
the first two cannot pass vacuously. A beacon injected into the import path fails
the suite.

### 4.6 PII leak through the exporter — **a live hazard, not hypothetical**

*Attack surface:* `/v1/verify` returns `metadata` **unfiltered**
(`verify.py:53`, `metadata=artifact.metadata_`), and zknot-api's **public**
`POST /v1/units/{code}/register` writes `metadata.registration.email` into that
same blob. An exporter that copied `metadata` wholesale would publish a customer
email into a file designed to be emailed around.

*Mitigation:* **structural.** `mapApiResponse` is an allowlist that never spreads
`metadata`; `buildProofBundle` reads only named fields off that mapped record and
refuses a raw API body (its gate reads flattened fields a raw body lacks). A new
toxic field cannot leak because nothing copies it.

*Tests:* toxic-metadata fixture; allowlist test with an invented field; raw-body
rejection test; deny-list with mutation tests proving it fires. Injecting
`filename: rec.filename` into the exporter fails 3 privacy tests.

> **Out of scope but reported:** the units-registration email exposure on
> `GET /v1/verify` is a **pre-existing zknot-api issue**, independent of this
> feature. It is not touched here. See the final report.

### 4.7 Correlation / tracking via the bundle

*Attack:* embed a per-export identifier and correlate archived copies to an exporter.

*Mitigation:* `bundle_id` is a deterministic hash of the evidence only. No
timestamp, client id, or filename feeds it. `exported_at` is the only
export-time value and is coarse and honest about being non-evidential.

### 4.8 Snooping the skeptic's check

*Attack:* learn which file a skeptic is verifying.

*Mitigations:* offline import sends nothing. The optional online check sends only
the verification code — already public — via one plain GET with no headers, body,
query string, or credentials. Fingerprint, signature, local filename, local hash
and verdict are never transmitted (tested).

*Residual:* pressing the online button reveals to ZKNOT/network observers *that
this code is being checked*, plus the usual IP/TLS metadata. Documented on the
button itself.

### 4.9 Stale evidence (revocation / supersession)

*Attack:* present a bundle whose key was later revoked, or which a later record supersedes.

*Mitigation:* **none offline — and we say so.** `key_revocation_status:
NOT_CHECKED_OFFLINE`, badge **CURRENT KEY STATUS NOT CHECKED**, always rendered.
Even *after* the online check, key status stays NOT CHECKED, because `/v1/verify`
publishes no key-status or revocation record. Claiming otherwise would invent
assurance. Tested (`ONLINE-KEY-STATUS` `pass: null`).

### 4.10 Chain-linkage over-claim

*Attack:* a reader assumes `chain.position: 4211` means "proven to be in the chain".

*Mitigation:* `chain_linkage: METADATA_ONLY`; badge **CHAIN PROOF NOT INCLUDED**;
`inclusion_proof`/`checkpoint` explicitly `null`. Not verified offline —
rationale in SPEC §9 (linkage needs neighbours the bundle lacks; and CHAIN-TZ-001
makes entry-hash recomputation timezone-fragile, which would yield false
"tampered" verdicts).

### 4.11 Time over-claim

*Attack:* read `stamped_at` as an independent timestamp.

*Mitigation:* `time_basis: HASHSTAMP_SERVICE_TIME`, `external_time_anchor:
NOT_PRESENT`, badge **EXTERNAL TIME ANCHOR NOT PRESENT**, and the time evidence
row names the service explicitly. ZKNOT's own clock is not a time authority.

### 4.12 Service-key compromise or ZKNOT malfeasance

*Attack:* the Worker's `HASHSTAMP_PRIVATE_KEY_PKCS8` leaks, or ZKNOT back-dates a stamp.

*Mitigation:* **none in this format.** One hosted key, no external anchor, no
transparency log ⇒ a stamp is only as trustworthy as ZKNOT's key handling and
honesty. The bundle's `limitations[]` says the trust model plainly; the spec
refuses the "cannot be forged" claim. An RFC 3161 token or a public checkpoint
would materially reduce this — both are reserved, unimplemented, and rendered as
NOT PRESENT rather than pending.

### 4.13 Downgrade / confusion

*Attack:* a v2 bundle fed to a v1 reader, or a hand-rolled `schema` value.

*Mitigation:* unknown schema ⇒ fail closed before any field is interpreted. No
best-effort parse. Tests `17.`, `17b.`, UI unsupported-schema test.

## 5. Non-goals

Identity of the submitter · delivery/receipt · authorship · ownership · legal
admissibility · content truth · protection against a compromised verifier page ·
protection against ZKNOT itself.

## 6. Residual risk summary

| Risk | Status |
|---|---|
| Substituted verifier page / hostile fork | **Unmitigated by design.** Disclosed in spec + bundle limitations. |
| ZKNOT key compromise or malfeasance | **Unmitigated.** Single hosted key, no anchor. Disclosed. |
| Revoked-key bundle presented offline | Cannot be detected offline; badged NOT CHECKED, both offline and online. |
| Chain membership | Not proven. Badged NOT INCLUDED. |
| Skeptic ignores red badges | Mitigated only by design: comparison is blocked, not merely warned. |
| Online check reveals a code is being checked | Disclosed on the button. |
