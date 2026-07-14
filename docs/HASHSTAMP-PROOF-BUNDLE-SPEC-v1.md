# HashStamp Portable Proof Bundle — Specification v1

**Schema id:** `zknot.hashstamp.proof.v1`
**Generator:** `verifyknot-proof-bundle/1.0.0`
**Extension:** `.hashstamp` · **Media type:** `application/json`
**Status:** staged, behind `ENABLE_PORTABLE_PROOF_BUNDLE` (default `false`)
**Implementation:** `proof-bundle.js` (format + crypto), `proof-bundle-ui.js` (rendering)

---

## 1. What this format is for

A HashStamp record lives at `api.zknot.io`. A proof bundle turns one such record —
*after* it has verified cryptographically in the holder's browser — into a single
self-contained JSON file that can be archived, emailed, or handed to a skeptic,
and re-checked later **offline**, with no account and without uploading the
original file.

A bundle is **not** a copy of the file. It is the verification *material*: the
file's fingerprint, the service's signature over that fingerprint, and the public
key needed to check it.

## 2. The trust model — read this before anything else

Verifying a signature against a public key **carried in the same file** proves
nothing on its own. Anyone can generate a P-256 keypair, sign any fingerprint,
and produce a bundle whose internal math is flawless.

Therefore this format's verifier reports **two independent results and never
merges them**:

| Result | Question it answers | Where it comes from |
|---|---|---|
| `signature_math` | Does the signature verify against the key in this file? | pure computation over the bundle |
| `key_identity` | Is that key ZKNOT's HashStamp service key? | comparison against a **pinned** key in the verifier |

A bundle that passes the first and fails the second is **a valid signature by a
stranger**. It renders as `VERIFIED_UNRECOGNIZED_KEY`, and "Verify your copy" is
refused for it — a green "match" against a stranger's signature would be a
reassuring lie.

The pin (`KNOWN_SIGNING_KEYS` in `proof-bundle.js`) is sourced from the Worker's
`wrangler.toml` `[vars] HASHSTAMP_PUBLIC_KEY_HEX` — the deliberately non-secret,
already-committed public half of the service keypair.

**The pin's own limit, stated plainly:** it is a *hosted service key held by
ZKNOT*. A match proves the ZKNOT HashStamp service signed this fingerprint. It
does **not** make a bundle unforgeable *by ZKNOT*, and it is only as trustworthy
as the copy of `proof-bundle.js` the reader is running. A reader who does not
trust verifyknot.io should compare `signing_key.public_key` against ZKNOT's
published key obtained independently. This is a single-key, single-issuer trust
model with no CA, no transparency log, and no external anchor.

## 3. Canonicalization — why there is no gap here

This is the question that decides whether offline verification is real or theatre.
For HashStamp document-timestamps, **there is no canonical-JSON problem at all**,
because the service does not sign a JSON document. It signs the raw fingerprint.

From `hashstamp-worker.js` `handleStamp()`:

```
fileHash       = SHA-256(file)                  computed in the sender's browser
fileHashBytes  = the raw 32 bytes of fileHash
challenge_hash = SHA-256(fileHashBytes)
signature      = ECDSA-P256 sign(privateKey, fileHashBytes)
```

WebCrypto's `sign({name:"ECDSA", hash:"SHA-256"}, key, INPUT)` hashes `INPUT`
once and signs the digest. Passing `fileHashBytes` as `INPUT` therefore means the
signed digest is exactly `SHA-256(fileHashBytes)` = `challenge_hash`.

Verification is the mirror image: feed WebCrypto the **preimage**
(`fileHashBytes`) and it hashes once and checks. So:

- **the signed message is the 32-byte file fingerprint, verbatim;**
- there is no field ordering, no key sorting, no whitespace question, no encoding
  ambiguity, and nothing to reconstruct from display fields;
- the bundle carries that preimage byte-for-byte in `signature.signed_payload`.

| Property | Value |
|---|---|
| Canonical serialization of the signed payload | **none needed** — the payload is 32 raw bytes, not a document |
| Field ordering | not applicable |
| Signed-payload encoding in the bundle | lowercase hex, 64 chars |
| Signature algorithm | ECDSA P-256 with SHA-256 |
| Signature encoding | raw `r‖s` (IEEE P1363), 64 bytes, lowercase hex (DER also accepted on read) |
| Public-key format | SEC1 uncompressed `04‖X‖Y`, lowercase hex (bare `X‖Y` accepted and normalized) |
| Hash algorithm | SHA-256 |
| Bundle serialization | JSON, UTF-8, pretty-printed 2-space, trailing newline |

**Legacy-record behavior.** Every HashStamp record ever written carries
`metadata.file_sha256`; the Worker has set it since its first revision. "Legacy"
(pre-F2) records differ only by *also* carrying `metadata.filename` (the sender's
private filename, published back when the browser still sent it) and lacking
`metadata.public_label`. Both export fine. **The private filename is never copied
into a bundle** — see §6. The signing math has never changed, so legacy records
verify offline by the identical path.

## 4. The schema

```jsonc
{
  "schema": "zknot.hashstamp.proof.v1",   // REQUIRED. Unknown value => fail closed.
  "generator": "verifyknot-proof-bundle/1.0.0",
  "min_verifier": "zknot.hashstamp.proof.v1",
  "bundle_id": "hsb1_<32 hex>",           // deterministic; see §5
  "exported_at": "<ISO-8601>",            // when this FILE was written (not evidence)

  "record": {
    "verification_code": "ZK-XXXX-XXX",   // public short code
    "artifact_type": "COMBINED_SESSION",
    "kind": "document_timestamp",
    "product": "hashstamp",
    "record_version": null,               // null for HashStamp records today
    "public_label": "Invoice 2026-07",    // OPTIONAL, user-chosen, already public
    "signed_at": "<ISO-8601>",            // SERVICE time — not an anchor
    "stamped_at": "<ISO-8601>"            // SERVICE time — not an anchor
  },

  "file_fingerprint": {                   // the evidence subject
    "algorithm": "SHA-256",
    "value": "<64 hex>"
  },

  "signature": {
    "algorithm": "ECDSA-P256-SHA256",
    "encoding": "p1363-r||s-hex",
    "value": "<128 hex>",
    "key_id": "HASHSTAMP-SVC-01",
    "signed_payload": {                   // the EXACT bytes signed, carried verbatim
      "encoding": "hex",
      "value": "<64 hex>",                // == file_fingerprint.value (asserted, not assumed)
      "description": "..."
    },
    "challenge_hash": "<64 hex>"          // SHA-256(signed_payload) — the signed digest
  },

  "signing_key": {
    "key_id": "HASHSTAMP-SVC-01",
    "algorithm": "ECDSA-P256",
    "format": "sec1-uncompressed-hex",
    "public_key": "04<128 hex>",
    "valid_from": null,                   // null = UNKNOWN, never "valid forever"
    "valid_until": null,
    "recognized_at_export": true          // what the EXPORTER concluded; never trusted on import
  },

  "chain": {                              // SERVICE-REPORTED METADATA ONLY — not proof
    "position": 4211,
    "previous_hash": "<hex|null>",
    "entry_hash": "<hex|null>",
    "artifact_id": "<uuid|null>",
    "service_reported_integrity": true,
    "checkpoint": null,                   // reserved — see FUTURE-EXTENSIONS
    "inclusion_proof": null               // reserved — absent means absent
  },

  "assurance": { /* closed enums — §7 */ },
  "limitations": [ "..." ]                // human-readable, carried with the file
}
```

### Field semantics

| Field | Meaning | Evidence class (§7) |
|---|---|---|
| `schema` | Format id. Unknown ⇒ refuse to parse. | — |
| `generator` | Which code wrote the file. Diagnostic only. | reported |
| `min_verifier` | Lowest schema a reader must support. Additive fields must not bump it. | — |
| `bundle_id` | Deterministic id of the evidence (§5). Not a secret, not a nonce. | — |
| `exported_at` | When the file was written. **Not** evidence of anything about the file. | reported |
| `record.verification_code` | Public short code; the only value ever sent online. | reported |
| `record.public_label` | Optional user label, already public on the record. Untrusted text. | reported |
| `record.signed_at` / `stamped_at` | **HashStamp service time.** Not an independent timestamp. | reported |
| `file_fingerprint.value` | SHA-256 of the original file. The subject of the evidence. | **contained** |
| `signature.value` | Service signature over `signed_payload`. | **verifiable offline** |
| `signature.signed_payload.value` | The exact signed bytes. Equals the fingerprint; **asserted** at import. | **contained** |
| `signature.challenge_hash` | `SHA-256(signed_payload)` — the digest the signature covers. | **verifiable offline** |
| `signing_key.public_key` | The key to check the signature with. Meaningful only when it matches the pin. | **contained**; identity requires the pin |
| `signing_key.valid_from` / `valid_until` | `null` ⇒ **unknown**. No validity window is published today. | not present |
| `chain.*` | Position and hashes as reported by the service. **No proof.** | **reported** |
| `assurance.*` | Machine-readable statement of what is/is not established. | — |
| `limitations[]` | Plain-language limits, travelling with the file. | — |

## 5. `bundle_id`

`hsb1_` + first 32 hex of `SHA-256("zknot.hashstamp.proof.v1|<code>|<fingerprint>|<signature>")`.

Deterministic on purpose: exporting the same record twice yields the same id, so
two archived copies are recognisably the same evidence. It deliberately carries
**no** entropy about the exporter — no timestamp, no client id, no filename — so
it cannot become a tracking token.

## 6. Privacy — allowlist, not denylist

`GET /v1/verify/{code}` echoes the artifact's `metadata` blob **unfiltered**. For
non-HashStamp artifact types that blob can contain a customer email (zknot-api's
public units-registration path writes `metadata.registration.email`).

The builder therefore reads **only named fields off the mapped record**
(`mapApiResponse` output), and never spreads `metadata`. A field invented
tomorrow is simply never copied. The deny-list test suite is a **backstop for
this property, not the mechanism enforcing it**.

Never included: original file bytes, sender's private filename, recipient's local
filename, customer email, Stripe identifiers (`cs_*`, `pi_*`, `sk_*`, `price_*`),
`session_id`, IP address, user agent, analytics ids, auth tokens, internal notes,
worker secrets, private keys.

Included because it is the evidence subject: **the file fingerprint**.
Included because it is already public: `public_label`, `verification_code`,
`device_id`/`key_id`, chain position/hashes, service timestamps.

See `HASHSTAMP-PROOF-BUNDLE-PRIVACY.md`.

## 7. Evidence classes

Every claim falls into exactly one, and the format never promotes one to another:

1. **Contained & verifiable offline** — the bundle carries everything needed to
   recompute the result: the signature check, the payload↔fingerprint binding,
   the challenge-hash derivation.
2. **Reported by the service** — copied so it can be quoted and compared, proven
   by nothing in the file: chain position/hashes, service timestamps.
3. **Requires an online lookup** — current key status, superseding records, live
   chain state.
4. **Not present** — external time anchor, inclusion proof, checkpoint,
   revocation record. *Absent means absent*, and is rendered as such.

### `assurance` enum values

| Key | Values |
|---|---|
| `record_signature` | `VERIFIABLE_OFFLINE` (in a file) / `VERIFIED_OFFLINE` \| `NOT_VERIFIED` (in a result) |
| `signing_key_identity` | `PINNED_KEY_COMPARISON_REQUIRED` (in a file) / `PINNED_KEY_MATCH` \| `UNRECOGNIZED_KEY` (in a result) |
| `file_fingerprint` | `INCLUDED` |
| `file_copy_match` | `NOT_ATTEMPTED` \| `MATCH` \| `MISMATCH` |
| `chain_linkage` | `METADATA_ONLY` |
| `external_time_anchor` | `NOT_PRESENT` |
| `time_basis` | `HASHSTAMP_SERVICE_TIME` |
| `key_revocation_status` | `NOT_CHECKED_OFFLINE` |
| `superseding_record_check` | `NOT_CHECKED_OFFLINE` |

## 8. Verification algorithm (import)

1. Reject > `MAX_BUNDLE_BYTES` (64 KiB) **on UTF-8 bytes**, before parsing.
2. `JSON.parse` with a reviver dropping `__proto__` / `constructor` / `prototype`.
3. Require a plain object with a **known** `schema`; unknown ⇒ fail closed.
4. Validate required fields' types, hex shapes, and lengths; sanitize all display
   text (strip control chars and angle brackets, cap length).
5. **BUN-20** — assert `signed_payload.value === file_fingerprint.value`.
   *(The signature must cover the fingerprint the bundle displays.)*
6. **BUN-21** — assert `challenge_hash === SHA-256(signed_payload)`.
7. **BUN-22** — verify the signature over `signed_payload` against the carried key.
8. **BUN-23** — compare the carried key against the pin ⇒ `key_identity`.
9. **BUN-24** — attach the scope note (what this does and does not prove).

### Verdicts

| Verdict | Meaning |
|---|---|
| `VERIFIED_OFFLINE` | Math passed **and** the key is ZKNOT's pinned HashStamp key. |
| `VERIFIED_UNRECOGNIZED_KEY` | Math passed; the key is a stranger's. **Not evidence that ZKNOT stamped anything.** |
| `FAILED` | The math did not pass. |
| `CANNOT_VERIFY` | The check could not be run at all. |

Steps 5–8 are independent: recomputing `challenge_hash` to match a mutated
payload still fails at step 7, and swapping in the pinned public key to satisfy
step 8 breaks step 7. Both are covered by tests.

## 9. Why the chain is **not** verified offline

The verify response carries enough to recompute *this entry's own* hash
(`sha256_dict` over position, artifact_id, challenge_hash, signature, signed_at,
prev_hash). We deliberately do **not**:

1. **It would prove almost nothing.** Recomputing your own entry hash shows the
   entry is internally consistent. Linkage needs the *neighbouring* entries —
   the predecessor's `entry_hash` and the successor's `prev_hash` — and the
   bundle carries neither. There is no `/v1/chain/entry/{position}` route to get
   them.
2. **It would be unreliable.** The entry hash covers `signed_at` serialized by
   Python's `.isoformat()`. Reproducing that from JSON is timezone-fragile —
   tracked as **CHAIN-TZ-001** — so a client-side recomputation would produce
   false negatives that look like tampering.

A false "chain broken" is worse than an honest "not checked". So `chain.*` is
carried as `METADATA_ONLY` and badged **CHAIN PROOF NOT INCLUDED**. A real
inclusion proof has a reserved home; see `FUTURE-EXTENSIONS`.

## 10. Versioning

- `SCHEMA_REGISTRY` in `proof-bundle.js` maps schema id ⇒ reader. A new version
  is a **new row**; it does not edit the v1 reader.
- **Unknown major versions fail closed** — no best-effort parse, ever.
- Unknown **optional** fields within v1 are ignored (additive growth is allowed
  and tested); unknown or malformed **required** fields fail.
- Additive fields must not bump `min_verifier`.

## 11. Claims

**Permitted:**
- "This bundle contains the material needed to verify the included HashStamp
  service signature and file fingerprint."
- "The selected local file has the same SHA-256 fingerprint as the fingerprint
  contained in this verified bundle."
- "This verification was performed locally in your browser."

**Prohibited** (asserted by test):
delivery · authorship · who downloaded it · ownership · legal admissibility ·
an independent timestamp (none is included) · offline chain verification (only
position metadata is present) · "cannot be forged" without qualifying the
single-hosted-key trust model.

## 12. Conformance

A reader claiming `zknot.hashstamp.proof.v1` support MUST: fail closed on unknown
schemas; enforce a size limit before parsing; perform BUN-20, -21, -22
independently; report key identity **separately** from signature validity against
a pin obtained out-of-band; and never render an absent property as a pass.
