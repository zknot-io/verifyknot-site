# HashStamp Portable Proof Bundle — Future Extensions

**Nothing in this document is implemented.** It reserves *locations* in the v1
schema so future evidence can be added without a breaking change.

## The rule these reservations exist to protect

A reserved field that is `null`, absent, or unknown means **NOT PRESENT**, and
must render as NOT PRESENT — never as "pending", never as a pass, and never
silently omitted (an absent badge reads as a pass). Adding a field must never
retroactively strengthen a claim about a bundle that does not carry it.

## Compatibility rules

1. **Additive only.** New fields go in reserved slots; `min_verifier` stays
   `zknot.hashstamp.proof.v1` while the *existing* checks are unchanged.
2. A v1 reader **ignores** unknown optional fields (tested).
3. Anything that changes how BUN-20/21/22/23 work is a **new schema id** with a
   new row in `SCHEMA_REGISTRY`, not an edit to the v1 reader.
4. Every new evidence type needs: its own `assurance` key with a closed enum, its
   own badge, and its own line in the offline/online split. It must not be folded
   into an existing badge.
5. No extension may add a network call to the import path.

## Reserved locations

### `chain.checkpoint` — signed checkpoint
```jsonc
"checkpoint": {
  "checkpoint_id": "...", "chain_size": 91021, "root_hash": "<hex>",
  "signed_at": "...", "signature": { "algorithm": "...", "value": "<hex>", "key_id": "..." }
}
```
Would allow: "this entry is inside a chain state ZKNOT signed at size N."
Requires a checkpoint-publishing endpoint. `assurance.chain_linkage` would gain
`CHECKPOINT_VERIFIED_OFFLINE`. Still not third-party-anchored.

### `chain.inclusion_proof` — Merkle inclusion proof
```jsonc
"inclusion_proof": {
  "type": "merkle-audit-path", "hash_algorithm": "SHA-256",
  "leaf_index": 4211, "tree_size": 91021,
  "path": ["<hex>", "..."], "root_hash": "<hex>"
}
```
Would upgrade `chain_linkage` from `METADATA_ONLY` to `INCLUSION_PROVEN_OFFLINE`
**only when combined with a checkpoint** — a path to an unsigned root proves
nothing. Blocked on the chain becoming a Merkle tree (today it is a hash-linked
list) or on a `/v1/chain/entry/{position}` route enabling neighbour walking.
See also **CHAIN-TZ-001**: `signed_at` normalization must be fixed first, or
offline recomputation is timezone-fragile.

### `time_anchor` — RFC 3161 timestamp token (new top-level block)
```jsonc
"time_anchor": {
  "type": "rfc3161", "token": "<base64 DER TimeStampToken>",
  "tsa_name": "...", "hashed_message": "<hex>", "gen_time": "...",
  "tsa_certificate_chain": ["<base64 DER>", "..."]
}
```
**The single most valuable extension.** It is the only one that removes ZKNOT's
clock from the trust model. `assurance.external_time_anchor` would move from
`NOT_PRESENT` to `RFC3161_VERIFIED_OFFLINE`, and the badge from **EXTERNAL TIME
ANCHOR NOT PRESENT** to a positive claim — the first time this format could
honestly say a time was independently established. Requires a TSA relationship
and a DER/ASN.1 verifier (WebCrypto alone is insufficient).

### `signing_key.rotation_proof` — key rotation proof
```jsonc
"rotation_proof": {
  "predecessor_key_id": "...", "predecessor_public_key": "04<hex>",
  "signed_at": "...", "signature": "<hex>"
}
```
Would let a bundle signed by a retired key still verify against a *current* pin,
by chaining old→new. Without it, rotating `HASHSTAMP_PUBLIC_KEY_HEX` makes every
historical bundle render **SIGNING KEY NOT RECOGNIZED** unless the old key stays
in `KNOWN_SIGNING_KEYS`. **Operational note:** until this exists, *never remove a
retired key from the pin registry — add the new one alongside it.* The
`SHAPE: pinned key matches the Worker` test is the tripwire for an unannounced
rotation.

### `signing_key.revocation_proof` — signed revocation record
```jsonc
"revocation_proof": {
  "status": "VALID" | "REVOKED", "as_of": "...",
  "signed_by_key_id": "...", "signature": "<hex>", "reason": "..."
}
```
The **only** way `key_revocation_status` could ever be anything but
`NOT_CHECKED_OFFLINE` in a file. Note the inherent limit: a signed "VALID as of
T" is only ever evidence about T, never about now — so the honest ceiling is
`VALID_AS_OF_TIMESTAMP`, not `VALID`. Requires a key-status endpoint publishing
signed records (`/v1/verify` publishes none today, which is why the online check
*still* reports NOT CHECKED).

### `acknowledgment` — recipient acknowledgment (new top-level block)
```jsonc
"acknowledgment": {
  "acknowledged_by_key_id": "...", "public_key": "04<hex>",
  "acknowledged_at": "...", "statement": "...",
  "signature": { "algorithm": "...", "value": "<hex>" }
}
```
⚠ **Claim hazard — the most dangerous reservation here.** This must never be
rendered as "proves delivery". A signature over "I received fingerprint X" proves
only that *a key* signed that sentence. It does not establish receipt, reading,
understanding, or agreement, and the identity of the acknowledging key needs its
own trust model. Requires a separate badge and its own `does_not_prove` copy
before any implementation.

### `witnessmark` — WitnessMark signature (new top-level block)
```jsonc
"witnessmark": {
  "device_serial": "...", "identity_tier": "...",
  "presence_binding_type": "...", "content_binding_type": "...",
  "signature": { "algorithm": "...", "value": "<hex>", "public_key": "04<hex>" },
  "attestation_chain": ["..."]
}
```
A hardware-held key with human-presence binding — a *different and stronger* claim
than a hosted service key. It must map onto `verifier.js`'s existing `TIER_VOCAB`
(SELF-ASSERTED / REGISTERED / REGISTRY-ASSERTED) and reuse its `proves` /
`does_not_prove` / `anchor` rows rather than inventing new copy. Likely a new
schema id, since presence/content binding changes what the bundle *means*, not
just what it carries.

### `trustseal` — TrustSeal identifier
```jsonc
"trustseal": { "trustseal_id": "...", "issued_at": "...", "registry_signature": "<hex>" }
```
Registry-asserted tier. Maps to `TIER_VOCAB["registry-asserted"]`: the registry
vouches that a registration exists and is unaltered — **not** a device-held key
and **not** a human-presence event. Copy must stay inside that row.

### `custody` — custody-transfer records
```jsonc
"custody": [{
  "from_key_id": "...", "to_key_id": "...", "transferred_at": "...",
  "prev_entry_hash": "<hex>", "signature": "<hex>"
}]
```
⚠ **Claim hazard.** A custody chain proves a sequence of *signatures*, never
lawful ownership, possession, or authority to transfer. Prohibited claims
("proves ownership") apply with full force. Each hop needs its own key trust
model; a chain of unrecognized keys is a chain of strangers.

## Explicitly not reserved

- **Original file content, ever.** The bundle is evidence *about* a file; putting
  the file in it would destroy the privacy property that makes it shareable, and
  a fingerprint match already proves byte-identity.
- **Any identity claim about the submitter.** No record kind here captures one.
- **A "verified" boolean.** The verdict is computed by the reader, never carried.
  (`/v1/verify` hardcodes `verified: true` on every 200 — a live illustration of
  why a carried verdict is worthless.)
