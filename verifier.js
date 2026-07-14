// @ts-check
/**
 * verifyknot client-side verifier — v0.1 (ATECC / v1-record generation)
 * Implements: VER-02 (offline-reproducible), VER-04 (honest translation),
 *             VER-11 (event signature), VER-20 (hash/short-code consistency),
 *             VER-26 (specific, honest failures), VER-33 (math runs client-side).
 *
 * THE RULE THIS FILE EXISTS TO ENFORCE:
 *   The verdict shown to a stranger is computed HERE, in their browser,
 *   from record DATA. The server's `verified` boolean is never displayed
 *   as the verdict. If the server's boolean disagrees with the local math,
 *   that discrepancy is surfaced — it is a finding, not noise.
 *
 * Zero dependencies. Web Crypto only (works in every modern browser and in
 * Node >= 20 for testing). TypeScript-checkable via // @ts-check + JSDoc.
 *
 * GENERATION NOTE: this verifies the v1 single-signature record (ATECC tier,
 * SELF-ASSERTED / REGISTERED). The WitnessMark generation (two signatures,
 * identity-domain attestation, COSE/CBOR, chain to HSM root — VER-12/13/14)
 * is a planned extension, not handled here. Records declaring a newer
 * record_version fail closed with an honest "unknown version" (VER-10).
 */

/** Supported record versions (VER-10). "v1" is the TrustSeal / registry-signed
 *  generation; it uses the SAME format-blind crypto (VER-20 + VER-11), so it
 *  needs no new verification math — only this allowlist entry + tier vocab. */
const SUPPORTED_VERSIONS = ["1.0", "v1"];

/**
 * IDENTITY-TIER VOCABULARY (VER-04 honest translation).
 *
 * The scalable shape: a new product or tier is a new ROW here, not a code
 * branch elsewhere. Each row says, in plain language, what the tier PROVES,
 * what it explicitly DOES NOT prove, and how a skeptic ANCHORS trust for it.
 * The verifier never claims more than the row allows.
 *
 * @typedef {Object} TierInfo
 * @property {string} label           display label
 * @property {string} proves          what a verified signature at this tier establishes
 * @property {string} does_not_prove  the limits — what it explicitly does NOT establish
 * @property {string} anchor          how a skeptic independently grounds trust here
 *
 * @type {Record<string, TierInfo>}
 */
const TIER_VOCAB = {
  "SELF-ASSERTED": {
    label: "SELF-ASSERTED",
    proves: "A signature exists that verifies against the public key carried in this record.",
    does_not_prove: "Nothing about WHO holds that key. The owner is whoever the record claims; no independent party vouches for it.",
    anchor: "None beyond the record itself. Trust rests entirely on the carried key's own claim.",
  },
  "registry-asserted": {
    label: "REGISTRY-ASSERTED",
    proves: "The record was signed by ZKNOT's published registry key (signer id = device_id, e.g. zknot-registry-v1). The registry vouches that this registration exists and has not been altered.",
    does_not_prove: "That an independent device with its own secure element signed it. It is NOT a device-held key and NOT a human-presence event.",
    anchor: "Verify the carried public key against ZKNOT's published registry public key, obtained out-of-band.",
  },
  "REGISTERED": {
    label: "REGISTERED",
    proves: "The signing device's own keypair is on file in the ZKNOT registry.",
    does_not_prove: "An X.509 CA certificate chain. No cert chain was verified.",
    anchor: "The device's public key as recorded in the ZKNOT registry.",
  },
  // "CA-ATTESTED" is intentionally NOT listed: it is gated/reserved until the
  // cert-chain provisioning SOP is confirmed live. An incoming "CA-ATTESTED"
  // record therefore falls to TIER_DEFAULT (treated as unverified identity)
  // rather than rendering a claim we cannot yet stand behind.
};

/** Safe fallback for any tier this verifier does not recognize. @type {TierInfo} */
const TIER_DEFAULT = {
  label: "UNVERIFIED",
  proves: "A signature verifies against the carried key — the math ran and passed.",
  does_not_prove: "Anything about identity. This tier is unrecognized by this verifier.",
  anchor: "None. Unrecognized tier — treat the identity as unverified.",
};

/**
 * DOCUMENT-TIMESTAMP vocabulary (VER-04 honest translation for HashStamp).
 * A doc-timestamp is NOT an identity tier — it proves a file existed at a time,
 * signed by a service key. Its honest scope is deliberately narrow: existence +
 * time, never authorship, presence, or content-binding. Copy stays within the
 * HASHSTAMP-VERIFY-HANDOFF-001 claim guardrail ("tamper-evident", not "-proof").
 * @type {TierInfo}
 */
const DOC_TIMESTAMP_INFO = {
  label: "DOCUMENT-TIMESTAMP",
  proves: "The file with the SHA-256 fingerprint below had its fingerprint signed by ZKNOT's hosted HashStamp service key and recorded at a position in HashStamp's tamper-evident, hash-linked chain. The stamp time is provided by the HashStamp service — it is not anchored to an independent time authority.",
  does_not_prove: "Who created, owned, or uploaded the file; that any specific person was present; or that a human was shown the content. It is tamper-evident, not tamper-proof — anyone holding the file can recompute this same fingerprint.",
  anchor: "Recompute SHA-256 of your own copy of the file and confirm it equals the fingerprint below; your browser has already re-verified the service-key signature over that fingerprint.",
};

/**
 * Is this a HashStamp document-timestamp record? Such records verify over the
 * file fingerprint directly (no reconstructable signed_payload), so they take a
 * dedicated path instead of failing the generic "incomplete data" check.
 * Primary signal: kind === "document_timestamp" (set by the Worker). Structural
 * fallback: a file fingerprint present, no signed_payload, no binding claims.
 * @param {Partial<VerifyRecord>} rec
 */
function isDocTimestamp(rec) {
  if (rec.kind === "document_timestamp") return true;
  return !!rec.file_sha256 && !rec.signed_payload_hex
    && (rec.presence_binding_type ?? "none") === "none"
    && (rec.content_binding_type ?? "none") === "none";
}

/**
 * Resolve a record's identity_tier to its vocabulary row. Exact match first,
 * then a case-insensitive match, else the safe default.
 * @param {Partial<VerifyRecord>} rec
 * @returns {TierInfo & {key: string}}
 */
function tierOf(rec) {
  const tier = rec.identity_tier ?? "SELF-ASSERTED";
  if (Object.prototype.hasOwnProperty.call(TIER_VOCAB, tier)) {
    return { key: tier, ...TIER_VOCAB[tier] };
  }
  const hit = Object.keys(TIER_VOCAB).find((k) => k.toLowerCase() === tier.toLowerCase());
  if (hit) return { key: hit, ...TIER_VOCAB[hit] };
  return { key: tier, ...TIER_DEFAULT };
}

/**
 * @typedef {Object} VerifyRecord
 * @property {string} record_version    e.g. "1.0"
 * @property {string} short_code        e.g. "ZK-6GUA-7DV"
 * @property {string} device_id
 * @property {string} identity_tier     "REGISTERED" | "SELF-ASSERTED"
 * @property {string} presence_binding_type  "secure-domain"|"hardware-interlock"|"firmware-mediated"|"none"
 * @property {string} content_binding_type   "secure-domain-display"|"firmware-display"|"none"
 * @property {string} signed_payload_hex     canonical message bytes (hex) — the preimage
 * @property {string} challenge_hash         hex SHA-256 of signed_payload
 * @property {string} signature              hex; raw r||s (64B) or DER
 * @property {string} public_key             hex; uncompressed SEC1 (04||X||Y, 65B)
 * @property {{name?: string, sha256?: string}=} artifact
 * -- HashStamp document-timestamp records (no reconstructable signed_payload;
 *    the signed message IS the file fingerprint) carry these instead: --
 * @property {string=} kind             "document_timestamp" when set by the Worker
 * @property {string=} file_sha256      hex; the raw 32-byte file SHA-256 — the signed message
 * @property {string=} filename         original file name (display only)
 * @property {string=} stamped_at       ISO time the fingerprint was stamped
 * @property {number=} chain_position   hash-linked chain index
 * @property {boolean=} chain_integrity server-reported chain-intact flag (displayed as data)
 * @property {string=} product          e.g. "hashstamp"
 * @property {string=} signed_at        ISO time the record was signed
 */

/**
 * ADAPTER — the ONE place to reconcile this module with the live
 * GET /v1/verify/{code} JSON. Map your API's field names here.
 * If a required field is absent, return null for it and the verifier
 * will fail closed with a specific reason (never guess).
 * @param {any} api  parsed JSON from /v1/verify/{code}
 * @returns {Partial<VerifyRecord> & {server_asserted_verified?: boolean}}
 */
export function mapApiResponse(api) {
  return {
    record_version: api.record_version ?? api.metadata?.record_version ?? "1.0",
    short_code: api.short_code ?? api.code,
    device_id: api.device_id,
    identity_tier: api.identity_tier ?? api.metadata?.identity_tier ?? "SELF-ASSERTED",
    presence_binding_type: api.presence_binding_type ?? api.metadata?.presence_binding_type ?? "none",
    content_binding_type: api.content_binding_type ?? api.metadata?.content_binding_type ?? "none",
    signed_payload_hex: api.signed_payload_hex ?? api.signed_payload ?? api.metadata?.signed_payload_hex,
    challenge_hash: api.challenge_hash,
    signature: api.signature,
    public_key: api.public_key,
    artifact: api.artifact,
    // HashStamp document-timestamp fields (live shape nests these under metadata)
    kind: api.metadata?.kind ?? api.kind,
    file_sha256: api.metadata?.file_sha256 ?? api.file_sha256,
    filename: api.metadata?.filename ?? api.filename, // legacy records only; not sent by new stamps
    public_label: api.metadata?.public_label ?? null, // F2: optional user label (new records)
    stamped_at: api.metadata?.stamped_at ?? api.signed_at,
    product: api.metadata?.product ?? api.product,
    chain_position: api.chain_position,
    chain_integrity: api.chain_integrity,
    signed_at: api.signed_at,
    server_asserted_verified: api.verified, // captured ONLY to detect discrepancy
  };
}

/* ---------------- file-comparison adapter (VER-33 / "Verify your copy") -------
 * Lets a recipient confirm that a file they hold is byte-for-byte the file whose
 * fingerprint this record already committed to. The comparison is a LOCAL
 * equality test between two hashes; it is not a second attestation. It proves
 * only sameness of bytes — never authorship, sender, receipt, ownership,
 * approval, agreement, or the truth of the contents.
 * ---------------------------------------------------------------------------- */

/** A SHA-256 fingerprint as 64 hex chars. Case-insensitive on input; the
 *  canonical form this module emits and compares is always lowercase. */
const SHA256_HEX_RE = /^[0-9a-f]{64}$/i;

/**
 * SCHEMA ADAPTER — the ONE place that decides what "the fingerprint this record
 * committed to" means. Returns the canonical expected SHA-256, or null when the
 * record carries no usable fingerprint (missing/malformed → the caller must fail
 * closed, never guess).
 *
 * FIELD LAYOUTS CONFIRMED IN PRODUCTION CODE (do not add speculative ones):
 *   1. `file_sha256` — top level. This is BOTH the mapApiResponse() output shape
 *      and the docTimestamp block of a verifyRecord() result.
 *   2. `metadata.file_sha256` — the raw GET /v1/verify/{code} JSON. Every
 *      HashStamp record ever written carries the fingerprint here: the Worker has
 *      set metadata.file_sha256 since its first revision (hashstamp-worker.js and
 *      the pre-phase1 backup agree), so "legacy" HashStamp records differ from
 *      current ones only by ALSO carrying metadata.filename (pre-F2, now private)
 *      and lacking metadata.public_label. The fingerprint field name never moved.
 *
 * NOTE ON `HASHSTAMP_FILE`: no such artifact_type exists in production. Every
 * HashStamp record is artifact_type "COMBINED_SESSION" discriminated by
 * metadata.kind === "document_timestamp" (see isDocTimestamp). HASHSTAMP_FILE is
 * a TARGET in docs/HASHSTAMP-LAUNCH-AUDIT-20260713.md §137, not a shipped shape,
 * and its field layout is not yet defined. This adapter therefore keys off the
 * fingerprint field itself, which that migration does not propose to move — so a
 * future rename of artifact_type needs no change here. Do not invent fields for
 * HASHSTAMP_FILE until a real record exists to read.
 *
 * @param {any} rec  a mapped record, a raw /v1/verify JSON body, or a
 *                   verifyRecord() result's docTimestamp block
 * @returns {{algorithm: "SHA-256", expectedHex: string}|null}
 */
export function extractExpectedFingerprint(rec) {
  if (!rec || typeof rec !== "object") return null;
  const meta = rec.metadata && typeof rec.metadata === "object" ? rec.metadata : {};
  const candidate = [rec.file_sha256, meta.file_sha256].find(
    (v) => typeof v === "string" && v.trim() !== ""
  );
  if (!candidate) return null;
  const hex = candidate.trim().toLowerCase();
  // Hex is case-insensitive as a value, so we accept either case and canonicalize.
  // Anything that is not exactly 32 bytes of hex is malformed → no fingerprint.
  if (!SHA256_HEX_RE.test(hex)) return null;
  return { algorithm: /** @type {const} */ ("SHA-256"), expectedHex: hex };
}

/**
 * TRUST GATE — may this browser offer to compare a local file against this
 * record? A match shown against a record we could not verify would be a
 * reassuring lie, so this fails closed on every doubt.
 *
 * Enabled ONLY when the record verified cryptographically IN THIS BROWSER, is a
 * HashStamp document-timestamp, carries a well-formed fingerprint, and is not in
 * a server-reported chain hard-failure. A failed fetch never reaches here (no
 * result to gate), which is itself the correct closed state.
 *
 * @param {any} result  a verifyRecord() return value
 * @returns {{enabled: true, fingerprint: {algorithm: "SHA-256", expectedHex: string}}
 *          |{enabled: false, reason: string}}
 */
export function fileComparisonGate(result) {
  const NO = "File comparison unavailable because this receipt could not be verified.";
  if (!result || typeof result !== "object") return { enabled: false, reason: NO };

  // Signature invalid, unsupported schema, unreproducible record, or any other
  // non-verified verdict — the record's own claim is not established.
  if (result.verdict !== "VERIFIED_CLIENT_SIDE") return { enabled: false, reason: NO };

  // Scope: only HashStamp doc-timestamps commit to a *file* fingerprint. Other
  // record kinds carry hashes that mean something else; comparing a file against
  // one of those would answer a question the record never asked.
  if (result.kind !== "document_timestamp" || !result.docTimestamp) {
    return { enabled: false, reason: NO };
  }

  const fingerprint = extractExpectedFingerprint(result.docTimestamp);
  if (!fingerprint) return { enabled: false, reason: NO }; // missing or malformed

  // Chain hard-failure (server-reported). The signature may still be good, but
  // the record's position in the tamper-evident chain is in a failure state, so
  // we do not put a reassuring green result next to it. `null`/not-reported is
  // NOT a hard failure — it is simply unreported, and the record's own signature
  // was re-verified here.
  if (result.docTimestamp.chain_integrity === false) return { enabled: false, reason: NO };
  if (result.docTimestamp.assurance?.chain_linkage?.startsWith("BROKEN")) {
    return { enabled: false, reason: NO };
  }

  return { enabled: true, fingerprint };
}

/**
 * Compare a local File/Blob against an expected fingerprint. Runs entirely in
 * this browser: the bytes go to WebCrypto and nowhere else. Never throws — a
 * read failure is returned as an honest "could not compare", which is NOT a
 * statement about the file's validity.
 *
 * @param {Blob} file
 * @param {{algorithm: "SHA-256", expectedHex: string}} expected
 * @returns {Promise<{outcome: "MATCH"|"MISMATCH", localHex: string}
 *          |{outcome: "ERROR", reason: string}>}
 */
export async function compareLocalFile(file, expected) {
  if (!file || typeof file.arrayBuffer !== "function") {
    return { outcome: /** @type {const} */ ("ERROR"), reason: "No readable file was selected." };
  }
  if (!expected || !SHA256_HEX_RE.test(expected.expectedHex ?? "")) {
    return { outcome: /** @type {const} */ ("ERROR"), reason: "This receipt does not carry a usable SHA-256 fingerprint to compare against." };
  }

  let localHex;
  try {
    // Whole-file read: WebCrypto's digest() has no streaming API, so a very large
    // file can exhaust memory here. That surfaces as a concrete read error below
    // rather than as a mismatch — we never call a file "different" when we simply
    // failed to read it.
    const buf = await file.arrayBuffer();
    localHex = bytesToHex(await subtle.digest("SHA-256", buf));
  } catch (e) {
    const msg = /** @type {Error} */ (e)?.message || String(e);
    return {
      outcome: /** @type {const} */ ("ERROR"),
      reason: `This file could not be read in your browser (${msg}). The file may be too large to hash here, or it may have changed on disk since you selected it. This says nothing about whether the file is valid.`,
    };
  }

  return localHex === expected.expectedHex
    ? { outcome: /** @type {const} */ ("MATCH"), localHex }
    : { outcome: /** @type {const} */ ("MISMATCH"), localHex };
}

/* ---------------- encoding helpers ---------------- */

/** @param {string} hex @returns {Uint8Array} */
export function hexToBytes(hex) {
  const clean = hex.replace(/^0x/, "").replace(/\s+/g, "");
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** @param {Uint8Array|ArrayBuffer} buf @returns {string} */
export function bytesToHex(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/**
 * Accept ECDSA signature as raw r||s (64 bytes, what ATECC608 emits and what
 * Web Crypto expects) or DER (0x30...), converting DER -> raw.
 * @param {Uint8Array} sig @returns {Uint8Array} raw 64-byte r||s
 */
export function signatureToRaw(sig) {
  if (sig.length === 64) return sig;
  if (sig[0] !== 0x30) throw new Error(`unrecognized signature encoding (len=${sig.length})`);
  // Minimal DER ECDSA-Sig-Value parse: SEQUENCE { INTEGER r, INTEGER s }
  let i = 2; // skip SEQUENCE header (assumes short-form length; P-256 sigs always are)
  if (sig[1] & 0x80) i = 2 + (sig[1] & 0x7f); // long-form length, skip length bytes
  const readInt = () => {
    if (sig[i++] !== 0x02) throw new Error("bad DER: expected INTEGER");
    let len = sig[i++];
    let start = i;
    i += len;
    let v = sig.slice(start, start + len);
    while (v.length > 32 && v[0] === 0x00) v = v.slice(1); // strip sign padding
    if (v.length > 32) throw new Error("bad DER: integer > 32 bytes");
    const padded = new Uint8Array(32);
    padded.set(v, 32 - v.length);
    return padded;
  };
  const r = readInt();
  const s = readInt();
  const out = new Uint8Array(64);
  out.set(r, 0);
  out.set(s, 32);
  return out;
}

/* ---------------- core checks ---------------- */

const subtle = globalThis.crypto.subtle;

/** @param {Uint8Array} pubkeyRaw uncompressed SEC1 (65B) */
async function importP256(pubkeyRaw) {
  if (pubkeyRaw.length === 64) {
    const padded = new Uint8Array(65); padded[0] = 0x04; padded.set(pubkeyRaw, 1);
    pubkeyRaw = padded;
  }
  if (pubkeyRaw.length !== 65 || pubkeyRaw[0] !== 0x04) {
    throw new Error("public key must be 64 bytes (X||Y) or 65 bytes (04||X||Y)");
  }
  return subtle.importKey(
    "raw",
    /** @type {BufferSource} */ (pubkeyRaw.buffer.slice(pubkeyRaw.byteOffset, pubkeyRaw.byteOffset + pubkeyRaw.byteLength)),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
}

/**
 * Run the full client-side check. Never throws on verification failure —
 * failures are returned as specific, honest reasons (VER-26).
 * @param {Partial<VerifyRecord> & {server_asserted_verified?: boolean}} rec
 * @returns {Promise<{
 *   verdict: "VERIFIED_CLIENT_SIDE" | "FAILED" | "CANNOT_VERIFY",
 *   checks: {id: string, pass: boolean|null, detail: string}[],
 *   headline: string,
 *   badges: {identity: string, identity_label?: string, proves?: string, does_not_prove?: string, anchor?: string, signer?: string, presence: string, content: string},
 *   server_discrepancy: string|null,
 *   kind?: string,
 *   docTimestamp?: {filename: string|null, file_sha256: string|null, stamped_at: string|null, chain_position: number|null, chain_integrity: boolean|null, product: string|null}
 * }>}
 */
export async function verifyRecord(rec) {
  /** @type {{id: string, pass: boolean|null, detail: string}[]} */
  const checks = [];
  const fail = (/** @type {string} */ headline) => ({
    verdict: /** @type {const} */ ("FAILED"),
    checks,
    headline,
    badges: badgesOf(rec),
    server_discrepancy: discrepancy(rec, false),
  });
  const cannot = (/** @type {string} */ headline) => ({
    verdict: /** @type {const} */ ("CANNOT_VERIFY"),
    checks,
    headline,
    badges: badgesOf(rec),
    server_discrepancy: discrepancy(rec, null),
  });

  // VER-10 — schema / version. Unknown future version: say so, don't guess.
  if (!rec.record_version || !SUPPORTED_VERSIONS.includes(rec.record_version)) {
    checks.push({ id: "VER-10", pass: false, detail: `record_version "${rec.record_version}" not supported by this verifier (supports: ${SUPPORTED_VERSIONS.join(", ")})` });
    return cannot("This record declares a version this verifier does not understand. No verdict.");
  }

  // HashStamp document-timestamp records verify over the file fingerprint, not a
  // reconstructable signed_payload. Route them to their own honest path BEFORE
  // the generic completeness check below (which would otherwise fail them for a
  // missing signed_payload_hex they are not supposed to carry). VER-04/Option 1.
  if (isDocTimestamp(rec)) return verifyDocTimestamp(rec);

  for (const f of ["signed_payload_hex", "challenge_hash", "signature", "public_key"]) {
    if (!(/** @type {any} */ (rec))[f]) {
      checks.push({ id: "VER-10", pass: false, detail: `missing field: ${f} — record data is incomplete, cannot reproduce the check` });
      return cannot("The record does not carry the data needed to reproduce the check in your browser. No verdict.");
    }
  }
  checks.push({ id: "VER-10", pass: true, detail: "record parsed; version supported; reproduction data present" });

  let payload, expectedHash, sigRaw, pubRaw;
  try {
    payload = hexToBytes(/** @type {string} */ (rec.signed_payload_hex));
    expectedHash = hexToBytes(/** @type {string} */ (rec.challenge_hash));
    sigRaw = signatureToRaw(hexToBytes(/** @type {string} */ (rec.signature)));
    pubRaw = hexToBytes(/** @type {string} */ (rec.public_key));
  } catch (e) {
    checks.push({ id: "VER-10", pass: false, detail: `encoding error: ${/** @type {Error} */ (e).message}` });
    return cannot("Record fields are malformed; the check cannot be reproduced. No verdict.");
  }

  // VER-20 — the hash the human could have read matches what was signed.
  const computedHash = new Uint8Array(await subtle.digest("SHA-256", /** @type {BufferSource} */ (payload)));
  const hashOk = bytesToHex(computedHash) === bytesToHex(expectedHash);
  checks.push({ id: "VER-20", pass: hashOk, detail: hashOk ? "SHA-256(signed_payload) recomputed in this browser matches challenge_hash" : "challenge_hash does NOT match SHA-256 of the signed payload — record is internally inconsistent" });
  if (!hashOk) return fail("Cryptographically invalid: the record's hash does not match its own payload.");

  // VER-11 — event signature over the canonical payload, against the carried key.
  let sigOk = false;
  try {
    const key = await importP256(pubRaw);
    sigOk = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      /** @type {BufferSource} */ (sigRaw),
      /** @type {BufferSource} */ (payload)
    );
  } catch (e) {
    checks.push({ id: "VER-11", pass: false, detail: `key import / verify error: ${/** @type {Error} */ (e).message}` });
    return cannot("The public key could not be imported; the signature check could not run. No verdict.");
  }
  checks.push({ id: "VER-11", pass: sigOk, detail: sigOk ? "ECDSA P-256 signature verified in this browser over the signed payload" : "signature does NOT verify against the carried public key" });
  if (!sigOk) return fail("Cryptographically invalid: the signature does not verify.");

  // VER-13 honesty note — this generation has no chain to the HSM root.
  // Sourced from TIER_VOCAB so the note never claims more than the tier allows
  // and stays consistent with the badges/headline below.
  const t13 = tierOf(rec);
  checks.push({
    id: "VER-13",
    pass: null,
    detail: `identity tier ${t13.label}: proves — ${t13.proves} Does NOT prove — ${t13.does_not_prove} Anchor — ${t13.anchor}`,
  });

  return {
    verdict: "VERIFIED_CLIENT_SIDE",
    checks,
    headline: headlineOf(rec), // VER-04 / VER-25: maps 1:1 to the binding fields
    badges: badgesOf(rec),
    server_discrepancy: discrepancy(rec, true),
  };
}

/**
 * Doc-timestamp verify path (HashStamp / Option 1). The Worker signs the raw
 * 32-byte file hash via WebCrypto, which internally computes
 * SHA-256(fileHashBytes) = challenge_hash and signs THAT. So we reproduce the
 * check in-browser by feeding WebCrypto the PRE-IMAGE (file_sha256 bytes) and
 * letting it hash once — no prehashed-verify support needed. Never throws on a
 * verification failure; returns a specific honest reason instead (VER-26).
 * @param {Partial<VerifyRecord> & {server_asserted_verified?: boolean}} rec
 */
async function verifyDocTimestamp(rec) {
  /** @type {{id: string, pass: boolean|null, detail: string}[]} */
  const checks = [];
  const cannot = (/** @type {string} */ headline) => ({
    verdict: /** @type {const} */ ("CANNOT_VERIFY"), kind: "document_timestamp",
    checks, headline, badges: docBadges(rec), docTimestamp: docFields(rec),
    server_discrepancy: discrepancy(rec, null),
  });
  const fail = (/** @type {string} */ headline) => ({
    verdict: /** @type {const} */ ("FAILED"), kind: "document_timestamp",
    checks, headline, badges: docBadges(rec), docTimestamp: docFields(rec),
    server_discrepancy: discrepancy(rec, false),
  });

  // DT-10 — the data needed to reproduce a doc-timestamp check is present.
  for (const f of ["file_sha256", "challenge_hash", "signature", "public_key"]) {
    if (!(/** @type {any} */ (rec))[f]) {
      checks.push({ id: "DT-10", pass: false, detail: `missing field: ${f} — cannot reproduce the timestamp check` });
      return cannot("This document-timestamp record does not carry the data needed to reproduce the check in your browser. No verdict.");
    }
  }
  checks.push({ id: "DT-10", pass: true, detail: "document-timestamp record; file fingerprint, signature and key present" });

  let fileHash, expectedHash, sigRaw, pubRaw;
  try {
    fileHash = hexToBytes(/** @type {string} */ (rec.file_sha256));
    expectedHash = hexToBytes(/** @type {string} */ (rec.challenge_hash));
    sigRaw = signatureToRaw(hexToBytes(/** @type {string} */ (rec.signature)));
    pubRaw = hexToBytes(/** @type {string} */ (rec.public_key));
  } catch (e) {
    checks.push({ id: "DT-10", pass: false, detail: `encoding error: ${/** @type {Error} */ (e).message}` });
    return cannot("Record fields are malformed; the check cannot be reproduced. No verdict.");
  }
  if (fileHash.length !== 32) {
    checks.push({ id: "DT-10", pass: false, detail: `file_sha256 is ${fileHash.length} bytes, expected 32 — not a valid SHA-256 fingerprint` });
    return fail("Cryptographically invalid: the file fingerprint is not a 32-byte SHA-256.");
  }

  // DT-20 — the on-chain challenge_hash IS SHA-256 of the file fingerprint.
  // This ties the chain entry to this exact file, independent of the signature.
  const computedHash = new Uint8Array(await subtle.digest("SHA-256", /** @type {BufferSource} */ (fileHash)));
  const hashOk = bytesToHex(computedHash) === bytesToHex(expectedHash);
  checks.push({ id: "DT-20", pass: hashOk, detail: hashOk ? "SHA-256(file fingerprint) recomputed in this browser matches the chain's challenge_hash" : "challenge_hash does NOT match SHA-256 of the file fingerprint — record is internally inconsistent" });
  if (!hashOk) return fail("Cryptographically invalid: the chain entry's hash does not match this file's fingerprint.");

  // DT-11 — the service key signed this exact file fingerprint (WebCrypto hashes
  // the pre-image once, so verifying over fileHash checks the signature over
  // SHA-256(fileHash) = challenge_hash).
  let sigOk = false;
  try {
    const key = await importP256(pubRaw);
    sigOk = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      /** @type {BufferSource} */ (sigRaw),
      /** @type {BufferSource} */ (fileHash)
    );
  } catch (e) {
    checks.push({ id: "DT-11", pass: false, detail: `key import / verify error: ${/** @type {Error} */ (e).message}` });
    return cannot("The public key could not be imported; the signature check could not run. No verdict.");
  }
  checks.push({ id: "DT-11", pass: sigOk, detail: sigOk ? "ECDSA P-256 signature verified in this browser — the HashStamp service key signed this file's fingerprint" : "signature does NOT verify against the carried public key" });
  if (!sigOk) return fail("Cryptographically invalid: the signature does not verify over this file's fingerprint.");

  // DT-13 honesty note — narrow, existence-and-time scope. Never more.
  checks.push({
    id: "DT-13", pass: null,
    detail: `document timestamp: proves — ${DOC_TIMESTAMP_INFO.proves} Does NOT prove — ${DOC_TIMESTAMP_INFO.does_not_prove} Anchor — ${DOC_TIMESTAMP_INFO.anchor}`,
  });

  return {
    verdict: /** @type {const} */ ("VERIFIED_CLIENT_SIDE"), kind: "document_timestamp",
    checks, headline: docHeadline(rec), badges: docBadges(rec), docTimestamp: docFields(rec),
    server_discrepancy: discrepancy(rec, true),
  };
}

/** File-centric facts for the freelancer-legible view (Option 3). */
function docFields(/** @type {Partial<VerifyRecord>} */ rec) {
  return {
    filename: rec.filename ?? null, // legacy records only
    public_label: rec.public_label ?? null, // F2: shown in preference to filename for new records
    file_sha256: rec.file_sha256 ?? null,
    stamped_at: rec.stamped_at ?? rec.signed_at ?? null,
    chain_position: rec.chain_position ?? null,
    chain_integrity: rec.chain_integrity ?? null,
    product: rec.product ?? null,
    // Assurance-tier disclosure (Phase 5). Honest, current reality: hosted service
    // key, service-provided time, no external anchor. Signature is re-verified in
    // THIS browser; chain linkage is reported by the server (not walked client-side).
    assurance: {
      time_basis: "HASHSTAMP_SERVICE_TIME",
      external_time_anchor: false,
      signer: "HOSTED_SERVICE_KEY",
      signature_check: "VERIFIED_IN_BROWSER",
      chain_linkage: rec.chain_integrity === true ? "VERIFIED (server-reported)"
        : rec.chain_integrity === false ? "BROKEN (server-reported)"
        : "NOT REPORTED",
    },
  };
}

/** Honest badges for a doc-timestamp — reuses the generic badge shape so the
 *  existing UI keeps working, but the identity IS the narrow doc-timestamp scope. */
function docBadges(/** @type {Partial<VerifyRecord>} */ rec) {
  return {
    identity: DOC_TIMESTAMP_INFO.label,
    identity_label: DOC_TIMESTAMP_INFO.label,
    proves: DOC_TIMESTAMP_INFO.proves,
    does_not_prove: DOC_TIMESTAMP_INFO.does_not_prove,
    anchor: DOC_TIMESTAMP_INFO.anchor,
    signer: rec.device_id ?? "HashStamp service key",
    presence: "none",
    content: "none",
  };
}

/** VER-04 honest headline for a doc-timestamp — existence + time, never authorship. */
function docHeadline(/** @type {Partial<VerifyRecord>} */ rec) {
  // Prefer the optional public_label (new records); fall back to filename for
  // historical records; else a neutral phrase. Never rewrites old records.
  const fn = rec.public_label ? `"${rec.public_label}"` : (rec.filename ? `"${rec.filename}"` : "this file");
  const when = rec.stamped_at ?? rec.signed_at;
  const pos = rec.chain_position;
  let s = `The SHA-256 fingerprint of ${fn} was signed by ZKNOT's HashStamp service key and recorded in a tamper-evident, hash-linked chain`;
  if (typeof pos === "number") s += ` at position ${pos}`;
  if (when) s += ` on ${when}`;
  s += ". Your browser re-verified that signature over the fingerprint just now.";
  if (rec.chain_integrity === true) s += " The chain is intact.";
  s += " This proves the file's contents existed at that time; it does not identify who submitted it.";
  return s;
}

/** VER-04 honest translation — the headline never exceeds the binding fields. */
function headlineOf(/** @type {Partial<VerifyRecord>} */ rec) {
  const dev = rec.device_id ?? "unknown device";
  const t = tierOf(rec);
  let s;
  if (t.key === "registry-asserted") {
    const signer = rec.device_id ?? "unknown signer";
    s = `A valid ECDSA signature over this exact payload was verified in your browser, signed by ZKNOT's registry key '${signer}' (REGISTRY-ASSERTED) — the registry vouches for this registration; it is not a device-held key.`;
  } else {
    s = `A valid ECDSA signature over this exact payload was verified in your browser, attributed to ${dev} (${t.label}).`;
  }
  if (rec.presence_binding_type === "secure-domain") s += " A human press was enforced inside the secure enclave.";
  else if (rec.presence_binding_type === "hardware-interlock") s += " A human press was enforced by an electrical interlock.";
  else if (rec.presence_binding_type === "firmware-mediated") s += " A human press was enforced by device firmware (firmware-trust, not silicon).";
  else s += " No human-presence enforcement is claimed by this record.";
  if (rec.content_binding_type === "secure-domain-display") s += " The signer was shown this exact content by the secure domain.";
  else if (rec.content_binding_type === "firmware-display") s += " A display was driven by ordinary firmware (rests on firmware trust).";
  else s += " The record does not claim the signer was shown the content.";
  return s;
}

function badgesOf(/** @type {Partial<VerifyRecord>} */ rec) {
  const t = tierOf(rec);
  return {
    // Back-compat: the current UI reads `identity` as a plain string.
    identity: t.label,
    // Self-explaining identity block: a skeptic reads exactly what the tier
    // means and what it does NOT mean, with no prior knowledge of the ladder.
    identity_label: t.label,
    proves: t.proves,
    does_not_prove: t.does_not_prove,
    anchor: t.anchor,
    signer: rec.device_id ?? "unknown",
    presence: rec.presence_binding_type ?? "none",
    content: rec.content_binding_type ?? "none",
  };
}

/**
 * If the server asserted a verdict and it disagrees with the local math,
 * say so explicitly. Local math wins; the disagreement is reported.
 * @param {Partial<VerifyRecord> & {server_asserted_verified?: boolean}} rec
 * @param {boolean|null} localOk
 */
function discrepancy(rec, localOk) {
  if (typeof rec.server_asserted_verified !== "boolean") return null;
  if (localOk === null) {
    return rec.server_asserted_verified
      ? "Server asserted verified=true, but the check could not even be run in this browser (incomplete or malformed record data). Treat the server assertion as unverified."
      : null;
  }
  if (rec.server_asserted_verified !== localOk) {
    return `Server asserted verified=${rec.server_asserted_verified} but the math in this browser says ${localOk}. The browser-computed verdict is authoritative; treat the server assertion as unverified.`;
  }
  return null;
}

/**
 * Convenience for the /v/{code} page: fetch record DATA, verify locally.
 * The fetch is a convenience transport (VER-02); the verdict is local.
 * @param {string} code @param {string=} apiBase
 */
export async function verifyShortCode(code, apiBase = "https://api.zknot.io") {
  const res = await fetch(`${apiBase}/v1/verify/${encodeURIComponent(code)}`);
  if (!res.ok) {
    return {
      verdict: /** @type {const} */ ("CANNOT_VERIFY"),
      checks: [{ id: "RESOLVE", pass: false, detail: `record fetch failed: HTTP ${res.status}` }],
      headline: "The record could not be fetched. No verdict — absence of data is not a failure of the attestation.",
      badges: { identity: "unknown", presence: "unknown", content: "unknown" },
      server_discrepancy: null,
    };
  }
  return verifyRecord(mapApiResponse(await res.json()));
}
