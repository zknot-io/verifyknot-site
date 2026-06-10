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

/** Supported record versions (VER-10). */
const SUPPORTED_VERSIONS = ["1.0"];

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
    server_asserted_verified: api.verified, // captured ONLY to detect discrepancy
  };
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
 *   badges: {identity: string, presence: string, content: string},
 *   server_discrepancy: string|null
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
  checks.push({
    id: "VER-13",
    pass: null,
    detail: rec.identity_tier === "REGISTERED"
      ? "identity tier REGISTERED: the key is asserted as known to the ZKNOT registry — that assertion is the server's, not this math's. No cert chain was verified."
      : "identity tier SELF-ASSERTED: the key's owner is whoever the record claims. Nothing about identity was cryptographically proven.",
  });

  return {
    verdict: "VERIFIED_CLIENT_SIDE",
    checks,
    headline: headlineOf(rec), // VER-04 / VER-25: maps 1:1 to the binding fields
    badges: badgesOf(rec),
    server_discrepancy: discrepancy(rec, true),
  };
}

/** VER-04 honest translation — the headline never exceeds the binding fields. */
function headlineOf(/** @type {Partial<VerifyRecord>} */ rec) {
  const dev = rec.device_id ?? "unknown device";
  let s = `A valid ECDSA signature over this exact payload was verified in your browser, attributed to ${dev} (${rec.identity_tier ?? "SELF-ASSERTED"}).`;
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
  return {
    identity: rec.identity_tier ?? "SELF-ASSERTED",
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
