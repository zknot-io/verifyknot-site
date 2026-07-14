// @ts-check
/**
 * verifyknot — portable HashStamp proof bundle (.hashstamp) — schema v1.
 *
 * WHAT THIS FILE IS FOR
 *   A HashStamp record lives at api.zknot.io. This module turns a record that
 *   ALREADY verified in this browser into a single self-contained JSON file the
 *   holder can archive, email, or hand to a skeptic — and turns that file back
 *   into a verdict computed locally, with no account and no upload of the
 *   original file.
 *
 * THE ONE HONEST FACT THIS FILE EXISTS TO ENFORCE
 *   Verifying a signature against a public key CARRIED IN THE SAME FILE proves
 *   nothing on its own. Anyone can generate a keypair, sign any fingerprint, and
 *   produce a bundle whose internal math is flawless. The signature check is
 *   only evidence when the key is ALSO recognised as ZKNOT's HashStamp service
 *   key, known independently of the bundle (see KNOWN_SIGNING_KEYS).
 *
 *   So this module reports TWO separate results and never merges them:
 *     1. signature_math   — did the signature verify against the carried key?
 *     2. key_identity     — is that carried key the pinned ZKNOT service key?
 *   A bundle that passes (1) and fails (2) is a valid signature by a STRANGER.
 *   It is rendered as such, not as "verified".
 *
 * WHY OFFLINE VERIFICATION IS GENUINELY POSSIBLE HERE (no canonicalization gap)
 *   A HashStamp doc-timestamp signs the RAW 32-byte file fingerprint. There is
 *   no canonical JSON, no field ordering, no reconstructed payload:
 *       signed message = the 32 bytes of file_sha256
 *       challenge_hash = SHA-256(those 32 bytes)   (what WebCrypto actually signs)
 *   The bundle carries the preimage verbatim, so the check is reproduced from
 *   the bundle's own bytes. Nothing is reinterpreted from display fields.
 *   (Confirmed against hashstamp-worker.js handleStamp(); see the SPEC doc.)
 *
 * NETWORK
 *   This module contains NO fetch/XHR/beacon and MUST NOT gain one. Import and
 *   verification are pure computation over bytes the user already holds. The
 *   single optional online call lives in checkCurrentStatusOnline(), is never
 *   invoked by the import path, and transmits only a public verification code.
 *
 * Zero dependencies. Web Crypto only (browsers + Node >= 20 for tests).
 */

// Relative, not "/verifier.js": this module sits at the site root, so "./" resolves
// identically in the browser AND under Node's ESM loader, which lets the test suite
// import exactly the file the browser runs — no shim, no duplicate implementation.
import { hexToBytes, bytesToHex, signatureToRaw } from "./verifier.js";

/* ─────────────────────────── constants & registry ────────────────────────── */

/** Schema id of the format this module writes. */
export const SCHEMA_V1 = "zknot.hashstamp.proof.v1";

/** Identifies the code that produced a bundle. Bump on any format change. */
export const GENERATOR_VERSION = "verifyknot-proof-bundle/1.0.0";

/**
 * Schema versions this verifier understands. UNKNOWN MAJOR VERSIONS FAIL CLOSED:
 * an id that is not a key here yields "unsupported schema", never a best-effort
 * parse. A future v2 adds a ROW here; it does not edit the v1 reader.
 * @type {Record<string, {major: number, reader: (b: any) => ParseResult}>}
 */
const SCHEMA_REGISTRY = {
  [SCHEMA_V1]: { major: 1, reader: readV1 },
};

/**
 * Maximum accepted .hashstamp file size. A real v1 bundle is ~1.5 KB; 64 KiB is
 * ~40x headroom for future additive fields while still refusing a file that
 * could only be an attempt to exhaust the parser or the tab's memory.
 */
export const MAX_BUNDLE_BYTES = 64 * 1024;

/**
 * PINNED SIGNING KEYS — the out-of-band trust anchor, and the only reason an
 * offline signature check means anything (see the header note).
 *
 * Source of truth: hashstamp-worker `wrangler.toml` `[vars]`
 * HASHSTAMP_PUBLIC_KEY_HEX / HASHSTAMP_DEVICE_ID. That var is the PUBLIC half of
 * the service keypair and is deliberately non-secret and committed — it is the
 * value the Worker stamps into every record it signs. Pinning it here is what
 * lets a stranger's browser distinguish ZKNOT's signature from a forgery.
 *
 * Format note: the Worker publishes 64-byte X||Y hex with NO 0x04 prefix. We
 * normalise both sides to bare X||Y before comparing, so a bundle carrying the
 * SEC1 uncompressed form (04||X||Y) still matches.
 *
 * TRUST LIMIT, STATED PLAINLY: this is a hosted service key held by ZKNOT. A
 * match proves the ZKNOT HashStamp service signed this fingerprint. It does not
 * make the bundle unforgeable by ZKNOT itself, and it is only as good as this
 * file — a reader who does not trust this page should compare the key against
 * the published value obtained independently.
 *
 * @type {Record<string, {key_id: string, algorithm: string, public_key_xy: string, label: string, source: string}>}
 */
export const KNOWN_SIGNING_KEYS = {
  "HASHSTAMP-SVC-01": {
    key_id: "HASHSTAMP-SVC-01",
    algorithm: "ECDSA-P256",
    public_key_xy:
      "cccb34a751ccb1c95f925dfe955555f542d7beb2712aa0af482898fadc3adbb358c662f73c1d9c864c6077b30709bbdbae5e56bf6995cd27af92ae8213211ac0",
    label: "ZKNOT HashStamp service key (production)",
    source: "hashstamp-worker wrangler.toml [vars] HASHSTAMP_PUBLIC_KEY_HEX",
  },
};

/** Signature/key wire formats this schema pins. Values are descriptive, not free text. */
export const SIG_ALGORITHM = "ECDSA-P256-SHA256";
export const SIG_ENCODING = "p1363-r||s-hex"; // raw 64-byte r||s, as WebCrypto emits
export const KEY_FORMAT = "sec1-uncompressed-hex"; // 04||X||Y
export const FINGERPRINT_ALGORITHM = "SHA-256";

const SHA256_HEX_RE = /^[0-9a-f]{64}$/i;
const MAX_LABEL_LEN = 80; // mirrors the Worker's sanitizeLabel cap
const MAX_CODE_LEN = 64;
const MAX_SHORT_TEXT = 128;

/* ───────────────────────────── small helpers ─────────────────────────────── */

/** @param {unknown} v */
const isPlainObject = (v) =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** @param {unknown} v @returns {v is string} */
const isStr = (v) => typeof v === "string";

/**
 * Normalise a public key to bare lowercase X||Y hex for comparison, accepting
 * either 64-byte X||Y or 65-byte SEC1 04||X||Y. Returns null if it is neither.
 * @param {unknown} hex
 */
export function normalizePubkeyXY(hex) {
  if (!isStr(hex)) return null;
  const h = hex.trim().toLowerCase().replace(/^0x/, "");
  if (/[^0-9a-f]/.test(h)) return null;
  if (h.length === 128) return h; // X||Y
  if (h.length === 130 && h.startsWith("04")) return h.slice(2); // 04||X||Y
  return null;
}

/**
 * Untrusted display text arriving from a bundle FILE (which, unlike a record
 * from the API, was never sanitized by the Worker). A hand-crafted bundle may
 * carry markup here. Angle brackets are REMOVED rather than escaped, so the
 * string cannot become a tag even if some future renderer reached for innerHTML;
 * control chars go too, and length is capped. Mirrors the Worker's sanitizeLabel
 * so a round-tripped label is unchanged.
 * @param {unknown} raw @param {number} max
 * @returns {string|null} null when nothing safe remains
 */
export function sanitizeText(raw, max = MAX_LABEL_LEN) {
  if (!isStr(raw)) return null;
  let s = raw.normalize("NFC");
  s = s.replace(/[\u0000-\u001F\u007F]/g, " "); // control chars + DEL
  s = s.replace(/[<>]/g, "");
  s = s.replace(/\s+/g, " ").trim();
  s = s.slice(0, max);
  return s === "" ? null : s;
}

/**
 * JSON.parse reviver that drops prototype-poisoning keys. A .hashstamp file is
 * attacker-supplied; `__proto__` in a JSON object literal is inert under
 * JSON.parse's own semantics for most engines, but constructor/prototype keys
 * are cheap to refuse outright and cost nothing.
 * @param {string} key @param {any} value
 */
function safeReviver(key, value) {
  if (key === "__proto__" || key === "constructor" || key === "prototype") return undefined;
  return value;
}

/** UTF-8 byte length of a string (what the file on disk actually weighs). */
function utf8Bytes(/** @type {string} */ s) {
  return new TextEncoder().encode(s).length;
}

const subtle = globalThis.crypto.subtle;

/** @param {Uint8Array} xy bare X||Y (64 bytes) */
async function importP256XY(xy) {
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(xy, 1);
  return subtle.importKey(
    "raw",
    /** @type {BufferSource} */ (raw.buffer.slice(0, 65)),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
}

/* ──────────────────────────────── export gate ────────────────────────────── */

/**
 * May this browser offer a proof bundle for this record?
 *
 * Fails closed on every doubt. A bundle that looks reassuring but cannot be
 * re-verified by its recipient is worse than no bundle, so every requirement
 * below is a hard gate, not a warning:
 *   · the record verified CRYPTOGRAPHICALLY IN THIS BROWSER (not a server flag);
 *   · it is a supported HashStamp document-timestamp;
 *   · a well-formed SHA-256 file fingerprint is present;
 *   · the signed payload can be preserved exactly (it IS the fingerprint bytes);
 *   · the public verification key is present.
 *
 * @param {any} rec     mapApiResponse() output
 * @param {any} result  verifyRecord() output for that record
 * @param {{enabled?: boolean}} [opts] flag injection point (tests exercise both)
 * @returns {{enabled: true} | {enabled: false, reason: string, flagged_off?: true}}
 */
export function proofBundleExportGate(rec, result, opts = {}) {
  const enabled = opts.enabled ?? false;
  // Flag off: not an error, just not offered. Distinguished from a data problem
  // so the UI can render nothing at all rather than a scary explanation.
  if (!enabled) return { enabled: false, reason: "Portable proof bundles are not enabled on this site.", flagged_off: true };

  const NO =
    "A portable bundle is not available for this record because the complete verification material is not present.";

  if (!isPlainObject(rec) || !isPlainObject(result)) return { enabled: false, reason: NO };
  if (result.verdict !== "VERIFIED_CLIENT_SIDE") return { enabled: false, reason: NO };
  if (result.kind !== "document_timestamp") return { enabled: false, reason: NO };

  const fp = isStr(rec.file_sha256) ? rec.file_sha256.trim().toLowerCase() : null;
  if (!fp || !SHA256_HEX_RE.test(fp)) return { enabled: false, reason: NO };

  // The signed payload for this record kind is the fingerprint bytes. Preserving
  // it exactly is therefore possible iff the fingerprint is well-formed (above)
  // and the challenge_hash that binds it is present.
  if (!isStr(rec.challenge_hash) || !SHA256_HEX_RE.test(rec.challenge_hash.trim())) {
    return { enabled: false, reason: NO };
  }
  if (!isStr(rec.signature) || rec.signature.trim() === "") return { enabled: false, reason: NO };
  if (!normalizePubkeyXY(rec.public_key)) return { enabled: false, reason: NO };

  return { enabled: true };
}

/* ──────────────────────────────── the builder ────────────────────────────── */

/**
 * Deterministic bundle id: SHA-256 over the identifying evidence, hex-truncated.
 * Deterministic (not random) so exporting the same record twice yields the same
 * id — two archived copies are recognisably the same bundle. Carries no entropy
 * about the exporter, by design: no timestamp, no filename, no client id.
 * @param {string} code @param {string} fingerprint @param {string} signature
 */
async function deriveBundleId(code, fingerprint, signature) {
  const material = `${SCHEMA_V1}|${code}|${fingerprint}|${signature}`;
  const d = await subtle.digest("SHA-256", new TextEncoder().encode(material));
  return `hsb1_${bytesToHex(d).slice(0, 32)}`;
}

/**
 * Build a v1 proof bundle from a verified record.
 *
 * PRIVACY MODEL — ALLOWLIST, NOT DENYLIST. Every field below is written by name
 * from the MAPPED record (mapApiResponse output), which is itself an allowlist
 * of the API response. The raw `metadata` blob is NEVER copied wholesale. This
 * matters concretely: /v1/verify echoes `metadata` unfiltered, and for some
 * non-HashStamp artifact types that blob can contain a customer email
 * (zknot-api units registration). A denylist would have to anticipate that; an
 * allowlist cannot emit it at all. The deny-list test is a backstop for this
 * property, not the mechanism enforcing it.
 *
 * @param {any} rec     mapApiResponse() output — MUST have passed proofBundleExportGate
 * @param {any} result  verifyRecord() output
 * @param {{exported_at?: string}} [opts] exported_at injectable for deterministic tests
 * @returns {Promise<any>} the bundle object
 */
export async function buildProofBundle(rec, result, opts = {}) {
  const gate = proofBundleExportGate(rec, result, { enabled: true });
  if (!gate.enabled) {
    throw new Error("refusing to build a proof bundle for a record that does not meet the export gate");
  }

  const fingerprint = String(rec.file_sha256).trim().toLowerCase();
  const challenge = String(rec.challenge_hash).trim().toLowerCase();
  const signature = String(rec.signature).trim().toLowerCase();
  const pubXY = /** @type {string} */ (normalizePubkeyXY(rec.public_key));
  const code = isStr(rec.short_code) ? rec.short_code : null;
  const keyId = isStr(rec.device_id) ? rec.device_id : null;

  // Is the signing key one we recognise? Recorded as EVIDENCE ABOUT THE EXPORT,
  // not as a claim: the importer re-derives this itself and never trusts this
  // field. It is written so a human reading the raw JSON can see what the
  // exporting browser concluded.
  const known = keyId ? KNOWN_SIGNING_KEYS[keyId] : undefined;
  const keyRecognized = !!known && known.public_key_xy === pubXY;

  const bundle_id = await deriveBundleId(code ?? "", fingerprint, signature);

  return {
    schema: SCHEMA_V1,
    generator: GENERATOR_VERSION,
    /** Minimum reader that can parse this bundle. Additive fields must not bump it. */
    min_verifier: "zknot.hashstamp.proof.v1",
    bundle_id,
    exported_at: opts.exported_at ?? new Date().toISOString(),

    record: {
      verification_code: code,
      artifact_type: rec.artifact_type ?? null,
      kind: "document_timestamp",
      product: rec.product ?? null,
      record_version: rec.record_version ?? null,
      // Already-public, user-chosen label. Absent unless the record carried one.
      public_label: sanitizeText(rec.public_label),
      // Service-reported times. NOT independent timestamps — see assurance.
      signed_at: sanitizeText(rec.signed_at, MAX_SHORT_TEXT),
      stamped_at: sanitizeText(rec.stamped_at ?? rec.signed_at, MAX_SHORT_TEXT),
    },

    // The evidence subject: the fingerprint of the file this record commits to.
    file_fingerprint: {
      algorithm: FINGERPRINT_ALGORITHM,
      value: fingerprint,
    },

    signature: {
      algorithm: SIG_ALGORITHM,
      encoding: SIG_ENCODING,
      value: signature,
      key_id: keyId,
      /**
       * The exact bytes the service signed — carried verbatim, never rebuilt
       * from display fields. For v1 this equals the file fingerprint bytes by
       * construction, and the importer ASSERTS that equality (check BUN-20)
       * rather than assuming it.
       */
      signed_payload: {
        encoding: "hex",
        value: fingerprint,
        description:
          "The raw 32 bytes of the SHA-256 file fingerprint. WebCrypto ECDSA hashes this input once, so the signed digest is SHA-256(these bytes) = challenge_hash.",
      },
      /** SHA-256(signed_payload) — the digest actually covered by the signature. */
      challenge_hash: challenge,
    },

    signing_key: {
      key_id: keyId,
      algorithm: "ECDSA-P256",
      format: KEY_FORMAT,
      public_key: `04${pubXY}`,
      // No validity window is published for this key today. NULL means UNKNOWN,
      // never "valid forever".
      valid_from: null,
      valid_until: null,
      recognized_at_export: keyRecognized,
    },

    /**
     * CHAIN — SERVICE-REPORTED METADATA ONLY. These values are copied so a
     * reader can quote them and so an online check can compare them, but this
     * bundle contains NO chain proof: no neighbouring entries, no signed
     * checkpoint, no inclusion path. Position + hashes alone cannot establish
     * linkage (see the THREAT MODEL doc, "why we do not verify the chain here").
     */
    chain: {
      position: typeof rec.chain_position === "number" ? rec.chain_position : null,
      previous_hash: isStr(rec.chain_prev_hash) ? rec.chain_prev_hash : null,
      entry_hash: isStr(rec.artifact_hash) ? rec.artifact_hash : null,
      artifact_id: isStr(rec.artifact_id) ? rec.artifact_id : null,
      service_reported_integrity:
        typeof rec.chain_integrity === "boolean" ? rec.chain_integrity : null,
      // Reserved. See FUTURE-EXTENSIONS; absent means absent, not pending.
      checkpoint: null,
      inclusion_proof: null,
    },

    /**
     * ASSURANCE — the machine-readable version of "what is actually proven".
     * Each value is a closed enum; a reader must never have to infer strength
     * from prose. These describe the BUNDLE's contents, and the importer
     * recomputes its own verdict rather than trusting them.
     */
    assurance: {
      record_signature: "VERIFIABLE_OFFLINE",
      signing_key_identity: "PINNED_KEY_COMPARISON_REQUIRED",
      file_fingerprint: "INCLUDED",
      chain_linkage: "METADATA_ONLY",
      external_time_anchor: "NOT_PRESENT",
      time_basis: "HASHSTAMP_SERVICE_TIME",
      key_revocation_status: "NOT_CHECKED_OFFLINE",
      superseding_record_check: "NOT_CHECKED_OFFLINE",
    },

    limitations: [
      "The signature in this bundle can be verified offline, but a signature only means something if the signing key is ZKNOT's. Compare signing_key.public_key against ZKNOT's published HashStamp key obtained independently of this file.",
      "This bundle proves that the file with the fingerprint above existed when the HashStamp service signed it. It does not prove who created, sent, received, downloaded, owned, or approved that file.",
      "The times in this bundle are provided by the HashStamp service. They are not anchored to an independent time authority, and no RFC 3161 or equivalent timestamp token is included.",
      "The chain fields are metadata reported by the service. This bundle contains no inclusion proof and no signed checkpoint, so chain membership and chain continuity cannot be checked from this file alone.",
      "Key revocation status cannot be determined offline. A key valid at stamping time may have been revoked since; this file cannot tell you.",
      "This file cannot tell you whether a later record supersedes this one.",
      "The original file is not included in this bundle, by design. A fingerprint match proves two files have identical bytes; it says nothing about the truth of their contents.",
    ],
  };
}

/**
 * Serialize a bundle for download. Pretty-printed on purpose: this artifact is
 * meant to be archived, diffed, and read by humans and greps, not minified.
 * @param {any} bundle
 */
export function serializeProofBundle(bundle) {
  return JSON.stringify(bundle, null, 2) + "\n";
}

/**
 * Suggested filename: HS-YYYYMMDD-CODE.hashstamp.
 * Derived only from already-public record data (stamp date + verification code).
 * Never from the original filename — that is private and not in the record.
 * @param {any} bundle
 */
export function proofBundleFilename(bundle) {
  const when = bundle?.record?.stamped_at ?? bundle?.record?.signed_at ?? bundle?.exported_at;
  let day = "00000000";
  if (isStr(when)) {
    const m = when.match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (m) day = `${m[1]}${m[2]}${m[3]}`;
  }
  const rawCode = bundle?.record?.verification_code;
  const code = isStr(rawCode) ? rawCode.replace(/[^A-Za-z0-9-]/g, "").slice(0, MAX_CODE_LEN) : "";
  return `HS-${day}${code ? `-${code}` : ""}.hashstamp`;
}

/* ──────────────────────────────── the reader ─────────────────────────────── */

/**
 * @typedef {{ok: true, bundle: any} | {ok: false, error: string}} ParseResult
 */

/**
 * Parse + structurally validate a .hashstamp file's TEXT. Never throws; every
 * failure is a specific, honest reason. Order matters: size before parse (do not
 * hand a 2 GB string to JSON.parse), schema before field reads (an unknown major
 * must fail closed before we interpret anything).
 *
 * @param {string} text
 * @param {{maxBytes?: number}} [opts]
 * @returns {ParseResult}
 */
export function parseProofBundle(text, opts = {}) {
  const maxBytes = opts.maxBytes ?? MAX_BUNDLE_BYTES;

  if (!isStr(text)) return { ok: false, error: "No proof bundle file content was provided." };

  const size = utf8Bytes(text);
  if (size === 0) return { ok: false, error: "This file is empty." };
  if (size > maxBytes) {
    return {
      ok: false,
      error: `This file is ${size.toLocaleString()} bytes, larger than the ${maxBytes.toLocaleString()}-byte limit for a proof bundle. A genuine bundle is a few kilobytes; this file was not read.`,
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(text, safeReviver);
  } catch (e) {
    return {
      ok: false,
      error: `This file is not valid JSON, so it is not a proof bundle (${/** @type {Error} */ (e).message}).`,
    };
  }

  if (!isPlainObject(parsed)) {
    return { ok: false, error: "This file does not contain a proof-bundle object." };
  }

  // Fail closed on unknown schemas BEFORE touching any other field.
  const schema = parsed.schema;
  if (!isStr(schema)) {
    return { ok: false, error: "This file does not declare a proof-bundle schema, so it cannot be verified." };
  }
  const entry = SCHEMA_REGISTRY[schema];
  if (!entry) {
    return {
      ok: false,
      error: `This bundle declares schema "${sanitizeText(schema, MAX_SHORT_TEXT) ?? "(unreadable)"}", which this verifier does not support. It supports: ${Object.keys(SCHEMA_REGISTRY).join(", ")}. No verdict — a newer bundle is not something this page may guess at.`,
    };
  }

  return entry.reader(parsed);
}

/**
 * v1 structural reader. Validates required field presence, types, and lengths,
 * and normalises the crypto material to canonical lowercase hex. Unknown
 * OPTIONAL fields are ignored (v1 permits additive growth); unknown or malformed
 * REQUIRED fields fail.
 * @param {any} b
 * @returns {ParseResult}
 */
function readV1(b) {
  const bad = (/** @type {string} */ m) => ({ ok: /** @type {const} */ (false), error: m });

  if (!isPlainObject(b.file_fingerprint)) return bad("This bundle has no file fingerprint block.");
  if (!isPlainObject(b.signature)) return bad("This bundle has no signature block.");
  if (!isPlainObject(b.signing_key)) return bad("This bundle has no signing-key block.");
  const record = isPlainObject(b.record) ? b.record : {};
  const chain = isPlainObject(b.chain) ? b.chain : {};

  // --- fingerprint
  if (b.file_fingerprint.algorithm !== FINGERPRINT_ALGORITHM) {
    return bad(`This bundle's fingerprint algorithm is not ${FINGERPRINT_ALGORITHM}; this verifier cannot check it.`);
  }
  const fingerprint = isStr(b.file_fingerprint.value) ? b.file_fingerprint.value.trim().toLowerCase() : "";
  if (!SHA256_HEX_RE.test(fingerprint)) return bad("This bundle's file fingerprint is not a valid SHA-256 value.");

  // --- signature
  if (b.signature.algorithm !== SIG_ALGORITHM) {
    return bad(`This bundle's signature algorithm "${sanitizeText(b.signature.algorithm, MAX_SHORT_TEXT) ?? "(missing)"}" is not supported by this verifier.`);
  }
  const sigHex = isStr(b.signature.value) ? b.signature.value.trim().toLowerCase() : "";
  if (!/^[0-9a-f]+$/.test(sigHex) || sigHex.length < 128 || sigHex.length > 160) {
    return bad("This bundle's signature is not a well-formed ECDSA P-256 signature.");
  }
  const challenge = isStr(b.signature.challenge_hash) ? b.signature.challenge_hash.trim().toLowerCase() : "";
  if (!SHA256_HEX_RE.test(challenge)) return bad("This bundle's challenge hash is not a valid SHA-256 value.");

  const sp = b.signature.signed_payload;
  if (!isPlainObject(sp)) return bad("This bundle does not carry the signed payload, so the signature cannot be reproduced.");
  if (sp.encoding !== "hex") return bad("This bundle's signed payload uses an encoding this verifier does not support.");
  const payloadHex = isStr(sp.value) ? sp.value.trim().toLowerCase() : "";
  if (!SHA256_HEX_RE.test(payloadHex)) return bad("This bundle's signed payload is not a valid 32-byte value.");

  // --- key
  const pubXY = normalizePubkeyXY(b.signing_key.public_key);
  if (!pubXY) return bad("This bundle's public key is not a valid P-256 key, so the signature cannot be checked.");

  return {
    ok: true,
    bundle: {
      schema: b.schema,
      generator: sanitizeText(b.generator, MAX_SHORT_TEXT),
      bundle_id: sanitizeText(b.bundle_id, MAX_SHORT_TEXT),
      exported_at: sanitizeText(b.exported_at, MAX_SHORT_TEXT),
      record: {
        verification_code: sanitizeText(record.verification_code, MAX_CODE_LEN),
        artifact_type: sanitizeText(record.artifact_type, MAX_SHORT_TEXT),
        kind: sanitizeText(record.kind, MAX_SHORT_TEXT),
        product: sanitizeText(record.product, MAX_SHORT_TEXT),
        record_version: sanitizeText(record.record_version, MAX_SHORT_TEXT),
        public_label: sanitizeText(record.public_label),
        signed_at: sanitizeText(record.signed_at, MAX_SHORT_TEXT),
        stamped_at: sanitizeText(record.stamped_at, MAX_SHORT_TEXT),
      },
      file_fingerprint: { algorithm: FINGERPRINT_ALGORITHM, value: fingerprint },
      signature: {
        algorithm: b.signature.algorithm,
        encoding: sanitizeText(b.signature.encoding, MAX_SHORT_TEXT),
        value: sigHex,
        key_id: sanitizeText(b.signature.key_id, MAX_SHORT_TEXT),
        signed_payload: { encoding: "hex", value: payloadHex },
        challenge_hash: challenge,
      },
      signing_key: {
        key_id: sanitizeText(b.signing_key.key_id, MAX_SHORT_TEXT),
        algorithm: sanitizeText(b.signing_key.algorithm, MAX_SHORT_TEXT),
        format: KEY_FORMAT,
        public_key: `04${pubXY}`,
        public_key_xy: pubXY,
        valid_from: sanitizeText(b.signing_key.valid_from, MAX_SHORT_TEXT),
        valid_until: sanitizeText(b.signing_key.valid_until, MAX_SHORT_TEXT),
      },
      chain: {
        position: typeof chain.position === "number" && Number.isFinite(chain.position) ? chain.position : null,
        previous_hash: sanitizeText(chain.previous_hash, MAX_SHORT_TEXT),
        entry_hash: sanitizeText(chain.entry_hash, MAX_SHORT_TEXT),
        artifact_id: sanitizeText(chain.artifact_id, MAX_SHORT_TEXT),
        service_reported_integrity:
          typeof chain.service_reported_integrity === "boolean" ? chain.service_reported_integrity : null,
        checkpoint: chain.checkpoint ?? null,
        inclusion_proof: chain.inclusion_proof ?? null,
      },
      limitations: Array.isArray(b.limitations)
        ? b.limitations.map((l) => sanitizeText(l, 400)).filter(Boolean)
        : [],
    },
  };
}

/* ────────────────────────────── offline verify ───────────────────────────── */

/**
 * Verify a parsed bundle. PURE COMPUTATION — no network, by construction.
 *
 * Reports signature math and key identity SEPARATELY (see the header note). The
 * verdict is deliberately conservative:
 *   VERIFIED_OFFLINE          — math passed AND the key is the pinned ZKNOT key
 *   VERIFIED_UNRECOGNIZED_KEY — math passed, key is a stranger's. NOT evidence
 *                               that ZKNOT stamped anything.
 *   FAILED                    — the math did not pass
 *   CANNOT_VERIFY             — the check could not be run at all
 *
 * @param {any} bundle a parseProofBundle() .bundle
 * @returns {Promise<{
 *   verdict: "VERIFIED_OFFLINE"|"VERIFIED_UNRECOGNIZED_KEY"|"FAILED"|"CANNOT_VERIFY",
 *   checks: {id: string, pass: boolean|null, detail: string}[],
 *   headline: string,
 *   badges: {id: string, state: "PASS"|"INFO"|"WARN"|"FAIL", label: string, detail: string}[],
 *   key_identity: {recognized: boolean, key_id: string|null, label: string|null},
 *   fingerprint: {algorithm: "SHA-256", expectedHex: string}|null,
 *   assurance: Record<string,string>
 * }>}
 */
export async function verifyProofBundle(bundle) {
  /** @type {{id: string, pass: boolean|null, detail: string}[]} */
  const checks = [];
  const keyId = bundle?.signing_key?.key_id ?? null;
  const known = keyId ? KNOWN_SIGNING_KEYS[keyId] : undefined;
  const recognized = !!known && known.public_key_xy === bundle?.signing_key?.public_key_xy;
  const key_identity = { recognized, key_id: keyId, label: known?.label ?? null };

  const out = (/** @type {any} */ verdict, /** @type {string} */ headline) => ({
    verdict,
    checks,
    headline,
    badges: badgesFor(verdict, recognized, bundle),
    key_identity,
    fingerprint:
      verdict === "VERIFIED_OFFLINE" || verdict === "VERIFIED_UNRECOGNIZED_KEY"
        ? { algorithm: /** @type {const} */ ("SHA-256"), expectedHex: bundle.file_fingerprint.value }
        : null,
    assurance: assuranceFor(verdict, recognized),
  });

  // BUN-20 — the carried signed payload IS the carried fingerprint. Asserted,
  // not assumed: this is what makes "the signature covers THIS file's
  // fingerprint" true rather than merely plausible.
  const payloadHex = bundle.signature.signed_payload.value;
  const fpHex = bundle.file_fingerprint.value;
  const boundOk = payloadHex === fpHex;
  checks.push({
    id: "BUN-20",
    pass: boundOk,
    detail: boundOk
      ? "the signed payload in this bundle is exactly the file fingerprint it claims to cover"
      : "the signed payload does NOT match the file fingerprint — this bundle's signature covers a different value than the fingerprint it displays",
  });
  if (!boundOk) return out("FAILED", "This bundle is internally inconsistent: its signature does not cover the fingerprint it shows.");

  let payload, expectedDigest, sigRaw, pubXY;
  try {
    payload = hexToBytes(payloadHex);
    expectedDigest = hexToBytes(bundle.signature.challenge_hash);
    sigRaw = signatureToRaw(hexToBytes(bundle.signature.value));
    pubXY = hexToBytes(bundle.signing_key.public_key_xy);
  } catch (e) {
    checks.push({ id: "BUN-21", pass: false, detail: `encoding error: ${/** @type {Error} */ (e).message}` });
    return out("CANNOT_VERIFY", "This bundle's fields are malformed; the check could not be run. No verdict.");
  }

  // BUN-21 — challenge_hash is genuinely SHA-256(signed_payload).
  const digest = new Uint8Array(await subtle.digest("SHA-256", /** @type {BufferSource} */ (payload)));
  const digestOk = bytesToHex(digest) === bytesToHex(expectedDigest);
  checks.push({
    id: "BUN-21",
    pass: digestOk,
    detail: digestOk
      ? "SHA-256(signed payload) recomputed in this browser matches the bundle's challenge hash"
      : "the challenge hash is NOT SHA-256 of the signed payload — this bundle is internally inconsistent",
  });
  if (!digestOk) return out("FAILED", "This bundle is internally inconsistent: its challenge hash does not match its own signed payload.");

  // BUN-22 — the signature verifies over the payload against the CARRIED key.
  // On its own this proves only "somebody with the matching private key signed
  // this". BUN-23 is what turns it into evidence.
  let sigOk = false;
  try {
    const key = await importP256XY(pubXY);
    sigOk = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      /** @type {BufferSource} */ (sigRaw),
      /** @type {BufferSource} */ (payload)
    );
  } catch (e) {
    checks.push({ id: "BUN-22", pass: false, detail: `key import / verify error: ${/** @type {Error} */ (e).message}` });
    return out("CANNOT_VERIFY", "The public key in this bundle could not be imported; the signature check could not run. No verdict.");
  }
  checks.push({
    id: "BUN-22",
    pass: sigOk,
    detail: sigOk
      ? "ECDSA P-256 signature verified in this browser over the signed payload, against the public key carried in this bundle"
      : "the signature does NOT verify against the public key carried in this bundle",
  });
  if (!sigOk) return out("FAILED", "Cryptographically invalid: the signature in this bundle does not verify.");

  // BUN-23 — key identity. THE decisive check.
  checks.push({
    id: "BUN-23",
    pass: recognized,
    detail: recognized
      ? `the signing key matches ZKNOT's pinned HashStamp service key (${keyId}) that this verifier was built with — the signature is ZKNOT's`
      : `the signing key is NOT a ZKNOT HashStamp key known to this verifier (key_id "${keyId ?? "none"}"). The signature is mathematically valid, but it was made by a key this page cannot vouch for. Anyone can sign a fingerprint with their own key.`,
  });

  if (!recognized) {
    return out(
      "VERIFIED_UNRECOGNIZED_KEY",
      "This bundle carries a mathematically valid signature, but it was NOT made by a ZKNOT HashStamp key this verifier recognises. Treat it as unverified: anyone can generate a key and sign any fingerprint with it."
    );
  }

  checks.push({
    id: "BUN-24",
    pass: null,
    detail:
      "scope: proves the file with this fingerprint existed when ZKNOT's HashStamp service signed it. Does NOT prove who created, sent, received or owned it; carries no independent time anchor; carries no chain proof.",
  });

  return out("VERIFIED_OFFLINE", headlineFor(bundle));
}

/** @param {any} bundle */
function headlineFor(bundle) {
  const label = bundle?.record?.public_label ? `"${bundle.record.public_label}"` : "this file";
  const when = bundle?.record?.stamped_at ?? bundle?.record?.signed_at;
  let s = `Your browser verified, offline, that ZKNOT's HashStamp service key signed the SHA-256 fingerprint of ${label}`;
  if (when) s += ` on ${when} (a time reported by the service, not an independent authority)`;
  s += ". This proves the file's contents existed at that time; it does not identify who submitted it.";
  return s;
}

/**
 * Badges — one per PROPERTY, never one green tick for everything. Each badge
 * states a single fact a reader can act on. Properties we did NOT check appear
 * here as explicit "not checked", because an absent badge reads as a pass.
 * @param {string} verdict @param {boolean} recognized @param {any} bundle
 */
function badgesFor(verdict, recognized, bundle) {
  const verified = verdict === "VERIFIED_OFFLINE" || verdict === "VERIFIED_UNRECOGNIZED_KEY";
  /** @type {{id: string, state: "PASS"|"INFO"|"WARN"|"FAIL", label: string, detail: string}[]} */
  const out = [];

  out.push(
    verified
      ? { id: "SIGNATURE", state: "PASS", label: "SIGNATURE VERIFIED OFFLINE", detail: "The signature verified in this browser against the public key carried in this bundle. No network was used." }
      : { id: "SIGNATURE", state: "FAIL", label: "SIGNATURE NOT VERIFIED", detail: "The signature in this bundle did not verify." }
  );

  out.push(
    recognized
      ? { id: "KEY_IDENTITY", state: "PASS", label: "SIGNING KEY RECOGNIZED", detail: `The signing key matches ZKNOT's pinned HashStamp service key (${bundle?.signing_key?.key_id}). Without this, the signature above would prove nothing about ZKNOT.` }
      : { id: "KEY_IDENTITY", state: "FAIL", label: "SIGNING KEY NOT RECOGNIZED", detail: "The signing key is not a ZKNOT HashStamp key this verifier knows. A valid signature by an unknown key is not evidence that ZKNOT stamped this file." }
  );

  if (bundle?.file_fingerprint?.value) {
    out.push({ id: "FINGERPRINT", state: "INFO", label: "FILE FINGERPRINT INCLUDED", detail: "The bundle contains the expected SHA-256 fingerprint. The original file is not included — use Verify your copy to compare a file you hold." });
  }

  out.push({ id: "CHAIN", state: "WARN", label: "CHAIN PROOF NOT INCLUDED", detail: "Chain position and hashes are metadata reported by the service. This bundle carries no inclusion proof and no signed checkpoint, so chain membership was not checked here." });
  out.push({ id: "TIME_ANCHOR", state: "WARN", label: "EXTERNAL TIME ANCHOR NOT PRESENT", detail: "The times shown come from the HashStamp service. No RFC 3161 or equivalent independent timestamp token is included, so the time was not independently verified." });
  out.push({ id: "KEY_STATUS", state: "WARN", label: "CURRENT KEY STATUS NOT CHECKED", detail: "Whether the signing key has since been revoked cannot be determined offline. Use Check current status online if you need this." });

  return out;
}

/** @param {string} verdict @param {boolean} recognized */
function assuranceFor(verdict, recognized) {
  const sigOk = verdict === "VERIFIED_OFFLINE" || verdict === "VERIFIED_UNRECOGNIZED_KEY";
  return {
    record_signature: sigOk ? "VERIFIED_OFFLINE" : "NOT_VERIFIED",
    signing_key_identity: recognized ? "PINNED_KEY_MATCH" : "UNRECOGNIZED_KEY",
    file_fingerprint: "INCLUDED",
    file_copy_match: "NOT_ATTEMPTED",
    chain_linkage: "METADATA_ONLY",
    external_time_anchor: "NOT_PRESENT",
    time_basis: "HASHSTAMP_SERVICE_TIME",
    key_revocation_status: "NOT_CHECKED_OFFLINE",
    superseding_record_check: "NOT_CHECKED_OFFLINE",
  };
}

/**
 * The fingerprint an imported bundle commits to, for "Verify your copy".
 * Gated on a verdict we actually stand behind: comparing a local file against a
 * bundle signed by an unrecognised key would render a green "match" that means
 * nothing, which is precisely the reassuring lie this feature must not tell.
 * @param {any} result verifyProofBundle() output
 * @returns {{enabled: true, fingerprint: {algorithm: "SHA-256", expectedHex: string}}|{enabled: false, reason: string}}
 */
export function bundleFileComparisonGate(result) {
  if (!result || result.verdict !== "VERIFIED_OFFLINE" || !result.fingerprint) {
    return {
      enabled: false,
      reason:
        "File comparison is unavailable because this bundle's signature and signing key were not both verified.",
    };
  }
  return { enabled: true, fingerprint: result.fingerprint };
}

/* ─────────────────────── the one optional online call ────────────────────── */

/**
 * OPTIONAL, EXPLICIT online status check. Never called by the import path — only
 * by a button the user presses.
 *
 * EXACTLY WHAT IS TRANSMITTED: one HTTPS GET to
 *   {apiBase}/v1/verify/{verification_code}
 * carrying only the verification code — a value that is already public (it is
 * the code printed on the receipt and resolvable by anyone). Plus whatever the
 * browser attaches to any request (TLS SNI, IP, User-Agent); this function adds
 * no headers, no cookies, no body, no query string.
 *
 * EXPLICITLY NOT TRANSMITTED: the bundle or any part of it, the offline
 * verification result, the selected local file, its filename, or any locally
 * computed hash. Nothing is uploaded; this is a read of a public record.
 *
 * @param {string} code @param {string} [apiBase]
 * @returns {Promise<{ok: true, status: any} | {ok: false, error: string}>}
 */
export async function checkCurrentStatusOnline(code, apiBase = "https://api.zknot.io") {
  if (!isStr(code) || !code.trim()) {
    return { ok: false, error: "This bundle carries no verification code, so its current status cannot be looked up." };
  }
  let res;
  try {
    res = await fetch(`${apiBase}/v1/verify/${encodeURIComponent(code.trim())}`);
  } catch (e) {
    return { ok: false, error: `The status check could not reach the server (${/** @type {Error} */ (e).message}). Your offline result above is unaffected.` };
  }
  if (res.status === 404) {
    return { ok: false, error: "This verification code is not found on the server right now. That is a finding: the record may have been withdrawn, or this bundle's code may be wrong." };
  }
  if (!res.ok) {
    return { ok: false, error: `The server returned HTTP ${res.status}. Your offline result above is unaffected.` };
  }
  let live;
  try {
    live = await res.json();
  } catch {
    return { ok: false, error: "The server's response could not be read. Your offline result above is unaffected." };
  }
  return { ok: true, status: live };
}

/**
 * Compare a live /v1/verify response against the bundle. Pure; takes the fetched
 * body so the comparison itself is testable with no network.
 * @param {any} bundle @param {any} live
 */
export function compareWithLiveRecord(bundle, live) {
  /** @type {{id: string, pass: boolean|null, detail: string}[]} */
  const findings = [];
  const liveFp = live?.metadata?.file_sha256 ?? live?.file_sha256;
  const fpOk = isStr(liveFp) && liveFp.toLowerCase() === bundle?.file_fingerprint?.value;
  findings.push({
    id: "ONLINE-FINGERPRINT",
    pass: fpOk,
    detail: fpOk
      ? "the record on the server still carries the same file fingerprint as this bundle"
      : "the record on the server carries a DIFFERENT file fingerprint than this bundle — treat this bundle as suspect",
  });

  const liveKey = normalizePubkeyXY(live?.public_key);
  const keyOk = !!liveKey && liveKey === bundle?.signing_key?.public_key_xy;
  findings.push({
    id: "ONLINE-KEY",
    pass: keyOk,
    detail: keyOk
      ? "the server still publishes the same signing key as this bundle carries"
      : "the server publishes a different signing key than this bundle carries — the key may have been rotated, or this bundle may be forged",
  });

  const livePos = live?.chain_position;
  const posOk = bundle?.chain?.position == null || livePos === bundle.chain.position;
  findings.push({
    id: "ONLINE-CHAIN-POSITION",
    pass: posOk,
    detail: posOk
      ? "the record's chain position is unchanged from this bundle"
      : `the record's chain position is now ${livePos}, but this bundle says ${bundle?.chain?.position}`,
  });

  findings.push({
    id: "ONLINE-CHAIN-INTEGRITY",
    pass: typeof live?.chain_integrity === "boolean" ? live.chain_integrity : null,
    detail:
      typeof live?.chain_integrity === "boolean"
        ? `the service reports chain_integrity=${live.chain_integrity}. This remains the SERVICE's report — your browser did not walk the chain.`
        : "the service did not report chain integrity.",
  });

  // Deliberately NOT a claim of revocation status: /v1/verify publishes no key
  // status or revocation record, so a 200 here says the record resolves, not
  // that the key is still trusted. Saying otherwise would invent assurance.
  findings.push({
    id: "ONLINE-KEY-STATUS",
    pass: null,
    detail:
      "no key revocation status is published by this endpoint, so key status remains NOT CHECKED even after this online lookup.",
  });

  return findings;
}
