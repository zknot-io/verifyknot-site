// @ts-check
/**
 * Fixtures for the portable-proof-bundle suite.
 *
 * WHY THESE ARE GENERATED, NOT CAPTURED
 *   A captured production record would let us assert against real bytes, but it
 *   would also pin a real signature we cannot re-sign — so no test could then
 *   exercise "one-byte mutation still verifies against a freshly signed record".
 *   Instead we reproduce the Worker's EXACT signing math (see makeStampedRecord)
 *   with a throwaway keypair, and separately assert that our reproduction matches
 *   the shape the Worker actually emits (see record-shape.test.mjs, which reads
 *   hashstamp-worker.js and zknot-api's response model rather than trusting us).
 *
 * The signing math mirrored here is hashstamp-worker.js handleStamp():
 *   fileHashBytes  = bytes(SHA-256(file))
 *   challenge_hash = SHA-256(fileHashBytes)
 *   signature      = ECDSA-P256 over fileHashBytes  (WebCrypto hashes it once)
 * so the signature is verifiable by feeding WebCrypto the PREIMAGE. That is the
 * property the whole offline story rests on; if the Worker ever changes it,
 * these fixtures and the real records diverge and the shape test fires.
 */

import { KNOWN_SIGNING_KEYS } from "../proof-bundle.js";

const subtle = globalThis.crypto.subtle;

/** @param {string} hex */
export function hexToBytes(hex) {
  return Uint8Array.from(/** @type {RegExpMatchArray} */ (hex.match(/../g)).map((b) => parseInt(b, 16)));
}
/** @param {Uint8Array|ArrayBuffer} buf */
export function bytesToHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** SHA-256 hex of arbitrary bytes. */
export async function sha256Hex(/** @type {Uint8Array} */ bytes) {
  return bytesToHex(await subtle.digest("SHA-256", bytes));
}

/** A fresh P-256 keypair + its X||Y hex, as the Worker publishes it. */
export async function makeKeypair() {
  const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const raw = new Uint8Array(await subtle.exportKey("raw", kp.publicKey)); // 04||X||Y
  return { keypair: kp, publicKeyXY: bytesToHex(raw.slice(1)), publicKeySec1: bytesToHex(raw) };
}

/**
 * Build a raw `GET /v1/verify/{code}` response body for a HashStamp
 * document-timestamp, signed for real with `keys`.
 *
 * Field-for-field this mirrors what zknot-api's VerifyResponse returns for a
 * record the Worker created — including `verified: true`, which the API
 * hardcodes on every 200 and which the client must therefore never trust.
 *
 * @param {{file: Uint8Array, keys: Awaited<ReturnType<typeof makeKeypair>>,
 *          code?: string, deviceId?: string, publicLabel?: string|null,
 *          legacyFilename?: string|null, chainPosition?: number|null,
 *          chainIntegrity?: boolean|null, signedAt?: string, extraMetadata?: object}} o
 */
export async function makeStampedRecord(o) {
  const {
    file,
    keys,
    code = "ZK-8H3M-2QP",
    deviceId = "HASHSTAMP-SVC-01",
    publicLabel = "Invoice 2026-07",
    legacyFilename = null,
    chainPosition = 4211,
    chainIntegrity = true,
    signedAt = "2026-07-14T09:31:22.417000+00:00",
    extraMetadata = {},
  } = o;

  const fileHash = await sha256Hex(file);
  const fileHashBytes = hexToBytes(fileHash);
  const challengeHash = await sha256Hex(fileHashBytes);
  const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.keypair.privateKey, fileHashBytes));

  return {
    verified: true, // hardcoded by zknot-api on every 200 — never a verdict
    short_code: code,
    artifact_id: `${challengeHash.slice(0, 8)}-${challengeHash.slice(8, 12)}-4${challengeHash.slice(13, 16)}-a${challengeHash.slice(17, 20)}-${challengeHash.slice(20, 32)}`,
    artifact_type: "COMBINED_SESSION",
    device_id: deviceId,
    session_id: null,
    challenge_hash: challengeHash,
    signature: bytesToHex(sig),
    public_key: keys.publicKeyXY, // Worker publishes bare X||Y, no 04 prefix
    signed_at: signedAt,
    chain_position: chainPosition,
    chain_prev_hash: "9f2c" + "0".repeat(60),
    artifact_hash: "1a7e" + "0".repeat(60),
    chain_integrity: chainIntegrity,
    verification_message: "Signature verified.",
    signed_payload_hex: null, // doc-timestamps carry no reconstructable payload
    record_version: null,
    identity_tier: null,
    presence_binding_type: null,
    content_binding_type: null,
    metadata: {
      product: "hashstamp",
      kind: "document_timestamp",
      file_sha256: fileHash,
      ...(publicLabel ? { public_label: publicLabel } : {}),
      ...(legacyFilename ? { filename: legacyFilename } : {}),
      stamped_at: signedAt,
      ...extraMetadata,
    },
  };
}

/**
 * A LEGACY HashStamp record: pre-F2 shape, carrying `metadata.filename` (the
 * sender's private filename, published back when the browser still sent it) and
 * NO public_label. Real records like this exist and must still export — with the
 * filename left behind. That exclusion is the point of the legacy fixture.
 * @param {{file: Uint8Array, keys: Awaited<ReturnType<typeof makeKeypair>>}} o
 */
export async function makeLegacyRecord(o) {
  return makeStampedRecord({
    ...o,
    code: "ZK-4KD9-1MR",
    publicLabel: null,
    legacyFilename: "Q3-payroll-CONFIDENTIAL-v7-FINAL.xlsx",
    chainPosition: 118,
  });
}

/**
 * A record whose metadata carries the fields the bundle must never emit. This is
 * not hypothetical: /v1/verify echoes `metadata` unfiltered, and zknot-api's
 * public units-registration path writes a customer email into that same blob.
 * The deny-list tests export THIS and assert none of it survives.
 * @param {{file: Uint8Array, keys: Awaited<ReturnType<typeof makeKeypair>>}} o
 */
export async function makeRecordWithToxicMetadata(o) {
  return makeStampedRecord({
    ...o,
    code: "ZK-TOX1-9ZZ",
    legacyFilename: "sender-private-name.pdf",
    extraMetadata: {
      registration: {
        email: "victim@example.com",
        shopify_order_id: "SHOP-99881",
        purchase_date: "2026-02-02",
      },
      stripe_session_id: "cs_live_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ",
      stripe_test_session: "cs_test_a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ",
      payment_intent: "pi_3QxYzAbCdEfGhIjK0LmNoPqR",
      customer_email: "buyer@example.com",
      ip_address: "203.0.113.42",
      user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      analytics_id: "ga-8817263-x",
      authorization: "Bearer sk_live_supersecrettoken",
      private_key: "-----BEGIN PRIVATE KEY-----MIIEvQIBADANBg-----END PRIVATE KEY-----",
      worker_secret: "whsec_9911aabbccdd",
      internal_notes: "customer disputed charge, flagged by ops",
    },
  });
}

/** The pinned production key id + X||Y, for tests that assert real-key recognition. */
export const PINNED = KNOWN_SIGNING_KEYS["HASHSTAMP-SVC-01"];
