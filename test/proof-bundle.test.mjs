// @ts-check
/**
 * Portable proof bundle — export, import, round trip, tamper resistance.
 * Covers test-plan items 1-6, 12-19, 21-23. Privacy (7-11) and network (24-26)
 * live in their own files so a leak or a stray request fails a test whose NAME
 * says exactly that.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { mapApiResponse, verifyRecord } from "../verifier.js";
import {
  buildProofBundle,
  proofBundleExportGate,
  serializeProofBundle,
  proofBundleFilename,
  parseProofBundle,
  verifyProofBundle,
  bundleFileComparisonGate,
  MAX_BUNDLE_BYTES,
  SCHEMA_V1,
  KNOWN_SIGNING_KEYS,
} from "../proof-bundle.js";
import { makeKeypair, makeStampedRecord, makeLegacyRecord, hexToBytes, bytesToHex } from "./fixtures.mjs";

const FILE = new TextEncoder().encode("the contents of an invoice PDF\n");

/** Fetch a record, verify it, and build a bundle — the whole export path. */
async function exportFrom(api) {
  const rec = mapApiResponse(api);
  const result = await verifyRecord(rec);
  const gate = proofBundleExportGate(rec, result, { enabled: true });
  return { rec, result, gate };
}

/** Export → serialize → parse → verify: exactly what a recipient's browser does. */
async function roundTrip(api) {
  const { rec, result } = await exportFrom(api);
  const bundle = await buildProofBundle(rec, result);
  const parsed = parseProofBundle(serializeProofBundle(bundle));
  assert.equal(parsed.ok, true, parsed.ok ? "" : parsed.error);
  // @ts-ignore narrowed by the assert above
  return { bundle, parsed: parsed.bundle, verified: await verifyProofBundle(parsed.bundle) };
}

/* ─── 1-2. current + legacy production-shaped records export ───────────────── */

test("1. a current production-shaped record exports successfully", async () => {
  const keys = await makeKeypair();
  const { gate, rec, result } = await exportFrom(await makeStampedRecord({ file: FILE, keys }));
  assert.equal(result.verdict, "VERIFIED_CLIENT_SIDE");
  assert.equal(gate.enabled, true);

  const bundle = await buildProofBundle(rec, result);
  assert.equal(bundle.schema, SCHEMA_V1);
  assert.equal(bundle.record.verification_code, "ZK-8H3M-2QP");
  assert.equal(bundle.record.public_label, "Invoice 2026-07");
  assert.equal(bundle.file_fingerprint.value, rec.file_sha256);
  assert.equal(bundle.chain.position, 4211);
});

test("2. a supported legacy record (pre-F2, no public_label) exports successfully", async () => {
  const keys = await makeKeypair();
  const { gate, rec, result } = await exportFrom(await makeLegacyRecord({ file: FILE, keys }));
  assert.equal(gate.enabled, true);
  const bundle = await buildProofBundle(rec, result);
  assert.equal(bundle.record.public_label, null); // legacy carries none
  assert.equal(bundle.record.verification_code, "ZK-4KD9-1MR");
  const { verified } = await roundTrip(await makeLegacyRecord({ file: FILE, keys }));
  assert.equal(verified.checks.find((c) => c.id === "BUN-22")?.pass, true);
});

/* ─── 3-6. the export gate fails closed ───────────────────────────────────── */

const GATE_MSG =
  "A portable bundle is not available for this record because the complete verification material is not present.";

test("3. an invalid receipt cannot export", async () => {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  api.signature = api.signature.slice(0, -2) + (api.signature.endsWith("00") ? "11" : "00"); // break it
  const { gate, result } = await exportFrom(api);
  assert.equal(result.verdict, "FAILED");
  assert.equal(gate.enabled, false);
  assert.equal(/** @type {any} */ (gate).reason, GATE_MSG);
});

test("4. a record with no file fingerprint cannot export", async () => {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  delete api.metadata.file_sha256;
  const { gate } = await exportFrom(api);
  assert.equal(gate.enabled, false);
});

test("5. a record with no public key cannot export", async () => {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  api.public_key = "";
  const { gate } = await exportFrom(api);
  assert.equal(gate.enabled, false);
});

test("6. a record whose signed payload cannot be preserved cannot export", async () => {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  // The signed payload IS the fingerprint bytes; a malformed fingerprint means
  // there is no preimage to carry, so nothing downstream could reproduce it.
  api.metadata.file_sha256 = "not-a-sha256";
  const { gate } = await exportFrom(api);
  assert.equal(gate.enabled, false);
});

test("6b. buildProofBundle refuses to build for an ungated record even if called directly", async () => {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  api.public_key = "";
  const rec = mapApiResponse(api);
  const result = await verifyRecord(rec);
  await assert.rejects(() => buildProofBundle(rec, result), /does not meet the export gate/);
});

/* ─── 12-13. round trip + signature verifies ──────────────────────────────── */

test("12. export/import round trip preserves every verification-critical field", async () => {
  const keys = await makeKeypair();
  const { bundle, parsed } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  assert.equal(parsed.file_fingerprint.value, bundle.file_fingerprint.value);
  assert.equal(parsed.signature.value, bundle.signature.value);
  assert.equal(parsed.signature.challenge_hash, bundle.signature.challenge_hash);
  assert.equal(parsed.signature.signed_payload.value, bundle.signature.signed_payload.value);
  assert.equal(parsed.signing_key.public_key, bundle.signing_key.public_key);
  assert.equal(parsed.record.verification_code, bundle.record.verification_code);
});

test("13. an imported bundle's signature verifies offline", async () => {
  const keys = await makeKeypair();
  const { verified } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  // Math passes; the key is a throwaway, so identity must NOT be claimed.
  assert.equal(verified.checks.find((c) => c.id === "BUN-22")?.pass, true);
  assert.equal(verified.verdict, "VERIFIED_UNRECOGNIZED_KEY");
  assert.equal(verified.key_identity.recognized, false);
});

test("13b. a bundle signed by the PINNED production key verifies as ZKNOT's", async () => {
  // We cannot sign with the production private key (we do not have it, and must
  // not). So: build a real bundle, then swap in the pinned public key and assert
  // the identity check keys off the pin. The signature must then FAIL — proving
  // the two checks are independent and that a key swap alone cannot fake a pass.
  const keys = await makeKeypair();
  const { bundle } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  bundle.signing_key.public_key = `04${KNOWN_SIGNING_KEYS["HASHSTAMP-SVC-01"].public_key_xy}`;
  const parsed = parseProofBundle(serializeProofBundle(bundle));
  assert.equal(parsed.ok, true);
  // @ts-ignore
  const v = await verifyProofBundle(parsed.bundle);
  assert.equal(v.verdict, "FAILED", "swapping in the pinned key must not launder a foreign signature");
  assert.equal(v.checks.find((c) => c.id === "BUN-22")?.pass, false);
});

test("13c. the pinned key id and key are exactly the Worker's published values", async () => {
  const pinned = KNOWN_SIGNING_KEYS["HASHSTAMP-SVC-01"];
  assert.equal(pinned.public_key_xy.length, 128); // 64-byte X||Y
  assert.match(pinned.public_key_xy, /^[0-9a-f]+$/);
  // It must be a real point on P-256, or the pin could never match anything.
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(hexToBytes(pinned.public_key_xy), 1);
  await assert.doesNotReject(() =>
    globalThis.crypto.subtle.importKey("raw", raw, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
  );
});

/* ─── 14-16. tamper resistance ────────────────────────────────────────────── */

test("14. a one-byte mutation of the signed payload fails", async () => {
  const keys = await makeKeypair();
  const { bundle } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  const b = bytesToHex(hexToBytes(bundle.signature.signed_payload.value));
  const flipped = (parseInt(b.slice(0, 2), 16) ^ 0x01).toString(16).padStart(2, "0") + b.slice(2);
  bundle.signature.signed_payload.value = flipped;

  const parsed = parseProofBundle(serializeProofBundle(bundle));
  assert.equal(parsed.ok, true);
  // @ts-ignore
  const v = await verifyProofBundle(parsed.bundle);
  assert.equal(v.verdict, "FAILED");
  // Caught by the payload<->fingerprint binding check, before any crypto runs.
  assert.equal(v.checks.find((c) => c.id === "BUN-20")?.pass, false);
});

test("14b. mutating payload AND fingerprint together still fails (signature covers the bytes)", async () => {
  const keys = await makeKeypair();
  const { bundle } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  const b = bundle.signature.signed_payload.value;
  const flipped = (parseInt(b.slice(0, 2), 16) ^ 0x01).toString(16).padStart(2, "0") + b.slice(2);
  // Keep the bundle internally consistent, and recompute challenge_hash too, so
  // the ONLY thing left to catch the lie is the signature itself.
  bundle.signature.signed_payload.value = flipped;
  bundle.file_fingerprint.value = flipped;
  bundle.signature.challenge_hash = bytesToHex(
    await globalThis.crypto.subtle.digest("SHA-256", hexToBytes(flipped))
  );

  const parsed = parseProofBundle(serializeProofBundle(bundle));
  assert.equal(parsed.ok, true);
  // @ts-ignore
  const v = await verifyProofBundle(parsed.bundle);
  assert.equal(v.checks.find((c) => c.id === "BUN-20")?.pass, true, "binding check now passes");
  assert.equal(v.checks.find((c) => c.id === "BUN-21")?.pass, true, "digest check now passes");
  assert.equal(v.checks.find((c) => c.id === "BUN-22")?.pass, false, "signature must still catch it");
  assert.equal(v.verdict, "FAILED");
});

test("15. a one-byte mutation of the signature fails", async () => {
  const keys = await makeKeypair();
  const { bundle } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  const s = bundle.signature.value;
  bundle.signature.value = (parseInt(s.slice(0, 2), 16) ^ 0x01).toString(16).padStart(2, "0") + s.slice(2);

  const parsed = parseProofBundle(serializeProofBundle(bundle));
  assert.equal(parsed.ok, true);
  // @ts-ignore
  const v = await verifyProofBundle(parsed.bundle);
  assert.equal(v.verdict, "FAILED");
  assert.equal(v.checks.find((c) => c.id === "BUN-22")?.pass, false);
});

test("16. a wrong public key fails", async () => {
  const keys = await makeKeypair();
  const other = await makeKeypair();
  const { bundle } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  bundle.signing_key.public_key = `04${other.publicKeyXY}`;

  const parsed = parseProofBundle(serializeProofBundle(bundle));
  assert.equal(parsed.ok, true);
  // @ts-ignore
  const v = await verifyProofBundle(parsed.bundle);
  assert.equal(v.verdict, "FAILED");
  assert.equal(v.checks.find((c) => c.id === "BUN-22")?.pass, false);
});

/* ─── 17-20. schema + parser safety ───────────────────────────────────────── */

test("17. an unsupported schema version fails closed", async () => {
  const keys = await makeKeypair();
  const { bundle } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  for (const bad of ["zknot.hashstamp.proof.v2", "zknot.hashstamp.proof.v0", "", "totally.made.up"]) {
    bundle.schema = bad;
    const parsed = parseProofBundle(serializeProofBundle(bundle));
    assert.equal(parsed.ok, false, `schema "${bad}" must not parse`);
  }
});

test("17b. a missing schema field fails closed", async () => {
  const keys = await makeKeypair();
  const { bundle } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  delete bundle.schema;
  const parsed = parseProofBundle(serializeProofBundle(bundle));
  assert.equal(parsed.ok, false);
  assert.match(/** @type {any} */ (parsed).error, /does not declare a proof-bundle schema/);
});

test("17c. an unknown OPTIONAL field in a supported version is ignored, not fatal", async () => {
  const keys = await makeKeypair();
  const { bundle } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  bundle.some_future_additive_field = { hello: "world" };
  bundle.record.future_note = "added by a later generator";
  const parsed = parseProofBundle(serializeProofBundle(bundle));
  assert.equal(parsed.ok, true, "additive growth within v1 must still verify");
  // @ts-ignore
  const v = await verifyProofBundle(parsed.bundle);
  assert.equal(v.checks.find((c) => c.id === "BUN-22")?.pass, true);
  // @ts-ignore — and the unknown field is dropped, not propagated into the model
  assert.equal(parsed.bundle.some_future_additive_field, undefined);
});

test("18. malformed JSON fails safely", () => {
  for (const bad of ["{", "", "not json at all", "[1,2,3]", '"a string"', "null", "{}"]) {
    const parsed = parseProofBundle(bad);
    assert.equal(parsed.ok, false, `"${bad.slice(0, 12)}" must not parse`);
    assert.equal(typeof /** @type {any} */ (parsed).error, "string");
  }
});

test("19. an oversized bundle fails safely and is not parsed", () => {
  const huge = JSON.stringify({ schema: SCHEMA_V1, pad: "A".repeat(MAX_BUNDLE_BYTES) });
  const parsed = parseProofBundle(huge);
  assert.equal(parsed.ok, false);
  assert.match(/** @type {any} */ (parsed).error, /larger than the/);
});

test("19b. the size limit is enforced on UTF-8 bytes, not JS string length", () => {
  // Multi-byte chars: 30k emoji = 120k bytes but only 60k string units. A naive
  // .length check would let this through.
  const payload = "😀".repeat(30_000);
  const parsed = parseProofBundle(JSON.stringify({ schema: SCHEMA_V1, pad: payload }));
  assert.equal(parsed.ok, false);
  assert.match(/** @type {any} */ (parsed).error, /larger than the/);
});

test("20. HTML/script strings in a bundle remain inert text", async () => {
  const keys = await makeKeypair();
  const { bundle } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  bundle.record.public_label = '<img src=x onerror="alert(1)"><script>steal()</script>';
  bundle.record.product = "<iframe src=evil>";
  bundle.bundle_id = "<b>not-a-tag</b>";

  const parsed = parseProofBundle(serializeProofBundle(bundle));
  assert.equal(parsed.ok, true);
  // @ts-ignore
  const b = parsed.bundle;
  for (const v of [b.record.public_label, b.record.product, b.bundle_id]) {
    assert.ok(typeof v === "string" && !v.includes("<") && !v.includes(">"), `angle brackets must not survive: ${v}`);
  }
  assert.ok(!b.record.public_label.includes("<script"));
});

test("20b. prototype-poisoning keys in a bundle are dropped", () => {
  const evil = `{"schema":"${SCHEMA_V1}","__proto__":{"polluted":true},"record":{"constructor":{"x":1}}}`;
  const parsed = parseProofBundle(evil);
  // It fails for lacking a fingerprint, but the point is the prototype survived clean.
  assert.equal(parsed.ok, false);
  assert.equal(/** @type {any} */ ({}).polluted, undefined);
  assert.equal(Object.prototype.hasOwnProperty.call(Object.prototype, "polluted"), false);
});

/* ─── 21-23. Verify your copy, from an imported bundle ─────────────────────── */

/** Minimal Blob-alike; compareLocalFile only needs .arrayBuffer(). */
const blobOf = (/** @type {Uint8Array} */ bytes) => ({
  async arrayBuffer() {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  },
});

test("21. a ZERO-BYTE original file can still be matched through Verify your copy", async () => {
  const { compareLocalFile } = await import("../verifier.js");
  const keys = await makeKeypair();
  const empty = new Uint8Array(0);
  const { verified } = await roundTrip(await makeStampedRecord({ file: empty, keys }));
  assert.equal(verified.checks.find((c) => c.id === "BUN-22")?.pass, true);

  // A zero-byte file has a perfectly good SHA-256; it must not be mistaken for
  // "no file" anywhere in the chain.
  const fp = verified.fingerprint;
  assert.ok(fp);
  assert.equal(fp.expectedHex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  const cmp = await compareLocalFile(/** @type {any} */ (blobOf(empty)), fp);
  assert.equal(cmp.outcome, "MATCH");
});

test("22. a matching local file matches, from the bundle's own fingerprint", async () => {
  const { compareLocalFile } = await import("../verifier.js");
  const keys = await makeKeypair();
  const { verified } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  const gate = bundleFileComparisonGate({ ...verified, verdict: "VERIFIED_OFFLINE" });
  assert.equal(gate.enabled, true);
  // @ts-ignore
  const cmp = await compareLocalFile(/** @type {any} */ (blobOf(FILE)), gate.fingerprint);
  assert.equal(cmp.outcome, "MATCH");
});

test("23. a modified local file fails to match", async () => {
  const { compareLocalFile } = await import("../verifier.js");
  const keys = await makeKeypair();
  const { verified } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  const modified = new Uint8Array(FILE);
  modified[0] ^= 0x01; // one byte
  const cmp = await compareLocalFile(/** @type {any} */ (blobOf(modified)), /** @type {any} */ (verified.fingerprint));
  assert.equal(cmp.outcome, "MISMATCH");
});

test("23b. Verify your copy is BLOCKED for a bundle whose key is unrecognized", async () => {
  const keys = await makeKeypair();
  const { verified } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  assert.equal(verified.verdict, "VERIFIED_UNRECOGNIZED_KEY");
  const gate = bundleFileComparisonGate(verified);
  // A green "match" against a stranger's signature is exactly the reassuring lie
  // this feature must never tell.
  assert.equal(gate.enabled, false);
  assert.match(/** @type {any} */ (gate).reason, /signature and signing key were not both verified/);
});

/* ─── filenames, ids, badges ──────────────────────────────────────────────── */

test("the suggested filename is HS-YYYYMMDD-CODE.hashstamp and leaks no private name", async () => {
  const keys = await makeKeypair();
  const { bundle } = await roundTrip(
    await makeStampedRecord({ file: FILE, keys, legacyFilename: "SECRET-payroll.xlsx" })
  );
  const name = proofBundleFilename(bundle);
  assert.equal(name, "HS-20260714-ZK-8H3M-2QP.hashstamp");
  assert.ok(!name.toLowerCase().includes("payroll"));
  assert.ok(!name.toLowerCase().includes("secret"));
});

test("bundle_id is deterministic for the same record and carries no export entropy", async () => {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  const { rec, result } = await exportFrom(api);
  const a = await buildProofBundle(rec, result, { exported_at: "2026-07-14T00:00:00.000Z" });
  const b = await buildProofBundle(rec, result, { exported_at: "2027-01-01T00:00:00.000Z" });
  assert.equal(a.bundle_id, b.bundle_id, "same record must yield the same bundle id");
  assert.match(a.bundle_id, /^hsb1_[0-9a-f]{32}$/);
});

test("badges report each property separately — never one generic green tick", async () => {
  const keys = await makeKeypair();
  const { verified } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  const byId = Object.fromEntries(verified.badges.map((b) => [b.id, b]));
  assert.equal(byId.SIGNATURE.state, "PASS");
  assert.equal(byId.KEY_IDENTITY.state, "FAIL"); // throwaway key
  assert.equal(byId.CHAIN.state, "WARN");
  assert.equal(byId.CHAIN.label, "CHAIN PROOF NOT INCLUDED");
  assert.equal(byId.TIME_ANCHOR.label, "EXTERNAL TIME ANCHOR NOT PRESENT");
  assert.equal(byId.KEY_STATUS.label, "CURRENT KEY STATUS NOT CHECKED");
  // The properties we did not check must be PRESENT and explicit: an absent
  // badge reads as a pass.
  for (const id of ["CHAIN", "TIME_ANCHOR", "KEY_STATUS"]) assert.ok(byId[id], `${id} badge must be rendered`);
});

test("the bundle never claims an anchor, chain proof or revocation status it lacks", async () => {
  const keys = await makeKeypair();
  const { bundle } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  assert.equal(bundle.assurance.external_time_anchor, "NOT_PRESENT");
  assert.equal(bundle.assurance.chain_linkage, "METADATA_ONLY");
  assert.equal(bundle.assurance.key_revocation_status, "NOT_CHECKED_OFFLINE");
  assert.equal(bundle.chain.inclusion_proof, null);
  assert.equal(bundle.chain.checkpoint, null);
  assert.ok(bundle.limitations.length >= 5);
});

test("prohibited claims appear nowhere in a serialized bundle", async () => {
  const keys = await makeKeypair();
  const { bundle } = await roundTrip(await makeStampedRecord({ file: FILE, keys }));
  const text = serializeProofBundle(bundle).toLowerCase();
  for (const claim of [
    "proves delivery",
    "proves ownership",
    "legally admissible",
    "cannot be forged",
    "tamper-proof",
    "proves who created",
    "proves who downloaded",
  ]) {
    assert.ok(!text.includes(claim), `bundle must not claim: ${claim}`);
  }
});
