// @ts-check
/**
 * Feature-flag behaviour (both states) + the record-shape contract.
 *
 * The shape test is the one that matters most over time: these fixtures are
 * GENERATED, so nothing but this test stops them drifting away from the record
 * the Worker actually writes. It reads hashstamp-worker.js and asserts the
 * signing math and field names this bundle format depends on are still there.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { ENABLE_PORTABLE_PROOF_BUNDLE } from "../flags.js";
import { mapApiResponse, verifyRecord } from "../verifier.js";
import { proofBundleExportGate } from "../proof-bundle.js";
import { makeKeypair, makeStampedRecord, PINNED } from "./fixtures.mjs";

const FILE = new TextEncoder().encode("invoice\n");
const WORKER = "/home/mt/hashstamp-worker/hashstamp-worker.js";

/* ─── the flag ────────────────────────────────────────────────────────────── */

test("the feature flag is OFF by default in the committed source", () => {
  // This is the production default. If this test fails, someone shipped the
  // feature by accident.
  assert.equal(ENABLE_PORTABLE_PROOF_BUNDLE, false);
});

test("DISABLED state: the export gate refuses and marks it as flagged-off, not broken", async () => {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  const rec = mapApiResponse(api);
  const result = await verifyRecord(rec);

  const gate = proofBundleExportGate(rec, result, { enabled: false });
  assert.equal(gate.enabled, false);
  // flagged_off lets the UI render NOTHING rather than an alarming explanation
  // about missing material — the record is fine; the feature is just not live.
  assert.equal(/** @type {any} */ (gate).flagged_off, true);
});

test("DISABLED state is the default when no flag is passed at all (fail closed)", async () => {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  const rec = mapApiResponse(api);
  const result = await verifyRecord(rec);
  const gate = proofBundleExportGate(rec, result); // no opts
  assert.equal(gate.enabled, false);
  assert.equal(/** @type {any} */ (gate).flagged_off, true);
});

test("ENABLED state: the same record exports", async () => {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  const rec = mapApiResponse(api);
  const result = await verifyRecord(rec);
  const gate = proofBundleExportGate(rec, result, { enabled: true });
  assert.equal(gate.enabled, true);
});

test("ENABLED state does not weaken any other gate", async () => {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  api.public_key = ""; // material missing
  const rec = mapApiResponse(api);
  const result = await verifyRecord(rec);
  const gate = proofBundleExportGate(rec, result, { enabled: true });
  assert.equal(gate.enabled, false);
  assert.equal(/** @type {any} */ (gate).flagged_off, undefined); // a real data problem
});

test("flags.js documents the exact activation procedure", async () => {
  const src = await readFile(fileURLToPath(new URL("../flags.js", import.meta.url)), "utf8");
  assert.match(src, /ACTIVATION PROCEDURE/);
  assert.match(src, /ENABLE_PORTABLE_PROOF_BUNDLE = true/);
});

/* ─── the record-shape contract with the real Worker ──────────────────────── */

test("SHAPE: the Worker still signs the raw file-hash bytes (the whole offline story)", async () => {
  const src = await readFile(WORKER, "utf8");
  // If this changes, the signed payload is no longer the fingerprint preimage
  // and proof-bundle.js's BUN-20/BUN-22 checks are verifying the wrong thing.
  assert.match(src, /const fileHashBytes = hexToBytes\(fileHash\)/);
  assert.match(src, /const challengeHash = await sha256Hex\(fileHashBytes\)/);
  assert.match(src, /signDigest\(priv, fileHashBytes\)/);
});

test("SHAPE: the Worker still publishes the field names the bundle reads", async () => {
  const src = await readFile(WORKER, "utf8");
  assert.match(src, /kind: "document_timestamp"/);
  assert.match(src, /file_sha256: fileHash/);
  assert.match(src, /challenge_hash: challengeHash/);
  assert.match(src, /public_key: publicKeyHex/);
  assert.match(src, /artifact_type: "COMBINED_SESSION"/);
});

test("SHAPE: the pinned key matches the Worker's published HASHSTAMP_PUBLIC_KEY_HEX", async () => {
  // The pin is the trust anchor. If the Worker's key var and this pin ever
  // diverge, every real bundle would render "SIGNING KEY NOT RECOGNIZED" — so
  // this test is the tripwire for a key rotation nobody told the verifier about.
  const toml = await readFile("/home/mt/hashstamp-worker/wrangler.toml", "utf8");
  const m = toml.match(/HASHSTAMP_PUBLIC_KEY_HEX\s*=\s*"([0-9a-fA-F]+)"/);
  assert.ok(m, "wrangler.toml must publish HASHSTAMP_PUBLIC_KEY_HEX");
  assert.equal(PINNED.public_key_xy, m[1].toLowerCase(), "pinned key is out of sync with the Worker");

  const id = toml.match(/HASHSTAMP_DEVICE_ID\s*=\s*"([^"]+)"/);
  assert.ok(id);
  assert.equal(PINNED.key_id, id[1], "pinned key_id is out of sync with the Worker");
});

test("SHAPE: the Worker never sends the private filename, so no bundle can carry one", async () => {
  const src = await readFile(WORKER, "utf8");
  assert.match(src, /the original filename is NEVER published/);
  // body.filename must not be read anywhere.
  assert.ok(!/body\.filename/.test(src), "the Worker must not read body.filename");
});
