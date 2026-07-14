// @ts-check
/**
 * Privacy deny-list + leak-detector mutation tests (plan items 7-11, 28).
 *
 * HOW THIS SUITE IS BUILT TO ACTUALLY WORK
 *   A deny-list test that only ever runs against clean data proves nothing —
 *   it passes just as happily when the detector is broken. So this file does
 *   two things:
 *     1. exports a record whose metadata is FULL of prohibited material (see
 *        makeRecordWithToxicMetadata) and asserts none of it survives;
 *     2. MUTATION-TESTS the detector itself: it injects each forbidden value
 *        into a known-clean bundle and asserts the detector FIRES. If someone
 *        weakens the detector, those tests fail.
 *
 *   The detector inspects SERIALIZED OUTPUT, not field names: a leak that
 *   arrives under an innocent key is still a leak.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { mapApiResponse, verifyRecord } from "../verifier.js";
import { buildProofBundle, serializeProofBundle } from "../proof-bundle.js";
import { makeKeypair, makeStampedRecord, makeLegacyRecord, makeRecordWithToxicMetadata } from "./fixtures.mjs";

const FILE = new TextEncoder().encode("payroll spreadsheet bytes\n");

/**
 * THE DENY-LIST. Patterns that must never appear in a serialized bundle.
 * Each is a {name, re} so a failure says WHAT leaked, not just "regex matched".
 */
export const DENY = [
  { name: "Stripe live session id", re: /cs_live_[A-Za-z0-9]+/i },
  { name: "Stripe test session id", re: /cs_test_[A-Za-z0-9]+/i },
  { name: "Stripe payment intent", re: /\bpi_[A-Za-z0-9]{6,}/i },
  { name: "Stripe secret key", re: /\bsk_(live|test)_[A-Za-z0-9]+/i },
  { name: "Stripe webhook secret", re: /\bwhsec_[A-Za-z0-9]+/i },
  { name: "email address", re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/ },
  { name: "customer_email field", re: /"?customer_email"?\s*[:=]/i },
  { name: "registration block", re: /"registration"\s*:/i },
  { name: "private key material", re: /private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY/i },
  { name: "secret", re: /"[^"]*secret[^"]*"\s*:|\bsecret\b/i },
  { name: "authorization header", re: /"?authorization"?\s*[:=]/i },
  { name: "bearer token", re: /\bbearer\s+\S+/i },
  { name: "IP address", re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/ },
  { name: "user agent", re: /user[_-]?agent|Mozilla\/\d/i },
  { name: "analytics id", re: /analytics[_-]?id|\bga-\d/i },
  { name: "internal notes", re: /internal[_-]?notes/i },
  { name: "shopify order id", re: /shopify[_-]?order[_-]?id|SHOP-\d+/i },
  { name: "private filename (fixture value)", re: /payroll|CONFIDENTIAL|sender-private-name|\.xlsx\b/i },
  { name: "legacy filename field", re: /"filename"\s*:/i },
  { name: "session_id field", re: /"session_id"\s*:/i },
];

/** @param {string} text @returns {{name: string, match: string}[]} */
export function findLeaks(text) {
  const hits = [];
  for (const d of DENY) {
    const m = text.match(d.re);
    if (m) hits.push({ name: d.name, match: m[0] });
  }
  return hits;
}

/** Export a bundle and return its serialized text. */
async function serializedBundleFor(api) {
  const rec = mapApiResponse(api);
  const result = await verifyRecord(rec);
  return serializeProofBundle(await buildProofBundle(rec, result));
}

/* ─── 7-11. the export leaks nothing ──────────────────────────────────────── */

test("7-11. a bundle built from a record with TOXIC metadata leaks none of it", async () => {
  const keys = await makeKeypair();
  const text = await serializedBundleFor(await makeRecordWithToxicMetadata({ file: FILE, keys }));
  const leaks = findLeaks(text);
  assert.deepEqual(leaks, [], `bundle leaked: ${leaks.map((l) => `${l.name} (${l.match})`).join(", ")}`);
});

test("7. the export contains no original file content", async () => {
  const keys = await makeKeypair();
  const secret = "TOP-SECRET-CONTENTS-c0ffee-do-not-publish";
  const text = await serializedBundleFor(
    await makeStampedRecord({ file: new TextEncoder().encode(secret), keys })
  );
  assert.ok(!text.includes(secret), "the file's bytes must never be in the bundle");
  assert.ok(!text.includes("c0ffee"));
});

test("8. the export contains no private filename, even from a legacy record that has one", async () => {
  const keys = await makeKeypair();
  const text = await serializedBundleFor(await makeLegacyRecord({ file: FILE, keys }));
  assert.ok(!/Q3-payroll-CONFIDENTIAL-v7-FINAL\.xlsx/i.test(text));
  assert.ok(!/"filename"\s*:/.test(text));
  assert.deepEqual(findLeaks(text), []);
});

test("9. the export contains no Stripe identifiers", async () => {
  const keys = await makeKeypair();
  const text = await serializedBundleFor(await makeRecordWithToxicMetadata({ file: FILE, keys }));
  for (const re of [/cs_live_/, /cs_test_/, /\bpi_[A-Za-z0-9]{6,}/, /price_/, /sk_live_/]) {
    assert.ok(!re.test(text), `${re} must not appear`);
  }
});

test("10. the export contains no customer email", async () => {
  const keys = await makeKeypair();
  const text = await serializedBundleFor(await makeRecordWithToxicMetadata({ file: FILE, keys }));
  assert.ok(!/victim@example\.com/.test(text));
  assert.ok(!/buyer@example\.com/.test(text));
  assert.ok(!/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(text), "no email-shaped string at all");
});

test("11. the export contains no secret material, tokens, IPs or user agents", async () => {
  const keys = await makeKeypair();
  const text = await serializedBundleFor(await makeRecordWithToxicMetadata({ file: FILE, keys }));
  for (const re of [/private_key/i, /BEGIN PRIVATE KEY/i, /whsec_/, /Bearer /i, /203\.0\.113\.42/, /Mozilla\//]) {
    assert.ok(!re.test(text), `${re} must not appear`);
  }
});

test("the exporter reads an ALLOWLIST: a brand-new toxic metadata field cannot leak", async () => {
  // The structural guarantee, not the deny-list: buildProofBundle only ever
  // reads named fields off the mapped record, so a field invented tomorrow is
  // simply never copied. This is what makes the deny-list a backstop and not
  // the mechanism.
  const keys = await makeKeypair();
  const api = await makeStampedRecord({
    file: FILE,
    keys,
    extraMetadata: { some_field_that_does_not_exist_yet: "ssn-078-05-1120-leaked" },
  });
  const text = await serializedBundleFor(api);
  assert.ok(!text.includes("078-05-1120"));
  assert.ok(!text.includes("some_field_that_does_not_exist_yet"));
});

test("passing the RAW api response to the builder fails closed instead of leaking metadata", async () => {
  // The allowlist lives in mapApiResponse. A caller who skips it and hands the
  // raw /v1/verify body straight to buildProofBundle must not get a bundle at
  // all — the export gate reads flattened fields (file_sha256 etc.) that only
  // exist on a MAPPED record, so a raw body cannot satisfy it. This is the
  // failure mode that would otherwise re-open the metadata leak.
  const keys = await makeKeypair();
  const api = await makeRecordWithToxicMetadata({ file: FILE, keys });
  const rec = mapApiResponse(api);
  const result = await verifyRecord(rec);
  await assert.rejects(
    () => buildProofBundle(/** @type {any} */ (api), result),
    /does not meet the export gate/,
    "a raw API body must never build a bundle"
  );
});

test("the bundle DOES include the file fingerprint — it is the evidence subject", async () => {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  const text = await serializedBundleFor(api);
  assert.ok(text.includes(api.metadata.file_sha256), "the fingerprint is expected and required");
});

test("the bundle includes a public_label, because it is already public", async () => {
  const keys = await makeKeypair();
  const text = await serializedBundleFor(await makeStampedRecord({ file: FILE, keys, publicLabel: "Invoice 42" }));
  assert.ok(text.includes("Invoice 42"));
});

/* ─── 28. MUTATION TESTS — prove the detector actually catches a leak ──────── */

test("MUTATION: the leak detector fires on every prohibited pattern injected into a clean bundle", async () => {
  const keys = await makeKeypair();
  const clean = await serializedBundleFor(await makeStampedRecord({ file: FILE, keys }));
  assert.deepEqual(findLeaks(clean), [], "baseline bundle must be clean");

  /** Each entry is a leak someone might plausibly re-introduce. */
  const injections = [
    ["Stripe live session id", '"ref": "cs_live_a1B2c3D4e5F6g7H8"'],
    ["Stripe test session id", '"ref": "cs_test_a1B2c3D4e5F6g7H8"'],
    ["Stripe payment intent", '"pay": "pi_3QxYzAbCdEfGhIjK0L"'],
    ["Stripe secret key", '"k": "sk_live_abcdef123456"'],
    ["Stripe webhook secret", '"w": "whsec_9911aabbccdd"'],
    ["email address", '"who": "victim@example.com"'],
    ["customer_email field", '"customer_email": "x"'],
    ["registration block", '"registration": {}'],
    ["private key material", '"private_key": "x"'],
    ["authorization header", '"authorization": "x"'],
    ["bearer token", '"h": "Bearer abc123"'],
    ["IP address", '"ip": "203.0.113.42"'],
    ["user agent", '"ua": "Mozilla/5.0 (X11)"'],
    ["analytics id", '"analytics_id": "ga-8817263-x"'],
    ["internal notes", '"internal_notes": "x"'],
    ["shopify order id", '"shopify_order_id": "SHOP-99881"'],
    ["private filename (fixture value)", '"name": "Q3-payroll.xlsx"'],
    ["legacy filename field", '"filename": "x.pdf"'],
    ["session_id field", '"session_id": "abc"'],
  ];

  for (const [expected, snippet] of injections) {
    // Inject the leak as a real extra JSON member of the bundle object.
    const mutated = clean.replace(/^\{/, `{${snippet},`);
    const leaks = findLeaks(mutated);
    assert.ok(
      leaks.some((l) => l.name === expected),
      `detector FAILED to catch an injected "${expected}" leak (${snippet}). Detected: ${JSON.stringify(leaks.map((l) => l.name))}`
    );
  }
});

test("MUTATION: the detector catches a leak hidden under an innocent-looking key name", async () => {
  // Field-name checks alone would miss this; we inspect serialized VALUES.
  const keys = await makeKeypair();
  const clean = await serializedBundleFor(await makeStampedRecord({ file: FILE, keys }));
  const mutated = clean.replace(/^\{/, '{"note": "contact ops@zknot.io for help",');
  const leaks = findLeaks(mutated);
  assert.ok(leaks.some((l) => l.name === "email address"), "an email in a harmless-looking field is still a leak");
});

test("MUTATION: a deliberately sabotaged exporter is caught by the deny-list", async () => {
  // Simulates the regression this suite exists to prevent: someone "helpfully"
  // spreads the raw metadata blob into the bundle. The deny-list must fire.
  const keys = await makeKeypair();
  const api = await makeRecordWithToxicMetadata({ file: FILE, keys });
  const rec = mapApiResponse(api);
  const result = await verifyRecord(rec);
  const good = await buildProofBundle(rec, result);

  const sabotaged = { ...good, record: { ...good.record, ...api.metadata } }; // the bug
  const leaks = findLeaks(JSON.stringify(sabotaged, null, 2));
  assert.ok(leaks.length > 0, "deny-list must catch a metadata-spreading exporter");
  for (const expect of ["email address", "Stripe live session id", "registration block"]) {
    assert.ok(leaks.some((l) => l.name === expect), `sabotage should surface: ${expect}`);
  }
});
