// @ts-check
/**
 * Offline guarantee + the one optional online call (plan items 24, 25, 26).
 *
 * "No network during import" is the load-bearing privacy promise of this whole
 * feature, so it is verified three independent ways — any one of them alone
 * would be weak:
 *   1. STATIC: proof-bundle.js's source contains no network primitive on the
 *      import path (catches a call that a test happens not to execute).
 *   2. DYNAMIC: every network global is replaced with a booby trap that FAILS
 *      the test if touched, then the full import+verify+compare path is run.
 *   3. MUTATION: the booby trap is proven to actually fire, so tests 1-2 cannot
 *      pass vacuously.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { mapApiResponse, verifyRecord, compareLocalFile } from "../verifier.js";
import {
  buildProofBundle,
  serializeProofBundle,
  parseProofBundle,
  verifyProofBundle,
  bundleFileComparisonGate,
  checkCurrentStatusOnline,
  compareWithLiveRecord,
} from "../proof-bundle.js";
import { makeKeypair, makeStampedRecord } from "./fixtures.mjs";

const FILE = new TextEncoder().encode("an invoice\n");
const SRC = (p) => fileURLToPath(new URL(p, import.meta.url));

/**
 * Replace every way a browser can talk to the network with a trap that records
 * the attempt. Returns {calls, restore}.
 */
function trapNetwork() {
  /** @type {string[]} */
  const calls = [];
  const g = /** @type {any} */ (globalThis);
  /** @type {{key: string, desc: PropertyDescriptor|undefined}[]} */
  const saved = [];

  // defineProperty, not assignment: on Node >= 20 `globalThis.navigator` is an
  // accessor with no setter, so `g.navigator = x` throws. Capturing the original
  // descriptor is also the only way to restore it exactly.
  const install = (/** @type {string} */ key, /** @type {any} */ value) => {
    saved.push({ key, desc: Object.getOwnPropertyDescriptor(g, key) });
    Object.defineProperty(g, key, { value, configurable: true, writable: true });
  };

  const boom = (/** @type {string} */ what) => (/** @type {any[]} */ ...a) => {
    calls.push(a.length ? `${what}(${String(a[0])})` : what);
    throw new Error("NETWORK CALL DURING OFFLINE PATH");
  };

  install("fetch", boom("fetch"));
  install("XMLHttpRequest", boom("XMLHttpRequest"));
  install("WebSocket", boom("WebSocket"));
  install("EventSource", boom("EventSource"));
  // sendBeacon is the sneaky one: it is fire-and-forget and never throws in a
  // way a caller would notice, so a beacon leak would otherwise be invisible.
  // It must RECORD rather than throw, exactly as the real API behaves.
  install("navigator", {
    sendBeacon: (/** @type {any[]} */ ...a) => {
      calls.push(`sendBeacon(${String(a[0])})`);
      return true;
    },
  });

  return {
    calls,
    restore() {
      for (const { key, desc } of saved) {
        if (desc) Object.defineProperty(g, key, desc);
        else delete g[key];
      }
    },
  };
}

/* ─── 24. import causes no network request ────────────────────────────────── */

test("24. STATIC: proof-bundle.js has exactly one fetch, and it is the explicit online check", async () => {
  const src = await readFile(SRC("../proof-bundle.js"), "utf8");
  // Strip comments so prose about fetch does not count as a call.
  const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");

  for (const banned of [/XMLHttpRequest/, /sendBeacon/, /new WebSocket/, /EventSource/, /navigator\.connection/, /import\s*\(/]) {
    assert.ok(!banned.test(code), `proof-bundle.js must not contain ${banned}`);
  }
  const fetches = code.match(/\bfetch\s*\(/g) ?? [];
  assert.equal(fetches.length, 1, "exactly one fetch may exist in this module");
  // ...and it must live inside checkCurrentStatusOnline, not anywhere else.
  const online = code.slice(code.indexOf("export async function checkCurrentStatusOnline"));
  assert.equal((online.match(/\bfetch\s*\(/g) ?? []).length, 1, "the only fetch must be in checkCurrentStatusOnline");
});

test("24. DYNAMIC: parse + verify + compare touches no network primitive at all", async () => {
  const keys = await makeKeypair();
  const rec = mapApiResponse(await makeStampedRecord({ file: FILE, keys }));
  const result = await verifyRecord(rec);
  const text = serializeProofBundle(await buildProofBundle(rec, result));

  const trap = trapNetwork();
  try {
    const parsed = parseProofBundle(text);
    assert.equal(parsed.ok, true);
    // @ts-ignore
    const v = await verifyProofBundle(parsed.bundle);
    assert.equal(v.checks.find((c) => c.id === "BUN-22")?.pass, true);

    // ...including the Verify-your-copy comparison, where the FILE is present —
    // the moment an upload would happen if this feature were dishonest.
    const gate = bundleFileComparisonGate({ ...v, verdict: "VERIFIED_OFFLINE" });
    // @ts-ignore
    const cmp = await compareLocalFile({ async arrayBuffer() { return FILE.buffer; } }, gate.fingerprint);
    assert.equal(cmp.outcome, "MATCH");
  } finally {
    trap.restore();
  }
  assert.deepEqual(trap.calls, [], `offline path attempted network: ${trap.calls.join(", ")}`);
});

test("24. MUTATION: the network trap provably fires when a call IS made", async () => {
  // Without this, the two tests above could pass simply because the trap is
  // broken. Prove the detector detects.
  const trap = trapNetwork();
  try {
    // throws synchronously by design, so the offending caller dies loudly at the
    // call site rather than leaking an unhandled rejection into the test runner.
    assert.throws(
      () => /** @type {any} */ (globalThis).fetch("https://example.com/leak"),
      /NETWORK CALL DURING OFFLINE PATH/
    );
    /** @type {any} */ (globalThis).navigator.sendBeacon("https://example.com/beacon", "data");
  } finally {
    trap.restore();
  }
  assert.equal(trap.calls.length, 2);
  assert.match(trap.calls[0], /fetch\(https:\/\/example\.com\/leak\)/);
  assert.match(trap.calls[1], /sendBeacon/);
});

/* ─── 25. the optional online button makes only the documented request ─────── */

test("25. checkCurrentStatusOnline issues exactly ONE GET to /v1/verify/{code} and sends nothing else", async () => {
  const g = /** @type {any} */ (globalThis);
  const saved = g.fetch;
  /** @type {any[]} */
  const calls = [];
  g.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return { ok: true, status: 200, json: async () => ({ verified: true, short_code: "ZK-8H3M-2QP" }) };
  };
  try {
    const r = await checkCurrentStatusOnline("ZK-8H3M-2QP");
    assert.equal(r.ok, true);
  } finally {
    g.fetch = saved;
  }

  assert.equal(calls.length, 1, "exactly one request");
  assert.equal(calls[0].url, "https://api.zknot.io/v1/verify/ZK-8H3M-2QP");
  // No init at all => default GET, no headers, no body, no credentials. This is
  // the documented contract: the code travels, nothing else does.
  assert.equal(calls[0].init, undefined);
  assert.ok(!calls[0].url.includes("?"), "no query string");
});

test("25. the online check transmits no bundle content, no local file, no computed hash", async () => {
  const keys = await makeKeypair();
  const rec = mapApiResponse(await makeStampedRecord({ file: FILE, keys }));
  const result = await verifyRecord(rec);
  const bundle = await buildProofBundle(rec, result);

  const g = /** @type {any} */ (globalThis);
  const saved = g.fetch;
  /** @type {string[]} */
  const wire = [];
  g.fetch = async (url, init) => {
    wire.push(String(url) + JSON.stringify(init ?? {}));
    return { ok: true, status: 200, json: async () => ({}) };
  };
  try {
    await checkCurrentStatusOnline(bundle.record.verification_code);
  } finally {
    g.fetch = saved;
  }

  const sent = wire.join("|");
  assert.ok(!sent.includes(bundle.file_fingerprint.value), "the fingerprint must not be transmitted");
  assert.ok(!sent.includes(bundle.signature.value), "the signature must not be transmitted");
  assert.ok(!sent.includes(bundle.signing_key.public_key), "the key must not be transmitted");
  assert.ok(!sent.includes(bundle.bundle_id), "the bundle id must not be transmitted");
  assert.ok(!/VERIFIED/.test(sent), "the offline verdict must not be transmitted");
  assert.ok(sent.includes("ZK-8H3M-2QP"), "only the public code travels");
});

test("25. a bundle with no verification code makes NO request at all", async () => {
  const trap = trapNetwork();
  try {
    const r = await checkCurrentStatusOnline("");
    assert.equal(r.ok, false);
    assert.match(/** @type {any} */ (r).error, /no verification code/i);
  } finally {
    trap.restore();
  }
  assert.deepEqual(trap.calls, []);
});

test("25. the online comparison reports findings without inventing revocation assurance", async () => {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  const rec = mapApiResponse(api);
  const result = await verifyRecord(rec);
  const bundle = await buildProofBundle(rec, result);
  const parsed = parseProofBundle(serializeProofBundle(bundle));
  // @ts-ignore
  const b = parsed.bundle;

  const findings = compareWithLiveRecord(b, api);
  const byId = Object.fromEntries(findings.map((f) => [f.id, f]));
  assert.equal(byId["ONLINE-FINGERPRINT"].pass, true);
  assert.equal(byId["ONLINE-KEY"].pass, true);
  assert.equal(byId["ONLINE-CHAIN-POSITION"].pass, true);
  // Even after going online, key status stays UNKNOWN: the endpoint publishes
  // no revocation record, so claiming otherwise would invent assurance.
  assert.equal(byId["ONLINE-KEY-STATUS"].pass, null);
  assert.match(byId["ONLINE-KEY-STATUS"].detail, /remains NOT CHECKED/);

  // A server that now reports a different fingerprint is a finding, not a shrug.
  const tampered = { ...api, metadata: { ...api.metadata, file_sha256: "b".repeat(64) } };
  const bad = compareWithLiveRecord(b, tampered);
  assert.equal(bad.find((f) => f.id === "ONLINE-FINGERPRINT")?.pass, false);
});

/* ─── 26. existing online verification is unchanged ───────────────────────── */

test("26. the existing /v1/verify client path still works unchanged", async () => {
  const { verifyShortCode } = await import("../verifier.js");
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });

  const g = /** @type {any} */ (globalThis);
  const saved = g.fetch;
  /** @type {string[]} */
  const urls = [];
  g.fetch = async (url) => {
    urls.push(String(url));
    return { ok: true, status: 200, json: async () => api };
  };
  let r;
  try {
    r = await verifyShortCode("ZK-8H3M-2QP");
  } finally {
    g.fetch = saved;
  }

  assert.deepEqual(urls, ["https://api.zknot.io/v1/verify/ZK-8H3M-2QP"], "same single request as before");
  assert.equal(r.verdict, "VERIFIED_CLIENT_SIDE");
  assert.equal(r.kind, "document_timestamp");
  // The proof-bundle work must not have perturbed the live page's behaviour.
  assert.equal(r.docTimestamp?.file_sha256, api.metadata.file_sha256);
  assert.equal(r.server_discrepancy, null);
});

test("26. a failed fetch still yields CANNOT_VERIFY, not a crash", async () => {
  const { verifyShortCode } = await import("../verifier.js");
  const g = /** @type {any} */ (globalThis);
  const saved = g.fetch;
  g.fetch = async () => ({ ok: false, status: 404 });
  let r;
  try {
    r = await verifyShortCode("ZK-NOPE-000");
  } finally {
    g.fetch = saved;
  }
  assert.equal(r.verdict, "CANNOT_VERIFY");
});
