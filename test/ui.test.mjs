// @ts-check
/**
 * UI tests — the real proof-bundle-ui.js driven against the real index.html DOM,
 * in BOTH flag states. Covers the honest-rendering rules that no module test can
 * see: one badge per property, an unrecognized key blocking Verify-your-copy,
 * untrusted bundle strings staying inert text, and no network on import.
 *
 * NOTE ON METHOD
 *   jsdom does not execute <script type="module">, so a test that merely loads
 *   index.html and asserts on the DOM would pass VACUOUSLY — nothing would have
 *   run. That is exactly why the UI logic lives in proof-bundle-ui.js: we parse
 *   the shipped index.html for its real markup, then drive the real controller
 *   over it. If index.html and the controller ever disagree about an element id,
 *   these tests fail — which is the point.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { JSDOM } from "jsdom";

import { mapApiResponse, verifyRecord, compareLocalFile } from "../verifier.js";
import { buildProofBundle, serializeProofBundle, KNOWN_SIGNING_KEYS } from "../proof-bundle.js";
import { createProofBundleUi } from "../proof-bundle-ui.js";
import { makeKeypair, makeStampedRecord } from "./fixtures.mjs";

const INDEX = new URL("../index.html", import.meta.url);
const FILE = new TextEncoder().encode("an invoice\n");

/** The shipped page's markup + the real controller wired over it. */
async function mount({ enabled, onlineCheck } = /** @type {any} */ ({})) {
  const html = await readFile(INDEX, "utf8");
  const dom = new JSDOM(html, { url: "https://verifyknot.io/", pretendToBeVisual: true });
  const { window } = dom;
  const doc = window.document;
  // The page's markup must actually contain the feature's elements.
  assert.ok(doc.getElementById("pbOpenRow"), "index.html is missing the proof-bundle markup");

  const ui = createProofBundleUi({
    doc,
    win: window,
    enabled,
    compareLocalFile,
    ...(onlineCheck ? { onlineCheck } : {}),
  });
  ui.wire();
  return { dom, window, doc, ui };
}

/** A real, signed bundle (throwaway key => key identity must NOT be claimed). */
async function realBundle(opts = {}) {
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys, ...opts });
  const rec = mapApiResponse(api);
  const result = await verifyRecord(rec);
  const bundle = await buildProofBundle(rec, result);
  return { bundle, text: serializeProofBundle(bundle), api, rec, result };
}

/** A File-alike; the real code only needs .name/.size/.text(). */
const fileOf = (text, name = "HS-20260714-ZK-8H3M-2QP.hashstamp") => ({
  name,
  size: Buffer.byteLength(text),
  async text() {
    return text;
  },
});

/* ─── flag OFF ────────────────────────────────────────────────────────────── */

test("UI, flag OFF: the entry point stays hidden and no listener is attached", async () => {
  const { doc, ui } = await mount({ enabled: false });
  assert.equal(doc.getElementById("pbOpenRow").style.display, "none");

  // wire() ran, but with the flag off it must attach nothing: a click on the
  // (hidden) button must not open anything.
  doc.getElementById("pbOpenBtn").click();
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(doc.getElementById("pbResult").style.display, "none");
  assert.ok(ui);
});

test("UI, flag OFF: a verified record shows NO export panel at all", async () => {
  const { doc, ui } = await mount({ enabled: false });
  const { rec, result } = await realBundle();
  ui.showForRecord(rec, result);
  // Not "disabled with an explanation" — absent. The record is fine; the feature
  // simply is not launched, so an explanation would be noise.
  assert.equal(doc.getElementById("pbPanel").style.display, "none");
});

/* ─── flag ON: export ─────────────────────────────────────────────────────── */

test("UI, flag ON: a verified doc receipt offers the download with honest supporting text", async () => {
  const { doc, ui } = await mount({ enabled: true });
  const { rec, result } = await realBundle();
  ui.showForRecord(rec, result);

  assert.equal(doc.getElementById("pbPanel").style.display, "block");
  assert.equal(doc.getElementById("pbActive").style.display, "block");
  assert.equal(doc.getElementById("pbBlocked").style.display, "none");
  assert.equal(doc.getElementById("pbDownload").disabled, false);
  assert.match(doc.getElementById("pbPanel").textContent, /The original file is not included/);
});

test("UI, flag ON: a record missing verification material disables export and explains", async () => {
  const { doc, ui } = await mount({ enabled: true });
  const keys = await makeKeypair();
  const api = await makeStampedRecord({ file: FILE, keys });
  api.signature = api.signature.slice(0, -2) + "00"; // no longer verifies
  const rec = mapApiResponse(api);
  const result = await verifyRecord(rec);
  ui.showForRecord(rec, result);

  assert.equal(doc.getElementById("pbBlocked").style.display, "block");
  assert.equal(doc.getElementById("pbActive").style.display, "none");
  assert.match(
    doc.getElementById("pbBlocked").textContent,
    /A portable bundle is not available for this record because the complete verification material is not present\./
  );
});

test("UI, flag ON: downloading builds the file locally and issues no request", async () => {
  const { window, doc, ui } = await mount({ enabled: true });
  /** @type {string[]} */
  const net = [];
  Object.defineProperty(window, "fetch", {
    value: (...a) => {
      net.push(String(a[0]));
      throw new Error("network during download");
    },
    configurable: true,
  });
  /** @type {any} */
  let saved = null;
  window.URL.createObjectURL = (blob) => {
    saved = blob;
    return "blob:mock";
  };
  window.URL.revokeObjectURL = () => {};

  const { rec, result } = await realBundle();
  ui.showForRecord(rec, result);
  await ui.downloadProofBundle();

  assert.deepEqual(net, [], "the bundle must be built in the browser, not requested");
  assert.ok(saved, "a blob must have been produced");
  const a = [...doc.body.querySelectorAll("a")].find((el) => el.download);
  // The anchor is removed after clicking, so assert on the blob we captured.
  assert.equal(a, undefined, "the temporary anchor must be cleaned up");
  const text = await saved.text();
  const parsed = JSON.parse(text);
  assert.equal(parsed.schema, "zknot.hashstamp.proof.v1");
  assert.equal(parsed.file_fingerprint.value, rec.file_sha256);
});

/* ─── flag ON: import ─────────────────────────────────────────────────────── */

test("UI, flag ON: importing renders a separate badge per property, never one green tick", async () => {
  const { doc, ui } = await mount({ enabled: true });
  const { text } = await realBundle();
  await ui.handleBundleFile(fileOf(text));

  assert.equal(doc.getElementById("pbResult").style.display, "block");
  assert.equal(doc.getElementById("pbOk").style.display, "block");
  assert.equal(doc.getElementById("pbError").style.display, "none");

  const labels = [...doc.getElementById("pbBadges").children].map((el) => el.textContent);
  for (const want of [
    "SIGNATURE VERIFIED OFFLINE",
    "FILE FINGERPRINT INCLUDED",
    "CHAIN PROOF NOT INCLUDED",
    "EXTERNAL TIME ANCHOR NOT PRESENT",
    "CURRENT KEY STATUS NOT CHECKED",
    "SIGNING KEY NOT RECOGNIZED", // throwaway fixture key — must say so
  ]) {
    assert.ok(labels.includes(want), `missing badge "${want}"; got ${JSON.stringify(labels)}`);
  }
  assert.ok(!labels.some((l) => l.trim() === "VERIFIED"), "no single generic green badge");

  // Both honest sections must be populated.
  assert.ok(doc.getElementById("pbVerified").children.length > 0);
  assert.ok(doc.getElementById("pbUnchecked").children.length > 0);
  // The "not checked" column must actually carry the not-checked properties.
  const un = doc.getElementById("pbUnchecked").textContent;
  assert.match(un, /CURRENT KEY STATUS NOT CHECKED/);
  assert.match(un, /CHAIN PROOF NOT INCLUDED/);
});

test("UI, flag ON: an unrecognized-key bundle BLOCKS Verify your copy", async () => {
  const { doc, ui } = await mount({ enabled: true });
  const { text } = await realBundle();
  await ui.handleBundleFile(fileOf(text));

  // Math passed, key is a stranger's: a green "match" would be a reassuring lie.
  assert.equal(doc.getElementById("pbCopyActive").style.display, "none");
  assert.equal(doc.getElementById("pbCopyBlocked").style.display, "block");
  assert.match(doc.getElementById("pbCopyBlocked").textContent, /not both verified/);
});

test("UI, flag ON: malformed JSON fails honestly and shows no result", async () => {
  const { doc, ui } = await mount({ enabled: true });
  await ui.handleBundleFile(fileOf("{not json"));
  assert.equal(doc.getElementById("pbError").style.display, "block");
  assert.match(doc.getElementById("pbError").textContent, /not valid JSON/);
  assert.equal(doc.getElementById("pbOk").style.display, "none");
});

test("UI, flag ON: an oversized file is refused WITHOUT being read", async () => {
  const { doc, ui } = await mount({ enabled: true });
  let read = false;
  await ui.handleBundleFile({
    name: "big.hashstamp",
    size: 9_000_000,
    async text() {
      read = true;
      return "{}";
    },
  });
  assert.equal(read, false, "an oversized file must never be read into memory");
  assert.match(doc.getElementById("pbError").textContent, /larger than the/);
  assert.equal(doc.getElementById("pbOk").style.display, "none");
});

test("UI, flag ON: an unsupported schema fails closed with an honest reason", async () => {
  const { doc, ui } = await mount({ enabled: true });
  const { bundle } = await realBundle();
  bundle.schema = "zknot.hashstamp.proof.v99";
  await ui.handleBundleFile(fileOf(serializeProofBundle(bundle)));
  assert.equal(doc.getElementById("pbError").style.display, "block");
  assert.match(doc.getElementById("pbError").textContent, /does not support/);
  assert.equal(doc.getElementById("pbOk").style.display, "none");
});

test("UI, flag ON: script/HTML in a bundle renders as inert text, never as markup", async () => {
  const { window, doc, ui } = await mount({ enabled: true });
  const { bundle } = await realBundle();
  bundle.record.public_label = '<script>window.__pwned=1</script><img src=x onerror=alert(1)>';
  bundle.limitations.push('<script>window.__pwned2=1</script>');
  bundle.record.product = "<iframe src=evil></iframe>";

  await ui.handleBundleFile(fileOf(serializeProofBundle(bundle)));
  const panel = doc.getElementById("pbResult");

  assert.equal(window.__pwned, undefined, "no script from a bundle may execute");
  assert.equal(window.__pwned2, undefined);
  assert.equal(panel.querySelectorAll("script").length, 0);
  assert.equal(panel.querySelectorAll("img").length, 0);
  assert.equal(panel.querySelectorAll("iframe").length, 0);
  assert.ok(!panel.innerHTML.includes("<script"), "no injected markup anywhere in the panel");
});

test("UI, flag ON: import touches NO network primitive", async () => {
  const { window, ui, doc } = await mount({ enabled: true });
  /** @type {string[]} */
  const calls = [];
  const boom = (what) => (...a) => {
    calls.push(`${what}(${String(a[0])})`);
    throw new Error("network during import");
  };
  Object.defineProperty(window, "fetch", { value: boom("fetch"), configurable: true });
  Object.defineProperty(window, "XMLHttpRequest", { value: boom("xhr"), configurable: true });
  Object.defineProperty(window.navigator, "sendBeacon", {
    value: (...a) => {
      calls.push(`sendBeacon(${String(a[0])})`);
      return true;
    },
    configurable: true,
  });

  const { text } = await realBundle();
  await ui.handleBundleFile(fileOf(text));

  assert.equal(doc.getElementById("pbOk").style.display, "block", "it still verified");
  assert.deepEqual(calls, [], `import touched the network: ${calls.join(", ")}`);
});

test("UI, flag ON: the online button is explicit — nothing leaves until it is pressed", async () => {
  /** @type {string[]} */
  const codes = [];
  const onlineCheck = async (code) => {
    codes.push(code);
    return { ok: true, status: { verified: true, chain_position: 4211 } };
  };
  const { doc, ui } = await mount({ enabled: true, onlineCheck });

  const { text, bundle } = await realBundle();
  await ui.handleBundleFile(fileOf(text));
  assert.deepEqual(codes, [], "import must not call the online check");

  await ui.runOnlineStatusCheck();
  assert.deepEqual(codes, ["ZK-8H3M-2QP"], "only the public code is passed");

  const out = doc.getElementById("pbOnlineResult");
  assert.equal(out.style.display, "block");
  // Even after going online, key status must remain NOT CHECKED.
  assert.match(out.textContent, /remains NOT CHECKED/);
  assert.ok(!out.textContent.includes(bundle.signature.value));
});

/* ─── Verify your copy, from a bundle we DO stand behind ──────────────────── */

test("UI: an ungated (unrecognized-key) bundle refuses to compare a file at all", async () => {
  const { doc, ui } = await mount({ enabled: true });
  const { text } = await realBundle();
  await ui.handleBundleFile(fileOf(text));

  assert.equal(doc.getElementById("pbCopyActive").style.display, "none");
  const res = await ui.handleBundleCopyFile({ name: "x.pdf", async arrayBuffer() { return FILE.buffer; } });
  assert.equal(res, undefined, "an ungated bundle must never compare a file");
});

/**
 * The MATCH path needs a bundle whose key IS recognized. We cannot sign with the
 * production private key (we do not have it, and must not), so we temporarily
 * register the throwaway key in the pinning registry — which also proves the
 * registry is the single place key trust is decided. Always removed afterwards.
 */
async function withRegisteredKey(publicKeyXY, keyId, fn) {
  KNOWN_SIGNING_KEYS[keyId] = {
    key_id: keyId,
    algorithm: "ECDSA-P256",
    public_key_xy: publicKeyXY,
    label: "test-only key",
    source: "ui.test.mjs",
  };
  try {
    return await fn();
  } finally {
    delete KNOWN_SIGNING_KEYS[keyId];
  }
}

test("UI: a recognized-key bundle unlocks Verify your copy and reports a local MATCH", async () => {
  const keys = await makeKeypair();
  const KEY_ID = "TEST-SVC-UI";
  await withRegisteredKey(keys.publicKeyXY, KEY_ID, async () => {
    const { doc, ui } = await mount({ enabled: true });
    const api = await makeStampedRecord({ file: FILE, keys, deviceId: KEY_ID });
    const rec = mapApiResponse(api);
    const result = await verifyRecord(rec);
    const bundle = await buildProofBundle(rec, result);

    await ui.handleBundleFile(fileOf(serializeProofBundle(bundle)));

    // Now the key IS recognized, so the badge flips and comparison unlocks.
    const labels = [...doc.getElementById("pbBadges").children].map((el) => el.textContent);
    assert.ok(labels.includes("SIGNING KEY RECOGNIZED"), `got ${JSON.stringify(labels)}`);
    assert.equal(doc.getElementById("pbCopyBlocked").style.display, "none");
    assert.equal(doc.getElementById("pbCopyActive").style.display, "block");

    // The matching file.
    const res = await ui.handleBundleCopyFile({
      name: "invoice.pdf",
      async arrayBuffer() {
        return FILE.buffer.slice(FILE.byteOffset, FILE.byteOffset + FILE.byteLength);
      },
    });
    assert.equal(res.outcome, "MATCH");
    assert.equal(doc.getElementById("pbCopyTitle").textContent, "FILE COPY MATCHED LOCALLY");
    assert.match(doc.getElementById("pbCopyBody").textContent, /same SHA-256 fingerprint/);
    assert.match(doc.getElementById("pbCopyHashes").textContent, new RegExp(bundle.file_fingerprint.value));
    // The claim must stay within scope: bytes only.
    assert.ok(!doc.getElementById("pbCopyBody").textContent.match(/who (created|sent|owns)/i));

    // ...and a modified file must fail.
    const modified = new Uint8Array(FILE);
    modified[0] ^= 0x01;
    const bad = await ui.handleBundleCopyFile({
      name: "invoice-modified.pdf",
      async arrayBuffer() {
        return modified.buffer;
      },
    });
    assert.equal(bad.outcome, "MISMATCH");
    assert.equal(doc.getElementById("pbCopyTitle").textContent, "FILE COPY DOES NOT MATCH");
  });
});

test("UI: the local filename is displayed but never leaves the browser", async () => {
  const keys = await makeKeypair();
  const KEY_ID = "TEST-SVC-UI2";
  await withRegisteredKey(keys.publicKeyXY, KEY_ID, async () => {
    /** @type {string[]} */
    const codes = [];
    const { doc, ui, window } = await mount({
      enabled: true,
      onlineCheck: async (c) => {
        codes.push(c);
        return { ok: true, status: {} };
      },
    });
    Object.defineProperty(window, "fetch", {
      value: () => {
        throw new Error("no network allowed here");
      },
      configurable: true,
    });

    const api = await makeStampedRecord({ file: FILE, keys, deviceId: KEY_ID });
    const rec = mapApiResponse(api);
    const bundle = await buildProofBundle(rec, await verifyRecord(rec));
    await ui.handleBundleFile(fileOf(serializeProofBundle(bundle)));

    const PRIVATE_NAME = "MY-PRIVATE-TAXES-2026.pdf";
    await ui.handleBundleCopyFile({
      name: PRIVATE_NAME,
      async arrayBuffer() {
        return FILE.buffer.slice(FILE.byteOffset, FILE.byteOffset + FILE.byteLength);
      },
    });
    // Shown locally...
    assert.equal(doc.getElementById("pbCopyDropText").textContent, PRIVATE_NAME);
    // ...and not transmitted, even when the user then goes online.
    await ui.runOnlineStatusCheck();
    assert.deepEqual(codes, [api.short_code], "only the public code travels");
    assert.ok(!codes.join("|").includes(PRIVATE_NAME));
  });
});

test("UI: the page markup and the controller agree on every element id it touches", async () => {
  // A cheap contract test: if index.html renames an id, the controller silently
  // stops working. Assert every id the controller reaches for exists.
  const html = await readFile(INDEX, "utf8");
  const dom = new JSDOM(html);
  const src = await readFile(new URL("../proof-bundle-ui.js", import.meta.url), "utf8");
  const ids = [...src.matchAll(/\$\("([a-zA-Z0-9_]+)"\)/g)].map((m) => m[1]);
  assert.ok(ids.length > 10, "expected the controller to reference many ids");
  for (const id of new Set(ids)) {
    assert.ok(dom.window.document.getElementById(id), `index.html is missing #${id}`);
  }
});
