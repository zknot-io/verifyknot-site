// Verify page for a device-document record (DECISION-DEVICE-ISSUANCE-001), in jsdom
// against the REAL inline script in index.html and the real verifier.js.
//
// Every claim on the card must come from the bytes the device signed. Each positive
// case has a negative control that differs only in the property under test:
//   1. registered document: VERIFIED, card shows device, tier, SHA-256 and the server
//      time WINDOW; the right file MATCHES, a changed file does NOT;
//   2. test purpose: TEST RECORD banner and badge, and the match text says "test";
//   3. a valid signature over a DIFFERENT record (artifact_id swapped) -> FAILED, no compare;
//   4. an unregistered key -> no compare offered, badge not VALID;
//   5. a decoy fingerprint in unsigned metadata is ignored;
//   6. non-canonical signed bytes (whitespace) -> FAILED.
//
// Run:  node tests/test_device_document_page.mjs
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import assert from "node:assert";
import * as V from "../verifier.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const html = readFileSync(resolve(root, "index.html"), "utf8");
const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
const importNames = script.match(/import\s*\{([^}]*)\}\s*from/)[1].split(",").map((s) => s.trim()).filter(Boolean);
const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const hex = V.bytesToHex;
const sha = async (b) => hex(new Uint8Array(await subtle.digest("SHA-256", b)));

const FILE = enc.encode("ZKNOT issuance gate test file - not a document\n");
const AID = "11111111-2222-3333-4444-555555555555";
const ZKU = "ZKU-GBT8-RAMB-TE1G";

async function makeRecord({ purpose = "document", anchored = true, payloadAid = AID, spaced = false, decoy = false } = {}) {
  const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  const fields = { artifact_id: payloadAid, artifact_type: "DEVICE_DOCUMENT", binding_version: "v4",
    content_hash: await sha(FILE), device_id: ZKU, nonce: "cd".repeat(32), purpose, session_id: "",
    signed_at: "2026-10-11T18:00:00Z" };
  let text = JSON.stringify(fields);
  if (spaced) text = JSON.stringify(fields, null, 1);
  const payload = enc.encode(text);
  const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, payload));
  return {
    short_code: "ZK-DDOC-001", artifact_id: AID, artifact_type: "DEVICE_DOCUMENT", device_id: ZKU, session_id: null,
    signed_at: "2026-10-11T18:00:00+00:00", chain_position: 150, chain_prev_hash: "ab".repeat(32),
    artifact_hash: "ef".repeat(32), challenge_hash: await sha(payload), signature: hex(sig), public_key: hex(pub),
    key_anchored: anchored, signature_valid: true, verified: anchored, identity_tier: anchored ? "KEY-REGISTERED" : "SELF-ASSERTED",
    identity_binding_type: "canonical-record",
    metadata: { record_kind: "device_document", record_version: "1.0", signed_payload_hex: hex(payload),
      presence_binding_type: "firmware-mediated", content_binding_type: "none", spend_window_seconds: 300,
      ...(decoy ? { content_sha256: "00".repeat(32), file_sha256: "00".repeat(32) } : {}) },
  };
}

async function page(record) {
  const dom = new JSDOM(html.replace(/<script type="module">[\s\S]*?<\/script>/, ""),
    { url: "https://verifyknot.io/v/ZK-DDOC-001", runScripts: "outside-only" });
  const w = dom.window;
  for (const n of importNames) w[n] = V[n];      // exactly what the page imports
  w.fetch = async () => ({ ok: true, json: async () => record });
  w.eval(script.replace(/import\s*\{[^}]*\}\s*from\s*['"][^'"]+['"];/, "").replace(/const m = window\.location\.pathname[\s\S]*$/, ""));
  await w.verify("ZK-DDOC-001");
  await new Promise((r) => setTimeout(r, 50));
  return { w, $: (id) => w.document.getElementById(id) };
}

async function choose(w, $, bytes) {
  const f = new w.File([bytes], "copy.md");
  Object.defineProperty($("ddFile"), "files", { value: [f], configurable: true });
  $("ddFile").dispatchEvent(new w.Event("change"));
  for (let i = 0; i < 50 && !/MATCH/.test($("ddCopyResult").textContent); i++) await new Promise((r) => setTimeout(r, 10));
  return $("ddCopyResult").textContent;
}

// 1 — registered document
{
  const { w, $ } = await page(await makeRecord());
  assert.equal($("rStatusText").textContent, "VERIFIED — IN YOUR BROWSER");
  assert.equal($("ddCard").style.display, "block");
  assert.equal($("ddTestBanner").style.display, "none");
  assert.equal($("ddDevice").textContent, ZKU);
  assert.equal($("ddTier").textContent, "KEY-REGISTERED");
  assert.equal($("ddHash").textContent, await sha(FILE));
  assert.equal($("ddWhen").textContent, "between 2026-10-11T18:00:00Z and 2026-10-11T18:05:00Z, by ZKNOT's server clock");
  assert.equal($("ddBadge").textContent, "VALID");
  assert.equal($("ddCopyPanel").style.display, "block");
  assert.match($("ddScope").textContent, /does NOT prove: that the device showed the document/);
  assert.match(await choose(w, $, FILE), /^✓ MATCH — your file is byte-for-byte/);
  assert.match(await choose(w, $, enc.encode("ZKNOT issuance gate test file - not a document!\n")), /NO MATCH/);
  assert.equal($("ddBadge").textContent, "INVALID");
  console.log("PASS registered document: verified, window shown, match and mismatch");
}

// 2 — test purpose
{
  const { w, $ } = await page(await makeRecord({ purpose: "test" }));
  assert.equal($("ddTestBanner").style.display, "block");
  assert.equal($("ddTitle").textContent, "Test record from a ZKNOT device");
  assert.equal($("ddBadge").textContent, "VALID · TEST");
  assert.match($("rHeadline").textContent, /^TEST RECORD — not a document\./);
  assert.match(await choose(w, $, FILE), /this is the issuance test file/);
  console.log("PASS test purpose: labelled from the signed bytes");
}

// 3 — signature over a different record
{
  const { $ } = await page(await makeRecord({ payloadAid: "99999999-2222-3333-4444-555555555555" }));
  assert.equal($("rStatusText").textContent, "VERIFICATION FAILED");
  assert.equal($("ddCopyPanel").style.display, "none");
  assert.equal($("ddHash").textContent, "—");
  console.log("PASS signature over a different record: FAILED, nothing to compare");
}

// 4 — unregistered key
{
  const { $ } = await page(await makeRecord({ anchored: false }));
  assert.equal($("rStatusText").textContent, "VERIFIED — IN YOUR BROWSER");   // the math still checks
  assert.equal($("ddCopyPanel").style.display, "none");
  assert.match($("ddCopyDisabled").textContent, /not one ZKNOT vouches for/);
  assert.notEqual($("ddBadge").textContent, "VALID");
  assert.match($("rHeadline").textContent, /whose key ZKNOT does not vouch for/);
  console.log("PASS unregistered key: no compare, not VALID");
}

// 5 — decoy unsigned fingerprint
{
  const { w, $ } = await page(await makeRecord({ decoy: true }));
  assert.equal($("ddHash").textContent, await sha(FILE));
  assert.match(await choose(w, $, FILE), /MATCH/);
  console.log("PASS decoy metadata fingerprint ignored");
}

// 6 — non-canonical bytes
{
  const { $ } = await page(await makeRecord({ spaced: true }));
  assert.equal($("rStatusText").textContent, "VERIFICATION FAILED");
  console.log("PASS non-canonical signed bytes: FAILED");
}
console.log("ALL PASS test_device_document_page");
