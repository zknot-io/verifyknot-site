// Full-page render test (jsdom) — exercises the REAL inline glue in index.html
// (renderVerdict/renderBip/onCopyFileChosen), not a reimplementation. Loads the
// page, mocks the rail fetch with a BIP record, runs verify(), and asserts the
// witness card renders VALID with the right fields; then simulates selecting the
// original copy (-> stays VALID) and an altered copy (-> flips to INVALID).
//
// Run:  node tests/test_bip_page.mjs
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import assert from "node:assert";
import * as V from "../verifier.js";

const __dir = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dir, "..");
const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const hex = V.bytesToHex;

async function sha(b) { return hex(await subtle.digest("SHA-256", b)); }

const FILE = enc.encode("---\nslug: dishonesty-thesis\n---\n\nMost fraud isn't a hack.\n");

async function makeRecord(fileBytes) {
  const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const rawPub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
  const contentHash = await sha(fileBytes);
  const aid = "11111111-2222-3333-4444-555555555555";
  const signedAt = "2026-07-24T15:00:00+00:00";
  const payload = enc.encode(["ZKNOT-BIP1", aid, "WM-0001", contentHash, "dishonesty-thesis", "2", signedAt].join("\n"));
  const challenge = await sha(payload);
  const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, payload));
  return {
    short_code: "ZK-BIP-0002", artifact_type: "ZKEY_SIGN", device_id: "WM-0001",
    session_id: null, signed_at: signedAt, chain_position: 42, chain_prev_hash: "ab".repeat(32),
    artifact_hash: "cd".repeat(32), challenge_hash: challenge,
    signature: hex(sig), public_key: hex(rawPub),
    key_anchored: true, signature_valid: true, verified: true,
    metadata: {
      record_version: "1.0", record_kind: "bip_post", identity_tier: "WITNESSMARK-DEVICE",
      presence_binding_type: "none", content_binding_type: "none",
      signed_payload_hex: hex(payload), content_sha256: contentHash,
      artifact_name: "wk01_dishonesty-thesis.md", post_id: "dishonesty-thesis", version: 2,
      version_history: [
        { version: 1, content_sha256: "ee".repeat(32), short_code: "ZK-BIP-0001", signed_at: "2026-07-17T15:00:00+00:00" },
        { version: 2, content_sha256: contentHash, short_code: "ZK-BIP-0002", signed_at: signedAt },
      ],
      post_url: "https://zknot.io/bip/dishonesty-thesis",
    },
  };
}

function buildDom(html, record) {
  // Strip the ESM import; the verifier functions are injected as window globals.
  const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1]
    .replace(/import\s+\{[^}]*\}\s+from\s+['"][^'"]+['"];/, "");
  const dom = new JSDOM(html.replace(/<script type="module">[\s\S]*?<\/script>/, ""),
    { url: "https://verifyknot.io/v/ZK-BIP-0002", runScripts: "outside-only" });
  const w = dom.window;
  // No need to inject crypto: the imported verifier fns bound node's WebCrypto at
  // load, and the inline glue never touches crypto.subtle directly.
  for (const k of ["verifyRecord", "mapApiResponse", "fileComparisonGate", "compareLocalFile"]) w[k] = V[k];
  w.fetch = async () => ({ ok: true, json: async () => record });
  // Prevent the URL auto-run from firing before we call verify() deliberately.
  const noAuto = script.replace(/const m = window\.location\.pathname[\s\S]*$/, "");
  w.eval(noAuto);
  return dom;
}

async function run() {
  const html = readFileSync(resolve(root, "index.html"), "utf8");
  const record = await makeRecord(FILE);
  const dom = buildDom(html, record);
  const w = dom.window, $ = (id) => w.document.getElementById(id);

  await w.verify("ZK-BIP-0002");
  // let the async verifyRecord()/renderVerdict microtasks settle
  await new Promise((r) => setTimeout(r, 50));

  assert.equal($("bipCard").style.display, "block", "witness card shown");
  assert.equal($("bcBadge").textContent, "VALID", "verdict VALID for anchored WM-0001 record");
  assert.equal($("bcWitness").textContent, "WM-0001");
  assert.match($("bcSignedAt").textContent, /2026-07-24T15:00:00/);
  assert.equal($("bcContentHash").textContent, record.metadata.content_sha256);
  assert.equal($("bcVersion").textContent, "v2");
  assert.match($("bcScope").textContent, /does not prove/i);
  assert.match($("bcScope").textContent, /witness, not a gate/i);
  assert.equal($("bcPostLink").querySelector("a").href, "https://zknot.io/bip/dishonesty-thesis");
  assert.equal($("bcHistory").style.display, "block", "version history shown (2 versions)");
  assert.ok($("bcHistoryList").textContent.includes("v1"), "history lists v1");
  assert.equal($("bcCopyPanel").style.display, "block", "verify-your-copy panel enabled");
  console.log("ok: witness card renders VALID with witness/time/hash/version/scope/postlink/history");

  // Simulate selecting the ORIGINAL copy -> MATCH -> VALID.
  await w.onCopyFileChosen(new w.Blob([FILE]));
  await new Promise((r) => setTimeout(r, 20));
  assert.match($("bcCopyResult").textContent, /MATCH/);
  assert.equal($("bcBadge").textContent, "VALID");
  console.log("ok: original copy -> MATCH, badge stays VALID");

  // Simulate selecting an ALTERED copy -> MISMATCH -> INVALID.
  const altered = Uint8Array.from(FILE); altered[10] ^= 0x01;
  await w.onCopyFileChosen(new w.Blob([altered]));
  await new Promise((r) => setTimeout(r, 20));
  assert.match($("bcCopyResult").textContent, /INVALID/);
  assert.equal($("bcBadge").textContent, "INVALID");
  console.log("ok: ACCEPTANCE (page) — altered copy -> MISMATCH, badge flips to INVALID");

  console.log("\nBIP PAGE RENDER TESTS PASSED");
}

run().catch((e) => { console.error(e); process.exit(1); });
