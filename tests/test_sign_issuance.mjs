// /sign with device issuance (DECISION-DEVICE-ISSUANCE-001). Supersedes
// test_sign_paused.mjs, whose subject (issuing paused) no longer exists.
//
// Runs the REAL inline script from sign/index.html in jsdom against a simulated
// SelfKnot on a fake serial port. The device behaves like the firmware of record:
// Ctrl-C/Ctrl-D prints "BOOT serial=… selftest=PASS"; a 64-hex line followed by a
// "press" prints "SIG <serial> <digest> <r||s>" over THAT digest, verbatim.
// It signs with Python `cryptography` (Prehashed), because the device signs a raw
// 32-byte digest and WebCrypto cannot.
//
// Asserts, each with a control that differs only in the property under test:
//   1. registered unit: challenge requested, device signs the v4 record, the POST
//      carries exactly the expected fields (no file name, no metadata), and the
//      record view shows the code;
//   2. purpose: the test box puts purpose:"test" in the signed bytes;
//   3. unregistered unit (by-key 404): NO issuance request at all, local check only;
//   4. issuance switched off (503): no device-sign POST, local check only;
//   5. cross-language: zknot-api's own Python computes the same v4 hash the page did
//      (runs only when ZKNOT_API_DIR points at a zknot-api checkout).
//
// Run:  node tests/test_sign_issuance.mjs      (ZKNOT_API_DIR=~/zknot-api for check 5)
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import assert from "node:assert";
import * as V from "../verifier.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const html = readFileSync(resolve(root, "sign/index.html"), "utf8");
const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
const importNames = [...script.matchAll(/import\s*\{([^}]*)\}\s*from/g)]
  .flatMap((m) => m[1].split(",").map((s) => s.trim()).filter(Boolean));
const body = script.replace(/^\s*import .*$/gm, "");

const PY = `
import sys, json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
cmd = sys.argv[1]
if cmd == "keygen":
    k = ec.generate_private_key(ec.SECP256R1())
    n = k.public_key().public_numbers()
    print(json.dumps({"pem": k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
                      "xy": f"{n.x:064x}{n.y:064x}"}))
else:
    k = serialization.load_pem_private_key(sys.stdin.read().encode(), None)
    r, s = decode_dss_signature(k.sign(bytes.fromhex(sys.argv[2]), ec.ECDSA(Prehashed(hashes.SHA256()))))
    print(f"{r:064x}{s:064x}")
`;
const py = (args, input) => {
  const r = spawnSync("python3", ["-I", "-c", PY, ...args], { input, encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout.trim();
};

const SERIAL = "0123ABCDEF01234567";
const ZKU = "ZKU-GBT8-RAMB-TE1G";
const CH = { nonce: "ab".repeat(32), artifact_id: "11111111-2222-3333-4444-555555555555",
  signed_at: "2026-10-11T18:00:00Z", expires_at: "2026-10-11T18:05:00Z",
  artifact_type: "DEVICE_DOCUMENT", binding_version: "v4", spend_window_seconds: 300 };

function fakeSelfKnot(w, key) {
  let emit;
  const readable = new ReadableStream({ start(c) { emit = (s) => c.enqueue(new TextEncoder().encode(s)); } });
  let buf = "";
  const writable = new WritableStream({
    write(chunk) {
      const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
      if (bytes.length === 1 && bytes[0] === 0x04) { setTimeout(() => emit(`BOOT serial=${SERIAL} selftest=PASS\r\n`), 5); return; }
      if (bytes.length === 1 && bytes[0] === 0x03) return;
      buf += new TextDecoder().decode(bytes);
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim(); buf = buf.slice(nl + 1);
        if (/^[0-9a-fA-F]{64}$/.test(line) && !w.__signed) {
          w.__signed = line;                         // the "press": sign once
          const sig = py(["sign", line], key.pem);
          setTimeout(() => emit(`SIG ${SERIAL} ${line} ${sig}\r\n`), 5);
        }
      }
    },
  });
  return { open: async () => {}, close: async () => {}, readable, writable };
}

function buildDom({ byKey, challenge }) {
  const dom = new JSDOM(html.replace(/<script type="module">[\s\S]*?<\/script>/, ""),
    { url: "https://verifyknot.io/sign/", runScripts: "outside-only" });
  const w = dom.window;
  for (const n of importNames) {
    if (n in V) w[n] = V[n];
  }
  w.transport = () => "serial";
  Object.assign(w, { TextEncoder, TextDecoder, ReadableStream, WritableStream });
  Object.defineProperty(w, "crypto", { value: globalThis.crypto });
  w.__calls = [];
  w.fetch = async (url, opts = {}) => {
    w.__calls.push({ url, opts });
    if (url.includes("/v1/units/by-key/")) return byKey;
    if (url.endsWith("/v1/issuance/challenge")) return challenge;
    if (url.endsWith("/v1/issuance/device-sign")) {
      return { ok: true, status: 201, json: async () => ({ short_code: "ZK-TEST-001", artifact_type: "DEVICE_DOCUMENT" }) };
    }
    throw new Error("unexpected fetch " + url);
  };
  return dom;
}

const ok = (j) => ({ ok: true, status: 200, json: async () => j });
const status = (n) => ({ ok: false, status: n, json: async () => ({ detail: `HTTP ${n}` }) });

async function run({ byKey, challenge, test = false }) {
  const key = JSON.parse(py(["keygen"]));
  const dom = buildDom({ byKey, challenge });
  const w = dom.window, $ = (id) => w.document.getElementById(id);
  w.pickPort = async () => fakeSelfKnot(w, key);
  w.eval(body + `\nwindow.__seed = (k, xy) => { BUNDLED_PUBKEYS[k] = xy; };`);
  w.__seed(SERIAL.toLowerCase(), key.xy);
  if (test) $("isTest").checked = true;
  const file = new w.File([new TextEncoder().encode("ZKNOT issuance gate test file - not a document\n")], "secret-name.md");
  Object.defineProperty($("fileInput"), "files", { value: [file] });
  $("fileInput").dispatchEvent(new w.Event("change"));
  $("connectBtn").click();
  for (let i = 0; i < 200 && !/Record created|checked on this computer|Not signed/.test($("result").textContent); i++) {
    await new Promise((r) => setTimeout(r, 10));
  }
  return { w, $, key };
}

const fileSha = V.bytesToHex(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256",
  new TextEncoder().encode("ZKNOT issuance gate test file - not a document\n"))));

// 1 + 2 + 5 — registered unit, document and test purpose
for (const test of [false, true]) {
  const { w, $ } = await run({ byKey: ok({ artifact_type: "SELFKNOT_UNIT", device_id: ZKU }), challenge: ok(CH), test });
  assert.match($("result").textContent, test ? /Test record created/ : /Record created/, $("result").textContent);
  assert.match($("result").textContent, /ZK-TEST-001/);
  const post = w.__calls.find((c) => c.url.endsWith("/device-sign"));
  assert.ok(post, "device-sign POST sent");
  const sent = JSON.parse(post.opts.body);
  assert.deepEqual(Object.keys(sent).sort(),
    ["artifact_id", "challenge_hash", "content_hash", "device_id", "nonce", "public_key", "purpose", "signature"]);
  assert.ok(!post.opts.body.includes("secret-name"), "the file name never leaves the page");
  assert.equal(sent.purpose, test ? "test" : "document");
  assert.equal(sent.content_hash, fileSha);
  assert.equal(sent.device_id, ZKU);
  assert.equal(w.__signed, sent.challenge_hash, "the device signed the v4 record digest, not the file");
  const rec = JSON.stringify(Object.fromEntries(Object.entries({
    artifact_id: CH.artifact_id, artifact_type: "DEVICE_DOCUMENT", binding_version: "v4", content_hash: fileSha,
    device_id: ZKU, nonce: CH.nonce, purpose: sent.purpose, session_id: "", signed_at: CH.signed_at,
  }).sort()));
  const expect = V.bytesToHex(new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(rec))));
  assert.equal(sent.challenge_hash, expect);

  if (process.env.ZKNOT_API_DIR) {
    const r = spawnSync("python3", ["-c", `
import sys; sys.path.insert(0, sys.argv[1])
from app.services.record_binding import device_document_challenge_hash as h
print(h(artifact_id=sys.argv[2], artifact_type="DEVICE_DOCUMENT", device_id=sys.argv[3], signed_at=sys.argv[4],
        content_hash=sys.argv[5], nonce=sys.argv[6], purpose=sys.argv[7]))`,
      process.env.ZKNOT_API_DIR, CH.artifact_id, ZKU, CH.signed_at, fileSha, CH.nonce, sent.purpose], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), sent.challenge_hash, "page and API agree on the v4 bytes");
    console.log(`PASS cross-language v4 hash (purpose=${sent.purpose})`);
  }
  console.log(`PASS registered unit, purpose=${sent.purpose}`);
}

// 3 — unregistered: no issuance traffic at all
{
  const { w, $ } = await run({ byKey: status(404), challenge: ok(CH) });
  assert.match($("result").textContent, /checked on this computer/);
  assert.ok(!w.__calls.some((c) => c.url.includes("/v1/issuance/")), "no issuance request for an unregistered unit");
  assert.match($("identity").textContent, /not registered/);
  console.log("PASS unregistered unit: local check only, nothing sent to issuance");
}

// 4 — switched off: challenge refused, nothing signed into a record
{
  const { w, $ } = await run({ byKey: ok({ artifact_type: "SELFKNOT_UNIT", device_id: ZKU }), challenge: status(503) });
  assert.match($("result").textContent, /checked on this computer/);
  assert.ok(!w.__calls.some((c) => c.url.endsWith("/device-sign")), "no device-sign POST when issuing is off");
  assert.match($("identity").textContent, /switched off/);
  console.log("PASS issuing switched off: local check only");
}
console.log("ALL PASS test_sign_issuance");
process.exit(0);
