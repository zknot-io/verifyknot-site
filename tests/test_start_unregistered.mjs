// /start: an OPTIGA device (Vitni Plus / Ostensor) whose key is NOT on the rail is challenged and
// verified as SELF-ASSERTED, instead of being turned away (operator, 2026-10-05). A registered
// key keeps the registry's tier. Runs the REAL inline script from start/index.html in jsdom.
//
// Run:  node tests/test_start_unregistered.mjs
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import assert from "node:assert";
import * as V from "../verifier.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const subtle = globalThis.crypto.subtle;
const hex = V.bytesToHex;
const html = readFileSync(resolve(root, "start/index.html"), "utf8");
const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1].replace(/^\s*import .*$/m, "");

function rawToDer(raw) {
  const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i);
    if (b[0] & 0x80) b = Uint8Array.of(0, ...b); return Uint8Array.of(0x02, b.length, ...b); };
  const r = int(raw.slice(0, 32)), s = int(raw.slice(32));
  return Uint8Array.of(0x30, r.length + s.length, ...r, ...s);
}

async function scenario({ registered, tamper }) {
  const dom = new JSDOM(html.replace(/<script type="module">[\s\S]*?<\/script>/, ""),
    { url: "https://verifyknot.io/start/", runScripts: "outside-only" });
  const w = dom.window;
  w.verifyRecord = V.verifyRecord; w.bytesToHex = V.bytesToHex;
  w.eval(script + `
    window.__setPayload = (p, c) => { currentPayloadHex = p; currentChallengeHex = c; };
    window.__state = () => ostensorState;`);

  const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pubHex = hex(new Uint8Array(await subtle.exportKey("raw", kp.publicKey)));
  let challenged = false;
  w.detectOstensor = async () => true;
  w.ostensorIdentity = async () => ({ pubHex });
  w.resolveByKey = async () => registered
    ? { found: true, rec: { identity_tier: "KEY-REGISTERED", short_code: "ZK-TEST-001", device_id: "VIT-P1-TEST" } }
    : { found: false };
  w.ostensorChallenge = async () => { challenged = true; };

  await w.startFlow();
  assert.ok(challenged, "device was challenged");
  assert.equal(w.__state().registered, registered, "registered flag");

  const payload = crypto.getRandomValues(new Uint8Array(32));
  const challenge = new Uint8Array(await subtle.digest("SHA-256", payload));
  w.__setPayload(hex(payload), hex(challenge));
  const raw = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, payload));
  if (tamper) raw[40] ^= 1;
  await w.onOstensorSignature(hex(rawToDer(raw)));
  await new Promise((r) => setTimeout(r, 30));
  return w.document.getElementById("result").textContent.replace(/\s+/g, " ");
}

async function run() {
  let out = await scenario({ registered: false, tamper: false });
  assert.match(out, /VERIFIED/, "unregistered: verified");
  assert.match(out, /SELF-ASSERTED/, "unregistered: SELF-ASSERTED");
  assert.match(out, /NOT A REGISTERED UNIT — SELF-ASSERTED/, "unregistered: note shown");
  assert.match(out, /not registered with ZKNOT either/, "unregistered: chain note says so");
  assert.ok(!/registry match/.test(out), "unregistered: no registry-match wording");
  assert.ok(!/KEY-REGISTERED/.test(out), "unregistered: no KEY-REGISTERED");
  console.log("PASS  unregistered OPTIGA key: challenged, VERIFIED, SELF-ASSERTED, labelled");

  out = await scenario({ registered: false, tamper: true });
  assert.match(out, /VERIFICATION FAILED/, "tampered: VERIFICATION FAILED shown");
  console.log("PASS  unregistered OPTIGA key, tampered signature: not verified");

  out = await scenario({ registered: true, tamper: false });
  assert.match(out, /VERIFIED/, "registered: verified");
  assert.match(out, /KEY-REGISTERED/, "registered: registry tier");
  assert.ok(!/NOT A REGISTERED UNIT/.test(out), "registered: no unregistered note");
  assert.match(out, /registry match/, "registered: chain note unchanged");
  console.log("PASS  registered key: unchanged behaviour");
}
run().catch((e) => { console.error("FAIL ", e.message); process.exit(1); });
