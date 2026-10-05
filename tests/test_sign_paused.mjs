// /sign with issuing paused (DECISION-SIGN-ISSUANCE-SECURITY-001, 2026-10-05).
// Loads the REAL inline script from sign/index.html in jsdom and checks that:
//   1. a valid device signature renders "checked on this computer" and NO request is sent;
//   2. a bad signature renders "Not signed" and NO request is sent;
//   3. the page carries the paused notice, and no copy promises a ZK number.
//
// Run:  node tests/test_sign_paused.mjs
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import assert from "node:assert";
import * as V from "../verifier.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const subtle = globalThis.crypto.subtle;
const hex = V.bytesToHex;

const html = readFileSync(resolve(root, "sign/index.html"), "utf8");
const script = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1]
  .replace(/^\s*import .*$/m, "");

function buildDom() {
  const dom = new JSDOM(html.replace(/<script type="module">[\s\S]*?<\/script>/, ""),
    { url: "https://verifyknot.io/sign/", runScripts: "outside-only" });
  const w = dom.window;
  w.verifyRecord = V.verifyRecord;
  w.bytesToHex = V.bytesToHex;
  w.__sent = 0;
  w.fetch = async () => { w.__sent++; throw new Error("network must not be used"); };
  // One eval: the script's const/let bindings are not visible to a second eval here,
  // so the test hook that seeds them is appended to the same script.
  w.eval(script + `
    window.__seed = (k, xy, d, c) => { BUNDLED_PUBKEYS[k] = xy; docHashHex = d; challengeHex = c; };
    window.onSignature = onSignature;`);
  return dom;
}

async function deviceSign(kp, docHash) {
  // SelfKnot signs SHA-256(docHash) as a digest; WebCrypto hashes the data, so sign docHash.
  return hex(new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, docHash)));
}

async function run() {
  const doc = new TextEncoder().encode("DEMO PROP - NOT A REAL TRANSACTION\n");
  const docHash = new Uint8Array(await subtle.digest("SHA-256", doc));
  const challenge = new Uint8Array(await subtle.digest("SHA-256", docHash));
  const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const xy = hex(new Uint8Array(await subtle.exportKey("raw", kp.publicKey))).slice(2);
  const serial = "0123AAAABBBBCCCCEE";

  for (const [label, good] of [["valid signature", true], ["bad signature", false]]) {
    const dom = buildDom(), w = dom.window, $ = (id) => w.document.getElementById(id);
    w.__seed(serial.toLowerCase(), xy, hex(docHash), hex(challenge));
    let sig = await deviceSign(kp, docHash);
    if (!good) sig = sig.slice(0, 127) + (sig[127] === "0" ? "1" : "0");
    await w.onSignature(serial, sig);
    await new Promise((r) => setTimeout(r, 20));
    const out = $("result").textContent;
    if (good) {
      assert.match(out, /checked on this computer/, `${label}: verdict`);
      assert.match(out, /No public record was created and nothing was\s+sent/, `${label}: says nothing sent`);
      assert.ok(!/ZK-[0-9A-Z]{4}/.test(out), `${label}: no ZK number shown`);
    } else {
      assert.match(out, /Not signed/, `${label}: refused`);
    }
    assert.equal(w.__sent, 0, `${label}: no network request`);
    console.log(`PASS  ${label}`);
  }

  const page = buildDom().window.document.body.textContent;
  assert.match(page, /Record issuing is paused/, "paused notice present");
  assert.ok(!/get a verifiable ZK number/.test(page), "old promise removed");
  console.log("PASS  paused notice present, old promise gone");

  const retail = readFileSync(resolve(root, "retail/index.html"), "utf8");
  assert.ok(!/You get a\s+short code back/.test(retail), "/retail no longer promises a short code");
  assert.ok(!/They open the signing code/.test(retail), "/retail no longer tells buyers to open a signing code");
  assert.ok(!/Put both codes/.test(retail), "/retail no longer asks for both codes");
  console.log("PASS  /retail no longer promises the signing loop");
}

run().catch((e) => { console.error("FAIL ", e.message); process.exit(1); });
