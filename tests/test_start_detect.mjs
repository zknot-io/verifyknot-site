// /start device detection (operator, 2026-10-15). Runs the REAL inline script from
// start/index.html in jsdom against simulated devices that speak the firmware of record:
//
//   1. Vitni Plus that misses the PING window and rejects the bare challenge with
//      "ERR fmt (... PING | ARM <64hex> ...)": the page must switch to ARM. This is the
//      bench failure: before the fix ARM was never sent and the press was REFUSED NOT ARMED.
//   2. Vitni Plus whose PONG lands after the 1800 ms window: the late PONG switches it.
//   3. plain Vitni (bring-up: SIGN / SIGNAUTH, no ARM): stop, say it cannot be verified here,
//      and stop resending. It is NOT armed and NOT asked to SIGN (that firmware has no press gate).
//   4. control — SelfKnot (never prints ERR fmt or PONG): stays on the SelfKnot path, no ARM.
//   5. Ostensor whose bare "ERR fmt" lists nothing: a second PING decides, and it is answered.
//   6. an armed OPTIGA session ignores a stray "ERR fmt" (no re-detection, no teardown).
//
// Run:  node tests/test_start_detect.mjs
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import assert from "node:assert";
import * as V from "../verifier.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const html = readFileSync(resolve(root, "start/index.html"), "utf8");
const moduleSrc = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
const imports = moduleSrc.match(/import\s*\{([^}]*)\}\s*from\s*"\/verifier\.js"/)[1]
  .split(",").map((x) => x.trim()).filter(Boolean);
const script = moduleSrc.replace(/^\s*import .*$/gm, "");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const PLUS_ERR = "ERR fmt (ID PINS SCAN SERST SE CERT BTN LSE STATE DISARM LED LEDON LEDOFF LED0-4 LASTSIG E0F3? PING | ARM <64hex> | META <4hex> | DATA <4hex>)";
const VITNI_ERR = "ERR fmt (ID PINS SCAN INFO CONFIG BTN LED LEDON LEDOFF LED0-3 SLEEP SIGN <64hex> | SIGNAUTH <64hex> | PROV SECRET <64hex> | PROV READ/NONCE/SAVE/FORGET/STATUS, PROV WRITECFG/LOCKCFG/GENKEY/LOCKDATA <18hex serial>)";

// A certificate-shaped DER carrying a P-256 key, as the page parses it (see test_start_unregistered).
async function certHex() {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  const pub = V.bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)));
  const spki = "3059301306072a8648ce3d020106082a8648ce3d03010703420004" + pub.slice(2);
  const tbs = "3003020102" + spki;
  const len = (n) => n < 128 ? n.toString(16).padStart(2, "0") : "81" + n.toString(16).padStart(2, "0");
  const tbsSeq = "30" + len(tbs.length / 2) + tbs;
  return "C000000000000000" + "00" + "30" + len(tbsSeq.length / 2) + tbsSeq;
}

// device(cmd, reply) decides how the simulated firmware answers each line the page sends.
async function run(device, waitMs) {
  const dom = new JSDOM(html.replace(/<script type="module">[\s\S]*?<\/script>/, ""),
    { url: "https://verifyknot.io/start/", runScripts: "outside-only" });
  const w = dom.window;
  for (const n of imports) w[n] = V[n];
  w.transport = () => "serial";
  w.pickPort = async () => { throw new Error("no port in this test"); };
  Object.defineProperty(w, "crypto", { value: globalThis.crypto });
  w.eval(script + `\nwindow.__state = () => ostensorState;`);
  const sent = [];
  w.sendLine = async (cmd) => {
    sent.push(cmd);
    device(cmd, (line, ms = 5) => setTimeout(() => w.handleLine(line), ms));
  };
  w.resolveByKey = async () => ({ found: false });
  w.startFlow();
  await sleep(waitMs);
  if (w._resendTimer) clearInterval(w._resendTimer);
  const text = (id) => w.document.getElementById(id).textContent.replace(/\s+/g, " ");
  return { sent, state: w.__state(), result: text("result") };
}

const isHex = (c) => /^[0-9a-f]{64}$/.test(c);
const cert = await certHex();

// 1 — PONG lost; the device's ERR fmt names ARM
{
  const r = await run((cmd, reply) => {
    if (cmd === "PING") return;                         // the reply never lands
    if (isHex(cmd)) return reply(PLUS_ERR);
    if (cmd === "CERT") return reply("CERT=" + cert);
    if (cmd.startsWith("ARM ")) return reply("ARMED - press CONFIRM");
  }, 2600);
  assert.ok(r.sent.some((c) => c.startsWith("ARM ")), "ARM was sent: " + r.sent.join(" | "));
  assert.equal(r.state.is, true);
  assert.equal(r.state.armed, true, "the device is armed and waiting for the press");
  assert.equal(r.sent.filter(isHex).length, 1, "no more bare challenges after the switch");
  console.log("PASS missed PONG + ERR fmt listing ARM: switched, ARM sent, armed");
}

// 1b — a late ERR fmt reply racing the ARM is not mistaken for the device refusing ARM
{
  const r = await run((cmd, reply) => {
    if (cmd === "PING") return;
    if (isHex(cmd)) { reply(PLUS_ERR); return reply(PLUS_ERR, 60); }   // a second, late copy
    if (cmd === "CERT") return reply("CERT=" + cert);
    if (cmd.startsWith("ARM ")) return reply("ARMED - press CONFIRM", 120);
  }, 2600);
  assert.equal(r.state.armed, true, "late ERR fmt did not abort the ARM");
  assert.ok(!/DEVICE DID NOT ARM/.test(r.result));
  console.log("PASS late ERR fmt during ARM: still armed");
}

// 2 — PONG arrives after the 1800 ms window
{
  const r = await run((cmd, reply) => {
    if (cmd === "PING") return reply("PONG", 2000);
    if (isHex(cmd)) return;                              // still mid-boot, says nothing
    if (cmd === "CERT") return reply("CERT=" + cert);
    if (cmd.startsWith("ARM ")) return reply("ARMED - press CONFIRM");
  }, 2600);
  assert.ok(r.sent.some((c) => c.startsWith("ARM ")), "ARM was sent after the late PONG");
  assert.equal(r.state.armed, true);
  console.log("PASS late PONG: switched, ARM sent, armed");
}

// 3 — plain Vitni: no ARM in its verb list
{
  const r = await run((cmd, reply) => {
    if (isHex(cmd)) return reply(VITNI_ERR);
    if (cmd === "PING") { reply(VITNI_ERR); return reply(VITNI_ERR, 2500); }   // + a stray late copy
  }, 5000);
  assert.ok(!r.sent.some((c) => c.startsWith("ARM ") || c.startsWith("SIGN")), "neither ARM nor SIGN sent");
  assert.match(r.result, /THIS DEVICE CANNOT BE VERIFIED HERE/);
  assert.match(r.result, /Nothing failed to verify/);
  assert.equal(r.sent.filter(isHex).length, 1, "stopped resending after the rejection");
  assert.equal(r.sent.filter((c) => c === "PING").length, 2, "asked PING once more before giving up, and not again after");
  assert.ok(!/VERIFIED —|VERIFICATION FAILED/.test(r.result));
  console.log("PASS plain Vitni: not armed, not SIGNed, told it cannot be verified here, resend stopped");
}

// 5 — Ostensor (witnessmark firmware): misses the first PING, rejects the bare challenge with a
//     bare "ERR fmt" (no verb list), answers the second PING -> switched, ARM sent
{
  let pings = 0;
  const r = await run((cmd, reply) => {
    if (cmd === "PING") { if (pings++ > 0) reply("PONG"); return; }
    if (isHex(cmd)) return reply("ERR fmt");
    if (cmd === "CERT") return reply("CERT=" + cert);
    if (cmd.startsWith("ARM ")) return reply("ARMED - press CONFIRM");
  }, 3000);
  assert.equal(pings, 2, "asked PING a second time");
  assert.ok(r.sent.some((c) => c.startsWith("ARM ")), "ARM sent after the second PONG");
  assert.equal(r.state.armed, true);
  assert.ok(!/CANNOT BE VERIFIED HERE/.test(r.result));
  console.log("PASS Ostensor bare ERR fmt: second PING answered, switched, armed");
}

// 6 — an armed OPTIGA session is not torn down by a stray bare "ERR fmt"
{
  let n = 0;
  const r = await run((cmd, reply) => {
    if (cmd === "PING") return reply("PONG");
    if (cmd === "CERT") return reply("CERT=" + cert);
    if (cmd.startsWith("ARM ")) { reply("ARMED - press CONFIRM"); return reply("ERR fmt", 100); }
  }, 600);
  assert.equal(r.state.armed, true, "still armed");
  assert.ok(!/CANNOT BE VERIFIED HERE/.test(r.result));
  assert.equal(r.sent.filter((c) => c === "PING").length, 1, "no re-detection once on the OPTIGA path");
  console.log("PASS armed OPTIGA session ignores a stray ERR fmt");
}

// 4 — control: SelfKnot never prints PONG or ERR fmt
{
  const r = await run((cmd) => {}, 5000);
  assert.ok(!r.sent.some((c) => c.startsWith("ARM ")), "a SelfKnot is never sent ARM");
  assert.equal(r.state.is, false);
  assert.ok(r.sent.filter(isHex).length >= 2, "the SelfKnot path keeps resending its challenge");
  assert.ok(!/CANNOT BE VERIFIED HERE/.test(r.result));
  console.log("PASS SelfKnot control: unchanged path, no ARM");
}
console.log("ALL PASS test_start_detect");
process.exit(0);
