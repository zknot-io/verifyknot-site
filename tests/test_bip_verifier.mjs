// Browser-side BIP verifier test — runs verifier.js in Node (same WebCrypto path
// the browser uses). Proves the acceptance property in the client that actually
// renders the verdict: original copy MATCH, one-byte-altered copy MISMATCH, and
// that the file-comparison gate fails closed for tampered / unanchored records.
//
// Run:  node tests/test_bip_verifier.mjs
import {
  mapApiResponse, verifyRecord, fileComparisonGate, compareLocalFile,
  bytesToHex, hexToBytes,
} from "../verifier.js";
import assert from "node:assert";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();

async function sha256Hex(bytes) {
  return bytesToHex(await subtle.digest("SHA-256", bytes));
}

// Build a BIP record signed with an ephemeral P-256 key, exactly as the rail
// would return it from GET /v1/verify/{code}. WM-0001 produces the same shape:
// an ECDSA signature over SHA-256(signed_payload) == challenge_hash.
async function makeRecord(fileBytes, { anchored = true, version = 1 } = {}) {
  const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const rawPub = new Uint8Array(await subtle.exportKey("raw", kp.publicKey)); // 04||X||Y
  const contentHash = await sha256Hex(fileBytes);
  const aid = "11111111-2222-3333-4444-555555555555";
  const signedAt = "2026-07-24T15:00:00+00:00";
  const postId = "dishonesty-thesis";
  const payload = enc.encode(
    ["ZKNOT-BIP1", aid, "WM-0001", contentHash, postId, String(version), signedAt].join("\n"));
  const challenge = await sha256Hex(payload);
  const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, payload));
  return {
    short_code: "ZK-BIP-0001", artifact_type: "ZKEY_SIGN", device_id: "WM-0001",
    session_id: null, signed_at: signedAt, chain_position: 42, chain_prev_hash: null,
    artifact_hash: "ab".repeat(32), challenge_hash: challenge,
    signature: bytesToHex(sig), public_key: bytesToHex(rawPub),
    key_anchored: anchored, signature_valid: true, verified: anchored,
    metadata: {
      record_version: "1.0", record_kind: "bip_post", identity_tier: "WITNESSMARK-DEVICE",
      presence_binding_type: "none", content_binding_type: "none",
      signed_payload_hex: bytesToHex(payload), content_sha256: contentHash,
      artifact_name: "wk01_dishonesty-thesis.md", post_id: postId, version,
      version_history: [{ version: 1, content_sha256: contentHash, short_code: "ZK-BIP-0001",
                          artifact_id: aid, signed_at: signedAt, artifact_name: "wk01_dishonesty-thesis.md" }],
      post_url: "https://zknot.io/bip/dishonesty-thesis",
    },
  };
}

const FILE = enc.encode("---\nslug: dishonesty-thesis\n---\n\nMost fraud isn't a hack.\n");

async function run() {
  // 1. Happy path: verified, BIP block present, gate enabled, original copy MATCH.
  const rec = await makeRecord(FILE);
  const r = await verifyRecord(mapApiResponse(rec));
  assert.equal(r.verdict, "VERIFIED_CLIENT_SIDE", "record must verify in browser");
  assert.equal(r.kind, "bip_post");
  assert.equal(r.bip.witness, "WM-0001");
  assert.equal(r.bip.key_anchored, true);
  assert.equal(r.bip.version_history.length, 1);
  assert.equal(r.badges.identity, "WITNESSMARK-DEVICE");
  console.log("ok: BIP record verifies; witness=WM-0001, tier + history present");

  const gate = fileComparisonGate(r);
  assert.equal(gate.enabled, true, "gate must enable for a verified, anchored BIP record");
  const okCmp = await compareLocalFile(new Blob([FILE]), gate.fingerprint);
  assert.equal(okCmp.outcome, "MATCH", "original copy must MATCH");
  console.log("ok: gate enabled; original copy MATCH (VALID)");

  // 2. ACCEPTANCE: alter one byte -> MISMATCH (INVALID for the altered copy).
  const altered = Uint8Array.from(FILE); altered[10] ^= 0x01;
  const badCmp = await compareLocalFile(new Blob([altered]), gate.fingerprint);
  assert.equal(badCmp.outcome, "MISMATCH", "one-byte-altered copy must MISMATCH");
  console.log("ok: ACCEPTANCE — one-byte-altered copy MISMATCH (INVALID)");

  // 3. Fingerprint is taken from the SIGNED payload, not unsigned metadata:
  //    tampering metadata.content_sha256 must NOT move the compare target.
  const tampered = await makeRecord(FILE);
  tampered.metadata.content_sha256 = "00".repeat(32);
  const rt = await verifyRecord(mapApiResponse(tampered));
  const gt = fileComparisonGate(rt);
  const stillMatch = await compareLocalFile(new Blob([FILE]), gt.fingerprint);
  assert.equal(stillMatch.outcome, "MATCH", "compare must use the SIGNED content hash");
  console.log("ok: copy check uses the SIGNED content hash (metadata tamper ignored)");

  // 4. Tampered signature -> verdict FAILED -> gate closed.
  const badsig = await makeRecord(FILE);
  const sb = hexToBytes(badsig.signature); sb[0] ^= 0xff; badsig.signature = bytesToHex(sb);
  const rb = await verifyRecord(mapApiResponse(badsig));
  assert.equal(rb.verdict, "FAILED", "bad signature must FAIL");
  assert.equal(fileComparisonGate(rb).enabled, false, "gate closed on failed record");
  console.log("ok: tampered signature -> FAILED, gate closed");

  // 5. Unanchored key -> gate closed (valid math, but ZKNOT vouches for nothing).
  const unanch = await makeRecord(FILE, { anchored: false });
  const ru = await verifyRecord(mapApiResponse(unanch));
  assert.equal(ru.verdict, "VERIFIED_CLIENT_SIDE", "math still passes");
  assert.equal(fileComparisonGate(ru).enabled, false, "gate closed when key not anchored");
  console.log("ok: unanchored key -> math passes but gate closed (honest)");

  console.log("\nBIP VERIFIER TESTS PASSED");
}

run().catch((e) => { console.error(e); process.exit(1); });
