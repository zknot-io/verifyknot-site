// @ts-check
/**
 * verifyknot — portable proof bundle, UI layer.
 *
 * WHY THIS IS A MODULE AND NOT AN INLINE <script>
 *   The honesty rules of this feature live in the RENDERING, not just the crypto:
 *   badges must stay one-per-property, an unrecognized signing key must block
 *   "Verify your copy", and an untrusted bundle's strings must remain inert text.
 *   None of that is testable while it sits inside a <script type="module"> in
 *   index.html (jsdom does not execute module scripts at all). Keeping it here
 *   lets the test suite drive the real code against a real DOM — and keeps the
 *   bundle format from being tied to one webpage.
 *
 * Everything user-controlled is written with textContent. A .hashstamp file is
 * attacker-supplied; nothing from it ever reaches innerHTML.
 *
 * NETWORK: nothing here calls the network except runOnlineStatusCheck(), which
 * only ever runs from an explicit button press.
 */

import {
  proofBundleExportGate,
  buildProofBundle,
  serializeProofBundle,
  proofBundleFilename,
  parseProofBundle,
  verifyProofBundle,
  bundleFileComparisonGate,
  checkCurrentStatusOnline,
  compareWithLiveRecord,
  MAX_BUNDLE_BYTES,
} from "./proof-bundle.js";

const BADGE_COLOR = { PASS: "#22c55e", INFO: "#9ca3af", WARN: "#f59e0b", FAIL: "#ef4444" };

/**
 * Build the proof-bundle UI controller over a document.
 *
 * Dependencies are injected rather than imported-and-assumed so a test can drive
 * the real logic with a real DOM and a trapped network.
 *
 * @param {{
 *   doc: Document,
 *   win: any,
 *   enabled: boolean,
 *   compareLocalFile: (file: any, expected: any) => Promise<any>,
 *   onlineCheck?: typeof checkCurrentStatusOnline,
 * }} deps
 */
export function createProofBundleUi({ doc, win, enabled, compareLocalFile, onlineCheck = checkCurrentStatusOnline }) {
  const $ = (/** @type {string} */ id) => doc.getElementById(id);

  /* State. Deliberately narrow, and dropped aggressively — the only thing worth
     retaining between actions is data the record already made public. */
  let lastExport = null; // {rec, result} of the record currently displayed
  let importedBundle = null; // the parsed bundle currently on screen
  let expectedFingerprint = null; // {algorithm, expectedHex} from the imported bundle
  let selectedFile = null; // transient; only ever reaches WebCrypto

  /* ── export side (on a live, verified record) ───────────────────────────── */

  /**
   * Offer (or refuse) an export for a record that just verified in this browser.
   * @param {any} rec mapApiResponse output @param {any} result verifyRecord output
   */
  function showForRecord(rec, result) {
    lastExport = { rec, result };
    const panel = $("pbPanel");
    if (!panel) return;
    const gate = proofBundleExportGate(rec, result, { enabled });

    // Flag off: render nothing at all. The record is fine; the feature is simply
    // not launched, and an explanation here would be noise.
    if (!gate.enabled && /** @type {any} */ (gate).flagged_off) {
      panel.style.display = "none";
      return;
    }

    panel.style.display = "block";
    $("pbBlocked").style.display = "none";
    $("pbActive").style.display = "none";

    if (!gate.enabled) {
      // Explain rather than silently produce a reassuring but incomplete bundle.
      $("pbBlocked").textContent = /** @type {any} */ (gate).reason;
      $("pbBlocked").style.display = "block";
      /** @type {any} */ ($("pbDownload")).disabled = true;
      return;
    }
    /** @type {any} */ ($("pbDownload")).disabled = false;
    $("pbActive").style.display = "block";
  }

  /** Not a file receipt (or no record): the feature does not apply. */
  function hideForRecord() {
    lastExport = null;
    const panel = $("pbPanel");
    if (panel) panel.style.display = "none";
  }

  /** Build the bundle here in the browser and save it. No backend request. */
  async function downloadProofBundle() {
    if (!lastExport) return;
    const btn = /** @type {any} */ ($("pbDownload"));
    btn.disabled = true;
    btn.textContent = "BUILDING…";
    try {
      const bundle = await buildProofBundle(lastExport.rec, lastExport.result);
      const blob = new win.Blob([serializeProofBundle(bundle)], { type: "application/json" });
      const url = win.URL.createObjectURL(blob);
      const a = doc.createElement("a");
      a.href = url;
      a.download = proofBundleFilename(bundle);
      doc.body.appendChild(a);
      a.click();
      a.remove();
      win.URL.revokeObjectURL(url);
      btn.textContent = "✓ DOWNLOADED";
      win.setTimeout(() => {
        btn.textContent = "DOWNLOAD PROOF BUNDLE";
        btn.disabled = false;
      }, 2200);
    } catch (e) {
      // Fail loudly rather than hand the user a half-built artifact.
      $("pbBlocked").textContent =
        "This proof bundle could not be built in your browser, so none was saved. " + /** @type {Error} */ (e).message;
      $("pbBlocked").style.display = "block";
      $("pbActive").style.display = "none";
      btn.textContent = "DOWNLOAD PROOF BUNDLE";
    }
  }

  /* ── import side (a .hashstamp file someone handed you) ─────────────────── */

  function reset() {
    importedBundle = null;
    expectedFingerprint = null;
    selectedFile = null;
    const fi = /** @type {any} */ ($("pbFileInput"));
    if (fi) fi.value = ""; // drop the browser's own reference to the file
    const ci = /** @type {any} */ ($("pbCopyInput"));
    if (ci) ci.value = "";
    if (!$("pbResult")) return;
    $("pbResult").style.display = "none";
    $("pbError").style.display = "none";
    $("pbOk").style.display = "none";
    $("pbOnlineResult").style.display = "none";
    $("pbCopyResult").style.display = "none";
    $("pbCopyDropText").textContent = "Drop a file here, or click to choose";
  }

  function showImportError(/** @type {string} */ msg) {
    $("pbResult").style.display = "block";
    $("pbOk").style.display = "none";
    $("pbError").textContent = msg;
    $("pbError").style.display = "block";
  }

  /** @param {any} file a File (or File-alike with .size/.text()) */
  async function handleBundleFile(file) {
    if (!file) return;
    reset();

    // Refuse an oversized file BEFORE reading it into memory. file.size is the
    // browser's figure; parseProofBundle re-checks the decoded UTF-8 bytes.
    if (typeof file.size === "number" && file.size > MAX_BUNDLE_BYTES) {
      showImportError(
        `This file is ${file.size.toLocaleString()} bytes, larger than the ${MAX_BUNDLE_BYTES.toLocaleString()}-byte limit for a proof bundle. A genuine bundle is a few kilobytes; this file was not read.`
      );
      return;
    }

    let text;
    try {
      text = await file.text(); // local read — the file never leaves this browser
    } catch (e) {
      showImportError(`This file could not be read in your browser (${/** @type {Error} */ (e).message}).`);
      return;
    }

    const parsed = parseProofBundle(text);
    if (!parsed.ok) {
      showImportError(parsed.error);
      return;
    }
    const result = await verifyProofBundle(parsed.bundle);
    importedBundle = parsed.bundle;
    renderImported(parsed.bundle, result);
    return result;
  }

  /** @param {any} bundle @param {any} result */
  function renderImported(bundle, result) {
    $("pbResult").style.display = "block";
    $("pbError").style.display = "none";
    $("pbOk").style.display = "block";
    $("pbHeadline").textContent = result.headline;

    // Badges — one per PROPERTY, each with its own state. Never collapsed into a
    // single green "Verified": these properties are not equally established.
    const badges = $("pbBadges");
    badges.textContent = "";
    for (const b of result.badges) {
      const el = doc.createElement("span");
      const color = BADGE_COLOR[b.state] || "#9ca3af";
      el.style.cssText = `font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.04em;border:1px solid ${color};color:${color};border-radius:20px;padding:3px 9px;white-space:nowrap`;
      el.textContent = b.label;
      el.title = b.detail;
      badges.appendChild(el);
    }

    // The two-section split the reader actually needs: what this FILE proved,
    // versus what no file can prove without going online.
    const verified = $("pbVerified");
    const unchecked = $("pbUnchecked");
    verified.textContent = "";
    unchecked.textContent = "";
    const li = (/** @type {string} */ text) => {
      const el = doc.createElement("li");
      el.textContent = text;
      return el;
    };
    for (const b of result.badges) {
      (b.state === "PASS" || b.state === "INFO" ? verified : unchecked).appendChild(li(`${b.label} — ${b.detail}`));
    }
    for (const c of result.checks) {
      if (c.pass === null) continue; // notes are scope prose, not a check outcome
      (c.pass ? verified : unchecked).appendChild(li(`[${c.pass ? "PASS" : "FAIL"}] ${c.id}: ${c.detail}`));
    }

    $("pbSchema").textContent = bundle.schema + (bundle.generator ? ` · ${bundle.generator}` : "");
    $("pbCode").textContent = bundle.record.verification_code || "—";
    $("pbFingerprint").textContent = bundle.file_fingerprint.value;
    $("pbSig").textContent = `${bundle.signature.algorithm} · ${bundle.signature.encoding || "—"}`;
    $("pbKey").textContent = result.key_identity.recognized
      ? `${bundle.signing_key.key_id} — recognized as ${result.key_identity.label}`
      : `${bundle.signing_key.key_id || "(none)"} — NOT recognized by this verifier`;
    $("pbChain").textContent =
      bundle.chain.position != null
        ? `Position ${bundle.chain.position} (service-reported metadata; no inclusion proof in this bundle)`
        : "No chain metadata in this bundle";
    $("pbTime").textContent =
      (bundle.record.stamped_at || bundle.record.signed_at || "unknown") +
      " — HashStamp service time; no independent time anchor included";

    const limits = $("pbLimits");
    limits.textContent = "";
    if (bundle.limitations?.length) {
      const head = doc.createElement("div");
      head.style.cssText = "font-weight:700;margin-bottom:4px";
      head.textContent = "Limitations carried by this bundle:";
      limits.appendChild(head);
      const ul = doc.createElement("ul");
      ul.style.cssText = "margin:0 0 0 16px";
      for (const l of bundle.limitations) ul.appendChild(li(l));
      limits.appendChild(ul);
    }

    // Verify your copy — gated on a verdict we stand behind (signature AND key).
    const gate = bundleFileComparisonGate(result);
    $("pbCopyBlocked").style.display = "none";
    $("pbCopyActive").style.display = "none";
    if (gate.enabled) {
      expectedFingerprint = gate.fingerprint;
      $("pbCopyActive").style.display = "block";
    } else {
      expectedFingerprint = null;
      $("pbCopyBlocked").textContent = /** @type {any} */ (gate).reason;
      $("pbCopyBlocked").style.display = "block";
    }
  }

  /** @param {any} file */
  async function handleBundleCopyFile(file) {
    if (!file) return;
    if (!expectedFingerprint) return; // defence in depth: never compare ungated
    selectedFile = file;
    $("pbCopyDropText").textContent = file.name; // local display only, never sent

    const box = $("pbCopyResult");
    const paint = (icon, color, title, body, hashes) => {
      box.style.display = "block";
      box.style.borderColor = color;
      $("pbCopyIcon").textContent = icon;
      $("pbCopyIcon").style.color = color;
      $("pbCopyTitle").textContent = title;
      $("pbCopyTitle").style.color = color;
      $("pbCopyBody").textContent = body;
      if (hashes) {
        $("pbCopyHashes").textContent = hashes;
        $("pbCopyHashes").style.display = "block";
      } else {
        $("pbCopyHashes").style.display = "none";
      }
    };
    paint("…", "rgb(156,163,175)", "Hashing in your browser…", "Computing this file's SHA-256 fingerprint locally.", null);

    const res = await compareLocalFile(file, expectedFingerprint);
    if (selectedFile !== file) return; // superseded while hashing — honour that

    if (res.outcome === "MATCH") {
      paint(
        "✓",
        "rgb(34,197,94)",
        "FILE COPY MATCHED LOCALLY",
        "The selected local file has the same SHA-256 fingerprint as the fingerprint contained in this verified bundle. This comparison ran in your browser.",
        `your copy   ${res.localHex}\nin bundle   ${expectedFingerprint.expectedHex}`
      );
    } else if (res.outcome === "MISMATCH") {
      paint(
        "✗",
        "rgb(239,68,68)",
        "FILE COPY DOES NOT MATCH",
        "This file does not match the fingerprint in this bundle. It may be a different version, a modified copy, or an unrelated file.",
        `your copy   ${res.localHex}\nin bundle   ${expectedFingerprint.expectedHex}`
      );
    } else {
      paint("⚠", "rgb(245,158,11)", "Could not compare this file", res.reason, null);
    }
    return res;
  }

  /** The ONLY thing here that touches the network, and only on a button press. */
  async function runOnlineStatusCheck() {
    if (!importedBundle) return;
    const btn = /** @type {any} */ ($("pbOnlineBtn"));
    const out = $("pbOnlineResult");
    btn.disabled = true;
    btn.textContent = "CHECKING…";
    out.style.display = "block";
    out.textContent = "Requesting the live record…";

    const r = await onlineCheck(importedBundle.record.verification_code);
    out.textContent = "";
    if (!r.ok) {
      out.style.color = "#f59e0b";
      out.textContent = r.error;
    } else {
      out.style.color = "";
      const ul = doc.createElement("ul");
      ul.style.cssText = "margin:0 0 0 16px";
      for (const f of compareWithLiveRecord(importedBundle, r.status)) {
        const el = doc.createElement("li");
        el.textContent = `[${f.pass === true ? "PASS" : f.pass === false ? "FAIL" : "NOTE"}] ${f.id}: ${f.detail}`;
        if (f.pass === false) el.style.color = "#ef4444";
        ul.appendChild(el);
      }
      out.appendChild(ul);
    }
    btn.disabled = false;
    btn.textContent = "CHECK CURRENT STATUS ONLINE";
    return r;
  }

  /** Attach listeners + reveal the entry points. No-op while the flag is off. */
  function wire() {
    // The flag gates the ENTIRE surface: with it off, no listener is attached and
    // no entry point is revealed, so there is no dead or hidden behaviour.
    if (!enabled) return;

    const openRow = $("pbOpenRow");
    if (openRow) openRow.style.display = "flex";
    $("pbOpenBtn")?.addEventListener("click", () => /** @type {any} */ ($("pbFileInput")).click());
    $("pbFileInput")?.addEventListener("change", (e) => handleBundleFile(/** @type {any} */ (e.target).files?.[0]));
    $("pbDownload")?.addEventListener("click", downloadProofBundle);
    $("pbClose")?.addEventListener("click", reset);
    $("pbOnlineBtn")?.addEventListener("click", runOnlineStatusCheck);

    const drop = $("pbCopyDrop");
    const input = /** @type {any} */ ($("pbCopyInput"));
    if (drop && input) {
      drop.addEventListener("click", () => input.click());
      drop.addEventListener("keydown", (e) => {
        const k = /** @type {any} */ (e).key;
        if (k === "Enter" || k === " ") {
          e.preventDefault();
          input.click();
        }
      });
      input.addEventListener("change", (e) => handleBundleCopyFile(/** @type {any} */ (e.target).files?.[0]));
      ["dragenter", "dragover"].forEach((ev) =>
        drop.addEventListener(ev, (e) => {
          e.preventDefault();
          /** @type {any} */ (drop).style.borderColor = "var(--accent)";
        })
      );
      ["dragleave", "drop"].forEach((ev) =>
        drop.addEventListener(ev, (e) => {
          e.preventDefault();
          /** @type {any} */ (drop).style.borderColor = "var(--border-active)";
        })
      );
      drop.addEventListener("drop", (e) => handleBundleCopyFile(/** @type {any} */ (e).dataTransfer?.files?.[0]));
    }
    // Drop every file reference when the user navigates away.
    win.addEventListener("pagehide", reset);
  }

  return { wire, showForRecord, hideForRecord, reset, handleBundleFile, handleBundleCopyFile, runOnlineStatusCheck, downloadProofBundle };
}
