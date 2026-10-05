// /retail claim checks: offers that are not ruled must not appear on the page.
//   - custom seal text: pulled until DECISION-TV-PERSONALIZATION-001 is signed (operator, 2026-10-05)
//
// Run:  node tests/test_retail_claims.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import assert from "node:assert";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const text = readFileSync(resolve(root, "retail/index.html"), "utf8")
  .replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");

assert.ok(text.length > 1000, "page text was read (an empty read would pass every absence check)");
for (const re of [/own text/i, /personali[sz]ed/i, /16 characters/i, /store name/i]) {
  assert.ok(!re.test(text), `custom-text offer still present: ${re}`);
}
assert.match(text, /custom text on the seal is not offered/i, "the page says plainly it is not offered");
console.log("PASS  /retail makes no custom-seal-text offer");
