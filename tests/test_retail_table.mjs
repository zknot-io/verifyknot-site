// /retail availability claims, per the operator 2026-10-05: all four devices are for sale.
// SelfKnot, Vitni Plus and Ostensor verify on /start. Vitni does NOT: measured 2026-10-05, a Vitni
// answered /start's challenge with "ERR fmt (... SIGN <64hex> | SIGNAUTH <64hex> ...)". Also guards that no unit is claimed KEY-REGISTERED outright: a unit that is
// not enrolled on the rail shows SELF-ASSERTED on /start (start/index.html, unit lookup miss).
//
// Run:  node tests/test_retail_table.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import assert from "node:assert";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const html = readFileSync(resolve(root, "retail/index.html"), "utf8");
const text = html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
assert.ok(text.length > 1000, "page text was read");

for (const stale of [/Not yet available/, /Pilot\s*(&mdash;|—)\s*ask/, /By request/, /Nothing here can be bought today/]) {
  assert.ok(!stale.test(html), `stale availability claim still present: ${stale}`);
}
const rows = [...html.matchAll(/<tr>\s*<td><b>(SelfKnot|Vitni|Vitni Plus|Ostensor)<\/b><\/td>([\s\S]*?)<\/tr>/g)];
assert.equal(rows.length, 4, "four device rows found");
for (const [, name, cells] of rows) {
  assert.match(cells, /For sale/, `${name}: for sale`);
  if (name === "Vitni") {
    assert.match(cells, /does not verify on \/start yet/, "Vitni: says it does not verify on /start");
    assert.ok(!/verifies on \/start/.test(cells), "Vitni: must not claim it verifies on /start");
  } else {
    assert.match(cells, /verifies on \/start/, `${name}: verifies on /start`);
    assert.match(cells, /SELF-ASSERTED on \/start until/, `${name}: does not claim KEY-REGISTERED outright`);
  }
}
assert.ok(!/every device proves itself/i.test(text), "notice must not say every device works on /start");
console.log("PASS  /retail: four devices for sale; Vitni marked not on /start; no outright KEY-REGISTERED");
