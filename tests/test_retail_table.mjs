// /retail availability claims, per the operator 2026-10-05: all four devices are for sale and
// verify on /start. Also guards that no unit is claimed KEY-REGISTERED outright: a unit that is
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
  assert.match(cells, /For sale · verifies on \/start/, `${name}: availability`);
  assert.match(cells, /SELF-ASSERTED on \/start until/, `${name}: does not claim KEY-REGISTERED outright`);
}
console.log("PASS  /retail: four devices for sale, verify on /start, no outright KEY-REGISTERED");
