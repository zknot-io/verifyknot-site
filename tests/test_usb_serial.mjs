// usb-serial.js: the WebUSB stand-in for a Web Serial port that /start and /sign use on Chrome
// for Android, where the Web Serial picker lists no USB devices (operator, 2026-10-08).
// Drives the real module against a fake WebUSB device shaped like each ZKNOT fleet.
//
// Run:  node tests/test_usb_serial.mjs
import assert from "node:assert";

function fakeDevice({ composite }) {
  // ST fleets (Ostensor / Vitni / Vitni Plus): comm iface 0 + data iface 1, data EP1 bulk.
  // SelfKnot (CircuitPython): the CDC pair is not first and the device also has MSC and HID.
  const ep = (endpointNumber, direction, type) => ({ endpointNumber, direction, type, packetSize: 64 });
  const iface = (n, cls, eps = []) => ({ interfaceNumber: n, alternates: [{ interfaceClass: cls, endpoints: eps }] });
  const interfaces = composite
    ? [iface(0, 0x08, [ep(1, "in", "bulk"), ep(1, "out", "bulk")]),        // MSC: bulk pair, NOT CDC
       iface(1, 0x02, [ep(2, "in", "interrupt")]),
       iface(2, 0x0a, [ep(3, "in", "bulk"), ep(3, "out", "bulk")]),
       iface(3, 0x03, [ep(4, "in", "interrupt")])]
    : [iface(0, 0x02, [ep(2, "in", "interrupt")]),
       iface(1, 0x0a, [ep(1, "out", "bulk"), ep(1, "in", "bulk")])];
  const dataEp = composite ? 3 : 1;
  const log = { claimed: [], ctl: [], out: [], closed: false };
  const rx = [];
  let waiter = null;
  const dev = {
    configuration: null,
    async open() {},
    async selectConfiguration() { dev.configuration = { interfaces }; },
    async claimInterface(n) { log.claimed.push(n); },
    async controlTransferOut(setup, body) { log.ctl.push({ ...setup, body }); return { status: "ok" }; },
    async transferOut(n, data) { assert.equal(n, dataEp, "write goes to the CDC data endpoint"); log.out.push(new TextDecoder().decode(data)); return { status: "ok" }; },
    async transferIn(n) {
      assert.equal(n, dataEp, "read comes from the CDC data endpoint");
      if (log.closed) throw new Error("device closed");
      const b = rx.length ? rx.shift() : await new Promise((r) => { waiter = r; });
      if (b === null) throw new Error("transfer aborted");
      return { status: "ok", data: new DataView(b.buffer) };
    },
    async clearHalt() {},
    async close() { log.closed = true; if (waiter) waiter(null); },
  };
  const feed = (s) => { const b = new TextEncoder().encode(s); if (waiter) { const w = waiter; waiter = null; w(b); } else rx.push(b); };
  return { dev, log, feed, commIf: composite ? 1 : 0, dataIf: composite ? 2 : 1 };
}

function setNavigator({ android, serial, device }) {
  const nav = { userAgent: android ? "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/129" : "Mozilla/5.0 (X11; Linux x86_64) Chrome/129" };
  if (serial) nav.serial = { requestPort: async () => "WEB-SERIAL-PORT" };
  nav.usb = { requestDevice: async ({ filters }) => { nav.usb.filters = filters; return device; } };
  Object.defineProperty(globalThis, "navigator", { value: nav, configurable: true });
  return nav;
}

const { pickPort, transport } = await import("../usb-serial.js");

async function run() {
  // Transport choice.
  setNavigator({ android: false, serial: true });
  assert.equal(transport(), "serial", "desktop with Web Serial keeps Web Serial");
  assert.equal(await pickPort(), "WEB-SERIAL-PORT");
  setNavigator({ android: true, serial: true });
  assert.equal(transport(), "usb", "Android uses WebUSB even though navigator.serial exists");
  setNavigator({ android: false, serial: false });
  assert.equal(transport(), "usb", "no Web Serial but WebUSB: use WebUSB");
  Object.defineProperty(globalThis, "navigator", { value: { userAgent: "iPhone" }, configurable: true });
  assert.equal(transport(), null, "iOS: neither, page shows the unsupported card");
  console.log("PASS  transport choice: desktop serial, Android usb, iOS none");

  for (const composite of [false, true]) {
    const name = composite ? "SelfKnot-shaped composite (CircuitPython)" : "ST 0483:5740 (Ostensor / Vitni / Vitni Plus)";
    const f = fakeDevice({ composite });
    const nav = setNavigator({ android: true, serial: true, device: f.dev });
    const port = await pickPort();
    assert.ok(nav.usb.filters.some((x) => x.vendorId === 0x0483 && x.productId === 0x5740), "ST filter");
    assert.ok(nav.usb.filters.some((x) => x.classCode === 0x02), "CDC class filter");
    await port.open({ baudRate: 115200 });
    assert.deepEqual(f.log.claimed, [f.commIf, f.dataIf], `${name}: claims the CDC pair only`);
    const lc = f.log.ctl.find((c) => c.request === 0x20), dtr = f.log.ctl.find((c) => c.request === 0x22);
    assert.equal(new DataView(lc.body).getUint32(0, true), 115200, "line coding baud");
    assert.equal(dtr.value & 1, 1, "DTR raised (CircuitPython console needs it)");
    assert.equal(dtr.index, f.commIf, "control requests go to the comm interface");

    // The pages' exact usage: getWriter, getReader, line protocol, then disconnect order.
    const writer = port.writable.getWriter();
    await writer.write(new TextEncoder().encode("PING\n"));
    assert.deepEqual(f.log.out, ["PING\n"]);
    const reader = port.readable.getReader();
    f.feed("PO"); f.feed("NG\r\n");
    let got = "";
    while (!got.includes("\n")) { const { value } = await reader.read(); got += new TextDecoder().decode(value); }
    assert.equal(got, "PONG\r\n", `${name}: bytes arrive in order`);
    const pending = reader.read().catch(() => ({ done: true }));
    await reader.cancel(); reader.releaseLock(); writer.releaseLock();
    await port.close();
    await pending;
    assert.ok(f.log.closed, "device closed on disconnect");
    console.log(`PASS  ${name}: open, DTR, write, read, disconnect`);
  }
}
run().catch((e) => { console.error("FAIL ", e.message); process.exit(1); });
