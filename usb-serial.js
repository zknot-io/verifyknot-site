// usb-serial.js — a WebUSB stand-in for a Web Serial port, for Chrome on Android.
//
// WHY: Chrome on Android exposes navigator.serial, but its port picker does not list USB
// CDC devices, so /start and /sign showed an empty chooser and "No port selected" on every
// phone (operator, 2026-10-08). Android Chrome DOES have WebUSB, and every ZKNOT device is a
// plain CDC-ACM function: Ostensor, Vitni and Vitni Plus enumerate as ST 0483:5740 with a
// class-0x02 control interface and a class-0x0A data interface; SelfKnot is CircuitPython,
// whose console is a CDC-ACM pair inside a composite device. This module speaks CDC-ACM over
// WebUSB and returns an object shaped like a SerialPort (open / readable / writable / close),
// so the pages' existing line protocol runs on it unchanged.
//
// Desktop keeps Web Serial: there the OS's cdc_acm driver owns the interface and WebUSB
// cannot claim it. pickPort() chooses the transport.

const CDC_COMM = 0x02, CDC_DATA = 0x0a;
const SET_LINE_CODING = 0x20, SET_CONTROL_LINE_STATE = 0x22;

// A device-level classCode filter also matches interface classes, which is what catches the
// CircuitPython composite (device class 0xEF) as well as the ST devices (device class 0x02).
const FILTERS = [{ vendorId: 0x0483, productId: 0x5740 }, { classCode: CDC_COMM }];

export const isAndroid = () => /Android/i.test(navigator.userAgent || "");

// WebUSB only where Web Serial cannot see USB: Android, or a browser with no Web Serial.
export function transport() {
  if ("usb" in navigator && (isAndroid() || !("serial" in navigator))) return "usb";
  if ("serial" in navigator) return "serial";
  return null;
}

export async function pickPort() {
  if (transport() === "usb") return new UsbSerialPort(await navigator.usb.requestDevice({ filters: FILTERS }));
  return navigator.serial.requestPort();
}

class UsbSerialPort {
  constructor(device) {
    this.device = device;
    this.readable = null;
    this.writable = null;
  }

  async open({ baudRate = 115200 } = {}) {
    const d = this.device;
    await d.open();
    if (d.configuration === null) await d.selectConfiguration(1);

    let comm = null, data = null;
    for (const itf of d.configuration.interfaces) {
      const cls = itf.alternates[0].interfaceClass;
      if (cls === CDC_COMM && comm === null) comm = itf;
      if (cls === CDC_DATA && data === null) data = itf;
    }
    if (!data) throw new Error("device has no CDC data interface");

    const eps = data.alternates[0].endpoints;
    const epIn = eps.find((e) => e.direction === "in" && e.type === "bulk");
    const epOut = eps.find((e) => e.direction === "out" && e.type === "bulk");
    if (!epIn || !epOut) throw new Error("CDC data interface has no bulk endpoint pair");

    if (comm) await d.claimInterface(comm.interfaceNumber);
    await d.claimInterface(data.interfaceNumber);

    if (comm) {
      const ctl = (request, value, body) => d.controlTransferOut(
        { requestType: "class", recipient: "interface", request, value, index: comm.interfaceNumber }, body);
      // Line coding is advisory on a USB CDC function, and a device that stalls it still
      // moves bytes, so a refusal here is not fatal.
      const lc = new DataView(new ArrayBuffer(7));
      lc.setUint32(0, baudRate, true); lc.setUint8(4, 0); lc.setUint8(5, 0); lc.setUint8(6, 8);
      try { await ctl(SET_LINE_CODING, 0, lc.buffer); } catch {}
      // DTR is not advisory: CircuitPython does not treat its console as connected without it,
      // so a SelfKnot would never print its SIG line.
      try { await ctl(SET_CONTROL_LINE_STATE, 0x03); } catch {}
    }

    const inNum = epIn.endpointNumber, inSize = epIn.packetSize, outNum = epOut.endpointNumber;
    this.readable = new ReadableStream({
      async pull(controller) {
        try {
          const r = await d.transferIn(inNum, inSize);
          if (r.status === "stall") { await d.clearHalt("in", inNum); return; }
          if (r.data && r.data.byteLength) {
            controller.enqueue(new Uint8Array(r.data.buffer, r.data.byteOffset, r.data.byteLength));
          }
        } catch (e) { controller.error(e); }
      },
    });
    this.writable = new WritableStream({
      async write(chunk) { await d.transferOut(outNum, chunk); },
    });
  }

  async close() {
    // Closing the device aborts any transferIn still pending, which ends the read loop.
    try { await this.device.close(); } catch {}
    this.readable = this.writable = null;
  }
}
