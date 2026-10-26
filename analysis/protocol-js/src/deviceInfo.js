// Device-info record and firmware-version handling.
//
// Spec: native_transport.md §7 step 2.3, §3.2. Source: L6AndroidNdkDevice::prepareForDeviceInfo
// 0xa5cd0, L6StringToL6VersionInt 0xa13e3, SetVersionNum 0xa1340,
// setupMessageChannelParameters 0xa4b14.

import { readU32, viewOf } from './values.js';
import { AmpProtocolError } from './errors.js';

/** Size of the device-info record read after service-mode word 2. CONFIRMED. */
export const DEVICE_INFO_SIZE = 200;

/** Product ids by product name. 0x200002 = AMPLIFi 150 CONFIRMED; the others INFERRED (§9 table order). */
export const PRODUCT_IDS = Object.freeze({
  'AMPLIFi 75': 0x200001,
  'AMPLIFi 150': 0x200002,
  'AMPLIFi FX100': 0x200003,
  'AMPLIFi TT': 0x200005,
  'AMPLIFi 30': 0x200007,
});

const latin = (b) => {
  let end = b.indexOf(0);
  if (end < 0) end = b.length;
  let s = '';
  for (let i = 0; i < end; i++) s += String.fromCharCode(b[i]);
  return s;
};

/**
 * Parse the 200-byte record: char productName[64] @0, char model[64] @0x40,
 * char serialNumber[64] @0x80, u32 firmwareRevision @0xC0, 4 unknown bytes @0xC4. CONFIRMED.
 * firmwareRevision (as a u32) = major<<24 | minor<<16 | patch<<8 | letter (prepareForDeviceInfo
 * formats it with "%d.%02d.%d%c").
 */
export function parseDeviceInfo(bytes) {
  if (bytes.length < DEVICE_INFO_SIZE) throw new AmpProtocolError(`device info needs ${DEVICE_INFO_SIZE} bytes, got ${bytes.length}`);
  const productName = latin(bytes.subarray(0, 64));
  const firmwareRevision = readU32(bytes, 0xc0);
  return {
    productName,
    model: latin(bytes.subarray(0x40, 0x80)),
    serialNumber: latin(bytes.subarray(0x80, 0xc0)),
    firmwareRevision,
    firmwareString: firmwareRevisionToString(firmwareRevision),
    correctedVersion: correctedVersion(firmwareRevision),
    unknownTail: bytes.slice(0xc4, 0xc8),
    productId: PRODUCT_IDS[productName] ?? null,
  };
}

/** Build a 200-byte record (mock amp). */
export function encodeDeviceInfo({ productName = 'AMPLIFi 150', model = 'AMPLIFi 150', serialNumber = 'MOCK0000', firmwareRevision }) {
  const b = new Uint8Array(DEVICE_INFO_SIZE);
  const put = (s, off) => {
    for (let i = 0; i < Math.min(s.length, 63); i++) b[off + i] = s.charCodeAt(i) & 0xff;
  };
  put(productName, 0);
  put(model, 0x40);
  put(serialNumber, 0x80);
  viewOf(b).setUint32(0xc0, firmwareRevision >>> 0, true);
  return b;
}

/** "%d.%02d.%d%c" of the raw revision (a zero letter ends the string). */
export function firmwareRevisionToString(raw) {
  const letter = raw & 0xff;
  return `${raw >>> 24}.${String((raw >>> 16) & 0xff).padStart(2, '0')}.${(raw >>> 8) & 0xff}${letter ? String.fromCharCode(letter) : ''}`;
}

/** "2.50.2" / "2.10.1a" → raw firmwareRevision u32. */
export function parseFirmwareString(s) {
  const m = /^(\d+)\.(\d+)\.(\d+)([A-Za-z]?)$/.exec(String(s).trim());
  if (!m) throw new AmpProtocolError(`bad firmware version string ${s}`);
  return ((+m[1] << 24) | (+m[2] << 16) | (+m[3] << 8) | (m[4] ? m[4].charCodeAt(0) : 0)) >>> 0;
}

/**
 * L6StringToL6VersionInt + SetVersionNum (CONFIRMED from decompile, resolves the "packing" open
 * question): the minor number is split into decimal digits:
 *   corrected = major<<24 | (minor/10)<<20 | (minor%10)<<16 | patch<<8 | lowercase letter (or 0)
 * so raw 2.10.1 (0x020A0100) → 0x02100100, the MTU threshold in setupMessageChannelParameters.
 */
export function correctedVersion(raw) {
  const major = raw >>> 24;
  const minor = (raw >>> 16) & 0xff;
  const patch = (raw >>> 8) & 0xff;
  let letter = raw & 0xff;
  let v = ((major & 0xff) << 24) | ((Math.floor(minor / 10) & 0xff) << 20) | ((minor % 10 & 0xff) << 16) | ((patch & 0xff) << 8);
  if (letter) {
    if (letter > 0x40 && letter < 0x5b) letter += 0x20; // upper → lower case
    if (letter < 0x61 || letter > 0x7a) letter = 0;
    v |= letter;
  }
  return v >>> 0;
}

/**
 * setupMessageChannelParameters 0xa4b14 (CONFIRMED): AMPLIFi (not 30) with corrected version
 * < 0x02100100 → MTU 256 and stream timeout 4000 ms, else MTU 240 / 16000 ms. AMPLIFi 30 uses
 * threshold 0x00010000.
 * @returns {{mtu:number, timeoutMs:number}}
 */
export function channelParametersFor(info) {
  const threshold = info.productName === 'AMPLIFi 30' ? 0x00010000 : 0x02100100;
  return info.correctedVersion < threshold ? { mtu: 256, timeoutMs: 4000 } : { mtu: 240, timeoutMs: 16000 };
}
