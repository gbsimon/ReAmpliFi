// Byte helpers + editor TypedValue.
//
// Everything on the wire is little-endian (native_transport.md, header note: the native code
// copies x86/ARM-LE structs straight to the stream). Only Uint8Array / DataView are used so the
// module runs unchanged in browsers (no Node Buffer).

/** Empty byte array constant. */
export const EMPTY = new Uint8Array(0);

/** Concatenate any number of Uint8Arrays (or arrays of byte numbers). */
export function concatBytes(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Hex string ("0a 00 ff" / "0a00ff") -> Uint8Array. */
export function hexToBytes(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2) throw new Error(`odd-length hex string: ${hex}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

/** Uint8Array -> lowercase hex without separators. */
export function bytesToHex(bytes, sep = '') {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(sep);
}

/** ASCII string -> bytes (no NUL terminator). */
export function asciiBytes(s) {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

/** Bytes equality. */
export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** DataView over a Uint8Array (respecting its byteOffset). */
export function viewOf(bytes) {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

/** u32 LE -> 4 bytes. Negative numbers are written as their two's complement. */
export function u32le(n) {
  const b = new Uint8Array(4);
  viewOf(b).setUint32(0, n >>> 0, true);
  return b;
}

/** u16 LE -> 2 bytes. */
export function u16le(n) {
  const b = new Uint8Array(2);
  viewOf(b).setUint16(0, n & 0xffff, true);
  return b;
}

/** Several u32 LE words -> bytes. */
export function u32words(...words) {
  const b = new Uint8Array(words.length * 4);
  const v = viewOf(b);
  words.forEach((w, i) => v.setUint32(i * 4, w >>> 0, true));
  return b;
}

/** f32 LE -> 4 bytes. */
export function f32le(x) {
  const b = new Uint8Array(4);
  viewOf(b).setFloat32(0, x, true);
  return b;
}

export const readU16 = (bytes, off = 0) => viewOf(bytes).getUint16(off, true);
export const readU32 = (bytes, off = 0) => viewOf(bytes).getUint32(off, true);
export const readI32 = (bytes, off = 0) => viewOf(bytes).getInt32(off, true);
export const readF32 = (bytes, off = 0) => viewOf(bytes).getFloat32(off, true);
export const readU64 = (bytes, off = 0) => viewOf(bytes).getBigUint64(off, true);

/** IEEE float32 -> its u32 bit pattern. */
export function float32ToBits(x) {
  const b = new Uint8Array(4);
  viewOf(b).setFloat32(0, x, true);
  return viewOf(b).getUint32(0, true);
}

/** u32 bit pattern -> IEEE float32 value (as a JS double). */
export function bitsToFloat32(bits) {
  const b = new Uint8Array(4);
  viewOf(b).setUint32(0, bits >>> 0, true);
  return viewOf(b).getFloat32(0, true);
}

/** Round a JS number to the nearest float32 (what actually travels on the wire). */
export const toFloat32 = (x) => Math.fround(x);

// ------------------------------------------------------------------------------ TypedValue
//
// Editor-service TypedValue = { u32 tag, u32 bits } (8 bytes, LE).
// CONFIRMED: FUN_000ec4c5 builds it; tag names from handleParamEvent 0x109c86
// (native_messages.md §0.3). NOTE: the *preset blob* uses a different tag numbering
// (see presetBlob.js) - do not mix them up.

/** Editor TypedValue tags. CONFIRMED (native_messages.md §0.3). */
export const TV = Object.freeze({
  VOID: 0,
  SYMBOL: 1, // bits = symbol-table index
  INT: 2, // bits = int32
  BOOL: 3, // bits = 0 / 1
  FLOAT: 4, // bits = IEEE float32 bit pattern
  VARRAY: 5, // never seen in the AMPLIFi paths; listed for completeness
});

export const TV_NAMES = Object.freeze(['void', 'symbol', 'int', 'bool', 'float', 'varray']);

/**
 * @typedef {{ tag: number, bits: number }} TypedValue
 * `bits` is always the raw unsigned 32-bit payload.
 */

/** @returns {TypedValue} */
export const tvVoid = () => ({ tag: TV.VOID, bits: 0 });
/** @returns {TypedValue} */
export const tvSymbol = (index) => ({ tag: TV.SYMBOL, bits: index >>> 0 });
/** @returns {TypedValue} */
export const tvInt = (n) => ({ tag: TV.INT, bits: Math.trunc(n) >>> 0 });
/** @returns {TypedValue} */
export const tvBool = (b) => ({ tag: TV.BOOL, bits: b ? 1 : 0 });
/** @returns {TypedValue} */
export const tvFloat = (x) => ({ tag: TV.FLOAT, bits: float32ToBits(x) });

/** Encode a TypedValue to its 8 wire bytes. */
export function encodeTypedValue(tv) {
  return u32words(tv.tag, tv.bits);
}

/** Decode a TypedValue at `off`. Returns { tag, bits }. */
export function decodeTypedValue(bytes, off = 0) {
  if (bytes.length < off + 8) throw new RangeError('TypedValue needs 8 bytes');
  return { tag: readU32(bytes, off), bits: readU32(bytes, off + 4) };
}

/**
 * TypedValue -> plain JS value: float -> number (float32 precision), int -> signed number,
 * bool -> boolean, symbol -> index (number), void -> null.
 */
export function typedValueToJs(tv) {
  switch (tv.tag) {
    case TV.FLOAT:
      return bitsToFloat32(tv.bits);
    case TV.INT:
      return tv.bits | 0;
    case TV.BOOL:
      return tv.bits !== 0;
    case TV.SYMBOL:
      return tv.bits >>> 0;
    case TV.VOID:
      return null;
    default:
      return tv.bits >>> 0;
  }
}

/** Human-readable TypedValue, e.g. "float(0.5)". */
export function describeTypedValue(tv) {
  return `${TV_NAMES[tv.tag] ?? `tag${tv.tag}`}(${typedValueToJs(tv)})`;
}
