// Checksums used on the AMPLIFi wire.
//
// CRC-16/CCITT-FALSE (IBM-3740): poly 0x1021, init 0xFFFF, no reflection, no final XOR.
//   CONFIRMED: bit-exact port of CRC16_Process @0x113b10 (native_transport.md §3.4).
//   Used for the RobustSerial frame header and payload CRCs.
// CRC-32 (zlib / ISO-HDLC): reflected 0xEDB88320, init/final 0xFFFFFFFF.
//   CONFIRMED: CRC32_bs @0xd177c, table @0x1cd3a0 equals the standard table (§3.5).
//   Used for the symbol-table Handshake argument and symbol-name hashes.

/**
 * CRC-16/CCITT-FALSE. Incremental: pass the previous result as `crc` to continue.
 * check("123456789") === 0x29B1.
 * @param {Uint8Array|number[]} data
 * @param {number} [crc=0xFFFF] running CRC (every native caller seeds 0xFFFF)
 * @returns {number} 16-bit CRC
 */
export function crc16CcittFalse(data, crc = 0xffff) {
  // Same shift-only formulation as CRC16_Process (no lookup table in the binary).
  for (let i = 0; i < data.length; i++) {
    let x = (data[i] ^ (crc >> 8)) & 0xff;
    x ^= x >> 4;
    crc = ((crc << 8) ^ (x << 12) ^ (x << 5) ^ x) & 0xffff;
  }
  return crc;
}

let CRC32_TABLE = null;
function crc32Table() {
  if (CRC32_TABLE) return CRC32_TABLE;
  CRC32_TABLE = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1;
    CRC32_TABLE[i] = c >>> 0;
  }
  return CRC32_TABLE;
}

/**
 * CRC-32 (zlib). Incremental like zlib.crc32(data, prev): pass the previous result as `prev`.
 * check("123456789") === 0xCBF43926.
 * @param {Uint8Array|number[]} data
 * @param {number} [prev=0]
 * @returns {number} unsigned 32-bit CRC
 */
export function crc32(data, prev = 0) {
  const t = crc32Table();
  let c = (prev ^ 0xffffffff) >>> 0;
  for (let i = 0; i < data.length; i++) c = t[(c ^ data[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
