// Symbol table: string <-> index dictionary shared by the app and the amp.
//
// File / wire format (SymbolTable::InitFromTableData 0xd2a42, CONFIRMED; native_messages.md §8):
//   u32 count
//   u32 size            (total byte length of the table)
//   count × { u32 strOff (relative to the string blob), u32 crc32(name), u32 len }
//   string blob: NUL-terminated names, starting at 8 + 12 × count
//
// Wire ids are the 0-based INDEX of a name (SymbolTable::LookupString 0xd2b70 hashes the name
// with CRC-32 only to find the entry, then returns the loop index). CONFIRMED (§0.2).
// The whole-file CRC-32 is the Handshake argument (editor/librarian cmd 4).

import { crc32 } from './crc.js';
import { readU32, u32words, concatBytes } from './values.js';
import { AmpProtocolError, SymbolNotFoundError } from './errors.js';

/** Root DSP slot (lookup of "" in SetToneMatchModelParam). CONFIRMED. */
export const ROOT_SLOT_INDEX = 0xffffffff;

/** CRC-32 (zlib) of a whole table file: the u32 sent in Handshake (cmd 4). */
export function tableCrc(bytes) {
  return crc32(bytes);
}

const latin1 = (bytes) => {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return s;
};

/**
 * Parsed symbol table.
 */
export class SymbolTable {
  /**
   * @param {Uint8Array} bytes  raw table (bundled file or downloaded via editor cmds 2/3)
   */
  constructor(bytes) {
    if (bytes.length < 8) throw new AmpProtocolError('symbol table shorter than 8 bytes');
    this.bytes = bytes;
    this.count = readU32(bytes, 0);
    this.size = readU32(bytes, 4);
    const blob = 8 + 12 * this.count;
    if (blob > bytes.length) throw new AmpProtocolError(`symbol table truncated: ${this.count} entries need ${blob} bytes`);
    /** @type {{off:number, hash:number, len:number, name:string}[]} */
    this.entries = [];
    this.names = [];
    /** @type {Map<string, number>} */
    this._index = new Map();
    for (let i = 0; i < this.count; i++) {
      const off = readU32(bytes, 8 + 12 * i);
      const hash = readU32(bytes, 12 + 12 * i);
      const len = readU32(bytes, 16 + 12 * i);
      const start = blob + off;
      if (start + len > bytes.length) throw new AmpProtocolError(`symbol ${i} runs past the end of the table`);
      const name = latin1(bytes.subarray(start, start + len));
      this.entries.push({ off, hash, len, name });
      this.names.push(name);
      if (!this._index.has(name)) this._index.set(name, i); // first match wins, like LookupString
    }
    this.crc32 = tableCrc(bytes);
  }

  /** Index of `name`, or -1. */
  indexOf(name) {
    return this._index.has(name) ? this._index.get(name) : -1;
  }

  /** True when the table has `name`. */
  has(name) {
    return this._index.has(name);
  }

  /**
   * Wire id for `name`. "" maps to 0xFFFFFFFF (root slot, slot argument only).
   * Throws SymbolNotFoundError (native −21) when missing.
   */
  lookup(name) {
    if (name === '') return ROOT_SLOT_INDEX;
    const i = this.indexOf(name);
    if (i < 0) throw new SymbolNotFoundError(name);
    return i;
  }

  /** Name for an index; 0xFFFFFFFF → "" (root); unknown → undefined. */
  nameOf(index) {
    if (index >>> 0 === ROOT_SLOT_INDEX) return '';
    return this.names[index];
  }

  /**
   * Check every entry's hash = crc32(name) and that `size` matches the byte length.
   * @returns {{ok:boolean, sizeOk:boolean, mismatches:number[]}}
   */
  verify() {
    const enc = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
    const mismatches = [];
    this.entries.forEach((e, i) => {
      if (crc32(enc(e.name)) !== e.hash) mismatches.push(i);
    });
    const sizeOk = this.size === this.bytes.length;
    return { ok: mismatches.length === 0 && sizeOk, sizeOk, mismatches };
  }
}

/** Parse table bytes. */
export function parseSymbolTable(bytes) {
  return new SymbolTable(bytes);
}

/**
 * Build a table file from a list of names (used by the mock amp and tests, so the project
 * never needs to ship Line 6's table). Same layout as the bundled file.
 * @param {string[]} names
 * @returns {Uint8Array}
 */
export function buildSymbolTable(names) {
  const strs = names.map((n) => Uint8Array.from(n, (c) => c.charCodeAt(0) & 0xff));
  const entries = [];
  let off = 0;
  for (const s of strs) {
    entries.push(off, crc32(s), s.length);
    off += s.length + 1;
  }
  const blob = new Uint8Array(off);
  let o = 0;
  for (const s of strs) {
    blob.set(s, o);
    o += s.length + 1; // NUL already zero
  }
  const total = 8 + 12 * names.length + blob.length;
  return concatBytes(u32words(names.length, total), u32words(...entries), blob);
}
