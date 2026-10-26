// Transport selection (PLAN.md §4.1):
//   ?mock=1  (or the "Mock amp" toggle, remembered in localStorage) → MemoryTransport ⇄ MockAmp
//            running in this page with the real clock;
//   ?mock=0  clears the toggle;
//   default  → WebSerialTransport (Bluetooth SPP via Web Serial).

import { realClock } from '@protocol/clock.js';
import { buildSymbolTable } from '@protocol/symtab.js';
import {
  WebSerialTransport,
  webSerialSupport,
  requestSppPort,
  getRememberedSppPorts,
} from '@protocol/transports/webSerial.js';
import { MockAmp } from '@mock/MockAmp.js';
import { createMemoryTransportPair } from '@mock/memoryTransport.js';
import { MOCK_SYMBOL_NAMES } from '@mock/mockSymbols.js';

export const MOCK_STORAGE_KEY = 'reamplifi.mock';

function storage() {
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

/** 'mock' | 'serial' from the URL and the remembered toggle. */
export function resolveMode(loc = globalThis.location) {
  const q = new URLSearchParams(loc?.search ?? '').get('mock');
  const ls = storage();
  try {
    if (q === '1' || q === 'true') ls?.setItem(MOCK_STORAGE_KEY, '1');
    if (q === '0' || q === 'false') ls?.removeItem(MOCK_STORAGE_KEY);
  } catch {
    /* storage blocked: the URL alone decides */
  }
  if (q === '1' || q === 'true') return 'mock';
  if (q === '0' || q === 'false') return 'serial';
  try {
    return ls?.getItem(MOCK_STORAGE_KEY) === '1' ? 'mock' : 'serial';
  } catch {
    return 'serial';
  }
}

/** Switch mode and reload (the toggle in the header). */
export function setMode(mode) {
  const url = new URL(globalThis.location.href);
  url.searchParams.set('mock', mode === 'mock' ? '1' : '0');
  globalThis.location.assign(url.toString());
}

export function serialSupport() {
  return webSerialSupport();
}

const portLabel = (port, i) => {
  const info = port.getInfo?.() ?? {};
  return info.bluetoothServiceClassId ? `Bluetooth serial port ${i + 1} (SPP)` : `Serial port ${i + 1}`;
};

/** Remembered SPP ports for one-click reconnect: [{ port, label }]. */
export async function rememberedPorts() {
  if (!webSerialSupport().supported) return [];
  const ports = await getRememberedSppPorts();
  return ports.map((port, i) => ({ port, label: portLabel(port, i) }));
}

/**
 * Open a Web Serial transport: the picker, or a remembered port.
 * @param {{port?:SerialPort, onWarning?:(e:Error)=>void, onPicked?:()=>void}} [o]
 */
export async function openSerialTransport({ port, onWarning, onPicked } = {}) {
  const p = port ?? (await requestSppPort());
  onPicked?.();
  const t = new WebSerialTransport(p, { onWarning });
  await t.open();
  return t;
}

/** Symbol table the mock "ships with" (synthetic, built from public identifiers). */
export const MOCK_BUNDLED_TABLE = buildSymbolTable(MOCK_SYMBOL_NAMES);

/**
 * In-page mock amp with fault injection. Options apply to this connection only.
 * @param {{latencyMs?:number, dropRate?:number, chunkSize?:number, forceTableDownload?:boolean, firmwareVersion?:string, seed?:number}} o
 */
export function createMockLink(o = {}) {
  const pair = createMemoryTransportPair({
    clock: realClock,
    latencyMs: Number(o.latencyMs) || 0,
    dropRate: Number(o.dropRate) || 0,
    chunkSize: Number(o.chunkSize) > 0 ? Number(o.chunkSize) : undefined,
    seed: o.seed ?? (Date.now() & 0xffff),
  });
  const mock = new MockAmp(pair.amp, {
    clock: realClock,
    firmwareVersion: o.firmwareVersion || '2.50.2',
    forceTableDownload: !!o.forceTableDownload,
    serialNumber: 'MOCK-0001',
  });
  return { transport: pair.phone, ampSide: pair.amp, mock, stats: pair.stats };
}
