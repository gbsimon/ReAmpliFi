// AmpSession read-side API used by the P1 read-only app: state / phase / command / editBuffer
// events, table-download progress, preset-name progress, readOnly mode, link loss.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AmpSession } from '../src/session.js';
import { FakeClock } from '../src/clock.js';
import { buildSymbolTable } from '../src/symtab.js';
import { ReadOnlyError } from '../src/errors.js';
import { MockAmp } from '../mock/MockAmp.js';
import { createMemoryTransportPair } from '../mock/memoryTransport.js';
import { MOCK_SYMBOL_NAMES } from '../mock/mockSymbols.js';

const MOCK_TABLE = buildSymbolTable(MOCK_SYMBOL_NAMES);

function rig({ mock = {}, session = {} } = {}) {
  const clock = new FakeClock();
  const { phone, amp } = createMemoryTransportPair({ clock, latencyMs: 5 });
  const m = new MockAmp(amp, { clock, ...mock });
  const s = new AmpSession(phone, { clock, ...session });
  const ev = {};
  for (const e of ['state', 'phase', 'command', 'editBuffer', 'disconnect', 'presetChanged', 'paramChanged', 'tunerEnabled', 'error']) {
    ev[e] = [];
    s.on(e, (d) => ev[e].push(d));
  }
  const run = (p, maxMs) => clock.runUntil(p, { maxMs });
  return { clock, phone, amp, m, s, ev, run };
}

test('connect emits state + ordered phases, with table-download progress', async () => {
  const { s, ev, run } = rig();
  await run(s.connect());
  assert.deepEqual(ev.state.map((x) => x.state), ['connecting', 'connected']);
  const order = ev.phase.map((p) => p.phase).filter((p, i, a) => p !== a[i - 1]);
  assert.deepEqual(order, ['sync', 'deviceInfo', 'channel', 'handshake', 'tableDownload', 'librarian', 'editBuffer', 'tuner', 'ready']);
  const dl = ev.phase.filter((p) => p.phase === 'tableDownload');
  assert.ok(dl.length >= 3, `${dl.length} progress events`);
  assert.equal(dl[0].received, 0);
  assert.equal(dl.at(-1).received, MOCK_TABLE.length);
  assert.ok(dl.every((p) => p.total === MOCK_TABLE.length));
  assert.ok(dl.some((p) => p.received > 0 && p.received < p.total), 'intermediate progress reported');
  for (let i = 1; i < dl.length; i++) assert.ok(dl[i].received >= dl[i - 1].received, 'monotonic');
  const ch = ev.phase.find((p) => p.phase === 'channel');
  assert.deepEqual([ch.mtu, ch.timeoutMs], [240, 16000]);
  assert.equal(s.summary.symbolTableSource, 'downloaded');
  await run(s.disconnect());
  assert.deepEqual(ev.state.map((x) => x.state).slice(-2), ['disconnecting', 'disconnected']);
});

test("bundled table accepted → no 'tableDownload' phase", async () => {
  const { s, ev, run } = rig({ session: { symbolTable: MOCK_TABLE } });
  const sum = await run(s.connect());
  assert.equal(sum.symbolTableSource, 'bundled');
  assert.ok(!ev.phase.some((p) => p.phase === 'tableDownload'));
  await run(s.disconnect());
});

test("'command' log: the read-only connect sequence sends no storage write", async () => {
  const { s, ev, run } = rig({ session: { readOnly: true } });
  await run(s.connect());
  await run(s.getPresetNames());
  assert.ok(ev.command.length > 10);
  assert.ok(ev.command.every((c) => c.writesStorage === false));
  assert.deepEqual(
    ev.command.slice(0, 7).map((c) => `${c.service}.${c.name}`),
    ['editor.GetVersion', 'editor.GetSymbolTableSize', 'editor.GetSymbolTable', 'editor.Handshake', 'librarian.GetVersion', 'librarian.GetNumPresets', 'librarian.Handshake'],
  );
  const gpf = ev.command.find((c) => c.name === 'GetPresetFile');
  assert.equal(gpf.index, 0xffffffff);
  assert.equal(typeof gpf.t, 'number');
  await run(s.disconnect());
});

test('the command log marks storage writes (non read-only session)', async () => {
  const { s, ev, run } = rig({ session: { symbolTable: MOCK_TABLE } });
  await run(s.connect());
  await run(s.savePreset(2, s.editBufferBlob, { confirmWrite: true }));
  const w = ev.command.filter((c) => c.writesStorage);
  assert.deepEqual(w.map((c) => [c.service, c.cmd, c.index]), [['librarian', 12, 2]]);
  await run(s.selectPreset(1)); // SetPresetFile to the edit buffer is not a storage write
  assert.equal(ev.command.filter((c) => c.writesStorage).length, 1);
  await run(s.disconnect());
});

test('readOnly: edits, loads and storage writes are refused locally; tuner still works', async () => {
  const { s, m, ev, run, clock } = rig({ session: { readOnly: true, symbolTable: MOCK_TABLE } });
  await run(s.connect());
  const sent = m.requests.length;
  const cmds = ev.command.length;
  await assert.rejects(run(s.setParam('amp', 'Drive', 0.5)), ReadOnlyError);
  await assert.rejects(run(s.setParam('fx1', '@enabled', true)), ReadOnlyError);
  await assert.rejects(run(s.setDeviceSetting('Master', 0.5)), ReadOnlyError);
  await assert.rejects(run(s.setTempo(120)), ReadOnlyError);
  await assert.rejects(run(s.bindTweak('amp', 'Drive')), ReadOnlyError);
  await assert.rejects(run(s.selectPreset(2)), ReadOnlyError);
  await assert.rejects(run(s.writeEditBuffer(s.editBufferBlob)), ReadOnlyError);
  await assert.rejects(run(s.savePreset(2, s.editBufferBlob, { confirmWrite: true })), ReadOnlyError);
  await assert.rejects(run(s.movePreset(1, 2, { confirmWrite: true })), ReadOnlyError);
  // the internal command path refuses too (second line of defence)
  await assert.rejects(s._ed(10, () => new Uint8Array(0)), ReadOnlyError);
  await assert.rejects(s._lib(12, () => new Uint8Array(0), { index: 0xffffffff }), ReadOnlyError);
  await clock.advance(1000);
  assert.equal(m.requests.length, sent, 'nothing reached the amp');
  assert.equal(ev.command.length, cmds, 'nothing was logged as sent');
  // tuner engage / disengage is the one live change allowed
  await run(s.setTuner(true));
  assert.equal(m.tuner.enabled, true);
  await run(s.setTuner(false));
  assert.equal(m.tuner.enabled, false);
  await run(s.disconnect());
});

test("'editBuffer' event on connect and after an amp-side preset change; getPresetNames progress", async () => {
  const { s, m, ev, run, clock } = rig({ session: { symbolTable: MOCK_TABLE, readOnly: true } });
  await run(s.connect());
  assert.equal(ev.editBuffer.length, 1);
  assert.equal(ev.editBuffer[0].preset.name, 'Mock Tone 1');
  const prog = [];
  const names = await run(s.getPresetNames({ onProgress: (p) => prog.push(p) }));
  assert.equal(names.length, 8);
  assert.deepEqual(prog.at(-1), { index: 7, name: 'Mock Tone 8', done: 8, total: 8 });
  assert.equal(s.currentPresetIndex, null, 'unknown until a patch event');
  m.selectPresetOnAmp(4);
  await clock.advance(4000);
  assert.equal(s.currentPresetIndex, 4);
  assert.equal(ev.editBuffer.at(-1).preset.name, 'Mock Tone 5');
  assert.deepEqual(ev.presetChanged.at(-1), { index: 4, onDevice: true });
  await run(s.disconnect());
});

test("link loss while connected → 'disconnect' {reason:'error'} and state disconnected", async () => {
  const { s, amp, ev, run, clock } = rig({ session: { symbolTable: MOCK_TABLE } });
  await run(s.connect());
  amp.close(); // the amp side drops the link
  await clock.advance(2000);
  assert.equal(s.state, 'disconnected');
  assert.equal(ev.disconnect.length, 1);
  assert.equal(ev.disconnect[0].reason, 'error');
  assert.equal(ev.state.at(-1).state, 'disconnected');
});

test('heartbeat loss (amp goes silent) → disconnect with a timeout error', async () => {
  const { s, m, ev, run, clock } = rig({ session: { symbolTable: MOCK_TABLE } });
  await run(s.connect());
  m.destroy(); // stops answering and stops heartbeats, transport stays "open"
  await clock.advance(30_000);
  assert.equal(s.state, 'disconnected');
  assert.equal(ev.disconnect.length, 1);
  assert.equal(ev.disconnect[0].reason, 'error');
});
