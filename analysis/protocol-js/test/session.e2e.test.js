// End-to-end: AmpSession ⇄ MockAmp over the in-memory transport, deterministic FakeClock.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readTable, assetsSkipReason } from './helpers.js';
import { AmpSession, Channel } from '../src/session.js';
import { FakeClock } from '../src/clock.js';
import { decodeHeader, IAP_STOP } from '../src/link.js';
import { ADDR } from '../src/router.js';
import { buildSymbolTable, tableCrc } from '../src/symtab.js';
import { u32words, bytesToHex } from '../src/values.js';
import { WriteNotConfirmedError } from '../src/errors.js';
import { UnsupportedFirmwareError } from '../src/guard.js';
import { MockAmp } from '../mock/MockAmp.js';
import { createMemoryTransportPair } from '../mock/memoryTransport.js';
import { MOCK_SYMBOL_NAMES } from '../mock/mockSymbols.js';

const REAL = assetsSkipReason ? null : readTable();
const MOCK_TABLE = buildSymbolTable(MOCK_SYMBOL_NAMES);

function rig({ mock = {}, session = {}, transport = {} } = {}) {
  const clock = new FakeClock();
  const { phone, amp, stats, log } = createMemoryTransportPair({ clock, latencyMs: 5, ...transport });
  const m = new MockAmp(amp, { clock, ...mock });
  const s = new AmpSession(phone, { clock, symbolTable: REAL ?? MOCK_TABLE, ...session });
  const events = [];
  for (const e of ['paramChanged', 'presetChanged', 'presetSaved', 'tuner', 'tunerEnabled', 'deviceSettingChanged', 'tapTempo', 'symbolTable', 'disconnect', 'error', 'fbvStatus']) {
    s.on(e, (d) => events.push({ e, d }));
  }
  const run = (p, maxMs) => clock.runUntil(p, { maxMs });
  return { clock, phone, amp, m, s, events, stats, log, run };
}

const reqs = (m, service) => m.requests.filter((r) => r.service === service).map((r) => r.cmd);

test('connect: device info phase, link restart, handshake fallback downloads the amp table', async () => {
  const { s, m, run, events } = rig();
  const sum = await run(s.connect());
  assert.equal(s.state, 'connected');
  assert.equal(sum.deviceInfo.productName, 'AMPLIFi 150');
  assert.equal(sum.deviceInfo.firmwareString, '2.50.2');
  assert.deepEqual(sum.channel, { mtu: 240, timeoutMs: 16000 }, 'fw ≥ 2.10.1 → MTU 240 / T 16 s');
  assert.equal(m.deviceInfoReads, 1);
  assert.equal(m.channelStarts, 2, 'IAP x START twice: device-info phase and editor/librarian phase');
  assert.equal(sum.symbolTableSource, 'downloaded');
  assert.equal(sum.symbolTableCrc, tableCrc(MOCK_TABLE));
  assert.ok(events.some((x) => x.e === 'symbolTable' && x.d.source === 'downloaded'));
  // editor: GetVersion, Handshake(bundled) rejected, GetSymbolTableSize, GetSymbolTable, Handshake ok,
  // GetDirtyState, GetDspModelParam(Tuner, Enable)
  assert.deepEqual(reqs(m, 'editor'), [1, 4, 2, 3, 4, 15, 9]);
  // librarian: GetVersion, GetNumPresets, Handshake, GetPresetFile(edit buffer)
  assert.deepEqual(reqs(m, 'librarian'), [1, 5, 4, 11]);
  assert.equal(m.requests.find((r) => r.service === 'librarian' && r.cmd === 11).args.index, 0xffffffff);
  assert.equal(s.presetCount, 8);
  assert.equal(s.editBuffer.name, 'Mock Tone 1');
  assert.equal(s.getEditBufferParams().groups.amp['@model'], 'BritGainJ800');
  assert.equal(m.unknownCommands.length, 0);
  await run(s.disconnect());
});

test('connect: amp accepts the bundled table CRC → no download', { skip: assetsSkipReason }, async () => {
  const { s, m, run } = rig({ mock: { symbolTable: REAL } });
  const sum = await run(s.connect());
  assert.equal(sum.symbolTableSource, 'bundled');
  assert.equal(sum.symbolTableCrc, 0xb68b291e);
  assert.deepEqual(reqs(m, 'editor'), [1, 4, 15, 9]);
  await run(s.disconnect());
});

test('connect: cached table is tried first', async () => {
  const { s, m, run } = rig({ session: { cachedSymbolTable: MOCK_TABLE } });
  const sum = await run(s.connect());
  assert.equal(sum.symbolTableSource, 'cached');
  assert.deepEqual(reqs(m, 'editor').slice(0, 2), [1, 4]);
  await run(s.disconnect());
});

test('connect: forceTableDownload rejects even a matching CRC until the table was downloaded', { skip: assetsSkipReason }, async () => {
  const { s, m, run } = rig({ mock: { symbolTable: REAL, forceTableDownload: true } });
  const sum = await run(s.connect());
  assert.equal(sum.symbolTableSource, 'downloaded');
  assert.equal(sum.symbolTableCrc, 0xb68b291e);
  assert.deepEqual(reqs(m, 'editor').slice(0, 5), [1, 4, 2, 3, 4]);
  await run(s.disconnect());
});

test('connect: old firmware (2.00.6) → MTU 256 / T 4 s', async () => {
  const { s, run } = rig({ mock: { firmwareVersion: '2.00.6' } });
  const sum = await run(s.connect());
  assert.deepEqual(sum.channel, { mtu: 256, timeoutMs: 4000 });
  await run(s.disconnect());
});

test('connect: firmware < 0x01000000 is refused after device info; librarian mode is never entered', async () => {
  const { s, m, run } = rig({ mock: { firmwareVersion: '0.99.0' } });
  await assert.rejects(run(s.connect()), UnsupportedFirmwareError);
  assert.equal(m.deviceInfoReads, 1);
  assert.equal(m.requests.length, 0);
  assert.equal(s.state, 'disconnected');
});

test('setParam: knob, switch, @mic, @temposync, device setting, tempo — mock state follows', async () => {
  const { s, m, run, events } = rig();
  await run(s.connect());
  await run(s.setParam('amp', 'Drive', 0.25));
  assert.equal(m.getParam('amp', 'Drive'), 0.25);
  assert.equal(s.getParam('amp', 'Drive'), 0.25);
  assert.deepEqual(events.find((x) => x.e === 'paramChanged').d, { group: 'amp', paramId: 'Drive', value: 0.25, onDevice: false });
  await run(s.setParam('fx2', '@enabled', true));
  assert.equal(m.getParam('fx2', '@enabled'), true);
  await run(s.setParam('cab', '@mic', 3));
  assert.equal(m.editBuffer.root.children.find((c) => c.slot === 'StudioCab').asset, '4x12BritT75StudioU67');
  assert.equal(s.getParam('cab', '@mic'), 3);
  await run(s.setParam('fx3', '@temposync', true)); // stored SyncSelect of preset 1 is 6
  assert.equal(m.getParam('fx3', 'SyncSelect'), 6);
  await run(s.setParam('fx3', '@temposync', false));
  assert.equal(m.getParam('fx3', 'SyncSelect'), 0);
  await run(s.setDeviceSetting('MasterVolume', 0.8));
  assert.ok(Math.abs(m.deviceSettings.Master - 0.8) < 1e-6);
  assert.ok(Math.abs((await run(s.getDeviceSetting('Master'))) - 0.8) < 1e-6);
  await run(s.setTempo(133));
  assert.equal(m.tempo, 133);
  await assert.rejects(run(s.setDeviceSetting('TapTempoLED', false)), WriteNotConfirmedError);
  await run(s.setDeviceSetting('TapTempoLED', false, { confirmWrite: true }));
  assert.equal(m.sysParams.get(7).bits, 0);
  await run(s.disconnect());
});

test('selectPreset(n): GetPresetFile(n) then SetPresetFile(edit buffer) pass-through', async () => {
  const { s, m, run, events } = rig();
  await run(s.connect());
  const before = m.requests.length;
  await run(s.selectPreset(3));
  const r = m.requests.slice(before);
  assert.deepEqual(r.map((x) => [x.service, x.cmd, x.args.index]), [
    ['librarian', 11, 3],
    ['librarian', 12, 0xffffffff],
  ]);
  assert.equal(bytesToHex(r[1].args.blob), bytesToHex(m.presets[3].blob), 'blob passed through unchanged');
  assert.equal(m.editBuffer.name, 'Mock Tone 4');
  assert.equal(s.editBuffer.name, 'Mock Tone 4');
  assert.equal(s.currentPresetIndex, 3);
  assert.deepEqual(events.filter((x) => x.e === 'presetChanged').map((x) => x.d), [{ index: 3, onDevice: false }]);
  await run(s.disconnect());
});

test('preset names / info, savePreset needs confirmWrite', async () => {
  const { s, m, run } = rig();
  await run(s.connect());
  assert.equal(await run(s.getPresetName(5)), 'Mock Tone 6');
  const names = await run(s.getPresetNames());
  assert.equal(names.length, 8);
  const info = await run(s.getPresetInfo(2));
  assert.equal(info.name, 'Mock Tone 3');
  assert.equal(info.size, m.presets[2].blob.length);
  const blob = s.editBufferBlob;
  const n = m.requests.length;
  await assert.rejects(run(s.savePreset(6, blob)), WriteNotConfirmedError);
  assert.equal(m.requests.length, n, 'nothing was sent');
  await run(s.savePreset(6, blob, { confirmWrite: true }));
  assert.equal(bytesToHex(m.presets[6].blob), bytesToHex(blob));
  assert.equal(await run(s.getPresetName(6)), 'Mock Tone 1');
  await run(s.disconnect());
});

test('amp-side knob turn, master knob, tap tempo, FBV and preset buttons raise events', async () => {
  const { s, m, run, clock, events } = rig();
  await run(s.connect());
  m.turnKnob('amp', 'Drive', 0.7);
  m.turnKnob('fx1', '@enabled', true);
  m.setMasterVolume(0.4);
  m.tapTempo(98);
  m.setFbvConnected(true);
  await clock.advance(2000);
  const pc = events.filter((x) => x.e === 'paramChanged').map((x) => x.d);
  assert.equal(pc[0].group, 'amp');
  assert.equal(pc[0].paramId, 'Drive');
  assert.ok(Math.abs(pc[0].value - 0.7) < 1e-6);
  assert.equal(pc[0].onDevice, true);
  assert.deepEqual(pc[1], { group: 'fx1', paramId: '@enabled', value: true, onDevice: true });
  assert.ok(Math.abs(s.getParam('amp', 'Drive') - 0.7) < 1e-6, 'mirror updated');
  const ds = events.find((x) => x.e === 'deviceSettingChanged').d;
  assert.equal(ds.setting, 'Master');
  assert.equal(ds.onDevice, true);
  assert.deepEqual(events.find((x) => x.e === 'tapTempo').d, { bpm: 98 });
  assert.deepEqual(events.find((x) => x.e === 'fbvStatus').d, { connected: true });
  m.selectPresetOnAmp(5);
  await clock.advance(4000);
  assert.deepEqual(events.filter((x) => x.e === 'presetChanged').at(-1).d, { index: 5, onDevice: true });
  assert.equal(s.editBuffer.name, 'Mock Tone 6', 'edit buffer re-read after the patch event');
  await run(s.disconnect());
});

test('tuner: engage → RegisterDspEvent → note events; disengage stops them; amp-side tuner switch', async () => {
  const { s, m, run, clock, events } = rig({ mock: { tunerValues: [2.1, 7.0, 11.8] } });
  await run(s.connect());
  await run(s.setTuner(true));
  assert.equal(m.tuner.enabled && m.tuner.registered, true);
  await clock.advance(1000);
  const notes = events.filter((x) => x.e === 'tuner').map((x) => x.d);
  assert.ok(notes.length >= 5, `${notes.length} tuner events`);
  assert.equal(notes[0].note, 2);
  assert.ok(Math.abs(notes[0].cents - 10) < 0.01);
  assert.equal(notes[1].note, 7);
  assert.equal(notes[2].note, 0, '11.8 wraps to −0.2 → A');
  await run(s.setTuner(false));
  const count = events.filter((x) => x.e === 'tuner').length;
  await clock.advance(1000);
  assert.ok(events.filter((x) => x.e === 'tuner').length <= count + 1);
  // the amp's own tuner button
  m.setTunerOnAmp(true);
  await clock.advance(1500);
  assert.deepEqual(events.filter((x) => x.e === 'tunerEnabled').at(-1).d, { enabled: true, onDevice: true });
  assert.equal(m.tuner.registered, true, 'session registered for Note events on its own');
  assert.ok(events.filter((x) => x.e === 'tuner').length > count + 2);
  await run(s.disconnect());
});

test('packet drop + retransmit recovery (drops in both directions)', async () => {
  const dropped = { 'phone→amp': 0, 'amp→phone': 0 };
  const seen = { 'phone→amp': 0, 'amp→phone': 0 };
  // drop the 3rd, 7th and 15th data frame in each direction
  const dropFilter = (bytes, dir) => {
    const h = decodeHeader(bytes);
    if (!h || h.len === 0) return false;
    seen[dir]++;
    if ([3, 7, 15].includes(seen[dir])) {
      dropped[dir]++;
      return true;
    }
    return false;
  };
  const { s, m, run, stats } = rig({ transport: { dropFilter } });
  await run(s.connect());
  await run(s.setParam('amp', 'Bass', 0.33));
  await run(s.selectPreset(2));
  assert.equal(m.editBuffer.name, 'Mock Tone 3');
  assert.equal(dropped['phone→amp'], 3);
  assert.equal(dropped['amp→phone'], 3);
  assert.ok(stats['phone→amp'].dropped >= 3);
  assert.ok(s._channel.link.stats.retransmits >= 1, 'phone retransmitted');
  assert.ok(m.link.stats.retransmits >= 1, 'mock retransmitted');
  await run(s.disconnect());
});

test('fault injection: 5% random drop + 7-byte chunking (seeded) still connects and edits', async () => {
  const { s, m, run } = rig({ transport: { dropRate: 0.05, seed: 42, chunkSize: 7 } });
  await run(s.connect(), 300_000);
  await run(s.setParam('reverb', '@mix', 0.6), 60_000);
  assert.ok(Math.abs(m.getParam('reverb', '@mix') - 0.6) < 1e-6);
  await run(s.disconnect(), 60_000);
});

test('idle connection stays up for 60 s (heartbeats ≤ 1 s against the mock 4 s timeout)', async () => {
  const { s, run, clock, events } = rig();
  await run(s.connect());
  await clock.advance(60_000);
  assert.equal(s.state, 'connected');
  assert.ok(!events.some((x) => x.e === 'disconnect'));
  await run(s.setParam('amp', 'Mid', 0.5));
  await run(s.disconnect());
});

test('disconnect: FIN, IAP x STOP, no timers left running', async () => {
  const { s, m, run, clock, events, log } = rig();
  await run(s.connect());
  const stops = [];
  m.on('iap', (c) => stops.push(c));
  await run(s.disconnect());
  assert.deepEqual(stops, ['STOP']);
  assert.ok(log.some((x) => x.dir === 'phone→amp' && bytesToHex(x.bytes) === bytesToHex(IAP_STOP)));
  assert.deepEqual(events.at(-1), { e: 'disconnect', d: { reason: 'user' } });
  m.destroy();
  await clock.advance(1000);
  assert.equal(clock.pendingTimers, 0);
});

test('MockAmp also refuses service-mode word 0 (guard regression would fail twice)', async () => {
  const clock = new FakeClock();
  const { phone, amp } = createMemoryTransportPair({ clock, latencyMs: 5 });
  const m = new MockAmp(amp, { clock });
  const violations = [];
  m.on('guardViolation', (v) => violations.push(v));
  // hand-built client that bypasses AmpSession (and therefore guard.js) on purpose
  phone.onData((b) => ch.receive(b));
  const ch = new Channel({ transport: phone, clock });
  await clock.runUntil(ch.open());
  const st = ch.createStream({ local: ADDR.LIBRARIAN_LOCAL, remote: ADDR.LIBRARIAN_REMOTE, timeoutMs: 4000 });
  await clock.runUntil(st.connect());
  st.write(u32words(0));
  await clock.advance(2000);
  assert.equal(violations.length, 1);
  assert.equal(violations[0].word, 0);
  assert.equal(m.deviceInfoReads, 0);
  st.destroy();
  await clock.runUntil(ch.close());
  m.destroy();
});
