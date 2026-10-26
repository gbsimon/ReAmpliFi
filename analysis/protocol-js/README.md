# amplifi-protocol (protocol-js)

A pure-JavaScript (ES modules, zero dependencies) implementation of the Bluetooth SPP protocol
spoken between the Line 6 AMPLIFi Remote app and an AMPLIFi 150 amp, plus a **software mock amp**
so everything can be tested without hardware. Written for interoperability with your own amp.

- Runs in browsers (Web Serial over Bluetooth RFCOMM on desktop Chrome, a Capacitor SPP plugin
  later) and in Node 20+. `src/` uses only `Uint8Array` / `DataView` / `TextEncoder`.
- **Scope: settings and presets only.** Firmware update / flash / DFU / the updater service
  mode are permanently out of scope. `src/guard.js` is an allow-list that refuses them
  (see "Firmware guardrail" below).

## Status: read this first

- The protocol was reconstructed by **static analysis** of the Android app
  (`analysis/notes/native_transport.md`, `native_messages.md`, `java_side.md`).
  **None of it has been tested against a real amp yet.**
- Every encoder carries a `status` of `CONFIRMED` (read in decompiled code) or `INFERRED`.
  The preset-blob codec (`src/presetBlob.js`) is **INFERRED** as a whole.
- Things the analysis could not determine (the amp's answer to the bundled symbol-table CRC,
  whether the IAP strings are required, the amp's heartbeat timeout, blob byte-exactness, …)
  are listed in `analysis/notes/*` §"open questions". Where the mock has to pick a behaviour,
  it is documented as a *mock choice*, not a finding.

## Layer map → file map

| Layer | What | File |
|---|---|---|
| bytes | LE helpers, editor `TypedValue {tag, bits}` | `src/values.js` |
| checksums | CRC-16/CCITT-FALSE (incremental), CRC-32 (zlib) | `src/crc.js` |
| L6 link sync | `IAP x OK` / `IAP x START` / `IAP x STOP`, 200 ms state machine | `src/link.js` (`IapSync`, `IapDetector`) |
| L5 RSMC | 12-byte frames `55 55 …`, streaming parser with resync, ARQ (seq/ack/credit window 8, retransmit 1000 ms, 200 ms header-only keepalive) | `src/link.js` (`encodeFrame`, `FrameParser`, `LinkEndpoint`) |
| L4 McBsp | 8-byte transport header, 4-byte padding, several messages per frame, routing by address, option rewrite | `src/router.js` |
| L3 stream | SYN/FIN/DATA/WND/HB segments, 8-bit seq (abort on gap), window edge, heartbeat/timeout | `src/stream.js` |
| L1 RPC | `u32 cmd, u32 len, payload` requests, FIFO responses, events | `src/rpc.js` |
| editor service | all 22 commands, events types 2–8, tuner math | `src/editor.js` |
| librarian service | commands 1–15 (no status word on 1, 2, 3, 5) | `src/librarian.js` |
| names | editor `(group, paramID)` → DSP `(slot, param)` → symbol indexes; cab `@mic` → `LoadDspModel`; `@temposync` → `SyncSelect`; `@tempo` → cmd 14; device settings | `src/mapping.js` |
| symbol table | parse / verify / build, `tableCrc()` for the Handshake | `src/symtab.js` |
| preset blob | INFERRED port of `scripts/preset_blob.py` (lossless decode → encode) | `src/presetBlob.js` |
| device info | 200-byte record, firmware version correction, MTU/heartbeat rule | `src/deviceInfo.js` |
| guardrail | allow-list of streams, service modes, commands; storage-write confirmation; old-firmware refusal | `src/guard.js` |
| session | `AmpSession`: whole connect sequence and high-level API | `src/session.js` |
| time | `realClock`, deterministic `FakeClock` | `src/clock.js` |
| mock | `MockAmp`, in-memory transport pair with latency/drop/chunking | `mock/` |

## Using it

```js
import { AmpSession } from './src/index.js';

// transport = { write(Uint8Array), onData(cb) → unsubscribe, close(), onClose?(cb) }
const amp = new AmpSession(transport, {
  symbolTable: bundledTableBytes, // optional: your own copy of the app's defaultSymbolTable.bin
  cachedSymbolTable,              // optional: the table saved from a previous session
  models,                         // optional: mapping.indexModels(...the app's *.models JSON)
});
amp.on('symbolTable', ({ bytes }) => saveForNextTime(bytes));
amp.on('paramChanged', (e) => console.log(e)); // { group, paramId, value, onDevice }
amp.on('tuner', ({ note, name, cents }) => {});

await amp.connect();
await amp.setParam('amp', 'Drive', 0.5);
await amp.setParam('fx1', '@enabled', true);
await amp.setDeviceSetting('Master', 0.6);
await amp.selectPreset(3);                      // read slot 3 → write edit buffer
await amp.tunerOn();
await amp.savePreset(3, amp.editBufferBlob, { confirmWrite: true }); // writes the amp's storage
await amp.disconnect();
```

A Web Serial transport is a few lines (not included yet):

```js
const port = await navigator.serial.requestPort({ allowedBluetoothServiceClassIds: ['00001101-0000-1000-8000-00805f9b34fb'] });
await port.open({ baudRate: 115200 });
const writer = port.writable.getWriter();
const listeners = new Set();
(async () => { const r = port.readable.getReader(); for (;;) { const { value, done } = await r.read(); if (done) break; listeners.forEach((cb) => cb(value)); } })();
const transport = { write: (b) => writer.write(b), onData: (cb) => (listeners.add(cb), () => listeners.delete(cb)), close: () => port.close() };
```

No Line 6 asset is needed to run the library against the mock. For a real amp, the session
handshakes with the bundled table if you pass one; otherwise (or if the amp rejects it) it
downloads the amp's own table (editor cmds 2/3, ~16 KB, ~13 s at ~1.2 KB/s).

## Running the tests

```sh
cd analysis/protocol-js
node --test        # or: npm test
```

Some tests read the app's assets **at test time** from `../work/apktool/assets`
(`defaultSymbolTable.bin`, `*.models`, `default_preset.json`) and the vectors from
`../notes/test_vectors.json`. Nothing is copied into this folder; those tests skip with a
reason if the files are absent. Every vector in `test_vectors.json` must have a builder in
`test/vectors.test.js` or the suite fails.

## How the mock works

`mock/MockAmp.js` implements the amp side of every layer over `mock/memoryTransport.js`:

- watches the raw byte stream for `IAP x START` (resets RSMC and all streams: a *mock choice*)
  and `IAP x STOP`;
- RSMC endpoint, router, and stream listeners on 0x03ED (editor) and 0x03EF
  (librarian / device info). On 0x03EF it reads the service-mode word: 2 → echo + 200-byte
  device-info record; 1 → echo + librarian RPC; **0 → guard violation** (emits
  `guardViolation`, or throws if nobody listens);
- answers every editor and librarian command from its own state: edit buffer (a structured
  preset), 8 synthetic presets built with `presetToBlob` from made-up values (no Line 6 demo
  tones), names, device settings, sys params, PS keys, tempo, dirty flag;
- simulates the hardware: `turnKnob(group, param, value)`, `setMasterVolume(v)`,
  `selectPresetOnAmp(n)`, `saveOnAmp(n)`, `tapTempo(bpm)`, `setTunerOnAmp(on)`,
  `setFbvConnected(b)`, and a tuner that emits `Note` DSP events every `tunerIntervalMs`
  while enabled and registered.

Options: `firmwareVersion` ('2.50.2' or a raw u32), `productName`, `serialNumber`,
`symbolTable` (default: a synthetic table built from `mock/mockSymbols.js`, with indexes that
differ from the real table, so the download fallback is exercised), `forceTableDownload`,
`acceptCrcs`, `mtu` (TX, default 240), `rxMtu` (default 256), `presetCount`, `tunerValues`,
`tunerIntervalMs`, `maxDataFramesPerTick`.

`createMemoryTransportPair({ clock, latencyMs, dropFilter, dropRate, seed, chunkSize, corrupt })`
gives two linked transports with fault injection. With a shared `FakeClock` every test is
deterministic: `await clock.runUntil(session.connect())`.

## Firmware guardrail (PLAN.md §5.8)

`src/guard.js` is an allow-list, checked by `AmpSession` before any bytes are encoded and again
by `RpcClient` on the encoded bytes:

- streams 0x2002→0x03ED and 0x2003→0x03EF only;
- service-mode words 1 (LIBRARIAN) and 2 (DEVICE_INFO) only; word 0 (UPDATER) and port mode 1
  throw `FirmwareGuardError`;
- editor 1–17, 20, 21 and librarian 1–8, 10, 11, 14 and 12-to-edit-buffer are free;
  storage writes (librarian 9, 12 with idx ≠ 0xFFFFFFFF, 15; editor 18, 19, 22) need
  `{ confirmWrite: true }`; anything else (e.g. librarian 13) throws;
- an amp reporting firmware < 0x01000000 is refused (the official app would force an update).

`test/guard.test.js` also scans `src/` and fails if `update|flash|dfu|updater` appears in an
identifier outside `guard.js`.

## Implementation notes worth knowing

- **Heartbeat caveat.** Natively the stream heartbeat is T>>2 (4 s for fw ≥ 2.10.1) while a
  listener that saw flag 0x20 times out after 4 s. `AmpSession` therefore heartbeats every
  1 s by default (`heartbeatIntervalMs`). A test shows that one tick of jitter at 4 s kills a
  4 s listener.
- **MTU.** A receiver drops frames longer than its own MTU−12 as length errors, and the
  sender would retransmit the same oversize packet forever. The mock therefore sends ≤ 240-byte
  frames by default.
- **Back-pressure.** Streams only queue new DATA while the link backlog is < 2 messages
  (stand-in for the native RSMC's limited TX slots), so one stream's bulk transfer cannot
  starve another stream's heartbeats.
- **Firmware version.** `SetVersionNum` splits the minor number into decimal digits, so raw
  2.10.1 (0x020A0100) becomes 0x02100100, the MTU threshold (`deviceInfo.correctedVersion`).
- FIFO responses have no transaction id; a timed-out request keeps its slot so a late reply is
  discarded instead of being matched to the next request.

## Next steps (from PLAN.md, not built yet)

- `tools/btsnoop.js`: turn an Android HCI snoop capture into `{t, dir, hex}` RFCOMM chunks.
- `ReplayTransport`: replay amp→phone bytes from a capture and assert our phone→amp bytes.
- `WebSocketBridgeTransport`: binary WebSocket relay for devices without Web Serial (iPhone).
- A Web Serial transport module and the PWA itself.

## Contents and licensing

This folder contains only original code. It contains **no Line 6 assets**: no symbol tables,
model files, demo tones or binaries. Tests read the analysis copies at run time.
