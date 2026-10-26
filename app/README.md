# ReAmpliFi app (P1, read-only)

A Vite + Alpine.js PWA that works with the AMPLIFi 150 over Bluetooth SPP via Web Serial, plus a
full in-browser mock amp. All protocol bytes come from `../analysis/protocol-js` (Vite alias
`@protocol`, and `@mock` for MockAmp). The UI never builds bytes.

## Commands

```sh
npm install
npm run dev          # dev server, http://localhost:5173/ (Vite picks another port if busy)
npm run build        # production build in dist/, WITHOUT local model metadata (safe to deploy)
npm run build:local  # same, but bundles src/generated/metadata.json (private use only)
npm run preview      # serve dist/ locally
npm run gen-metadata -- --apk /path/to/Line.6.Remote.apk   # see "Model metadata"
```

## Mock mode

Open `http://localhost:5173/?mock=1`. The choice is remembered in `localStorage`; `?mock=0` or the
"Leave mock mode" button switches back to Web Serial.

In mock mode, `MemoryTransport ⇄ MockAmp` run in the page with the real clock and the native
link pacing (about one RSMC frame every 200 ms), so a connect takes 15–20 s, as expected on the
real amp. The **Mock amp** tab has:

- amp-side controls: turn a virtual knob, Master knob, select or save a preset on the amp, tap
  tempo, tuner button, guitar pitch for the tuner;
- link faults now: drop the link, or make the amp go silent (heartbeat timeout);
- next-connection options: firmware version (including one that is refused as too old), forced
  symbol-table download, drop rate, chunking, latency.

## Browser requirements

- **Web Serial** with Bluetooth RFCOMM: Chrome or Edge on desktop (117+, 130+ recommended for
  disconnect events), or Chrome 138+ on Android. Safari, Firefox, iOS browsers and Android
  WebViews cannot reach the amp. Mock mode works in any modern browser.
- A **secure context**: `https://`, or `http://localhost` during development.
- The Connect button opens the browser's port picker, narrowed to Serial Port Profile devices.
  Once a port was granted, "Reconnect" reuses it without the picker.

## Pairing the amp first

1. Switch the amp on and pair it in your OS Bluetooth settings (macOS System Settings →
   Bluetooth, Windows Settings → Bluetooth & devices, Android Settings → Connected devices).
   The browser lists only paired devices.
2. Disconnect other remotes: a phone running the official app may hold the amp's link.
3. In the app, press **Connect…** and pick the amp.

If the port opens but the amp never answers, toggle Bluetooth or re-pair. The connection log and
the byte log (Log drawer → "Byte log") show what happened, and "Copy log" copies both logs.

## What P1 sends

The session is opened with `readOnly: true`: param edits, preset loads and every storage write
are refused before anything is encoded. The connect sequence, preset-name reads and edit-buffer
reads are read-only commands. Tuner engage and disengage are the only live changes. The Device
tab and the log show every command sent and the number of storage writes (always 0 in P1).

## Model metadata

`src/generated/metadata.json` (gitignored) gives model display names, categories and param
ranges. Generate it from your own APK with `npm run gen-metadata -- --apk <file>` (it uses the
system `unzip`), or `-- --assets <extracted assets folder>`. Without it, the Tone view shows raw
symbol names and 0–1 ranges. Never commit or publish that file.
