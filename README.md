# ReAmpliFi

An independent remote-control app that **works with the AMPLIFi 150** guitar amp. It talks to your
own amp over Bluetooth Classic (SPP) from the browser, through Web Serial.

ReAmpliFi is not affiliated with, endorsed by or supported by Line 6 or Yamaha. "AMPLIFi" is used
only to say which amp the app works with.

Scope: settings and presets only. Firmware update, flashing, DFU and the amp's updater mode are out
of scope for good, and the code refuses them (`analysis/protocol-js/src/guard.js`).

## Status

- The protocol was reconstructed by **static analysis** of the official Android app, for
  interoperability. **Nothing has been tested on a real amp yet.**
- Phase 1 (this version) is **read-only**: connect, device info, symbol-table handshake (with
  download fallback), preset names, a live view of the current tone, the tuner, and a byte log.
  It sends no param edits and no storage writes. The tuner on/off switch is the only live change.
- Everything can be developed and checked against **MockAmp**, a software amp that runs in the
  browser or in Node.

See `analysis/PLAN.md` for the phases (P2 live edits, P3 preset select, P4 storage writes with
backups first).

## Repository map

| Path | What |
|---|---|
| `analysis/PROTOCOL.md`, `FINDINGS.md`, `INVENTORY.md`, `notes/` | Protocol spec and analysis notes |
| `analysis/PLAN.md` | Platform choice, architecture, phased plan, on-device checklist |
| `analysis/protocol-js/` | Pure-JS protocol library (`src/`), Web Serial transport (`src/transports/`), MockAmp (`mock/`), tests, `tools/gen-metadata.js` |
| `app/` | The ReAmpliFi PWA (Vite + Alpine.js) |

## Run the tests

```sh
cd analysis/protocol-js
node --test
```

Node 20 or later. Some tests read your local, gitignored copy of the app's assets in
`analysis/work/` when it exists, and skip otherwise.

## Run the app

```sh
cd app
npm install
npm run dev
```

Then open <http://localhost:5173/?mock=1> for the mock amp. (If port 5173 is busy, Vite prints the
port it picked.) Without `?mock=1` the app uses Web Serial: Chrome or Edge on desktop, or Chrome
138+ on Android, with the amp paired in the OS Bluetooth settings first. Details in
`app/README.md`.

## Model names from your own APK (optional)

The amp reports parameters by index. Readable model names, categories and ranges come from the
official app's asset files, which this repository does not contain. Generate them locally from your
own copy of the APK:

```sh
node analysis/protocol-js/tools/gen-metadata.js --apk /path/to/Line.6.Remote.apk
# or, from an extracted copy:  --assets analysis/work/apktool/assets
```

This writes `app/src/generated/metadata.json`, which is gitignored. Without it the app shows raw
symbol names (for example `BritGainJ800`) and 0–1 ranges. `npm run dev` uses the file when it
exists. `npm run build` leaves it out, so a public deploy carries no Line 6-derived data.
`npm run build:local` includes it, for your own use only.

## What is deliberately not here

No Line 6 files: no APK, no decompiled code, no symbol tables, no `*.models`, catalogs, preset
JSON, demo audio, images, icons or logos. `.gitignore` blocks these file types. The mock amp
uses a synthetic symbol table and made-up presets. The app icon is original artwork.
