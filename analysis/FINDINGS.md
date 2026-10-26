# FINDINGS: app structure and investigation log

Companion to `PROTOCOL.md`, which is the spec. This file covers how the official app is built, how it was analysed, what went wrong along the way, and what is still open.

Status tags: **CONFIRMED** (read in code or data), **INFERRED**, **UNKNOWN**. Ghidra address = ELF vaddr + 0x10000. Java paths are relative to `work/jadx/sources/com/line6/amplifi/`.

## 1. Package and versions
See `INVENTORY.md` §0–§1 for the full manifest, permissions, ABIs and file sizes. In short:
- `com.line6.amplifi` "AMPLIFi Remote", versionName 2.61.0, versionCode 17 (build stamp May 2018), minSdk 19, targetSdk 24.
- 32-bit native code only (armeabi, x86).
- Classic Bluetooth SPP. No BLE, USB or Wi-Fi control.

**Correction to INVENTORY §2.** The name filter matches the substring `FX100`, not `AMPLIFI_FX100` (`device/DeviceConnectionManager.java:34`, `AmplifiDeviceConnectionManager.java:21`). `notes/java_side.md` §1.2 has it right.

## 2. Architecture

```
Android UI (fragments, Otto bus) ──▶ EditorBuffer / BaseEditorBuffer  (string API: group, param, value)
                                         │  CommandRestrictingHandler (coalesce, ≥100 ms spacing)
                                         ▼
                               AmplifiDeviceManager  ── JNI ──▶ libAmplifiRemoteNdk.so ("EdLib")
   RFCOMM socket ◀── SppOutStreamData(byte[]) ───────────────┘  all framing, handshake, preset logic
   RFCOMM socket ──▶ nativeSppInStreamData(bytes) ──────────▶
```
Java is a thin shell. Every protocol decision is in the NDK library: framing, ARQ, handshake, symbol tables, preset serialization and firmware gates (CONFIRMED). Java calls a high-level edit-buffer API with string ids and receives `HashMap` notifications.

### 2.1 Notable Java classes (one-line roles)
| Class | Role |
|---|---|
| `device/AmplifiDeviceManager` | JNI declarations (lines 150–241), RFCOMM socket open/close (408–428), reader thread (346–387), SPP write callback (1072–1085), notification dispatch (774–960) |
| `device/DeviceConnectionManager`, `AmplifiDeviceConnectionManager` | Bonded-device list, name filter, ACL and A2DP triggers (5 s delay after A2DP connect) |
| `device/EditorBuffer`, `BaseEditorBuffer` | Public edit API (`setProcessorParamValueAsync`, `loadHardwarePreset`, `saveCurrentToHardware`, …); copies assets to filesDir |
| `device/EdlibScenarioManager` | Connect/disconnect scenarios; 3 retries, 6 s apart |
| `device/utils/CommandRestrictingHandler` | Drops superseded edits per key and keeps ≥ 100 ms between commands |
| `device/AssetManager`, `AmplifiAssetManager` | Parses `*.models` and catalogs for the UI |
| `models/Line6Device`, `ConnectedLine6Device` | Product ids (0x200001..0x200007) and model enum |
| `line6logic/SlidersLogicLibJNI` (+ `libSlidersLogicLib.so`) | UI slider layout and control→param curves; not protocol |
| `ui/editor/slider/logic/ModelParamLayouts` | Linear control→param map (EQ frequency curve exception) |
| `ui/tuner/TunerFragment` | `EngageTuner`, tuner callbacks |
| `ui/settings/ProductSpecificSettingsFragment` | TapTempoLED, with the fw gate constant 0x02000600 |
| `device/data/TonesContentProvider`, `cloud/*` | Local tone DB and Line 6 cloud (not needed for control) |
| `device/FirmwareUpdateService`, `DeviceUpdateManager`, `ui/firmware/*` | **AVOID** (§6) |

### 2.2 Notable native classes (libAmplifiRemoteNdk.so, C/C++, GCC 4.6, stripped but with many RTTI/log names)
| Class / module | Role |
|---|---|
| `AmplifiRemoteManager` | JNI façade. `OpenOnLine` 0x84b7e drives the connection sequence |
| `L6AndroidNdkDevice` | Device orchestration: device-info phase 0xa5cd0, MTU/timeout choice 0xa4b14, port open 0xa57e0 |
| `L6Device`, `L6DeviceCenter*` | Product id, name, model, serial, raw fw version holders |
| `AndroidSppMsgChannel` | IAP ASCII sync state machine, 200 ms timer, 4 KB out ring |
| `RobustSerialMsgChannel` (C) | RSMC framing, CRC-16, selective-repeat ARQ |
| `MsgRouter` / `BspRouter`, `MsgPortManager` | McBsp message routing by 16-bit address; router and timer threads |
| `MsgPort_Stream_*` (C) | TCP-like stream: SYN/FIN/DATA/WND/heartbeat |
| `L6BspMsgPort`, `L6BspMsgPort_Amplifi` | Port open/close, service-mode word |
| `ToneMatchEdit_Remote`, `ToneMatchLibrarian_Remote` | RPC client stubs (DoCommandCommon, HandleInPacket, FIFO tokens) |
| `FirmwareServiceInterfaceBase/Editor/Librarian(V2)` | Service wrappers: handshake choices, symbol lookups, preset cache thread. Despite the name, mostly *not* firmware |
| `ToneMatchFirmwareService`, `ToneMatchEditorService`, `ToneMatchLibrarianService` | Service lifecycle, event registration, V1/V2 choice, table caching |
| `A36EditorLibrarian` | Edit-buffer/librarian façade: setParam, settings, URIs, tuner, move |
| `A36EditBufferContext` | Local mirror of the edit buffer; sendParamToDevice, loadModel, preset load/save/sync |
| `L6A36Preset`, `L6SPePresetSerializer` | Device-preset blob serializer and parser; JSON tone read/write |
| `SymbolTable` | Name↔index table; `LookupString` returns the index |
| `L6EdLibModelDefs` | Reads `*.models`, value coercion and clamping |
| `L6EdLibPresetV5`, `L6EdLibDIFRead/Write` | Tone-file JSON container (zlib, Base64, stubbed "encryption") |
| `L6EdLibNotificationCenter` | Posts the `HashMap` notifications to Java |
| `L6BspUpdateEngine`, `L6UUE::*` | **AVOID**: firmware updater |

## 3. Tools and method

| Tool | Version | Use |
|---|---|---|
| jadx | 1.5.6 (Homebrew) | Java decompile → `work/jadx/sources`. 2 errors in 4088 classes; one com.line6 method left as a dump; smali from apktool is the fallback |
| apktool | 3.0.3 | Manifest, resources, assets, smali, libs → `work/apktool` |
| Ghidra | 12.2 (Homebrew), run headless on **openjdk@25** (25.0.5) | x86 `libAmplifiRemoteNdk.so`; `work/ghidra/run.log`, `run2.log` |
| OpenJDK | 27.0.1 also installed (jadx/apktool dependency) | – |
| Python 3 | stdlib only, always `python3 -I` | helper scripts below |

Ghidra pipeline:
- `analyzeHeadless` on the **x86** build. x86 was chosen over ARM because it is easier to read.
- **`scripts/ghidra/FixThunks.java` pre-script**: tags the x86 PIC helpers `__x86.get_pc_thunk.{bx,ax,cx,dx,si,di,bp}` with the call-fixup. Without it the decompiler cannot resolve GOT-relative addresses: strings, globals and vtables all come out wrong. The first run (`run.log`) had no pre-script; `run2.log` used it.
- **`ExportAll.java` post-script**: writes per-class C files to `work/ghidra/decomp/` (459 files, about 5,100 functions), `functions.tsv`, `strings_xrefs.tsv`, `jni_exports.txt` and `data_tables.txt`.
- **`DecompAt.java`**: creates functions Ghidra missed (static helpers reached only through function pointers) and decompiles them → `work/ghidra/extra/{msg_static.c, iostream.c}`.

Helper scripts (`scripts/`):
- `fn.py`: print a decompiled function by name or address.
- `vtables.py`: vtables with REL relocations → `work/vtables.txt`.
- `elfpeek.py`, `elfmem.py`: bytes, strings and pointer tables at Ghidra addresses.
- `parse_symtab.py`: symbol-table format and hash check.
- `crc16.py`: CRC identification, frame builders, self-test.
- `app_messages.py`: RPC vectors → `notes/test_vectors.json`.
- `preset_blob.py`: blob encode/decode.

Method notes:
- Ghidra address = ELF vaddr + 0x10000. Text file offset = vaddr; data file offset = vaddr − 0x1000.
- Every claim was traced to a function or data address. Java claims cite file:line.
- Binary content and assets were treated as untrusted data: scripts parse with `json` and `struct` only, and nothing from the APK was executed.
- Firmware paths were identified by name only and not analysed.

## 4. Dead ends, corrections and reconciliations

1. **"Params are CRC-32 hashes on the wire."** This was the early hypothesis in `java_side.md` §0.3 and §4.4. The symbol-table entries carry `crc32(name)`, and the native strings mention CalcCRC32. **Wrong.** `SymbolTable::LookupString` 0xd2b70 hashes the name only to find the entry and returns the **entry index**. The wire carries indexes. CRC-32 appears on the wire once, as the Handshake argument computed over the whole table file.
2. **"Encryption."** The `"encryption"` and `decrypted_size` strings belong to the DIF tone-file JSON container (`L6EdLibDIFWrite` 0xc00c2 / `Read` 0xc0733). The only type is `"L6"`, whose helpers 0xc0fd3 and 0xc1236 return −8301: an unimplemented stub. The link has no encryption or authentication (CONFIRMED by tracing every layer). The "handshake" is a symbol-table CRC comparison.
3. **Librarian status word (conflict between notes).**
   - `native_transport.md` §6.3/6.4 says every librarian response starts with an i32 status. `native_messages.md` §1 says cmds 1, 2, 3 and 5 have none. **native_messages wins.**
   - Re-checked in this pass: those four call `DoCommandCommon` with a null status pointer (0x10b670, 0x10b720, 0x10b7d0, 0x10b95e), and `HandleResponse` 0x10c352 adds 4 bytes of capacity only when a status pointer exists. A body larger than the capacity returns −19.
   - The amp actually replying without status is INFERRED, since the official app works.
4. **Ghidra missed static functions.** The router task 0x110300, stream TX 0x110880 and RX 0x1112e0, and the IOStream vtable targets 0x110d00/0x110e80/0x111010 had no function objects, because they are reached only via function pointers or DeferredTask. Recovered with `DecompAt.java`. `FUN_00110240` (routing lookup) is `__regparm2`, and the decompiler dropped its arguments, so routing by *dst* is INFERRED.
5. **x86 PIC.** Without `FixThunks.java`, every GOT-relative access was garbage (see §3).
6. **Cab models "missing" from the symbol table** (`java_side.md` §3.3 marked the cab wire id UNKNOWN). Resolved: cabs appear only with a mic suffix (`57OnAxis`, `57OffAxis`, `421`, `U67`) and are sent via editor cmd 8 LoadDspModel on slot StudioCab.
7. **Which symbol table the 150 uses.** `java_side.md` said `defaultSymbolTable.bin` (INFERRED, strong). Now CONFIRMED in `A36EditorLibrarian::connect` 0xe0a9e.
8. **Value wire encoding** (`java_side.md` §3.2, UNKNOWN). Resolved: TypedValue `{u32 tag, u32 bits}`, with floats as IEEE f32 in model units, clamped to the model range.
9. **Firmware threshold 0x02100100 = "2.10.1".** `native_transport.md` §3.2 had this as INFERRED. Upgraded to **CONFIRMED** in this pass: `L6StringToL6VersionInt` 0xa13e3 parses `"%d.%d.%d%c"`, splits minor into tens and units, and `SetVersionNum` 0xa1340 packs `maj<<24 | tens<<20 | units<<16 | patch<<8 | letter`. Two related facts:
   - **Java receives the raw (binary-minor) value**, while native gates use the corrected one. They differ only when minor ≥ 10.
   - Java's tap-tempo constant 0x02000600 decodes to 2.00.6, yet the UI text says "2.01" (minor oddity).
10. **Broken regex.** `isOldFirmware` contains literal quotes, so it never matches (`AmplifiDeviceConnectionManager.java:29-30`). It is harmless.
11. **Unused pull API.** `nativeSppOutStreamData/Count` are declared but never called. Native pushes via the `SppOutStreamData` callback instead.
12. **Offline mode.** The app starts the native library offline as an AMPLIFi 75 (0x200001, fw 0) for the UI, before any amp connects. This is not a wire behaviour.
13. **Overstatement softened.** `native_messages.md` says the amp "must reply to cmd 5 with exactly" 12 bytes. The client accepts any body ≤ 4 bytes, so PROTOCOL.md states the client rule as CONFIRMED and the amp's reply as INFERRED.

## 5. Assets of interest (in `work/apktool/assets/`)

**Rule: these are Line 6 assets.** Do not copy them into anything you publish: repos, app bundles, websites. At runtime, a personal tool can read them from the user's own APK. The symbol table can also be downloaded from the amp itself with editor cmds 2 and 3, which is read-only. PROTOCOL.md quotes only protocol identifiers (symbol names and indexes).

| Asset | Why it matters |
|---|---|
| `defaultSymbolTable.bin` (15,764 B, 611 entries, CRC-32 0xB68B291E) | The 150's index space for every wire id; handshake choice 2 |
| `defaultSymbolTable_{FX100,TT,Dio,AEON,Firebird}.bin` | Other products; not used by the 150 |
| `amps.models`, `cabs.models`, `stomps.models`, `mod.models`, `delay.models`, `reverbs.models`, `wahs.models`, `fixed.models` | Per-model params: `symbolicID`, `valueType`, `min`/`max`/`default`, `persist`, `tweak`; amps also have `cablink`, `cabER`, `cabmic`. Needed for value coercion, model-change defaults and blob building. `fixed.models` holds `@global_params` (tempo, tweak) |
| `*Catalog.json` | UI category → model lists (UI only) |
| `default_preset.json` (device 0x200002) | Reference tone; source of the 1210-byte blob vector |
| `Demo.zip` | Demo `.l6p` tones (JSON) and copyrighted mp3 jam tracks. **Never redistribute** |
| `manual.pdf`, images, fonts | Irrelevant to the protocol; do not copy |

Derived local files (keep them private):
- `work/symtab_default_dump.txt`
- `work/preset_blob_default_preset.hex`
- `work/l6p_sample/DemoAcousticSim.l6p`

## 6. Firmware-related code map (AVOID; names only, not analysed)
- **Java:** `device/FirmwareUpdateService`, `device/DeviceUpdateManager`, `EdlibScenarioManager.FirmwareUpdateScenario` and the force-update state helpers, `AmplifiDeviceManager.startFirmwareUpdate`, `cloud/firmware/*`, `ui/firmware/*`, `device/events/{ForceUpdateDeviceEvent, DeviceIsBrickedEvent, OutdatedFirmwareDetectedEvent, NoNeedToForceUpdateDeviceEvent, UpdateDialogEvent}`.
- **JNI:** `nativeStartFirmwareUpdate`; `nativeOpen` mode 2.
- **Native:** `AmplifiRemoteManager::OpenFirmwareUpdate` 0x850b4 / `startFirmwareUpdate` 0x89954; `L6AndroidNdkDevice::prepareForUpdating` 0xa5a2c / `startUpdate` / `forceFirmwareUpdate` / `handleUpdateEngineCallback`; `L6BspUpdateEngine::*`; `L6UUE::*`; `Checksum_Fletcher` 0xb8bd4; `FirmwareServiceInterface{Editor,Librarian}::PrepareForUpdate`, `ConvertToUpdater`; `ToneMatchFirmwareService::prepareServiceForUpdate`; `MsgPort_Stream_Abort`.
- **Wire markers:** ePortMode 1, service-mode word 0.
- **Notifications:** `DeviceUpdate*`, `Device_Bricked`; errors −9100 / −9101.
- No firmware images are bundled. They come from the Line 6 cloud and are MD5-checked in Java.

## 7. Consolidated open questions
Full table with the capture that answers each: PROTOCOL.md §17. In priority order for a first client:
1. Is the IAP ASCII sync required, and does the amp answer it? (HCI snoop of the official connect)
2. The amp's RSMC and stream parameters: initial rx_limit, SYN flags/MSS, heartbeat cadence, WND usage. (Same snoop)
3. Does the amp accept the bundled table CRC 0xB68B291E, or force a download? (Snoop, or a live read-only handshake)
4. This amp's firmware version, and therefore MTU 240 vs 256. Also the unknown last 4 bytes of the device-info record. (Read-only phase A)
5. Is the preset blob byte-exact? Compare one GetPresetFile reply with `preset_blob.py`. (Snoop of connect sync)
6. Learning the current preset index at connect, and the effect of LoadHardwarePreset (13). (Experiment)
7. MovePresetFiles semantics; whether `nameLen` includes the NUL; amp status codes. (Snoop of reorder/list/bad request)
8. Units and persistence of Master/GuitOutputGain, and persistence of PS-key writes (cmd 19). (Experiment, after a backup)
9. Tuner event rate; event/response interleaving. (Long snoop)
10. Global-EQ sys params on the 150; `device_version` packing in `.l6p`. (Read-only experiment / comparison)
