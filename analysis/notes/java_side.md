# Java side + data assets (Line 6 AMPLIFi Remote 2.61.0) — static analysis

Scope: Java (jadx) + assets. Native (libAmplifiRemoteNdk.so) is analysed separately; only a few native
*string* observations are included here (marked "native strings") as hints, read with `strings`.

Legend: **CONFIRMED** = read in code/data (file:line, method). **INFERRED** = deduced. **UNKNOWN** = not determinable from Java.
Paths are relative to `analysis/work/jadx/sources/com/line6/amplifi/` unless stated.
Assets are in `analysis/work/apktool/assets/`.

Helper script: `analysis/scripts/parse_symtab.py` (run with `python3 -I`). Derived dump of the 150's symbol
table: `analysis/work/symtab_default_dump.txt`. One sample tone: `analysis/work/l6p_sample/DemoAcousticSim.l6p` (JSON only, no audio).

---------------------------------------------------------------------------------------------------

## 0. Key takeaways

1. Java is a thin shell. The whole protocol (framing, handshake, sync, keepalive, preset serialization) is native.
   Java exposes a **high-level, string-addressed "edit buffer" API**: `(groupID, paramID, value)` where
   groupID is a block name (`amp`, `cab`, `fx1`…) and paramID is a symbolic id (`Drive`, `@model`, `@enabled`, `@tempo`…). CONFIRMED.
2. Values are boxed Java objects: `Float` (most knobs, normalized 0..1), `Long` (enums/indices), `Boolean` (switches), `String` (model ids, tweak targets). CONFIRMED.
3. The `defaultSymbolTable*.bin` files are **CRC32 → name tables** (standard zlib CRC32 of the ASCII name; verified for 100% of entries in all 6 tables). CONFIRMED.
   They contain DSP-side names (`Drive`, `BritGainJ800`, `FX1Enable`, `ChannelVolume`, `Master`, `GuitOutputGain`…), not the `@`-prefixed editor ids.
   So the wire protocol very likely addresses models/params by 32-bit CRC32 of the DSP symbol name, and native translates editor ids → DSP symbols. INFERRED.
4. Outbound bytes are **pushed by native** via Java callback `SppOutStreamData(byte[])` on a native thread. `nativeSppOutStreamData/Count` are declared but never called from Java. CONFIRMED.
5. No Java-side crypto, authentication, pairing (`createBond`), or handshake logic. A handshake exists **in native** (strings). CONFIRMED (Java) / native strings.

---------------------------------------------------------------------------------------------------

## 1. Connection sequence end to end

### 1.1 App start (offline init) — CONFIRMED
- `MainApplication.onCreate` (MainApplication.java:64-72) starts a thread: `assetManager.initializeAssets(this)` (parses *.models + catalogs in Java) then `editorBuffer.startOffline(2097153, 0)` (= product 0x200001 AMPLIFi 75, fw 0).
- `EditorBuffer` constructor (device/EditorBuffer.java:12-17) → `AmplifiDeviceManager` ctor → `init()` (device/AmplifiDeviceManager.java:313-323) copies these assets to `context.getFilesDir()` (EditorBuffer.getProductSpecificResources, EditorBuffer.java:20-36):
  `amps.models, cabs.models, delay.models, fixed.models, mod.models, reverbs.models, stomps.models, wahs.models, default_preset.json, defaultSymbolTable.bin, defaultSymbolTable_FX100.bin, defaultSymbolTable_TT.bin, defaultSymbolTable_Dio.bin`.
  (`_AEON`/`_Firebird` tables and `default_preset_AEON.json` are NOT copied by this flavor.)
- `System.loadLibrary("AmplifiRemoteNdk")` static init (AmplifiDeviceManager.java:255-257).
- `OfflineConnectScenario.onStarted` (EdlibScenarioManager.java:331-335) → `initializeOfflineLibrary(productId, fw)` (AmplifiDeviceManager.java:470-480):
  1. `nativeInitialize(filesDir.getAbsolutePath())` — **only argument is the files dir path**; native finds the copied assets by name (native strings contain `defaultSymbolTable*.bin`, `default_preset.json`, `defaultSymbolTablePath : %s`).
  2. `nativeSetNotificationDelegate(this)` — the only place it is set.
  3. `nativeOpen(1 /*OFFLINE_MODE*/, 2097153, 0, editorFlags=0, librarianFlags=0)`.
  - Completion comes asynchronously as notification `EdLib_Connect` → `offlineInitialized = true` (EdlibScenarioManager.java:338-344).
- `nativeTerminate()` is declared but never called. CONFIRMED.

### 1.2 Discovery — CONFIRMED
- No scanning/inquiry, no `createBond`. The amp must already be paired in Android settings.
- `DeviceConnectionManager.open()` (DeviceConnectionManager.java:93-101), called from `ui/MainActivity.java:218`:
  - registers a receiver for `ACL_CONNECTED` / `ACL_DISCONNECTED` (lines 47-74);
  - requests A2DP profile proxy (`getProfileProxy(ctx, this, 2)`, line 99).
- Triggers to connect:
  - `ACL_CONNECTED` for a supported name → `EditorBuffer.line6BluetoothDeviceSystemConnected(dev)` immediately (line 63-68).
  - A2DP `onServiceConnected` (lines 195-215): if an already-connected A2DP sink has a supported name → same call **after a 5 s delay** (`schedule(…, 5L, SECONDS)`, line 210).
  - Manual pick in settings: `ui/settings/DeviceSelectionFragment.java:119` → `userHasChosenLine6Device(item)`; list = bonded devices filtered by name (`getAMPLIFiDevices`, DeviceConnectionManager.java:161-175).
  - `connectAsAudioSink` uses reflection `BluetoothA2dp.connect(BluetoothDevice)` (line 116-125) — audio only, not control.
- Name matching (`AmplifiDeviceConnectionManager.checkIfSupportedDevice`, AmplifiDeviceConnectionManager.java:20-22): `name.toUpperCase().contains()` any of `AMPLIFI_75`, `AMPLIFI_150`, `FX100`, `AMPLIFI_TT`, `AMPLIFI_30`. (Firehawk names are defined but not accepted in this flavor.)
- Routing: `AccountManager.getUserAdvancedRouting()` false (default "simple routing") → a newly ACL-connected amp replaces the current one; advanced → keep current (EdlibScenarioManager.java:182-201).

### 1.3 Socket + open — CONFIRMED
`OnlineConnectScenario.onStarted` (EdlibScenarioManager.java:362-369) → state CONNECTING → `openOnlineWithDevice` → `openOnline` (lines 441-448) → `openWithDeviceInMode(device, 0 /*NORMAL_ONLINE_MODE*/, 0)` (AmplifiDeviceManager.java:482-526):
1. `stopSppThreads()`; if no socket or different device: `closeSppSocket()` then `openSppSocket(device)` (lines 408-428):
   - `device.createInsecureRfcommSocketToServiceRecord(UUID 00001101-0000-1000-8000-00805f9b34fb)` (line 412) — **insecure** RFCOMM, SDP lookup of SPP UUID.
   - **No** secure variant, **no** reflection `createRfcommSocket(1)` fallback, **no** `cancelDiscovery()`.
   - `socket.connect()` blocking; then get streams.
   - failure → `statusChangeListener.connectionFailed()`, return `L6_ERROR_SPP_OPEN_FAILED (-123)`.
2. `startSppThreads()` → `handleBluetoothInputStream()` (lines 343-400): starts reader thread, waits up to 50×10 ms for it to run.
3. `nativeSetSppDelegate(this)`, `nativeSetTunerDelegate(this)`.
4. `nativeOpen(0, 0 /*productId: let native detect*/, 0 /*minOnlineFwVersion*/, 0, 0)` (line 509).
   - returns 0 = opened, 1 = pending (normal; await `EdLib_Connect`), negative = error.
   - `-9100 L6ERR_DEVLIB_DEVICE_FORCE_UPDATE` → builds ConnectedLine6Device from native getters and enters force-update state (AVOID path); `-9101` bricked; `-9102` not supported. Any error → `openCleanup()` = `nativeClose`, delegates null, stop threads, close socket (lines 535-545).
5. `EdLib_Connect` notification (value `Long`, 0 = success) → `edlibConnectNotification` (EdlibScenarioManager.java:256-266) → `OnlineConnectScenario.onEdlibConnect` (lines 372-376): `initializeLine6DeviceState()` (AmplifiDeviceManager.java:756-762: reads `nativeGetModelName/OfficialModelName/ProductId/FirmwareVersionAsString/FirmwareVersion`) → state CONNECTED. Then `BaseEditorBuffer.onLine6DeviceStateCreated` → `checkFootPedalConnection()` (`GetDeviceSetting("FBVConnected")`) and cloud firmware list refresh (AVOID).

### 1.4 Retries — CONFIRMED
- `NEXT_RECONNECT_DELAY_MILLIS = 6000`, `RECONNECT_COUNT_MAX = 3` (EdlibScenarioManager.java:21-22).
- Only when `openWithDeviceInMode` returns a generic error synchronously (incl. socket failure −123): `shouldScheduleReconnect` re-posts the same scenario with 6 s delay while `reconnectCount <= 3` → **max 4 attempts** (lines 450-458).
- Async `EdLib_Connect` failure (non-zero) only calls `connectionFailed()`; no retry (lines 386-390).

### 1.5 Read path — CONFIRMED
- Reader thread (AmplifiDeviceManager.java:346-387): `byte[64]` buffer; loop: if `available() > 0` → `read(buf, 0, 64)` → `nativeSppInStreamData(bytesRead, buf)`; else `Thread.sleep(5)`. IOException/NPE → just stop the loop (native is **not** told).

### 1.6 Write path — CONFIRMED
- Native calls back `SppListener.SppOutStreamData(byte[])` (AmplifiDeviceManager.java:1072-1085) which writes the whole array to `bluetoothOutputStream`. On IOException sets `receivedOutputStreamException` and silently drops all further writes until next `startSppThreads`.
- Native strings: callback looked up with signature `([B)V` name `SppOutStreamData`, from a native thread attached to the VM (`handleSpp() Unable to attach … thread to Java VM`).
- `nativeSppOutStreamData(int)` / `nativeSppOutStreamDataCount()` (pull API) are **never called** from Java (grep). CONFIRMED.
- Who triggers sends: native (on API calls, handshake, timers). No Java timer/poller.
- Java-side throttling of parameter edits: `CommandRestrictingHandler` (device/utils/CommandRestrictingHandler.java:8,23-30) on thread `paramChangeHandlerThread` (BaseEditorBuffer.java:41-43): removes queued runnables with the same key (group+param for params, name for settings/meta), and delays to keep **≥100 ms** between posted commands. So the official app sends at most ~10 edits/s (coalesced).

### 1.7 Disconnect — CONFIRMED
- Requested: `closeCurrentSPPAsync()` → `OnlineDisconnectScenario` (EdlibScenarioManager.java:480-506): `destroyLine6DeviceState()`, state DISCONNECTING, `nativeClose()`; on `EdLib_Disconnect` notification → `stopSppThreads`, `closeSppSocket`, DISCONNECTED.
- `ACL_DISCONNECTED` for supported device (simple routing) → `closeCurrentSPPAsync()` (lines 203-207).
- Unexpected `EdLib_Disconnect` with no scenario running → `OnlineUnexpectedDisconnect` → `connectionFailed()` + same cleanup (lines 293-301, 466-478).
- Switching amps: post Disconnect then Connect scenarios (lines 229-235).

### 1.8 Keepalive / timers
- Java: none (no Timer/ScheduledExecutor in the device path apart from the 5 s A2DP delay). CONFIRMED.
- Native strings mention `AndroidSppMsgChannel::execTasks() - stopping timer`, states `SYNCHING_STAGE1 Iap_Ok`, `SYNCHING_STAGE2 Iap_Start`, `RSMC` → keepalive/sync handshake is native. INFERRED.

### 1.9 Flags — CONFIRMED
`editorFlags`/`librarianFlags` start at 0 and `enable*Flag` is never called anywhere → always 0. `LIBRARIAN_DISABLE_CACHE = 2` exists but is unused (so native librarian caching is presumably enabled).

---------------------------------------------------------------------------------------------------

## 2. JNI surface

### 2.1 Java → native: `com.line6.amplifi.device.AmplifiDeviceManager` (declared lines 150-241; all exported in native as `Java_com_line6_amplifi_device_AmplifiDeviceManager_*`)

| native method | signature | Java wrapper / caller | purpose |
|---|---|---|---|
| nativeInitialize | (String filesDir) int | initializeOfflineLibrary (470) | init lib, load assets from dir. CONFIRMED |
| nativeTerminate | () int | — never called | teardown |
| nativeOpen | (int mode, int productId, int fwVersion, int editorFlags, int librarianFlags) int | initializeOfflineLibrary (476): (1,0x200001,0,0,0); openWithDeviceInMode (509): (0,0,0,0,0) online / (2,0,0,…) fw-update AVOID | open edlib in mode 0 online, 1 offline, 2 firmware-update |
| nativeClose | () int | closeEdlibMode, openCleanup | close session (async EdLib_Disconnect) |
| nativeSetNotificationDelegate | (NotificationListener) void | offline init (473) | register handleNotification target |
| nativeSetSppDelegate | (SppListener) void | openWithDeviceInMode (507), null in openCleanup | register SppOutStreamData target |
| nativeSetTunerDelegate | (TunerListener) void | same | register tuner callbacks |
| nativeSppInStreamData | (int count, byte[] buf) int | reader thread (364) | feed received bytes |
| nativeSppOutStreamData | (int) byte[] | — unused | pull outgoing bytes (alt. API) |
| nativeSppOutStreamDataCount | () int | — unused | pending outgoing byte count |
| nativeGetProductId | () int | GetProductId | e.g. 0x200002 for 150 |
| nativeGetFirmwareVersion | () int | GetFirmwareVersion | packed fw version |
| nativeGetFirmwareVersionAsString | () String | GetFirmwareVersionAsString | |
| nativeGetProductName / nativeGetModelName / nativeGetOfficialModelName | () String | Get* (ProductName unused) | |
| nativeStartFirmwareUpdate | (byte[] image) int | FirmwareUpdateScenario | **AVOID** |
| nativeSetDeviceSetting | (String name, Object value) int | SetDeviceSetting ← BaseEditorBuffer.DeviceSettingChangeRunnable | global settings (Master, GuitOutputGain, TapTempoLED) |
| nativeGetDeviceSetting | (String) Object | GetDeviceSetting | read setting (Float/Boolean/Long) |
| nativeGetModelList | () String[] | — unused | |
| nativeGetModelInfo | (String) HashMap | — unused | |
| nativeIsEditBufferModified / nativeSetEditBufferModified | ()Z / (Z)I | isDirty, SetEditBufferMetaTagNoDirty… | dirty flag |
| nativeSetEditBufferParam | (String groupID, String paramID, Object value) int | SetEditBufferParam ← ParamChangeRunnable | **main edit call** |
| nativeGetEditBufferParam | (String groupID, String paramID) Object | GetEditBufferParam | read cached value |
| nativeGetEditBufferParamGroups | () String[] | getProcessorNames | list blocks in edit buffer |
| nativeGetEditBufferParamIDsForGroup | (String) String[] | wrapper only, unused | |
| nativeMoveEditBufferItem | (String src, String dst) int | moveProcessor ← FlowView | FX reorder |
| nativeSetEditBufferMetaTag / nativeGetEditBufferMetaTag | (String, Object) int / (String) Object | meta getters/setters | tone metadata (name, author…) |
| nativeSetPresetBufferMetaData | (byte[] preset, String tag, Object v) byte[] | SyncAdapter, Upload/RateToneLoader | edit meta inside a serialized preset blob |
| nativeSaveEditBufferTo | (String uri) int | SaveEditBufferToUri ← saveCurrentToHardwarePreset | store edit buffer to amp slot |
| nativeLoadEditBufferFrom | (String uri) int | loadHardwarePreset | recall amp slot |
| nativeSaveEditBufferToDataBuffer | () byte[] | getCurrentPresetBytes | export current tone (L6Preset JSON, INFERRED) |
| nativeLoadEditBufferFromDataBuffer | (byte[]) int | loadNewPresetIntoBuffer | load tone JSON (cloud/DB/demo) into edit buffer |
| nativeGetEditBufferUri | () String | unused | |
| nativeGetPresetUUID | (String uri) long | unused | |
| nativeSetResourceName / nativeGetResourceName | (String uri, String) int / (String) String | GetResourceName ← getPresetNameByPosition (Set unused) | slot names |
| nativeCopyResource / nativeSetResource / nativeGetResource | … | unused | |
| nativeMoveResource | (String uri, int index) int | ManageHardwareTonesFragment.java:53 | reorder amp slots |
| nativeGetResourceCount | (String uri) int | getHardwarePresetsNumber | slot count |
| nativeEngageTuner | (boolean) int | EngageTuner ← ui/tuner/TunerFragment.java:220 | tuner on/off |
| nativeDebugEditor | (String, Object) int | unused | debug |
| *(native-only)* nativeIsTunerEngaged | exported in .so, **not declared** in Java | — | (native strings) |

### 2.2 Native → Java callbacks — CONFIRMED (Java side) + native strings (signatures)
| Java method | interface | sig (native strings) | thread | behaviour |
|---|---|---|---|---|
| `handleNotification(HashMap<String,Object>)` | NotificationListener (AmplifiDeviceManager.java:774-960) | `(Ljava/util/HashMap;)V` | native-attached thread | dispatch by key (see 3.3) |
| `SppOutStreamData(byte[])` | SppListener (1072-1085) | `([B)V` | native thread | write bytes to RFCOMM |
| `tunerEngaged(boolean engaged, boolean onDevice)` | TunerListener (1088-1100) | `(ZZ)V` | native | |
| `tunerValue(int note, float cents)` | TunerListener (1103-1111) | `(IF)V` | native | |
No `@Keep`/annotations (app is not obfuscated, so none needed).

### 2.3 Other JNI: `line6logic/SlidersLogicLibJNI` (libSlidersLogicLib.so, SWIG)
UI-only: panel/param layout definitions per model id (`GetModelPanelViewDefForModelID(long)`, `GetParamIDLayoutDefFromParamLayoutType(int)`, `Get{Amp,Cab,Delay,Mod,Reverb,Stomp,Wah,…}Panels`, `IS_HD_*`, ParamLayoutDefs getters for control/param/display min/max, curve type, detents), plus `SetVersionNum(short×4,char)` and `toL6VersionInt(String)`. Not involved in transport. CONFIRMED. Its param min/max define the Java slider→param mapping (see 3.2).

---------------------------------------------------------------------------------------------------

## 3. Feature map

### 3.1 Addressing model — CONFIRMED
- Edit buffer = groups (blocks) × params. Group ids (SlidersLogicLibConstants): `amp, cab, compressor, eq, fx1, fx2, fx3, fx4, gate, global, reverb, volume, wah` (+ `looper`, `variax` constants). Matches `default_preset.json` "tone" keys.
- Param ids: plain DSP names from `*.models` (`Drive`, `Bass`, `Mid`, `Treble`, `Presence`, `Time`, `Feedback`, `SyncSelect`…) or editor pseudo-params with `@`: `@model, @enabled, @post, @mix, @mixtype, @stereo, @temposync, @volume (amp), @mic (cab), @level (looper)`, global `@tempo, @tweakgroup, @tweakparam, @tweakmin, @tweakmax, @pedal2assign` (AEON only `@fs1group…@fs5group`).
- Device (global, non-preset) settings: string names via SetDeviceSetting: `Master`, `GuitOutputGain`, `TapTempoLED`, read-only `FBVConnected` (Boolean), `VariaxConnected` (Long). Global-EQ/crossover names (`BypassGlobalEQ`, `GlobalLowGain`…, `Crossover`, `StereoWidth`, `WooferHPFSelect`) are defined as constants but not used by this Java flavor.
- Hardware preset URIs (BaseEditorBuffer.java:58-66; AmplifiDeviceManager.java:48-51; ConnectedLine6Device.getMidiInHexFormat `"0x%08x"`):
  - count: `l6device://0x00200002:/preset/`
  - slot n: `l6device://0x00200002:/preset//<n>` (native string `l6device://0x%08x:/preset//%d`).
  - n is 0-based; UI maps bank/slot as `n = (bank-1)*4 + posInBank - 1` (ui/tones/HardwareTonesAdapter.java:92-95) → banks of 4.
- Value types: `SingleSliderValue.getValueInProperType` (ui/editor/slider/SingleSliderValue.java) converts by the existing value's class: `Long` (rounded), `Float`, `Boolean` (round==1). `*.models` `valueType`: 0=int→Long, 1=float→Float, 2=bool→Boolean, 3=string→String. CONFIRMED.

### 3.2 Value scaling — CONFIRMED (Java), wire encoding UNKNOWN
- UI control value → param value: `ModelParamLayouts.ControlValueToParamValue` (ui/editor/slider/logic/ModelParamLayouts.java:744-762): linear map control[min,max] → param[min,max] from SlidersLogicLib layout def; special piecewise curves only for EQ frequency (`XTEQFreqDSPCurve`, k-scaled breakpoint at 0.503937).
- The values handed to native are therefore the "param values" as stored in preset JSON: mostly normalized floats 0..1; exceptions (from *.models min/max): `@tempo` 30..240 BPM; Gate `Thresh` −96..0 (dB); FXLoop `Send/Return` −59.5..12 dB; Looper `HP Frequency` 5..1000, `LP Frequency` 1000..20000 Hz; ints e.g. `SyncSelect` 1..14 (note division), `@mixtype` 0..2, cab `@mic` 0..3, Variax ints.
- How native turns these into wire values (float32? 16-bit?) is UNKNOWN from Java.

### 3.3 Features

| feature | Java entry point | native call | addressing / value | status |
|---|---|---|---|---|
| Select amp preset slot | `BaseEditorBuffer.loadHardwarePreset(idx)` (78-89) ← loaders/HardwareToneLoader.java:29 | nativeLoadEditBufferFrom(uri) | `l6device://0x00200002:/preset//idx` | CONFIRMED |
| Load app tone (cloud/DB/demo .l6p) to amp | `loadNewPresetIntoBuffer(bytes,rowId)` (46-56) ← GetToneLoader:40, DatabaseLoadToneLoader:31, ui/music/JamGetToneLoader.java:43-44 | nativeLoadEditBufferFromDataBuffer(jsonBytes) | raw L6Preset JSON bytes | CONFIRMED (that it is pushed to amp when online: INFERRED) |
| Save to amp slot | `saveCurrentToHardware(idx)` (91-101) ← SaveToHardwareLoader:33 | nativeSaveEditBufferTo(uri) then reload slot | slot uri | CONFIRMED |
| Read preset list/names | loaders/HardwareTonesLoader.java:31-35 → `getHardwarePresetsNumber`, `getPresetNameByPosition(i)` | nativeGetResourceCount(".../preset/"), nativeGetResourceName(".../preset//i") | | CONFIRMED (native likely serves from handshake cache: native strings "Handshake - %d presets", "GetPresetName(%d)") |
| Reorder amp slots | ManageHardwareTonesFragment.java:53 | nativeMoveResource(uri, toIndex) | | CONFIRMED |
| Rename slot | (SetResourceName exists, unused) — name set via meta `name` then save | nativeSetEditBufferMetaTag("name", String) | | CONFIRMED |
| Amp model change | `changeProcessorToAsync("amp", symbolicID)` (529-531) ← DevicePickerFragment.java:103 | nativeSetEditBufferParam("amp","@model","BritGainJ800") | String symbolicID from amps.models | CONFIRMED |
| Cab model / mic / level | same, group `cab` | ("cab","@model",String) / ("cab","@mic",Long 0..3) / ("cab","Level",Float) | | CONFIRMED (Java); cab names absent from symbol table → cab wire id UNKNOWN |
| Effect on/off | `setProcessorEnabledAsync(group, b)` (508-510) ← SlidersFragment.java:113 | ("fx1","@enabled",Boolean) | | CONFIRMED |
| Effect model change | `changeProcessorToAsync("fx1", id)` | ("fx1","@model",String) | | CONFIRMED |
| Pre/post amp | — (read via isPostProcessor) | ("fxN","@post",Boolean) | | CONFIRMED (read); write path via generic param |
| FX reorder | ui/editor/flow/FlowView.java:587 → `moveProcessor(src,dst)` | nativeMoveEditBufferItem("fx1","fx3") | notification `EditBuffer_AmplifiFXReordered{onDevice,newFXGroups}` | CONFIRMED |
| Knob params (gain/drive, bass, mid, treble, presence, amp volume, delay time/feedback, reverb decay/mix…) | `setProcessorParamValueAsync(group, symId, v)` (512-515) ← SlidersFragment.java:260,276 | nativeSetEditBufferParam(group, symId, Float) | e.g. ("amp","Drive",0.63f), ("amp","@volume",…), ("reverb","@mix",…) | CONFIRMED |
| Master volume | `setMasterVolumeAsync(Float)` (319-321) ← ui/volume/VolumeFragment.java:63 | nativeSetDeviceSetting("Master", Float) | percent slider, likely 0..1 (INFERRED) | CONFIRMED |
| Guitar volume | `setGuitarVolumeAsync` (327-329) ← VolumeFragment.java:54 | nativeSetDeviceSetting("GuitOutputGain", Float) | | CONFIRMED |
| Tap tempo | ui/editor/slider/BPMButton.java onTouchEvent: BPM = 60000/Δt (avg of last 2 intervals), clamp 30..240 → SlidersFragment.java:121 `setTempoAsync` (311-313) | ("global","@tempo",Float BPM) | tap timing computed in Java; no "tap" command sent | CONFIRMED |
| Tempo sync per FX | `setProcessorTempoSyncParamValueAsync` (546-548) | ("fxN","@temposync",Boolean); note division ("fxN","SyncSelect",Long 1..14) | | CONFIRMED |
| Tap-tempo LED | ui/settings/ProductSpecificSettingsFragment.java:21 → `setTapTempoLEDAsync` | nativeSetDeviceSetting("TapTempoLED", Boolean) | gated on fw ≥ 33555968 (0x02000600, "2.01") | CONFIRMED |
| Tweak knob assign | `setTweakParamAsync`, `setTweakMin/MaxValueAsync`, `setPedal2AssignAsync` (290-382) | ("global","@tweakgroup",String group), ("global","@tweakparam",String symId), @tweakmin/@tweakmax Float 0..1, @pedal2assign Boolean | | CONFIRMED |
| Tuner | ui/tuner/TunerFragment.java:220 `EngageTuner(bool)` | nativeEngageTuner(bool) | callbacks: tunerEngaged(engaged,onDevice); tunerValue(note,cents): note ordinal 0=A,1=B♭…11=A♭, −1 invalid; cents ±51 | CONFIRMED |
| Global FX bypass | none found | — | only per-block @enabled | UNKNOWN / not in app |
| Tone metadata | `setMeta*Async` (157-283) | nativeSetEditBufferMetaTag(tag, v) | tags: name, song, style, substyle, comments, band, guitarist, author, rating, instrument, pickuptype, ptyp, modifieddate (s), pickupconfig, tnid | CONFIRMED |
| State query / sync | `getProcessorsViewsDescriptions` (453-480), `getProcessorModel` (482-493), `getProcessorParamValue`, `GetDeviceSetting` | nativeGetEditBufferParamGroups / GetEditBufferParam / GetDeviceSetting | reads native's mirrored state (no explicit "request state" call in Java) | CONFIRMED (Java); sync-on-connect is native (INFERRED) |
| Amp-side changes (knob turn, preset knob, save on amp) | `handleNotification` (774-960) → BaseEdlibNotificationManager → Otto bus | — | see notification list below | CONFIRMED |
| Firmware version read | `initializeLine6DeviceState` (756-762) | nativeGetFirmwareVersion / AsString | int packed (format UNKNOWN; 0x02000600 ≈ "2.01") | CONFIRMED |
| Foot pedal (FBV) | `checkFootPedalConnection` (576-585) | GetDeviceSetting("FBVConnected") Boolean | also Device_SettingChanged | CONFIRMED |

Notification keys handled by Java (AmplifiDeviceManager.java:52-66, 782-958) — payload is a HashMap:
- `EdLib_Connect` → Long result (0 ok); `EdLib_Disconnect`.
- `EditBuffer_ParamChanged` → {groupID:String, paramID:String, value:Object, onDevice:Boolean} — onDevice=true means the change came from the amp (knob turn). Bus: PresetParameterChangeEvent.
- `EditBuffer_PropChanged` → {groupID, tagID, value} (meta).
- `EditBuffer_PresetChanged` (no payload) — whole edit buffer replaced.
- `EditBuffer_DevicePresetChanged` → {onDevice:Boolean, presetIndex:Long} — preset selected on amp.
- `EditBuffer_PresetSavedToDevice` → {onDevice, presetIndex}.
- `EditBuffer_AmplifiFXReordered` → {onDevice, newFXGroups: HashMap fx1..fx4 → new group}.
- `EditBuffer_AmplifiTweakAssignChanged` (HashMap, ignored contents).
- `Device_SettingChanged` → {setting:String, value:Object} (Master/GuitOutputGain Float, FBVConnected Boolean, VariaxConnected Long).
- `DeviceUpdateStarting/Status(Float)/Finished/Failed/Cancelled` → AVOID.
- Native emits more keys not handled by Java (native strings): `EditBuffer_TunerEnable`, `EditBuffer_TunerValue`, `EdLib_TaskProgress`, `DeviceConnect`, `DeviceFirmwareVersion`, `DeviceSerialNo`, `DeviceMidiId`, `DeviceInterlockHeld`, `Device_Bricked`, Helix librarian keys (shared library).

---------------------------------------------------------------------------------------------------

## 4. Data formats

### 4.1 `*.models` (amps, cabs, delay, fixed, mod, reverbs, stomps, wahs) — CONFIRMED
JSON array of models. Model keys: `symbolicID` (String, editor/DSP model name), `id` (int, Line 6 "A36" model id; bit layout in line6logic/SlidersLogicLibConstants: A36_TYPE_MASK 0x0FF00000: amp=0, cab=0x01000000, fx=0x02000000, electric gtr=0x03000000; A36_FAMILY_MASK 0x00FF0000, e.g. FX delay 0x020000; e.g. L6LowRezDelay id 0x0202000D), `category` (int UI category), `name`, `shortname`, `icon`, `params[]`; amps also `cablink` (default cab symbolicID), `cabER` (float), `cabmic` (int); one delay has `devices` [product ids] (DynamicDelay → Firehawk only).
Param keys: `symbolicID`, `name` (absent for hidden), `valueType` (0 int, 1 float, 2 bool, 3 string), `min`, `max`, `default`, `persist` (0..4, 1000=@enabled, 1001=@post, absent for hidden params), `tweak` (int, tweak-knob ordering/eligibility).
- Counts: amps 79, cabs 26, delay 15, fixed 9 (`@global_params` id 1047527424, VolumePedal, Gate, SharcPodFixedComp, ParaGraphic4_band, FXLoop, LooperFx500, `@variax`, `@global_params_AEON`), mod 23, reverbs 15, stomps 31, wahs 8.
- Ranges: 875/882 floats are 0..1 (exceptions listed in 3.2).
- Java parses these itself (`AssetManager.parseProcessorsFromFile`, device/AssetManager.java:87-95) for UI; native also reads the copied files. `id` is used by SlidersLogicLib for slider layouts (`GetModelPanelViewDefForModelID`). Whether `id` or CRC32(symbolicID) goes on the wire: UNKNOWN (see 4.4: amp/FX model names are in the symbol table, cab names are not).
- `persist` meaning INFERRED: a per-model ordinal of the param in the device's persistent preset layout (0..4 for knobs; 1000/1001 for enable/post).

### 4.2 Catalogs — CONFIRMED
`AmpCatalog.json` {Clean, American, British, High Gain}, `FXCatalog.json` {Drives & Dynamics, Mods, Delays, "Filters, Synths, and Pitch"}, `CabCatalog.json` {Cabinets}, `ReverbCatalog.json` {Reverbs}, `WahCatalog.json` {Wahs}: map category → ordered list of model symbolicIDs (UI only; device/AmplifiAssetManager.java:32-41).

### 4.3 `default_preset.json` / `.l6p` tones — CONFIRMED
Plain JSON, schema:
```
{ "schema": "L6Preset", "version": 5,
  "data": { "device": <productId int>, "device_version": <int>,
            "meta": { name, author, band, song, style, substyle, guitarist, comments, instrument, pickuptype, pickupconfig, ptyp, rating, modifieddate(unix s), tnid, [application, appversion] },
            "tone": { "<group>": { "@model": "<symbolicID>", "<param>": value, ... }, ..., "global": {"@tempo":..., "@tweakgroup":..., ...} } } }
```
- default_preset.json: device 2097154 (AMPLIFi 150), device_version 7471224 (0x00720078), groups amp, cab, compressor, eq, fx1..fx3, gate, global, reverb, volume, wah.
- Demo.zip → `Demo/Tones/*.l6p` (63 entries, incl. __MACOSX junk); sample `DemoAcousticSim.l6p` (3074 B) is the same JSON (not binary, not zipped), device 2097159 (AMPLIFi 30), device_version 38338816 (0x02490100), meta has `application:"AMPLIFi"`, `appversion:1`.
- Demo tones are read as text and passed raw to `nativeLoadEditBufferFromDataBuffer` (ui/music/JamGetToneLoader.java:43-44; ui/music/presenter/JamTrackCategoriesPresenter.java:196-216). Cloud tones (`cloudApiManager.getTone`) take the same path (loaders/GetToneLoader.java:39-40).
- Device-side preset format is different: native has `L6SPePresetSerializer`, `L6A36Preset::SerializeToDeviceForGroup(SymbolTable*, …)` (native strings) → binary key/typed-value serialization keyed by symbol ids. INFERRED.
- `device_version` packing UNKNOWN (0x02490100 for an AMPLIFi 30 tone suggests 0xMMmmbbxx-style, 2.49.1? not verified).

### 4.4 `defaultSymbolTable*.bin` — CONFIRMED (format), INFERRED (role)
Layout (little-endian), verified by `analysis/scripts/parse_symtab.py` on all 6 files:
```
u32 count            (defaultSymbolTable.bin: 611)
u32 file_size        (== actual length, 15764)
count × { u32 str_offset (relative to blob), u32 crc32(name), u32 str_len }   (12 bytes each)
blob: NUL-terminated ASCII names, starting at 8 + 12*count (0x1CAC)
```
- hash = standard CRC-32 (zlib/IEEE) of the name: 611/611 match (also 100% for _AEON 1145, _Dio 629, _FX100 629, _Firebird 1180, _TT 629). Entries are not sorted.
- Contents: DSP graph names: model names (all 79 amps + all stomps/mod/reverb/wah models present), param names (`Drive`, `Bass`, `Time`…), per-param companions `<name>State`, routing/system names (`ToneMatchMain`, `GuitarProc`, `Crossover`, `GuitFixedEQ`, `TMCrossoverTable12`, `FX1Enable`, `FX1Post`, `FX1MixType`, `ChannelVolume`, `CabEnable`, `Tuner`, `Reference`, `Period`, `Note`, `Master`, `Headphone`, `GuitOutputGain`, `GuitInputGain`, `MusicGain`…). Editor `@` ids and group names (`amp`, `fx1`) are NOT present; cab model names are NOT present.
- Which file for AMPLIFi 150: Java copies 4 tables and lets native choose. `defaultSymbolTable.bin` is the one containing ToneMatch / `TMCrossover*Table12/8` / `MusicGain` entries (the 75/150 "ToneMatch" family; TT/FX100/Dio tables drop those and add `MainOutL/R`, `SB*__GP_*` EQ). → 150 uses `defaultSymbolTable.bin`. INFERRED (strong). Native strings list all six filenames in order default, FX100, TT, Dio, AEON, Firebird.
- Role: native strings `FirmwareServiceInterfaceEditor::FetchSymbolTable`, `Handshake fetching symbol table...`, `Handshake (choice N) - symbolTableSize %d`, `SymbolTable::CalcCRC32`, `SymbolTable::InitFromTableData`, `ToneMatchEdit_Remote::SetDspModelParam(uint, uint, TypedValue*)` → the amp can supply its own symbol table during handshake, the bundled file is a default/cache (probably compared by CRC32), and DSP params are addressed by (u32 model/block hash, u32 param hash). INFERRED.

---------------------------------------------------------------------------------------------------

## 5. Firmware-related code — AVOID (listed only, not analysed)
- `device/FirmwareUpdateService.java` — Android service: downloads image from Line 6 cloud, MD5 check, calls `editorBuffer.prepareForFirmwareUpdate` / `finishFirmwareUpdate`.
- `device/DeviceUpdateManager.java` — fetches cloud firmware list, `startFirmwareUpdateService(...)`.
- `EdlibScenarioManager.FirmwareUpdateScenario`, `prepareForFirmwareUpdate`, `finishFirmwareUpdate`, `isFirmwareUpdating`, force-update state (`forceUpdateWillBeNeeded`, `isInForceUpdateState`, `cleanForceUpdateState`).
- `AmplifiDeviceManager.startFirmwareUpdate` / `StartFirmwareUpdate` → `nativeStartFirmwareUpdate(byte[])`; `nativeOpen` with mode `FIRMWARE_UPDATE_MODE = 2`; `FirmwareUpdateClientListener`; `DeviceUpdate*` notifications; error codes −9100 (force update) / −9101 (bricked).
- `cloud/firmware/*` (FirmwareUpdate, FirmwareUpdatesList*), `ui/firmware/*` (AmpFlashFragment, FirmwareUpdateDialogFragment, UpdateDetailsFragment, UpdateInformationDialogFragment, UpdatesListAdapter, ProductSpecific* variants, events/*).
- `device/events/{ForceUpdateDeviceEvent, DeviceIsBrickedEvent, OutdatedFirmwareDetectedEvent, NoNeedToForceUpdateDeviceEvent, UpdateDialogEvent}`.
A control app must never call nativeOpen mode 2 equivalents or any of the above.

---------------------------------------------------------------------------------------------------

## 6. Handshake / auth / encryption / version checks visible from Java
- No `javax.crypto`, no key material, no challenge/response, no `createBond`, insecure RFCOMM (no link-level authentication requested by the app). CONFIRMED.
- Handshake is fully native; Java only waits for `EdLib_Connect` (Long 0). CONFIRMED.
- Version checks: native returns −9100 force-update / −9102 not supported; Java passes `minOnlineFwVersion = 0` (EdlibScenarioManager.java:443-447, `EnvironmentSettings.MIN_SUPPORTED_FIRMWARE_VERSION = 0`); tap-tempo LED gated on fw ≥ 0x02000600; `isOldFirmware` BT-name regex is broken (literal quotes) so never matches. CONFIRMED.
- Native strings suggest integrity checks, not encryption: `CRC16_Process`, `Checksum_Fletcher`, `GetToneMatchPresetChecksum`, `SymbolTable::CalcCRC32`; no AES/cipher strings seen. INFERRED.

---------------------------------------------------------------------------------------------------

## 7. Open questions for the native-side analyst
1. Framing of `AndroidSppMsgChannel` / "RSMC": start bytes, length, CRC16 (which polynomial/init?), sequence/ack, and the `SYNCHING_STAGE1 Iap_Ok` / `STAGE2 Iap_Start` sync exchange — iAP-style? What must the host send first after RFCOMM connect?
2. Keepalive/timer period and what happens on missed acks (since Java never reports read errors to native).
3. Handshake "choice 1/2/3": what selects it, what version word is exchanged (`Handshake - version 0x%x`), and is the symbol table fetched from the amp each time or only when CRC32 differs from `defaultSymbolTable.bin`?
4. Wire encoding of `SetDspModelParam(u32,u32,TypedValue)`: are the two u32 the CRC32 of block/model and param DSP names from the symbol table? How are `@enabled`/`@post`/`@mix`/`@volume` mapped (→ `FX1Enable`, `FX1Post`, `ChannelVolume`…)? TypedValue tags for float/int/bool/string; float32 or scaled int?
5. How cab models are identified (names absent from symbol table) — by A36 `id`, by index, or by `cablink`?
6. Preset slot recall/store/rename/move messages (`l6device://…/preset//n` → which command; 0-based index?), and the librarian handshake (preset count, names, checksums, file sizes).
7. System settings (`SetSystemSetting(appSystemSettingsKey…)`, `SetPersistentSysParam`): numeric keys for `Master`, `GuitOutputGain`, `TapTempoLED`, `FBVConnected`.
8. Inbound events: format of amp-originated param change / preset change / tap tempo (`ProcessTapTempoEventQueue`) / FBV status messages, and tuner stream (`tunerValue(note,cents)` source).
9. `nativeGetFirmwareVersion` int packing (0x02000600 ≙ "2.01"?) and `device_version` in presets (0x00720078, 0x02490100).
10. Offline open uses product 0x200001 (AMPLIFi 75); does online open re-select symbol table/product after reading the amp's product id (0x200002 for 150)?
