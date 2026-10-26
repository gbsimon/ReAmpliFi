# Native APPLICATION layer: service RPC payloads (libAmplifiRemoteNdk.so, x86)

Scope: what goes *inside* the editor / librarian service streams. McBsp, stream, RSMC framing, CRC16, IAP sync, keepalive and the DeviceInfo phase are in `native_transport.md`; they are not repeated here.

**Legend**
- **CONFIRMED**: read in decompiled code (function and Ghidra address given).
- **INFERRED**: deduced, not read directly.
- **UNKNOWN**: not determinable statically.

Ghidra address = file vaddr + 0x10000.

**Helper scripts** (all `python3 -I`, in `analysis/scripts/`):
- `fn.py`: print a decompiled function by name or address.
- `vtables.py`: dump `_ZTV*` vtables with resolved REL relocations. Output is in `work/vtables.txt`.
- `elfmem.py`: read pointer and string tables from the .so.
- `app_messages.py`: encoder/decoder for these messages, and the generator of `notes/test_vectors.json`.
- `preset_blob.py`: device-preset blob encoder/decoder.

---------------------------------------------------------------------------------------------------

## 0. Verdicts

1. **Envelope.** Every request is `u32 cmd LE, u32 payload_len LE, payload`. Every inbound message is `u32 type LE, u32 len LE, body`. CONFIRMED (`ToneMatchEdit_Remote::DoCommandCommon` 0x103850, `HandleInPacket` 0x106b16, librarian 0x10b4ea / 0x10c61e).
2. **Parameter addressing.** Parameters are addressed as `(u32 slotIndex, u32 paramIndex)`. These are the **0-based indexes of the DSP names in the symbol table**, not CRC-32s. CONFIRMED:
   - `SymbolTable::LookupString` 0xd2b70 hashes the name with CRC-32 only to find the entry, then **returns the entry index**.
   - The CRC-32 appears on the wire only once: as the Handshake argument, computed over the whole table file.
3. **Values.** Values travel as an 8-byte `TypedValue {u32 tag, u32 bits}`:
   - tag 0 = void, 1 = symbol (a symbol-table index), 2 = int32, 3 = bool (0/1), 4 = float32 IEEE, 5 = varray.
   - Knobs are float32 in model units (mostly 0..1), clamped to the model's min/max before sending.
   - CONFIRMED (`FUN_000ec4c5` 0xec4c5, the type names in `handleParamEvent` 0x109c86, `CheckParamValueForModel` 0xc2e10).
4. **Single-parameter edits** go to editor cmd 10 `SetDspModelParam`. The editor ids (`@enabled`, `@volume`, …) are first mapped to DSP names by fixed tables in the .so (§2). CONFIRMED.
5. **Bulk operations use one binary "device preset" blob over the librarian**, never one message per parameter (CONFIRMED). This covers:
   - model changes, FX reorder, preset select, save, and loading a JSON tone.
   - The blob goes through `GetPresetFile` (11) and `SetPresetFile` (12), with index `0xFFFFFFFF` meaning the edit buffer.
   - **Preset select = read slot N, then write that blob into the edit buffer.** The dedicated "LoadHardwarePreset" (13) exists but is never used.
6. **Inbound events are pushed by the amp without being requested.** Registering patch, param, tap and FBV events is local only. Only DSP events (the tuner `Note`) need `RegisterDspEvent` (11). CONFIRMED.
7. **No encryption or authentication at this layer.** The "handshake" only checks that the amp's symbol table matches the client's, by CRC-32. CONFIRMED.

---------------------------------------------------------------------------------------------------

## 1. Envelope and services

| | editor service | librarian service |
|---|---|---|
| Transport port | BSP port mode 2, 0x2002↔0x03ED (`L6AndroidNdkDevice::connectWithObjHelper` 0xa53xx) | mode 3, 0x2003↔0x03EF; the transport sends service-mode word 1 first |
| RPC object | `ToneMatchEdit_Remote`, `Init(port, 0x200 tokens, 7 event tokens, 0x10 max event body)` 0x106dfa | `ToneMatchLibrarian_Remote`, `Init(port, 0x200)` |
| Request | `write(&{u32 cmd, u32 len}, 8)` then `write(payload, len)` (port vtable +0x18) | same; `len` may cover a third write (SetPresetFile blob) |
| Inbound | `read(&{u32 type, u32 len}, 8)`, then `read(body, len)` (port vtable +0x14) | same; only type 0 (ignored) or 1 (response). Anything else → −4 |
| Response match | FIFO against the oldest outstanding request; no sequence id | FIFO; when the call supplies a status pointer, the body is `i32 status` + data |
| Timeouts | 5000 ms; BindTweakParam 1000 ms; GetSymbolTable infinite. Timeout → −28 | 5000 ms; GetSymbolTable infinite |

- "Async" sends (e.g. `SetDspModelParamAsync` 0x104168) still queue a token, so the amp still answers. The client then drains and discards the reply (`FUN_001063d1`). CONFIRMED client side.
- Editor responses are raw. They begin with an `i32 status` only where the table in §8 lists one.
- **Correction to `native_transport.md` §6.3/6.4:** librarian GetVersion (1), GetSymbolTableSize (2), GetSymbolTable (3) and GetNumPresets (5) take **no status word**.
  - Their call sites pass a null status pointer: `GetVersion` 0x10b670, `GetNumPresets` 0x10b95e.
  - `HandleResponse` 0x10c352 then rejects any body longer than the data capacity.
  - The amp must therefore reply to cmd 5 with exactly `01000000 04000000 <u32 count>`. CONFIRMED.

---------------------------------------------------------------------------------------------------

## 2. Addressing: editor ids → DSP (slot, param) → symbol indexes

Call chain, all CONFIRMED:

1. JNI `nativeSetEditBufferParam` 0x7e0d8 → `NewL6Variant` (Java Float → L6Variant type 6, Boolean → 9, String → 8, Long → integer type).
2. → `AmplifiRemoteManager::setEditBufferParam` 0x87a74 (vtable +0x58) → `IL6EditorLibrarian::setEditBufferParam` 0xde00e → `A36EditorLibrarian::setEditBufferParam` 0xe2486.
3. That function branches on the parameter:
   - `paramID == "@model"` → `A36EditBufferContext::loadModel` 0xd5a9c, which sends a partial blob (§4).
   - otherwise → `A36EditBufferContext::setParam` 0xd6eda:
     - `L6A36Preset::SetParamWithValidation` updates the local mirror;
     - `sendParamToDevice` 0xdaa7a;
     - posts `EditBuffer_ParamChanged{groupID, paramID, value, onDevice:false}`.
4. `sendParamToDevice`:
   - finds the group's current `@model` (`@global_params` for group `global`);
   - runs `L6EdLibModelDefs::CheckParamValueForModel` 0xc2e10 (coerce and clamp);
   - resolves `GetDSPSlotForGroupAndParam` 0xeafcf;
   - → `ToneMatchEditorService::setToneMatchModelParam(param, slot, v, false)` 0x108c62 → `FirmwareServiceInterfaceEditor::SetToneMatchModelParam` 0xecc98.
5. `SetToneMatchModelParam` does `slotIdx = LookupString(slot)`, `paramIdx = LookupString(param)`, then `FUN_000ec4c5` builds the TypedValue. It then calls `ToneMatchEdit_Remote::SetDspModelParamAsync` 0x104168 → `SetModelParamCommon` 0x10403e → `DoCommandCommon(10, {slotIdx, paramIdx, tag, bits}, 16)`.
   - `""` as the slot gives 0xFFFFFFFF, the root slot.
   - An unknown name gives error −21.

**`GetDSPSlotForGroupAndParam` 0xeafcf.** The AMPLIFi tables are below; AEON/Firehawk use a different table at 0x23e660 / 0x23e8e0.

- **Param starts with `@`:** the slot is `GuitarProc`, and the parameter comes from table @0x23e540 (via `FUN_000eb6c2`):

| group | @enabled | @post | @mix | @mixtype | other |
|---|---|---|---|---|---|
| cab | CabEnable | – | – | – | `@mic`: see below |
| gate / compressor / eq | GateEnable / PostCompEnable / PostEQEnable | – | – | – | |
| wah | WahEnable | – | – | – | |
| volume | VolumePedalEnable | VolumePost | – | – | |
| fx1 / fx2 / fx3 | FXnEnable | FXnPost | FXnMix | FXnMixType | |
| reverb | FX4Enable | FX4Post | FX4Mix | **none** (fails −4) | |
| amp | – | – | – | – | `@volume` → ChannelVolume |

  `@stereo` exists only on AEON. On the 150 it is unresolvable and returns −4.

- **Plain param** (e.g. `Drive`): the slot is `GroupIDToSlotSymbol` 0xeaec6 (table @0x23e820) and the parameter name is passed through unchanged.
  - Slots: gate→Gate, volume→VolumePedal, wah→Wah, fx1/fx2/fx3→FX1/FX2/FX3, **reverb→FX4**, amp→Amp, cab→StudioCab, compressor→PostComp, eq→PostEQ.
  - **Exception:** `cab`/`Level` → slot `Air`, param `Level`.

**Special cases in `sendParamToDevice`** (CONFIRMED):
- **`@temposync`.** The param is renamed to `SyncSelect`:
  - false → `TypedValue int 0`;
  - true → the stored `SyncSelect` value (int 1..14).
  - It is sent to the FX slot, e.g. `(FX2, SyncSelect)`.
- **`cab`/`@mic` (0..3).** `L6A36Preset::CabModelAndMicToStudioCabSymbol(cab@model, mic)` appends `57OnAxis` / `57OffAxis` / `421` / `U67` (table @0x23eb04) to the cab name, e.g. `4x12BritT75Studio421`. That goes out as editor **cmd 8 `LoadDspModel {slotIdx("StudioCab"), modelIdx(symbol)}`** via `setToneMatchModel` 0x108b88 → `LoadToneMatchModel` 0xec9fe.
  - **Cab models do not appear in the symbol table under their plain names, only with the mic suffix.** All 25×4 combinations are present.
- **`global`:**
  - `@tempo` → cmd 14 `SetGlobalTempo(float32 BPM)`.
  - `@tweakmin`, `@tweakmax`, `@pedal2assign` (and Variax keys 25..33) → `ParamIDToPSKey` 0xeb1c9 (table @0x23e9e0) → cmd 19 `SetPresetPSKeyParam {u32 key, TypedValue}`. Keys: 3 tempo, 7 tweakmin, 8 tweakmax, 9 pedal2assign. Firmware gate in §9.
  - `@tweakgroup` / `@tweakparam` → `bindTweakParam` 0xd8618 → `bindTweakOnDeviceForGroup` 0xdbd1c → cmd 13 `BindTweakParam {slotIdx, paramIdx}`, with the DSP address of the tweaked parameter.
- **`variax`** group → PS keys. Not relevant for the 150.

**Value typing** (CONFIRMED, `CheckParamValueForModel` 0xc2e10, using `valueType` from the `*.models` JSON):

| model valueType | coercion | TypedValue |
|---|---|---|
| 1 float | int → float; out of range → clamped to min/max; non-number → default | tag 4, float32 bits |
| 0 int | float → round half away from zero; bool → 0/1 | tag 2, int32 |
| 2 bool | int → bool | tag 3, 0/1 |
| 3 string | `@model`, tweak group/param | never sent as a TypedValue (model changes go by blob; tweak by bind) |

**Ranges** (from the models): most parameters are 0..1. `@tempo` 30..240, `SyncSelect` 1..14, `@mixtype` 0..2, `@mic` 0..3.

**Example** (`app_messages.py setparam … amp Drive 0.5`; indexes from `defaultSymbolTable.bin`):
```
0a000000 10000000 | 17020000 (Amp=535) 17000000 (Drive=23) 04000000 0000003f (float 0.5)
```

**Model change** (`@model`). CONFIRMED by the blob fork:
- `loadModel` sets `@model` and repopulates parameters:
  - values carry over where the `persist` number matches;
  - otherwise they take the model default;
  - an amp change also loads its `cablink` cab, `cabER` and `cabmic`.
- It then sends **one partial blob** via `sendModelToDeviceForGroup` 0xda900 → `WriteModelToDevice` → librarian `SetPresetFile(0xFFFFFFFF, blob)`.
- Editor `LoadDspModel` is not used for this.

**FX reorder** (`nativeMoveEditBufferItem`): `swapFXModel*` 0xd8f00..0xd9a5c → `WriteFXToDevice(mask)` → a partial blob, sent the same way.

---------------------------------------------------------------------------------------------------

## 3. Device settings (`nativeSetDeviceSetting`)

Chain: JNI 0x7da68 → `AmplifiRemoteManager::setDeviceSetting` 0x8764a → `A36EditorLibrarian::setDeviceSetting` 0xe15ac. CONFIRMED.

- **Name aliases:** `"MasterVolume"` → `"Master"`, `"GuitarVolume"` → `"GuitOutputGain"`.
- **If `ParamIDToSysParamKey` 0xeb30b (table @0x23e480) has the name** → cmd 18 `SetPersistentSysParam {u32 key, TypedValue}` (`FSIEditor::SetPersistentSysParam` 0xedd58).
  - Keys 14..24 are sent async; everything else waits for the reply.
  - Key 29 (Crossover) sends a TypedValue of tag 1 (symbol) holding a symbol index.
  - Keys: TapTempoLED **7**, VariaxSettings 8, VariaxTuningMode 9, GlobalLowCut 14, GlobalLowFreq 15, GlobalLowQ 16, GlobalLowGain 17, GlobalMidFreq 18, GlobalMidQ 19, GlobalMidGain 20, GlobalHighFreq 21, GlobalHighQ 22, GlobalHighGain 23, GlobalHighCut 24, GuitarOnlyGlobalEQ 25, BypassGlobalEQ 26, Divergence 27, StereoWidth 28, Crossover 29.
- **Otherwise**, as a DSP parameter on the **root slot**: `setToneMatchModelParam(name, "")` → cmd 10 `{0xFFFFFFFF, idx(name), TypedValue}`. This is how **`Master` (idx 608) and `GuitOutputGain` (idx 610)** are set, as float32 (Java Float). The range 0..1 is INFERRED from the Java slider.
- `FBVConnected` and `VariaxConnected` are read-only; setting them returns −4.
- On success the native side posts `Device_SettingChanged{setting, value, onDevice:false}`.

**Reads** (`getDeviceSetting` 0xe192c):
- sys-param keys → cmd 17 `GetPersistentSysParam {u32 key}` → `{i32 status, TypedValue}`;
- `FBVConnected` → cmd 16 → `u32`;
- `VariaxConnected` → cmd 21 `GetSystemSetting` (AEON only);
- anything else → cmd 9 `GetDspModelParam {0xFFFFFFFF, idx}` → `{i32 status, TypedValue}`.

**Examples:**
- Master 0.5: `0a000000 10000000 ffffffff 60020000 04000000 0000003f`
- TapTempoLED on: `12000000 0c000000 07000000 03000000 01000000`

---------------------------------------------------------------------------------------------------

## 4. Presets: librarian messages and the blob

All CONFIRMED unless marked otherwise.

**URI parsing** (`ParseURI` 0xcf85e):
- `l6device://0x00200002:/preset//<n>` gives folder 0 and **index n, 0-based, no offset**.
- `l6device://0x00200002:/preset/` gives index −1 (the count URI).

| feature (JNI) | chain | wire |
|---|---|---|
| Select slot n (`LoadEditBufferFrom`) | `A36EditorLibrarian::loadEditBufferFrom` 0xe3fee → `A36EditBufferContext::loadPresetFromDevice` 0xd5444 | 1. librarian **11 GetPresetFile {u32 n}** → `{i32 status, blob}`<br>2. parse locally<br>3. **12 SetPresetFile {u32 0xFFFFFFFF, u32 L, blob}** (header len = 8+L)<br>4. post `EditBuffer_PresetChanged` |
| Save to slot n (`SaveEditBufferTo`) | `saveEditBufferTo` 0xe3be4 → `savePresetToDevice` 0xd5796 → `L6A36Preset::WriteToDevice` | **12 SetPresetFile {n, L, fullBlob}**, then post `EditBuffer_PresetSavedToDevice{onDevice:false, presetIndex}` |
| Rename (`SetResourceName`) | `setResourceName` 0xe4dc8 returns −3 for device URIs | **no message.** Set meta `name` (local only, `setMetaData` 0xd7d26 sends nothing), then save; the name is settings key 0 inside the blob (≤63 chars) |
| Move (`MoveResource(uri src, dst)`) | `moveResource` 0xe5e46 → `MovePresetFiles` 0x10bcb4 | **9 {u32 dst, u32 src}**; local cache shifted as insert/move (INFERRED amp semantics) |
| Name (`GetResourceName`) | `getResourceName` 0xe54aa → cache, or **6 GetPresetName {u32 n}** | resp `{i32 status, u32 nameLen, char[nameLen ≤ 64]}` (NUL included: INFERRED) |
| Count (`GetResourceCount`) | `getResourceCount` 0xe60d4 | cached from handshake **5 GetNumPresets** → `u32` (no status) |
| UUID / info | 7 GetPresetUUID → `{status, u64}`; 14 GetPresetInfo → `{status, u64 uuid, u32 checksum, u32 size, u32 nameLen, char[64]}` | background cache refresh |
| Recall without blob | **13 LoadHardwarePreset {u32 n}** → `{status}` | layout CONFIRMED; unused by the app; effect INFERRED |

- **Librarian V1 vs V2.** Chosen in the `ToneMatchLibrarianService` constructor 0x10d230: V2 when the product is 0x200001 or 0x200002 with fw > 0x010008FF, or the product is 0x200003–0x200007.
  - V2 refreshes each cache entry with a single cmd 14 GetPresetInfo.
  - V1 uses cmds 8, 6, 7, 10 and 11.
  - The message formats are identical.
  - Cmd 15 (SetPresetFile, AEON flag) is used only by AEON.
- **Blob size limit:** 0x8000 bytes.

**Device-preset blob** (CONFIRMED structure, from the serializer at 0x100302.. and the parser at 0x100eec; `preset_blob.py`):
- **Records:** `u32 key LE, u16 tag LE, payload`. The blob tags are *not* the editor tags:
  - 0 void
  - 1 bool u32
  - 2 int i32
  - 3 float f32
  - 4 string: u32 length (including NUL), then bytes
  - 6 varray: u32 word count, then words
  - 7 symbol: u32 **symbol index**
- **Directive keys:** 0x80000000 section id (2 = PS settings, 1 = DSP), 0x80000001 section magic (`PSRP` 0x50525350 / 0x47545254), 0x80000002 section end, 0x80000003 slot start (symbol), 0x80000004 slot end, 0x80000005 asset/model (symbol), 0x80000006 state count, then that many `(u32 idx("<Param>State"), typed)` pairs.
- **PS section keys:**
  - 0 name
  - 4/5 tweak slot/param symbols
  - 1/2 tnid lo/hi, full tone only
  - 3 tempo, full tone only
  - 7/8/9 tweakmin/max/pedal2assign, only when target fw ≥ 0x02110300
- **DSP section:** root slot `GuitarProc` with model `ToneMatchGuitarFlow` (the enables, post, mix and mixtype states, ChannelVolume), then the slots Gate, VolumePedal, Wah, FX1, FX2, FX3, FX4 (reverb), Amp, Air (`TNGAIRReflections`, LevelState), StudioCab (cab+mic symbol), LiveCab (the amp's `cablink`), PostComp, PostEQ.
- **Partial blobs** (model change) have the PS section without keys 1/2/3, plus the GuitarProc entries and slots of that one group. For `amp`: Amp, Air, StudioCab, LiveCab.
- **Not verified on hardware.** The blob for `assets/default_preset.json` is 1210 bytes; it is in `test_vectors.json` as INFERRED.
- **Order of states inside a slot:** UNKNOWN (hash order). The amp probably matches states by symbol (INFERRED).

---------------------------------------------------------------------------------------------------

## 5. Full JSON tone load (`nativeLoadEditBufferFromDataBuffer`)

CONFIRMED (blob fork):
1. JNI 0x7f31c → `AmplifiRemoteManager::loadEditBufferFromDataBuffer` 0x88472 → `A36EditorLibrarian::loadEditBufferFromDataBuffer` 0xe4578 → `A36EditBufferContext::loadPresetFromFile` 0xd4ee8.
2. The JSON (L6Preset v5) is parsed by `L6A36Preset::ReadFromFile` 0xf3ed4. `tnid` is carried over if the new tone has none.
3. **If the tone equals the current one (`DeviceDataEqualTo` 0xf3d7e), nothing is sent.**
4. Otherwise `syncWithDeviceAsMaster(false)` 0xda514 runs:
   - `WriteToDevice` 0xf51ba → `SerializeToDeviceForGroup(…, "Preset")` 0xfa480 builds the full blob;
   - editor flush;
   - **librarian 12 `SetPresetFile(0xFFFFFFFF, blob)`**;
   - post `EditBuffer_PresetChanged`.

**Answer: one bulk blob, not one message per parameter.**

---------------------------------------------------------------------------------------------------

## 6. Connect / sync sequence and inbound messages

The order is CONFIRMED per function; the whole sequence also matches `native_transport.md` §7.

**1. Editor service handshake** (`FirmwareServiceInterfaceBase::HandleHandshake` 0xd2302):
   1. `FetchVersion` → **cmd 1** → `u32` service version.
   2. **cmd 4 Handshake** with the CRC-32 of the *cached* table (`<filesDir>/cachedSymbolTable.bin`, written after a previous success).
   3. If the reply is < 0: cmd 4 with the CRC-32 of the bundled default (`defaultSymbolTable.bin` for 0x200002; chosen in `A36EditorLibrarian::connect` 0xe0a9e).
   4. If that fails too: **cmd 2** GetSymbolTableSize, **cmd 3** GetSymbolTable (raw table, same file format), then cmd 4 with its CRC-32.
   5. On success the table is cached (`ToneMatchFirmwareService::completeHandshake` 0x10b236).
   - Default-table CRC-32 = **0xB68B291E** → request `04000000 04000000 1e298bb6`.

**2. Librarian service handshake** (opened from `A36EditorLibrarian::handleNotification` 0xdf576 once the editor reports done): GetVersion (1), **GetNumPresets (5)**, Handshake (4) with the same table CRC, then the cache is initialised. Cache refresh runs in the background (§4).

**3.** `A36EditBufferContext::bindServices` 0xd4b16 → `syncWithDeviceAsMaster(true)` 0xda514:
   1. editor **cmd 15 GetDirtyState** → `u32`;
   2. librarian **cmd 11 GetPresetFile(0xFFFFFFFF)** → current edit-buffer blob;
   3. the blob is parsed into the local L6A36Preset and `EditBuffer_PresetChanged` is posted.

   **This is how the app learns the current tone.** It does not learn the current preset *index* at connect: that index is UNKNOWN until a patch event arrives (CONFIRMED absence; no index query was found).

**4.** `ToneMatchEditorService::registerForEvents` 0x10957c registers local callbacks for patch, param, tap and FBV events, plus PS-key events when fw ≥ 0x02110300. **Nothing is sent.**

**5.** Editor **cmd 9 GetDspModelParam(Tuner, Enable)**. If the tuner is already on, the client registers for tuner events (§7).

**6.** `EdLib_Connect(0)` reaches Java. Java then calls `nativeGetModelName`, `nativeGetProductId` and `nativeGetFirmwareVersion*`:
   - these come from `L6Device` and the transport's **DeviceInfo** 200-byte record (`native_transport.md` §7), *not* from the editor GetVersion;
   - Java also reads `GetDeviceSetting("FBVConnected")` (cmd 16);
   - preset names come from cache or cmd 6.

**Inbound editor message types** (`HandleInPacket` 0x106b16). Body ≤ 16 bytes, otherwise −19.

| type | body | handler → notification |
|---|---|---|
| 0 | – | ignored |
| 1 | response body | FIFO-matched to the oldest pending request |
| 2 DSP event | `u32 slot, u32 param, TV` | callbacks registered by `RegisterDspEvent`, matched on (slot, param); only the tuner uses this |
| 3 patch | `TV int presetIndex, TV int isSave` | `handlePatchEvent` 0x109bc4 → `consumePatchEvent` 0xd433c:<br>• isSave 0 → `EditBuffer_DevicePresetChanged{presetIndex, onDevice:true}`, the edit-buffer URI is set to slot n, then a resync (step 3 above) via `onThreadEvent(3)` 0xdfe9c<br>• isSave 1 → cache invalidated, then `EditBuffer_PresetSavedToDevice{onDevice:true, presetIndex}` |
| 4 param | `u32 slot, u32 param, TV` | `handleParamEvent` 0x109c86. The ids are mapped back to names (`LookupID`) and then:<br>• slot 0xFFFFFFFF → `consumeRootSlotParamEvent` 0xd405a: only Master / GuitOutputGain → `Device_SettingChanged{onDevice:true}`<br>• `(Tuner, Enable)` → `EditBuffer_TunerEnable`<br>• otherwise `GetGroupForDSPSlotAndParam` → `setParam(…, onDevice)` → `EditBuffer_ParamChanged{onDevice:true}`<br>Float values for `@enabled` count as on when > 0.1. Types accepted: int, bool, float |
| 5 tap tempo | `TV float BPM` | `consumeTapTempoEvent` 0xd4248 → set `global/@tempo` → ParamChanged |
| 6 FBV status | `TV float` (> 0 means connected) | delegate +0x18 → FBV notification |
| 7 PS-key change | `u32 key, TV` | `handlePSKeyChangeEvent` 0x10a15c → `consumePSKeyChangeEvent` 0xd47b8 → setParam(global, …) |
| 8 sys-setting change | `u32 key, TV` | AEON only |

---------------------------------------------------------------------------------------------------

## 7. Tuner

All CONFIRMED.

**Engage** (`nativeEngageTuner(true)` → `A36EditorLibrarian::engageTuner` 0xe46f6 → `engageTunerInternal(on, onDevice=false)` 0xe7240):
1. **cmd 10 SetDspModelParam {idx("Tuner")=587, idx("Enable")=593, TV int 1}**. The value is `L6Variant(uint)`, so the tag is **2 (int)**, not bool. This call waits for the reply.
2. Then **cmd 11 RegisterDspEvent {587, idx("Note")=594}** (`registerToneMatchTunerEvent` 0x108eba).

**Disengage:** SetDspModelParam with int 0, then **cmd 12 UnregisterDspEvent {587, 594}**.

**When the tuner is switched on or off at the amp:** a param event `(Tuner, Enable)` arrives → `EditBuffer_TunerEnable` → `engageTunerInternal(on, onDevice=true)`, which only registers or unregisters the event.

**Data stream:** type-2 DSP events `{587, 594, TV float v}` (`handleTunerEvent` 0x109b52 requires tag 4) → `consumeTunerEvent` 0xd49a2 → `convertA36TunerValueToNoteCents` 0xea729:
- v is the pitch in semitones above A within one octave, in [0, 12); v ≥ 11.5 wraps to v − 12.
- f = 440·2^(v/12).
- note = the bucket of table @0x23e3c0 (0 = A … 11 = G#/Ab).
- cents = 1200·log2(f / f_note).
- v < 0 or ≥ 12 → note −1 (no signal).
- This feeds Java `tunerValue(note, cents)`. Whether the amp sends the value continuously or on change is UNKNOWN.

---------------------------------------------------------------------------------------------------

## 8. Symbol table: fetch and fallback (item 7)

All CONFIRMED.
- Bundled `defaultSymbolTable.bin` is the **fallback** (choice 2). `cachedSymbolTable.bin` (choice 1) is the copy saved from the last successful session.
- Choice 3 downloads the amp's own table (editor cmds 2 and 3); the librarian never fetches it.
- Both services handshake with the same table.
- **A custom app must use the indexes of the table the amp accepted.** Safe flow:
  1. Handshake with the CRC-32 of the bundled table.
  2. If the reply is < 0, fetch the table with cmds 2 and 3, then Handshake with its CRC-32.
  3. Cache it.
- File format: `u32 count, u32 size, count × {u32 strOff, u32 crc32(name), u32 len}, NUL-terminated strings` (`SymbolTable::InitFromTableData` 0xd2a42).

**Command table.** Ids, layouts, and directions are read from the call sites (CONFIRMED). Payload is the body after the 8-byte header; all fields are u32 LE unless stated.

| svc | id | name | → amp payload | ← response body | used for |
|---|---|---|---|---|---|
| E | 1 | GetVersion | – | u32 | handshake |
| E | 2 | GetSymbolTableSize | – | u32 | handshake choice 3 |
| E | 3 | GetSymbolTable | – | raw table | handshake choice 3 |
| E | 4 | Handshake | u32 crc32(table) | i32 status | handshake |
| E | 5 | GetNumAddressableSlots | – | u32 | unused |
| E | 6 | GetAddressableSlots | – | u32[n] | unused |
| E | 7 | QueryCurrentDspModel | u32 slot | i32 st, u32 model | unused |
| E | 8 | LoadDspModel | u32 slot, u32 model | i32 st | cab mic change |
| E | 9 | GetDspModelParam | u32 slot, u32 param | i32 st, TV | settings read, tuner state |
| E | 10 | SetDspModelParam(Async) | u32 slot, u32 param, TV | i32 st | param edits, Master, GuitOutputGain, tuner |
| E | 11 | RegisterDspEvent | u32 slot, u32 param | i32 st | tuner Note |
| E | 12 | UnregisterDspEvent | u32 slot, u32 param | i32 st | tuner |
| E | 13 | BindTweakParam | u32 slot, u32 param | i32 st | tweak knob |
| E | 14 | SetGlobalTempo | f32 bpm | i32 st | @tempo |
| E | 15 | GetDirtyState | – | u32 | sync |
| E | 16 | GetFbvConnectivityStatus | – | u32 | FBVConnected |
| E | 17 | GetPersistentSysParam | u32 key | i32 st, TV | settings read |
| E | 18 | SetPersistentSysParam(Async) | u32 key, TV | i32 st | TapTempoLED, global EQ |
| E | 19 | SetPresetPSKeyParam(Async) | u32 key, TV | i32 st | tweakmin/max, pedal2assign |
| E | 20 | GetPresetPSKeyParam | u32 key | i32 st, TV | – |
| E | 21 | GetSystemSetting | u32 key | i32 st, TV | AEON only |
| E | 22 | SetSystemSetting | u32 key, TV | i32 st | AEON only |
| L | 1 | GetVersion | – | u32 (no status) | handshake |
| L | 2 / 3 | GetSymbolTableSize / GetSymbolTable | – | u32 / table (no status) | unused |
| L | 4 | Handshake | u32 crc32 | i32 st | handshake |
| L | 5 | GetNumPresets | – | u32 (no status) | count |
| L | 6 | GetPresetName | u32 idx | i32 st, u32 len, char[≤64] | names |
| L | 7 | GetPresetUUID | u32 idx | i32 st, u64 | cache |
| L | 8 | GetPresetChecksum | u32 idx | i32 st, u32 | cache V1 |
| L | 9 | MovePresetFiles | u32 dst, u32 src | i32 st | reorder (**writes storage**) |
| L | 10 | GetPresetFileSize | u32 idx | i32 st, u32 | cache V1 |
| L | 11 | GetPresetFile | u32 idx / 0xFFFFFFFF | i32 st, blob | select, sync |
| L | 12 | SetPresetFile | u32 idx / 0xFFFFFFFF, u32 L, blob (header len 8+L) | i32 st | select, save, tone load, model change (**writes storage when idx ≠ −1**) |
| L | 13 | LoadHardwarePreset | u32 idx | i32 st | unused (INFERRED: recall) |
| L | 14 | GetPresetInfo | u32 idx | i32 st, u64, u32, u32, u32, char[64] | cache V2 |
| L | 15 | SetPresetFile (AEON flag) | as 12 | i32 st | AEON only |
| in | 0–8 | see the inbound table in §6 | | | |

No editor or librarian id is a firmware command. The update path uses a different port mode and engine (§10).

---------------------------------------------------------------------------------------------------

## 9. Per-product / per-firmware branches

All CONFIRMED. The 0xMMmmpp.. packing of the version is defined by the transport DeviceInfo record.

| condition | effect | where |
|---|---|---|
| product 0x200001/0x200002 and fw ≤ 0x010008FF | no UI events (patch, param, tap, FBV callbacks never registered); librarian V1 | `ToneMatchEditorService` ctor 0x1087f8, `ToneMatchLibrarianService` ctor 0x10d230 |
| AMPLIFi family (0x200001/02/03/05/07) and fw < 0x02000600 | persistent sys params (cmds 17/18, e.g. **TapTempoLED**) refused locally with −8209-class error | `FUN_001084af` (matches the Java "2.01" gate) |
| AMPLIFi family and fw < 0x02110300 | PS-key cmds 19/20 and PS-key events disabled (tweakmin/max, pedal2assign edits not sent); blob omits PS keys 7/8/9 | `FUN_001084fb`, L6A36Preset 0xfa480 |
| AEON (0x200004/0x200006) only | system settings 21/22 and event 8; footswitch assigns via PS keys 10+3i/11+3i/12+3i; `@fsNgroup`; SetPresetFile 15; different GuitarProc and slot tables (FX5, Looper, Stereo) | `FUN_00108547`, `IsAeonDevice`, tables 0x23e660 / 0x23e8e0 |
| product → table | 0x200003 `_FX100`, 0x200004 `_AEON`, 0x200005 `_TT`, 0x200006 `_Firebird`, 0x200007 `_Dio`, others (incl. **150**) `defaultSymbolTable.bin` | `A36EditorLibrarian::connect` 0xe0a9e |
| fw < 0x01000000 | force update (transport) — **AVOID**; a custom app should refuse such amps | `native_transport.md` §7 |

No other message format changes with firmware: the envelopes and TypedValue are the same everywhere.

---------------------------------------------------------------------------------------------------

## 10. AVOID (names only; never call, port, or emulate)

- **JNI and manager:** `nativeStartFirmwareUpdate`, `nativeOpen` mode 2, `AmplifiRemoteManager::OpenFirmwareUpdate` 0x850b4, `AmplifiRemoteManager::startFirmwareUpdate` 0x89954.
- **Device and transport:** `L6AndroidNdkDevice::prepareForUpdating` (and its "WillBeginUpdate" port notification); the transport's `forceFirmwareUpdate`.
- **Update engine:** `L6UUE::UpdateEngine::Session::DoUpdate` and all `L6UUE::*` (UpdateDevice, UpdateDevice_TypeIO, UpdateCommand/ImageInfo maps).
- **Services:** `FirmwareServiceInterfaceEditor::PrepareForUpdate`, `FirmwareServiceInterfaceLibrarian::PrepareForUpdate` / `ConvertToUpdater`, `ToneMatchFirmwareService::prepareServiceForUpdate`.
- **Status and notifications:** `A36EditBufferContext::consumeFirmwareStatusEvent`; the `DeviceUpdate*` / `Device_Bricked` notifications; error codes −9100 / −9101.
- **Not firmware, but they modify stored data** (use deliberately): librarian 9 / 12 (idx ≠ −1) / 15, editor 18 / 19 / 22.

---------------------------------------------------------------------------------------------------

## 11. Biggest unknowns

1. **Symbol indexes depend on the table the amp accepts.** All examples use the bundled table (CRC 0xB68B291E). Whether a 150 on its last firmware accepts that CRC, or forces a table download, is UNKNOWN.
2. **Blob byte-exactness** (state order, any amp-side checksum or UUID requirements) is unverified, and the blob is required for select, save, model change and tone load. A capture of one GetPresetFile reply would settle it.
3. **Amp behaviour:** what the amp does with `MovePresetFiles` argument order, with `LoadHardwarePreset` (13), and whether `nameLen` includes the NUL.
4. **Current preset index after connect:** no query found. The app knows it only after a patch event.
5. **Value semantics:** the units of Master / GuitOutputGain (0..1 INFERRED), and the tuner event rate.
6. **Status codes:** amp-side error values in `i32 status` are not enumerated (the client only tests < 0).
