# Line 6 Remote (AMPLIFi Remote) APK - Step 1 Inventory

Legend: CONFIRMED = seen directly in extracted files/decompiled code. INFERRED = deduced, not directly verified.

## 0. Setup / provenance
- Input: Line.6.Remote.apk (52,888,168 B). Plain single APK (CONFIRMED; not XAPK/APKS, one classes.dex, no split APKs).
- Working copy: analysis/work/app.apk. Original untouched.
- Installed via Homebrew (CONFIRMED): jadx 1.5.6, apktool 3.0.3, openjdk 27.0.1.0.3 (dependency). Homebrew auto-cleanup also pruned old logs.
- Outputs: analysis/work/jadx/{sources,resources}, analysis/work/apktool/{AndroidManifest.xml,smali,res,assets,lib}.
- jadx finished with 2 errors (of 4088 classes); 1 file in com.line6 has a "code restructure failed/dump skipped" marker. Smali in apktool/smali is the fallback.

## 1. Package / manifest (CONFIRMED)
- Package: com.line6.amplifi; app label "AMPLIFi Remote"; BuildConfig FLAVOR=amplifi, release.
- versionName 2.61.0, versionCode 17 (Crashlytics build stamp: 17 May 2018).
- minSdk 19, targetSdk 24. compileSdk not stored; manifest platformBuildVersionCode=19 (Android 4.4.2) (build platform, INFERRED as compileSdk 19-ish).
- Permissions: WRITE_EXTERNAL_STORAGE, BLUETOOTH, BLUETOOTH_ADMIN, ACCESS_WIFI_STATE, ACCESS_NETWORK_STATE, INTERNET, READ_SYNC_SETTINGS, WRITE_SYNC_SETTINGS, AUTHENTICATE_ACCOUNTS, GET_ACCOUNTS, READ_PHONE_STATE, MODIFY_AUDIO_SETTINGS.
  - NO location permission, NO BLUETOOTH_CONNECT/SCAN, NO USB/host permission, NO BLE feature.
- Activities: ui.ProductSpecificSplashActivity (launcher; deep link amplifi://load), ui.MainActivity, MainActivityEx, login.{Login,CreateAccount,ResetPass,PrivacyPolicy}Activity, tutorial.{Tutorial,TermsAndConditions}Activity.
- Services: device.FirmwareUpdateService (not exported), cloud.network.CloudAPIIntentService, ui.music.MusicPlayerServiceEx, credentials.AuthenticatorService, cloud.sync.SyncService (exported, :sync process).
- Receiver: cloud.network.NetworkConnectivityBroadcastReceiver. Provider: device.data.TonesContentProvider (com.line6.amplifi.provider).
- res/xml: application_tracker.xml, authenticator.xml, syncadapter.xml. NO usb device filter, NO MIDI/BLE declarations.
- Manifest contains a Crashlytics API key (meta-data) - irrelevant to protocol.

## 2. Supported amps / firmware
- Device name filter (CONFIRMED, AmplifiDeviceConnectionManager.checkIfSupportedDevice): paired Bluetooth device name, uppercased, CONTAINS one of AMPLIFI_75, AMPLIFI_150, AMPLIFI_FX100, AMPLIFI_TT, AMPLIFI_30. Display names: "AMPLIFi 75/150/30/TT", "FX100"; also constants "Firehawk 1500", "Firehawk FX".
- "Old firmware" name pattern: old = "AMPLIFI_xx"/"FX100_xx" (hex suffix) without model; new = AMPLIFI_(75|150|TT|FX100|30)_XX where XX = 2 hex digits (device name carries a hex suffix; probably BT MAC tail, INFERRED). Note regex has literal quotes so it never matches as written (CONFIRMED oddity).
- Product IDs (Line6Device / ConnectedLine6Device, CONFIRMED): 2097153 (0x200001) AMPLIFi 75 / "ToneMatch" base; 2097154 (0x200002) AMPLIFi 150; 2097155 (0x200003) FX100; 2097156 (0x200004) Firehawk FX ("PhoenixFloor"); 2097157 (0x200005) AMPLIFi TT; 2097158 (0x200006) Firehawk 1500 ("PhoenixAmp"); 2097159 (0x200007) AMPLIFi 30. These are Line 6 "MIDI product ids" (L6MIDI_PRODID_*), not USB PIDs.
- AmpliFi 150 specifics: default_preset.json has "device": 2097154 (0x200002) and device_version 7471224 (= 0x720078; probably packed firmware version, INFERRED). defaultSymbolTable.bin is the generic table; _FX100/_TT/_Dio/_AEON/_Firebird variants for other products. The 75 and 150 share one native string "AMPLIFi 75/150" (CONFIRMED).
- Firmware version: read from device at runtime via native nativeGetFirmwareVersion/AsString. EnvironmentSettings.MIN_SUPPORTED_FIRMWARE_VERSION=0. UI strings: tap tempo needs fw >= 2.01; fw 2.0+ required for Android BT (older fw updated via USB with "Line 6 Updater"). Firmware list comes from Line 6 cloud API (FirmwareUpdate: version, md5Checksum, filesize...), not bundled (CONFIRMED).
- USB VID 0x0E41 / PIDs: NOT present in Java code (grep 0E41/3649 no hits) (CONFIRMED for Java; native strings not exhaustively searched). App does not use USB at all.
- Internal codenames in assets/native (CONFIRMED strings): AEON, Dio, Firebird (Firehawk 1500?), FX100, TT. Mapping beyond names is INFERRED.

## 3. Native libraries (CONFIRMED)
Only ABIs armeabi (ARM 32-bit EABI5) and x86 (32-bit). NO arm64, NO armeabi-v7a.
| lib | armeabi | x86 | purpose |
|---|---|---|---|
| libAmplifiRemoteNdk.so | 2,154,136 | 2,285,972 | THE protocol/device layer (Line 6 "EdLib"/Line6EditorLib, C++, stripped, GCC 4.6) |
| libSlidersLogicLib.so | 94,696 | 94,892 | UI slider/param layout (SWIG JNI) |
| libvudroid.so | 3,779,416 | 3,472,916 | djvu/pdf viewer (manual), irrelevant |
- Framework: plain native Android Java + NDK. NOT Xamarin/Unity/Qt/Flutter/RN/JUCE/Cordova. DI via RoboGuice/Guice, Retrofit/OkHttp, Otto-like MainThreadBus, Crashlytics. jadx is the right tool for Java; protocol framing/parsing lives in native code (needs Ghidra/radare2 later, or black-box capture).
- libAmplifiRemoteNdk JNI exports (47): nativeInitialize/Open/Close/Terminate, nativeSetSppDelegate, nativeSppInStreamData (Java->native bytes in), nativeSppOutStreamData / nativeSppOutStreamDataCount (native->Java bytes out), nativeGet/SetEditBufferParam, nativeGetEditBufferParamGroups/IDsForGroup, Load/SaveEditBufferFrom/To (+DataBuffer), nativeGet/SetDeviceSetting, nativeGet/SetResource(+Name/Count/Move/Copy), nativeGetModelList/ModelInfo/Name/OfficialModelName/ProductId/ProductName/PresetUUID, nativeGet/SetEditBufferMetaTag, nativeEngageTuner/IsTunerEngaged/SetTunerDelegate, nativeSetNotificationDelegate, nativeStartFirmwareUpdate, nativeDebugEditor, etc.
- Notable native strings: AndroidSppMsgChannel, "AmplifiRemoteNdk spp thread", FirmwareServiceInterfaceEditor/LibrarianV1/V2/Base ("FirmwareInterfaceService..."), Fis2, PS KEY (persistent/preset-store keys with UUID HI/LO, Tweak, Variax, FS = footswitch), ToneMatch preset APIs, CRC16_Process, "Failed getting checksum", HandshakeSucceeded/HandshakeFailed, EdLib_Connect/Disconnect/TaskProgress, L6ERR_DEVLIB_DEVICE_FORCE_UPDATE, DeviceMidiId/ComponentMidiId, "Unable to init McBsp". Full strings dump was in scratch; regenerate with `strings -a`.
- Crypto strings in native: only CRC16 / checksum seen in the filtered grep; no AES/HMAC/openssl hits in the filtered output (INFERRED absence; not exhaustively checked).

## 4. Assets (apktool/assets, 27 files + fonts/Roboto-Thin.ttf)
- Model definition JSON (VERY VALUABLE): amps.models (112 KB), cabs.models, stomps.models (54 KB), mod.models (49 KB), delay.models (35 KB), reverbs.models (23 KB), wahs.models, fixed.models (globals e.g. @tempo). Each entry: symbolicID, numeric id, category, name, shortname, icon, params[] (default/min/max/name/persist/symbolicID...). e.g. Class A-30 Fawn id 131149.
- Catalogs: AmpCatalog.json, CabCatalog.json, FXCatalog.json, ReverbCatalog.json, WahCatalog.json (category -> symbolicID lists).
- Presets: default_preset.json (device 2097154 = AMPLIFi 150), default_preset_AEON.json.
- Symbol tables (binary, format unknown): defaultSymbolTable.bin 15.8 KB, _FX100 16.2 KB, _TT 16.2 KB, _Dio 16.2 KB, _AEON 28.7 KB, _Firebird 29.6 KB. Loaded by EditorBuffer.resourceFiles (Java lists defaultSymbolTable, _FX100, _TT, _Dio) and passed to native.
- Demo.zip (2.8 MB): 59 .l6p demo tone (preset) files in Demo/Tones plus 6 mp3 jam-track demos in Demo/Audio (copyrighted audio: do not redistribute). .l6p = Line 6 preset (JSON, INFERRED from default_preset.json).
- Other: manual.pdf (1.1 MB), termsAndConditions.html, crashlytics-build.properties.
- Firmware / DFU files: NONE bundled (no .bin/.hex/.dfu/.syx; the only .bin are symbol tables). Firmware is downloaded from the Line 6 cloud and flashed through native nativeStartFirmwareUpdate. AVOID - firmware (not analyzed).
- Resources: 1813 files in res, 1429 images (not copied elsewhere).

## 5. Obfuscation / code structure
- Java is NOT obfuscated for app code (CONFIRMED): readable names under com.line6.amplifi (382 classes, 3819 java files total incl. libs). Libraries (gms, guava, guice, cglib, okhttp, retrofit, picasso, mp3agic, roboguice, asm) are also readable.
- Key packages: com.line6.amplifi.device (13 + data, events 16, interfaces, models, utils), .line6logic (12; SlidersLogicLib JNI), .cloud (api: firmware, login, sync, tone*, user), .ui.editor (+slider, processor, catalog), .ui.firmware, .ui.tuner, .credentials, .loaders.
- Most promising for transport/protocol: device/AmplifiDeviceManager.java (JNI decls, SPP socket, nativeOpen), device/DeviceConnectionManager.java + AmplifiDeviceConnectionManager.java (BT discovery/name filter), device/EditorBuffer.java + BaseEditorBuffer.java, EdlibScenarioManager.java, FirmwareUpdateService.java, DeviceUpdateManager.java, models/Line6Device.java + ConnectedLine6Device.java.
- Grep hits (files in com.line6):
  - BluetoothGatt: 0 (NO BLE)
  - UUID.fromString: AmplifiDeviceManager.java (1)
  - BluetoothSocket / RFCOMM: AmplifiDeviceManager.java (1 file)
  - UsbManager: 0; MidiManager: 0; 0xF0/sysex: 0 in Java
  - Wi-Fi sockets (DatagramSocket/ServerSocket/NSD): 0
  - BluetoothDevice/Adapter: ~15 files (device/*, ui/firmware/*, helpers/Utils)
  - System.loadLibrary: AmplifiDeviceManager ("AmplifiRemoteNdk"), SlidersLogicLibJNI ("SlidersLogicLib")
- TRANSPORT (CONFIRMED): Classic Bluetooth RFCOMM/SPP, UUID 00001101-0000-1000-8000-00805f9b34fb (const SPP_UUID). Java reads bluetoothInputStream in a thread and passes bytes to nativeSppInStreamData; native emits outbound bytes via SppOutStreamData(Count) and Java writes them to bluetoothOutputStream. Device found via paired (bonded) devices + ACL_CONNECTED/DISCONNECTED broadcasts + A2DP audio sink; selection by name (see §2). Protocol framing/message set is implemented entirely in native code (Line 6 EdLib "FirmwareInterfaceService"/"Fis2"). Wire protocol is the thing to reverse next, inside libAmplifiRemoteNdk.so (armeabi ARM32 or x86 - x86 may be easier to disassemble).

## 6. Crypto / auth
- javax.crypto: no usage found in com.line6 (grep Cipher/SecretKeySpec/Mac.getInstance: 0).
- MessageDigest MD5: FirmwareUpdateService.java only (verifies downloaded firmware vs md5Checksum from cloud API). 
- createBond: 0 hits (app relies on OS pairing; user pairs amp in Android BT settings).
- Cloud login (Retrofit, line6.com/api/rest/v1/, account authenticator) is separate from device link; endpoints in res/values/strings.xml: line6.com, l6c-staging/dev1/test3.line6.net, preview.line6.com (server-side, not needed for local control; firmware list endpoint is cloud-only).
- Native: CRC16 and "checksum" strings and HandshakeSucceeded/Failed present - handshake/auth in native layer needs checking (UNVERIFIED).

## 7. Plan-changing notes
- Not Xamarin/Unity/Flutter; no need for .NET tooling.
- Link is classic BT SPP, so a replacement app must use RFCOMM (works on desktop macOS/Linux/Windows and Android; NOT iOS without MFi; Web Bluetooth can't do classic SPP). Android: BLUETOOTH perms of 2018 era; modern app needs BLUETOOTH_CONNECT.
- The actual wire protocol lives in stripped 32-bit native code (1.4-2.2 MB), not Java. Options later: Ghidra on the x86 or ARM lib (symbols mostly stripped but many log strings) and/or capture HCI snoop logs from the official app on a real amp session. Model/param JSON assets give param IDs/ranges for free.
- Official app is old (targetSdk 24, 32-bit only): runs on Android emulators/phones that still support 32-bit ABIs; many modern phones are 64-bit-only, which is likely why the app is unsupported.
