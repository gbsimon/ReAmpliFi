#!/usr/bin/env python3
"""AMPLIFi application-layer (service RPC) message encoder/decoder.

Static re-implementation of the ToneMatch Editor / Librarian RPC payloads found in
libAmplifiRemoteNdk.so (x86, Ghidra addresses = file vaddr + 0x10000). Payload ONLY:
the bytes produced here are what ToneMatchEdit_Remote::DoCommandCommon (0x103850) /
ToneMatchLibrarian_Remote::DoCommandCommon (0x10b4ea) write into the service stream
(port write). McBsp/stream/RSMC framing + CRC16 are NOT included (see native_transport.md).

usage:
  python3 -I app_messages.py vectors <symtab.bin> <assets_dir> <out.json> [preset_blob.py dir]
  python3 -I app_messages.py setparam <symtab.bin> <assets_dir> <group> <param> <value>
  python3 -I app_messages.py decode-in <hex>           # decode an inbound editor message
  python3 -I app_messages.py tuner <float>              # tuner Note value -> (note, cents)

Treats all input files as untrusted data (no eval, JSON + struct only).
"""
import json, math, os, struct, sys, zlib

# ---------------------------------------------------------------- symbol table
class SymTab:
    """Wire ids are the INDEX of a name in the symbol table (SymbolTable::LookupString 0xd2b70
    returns the loop index whose (crc32,name) match), NOT the CRC32 itself."""
    def __init__(self, path):
        self.raw = open(path, 'rb').read()
        cnt, = struct.unpack_from('<I', self.raw, 0)
        blob = 8 + 12 * cnt
        self.names = []
        for i in range(cnt):
            off, h, ln = struct.unpack_from('<III', self.raw, 8 + 12 * i)
            self.names.append(self.raw[blob + off: blob + off + ln].decode('latin-1'))
        self.idx = {}
        for i, n in enumerate(self.names):
            self.idx.setdefault(n, i)          # first match wins, like LookupString
    def lookup(self, name):
        if not name:
            return 0xFFFFFFFF                  # "" -> -1 (allowed for slot only, = root slot)
        if name not in self.idx:
            raise KeyError('symbol not in table: %r' % name)
        return self.idx[name]
    def crc32(self):
        return zlib.crc32(self.raw) & 0xFFFFFFFF   # CRC32_bs over whole table (Handshake cmd 4)

# ---------------------------------------------------------------- editor -> DSP address map (non-AEON)
# GuitarProc table @0x23e540 (dsp param, group, editor @param)   [FUN_000eb6c2]
GUITARPROC = [('CabEnable', 'cab', '@enabled'), ('GateEnable', 'gate', '@enabled'),
    ('PostCompEnable', 'compressor', '@enabled'), ('PostEQEnable', 'eq', '@enabled'),
    ('WahEnable', 'wah', '@enabled'), ('VolumePedalEnable', 'volume', '@enabled'),
    ('FX1Enable', 'fx1', '@enabled'), ('FX2Enable', 'fx2', '@enabled'), ('FX3Enable', 'fx3', '@enabled'),
    ('FX4Enable', 'reverb', '@enabled'), ('VolumePost', 'volume', '@post'), ('FX1Post', 'fx1', '@post'),
    ('FX2Post', 'fx2', '@post'), ('FX3Post', 'fx3', '@post'), ('FX4Post', 'reverb', '@post'),
    ('FX1Mix', 'fx1', '@mix'), ('FX2Mix', 'fx2', '@mix'), ('FX3Mix', 'fx3', '@mix'), ('FX4Mix', 'reverb', '@mix'),
    ('FX1MixType', 'fx1', '@mixtype'), ('FX2MixType', 'fx2', '@mixtype'), ('FX3MixType', 'fx3', '@mixtype'),
    ('ChannelVolume', 'amp', '@volume')]
# Group -> DSP slot @0x23e820 (first match wins)                [GroupIDToSlotSymbol 0xeaec6]
GROUP_SLOT = {'gate': 'Gate', 'volume': 'VolumePedal', 'wah': 'Wah', 'fx1': 'FX1', 'fx2': 'FX2',
              'fx3': 'FX3', 'reverb': 'FX4', 'amp': 'Amp', 'cab': 'StudioCab',
              'compressor': 'PostComp', 'eq': 'PostEQ'}
# Global group: ParamIDToPSKey table @0x23e9e0 (AMPLIFi part)    [0xeb1c9]
PSKEY = {'@tempo': 3, '@tweakmin': 7, '@tweakmax': 8, '@pedal2assign': 9,
         '@modelmagmode': 25, '@variaxmodel': 26, '@toneknob': 27,
         '@string1tuning': 28, '@string2tuning': 29, '@string3tuning': 30,
         '@string4tuning': 31, '@string5tuning': 32, '@string6tuning': 33}
# Device settings: ParamIDToSysParamKey table @0x23e480          [0xeb30b]
SYSPARAM = {'TapTempoLED': 7, 'VariaxSettings': 8, 'VariaxTuningMode': 9, 'GlobalLowCut': 14,
            'GlobalLowFreq': 15, 'GlobalLowQ': 16, 'GlobalLowGain': 17, 'GlobalMidFreq': 18,
            'GlobalMidQ': 19, 'GlobalMidGain': 20, 'GlobalHighFreq': 21, 'GlobalHighQ': 22,
            'GlobalHighGain': 23, 'GlobalHighCut': 24, 'GuitarOnlyGlobalEQ': 25,
            'BypassGlobalEQ': 26, 'Divergence': 27, 'StereoWidth': 28, 'Crossover': 29}
MIC_SUFFIX = ['57OnAxis', '57OffAxis', '421', 'U67']                # @0x23eb04

def dsp_address(group, param):
    """GetDSPSlotForGroupAndParam 0xeafcf (non-AEON, stereo=false) -> (slot, param) names."""
    if param.startswith('@'):
        for dsp, g, p in GUITARPROC:
            if g == group and p == param:
                return 'GuitarProc', dsp
        raise KeyError('no DSP mapping for %s/%s' % (group, param))
    if group == 'cab' and param == 'Level':
        return 'Air', 'Level'
    if group not in GROUP_SLOT:
        raise KeyError('no DSP slot for group %s' % group)
    return GROUP_SLOT[group], param

# ---------------------------------------------------------------- typed value
TV_VOID, TV_SYMBOL, TV_INT, TV_BOOL, TV_FLOAT, TV_VARRAY = range(6)   # handleParamEvent 0x109c86 strings

def tv(tag, value):
    """toneMatchEditorTypedValue = {u32 tag, u32 value} LE (FUN_000ec4c5)."""
    if tag == TV_FLOAT:
        return struct.pack('<If', tag, float(value))
    if tag == TV_BOOL:
        return struct.pack('<II', tag, 1 if value else 0)
    return struct.pack('<Ii', tag, int(value)) if int(value) < 0 else struct.pack('<II', tag, int(value))

def load_models(assets):
    m = {}
    for f in os.listdir(assets):
        if f.endswith('.models'):
            with open(os.path.join(assets, f)) as fh:
                for model in json.load(fh):
                    m[model['symbolicID']] = {p['symbolicID']: p for p in model.get('params', [])}
    return m

def typed_for_model(models, model, param, value):
    """L6EdLibModelDefs::CheckParamValueForModel 0xc2e10: coerce to the model's valueType,
    clamp floats to [min,max]; valueType 0 int->TV_INT, 1 float->TV_FLOAT, 2 bool->TV_BOOL."""
    pd = models[model][param]
    vt = pd.get('valueType', 1)
    if vt == 1:
        v = min(max(float(value), float(pd['min'])), float(pd['max']))
        return tv(TV_FLOAT, v)
    if vt == 0:
        v = float(value); v = int(v + 0.5) if v >= 0 else int(v - 0.5)
        return tv(TV_INT, v)
    if vt == 2:
        return tv(TV_BOOL, bool(value))
    raise ValueError('string params (valueType 3) are not sent as typed values')

# ---------------------------------------------------------------- request envelopes
def req(cmd, payload=b'', total_len=None):
    """u32 cmd, u32 payload_len, payload (DoCommandCommon)."""
    n = len(payload) if total_len is None else total_len
    return struct.pack('<II', cmd, n) + payload

# Editor service (stream 0x2002<->0x03ED)
ED = dict(GetVersion=1, GetSymbolTableSize=2, GetSymbolTable=3, Handshake=4, GetNumAddressableSlots=5,
          GetAddressableSlots=6, QueryCurrentDspModel=7, LoadDspModel=8, GetDspModelParam=9,
          SetDspModelParam=10, RegisterDspEvent=11, UnregisterDspEvent=12, BindTweakParam=13,
          SetGlobalTempo=14, GetDirtyState=15, GetFbvConnectivityStatus=16, GetPersistentSysParam=17,
          SetPersistentSysParam=18, SetPresetPSKeyParam=19, GetPresetPSKeyParam=20,
          GetSystemSetting=21, SetSystemSetting=22)
# Librarian service (stream 0x2003<->0x03EF)
LIB = dict(GetVersion=1, GetSymbolTableSize=2, GetSymbolTable=3, Handshake=4, GetNumPresets=5,
           GetPresetName=6, GetPresetUUID=7, GetPresetChecksum=8, MovePresetFiles=9, GetPresetFileSize=10,
           GetPresetFile=11, SetPresetFile=12, LoadHardwarePreset=13, GetPresetInfo=14, SetPresetFileAeon=15)
EDIT_BUFFER = 0xFFFFFFFF

def ed_set_dsp_param(slot_idx, param_idx, tvb):
    return req(ED['SetDspModelParam'], struct.pack('<II', slot_idx, param_idx) + tvb)
def ed_get_dsp_param(slot_idx, param_idx):
    return req(ED['GetDspModelParam'], struct.pack('<II', slot_idx, param_idx))
def ed_load_dsp_model(slot_idx, model_idx):
    return req(ED['LoadDspModel'], struct.pack('<II', slot_idx, model_idx))
def ed_handshake(crc):
    return req(ED['Handshake'], struct.pack('<I', crc))
def lib_get_preset_file(idx):
    return req(LIB['GetPresetFile'], struct.pack('<I', idx & 0xFFFFFFFF))
def lib_set_preset_file(idx, blob):
    return req(LIB['SetPresetFile'], struct.pack('<II', idx & 0xFFFFFFFF, len(blob)) + blob)

def set_edit_buffer_param(sym, models, preset_models, group, param, value):
    """nativeSetEditBufferParam(group, param, value) -> editor message (non-@model params).
    preset_models: dict group -> current @model symbolicID (needed for type coercion)."""
    if group == 'global':
        if param == '@tempo':
            return req(ED['SetGlobalTempo'], struct.pack('<f', float(value)))
        if param in PSKEY:
            m = models['@global_params']
            return req(ED['SetPresetPSKeyParam'], struct.pack('<I', PSKEY[param]) +
                       typed_for_model({'g': m}, 'g', param, value))
        raise KeyError('global param %s handled elsewhere (tweak bind)' % param)
    if group == 'cab' and param == '@mic':
        name = preset_models['cab'] + MIC_SUFFIX[int(value)] if preset_models['cab'] != '@NoCabinet' \
            else '2x12Line6Studio57OnAxis'
        # CabModelAndMicToStudioCabSymbol: '<cab>Studio' already ends in 'Studio'; suffix appended
        return ed_load_dsp_model(sym.lookup('StudioCab'), sym.lookup(name))
    if param == '@temposync':
        param = 'SyncSelect'          # false -> int 0, true -> current SyncSelect value
    slot, dparam = dsp_address(group, param)
    tvb = typed_for_model(models, preset_models[group], param if not param.startswith('@') else param, value) \
        if param in models.get(preset_models[group], {}) else tv(TV_FLOAT, value)
    return ed_set_dsp_param(sym.lookup(slot), sym.lookup(dparam), tvb)

# ---------------------------------------------------------------- inbound
IN_TYPES = {0: 'none', 1: 'response', 2: 'dsp_event', 3: 'patch_event', 4: 'param_event',
            5: 'tap_tempo_event', 6: 'fbv_status_event', 7: 'pskey_change_event', 8: 'sys_setting_change_event'}

def decode_tv(b, o=0):
    tag, = struct.unpack_from('<I', b, o)
    if tag == TV_FLOAT: v, = struct.unpack_from('<f', b, o + 4)
    elif tag == TV_INT: v, = struct.unpack_from('<i', b, o + 4)
    else: v, = struct.unpack_from('<I', b, o + 4)
    return {'tag': tag, 'value': v}

def decode_inbound(b, sym=None):
    typ, ln = struct.unpack_from('<II', b, 0); body = b[8:8 + ln]
    out = {'type': typ, 'name': IN_TYPES.get(typ, '?'), 'len': ln}
    nm = (lambda i: (sym.names[i] if sym and i < len(sym.names) else ('ROOT' if i == 0xFFFFFFFF else i)))
    if typ in (2, 4):
        s, p = struct.unpack_from('<II', body, 0)
        out.update(slot=nm(s), param=nm(p), value=decode_tv(body, 8))
    elif typ == 3:
        out.update(preset_index=decode_tv(body, 0), is_save=decode_tv(body, 8))
    elif typ in (5, 6):
        out.update(value=decode_tv(body, 0))
    elif typ in (7, 8):
        k, = struct.unpack_from('<I', body, 0); out.update(key=k, value=decode_tv(body, 4))
    else:
        out['body_hex'] = body.hex()
    return out

def tuner_note_cents(v):
    """convertA36TunerValueToNoteCents 0xea729: v = semitones above A (0..12), 440 Hz ref."""
    if v < 0.0 or v >= 12.0:
        return -1, 0.0
    if v >= 11.5:
        v -= 12.0
    f = 440.0 * 2.0 ** (v / 12.0)
    for n in range(12):
        lo = 440.0 * 2 ** ((n - 0.5) / 12); hi = 440.0 * 2 ** ((n + 0.5) / 12)
        if lo <= f < hi:
            return n, math.log(f / (440.0 * 2 ** (n / 12))) / math.log(2) * 1200.0
    return -1, 0.0

# ---------------------------------------------------------------- vectors
def V(name, rtype, direction, service, inputs, payload, src, addr, status, note=None):
    d = dict(name=name, request_type=rtype, direction=direction, service=service, inputs=inputs,
             payload_hex=payload.hex() if isinstance(payload, (bytes, bytearray)) else payload,
             source_function=src, address=addr, status=status)
    if note: d['note'] = note
    return d

def build_vectors(sym, models, blob_dir=None):
    i = sym.lookup
    S = 'symbol indices from defaultSymbolTable.bin; valid only if the amp accepted Handshake with this table CRC'
    v = []
    v.append(V('editor_get_version', 'GetVersion', 'out', 'editor', {}, req(1),
               'ToneMatchEdit_Remote::GetVersion', '0x001039d2', 'CONFIRMED', 'response body: u32 version, no status'))
    v.append(V('editor_handshake_default_table', 'Handshake', 'out', 'editor', {'crc32': '%08x' % sym.crc32()},
               ed_handshake(sym.crc32()), 'ToneMatchEdit_Remote::Handshake', '0x00103bac', 'CONFIRMED',
               'payload = CRC32 (zlib) of the whole defaultSymbolTable.bin; response i32 status (>=0 ok)'))
    v.append(V('editor_get_symtab_size', 'GetSymbolTableSize', 'out', 'editor', {}, req(2),
               'ToneMatchEdit_Remote::GetSymbolTableSize', '0x00103a6e', 'CONFIRMED'))
    v.append(V('editor_get_symtab', 'GetSymbolTable', 'out', 'editor', {}, req(3),
               'ToneMatchEdit_Remote::GetSymbolTable', '0x00103b0a', 'CONFIRMED',
               'response body = raw symbol table, same format as defaultSymbolTable.bin; no timeout'))
    cases = [('amp', 'Drive', 0.5, 'BritGainJ800'), ('amp', 'Bass', 0.25, 'BritGainJ800'),
             ('amp', '@volume', 0.75, 'BritGainJ800'), ('fx1', '@enabled', True, None),
             ('fx1', '@enabled', False, None), ('reverb', '@mix', 0.33, 'DarkHall1'),
             ('reverb', '@post', True, 'DarkHall1'), ('cab', 'Level', 0.5, '4x12BritT75Studio'),
             ('reverb', 'Decay', 1.5, 'DarkHall1')]
    for g, p, val, model in cases:
        slot, dp = dsp_address(g, p)
        if model and p in models.get(model, {}):
            tvb = typed_for_model(models, model, p, val)
        elif isinstance(val, bool):
            tvb = tv(TV_BOOL, val)
        else:
            tvb = tv(TV_FLOAT, val)
        nm = 'set_param_%s_%s_%s' % (g, p.strip('@'), str(val).lower())
        v.append(V(nm, 'SetDspModelParam', 'out', 'editor',
                   {'group': g, 'param': p, 'value': val, 'model': model, 'dsp_slot': slot, 'dsp_param': dp,
                    'slot_idx': i(slot), 'param_idx': i(dp)},
                   ed_set_dsp_param(i(slot), i(dp), tvb),
                   'A36EditBufferContext::sendParamToDevice -> FSIEditor::SetToneMatchModelParam -> ToneMatchEdit_Remote::SetModelParamCommon',
                   '0x000daa7a/0x000ecc98/0x0010403e',
                   'CONFIRMED (layout, mapping, value typing); indices INFERRED-valid',
                   S + ('; value clamped to model max' if val == 1.5 else '')))
    # tempo sync: @temposync false -> SyncSelect int 0 on FX slot
    v.append(V('set_param_fx2_temposync_false', 'SetDspModelParam', 'out', 'editor',
               {'group': 'fx2', 'param': '@temposync', 'value': False},
               ed_set_dsp_param(i('FX2'), i('SyncSelect'), tv(TV_INT, 0)),
               'A36EditBufferContext::sendParamToDevice', '0x000daa7a', 'CONFIRMED', S))
    v.append(V('set_param_fx2_SyncSelect_4', 'SetDspModelParam', 'out', 'editor',
               {'group': 'fx2', 'param': 'SyncSelect', 'value': 4},
               ed_set_dsp_param(i('FX2'), i('SyncSelect'), tv(TV_INT, 4)),
               'A36EditBufferContext::sendParamToDevice', '0x000daa7a', 'CONFIRMED', S))
    v.append(V('cab_mic_change_to_421', 'LoadDspModel', 'out', 'editor',
               {'group': 'cab', 'param': '@mic', 'value': 2, 'cab': '4x12BritT75Studio'},
               ed_load_dsp_model(i('StudioCab'), i('4x12BritT75Studio421')),
               'sendParamToDevice -> CabModelAndMicToStudioCabSymbol -> setToneMatchModel -> LoadDspModel',
               '0x000daa7a/0x00108b88/0x00103e86', 'CONFIRMED', S))
    v.append(V('global_tempo_120', 'SetGlobalTempo', 'out', 'editor', {'group': 'global', 'param': '@tempo', 'value': 120.0},
               req(ED['SetGlobalTempo'], struct.pack('<f', 120.0)),
               'ToneMatchEdit_Remote::SetGlobalTempo', '0x001054aa', 'CONFIRMED', 'float32 BPM, 30..240'))
    v.append(V('global_tweakmin_0.2', 'SetPresetPSKeyParam', 'out', 'editor',
               {'group': 'global', 'param': '@tweakmin', 'value': 0.2},
               req(ED['SetPresetPSKeyParam'], struct.pack('<I', 7) + tv(TV_FLOAT, 0.2)),
               'ToneMatchEdit_Remote::SetPresetPSKeyParam', '0x00105980', 'CONFIRMED',
               'only sent when fw >= 0x02110300 on AMPLIFi (FUN_001084fb)'))
    v.append(V('global_pedal2assign_true', 'SetPresetPSKeyParam', 'out', 'editor',
               {'group': 'global', 'param': '@pedal2assign', 'value': True},
               req(ED['SetPresetPSKeyParam'], struct.pack('<I', 9) + tv(TV_BOOL, True)),
               'ToneMatchEdit_Remote::SetPresetPSKeyParam', '0x00105980', 'CONFIRMED', 'fw gate as above'))
    v.append(V('tweak_bind_amp_Drive', 'BindTweakParam', 'out', 'editor',
               {'tweakgroup': 'amp', 'tweakparam': 'Drive'},
               req(ED['BindTweakParam'], struct.pack('<II', i('Amp'), i('Drive'))),
               'A36EditBufferContext::bindTweakOnDeviceForGroup -> BindTweakParam', '0x000dbd1c/0x001053e0',
               'CONFIRMED', S + '; 1000 ms timeout'))
    v.append(V('device_setting_Master_0.5', 'SetDspModelParam', 'out', 'editor',
               {'setting': 'Master', 'value': 0.5},
               ed_set_dsp_param(0xFFFFFFFF, i('Master'), tv(TV_FLOAT, 0.5)),
               'A36EditorLibrarian::setDeviceSetting -> setToneMatchModelParam("Master","")', '0x000e15ac',
               'CONFIRMED (slot "" -> 0xFFFFFFFF root slot); value range INFERRED 0..1', S))
    v.append(V('device_setting_GuitOutputGain_0.8', 'SetDspModelParam', 'out', 'editor',
               {'setting': 'GuitOutputGain', 'value': 0.8},
               ed_set_dsp_param(0xFFFFFFFF, i('GuitOutputGain'), tv(TV_FLOAT, 0.8)),
               'A36EditorLibrarian::setDeviceSetting', '0x000e15ac', 'CONFIRMED; range INFERRED', S))
    v.append(V('device_setting_TapTempoLED_true', 'SetPersistentSysParam', 'out', 'editor',
               {'setting': 'TapTempoLED', 'value': True},
               req(ED['SetPersistentSysParam'], struct.pack('<I', 7) + tv(TV_BOOL, True)),
               'A36EditorLibrarian::setDeviceSetting -> FSIEditor::SetPersistentSysParam -> SetPersistentSysParam',
               '0x000e15ac/0x000edd58/0x00105768', 'CONFIRMED',
               'key 7; AMPLIFi gate fw >= 0x02000600 (FUN_001084af); Java Boolean -> TV_BOOL'))
    v.append(V('get_Master', 'GetDspModelParam', 'out', 'editor', {'setting': 'Master'},
               ed_get_dsp_param(0xFFFFFFFF, i('Master')), 'A36EditorLibrarian::getDeviceSetting -> GetDspModelParam',
               '0x000e192c/0x00103f50', 'CONFIRMED', 'response: i32 status, TV'))
    v.append(V('get_FBVConnected', 'GetFbvConnectivityStatus', 'out', 'editor', {}, req(16),
               'ToneMatchEdit_Remote::GetFbvConnectivityStatus', '0x001055f4', 'CONFIRMED', 'response: u32 (no status)'))
    v.append(V('get_dirty_state', 'GetDirtyState', 'out', 'editor', {}, req(15),
               'ToneMatchEdit_Remote::GetDirtyState', '0x00105558', 'CONFIRMED', 'response: u32 (no status)'))
    v.append(V('tuner_query_state', 'GetDspModelParam', 'out', 'editor', {'slot': 'Tuner', 'param': 'Enable'},
               ed_get_dsp_param(i('Tuner'), i('Enable')), 'A36EditorLibrarian::handleNotification (on connect)',
               '0x000df576', 'CONFIRMED', S))
    v.append(V('tuner_engage', 'SetDspModelParam', 'out', 'editor', {'engage': True},
               ed_set_dsp_param(i('Tuner'), i('Enable'), tv(TV_INT, 1)),
               'A36EditorLibrarian::engageTunerInternal', '0x000e7240', 'CONFIRMED',
               'L6Variant(uint) -> TV_INT 1 (not BOOL); synchronous'))
    v.append(V('tuner_register_note_events', 'RegisterDspEvent', 'out', 'editor', {'slot': 'Tuner', 'param': 'Note'},
               req(ED['RegisterDspEvent'], struct.pack('<II', i('Tuner'), i('Note'))),
               'ToneMatchEditorService::registerToneMatchTunerEvent -> RegisterDspEvent', '0x00108eba/0x00104ef6',
               'CONFIRMED', 'sent after engage succeeded'))
    v.append(V('tuner_disengage', 'SetDspModelParam', 'out', 'editor', {'engage': False},
               ed_set_dsp_param(i('Tuner'), i('Enable'), tv(TV_INT, 0)),
               'A36EditorLibrarian::engageTunerInternal', '0x000e7240', 'CONFIRMED', 'followed by UnregisterDspEvent'))
    v.append(V('tuner_unregister_note_events', 'UnregisterDspEvent', 'out', 'editor', {},
               req(ED['UnregisterDspEvent'], struct.pack('<II', i('Tuner'), i('Note'))),
               'ToneMatchEdit_Remote::UnregisterDspEvent', '0x0010519c', 'CONFIRMED'))
    # inbound examples
    ev = struct.pack('<II', 2, 16) + struct.pack('<II', i('Tuner'), i('Note')) + tv(TV_FLOAT, 2.1)
    n, c = tuner_note_cents(2.1)
    v.append(V('in_tuner_note_event', 'DSP event (type 2)', 'in', 'editor',
               {'value': 2.1, 'expected_note': n, 'expected_cents': round(c, 3)}, ev,
               'ToneMatchEdit_Remote::HandleEvent -> handleTunerEvent -> convertA36TunerValueToNoteCents',
               '0x001066e2/0x00109b52/0x000ea729', 'CONFIRMED (layout+math); amp-side value semantics INFERRED'))
    ev = struct.pack('<II', 4, 16) + struct.pack('<II', i('Amp'), i('Drive')) + tv(TV_FLOAT, 0.7)
    v.append(V('in_param_event_amp_drive', 'param event (type 4)', 'in', 'editor',
               {'slot': 'Amp', 'param': 'Drive', 'value': 0.7,
                'notification': 'EditBuffer_ParamChanged{groupID:amp,paramID:Drive,value:0.7,onDevice:true}'}, ev,
               'HandleParamEvent -> handleParamEvent -> consumeParamEvent', '0x00106826/0x00109c86/0x000d3dfa', 'CONFIRMED'))
    ev = struct.pack('<II', 4, 16) + struct.pack('<II', 0xFFFFFFFF, i('Master')) + tv(TV_FLOAT, 0.4)
    v.append(V('in_param_event_master', 'param event (type 4), root slot', 'in', 'editor',
               {'slot': 0xFFFFFFFF, 'param': 'Master', 'value': 0.4,
                'notification': 'Device_SettingChanged{setting:Master,value:0.4,onDevice:true}'}, ev,
               'handleParamEvent -> consumeRootSlotParamEvent', '0x00109c86/0x000d405a', 'CONFIRMED'))
    ev = struct.pack('<II', 3, 16) + tv(TV_INT, 5) + tv(TV_INT, 0)
    v.append(V('in_patch_event_select_5', 'patch event (type 3)', 'in', 'editor',
               {'preset_index': 5, 'is_save': 0, 'notification': 'EditBuffer_DevicePresetChanged{presetIndex:5,onDevice:true}'},
               ev, 'HandlePatchEvent -> handlePatchEvent -> consumePatchEvent', '0x0010678a/0x00109bc4/0x000d433c', 'CONFIRMED'))
    ev = struct.pack('<II', 5, 8) + tv(TV_FLOAT, 120.0)
    v.append(V('in_tap_tempo_event', 'tap tempo event (type 5)', 'in', 'editor', {'bpm': 120.0}, ev,
               'HandleTapTempoEvent -> handleTapTempoEvent -> consumeTapTempoEvent', '0x001068ce/0x0010a054/0x000d4248',
               'CONFIRMED', 'value must be TV_FLOAT; sets global/@tempo'))
    ev = struct.pack('<II', 6, 8) + tv(TV_FLOAT, 1.0)
    v.append(V('in_fbv_connected', 'FBV status event (type 6)', 'in', 'editor', {'connected': True}, ev,
               'handleFbvStatusEvent', '0x0010a0ca', 'CONFIRMED', 'float > 0 = connected'))
    ev = struct.pack('<II', 1, 4) + struct.pack('<i', 0)
    v.append(V('in_response_status_ok', 'response (type 1)', 'in', 'editor', {'status': 0}, ev,
               'ToneMatchEdit_Remote::HandleResponse', '0x001064d8', 'CONFIRMED', 'FIFO-matched to oldest pending request'))
    # librarian
    v.append(V('lib_get_num_presets', 'GetNumPresets', 'out', 'librarian', {}, req(5),
               'ToneMatchLibrarian_Remote::GetNumPresets', '0x0010b95e', 'CONFIRMED', 'response: u32 count, NO status word'))
    v.append(V('lib_handshake_default_table', 'Handshake', 'out', 'librarian', {'crc32': '%08x' % sym.crc32()},
               req(4, struct.pack('<I', sym.crc32())), 'ToneMatchLibrarian_Remote::Handshake', '0x0010b884', 'CONFIRMED'))
    for k in (0, 5):
        v.append(V('lib_get_preset_name_%d' % k, 'GetPresetName', 'out', 'librarian', {'index': k},
                   req(6, struct.pack('<I', k)), 'ToneMatchLibrarian_Remote::GetPresetName', '0x0010ba0e', 'CONFIRMED',
                   'response: i32 status, u32 nameLen, char[nameLen<=64]'))
    for k in (0, 5):
        v.append(V('select_preset_%d_step1_get' % k, 'GetPresetFile', 'out', 'librarian', {'index': k},
                   lib_get_preset_file(k), 'A36EditBufferContext::loadPresetFromDevice -> GetPresetFile',
                   '0x000d5444/0x0010be42', 'CONFIRMED', 'response: i32 status, blob (len-4 bytes, <=0x8000)'))
    v.append(V('select_preset_step2_put_editbuffer', 'SetPresetFile', 'out', 'librarian',
               {'index': 'EDIT_BUFFER(0xFFFFFFFF)', 'blob': 'raw bytes from step1 (L bytes)'},
               '0c000000<u32 8+L>ffffffff<u32 L><blob>', 'loadPresetFromDevice -> SetPresetFile',
               '0x000d5444/0x0010bf12', 'CONFIRMED'))
    v.append(V('save_to_slot_3', 'SetPresetFile', 'out', 'librarian', {'index': 3, 'blob': 'full-tone blob (preset_blob.py)'},
               '0c000000<u32 8+L>03000000<u32 L><blob>', 'savePresetToDevice -> SetPresetFile',
               '0x000d5796/0x0010bf12', 'CONFIRMED'))
    v.append(V('lib_move_src1_dst4', 'MovePresetFiles', 'out', 'librarian', {'src': 1, 'dst': 4},
               req(9, struct.pack('<II', 4, 1)), 'A36EditorLibrarian::moveResource -> MovePresetFiles',
               '0x000e5e46/0x0010bcb4', 'CONFIRMED order (dst first); amp semantics INFERRED (insert/move)'))
    v.append(V('lib_get_preset_info_0', 'GetPresetInfo', 'out', 'librarian', {'index': 0}, req(14, struct.pack('<I', 0)),
               'ToneMatchLibrarian_Remote::GetPresetInfo', '0x0010c0d4', 'CONFIRMED',
               'response: i32 status, u64 uuid, u32 checksum, u32 size, u32 nameLen, char[64]'))
    v.append(V('lib_get_editbuffer', 'GetPresetFile', 'out', 'librarian', {'index': 'EDIT_BUFFER'},
               lib_get_preset_file(EDIT_BUFFER), 'syncWithDeviceAsMaster(true) -> getToneMatchPreset(-1)',
               '0x000da514', 'CONFIRMED', 'read current edit buffer after connect'))
    return v

def main():
    a = sys.argv
    if len(a) < 2:
        print(__doc__); return
    if a[1] == 'vectors':
        sym = SymTab(a[2]); models = load_models(a[3])
        vec = build_vectors(sym, models)
        extra = []
        pbpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'preset_blob.py')
        if os.path.exists(pbpath):
            import subprocess
            dp = os.path.join(a[3], 'default_preset.json')
            for grp in ('Preset', 'fx1', 'amp'):
                r = subprocess.run([sys.executable, '-I', pbpath, 'encode', dp, a[2], a[3]] +
                                   ([] if grp == 'Preset' else [grp]) + ['--hex'], capture_output=True, text=True)
                hx = r.stdout.strip()
                if r.returncode == 0 and hx:
                    blob = bytes.fromhex(hx)
                    extra.append(V('preset_blob_default_preset_%s' % grp, 'device preset blob (SetPresetFile body)', 'out',
                                   'librarian', {'json': 'assets/default_preset.json', 'group': grp, 'len': len(blob)},
                                   hx, 'L6A36Preset::SerializeToDeviceForGroup + L6SPePresetSerializer',
                                   '0x000fa480/0x00100302', 'INFERRED (static re-implementation, not capture-verified)'))
                    if grp == 'Preset':
                        extra.append(V('load_tone_json_editbuffer', 'SetPresetFile', 'out', 'librarian',
                                       {'index': 'EDIT_BUFFER', 'blob': 'preset_blob_default_preset_Preset'},
                                       lib_set_preset_file(EDIT_BUFFER, blob)[:16].hex() + '<blob>',
                                       'loadEditBufferFromDataBuffer -> loadPresetFromFile -> syncWithDeviceAsMaster(false)',
                                       '0x000e4578/0x000d4ee8/0x000da514', 'CONFIRMED envelope; blob INFERRED'))
        out = dict(description='Application-layer (service RPC) payload test vectors for AMPLIFi 150. '
                   'Each payload_hex = u32 cmd/type LE + u32 len LE + body, as written to/read from the '
                   'editor (0x2002<->0x03ED) or librarian (0x2003<->0x03EF) service stream. No McBsp/stream/RSMC '
                   'framing or CRC16. Symbol indices come from assets/defaultSymbolTable.bin (CRC32 %08x).' % sym.crc32(),
                   generator='analysis/scripts/app_messages.py', vectors=vec + extra)
        with open(a[4], 'w') as fh:
            json.dump(out, fh, indent=1)
        print('wrote %d vectors to %s' % (len(out['vectors']), a[4]))
    elif a[1] == 'setparam':
        sym = SymTab(a[2]); models = load_models(a[3])
        g, p, val = a[4], a[5], a[6]
        val = {'true': True, 'false': False}.get(val.lower(), val)
        try: val = float(val) if not isinstance(val, bool) else val
        except ValueError: pass
        pm = json.load(open(os.path.join(a[3], 'default_preset.json')))['data']['tone']
        print(set_edit_buffer_param(sym, models, {k: v.get('@model') for k, v in pm.items()}, g, p, val).hex())
    elif a[1] == 'decode-in':
        print(json.dumps(decode_inbound(bytes.fromhex(a[2])), indent=1))
    elif a[1] == 'tuner':
        print(tuner_note_cents(float(a[2])))

if __name__ == '__main__':
    main()
