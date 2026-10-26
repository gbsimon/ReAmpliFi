#!/usr/bin/env python3
"""AMPLIFi device-preset ("SPe") blob encoder/decoder - static re-implementation of
L6A36Preset::SerializeToDeviceForGroup (Ghidra 000fa480) + L6SPePresetSerializer (00100302..).
Non-AEON (AMPLIFi 75/150/FX100/TT/30) path only. Payload only (no librarian/transport framing).

usage:
  python3 -I preset_blob.py encode <preset.json|.l6p> <symtab.bin> <assets_dir> [group] [--fw 0xVER] [--hex]
       group: Preset (default, full tone) | amp | cab | fx1 | fx2 | fx3 | reverb | gate | wah | volume | compressor | eq
  python3 -I preset_blob.py decode <blob.bin|hexstring> <symtab.bin>

Record = u32 key LE, u16 tag LE, payload:
  tag 0 void (no payload) | 1 bool u32 | 2 int i32 | 3 float f32 | 7 symbol u32 (symbol-table INDEX)
  tag 4 string: u32 len (incl. NUL) + bytes | tag 6 varray: u32 nwords + 4*n bytes
Directive keys: 0x80000000 SectionID(int) 0x80000001 SectionMagic(int) 0x80000002 SectionEnd(void)
  0x80000003 SlotStart(symbol) 0x80000004 SlotEnd(void) 0x80000005 Asset(symbol) 0x80000006 StateCount(int)
"""
import json, os, struct, sys

K_SEC, K_SECMAGIC, K_SECEND, K_SLOT, K_SLOTEND, K_ASSET, K_NSTATE = range(0x80000000, 0x80000007)
T_VOID, T_BOOL, T_INT, T_FLOAT, T_STR, T_VARR, T_SYM = 0, 1, 2, 3, 4, 6, 7
PS_SECTION, DSP_SECTION = 2, 1
PS_MAGIC, DSP_MAGIC = 0x50525350, 0x47545254
MIC_SUFFIX = ['57OnAxis', '57OffAxis', '421', 'U67']            # @0023eb04
# GuitarProc table, non-AEON (@0023e540): (dsp symbol, group, editor param)
GUITARPROC = [('CabEnable', 'cab', '@enabled'), ('GateEnable', 'gate', '@enabled'),
    ('PostCompEnable', 'compressor', '@enabled'), ('PostEQEnable', 'eq', '@enabled'),
    ('WahEnable', 'wah', '@enabled'), ('VolumePedalEnable', 'volume', '@enabled'),
    ('FX1Enable', 'fx1', '@enabled'), ('FX2Enable', 'fx2', '@enabled'), ('FX3Enable', 'fx3', '@enabled'),
    ('FX4Enable', 'reverb', '@enabled'), ('VolumePost', 'volume', '@post'), ('FX1Post', 'fx1', '@post'),
    ('FX2Post', 'fx2', '@post'), ('FX3Post', 'fx3', '@post'), ('FX4Post', 'reverb', '@post'),
    ('FX1Mix', 'fx1', '@mix'), ('FX2Mix', 'fx2', '@mix'), ('FX3Mix', 'fx3', '@mix'), ('FX4Mix', 'reverb', '@mix'),
    ('FX1MixType', 'fx1', '@mixtype'), ('FX2MixType', 'fx2', '@mixtype'), ('FX3MixType', 'fx3', '@mixtype'),
    ('ChannelVolume', 'amp', '@volume')]
# slot symbol -> group, non-AEON (@0023e820)
SLOT_GROUP = {'Gate': 'gate', 'VolumePedal': 'volume', 'Wah': 'wah', 'FX1': 'fx1', 'FX2': 'fx2', 'FX3': 'fx3',
              'FX4': 'reverb', 'Amp': 'amp', 'StudioCab': 'cab', 'LiveCab': 'cab', 'Air': 'cab',
              'PostComp': 'compressor', 'PostEQ': 'eq'}
GROUP_SLOT = {'gate': 'Gate', 'volume': 'VolumePedal', 'wah': 'Wah', 'fx1': 'FX1', 'fx2': 'FX2', 'fx3': 'FX3',
              'reverb': 'FX4', 'amp': 'Amp', 'cab': 'StudioCab', 'compressor': 'PostComp', 'eq': 'PostEQ'}
FULL_SLOTS = ['Gate', 'VolumePedal', 'Wah', 'FX1', 'FX2', 'FX3', 'FX4', 'Amp', 'Air', 'StudioCab', 'LiveCab',
              'PostComp', 'PostEQ']
# PS keys from parameters (@0023e9e0): key -> (group, param, tag)
PSKEY_PARAM = {3: ('global', '@tempo', T_FLOAT), 7: ('global', '@tweakmin', T_FLOAT),
               8: ('global', '@tweakmax', T_FLOAT), 9: ('global', '@pedal2assign', T_BOOL)}


def load_symtab(path):
    d = open(path, 'rb').read()
    n = struct.unpack_from('<I', d, 0)[0]; blob = 8 + 12 * n; names = []
    for i in range(n):
        off, h, ln = struct.unpack_from('<III', d, 8 + 12 * i)
        names.append(d[blob + off: blob + off + ln].decode('latin1'))
    return names


class Sym:
    def __init__(s, names): s.names = names; s.idx = {}; [s.idx.setdefault(n, i) for i, n in enumerate(names)]
    def look(s, n): return s.idx.get(n, -1)          # SymbolTable::LookupString -> INDEX or -1
    def name(s, i): return s.names[i] if 0 <= i < len(s.names) else f'<#{i}>'


def load_models(assets):
    m = {}
    for f in os.listdir(assets):
        if f.endswith('.models'):
            for e in json.load(open(os.path.join(assets, f))): m[e['symbolicID']] = e
    return m


def check_value(model, pname, v):
    """L6EdLibModelDefs::CheckParamValueForModel (000c2e10): returns (tag, value) or None."""
    if model is None: return None
    pd = next((p for p in model['params'] if p['symbolicID'] == pname), None)
    if pd is None: return None
    vt = pd['valueType']
    if vt == 1:
        x = float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else float(pd['default'])
        x = min(max(x, float(pd['min'])), float(pd['max'])); return (T_FLOAT, x)
    if vt == 0:
        if isinstance(v, bool): x = int(v)
        elif isinstance(v, float): x = int(v + 0.5) if v >= 0 else int(v - 0.5)
        elif isinstance(v, int): x = v
        else: x = int(pd['default'])
        x = min(max(x, int(pd['min'])), int(pd['max'])); return (T_INT, x)
    if vt == 2:
        return (T_BOOL, 1 if (bool(v) if isinstance(v, (bool, int, float)) else bool(pd['default'])) else 0)
    return (T_STR, str(v))


class W:
    def __init__(s): s.b = bytearray()
    def kv(s, key, tag, val=None):
        s.b += struct.pack('<IH', key & 0xffffffff, tag)
        if tag == T_VOID: return
        if tag == T_STR:
            raw = val.encode('utf-8') + b'\0'; s.b += struct.pack('<I', len(raw)) + raw
        elif tag == T_FLOAT: s.b += struct.pack('<f', val)
        elif tag == T_INT: s.b += struct.pack('<i', val)
        else: s.b += struct.pack('<I', val & 0xffffffff)
    def asset(s, asset_idx, states):          # StoreAssetState (00101452)
        s.kv(K_ASSET, T_SYM, asset_idx); s.kv(K_NSTATE, T_INT, len(states))
        for k, (t, v) in states: s.kv(k, t, v)


def encode(preset, sym, models, group='Preset', fw=0):
    tone = preset['data']['tone']; meta = preset['data'].get('meta', {})
    g = lambda grp, p: tone.get(grp, {}).get(p)
    model_of = lambda grp: models.get(g(grp, '@model'))
    def gpv(grp, p):                          # GetParamWithValidation
        v = g(grp, p)
        if v is None: return None
        mdl = models.get('@global_params') if grp == 'global' else model_of(grp)
        return check_value(mdl, p, v)
    w = W(); log = []
    # ---- PS section
    w.kv(K_SEC, T_INT, PS_SECTION); w.kv(K_SECMAGIC, T_INT, PS_MAGIC)
    nm = meta.get('name')
    if isinstance(nm, str): w.kv(0, T_STR, nm.encode('utf-8')[:63].decode('utf-8', 'ignore'))
    def pskey(k):
        grp, p, t = PSKEY_PARAM[k]; cv = gpv(grp, p)
        if cv is None: return
        v = cv[1]
        w.kv(k, t, (1 if v else 0) if t == T_BOOL else (int(v) if t == T_INT else float(v)))
    if fw >= 0x2110300:
        for k in (7, 8, 9): pskey(k)
    tg, tp = g('global', '@tweakgroup'), g('global', '@tweakparam')
    if tg is not None and tp is not None:
        slot, par = dsp_slot(tg, tp)
        if slot is None: w.kv(4, T_SYM, -1); w.kv(5, T_SYM, -1)
        else:
            a, b = sym.look(slot), sym.look(par)
            if a < 0 or b < 0: raise ValueError('tweak symbol missing')
            w.kv(4, T_SYM, a); w.kv(5, T_SYM, b)
    if group == 'Preset':
        tnid = meta.get('tnid')
        if tnid is not None:
            w.kv(1, T_INT, int(tnid) & 0xffffffff if (int(tnid) & 0x80000000) == 0 else (int(tnid) & 0xffffffff) - (1 << 32))
            w.kv(2, T_INT, (int(tnid) >> 32) & 0xffffffff)
        pskey(3)
    w.kv(K_SECEND, T_VOID)
    # ---- DSP section
    w.kv(K_SEC, T_INT, DSP_SECTION); w.kv(K_SECMAGIC, T_INT, DSP_MAGIC)
    w.kv(K_SLOT, T_SYM, sym.look('GuitarProc'))
    sel = {'Preset': None, 'amp': ('amp', 'cab')}.get(group, (group,))
    states = []
    for dsp, grp, p in GUITARPROC:
        if sel is not None and grp not in sel: continue
        if dsp == 'CabEnable': cv = (T_BOOL, 1 if g('cab', '@model') != '@NoCabinet' else 0)
        else:
            cv = gpv(grp, p)
            if cv is None and p == '@mix': cv = (T_FLOAT, 1.0)
        if cv is None: continue
        k = sym.look(dsp + 'State')
        if k < 0: log.append(f'skip {dsp}State (no symbol)'); continue
        states.append((k, cv))
    w.asset(sym.look('ToneMatchGuitarFlow'), states)
    slots = FULL_SLOTS if group == 'Preset' else (['Amp', 'Air', 'StudioCab', 'LiveCab'] if group == 'amp' else
             (['Air', 'StudioCab', 'LiveCab'] if group == 'cab' else [GROUP_SLOT[group]]))
    for s in slots:
        w.kv(K_SLOT, T_SYM, sym.look(s)); st = []
        cab = g('cab', '@model')
        if s == 'Air':
            asset = sym.look('TNGAIRReflections')
            lv = (T_FLOAT, 0.0) if cab == '@NoCabinet' else (gpv('cab', 'Level') or (T_FLOAT, 0.0))
            st.append((sym.look('LevelState'), (T_FLOAT, float(lv[1]))))
        elif s == 'StudioCab':
            if cab == '@NoCabinet': asset = sym.look('2x12Line6Studio57OnAxis')
            else:
                mic = gpv('cab', '@mic'); mic = mic[1] if mic else 0
                asset = sym.look(cab + MIC_SUFFIX[mic]) if 0 <= mic < 4 else -1
        elif s == 'LiveCab':
            asset = sym.look(models.get(cab, {}).get('cablink', ''))
        else:
            grp = SLOT_GROUP[s]; mid = g(grp, '@model'); mdl = models.get(mid)
            asset = sym.look(mid) if mid else -1
            has_sync = mdl is not None and any(p['symbolicID'] == 'SyncSelect' for p in mdl['params'])
            did_sync = False
            for p, v in tone.get(grp, {}).items():
                if p.startswith('@'): continue
                cv = check_value(mdl, p, v)
                if cv is None: continue
                if p == 'SyncSelect':
                    if not g(grp, '@temposync'): cv = (T_INT, 0)
                    did_sync = True
                k = sym.look(p + 'State')
                if k < 0: log.append(f'skip {p}State for {mid} (no symbol)'); continue
                st.append((k, cv))
            if has_sync and not did_sync: st.append((sym.look('SyncSelectState'), (T_INT, 0)))
        if asset < 0: raise ValueError(f'asset symbol missing for slot {s}')
        w.asset(asset, st); w.kv(K_SLOTEND, T_VOID)
    w.kv(K_SLOTEND, T_VOID); w.kv(K_SECEND, T_VOID)
    return bytes(w.b), log


def dsp_slot(group, param):
    """GetDSPSlotForGroupAndParam (000eafcf), non-AEON."""
    if param.startswith('@'):
        for dsp, grp, p in GUITARPROC:
            if grp == group and p == param: return 'GuitarProc', dsp
        return None, None
    if group == 'cab' and param == 'Level': return 'Air', param
    s = GROUP_SLOT.get(group); return (s, param) if s else (None, None)


def decode(b, sym):
    o = 0; depth = 0; out = []
    dk = {K_SEC: 'SectionID', K_SECMAGIC: 'SectionMagic', K_SECEND: 'SectionEnd', K_SLOT: 'SlotStart',
          K_SLOTEND: 'SlotEnd', K_ASSET: 'Asset', K_NSTATE: 'StateCount'}
    while o + 6 <= len(b):
        key, tag = struct.unpack_from('<IH', b, o); o += 6
        if tag == T_VOID: val = None
        elif tag == T_STR:
            n = struct.unpack_from('<I', b, o)[0]; val = b[o+4:o+4+n].rstrip(b'\0').decode('utf-8', 'replace'); o += 4 + n
        elif tag == T_VARR:
            n = struct.unpack_from('<I', b, o)[0]; val = b[o+4:o+4+4*n].hex(); o += 4 + 4*n
        else:
            raw = b[o:o+4]; o += 4
            val = {T_BOOL: lambda: bool(struct.unpack('<I', raw)[0]), T_INT: lambda: struct.unpack('<i', raw)[0],
                   T_FLOAT: lambda: round(struct.unpack('<f', raw)[0], 6),
                   T_SYM: lambda: sym.name(struct.unpack('<i', raw)[0])}.get(tag, lambda: raw.hex())()
        if key == K_SLOTEND: depth -= 1
        kn = dk.get(key, (sym.name(key) if key < 0x80000000 and depth > 0 else f'PSKey{key}'))
        out.append('  ' * max(depth, 0) + f'{kn} [{tag}] = {val!r}')
        if key == K_SLOT: depth += 1
    return '\n'.join(out)


def main():
    a = sys.argv
    if a[1] == 'encode':
        preset = json.load(open(a[2])); sym = Sym(load_symtab(a[3])); models = load_models(a[4])
        group = a[5] if len(a) > 5 and not a[5].startswith('--') else 'Preset'
        fw = int(a[a.index('--fw') + 1], 0) if '--fw' in a else 0
        blob, log = encode(preset, sym, models, group, fw)
        for l in log: print('#', l, file=sys.stderr)
        if '--hex' in a: print(blob.hex())
        else: sys.stdout.buffer.write(blob)
    elif a[1] == 'decode':
        src = a[2]; sym = Sym(load_symtab(a[3]))
        b = open(src, 'rb').read() if os.path.exists(src) else bytes.fromhex(src)
        print(decode(b, sym))

if __name__ == '__main__': main()
