# Native transport and session layers (libAmplifiRemoteNdk.so, x86 build)

Scope: the bytes on the Bluetooth SPP link up to the service RPC layer (ToneMatch Editor / Librarian).
Parameter and message meanings are out of scope (another note covers them).
Firmware update, flash and bootloader paths are only **named as AVOID** here (section 12). Nothing in this note explains how to drive them.

Legend: **CONFIRMED** = read directly in decompiled code or disassembly (function + Ghidra address cited).
**INFERRED** = deduced from code structure or naming, or depends on what the amp does. **UNKNOWN** = not determinable statically.
Ghidra addresses = ELF vaddr + 0x10000. Text segment file offset = vaddr; data segment file offset = vaddr − 0x1000.
All multi-byte fields are **little-endian** on the wire, because the code copies native x86/ARM-LE structs straight to the stream (CONFIRMED for this build; an HCI snoop capture should confirm the amp side).

Tools written for this note:
- `analysis/scripts/crc16.py`: CRC16/CRC32 ports, catalogue identification, frame/segment builders, example vectors, self-test. Run `python3 -I analysis/scripts/crc16.py --lib analysis/work/ghidra/input/libAmplifiRemoteNdk.so --symtab analysis/work/apktool/assets/defaultSymbolTable.bin`.
- `analysis/scripts/elfpeek.py`: reads bytes, strings and dwords at Ghidra addresses.
- `analysis/scripts/ghidra/DecompAt.java`: headless post-script. It creates functions at static labels that Ghidra missed (function-pointer targets) and decompiles them. Outputs are in `analysis/work/ghidra/extra/{msg_static.c,iostream.c}`.

---------------------------------------------------------------------------------------------------

## 0. Verdicts at a glance

| Question | Answer |
|---|---|
| Framing | Fixed 12-byte header with sync word `55 55`, a header CRC and a payload CRC. **No escaping or byte stuffing.** Length-delimited. CONFIRMED |
| CRC16 | **CRC-16/CCITT-FALSE** (IBM-3740): poly 0x1021, init 0xFFFF, refin/refout false, xorout 0. Computed bitwise, no table. Stored LE. CONFIRMED |
| Reliability | Selective-repeat ARQ: 8-bit seq, cumulative ACK, credit window of 8 packets, 1000 ms retransmit of the oldest unacked packet, no NAK, no retry limit. CONFIRMED |
| Multiplexing | McBsp "message" layer: 8-byte transport header with 16-bit src/dst addresses (node byte + port byte). A TCP-like **stream** protocol sits on top. Editor = 0x2002↔0x03ED, Librarian / DeviceInfo / (Updater) = 0x2003↔0x03EF. CONFIRMED |
| Service RPC | `u32 cmd, u32 len, payload` requests. `u32 type, u32 len, payload` responses and events. Responses are matched FIFO (no transaction id). CONFIRMED |
| Handshake | ASCII link sync (`IAP x OK`, then `IAP x START`), stream SYN, a 4-byte service-mode word on 0x03EF, then per service: GetVersion → Handshake(CRC32 of symbol table) → (fallback) download the symbol table from the amp. CONFIRMED |
| Symbol table | String↔ID dictionary. The app **downloads** it from the amp (cmd 2/3) when its cached or bundled copy is rejected. Only its **CRC32 is uploaded**. CONFIRMED |
| Encryption / auth on the wire | **NONE**. Evidence in section 9. |
| `"encryption"` key | Tone-file container (DIF) field only. The `"L6"` encryption path is a stub that returns −8301. It is not used on the wire. CONFIRMED |

---------------------------------------------------------------------------------------------------

## 1. Layer diagram

```
 Java  AmplifiDeviceManager: BluetoothSocket RFCOMM, UUID 00001101-...-00805f9b34fb
   |  nativeSppInStreamData(bytes)         ^ ISppOutStreamSink callback (SPP thread, byte[]),
   v                                       | also nativeSppOutStreamData/Count (pull)
 L7  AmplifiRemoteManager::SppInStreamData 0x86b90 / ConsumeSppOutStreamData 0x86b14 / handleSpp 0x86cc8
       -> L6AndroidNdkDevice::SppInData 0xa63f4 / SppOutStreamData 0xa64c8
 L6  AndroidSppMsgChannel (C++ glue, 0xa2490..0xa38ea)
       link sync state machine ("IAP x OK", "IAP x START", "IAP x STOP"), 200 ms timer,
       4 KB out ring buffer; write 0xa2ed0 drops bytes unless state RUNNING
 L5  RobustSerialMsgChannel (C, 0x1122f0..0x1132d0)   <-- "RSMC", framing + ARQ + CRC16
       Init 0x1131f0, Start 0x112f50, Stop 0x113020, HandleRxData 0x112440,
       ExecTasks 0x112950, QueueOutMessage 0x112370, CompleteInPacket 0x1122f0; CRC16_Process 0x113b10
 L4  MsgRouter (C) + BspRouter (C++)      -- splits RSMC payload into messages and routes by dst address
       MsgRouter_HandleChannelInPacket 0x1107f0 -> router task 0x110300 (static, via DeferredTask)
       routing lookup 0x110240, MsgRouter_AddRoutingEntry 0x110720, BspRouter::Init 0x113510
       MsgTransportHeader_Pack 0x1122b0 / _Unpack 0x112280, MsgPort_PrepareTransportHeader 0x1101e0
 L3  MsgPortManager (node 0x20) 0x10fc70, handler 0x10fac0 (dispatch by dst port)
       MsgPort_Stream_* (TCP-like):   Init 0x111970, Bind 0x111b10, Connect 0x111d60,
       Accept 0x111ba0, Close 0x1120c0, SetHeartbeatTimeout 0x112080, SetAutoFlush 0x111fc0,
       RX handler 0x1112e0, TX task 0x110880, TX-done 0x111040,
       IOStream vtable @0x239110: read 0x110e80, write 0x110d00, read2 0x111010, flush 0x1111b0
       (MsgPort_Datagram_* 0x10f760.. exists but has no callers)
 L2  L6BspMsgPort / L6BspMsgPort_Amplifi (IDevicePort): open 0x9ba70 / 0xa1c24, changeMode 0xa1d5e
       (4-byte service-mode word on the librarian port), read 0x9bf04, readAll 0x9bf4c, write 0x9bf94
 L1  ToneMatchEdit_Remote (Editor RPC) 0x103850.. / ToneMatchLibrarian_Remote 0x10b4ea..
       DoCommandCommon, HandleInPacket (0x106b16 / 0x10c61e), HandleResponse, HandleEvent
 L0  FirmwareServiceInterfaceBase/Editor/Librarian(V2): open 0xd1ecc, HandleHandshake 0xd2302,
       ReceiveCrank 0xd27e0 -> ToneMatchFirmwareService 0x10ae82.. -> ToneMatchEditorService /
       ToneMatchLibrarianService -> A36EditBufferContext / A36EditorLibrarian -> JNI
```
Device orchestration: `L6AndroidNdkDevice::initialize 0xa4ca2`, `prepareForDeviceInfo 0xa5cd0`, `connectWithObjHelper 0xa51b4`, `openHelper 0xa5168`, `disconnect 0xa5558`. All CONFIRMED.

---------------------------------------------------------------------------------------------------

## 2. Link bring-up on the raw SPP stream (AndroidSppMsgChannel)

CONFIRMED in `AndroidSppMsgChannel::Open 0xa2baa`, `execTasks 0xa35ac`, `Close 0xa2e08` and `AndroidSppMsgChannel_write 0xa2ed0`. String bytes are at 0x1b7be5 (dumped with elfpeek):

| State | Name in logs | Action on each 200 ms tick |
|---|---|---|
| 2 | SYNCHING_STAGE1 | Write ASCII `IAP x OK` (8 bytes, **no NUL**): `49 41 50 20 78 20 4F 4B`. Counter = 5. Go to state 3. |
| 3 | SYNCHING_STAGE2 | Decrement counter. At 0, write `IAP x START` (11 bytes): `49 41 50 20 78 20 53 54 41 52 54`. Counter = 5. Go to state 4. |
| 4 | SYNCHING_STAGE3 | Decrement counter. At 0, go to RUNNING (5). |
| 5 | RUNNING | RSMC frames are copied to the out buffer. |
| 6 | stopping | Set by Close, which first writes `IAP x STOP` (10 bytes): `49 41 50 20 78 20 53 54 4F 50`. Next tick: channel-down event, then `RobustSerialMsgChannel_Stop`. |
| 7 | stopped | Timer stopped and destroyed. |

- Timeline: `IAP x OK` ≈0.2 s after open, `IAP x START` ≈1.2 s, RUNNING ≈2.2 s. `Open()` waits up to 10 × 500 ms for RUNNING. CONFIRMED
- **Nothing received is parsed as ASCII.** The RX path goes straight to RSMC sync hunting (section 3), so the phone never waits for a reply to these strings. CONFIRMED
- While in states 2–4 and 6–7, `AndroidSppMsgChannel_write` returns 0 (success) but **drops** the RSMC bytes. The RSMC already runs during sync (its ExecTasks is called on every tick), so early frames are silently lost and later recovered by the RSMC retransmit or ACK logic. CONFIRMED
- INFERRED: the strings are commands to the amp's BT bridge or firmware ("iAP" heritage from the iOS accessory version) that start and stop its RSMC endpoint. Whether the amp *requires* them, and whether it sends anything back, is UNKNOWN. **Capture with an HCI snoop.**
- The native code keeps a 200 ms periodic timer (`Timer_StartPeriodic(...,0,200)`, BspRouter timer group fed every ~100 ms by `RouterTimerTask 0x113890`). Each tick runs `execTasks` (sync state machine + `RobustSerialMsgChannel_ExecTasks`) and `HandleSppOutputData` (pushes bytes to Java). CONFIRMED

---------------------------------------------------------------------------------------------------

## 3. RobustSerialMsgChannel (RSMC) framing, byte-exact

### 3.1 Frame layout (CONFIRMED: TX in ExecTasks 0x112950, RX in HandleRxData 0x112440)
```
off size field      TX value / RX handling
 0   2   sync       0x55 0x55. RX hunts with a sliding 2-byte window.
 2   1   reserved   always 0x00 on TX; ignored on RX
 3   1   seq        tx sequence number of this packet (u8, wraps). Data packets start at 1.
                    Header-only frames carry the *last sent* seq (the receiver ignores it when len==0).
 4   1   ack        cumulative ACK = last peer seq delivered in order (starts 0)
 5   1   rx_limit   flow-control credit = highest peer seq this side will accept.
                    Starts at rx window size (8) and grows +1 per packet the upper layer finishes.
 6   2   len  u16   payload length in bytes (0 = header-only ACK/status frame); must be <= MTU-12
 8   2   pcrc u16   CRC-16/CCITT-FALSE over the len payload bytes; 0x0000 when len==0 (not checked)
10   2   hcrc u16   CRC-16/CCITT-FALSE over all 12 header bytes with the hcrc field set to 0x0000
12   len payload    concatenation of McBsp messages, each padded with 0x00 to a 4-byte multiple
```
- The header CRC is computed over **12 bytes including two zero bytes**, not over 10 bytes. The sync bytes are covered. CONFIRMED (TX sets `local_1e=0` before `CRC16_Process(&crc,&hdr,0xc)`; RX zeroes +0x2e before the check)
- The payload CRC is accumulated as bytes arrive and covers the zero padding (TX feeds the padding zeros through CRC16 too). CONFIRMED
- No escaping. `55 55` may appear inside the payload; resync relies on the header CRC. If the header CRC is bad, the receiver drops those 12 bytes, increments the error counter (+0x38) and resumes hunting **after** them, not at sync+1. CONFIRMED
- Both sides never send `len > MTU − 12`. The receiver treats a larger `len` as an error and resets the hunt. CONFIRMED

### 3.2 Parameters (CONFIRMED in `AndroidSppMsgChannel::AndroidSppMsgChannel 0xa2490` → `RobustSerialMsgChannel_Init(rsmc, ops@0x239100, mtu, txSlots, 8, rxSlots, 8, 1000)`)
- TX window = 8 packets, RX window = 8 packets, retransmit timeout = 1000 ms (compared with `currentTimeInMilliseconds`).
- MTU (whole frame) = `L6AndroidNdkDevice+0x6c`. The constructor value is **240** (`AmplifiRemoteManager::OpenOnLine` passes 0xF0). After device info is read, `setupMessageChannelParameters 0xa4b14` picks the final value:
  - AMPLIFi (not 30) with corrected firmware version < 0x02100100: **MTU 256**, stream heartbeat timeout 4000 ms.
  - Otherwise: **MTU 240**, timeout 16000 ms.
  - AMPLIFi 30 uses a threshold of 0x00010000. Heartbeat "interval" is logged as 1000, but see section 5.4.
  - The version is built by `L6StringToL6VersionInt` from "%d.%02d.%d%c". 0x02100100 most likely means fw **2.10.1** (INFERRED; `SetVersionNum` packing was not read).
- Max payload = MTU − 12 (228 or 244). Each upper-layer message must fit in one RSMC packet; `QueueOutMessage` rejects larger ones with −36. CONFIRMED

### 3.3 ARQ behaviour (CONFIRMED in ExecTasks / HandleRxData)
- **Send rule**: a new packet `seq = last_sent+1` goes out only if `(last_acked + 8 − last_sent) ≥ 1` **and** `(peer_rx_limit − last_sent) ≥ 1` (signed 8-bit differences) **and** messages are queued. The packet takes as many queued messages as fit.
- **ACK processing**, on every valid header including header-only frames: frees TX slots `last_acked+1 .. ack` (if `0 < ack−last_acked ≤ 8`) and records `peer_rx_limit = hdr[5]`.
- **RX ordering**: a packet is stored in slot `seq % 8`. If `seq == last_delivered+1`, it is delivered up, followed by any consecutive buffered packets. Out-of-order packets inside the window are buffered. Duplicates or out-of-window packets are discarded. The credit (`rx_limit`) grows only when the router has finished with the packet (`CompleteInPacket`).
- **Retransmit**: on a tick with nothing new to send, if the oldest unacked packet has waited ≥ 1000 ms, it is resent (same seq, same payload, refreshed ack/limit). Only that one packet per tick. No retry limit, no NAK. Counter at +0x3c.
- **Idle**: when there is nothing to send or retransmit, **every ExecTasks call (every 200 ms) emits a 12-byte header-only frame** (`seq=last_sent, ack, rx_limit, len=0, pcrc=0`). This is the de-facto link keepalive and ACK carrier. CONFIRMED
- The first data packet can only go out after the peer has advertised `rx_limit > 0`, because `peer_rx_limit` starts at 0 after `Start()`. CONFIRMED
- Throughput consequence: at most one data frame per 200 ms tick → ≤ 5 × 244 B/s ≈ 1.2 KB/s. INFERRED from the timer-driven ExecTasks. `AndroidSppMsgChannel_requestTask 0xa3152` is a no-op, so requests do not trigger an immediate send.
- Stop: queued and in-flight messages complete with −35. CONFIRMED

### 3.4 CRC16 (CONFIRMED: decompile and disassembly of `CRC16_Process 0x113b10`)
```
x = (byte ^ (crc >> 8)) & 0xFF;  x ^= x >> 4;  crc = (crc << 8) ^ (x << 12) ^ (x << 5) ^ x   (16-bit)
```
Every caller seeds `0xFFFF`. No final XOR, no reflection. `crc16.py` matches only **CRC-16/CCITT-FALSE** (check("123456789") = 0x29B1) among CCITT-FALSE, XMODEM, KERMIT, AUG-CCITT, GENIBUS, X-25, MCRF4XX, MODBUS and ARC. There is **no lookup table** in the binary. The function's raw bytes are printed by the script. On the wire the CRC is LE (low byte first).

### 3.5 Other checksums in the binary (CONFIRMED)
| Function | Algorithm | Used by |
|---|---|---|
| `CRC32_bs 0xd177c` (table @0x1cd3a0, dumped = standard 0xEDB88320 table) | CRC-32/ISO-HDLC (zlib): init 0xFFFFFFFF, reflected, final ~ | (a) **Handshake payload**: `ToneMatchEdit_Remote::Handshake 0x103bac`, `ToneMatchLibrarian_Remote::Handshake 0x10b884` send `CRC32_bs(symbolTable, size)`. (b) `SymbolTable::LookupString 0xd2b70` (string hash). (c) `SymbolTable::CalcCRC32 0xd2cd0` (no callers). |
| `L6CRC32::calc 0xbf9fc` (runtime table from a poly argument) | Callers always pass 0x04C11DB7 → same CRC-32 as zlib | Only the 4 DIF tone-file helpers (0xc0fd3, 0xc1236, 0xc1521, 0xc1750) under `L6EdLibDIFWrite/Read` (`"crc32"` field of compressed/encrypted blobs). Not on the wire. |
| `Checksum_Fletcher 0xb8bd4` | Fletcher | Only `L6UUE::UpdateEngine::Session::DoChecksum` (firmware updater, AVOID). |

---------------------------------------------------------------------------------------------------

## 4. McBsp message layer (inside the RSMC payload)

### 4.1 Transport header, 8 bytes (CONFIRMED in `MsgTransportHeader_Pack 0x1122b0`, `_Unpack 0x112280`, `MsgPort_PrepareTransportHeader 0x1101e0`)
```
word0 (u32 LE): bits 0-15  length = bytes following this 8-byte header (option + stream hdr + data)
                bits 16-25 0
                bits 26-27 version, always 2
                bits 28-31 type: 1 = plain, 2 = with 4-byte option word (stream SYN)
word1 (u32 LE): bits 0-15  source address, bits 16-31 destination address
```
On the wire: `len_lo len_hi 00 T` with `T = 0x18` (type 1) or `0x28` (type 2), followed by `src_lo src_hi dst_lo dst_hi`.

- **Message packing**: the router task (0x110300) walks the RSMC payload. For each message it takes `size = (len + 8 + 3) & ~3` and dispatches it, as long as ≥ 8 bytes remain. CONFIRMED
- **Inbound type-2 rewrite**: the router clamps option bits 16-31 (MSS) to its own channel MSS and increments the low byte (hop count). Bits 8-15 are cleared. CONFIRMED

### 4.2 Addressing and routing (CONFIRMED)
- Address = `node << 8 | port`. The phone node is **0x20** (`McBspMessaging_Init(0x2000)` in `AmplifiRemoteManager::Initialize`). The amp node is **0x03** (remote addresses 0x03ED, 0x03EF).
- Routing table (`MsgRouter_AddRoutingEntry(addr, mask, prio, channel)`; match when `(dst & ~mask) == addr`; the entry with the smallest mask wins):
  - 0x2000 / 0x00FF → local MsgPortManager (phone ports).
  - 0x0300 / 0x00FF → SPP channel (added in the AndroidSppMsgChannel ctor).
  - 0x0000 / 0x0FFF → SPP channel (added in `connectWithObjHelper`).
- The local port is chosen in `L6BspMsgPort::open 0x9ba70` as `Bind(local | 0x2000)` then `Connect(remote)`. Ports 0x80–0xEF would be ephemeral, but they are never used here.

| Port object | ePortMode | Local | Remote | After stream connect |
|---|---|---|---|---|
| Editor port | 2 kEditorMode | **0x2002** | **0x03ED** | nothing (editor RPC starts directly) |
| Librarian port | 3 kLibrarianMode | **0x2003** | **0x03EF** | write u32 **1** (LIBRARIAN), read 4-byte echo |
| Device-info port | 4 kDeviceInfoMode | 0x2003 | 0x03EF | write u32 **2** (DEVICE_INFO), read echo, then read the 200-byte info struct |
| (Updater port) | 1 kUpdateMode | 0x2003 | 0x03EF | u32 **0** (UPDATER). **AVOID: never send** |

Mode translation is `L6BspMsgPort_Amplifi::TranslateePortMode 0xa1d2a`. The service-mode exchange is in `changeMode 0xa1d5e`: it writes 4 bytes, reads 4 bytes, and fails with −2006 (or −2008) if the echo differs. CONFIRMED

---------------------------------------------------------------------------------------------------

## 5. Stream protocol (MsgPort_Stream), a small TCP over McBsp

### 5.1 Segment layout (CONFIRMED: TX task 0x110880, RX handler 0x1112e0)
```
[transport hdr 8B: type 1, or type 2 when SYN]
[type 2 only] option u32: bits 16-31 = MSS (sender's channel MTU-12), bits 0-7 = hop count (0 at origin)
stream word A u32: bits 24-31 = flags, bits 8-15 = seq (u8), other bits 0
stream word B u32: window edge = cumulative "peer may send up to this byte count"
                   (initial = free rx buffer = 4096, + every byte the app has consumed)
data (0..N bytes)
```
| Flag | Meaning | Evidence |
|---|---|---|
| 0x01 SYN | Connect. Accept also answers with SYN. | Connect sets pending 0x01 (0x21 when heartbeat is enabled); Accept sets 0x01 |
| 0x02 FIN | Close | `MsgPort_Stream_Close` sets 0x02. Receiving FIN in state 3 → 7, in state 0xB → 0 |
| 0x04 DATA | Segment carries data | Set by the TX task when bytes are queued |
| 0x08 WND | Window update / ACK of consumed bytes | Set on tick after the app read data (+0x1c3 bit 2) or after a flush |
| 0x10 HB | Heartbeat (sent after TX has been idle for the interval) | Tick handler |
| 0x20 HB-enable | Only in SYN: asks a listening peer to use 4000 ms timeout / 1000 ms interval | RX: listener with flag 0x20 → +0x1cc=4000, +0x1c4=1000; without it heartbeat is disabled |

- **seq** starts at 1 with the SYN and increments on **every** segment (data, window updates and heartbeats included). The receiver requires exactly `last+1` on non-SYN segments; anything else **aborts the stream with −4**. Ordering is guaranteed by the RSMC underneath. CONFIRMED
- Max data per segment = `peerMSS − 16`, or `peerMSS − 20` when the SYN carries data. It is also limited by `window_edge − bytes_sent`. CONFIRMED
- Writes are buffered (4 KB TX ring). With auto-flush (always on) the data is pushed on the next 200 ms MsgPortManager tick. INFERRED latency ≤ 200 ms + RSMC tick. CONFIRMED mechanism: write 0x110d00 sets +0x1c3 bit 3, and the tick then schedules TX.
- States (+0x1b8): 0 idle/listen, 2 SYN sent, 3 established, 7 peer closed (FIN received), 0xB local close sent; negative = error. Errors: −4 protocol, −28 heartbeat timeout, −37 remote node down, −12 aborted, −41 = EOF seen by readAll.

### 5.2 Connect sequence (phone is the connector) (CONFIRMED)
1. `SetAutoFlush(1)` and `SetHeartbeatTimeout(timeout)`, then `Bind(0x2002|0x2003)` and `Connect(0x03ED|0x03EF)`.
2. TX SYN: type 2, option = MSS<<16, flags 0x21, seq 1, window 4096.
3. On a SYN from the remote in state 2, the stream goes to state 3 (established) and the peer MSS, seq and window are recorded. This is a 2-way handshake; no third ACK is required.
4. `SetHeartbeatTimeout` is applied again, so the phone always uses its own values.

### 5.3 Close (CONFIRMED)
`L6BspMsgPort::close` → `MsgPort_Stream_Close`: flush, send FIN (state 3 → 0xB), wait for the peer FIN, then the heartbeat timers are disabled. After that `AndroidSppMsgChannel::Close` writes `IAP x STOP`.

### 5.4 Heartbeat and timeouts (CONFIRMED in `MsgPort_Stream_SetHeartbeatTimeout 0x112080`, checked in disassembly)
- `SetHeartbeatTimeout(port, T)`: RX-silence timeout = **T**, TX-idle heartbeat interval = **T >> 2**. The third argument (the logged "heartbeatInterval") is ignored.
  - Device-info phase and old firmware: T = 4000 → heartbeat every 1000 ms of TX silence, link dead after 4 s without RX.
  - fw ≥ (INFERRED) 2.10.1: T = 16000 → heartbeat every 4 s, dead after 16 s.
- RX timer: reloaded on every received segment and decremented by the 200 ms ticks. On expiry the stream fails with −28.
- Caution (INFERRED): if the amp runs the same library, the phone's SYN flag 0x20 makes the **amp** use 4000/1000 (hard-coded in the RX SYN path). A phone using T = 16000 heartbeats only every 4 s, which leaves the amp's 4 s timeout borderline. A custom client should send a heartbeat (or any segment) at least **every 1 s**.

---------------------------------------------------------------------------------------------------

## 6. Service RPC framing (over the stream byte pipe)

### 6.1 Requests, phone → amp (CONFIRMED in `ToneMatchEdit_Remote::DoCommandCommon 0x103850`, `ToneMatchLibrarian_Remote::DoCommandCommon 0x10b4ea`)
```
u32 cmd_id, u32 payload_len, payload...
```
For Librarian `SetPresetFile`, `payload_len` counts the 8-byte argument block plus the file data, which is written separately.

### 6.2 Inbound messages, amp → phone (CONFIRMED in `HandleInPacket 0x106b16` / `0x10c61e`)
```
u32 type, u32 len, len bytes
```
- `type 0`: ignored. No body is consumed, so it presumably always has len 0 (INFERRED).
- `type 1`: response.
- Editor only:
  - `2` DSP event (u32, u32, typed value)
  - `3` patch event
  - `4` param event
  - `5` tap tempo
  - `6` FBV status
  - `7` PS-key change
  - `8` system-setting change
  - Event `len` must be ≤ 16 (the event buffer from `Init(port,0x200,7,0x10)`). A longer event fails with −19 and kills the receive loop.
- Any other type → −4 and the receive loop ends.

### 6.3 Response matching (CONFIRMED)
- There is no transaction id. Responses are matched to the **oldest outstanding request** (FIFO). Up to 512 requests can be outstanding.
- Editor response: the body is the raw result (e.g. 4-byte version).
- Librarian response: the body is `int32 status` followed by data, and `len` includes the status.
- Wait timeouts: 5000 ms; GetSymbolTable has none (∞); BindTweakParam uses 1000 ms. A timeout returns −28.
- "Async" variants still queue a token and expect, then discard, a response (INFERRED).

### 6.4 Command ids, all phone→amp requests answered by a type-1 response (CONFIRMED from `DoCommandCommon` call sites; payload sizes in bytes)

Editor service (stream 0x2002↔0x03ED):

| id | Function | Req | Resp |
|---|---|---|---|
| 1 | GetVersion | 0 | 4 |
| 2 | GetSymbolTableSize | 0 | 4 |
| 3 | GetSymbolTable | 0 | N |
| 4 | Handshake (u32 CRC32) | 4 | 4 (int32 ≥0 ok) |
| 5 | GetNumAddressableSlots | 0 | 4 |
| 6 | GetAddressableSlots | 0 | 4n |
| 7 | QueryCurrentDspModel | 4 | 8 |
| 8 | LoadDspModel | 8 | 4 |
| 9 | GetDspModelParam | 8 | 12 |
| 10 | SetDspModelParam (+Async) | 16 | 4 |
| 11 | RegisterDspEvent | 8 | 4 |
| 12 | UnregisterDspEvent | 8 | 4 |
| 13 | BindTweakParam | 8 | 4 |
| 14 | SetGlobalTempo | 4 | 4 |
| 15 | GetDirtyState | 0 | 4 |
| 16 | GetFbvConnectivityStatus | 0 | 4 |
| 17 | GetPersistentSysParam | 4 | 12 |
| 18 | SetPersistentSysParam (+Async) | 12 | 4 |
| 19 | SetPresetPSKeyParam (+Async) | 12 | 4 |
| 20 | GetPresetPSKeyParam | 4 | 12 |
| 21 | GetSystemSetting | 4 | 12 |
| 22 | SetSystemSetting | 12 | 4 |

The Register/Unregister Patch, Param, TapTempo, FbvStatus, PSKey and SysSetting event calls are **local** subscriptions only; they send nothing on the wire.

Librarian service (stream 0x2003↔0x03EF after service mode 1). Every response starts with an int32 status:

| id | Function | Req | Resp after status |
|---|---|---|---|
| 1 | GetVersion | 0 | 4 |
| 2 | GetSymbolTableSize | 0 | 4 |
| 3 | GetSymbolTable | 0 | N (not used: Librarian FetchSymbolTable returns −1) |
| 4 | Handshake (u32 CRC32) | 4 | – |
| 5 | GetNumPresets | 0 | 4 |
| 6 | GetPresetName | 4 | ≤0x44 |
| 7 | GetPresetUUID | 4 | 8 |
| 8 | GetPresetChecksum | 4 | 4 |
| 9 | MovePresetFiles | 8 | – |
| 10 | GetPresetFileSize | 4 | 4 |
| 11 | GetPresetFile | 4 | N |
| 12 | SetPresetFile (u32 idx, u32 size, data) | 8+N | – |
| 15 | SetPresetFile, bool-flag variant | 8+N | – |
| 13 | LoadHardwarePreset | 4 | – |
| 14 | GetPresetInfo | 4 | ≤0x54 |

Ids 9/12/15 write the amp's preset storage. That is user data, not firmware, but test carefully.

---------------------------------------------------------------------------------------------------

## 7. Session sequence (native side)

CONFIRMED per function. The call order across AmplifiRemoteManager and L6AndroidNdkDevice vtables is INFERRED.

1. `AmplifiRemoteManager::Initialize`: `McBspMessaging_Init(0x2000)` creates BspRouter, the "McBsp Router thread" and the "McBsp Timer thread".
2. Open online: `new L6AndroidNdkDevice(center, mtu=240)` with base defaults heartbeat T=4000. Then `initialize 0xa4ca2` → `prepareForDeviceInfo 0xa5cd0`:
   1. `connectWithObjHelper(0, kDeviceInfoMode)` creates the AndroidSppMsgChannel (MTU 240), the routes, and Open (IAP sync, RSMC start). Only the librarian-side port exists in this phase.
   2. Port open: stream SYN 0x2003→0x03EF (MSS 228), service-mode word `02 00 00 00`, echo expected.
   3. Read **200 bytes**: `char productName[64]` @0, `char model[64]` @0x40, `char serialNumber[64]` @0x80, `u32 firmwareRevision` @0xC0 (bytes major, minor, patch, char), 4 unknown bytes.
   4. Close the port (FIN), disconnect (IAP x STOP, RSMC stop, channel deleted).
   5. Product-id mapping by name: AMPLIFi 150 = 0x200002.
3. `setupMessageChannelParameters` picks MTU 256/240 and T 4000/16000 from the corrected version (section 3.2).
4. `connectWithObj` → `connectWithObjHelper(kEditorMode, kLibrarianMode)` builds a new channel: **IAP sync and RSMC start again from seq 0**.
5. `open 0xa57e0` → `openHelper`:
   1. Editor port: SYN 0x2002→0x03ED.
   2. Librarian port: SYN 0x2003→0x03EF, then service-mode word `01 00 00 00` with echo.
   3. If `firmwareRevision < 0x01000000` (FX100: 0x01000400), `forceFirmwareUpdate` is invoked. **AVOID**: a custom app must just refuse such amps.
6. Per service, `FirmwareServiceInterfaceBase::open 0xd1ecc` starts the ReceiveThread (HandleInPacket loop), then `HandleHandshake 0xd2302`:
   1. `FetchVersion` (cmd 1) → 4-byte version.
   2. Choice 1: `Handshake(cmd 4, CRC32_bs(cached symbol table))`. Choice 2: the same with the bundled `defaultSymbolTable*.bin` (path from Java).
   3. Choice 3 (Editor only): `GetSymbolTableSize` (cmd 2) and `GetSymbolTable` (cmd 3) **download** the table from the amp, then Handshake with its CRC32.
   4. On success `ToneMatchFirmwareService::completeHandshake 0x10b236` writes the table to the cache file and posts "HandshakeSucceeded".
   5. The Librarian does `GetNumPresets` (cmd 5) **before** its Handshake (cmd 4), then fills its preset cache (checksums, sizes, names).
- The handshake result int32 (Editor, stored at +0xd4) must be ≥ 0. There is no challenge, nonce or key: the "handshake" is a symbol-table compatibility check. CONFIRMED

---------------------------------------------------------------------------------------------------

## 8. Example frames (unit-test vectors; produced by `crc16.py`)

| # | Bytes (hex) | Status |
|---|---|---|
| E1 | `49 41 50 20 78 20 4F 4B` ("IAP x OK", first bytes the phone writes) | CONFIRMED |
| E2 | `49 41 50 20 78 20 53 54 41 52 54` ("IAP x START", ~1 s later) | CONFIRMED |
| E3 | `49 41 50 20 78 20 53 54 4F 50` ("IAP x STOP", on close) | CONFIRMED |
| E4 | RSMC header-only frame of a fresh channel (seq 0, ack 0, limit 8): `55 55 00 00 00 08 00 00 00 00 03 6B` | CONFIRMED (layout and values from Start/ExecTasks; CRC computed) |
| E5 | Device-info stream SYN message: `0C 00 00 28  03 20 EF 03  00 00 E4 00  00 01 00 21  00 10 00 00` (type 2, len 12, 0x2003→0x03EF, MSS 228, flags SYN|HB-enable, seq 1, window 4096) | CONFIRMED structure and values for MTU 240 |
| E6 | E5 inside RSMC data packet seq 1: `55 55 00 01 00 08 14 00 B1 BD CE A7` + E5 | INFERRED: ack=0 and limit=8 assume no amp data packet was delivered yet |
| E7 | Editor SYN: `0C 00 00 28 02 20 ED 03 00 00 E4 00 00 01 00 21 00 10 00 00` (MTU 240; with MTU 256 bytes 10-11 become `F4 00`) | CONFIRMED structure; MTU choice INFERRED |
| E8 | Service-mode words: DEVICE_INFO `02 00 00 00`, LIBRARIAN `01 00 00 00` | CONFIRMED |
| E9 | Editor GetVersion request (stream data): `01 00 00 00 00 00 00 00` | CONFIRMED |
| E10 | Editor Handshake with the bundled default table (CRC32_bs = 0xB68B291E): `04 00 00 00 04 00 00 00 1E 29 8B B6` | CONFIRMED format. Whether the amp accepts this CRC is UNKNOWN |
| E11 | Data segment carrying E9, seq 2: `10 00 00 18 02 20 ED 03 00 02 00 04 <u32 window> 01 00 00 00 00 00 00 00` | INFERRED: other pending flags (0x08) may be OR-ed in |

---------------------------------------------------------------------------------------------------

## 9. Encryption / authentication on the wire: **NONE**

Evidence (all CONFIRMED):
- Every byte path from `nativeSppInStreamData` to the services was traced: AndroidSppMsgChannel → RSMC (CRC16 only) → router (header parse) → stream (seq/window) → RPC (`u32` headers). No transform is applied to payloads at any layer, and the TX path mirrors it (struct copies plus CRC16).
- The handshake payload is a plain CRC32 of a public asset file (`defaultSymbolTable.bin`, or a table the amp itself hands out via cmd 3). No nonce, no challenge, no response computation, no key material.
- No crypto primitives in the binary: `strings` and the Ghidra string xrefs show no AES, cipher, HMAC, SHA, MD5, RSA or similar. The only "crypt" strings are `encryption` and `decrypted_size` in the DIF tone-file code. Java has no `javax.crypto` use either (INVENTORY §6; MD5 is used only for firmware download verification).
- The ASCII `IAP x ...` strings are fixed constants.
- Bluetooth BR/EDR pairing and link encryption, if active, are handled by the OS and are transparent to this protocol.

### "encryption" L6Variant key (CONFIRMED)
- It appears only in `L6EdLibDIFWrite 0xc00c2` / `L6EdLibDIFRead 0xc0733`, which `L6EdLibPresetV5::WriteToFile/ReadFromFile` call. This is the JSON container for preset (tone) files, with keys version, schema, meta, data, compression ("zlib", crc32, decompressed_size), encryption (type, data, decrypted_size, crc32), encoding "Base64" and encoded_data.
- The only recognised encryption type is the string `"L6"` (`FUN_000c0078`).
- Both the encrypt helper (0xc0fd3) and the decrypt helper (0xc1236) only Base64-handle the data and compute or read a CRC32, then **return −8301 (0xffffdf93)**. The writer clears the variant. The path is unimplemented in this build.
- It is not related to the BT link.

---------------------------------------------------------------------------------------------------

## 10. Keepalives, timeouts, reconnect

| Layer | Mechanism | Value |
|---|---|---|
| RSMC | Header-only frame every 200 ms tick when idle | CONFIRMED |
| RSMC | Retransmit of the oldest unacked packet | 1000 ms, unlimited. CONFIRMED |
| RSMC | No RX-silence timeout | CONFIRMED absent in RSMC code |
| Stream | Heartbeat segment (flag 0x10) after T/4 of TX silence | CONFIRMED |
| Stream | Stream failure −28 after T of RX silence | T = 4000 or 16000 ms. CONFIRMED |
| RPC | Per-request wait | 5 s (1 s for BindTweakParam, ∞ for GetSymbolTable) → −28. CONFIRMED |

- Error propagation: a stream error makes `ReceiveCrank` exit. −41 maps to callback reason 2 (port terminated); other errors map to reason 1. The upper layers then go offline.
- Native code never reconnects on its own. Java retries `openWithDeviceInMode` up to 3 times with a 6 s delay (see `notes/java_side.md` §1.7).
- Every (re)connect rebuilds the AndroidSppMsgChannel: IAP sync again, and RSMC seq numbers restart at 0. There is no RSMC-level reset message, so the amp presumably resets its RSMC state on `IAP x START`/`STOP` or on the RFCOMM reconnect (INFERRED, **verify by capture**).

---------------------------------------------------------------------------------------------------

## 11. Gaps in the decompiler output and where an HCI snoop capture is needed

- `FUN_00110240` (routing lookup) is `__regparm2`, and the decompiler dropped its arguments in the router task. The use of *dst* for the lookup is INFERRED from `MsgPort_SetRemote`.
- Several static functions (router task, stream RX/TX, IOStream vtable) were missing from the original export. They were recovered with `DecompAt.java`. The struct offsets used above come from those decompiles and should be cross-checked in a capture.
- Needs a capture:
  - What the amp sends during IAP sync (does it echo ASCII?).
  - The amp's RSMC `rx_limit` value.
  - Whether the amp's SYN carries flag 0x20 and which MSS it advertises.
  - Whether data segments carry 0x04 alone or 0x0C.
  - The actual heartbeat cadence.
  - The amp's handshake reply to the bundled CRC 0xB68B291E.
  - The last 4 bytes of the 200-byte device-info struct.

---------------------------------------------------------------------------------------------------

## 12. AVOID list (never send or call; listed only so a custom app excludes them)

- **ePortMode 1 `kUpdateMode`** and the **service-mode word `00 00 00 00` ("UPDATER") on stream 0x03EF**. Only modes 2, 3 and 4 and words 1 and 2 are needed. Also note that the byte at `L6BspMsgPort_Amplifi+0x64` makes `open 0xa1c24` switch to mode 1 instead of the requested mode (updater path).
- JNI `nativeStartFirmwareUpdate`, `nativeOpen` mode 2 (FIRMWARE_UPDATE_MODE); `AmplifiRemoteManager::OpenFirmwareUpdate 0x850b4`, `AmplifiRemoteManager::startFirmwareUpdate`.
- `L6AndroidNdkDevice::prepareForUpdating 0xa5a2c`, `startUpdate`, `forceFirmwareUpdate`, `handleUpdateEngineCallback`.
- `L6BspUpdateEngine::*` (StartUpdate 0xa7c6e, UpdateProc 0xa8316, ReadFlashImage 0xa7ec8, ...), all `L6UUE::*` (UpdateEngine, IOStreamUpdateEngine, UpdateDevice::UpdateHandshake 0xae078, ImageArchive, ...), and `Checksum_Fletcher`.
- `FirmwareServiceInterface{Editor,Librarian}::PrepareForUpdate`, `FirmwareServiceInterfaceLibrarian::ConvertToUpdater`, `ToneMatchFirmwareService::prepareServiceForUpdate`, and `MsgPort_Stream_Abort` (used only by the updater).
- Behavioural: when the device-info firmware revision is below 0x01000000, the official app forces an update. A custom app should refuse to proceed instead.
- Not firmware, but they modify stored data: Librarian ids 9, 12, 15 (move/write preset files) and Editor 18/19/22 (persistent settings). Use them deliberately.

---------------------------------------------------------------------------------------------------

## 13. Top open questions
1. Are `IAP x OK` / `IAP x START` mandatory for the amp to start its RSMC endpoint, and does the amp send anything during sync? (capture)
2. Does the amp accept the bundled symbol-table CRC (0xB68B291E for `defaultSymbolTable.bin`), or does it always force a download via cmd 2/3? (capture, or try it live; harmless read-only)
3. Is the amp's stream heartbeat timeout 4 s, which would require a client heartbeat ≤ 1 s, and what is the amp's MSS?
4. The `SetVersionNum` packing, to confirm that the 0x02100100 threshold means fw 2.10.1, and therefore whether the AMPLIFi 150 runs MTU 240/T 16 s or 256/4 s.
5. The ordering guarantee on the amp side for FIFO response matching (does it ever reorder responses or interleave events between response bytes?).
