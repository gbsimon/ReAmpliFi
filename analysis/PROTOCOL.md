# AMPLIFi 150 remote-control protocol (static reverse-engineering spec)

Derived from the official Android app "AMPLIFi Remote" 2.61.0 (`com.line6.amplifi`, versionCode 17). The Java layer was decompiled with jadx. The x86 build of `libAmplifiRemoteNdk.so` was decompiled with Ghidra. This file is self-contained: you can implement a client from it without reading `notes/`.

> **Not tested on hardware.** Everything here comes from reading code. Nothing has been checked against a real amp or a Bluetooth capture yet. Treat byte-exact claims about what the **amp** sends as hypotheses until an HCI snoop log confirms them (see §17).

> **Firmware rule.** Firmware update, flash and DFU paths appear only as names in §16 (AVOID). This spec does not describe how they work, and a client must never send them.

## 0. Conventions

### 0.1 Status legend

| Tag | Meaning |
|---|---|
| **CONFIRMED** | Read directly in decompiled code, disassembly or asset bytes. The function name and Ghidra address (or Java file:line) are given. "Confirmed" means *this is what the official app does*. It does not mean the amp was observed doing it. |
| **INFERRED** | Deduced from code structure, naming, or the assumption that the amp mirrors the phone's library. |
| **UNKNOWN** | Cannot be decided statically. A capture or experiment is needed. |

### 0.2 Scope
- **Target:** AMPLIFi 150, Line 6 product id **0x200002** (2097154). Symbol table: `assets/defaultSymbolTable.bin` (611 entries, CRC-32 0xB68B291E).
- **Other models** are mentioned only where they differ. 0x200001 AMPLIFi 75 shares the 150's code paths. Also mentioned: 0x200003 FX100, 0x200005 TT, 0x200007 AMPLIFi 30, and the AEON/Firehawk family (0x200004, 0x200006).
- **Covered:** settings and presets. **Not covered:** cloud, account, tone-sharing, firmware.

### 0.3 Glossary (defined once)
- **SPP / RFCOMM:** Classic Bluetooth (BR/EDR, *not* BLE). RFCOMM gives you a reliable byte stream, like a serial cable or a TCP socket. SPP (Serial Port Profile) is the standard service record that advertises an RFCOMM channel, UUID `00001101-0000-1000-8000-00805F9B34FB`. Web Bluetooth cannot reach it. Desktop OSes expose a paired SPP device as a serial port, and Chromium's Web Serial API can open Bluetooth RFCOMM serial ports (INFERRED, outside this analysis).
- **Little-endian (LE):** the least significant byte comes first. The u32 value `0x00000001` is sent as `01 00 00 00`. **Every multi-byte integer in this protocol is LE** (CONFIRMED: the code copies native little-endian x86/ARM structs straight to the stream).
- **MTU:** the maximum size of one link frame in bytes, header included.
- **MSS:** the maximum message size a peer accepts (MTU − 12 here).
- **ACK:** acknowledgement, "I received up to number N".
- **ARQ:** automatic repeat request. The sender retransmits until it gets an ACK.
- **Seq:** sequence number.
- **TypedValue (TV):** an 8-byte `{u32 tag, u32 bits}` value (see §10.4).
- **Ghidra address** = ELF virtual address + 0x10000. For the text segment, file offset = vaddr. For the data segment, file offset = vaddr − 0x1000.
- **Types:** `u8/u16/u32` unsigned, `i32` signed, `f32` IEEE-754 single. All LE.

---

## 1. Layer diagram

```
 [App]  Editor commands (1-22)   Librarian commands (1-15)        §11, §12
          |  typed values, symbol-table INDEXES, preset blob      §10, §14
 [L7]   RPC envelope: req {u32 cmd, u32 len, payload}             §8
                      in  {u32 type, u32 len, body}  (FIFO-matched responses, events)
 [L6]   Service-mode word (librarian port only): u32 1=LIBRARIAN, 2=DEVICE_INFO   §7
 [L5]   Stream (MsgPort_Stream, "tiny TCP"): SYN/FIN/DATA/WND/HEARTBEAT,          §6
          8-bit seq per segment, byte-count window, heartbeat timeout
 [L4]   McBsp message router: 8-byte transport header, 16-bit src/dst            §5
          addresses (node<<8|port): editor 0x2002<->0x03ED, librarian 0x2003<->0x03EF
 [L3]   RobustSerialMsgChannel (RSMC) link frames: 55 55 sync, 12-byte header,     §3, §4
          CRC-16 header+payload, 8-bit seq/ack, window 8, 1000 ms retransmit
 [L2]   IAP ASCII link sync: "IAP x OK", "IAP x START", ..., "IAP x STOP"          §2
 [L1]   Bluetooth Classic RFCOMM / SPP byte stream                                 §2
```

Native implementation of each layer (CONFIRMED):

| Layer | Native code (Ghidra addresses) |
|---|---|
| L1–L2 | `AndroidSppMsgChannel` 0xa2490..0xa38ea (Open 0xa2baa, execTasks 0xa35ac, write 0xa2ed0) |
| L3 | `RobustSerialMsgChannel_*` 0x1122f0..0x1132d0 (Init 0x1131f0, HandleRxData 0x112440, ExecTasks 0x112950), `CRC16_Process` 0x113b10 |
| L4 | `MsgRouter_HandleChannelInPacket` 0x1107f0, router task 0x110300, `MsgTransportHeader_Pack` 0x1122b0 / `_Unpack` 0x112280 |
| L5 | `MsgPort_Stream_*`: Connect 0x111d60, RX 0x1112e0, TX task 0x110880, SetHeartbeatTimeout 0x112080 |
| L6 | `L6BspMsgPort::open` 0x9ba70, `L6BspMsgPort_Amplifi::changeMode` 0xa1d5e |
| L7 | `ToneMatchEdit_Remote::DoCommandCommon` 0x103850 / `HandleInPacket` 0x106b16; `ToneMatchLibrarian_Remote::DoCommandCommon` 0x10b4ea / `HandleInPacket` 0x10c61e |
| App | `FirmwareServiceInterfaceBase::HandleHandshake` 0xd2302, `A36EditorLibrarian` 0xdf576.., `A36EditBufferContext` 0xd4b16.. |

There is **no encryption or authentication at any layer** (CONFIRMED by tracing every byte path, from `nativeSppInStreamData` to the services and back). The only integrity checks are the CRC-16s (L3). The "handshake" is a symbol-table compatibility check (§9.4). The string `"encryption"` in the binary belongs to the tone-file JSON container, not the link (see FINDINGS.md).

---

## 2. L1/L2: Bluetooth link and IAP ASCII sync

### 2.1 RFCOMM socket (CONFIRMED, Java)
- `createInsecureRfcommSocketToServiceRecord(UUID 00001101-0000-1000-8000-00805f9b34fb)`. The channel comes from an SDP lookup of the SPP UUID. The socket is "insecure", so the app requests no MITM authentication. There is no fallback to a fixed channel. (`device/AmplifiDeviceManager.java:46, 408-428`)
- The amp must already be paired in the OS. The app never scans and never calls `createBond`. A device is accepted when its upper-cased Bluetooth name contains `AMPLIFI_75`, `AMPLIFI_150`, `FX100`, `AMPLIFI_TT` or `AMPLIFI_30` (`AmplifiDeviceConnectionManager.java:20-22`, constants in `DeviceConnectionManager.java:27-36`).
- Java reads up to 64 bytes at a time and feeds them to native. Native pushes outbound byte arrays back to Java, which writes them unchanged (`AmplifiDeviceManager.java:346-387, 1072-1085`). **All framing is native.**

### 2.2 IAP sync state machine (CONFIRMED: `AndroidSppMsgChannel::Open` 0xa2baa, `execTasks` 0xa35ac, `Close` 0xa2e08)
A 200 ms periodic timer drives everything below. Each tick runs this state machine, then `RobustSerialMsgChannel_ExecTasks`, then pushes the pending output bytes to the socket.

| State | Name | Action on each 200 ms tick |
|---|---|---|
| 2 | SYNCHING_STAGE1 | Write `IAP x OK` (8 bytes, no NUL) = `49 41 50 20 78 20 4F 4B`. Counter = 5. Go to state 3. |
| 3 | SYNCHING_STAGE2 | Decrement the counter. At 0, write `IAP x START` (11 bytes) = `49 41 50 20 78 20 53 54 41 52 54`. Counter = 5. Go to state 4. |
| 4 | SYNCHING_STAGE3 | Decrement the counter. At 0, go to state 5. |
| 5 | RUNNING | RSMC frame bytes are written to the socket. |
| 6 | stopping | Entered from `Close()`, which first writes `IAP x STOP` (10 bytes) = `49 41 50 20 78 20 53 54 4F 50`. On the next tick: channel-down, then RSMC stop. |
| 7 | stopped | Timer destroyed. |

- Timeline: `IAP x OK` at about 0.2 s after open, `IAP x START` at about 1.2 s, RUNNING at about 2.2 s. `Open()` polls for RUNNING up to 10 × 500 ms. CONFIRMED.
- **The phone never parses received ASCII.** All received bytes go straight to the RSMC sync hunt (§3.4). It does not wait for a reply to the IAP strings. CONFIRMED.
- RSMC already runs during sync. In states 2–4 and 6–7, the channel write function returns success but **discards** the RSMC bytes. Early frames are lost and recovered later by retransmission. CONFIRMED.
- INFERRED: the strings are commands to the amp's Bluetooth bridge ("iAP" is a leftover from the iOS accessory protocol) that start and stop its RSMC endpoint. **UNKNOWN:** whether the amp requires them, and whether it answers.
- Client recommendation (INFERRED): reproduce the official behaviour exactly. Send `IAP x OK`, wait about 1 s, send `IAP x START`, wait about 1 s, then start RSMC. On a clean shutdown, send `IAP x STOP` after closing the streams.

---

## 3. L3: RSMC link frame

### 3.1 Frame layout (CONFIRMED: TX in `RobustSerialMsgChannel_ExecTasks` 0x112950, RX in `HandleRxData` 0x112440)

| Off | Size | Type | Field | Meaning |
|---|---|---|---|---|
| 0 | 2 | bytes | sync | Always `55 55`. |
| 2 | 1 | u8 | reserved | 0x00 on TX. Ignored on RX. |
| 3 | 1 | u8 | seq | Sequence number of this packet. It wraps at 256. Data packets start at 1. A header-only frame repeats the *last sent* seq, and the receiver ignores seq when len = 0. |
| 4 | 1 | u8 | ack | Cumulative ACK: the last peer seq delivered in order. Starts at 0. |
| 5 | 1 | u8 | rx_limit | Flow-control credit: the highest peer seq this side will accept. Starts at 8 (the RX window) and grows by 1 per packet the upper layer has finished with. |
| 6 | 2 | u16 LE | len | Payload length. 0 = header-only (ACK/keepalive) frame. Must be ≤ MTU − 12. |
| 8 | 2 | u16 LE | pcrc | CRC-16 of the `len` payload bytes. 0x0000 when len = 0 (not checked). |
| 10 | 2 | u16 LE | hcrc | CRC-16 of all **12** header bytes, computed with this field set to 0x0000. |
| 12 | len | bytes | payload | One or more McBsp messages (§5). Each is zero-padded to a multiple of 4 bytes. |

- **No byte stuffing or escaping.** `55 55` may appear inside a payload, so resynchronisation relies on the header CRC. CONFIRMED.
- The header CRC covers the sync bytes and the two zeroed hcrc bytes, so it runs over 12 bytes, not 10. CONFIRMED: TX zeroes the field before `CRC16_Process(&crc, hdr, 0xC)`, and RX zeroes it before checking.
- The payload CRC covers the zero padding as well. CONFIRMED.

### 3.2 Parameters (CONFIRMED: `AndroidSppMsgChannel::AndroidSppMsgChannel` 0xa2490 calls `RobustSerialMsgChannel_Init(rsmc, ops, mtu, txSlots, 8, rxSlots, 8, 1000)`)
| Parameter | Value |
|---|---|
| TX window | 8 packets |
| RX window | 8 packets |
| Retransmit timeout | 1000 ms |
| Tick | 200 ms (`Timer_StartPeriodic(...,0,200)`) |
| MTU (whole frame) | **240** during the device-info phase. After that **256 or 240**, depending on firmware (§15). Max payload = MTU − 12 = 228 or 244. |
| Message size | Each McBsp message must fit inside one RSMC packet. `QueueOutMessage` 0x112370 rejects bigger ones with −36. |

### 3.3 Sender state machine (CONFIRMED in ExecTasks)
State variables: `last_sent` (0), `last_acked` (0), `peer_rx_limit` (0 after `Start`), `last_delivered` (0), `my_rx_limit` (8). All differences below are **signed 8-bit**.

On every 200 ms tick:
1. **New packet.** Send one if all three hold: `(i8)(last_acked + 8 − last_sent) ≥ 1` (TX window not full), `(i8)(peer_rx_limit − last_sent) ≥ 1` (peer gave credit), and at least one message is queued. Then `seq = ++last_sent` and the packet takes as many queued messages as fit in MTU − 12.
2. **Otherwise retransmit.** If the oldest unacked packet was sent ≥ 1000 ms ago, resend it. It keeps the same seq and payload, but carries the current ack and rx_limit (so its hcrc is recomputed). Only one packet per tick. There is no retry limit and no NAK.
3. **Otherwise keepalive.** Emit a 12-byte header-only frame: `seq = last_sent, ack = last_delivered, rx_limit = my_rx_limit, len = 0, pcrc = 0`. The channel therefore sends something at least every 200 ms.

Consequences:
- At most one data frame goes out per tick, so the official app manages about 5 frames/s, roughly 1.2 KB/s (INFERRED). `AndroidSppMsgChannel_requestTask` 0xa3152 is a no-op, so queuing data does not trigger an immediate send.
- The first data packet cannot leave until the peer has advertised `rx_limit ≥ 1`, because `peer_rx_limit` starts at 0. In other words, **the phone waits for one valid header from the amp**. CONFIRMED.
- On Stop, queued and in-flight messages complete with −35.

### 3.4 Receiver (CONFIRMED in HandleRxData)
1. **Hunt** for `55 55` with a sliding 2-byte window. Collect 12 bytes. Zero bytes 10–11 and check hcrc. On a mismatch, drop **those 12 bytes**, increment the error counter, and resume hunting *after* them.
2. If `len > MTU − 12`, treat it as an error and restart the hunt.
3. **Every valid header**, including header-only frames, gets ACK processing: if `0 < (u8)(ack − last_acked) ≤ 8`, free TX slots `last_acked+1 .. ack` and set `last_acked = ack`. Then always set `peer_rx_limit = hdr[5]`.
4. When `len > 0`, accumulate the payload and check pcrc. The packet goes into slot `seq % 8`:
   - If `seq == last_delivered + 1`: deliver it to the router, then any consecutive packets already buffered.
   - If it is out of order but inside the window: buffer it.
   - If it is a duplicate or outside the window: discard it.
5. `my_rx_limit += 1` happens only when the router has finished with a delivered packet (`CompleteInPacket` 0x1122f0).

There is no RX-silence timeout at this layer (CONFIRMED absent). Liveness is detected by the stream heartbeat (§6.4).

### 3.5 Worked examples (CRCs computed with `scripts/crc16.py`)

**E4: header-only frame of a fresh channel.** CONFIRMED values.
```
55 55 | 00 | 00 | 00 | 08 | 00 00 | 00 00 | 03 6B
sync   res  seq  ack  lim  len=0   pcrc=0  hcrc=0x6B03 (LE)
```

**E6: data packet seq 1 carrying the device-info stream SYN (§6.6).** INFERRED: ack 0 and limit 8 assume no amp data has been delivered yet.
```
55 55 00 01 00 08 | 14 00 | B1 BD | CE A7 | <20 payload bytes = E5>
                   len=20  pcrc=0xBDB1 hcrc=0xA7CE
```

**Editor GetVersion inside a data segment, inside an RSMC frame.** Example dynamic values: RSMC seq 2, ack 1, limit 9; stream seq 2; window 4096.
```
55 55 00 02 01 09 18 00 A4 96 0E AF            RSMC hdr: seq 2, ack 1, lim 9, len 24
10 00 00 18 02 20 ED 03                        McBsp hdr: len 16, type 1, 0x2002 -> 0x03ED
00 02 00 04 00 10 00 00                        stream: flags DATA, seq 2, window 4096
01 00 00 00 00 00 00 00                        RPC: cmd 1 GetVersion, len 0
```

---

## 4. CRC specifications

### 4.1 CRC-16 (link frames) (CONFIRMED: decompile and disassembly of `CRC16_Process` 0x113b10)

| Property | Value |
|---|---|
| Catalogue name | **CRC-16/CCITT-FALSE** (also called CRC-16/IBM-3740) |
| Width / poly | 16 / 0x1021 |
| Init | 0xFFFF (every caller seeds it) |
| RefIn / RefOut | false / false |
| XorOut | 0x0000 |
| Check ("123456789") | **0x29B1** |
| Coverage | hcrc: the 12 header bytes with hcrc = 0. pcrc: the payload bytes, padding included. |
| Wire order | u16 **little-endian** (low byte first) |
| Implementation | Bitwise, no lookup table in the binary. The script tested 9 catalogue CRC-16 variants and only CCITT-FALSE matches. |

Byte-wise form taken from the binary, with `crc` held as a 16-bit value:
```js
function crc16(bytes, crc = 0xFFFF) {
  for (const b of bytes) {
    let x = (b ^ (crc >> 8)) & 0xFF;
    x ^= x >> 4;
    crc = ((crc << 8) ^ (x << 12) ^ (x << 5) ^ x) & 0xFFFF;
  }
  return crc;
}
```

### 4.2 CRC-32 (zlib / CRC-32/ISO-HDLC)
Reflected poly 0xEDB88320 (normal form 0x04C11DB7), init 0xFFFFFFFF, final XOR 0xFFFFFFFF, check value 0xCBF43926. This is the same result as `zlib.crc32`. Uses:

| Use | Where | On the wire? |
|---|---|---|
| **Handshake argument** = CRC-32 over the whole symbol-table *file* (all bytes). The bundled `defaultSymbolTable.bin` gives **0xB68B291E**. | `CRC32_bs` 0xd177c (table @0x1cd3a0 dumped, identical to the standard table); `ToneMatchEdit_Remote::Handshake` 0x103bac, `ToneMatchLibrarian_Remote::Handshake` 0x10b884 | Yes, the only place. CONFIRMED |
| Per-entry name hash inside the symbol table (lookup accelerator) | `SymbolTable::LookupString` 0xd2b70 | No. The wire carries the **index** (§9). CONFIRMED |
| `"crc32"` field of compressed tone-file containers | `L6CRC32::calc` 0xbf9fc, called only by the DIF tone-file helpers | No. CONFIRMED |

---

## 5. L4: McBsp message layer (inside the RSMC payload)

### 5.1 Transport header, 8 bytes (CONFIRMED: `MsgTransportHeader_Pack` 0x1122b0, `MsgPort_PrepareTransportHeader` 0x1101e0)

| Off | Size | Field | Meaning |
|---|---|---|---|
| 0 | 2 | u16 LE length | Bytes following this 8-byte header (option word + stream header + data). |
| 2 | 1 | 0x00 | Bits 16–23 of word0, always 0. |
| 3 | 1 | type/version | Bits 24–31 of word0: `type << 4 \| version << 2`, with version always 2. **0x18** = type 1 (plain). **0x28** = type 2 (an option word follows; used by stream SYN). |
| 4 | 2 | u16 LE src | Source address. |
| 6 | 2 | u16 LE dst | Destination address. |

The packed word form is `word0 = type<<28 | 2<<26 | len16` and `word1 = src | dst<<16`.

- **Packing several messages in one RSMC payload** (router task 0x110300): each message occupies `(len + 8 + 3) & ~3` bytes. Parsing continues while ≥ 8 bytes remain. CONFIRMED.
- When the phone receives a type-2 message, it rewrites the option word: it clamps the MSS (bits 16–31) to its own MSS, increments the hop count (bits 0–7) and clears bits 8–15. A client only needs to *read* the peer's MSS from it. CONFIRMED.

### 5.2 Addresses and routing (CONFIRMED)
- Address = `node << 8 | port`. The phone's node is **0x20** (`McBspMessaging_Init(0x2000)` in `AmplifiRemoteManager::Initialize`). The amp's node is **0x03**.
- Routing table (match `(dst & ~mask) == addr`, smallest mask wins): 0x2000/0x00FF → local ports. 0x0300/0x00FF → SPP channel. 0x0000/0x0FFF → SPP channel.

| Port | Phone (local) | Amp (remote) | After the stream connects |
|---|---|---|---|
| Editor (ePortMode 2) | **0x2002** | **0x03ED** | RPC starts directly. |
| Librarian (ePortMode 3) | **0x2003** | **0x03EF** | Service-mode word 1 (§7). |
| Device info (ePortMode 4) | 0x2003 | 0x03EF | Service-mode word 2, then the 200-byte record (§7.2). |
| Updater (ePortMode 1) | AVOID | AVOID | AVOID (§16) |

`L6BspMsgPort::open` 0x9ba70 does `Bind(local | 0x2000)` then `Connect(remote)`. Mode translation: `L6BspMsgPort_Amplifi::TranslateePortMode` 0xa1d2a.

---

## 6. L5: Stream protocol (MsgPort_Stream)

A small TCP-like protocol over McBsp messages. Each port pair is an independent stream with its own sequence counter.

### 6.1 Segment layout (CONFIRMED: TX task 0x110880, RX handler 0x1112e0)

| Off (after McBsp hdr) | Size | Field | Meaning |
|---|---|---|---|
| 0 | 4 | option (type-2 / SYN only) | bits 16–31 = MSS (the sender's MTU − 12), bits 0–7 = hop count (0 at the origin) |
| +0 | 4 | word A | bits 24–31 = **flags**, bits 8–15 = **seq** (u8), all other bits 0. On the wire: `00 <seq> 00 <flags>`. |
| +4 | 4 | word B | **Window edge**, a u32 cumulative byte count: "the peer may send up to this many bytes in total". Initial value = free RX buffer = 4096. It grows by every byte the application has consumed. |
| +8 | n | data | 0..N bytes of the stream byte pipe. |

| Flag | Name | Meaning |
|---|---|---|
| 0x01 | SYN | Connect. The listener also answers with SYN. |
| 0x02 | FIN | Close. |
| 0x04 | DATA | The segment carries data. |
| 0x08 | WND | Window update (the app consumed bytes). |
| 0x10 | HB | Heartbeat, sent after the TX side has been idle for the interval. |
| 0x20 | HB-enable | SYN only. It asks the listening peer to use a 4000 ms timeout and a 1000 ms interval. |

- Data segments carry `DATA | <pending flags>`. The TX task ORs DATA (0x04) onto any pending bits, so a WND (0x08) can ride along and make 0x0C. CONFIRMED in 0x110880. Which combination the amp sends is UNKNOWN.
- **Max data per segment** = `peerMSS − 16`, or `peerMSS − 20` on a SYN carrying data. It is also limited by `peer_window_edge − bytes_sent`. With MTU 240: 212 bytes. CONFIRMED.
- Writes go through a 4 KB TX ring. Auto-flush is always on, so data leaves on the next 200 ms port tick. CONFIRMED.

### 6.2 Sequence rule (CONFIRMED)
- `seq` = 1 on the SYN. It increments by 1 on **every** segment: data, window updates, heartbeats and FIN.
- The receiver requires exactly `last + 1` on every non-SYN segment. **Any other value aborts the stream with −4.** No reordering is needed, because RSMC already delivers in order. A client must therefore never skip or repeat a stream seq. It must also never resend a stream segment itself; retransmission happens only at RSMC.

### 6.3 Stream state machine (CONFIRMED; state stored at +0x1b8)
```
 0 idle ──Connect: send SYN (flags 0x21, seq 1, window 4096, option MSS<<16)──▶ 2 SYN-sent
 2 ──receive SYN from peer: record peer MSS/seq/window──▶ 3 ESTABLISHED   (2-way, no 3rd ACK)
 3 ──receive FIN──▶ 7 peer-closed          3 ──local Close: flush, send FIN──▶ 0xB
 0xB ──receive FIN──▶ 0 (closed)
 negative = error: −4 protocol/seq, −28 heartbeat timeout, −37 remote node down, −12 aborted, −41 EOF
```
Phone side: `SetAutoFlush(1)`, `SetHeartbeatTimeout(T)`, `Bind`, `Connect`. After the SYN exchange, `SetHeartbeatTimeout(T)` is applied again, so the phone always keeps its own values.

### 6.4 Heartbeat and timeouts (CONFIRMED: `MsgPort_Stream_SetHeartbeatTimeout` 0x112080, checked in the disassembly)
- `SetHeartbeatTimeout(port, T)` sets the RX-silence timeout to **T** and the TX-idle heartbeat interval to **T >> 2**. The logged "heartbeatInterval" argument is ignored.
- T = **4000 ms** in the device-info phase and on older firmware. T = **16000 ms** on newer firmware (§15).
- The RX timer reloads on every received segment and counts down with the 200 ms ticks. On expiry the stream fails with −28.
- **Client rule (INFERRED, important).** The phone's SYN sets HB-enable (0x20). If the amp runs the same library, that hard-codes the **amp's** timeout to 4000 ms. So send *some* segment, a heartbeat (flag 0x10, no data) if nothing else, at least **every 1 s** on each open stream.

### 6.5 Window rule (CONFIRMED mechanism)
- Your word B tells the amp how many bytes in total it may send you. Start at 4096. After consuming N bytes, raise it by N and send a WND segment (0x08), as the phone does on the next tick after a read.
- If you never advance it, the amp stops after 4096 bytes. That would stall a symbol-table download (~16 KB) or a preset blob (≤ 32 KB).
- Never send beyond the peer's word B.

### 6.6 Worked examples (CONFIRMED structure; built with `crc16.py`)

**E5: device-info stream SYN, 0x2003 → 0x03EF, MTU 240.**
```
0C 00 | 00 | 28 | 03 20 | EF 03    McBsp: len 12, type 2 (option), src 0x2003, dst 0x03EF
00 00 E4 00                        option: MSS 0x00E4 = 228, hop 0
00 01 00 21                        word A: seq 1, flags 0x21 (SYN | HB-enable)
00 10 00 00                        word B: window 4096
```

**E7: editor SYN.** Identical except for the addresses: `0C 00 00 28 02 20 ED 03 00 00 E4 00 00 01 00 21 00 10 00 00`. With MTU 256 the option word becomes `00 00 F4 00` (MSS 244). The MTU choice for a given amp is INFERRED (§15).

**Librarian service-mode word as the first data segment (seq 2):**
```
0C 00 00 18 03 20 EF 03 | 00 02 00 04 | 00 10 00 00 | 01 00 00 00
```

**Heartbeat (seq 3):** `08 00 00 18 02 20 ED 03 00 03 00 10 00 10 00 00`

---

## 7. L6: Service-mode word and the device-info record

### 7.1 Service-mode word (CONFIRMED: `L6BspMsgPort_Amplifi::changeMode` 0xa1d5e)
This applies only on the 0x2003 ↔ 0x03EF stream, right after it reaches ESTABLISHED. The phone writes a u32 as stream data, then reads 4 bytes back, which **must echo the same value**. Otherwise the open fails with −2006 or −2008.

| Word | Bytes | Meaning |
|---|---|---|
| 1 | `01 00 00 00` | LIBRARIAN service |
| 2 | `02 00 00 00` | DEVICE_INFO |
| 0 | — | **AVOID** (updater). Never send. |

The editor stream (0x2002 ↔ 0x03ED) has **no** mode word. Editor RPC starts right after the SYN exchange.

### 7.2 Device-info record (CONFIRMED: `L6AndroidNdkDevice::prepareForDeviceInfo` 0xa5cd0; field roles from the `L6Device` getters at +0x20/+0x38/+0x40/+0x50)
After mode word 2 and its echo, the phone reads exactly **200 bytes** of stream data:

| Off | Size | Type | Field |
|---|---|---|---|
| 0x00 | 64 | char[] NUL-padded | productName (`getProductName`). It is used to map the product id; AMPLIFi 150 → 0x200002. |
| 0x40 | 64 | char[] | model (`getModel`) |
| 0x80 | 64 | char[] | serialNumber (`getSerialNumber`) |
| 0xC0 | 4 | u32 LE | firmwareRevision, "raw" packing: `major<<24 \| minor<<16 \| patch<<8 \| suffixChar` (minor is binary) |
| 0xC4 | 4 | ? | UNKNOWN |

The phone formats the raw value with `"%d.%02d.%d%c"` (e.g. "2.10.1"), then re-packs it into the **corrected version** that every native firmware gate uses (§15.1).

---

## 8. L7: RPC envelope

### 8.1 Requests, phone → amp (CONFIRMED: `DoCommandCommon` 0x103850 / 0x10b4ea)
```
u32 cmd_id | u32 payload_len | payload (payload_len bytes)
```
The 8-byte header and the payload are separate `write()` calls on the stream byte pipe. Message boundaries are not tied to segment boundaries. For librarian SetPresetFile, `payload_len` = 8 + blob length (the 8-byte arguments, then the blob).

### 8.2 Inbound messages, amp → phone (CONFIRMED: `HandleInPacket` 0x106b16 editor, 0x10c61e librarian)
```
u32 type | u32 len | body (len bytes)
```
| type | Editor stream | Librarian stream |
|---|---|---|
| 0 | ignored, no body read (INFERRED: always len 0) | same |
| 1 | response | response |
| 2–8 | events (§13); body ≤ 16 bytes, otherwise −19 and the receive loop dies | **−4, the receive loop ends** |
| other | −4, loop ends | −4, loop ends |

### 8.3 Response matching (CONFIRMED: `HandleResponse` 0x1064d8 / 0x10c352)
- **No transaction id.** A response is matched to the **oldest outstanding request** on that stream (FIFO). Up to 512 requests may be outstanding.
- Each request declares a response *capacity*. If the response `len` is greater than the capacity, the result is **−19**, and the body is not consumed, which desynchronises the stream. A shorter body is accepted. CONFIRMED on both services.
- **Editor responses** are raw bytes in the layout the caller expects. Most begin with an `i32 status`, but GetVersion, GetSymbolTableSize, GetNumAddressableSlots, GetDirtyState and GetFbvConnectivityStatus return a bare u32 (tables in §11).
- **Librarian responses**: when the call supplies a status pointer, the body is `i32 status` followed by the data, and `len` includes the status. **Cmds 1, 2, 3 and 5 pass no status pointer, so their body is the data alone** (§12, reconciliation note).
- Status < 0 means failure. The amp's error values are not enumerated (UNKNOWN).
- Wait timeout: **5000 ms** (BindTweakParam 1000 ms; GetSymbolTable none). On timeout: −28.
- "Async" variants (e.g. `SetDspModelParamAsync` 0x104168) still queue a token. The amp still answers, and the client drains and discards the reply (`FUN_001063d1`). CONFIRMED on the client side.

---

## 9. Connection sequence (numbered timeline)

CONFIRMED per function. The order across the vtables is INFERRED from `AmplifiRemoteManager::OpenOnLine` 0x84b7e and `L6AndroidNdkDevice::initialize` 0xa4ca2.

**Phase A: device info (MTU 240, T = 4000)**
1. Open RFCOMM (§2.1). Create the channel with MTU 240. Run the IAP sync (§2.2: OK, about 1 s, START, about 1 s, RUNNING). Start RSMC from seq 0.
2. Stream SYN 0x2003 → 0x03EF (example E5/E6). Wait for the amp's SYN.
3. Send mode word `02 00 00 00` and read the 4-byte echo.
4. Read the 200-byte device-info record (§7.2) and compute the corrected version (§15.1).
5. **If the raw firmwareRevision is < 0x01000000 (FX100: < 0x01000400), the official app forces a firmware update. AVOID. A custom client must refuse such an amp and stop.**
6. Close the stream (FIN, wait for the peer FIN). Send `IAP x STOP`. Stop RSMC and destroy the channel. (`prepareForDeviceInfo` 0xa5cd0)

**Phase B: link restart with final parameters**
7. `setupMessageChannelParameters` 0xa4b14 picks the MTU and heartbeat T from the corrected version (§15.2): **256 / 4000 ms** below 2.10.1, otherwise **240 / 16000 ms**.
8. The official app sleeps **1000 ms** (`Thread_Sleep(1000)` in OpenOnLine). It then builds a **new** channel: IAP sync again, and **RSMC seq restarts at 0**. There is no RSMC reset message, so the amp presumably resets on IAP START/STOP or on the restart (INFERRED). The app sleeps another **1000 ms** before opening the ports.
9. Editor stream SYN 0x2002 → 0x03ED (E7). No mode word.
10. Librarian stream SYN 0x2003 → 0x03EF, then mode word `01 00 00 00` with echo.

**Phase C: editor service handshake** (`FirmwareServiceInterfaceBase::HandleHandshake` 0xd2302)
11. Editor **cmd 1 GetVersion** → u32 service version (no status).
12. **Choice 1:** cmd 4 Handshake with the CRC-32 of the *cached* table (the copy from the last successful session).
13. **Choice 2**, if the reply is < 0: cmd 4 with the CRC-32 of the bundled table. For 0x200002 that is `defaultSymbolTable.bin`, **0xB68B291E** (`A36EditorLibrarian::connect` 0xe0a9e): `04 00 00 00 04 00 00 00 1E 29 8B B6`.
14. **Choice 3**, if that fails too: **cmd 2 GetSymbolTableSize**, then **cmd 3 GetSymbolTable** (raw table file, no timeout). Then cmd 4 with the downloaded table's CRC-32.
15. On success (status ≥ 0) the table is cached (`ToneMatchFirmwareService::completeHandshake` 0x10b236). **From now on every slot, param and model id is an index into *this* table.**

**Phase D: librarian service handshake** (`A36EditorLibrarian::handleNotification` 0xdf576, after the editor is done)
16. Librarian **cmd 1 GetVersion** → u32 (no status).
17. Librarian **cmd 5 GetNumPresets** → u32 count (no status). This comes *before* the handshake.
18. Librarian **cmd 4 Handshake** with the same CRC-32 → i32 status. (The librarian never downloads the table: its FetchSymbolTable returns −1.)
19. Background preset-cache fill. Librarian V2 (the 150 on fw ≥ 1.00.9) sends cmd 14 GetPresetInfo per slot. V1 uses cmds 8, 6, 7, 10, 11 (§15.3).

**Phase E: state sync** (`A36EditBufferContext::bindServices` 0xd4b16 → `syncWithDeviceAsMaster(true)` 0xda514)
20. Editor **cmd 15 GetDirtyState** → u32.
21. Librarian **cmd 11 GetPresetFile(0xFFFFFFFF)** → `{i32 status, blob}` = the current edit buffer. Parse it with §14.3. **This is how the app learns the current tone.** It does **not** learn the current preset *index*; no query for it exists (UNKNOWN until a patch event arrives).
22. `registerForEvents` 0x10957c registers local callbacks only. **Nothing is sent** (§13).
23. Editor **cmd 9 GetDspModelParam(Tuner, Enable)**. If the tuner is on, register tuner events (§14.6).
24. The app reads `FBVConnected` with cmd 16. Preset names come from the cache or cmd 6.

**During the session:** keep each stream alive (§6.4, at least one segment every 1 s), keep RSMC header-only frames flowing every 200 ms, and advance the stream windows (§6.5). The official Java layer coalesces edits per (group, param) and keeps **≥ 100 ms** between commands (`device/utils/CommandRestrictingHandler.java:8,23-30`), so at most about 10 edits per second.

**Close:** FIN on each stream, wait for the peer FIN, `IAP x STOP`, close the socket. Native never reconnects by itself. Java retries a failed synchronous open up to 3 more times, 6 s apart (`EdlibScenarioManager.java:21-22, 450-458`). Every reconnect redoes the whole sequence from step 1.

**Read-only minimal session** (INFERRED safe): steps 1–24 send no write except the cmd 4 handshakes, which only compare CRCs. Step 23 is a read. Nothing in phases A–E changes sound or storage.

---

## 10. Symbol table, addressing and values

### 10.1 File format (CONFIRMED: `SymbolTable::InitFromTableData` 0xd2a42; verified on all 6 bundled tables by `scripts/parse_symtab.py`)

| Off | Size | Field |
|---|---|---|
| 0 | 4 | u32 count (611 for `defaultSymbolTable.bin`) |
| 4 | 4 | u32 total file size (15764) |
| 8 | 12 × count | entries `{u32 strOffset (relative to the string blob), u32 crc32(name), u32 strLen}` |
| 8 + 12·count | … | string blob: NUL-terminated ASCII names (blob starts at 0x1CAC) |

The cmd 3 download response has the same format. The entries are not sorted.

### 10.2 The index rule (CONFIRMED: `SymbolTable::LookupString` 0xd2b70)
**On the wire, every slot, param, model and symbol value is the 0-based ENTRY INDEX of a name in the table the amp accepted at handshake.** LookupString uses the CRC-32 only to find the entry, then returns its loop index (first match wins). An unknown name gives −21 locally. The empty name `""` as a *slot* means **0xFFFFFFFF = root slot**.

Indexes in `defaultSymbolTable.bin` (valid only if the amp accepted CRC 0xB68B291E):

| Name | Idx | Name | Idx | Name | Idx |
|---|---|---|---|---|---|
| Gate | 318 | FX4 (reverb) | 533 | GuitarProc | 596 |
| VolumePedal | 499 | Amp | 535 | ToneMatchGuitarFlow | 523 |
| Wah | 526 | Air | 536 | Tuner | 587 |
| FX1 | 527 | LiveCab | 537 | Enable | 593 |
| FX2 | 529 | StudioCab | 538 | Note | 594 |
| FX3 | 531 | PostComp | 539 | Master | 608 |
| ChannelVolume | 540 | PostEQ | 541 | GuitOutputGain | 610 |
| SyncSelect | 146 | TNGAIRReflections | 8 | LevelState | 9 |

**Client rule:** never hard-code indexes. Resolve names against the table that won the handshake. Downloading the table from the amp (cmds 2 and 3) is read-only. It also avoids shipping Line 6's asset file (INFERRED to work: it is the official app's own fallback).

### 10.3 Editor ids → DSP (slot, param) (CONFIRMED: `GetDSPSlotForGroupAndParam` 0xeafcf; AMPLIFi tables @0x23e540 and @0x23e820)
The app's high-level API uses `(groupID, paramID)`, for example `("amp", "Drive")` or `("fx1", "@enabled")`. The native layer maps these to DSP symbol names.

**Rule 1: `@`-params** go to slot **GuitarProc**, with the param name from this table:

| group | `@enabled` | `@post` | `@mix` | `@mixtype` | other |
|---|---|---|---|---|---|
| cab | CabEnable | – | – | – | `@mic`: special (§10.5) |
| gate | GateEnable | – | – | – | |
| compressor | PostCompEnable | – | – | – | |
| eq | PostEQEnable | – | – | – | |
| wah | WahEnable | – | – | – | |
| volume | VolumePedalEnable | VolumePost | – | – | |
| fx1 / fx2 / fx3 | FX*n*Enable | FX*n*Post | FX*n*Mix | FX*n*MixType | |
| reverb | FX4Enable | FX4Post | FX4Mix | **none: −4** (even though reverb models list `@mixtype`) | |
| amp | – | – | – | – | `@volume` → **ChannelVolume** |

`@stereo` exists only on AEON. On the 150 it does not resolve (−4).

**Rule 2: plain params** (`Drive`, `Bass`, `Time`, …): the slot comes from the group and the param name passes through unchanged.

| group | gate | volume | wah | fx1 | fx2 | fx3 | **reverb** | amp | cab | compressor | eq |
|---|---|---|---|---|---|---|---|---|---|---|---|
| slot | Gate | VolumePedal | Wah | FX1 | FX2 | FX3 | **FX4** | Amp | StudioCab | PostComp | PostEQ |

Exception: `cab`/`Level` → slot **Air**, param **Level**.

### 10.4 TypedValue and value typing (CONFIRMED: `FUN_000ec4c5`, type names in `handleParamEvent` 0x109c86, `CheckParamValueForModel` 0xc2e10)
`TypedValue = { u32 tag LE, u32 bits LE }` (8 bytes)

| Tag | Type | bits |
|---|---|---|
| 0 | void | 0 |
| 1 | symbol | u32 symbol-table index |
| 2 | int | i32 |
| 3 | bool | 0 / 1 |
| 4 | float | IEEE-754 f32 bits |
| 5 | varray | (not used by the 150 paths) |

Before sending, the value is coerced to the current model's param `valueType` (taken from the `*.models` JSON of the model loaded in that group, or `@global_params` for `global`):

| valueType | Coercion | Sent as |
|---|---|---|
| 1 float | int → float; **clamped to [min, max]**; a non-number gives the default | tag 4 |
| 0 int | float rounded half away from zero; bool → 0/1 | tag 2 |
| 2 bool | int → bool | tag 3 |
| 3 string | never sent as a TV (`@model` goes via the blob, tweak via bind) | – |

Ranges: 875 of 882 float params are 0..1. Exceptions: `@tempo` 30..240 BPM, Gate `Thresh` −96..0 dB, FXLoop Send/Return −59.5..12 dB. Ints: `SyncSelect` 1..14, `@mixtype` 0..2, `@mic` 0..3. All `@enabled` and `@post` are bool, and `@mix` is a 0..1 float. (Asset JSON, CONFIRMED.)

**Example: `("amp", "Drive", 0.5)` with model BritGainJ800** (CONFIRMED layout; indexes INFERRED-valid):
```
0A 00 00 00 | 10 00 00 00 | 17 02 00 00 | 17 00 00 00 | 04 00 00 00 | 00 00 00 3F
cmd 10        len 16        slot Amp=535  param Drive=23 tag float    0.5f
```

### 10.5 Special cases in `sendParamToDevice` 0xdaa7a (CONFIRMED)
| Editor id | Wire |
|---|---|
| `fxN/@temposync` | The param is renamed **SyncSelect** on slot FX*n*. false → `TV int 0`. true → the stored SyncSelect value (int 1..14). Example (fx2 false): `0A000000 10000000 11020000 92000000 02000000 00000000` |
| `fxN/SyncSelect` | Normal param, TV int. Example value 4: `… 92000000 02000000 04000000` |
| `cab/@mic` (0..3) | `CabModelAndMicToStudioCabSymbol` appends `57OnAxis` / `57OffAxis` / `421` / `U67` (table @0x23eb04) to the cab name, e.g. `4x12BritT75Studio421`. Sent as **editor cmd 8 LoadDspModel {slotIdx(StudioCab), modelIdx(name+suffix)}**: `08000000 08000000 1A020000 D7010000`. Cab models appear in the table **only** with a mic suffix (all 25 × 4). `@NoCabinet` maps to `2x12Line6Studio57OnAxis`. |
| `global/@tempo` | **cmd 14 SetGlobalTempo {f32 BPM}**: `0E000000 04000000 0000F042` (120.0) |
| `global/@tweakmin`, `@tweakmax`, `@pedal2assign` | `ParamIDToPSKey` 0xeb1c9 (table @0x23e9e0) → **cmd 19 SetPresetPSKeyParam {u32 key, TV}**. Keys: 3 tempo (blob only), **7 tweakmin**, **8 tweakmax**, **9 pedal2assign**. Only sent when fw ≥ 2.11.3 (§15). Example tweakmin 0.2: `13000000 0C000000 07000000 04000000 CDCC4C3E` |
| `global/@tweakgroup` + `@tweakparam` | `bindTweakOnDeviceForGroup` 0xdbd1c → **cmd 13 BindTweakParam {slotIdx, paramIdx}** of the target's DSP address (1000 ms timeout). Example amp/Drive: `0D000000 08000000 17020000 17000000` |
| `*/@model` | **Not an editor command.** A partial preset blob is written to the edit buffer (§14.4). |
| `variax` group, Variax PS keys 25..33 | Not relevant to the 150. |

### 10.6 Device (global) settings (CONFIRMED: `A36EditorLibrarian::setDeviceSetting` 0xe15ac / `getDeviceSetting` 0xe192c)
Aliases: `MasterVolume` → `Master`, `GuitarVolume` → `GuitOutputGain`.

| Setting | Write | Read | Notes |
|---|---|---|---|
| **Master** | cmd 10 `{0xFFFFFFFF, idx(Master)=608, TV float}` | cmd 9 `{0xFFFFFFFF, 608}` → `{i32 st, TV}` | Range 0..1 INFERRED (Java slider). Ex. 0.5: `0A000000 10000000 FFFFFFFF 60020000 04000000 0000003F` |
| **GuitOutputGain** | cmd 10 `{0xFFFFFFFF, 610, TV float}` | cmd 9 `{0xFFFFFFFF, 610}` | Ex. 0.8: `… FFFFFFFF 62020000 04000000 CDCC4C3F` |
| **TapTempoLED** | cmd 18 SetPersistentSysParam `{u32 key 7, TV bool}` | cmd 17 `{7}` → `{i32 st, TV}` | Refused locally below fw 2.00.6 (§15). Ex. on: `12000000 0C000000 07000000 03000000 01000000` |
| FBVConnected | read-only (setting it gives −4) | cmd 16 → u32 | foot controller attached |
| Global EQ / Crossover / Divergence / StereoWidth / Variax | cmd 18 keys 8, 9, 14–29 (`ParamIDToSysParamKey` @0x23e480: VariaxSettings 8, VariaxTuningMode 9, GlobalLowCut 14, GlobalLowFreq 15, GlobalLowQ 16, GlobalLowGain 17, GlobalMidFreq 18, GlobalMidQ 19, GlobalMidGain 20, GlobalHighFreq 21, GlobalHighQ 22, GlobalHighGain 23, GlobalHighCut 24, GuitarOnlyGlobalEQ 25, BypassGlobalEQ 26, Divergence 27, StereoWidth 28, Crossover 29 (TV symbol)) | cmd 17 | Present natively but **not used by this app flavour**. Whether the 150 implements them is UNKNOWN. Keys 14–24 are sent async. |

Unknown names fall through to the root-slot cmd 10 path.

---

## 11. Editor commands (stream 0x2002 ↔ 0x03ED)

CONFIRMED: ids, request layouts and response capacities from the `DoCommandCommon` call sites at 0x1039d2..0x105b98. All fields are u32 LE unless noted. *Resp* is the response body after `{type 1, len}`.

| id | Name | Request payload | Response body | Used by the app for | Write risk |
|---|---|---|---|---|---|
| 1 | GetVersion | – | u32 version | handshake | read-only |
| 2 | GetSymbolTableSize | – | u32 size | handshake choice 3 | read-only |
| 3 | GetSymbolTable | – | raw table (§10.1), no timeout | handshake choice 3 | read-only |
| 4 | Handshake | u32 crc32(table) | i32 status (≥ 0 ok) | handshake | read-only (compatibility check) |
| 5 | GetNumAddressableSlots | – | u32 | unused | read-only |
| 6 | GetAddressableSlots | – | u32[n] | unused | read-only |
| 7 | QueryCurrentDspModel | u32 slot | i32 st, u32 model | unused | read-only |
| 8 | LoadDspModel | u32 slot, u32 model | i32 st | cab mic change only | changes live sound only |
| 9 | GetDspModelParam | u32 slot, u32 param | i32 st, TV | settings read, tuner state | read-only |
| 10 | SetDspModelParam (+Async) | u32 slot, u32 param, TV (16 B) | i32 st | param edits, Master, GuitOutputGain, tuner | changes live sound only (edit buffer; whether Master/GuitOutputGain persist is UNKNOWN) |
| 11 | RegisterDspEvent | u32 slot, u32 param | i32 st | tuner Note events | read-only (subscription) |
| 12 | UnregisterDspEvent | u32 slot, u32 param | i32 st | tuner | read-only |
| 13 | BindTweakParam | u32 slot, u32 param | i32 st (1 s timeout) | tweak knob target | changes live sound only (edit buffer) |
| 14 | SetGlobalTempo | f32 BPM | i32 st | `@tempo` | changes live sound only |
| 15 | GetDirtyState | – | u32 | sync on connect | read-only |
| 16 | GetFbvConnectivityStatus | – | u32 | FBVConnected | read-only |
| 17 | GetPersistentSysParam | u32 key | i32 st, TV | settings read | read-only |
| 18 | SetPersistentSysParam (+Async) | u32 key, TV (12 B) | i32 st | TapTempoLED (key 7) | **WRITES STORAGE** (persistent system setting) |
| 19 | SetPresetPSKeyParam (+Async) | u32 key, TV | i32 st | tweakmin/max, pedal2assign (fw ≥ 2.11.3) | edit-buffer preset key. Persistence UNKNOWN: **treat as WRITES STORAGE** until verified |
| 20 | GetPresetPSKeyParam | u32 key | i32 st, TV | – | read-only |
| 21 | GetSystemSetting | u32 key | i32 st, TV | AEON only | read-only; not for the 150 |
| 22 | SetSystemSetting | u32 key, TV | i32 st | AEON only | **WRITES STORAGE**; do not send to a 150 |

Example response OK: `01000000 04000000 00000000` (type 1, len 4, status 0).

Register/Unregister for Patch, Param, TapTempo, FbvStatus, PSKey and SysSetting events are **local only and send nothing**. None of these ids is a firmware command.

---

## 12. Librarian commands (stream 0x2003 ↔ 0x03EF, after mode word 1)

CONFIRMED: call sites at 0x10b670..0x10c0d4. "St" = an `i32 status` that starts the body.

| id | Name | Request payload | Response body | Used by the app for | Write risk |
|---|---|---|---|---|---|
| 1 | GetVersion | – | **u32 (no status)** | handshake | read-only |
| 2 | GetSymbolTableSize | – | **u32 (no status)** | unused | read-only |
| 3 | GetSymbolTable | – | **table (no status)** | unused | read-only |
| 4 | Handshake | u32 crc32 | i32 st | handshake | read-only |
| 5 | GetNumPresets | – | **u32 count (no status)** | slot count | read-only |
| 6 | GetPresetName | u32 idx | st, u32 nameLen, char[nameLen ≤ 64] (capacity 0x44 after st) | names | read-only |
| 7 | GetPresetUUID | u32 idx | st, u64 uuid | cache (V1) | read-only |
| 8 | GetPresetChecksum | u32 idx | st, u32 | cache (V1) | read-only |
| 9 | MovePresetFiles | **u32 dst, u32 src** (both < count) | st | reorder slots | **WRITES STORAGE** |
| 10 | GetPresetFileSize | u32 idx | st, u32 | cache (V1) | read-only |
| 11 | GetPresetFile | u32 idx, or 0xFFFFFFFF = edit buffer | st, blob (≤ 0x8000) | select, sync | read-only |
| 12 | SetPresetFile | u32 idx / 0xFFFFFFFF, u32 L, blob (header len = 8 + L) | st | select, save, tone load, model change, FX reorder | idx = 0xFFFFFFFF: **changes live sound only**. idx ≥ 0: **WRITES STORAGE** |
| 13 | LoadHardwarePreset | u32 idx | st | **unused by the app** (INFERRED: recall slot) | changes live sound only (INFERRED) |
| 14 | GetPresetInfo | u32 idx | st, u64 uuid, u32 checksum, u32 size, u32 nameLen, char[64] (capacity 0x54 after st) | cache (V2) | read-only |
| 15 | SetPresetFile, AEON flag | as 12 | st | AEON only | **WRITES STORAGE**; do not send to a 150 |

**Reconciliation note.** `notes/native_transport.md` §6.3–6.4 says every librarian response starts with an i32 status. `notes/native_messages.md` §1 corrects this for cmds 1, 2, 3 and 5, and **native_messages wins**. Re-checked for this spec:
- `GetVersion` 0x10b670, `GetSymbolTableSize` 0x10b720, `GetSymbolTable` 0x10b7d0 and `GetNumPresets` 0x10b95e call `DoCommandCommon(…, statusPtr = 0, out, cap 4 or N, …)`.
- `HandleResponse` 0x10c352 adds 4 to the capacity only when a status pointer exists, and returns −19 when `len` exceeds the capacity.
- So a status+count reply to cmd 5 would be *rejected* by the official app.
- That the amp actually replies `01000000 04000000 <u32 count>` is a strong INFERENCE, since the official app works.

The transport note's sizes for the other commands agree.

**Move (cmd 9).** The call chain is `A36EditorLibrarian::moveResource` 0xe5e46 → `ToneMatchLibrarianService::moveToneMatchPresetFrom(src, dst)` 0x10d6f0 → `FirmwareServiceInterfaceLibrarian::MoveToneMatchPreset(dst, src)` 0xef25a. The last one logs "src %d, dest %d", checks both indexes against the count, then sends `{dst, src}` (`MovePresetFiles` 0x10bcb4). CONFIRMED. Example src 1 → dst 4: `09000000 08000000 04000000 01000000`. Whether the amp inserts, swaps or overwrites is INFERRED as insert/move (the client-side cache does `MoveEntry`).

---

## 13. Inbound editor events (amp → phone, unsolicited)

CONFIRMED: `HandleInPacket` 0x106b16 and handlers. The amp pushes these without any registration (registration is local), except the DSP event, which needs cmd 11. Body ≤ 16 bytes.

| type | Body | Meaning / official handling | Example (hex, full message) |
|---|---|---|---|
| 2 DSP event | u32 slot, u32 param, TV | Only the tuner uses it: (Tuner 587, Note 594, TV float) (§14.6) | `02000000 10000000 4B020000 52020000 04000000 66660640` (v = 2.1) |
| 3 patch | TV int presetIndex, TV int isSave | isSave 0: the amp changed preset → app treats the slot as current and **re-reads the edit buffer** (cmd 11, 0xFFFFFFFF). isSave 1: slot saved on the amp → invalidate the name cache. (`consumePatchEvent` 0xd433c) | `03000000 10000000 02000000 05000000 02000000 00000000` (select 5) |
| 4 param | u32 slot, u32 param, TV (int/bool/float) | A knob was turned on the amp. The ids are mapped back to (group, param) by `GetGroupForDSPSlotAndParam` 0xeb121, which reverses the tables in §10.3. Root slot 0xFFFFFFFF: only Master and GuitOutputGain are handled. (Tuner, Enable): the tuner was toggled on the amp. A float `@enabled` counts as on when > 0.1. (`handleParamEvent` 0x109c86) | `04000000 10000000 17020000 17000000 04000000 3333333F` (amp Drive 0.7) |
| 5 tap tempo | TV **float** BPM | Sets `global/@tempo`. | `05000000 08000000 04000000 0000F042` (120) |
| 6 FBV status | TV float (> 0 = connected) | Foot controller plugged or unplugged. | `06000000 08000000 04000000 0000803F` |
| 7 PS-key change | u32 key, TV | tweakmin/max/pedal2assign changed (fw ≥ 2.11.3) | – |
| 8 sys-setting change | u32 key, TV | AEON only | – |

Firmware ≤ 1.00.8 on the 75/150: the app registers no UI event callbacks at all (§15).

---

## 14. Preset operations, blob format, tuner

### 14.1 Slot addressing (CONFIRMED)
- URI form in the app: `l6device://0x00200002:/preset//<n>`, where **n is 0-based**. The wire index is n, with no offset (`ParseURI` 0xcf85e).
- The UI shows banks of 4: `n = (bank − 1)·4 + posInBank − 1` (`ui/tones/HardwareTonesAdapter.java:92-95`).
- Edit buffer = index **0xFFFFFFFF**. Count = cmd 5.

### 14.2 Operations

| Operation | Wire sequence | Status | Risk |
|---|---|---|---|
| **Select slot n** | 1. Editor flush. 2. Librarian **11 GetPresetFile {n}** → `{st, blob}`. 3. Parse locally; the write happens only if parsing succeeds. 4. Librarian **12 SetPresetFile {0xFFFFFFFF, L, same blob bytes}**. It is a **pass-through**: the very buffer read in step 2 is written back (`loadPresetFromDevice` 0xd5444 → `setToneMatchPreset(buf, 0xFFFFFFFF)`). 5. Local "preset changed". | CONFIRMED | live sound only |
| Select (alternative) | Librarian **13 LoadHardwarePreset {n}** → st. Never used by the app. | layout CONFIRMED, effect INFERRED | live sound only (INFERRED) |
| **Save to slot n** | Serialize the full blob from the local mirror of the edit buffer (§14.3), then **12 SetPresetFile {n, L, blob}**. Java then reloads the slot. (`savePresetToDevice` 0xd5796) | CONFIRMED | **WRITES STORAGE** |
| **Rename slot n** | No rename command (`setResourceName` returns −3 for device URIs). Set the tone name (PS key 0 inside the blob, ≤ 63 chars), then **save** to slot n. | CONFIRMED | **WRITES STORAGE** |
| **Move slot** | **9 MovePresetFiles {dst, src}** | CONFIRMED order; semantics INFERRED | **WRITES STORAGE** |
| Read name | cache, or **6 GetPresetName {n}** → `{st, u32 nameLen, chars}`. Whether nameLen includes the NUL is INFERRED (yes). | CONFIRMED | read-only |
| Read info | **14 GetPresetInfo {n}** → `{st, u64 uuid, u32 checksum, u32 size, u32 nameLen, char[64]}` | CONFIRMED | read-only |
| **Load a tone (JSON .l6p)** | Parse the L6Preset v5 JSON. **If it equals the current tone, send nothing** (`DeviceDataEqualTo` 0xf3d7e). Otherwise build the full blob, flush the editor, then **12 SetPresetFile {0xFFFFFFFF, L, blob}**. (`loadPresetFromFile` 0xd4ee8 → `syncWithDeviceAsMaster(false)` 0xda514) | CONFIRMED path; blob bytes INFERRED | live sound only |
| **Change a model** (`group/@model`) | `loadModel` 0xd5a9c sets the new model. Params carry over where the `persist` ordinal matches, otherwise they take the defaults. An amp change also applies its `cablink` cab, `cabER` and `cabmic`. Then a **partial blob** is sent with **12 SetPresetFile {0xFFFFFFFF, …}** (`sendModelToDeviceForGroup` 0xda900). | CONFIRMED | live sound only |
| **FX reorder** | `swapFXModel*` 0xd8f00..0xd9a5c → partial blob with the affected groups → 12 to 0xFFFFFFFF | CONFIRMED | live sound only |
| Current index | No query exists. It is known only from a type-3 patch event. | CONFIRMED absence | – |

Example envelope for a full-tone load (the 1210-byte blob of `default_preset.json`): `0C000000 C2040000 FFFFFFFF BA040000 <blob>`. Here 0x4C2 = 8 + 0x4BA.

### 14.3 Device-preset blob format (structure CONFIRMED: serializer `L6A36Preset::SerializeToDeviceForGroup` 0xfa480 + `L6SPePresetSerializer` 0x100302.., parser 0x100eec; re-implemented in `scripts/preset_blob.py`)

A flat sequence of records:
```
u32 key LE | u16 tag LE | payload
```
| Blob tag | Type | Payload |
|---|---|---|
| 0 | void | none |
| 1 | bool | u32 0/1 |
| 2 | int | i32 |
| 3 | float | f32 |
| 4 | string | u32 length (incl. NUL), then bytes |
| 6 | varray | u32 word count, then 4·n bytes |
| 7 | symbol | u32 **symbol-table index** |

Note that blob tags differ from TypedValue tags (§10.4).

Directive keys:

| Key | Name | Tag | Meaning |
|---|---|---|---|
| 0x80000000 | SectionID | int | 2 = PS (preset settings), 1 = DSP |
| 0x80000001 | SectionMagic | int | PS: 0x50525350 (bytes `50 53 52 50` "PSRP"). DSP: 0x47545254 (bytes `54 52 54 47` "TRTG"). |
| 0x80000002 | SectionEnd | void | |
| 0x80000003 | SlotStart | symbol | opens a slot; slots **nest** |
| 0x80000004 | SlotEnd | void | closes the innermost slot |
| 0x80000005 | Asset | symbol | model loaded in this slot |
| 0x80000006 | StateCount | int | the next *n* records are `(u32 idx("<Param>State"), typed)` |

Layout and per-field confidence:

| Part | Content | Confidence |
|---|---|---|
| PS section | `SectionID 2`, `SectionMagic PSRP` | CONFIRMED |
| PS key 0 | name, string ≤ 63 chars UTF-8 | CONFIRMED |
| PS keys 4 / 5 | tweak target slot / param (symbols; −1 if unmapped) | CONFIRMED |
| PS keys 1 / 2 | tnid low / high 32 bits (int), full tone only | CONFIRMED |
| PS key 3 | tempo (float), full tone only | CONFIRMED |
| PS keys 7 / 8 / 9 | tweakmin / tweakmax (float), pedal2assign (bool); only when target fw ≥ 2.11.3 | CONFIRMED |
| | `SectionEnd` | CONFIRMED |
| DSP section | `SectionID 1`, `SectionMagic TRTG`, `SlotStart GuitarProc`, `Asset ToneMatchGuitarFlow`, `StateCount n`, then `<X>State` for the GuitarProc params of §10.3 (`FX1EnableState` bool, `FX1MixState` float, `ChannelVolumeState`, `CabEnableState` = cab ≠ `@NoCabinet`, …) | CONFIRMED structure |
| Child slots (nested inside GuitarProc), in this order | Gate, VolumePedal, Wah, FX1, FX2, FX3, FX4, Amp, **Air** (asset `TNGAIRReflections`, state `LevelState` = cab Level, 0 for no cab), **StudioCab** (asset = cab + mic suffix, no states), **LiveCab** (asset = the amp's `cablink`, no states), PostComp, PostEQ. Each is `SlotStart <slot>`, `Asset <model>`, `StateCount n`, `<Param>State` records, `SlotEnd`. | CONFIRMED order |
| | `SyncSelectState` = 0 when temposync is off; added as 0 if the model has SyncSelect but the tone lacks it | CONFIRMED |
| | closing `SlotEnd` (GuitarProc), `SectionEnd` | CONFIRMED |
| Order of states inside a slot | hash order in the app | **UNKNOWN**. INFERRED: the amp matches states by symbol. |
| Exact bytes for a given tone | e.g. 1210 B for `default_preset.json` (`test_vectors.json`) | **INFERRED** (not capture-verified) |
| Amp-side checksum or UUID requirements on write | none seen client-side | UNKNOWN |
| Max size | 0x8000 bytes | CONFIRMED |

**Partial blob** (model change): the PS section without keys 1, 2 and 3, the GuitarProc states of that group only, and that group's child slots only. Group `amp` → Amp, Air, StudioCab, LiveCab (and the cab's GuitarProc states). Group `cab` → Air, StudioCab, LiveCab.

**Worked example: partial blob for group fx1 of `default_preset.json`** (238 bytes, INFERRED bytes), decoded by `preset_blob.py decode`:
```
00000080 0200 02000000                      SectionID   int  2 (PS)
01000080 0200 50535250                      SectionMagic int "PSRP"
00000000 0400 0e000000 "Fidelity Lead\0"    PS key 0 name (len 14 incl NUL)
04000000 0700 54020000                      PS key 4 tweak slot  = GuitarProc (596)
05000000 0700 14020000                      PS key 5 tweak param = FX3Mix (532)
02000080 0000                               SectionEnd
00000080 0200 01000000                      SectionID 1 (DSP)
01000080 0200 54525447                      SectionMagic "TRTG"
03000080 0700 54020000                      SlotStart GuitarProc
05000080 0700 0b020000                        Asset ToneMatchGuitarFlow (523)
06000080 0200 04000000                        StateCount 4
2b020000 0100 00000000                        FX1EnableState  bool false
23020000 0100 00000000                        FX1PostState    bool false
20020000 0300 0000803f                        FX1MixState     float 1.0
34020000 0200 00000000                        FX1MixTypeState int 0
03000080 0700 0f020000                        SlotStart FX1
05000080 0700 23010000                          Asset Screamer
06000080 0200 03000000                          StateCount 3
16000000 0300 9f21403f                          DriveState 0.7505
0f000000 0300 895cb03e                          GainState  0.3445
b5000000 0300 9f21403f                          ToneState  0.7505
04000080 0000                                 SlotEnd (FX1)
04000080 0000                               SlotEnd (GuitarProc)
02000080 0000                               SectionEnd
```

### 14.4 Model change summary
Changing `amp/@model` (or any group's model) means building the partial blob for that group with the new model, its defaults and carried-over params, then writing it to the edit buffer (§14.2). Editor cmd 8 LoadDspModel is used **only** for the cab mic.

### 14.5 Metadata
Tone metadata (`name`, `author`, `song`, `style`, …) lives in the app-side JSON. Only `name` (PS key 0) and `tnid` (keys 1 and 2) reach the device blob. Setting metadata sends nothing (`setMetaData` 0xd7d26).

### 14.6 Tuner (CONFIRMED: `engageTunerInternal` 0xe7240, `handleTunerEvent` 0x109b52, `convertA36TunerValueToNoteCents` 0xea729)
1. **Engage:** editor cmd 10 `{Tuner 587, Enable 593, TV int 1}`. Note: tag **2 int**, not bool. It waits for the reply. `0A000000 10000000 4B020000 51020000 02000000 01000000`
2. Then cmd 11 RegisterDspEvent `{587, Note 594}`: `0B000000 08000000 4B020000 52020000`
3. **Data:** type-2 events `{587, 594, TV float v}`. The tag must be 4.
   - v = pitch in semitones above A within one octave, in [0, 12). v ≥ 11.5 wraps to v − 12.
   - f = 440 · 2^(v/12). note = nearest semitone (0 = A, 1 = A#/Bb, … 11 = G#/Ab). cents = 1200 · log2(f / f_note).
   - v < 0 or v ≥ 12 → no signal (note −1).
   - Example: v = 2.1 → note 2 (B), +10 cents.
4. **Disengage:** cmd 10 with TV int 0 (`… 02000000 00000000`), then cmd 12 UnregisterDspEvent `{587, 594}`.
5. The tuner switched on the amp itself arrives as param event (Tuner, Enable). The app then only registers or unregisters the Note event.
6. Initial state: cmd 9 `{587, 593}`.
7. Event rate (continuous vs on change): UNKNOWN.

Risk: changes live sound only (the tuner mutes or bypasses).

---

## 15. Firmware-version branches

### 15.1 Version packing (CONFIRMED: `SetVersionNum` 0xa1340, `L6StringToL6VersionInt` 0xa13e3, `prepareForDeviceInfo` 0xa5cd0)
- **Raw** (device-info u32 @0xC0; also what Java's `nativeGetFirmwareVersion` returns via `L6Device::getVersion`): `major<<24 | minor<<16 | patch<<8 | suffixChar`, with minor in binary.
- **Corrected** (passed to the editor/librarian services and used by **every native gate**; `L6AndroidNdkDevice::getCorrectedVersion` 0x83aaa):
  - The raw value is printed as `"%d.%02d.%d%c"` and re-parsed.
  - The result is `major<<24 | (minor/10)<<20 | (minor%10)<<16 | patch<<8 | lowercaseLetterOrZero`.
  - This is decimal digits in nibbles. For minor < 10 it equals the raw value.

Example: fw "2.10.1" → raw 0x020A0100 → corrected **0x02100100**.

### 15.2 Branch table (all CONFIRMED)

| Condition (corrected version) | Effect | Where |
|---|---|---|
| raw < 0x01000000 (1.00.0); FX100 < 0x01000400 | Official app forces an update. **AVOID. A client must refuse.** | `L6AndroidNdkDevice::open` 0xa57e0 |
| AMPLIFi (not 30) and < **0x02100100 (2.10.1)** | **MTU 256, stream timeout T = 4000 ms** (heartbeat every 1 s) | `setupMessageChannelParameters` 0xa4b14 |
| AMPLIFi (not 30) and ≥ 2.10.1 | **MTU 240, T = 16000 ms** (heartbeat every 4 s) | same |
| AMPLIFi 30: threshold 0x00010000 (0.01.0) | in practice always MTU 240 / 16000 | same |
| AEON | MTU 240 / 16000 | same |
| 0x200001/0x200002 and ≤ **0x010008FF** (≤ 1.00.8x) | no UI event callbacks; librarian **V1** (cmds 8, 6, 7, 10, 11 for the cache) | `ToneMatchEditorService` ctor 0x1087f8, `ToneMatchLibrarianService` ctor 0x10d230 |
| 0x200001/0x200002 above that; 0x200003–0x200007 always | librarian **V2** (cmd 14 per slot). Message formats are identical. | same |
| AMPLIFi family and < **0x02000600 (2.00.6)** | cmds 17/18 (e.g. TapTempoLED) refused locally. Java uses the same constant (`ProductSpecificSettingsFragment.java:16`); its UI text says "2.01". | `FUN_001084af` |
| AMPLIFi family and < **0x02110300 (2.11.3)** | PS-key cmds 19/20 and event 7 disabled; blob omits PS keys 7/8/9 | `FUN_001084fb`, L6A36Preset 0xfa480 |
| product → bundled table | 0x200003 `_FX100`, 0x200004 `_AEON`, 0x200005 `_TT`, 0x200006 `_Firebird`, 0x200007 `_Dio`, everything else (**150**) `defaultSymbolTable.bin` | `A36EditorLibrarian::connect` 0xe0a9e |
| AEON only | system settings 21/22, event 8, SetPresetFile 15, other slot tables | `FUN_00108547` |

No envelope, TypedValue or command layout changes with firmware. Which branch a given 150 takes depends on its firmware, which phase A reads (UNKNOWN until you read your own amp).

---

## 16. AVOID (names only; never send, call, port or emulate)

- **Wire:** ePortMode 1 `kUpdateMode`; service-mode word **0** ("UPDATER") on stream 0x03EF; the `L6BspMsgPort_Amplifi+0x64` updater switch inside `open` 0xa1c24.
- **JNI / manager:** `nativeStartFirmwareUpdate`, `nativeOpen` mode 2 (FIRMWARE_UPDATE_MODE), `AmplifiRemoteManager::OpenFirmwareUpdate` 0x850b4, `AmplifiRemoteManager::startFirmwareUpdate` 0x89954.
- **Device:** `L6AndroidNdkDevice::prepareForUpdating` 0xa5a2c, `startUpdate`, `forceFirmwareUpdate`, `handleUpdateEngineCallback`.
- **Engines:** `L6BspUpdateEngine::*`, all `L6UUE::*` (UpdateEngine, IOStreamUpdateEngine, UpdateDevice, ImageArchive, …), `Checksum_Fletcher` 0xb8bd4.
- **Services:** `FirmwareServiceInterfaceEditor::PrepareForUpdate`, `FirmwareServiceInterfaceLibrarian::PrepareForUpdate` / `ConvertToUpdater`, `ToneMatchFirmwareService::prepareServiceForUpdate`, `MsgPort_Stream_Abort`.
- **Notifications / errors:** `DeviceUpdate*`, `Device_Bricked`, `consumeFirmwareStatusEvent`, −9100 (force update), −9101 (bricked).
- **Java:** `FirmwareUpdateService`, `DeviceUpdateManager`, `FirmwareUpdateScenario`, `cloud/firmware/*`, `ui/firmware/*`.
- **Behaviour:** if the raw firmware is below 1.00.0, refuse to connect. Do not offer an update.
- **Not firmware, but they modify stored data** (use deliberately, after a backup with cmd 11): librarian 9, 12 (idx ≠ 0xFFFFFFFF), 15; editor 18, 19, 22.

---

## 17. Open questions and the capture that would answer each

An HCI snoop log is Android's "Bluetooth HCI snoop log" developer option, recorded while the official app runs against the amp. Open it in Wireshark. Items 1–7 need only a single connect, select, knob-turn and tuner session.

| # | Question | Resolved by |
|---|---|---|
| 1 | Are `IAP x OK/START` required, and does the amp answer them (ASCII or nothing)? | Snoop of an official connect: the first 3 s in both directions. |
| 2 | Amp RSMC values: initial `rx_limit`, does it also send header-only frames every 200 ms, does it reset seq on reconnect? | Same snoop. |
| 3 | Amp stream SYN: does it set flag 0x20, which MSS does it advertise, what is its heartbeat cadence and real timeout? | Same snoop, idle for 30 s. |
| 4 | Do amp data segments carry 0x04 or 0x0C, and when does it send WND? | Same snoop. |
| 5 | Last 4 bytes of the 200-byte device-info record; exact productName/model strings; this amp's firmware → MTU 240 or 256? | Same snoop, or a read-only phase A from your client. |
| 6 | Does the amp accept handshake CRC 0xB68B291E, or does it force the cmd 2/3 download? | Snoop (look for cmd 2/3), or a live read-only handshake. |
| 7 | Blob byte-exactness: state order, any hidden checksum/UUID; does `preset_blob.py encode` of a tone equal what the amp returns? | Snoop of one GetPresetFile reply (connect sync step 21), decoded and diffed. |
| 8 | MovePresetFiles semantics (insert vs swap) | Snoop of a reorder in the official app, then a list of names. |
| 9 | LoadHardwarePreset (13): does it recall slot n, and does the amp then emit a patch event? | Live experiment (unused by the app, so no capture exists). Live-sound risk only. |
| 10 | Does `nameLen` include the NUL; is the name UTF-8 or Latin-1? | Snoop of cmd 6 / cmd 14 replies. |
| 11 | How do you learn the current preset index at connect? | Experiment: does the amp emit a type-3 event after connect, or does cmd 13 or a patch-knob turn reveal it? |
| 12 | Units and range of Master/GuitOutputGain; do they persist across power cycles? | Snoop of param events while turning the amp's master knob, plus a power-cycle test. |
| 13 | Does SetPresetPSKeyParam (19) persist without a save? | Experiment after a backup. |
| 14 | Tuner event rate and value behaviour with no signal | Snoop with the tuner on. |
| 15 | Amp-side status codes (`i32 status` values) | Snoop of a deliberately bad request (e.g. GetPresetName with an out-of-range index). |
| 16 | Can events (type 2–8) be interleaved between consecutive responses, and does the amp ever reorder responses? | Long snoop with knob turns during preset reads. |
| 17 | `device_version` packing in `.l6p` files (0x00720078, 0x02490100) | Compare with the device-info version of the amp that saved the tone. |
| 18 | Are global-EQ sys params (keys 14–29) implemented on the 150? | Experiment with cmd 17 (read-only) per key. |

---

## Appendix A: where the test vectors live
- `notes/test_vectors.json`: 50+ RPC payloads (requests and inbound) with source function and status. No transport framing.
- `scripts/crc16.py`: CRC-16/CRC-32, RSMC and stream builders, examples E1–E7, self-test. Run `python3 -I scripts/crc16.py --lib work/ghidra/input/libAmplifiRemoteNdk.so --symtab work/apktool/assets/defaultSymbolTable.bin`.
- `scripts/app_messages.py`: RPC encoder/decoder (`setparam`, `decode-in`, `tuner`).
- `scripts/preset_blob.py`: blob `encode` (full or per group) and `decode`.
- `scripts/parse_symtab.py`: symbol-table dump and hash check.
