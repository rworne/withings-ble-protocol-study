# Withings BLE / WPP — Command & TLV Reference

> **Project:** `withings-ble-protocol-study`  
> **Status:** Independent research notes; incomplete, model/firmware-dependent  
> **Updated:** 2026-10-24  
> **Companion:** [Protocol research report](PROTOCOL.md)

This reference is a **developer lookup table**, not an official protocol specification. It summarizes the provided BLE capture analysis, provisioning experiments, and BeamO Explorer source. Command meanings are **context-specific**: a command number and a TLV number occupy separate namespaces. No identifying data, device keys, passwords, or personal measurements are reproduced here.

**Evidence labels:** **Captured** = observed in analyzed BLE exchanges; **Tested** = reproduced by experimental software; **Implemented** = decoded/sent in supplied application source; **External** = documented by another independent project but not necessarily independently verified for each device; **Unresolved** = meaning or layout incomplete. These labels are not claims of interoperability across all Withings devices.

## 1. Transport and framing

Observed Withings GATT identifiers in the study:

| Element | UUID |
|---|---|
| Service | `00000000-0000-5749-5448-494E47530000` |
| WPP data characteristic | `00000004-0000-5749-5448-494E47530000` |

A WPP message has a **five-byte header**, followed by TLVs:

```text
01 CC CC LL LL [TT TT NN NN VALUE...]...
│  │     │       └─ repeated TLVs: type (BE16), length (BE16), value
│  │     └───────── payload length (BE16), excludes 5-byte header
│  └─────────────── command (BE16)
└────────────────── version/prefix 0x01
```

Integers in WPP framing are big-endian. **Do not equate an ATT notification with one complete WPP message.** Accumulate bytes until `5 + payload_length` bytes are available; parse every TLV with bounds checks. Large logical transfers can span multiple complete WPP frames, ending with a zero-length `0x0100` TLV. Preserve frame boundaries and ordering in forensic logs. The supplied Swift decoder implements buffering across notifications.

**Exact constructed example (valid WPP encoding; not represented as a captured packet):**

```hex
01 01 0F 00 06  01 14 00 02 01 00
|  cmd   len     TLV    len   value
```

This encodes inventory command `0x010F` with TLV `0x0114 = 01 00`.

### Direction and response matching

- **Host → device:** command request; **device → host:** response or asynchronous device message.
- A command may be returned with bit `0x4000` set in observed processing. The BeamO downloader matches `(command & ~0x4000) == 0x0147`; broader interpretation of the bit is **not fully established**.
- Distinguish **command `0x0100`** (general error; external reference) from **TLV `0x0100`** (empty terminator/status marker).

## 2. Command index

| Command | Direction / role | Description | Evidence / caution |
|---|---|---|---|
| `0x0100` | Device → host | General WPP error response | External; see §7 |
| `0x0101` | Host ↔ device | Probe / identification | Captured; identity payload varies |
| `0x0102` | Host ↔ device | Wi-Fi network scan | Captured; **documentation only** |
| `0x0103` | Host ↔ device | Wi-Fi credentials / result | Captured; **documentation only** |
| `0x0104` | Host ↔ device | Additional Wi-Fi-related operation | Captured, unresolved |
| `0x0105` | Host ↔ device | Battery information | Captured / external; field layout not asserted |
| `0x0108` | Host → device | Region configuration | Captured; exact value layout omitted here |
| `0x0109` | Host ↔ device | Post-Wi-Fi operation | Captured, unresolved |
| `0x010D` | Host → device | Primary configuration JSON | Captured / tested; see §4 |
| `0x010F` | Host ↔ device | Stored numeric measurement inventory | Implemented; see §5 |
| `0x0110` | Host ↔ device | Provisioning completion stage | Captured; sequence model-dependent |
| `0x0111` | Host ↔ device | Connection reason | Captured / external |
| `0x0112` | Host ↔ device | Setup/settings stage | Captured, partially decoded |
| `0x0113` | Host ↔ device | Setup completion/acknowledgment | Captured / external |
| `0x0116` | Host ↔ device | Additional measurement-related operation | Earlier investigation; **not** interchangeable with TLV `0x0116` |
| `0x0118` | Host ↔ device | Additional data-transfer operation | Captured, partially decoded |
| `0x011A` | Host → device | Language configuration | Captured |
| `0x0128` | Host ↔ device | Existing-association challenge/response | Offline verified / implemented; see §3 |
| `0x0134` | Host → device | Association / owner key installation | Tested; sensitive payload |
| `0x0147` | Host ↔ device | Fetch current pending binary signal | Implemented; see §6 |
| `0x0148` | Host ↔ device | Acknowledge signal; advance pending queue | Implemented; see §6 |
| `0x0501` | Host ↔ device | Set time | External; not characterized here |
| `0x0502` | Host ↔ device | Clock drift information | External; not characterized here |
| `0x09B2` | Host ↔ device | Initial-setup challenge/negotiation | Captured; cryptographic role unresolved |
| `0x09C1` | Host ↔ device | Initial-setup negotiation continuation | Captured; semantics unresolved |
| `0x09C3` | Host → device | Secondary global / per-user settings | Captured / tested; see §4 |

**Do not infer direction or precise payload structure from the name alone.** For commands not expanded below, consult the full report and original captures.

## 3. Identification and authentication

### `0x0101` — probe / identity

| TLV | Role | Status |
|---|---|---|
| `0x0101` | Length-prefixed identity data (reported name, MAC, firmware and related fields) | Captured; detailed offsets require per-device validation |
| `0x012C` | Additional identification field observed in some responses | Captured; unresolved |

Do not fabricate firmware subversions or device IDs from an app screen if they are absent from the captured BLE message.

### `0x0128` — already-associated mutual authentication

Observed TLVs include `0x0122` (device challenge), `0x0123` (authentication response), and `0x012A` (application probe/challenge). The previously verified host digest construction is:

```python
import hashlib
host_proof = hashlib.sha1(device_challenge + mac_ascii + kl_ascii).digest()
```

| Input | Encoding |
|---|---|
| `device_challenge` | 16 raw bytes from current device exchange |
| `mac_ascii` | Lowercase MAC address as ASCII, preserving separators |
| `kl_ascii` | Existing association key, ASCII bytes; **never publish** |
| `host_proof` | 20-byte SHA-1 digest |

Prior analysis reported three exact digest matches in BeamO traces. The supplied Swift code additionally verifies the reciprocal device proof. This mechanism requires an **authorized, existing association key**; it does not defeat or bypass encryption.

#### BPM Connect: `0x0128` authentication observations

During repeated BPM Connect pairing attempts, the device initiated an existing-association authentication exchange using WPP command `0x0128`.

The captured sequence was:

| Step | Direction | Command | Observed contents |
|---|---|---|---|
| 1 | Device → host | `0x0128` | TLV `0x0122` (35 bytes) |
| 2 | Host → device | `0x0128` | TLVs `0x012A` (6 bytes), `0x0123` (21 bytes), and `0x0122` (35 bytes) |
| 3 | Device → host | `0x0100` | Error TLV `0x0110`, reporting `0x0128` error `−6` |
| 4 | Host → device | `0x0110` | Subsequent command |
| 5 | Device → host | `0x0100` | Error TLV `0x0110`, reporting `0x0110` error `−5` |

Captured authentication error:

```text
01 01 00 00 0A 01 10 00 06 01 28 FF FF FF FA
```

The `0x0128` response reports signed error code `−6`.

The subsequent `0x0110` response reports signed error code `−5`.

Both errors were returned promptly. The official application remained on its configuration screen until a later application-level timeout.

**Interpretation:** The precise cause of error `−6` remains unresolved. The captures do not establish that the association key was incorrect or that a BLE transport timeout caused the authentication failure.

A later connection in the longer BPM Connect capture successfully completed provisioning without a visible repeat of this `0x0128` exchange on that connection.

### `0x09B2` / `0x09C1` — initial provisioning negotiation

| Exchange | TLV | Observed structure | Status |
|---|---|---|---|
| `0x09B2` request | `0x09C2` | Byte `0x20` + 32 fresh nonce bytes | Captured |
| `0x09B2` response | `0x09C3` | Host challenge echo and device-generated material | Captured; exact semantics unresolved |
| `0x09B2` response | `0x09C4` | 64-byte opaque field | Captured; purpose unresolved |
| `0x09C1` response | `0x0961` | Observed byte `01` | Captured; meaning unresolved |
| `0x09C1` response | `0x09D3` | 32 opaque bytes | Captured; purpose unresolved |

The official BPM Vision Wi-Fi setup capture included three `0x09B2` stages; the working independent BLE-only path used two. **These are not `0x0128` exchanges.** Avoid asserting a cryptographic primitive for the opaque fields without proof.

---

#### Body Smart: `0x09C1` behavior

During initial provisioning, Body Smart responds to the empty `0x09C1` request with a WPP error rather than the `0x0961` and `0x09D3` TLVs observed on BeamO and BPM Vision.

Request:

```text
01 09 C1 00 00
```

Response:

```text
01 01 00 00 0A 01 10 00 06 09 C1 FF FF FF FD
```

The response contains error TLV `0x0110`, identifying command `0x09C1` and reporting signed error code `−3`.

The provisioning sequence continues after this response.

**Observed compatibility difference:** BeamO and BPM Vision successfully respond to `0x09C1`, while the captured Body Smart firmware returns `−3`. This does not establish whether the difference is caused by firmware version, device capabilities, or provisioning state.

## 4. Provisioning and feature configuration

### `0x0134` — association keys

Installs the Withings account identifier and device association credentials, including the KL and advertiser key.

The observed request contains two TLVs:

| TLV | Length | Contents |
|---|---:|---|
| `0x0135` | 37 bytes | Account ID followed by length-prefixed KL |
| `0x0136` | 33 bytes | Length-prefixed advertiser key |

#### TLV `0x0135` — account identifier and KL

| Offset | Size | Format | Description |
|---|---:|---|---|
| 0 | 4 | Big-endian `uint32` | Withings account ID |
| 4 | 1 | `uint8` | KL length |
| 5 | Variable | ASCII | KL |

In the analyzed captures, the KL is 32 ASCII bytes, preceded by the length byte `0x20`.

**The account ID is distinct from the user ID and device ID.** These identifiers must not be used interchangeably.

#### TLV `0x0136` — advertiser key

| Offset | Size | Format | Description |
|---|---:|---|---|
| 0 | 1 | `uint8` | Advertiser-key length |
| 1 | Variable | ASCII | Advertiser key |

In the analyzed captures, the advertiser key is 32 ASCII bytes, preceded by the length byte `0x20`.

#### Security considerations

The KL and advertiser key are sensitive association credentials. Never include actual credentials or unredacted ownership packets in public documentation, test fixtures, or examples.

### `0x010D` — primary JSON configuration

Captured configurations contain fields such as:

```json
{
  "body": {
    "ind": {"ft": ["<feature IDs from actual capture>"], "mcr": "<captured value>"},
    "sp": {"users": [{"id": "<user ID>", "ft": ["<per-user feature IDs>"]}]}
  }
}
```

**The JSON above is a schematic field map, not a captured packet or a valid provisioning payload.** Preserve all unknown keys and original types in an actual extractor. Keep account IDs, user IDs, and target IDs consistently remapped while preserving their respective identity relationships. Do not assume account IDs and user IDs are interchangeable. Global target `0` remains `0`.

### `0x09C3` — secondary settings

| TLV | Length | Interpretation | Evidence |
|---|---:|---|---|
| `0x0145` | 4 | Target ID, BE `uint32`; `0` global, nonzero per-user | Captured / tested |
| `0x09D5` | 12 | Eight `00` bytes + BE `uint16` feature ID + BE `uint16` value | Captured / tested |
| `0x0100` | 0 | Marker/status | Captured |

**Constructed encoding example (not from a capture):** set feature 27 (`0x001B`) to 1 for global target 0:

```hex
01 09 C3 00 18
   01 45 00 04 00 00 00 00
   09 D5 00 0C 00 00 00 00 00 00 00 00 00 1B 00 01
```

`0x0018` is the 24-byte TLV payload length (8 + 16). This example illustrates the observed field encoding; it does **not** claim that one command alone enables a device feature. Primary `ind.ft`, per-user feature lists, and secondary global/per-user values are distinct layers.

**Feature observations:** BPM Vision feature `27` was involved in an experimental ECG/AFib configuration; BeamO feature `12` removal altered observed region-related behavior, while `15`, `27`, and `57` have been investigated. Do **not** assign definitive regional or medical meanings to feature numbers without controlled evidence. See the research report.

### Captured setup order (representative; not universal)

```text
0x0101 → 0x09B2 → 0x09C1 → 0x0134 → 0x09B2
       → 0x010D → 0x0108 → 0x011A → 0x09C3
       → 0x0112 / 0x0113 / 0x0110
```

The independent provisioning experiment did **not** transmit Wi-Fi provisioning messages or communicate with vendor servers.

## 5. Stored numeric measurements: `0x010F`

**Request (implemented):** TLV `0x0114` with value `01 00` (`GET_ALL` in the supplied code).

```hex
01 01 0F 00 06 01 14 00 02 01 00
```

| Response TLV | Length | Meaning |
|---|---:|---|
| `0x0116` | Variable | New measurement/session header; BE `uint32` user ID at offsets 6–9; BE `uint32` session ID in final four bytes |
| `0x0117` | 8 | Numeric measurement belonging to current session |
| `0x0993` | 1 | Stethoscope position code associated with current session (when present) |
| `0x0100` | 0 | Logical inventory terminator |

**`0x0117` eight-byte layout:**

| Byte offset | Size | Type |
|---:|---:|---|
| 0 | 4 | Signed BE `int32` mantissa |
| 4 | 2 | BE `uint16` measurement type |
| 6 | 2 | Signed BE `int16` decimal exponent |

`value = mantissa × 10^exponent`. Unknown measurement types must be preserved rather than guessed. The inventory `0x0116` header is **not** the same structure as the signal-transfer `0x0116` metadata below.

## 6. Binary signals: `0x0147` and `0x0148`

### `0x0147` — fetch pending FIFO head

**Request:** no TLVs, exactly:

```hex
01 01 47 00 00
```

**Response:** accumulate WPP messages associated with `0x0147` until TLV `0x0100` terminates the logical transfer.

| TLV | Value size | Meaning / layout | Status |
|---|---:|---|---|
| `0x0116` | 23 | Signal ID BE `uint32` at offset 0; parent session ID BE `uint32` at offset 19; intervening 15 bytes not fully decoded | Implemented |
| `0x0143` | 8 | Opaque signal descriptor; retain byte-for-byte for ACK | Implemented |
| `0x0146` | 12 | Signal header; expected total binary payload length BE `uint32` at offset 4 | Implemented |
| `0x0144` | Variable | First byte `N`, followed by **exactly N** waveform bytes | Implemented |
| `0x0100` | 0 | End of signal; if no signal metadata/data, empty queue | Implemented |

**Constructed TLV chunk example (not captured):** `01 44 00 04 03 AA BB CC` encodes three waveform bytes `AA BB CC` preceded by the count byte `03`.

**Validation:** require correct metadata/descriptor/header sizes; verify each chunk count; concatenate only the data bytes; reject overrun and require assembled length to equal the declared length before considering transfer complete. The supplied assembler caps expected length at 64 MiB.

### `0x0148` — acknowledge and advance

**Request TLVs:**

| TLV | Length | Value |
|---|---:|---|
| `0x0145` | 4 | Signal ID BE `uint32` |
| `0x0143` | 8 | Exact eight descriptor bytes received in `0x0147` |

**Constructed WPP request (illustrative ID and descriptor, not a captured packet):**

```hex
01 01 48 00 14
   01 45 00 04 00 00 00 01
   01 43 00 08 00 0D 01 F4 00 02 10 02
```

This is a **state-changing** acknowledgment: the next `0x0147` can return the next pending signal. It does **not** transmit a numeric queue offset. Whether the device deletes or merely marks the acknowledged signal is unknown. A read-only client omits `0x0148` and therefore only inspects the current FIFO head.

**Recommended safe sequence:** `0x0147` → validate → persist binary file durably → read back and compare → save metadata → **only with authorization** send `0x0148` → await response → repeat.

### Associating a recording with its measurement

The signal `0x0116` parent ID (offset 19) matches the numeric inventory `0x0116` session ID (final four bytes). Join by **ID**, not by timestamp or arrival order. A `0x0993` position code may annotate a stethoscope session (implemented codes include heart 15–19, lung 20–27, general 28).

### Observed binary formats

| Signal | Descriptor / codec | Decoding supported in supplied source |
|---|---|---|
| ECG | Descriptor `00 0D 01 F4 00 02 10 02` | Two interleaved signed 16-bit **little-endian** streams at 500 frames/s; raw/filtered labels provisional |
| Stethoscope | G.711 A-law | 8-bit compressed mono audio, 4,000 samples/s; decode to signed 16-bit PCM |

The waveform illustrations in the repository were generated from recovered recordings. The examples are for **binary format demonstration**, not medical interpretation. Other descriptors remain possible.

## 7. Wi-Fi (capture documentation only)

These messages were observed in official-app setup captures; they are **not used by the independent BLE-only provisioning runner**.

| Command / TLV | Observed function | Limitations |
|---|---|---|
| `0x0102` response / `0x0103` | Network scan entries | Network name may be sensitive |
| `0x0103` request / `0x0104` | `[SSID length:1][SSID][password length:1][password]` | **Never publish raw payload** |
| `0x0103` response / `0x0106` | First byte: setup status | Only `0x02` associated with displayed Wi-Fi authentication failure in experiment |
| `0x0103` response / `0x010A` | Additional network/device data | Mostly unknown |
| `0x0109` / `0x010D`, `0x010E` | Post-Wi-Fi exchange | Unresolved |

Observed `0x0106` first-byte values included `0x00` (successful BPM Vision case), `0x02` (BeamO case with displayed authentication failure), and `0x03` / `0x05` (**unknown failure meanings**). These Wi-Fi status bytes are **not** WPP general error codes.

## 8. General errors and unresolved areas

External independent documentation describes **command `0x0100`** containing **TLV `0x0110`**, with the originating command and signed 32-bit error code. Reported codes include:

| Code | External description |
|---:|---|
| `-2` | Busy |
| `-3` | Unsupported |
| `-4` | Rejected |
| `-5` | Unauthenticated |
| `-8` | Invalid arguments |
| `-9` | Arguments not set |

These codes are **externally documented**, not established here as exhaustive or universally applicable. Preserve the original error bytes and command context.

**Open questions:** cryptographic interpretation of `0x09B2` / `0x09C1`; exact per-device identity subfield offsets; some provisioning completion commands; additional signal descriptors; the internal FIFO pointer representation; whether ACK deletes or only marks recordings; arbitrary-ID historical retrieval; meanings of unknown feature IDs and Wi-Fi status bytes.

## 9. Research and publication guidance

- Record **device model, observed firmware, capture source, command, direction, and offset** for every new claim.
- Separate **captured hex** from **constructed demonstration packets**; do not silently promote an implementation assumption to protocol fact.
- Keep unknown TLVs as raw bytes in private local analysis, but redact secrets and identifying content in published output.
- Never publish KL, advertiser keys, account identifiers, SSIDs/passwords, raw personal databases, or unsanitized packet captures.
- Do not assume a command works identically on another model or firmware.
- Treat `0x0148` as state-changing and potentially irreversible from the perspective of pending synchronization.

See [PROTOCOL.md](PROTOCOL.md) for the full experimental narrative, caveats, and reproduction roadmap. This project is independent educational research; it is not affiliated with Withings, does not defeat encryption, and is provided without warranty. Released code is under the repository's MIT license.
