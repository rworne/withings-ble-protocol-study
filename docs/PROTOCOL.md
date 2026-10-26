# Withings BLE / WPP: Protocol Discovery, Analysis, and Reproduction Guide

> **Community research report · Updated 24 October 2026**  
> **Status:** Experimental, partially decoded; reproducible observations and open questions  
> **Reference devices:** Withings Body Scan 2, BeamO (two units, advertised suffixes A8 and C8), BPM Connect, and BPM Vision (WPM07)  
> **Code license:** MIT License (see [License](#license-and-disclaimer))  
> **Scope:** Local BLE communications. Wi-Fi provisioning is analyzed **offline only**; the independent provisioning implementation deliberately does not configure Wi-Fi or contact Withings servers.

## Contents

1. [Purpose and results](#1-purpose-and-results)
2. [Ethics, scope, and experimental conditions](#2-ethics-scope-and-experimental-conditions)
3. [Tools, captures, and repeatable methodology](#3-tools-captures-and-repeatable-methodology)
4. [BLE discovery and transport](#4-ble-discovery-and-transport)
5. [WPP framing and conversation reconstruction](#5-wpp-framing-and-conversation-reconstruction)
6. [Identification and device metadata](#6-identification-and-device-metadata)
7. [Authentication and pairing](#7-authentication-and-pairing)
8. [Ownership and BLE-only provisioning](#8-ownership-and-ble-only-provisioning)
9. [Users, feature configuration, and experiments](#9-users-feature-configuration-and-experiments)
10. [Wi-Fi setup: passive documentation](#10-wi-fi-setup-passive-documentation)
11. [Measurement inventory, transfer, and associated data](#11-measurement-inventory-transfer-and-associated-data)
12. [Download cursors, record selection, and resumption](#12-download-cursors-record-selection-and-resumption)
13. [Command and TLV reference](#13-command-and-tlv-reference)
14. [How to reproduce and extend the research](#14-how-to-reproduce-and-extend-the-research)
15. [Open questions and contribution roadmap](#15-open-questions-and-contribution-roadmap)
16. [License and disclaimer](#license-and-disclaimer)

---

## 1. Purpose and results

This report documents an educational investigation into the **Withings proprietary protocol (WPP)** carried over Bluetooth Low Energy. Its purpose is to help device owners and researchers understand the observable interface, independently inspect their own measurements, reproduce documented **local** BLE exchanges, and extend the decoding work without starting from scratch.

### Demonstrated outcomes

- Captured and decoded portions of official-app discovery, pairing, ownership installation, configuration, and measurement exchanges using Apple PacketLogger.
- Independently provisioned a BPM Vision using **locally generated owner credentials** and BLE-only communication. Three configured users appeared and ordinary blood-pressure operation worked in the experiment.
- Experimentally enabled BPM Vision ECG/AFib functionality by applying feature `27` in the primary device feature list and global/per-user secondary feature configuration. This observation **does not establish medical validation, regulatory authorization, or which individual setting is necessary**.
- Built a **BeamO Explorer** implementation capable of retrieving measurements and associated ECG waveforms and stethoscope audio recordings over BLE. The supplied BeamO Explorer implementation now establishes the pending-signal FIFO retrieval and acknowledgment protocol, including the `0x0147`/`0x0148` exchange, binary layouts, and parent-session association; see §11–12.
- Verified, in prior offline capture analysis, an existing-association `0x0128` SHA-1 challenge-response against three BeamO exchanges using the matching device-specific KL and MAC representation. Two BeamO units require separate key contexts.
- Compared successful BPM Vision Wi-Fi setup with unsuccessful BeamO setup and identified Wi-Fi status `0x02` as **authentication failure** (confirmed by the official app). Codes `0x03` and `0x05` remain **unknown Wi-Fi setup failures**.

### Evidence vocabulary

| Label | Meaning |
|---|---|
| **Captured** | Packet bytes, timing, or ordering seen in a named capture |
| **Experimentally tested** | Observed working behavior from a controlled local experiment |
| **App-confirmed** | The official app explicitly displayed the outcome |
| **Externally documented** | Published by another reverse-engineering project; applicability may differ by model |
| **Inferred** | Plausible interpretation not yet independently verified |
| **Unknown** | Structure or meaning not established |

Do not turn an inference into a protocol constant. In particular, a value's presence in a packet is not proof of its purpose.

## 2. Ethics, scope, and experimental conditions

This was an educational interoperability experiment conducted with devices under the researcher's control. Devices were not modified, jailbroken, or subjected to firmware patching. No encryption mechanisms were defeated or bypassed.

Authentication experiments used two distinct categories of cryptographic material.

The Body Scan 2 TLS and WPP authentication experiments used a valid KL (authentication key) and advertising key associated with the device. The acquisition method, source, storage location, and actual credential values are intentionally excluded from this publication.

All independent BLE communication, TLS negotiation, authentication, and measurement retrieval were performed locally, without using Withings cloud services or developer APIs.

The experiments demonstrated successful authentication and retrieval of stored measurements. Initial pairing and provisioning of a Body Scan 2 using independently generated credentials have not yet been investigated. Consequently, compatibility with randomly generated keys remains unverified.

The official Withings application was used separately to observe normal device behavior and validate retrieved measurements.
At the conclusion of the experiments, devices were **restored to factory condition and re-provisioned according to Withings requirements**. Experimental changes should not be interpreted as an endorsed configuration or a statement about clinical accuracy.

**Sensitive data:** Packet captures can contain MAC addresses, owner/user IDs, association keys, Wi-Fi SSIDs/passwords, names, and health measurements. Publish sanitized examples only; do not publish raw private captures or secret-bearing TLVs. The private analyzer mode is for local examination, not public distribution.

## 3. Tools, captures, and repeatable methodology

### Equipment and software

- macOS with Apple **Bluetooth PacketLogger** for `.pklg` captures; Wireshark for packet inspection.
- Python scripts for PacketLogger decoding, WPP framing, and experimental BLE interaction (using `bleak` where appropriate).
- Official Withings mobile app for baseline captures and user-visible outcome verification.
- BLE scanner for advertisements and GATT inventory.
- Local device data (including Withings CoreData/SQLite) used **only as an independent comparison source**, not as proof that a field was present on the wire.
- BeamO Explorer as the existing working measurement, ECG, and stethoscope retrieval reference implementation.

### Reference capture set

| Capture | Role |
|---|---|
| `BPM Vision-pairing.pklg` | Original BPM Vision BLE setup, without Wi-Fi credential stage |
| `BPM_Vision-pairing.wifi.pklg` | Full official-app pairing including Wi-Fi setup |
| `beamo-setup(1).pklg` | BeamO setup with multiple Wi-Fi attempts and differing status codes |
| `BeamO(1).pklg` | Large BeamO session, dominated by measurement/data transfer |
| `BeamO.pklg - (null)(1).pklg` | Shorter BeamO identification/connection trace containing `0x0128` |

Record numbers cited below are from prior analysis of these specific files, not stable protocol identifiers. Re-run decoding and confirm handle/direction when porting to another parser.

### Suggested evidence workflow

1. Capture **advertising**, initial connection, GATT discovery, authentication, and one known measurement download.
2. Save the untouched `.pklg` and record device model, app version, firmware **as shown by the device**, and observed measurement timestamp/value separately.
3. Parse HCI records, reassemble ACL/L2CAP, decode ATT, then decode WPP. **Do not skip any layer.**
4. Correlate WPP requests and responses by connection, direction, command, timestamp, and termination markers.
5. Compare one variable at a time across captures; annotate every decoded field with its source bytes and record range.
6. Validate measurement selectors and transfer cursors with **at least two records**, then test interrupted/resumed downloads.
7. Redact identifiers, credentials, network names, and health data before sharing.

## 4. BLE discovery and transport

Observed Withings-specific GATT identifiers:

```text
Service:        00000000-0000-5749-5448-494E47530000
Characteristic: 00000004-0000-5749-5448-494E47530000
```

The characteristic carries WPP requests/responses using ATT writes and notifications/indications as applicable. Confirm characteristic properties and notification setup for each model; a characteristic UUID alone does not describe every connection's behavior.

Unassociated advertisements have been observed with service data under UUID `0xFD77`. The device name convention `BeamO A8`, `BeamO C8`, and `BPM Vision 2E` matches the **last byte of each respective MAC** in the observed devices. This is a supported naming pattern, **not** proof that every Withings product follows it or that the name cannot change.

Distinguish: BLE hardware MAC, CoreBluetooth peripheral UUID, Withings cloud/device ID, Withings account ID (encoded in WPP TLV `0x0135`), and per-user IDs. These are **not interchangeable**.

## 5. WPP framing and conversation reconstruction

### Envelope and TLVs

```text
WPP:  01 | command:uint16_be | payload_length:uint16_be | payload
TLV:       type:uint16_be | value_length:uint16_be   | value bytes
```

For example, a global secondary configuration request observed on BPM Vision is structurally:

```text
01 09 C3 00 0C  01 45 00 04 00 00 00 00  01 00 00 00
|  command length |  TLV target ID (global)  |  end/status TLV
```

The same numeric identifier can appear as a **command** and as a **TLV type** with different meanings: e.g. command `0x09C3` is secondary configuration; TLV `0x09C3` appears in negotiation replies. Likewise, command `0x0100` (general error, externally documented) is distinct from an empty TLV `0x0100` used as a marker.

### Fragmentation is layered

1. HCI ACL fragmentation.
2. L2CAP/ATT reassembly.
3. Individual WPP frames and TLVs.
4. **Logical WPP conversation** reconstruction: multiple frames may form one large response/configuration (notably `0x010D`). An empty `0x0100` TLV may mark completion of a multi-frame response, as documented by `withings-local`.

A parser that decodes each ATT value independently can produce incomplete JSON, false command matches, or missing binary transfers. Preserve raw fragments and source record IDs even after successful reassembly.

### Protocol-level errors

The external `withings-local` documentation describes command `0x0100`, TLV `0x0110`, containing an original command identifier and a signed error value. Published examples include `-2` busy, `-3` unsupported, `-4` rejected, `-5` unauthenticated, `-8` invalid arguments, and `-9` arguments not set. These are **not** the same namespace as Wi-Fi status bytes in `0x0106`.

## 6. Identification and device metadata

Command `0x0101` probes device identity. Captured identification responses include TLV `0x0101` and, in observed sessions, `0x012C`. The `withings-local` protocol documentation describes a length-prefixed identity structure including VID/PID, name, MAC, a distinct device-reported secret, hardware/manufacturer data, bootloader, main firmware, and rescue revision. Validate offsets against each device's actual payload rather than assuming the layout is universal.

For BPM Vision, the captured identification payload contained main firmware **221** (`00 00 00 DD`, big-endian), consistent with the independently observed version. The separately reported **FW2 `1.0.1` was not identified in the analyzed BLE messages**; it must not be injected into an extracted configuration. Likewise, do not copy device IDs from a local database and claim they were extracted from BLE unless a specific message and byte offset establish that.

**Reproduction:** decode the entire length-prefixed identity payload, assert no unexplained trailing bytes where possible, and annotate firmware fields by source TLV and offset. Search for secondary firmware in binary encodings as well as ASCII, but label any candidate unverified until its field boundaries are established.

## 7. Authentication and pairing

### Existing-association challenge: `0x0128`

An already-associated device can issue a probe challenge (`0x0128`; observed TLVs include `0x0122`, `0x0123`, and `0x012A`). The externally documented and previously offline-verified response is:

```python
import hashlib
response = hashlib.sha1(
    device_challenge + mac_ascii + kl_ascii
).digest()
```

- `device_challenge`: 16 raw bytes from the device.
- `mac_ascii`: exact lowercase ASCII MAC representation as supplied by the device (including separators).
- `kl_ascii`: device-specific 32-byte ASCII association key.
- Response: 20-byte SHA-1 digest.

Prior offline analysis reported byte-for-byte matches on three captured BeamO exchanges. **BeamO A8 and C8 are separate hardware identities with separate KLs**; a mismatch obtained with the other device's key does not disprove the algorithm. The app also supplies a challenge to the device, but the reciprocal verification exchange still merits its own explicit byte-level test.

**Security interpretation:** this is a documented authentication mechanism using an existing association key, not a claim that SHA-1 or encryption was broken. Never replay an old digest in place of calculating the response to a fresh challenge.

### Initial-setup negotiation: `0x09B2` and `0x09C1`

These are **separate** from `0x0128` and must not be conflated.

| Exchange | Captured shape | Status |
|---|---|---|
| `0x09B2` request | TLV `0x09C2`, value `0x20` followed by 32 fresh nonce bytes | Captured |
| `0x09B2` response | TLV `0x09C3` includes echoed challenge and device-generated material; TLV `0x09C4` contains additional device material | Captured; cryptographic meaning unknown |
| `0x09C1` response | TLV `0x0961` (observed `01`) and TLV `0x09D3` (32 variable bytes) | Captured; precise semantics unknown |

The full official BPM Vision Wi-Fi setup contained **three** `0x09B2` stages (before Wi-Fi, after Wi-Fi, after ownership). The successful independent **BLE-only** provisioning flow used **two** (`0x09B2` before and after ownership installation). The extra official-app stage is not established as a BLE-only requirement.

### Cross-device authentication observations

The investigated Withings devices share WPP framing and several provisioning commands, but their observed authentication sequences are not identical.

| Device | `0x0128` | `0x09B2` | `0x09C1` |
|---|---|---|---|
| BPM Connect | Observed; error `−6` in repeated pairing attempts | Not observed in analyzed captures | Not observed in analyzed captures |
| Body Smart | Not established | Observed | Error `−3`; provisioning continued |
| BeamO | Observed in existing-association captures | Observed | Successful response |
| BPM Vision | Observed in existing-association captures | Observed | Successful response |

#### Body Smart

During initial provisioning, Body Smart returned error `−3` in response to an empty `0x09C1` request. The provisioning sequence continued afterward.

BeamO and BPM Vision instead returned TLVs `0x0961` and `0x09D3` in their captured `0x09C1` exchanges.

This demonstrates a device-specific difference in observed behavior. It does not establish whether the difference is attributable to firmware, device capabilities, or association state.

#### BPM Connect

Repeated BPM Connect pairing attempts included a `0x0128` challenge/response exchange. The device returned error `−6` following the host authentication response.

A subsequent `0x0110` command received error `−5`.

Both responses were prompt. The official application remained on its configuration screen until a later application-level timeout. The cause of error `−6` remains unresolved.

In a later connection from the longer capture, BPM Connect successfully completed provisioning without a visible repeat of `0x0128` on that connection.

#### Interpretation

These observations establish differences in captured authentication behavior, not distinct formal WPP protocol versions.

The presence or absence of a particular command may depend on device firmware, association state, and provisioning workflow. A command not observed in a capture must not automatically be classified as unsupported.

Detailed command structures and captured error responses are documented in `docs/COMMAND_REFERENCE.md`.

## 8. Ownership and BLE-only provisioning

### `0x0134`: association-key installation

Ownership installation supplies the Withings account ID, KL, and advertiser key.

The captured `0x0134` request contains two TLVs:

| TLV | Length | Description |
|---|---:|---|
| `0x0135` | 37 bytes | Four-byte big-endian account ID, one-byte KL length, and 32-byte ASCII KL |
| `0x0136` | 33 bytes | One-byte advertiser-key length and 32-byte ASCII advertiser key |

The account ID is distinct from the user ID and physical device ID. These identifiers must not be used interchangeably.

In independent BLE-only provisioning experiments, fresh identifiers and credentials were generated rather than reusing credentials from an official account. The installation was followed by further negotiation and configuration.

For sanitized captures, maintain separate mappings for Withings account IDs, per-user IDs, and device IDs. Replace each original identifier consistently wherever it appears, preserving repeated references within its identifier category. Do not infer relationships between identifiers merely because their numeric values happen to match. Global target `0` remains `0`.

The detailed binary layouts are documented in `docs/COMMAND_REFERENCE.md`.

### Working BLE-only sequence

```text
BLE discovery/connect
  → 0x0101 identification
  → 0x09B2 challenge/negotiation
  → 0x09C1 negotiation continuation
  → 0x0134 account ID + KL + advertiser key
  → 0x09B2 post-ownership negotiation
  → 0x010D primary JSON configuration
  → 0x0108 region
  → 0x011A language
  → 0x09C3 global and per-user secondary settings
  → 0x0112 / 0x0113 / 0x0110 finalization (verify exact order per script/capture)
```

This is a description of the **observed working experimental path**, not a universal setup recipe for every model or firmware. The independent runner deliberately **does not send `0x0102` Wi-Fi scans, `0x0103` Wi-Fi credentials, or other Wi-Fi provisioning operations**. It does not call Withings APIs or contact vendor servers.

## 9. Users, feature configuration, and experiments

### Primary configuration: `0x010D`

The official app sends a JSON configuration containing `body.ind` (device settings), `body.sp.users` (profiles), session information, and synchronization parameters. Observed fields include:

```json
{
  "body": {
    "ind": { "stp": 51, "lg": "en_EN", "mit": 60, "mcr": 1, "ft": [57, 83, 84, 85, 106, 107] },
    "sp": {
      "users": [
        { "id": 100001, "sn": "USER", "wt": 70.0, "ht": 1.75, "agt": 40, "sx": 0, "fm": 3, "att": 0, "ft": [100, 105], "fn": "Example" }
      ]
    }
  }
}
```

**Illustrative schema only:** values above are sanitized examples, not a captured message or recommended configuration. Other captured fields include `cr`, `syp.utc`, `syp.fwupd`, `duration`, and `creation_time`. Preserve unknown fields verbatim during analysis rather than deleting them or assigning speculative meanings.

### PacketLogger-validated `0x010D` logical transfer framing (24 October 2026)

**Evidence:** PacketLogger Analyzer v1.1 output for a BPM Vision Wi-Fi provisioning capture and `beamo-setup(1).pklg`. This section describes observed **on-wire framing**; it does not establish that every firmware uses the same transfer format or that all reconstructed content is JSON.

A configuration transfer consists of multiple **independently framed WPP `0x010D` messages**, each carrying a `0x0112` TLV, followed by a `0x010D` message containing an empty `0x0100` TLV and a device acknowledgment using command `0x010D` with a zero-length payload. These messages are **application-level chunks**, not L2CAP fragments.

```text
WPP frame: 01 | command BE16 | payload_length BE16 | TLVs...
Data:      01 01 0D 00 44 | 01 12 00 40 | [64-byte TLV value]
Terminator:01 01 0D 00 04 | 01 00 00 00
Reply:     01 01 0D 00 00
```

In the analyzed captures, each `0x0112` TLV value starts with a **one-byte content-length prefix**, followed by that number of content bytes. Thus a 64-byte TLV value holds 63 content bytes. A decoder should validate that the prefix agrees with the remaining value length before appending content. Concatenate content bytes **in capture order**, scoped to the connection handle and direction; finalize on the empty `0x0100` terminator and associate the subsequent device response. Preserve individual frames and record numbers alongside the reconstructed logical transfer.

| Capture | Handle | Data chunks | Wire TLV bytes | Assembled content | Terminator | Device acknowledgment | JSON status |
|---|---|---:|---:|---:|---|---|---|
| BPM Vision Wi-Fi provisioning | `0x0058` | 11 | 642 | **631 bytes** | Record 4113 | Record 4168 | Valid JSON in private reconstruction |
| BeamO provisioning (`beamo-setup(1).pklg`) | `0x005E` | 6 | 350 | **344 bytes** | Record 7142 | Record 7151 | **Not established** (`json_valid: null` in analyzer output) |

BPM Vision's data-bearing messages span records **4064–4107**; BeamO's span **7122–7140**. The first BPM Vision TLV has length 64 and the final one length 2. BeamO's six TLV lengths are 64, 64, 64, 64, 64, and 30. These lengths are **TLV value lengths**, including the one-byte prefix; they must not be mistaken for JSON/content lengths.

**Important distinctions and limitations:**

- The BPM Vision reconstruction was checked as valid JSON in a private analysis. The public redacted analyzer report alone does not expose or independently prove that JSON structure.
- The BeamO reconstruction demonstrates chunk aggregation and acknowledgment, **not** a successfully decoded JSON document. Do not invent fields or assume a particular encoding.
- A response establishes that an acknowledgment was observed; it does not alone prove that every configuration setting took effect.
- PacketLogger record numbers are local to each capture, not protocol sequence numbers. Transport-reassembly warnings elsewhere in a capture should be retained and investigated, not silently discarded.
- Keep raw captures, Wi-Fi credentials, owner/user identifiers, authentication keys, and unredacted configuration payloads out of the public repository.

See [`docs/examples/BEAMO_PROVISIONING.md`](examples/BEAMO_PROVISIONING.md) for the BeamO record-by-record example and `tools/packetlogger/README.md` for analyzer usage.

### Secondary configuration: `0x09C3`

- TLV `0x0145`: four-byte big-endian target ID (`0` = global; nonzero = user ID).
- TLV `0x09D5`: observed feature setting represented as eight zero bytes, two-byte big-endian feature ID, two-byte big-endian value.
- TLV `0x0100`: observed empty marker/status.

Primary `ind.ft`, per-user `users[].ft`, and secondary global/per-user `0x09D5` settings are **distinct layers**. A feature may require coordinated settings; do not infer sufficiency from one field.

### Experimentally observed feature behavior

| Observation | Evidence and limitation |
|---|---|
| BPM Vision feature `27` | Enabling in `ind.ft` and global/per-user `0x09D5` corresponded to working ECG and AFib detection in the experiment; individual necessity not isolated |
| BeamO features `12`, `15`, `27` | Presence/absence in primary and secondary settings affected available functionality in experiments; feature `12` removal was observed to alter regional-style behavior, but its precise regional meaning is unverified |
| BeamO features `57`, `81`, `82`, `83`–`85`, `133`, `134` | Observed or investigated; do **not** publish speculative feature labels as confirmed definitions |

Device functionality obtained experimentally is **not evidence of clinical safety, regulatory approval, or equivalent firmware behavior**.

## 10. Wi-Fi setup: passive documentation

Wi-Fi was examined **only in official-app captures** to complete the protocol record. The independent BLE runner must not execute these operations.

| Command/TLV | Observed function |
|---|---|
| Command `0x0102` | Wi-Fi network discovery request; responses contain repeated TLV `0x0103` network entries |
| Command `0x0103`, TLV `0x0104` | SSID/password submission; observed format: one-byte SSID length + SSID + one-byte password length + password |
| Command `0x0103` response, TLVs `0x0106`, `0x010A` | Network/setup result and additional device/network information; most internal fields not established |
| Command `0x0109`, TLVs `0x010D`, `0x010E` | Additional post-Wi-Fi operation; exact purpose unresolved |

**Observed first byte of TLV `0x0106`:**

| Code | Interpretation | Evidence |
|---|---|---|
| `0x00` | Wi-Fi setup success | Successful BPM Vision official-app pairing |
| `0x02` | **Wi-Fi authentication failure** | BeamO capture with empty password on a password-protected network; **official app explicitly displayed authentication failure** |
| `0x03` | Unknown Wi-Fi setup failure | BeamO with correct credentials, client blocked in UniFi |
| `0x05` | Unknown Wi-Fi setup failure | BeamO with correct credentials, client blocked in UniFi |

The later BeamO attempts used **the same SSID and password bytes** as the successful BPM Vision attempt. The BeamO was blocked using UniFi's **client → Block** control, which reportedly prevented LAN and internet traffic. This does **not** establish whether `0x03` or `0x05` specifically means DNS, IP configuration, or cloud-server failure. The device may perform its own network exchange during official setup, but BLE captures alone do not prove its remote destination or transaction semantics.

## 11. Measurement inventory, transfer, and associated data

This chapter is derived from the supplied BeamO Explorer Swift implementation (`BeamOBluetooth.swift`, `BeamOMeasurements.swift`, `BeamOSignalDownload.swift`, `BeamOECGView.swift`, `BeamOAudioWaveformView.swift`, and related persistence code) and **32 actual recovered binary signal payloads** in a local BeamO SQLite archive. The Swift source documents a working implementation; behavior of other firmware or device families remains to be verified.

### 11.1 Stored numeric measurements (`0x010F`)

To retrieve the inventory, send WPP command `0x010F` containing TLV `0x0114`, value `01 00` (GET_ALL as implemented). The response is a series of TLVs:

| TLV | Meaning in the implementation |
|---|---|
| `0x0116` | Starts a measurement/session record |
| `0x0117` | Numeric measurement belonging to the current session |
| `0x0993` | One-byte stethoscope recording-position metadata, associated with current session |
| `0x0100` | Logical response terminator |

For inventory `0x0116`, the code reads a four-byte big-endian user ID at offsets **6–9** and a four-byte big-endian parent/session ID from the **last four bytes**. This is a separate `0x0116` layout from the 23-byte signal metadata described below; **interpret TLVs in their command context**.

A numeric `0x0117` is eight bytes: signed BE `int32` mantissa at 0–3, BE `uint16` measurement type at 4–5, and signed BE `int16` base-10 exponent at 6–7. Value = mantissa × 10^exponent. Preserve the raw bytes and unknown type codes; do not synthesize missing results.

#### Body Scan 2: locally authenticated TLS/WPP measurement retrieval (October 2026)

**Evidence: experimentally tested on one Body Scan 2 (model 19); not yet established as universal across models or firmware.**

A local BLE client connected to the Withings service `00000000-0000-5749-5448-494e47530000`, using characteristic `00000005-0000-5749-5448-494e47530000` for the observed session. After a device-specific pre-TLS initialization, the device initiated a TLS handshake and the local client operated as the TLS server. The negotiated connection was TLS 1.3 with `TLS_CHACHA20_POLY1305_SHA256`.

Inside TLS, the existing-association WPP exchange succeeded: identification/probe `0x0101`, challenge `0x0128`, challenge response, and an authenticated `0x0101` response. Authentication used valid, pre-existing device credentials. **The credentials were not supplied directly by Withings.** No Withings cloud API, developer API, or remote authentication service was used for this independent BLE experiment. Credential acquisition, provenance, storage location, and values are deliberately outside the published scope. The separate official-app synchronization used for validation is not represented as an offline app operation.

The following authenticated requests were sent (WPP framing and 16-bit fields are big-endian):

| Operation | WPP bytes | Observation |
| --- | --- | --- |
| GET_STATE | `01 01 0F 00 06 01 14 00 02 00 00` | `0x010F` reply containing `0x0114` and `0x0115` |
| GET_ALL | `01 01 0F 00 06 01 14 00 02 01 00` | Multi-frame `0x010F` measurement transfer |

The GET_ALL response contained repeated `0x0116` session/group metadata, `0x0117` numeric measurement values, `0x0993` attributes, and other observed TLVs (`0x012B`, `0x0149`, `0x014A`, `0x09B9`). An empty `0x0100` TLV was observed at the end of the transfer. The presence of these fields is confirmed; their meaning may depend on device and context. The scale returned decoded weight `104.143 kg` in the test session, and additional body composition, segmental, bioimpedance, and cardiovascular values. Do not infer proprietary type labels from numerical magnitude alone.

The independently retrieved values were compared with local SQLite records after the official application synchronized the same session, including matching numerical values. The independent client did **not** send an explicit measurement acknowledgment, deletion, or sync-completion command. This does not prove that GET_ALL is free of all persistent side effects.



### 11.2 Stored binary signals: pending FIFO (`0x0147`)

The BeamO Explorer implementation requests the **head of the pending signal queue**, without a signal-ID selector:

```text
01 01 47 00 00      # WPP command 0x0147, zero-length payload
```

A logical signal response may span multiple WPP frames and BLE notifications. The signal assembler recognizes:

| TLV | Value length | Interpretation / verified offset |
|---|---:|---|
| `0x0116` | 23 | Signal ID: BE `uint32` at offset 0; parent measurement/session ID: BE `uint32` at offset 19; remaining 15 bytes not fully decoded |
| `0x0143` | 8 | Opaque binary signal descriptor (also sent back during ACK) |
| `0x0146` | 12 | Signal header; expected binary payload length: BE `uint32` at offset 4 |
| `0x0144` | Variable | First byte is chunk length; remaining bytes are waveform payload; require `length_byte == TLV_value_length - 1` |
| `0x0100` | 0 | Logical transfer termination; if no signal metadata/data preceded it, pending queue is empty |

The assembler rejects inconsistent repeated headers, malformed chunks, payloads exceeding the expected length, and a completed transfer with mismatched length. The implementation imposes a **64 MiB** upper bound as a client safety limit, not a demonstrated protocol maximum.

### 11.3 Acknowledgment and advancement (`0x0148`)

After a complete signal has been durably saved, automatic synchronization sends:

```text
Command 0x0148
    TLV 0x0145: 4-byte big-endian signal ID
    TLV 0x0143: 8-byte descriptor, exactly as received
```

The application waits for the `0x0148` response before retrieving the next signal. This is the observed **pending-queue advancement operation**. It is not a transmitted numeric index or byte offset. The actual internal pointer and whether acknowledged recordings are deleted, archived, or merely marked as transferred are unknown.

The supplied `BeamOSignalDownload.swift` assembler is intentionally **read-only** and explicitly does **not** send `0x0148`; the **separate automatic-sync path** in `BeamOBluetooth.swift` does send it after successful persistence. This difference is crucial for replicators: a read-only downloader can inspect the pending head without advancing the FIFO, but cannot iterate the entire pending queue using that mode alone.

**Data-loss precaution:** the client writes each signal to an exclusively created file, calls `fsync`, reads it back, checks byte-for-byte equality, calculates SHA-256, and records it in SQLite before ACK. A future implementation should preserve this ordering and consider ACK a state-changing operation.

### 11.4 Linking recordings to measurements

The signal `0x0116` metadata's `parentID` (bytes 19–22) links to the inventory `0x0116` session ID (last four bytes). **This is an explicit identifier relationship, not a timestamp or transfer-order guess.** A signal can be archived before its parent inventory record and joined later. The inventory may additionally carry `0x0993`, a one-byte stethoscope position code (observed implementation includes 15–19 heart positions, 20–27 lung positions, and 28 wide/general).

### 11.5 Recovered binary formats and independently generated figures

The accompanying archive contains **16 session rows, 40 numeric-measurement rows, 32 recovered binary signals, and 48 stored inventory packets** (counts observed when the report was prepared). Signals include several distinct eight-byte descriptors; **do not treat every signal as ECG or audio**.

**ECG example:** descriptor `00 0D 01 F4 00 02 10 02`, 60,000-byte payload. The supplied decoder treats it as **500 sample frames/s**, two interleaved **signed little-endian 16-bit** streams, four bytes/frame, yielding **15,000 frames / 30 seconds**. The channel meanings (e.g., raw versus filtered) and conversion to millivolts are **not established**. The figure plots both interleaved streams for the first five seconds from one actual recovered payload; the vertical axis is uncalibrated sample counts, **not a clinical ECG interpretation**.

![Recovered BeamO ECG, both stored streams, five-second excerpt](../beamo_ecg_two_streams.png)

**Stethoscope example:** descriptor `00 02 0F A0 01 01 08 01`, 80,000-byte payload. The supplied audio decoder treats it as **G.711 A-law, mono, 4,000 samples/s**: 80,000 encoded samples / 4,000 = **20 seconds**. The figure shows only the decoded waveform envelope (min/max per bucket); no audio, identifying information, medical labels, or raw recordings are published.

![Recovered BeamO stethoscope waveform, image only](../beamo_stethoscope_waveform_example.png)

The figures are produced from the **actual recovered SQLite `signals.payload` bytes**, not simulated or redrawn waveforms. The images omit names, hardware identifiers, user IDs, and timestamps. They are technical decoding examples, **not diagnostic evidence**. The original SQLite database and its WAL/SHM files should **not** be published because they contain personal health data and identifiers.

### 11.6 Suggested reproducible retrieval procedure

1. Discover the Withings BLE characteristic and decode the WPP byte stream with buffering across ATT notifications.
2. Authenticate with the device-specific association key when required.
3. Request `0x010F` / `0x0114=01 00`; collect `0x0116`, `0x0117`, and any `0x0993` until `0x0100`.
4. Request `0x0147` with no TLVs; accumulate `0x0116`, `0x0143`, `0x0146`, `0x0144` until `0x0100`.
5. Validate length and descriptor; save the **original binary bytes**, hash them, and associate `parentID` with inventory session ID.
6. For **explicitly authorized automatic sync only**, send `0x0148` with `0x0145` signal ID and `0x0143` descriptor, wait for acknowledgment, and repeat from step 4. Otherwise stop after a read-only retrieval.
7. Preserve unknown descriptors/TLVs verbatim for future decoding.

## 12. Download cursors, record selection, and resumption

### 12.1 What we now know

The observed BeamO binary-download protocol uses an **implicit device-maintained pending FIFO**, not a client-supplied "next index". `0x0147` retrieves the current pending head; `0x0148` acknowledges a specific signal by its **ID plus descriptor**, then the device advances the queue. `0x010F` separately obtains numerical measurement inventory and session identifiers. The `0x0145` field in this ACK is a **signal ID**, whereas `0x0145` in provisioning `0x09C3` identifies a **configuration target**: interpret by command context.

### 12.2 What remains unknown

- Whether the device permanently deletes, hides, or flags a recording after `0x0148`.
- Whether FIFO position survives power loss, factory reset, or interrupted ACK.
- Whether separate signal classes/users have separate queues.
- Whether there is another command to retrieve an arbitrary historical signal **by ID**; the supplied working downloader uses no such selector for `0x0147`.
- Exact behavior when ACK response is lost and the client retries; duplicate-safe synchronization needs testing.

### 12.3 Reproduction tests

Capture a queue with at least three known signals; fetch without ACK twice to test whether the head remains stable; then ACK only after durable storage and confirm the next signal ID. Interrupt a transfer before ACK and verify behavior after reconnect. Never assume an ACK is reversible. Keep the test device isolated from vendor cloud traffic when conducting independent BLE-only experiments.

## 13. Command and TLV reference

The same numeric value can name a command or TLV; context is mandatory.

| Command | Function / current interpretation | Confidence |
|---|---|---|
| `0x0100` | General WPP error response | External |
| `0x0101` | Probe / identification | Captured |
| `0x0102` | Wi-Fi scan | Captured |
| `0x0103` | Wi-Fi credentials / response | Captured |
| `0x0104` | Additional Wi-Fi-related operation in BeamO setup | Observed; unresolved |
| `0x0105` | Battery | Captured/external |
| `0x0108` | Region | Captured |
| `0x0109` | Post-Wi-Fi operation | Captured; unresolved |
| `0x010D` | Primary JSON configuration/session | Captured |
| `0x010F` | Stored/numeric measurement operations | Prior implementation/external |
| `0x0110` | Setup completion stage | Captured |
| `0x0111` | Connection reason | Captured/external |
| `0x0112` | Setup/settings stage | Captured; model-dependent |
| `0x0113` | Setup completion/acknowledgment | Captured/external |
| `0x0116` | Inventory in prior BeamO investigation | Prior implementation; validate |
| `0x0118` | Additional data-transfer messages | Captured; partially decoded |
| `0x011A` | Language | Captured |
| `0x0128` | Existing-association challenge | Offline verified |
| `0x0134` | Association/ownership key installation | Experimentally tested |
| `0x0147` | Binary measurement data | Prior Explorer implementation |
| `0x0501` | Time setting | External |
| `0x09B2` | Setup negotiation/challenge | Captured |
| `0x09C1` | Setup negotiation continuation | Captured |
| `0x09C3` | Secondary global/per-user configuration | Experimentally tested |

Selected TLVs:

| TLV | Context | Interpretation |
|---|---|---|
| `0x0100` | Multiple exchanges | Empty marker/status; distinguish from command `0x0100` |
| `0x0103` | Wi-Fi scan response | Network entry |
| `0x0104` | Wi-Fi credentials | Length-prefixed SSID and password |
| `0x0106` | Wi-Fi result | First byte status |
| `0x010A` | Wi-Fi result | Additional network/device data; mostly unknown |
| `0x0110` | General error | Original command and signed error code (external) |
| `0x0114`–`0x0117` | Measurement family | Action, status, metadata, typed values (external) |
| `0x0122`, `0x0123`, `0x012A` | `0x0128` | Challenge, response, app probe |
| `0x0145` | `0x09C3` | Global/user target ID (BE uint32) |
| `0x0961`, `0x09D3` | `0x09C1` | Negotiation response fields |
| `0x09C2`, `0x09C3`, `0x09C4` | `0x09B2` | Challenge and device reply fields |
| `0x09D5` | `0x09C3` | Feature ID/value setting |

Unknown identifiers must remain visible in decoded reports with raw bytes and source locations. A protocol dictionary is a convenience, not a substitute for validating the capture.

## 14. How to reproduce and extend the research

### Phase A — Read-only capture and decoding

1. Record device identity and firmware **separately** from the capture.
2. Capture official-app interaction with PacketLogger; preserve original files.
3. Run a `.pklg` analyzer in private mode **locally** to retain raw values; redact before publishing.
4. Reassemble WPP across ATT frames and inspect identification, `0x0128`, and measurement inventory.
5. Cross-check against a known displayed measurement without importing assumptions from SQLite.

### Phase B — Verify authentication offline

1. Identify the `0x0128` device challenge and exact MAC ASCII bytes.
2. Use only the matching device's legitimate KL.
3. Calculate SHA-1 over `challenge || MAC_ASCII || KL_ASCII`.
4. Compare the resulting 20 bytes with the captured app response.
5. Label the result match, mismatch-with-correct-key, or not-verifiable; never confuse two physical devices.

### Phase C — Map measurement transfers

1. Capture at least two numeric measurements plus ECG/audio objects.
2. Correlate inventory identities, measurement group, waveform/audio selector, and binary transfer.
3. Determine binary chunk boundaries, order, completeness, and integrity checks.
4. Test the **pending FIFO** using `0x0147` and (only after verified persistence) `0x0148`, including resumption as in §12.
5. Do not infer missing records, invent segmental data, or assume chronological adjacency proves an association.

### Phase D — Controlled BLE-only provisioning

1. Use a device under your control and preserve a reliable factory-recovery path.
2. Capture the original configuration and identity relationships.
3. Generate new unique owner/user IDs while preserving any captured owner=user equivalence; generate fresh KL and advertiser key.
4. Use only the known local BLE provisioning sequence and known configuration fields.
5. **Reject** Wi-Fi scan, Wi-Fi credential submission, and cloud operations in the experimental runner.
6. Verify locally visible users and functions; restore official provisioning when finished.

### Safe publication checklist

- [ ] All captures sanitized; no private `.pklg` or `--private` JSON uploaded.
- [ ] No owner/user IDs, MACs, KLs, advertiser keys, SSIDs, passwords, names, or identifiable health readings in examples.
- [ ] Unknown fields remain marked unknown; capture-derived values include provenance.
- [ ] No claim of medical certification or security defeat.
- [ ] MIT license file included for code; third-party dependencies retain their own licenses.
- [ ] Experiments can be repeated without contacting Withings servers through the independent tools.

## 15. Open questions and contribution roadmap

### Highest priority

1. **Validate pending-FIFO semantics under interruption and retry.** The supplied Explorer code establishes `0x0147` retrieval and `0x0148` ACK/advance; verify persistence, duplicate ACK behavior, and whether historical random-access retrieval exists.
2. Implement complete **WPP conversation reassembly**, including multi-frame `0x010D` JSON and binary transfers, with packet-level provenance.
3. Reconstruct the three official BPM Vision `0x09B2` exchanges, compare the two BLE-only exchanges, and determine the role of the additional pre-ownership exchange without inventing cryptographic semantics.
4. Decode the complete `0x0101` identification structure for each device and search for secondary firmware fields without hardcoding FW2.
5. Verify the **reverse** `0x0128` challenge calculation with captured device response bytes.

### Additional research

- Differentiate persistent sync cursors from explicit object selectors and post-upload acknowledgments.
- Correlate numeric measurements and binary ECG/audio with independently known record IDs; publish sanitized multi-record fixtures.
- Determine command `0x0109` and the remaining Wi-Fi response fields **offline**, without adding Wi-Fi execution to the runner.
- Characterize feature settings per firmware/model through one-variable experiments; avoid broad unsupported feature tables.
- Build an evidence-backed device profile format with firmware, capabilities, commands, and unknown TLVs; generate random experimental identity mappings consistently.
- Document general error responses and device-initiated request flags (`0x4000` reported externally), validating them against real captures.

### Related work

- [`pierosavi/withings-local`](https://github.com/pierosavi/withings-local) — independent WPP reverse engineering and [protocol notes](https://github.com/pierosavi/withings-local/blob/main/docs/protocol.md), especially identification, existing-device authentication, errors, time, and stored measurement framing.
- Existing BeamO Explorer implementation — primary project-specific reference for measurement, ECG, stethoscope, and download selection behavior. The report now documents the implemented command/TLV layouts; source release is not required for independent reproduction.

## License and disclaimer

### MIT License — code

**All code released as part of this project is licensed under the MIT License.** Include the full MIT license text in the repository's `LICENSE` file and retain copyright and permission notices as required by that license. This report is technical documentation; the repository should explicitly state the documentation license if one is desired, rather than assuming that a code license automatically settles all documentation reuse questions.

### No warranty; educational use only

This work is provided **“AS IS,” without warranty of any kind**, including merchantability, fitness for a particular purpose, accuracy, security, reliability, or noninfringement, to the extent permitted by law. Use of the research or code is at the user's own risk. It is **not medical advice** and does not certify any device function for diagnostic or clinical use.

This is an **independent educational research project**, not affiliated with, endorsed by, or supported by Withings. Device behavior can change across models, firmware, regions, and app versions. The independent experiments did not interact with Withings servers. Devices were not modified or jailbroken; no encryption protections were defeated or bypassed. At the end of the experiments, devices were factory-restored and re-provisioned using Withings' normal requirements.

**Withings** and the names of its products are trademarks of their respective owner(s).

---

*Contributions are welcome when accompanied by a sanitized capture, source reference, reproducible test, or clearly labeled hypothesis. Prefer precise evidence to plausible but unsupported decoding.*
