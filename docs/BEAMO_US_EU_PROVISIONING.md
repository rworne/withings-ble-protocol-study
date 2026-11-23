# BeamO: US and EU provisioning over BLE/WPP

**Updated:** 2026-11-23  
**Scope:** Captured official-application provisioning exchanges, firmware 781 static analysis, and offline execution of selected firmware routines.  
**Companion:** [WPP command reference](COMMAND_REFERENCE.md), [protocol report](PROTOCOL.md).

This document follows BeamO from BLE connection through identification, authentication, configuration delivery, profile feature settings, and completion. It compares a confirmed US unit with a confirmed EU unit. It describes observed behavior, not an official specification or a universal setup sequence.

No MAC addresses, account/user identifiers, names, association keys, authentication challenges/proofs, session tokens, Wi-Fi credentials, or measurements are included. Packet numbers in this document are **one-based Wireshark frame numbers**. The older analyzer/example documents use **zero-based record indices**; for the same capture, frame number = record index + 1. Packet numbers refer to the private source captures and permit the owner to reproduce the analysis; the captures are not included with this document.

## 1. Evidence and terminology

| Label | Meaning |
|---|---|
| **Captured** | Directly observed in a decoded BLE exchange |
| **Firmware** | Established from a traced code/data path in the supplied firmware |
| **Emulated** | Selected firmware routines executed offline with synthetic profiles |
| **Owner-observed** | Behavior reported from experiments on the owner's units |
| **Unresolved** | Meaning or causal relationship not yet demonstrated |

### Source material

| Source | Relevant contents |
|---|---|
| `beamo-probe.pklg - (null).pklg` | US BeamO identification and existing-association handshake; no full provisioning |
| `beamo-setup.pklg` | US probe, followed by EU setup including Wi-Fi and association-key installation |
| `beamo-update.pklg` | Identification and configuration refresh for both confirmed regional units |
| Firmware artifact described below | BeamO firmware 781, used to trace storage, activation, algorithm selection and profile isolation |

The filename `beamo-update.pklg` does not by itself mean that the configuration sequence documented here is a firmware installation. Configuration refresh and firmware-image transfer are different operations.

The firmware is 1,326,820 bytes, SHA-256:

```text
e1da7439eda074c924e853d2c57ab178d8b36a6f1222d688c224f56484449052
```

Its header word at file offset `0x14` is `0x0000030D` (781). Its firmware getter independently reads 781 from the application image. Main-image file offset `0x6C` maps to runtime address `0x08008000`, with segment length `0xBDD80`. Addresses below use that mapping.

### Regional identity is not firmware version

| Field in the comparison capture | US unit | EU unit |
|---|---|---|
| Reported name | BeamO | BeamO |
| Manufacturing ID | `002E0080` | `002E0080` |
| Bootloader version | 4 | 4 |
| Firmware at capture time | 691 | 781 |
| Provisioned `body.ind.mcr` | 1 | 0 |
| Configured Wi-Fi country | `US` | `US` |

The owner confirmed the regional identity of both units. The owner also reports that the latest US and EU firmware versions are identical, and that EU provisioning temporarily changes the US unit's behavior until the official application restores US provisioning. Consequently **691 versus 781 is a capture-time observation, not a general regional identification rule**.

`002E0080`, shown beside the factory icon, matches the manufacturing ID reported over WPP. It does not distinguish these regional units. Wi-Fi country and language also must not be treated as feature-region identifiers.

## 2. Transport and message framing

The study's Withings service UUID is `00000000-0000-5749-5448-494E47530000`; its WPP data characteristic UUID is `00000004-0000-5749-5448-494E47530000`.

In the analyzed captures:

| ATT operation | Observed handle | Purpose |
|---|---|---|
| Write Request, opcode `0x12` | `0x000C` | Application-to-device WPP data |
| Handle Value Notification, opcode `0x1B` | `0x000C` | Device-to-application WPP data |
| Write to CCC descriptor | `0x000D` | Enable/disable notifications |

Handles are capture-specific; discover characteristics by UUID rather than hard-coding handles across devices.

```text
WPP frame:
    version:u8 | command:BE16 | payload_length:BE16 | payload

Observed version:
    01

TLV within payload:
    type:BE16 | value_length:BE16 | value[value_length]
```

The five-byte WPP header is excluded from `payload_length`. Command IDs and TLV IDs are separate namespaces: command `0x09C3` is not TLV `0x09C3`, and command `0x0112` is not the JSON-chunk TLV `0x0112`.

Reassemble the BLE/ATT transport before parsing WPP. Then buffer until the declared WPP frame length is available. A larger logical transfer can span several complete WPP frames. An ATT packet, WPP frame, and complete configuration document are not necessarily the same boundary.

## 3. End-to-end provisioning flow

```mermaid
sequenceDiagram
    participant A as Official application
    participant D as BeamO
    participant S as Withings backend
    A->>D: BLE connection, GATT discovery, notifications
    A->>D: 0x0101 probe
    D-->>A: Identity or 0x0128 authentication challenge
    A->>D: Existing-association proof when required
    D-->>A: Identity and reciprocal proof when applicable
    A->>D: 0x0111 connection reason; 0x0105 battery
    A->>D: 0x09B2 / 0x09C1 negotiation
    Note over A,D: Initial setup may additionally configure Wi-Fi and install association keys
    Note over A,S: Backend provisioning acquisition is not directly visible in these BLE captures
    A->>D: 0x010D chunked session/configuration JSON
    D-->>A: 0x010D response
    A->>D: 0x09C3 profile-targeted feature records
    D-->>A: 0x09C3 response
    A->>D: Country, locale and additional settings/completion stages
    A->>D: 0x0110 disconnect
    D-->>A: Response
```

The diagram separates the observed BLE delivery from the inferred upstream backend transaction. The BLE capture contains the configuration forwarded by the application, not a packet capture of the application's HTTPS connection. The backend acquisition may occur earlier or overlap other work.

### 3.1 Identification and existing-association authentication

The application sends command `0x0101`, containing:

- TLV `0x012A`: six-byte application information structure.
- TLV `0x0976`: one-byte option observed as `01`.

An already-associated device can answer with command `0x0128`, TLV `0x0122`, instead of immediately returning its full identity. The application responds with command `0x0128`, including application information, an authentication proof in TLV `0x0123`, and a challenge structure in TLV `0x0122`. Successful continuation returns command `0x0101` with identity TLV `0x0101` and, where applicable, a reciprocal proof.

The companion reference documents the separately verified SHA-1 existing-association proof. That mechanism must not be confused with the `0x09B2` negotiation or the firmware's native server-session authentication.

The decoded identity includes the name, MAC address, manufacturing ID, bootloader and firmware values. Both regional units use the same initial command/TLV structure and field lengths. Their addresses and authentication material differ, as expected for distinct devices. A two-byte battery/status response also differs; that difference is not established as regional.

**No decoded initial-handshake field explicitly labels these units US or EU.** Opaque authentication fields have not been exhaustively assigned meanings.

### 3.2 Negotiation: `0x09B2` and `0x09C1`

| Command / direction | TLV | Observed value size and structure |
|---|---|---|
| `0x09B2`, app → device | `0x09C2` | 33 bytes: `20` followed by 32 bytes |
| `0x09B2`, device → app | `0x09C3` | 70 bytes of negotiation material |
| `0x09B2`, device → app | `0x09C4` | 65 bytes, including a length-prefixed 64-byte field |
| `0x09B2`, device → app | `0x0100` | Empty completion marker in the observed response |
| `0x09C1`, device → app | `0x0961` | One byte, observed as `01` |
| `0x09C1`, device → app | `0x09D3` | 33 bytes, including 32 opaque bytes |

Negotiation can repeat around setup stages. Its exact cryptographic roles remain unresolved; packet sizes alone do not establish a key-exchange or signature algorithm.

### 3.3 Initial setup: Wi-Fi and association credentials

The EU setup in `beamo-setup.pklg` contains the following additional steps. These are not required to appear during every later configuration refresh.

| Operation | Command | Relevant packets |
|---|---|---|
| Wi-Fi-related preparation and scan | `0x0104`, `0x0102` | 3917–4325; another scan at 6278–6354 |
| Wi-Fi country | `0x0108` | 4327/4346; 6356/6361 |
| Language | `0x011A` | 4347/4356; 6362/6367 |
| Wi-Fi credential/result exchanges, including retries | `0x0103` | 4830–6030 |
| Interface settings / Wi-Fi enable controls | `0x0109` | 6947/6952 |
| Repeated negotiation | `0x09B2` | 6975–6984 |
| Association credential installation | `0x0134` | 7083/7085 |
| Repeated negotiation | `0x09B2` | 7092–7102 |
| Session/configuration JSON | `0x010D` | 7123–7152 |
| Country and language reapplication | `0x0108`, `0x011A` | 7153–7167 |
| Profile feature settings | `0x09C3` | 7169–7179 |
| Additional setup and completion | `0x0112`, `0x0113` | 7184–7210 |
| Disconnect | `0x0110` | 7291/7293 |

Credential installation command `0x0134` contains TLV `0x0135` (37 bytes: account ID and length-prefixed association key/KL) and TLV `0x0136` (33 bytes: length-prefixed advertiser key). Account identity, user identity and device identity are distinct. No credential values are reproduced here.

### 3.4 Session JSON transfer: `0x010D`

The application forwards the session/configuration document through repeated command `0x010D` frames containing TLV `0x0112`.

```text
TLV 0x0112 value:
    chunk_length:u8 | text[chunk_length]
```

Full observed chunks have a 64-byte TLV value: one length byte (`3F`) and 63 text bytes. **Remove the length byte from every chunk before joining the text.** Concatenating complete TLV values inserts length bytes into the JSON and corrupts reconstruction.

The application finishes the logical transfer with an empty TLV `0x0100`; the device responds with command `0x010D`. The reconstructed documents in the regional comparison both have `status: 0`.

The following are exact non-sensitive **excerpts**, not complete documents or replay payloads:

EU:

```json
{"ind":{"stp":19,"tmp":13,"mcr":0,"ft":[15,27,57,81,82,83,84,85,133,134]}}
```

US:

```json
{"ind":{"stp":19,"tmp":13,"mcr":1,"ft":[12,57,81,82,83,84,85]}}
```

In the complete document, `ind` is under `body`. Other fields include session information, time configuration, user records, duration and creation time. The named user objects in these particular documents **do not contain `ft` fields**. Per-profile feature settings are delivered separately in the subsequent WPP records.

The `mcr` values correlate with the confirmed regional units. BeamO persists the parsed classification-region field under key `0x011F`. The same key/field family selects EU/US blood-pressure classification in the separately studied BPM Vision firmware; BeamO should not be described as implementing blood-pressure measurement on that basis.

### 3.5 Feature configuration: `0x09C3`

| TLV | Value format | Interpretation |
|---|---|---|
| `0x0145` | `target_id:BE32` | Selects the target profile/group for following tag records |
| `0x09D5` | Two BE32 fields, then `tag_id:BE16`, `value:BE16` | Feature record; the first eight bytes are zero in these captures and their broader meaning is unresolved |
| `0x0100` | Empty | Ends the transfer and triggers application/persistence in the inspected path |

Target selection can change within one WPP frame and can continue across frames. **Do not reset the selected target merely because a new frame begins.** In the US capture, one profile's final tag is in the next frame, and guest records also span frames.

An empty device response is an acknowledgment, not evidence that every supplied tag was retained: the firmware filters unsupported IDs before storing records.

In this BeamO firmware, target **0** occupies the guest/no-selected-user slot. The older reference's shorthand “global target” must not be interpreted as automatic defaults inherited by every named user.

## 4. Exact regional comparison

### 4.1 Delivered profile settings

The table lists transmitted ID/value pairs. Unsupported IDs can be transmitted without being stored by firmware 781.

| Device and target | Delivered tag settings |
|---|---|
| EU: named profile A | `15=1, 27=1, 81=1, 82=1, 133=1, 134=1` |
| EU: named profile B | Same as A |
| EU: Guest (`0`) | Same as A |
| US: named profile A | `80=1, 81=1, 82=1` |
| US: named profile B | Same as A |
| US: named profile C | Same as A |
| US: Guest (`0`) | `12=1, 80=0, 81=1, 82=1` |

Thus the US guest's requires-review flag is **not** a device-wide flag applied to all named users. A user-level ECG activation state is distinct from guest mode and from the device-level JSON list.

### 4.2 Packet index in `beamo-update.pklg`

The EU and US exchanges overlap in time on separate BLE links. Track the link as well as packet order.

| Stage | EU link `0x004C` | US link `0x004B` |
|---|---|---|
| Probe/authentication and identity | 17490–17520 | 17494–17527 |
| Connection reason / battery | 17521–17558 | 17529–17555 |
| `0x09B2` negotiation | 21623–21644 | 24016–24044 |
| `0x09C1` continuation | 21664–21671 | 24058–24063 |
| JSON chunks | 21683–21705 | 24086–24114 |
| JSON completion/response | Through 21710 | Through 24118 |
| Inventory / pending-signal requests | 21711–21718 | 24119–24128 |
| Profile feature settings | 21724–21734 | 24132–24153 |
| Additional raw-data-related operations (`0x0117`, `0x0118`, `0x0135`) | 21735–22345 | 24154–24482 |
| Wi-Fi country / language | 22346–22352 | 24483–24493 |
| Additional settings stage `0x0112` | 22353–22355 | 24494–24499 |
| Disconnect `0x0110` | 22438/22440 | 24573/24577 |

The raw-data-related commands are interleaved synchronization work, not established prerequisites for feature provisioning. Their contents are outside this document's scope. Command `0x0135` here is not credential TLV `0x0135` inside command `0x0134`.

A further firmware-781 probe appears at packet 23657 on link `0x004D`; it must not be mistaken for the US unit's link `0x004B`.

## 5. Feature-code map and actual precedence

The installed application (version 26.46.0) exposes `WTConstants.FeatureID.name`. Offline execution of that getter resolves the names below. Its raw-value getter is an identity return, confirming that these are the numeric feature IDs rather than unrelated enum ordinals. App names establish intended labels, not proof that every firmware implements the feature.

| Decimal / hex | Established behavior | Qualification |
|---|---|---|
| **80 / `0x0050`** | App name: **ECG No Library**; basic ECG activation and fallback selector | Present on the US named profiles; not by itself proof of a particular consent workflow |
| **27 / `0x001B`** | App name: **ECG SW2**; ECG activation plus newer analysis variant | On selects algorithm version constant `0x01060401` (1.6.4.1) |
| **15 / `0x000F`** | App name: **SpO2 Medical**; SpO₂ activation fallback | Used when legacy tag 3 is missing |
| **81 / `0x0051`** | App name: **Body Temperature**; temperature activation | Associated with the temperature activation tutorial |
| **82 / `0x0052`** | App name: **Heart Respiratory Sounds**; stethoscope recording | Associated with the sound-recording activation tutorial |
| **12 / `0x000C`** | App name: **ECG Requires Review**; ECG recording hidden from the user | Owner-observed: records an ECG while hiding the waveform and results from the user. **Not ECG authorization**; full algorithm effects and the review-clearing workflow remain unresolved |
| **3 / `0x0003`** | App name: **SpO2 Non-Medical**; legacy activation check | Takes precedence over tag 15 when present |
| **4 / `0x0004`** | App name: **ECG SW1**; legacy ECG activation/algorithm fallback | Checked by some routines; not in firmware 781's accepted-tag table |
| **49 / `0x0031`** | App name: **Eyes-Closed Mode** | Accepted by the firmware filter; no BeamO-specific consumer established |
| **57 / `0x0039`** | App name: **How to Use** | Tutorial/help eligibility; precise app behavior not yet traced |
| **83 / `0x0053`** | App name: **Share Healthcare Professional** | Healthcare-professional sharing feature, not a physiological measurement toggle |
| **84 / `0x0054`** | App name: **Share Family** | Family-sharing feature |
| **85 / `0x0055`** | App name: **Share Device** | Device-sharing feature |
| **133 / `0x0085`** | App name: **StethoMe medical** | Medical stethoscope-analysis eligibility label; exact activation path unresolved |
| **134 / `0x0086`** | App name: **eMurmur medical** | Medical stethoscope-analysis eligibility label; exact activation path unresolved |

The app's feature namespace includes tutorial, sharing and medical-analysis capabilities as well as hardware measurement activation. This explains why `body.ind.ft` must not be treated as a list of switches that all execute inside BeamO firmware.

IDs 57, 83, 84, 85, 133 and 134 remain outside the inspected firmware-781 per-profile allow-list. Their app names do not contradict that filtering result: a feature can be understood by the app/backend while being ignored by this firmware handler. The names alone do not establish where StethoMe/eMurmur analysis executes.

Tag 12's name, **ECG Requires Review**, is a state/restriction label. It does not make tag 12 the per-user ECG authorization switch. The owner's corrected observation is that BeamO records an ECG while hiding the waveform and results from the user. This supersedes the earlier waveform-only description. The firmware display checks support a restricted presentation mode; they do not independently establish the complete review workflow or what clears the state.

### 5.1 Missing is not the same as off

The profile getter returns success for an existing tag, with its low bit written as the on/off value. Missing tags return `−1`. Consequently a tag can be:

1. Absent.
2. Present and off.
3. Present and on.

Higher bits of a stored value are not used by these boolean checks. Avoid generalizing that observation to every WPP setting.

### 5.2 ECG menu activation

```text
if selected profile has tag 27:
    use tag 27's on/off value
else if selected profile has tag 80:
    use tag 80's on/off value
else:
    leave the entry's existing activation state unchanged
```

Examples established by offline execution:

| Profile tags | Menu activation result |
|---|---|
| `80=1`, no 27 | On |
| `80=0`, no 27 | Off |
| `27=0, 80=1` | Off: explicit 27 overrides 80 |
| `27=1, 80=0` | On: explicit 27 overrides 80 |

Both ECG and combined ECG/SpO₂ menu entries use this ECG activation path. The combined measurement's presentation is also affected by other feature checks; do not reduce the full combined mode to this one test.

The explicit activation/check routine has an additional legacy fallback: **27 → 4 → 80**, using the first present tag's value. The menu-state updater skips tag 4. These are separate paths, not contradictory implementations of one identical function.

### 5.3 ECG algorithm selection is a different rule

```text
if tag 27 is on:
    select variant 27, algorithm version 1.6.4.1
else if legacy tag 4 is on:
    select variant 4, algorithm version 1.1.2.0
else:
    select variant 80; this path reports algorithm version 0
```

Here an off tag permits the next algorithm choice, whereas the menu activation path stops at the first **present** tag. Therefore menu eligibility and algorithm selection must be analyzed separately.

A zero algorithm-version return is not proof that no signal processing of any kind takes place. A standalone “Afib Enable” ID has not been independently established.

### 5.4 SpO₂ and other activation checks

- SpO₂: use tag **3** if present, otherwise tag **15**.
- Temperature: check tag **81**.
- Stethoscope: check tag **82**.
- Tag **12** is checked separately from those activation flags and the ECG activation rule.

The measurement table links those checks to specific tutorial prompts, including “Visit the app tutorials to activate ECG recording.” This supports a user-activation workflow. It does not by itself identify the exact legal/consent conditions enforced upstream.

### 5.5 Profile isolation and persistence

The inspected implementation stores up to **nine profile slots**, each containing a user ID and up to **eight feature records**, under persistent key `0x013B`.

Lookup matches the selected user ID exactly. It **does not automatically fall back to target 0** when a named user's tag is absent. With no selected user, the current-user getter returns 0, causing the guest slot to be used.

The BLE parser assembles settings in a working buffer and applies them on the empty `0x0100` marker. A target declaration selects and clears that target's working slot before its feature records are added. This is not simply an append-only list of independent global flags.

The accepted per-profile IDs in firmware 781 are:

```text
80, 12, 3, 15, 81, 82, 27, 49
```

Both the inspected BLE and direct-server feature insertion paths use this filter. Its rejection of IDs 133/134 demonstrates why an acknowledged write must not be taken as proof of an enabled function. Other processors, firmware versions, or application-level uses remain possible.

## 6. Device-wide list versus user authorization

Three layers must remain distinct:

| Layer | What is established |
|---|---|
| `body.ind.ft` | Device-level list delivered in the session/configuration document; different between these US/EU units |
| WPP target-specific feature records | Effective per-profile values sent later by the application and stored by the inspected firmware |
| Measurement activation/display/algorithm checks | Firmware consumers use the selected profile and apply their own precedence rules |

The inspected session JSON schema enumerates `lg`, `stp`, `tmp` and `mcr` under `ind`; it does not enumerate `ft`. Its named-user schema likewise does not establish a session-JSON `ft` inheritance mechanism. The records in these captures contain no named-user JSON `ft` fields.

Therefore **“device-wide defaults, then user overrides” is a useful hypothesis for upstream policy, not a demonstrated generic firmware merge rule**. The application/server may resolve eligibility and authorization before sending effective WPP tags. Proving that requires tracing the producer of the WPP records.

The owner reports that US ECG use requires per-user authorization. The captured named-user `80=1` states are consistent with activation having been granted, but these captures do not contain a controlled before/after authorization comparison. Guest's `12=1, 80=0` must not be relabeled as that authorization.

## 7. Country, language, classification and market identity

Wi-Fi country command `0x0108` uses TLV `0x0108` with an operation byte, status byte, and length-prefixed country string. The captured set exchange contains:

```text
00 00 02 55 53
|  |  |  └── ASCII US
|  |  └───── string length 2
|  └──────── status byte, 0 in the observed response
└─────────── operation 0: set
```

Language command `0x011A` carries TLV `0x0121`, observed as `02 65 6E` (length 2, `en`).

The EU unit receives Wi-Fi country `US` while its JSON contains `mcr: 0`. These are demonstrably different settings. Neither English language nor a US Wi-Fi country establishes US medical-feature eligibility.

Firmware also contains a native server-session request builder using `auth` (MAC identity), an authentication hash, `mfgid`, `currentfw`, battery level, duration, trademark and network fields. Its hash input incorporates a persistent device secret. This establishes an authenticated per-device identity path that could support a manufacturing-record lookup.

**Unresolved:** the server's actual regional-selection rule. It could use a device identity/manufacturing record or additional policy inputs. Neither a matching manufacturing ID nor the absence of a readable region field proves which lookup is used. The native firmware request builder is not proof that the companion application constructs its BLE-assisted request identically.

## 8. Firmware evidence index

| Runtime address / location | Role |
|---|---|
| `0x0801400C` | Current selected user ID; 0 when no user selected |
| `0x080140D4` | Explicit measurement activation check, including legacy fallback |
| `0x080141A0` | Measurement-menu activation update |
| `0x08083180` | Measurement-to-activation-tag and tutorial table |
| `0x0803519C`; localization table `0x08082668` | Resolves labels such as ECG, temperature, SpO₂ and stethoscope |
| `0x080322E8` | Exact profile lookup |
| `0x08075B4A` | Tag presence/value getter |
| `0x08032508` | Supported-tag filter |
| `0x0808A216`; file `0x82282` | Eight accepted tag IDs |
| `0x08032534` | BLE profile/tag parser |
| `0x08032334` | Apply/persist profile-tag table |
| `0x0807E946` | Direct-server feature insertion using the same supported-tag filter |
| `0x0806EE62` | Tag-12 helper and its distinct mode-dependent result |
| `0x0806EE8E` | ECG algorithm selector |
| `0x080186C8` | ECG algorithm-version selection |
| `0x08049128`–`0x08049170` | Persist parsed classification region under key `0x011F` |
| `0x080858BC` → `0x080856C4` | Session JSON `ind` schema |
| `0x080493C0` | Native server-session request construction |

**Offline validation:** 36 passing cases cover ECG selector precedence, tag-12 boolean behavior, the accepted-tag filter, profile isolation, and ECG menu-state precedence. These are synthetic routine-level checks, not physical-device validation of every feature combination or every provisioning stage. No server request or device write was made during this analysis.

### App feature-name evidence

- App version: **26.46.0**.
- Framework: `WTConstants.framework/WTConstants`.
- `WTConstants.FeatureID.name` getter: `0x0005C058`.
- `WTConstants.FeatureID.rawValue` getter: `0x000067F0` (identity return).
- Offline decoded IDs: 3, 4, 12, 15, 27, 49, 57, 80, 81, 82, 83, 84, 85, 133, 134.
- Framework SHA-256: `ecf658efe2229bab7c04e1c8baad04f7e22dc660e2a2894d3fef60bdbfbd691f`.

These lookups map numeric IDs to human-readable names without loading the app, contacting a server or configuring a device. The firmware traces establish runtime behavior separately.

## 9. Remaining work

1. Capture a controlled US user before and after ECG authorization, preserving target relationships while removing personal data.
2. Trace how the official application converts backend eligibility and authorization into WPP target/tag records.
3. Trace the app consumers of the now-named IDs: establish any BeamO-specific effect of Eyes-Closed Mode (49), the exact tutorial/sharing workflows (57/83/84/85), and the activation/execution paths for StethoMe/eMurmur medical features (133/134).
4. Establish whether a separate Afib permission exists or whether availability follows ECG algorithm selection and other policy inputs.
5. Determine whether tag 12 affects analysis execution in addition to its observed display behavior.
6. Repeat firmware analysis against another version before generalizing the accepted-tag list or profile rules.

This document describes interoperability research. It does not establish medical validity, regulatory authorization, or clinical suitability of a function enabled by a configuration change. Withings and BeamO are trademarks of their respective owners; this study is independent and unaffiliated.
