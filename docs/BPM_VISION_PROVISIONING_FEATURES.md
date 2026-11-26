# BPM Vision: provisioning and feature behavior

**Updated:** 2026-11-23

**Scope:** BPM Vision firmware 221, its WPP setup sequence, device/user configuration and region handling.

**Related:** [Body Scan 2 provisioning](BODY_SCAN_2.md), [WPP command reference](COMMAND_REFERENCE.md), [BeamO US/EU provisioning](BEAMO_US_EU_PROVISIONING.md).

This document reports independent interoperability findings. Examples omit or replace identifying and confidential values. There are no real account/user identifiers, user names, MAC addresses, credentials, download-access tokens or personal measurements. Numeric identity aliases are synthetic.

The document is not an official authorization specification. Device-supported tags, application feature lists, region settings and user eligibility are separate concepts. A supported tag is not proof that a particular device or user is authorized to use it.

## 1. Configuration layers

| Layer | Purpose |
|---|---|
| Account/association | Establish ownership context and device association credentials |
| User profiles | Identify individual measurement users and supply profile configuration |
| Session indicators | Carry configuration such as language, classification region and application feature lists |
| Device profile 0 | Explicit target for device-level feature operations |
| Named-user feature profiles | Store selected per-user feature states |
| Blood-pressure classification region | Select EU or US classification behavior |
| Wi-Fi country | Configure radio country independently of classification |
| Language/locale | Configure presentation language independently of classification |

Do not combine all these layers into a single “country” or universal feature-enable switch. In particular, the radio country and the BP classification region use different stored settings.

## 2. Device and version scope

The device identifies as **BPM Vision**. Firmware version **221** is the version covered here. The image and protocol paths use **WPM08**; application firmware-check context also uses **WM08**. Those spellings occur in different namespaces and should not be silently treated as an error.

The identity response includes a firmware version, a bootloader value, a manufacturing identifier and a device address. The manufacturing identifier's market encoding is unresolved. Its presence is not evidence of an independently decoded US/EU retail designation.

The device's displayed **CE 0123** marking is not a demonstrated provisioning-region field and is not used here to infer its configuration.

## 3. Provisioning stages

The established Wi-Fi setup sequence has these logical stages:

1. Identify the device and query connection/battery state.
2. Exchange device challenges.
3. Negotiate the secure-update stage.
4. Discover/configure Wi-Fi and apply radio country and language.
5. Repeat the challenge operation around association setup.
6. Install association credentials.
7. Repeat the challenge operation after credential installation.
8. Transfer session/profile JSON.
9. Reapply Wi-Fi country and locale.
10. Apply a separate feature-profile transfer.
11. Complete setup and disconnect.

The sequence includes three `0x09B2` challenge stages. A separate BLE-only path can use a different number. They are not `0x0128` existing-association authentication exchanges. This is a representative setup sequence, not a requirement that every connection repeats all steps.

### 3.1 Framing and transport

WPP frames use:

```text
version:u8 | command:BE16 | payload_length:BE16 | payload
```

The version byte is `01`. The length excludes the five-byte header. Repeated structures inside the payload use:

```text
type:BE16 | value_length:BE16 | value[value_length]
```

The structure length excludes its four-byte header. Multi-byte integers in the documented wire layouts are big-endian.

A BLE write/notification boundary is not a universal application-frame boundary. Preserve direction and connection identity, check declared lengths and maintain transfer state across related frames. Discover services and characteristics rather than hardcoding an ATT handle.

BPM Vision's documented setup uses directly recognizable WPP messages. The Body Scan 2 TLS-over-BLE transport description must not be copied into this device's setup as though it had been established here.

### 3.2 Command map

| Command | Role | Important qualification |
|---|---|---|
| `0x0101` | Probe/device identity | Identifying fields omitted from examples |
| `0x0111` | Connection reason | Separate from feature authorization |
| `0x0105` | Battery | Operational state |
| `0x09B2` | Device challenge exchange | Repeated at multiple setup stages |
| `0x09C1` | Secure-update negotiation | Returns mode and challenge structures |
| `0x0102` | Wi-Fi scan | Network records contain private information |
| `0x0103` | Wi-Fi configuration | Credentials are omitted |
| `0x0104` | Wi-Fi operational stage | Exact role should retain context |
| `0x0109` | Wi-Fi operational stage | Do not infer feature eligibility from success |
| `0x0108` | Wi-Fi country | Structure `0x0108` |
| `0x011A` | Locale/language | Structure `0x0121` |
| `0x0134` | Association credential installation | Structures `0x0135` and `0x0136` |
| `0x010D` | Session/profile transfer | Length-prefixed `0x0112` chunks |
| `0x09C3` | Feature-profile transfer | Target `0x0145`, records `0x09D5`, completion `0x0100` |
| `0x014D` | Get classification region | Supported separately; not present as a standalone command in this setup |
| `0x014E` | Set classification region | Supported separately; session JSON supplies the region in this setup |
| `0x0113` | Setup completion | Does not establish every feature's usable state |
| `0x0110` | Disconnect | Distinct from feature application |

Command and structure identifiers are separate namespaces. For example, command `0x09C3` configures feature profiles, whereas structure `0x09C3` belongs to the `0x09B2` challenge response. Structure `0x0145` is a profile target here; it can mean a signal identifier under a different command.

### 3.3 Device challenge and secure-update stages

The `0x09B2` request carries structure `0x09C2`, 33 bytes long in this exchange. The device responds with a 70-byte `0x09C3` structure, followed by a 65-byte `0x09C4` structure and empty completion structure `0x0100`.

These values contain challenge/proof material and are omitted. The outer lengths and sequence alone do not establish the cryptographic primitive or which account/device attributes are covered by the proof.

An empty `0x09C1` request receives:

- Structure `0x0961`, length 1.
- Structure `0x09D3`, length 33.

This distinguishes the device's successful negotiation from devices that reject the stage. It does not by itself provide a firmware download URL, complete an update or establish a regional entitlement.

### 3.4 Association credentials

Command `0x0134` contains:

| Structure | Value layout | Length in this setup |
|---|---|---|
| `0x0135` | Owner/context `BE32`, then `length:u8`, then secret text | 37 bytes |
| `0x0136` | `length:u8`, then advertiser-key text | 33 bytes |

These lengths are consistent with a four-byte owner/context plus a length-prefixed 32-byte secret representation, and a separately length-prefixed 32-byte advertiser-key representation. Their textual representation must not be confused with the same number of decoded key bytes.

The device acknowledges with an empty `0x0100` structure. Account, association and measurement-user identifiers must remain distinct. Exact API-to-wire identity mapping is not asserted merely because fields have similar names.

The [association JSON illustration](examples/BPM_VISION_ASSOCIATION_RESPONSE_ILLUSTRATION.json) is a **constructed partial shape**, not a complete recorded transaction. It shows which identity categories and secret placeholders need to remain separate. It is not an executable association payload.

### 3.5 Session/profile transfer

Command `0x010D` carries repeated structure `0x0112`. Each value begins with a one-byte text length:

```text
chunk_text_length:u8 | chunk_text[chunk_text_length]
```

Remove the prefix from **each** chunk before concatenating. In this setup there are ten 64-byte structure values, each holding 63 text bytes, followed by one two-byte structure value holding one text byte: **631 JSON text bytes** in total.

The application then sends an empty `0x0100` structure under command `0x010D`; the device responds with an empty `0x010D` command payload. Transfer completion is not the same as proof that every included field controls a physical device feature.

The JSON has status 0 and a body containing session state, indicators, synchronization settings and three users. Its indicators include `mcr: 1`, so BP classification is supplied without a separate `0x014E` command in this setup.

The [sanitized session example](examples/BPM_VISION_SESSION_CONFIGURATION_SANITIZED.json) preserves the indicator values and feature lists, replaces identities, and omits demographics, measurements, time values and other fields. It is a **partial sanitized configuration**, not the complete 631-byte wire document. Its byte count and chunk count will therefore differ from the original transfer.

### 3.6 Feature-profile transfer

The separate `0x09C3` transfer in this setup contains only:

1. Target structure `0x0145`, length 4, with value **0**.
2. Empty completion structure `0x0100`.

There are **no `0x09D5` feature records** in that transfer. The device acknowledges with an empty `0x0100` structure.

The non-secret frame is:

```text
01 09 C3 00 0C
01 45 00 04 00 00 00 00
01 00 00 00
```

The payload is 12 bytes; the full frame is 17 bytes. The [structured JSON representation](examples/BPM_VISION_FEATURE_TRANSFER_SANITIZED.json) is an explanatory representation of this WPP transfer, not JSON sent over BLE.

This transfer selects/clears the target working slot and commits the resulting configuration. It must not be rewritten in documentation as an unseen list of ECG permissions. Nor does this one transfer prove that no later operation can update user features.

## 4. Supported device feature records

The profile insertion filter accepts these five feature IDs:

| ID | Application label | Qualification |
|---|---|---|
| **12** | ECG Requires Review | Separate from user ECG algorithm selection; exact BPM Vision display/review-clearing behavior is unresolved |
| **27** | ECG SW2 | Used by per-user ECG selection and distinct presence/enabled checks |
| **95** | Retake BP due to low HTN | Label identifies a retake-related feature; exact trigger policy remains unresolved |
| **96** | Retake BP due to medium HTN | Exact trigger thresholds/workflow remain unresolved |
| **97** | Retake BP due to low HTN | The application's label duplicates ID 95; do not silently relabel this as high HTN |

These are device-profile feature IDs, not measurement results or BP classification values.

The generic ECG selector also contains an older ID **4** (`ECG SW1`) fallback. However, ID 4 is not in this version's accepted insertion set. A reference in shared selection code does not establish that this provisioning route can install it.

For command `0x09C3`, a feature record uses structure `0x09D5` with a 12-byte value:

```text
first_field:BE32 | second_field:BE32 | feature_id:BE16 | feature_value:BE16
```

The final tag/value pair is retained in the feature profile. The first two fields should not be assigned a complete expiry/scheduling interpretation without confirming their semantics in the relevant operation. No such feature records occur in the separate transfer described above.

## 5. Per-user storage and lookup

The feature table uses nine 28-byte profile slots, totaling 252 bytes under persistent key `0x013B`. Each slot consists of a four-byte user identifier and six `(feature_id:u16, feature_value:u16)` positions.

There are six storage positions but five accepted IDs. Capacity and accepted-ID count are different properties.

Feature lookup uses an exact user identifier. Profile 0 is explicitly selectable; it is not automatic inheritance for every named user. The Boolean getter uses the stored value's low bit. A missing feature returns false in the Boolean lookup.

A separate presence-aware getter distinguishes “record missing” from “record present with value off.” This distinction is used in ECG-related eligibility logic; presence and permission must not be treated as synonymous.

The ECG selection order is:

```text
user's enabled ID 27 -> selection 27
otherwise user's enabled ID 4 -> selection 4
otherwise -> fallback 80
```

Fallback 80 is the selector's result; it is not proof that tag 80 can be installed through this profile filter. Eligibility also has separate profile/region-related conditions, so algorithm selection alone is not a complete user-authorization decision.

## 6. Application feature lists are not device entitlement lists

The session's `body.ind.ft` and `body.sp.users[].ft` arrays contain application feature identifiers. They are not the same representation as explicit device feature records with values.

### 6.1 Device-context/session indicator list

The supplied list is:

`57, 83, 84, 85, 106, 107`.

| ID | Application label |
|---|---|
| 57 | How to Use |
| 83 | Share Healthcare Professional |
| 84 | Share Family |
| 85 | Share Device |
| 106 | How to change the cuff |
| 107 | Hot to read your measurement |

ID 107 retains the application's spelling; its wording appears to be a typo. These labels concern tutorials/sharing rather than an ECG or Afib enable bit. The label of a sharing feature is not evidence that health data was actually shared.

### 6.2 Per-user session lists

| Synthetic profile | IDs in the supplied list |
|---|---|
| 100001 | 100, 114, 135 |
| 100002 | 100, 105 |
| 100003 | 100, 105 |

| ID | Application label |
|---|---|
| 100 | AI Health Assistant |
| 105 | New Home page |
| 114 | Zendesk SDK |
| 135 | AI Health Assistant Progressive Rollout |

These describe application capabilities/rollout state, not device-side ECG authorization. Do not reinterpret the absence of device tag 27 from these lists as a complete statement of the user's ECG eligibility.

## 7. Blood-pressure classification region

The classification region is stored separately under key `0x011F`, as one byte:

| Value | Classification selection |
|---|---|
| **0** | EU |
| **1** | US |

The standalone setter accepts 0 and 1 and rejects other values. A separate configuration route reads `body.ind.mcr` from session JSON and updates the stored classification selection when an accepted value is supplied. Missing or unsupported values bypass that update.

The documented session transfer has **`mcr: 1`**, which supplies US BP classification. No standalone `0x014D`/`0x014E` exchange appears in the same setup sequence.

The regional classifier applies different BP category tables. A classification-region setting is not equivalent to an ECG/Afib entitlement, and changing it alone is not established as a feature-unlock mechanism.

## 8. Wi-Fi country and language

The application sets Wi-Fi country **US** twice in the setup. Command and structure are both `0x0108`; the value layout is:

```text
operation:u8 | status:u8 | text_length:u8 | country_text
```

For the documented set operation:

```text
00 00 02 55 53
```

Operation 0 is set; the handler also supports get and delete. The country text can be up to three characters and is stored separately under key `0x0016`. The corresponding device responses repeat the country data/status.

The Wi-Fi initialization path has an **FR fallback** if the country setting is absent. That is a radio default, not proof that an individual device was sold in France or has EU medical feature permissions.

Locale is supplied separately using command `0x011A`, structure `0x0121`. The setup sends **en**, while the session indicator contains **en_EN**. These are different representations in different configuration fields, not evidence that either determines retail market authorization.

The session indicators also contain `stp: 51` and `mit: 60`. Their values are preserved in the sanitized example, but their full semantics/units are not established in this report.

## 9. Menus and user selection

The session provides three named profiles. Their real identities and demographic fields are omitted from the public examples. Per-user feature state must be associated with the correct profile alias, not applied indiscriminately to every user.

No Body Scan 2-style per-user metric-screen list or ranked menu configuration is established for BPM Vision by this setup. Its tutorial/sharing flags should not be documented as selectable measurement screens. No `0x050C`/`0x050D` menu transfer is established here.

A complete menu/page enumeration would require separate confirmation. In particular, the existence of ECG-related feature handling does not prove that an ECG page appears for every profile or market.

## 10. What determines the retail region?

This setup establishes that the application supplies US Wi-Fi country and US BP classification, and that named-user feature state is separately representable. It does **not** establish how the service chooses those values or the ECG/Afib permissions associated with a physical unit.

The following remain unresolved:

- Whether market-specific permissions are selected from the manufacturing identifier, registered device identity, a sales/SKU record, account properties or a combination.
- Whether another stored setting represents a manufacturing/sales-region designation.
- Whether US and EU retail devices differ in any initial identity field beyond what has been demonstrated here.
- The full eligibility/review workflow for each ECG-related profile.
- The exact behavior controlled by retake tags 95, 96 and 97.

The device address and manufacturing identifier can identify a registered unit, but their presence alone does not reveal the service's decision rules. Regulatory markings, Wi-Fi country, display language and BP classification must not be substituted for a demonstrated retail-market field.

## 11. JSON example guide

| File | Meaning |
|---|---|
| [Session configuration](examples/BPM_VISION_SESSION_CONFIGURATION_SANITIZED.json) | Partial sanitized session structure; actual non-secret indicators and feature lists retained, identities replaced, personal values omitted |
| [Association response illustration](examples/BPM_VISION_ASSOCIATION_RESPONSE_ILLUSTRATION.json) | Constructed partial example distinguishing account/association identifiers and redacted credentials |
| [Feature transfer representation](examples/BPM_VISION_FEATURE_TRANSFER_SANITIZED.json) | Explanatory JSON representation of the target-0/terminator WPP transfer; not an additional JSON API |

None of these examples contains sufficient credentials to associate with a device. The partial session document is not a wire-ready substitute for a complete session response. Illustrative fields must not be mistaken for a fully reproduced transaction.
