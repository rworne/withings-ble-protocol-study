# Body Scan 2: provisioning and feature behavior

**Updated:** 2026-11-23  
**Scope:** Body Scan 2 feature configuration, profile behavior and version-specific findings.  
**Related:** [Body Scan 2 TLS authentication](Body_Scan_2_TLS_Authentication.md), [WPP command reference](COMMAND_REFERENCE.md), [BeamO US/EU provisioning](BEAMO_US_EU_PROVISIONING.md).

This document reports independent interoperability findings. All examples omit or replace identifying and confidential values. It contains no device keys, account certificates, download-access tokens, MAC addresses, session tokens, real user names, real user identifiers or personal measurements. Numeric profile identifiers in examples are synthetic aliases.

Findings are scoped to the identified versions and configuration contexts. They are not a complete specification of the official application's authorization policy or a claim that every stage of an official setup has been independently reproduced end to end.

## 1. Configuration layers

Body Scan 2 configuration involves separate concepts:

| Layer | Meaning |
|---|---|
| Device-level feature state | General configuration associated with the device |
| User-level feature state | Configuration associated with an individual profile |
| Guest/profile-0 state | Settings explicitly selected by operations that use profile 0 |
| Measurement behavior | Activation, algorithm selection, display state and result handling |

Do not assume that these layers combine through a universal AND, OR or inheritance rule. A device-level value may differ from the corresponding approved user's value.

## 2. Version scope

The accepted profile-tag set below is the same in versions **1781** and **1811**. The detailed lookup, selection and measurement-behavior findings in this document are scoped to **1811** unless otherwise stated.

Matching accepted-ID sets do not establish that every other behavior is unchanged between versions. Distribution filenames and download locations are omitted.

## 3. Provisioning stages

The logical setup stages include:

1. Select account context and establish the TLS-protected BLE transport.
2. Identify the device and obtain connection-state and battery information.
3. Perform device-challenge and firmware-availability operations.
4. Configure network, country and locale settings when required.
5. Associate the account and install association credentials.
6. Transfer session and profile configuration.
7. Apply feature tags, screens and units.
8. Complete setup and disconnect.

Relevant WPP operations include `0x09B2` device challenge, `0x09C1` secure firmware-update start, `0x0134` association credentials, `0x010D` session configuration and `0x09C3` feature settings.

These are logical stages, not a supplied packet transcript or a universal command ordering. TLS transport roles and existing-association authentication are documented separately in the linked references. No credentials or reproduction instructions for acquiring them are provided here.

### 3.1 Transport roles and namespaces

The application acts as the TLS server and the scale as the TLS client. Account-context selection precedes the protected application conversation. After TLS establishment, WPP is carried in the decrypted TLS application byte stream; a BLE notification boundary is not a WPP boundary.

The study uses these Withings UUIDs:

| Element | UUID |
|---|---|
| Service | `00000000-0000-5749-5448-494E47530000` |
| TLS transport characteristic used for Body Scan 2 | `00000005-0000-5749-5448-494E47530000` |

Discover attributes by UUID; ATT handles can vary. Reassemble the appropriate transport before interpreting the WPP bytes.

Command and TLV identifiers occupy separate namespaces. For example:

- Command `0x0112` is not the session-chunk TLV `0x0112`.
- Command `0x0135` must not automatically be interpreted as ownership TLV `0x0135`.
- TLV `0x0145` is a profile target inside `0x09C3`, but a signal identifier inside `0x0148`.

### 3.2 WPP frame and TLV encoding

```text
Frame:
    version:u8 | command:BE16 | payload_length:BE16 | payload

Observed version:
    01

Repeated structures inside payload:
    type:BE16 | value_length:BE16 | value[value_length]
```

`payload_length` excludes the five-byte frame header. The TLV value length excludes its four-byte type/length header. Multi-byte integers in the wire layouts below are big-endian unless explicitly stated otherwise.

A decoder should:

1. Buffer a complete five-byte header.
2. Wait until `5 + payload_length` bytes are available.
3. Decode each TLV with bounds checks.
4. Preserve complete WPP frames in order, even when several arrive in one transport read.
5. Maintain logical-transfer state independently of transport fragmentation.
6. Associate responses with their command, connection and direction.

An empty **TLV `0x0100`** is a control/completion marker in these configuration transfers. It is not the same thing as **command `0x0100`**, used for general protocol error/status responses.

### 3.3 Command map

| Command | Role | Important structures / qualification |
|---|---|---|
| `0x09BF` | TLS/account-context selection | Mode TLV `0x0961`, context string TLV `0x0207`; precedes protected WPP |
| `0x0101` | Probe/identity | Identity TLV `0x0101`; authentication may be required before identity continuation |
| `0x0128` | Existing-association authentication | Challenge/proof TLVs `0x0122`, `0x0123`, application information `0x012A` |
| `0x0111` | Connection reason | Distinct from measurement/profile settings |
| `0x0105` | Battery information | Battery response structure |
| `0x09B2` | Device challenge/proof | Request `0x09C2`; response `0x09C3`, `0x09C4` |
| `0x09C1` | Secure firmware-update start | Response `0x0961`, `0x09D3`; distinct from `0x09B2` |
| `0x0102` | Wi-Fi scan | Network-entry structures; credentials omitted |
| `0x0103` | Wi-Fi configuration | Credential/result structures; no actual values published |
| `0x0108` | Wi-Fi country | TLV `0x0108`; separate from medical classification region |
| `0x011A` | Language/locale | TLV `0x0121` |
| `0x0134` | Association credential installation | Owner/secret `0x0135`, advertiser key `0x0136` |
| `0x010D` | Session/profile configuration | Length-prefixed chunk TLV `0x0112`; completion TLV `0x0100` |
| `0x09C3` | Profile feature configuration | Target `0x0145`, feature record `0x09D5`, completion `0x0100` |
| `0x0112` | Additional setup/settings stage | Exact stage contents are context-dependent |
| `0x0113` | Setup completion stage | Do not treat as proof that every feature was activated |
| `0x0110` | Disconnect | Response/completion distinct from feature application |

This map identifies the relevant protocol operations, not a requirement that every command occurs once or in this exact order. Association, challenge, configuration and synchronization operations may recur during one installation.

### 3.4 Account context and existing-association authentication

The pre-TLS context string uses the form:

```text
account:<REDACTED_ACCOUNT_ID>
```

The owner/account identifier is not the same identifier as an individual measurement user. Keep these identity categories separate when documenting or anonymizing traffic.

The existing-association challenge/proof exchange uses authorized association material. Its host-proof form is:

```text
SHA1(device_challenge || MAC_ASCII || KL_ASCII)
```

The device challenge is binary; the MAC and KL are text in the established representation. Actual values are intentionally omitted. Preserve case, separators and text encoding when evaluating a legitimate protocol implementation; hexadecimal-looking text must not automatically be decoded into binary.

A reciprocal proof is a separate device-to-host response. See the authentication reference for the established limits of that exchange. This WPP proof, the TLS account certificate and the device's provisioning proof are distinct credentials/mechanisms.

### 3.5 Device proof: `0x09B2`

| TLV | Wire-level contents |
|---|---|
| `0x09C2`, request | Length-prefixed host challenge |
| `0x09C3`, response | Length-prefixed host challenge, length-prefixed 32-byte device-generated value, four-byte metadata field |
| `0x09C4`, response | Length-prefixed 64-byte signature |

For the 32-byte challenge form, the length prefix is `20` (hex). A 64-byte signature uses prefix `40`. Prefix bytes are framing and are not part of the signed challenge message.

The identified proof is Ed25519 over:

```text
host_challenge_bytes || device_generated_bytes_32
```

The metadata field has the value `0x00000807` in the identified response construction; its complete meaning is unresolved. It must not be relabeled as a feature ID, firmware version or server authentication-method identifier without further evidence.

This device proof is separate from the account certificate used in TLS, the KL-based existing-association proof and the firmware-update challenge. The exact conversion of these response fields into every upstream provisioning request is outside the established WPP mapping here.

### 3.6 Firmware-check challenge: `0x09C1`

The response uses mode/status-like TLV `0x0961` and a length-prefixed 32-byte field in TLV `0x09D3`. Its purpose and lifecycle are separate from `0x09B2`.

```text
0x09D3 value:
    20 | <32_CHALLENGE_BYTES_REDACTED>
```

Do not substitute the challenge from one operation for another merely because both have 32 bytes. A firmware-availability check is not proof that an image was transferred or installed. Download URLs, access tokens and actual challenge/signature values are not part of this publication.

### 3.7 Association credentials: `0x0134`

| TLV | Value layout | Length rule |
|---|---|---|
| `0x0135` | `owner_id:BE32 \| secret_length:u8 \| secret_text` | `5 + secret_length` |
| `0x0136` | `key_length:u8 \| advertiser_key_text` | `1 + key_length` |

A compatible 32-character representation gives:

```text
TLV 0x0135:
    <OWNER_ID_REDACTED:4> | 20 | <SECRET_TEXT_REDACTED:32>

TLV 0x0136:
    20 | <ADVERTISER_KEY_TEXT_REDACTED:32>
```

For those lengths, the TLV values occupy 37 and 33 bytes; with both TLV headers the WPP payload is 78 bytes, and the complete frame is 83 bytes. The secret and advertiser key are separate values. Their contents, acquisition and distribution are not specified here.

The credential owner field must not be confused with the target user ID in a feature-setting message. The exact upstream owner-ID correspondence for a particular installation is not asserted without a matching transaction.

### 3.8 Session/profile document transfer: `0x010D`

Each session data structure is TLV `0x0112` with a length-prefixed text chunk:

```text
chunk_length:u8 | chunk_text[chunk_length]
```

Remove the length byte from **each** chunk before combining content. A 64-byte TLV value, for example, can contain one length byte and 63 content bytes. That is a valid encoding example, not an assertion about chunk counts in an unavailable setup transcript.

The logical sequence is:

```text
0x010D with one or more 0x0112 data structures
    [additional complete WPP frames as needed]
0x010D with empty 0x0100 completion structure
0x010D device response
```

The receiver maintains document parsing state across chunks and finalizes it at completion. Session data can include owner/session information, user profiles, classification region, locale, time settings and other configuration. Actual credentials, profile contents and personal values are omitted.

**Structural illustration only—not a complete document or replay payload:**

```json
{
  "body": {
    "ind": {"mcr": "<CLASSIFICATION_REGION>"},
    "sp": {"users": [{"id": "<USER_ID_REDACTED>"}]}
  }
}
```

Placeholder strings in this illustration do not specify the real field types. An implementation must retain the actual types and unknown fields of its authorized input. Do not assume that the session document itself contains all effective user-feature values; the separate feature-setting operation must also be considered.

### 3.9 Profile feature serialization: `0x09C3`

| TLV | Value length | Value structure |
|---|---:|---|
| `0x0145` | 4 | `target_user_id:BE32` |
| `0x09D5` | 12 | `start_field:BE32 \| end_field:BE32 \| feature_id:BE16 \| value:BE16` |
| `0x0100` | 0 | Apply/completion marker |

The shared feature structure defines the first two fields as start/end time fields. Do not assign units or expiry behavior to an unexplained nonzero value without validation. The profile table and boolean lookups described in this document retain/use the ID/value pair; they do not establish a device-side scheduling rule for those time fields.

A target selection groups the feature records that follow it. Target selection and the logical transfer can span several complete WPP frames. Keep the selected target across frame boundaries until another target is selected or the transfer ends.

For the reviewed configuration path:

1. Select a target with `0x0145`.
2. Clear that target's working profile slot before adding its supplied records.
3. Accept only supported IDs, up to the per-profile capacity.
4. Preserve target and record-count state across subsequent message fragments/frames.
5. Apply/persist the assembled table when the empty `0x0100` marker arrives.
6. Return a response for `0x09C3`.

Consequently this operation is not necessarily a single-tag patch of an otherwise immutable profile. Sending a new target block can replace that profile's working record set. Unsupported IDs may be skipped even when the command receives an acknowledgment.

The following is a **constructed serialization example**, not an actual setup packet. It encodes tag4 on for reserved target0, with zero time fields:

```hex
01 09 C3 00 18
   01 45 00 04 00 00 00 00
   09 D5 00 0C 00 00 00 00 00 00 00 00 00 04 00 01
```

The payload is 24 bytes: an eight-byte target TLV and a sixteen-byte feature TLV. A separate completion frame would be:

```hex
01 09 C3 00 04 01 00 00 00
```

These examples describe encoding only. They do not claim that this minimal record set is a sufficient, appropriate or complete configuration for a physical device. Named-user identifiers and actual configuration secrets are not included.

### 3.10 Country, locale, region and completion

Wi-Fi country uses command/TLV `0x0108` with:

```text
operation:u8 | status:u8 | country_length:u8 | country_text
```

The identified operations are **0 set**, **1 get**, and **2 delete**. A two-character country string is not interchangeable with a medical-feature eligibility flag.

Locale command `0x011A`, TLV `0x0121`, uses a length-prefixed string. A language code describes presentation language; it must not be used as proof of a device's intended medical market.

Classification region is a separate session field discussed in section 9. Screen selection, feature activation and display/review state are also separate operations or checks. Setup completion, command success and a feature's usable state must not be treated as synonymous.


## 4. Accepted profile tags

Versions 1781 and 1811 accept this ten-ID set in the reviewed profile-tag insertion paths:

```text
50, 67, 59, 78, 87, 4, 12, 27, 61, 30
```

An acknowledgment does not prove that an unsupported tag was retained. A feature name likewise does not establish that the device implements or exposes that feature.

| ID | Feature name | Body Scan 2 behavior |
|---:|---|---|
| **4** | ECG SW1 | Legacy ECG activation/analysis path and algorithm selection |
| **12** | ECG Requires Review | Separate ECG review/result-handling state; not the user ECG authorization switch |
| **27** | ECG SW2 | Preferred newer ECG analysis variant when enabled |
| **30** | Electrodermal Activity | Changes nerve-response/EDA-related measurement and display configuration |
| **50** | Pacemaker Mode | Changes measurement modes through a dedicated pacemaker-mode branch |
| **59** | Japan Mode | Changes the reviewed software weight-cap behavior from 200 kg to 150 kg |
| **61** | WBS Auto | Participates in automatic measurement/long-mode eligibility checks alongside elapsed time, other modes and measurement state |
| **67** | Athlete Mode | Supplies an athlete-mode parameter to body-composition/BIA processing |
| **78** | WBS Sudo Instant Result | Selects an immediate-result path associated with Sudoscan/EDA processing |
| **87** | PWV Instant Result | Controls a configuration choice associated with vascular/PWV instant results |

The instant-result names do not specify calculation formulas. Pacemaker-mode configuration is not a demonstration of medical safety. The software weight-cap behavior does not by itself establish the hardware's load capacity.

### Referenced features outside the accepted set

Some additional feature checks exist but the corresponding IDs are not accepted through the reviewed insertion paths:

| ID | Name | Identified behavior / limit |
|---:|---|---|
| **49** | Eyes-Closed Mode | A cross-profile helper can search for this ID; acceptance through the reviewed configuration paths is not established |
| **48** | Pregnancy | Referenced in measurement/long-mode restrictions |
| **98** | Always display the BIA values | A profile-0 check affects BIA error-handling behavior |

These may be retained, legacy or otherwise inaccessible paths. Do not infer that transmitting one of these IDs enables the corresponding behavior.

IDs **3, 15 and 34** are also outside the accepted set, even though they occur in a returned device/user configuration discussed below. Returned configuration and the subset used by the device must remain distinct.

## 5. Profile storage and lookup

The feature table supports **nine profile slots**, with capacity for **twelve tag records per slot**. Twelve is storage capacity; the accepted set contains ten IDs.

Each profile slot occupies **52 bytes**: a four-byte user identifier and twelve four-byte tag records. The table is **468 bytes (`0x1D4`)** and uses persistent configuration key **`0x013B`**. These storage dimensions are separate from the big-endian WPP wire representation.

Each profile slot has a user identifier and tag ID/value pairs. The normal lookup matches the requested profile exactly. It does not automatically inherit profile 0's value when a named user's tag is missing.

The presence-aware lookup distinguishes:

- Missing tag: `−1`.
- Existing tag, off: success with output value 0.
- Existing tag, on: success with output value 1.

The boolean consumers discussed here use the stored value's low bit. This observation must not be generalized to every WPP setting.

Some operations explicitly request **profile 0**, including the Japan-mode weight-cap check and the PWV instant-result configuration check. An explicit profile-0 lookup is not a generic inheritance rule for all users.

### Cross-profile lookup uses the first occurrence

A separate helper searches all nine slots for a tag and returns the value of the **first matching record**. It does not combine all profiles into “on if any profile is on.”

| Earlier slot | Later slot | Result |
|---|---|---:|
| Tag off | Same tag on | 0 |
| Tag on | Same tag off | 1 |
| Tag absent | Tag on | 1 |

The existence of this helper does not establish that every feature uses it, or that an unsupported tag can be installed through normal provisioning.

## 6. ECG variant selection

The ECG selector follows this rule for the requested user:

```text
if tag 27 is on:
    select ECG SW2 (27)
else if tag 4 is on:
    select ECG SW1 (4)
else:
    select basic/no-library variant (80)
```

| User tags | Selected variant |
|---|---:|
| Neither listed | 80 |
| `4=1` | 4 |
| `27=1` | 27 |
| `27=0, 4=1` | 4 |
| `27=1, 4=1` | 27 |

This is enabled-value fallback. An explicitly off 27 permits the selector to try 4. Activation and other measurement checks must be considered separately.

For the relevant ECG signal type (`0x82`), the associated version selection is:

| Variant | Algorithm version |
|---|---|
| 27 | `0x01060401` — 1.6.4.1 |
| 4 | `0x01010200` — 1.1.2.0 |
| Basic variant | 0 from the version helper |

A zero version return does not mean that no signal processing of any kind occurs.

### ECG Requires Review is separate

Tag **12** is named **ECG Requires Review** and has a separate result-handling check. It must not be relabeled as the user ECG authorization switch.

The corrected BeamO observation—recording while hiding waveform and results—must not automatically be applied to Body Scan 2. The scale's exact display behavior and review-clearing workflow need scale-specific confirmation.

No independently established standalone Afib authorization ID is claimed here. User activation, review state, algorithm selection and backend eligibility are separate concepts.

## 7. Approved-user provisioning state

The device owner confirms that Body Scan 2 is the only scale in the supplied configuration context and that **all three named users have ECG approved and unlocked**.

The repeated returned configuration has the following states:

| Feature | Device-level state | Each of the three approved users |
|---|---:|---:|
| 3 — SpO2 Non-Medical | On | On |
| 4 — ECG SW1 | **Off** | **On** |
| 12 — ECG Requires Review | On | Not listed |
| 34 — Pulse Wave Velocity | On | On |
| 30 — Electrodermal Activity | On | On |
| 50 — Pacemaker Mode | Off | Off |
| 67 — Athlete Mode | Off | Off |
| 87 — PWV Instant Result | On | Not listed |
| 61 — WBS Auto | On | On |

The important ECG comparison is:

```text
Device:        ECG SW1 off; ECG Requires Review on.
Approved user: ECG SW1 on; ECG Requires Review not listed.
```

This establishes that a device-level tag4 value of off does not universally prohibit approved users from using ECG. It is inconsistent with treating that value as a mandatory global AND gate. The exact-profile ECG selector separately supports selecting a named user's enabled tag4.

This is an observed **approved-user state**, not proof that manually changing tag4 reproduces the complete authorization workflow. Nor does the table imply that every returned ID is retained by the device: IDs3 and34 are outside the accepted set discussed earlier.

The returned device-level and user-level states are established; their exact transformation into a particular official WPP write is not claimed. Different configuration contexts must not be silently merged into one set of installed values.

## 8. Japan-mode software weight cap

The reviewed weight-cap behavior checks tag59 for **profile 0**:

```text
tag59 off or absent: maximum 200 kg
 tag59 on:           maximum 150 kg
```

Representative checked cases:

| Input | Profile-0 setting | Output |
|---:|---|---:|
| 149 kg | Tag absent | 149 kg |
| 175 kg | Tag absent | 175 kg |
| 250 kg | Tag absent | 200 kg |
| 149 kg | `59=1` | 149 kg |
| 175 kg | `59=1` | 150 kg |
| 175 kg | `59=0` | 175 kg |

These describe the software cap, not a physical load test or personal measurements.

## 9. Classification region

Classification region (`mcr`) is stored under persistent configuration key **`0x011F`**, independently of the feature-tag table. The reviewed application path accepts values **0** and **1** and persists changes. This must not be confused with the Wi-Fi country setting.

The existence of the field does not establish which server-side policy selected it. Device identity, user authorization and regional eligibility must not be collapsed into one inferred region switch.

## 10. Limits and remaining questions

- The ten accepted IDs are identical in versions 1781 and 1811; that does not establish complete behavioral equivalence.
- Profile lookup, ECG selection, tag filtering, first-occurrence behavior and software weight clipping are established for the specified paths. Full measurement hardware and authorization workflows are not claimed to have been reproduced end to end.
- The complete rule combining device eligibility and user authorization remains unresolved; no universal merge operator is asserted.
- Body Scan 2's exact review-state display and the operation that clears it need confirmation.
- WBS Auto and instant-result modes have identified roles, but their full conditions and calculation paths are not specified here.
- A referenced feature outside the accepted set is not an automatically accessible function.


## 11. JSON examples

The files below preserve the distinction between a returned feature configuration, a session document and an association response. They are **not interchangeable payloads**. Do not send an endpoint response verbatim as a WPP feature-setting message.

All identifiers are synthetic aliases. IDs 100001–100003 stand for the same three example users wherever they appear. Account 200001 and association 300001 are different identity categories. Names in the session illustration are invented. Tokens and keys are placeholders; unrelated metadata is omitted. No distribution filenames or download URLs are included.

### 11.1 Device and user feature configuration

File: [BS2_FEATURE_CONFIGURATION_SANITIZED.json](examples/BS2_FEATURE_CONFIGURATION_SANITIZED.json).

This sanitized example preserves the established feature IDs and boolean states. The three real user identifiers have been replaced with synthetic numeric aliases, preserving JSON types. It reflects the device/user configuration discussed in section 7; it is not a standalone device setup document.

```json
{
  "status": 0,
  "body": {
    "device_features": [
      {
        "id": 3,
        "active": true
      },
      {
        "id": 4,
        "active": false
      },
      {
        "id": 12,
        "active": true
      },
      {
        "id": 34,
        "active": true
      },
      {
        "id": 30,
        "active": true
      },
      {
        "id": 50,
        "active": false
      },
      {
        "id": 67,
        "active": false
      },
      {
        "id": 87,
        "active": true
      },
      {
        "id": 61,
        "active": true
      }
    ],
    "user_features": [
      {
        "userid": 100001,
        "featureids": [
          {
            "id": 3,
            "active": true
          },
          {
            "id": 4,
            "active": true
          },
          {
            "id": 34,
            "active": true
          },
          {
            "id": 30,
            "active": true
          },
          {
            "id": 50,
            "active": false
          },
          {
            "id": 67,
            "active": false
          },
          {
            "id": 61,
            "active": true
          }
        ]
      },
      {
        "userid": 100002,
        "featureids": [
          {
            "id": 3,
            "active": true
          },
          {
            "id": 4,
            "active": true
          },
          {
            "id": 34,
            "active": true
          },
          {
            "id": 30,
            "active": true
          },
          {
            "id": 50,
            "active": false
          },
          {
            "id": 67,
            "active": false
          },
          {
            "id": 61,
            "active": true
          }
        ]
      },
      {
        "userid": 100003,
        "featureids": [
          {
            "id": 3,
            "active": true
          },
          {
            "id": 4,
            "active": true
          },
          {
            "id": 34,
            "active": true
          },
          {
            "id": 30,
            "active": true
          },
          {
            "id": 50,
            "active": false
          },
          {
            "id": 67,
            "active": false
          },
          {
            "id": 61,
            "active": true
          }
        ]
      }
    ]
  }
}
```

Important details:

- Device-level tag4 is false while every approved user's tag4 is true.
- Device-level tag12 is true, but tag12 is not listed for any of these three users. **Absent does not mean an explicit false record.**
- Device-level tag87 is true and is absent from these user lists.
- Returned IDs3 and34 remain present in the example, although they are outside the accepted profile-tag set for the reviewed device paths. Do not silently discard or reinterpret them when documenting the server response.
- User-specific `featureids` are ID/boolean records, not a compact array of integers.

### 11.2 Session/profile document illustration

File: [BS2_SESSION_CONFIGURATION_ILLUSTRATION.json](examples/BS2_SESSION_CONFIGURATION_ILLUSTRATION.json).

This is a **constructed, partial structure illustration**, not a complete observed setup document. Its `mcr: 1` is an example value, not a claim about the installed classification-region setting. User identifiers match the synthetic aliases in the feature example. Required fields and personal profile attributes omitted here must not be guessed when implementing an authorized conversation.

```json
{
  "status": 0,
  "body": {
    "sessionid": "<REDACTED_SESSION_TOKEN>",
    "ind": {
      "mcr": 1
    },
    "sp": {
      "users": [
        {
          "id": 100001,
          "fn": "Example User A",
          "sn": "A"
        },
        {
          "id": 100002,
          "fn": "Example User B",
          "sn": "B"
        },
        {
          "id": 100003,
          "fn": "Example User C",
          "sn": "C"
        }
      ]
    }
  }
}
```

The session document is the class of content carried through length-prefixed `0x0112` chunks under WPP command `0x010D`. The separate feature response in section 11.1 is not established as the content of that transfer. In particular, this illustration does not put user feature lists into `sp.users` without a demonstrated mapping.

### 11.3 Association response illustration

File: [BS2_ASSOCIATION_RESPONSE_ILLUSTRATION.json](examples/BS2_ASSOCIATION_RESPONSE_ILLUSTRATION.json).

This is a **constructed response-shape illustration**. Its status and aliases do not assert the outcome of a specific installation. Placeholder strings are deliberately not usable credentials or valid fixed-length keys.

```json
{
  "status": 0,
  "body": {
    "accountid": 200001,
    "associationid": 300001,
    "kl": "<REDACTED_ASSOCIATION_KEY>",
    "advertise_key": "<REDACTED_ADVERTISER_KEY>"
  }
}
```

The association key and advertiser key have different purposes. They correspond to separate values in the `0x0134` credential-installation exchange. An upstream association identifier must not automatically be substituted for the wire owner/account identifier: the exact identity correspondence must be established for the transaction concerned.

### 11.4 From JSON feature records to WPP

The conceptual transformation is:

```text
Select the intended user/context
    ↓
Resolve effective feature ID/value records
    ↓
0x09C3: 0x0145 target user ID
    ↓
One or more 0x09D5 feature records
    ↓
Empty 0x0100 apply/completion marker
```

The exact upstream policy resolving device-level and user-level lists is **not established as a generic merge algorithm**. Therefore the example files do not prescribe “OR the lists,” “AND the lists,” or “copy every missing user value from the device.”

Once an authorized effective record set is known, a tag can be represented on the wire as:

```text
start time field:  BE32
end time field:    BE32
feature ID:       BE16
feature value:    BE16
```

The feature parser then applies its supported-ID filtering and profile replacement/completion behavior. Preserve command context, target continuity, and absent-versus-off distinctions. Never infer installed state merely from a returned JSON flag or command acknowledgment.


This study is independent of Withings. Feature names and configuration behavior do not establish clinical validity, regulatory authorization or suitability for diagnosis or treatment.

## 12. Per-user menus and measurement screens

Screen selection is a separate configuration layer from the feature permissions in sections 4–7. Users can have different screen lists and ordering on the same scale. An enabled feature does not, by itself, establish that its screen is selected; a screen entry does not, by itself, establish regulatory or user authorization for the associated feature.

### 12.1 JSON structure

The [complete sanitized screen configuration](examples/BS2_USER_SCREEN_CONFIGURATION_SANITIZED.json) preserves all screen records, field values and ordering for three profiles. Only the user identifiers are replaced, using the same aliases as the other examples. This is a sanitized configuration example, rather than a constructed list of hypothetical selections.

| Field | Meaning and limits |
|---|---|
| `body.user_screens` | Separate menu configuration for each user |
| `userid` | Target user; synthetic aliases 100001–100003 in this document |
| `screens` | Ordered screen records belonging to that user |
| `id` | Screen/configuration identifier; distinct from `embeddedid` |
| `source` | Screen-source discriminator; all records in this example use 1 |
| `embeddedid` | Embedded screen identifier consumed with its source; not a feature tag |
| `rank` | Explicit display ordering; contiguous ranks beginning at 1 in these lists |
| `parent_screen_id` | Relationship to another screen's `id`; not its embedded ID |
| `deactivable_status` | Optional activation/deactivation status code; values 2 and 6 occur here, but their exact flag meanings are not established |
| `body.device_screens` | Separate device-level list; empty in this configuration |

An omitted optional status is not an explicit zero or an explicit enabled flag. Do not reinterpret `deactivable_status: 2` or `6` as a Boolean. Similarly, an empty device-level list does not mean that the users have no screens. Some screen responses can contain empty user lists; their interpretation requires the operation's context and cannot automatically be treated as a command to erase a menu.

### 12.2 Actual ordering by profile

Each row below identifies the screen at that rank, using `id / embeddedid`. All have `source: 1`. A dash means that the profile has no entry at that rank.

| Rank | Profile 100001 | Profile 100002 | Profile 100003 |
|---|---|---|---|
| 1 | 66 / 11 | 66 / 11 | 66 / 11 |
| 2 | 109 / 2 | 116 / 1 | 116 / 1 |
| 3 | 116 / 1 | 54 / 16 | 54 / 16 |
| 4 | 54 / 16 | 41 / 15 | 58 / 12 |
| 5 | 302 / 22 | 253 / 20 | 118 / 3 |
| 6 | 253 / 20 | 466 / 26 | 65 / 10 |
| 7 | 466 / 26 | 58 / 12 | — |
| 8 | 58 / 12 | 118 / 3 | — |
| 9 | 118 / 3 | 465 / 25 | — |
| 10 | 465 / 25 | 464 / 23 | — |
| 11 | 464 / 23 | 65 / 10 | — |

The first two profiles each have 11 records; the third has 6. The first profile includes screens 109/2 and 302/22, while the second instead includes 41/15 and 65/10. Screen 58/12 explicitly names screen 118 as its parent in all three lists. The child precedes that parent in rank order; do not reorder the list merely to put parents first.

Screen 66/11 has `deactivable_status: 6` for all three profiles. Screen 65/10, present in profiles 100002 and 100003, has status 2. These are configuration status values, not the feature IDs 6 and 2.

### 12.3 Scale-side behavior

The per-user screen representation has separate source and screen-value fields. In the embedded-source path (`source: 1`), the scale uses the embedded screen value in its measurement-selection logic. It also has an explicit no-screen-list path that skips measurements in that selection routine. Consequently, the menu participates in measurement selection as well as display selection; it is not safe to describe every entry as purely cosmetic. Other feature, user and measurement conditions still apply.

The inspected profile representation reserves 16 eight-byte screen entries. This is an internal representation limit for that version, not a claim that the application's picker always offers 16 choices or that every source has the same identifier width. The embedded-source path reads a byte-sized screen value; another source path handles a wider value.

The application separately models scale screens, embedded screen IDs, screen sources and activation status. These distinctions support keeping the JSON fields separate. A generic device-screen-type label refers to a different concept and must not be used as a shortcut to name scale metric screens.

### 12.4 WPP mapping and remaining gaps

The study's command reference documents display configuration commands `0x050C` and `0x050D`, with repeated `0x0516` records, for Body Smart. That establishes a related protocol family, but not a verified Body Scan 2 wire mapping. The 18-byte Body Smart record layout must not be presented as a confirmed Body Scan 2 layout without additional confirmation. In particular, the byte positions of user target, source, embedded ID, status, parent and rank within a Body Scan 2 screen transfer remain unresolved here.

The confirmed pairs in this configuration are:

`41/15, 54/16, 58/12, 65/10, 66/11, 109/2, 116/1, 118/3, 253/20, 302/22, 464/23, 465/25, 466/26`.

The following section aligns the supplied menu labels with the selected configuration. Preserve both IDs; do not substitute measurement-type IDs or feature-tag names merely because their numbers coincide. The JSON example retains the actual identifiers without adding invented enabled/disabled fields.

### 12.5 User-visible menu labels and selected-profile alignment

The supplied full menu, in its displayed order, is:

1. Weight
2. BMI
3. Fat Mass
4. Muscle Mass
5. Visceral Fat
6. Body Water
7. Bone Mass
8. ECG 6-Lead
9. SpO2
10. Pulse Wave Velocity
11. Heart Rate
12. Vascular Age
13. Nerve Response
14. Weather
15. Air Quality

The supplied selected menu has 11 entries, matching the first profile's record count and order. The table below aligns those labels positionally with profile alias **100001**. The selections and labels are user-confirmed; the ID-to-name associations are inferred from that ordered alignment, rather than independently verified for each identifier.

| Selected rank | Screen ID | Embedded ID | User-visible label |
|---|---|---|---|
| 1 | 66 | 11 | Weight |
| 2 | 109 | 2 | BMI |
| 3 | 116 | 1 | Fat Mass |
| 4 | 54 | 16 | Muscle Mass |
| 5 | 302 | 22 | Visceral Fat |
| 6 | 253 | 20 | ECG 6-Lead |
| 7 | 466 | 26 | SpO2 |
| 8 | 58 | 12 | Pulse Wave Velocity |
| 9 | 118 | 3 | Heart Rate |
| 10 | 465 | 25 | Vascular Age |
| 11 | 464 | 23 | Nerve Response |

Body Water, Bone Mass, Weather and Air Quality are not selected in the supplied menu. Their IDs cannot be assigned from this list alone. In particular, the remaining pairs 41/15 and 65/10 in other profiles must not be arbitrarily assigned to those four labels.

Under this alignment, the explicit parent relationship connects Pulse Wave Velocity (screen 58) to Heart Rate (screen 118). This is consistent with a cardiovascular grouping, but the relationship does not by itself establish all display or measurement dependencies.

The JSON example deliberately keeps its original field structure. This label table is explanatory metadata, not an additional field that the scale is known to accept.
