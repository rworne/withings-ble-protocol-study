# Body Scan 2: protocol, provisioning, menus and firmware

Updated: November 25, 2026

- [Scope and version coverage](#scope-and-version-coverage)
- [Architecture and ordered setup](#architecture-and-ordered-setup)
- [TLS transport, certificates and offline access](#tls-transport-certificates-and-offline-access)
- [BLE transport and WPP framing](#ble-transport-and-wpp-framing)
- [Connection authentication and credential roles](#connection-authentication-and-credential-roles)
- [Association and session transfer](#association-and-session-transfer)
- [Network, locale, region and units](#network-locale-region-and-units)
- [Device and per-user feature provisioning](#device-and-per-user-feature-provisioning)
- [Per-user menus and screen configuration](#per-user-menus-and-screen-configuration)
- [Device authentication for server sessions](#device-authentication-for-server-sessions)
- [Firmware requests, approval and update transfer](#firmware-requests-approval-and-update-transfer)
- [Authenticated local measurement retrieval](#authenticated-local-measurement-retrieval)
- [Recorded ECG and risk-result fields](#recorded-ecg-and-risk-result-fields)
- [Firmware revision history](#firmware-revision-history)
- [Firmware implementation details](#firmware-implementation-details)
- [Inline JSON configuration examples](#inline-json-configuration-examples)
- [Completion, limitations and remaining questions](#completion-limitations-and-remaining-questions)

## Scope and version coverage

This reference consolidates Body Scan 2 / WBS15 transport, authentication, setup, feature provisioning, user menus, firmware updates and identified measurement behavior. Body Scan 2 is model **19** in the account-service model context; `WBS15` is its device-family code. These identifiers have different roles from a manufacturing identifier or an individual device identity.

This is an independent interoperability document, not an official Withings specification. Wire-format findings, observed outcomes, constructed examples and unresolved behavior are distinguished throughout. Complete independent factory-reset provisioning has **not** been demonstrated.

| Material | Version scope |
|---|---|
| TLS handshake and certificate-acceptance observations | 1781 |
| Detailed feature-table lookup, accepted-ID insertion and measurement gates | Detailed 1811 findings; corresponding accepted-ID, ECG-selection, profile-lookup and weight-cap behavior also established in 1831; accepted-ID set checked in 1781 |
| Detailed structured-menu replacement and persistence | 1811 |
| Eighteen-byte menu decoder | 1811 and 1831 |
| Secure-update handler structure and error handling | 1781, 1811 and 1831 |
| Device-proof signing path and direct network-secret path | Version-qualified findings in the relevant sections |
| Body-composition and calibration changes | 1781 → 1811 → 1831 |

All account/device identities, private credentials, signatures and firmware-download access suffixes are omitted or replaced. Numeric users 100001–100003, account 200001 and association 300001 are synthetic aliases. Original private material and firmware packages are not included.

## Architecture and ordered setup

Three participants have different responsibilities:

| Participant | Responsibility |
|---|---|
| Client | Establish transport, authenticate, request authorized configuration, select the applicable setup systems, serialize WPP and handle responses |
| Service | Supply account/device association state, session configuration, profile settings, screen configuration and update offers/approval material |
| Scale | Authenticate peers, answer challenges, parse WPP, assemble multi-packet transfers, persist supported configuration and enforce measurement/update rules |

The client has separate connection, handshake, setup, Wi-Fi, synchronization and upgrade coordinators. A system appearing in a coordinator's ordered plan does not mean that the system emits a command for every device. Capabilities, association state, pending synchronization and returned settings control which work is performed.

Consequently, a compatible implementation needs a **state machine**, not a recording replay. Fresh challenges, server-selected values and legitimate credentials cannot be replaced by constants from an earlier installation.

### Ordered setup systems

The setup coordinator branches on whether a specific user ID was supplied.

### Account-level branch: no supplied user ID

```text
Identity
Account Association
Device Sync
Association Key
Set Session
Feature Mask
Localization
Screens Set
Feature Tags
Weight Unit
Temperature Unit
```

### User-level branch: a supplied user ID

```text
Identity
User Association
User Set
Device Sync
Association Key
Set Session
Feature Mask
Localization
Screens Set
Feature Tags
Weight Unit
Temperature Unit
```

The user-level branch additionally schedules the shared framework's classification, workout-status, wear-position, shortcut, luminosity, glance, workout-screen, hand-position, time, goal, alarm, tracker-unit, notification, temperature-calibration and activity-class systems. These are **generic capability-gated steps**, not a claim that the scale implements watch-specific settings.

The sequence above is the ordered setup-system plan. It does not incorporate every operation of the outer installation UI, every server round trip, Wi-Fi selection or an optional firmware-update cycle into a single verified chronological transcript.

Notable consequences:

- Session transfer precedes menu transfer in this plan.
- Menu transfer precedes the separate feature-tag system.
- Account association and user association are different branches.
- Returning to an already installed device can follow synchronization rather than installation.
- A dedicated feature refresh schedules Set Session followed by Feature Tags; a feature update need not repeat full setup.

### Configuration objects

| Returned object | Client use | WPP destination |
|---|---|---|
| Association response: `accountid`, `associationid`, `kl`, `advertise_key` | Establish/store authorized association state | Association-key installation uses `0x0134`; do not confuse account and association IDs |
| Session document | Transfer the applicable scale/profile configuration | `0x010D`, with `0x0112` chunks |
| `device_features`, `user_features[].featureids` | Build device/profile feature records | `0x09C3`, target `0x0145`, records `0x09D5` |
| `user_screens[].screens`, optional device/custom screen configuration | Build ordered screen objects and any required custom-content transfers | Capability negotiation `0x050D`; structured list `0x050C` / `0x0516` |

Do not send an entire feature endpoint response as the session document, or send screen JSON verbatim as a screen-list payload. The client transforms these objects into different wire structures.

## TLS transport, certificates and offline access

An accepted certificate in the documented authentication context had these properties:

| Property | Observed value |
| --- | --- |
| Format | X.509 v3 |
| Subject | Account-specific identity |
| Issuer | `WBS15` |
| Public key | Ed25519 |
| Certificate signature | Ed25519 |
| Validity | Approximately 99 years |
| Basic constraints | `CA:FALSE` |
| Extended key usage | TLS server and client authentication |

The subject identifies an account rather than a particular scale. The issuer name is observable in the certificate; the certificate issuance process and trust-anchor implementation have not been established.

### Certificate acceptance outcomes

Three configurations were presented to both a previously paired device and a fully factory-reset device:

| Presented certificate | Result |
| --- | --- |
| Previously accepted certificate | TLS handshake completed |
| Reconstructed certificate with a new keypair, preserving identity fields and extensions | Rejected |
| Reconstructed certificate retaining the accepted public key, but with a different certificate signature | Rejected |

Rejected certificates produced the TLS fatal alert **`bad_certificate` (42 / `0x2A`)**. The alternative certificates retained the subject, issuer, serial number, validity period, and extensions of the accepted certificate.

These results show that matching certificate metadata—or even reusing the accepted public key—is not sufficient. They are consistent with validation against a persistent manufacturer trust anchor, but **do not distinguish issuer-signature verification from certificate pinning or another trust policy**.

### Handshake and offline behavior

1. Connect over BLE, discover the appropriate GATT attributes and enable notifications.
2. Send pre-TLS initialization with account context.
3. Receive the scale's TLS `ClientHello`.
4. Complete the application's TLS-server handshake with an accepted certificate and matching private key.
5. Exchange WPP inside TLS application records.

The documented successful negotiation was TLS 1.3 with `TLS_CHACHA20_POLY1305_SHA256`. An unacceptable certificate was rejected before encrypted provisioning commands could proceed.

An already accepted account certificate completed TLS without internet connectivity, including after a full factory reset. This demonstrates offline **TLS authentication**, not complete offline account association or setup. The long certificate validity does not establish indefinite access or an unlimited credential lifetime.

On macOS, CoreBluetooth peripheral identifiers changed between discovery sessions. Discover the device afresh and use the resulting peripheral object. Advertised names are not authenticated device identities.

Earlier uncertainty about whether session configuration used text or binary structures is superseded by the session and TLV formats below. Credential origin, certificate issuance and complete offline enrollment remain separate unresolved questions.

## BLE transport and WPP framing

The application side acts as the TLS server; the scale acts as TLS client. Account-context selection precedes protected WPP communication. The TLS transport characteristic is:

```text
Service:        00000000-0000-5749-5448-494E47530000
Characteristic: 00000005-0000-5749-5448-494E47530000
```

Discover characteristics by UUID rather than assuming fixed ATT handles. BLE fragments, TLS records and WPP frames have separate boundaries.

```text
WPP frame:
    version:u8 | command:BE16 | payload_length:BE16 | payload

TLV inside payload:
    type:BE16 | value_length:BE16 | value[value_length]
```

The established frame version is `1`. Frame length excludes its five-byte header; TLV length excludes its four-byte header.

An empty TLV `0x0100` terminates several logical configuration transfers. It is distinct from command `0x0100`. Buffer and parse complete frames, while keeping logical transfer state across frames.

### Command index

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

This is a command index, not a universal packet order. Operations may recur during installation or synchronization.

| Additional command | Purpose |
|---|---|
| `0x050D` | Query menu capability/count and screen protocol version |
| `0x050C` | Transfer the ordered screen list using `0x0516` records |
| `0x09C2` | Submit secure-update approval in `0x09D4` |
| `0x0967` | Announce firmware and negotiate transfer position |
| `0x0968` | Transfer firmware chunks and exchange progress |
| `0x0151` | Associated reboot operation |

Command and TLV identifiers have separate namespaces. Command `0x0112` is not session-chunk TLV `0x0112`; command `0x0135` is not automatically ownership TLV `0x0135`. TLV `0x0145` targets a profile in feature configuration but has a different meaning in other command contexts.


## Connection authentication and credential roles

The connection coordinator's named systems are **Probe**, **Connection Reason**, and **Identity**. The handshake coordinator separately handles account-context/SNI selection. Their existence does not establish one universal order of all transport and application operations in every installation.

Relevant operations:

| Command | Purpose |
|---|---|
| `0x09BF` | Account-context selection; mode `0x0961` and context string `0x0207` |
| `0x0101` | Probe/identity |
| `0x0128` | Existing-association authentication |
| `0x0111` | Connection reason |
| `0x0105` | Battery information |

The context string is of the form `account:<ACCOUNT_ID>`. The account identity, association identity and individual measurement-user identity are different categories.

Existing-association authentication uses a host proof of the form:

```text
SHA1(binary_device_challenge || MAC_ASCII || KL_ASCII)
```

The exact text representation matters. A hexadecimal-looking textual key must not automatically be converted to raw bytes. The reciprocal device proof is separate. TLS credentials, association keys and the device's server-session signing key are also separate.

### Separate credential roles

| Credential or field | Role established here |
|---|---|
| Device factory/network secret | Input to the appropriate secret/nonce session calculation |
| KL/shared association key (`ZSECRETKEY`) | BLE association challenge-response authentication |
| Advertiser key (`ZADVERTISEKEY`) | Recognizing protected BLE advertisements |
| Retrieved account/client certificate and private key | Authenticate the client software to BS2 over BLE TLS; the scale acts as the TLS client |
| Device's stored client-TLS signing key | Produce the device-side proof used by the newer session flow |
| Account session | Account operations; not interchangeable with a device session |
| Device session | Select/authenticate the device context used for the firmware offer |

KL and the advertiser key are distinct from the separate `secret` property consumed by the legacy web-session builder. Neither should be silently substituted for it.

The certificate-retrieval operation uses the account service with `action=getcertificate` and a model parameter. In the BS2 configuration covered here, the retrieved credential authenticates the client software to the scale; it is not established as disclosure of that physical scale's own signing key.

During account association, a response can provide `associationid`, `accountid`, `kl` and `advertise_key`. Those fields establish association material, not the presence of the separate factory secret or device signing key. Real values and identities are intentionally omitted.

## Association and session transfer

Command **`0x0134`** installs the separate association and advertiser values.

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

### Session/profile document transfer

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

A partial session/profile JSON illustration appears in the inline examples. Preserve real field types and unknown fields in authorized documents; the feature response is not interchangeable with the session document.

The client fragments the session text and sends the completion marker after the data chunks. This describes a logical transfer, not a required BLE notification size. A complete session document still requires the authorized profile fields and values; the inline illustration is not a replacement payload.

## Network, locale, region and units

| Setting | Operation | Qualification |
|---|---|---|
| Wi-Fi scan | `0x0102` | Network discovery is separate from medical eligibility |
| Wi-Fi configuration | `0x0103` | Credentials are omitted from examples |
| Wi-Fi country | `0x0108` / `0x0108` | `operation:u8, status:u8, length:u8, country_text`; operations 0=set, 1=get, 2=delete |
| Language/locale | `0x011A` / `0x0121` | Length-prefixed presentation-language string |
| Weight unit | `0x0112` / `0x0119` | Separate unit structure; command `0x0112` is not session-chunk TLV `0x0112` |
| Medical classification region | Session field `mcr` | Separate from Wi-Fi country and language; persistent key `0x011F` in the reviewed scale path |

The Wi-Fi coordinator separately defines settings-query, scan and localization systems. User choice/network operations also involve surrounding installation UI. Do not infer the timing of all network steps from the setup coordinator alone.

### Region storage

Classification region (`mcr`) is stored under persistent configuration key **`0x011F`**, independently of the feature-tag table. The reviewed application path accepts values **0** and **1** and persists changes. This must not be confused with the Wi-Fi country setting.

The existence of the field does not establish which server-side policy selected it. Device identity, user authorization and regional eligibility must not be collapsed into one inferred region switch.

## Device and per-user feature provisioning

Configuration has separate device-level, named-user, explicit profile-0 and measurement-behavior layers. No universal AND, OR or inheritance rule is established between them.

### Feature transfer format and transaction

Command **`0x09C3`** carries the following structures.

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

### Accepted profile tags

Versions 1781 and 1811 accept this ten-ID set in the reviewed profile-tag insertion paths:

```text
50, 67, 59, 78, 87, 4, 12, 27, 61, 30
```

An acknowledgment does not prove that an unsupported tag was retained. A feature name likewise does not establish that the device implements or exposes that feature.

| ID | Feature name | Body Scan 2 behavior |
|---:|---|---|
| **4** | ECG SW1 | Legacy ECG activation/analysis path and algorithm selection |
| **12** | ECG Requires Review | Separate review/result-handling state associated with hidden ECG presentation; not the user ECG authorization switch |
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

### Profile storage and lookup

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

### ECG variant selection

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

The device owner confirms that **Body Scan 2 also records the hidden ECG while withholding the waveform and results from the user**, as observed on BeamO. This establishes the scale's hidden presentation behavior. It does not establish the full review-clearing workflow or make tag 12 the user ECG authorization switch.

No independently established standalone Afib authorization ID is claimed here. User activation, review state, algorithm selection and backend eligibility are separate concepts.

### Approved-user provisioning state

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

### Japan-mode software weight cap

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

## Per-user menus and screen configuration

Before sending menu content, the screen system can query command `0x050D`.

The established scale response supplies:

| TLV | Value | Meaning |
|---|---|---|
| `0x0206` | `BE32(16)` | Maximum screen count advertised by this handler |
| `0x0961` | `u8(1)` | Partner-screen protocol version |

The client reads both values. Its structured screen-list branch is selected when the required settings are present and the returned version is `1`; there is also an older data-list branch. The version field is a screen protocol version, not firmware revision 1.

The screen system can skip a transfer when it considers device screens already synchronized. After successful work, a supported pending-screen-sync flag is cleared. Therefore, a missing screen transfer during a later connection is not proof that menu provisioning has ceased to exist.

### Structured menu records and replacement

Command **`0x050C`**, repeated TLV **`0x0516`**, each with exactly **18 value bytes**:

| Offset | Width | Field |
|---:|---:|---|
| 0 | 4 | Screen/app identifier, big-endian unsigned 32-bit |
| 4 | 4 | Target user identifier, big-endian unsigned 32-bit |
| 8 | 4 | Start timestamp, big-endian unsigned 32-bit |
| 12 | 4 | End timestamp, big-endian unsigned 32-bit |
| 16 | 1 | Embedded screen identifier |
| 17 | 1 | Screen source |

The client-side screen objects carry these six fields. Missing optional start/end dates become zero in the structured-record builder. Supplied dates are converted to Unix seconds and then unsigned integers; fractions are truncated. Identifiers must fit the corresponding widths. The structured builder skips objects missing the required web-service identifier, embedded identifier or screen-source value.

**Version scope:** the 18-byte receiver format is established for 1811 and the same decoder is present in 1831. The detailed replacement and persistence behavior below is established for the reviewed 1811 handler; matching decoder bytes alone do not establish every surrounding behavior in another release.

### Example with invented identity

Screen 66, embedded screen 11, source 1, target user 100001, no time bounds:

```text
Screen ID:   00000042
User ID:     000186A1
Start:       00000000
End:         00000000
Embedded ID: 0B
Source:      01
```

Complete constructed WPP frame:

```hex
01 05 0C 00 16
   05 16 00 12
      00 00 00 42 00 01 86 A1
      00 00 00 00 00 00 00 00 0B 01
```

Completion is a separate logical marker:

```hex
01 05 0C 00 04 01 00 00 00
```

These are encoding examples, not sufficient instructions to install a factory-reset scale. No real user is represented. The complete selected 11-entry screen list appears in the inline JSON examples.

### Where rank, status and parent information go

There are **no separate rank, activation-status or parent-ID fields** in this 18-byte structure. Screen order is represented by record order in the submitted list. Selection/status handling, dependencies and ordering must occur before this serialization boundary. Their exact complete upstream policy is not established merely by the record format.

Do not append `rank`, `parent_screen_id` or `deactivable_status` to the wire structure. In particular, `deactivable_status: 6` is not embedded screen 6, nor a six-byte field.

### Receiver behavior

1. Create a working copy of the current user/configuration table when processing the first screen record.
2. Match the target user against an existing user slot.
3. The first record for a matched user clears that user's working screen list.
4. Append subsequent records for that user in arrival order, including across complete WPP payload/frame boundaries.
5. Retain at most 16 screen entries for the matched profile in this handler.
6. Preserve the existing embedded-screen lists of profiles not touched by the transfer.
7. At the empty `0x0100` marker, perform the configuration commit and release the working transfer state.

The working user table has eight user slots in this path. Do not confuse that with the separate feature table's nine slots, which include profile-0 handling.

For `source == 1`, the stored screen entry retains the **embedded screen byte**. For other sources, it retains the **32-bit screen/app identifier**. Nonembedded records also participate in separate custom-content bookkeeping. An arbitrary non-1 source is not thereby established as a valid, supported custom-screen type.

An omitted profile is not an instruction to erase its menu. An explicit protocol for clearing a profile to a genuinely empty list is not established here; do not assume that sending only a completion marker does that. Likewise, a screen-list record is not a substitute for installing the corresponding user/profile first.

### JSON structure

The complete inline screen configuration below preserves all screen records, field values and ordering for three profiles. Only the user identifiers are replaced, using the same aliases as the other examples. This is a sanitized configuration example, rather than a constructed list of hypothetical selections.

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

### Actual ordering by profile

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

The first two example profiles each have 11 records; the third has 6. The first profile includes screens 109/2 and 302/22, while the second instead includes 41/15 and 65/10. Screen 58/12 explicitly names screen 118 as its parent in all three lists. The child precedes that parent in rank order; do not reorder the list merely to put parents first.

Screen 66/11 has `deactivable_status: 6` for all three profiles. Screen 65/10, present in profiles 100002 and 100003, has status 2. These are configuration status values, not the feature IDs 6 and 2.

### Scale-side behavior

The per-user screen representation has separate source and screen-value fields. In the embedded-source path (`source: 1`), the scale uses the embedded screen value in its measurement-selection logic. It also has an explicit no-screen-list path that skips measurements in that selection routine. Consequently, the menu participates in measurement selection as well as display selection; it is not safe to describe every entry as purely cosmetic. Other feature, user and measurement conditions still apply.

The reviewed profile representation reserves 16 eight-byte screen entries. This is an internal representation limit for that version, not a claim that the application's picker always offers 16 choices or that every source has the same identifier width. The embedded-source path reads a byte-sized screen value; another source path handles a wider value.

The application separately models scale screens, embedded screen IDs, screen sources and activation status. These distinctions support keeping the JSON fields separate. A generic device-screen-type label refers to a different concept and must not be used as a shortcut to name scale metric screens.

### User-visible menu labels and selected-profile alignment

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

## Device authentication for server sessions

Body Scan 2 also contains a direct network-session path using its own stored factory secret:

```text
authentication_hash = SHA256(MAC + ":" + stored_secret + ":" + server_nonce)
```

That request specifies `hashmethod=sha256`. It is separate from both the legacy MD5 calculation and the newer BLE challenge/proof path described below. A model can contain more than one authentication path; “newer device” does not mean “only one authentication mechanism.”

The stored factory secret uses persistent record `0x0003`, with space for 16 characters plus a terminator. A separate factory-personalization handler accepts supplied secret material, including a wrapped representation with auxiliary data at `0x0099`. The personalization erase path explicitly preserves the secret, MAC identity and client-TLS keys.

No write of this factory secret has been established as part of the normal account-association sequence documented here. That supports treating it separately from keys installed during ordinary pairing. The manufacturing process that originally chooses it is not established.

This path identifies a possible standalone authentication route **if the correct stored secret and any other applicable connection requirements are available**. It does not establish that an arbitrary client can obtain the secret, or that this device-side path has already been reproduced independently end to end.

### Device-generated proof

The newer device-session request supplies challenge data, a device-produced signature and a signature-method identifier. An illustrative partial request is:

```json
{
  "action": "new",
  "auth": "<REDACTED_DEVICE_MAC>",
  "hash": "<BASE64_DEVICE_SIGNATURE>",
  "challenge": "<BASE64_CHALLENGE_DATA>",
  "hashmethod": "2055",
  "mfgid": "<REDACTED_MANUFACTURING_ID>",
  "currentfw": "1831",
  "httpslink": "3",
  "appname": "wiscaleNG",
  "apppfm": "ios",
  "appliver": "202611052",
  "callctx": "foreground,syncForSCALEInstall"
}
```

In the BS2 path covered here:

1. The client sends platform-random challenge material using WPP command `0x09B2`.
2. The device adds its own random material.
3. The device signs the combined challenge data using its stored client-TLS signing key.
4. The response carries challenge metadata and signature material in the corresponding WPP structures.
5. The client submits the encoded challenge/signature in the server-session request.

The method identifier is `0x0807`, decimal **2055**. The signature is supplied in the request's `hash` field; that field name does not mean it is the same type of hash as the legacy MD5 value.

The BS2 stores its client-TLS key pair separately under record `0x012C`. The challenge handler requires that key material and reports missing client-TLS keys if it cannot load it. This key role must not be replaced by the account/client certificate merely because both involve Ed25519 credentials.

A standalone client would obtain the real device's proof and submit it when creating the session. Generating a fresh valid proof without the device, using only the credentials examined here, has not been established. Replay lifetime, nonce reuse and server enforcement are not assumed.

### Device-proof WPP structures

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

## Firmware requests, approval and update transfer

Firmware handling has four independent layers: connection authentication, device-session creation, update approval, and transfer/image validation. Satisfying one is not proof that the others have succeeded.

### Firmware offer request

```http
POST https://scalews.withings.net/cgi-bin/v2/firmware
Content-Type: application/x-www-form-urlencoded
```

JSON below is a readable representation of **URL-encoded form fields**, not a JSON HTTP-body requirement:

```json
{
  "action": "getupdate",
  "sessionid": "<REDACTED_DEVICE_SESSION>",
  "currentfw": "1830",
  "httpslink": "1",
  "final": "0",
  "challenge": "<REDACTED_DEVICE_UPDATE_CHALLENGE>",
  "callctx": "foreground,Upgrade,WBS15",
  "appname": "wiscaleNG",
  "apppfm": "ios",
  "appliver": "<APPLICATION_BUILD>"
}
```

This is an illustrative field arrangement. Operation context varies; use the actual challenge and session required by the authorized operation. `final=0` occurs in documented requests, but its complete semantics are unresolved. Some other device paths use different `httpslink` values; do not generalize this example across transports.

The authenticated device session selects the device. Lowering `currentfw` can cause an available offer, but does not select an arbitrary historical version. Changing the `WBS15` context token while keeping a session is not established as a target-model override. Status 0 without a usable URL is not a download offer.

### Firmware response

```json
{
  "status": 0,
  "body": {
    "url": "https://cdnfw.withings.net/wbs15/wbs15_1831_REDACTED.bin",
    "version": "1831",
    "md5": "<MD5_HEX>",
    "sha1": "<SHA1_HEX>",
    "signature": "<FIRMWARE_SIGNATURE_HEX>",
    "sha512": "<SHA512_HEX>"
  }
}
```

The final filename component is access information and is intentionally redacted. The corresponding earlier names are `wbs15_1811_REDACTED.bin` and `wbs15_1781_REDACTED.bin`. These are identified revisions, not a continuously maintained latest-version list. Checksums and authorization signatures have different purposes.

### Secure-update negotiation

The response uses mode/status-like TLV `0x0961` and a length-prefixed 32-byte field in TLV `0x09D3`. Its purpose and lifecycle are separate from `0x09B2`.

```text
0x09D3 value:
    20 | <32_CHALLENGE_BYTES_REDACTED>
```

Do not substitute the challenge from one operation for another merely because both have 32 bytes. A firmware-availability check is not proof that an image was transferred or installed. Download URLs, access tokens and actual challenge/signature values are not part of this publication.

The secure-update sequence is:

1. Initial device/server authentication negotiation uses `0x09B2`.
2. Secure-update negotiation uses `0x09C1`; the response includes `0x09D3`, carrying a length byte and a 32-byte random challenge.
3. The client submits `0x09C2` with structure `0x09D4`, containing two length-prefixed 64-byte fields: update hash material and signature material.
4. The device verifies the approval and responds with status in `0x0918`.
5. After acceptance, the client announces firmware and transfers chunks with `0x0967` / `0x0968`.

The firmware verifier incorporates the supplied 64-byte hash material, six bytes of device-related information, and the 32-byte challenge. It requires an existing generated challenge and records approval only after successful verification.

Observed failure handling includes:

| Condition | Handling |
|---|---|
| Missing `0x09D4` | `SIGN mandatory in SECURE FWUPDATE SIGN cmd` |
| Incorrect field lengths | `Sign info size mismatch` |
| Verification failure | `Hash sign mismatch`; status `2` |
| No generated challenge | `Secure update no random generated`; status `3` |
| Successful verification | Approval recorded; observed response status `0` |

The BS2 handler family has the same field-size requirements and error handling as the documented secure-update sequence. Its use in the encrypted live BS2 exchange is inferred from the matching implementation; a complete plaintext BS2 update transcript is not asserted here.

The exchange is consistent with server-issued authorization verified by the device using embedded verification material. The exact signing service implementation and precise cryptographic construction are not established here. The challenge binds authorization to the exchange; an earlier approval must not be assumed reusable for a fresh challenge.


### Chunk transfer and resumption

| Command / TLV | Purpose |
|---|---|
| `0x0967` / `0x096E` | Announce image and transfer metadata |
| `0x0967` / `0x096F` | Obtain transfer position and chunk parameters |
| `0x0968` / `0x0970` | Send image chunks and exchange progress |
| `0x0151` | Associated reboot operation; state-dependent |

Transfer resumption is separate from approval. Approval from an earlier challenge must not be assumed reusable after a new challenge. Stored image/header/component consistency checks do not replace vendor authorization. CRC repairs alone do not satisfy the BS2 secure-update approval path.

### Older-device comparison

Older streaming implementations use `0x0401` to start/negotiate a transfer, raw data for image content, `0x0402` acknowledgements and `0x0403` completion. Body Smart has a demonstrated application-image path based on package/component CRC checks; that result must not be carried over to Body Scan 2. Presence of older handlers or the newer chunking commands does not establish an alternative BS2 installation path without secure approval.

### Standalone client and hardware dependence

A standalone client can authenticate to the owned scale, request a fresh device proof, establish its own authenticated device session, and request an offer. An existing account certificate is not established as sufficient to sign a fresh device proof. Having a firmware image does not provide the device's separate persistent factory secret or private signing key.

A direct network-session route may be possible with the correct stored secret, subject to the documented limitations. No model-only firmware-discovery endpoint, hardware-free arbitrary-device enrollment, or general credential-extraction WPP command has been established.

Handle expired sessions by authenticating again. Status 501 with an invalid-session error means the session was rejected; it is not evidence about whether a requested model or revision exists. Avoid repeated identical requests after rejection. Preserve the offered filename, use `-2`, `-3`, etc. on collisions, finish downloads through temporary files, and keep account/session credentials out of CDN download requests.

Downloading an image is not installing it. Cross-model firmware compatibility is not established.

## Authenticated local measurement retrieval

Authenticated local retrieval has been demonstrated on a previously provisioned Body Scan 2, model 19, using existing legitimate authentication material.

The documented conversation established TLS 1.3 with `TLS_CHACHA20_POLY1305_SHA256`, completed the existing-association WPP authentication exchange, and retrieved stored measurements through **`0x010F` GET_STATE and GET_ALL** operations.

Returned records included session metadata (`0x0116`), numerical measurements (`0x0117`), additional attributes, and transfer completion (`0x0100`). A completion TLV must not be confused with a command to acknowledge, delete or permanently consume the returned records.

No explicit measurement acknowledgment, synchronization-completion or deletion command was sent in that retrieval. Persistence of the retrieved records was not independently established. This finding establishes access to an already provisioned scale; it does not establish replacement credential installation or independent enrollment of a factory-reset device.

## Recorded ECG and risk-result fields

The following result enumeration applies to diagnosis type **`0x82` (130)** in the documented 1811 result path. It is a classification, not a score out of 100.

| Code | Firmware label |
|---|---|
| -3 | Hidden |
| -2 | Undefined |
| -1 | Not processed |
| 0 | Negative |
| 1 | Positive |
| 2 | Inconclusive |
| 3 | No signal |
| 4 | Other |
| 5 | Noise |
| 6 | Low Heart rate |
| 7 | high heart rate |
| 8 | Inconclusive US |
| 9 | Negative normal HR |
| 10 | Negative high HR |
| 11 | Positive normal HR |
| 12 | Positive high HR |
| 13 | No diagnosis |

These are stored result classifications, not a 0–100 score. The device result path carries handle ECG diagnosis and heart rate separately. This establishes a result path on the device, not the internal detection formula.

### Other risk fields

No trustworthy enum or producer-to-export mapping is established for **Checked Atrial Fibrillation** or **Hypertension Risk Notification**.

Do not apply type-130's meaning of code 4 (Other) to Checked Atrial Fibrillation: it is a separate exported measurement type. Likewise no conclusion that hypertension result 0 means normal follows from this mapping.

The existing CSV metadata description of Checked Atrial Fibrillation, and earlier comments calling it feature enablement, remain provisional pending a verified mapping.

## Firmware revision history

### 1831

Compared with 1811:

- Revised force-sensor temperature calibration, including additional calibration checks and failure handling.
- Added clock validation before scheduling temperature calibration.
- Retains the segment-level body-composition smoothing correction introduced in 1811.
- No additional body-composition formula adjustment has been identified.
- No change has been identified in the reviewed provisioning behavior.

**Expected relevance:** Weight measurement and temperature compensation. Changes in measured weight can indirectly influence body-composition estimates, but this should not be described as a confirmed BIA accuracy improvement.

### 1811

Compared with 1781:

- **Corrected fat-free mass versus muscle mass handling in segment-level body-composition smoothing.** These are distinct quantities: fat-free mass includes muscle and other non-fat tissue.
- **Corrected the normalization basis from fat mass + muscle mass to fat mass + fat-free mass.** The corresponding muscle proportion now uses muscle mass rather than fat-free mass as its numerator.
- **Corrected coordinated result handling.** Updates how the smoothing process places and reads fat-free and muscle values for individual segments, including the remaining segment derived from the totals. This is more than a change to display labels.
- No broader recalibration of the whole-body composition model has been established.

**Expected relevance:** Segment-level fat, fat-free mass and muscle results. This correction does not establish that whole-body estimates became more accurate or that all reported body-composition discrepancies were resolved.

### 1781

Baseline for this comparison; no earlier firmware is covered.

- Uses the earlier segment-level smoothing behavior corrected in 1811.
- Predates the additional force-sensor temperature-calibration handling identified in 1831.

**Interpretation:** The later segment-smoothing correction does not mean that every measurement recorded with 1781 is incorrect, or that every body-composition metric is affected.


These are unofficial, non-exhaustive differences. They do not establish better accuracy against reference measurements.

## Firmware implementation details

### Proprietary BIA equations

The actual BIA measurement and body-composition prediction equations, coefficients, and complete algorithm implementations are proprietary and will not be published, just as credentials and other secrets will not be published. This document limits its discussion to high-level behavior, data flow, metric definitions, and identified changes between firmware revisions. The normalization ratios below explain fat, fat-free and muscle bookkeeping; they do not disclose the impedance-to-composition prediction equations.

### Package and component changes in 1831

| Item | 1811 | 1831 |
|---|---:|---:|
| Total package bytes | 1,710,148 | 1,710,660 |
| Main application component, type 1 | 798,504 | 798,880 |
| Component type 11 | 408,576 | 408,712 |

The 512-byte growth comprises 376 bytes in the main application and 136 in component 11. Components 4, 9, 13 and 15 are identical after accounting for their relocated package positions. Component numbers are package identifiers; no unverified hardware-role name is assigned to component 11.

The changed components have October 30, 2026 build timestamps; corresponding earlier components have October 12 and September 9 timestamps. These are build timestamps, not release dates.

The SHA-256 identifier of the documented 1831 package is:

```text
0add0af1bcf825c4c1c23996d017449c5550edee2bbc62606332393e86c1a519
```

This package checksum is not a credential or a download-access suffix.

### Force-sensor temperature calibration

1831 rejects a time before **December 18, 2024 at 00:00 UTC** when scheduling its temperature-calibration alarm. The diagnostic is:

```text
[FORCE] Invalid time, temp calib alarm not set
```

The corresponding 1811 scheduler lacks that check. Avoiding an uninitialized clock is a plausible purpose, not a documented product requirement.

Internal calibration command **`0x57`** retains the four-byte request `01 00 0F 00`, while its expected response grows from **28 to 32 bytes**. This is an internal subsystem exchange, not WPP command `0x0057`.

Both success and failure diagnostics add `init_std`, alongside standard error, temperature delta and initial sensor temperature. Component 11 adds the corresponding `Init_std` field. Its precise physical unit and numerical acceptance threshold remain unresolved; it is not a new body-temperature reading or a statement about displayed weight precision.

1831 checks an additional condition before calibration and after a nominally successful response; the second check can reject the result. It handles transport failure separately and initializes failure-report fields. The exact physical condition represented by the additional check remains unresolved. The persistent calibration-record size in this path remains **24 bytes**.

The standard-error diagnostic changes from signed `%ld` to unsigned `%lu`. That formatting change does not establish different CSV precision.

### Body-composition algorithm identifiers

| Firmware | Local algorithm identifier |
|---|---|
| 1781 | `0x0D040105` |
| 1811 | `0x0D040106` |
| 1831 | `0x0D040106` |

The identifier's encoding is not assumed to be a public semantic version.

### Segment smoothing correction in 1811

The correction concerns **historical post-calculation smoothing**, rather than an established replacement of the base BIA prediction model. The historical buffer has capacity for 16 records. Capacity does not mean 16 days or that all 16 records are present and usable.

The per-segment input triple represents **fat mass, fat-free mass, muscle mass**. The associated measurement identifiers are:

| ID | Meaning |
|---|---|
| 174 / `0xAE` | Segment fat mass in mass units |
| 173 / `0xAD` | Segment fat-free mass |
| 175 / `0xAF` | Segment muscle mass |

The normalization changes are:

```text
1781:
    denominator       = fat + muscle
    fat proportion    = fat / denominator
    muscle-path ratio = fat-free / denominator

1811 and retained in 1831:
    denominator       = fat + fat-free
    fat proportion    = fat / denominator
    muscle proportion = muscle / denominator
```

The corresponding reconstruction and caller change their second/third-field interpretation together. Segment fat is reconstructed from its fat proportion, fat-free mass is the remaining segment mass, and muscle is reconstructed from its muscle proportion. Four segments are processed in a loop; the fifth is derived from residual totals. The correction includes the fifth segment's fat-free/muscle destinations.

This is more than a display-label change. It also does not mean that two exported metric names were simply exchanged or that every measurement from 1781 is invalid. No numerical correction factor for historical user measurements is established.

### Body composition in 1831 versus 1811

The corresponding input/output path retains its arithmetic, field handling, error masks, output scaling and rounding in the examined regions. Inputs include sex, body mode, age, height, weight and impedance/phase values. Athlete-mode selection remains present without an identified new correction.

The result path covers fat mass, fat-free mass, water, muscle mass, bone mass, skeletal muscle, visceral-fat index, BMR, metabolic age, fat-mass index, muscle index and skeletal-muscle index. No new formula change is established in this path between 1811 and 1831.

In the corresponding 23,676-byte calculation region, differences are accounted for by branch/address relocation and pointers to matching data. The corresponding 6,400-byte numeric/data region retains its non-pointer words. These are bounded findings, not proof that every helper or coefficient anywhere in the image is unchanged.

The corresponding provisioning behavior retains the ten accepted feature IDs, ECG variant precedence, exact-user lookup, first-occurrence cross-profile lookup, missing-versus-off distinction and Japan-mode cap. The feature table remains nine 52-byte slots with twelve tag positions per slot. This does not establish every authorization/display workflow or every menu behavior in 1831.

No additional BIA accuracy improvement is established for 1831. Temperature-dependent weight changes can indirectly alter composition results because weight is an input; that dependency does not demonstrate a new fat/muscle model or corrected accuracy against reference measurements.

## Inline JSON configuration examples

These examples are not interchangeable: association, session, features and screens have different consumers. Tokens and keys are placeholders. The session and association examples are partial structural illustrations, not complete replay payloads. The feature and screen lists preserve the documented configuration states while replacing user identities with the synthetic aliases used throughout this reference.


### Association response

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

### Partial session document

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

### Device and named-user features

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

### Ordered user menus

```json
{
  "status": 0,
  "body": {
    "user_screens": [
      {
        "userid": 100001,
        "screens": [
          {
            "id": 66,
            "source": 1,
            "embeddedid": 11,
            "deactivable_status": 6,
            "rank": 1
          },
          {
            "id": 109,
            "source": 1,
            "embeddedid": 2,
            "rank": 2
          },
          {
            "id": 116,
            "source": 1,
            "embeddedid": 1,
            "rank": 3
          },
          {
            "id": 54,
            "source": 1,
            "embeddedid": 16,
            "rank": 4
          },
          {
            "id": 302,
            "source": 1,
            "embeddedid": 22,
            "rank": 5
          },
          {
            "id": 253,
            "source": 1,
            "embeddedid": 20,
            "rank": 6
          },
          {
            "id": 466,
            "source": 1,
            "embeddedid": 26,
            "rank": 7
          },
          {
            "id": 58,
            "source": 1,
            "embeddedid": 12,
            "parent_screen_id": 118,
            "rank": 8
          },
          {
            "id": 118,
            "source": 1,
            "embeddedid": 3,
            "rank": 9
          },
          {
            "id": 465,
            "source": 1,
            "embeddedid": 25,
            "rank": 10
          },
          {
            "id": 464,
            "source": 1,
            "embeddedid": 23,
            "rank": 11
          }
        ]
      },
      {
        "userid": 100002,
        "screens": [
          {
            "id": 66,
            "source": 1,
            "embeddedid": 11,
            "deactivable_status": 6,
            "rank": 1
          },
          {
            "id": 116,
            "source": 1,
            "embeddedid": 1,
            "rank": 2
          },
          {
            "id": 54,
            "source": 1,
            "embeddedid": 16,
            "rank": 3
          },
          {
            "id": 41,
            "source": 1,
            "embeddedid": 15,
            "rank": 4
          },
          {
            "id": 253,
            "source": 1,
            "embeddedid": 20,
            "rank": 5
          },
          {
            "id": 466,
            "source": 1,
            "embeddedid": 26,
            "rank": 6
          },
          {
            "id": 58,
            "source": 1,
            "embeddedid": 12,
            "parent_screen_id": 118,
            "rank": 7
          },
          {
            "id": 118,
            "source": 1,
            "embeddedid": 3,
            "rank": 8
          },
          {
            "id": 465,
            "source": 1,
            "embeddedid": 25,
            "rank": 9
          },
          {
            "id": 464,
            "source": 1,
            "embeddedid": 23,
            "rank": 10
          },
          {
            "id": 65,
            "source": 1,
            "embeddedid": 10,
            "deactivable_status": 2,
            "rank": 11
          }
        ]
      },
      {
        "userid": 100003,
        "screens": [
          {
            "id": 66,
            "source": 1,
            "embeddedid": 11,
            "deactivable_status": 6,
            "rank": 1
          },
          {
            "id": 116,
            "source": 1,
            "embeddedid": 1,
            "rank": 2
          },
          {
            "id": 54,
            "source": 1,
            "embeddedid": 16,
            "rank": 3
          },
          {
            "id": 58,
            "source": 1,
            "embeddedid": 12,
            "parent_screen_id": 118,
            "rank": 4
          },
          {
            "id": 118,
            "source": 1,
            "embeddedid": 3,
            "rank": 5
          },
          {
            "id": 65,
            "source": 1,
            "embeddedid": 10,
            "deactivable_status": 2,
            "rank": 6
          }
        ]
      }
    ],
    "device_screens": []
  }
}
```

The association ID must not automatically be substituted for the wire owner ID. Session fields and feature values must not be merged by an assumed universal inheritance rule. Menu ordering must be preserved independently of parent relationships.

## Completion, limitations and remaining questions

Setup completion and disconnect are separate operations (`0x0113` and `0x0110` in the established command map). A successful command response is not evidence that every desired feature or screen is usable.

Later synchronization has its own systems for session/profile updates, measurements, signals, events, features, menus, locale and units. Menu synchronization can be skipped when the client's synchronized flag says no update is required. Keep transport completion, logical-document completion, persistence completion and user-facing setup completion distinct.

### Remaining work

The strongest newly resolved part is the complete structured menu record and its multi-packet replacement behavior. These remaining areas must not be silently filled with guesses:

- The outer installation coordinator's full chronological orchestration of transport, network choice, association, any upgrade/reconnect and final setup completion.
- The complete upstream screen-selection policy: active-state filtering, dependency handling, rank normalization, nonembedded content and every fallback branch.
- A complete authorized session document schema and the full meaning/default behavior of every profile field.
- Factory-reset enrollment, credential issuance/replacement and recovery from interruption at each stage.
- A verified way to request an empty user menu, rather than omitting the profile or replacing it with a nonempty list.
- Every timeout, retry, capability distinction and error/status mapping for each firmware version.

The existence of defined WPP messages makes an independent client feasible to investigate. It does not establish hardware-free device authentication, the ability to manufacture vendor approval signatures, or complete independent factory enrollment.

The precise certificate trust anchor, issuance process and validation policy remain unresolved. Persistence of accepted TLS credentials after reset does not establish that all later enrollment requirements survive reset or can operate offline.

Full feature eligibility, per-user authorization, ECG review clearing and instant-result behavior must not be inferred from one feature flag. Configuration behavior does not establish clinical validity, regulatory authorization, or suitability for diagnosis or treatment.

This study is independent of Withings. For the generic WPP command catalogue and other device families, see [COMMAND_REFERENCE.md](COMMAND_REFERENCE.md) and [PROTOCOL.md](PROTOCOL.md). All Body Scan 2 findings consolidated here stand on their stated version and evidence limits.
