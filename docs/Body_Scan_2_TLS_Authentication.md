# Body Scan 2 — TLS Authentication and Provisioning Dependencies

**Device:** Withings Body Scan 2 (model 19)  
**Firmware tested:** 1781  
**Transport:** TLS 1.3 over Bluetooth Low Energy (BLE)  
**Investigation:** October 2026

## Overview

The Body Scan 2 (BS2) uses TLS 1.3 over a proprietary BLE transport. Unusually, **the scale acts as the TLS client and the companion application acts as the TLS server**. The scale checks the certificate presented by the application before encrypted device commands can be exchanged.

Testing establishes that an accepted account-specific certificate can authenticate to the scale **without an internet connection**, even after a full factory reset. This is distinct from completing device setup: the official provisioning workflow involves account association, installation of Bluetooth association credentials, and subsequent session and device configuration. Complete independent offline provisioning has **not** been demonstrated.

This document summarizes protocol behavior and experimental outcomes without attributing individual findings to particular investigative sources. It intentionally omits credentials, account and device identifiers, and credential acquisition details.

## 1. TLS certificate and trust

An accepted certificate examined during testing had these properties:

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

### Certificate validation experiments

Three configurations were tested against both a previously paired device and a fully factory-reset device:

| Presented certificate | Result |
| --- | --- |
| Previously accepted certificate | TLS handshake completed |
| Reconstructed certificate with a new keypair, preserving identity fields and extensions | Rejected |
| Reconstructed certificate retaining the accepted public key, but with a different certificate signature | Rejected |

Rejected certificates produced the TLS fatal alert **`bad_certificate` (42 / `0x2A`)**. The reconstructions retained the subject, issuer, serial number, validity period, and extensions of the accepted certificate.

These results show that matching certificate metadata—or even reusing the accepted public key—is not sufficient. They are consistent with validation against a persistent manufacturer trust anchor, but **do not distinguish issuer-signature verification from certificate pinning or another trust policy**.

## 2. BLE transport and TLS handshake

The observed sequence is:

1. Discover and connect to the scale over BLE; complete GATT setup and enable notifications.
2. Send a pre-TLS initialization message that includes account context.
3. Receive a TLS `ClientHello` from the scale.
4. Respond with the application's TLS server handshake and certificate.
5. Allow the scale to validate the certificate and complete the handshake.
6. Exchange device-protocol messages inside encrypted TLS application records.

The successful negotiation used:

```text
TLS version:  TLS 1.3
Cipher suite: TLS_CHACHA20_POLY1305_SHA256
TLS client:   Body Scan 2
TLS server:   Companion application
```

An unacceptable certificate is rejected **before** encrypted provisioning commands can proceed. The scale does not need Wi-Fi or a live internet connection to perform this observed TLS authentication step.

On macOS, CoreBluetooth peripheral identifiers were observed changing between discovery sessions. Discovering the device afresh by its advertisement and using the resulting peripheral object proved more reliable than relying on a previously recorded CoreBluetooth identifier. The advertised name is not itself an authenticated identity.

## 3. Account association and provisioning

The factory-reset provisioning workflow can be described at the following **high level**:

| Stage | Observed activity |
| --- | --- |
| Secure connection | BLE setup and TLS authentication |
| Device identification | Initial identification, connection context, battery status, and challenge exchanges |
| Basic configuration | Firmware checks, Wi-Fi settings, locale, and regional settings |
| Account association | Association with an account and synchronization of device/account state |
| Credential installation | Association credentials delivered to the scale |
| Session provisioning | A further challenge followed by session data transfer |
| Device preferences | Screen selection, feature configuration, and measurement units |
| Completion | Successful setup acknowledgment and disconnection |

The **credential-installation stage is not the end of setup**. A further challenge and session configuration occur afterward, followed by other device settings. Session provisioning appears to involve multiple operations, but whether these represent segmentation, retries, or another implementation detail has not been resolved. Some optional configuration operations can fail as unsupported without preventing setup from succeeding.

### Bluetooth association credentials

The provisioning sequence includes installation of an **association key (KL)** and a **Bluetooth advertising key** on the device. These credentials are consistent with the account-association mechanism used across related Withings products. Separate experiments with other Withings devices show that provisioned credentials can support subsequent authenticated BLE communication and measurement retrieval.

These observations **do not establish** whether the keys are generated on the server or elsewhere, nor do they prove that every device model uses identical binary credential encoding. The exact BS2 credential-installation payload remains inside encrypted TLS application data.

### Possible role of online services

The association and configuration stages are consistent with the possibility that the companion application obtains account-specific information from manufacturer-operated services. **This remains an architectural hypothesis; the BLE findings do not establish the role of those services.** The origin of association credentials and the source of user-specific configuration have not been established by the BLE experiments.

The BS2's encrypted application records have not been decoded sufficiently to reconstruct its complete provisioning payloads or determine whether configuration data is transmitted as JSON, binary structures, or another representation.

## 4. Comparison with other Withings devices

The provisioning workflows identified for **BeamO**, **Body Smart**, and **Body Scan 2** share a recognizable high-level order: device identification, account association, association-credential installation, an additional challenge, session configuration, device preferences, and setup completion.

This supports a **shared provisioning architecture** across these device families. It does **not** prove that their authentication transports, message layouts, or all device-specific configuration steps are interchangeable.

The Body Smart is a particularly relevant comparison because it is another scale and exposes binary configuration exchanges in a BLE capture. This provides a useful comparison for the BS2's encrypted provisioning stages, but exact on-wire equivalence remains unverified.

## 5. Offline operation and infrastructure dependence

The experiments distinguish three separate requirements:

| Requirement | Current finding |
| --- | --- |
| **TLS authentication** | An already accepted account certificate can complete TLS with the BS2 offline, including after factory reset. |
| **Obtaining an accepted certificate** | Independently reconstructed certificates were rejected. Issuance and trust mechanisms remain unknown. |
| **Complete device provisioning** | Online services may participate in association or configuration, but their precise role has not been established. A complete independent offline setup has not been demonstrated. |

The long certificate validity is notable, but it does not establish indefinite access: other checks, credential lifecycles, firmware behavior, or provisioning requirements may impose additional constraints.

If provisioning requires manufacturer-operated services, their unavailability could prevent the official application from configuring a reset device. The hardware's demonstrated ability to establish TLS offline **does not by itself establish** that the entire setup can be completed without those services.

## 6. Established findings and open questions

**Established by observation:**

- BS2 uses TLS 1.3 over BLE, with the scale as client and the application as server.
- The scale rejects reconstructed certificates with a `bad_certificate` alert.
- Acceptance of an existing certificate survives a full factory reset.
- An accepted certificate can complete the TLS handshake without internet connectivity.
- Successful setup includes account association, credential installation, further challenge/session provisioning, and device configuration.
- Other Withings devices show a closely related high-level provisioning sequence.

**Not yet established:**

- The precise certificate trust anchor, validation policy, or issuance process.
- Where account-association keys originate, and whether online services participate in their creation or delivery.
- The exact BS2 binary layouts for credential installation and session provisioning.
- Whether the BS2 performs any additional post-setup data transfer equivalent to that observed on another scale.
- Whether complete BS2 setup and recovery can be implemented offline using previously accepted credentials.

## Implications

The BS2 illustrates a distinction between **secure hardware communication** and **manufacturer-supported provisioning**. Offline TLS authentication has been demonstrated, but complete device setup still involves steps whose dependence on online services is not fully understood.

Further protocol analysis may clarify whether independently implementing the remaining provisioning operations could reduce that dependence and preserve the usefulness of otherwise functional hardware.
