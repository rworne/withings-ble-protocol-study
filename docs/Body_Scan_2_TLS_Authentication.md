# Body Scan 2 — TLS Authentication and Infrastructure Dependencies

**Device:** Withings Body Scan 2 (Model 19)  
**Firmware tested:** 1781  
**Protocol:** TLS 1.3 over Bluetooth Low Energy  
**Investigation:** October 2026

## Overview

The Withings Body Scan 2 (BS2) uses TLS 1.3 over Bluetooth Low Energy (BLE) to secure communication with the Withings application.

Interestingly, the scale operates as the **TLS client**, while the application operates as the **TLS server**.

Experiments demonstrate that the scale validates the certificate presented by the application, including when the scale has been factory-reset and has not yet been paired.

This behavior has significant implications for independent implementations and the long-term usability of the hardware.

## 1. TLS Certificate Characteristics

The TLS server certificate examined during testing has the following characteristics:

| Property | Value |
|---|---|
| Certificate format | X.509 v3 |
| Subject | Account-specific identifier |
| Issuer | `WBS15` |
| Public key algorithm | Ed25519 |
| Signature algorithm | Ed25519 |
| Validity | Approximately 99 years |
| Basic Constraints | `CA:FALSE` |
| Extended Key Usage | TLS Server Authentication, TLS Client Authentication |

The certificate is associated with an account rather than explicitly identifying an individual scale.

Its unusually long validity period suggests a design intended to minimize certificate renewal requirements.

The precise certificate issuance and renewal mechanisms have not been established.

### Certificate validation experiments

Three certificate configurations were tested:

| Certificate | Public key | Certificate signature | TLS result |
|---|---|---|---|
| Original certificate | Original | Original issuer signature | **Accepted** |
| Reconstructed certificate | Newly generated | Signed using new key | **Rejected** |
| Reconstructed certificate | Original | Signed using original account key | **Rejected** |

The reconstructed certificates preserved the original certificate's subject, issuer, serial number, validity period, and X.509 extensions.

Both reconstructed certificates were rejected with:

```text
TLS fatal alert: bad_certificate (0x2A)
```

The experiments were performed against both an already-paired scale and a factory-reset, unpaired scale.

The original certificate successfully established TLS in both states.

**Finding:** The scale enforces certificate trust independently of its pairing state. Merely reproducing the certificate's identity fields or retaining its original public key is insufficient.

The results are consistent with verification against a manufacturer-installed trust anchor, potentially associated with the `WBS15` issuer.

However, exact-certificate pinning or another trust mechanism that survives factory reset has not been conclusively excluded.

## 2. BLE/TLS Handshake

TLS communication is transported over a proprietary Withings GATT characteristic.

The observed handshake follows this sequence:

1. The application discovers the scale and establishes a BLE connection.
2. GATT discovery completes and notifications are enabled.
3. The application sends a pre-TLS initialization message containing an account identifier.
4. The scale responds with a TLS ClientHello.
5. The application responds with its TLS server handshake and certificate.
6. The scale validates the certificate.
7. If accepted, TLS negotiation completes.
8. Subsequent WPP protocol messages are exchanged within the encrypted TLS connection.

The successful handshake negotiated:

```text
TLS version: TLS 1.3
Cipher suite: TLS_CHACHA20_POLY1305_SHA256
```

### Certificate rejection behavior

With a reconstructed certificate, the observed sequence is:

```text
Scale → Application: TLS ClientHello
Application → Scale: TLS server handshake
Scale → Application: TLS fatal alert (bad_certificate)
```

With the original certificate, TLS negotiation completes successfully.

The certificate rejection occurs before WPP authentication or provisioning.

### BLE device discovery

During testing, macOS CoreBluetooth identifiers were observed changing between discovery sessions.

Reliable discovery was achieved by locating the device through its advertised name and connecting using the discovered BLE peripheral object.

This avoids reliance on persistent CoreBluetooth identifiers.

The advertised name is not considered a cryptographically secure device identifier.

## 3. Factory Reset and Certificate Trust

A factory-reset BS2 was tested before completing account pairing or Wi-Fi provisioning.

Two certificates were presented under otherwise equivalent conditions:

| Certificate | Factory-reset TLS result |
|---|---|
| Original certificate | **Handshake successful** |
| Reconstructed certificate | **Rejected: bad_certificate** |

This demonstrates that the certificate trust requirement exists before normal account pairing.

The scale can evaluate the presented certificate without first establishing an internet connection.

The most likely explanation is an offline trust mechanism built into the device.

The experiments do not establish whether the scale uses an embedded issuer public key, certificate pinning, or another validation mechanism.

## 4. Dependency on Withings Infrastructure

The official Withings application requires internet connectivity during device pairing.

However, the experiments demonstrate that the BS2 can establish TLS over BLE without internet connectivity when presented with an accepted certificate.

These are separate requirements:

**TLS authentication**

The scale requires a certificate that satisfies its trust mechanism. This validation can occur offline.

**Certificate issuance**

The scale rejects independently reconstructed certificates. Consequently, obtaining an accepted certificate may depend on Withings' certificate infrastructure.

**Device provisioning**

The official application requires online connectivity during pairing. The complete independent pairing and Wi-Fi provisioning workflow has not yet been reproduced.

### Long-term device usability

If Withings' online services become unavailable, factory-reset devices may become impossible to configure using the official application.

The hardware itself is capable of establishing secure BLE communication offline, but this does not guarantee that the remaining provisioning process can be completed independently.

The approximately 99-year certificate validity is noteworthy: an already accepted certificate may remain usable for an exceptionally long period.

However, the ability to establish TLS alone does not constitute a complete offline provisioning solution.

## 5. Conclusions

The investigation established the following:

- The Body Scan 2 uses TLS 1.3 over BLE.
- The scale acts as the TLS client.
- The application acts as the TLS server.
- The scale validates the application's certificate before completing TLS.
- Independently reconstructed certificates are rejected.
- Retaining the original account public key does not bypass certificate validation.
- Certificate trust enforcement persists after factory reset.
- TLS can be established without internet connectivity.
- The official pairing workflow nevertheless requires internet access.

The evidence strongly supports an offline certificate trust mechanism, although the precise verification method remains unidentified.

### Future Investigation

Further work should focus on:

1. Identifying the certificate trust mechanism implemented by the scale.
2. Determining whether the `WBS15` issuer signature is explicitly verified.
3. Characterizing the encrypted WPP pairing and provisioning exchanges.
4. Identifying which provisioning operations depend on Withings' online services.
5. Determining whether complete offline device recovery is possible.

## Implications

The Body Scan 2 demonstrates a significant distinction between **hardware capability** and **manufacturer-supported operation**.

The device can establish secure communication without internet access, but its official setup process depends on online services.

If those services become permanently unavailable, otherwise functional hardware may become difficult or impossible to reconfigure.

Independent implementation of the remaining provisioning protocol could potentially reduce that dependency and extend the useful life of the hardware.
