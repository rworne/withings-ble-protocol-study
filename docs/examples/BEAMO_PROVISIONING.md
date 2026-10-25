# BeamO BLE provisioning: annotated PacketLogger example

**Source:** `beamo-setup.pklg`, examined using Withings PacketLogger Analyzer v1.1.  
**Status:** Observed in a real capture; not a universal provisioning specification.  
**Privacy:** This document contains no raw authentication material, device identifiers, owner identifiers, Wi-Fi credentials, or configuration payloads. **Do not commit the source `.pklg` or private analyzer JSON to a public repository.**

## Capture and interpretation

The analyzer processed **9,346 PacketLogger records**. The principal provisioning sequence below uses connection handle `0x005E`. PacketLogger record numbers identify events within this specific capture, not protocol sequence numbers. The analyzer reported **eight L2CAP reassembly warnings** across the capture; none was reported within the `0x010D` configuration-transfer record range (7122–7142). This does not establish that every part of the capture is complete.

The table distinguishes **observed command exchanges** from higher-level interpretations. A device response establishes that a response was seen; it does not by itself prove that every user-facing feature became operational.

| Record(s) | Direction | WPP command | Observed structure / result |
|---|---|---|---|
| 7082 → 7084 | Host → device; device → host | `0x0134` | Request with `0x0135` and `0x0136` TLVs; response contains empty `0x0100` TLV. Sensitive values omitted. |
| 7091 → 7101 | Host → device; device → host | `0x09B2` | Request includes `0x09C2`; two device messages carry `0x09C3`, then `0x09C4` and empty `0x0100`. |
| 7122–7140 | Host → device | `0x010D` | Six messages containing `0x0112` data chunks. |
| 7142 | Host → device | `0x010D` | Empty `0x0100` TLV terminates the transfer. |
| 7151 | Device → host | `0x010D` | Empty WPP response; analyzer associates it with the transfer. |
| 7152 → 7162 | Host → device; device → host | `0x0108` | Both messages contain a `0x0108` TLV. |
| 7163 → 7166 | Host → device; device → host | `0x011A` | Request contains `0x0121`; response contains empty `0x0100`. |
| 7168, 7170, 7175 → 7178 | Host → device; device → host | `0x09C3` | Three requests carry `0x0145` and multiple `0x09D5` TLVs; final request also contains empty `0x0100`. Response contains empty `0x0100`. Feature values and target IDs omitted. |
| 7183 → 7194 | Host → device; device → host | `0x0112` | Request and response each contain `0x0119` TLV. |
| 7195 → 7209 | Host → device; device → host | `0x0113` | Empty-payload request and response observed. |
| 7290 → 7292 | Host → device; device → host | `0x0110` | Empty-payload request and response observed. |

## Reconstructed `0x010D` transfer

The analyzer reports one logical transfer on handle `0x005E`:

| Property | Observed |
|---|---|
| First chunk record | 7122 |
| Final data-chunk record | 7140 |
| Terminator record | 7142 |
| Acknowledgment record | 7151 |
| Data-bearing `0x0112` chunks | 6 |
| Total bytes within the `0x0112` TLV values | 350 |
| Reconstructed content bytes after removing per-chunk one-byte length prefixes | **344** |
| Explicit terminator seen | Yes |
| Device acknowledgment seen | Yes |
| Analyzer `json_valid` | **`null` (not established)** |

The six `0x0112` TLV value lengths are **64, 64, 64, 64, 64, and 30 bytes**. Under the observed one-byte chunk-length-prefix convention, this yields `(5 × 63) + 29 = 344` content bytes. Each of these messages is an individually framed WPP message, not merely a Bluetooth transport fragment.

**Important limitation:** The reconstructed BeamO content was **not validated as JSON** by this analyzer run (`json_valid: null`). Do not describe it as successfully decoded JSON or publish guessed field values. This result demonstrates transfer framing, chunk aggregation, termination, and response association—not complete semantic decoding of the payload.

## Secondary configuration (`0x09C3`)

Three host requests at records **7168**, **7170**, and **7175** each contain one `0x0145` TLV and six `0x09D5` TLVs. The final request additionally includes the empty `0x0100` terminator. The device responds at **7178** with an empty `0x0100` TLV.

This validates the **presence and grouping** of secondary configuration TLVs in this capture. The public analyzer output redacts their contents, so this example does **not** assert specific feature IDs, feature values, region mappings, or per-user settings. Those must be supported by a separate, explicitly reviewed private decode before being added to public documentation.

## Scope and reproducibility

- The source is an observed BeamO provisioning capture, **not** a generated or hypothetical message sequence.
- Record indices, WPP commands, TLV types and lengths, transfer statistics, and acknowledgments above come from the analyzer's sanitized report.
- The sequence is **not** evidence that provisioning was universally successful on every firmware or that a feature was activated merely because its configuration command received a response.
- The capture contains additional traffic not reproduced here; this is an annotated excerpt, **not a complete packet-by-packet transcript**.
- A separate BPM Vision capture also exhibits chunked `0x010D` configuration transfer, but the number of chunks and reconstructed payload length differ. Do not assume payload encoding is identical across devices.

To reproduce locally, run the analyzer against your own capture and inspect the `timeline`, `configuration_transfers`, and `warnings` fields of the sanitized JSON report. Keep private reports and raw PacketLogger captures outside the public repository.
