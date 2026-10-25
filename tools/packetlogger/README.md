# Withings PacketLogger Analyzer (experimental)

Offline, read-only Python 3 tool for inspecting Apple PacketLogger `.pklg` captures and reconstructing Withings WPP messages. **No network access, device connections, or third-party packages.**

## Run

```bash
python3 withings_pklg_analyzer.py /path/to/capture.pklg --out report.json
python3 withings_pklg_analyzer.py /path/to/capture.pklg --handle 0x58 --out report.json
python3 withings_pklg_analyzer.py /path/to/capture.pklg --private --out private-report.json
python3 -m unittest discover -s tests -v
```

By default the tool suppresses payload bytes, MAC addresses, advertising names, capture filename, and identifying JSON fields. Public output **still contains timing, connection handles, command sequences, payload lengths and feature IDs**, which may be sensitive in context. Inspect it before publishing. The tool does **not** anonymize the original `.pklg` capture.

`--private` preserves raw payload bytes, complete decoded JSON and identifiers. Private and public reports are written with file mode `0600` (owner only). Never commit private reports or raw captures.

## What it decodes

- PacketLogger records, LE advertising and connection events
- HCI ACL fragmentation and L2CAP ATT traffic
- WPP frames split across multiple ATT writes/notifications on the same connection, direction, and attribute handle
- Multiple WPP frames within a single ATT value
- Command registry, TLVs, feature settings (`0x09D5`), and logical primary configuration transfer (`0x010D`)
- Reassembles successive `0x010D` / `0x0112` length-prefixed chunks (one-byte length + bytes) through `0x0100`, and correlates the empty device acknowledgment
- Preserves every original WPP frame in `timeline`, and adds a `configuration_transfers` array with chunk count, assembled length, termination and acknowledgment
- Private mode decodes the completed JSON; public mode exposes only transfer metadata, never reconstructed JSON or payload
- WPP `0x0147` signal retrieval and `0x0148` acknowledgment at the command/TLV level

## Caveats

- **Experimental**. A WPP continuation is assumed to carry subsequent bytes on the same ATT attribute; other fragmentation patterns may need additional decoding.
- The analyzer does not reconstruct full ECG/audio files, decode audio, or automatically extract measurement databases.
- Incomplete WPP frames and overwritten L2CAP fragments are reported as warnings. A truncated capture cannot be repaired.
- Captures may contain multiple devices and recycled connection handles. Use `--handle` and inspect connection events.
- The command registry reflects observed devices; undocumented meanings may differ across firmware/models.
- A BLE packet capture does not grant access to encrypted traffic that was not recorded in plaintext.
- Sanitized synthetic tests do not prove correctness on every real capture. Compare against known captures locally.

See [`../../docs/COMMAND_REFERENCE.md`](../../docs/COMMAND_REFERENCE.md) after installing in the recommended repository structure.

MIT licensed; research-only, no warranty.

## Validated BPM Vision provisioning example

The 5,050-record local BPM Vision capture yielded **one** logical `0x010D` transfer: 11 complete WPP chunk frames, **631 JSON bytes** (642 bytes including eleven one-byte chunk prefixes), terminated by `0x0100` and acknowledged by an empty `0x010D` device response. The assembled private JSON parsed successfully. Earlier counts of 10 chunks / 642 JSON bytes were incorrect; the previous decoder mistook one chunk for standalone JSON.

Do not commit `--private` reports. The public output omits assembled JSON by design.
