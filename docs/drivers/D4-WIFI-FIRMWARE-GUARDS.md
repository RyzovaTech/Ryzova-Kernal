<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# D4 Wi-Fi firmware ingestion guards

Source-side safety changes for Intel iwl, Intel wpi, and Ralink rt2860 firmware readers:
- Reject zero, negative, or >16 MiB declared firmware lengths before allocation or reading.
- Guard the Ralink firmware metadata allocation against failure before dereference.
- This does not add Wi-Fi device IDs, distribute third-party firmware, verify firmware signatures, or certify radio interoperability.
- Real firmware API/version handling, matching device revisions, boot, connect/disconnect, suspend/resume, RF-kill and physical Wi-Fi tests remain required.
