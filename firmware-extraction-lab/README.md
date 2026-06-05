# Firmware Extraction from Network Traffic

Reconstructing and analyzing embedded device firmware from a packet capture using Scapy, base64 decoding, and binwalk.

## Overview

Given a packet capture containing a firmware download over a custom HTTP protocol, this lab demonstrates:

1. Traffic filtering and pattern analysis to identify the firmware transfer
2. Scapy-based packet reassembly to reconstruct the binary from fragmented, base64-encoded payloads
3. Filesystem extraction with binwalk
4. Static analysis of the extracted firmware to identify architecture, OS, and users

## Tools Used

- `scapy` — packet parsing and payload extraction
- `tcpdump` — initial traffic filtering
- `wireshark` — protocol analysis and pattern discovery
- `binwalk` — firmware extraction (`-M -e` recursive extract)
- `file`, `less` — filesystem investigation

## Skills Demonstrated

- Network forensics / PCAP analysis
- Binary reassembly from fragmented HTTP responses
- Base64 decoding of binary payloads
- Embedded Linux filesystem analysis

---

## Methodology

### 1. Traffic analysis

Loaded `firmware.pcap` in Wireshark and identified the firmware transfer on TCP port 9891. All relevant traffic was isolated with:

```bash
tcpdump -r firmware.pcap -w firmware_filtered.pcap 'tcp port 9891'
```

Key observations from packet inspection:
- Traffic flows between two hosts exclusively on port 9891
- Pattern is request → two responses; the second response contains the payload
- Each request includes an `offset` query parameter used for reassembly
- Payloads are base64-encoded binary data

### 2. Firmware reconstruction (Scapy)

```python
from scapy.all import sniff, TCP, Raw
from scapy.layers.http import HTTPRequest
from urllib.parse import parse_qs
from collections import defaultdict
import base64

# Load only packets with a raw payload
raw_packets = sniff(
    offline='firmware_filtered.pcap',
    filter="tcp",
    lfilter=lambda pkt: Raw in pkt
)

# Reassemble firmware chunks indexed by offset
flows = defaultdict(list)
i = 0

while i < len(raw_packets):
    pkt = raw_packets[i]
    if pkt[TCP].sport != 9891:
        try:
            path = str(HTTPRequest(pkt[Raw].load).Path)
            offset_str = parse_qs(path).get('offset', [None])
            offset = int(offset_str[0])
            if offset is None:
                i += 1
                continue
            j = i + 2
            while j < len(raw_packets):
                resp = raw_packets[j]
                if resp[TCP].sport == 9891:
                    flows[offset].append(resp[Raw].load)
                    j += 1
                else:
                    break
            i = j
            continue
        except Exception as e:
            print(f"Error parsing packet {i} at offset {offset}: {e}")
    i += 1

# Decode and write firmware binary
with open("download.bin", "wb") as f:
    for offset, payloads in sorted(flows.items()):
        for encoded in payloads:
            try:
                decoded = base64.b64decode(encoded)
                f.seek(offset)
                f.write(decoded)
                offset += len(decoded)
            except Exception as e:
                print(f"Error decoding at offset {offset}: {e}")
```

### 3. Firmware extraction

```bash
binwalk -M -e download.bin
```

This recursively extracts the squashfs filesystem into `_download.bin.extracted/squashfs-root/`.

### 4. Firmware analysis

**Architecture:**

```bash
file _download.bin.extracted/squashfs-root/bin/busybox
# ELF 32-bit MSB executable, MIPS
```

→ MIPS (big-endian, 32-bit)

**Operating system:**

```bash
less _download.bin.extracted/squashfs-root/etc/init.d/system
```

→ OpenWrt

**Users present on the system:**

```bash
less _download.bin.extracted/squashfs-root/etc/passwd
```

→ `root`, `daemon`, `ftp`, `network`, `nobody`, `dnsmasq`

---

## Key Takeaways

- Firmware transmitted over unencrypted HTTP with offset-based chunking is trivially reassembled from a passive capture — no credentials or active interception required
- Base64 encoding binary payloads over HTTP provides no meaningful security; it is an encoding scheme, not encryption
- OpenWrt on MIPS is a common embedded Linux stack for consumer routers and IoT devices; the default user list (`root`, `nobody`, `dnsmasq`) is a useful fingerprint for further analysis
- Binwalk's recursive extraction (`-M`) is effective against squashfs images typical of OpenWrt builds

## Notes

Performed as part of PSU CS 596, Network Security, Summer 2025. The packet capture was provided by the course instructor; no unauthorized access to production devices was involved.