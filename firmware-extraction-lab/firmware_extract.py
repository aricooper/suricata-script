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