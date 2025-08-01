# HW 4

## Instructions

Using the tools you’ve learned in this module, dissect the provided packet capture and extract the firmware. You will find the packet capture at ada.cs.pdx.edu:/disk/scratch/dmcgrath/firmware.pcap. Simply scp it to your kali machine. It is important to note that HTTP often transmits binary data via BASE64 encoding! Once you have a firmware extracted that matches the above, use a tool called binwalk to extract the contents (this isn’t a reverse engineering class, use the -M and -e options), then answer a few questions:  

1. What architecture is the firmware intended to run on?  
2. What OS is the firmware running?  
3. What users are present on the system?  
4. Write a document detailing how you extracted the firmware, how you investigated the firmware, and answers to the above questions. Please make sure to include any code you wrote or commands you executed.  

## Documentation

### Scapy python script implementation:

- **download and filter firmware.pcap file**
  - download pcap packet filter
  >scp <MCECS_Username>@ada.cs.pdx.edu:/disk/scratch/dmcgrath/firmware.pcap .  
  - use wireshark to upload firmware.pcap file for analysis
    - find pattern in capture that illuminate firmware request and response
    >all required traffic can be filtered with just "tcp.port == 9891" (no other hosts use this port)
  - use tcpdump to create a smaller, filtered pcap file
  >tcpdump -r firmware.pcap -w firmware_filtered.pcap 'tcp port 9891'
  - use firmware_filtered for scapy script and bpython testing  

- **further discovery and filtering**
  - still over 76000 packets in firmware_filtered.pcap
    - can further filter using sniff fuction to only keep packets with raw layer
    >raw_packets = sniff(offline = 'firmware_filtered.pcap', filter="tcp", lfilter=lambda pkt: Raw in pkt)
  - raw_packets now contains only packets with a raw payload between 192.168.8.191:9891 and 192.168.8.227
  - looking through array of packets leads to a few important realizations  
    1. the list of packets is in order already
    2. the list starts with a request and then receives two responses
    3. the second response contains the actual payload we want  
    4. the payload is encoded in base64  

- **create loop for raw_packets to reconstruct firmware**  
  - with new information, create while loop to iterate through each packet
    - understanding the packet list starts with request and is followed by two responses, the first of which we want to skip we can create a loop that extracts the offset from the first packet, use that as an index in a dictionary, and save the second response's raw payload in that index. The loop is set up to ensure multiple response packets can be saved in the same index in case a payload is split over more than one packet.  
    ```
    flows = defaultdict(list)
    i = 0

    while i < len(raw_packets):
        pkt = raw_packets[i]
        if pkt[TCP].sport != '9891':
            try:
                path = str(HTTPRequest(pkt[Raw].load).Path)
                offset_str = parse_qs(path).get('offset',[None])
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
                print(f"Error parsing packet {i}: at offset {offset}: {e}")
        i += 1
    ``` 

- **add loop to decode annd write download.bin file**
  - use each flow index in list to seek to offset, decode, and write the payload to file
  ```
  with open("download.bin", "wb") as f:
    for offset, payloads in sorted(flows.items()):
        for encrypted in payloads:
            try:
                decoded = base64.b64decode(encrypted)
                f.seek(offset)
                f.write(decoded)
                offset += len(decoded)
            except Exception as e:
                print(f"Error decoding packet at offset {offset}: {e}")
  ```
### Questions: ###
  1. the firmware is intended to run on MIPS architecture  
    > file _download.bin.extracted/squashfs-root/bin/busybox  
  2. the firmware is running OpenWrt OS  
    > less _download.bin.extracted/squashfs-root/etc/init.d/system  
  3. users include; root, daemon, ftp, network, nobody, dnsmasq  
    > less _download.bin.extracted/squashfs-root/etc/passwd  







