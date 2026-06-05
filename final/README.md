# CVE-2020-16898 — “Bad Neighbor” (ICMPv6 RDNSS length parsing) — Suricata Lua Detection

## 1) High-level description

CVE-2020-16898 (“Bad Neighbor”) is a Windows IPv6 stack vulnerability in the
parsing of **RDNSS** (Recursive DNS Server, option type **25**) inside
**ICMPv6 Router Advertisements** (RA, type **134**).

Per RFC 8106, an RDNSS option’s **Length** is in units of 8 bytes and must be:
- **≥ 3** (24 bytes total) and
- structured so that `(Length - 1)` is an **even** number (each IPv6 address is 16 bytes = 2 units).

Windows improperly handled certain malformed lengths (e.g., `Length < 3` or
non-even values), leading to a memory corruption/BSOD when such an RA was
processed on an interface that accepted IPv6 RAs.

**Detection strategy:** flag ICMPv6 RA packets that include an **RDNSS (25) option**
with an invalid Length per RFC rules.

---

## 2) Suricata Lua script

```lua
-- rdnss_badlen.lua
-- Detect malformed ICMPv6 RA RDNSS (opt 25) length per RFC 8106.

function init (args)
    local needs = {}
    needs["packet"] = tostring(true)  -- tell Suricata we need raw packet payload
    return needs
end

local function u8(str, off)            -- read 1 byte at 1-based index 'off'
    return string.byte(str, off)
end

function match (args)
    local p = args["payload"]          -- ICMPv6 payload (starts at Type)
    if p == nil then return 0 end
    local len = #p

    if len < 16 then return 0 end      -- need at least full RA fixed header
    local icmp_type = u8(p, 1)         -- byte 1 = ICMPv6 Type
    if icmp_type ~= 134 then           -- 134 = Router Advertisement
        return 0
    end

    -- ICMPv6 header: Type(1), Code(1), Checksum(2) = 4
    -- RA fixed fields: CurHopLimit(1), Flags(1), RouterLifetime(2),
    --                  ReachableTime(4), RetransTimer(4) = 12
    -- Total to skip = 16 bytes
    local off = 16

    -- Walk variable-length ND options: TLV blocks
    -- Each option: Type(1), Length(1, in units of 8 bytes), Value(...)
    while off + 1 <= len do
        local opt_type = u8(p, off + 1)         -- option Type
        local opt_len_units = u8(p, off + 2)    -- option Length (8-byte units)

        if opt_len_units == 0 then              -- zero length is invalid; stop safely
            return 0
        end

        local opt_total = opt_len_units * 8     -- total bytes for this option
        if off + opt_total > len then           -- truncated option; bail
            return 0
        end

        if opt_type == 25 then                  -- RDNSS option (RFC 8106)
            -- RFC rules:
            --  * Length >= 3 (24 bytes min)
            --  * (Length-1) must be even (each IPv6 addr = 16 bytes = 2 units)
            --  * at least one address present
            if opt_len_units < 3 then
                return 1                        -- alert: too short
            end
            local addr_units = opt_len_units - 1
            if (addr_units % 2) ~= 0 then
                return 1                        -- alert: not a whole number of addresses
            end
            if addr_units < 2 then
                return 1                        -- alert: zero addresses
            end
            return 0                            -- RDNSS present but length looks fine
        end

        off = off + opt_total                   -- advance to next option
        if opt_total == 0 then break end        -- safety, though we checked above
    end

    return 0                                    -- no malformed RDNSS seen
end
```

---

## What each part does

### `init(args)`
- Creates a `needs` table and sets `needs["packet"] = tostring(true)` to tell Suricata **we want the raw packet payload**. Suricata passes that payload to `match()` as `args["payload"]`.
- Returns the needs table.

### Helper: `u8(str, off)`
- Convenience function that returns the numeric value of **one byte** from the Lua string `str` at **1‑based index** `off` (Lua strings are 1‑indexed).

### `match(args)` — high level
1. **Get payload**: `p = args["payload"]`; bail if nil.  
2. **Basic length check**: need at least **16 bytes** to cover ICMPv6 header (4) + RA fixed fields (12).  
3. **ICMPv6 type check**: first byte must be **134** (Router Advertisement).  
4. **Set `off = 16`**: skip the RA fixed header, land on the start of the **ND options TLV list**.  
5. **Loop over options**: For each TLV, read:
   - `opt_type` (1 byte)
   - `opt_len_units` (1 byte, measured in **8‑byte units**)
   - Compute `opt_total = opt_len_units * 8` bytes; check bounds.
6. **If RDNSS (type 25)**, validate Length per **RFC 8106**:
   - `Length >= 3` (>= 24 bytes total)
   - `addr_units = Length - 1` must be **even** (each IPv6 address is 16 bytes = 2 units)
   - At least **one** IPv6 address: `addr_units >= 2`
   - If any rule fails → **`return 1`** (a match/alert).
7. Otherwise, **advance** `off` by `opt_total` to the next option and continue.  
8. If no malformed RDNSS is seen, **`return 0`** (no alert).

### Why `return 1` vs `return 0`?
- In Suricata Lua, returning **1** means “the condition is met” and the enclosing rule should **alert**.
- Returning **0** means “no match”. Your rule is:
  ```conf
  alert icmp6 any any -> any any (msg:"CVE-2020-16898 Bad Neighbor - malformed RDNSS option length"; lua:rdnss_badlen.lua; sid:10016898; rev:1;)
  ```

---

## RFC logic in plain terms

Per **RFC 8106 (RDNSS option)**:
- The **Length** field is in **8‑byte units** and **includes the 2‑byte Type/Length**.
- Minimum length is **3** (24 bytes): header (6 bytes) + at least **one** IPv6 address (16 bytes).
- The number of addresses is `(Length − 1) / 2` and must be an **integer ≥ 1**.  
  That’s equivalent to checking:
  - `addr_units = Length − 1`
  - `(addr_units % 2) == 0`
  - `addr_units >= 2`

The script encodes these checks exactly.

---

## Assumptions & safe exits

- If the payload is **too short** or an option looks **truncated**, the script **returns 0** (no alert) to avoid false positives.
- The script focuses on **RDNSS length** validity; it doesn’t parse other ND options.
- It alerts on the **first malformed RDNSS** found. If you want it to scan all options, you can change the final `return 0` inside the RDNSS block to `-- keep scanning` and continue the loop.

---

## Quick test commands

With Suricata installed on Linux/Kali:

```bash
# Run against the demo pcap with the local rule:
suricata -r final.pcap -S local.rules -k none -l ./logs
jq -c 'select(.alert and .alert.signature_id==10016898)' ./logs/eve.json
```

Rule (`local.rules`):

```conf
alert icmp6 any any -> any any (
    msg:"CVE-2020-16898 Bad Neighbor - malformed RDNSS option length";
    lua:rdnss_badlen.lua;
    classtype:attempted-user;
    sid:10016898;
    rev:1;
)
```

**Why Lua?** The RDNSS option lives inside a variable-length **TLV chain** following
the RA’s fixed header. Plain Suricata keywords can’t easily walk arbitrary TLVs.
Lua lets us parse that list and validate RDNSS Length precisely.

---

## 3) My process (what I did)

**RFC reading**  
RFC 4861 (ND) + RFC 8106 (RDNSS) → constraints: `Length >= 3` and `(Length-1)` even.

**Traffic generation.**  
I created a minimal ICMPv6 RA with **RDNSS Length=1** (invalid)
and saved it into `final.pcap` (attached). I also tested valid RDNSS (`Length=3`)
to ensure no false positives.

**Iterations**  
1. Match only `Length < 3` → missed odd values.
2. Add `(Length-1) % 2 != 0` → caught malformed odd cases.
3. Require `addr_units >= 2` (>=1 IPv6 address) → final detector.

## **How I tested**

### On Kali: install tools & quick Suricata check

```bash
apt update
apt install -y suricata jq tcpdump tshark python3-scapy
# Syntax check using our local rule (LuaJIT is built into Kali's Suricata):
suricata -S local.rules -k none -c /etc/suricata/suricata.yaml -T
```

---

## **First Method: Realistic RA traffic generator (Scapy)**

Create `gen_ra_rdnss.py` on Kali:

```bash
cat > gen_ra_rdnss.py <<'PY'
#!/usr/bin/env python3
from scapy.all import (
    Ether, IPv6, sendp, get_if_hwaddr,
    ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr,
    ICMPv6NDOptRDNSS, conf
)
import time, random, argparse

def good_rdnss(dns_list=None, lifetime=600):
    if dns_list is None:
        dns_list = ["2001:4860:4860::8888", "2606:4700:4700::1111"]
    return ICMPv6NDOptRDNSS(dns=dns_list, lifetime=lifetime)

def bad_rdnss_len1(lifetime=600):
    # Scapy enforces valid length, so we craft a valid RDNSS and then truncate to 8 bytes
    opt = ICMPv6NDOptRDNSS(dns=["2001:db8::53"], lifetime=lifetime)
    raw = bytes(opt)
    return raw[:8]  # type(1), len(1), reserved(2), lifetime(4) -> Length=1 (invalid)

def ra_pkt(iface, bad=False):
    src_ll = get_if_hwaddr(iface)
    base = Ether(dst="33:33:00:00:00:01")/IPv6(src="fe80::1", dst="ff02::1")/ICMPv6ND_RA()
    sll  = ICMPv6NDOptSrcLLAddr(lladdr=src_ll)
    if bad:
        hacked = bad_rdnss_len1(lifetime=random.choice([60,120,300]))
        return (base/sll)/hacked
    else:
        opt = good_rdnss(lifetime=random.choice([300,600,1200]))
        return base/sll/opt

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-i","--iface", required=True, help="Host-only interface (e.g.e eth0)")
    ap.add_argument("-n","--count", type=int, default=60, help="Packets to send")
    ap.add_argument("--interval", type=float, default=0.25, help="Seconds between packets")
    args = ap.parse_args()

    conf.iface = args.iface
    for idx in range(args.count):
        pkt = ra_pkt(args.iface, bad=(idx % 3 == 0))  # ~33% malformed
        sendp(pkt, iface=args.iface, verbose=False)
        time.sleep(args.interval)

if __name__ == "__main__":
    main()
PY

chmod +x gen_ra_rdnss.py
```

This emits a **mix of valid and malformed** RAs so the PCAP looks realistic and demonstrates no false positives.

---

### Capture live & run Suricata

Open **two terminals** on Kali.

### Terminal A — capture to PCAP
```bash
# replace eth0 with your host-only interface
tcpdump -e eth0 -w ra_mix.pcap icmp6 and 'ip6[40]=134'
```

### Terminal B — Suricata on the interface
```bash
suricata -e eth0 -S local.rules -l ./logs -k none
# watch alerts live in another shell:
tail -f ./logs/eve.json | jq 'select(.alert and .alert.signature_id==10016898)'
```

### Terminal C — generate traffic
```bash
./gen_ra_rdnss.py -e eth0 -n 60 --interval 0.25
```

Stop tcpdump/Suricata with Ctrl‑C after ~30–60 seconds.

---

### Verify results

```bash
# Count alerts
jq -c 'select(.alert and .alert.signature_id==10016898)' logs/eve.json | wc -l

# Sample alert lines
jq -c 'select(.alert and .alert.signature_id==10016898) | {ts:.timestamp,msg:.alert.signature,src:.src_ip,dst:.dest_ip}' logs/eve.json | head

# PCAP sanity
tshark -r ra_mix.pcap -Y "icmpv6.type==134" -T fields -e frame.number -e ipv6.addr -e icmpv6.opt.type | head
```

---

### replay & add noise

```bash
apt install -y tcpreplay nping

# Replay the tiny single-packet demo to pad captures
tcpreplay -e eth0 --pps=10 final.pcap

# Add general network noise
nping --icmp -c 20 ff02::e eth0
curl -s http://example.com/ >/dev/null 2>&1 || true
```

## **Method Two: radvd (valid RAs) + tcpreplay (malformed RAs)**

### 1) Configure **radvd** to send valid RAs (with RDNSS)

Edit `/etc/radvd.conf` (replacee eth0` with your host-only NIC):

```conf
interface eth0 {
  AdvSendAdvert on;
  MinRtrAdvInterval 5;
  MaxRtrAdvInterval 10;
  AdvManagedFlag off;
  AdvOtherConfigFlag on;

  prefix 2001:db8:1::/64 {
    AdvOnLink on;
    AdvAutonomous on;
  };

  RDNSS 2001:4860:4860::8888 2606:4700:4700::1111 {
    AdvRDNSSLifetime 600;
  };
}
```

Start radvd:
```bash
sudo systemctl enable --now radvd
sudo systemctl status radvd --no-pager
```

Verify RAs are present:
```bash
sudo tcpdump -e eth0 -vv icmp6 and 'ip6[40]=134' -c 3
```

---

### 2) Run Suricata and capture

In your working directory (contains `rdnss_badlen.lua` + `local.rules`):

**Terminal A — Suricata (live oe eth0):**
```bash
sudo suricata -e eth0 -S local.rules -l ./logs -k none
# in another terminal you can watch alerts:
tail -f ./logs/eve.json | jq 'select(.alert and .alert.signature_id==10016898)'
```

**Terminal B — capture to PCAP:**
```bash
sudo tcpdump -e eth0 -w ra_mix.pcap icmp6 and 'ip6[40]=134'
```

> You’ll see lots of *valid* RAs from radvd; no alerts yet (that’s good!).

---

### 3) Inject malformed RAs with **tcpreplay**

Use the provided `final.pcap` (contains malformed RDNSS Length). Send a small burst every 10 seconds:

```bash
cd ~/cve16898
while true; do
  sudo tcpreplay -e eth0 --pps=2 final.pcap
  sleep 10
done
```

Now Suricata should begin logging alerts (SID `10016898`) while tcpdump keeps capturing both valid and malformed RAs.

---

### 4) Validate results

Count alerts:
```bash
jq -c 'select(.alert and .alert.signature_id==10016898)' logs/eve.json | wc -l
```

Sample alert lines:
```bash
jq -c 'select(.alert and .alert.signature_id==10016898) | {ts:.timestamp,msg:.alert.signature,src:.src_ip,dst:.dest_ip}' logs/eve.json | head
```

PCAP sanity (should show many RA frames):
```bash
tshark -r ra_mix.pcap -Y "icmpv6.type==134" -T fields -e frame.number -e ipv6.addr -e icmpv6.opt.type | head
```

Stop tcpdump/Suricata when done (Ctrl-C).
