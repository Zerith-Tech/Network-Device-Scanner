import argparse
import ipaddress
import socket
import sys
import time
from typing import Optional, Dict

from scapy.all import ARP, Ether, srp, conf  # type: ignore
import requests # type: ignore

# Minimal OUI DB
OUI_VENDOR: Dict[str, str] = {
    "00163E": "Apple, Inc.",
    "F4F5E8": "Apple, Inc.",
    "B827EB": "Raspberry Pi Foundation",
    "E4115B": "Samsung Electronics",
    "3C5A37": "Google, Inc.",
    "FCFC48": "ASUSTek COMPUTER INC.",
    "F8E71E": "Huawei Technologies Co., Ltd",
    "3894ED": "Xiaomi Communications Co Ltd",
}

def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def guess_local_network() -> Optional[str]:
    try:
        iface_name, iface_ip, gw_ip = conf.route.route("0.0.0.0")
        local_ip = iface_ip if iface_ip and iface_ip != "0.0.0.0" else get_local_ip()
        # Assume /24
        net = ipaddress.IPv4Network(local_ip + "/24", strict=False)
        #print(str(net))
        return str(net)
    except Exception as e:
        #print(e)
        return None

def arp_scan(network: str, timeout: int = 2, iface: Optional[str] = None):
    print(f"[+] Scanning network {network} via ARP...")

    # Create ARP request to broadcast MAC
    package_arp = ARP(pdst=network)
    package_ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = package_ether / package_arp

    answered, unanswered = srp(packet, timeout=timeout, iface=iface, verbose=0)

    devices = []
    for sent, recv in answered:
        devices.append({
            "ip": recv.psrc,
            "mac": recv.hwsrc
        })

    return devices

def normalize_mac(mac: str) -> str:
    return "".join(c for c in mac.upper() if c in "0123456789ABCDEF")

def local_oui_lookup(mac: str) -> Optional[str]:
    norm = normalize_mac(mac)
    oui = norm[:6] # reading the first 3 bytes
    return OUI_VENDOR.get(oui)

def online_mac_lookup(mac: str, timeout: float = 3.0) -> Optional[str]:
    try:
        url = f"https://api.macvendors.com/{mac}"
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200 and resp.text.strip():
            return resp.text.strip()
    except Exception as e:
        print(e)
        return None

def identify_vendor(mac: str, use_online: bool = False):
    vendor = local_oui_lookup(mac)
    if vendor:
        return vendor

    if use_online:
        vendor = online_mac_lookup(mac)
        if vendor:
            return vendor
    
    return "Unknown"

def print_result(devices, use_online: bool, local_ip: str):
    if not devices:
        print("[-] No devices found.")
        return

    print("\nDiscovered devices:\n")
    header = f"{'IP Address':<16} {'MAC Address':<18} {'Vendor':<35} {'Flags'}"
    print(header)
    print("-" * len(header))

    for d in devices:
        ip = d["ip"]
        mac = d["mac"]
        vendor = identify_vendor(mac, use_online=use_online)

        flags = []
        if vendor == "Unknown":
            flags.append("UNKNOWN_VENDOR")
        if ip == local_ip:
            flags.append("THIS_HOST")

        print(f"{ip:<16} {mac:<18} {vendor:<35} {','.join(flags)}")

def main():
    parser = argparse.ArgumentParser(
        description="Simple home network mapper using ARP + MAC OUI lookup"
    )
    parser.add_argument(
        "-t", "--target",
        help="Target network in CIDR notation (e.g. 192.168.1.0/24). "
             "If omitted, the script will try to guess."
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to use (optional)."
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="Use online MAC vendor lookup (slower, may hit rate-limits)."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="ARP response timeout in seconds (default: 10)."
    )

    args = parser.parse_args()

    local_ip = get_local_ip()

    if args.target:
        network = args.target
    else:
        guessed = guess_local_network()
        if not guessed:
            print("[-] Could not auto-detect network. Please specify -t 192.168.1.0/24")
            print("[suggestion] Use ifconfig (linux) or ipconfig (Windows) to specify target ip address manually")
            sys.exit(1)
        print(f"[+] Auto-detected network: {guessed}")
        network = guessed

    # Quick validation of network
    try:
        ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"[-] Invalid network {network}: {e}")
        sys.exit(1)
    
    start = time.time()
    devices = arp_scan(network, timeout=args.timeout, iface=args.interface)
    end = time.time()

    print_result(devices, use_online=args.online, local_ip=local_ip)
    print(f"\n[+] Scan completed in {end - start:.2f} seconds. "
          f"Found {len(devices)} device(s).")


if __name__ == "__main__":
    main()
