#!/usr/bin/env python3
# Packet Sniffer (scapy)
# Capture packets on an interface (or pcap file)
# Print concise one-line summaries for each packet
# Optionally save captured packets to a pcap file
# Requires: scapy (run as root / with appropriate permissions)


import argparse
from datetime import datetime
from scapy.all import sniff, wrpcap, Ether, IP, TCP, UDP, Raw

def pretty_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def summarize_packet(pkt):
    """Return a short string summary for a packet."""
    ts = pretty_time()
    length = len(pkt)
    src = pkt[IP].src if IP in pkt else (pkt.src if Ether in pkt else "N/A")
    dst = pkt[IP].dst if IP in pkt else (pkt.dst if Ether in pkt else "N/A")
    proto = "OTHER"
    info = ""

    if TCP in pkt:
        proto = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        info = f"{sport}->{dport}"
        # show small payload snippet if present
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)[:30]
            try:
                info += f" | {payload.decode('utf-8', errors='replace')}"
            except Exception:
                info += f" | {payload!r}"
    elif UDP in pkt:
        proto = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        info = f"{sport}->{dport}"
    elif IP in pkt:
        proto = pkt[IP].proto

    return f"{ts} | {proto:3} | {src} -> {dst} | len={length} | {info}"

def packet_callback(pkt, args):
    """Called for every captured packet by scapy.sniff."""
    # print summary to stdout
    print(summarize_packet(pkt))
    # if saving, append the packet to the list
    if args.save is not None:
        args._pkts.append(pkt)

def main():
    parser = argparse.ArgumentParser(description="Simple Packet Sniffer (scapy)")
    parser.add_argument("-i", "--interface", help="Interface to sniff (default: scapy's default)", default=None)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (default: unlimited)", default=0)
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp and port 80')", default=None)
    parser.add_argument("-s", "--save", help="Save captured packets to this pcap file (optional)", default=None)
    parser.add_argument("--promisc", help="Enable promiscuous mode (default: True)", action="store_true")
    args = parser.parse_args()

    # Prepare container for packets if saving
    if args.save:
        args._pkts = []

    print("=== Packet Sniffer ===")
    print("Interface:", args.interface or "default")
    if args.filter:
        print("BPF filter:", args.filter)
    if args.save:
        print("Saving to:", args.save)
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.interface,
            prn=lambda pkt: packet_callback(pkt, args),
            filter=args.filter,
            count=args.count if args.count > 0 else 0,
            store=False,           # we handle storing only if user asked
            promisc=args.promisc or True
        )
    except KeyboardInterrupt:
        print("\n[+] Capture stopped by user.")
    except PermissionError:
        print("[!] Permission error: try running with sudo/root.")
        return
    except Exception as e:
        print("[!] Error while sniffing:", str(e))
        return

    # pcap to be written on request
    if args.save and getattr(args, "_pkts", None):
        try:
            wrpcap(args.save, args._pkts)
            print(f"[+] Saved {len(args._pkts)} packets to {args.save}")
        except Exception as e:
            print("[!] Failed to write pcap:", str(e))

if __name__ == "__main__":
    main()
