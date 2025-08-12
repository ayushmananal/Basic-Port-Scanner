# Basic CYBER SECURITY TOOLS
Metadata Extractor
  Format: python3 file_metadata.py mydocument.pdf
Packet Sniffer
  How to use
    Install scapy (prefer virtualenv):
    sudo apt update && sudo apt install python3-pip (if pip missing)
    pip3 install scapy or sudo apt install python3-scapy (Kali may have packages)
    Run as root (or with capabilities):
    sudo python3 packet_sniffer.py -i eth0 -f "tcp port 80" -s capture.pcap
    Example for unlimited capture on default interface: sudo python3 packet_sniffer.py
    Stop with Ctrl+C. If -s capture.pcap was used, the pcap will be written and can be opened in Wireshark.
