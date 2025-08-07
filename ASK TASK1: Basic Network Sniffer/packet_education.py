#!/usr/bin/env python3
"""
Network Packet Education Tool
Learn about network packet structures, protocols, and analysis.
"""

from scapy.all import *
import time

def demonstrate_packet_structure():
    """Demonstrate the structure of different packet types"""
    print("=== Network Packet Structure Education ===")
    print()
    
    # Create example packets
    print("1. TCP Packet Structure:")
    tcp_packet = IP(dst="8.8.8.8")/TCP(dport=80, flags="S")
    print(f"   IP Layer: {tcp_packet[IP].src} -> {tcp_packet[IP].dst}")
    print(f"   TCP Layer: Port {tcp_packet[TCP].sport} -> {tcp_packet[TCP].dport}")
    print(f"   TCP Flags: {tcp_packet[TCP].flags}")
    print()
    
    print("2. UDP Packet Structure:")
    udp_packet = IP(dst="8.8.8.8")/UDP(dport=53)
    print(f"   IP Layer: {udp_packet[IP].src} -> {udp_packet[IP].dst}")
    print(f"   UDP Layer: Port {udp_packet[UDP].sport} -> {udp_packet[UDP].dport}")
    print()
    
    print("3. ICMP Packet Structure:")
    icmp_packet = IP(dst="8.8.8.8")/ICMP(type=8)  # Echo request
    print(f"   IP Layer: {icmp_packet[IP].src} -> {icmp_packet[IP].dst}")
    print(f"   ICMP Type: {icmp_packet[ICMP].type} (Echo Request)")
    print()

def explain_protocols():
    """Explain different network protocols"""
    print("=== Network Protocols Explained ===")
    print()
    
    protocols = {
        "TCP (Transmission Control Protocol)": {
            "description": "Connection-oriented, reliable protocol",
            "characteristics": [
                "Guaranteed delivery",
                "Ordered delivery",
                "Error checking",
                "Flow control",
                "Used for: HTTP, HTTPS, FTP, SSH, SMTP"
            ],
            "ports": [80, 443, 22, 21, 25]
        },
        "UDP (User Datagram Protocol)": {
            "description": "Connectionless, fast protocol",
            "characteristics": [
                "No guaranteed delivery",
                "No ordering",
                "Minimal overhead",
                "Used for: DNS, DHCP, streaming, gaming"
            ],
            "ports": [53, 67, 68, 123]
        },
        "ICMP (Internet Control Message Protocol)": {
            "description": "Network diagnostic protocol",
            "characteristics": [
                "Error reporting",
                "Network diagnostics",
                "Used for: ping, traceroute"
            ],
            "types": ["Echo Request (8)", "Echo Reply (0)", "Destination Unreachable (3)"]
        },
        "ARP (Address Resolution Protocol)": {
            "description": "Maps IP addresses to MAC addresses",
            "characteristics": [
                "Layer 2 protocol",
                "Local network only",
                "Used for: Finding MAC addresses"
            ]
        }
    }
    
    for protocol, info in protocols.items():
        print(f"{protocol}:")
        print(f"  {info['description']}")
        print("  Characteristics:")
        for char in info['characteristics']:
            print(f"    • {char}")
        if 'ports' in info:
            print(f"  Common ports: {', '.join(map(str, info['ports']))}")
        if 'types' in info:
            print(f"  Common types: {', '.join(info['types'])}")
        print()

def explain_tcp_flags():
    """Explain TCP flags and their meanings"""
    print("=== TCP Flags Explained ===")
    print()
    
    flags = {
        "SYN (Synchronize)": {
            "bit": "0x02",
            "meaning": "Initiate connection",
            "use": "TCP handshake - first packet"
        },
        "ACK (Acknowledgment)": {
            "bit": "0x10",
            "meaning": "Acknowledge received data",
            "use": "Confirming receipt of packets"
        },
        "FIN (Finish)": {
            "bit": "0x01",
            "meaning": "End connection gracefully",
            "use": "TCP connection termination"
        },
        "RST (Reset)": {
            "bit": "0x04",
            "meaning": "Abort connection immediately",
            "use": "Error conditions, security"
        },
        "PSH (Push)": {
            "bit": "0x08",
            "meaning": "Send data immediately",
            "use": "Force immediate transmission"
        },
        "URG (Urgent)": {
            "bit": "0x20",
            "meaning": "Mark data as urgent",
            "use": "Priority data transmission"
        }
    }
    
    for flag, info in flags.items():
        print(f"{flag}:")
        print(f"  Bit: {info['bit']}")
        print(f"  Meaning: {info['meaning']}")
        print(f"  Use: {info['use']}")
        print()

def demonstrate_packet_analysis():
    """Demonstrate how to analyze captured packets"""
    print("=== Packet Analysis Techniques ===")
    print()
    
    print("1. Basic Packet Inspection:")
    print("   - Check packet layers: packet.haslayer(IP)")
    print("   - Extract IP addresses: packet[IP].src, packet[IP].dst")
    print("   - Get protocol info: packet[TCP].sport, packet[TCP].dport")
    print()
    
    print("2. Payload Analysis:")
    print("   - Raw payload: packet[Raw].load")
    print("   - Hex dump: packet[Raw].load.hex()")
    print("   - String conversion: packet[Raw].load.decode('utf-8', errors='ignore')")
    print()
    
    print("3. Protocol-Specific Analysis:")
    print("   - TCP flags: packet[TCP].flags")
    print("   - ICMP type: packet[ICMP].type")
    print("   - UDP length: packet[UDP].len")
    print()

def explain_network_layers():
    """Explain the OSI network model"""
    print("=== OSI Network Model ===")
    print()
    
    layers = {
        "7. Application Layer": {
            "examples": ["HTTP", "HTTPS", "FTP", "SSH", "DNS", "SMTP"],
            "description": "User applications and services"
        },
        "6. Presentation Layer": {
            "examples": ["SSL/TLS", "JPEG", "ASCII"],
            "description": "Data formatting and encryption"
        },
        "5. Session Layer": {
            "examples": ["NetBIOS", "RPC"],
            "description": "Session management"
        },
        "4. Transport Layer": {
            "examples": ["TCP", "UDP"],
            "description": "End-to-end communication"
        },
        "3. Network Layer": {
            "examples": ["IP", "ICMP", "ARP"],
            "description": "Routing and addressing"
        },
        "2. Data Link Layer": {
            "examples": ["Ethernet", "WiFi", "PPP"],
            "description": "Local network communication"
        },
        "1. Physical Layer": {
            "examples": ["Cables", "WiFi signals", "Fiber optics"],
            "description": "Physical transmission"
        }
    }
    
    for layer, info in layers.items():
        print(f"{layer}:")
        print(f"  Description: {info['description']}")
        print(f"  Examples: {', '.join(info['examples'])}")
        print()

def security_considerations():
    """Explain security aspects of packet analysis"""
    print("=== Security Considerations ===")
    print()
    
    print("1. Legal and Ethical:")
    print("   • Only capture traffic you own or have permission to monitor")
    print("   • Be aware of privacy implications")
    print("   • Follow local laws and regulations")
    print()
    
    print("2. Sensitive Information:")
    print("   • Passwords in plain text")
    print("   • Personal data in HTTP requests")
    print("   • Email content in SMTP traffic")
    print("   • File contents in FTP transfers")
    print()
    
    print("3. Security Applications:")
    print("   • Intrusion detection")
    print("   • Network monitoring")
    print("   • Traffic analysis")
    print("   • Forensic investigation")
    print()

def main():
    """Run the educational content"""
    print("Network Packet Education Tool")
    print("=" * 50)
    print()
    
    try:
        demonstrate_packet_structure()
        explain_protocols()
        explain_tcp_flags()
        demonstrate_packet_analysis()
        explain_network_layers()
        security_considerations()
        
        print("=" * 50)
        print("Education complete! Now try the packet capture tool:")
        print("python packet_capture.py -h")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
