#!/usr/bin/env python3
"""
Network Packet Capture and Analysis Tool
A comprehensive tool to capture, analyze, and display network traffic packets.
"""

import sys
import time
import socket
from datetime import datetime
from scapy.all import *
import argparse
import threading
from collections import defaultdict, Counter

class PacketAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = Counter()
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.packet_details = []
        self.running = False
        
    def start_capture(self, interface=None, filter_str=None, max_packets=None):
        """Start capturing packets on the specified interface"""
        print(f"[*] Starting packet capture...")
        print(f"[*] Interface: {interface or 'default'}")
        print(f"[*] Filter: {filter_str or 'all packets'}")
        print(f"[*] Max packets: {max_packets or 'unlimited'}")
        print("-" * 80)
        
        self.running = True
        
        try:
            # Start packet capture
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self.analyze_packet,
                store=0,
                stop_filter=lambda x: self.packet_count >= max_packets if max_packets else False
            )
        except KeyboardInterrupt:
            print("\n[!] Capture stopped by user")
        except Exception as e:
            print(f"[!] Error during capture: {e}")
        finally:
            self.running = False
            self.display_summary()
    
    def analyze_packet(self, packet):
        """Analyze individual packet and extract information"""
        self.packet_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        # Initialize packet info
        packet_info = {
            'number': self.packet_count,
            'timestamp': timestamp,
            'length': len(packet),
            'protocol': 'Unknown',
            'src_ip': 'Unknown',
            'dst_ip': 'Unknown',
            'src_port': 'Unknown',
            'dst_port': 'Unknown',
            'payload': '',
            'details': {}
        }
        
        # Analyze IP layer
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            self.ip_stats[packet[IP].src] += 1
            self.ip_stats[packet[IP].dst] += 1
            
            # Analyze transport layer
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['details']['flags'] = packet[TCP].flags
                packet_info['details']['seq'] = packet[TCP].seq
                packet_info['details']['ack'] = packet[TCP].ack
                
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                packet_info['details']['type'] = packet[ICMP].type
                packet_info['details']['code'] = packet[ICMP].code
                
        elif ARP in packet:
            packet_info['protocol'] = 'ARP'
            packet_info['src_ip'] = packet[ARP].psrc
            packet_info['dst_ip'] = packet[ARP].pdst
            
        # Extract payload (first 100 bytes)
        if Raw in packet:
            payload = bytes(packet[Raw])
            packet_info['payload'] = payload[:100].hex()
            if len(payload) > 100:
                packet_info['payload'] += "..."
        
        # Update statistics
        self.protocol_stats[packet_info['protocol']] += 1
        if packet_info['src_port'] != 'Unknown':
            self.port_stats[packet_info['src_port']] += 1
        if packet_info['dst_port'] != 'Unknown':
            self.port_stats[packet_info['dst_port']] += 1
        
        # Store packet details
        self.packet_details.append(packet_info)
        
        # Display packet information
        self.display_packet(packet_info)
        
        # Keep only last 100 packets in memory
        if len(self.packet_details) > 100:
            self.packet_details.pop(0)
    
    def display_packet(self, packet_info):
        """Display formatted packet information"""
        print(f"\n[{packet_info['number']:4d}] {packet_info['timestamp']} | "
              f"{packet_info['protocol']:6s} | "
              f"{packet_info['src_ip']:15s}:{str(packet_info['src_port']):5s} -> "
              f"{packet_info['dst_ip']:15s}:{str(packet_info['dst_port']):5s} | "
              f"Length: {packet_info['length']:4d}")
        
        # Show additional details for specific protocols
        if packet_info['protocol'] == 'TCP' and packet_info['details'].get('flags'):
            flags = packet_info['details']['flags']
            flag_str = []
            if flags & 0x01: flag_str.append('FIN')
            if flags & 0x02: flag_str.append('SYN')
            if flags & 0x04: flag_str.append('RST')
            if flags & 0x08: flag_str.append('PSH')
            if flags & 0x10: flag_str.append('ACK')
            if flags & 0x20: flag_str.append('URG')
            if flag_str:
                print(f"        TCP Flags: {' '.join(flag_str)}")
        
        if packet_info['payload']:
            print(f"        Payload: {packet_info['payload']}")
    
    def display_summary(self):
        """Display capture summary and statistics"""
        print("\n" + "="*80)
        print("CAPTURE SUMMARY")
        print("="*80)
        print(f"Total packets captured: {self.packet_count}")
        print(f"Capture duration: {self.get_capture_duration():.2f} seconds")
        
        print("\nProtocol Distribution:")
        for protocol, count in self.protocol_stats.most_common():
            percentage = (count / self.packet_count) * 100 if self.packet_count > 0 else 0
            print(f"  {protocol}: {count} packets ({percentage:.1f}%)")
        
        print("\nTop Source IPs:")
        for ip, count in sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count} packets")
        
        print("\nTop Ports:")
        for port, count in sorted(self.port_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            service = self.get_service_name(port)
            print(f"  Port {port} ({service}): {count} packets")
    
    def get_capture_duration(self):
        """Calculate capture duration"""
        if len(self.packet_details) < 2:
            return 0
        start_time = datetime.strptime(self.packet_details[0]['timestamp'], "%H:%M:%S.%f")
        end_time = datetime.strptime(self.packet_details[-1]['timestamp'], "%H:%M:%S.%f")
        return (end_time - start_time).total_seconds()
    
    def get_service_name(self, port):
        """Get service name for common ports"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3306: 'MySQL', 5432: 'PostgreSQL', 8080: 'HTTP-Alt'
        }
        return common_ports.get(port, 'Unknown')
    
    def save_to_file(self, filename):
        """Save captured packets to a file"""
        try:
            with open(filename, 'w') as f:
                f.write("Network Packet Capture Results\n")
                f.write("="*50 + "\n\n")
                
                for packet in self.packet_details:
                    f.write(f"Packet #{packet['number']} - {packet['timestamp']}\n")
                    f.write(f"Protocol: {packet['protocol']}\n")
                    f.write(f"Source: {packet['src_ip']}:{packet['src_port']}\n")
                    f.write(f"Destination: {packet['dst_ip']}:{packet['dst_port']}\n")
                    f.write(f"Length: {packet['length']} bytes\n")
                    if packet['payload']:
                        f.write(f"Payload: {packet['payload']}\n")
                    f.write("-"*30 + "\n")
            
            print(f"\n[+] Packet details saved to {filename}")
        except Exception as e:
            print(f"[!] Error saving to file: {e}")

def list_interfaces():
    """List available network interfaces"""
    print("Available network interfaces:")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces, 1):
        print(f"  {i}. {iface}")
    return interfaces

def main():
    parser = argparse.ArgumentParser(description="Network Packet Capture and Analysis Tool")
    parser.add_argument("-i", "--interface", help="Network interface to capture on")
    parser.add_argument("-f", "--filter", help="BPF filter string (e.g., 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture")
    parser.add_argument("-s", "--save", help="Save results to file")
    parser.add_argument("-l", "--list-interfaces", action="store_true", help="List available interfaces")
    
    args = parser.parse_args()
    
    if args.list_interfaces:
        list_interfaces()
        return
    
    # Check if running as administrator/root
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] Warning: This tool may require administrator privileges on Windows")
        except:
            pass
    else:  # Unix/Linux
        if os.geteuid() != 0:
            print("[!] Warning: This tool may require root privileges on Unix/Linux systems")
    
    # Initialize analyzer
    analyzer = PacketAnalyzer()
    
    try:
        # Start capture
        analyzer.start_capture(
            interface=args.interface,
            filter_str=args.filter,
            max_packets=args.count
        )
        
        # Save results if requested
        if args.save:
            analyzer.save_to_file(args.save)
            
    except KeyboardInterrupt:
        print("\n[!] Capture interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
