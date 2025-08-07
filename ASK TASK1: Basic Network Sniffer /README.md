# Network Packet Capture and Analysis Tool

A comprehensive Python tool for capturing, analyzing, and displaying network traffic packets. This tool helps you understand network protocols, data flow, and packet structures.

## Features

- **Real-time packet capture** using Scapy library
- **Protocol analysis** (TCP, UDP, ICMP, ARP)
- **Detailed packet information** including source/destination IPs, ports, and payloads
- **Statistics and summaries** with protocol distribution and top IPs/ports
- **BPF filtering** support for targeted capture
- **File export** capability for analysis
- **Cross-platform** support (Windows, Linux, macOS)

## Installation

### Prerequisites

- Python 3.7 or higher
- Administrator/root privileges (required for packet capture)

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Windows Users

On Windows, you may need to install Npcap or WinPcap for packet capture:

1. Download and install [Npcap](https://npcap.com/) (recommended)
2. Or install [WinPcap](https://www.winpcap.org/) (legacy)

## Usage

### Basic Usage

```bash
# Capture all packets (requires admin/root privileges)
python packet_capture.py

# List available network interfaces
python packet_capture.py -l

# Capture specific number of packets
python packet_capture.py -c 100

# Capture on specific interface
python packet_capture.py -i "Ethernet"

# Filter specific traffic (TCP port 80)
python packet_capture.py -f "tcp port 80"

# Save results to file
python packet_capture.py -c 50 -s capture_results.txt
```

### Advanced Filtering Examples

```bash
# Capture only HTTP traffic
python packet_capture.py -f "tcp port 80 or tcp port 443"

# Capture traffic from specific IP
python packet_capture.py -f "host 192.168.1.1"

# Capture DNS queries
python packet_capture.py -f "udp port 53"

# Capture ICMP (ping) packets
python packet_capture.py -f "icmp"

# Capture traffic between two hosts
python packet_capture.py -f "host 192.168.1.1 and host 192.168.1.2"
```

## Understanding Network Packets

### Packet Structure

Network packets follow a layered structure:

1. **Physical Layer** - Raw bits on the wire
2. **Data Link Layer** - Ethernet frames with MAC addresses
3. **Network Layer** - IP packets with source/destination IPs
4. **Transport Layer** - TCP/UDP segments with ports
5. **Application Layer** - HTTP, DNS, FTP, etc.

### Common Protocols

- **TCP (Transmission Control Protocol)**: Connection-oriented, reliable
- **UDP (User Datagram Protocol)**: Connectionless, fast
- **ICMP (Internet Control Message Protocol)**: Network diagnostics (ping)
- **ARP (Address Resolution Protocol)**: Maps IP to MAC addresses

### TCP Flags

- **SYN**: Synchronize (connection initiation)
- **ACK**: Acknowledgment
- **FIN**: Finish (connection termination)
- **RST**: Reset (abort connection)
- **PSH**: Push (send data immediately)
- **URG**: Urgent (priority data)

## Educational Value

### What You'll Learn

1. **Network Protocols**: How different protocols work and their characteristics
2. **Data Flow**: How information travels through networks
3. **Packet Analysis**: Understanding packet headers and payloads
4. **Network Security**: Identifying suspicious traffic patterns
5. **Troubleshooting**: Diagnosing network issues

### Common Use Cases

- **Network Monitoring**: Observe traffic patterns
- **Security Analysis**: Detect unusual network activity
- **Protocol Learning**: Understand how applications communicate
- **Troubleshooting**: Debug network connectivity issues
- **Research**: Study network behavior and performance

## Output Examples

### Packet Display
```
[   1] 14:30:25.123 | TCP    | 192.168.1.100:52431 -> 8.8.8.8:443     | Length:  150
        TCP Flags: SYN
        Payload: 16030100...

[   2] 14:30:25.124 | ICMP   | 192.168.1.100:Unknown -> 8.8.8.8:Unknown | Length:   84
```

### Summary Statistics
```
CAPTURE SUMMARY
================================================================================
Total packets captured: 150
Capture duration: 45.23 seconds

Protocol Distribution:
  TCP: 89 packets (59.3%)
  UDP: 45 packets (30.0%)
  ICMP: 16 packets (10.7%)

Top Source IPs:
  192.168.1.100: 45 packets
  8.8.8.8: 23 packets

Top Ports:
  Port 443 (HTTPS): 34 packets
  Port 53 (DNS): 28 packets
```

## Security and Legal Considerations

⚠️ **Important**: Packet capture tools should only be used on networks you own or have explicit permission to monitor.

- **Legal**: Ensure you have permission to capture network traffic
- **Privacy**: Be aware that packet capture can reveal sensitive information
- **Security**: Use responsibly and ethically
- **Educational**: This tool is for learning and legitimate network analysis

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run as administrator/root
2. **No Packets Captured**: Check interface name and permissions
3. **Scapy Import Error**: Install dependencies with `pip install -r requirements.txt`
4. **Windows Issues**: Install Npcap or WinPcap

### Getting Help

- Check interface names with `-l` flag
- Start with simple filters like `-f "tcp"`
- Use `-c 10` to limit packets for testing

## Advanced Features

### Custom Analysis

The `PacketAnalyzer` class can be extended for custom analysis:

```python
analyzer = PacketAnalyzer()
analyzer.start_capture(filter_str="tcp port 80")
```

### Integration

This tool can be integrated with other security tools or used as a learning platform for network analysis.

## Contributing

Feel free to extend this tool with additional features:
- Protocol-specific analyzers
- Graphical interfaces
- Database storage
- Real-time alerts
- Advanced filtering options
