#!/usr/bin/env python3
"""
Example usage of the Network Packet Capture Tool
Demonstrates how to use the PacketAnalyzer class programmatically.
"""

from packet_capture import PacketAnalyzer
import time
import threading

def example_basic_capture():
    """Example: Basic packet capture"""
    print("=== Basic Packet Capture Example ===")
    
    analyzer = PacketAnalyzer()
    
    # Start capture in a separate thread
    capture_thread = threading.Thread(
        target=analyzer.start_capture,
        kwargs={'max_packets': 10}
    )
    capture_thread.start()
    
    # Wait for capture to complete
    capture_thread.join()
    
    print("\nBasic capture completed!")

def example_filtered_capture():
    """Example: Capture specific traffic"""
    print("\n=== Filtered Capture Example ===")
    
    analyzer = PacketAnalyzer()
    
    # Capture only TCP traffic on port 80 (HTTP)
    print("Capturing HTTP traffic (TCP port 80)...")
    analyzer.start_capture(
        filter_str="tcp port 80",
        max_packets=5
    )
    
    print("Filtered capture completed!")

def example_icmp_capture():
    """Example: Capture ICMP (ping) packets"""
    print("\n=== ICMP Capture Example ===")
    
    analyzer = PacketAnalyzer()
    
    print("Capturing ICMP packets (ping traffic)...")
    analyzer.start_capture(
        filter_str="icmp",
        max_packets=5
    )
    
    print("ICMP capture completed!")

def example_save_to_file():
    """Example: Save capture results to file"""
    print("\n=== Save to File Example ===")
    
    analyzer = PacketAnalyzer()
    
    # Capture and save to file
    print("Capturing packets and saving to file...")
    analyzer.start_capture(
        max_packets=10
    )
    
    # Save results
    analyzer.save_to_file("example_capture.txt")
    print("Results saved to example_capture.txt")

def demonstrate_protocol_analysis():
    """Demonstrate protocol analysis capabilities"""
    print("\n=== Protocol Analysis Demonstration ===")
    
    analyzer = PacketAnalyzer()
    
    print("Capturing mixed traffic for protocol analysis...")
    analyzer.start_capture(
        max_packets=20
    )
    
    # The analyzer will automatically show:
    # - Protocol distribution
    # - Top source IPs
    # - Top ports
    # - TCP flags (for TCP packets)
    # - Payload previews

if __name__ == "__main__":
    print("Network Packet Capture Tool - Example Usage")
    print("=" * 50)
    
    try:
        # Run examples
        example_basic_capture()
        example_filtered_capture()
        example_icmp_capture()
        example_save_to_file()
        demonstrate_protocol_analysis()
        
        print("\n" + "=" * 50)
        print("All examples completed!")
        print("\nTo run the full tool with command line options:")
        print("python packet_capture.py -h")
        
    except KeyboardInterrupt:
        print("\n[!] Examples interrupted by user")
    except Exception as e:
        print(f"\n[!] Error running examples: {e}")
        print("\nMake sure you have:")
        print("1. Installed dependencies: pip install -r requirements.txt")
        print("2. Administrator/root privileges")
        print("3. Proper network interface permissions")
