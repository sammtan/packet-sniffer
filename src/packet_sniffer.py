#!/usr/bin/env python3
"""
Packet Sniffer - Advanced Network Traffic Analyzer
Educational cybersecurity tool for real-time packet capture and analysis

Author: Samuel Tan
GitHub: https://github.com/sammtan/packet-sniffer
License: MIT

WARNING: This tool captures network traffic and should only be used on networks
you own or have explicit permission to monitor. Unauthorized network monitoring
may violate privacy laws and regulations.
"""

import socket
import struct
import threading
import time
import json
import csv
import os
import sys
from datetime import datetime
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any
import argparse

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not installed. Limited functionality available.")
    SCAPY_AVAILABLE = False

@dataclass
class PacketInfo:
    """Data structure for parsed packet information"""
    timestamp: str
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: str
    length: int
    info: str
    raw_data: Optional[str] = None

class PacketStatistics:
    """Real-time packet statistics tracker"""
    
    def __init__(self):
        self.reset()
    
    def reset(self):
        """Reset all statistics"""
        self.total_packets = 0
        self.protocol_counts = Counter()
        self.ip_sources = Counter()
        self.ip_destinations = Counter()
        self.port_activity = Counter()
        self.start_time = time.time()
        self.packet_sizes = []
        self.suspicious_activity = []
    
    def update(self, packet_info: PacketInfo):
        """Update statistics with new packet"""
        self.total_packets += 1
        self.protocol_counts[packet_info.protocol] += 1
        self.ip_sources[packet_info.source_ip] += 1
        self.ip_destinations[packet_info.dest_ip] += 1
        self.packet_sizes.append(packet_info.length)
        
        if packet_info.source_port:
            self.port_activity[packet_info.source_port] += 1
        if packet_info.dest_port:
            self.port_activity[packet_info.dest_port] += 1
    
    def get_summary(self) -> Dict[str, Any]:
        """Get current statistics summary"""
        runtime = time.time() - self.start_time
        avg_size = sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
        
        return {
            "total_packets": self.total_packets,
            "runtime_seconds": round(runtime, 2),
            "packets_per_second": round(self.total_packets / runtime, 2) if runtime > 0 else 0,
            "average_packet_size": round(avg_size, 2),
            "protocols": dict(self.protocol_counts.most_common(10)),
            "top_sources": dict(self.ip_sources.most_common(10)),
            "top_destinations": dict(self.ip_destinations.most_common(10)),
            "active_ports": dict(self.port_activity.most_common(10))
        }

class PacketSniffer:
    """Main packet sniffer class with real-time Wi-Fi monitoring"""
    
    def __init__(self, interface=None, output_file=None, packet_count=0, 
                 filter_protocol=None, real_time=True):
        self.interface = interface
        self.output_file = output_file
        self.packet_count = packet_count
        self.filter_protocol = filter_protocol
        self.real_time = real_time
        self.captured_packets = []
        self.statistics = PacketStatistics()
        self.running = False
        self.capture_thread = None
        
        # Protocol mappings
        self.protocol_map = {
            1: "ICMP",
            6: "TCP", 
            17: "UDP",
            50: "ESP",
            51: "AH"
        }
        
        if not SCAPY_AVAILABLE:
            print("Error: Scapy is required for packet capture functionality.")
            print("Install with: pip install scapy")
            sys.exit(1)
    
    def get_available_interfaces(self) -> List[str]:
        """Get list of available network interfaces"""
        try:
            return get_if_list()
        except:
            return []
    
    def select_interface(self) -> str:
        """Interactive interface selection"""
        interfaces = self.get_available_interfaces()
        
        if not interfaces:
            print("No network interfaces found!")
            return None
        
        print("\nAvailable Network Interfaces:")
        print("-" * 40)
        for i, iface in enumerate(interfaces, 1):
            try:
                # Try to get interface details
                ip = get_if_addr(iface)
                print(f"{i}. {iface} ({ip})")
            except:
                print(f"{i}. {iface}")
        
        while True:
            try:
                choice = input(f"\nSelect interface (1-{len(interfaces)}): ").strip()
                if choice.lower() == 'q':
                    return None
                
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    return interfaces[idx]
                else:
                    print("Invalid selection. Try again.")
            except (ValueError, KeyboardInterrupt):
                print("\nOperation cancelled.")
                return None
    
    def parse_packet_scapy(self, packet) -> Optional[PacketInfo]:
        """Parse packet using Scapy"""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            # Initialize packet info
            source_ip = dest_ip = "Unknown"
            source_port = dest_port = None
            protocol = "Unknown"
            info = ""
            length = len(packet)
            
            # Extract Ethernet layer info if present
            if packet.haslayer(Ether):
                pass  # Could extract MAC addresses here
            
            # Extract IP layer info
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                source_ip = ip_layer.src
                dest_ip = ip_layer.dst
                protocol = self.protocol_map.get(ip_layer.proto, f"Protocol-{ip_layer.proto}")
                
                # Extract transport layer info
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    source_port = tcp_layer.sport
                    dest_port = tcp_layer.dport
                    protocol = "TCP"
                    
                    # Check for HTTP traffic
                    if packet.haslayer(HTTPRequest):
                        http = packet[HTTPRequest]
                        info = f"HTTP Request: {http.Method.decode()} {http.Host.decode()}{http.Path.decode()}"
                    elif packet.haslayer(HTTPResponse):
                        http = packet[HTTPResponse]
                        info = f"HTTP Response: {http.Status_Code}"
                    else:
                        flags = self._get_tcp_flags(tcp_layer)
                        info = f"TCP {source_port} -> {dest_port} [{flags}] Seq={tcp_layer.seq}"
                
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    source_port = udp_layer.sport
                    dest_port = udp_layer.dport
                    protocol = "UDP"
                    
                    # Check for DNS traffic
                    if packet.haslayer(DNS):
                        dns = packet[DNS]
                        if dns.qr == 0:  # Query
                            info = f"DNS Query: {dns.qd.qname.decode() if dns.qd else 'Unknown'}"
                        else:  # Response
                            info = f"DNS Response: {dns.ancount} answers"
                    else:
                        info = f"UDP {source_port} -> {dest_port} Len={len(udp_layer.payload)}"
                
                elif packet.haslayer(ICMP):
                    icmp = packet[ICMP]
                    protocol = "ICMP"
                    info = f"ICMP Type={icmp.type} Code={icmp.code}"
            
            # Create packet info
            packet_info = PacketInfo(
                timestamp=timestamp,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=protocol,
                length=length,
                info=info,
                raw_data=bytes(packet).hex() if hasattr(packet, '__bytes__') else None
            )
            
            return packet_info
            
        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None
    
    def _get_tcp_flags(self, tcp_layer) -> str:
        """Get TCP flags as string"""
        flags = []
        if tcp_layer.flags & 0x01: flags.append("FIN")
        if tcp_layer.flags & 0x02: flags.append("SYN")
        if tcp_layer.flags & 0x04: flags.append("RST")
        if tcp_layer.flags & 0x08: flags.append("PSH")
        if tcp_layer.flags & 0x10: flags.append("ACK")
        if tcp_layer.flags & 0x20: flags.append("URG")
        return ",".join(flags) if flags else "None"
    
    def packet_handler(self, packet):
        """Handle captured packets"""
        packet_info = self.parse_packet_scapy(packet)
        if not packet_info:
            return
        
        # Apply protocol filter
        if self.filter_protocol and packet_info.protocol.lower() != self.filter_protocol.lower():
            return
        
        # Store packet
        self.captured_packets.append(packet_info)
        self.statistics.update(packet_info)
        
        # Real-time display
        if self.real_time:
            self._display_packet_realtime(packet_info)
        
        # Check packet count limit
        if self.packet_count > 0 and len(self.captured_packets) >= self.packet_count:
            self.stop_capture()
    
    def _display_packet_realtime(self, packet_info: PacketInfo):
        """Display packet in real-time"""
        color_map = {
            "TCP": "\033[94m",    # Blue
            "UDP": "\033[92m",    # Green
            "ICMP": "\033[93m",   # Yellow
            "DNS": "\033[95m",    # Magenta
        }
        
        color = color_map.get(packet_info.protocol, "\033[0m")
        reset = "\033[0m"
        
        print(f"{color}[{packet_info.timestamp}] {packet_info.protocol:<6} "
              f"{packet_info.source_ip:<15} -> {packet_info.dest_ip:<15} "
              f"({packet_info.length:4d}B) {packet_info.info}{reset}")
    
    def start_capture(self):
        """Start packet capture"""
        if not self.interface:
            self.interface = self.select_interface()
            if not self.interface:
                print("No interface selected. Exiting.")
                return
        
        print(f"\n[*] Starting packet capture on interface: {self.interface}")
        print(f"[*] Filter: {self.filter_protocol or 'All protocols'}")
        print("[*] Press Ctrl+C to stop capture\n")
        
        self.running = True
        
        try:
            # Start statistics display thread
            if self.real_time:
                stats_thread = threading.Thread(target=self._display_statistics_loop)
                stats_thread.daemon = True
                stats_thread.start()
            
            # Start packet capture with Scapy
            sniff(iface=self.interface, prn=self.packet_handler, store=0, stop_filter=lambda x: not self.running)
            
        except KeyboardInterrupt:
            print("\n[*] Capture interrupted by user")
        except PermissionError:
            print("Error: Permission denied. Try running as administrator/root.")
        except Exception as e:
            print(f"Error during capture: {e}")
        finally:
            self.stop_capture()
    
    def stop_capture(self):
        """Stop packet capture"""
        self.running = False
        print(f"\n[*] Capture stopped. Total packets: {len(self.captured_packets)}")
        
        # Save to file if specified
        if self.output_file:
            self.save_packets()
        
        # Display final statistics
        self.display_statistics()
    
    def _display_statistics_loop(self):
        """Display statistics in real-time loop"""
        while self.running:
            try:
                time.sleep(5)  # Update every 5 seconds
                if self.statistics.total_packets > 0:
                    self._clear_stats_area()
                    stats = self.statistics.get_summary()
                    print(f"\n[Stats] Packets: {stats['total_packets']} | "
                          f"Rate: {stats['packets_per_second']:.1f}/s | "
                          f"Runtime: {stats['runtime_seconds']}s")
            except:
                break
    
    def _clear_stats_area(self):
        """Clear statistics display area"""
        # Move cursor up and clear line (basic terminal control)
        pass
    
    def display_statistics(self):
        """Display comprehensive packet statistics"""
        if not self.captured_packets:
            print("No packets captured.")
            return
        
        stats = self.statistics.get_summary()
        
        print("\n" + "="*60)
        print("PACKET CAPTURE STATISTICS")
        print("="*60)
        
        print(f"Total Packets Captured: {stats['total_packets']}")
        print(f"Capture Duration: {stats['runtime_seconds']} seconds")
        print(f"Average Rate: {stats['packets_per_second']} packets/second")
        print(f"Average Packet Size: {stats['average_packet_size']} bytes")
        
        print(f"\nProtocol Distribution:")
        for protocol, count in stats['protocols'].items():
            percentage = (count / stats['total_packets']) * 100
            print(f"  {protocol:<8}: {count:4d} ({percentage:5.1f}%)")
        
        print(f"\nTop Source IPs:")
        for ip, count in stats['top_sources'].items():
            print(f"  {ip:<15}: {count:4d} packets")
        
        print(f"\nTop Destination IPs:")
        for ip, count in stats['top_destinations'].items():
            print(f"  {ip:<15}: {count:4d} packets")
        
        print(f"\nActive Ports:")
        for port, count in stats['active_ports'].items():
            print(f"  Port {port:<5}: {count:4d} packets")
    
    def save_packets(self):
        """Save captured packets to file"""
        if not self.captured_packets:
            print("No packets to save.")
            return
        
        file_ext = os.path.splitext(self.output_file)[1].lower()
        
        try:
            if file_ext == '.json':
                self._save_json()
            elif file_ext == '.csv':
                self._save_csv()
            elif file_ext == '.pcap':
                self._save_pcap()
            else:
                self._save_text()
            
            print(f"[*] Packets saved to: {self.output_file}")
            
        except Exception as e:
            print(f"Error saving packets: {e}")
    
    def _save_json(self):
        """Save packets in JSON format"""
        data = {
            "capture_info": {
                "timestamp": datetime.now().isoformat(),
                "interface": self.interface,
                "total_packets": len(self.captured_packets),
                "filter": self.filter_protocol
            },
            "statistics": self.statistics.get_summary(),
            "packets": [asdict(p) for p in self.captured_packets]
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _save_csv(self):
        """Save packets in CSV format"""
        with open(self.output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(['Timestamp', 'Source IP', 'Dest IP', 'Source Port', 
                           'Dest Port', 'Protocol', 'Length', 'Info'])
            
            # Data
            for packet in self.captured_packets:
                writer.writerow([
                    packet.timestamp, packet.source_ip, packet.dest_ip,
                    packet.source_port, packet.dest_port, packet.protocol,
                    packet.length, packet.info
                ])
    
    def _save_pcap(self):
        """Save packets in PCAP format (requires scapy)"""
        print("PCAP export requires implementation with raw packet data")
        # Would need to store raw Scapy packets for proper PCAP export
    
    def _save_text(self):
        """Save packets in text format"""
        with open(self.output_file, 'w') as f:
            f.write("PACKET CAPTURE REPORT\n")
            f.write("="*50 + "\n\n")
            
            # Write statistics
            stats = self.statistics.get_summary()
            f.write(f"Total Packets: {stats['total_packets']}\n")
            f.write(f"Capture Duration: {stats['runtime_seconds']} seconds\n")
            f.write(f"Interface: {self.interface}\n")
            f.write(f"Filter: {self.filter_protocol or 'None'}\n\n")
            
            # Write packets
            f.write("PACKET DETAILS\n")
            f.write("-" * 50 + "\n")
            
            for i, packet in enumerate(self.captured_packets, 1):
                f.write(f"Packet {i}:\n")
                f.write(f"  Time: {packet.timestamp}\n")
                f.write(f"  {packet.source_ip}:{packet.source_port or 'N/A'} -> ")
                f.write(f"{packet.dest_ip}:{packet.dest_port or 'N/A'}\n")
                f.write(f"  Protocol: {packet.protocol}\n")
                f.write(f"  Length: {packet.length} bytes\n")
                f.write(f"  Info: {packet.info}\n\n")

def main():
    """Main function with command-line interface"""
    parser = argparse.ArgumentParser(
        description="Packet Sniffer - Advanced Network Traffic Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python packet_sniffer.py                          # Interactive mode
  python packet_sniffer.py -i eth0 -c 100          # Capture 100 packets
  python packet_sniffer.py -p tcp -o capture.json  # TCP only, save to JSON
  python packet_sniffer.py -f udp --quiet          # UDP only, no real-time display

Warning: This tool requires administrator/root privileges for packet capture.
Only use on networks you own or have explicit permission to monitor.
        """)
    
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-c', '--count', type=int, default=0, 
                       help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('-p', '--protocol', choices=['tcp', 'udp', 'icmp'], 
                       help='Filter by protocol')
    parser.add_argument('-o', '--output', help='Output file (supports .json, .csv, .txt)')
    parser.add_argument('--quiet', action='store_true', 
                       help='Disable real-time packet display')
    parser.add_argument('--list-interfaces', action='store_true',
                       help='List available network interfaces')
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list_interfaces:
        sniffer = PacketSniffer()
        interfaces = sniffer.get_available_interfaces()
        print("Available Network Interfaces:")
        for i, iface in enumerate(interfaces, 1):
            try:
                ip = get_if_addr(iface)
                print(f"{i}. {iface} ({ip})")
            except:
                print(f"{i}. {iface}")
        return
    
    # Create sniffer instance
    sniffer = PacketSniffer(
        interface=args.interface,
        output_file=args.output,
        packet_count=args.count,
        filter_protocol=args.protocol,
        real_time=not args.quiet
    )
    
    # Start capture
    try:
        sniffer.start_capture()
    except KeyboardInterrupt:
        print("\nCapture interrupted by user.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()