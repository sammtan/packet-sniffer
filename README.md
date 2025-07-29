# 📡 Packet Sniffer - Advanced Network Traffic Analyzer

A powerful, educational network packet capture and analysis tool designed for cybersecurity professionals and enthusiasts. Features real-time Wi-Fi monitoring with comprehensive protocol analysis.

## ⚠️ Important Legal Notice

**This tool is for educational and authorized testing purposes only.** Only use on networks you own or have explicit written permission to monitor. Unauthorized network monitoring may violate privacy laws and regulations in your jurisdiction.

## 🌟 Features

### Core Capabilities
- **Real-time Wi-Fi Packet Capture** - Monitor live network traffic from your wireless adapter
- **Multi-Protocol Analysis** - Deep inspection of TCP, UDP, ICMP, HTTP, DNS, and more
- **Advanced Filtering** - Filter by protocol, IP addresses, ports, and custom search queries
- **Live Statistics** - Real-time traffic analysis with protocol distribution and top talkers
- **Export Functionality** - Save captures in JSON, CSV, and text formats

### Web Interface
- **Professional Dark Theme** - Portfolio-consistent design with real-time packet visualization
- **Live Packet Stream** - Server-sent events for real-time packet display
- **Interactive Statistics** - Dynamic charts and graphs for traffic analysis
- **Search & Filter** - Advanced packet filtering and search capabilities
- **Export Tools** - Download captures in multiple formats

### Command Line Interface
- **Interactive Mode** - User-friendly interface selection and configuration
- **Flexible Filtering** - Protocol-specific capture with customizable parameters
- **Multiple Output Formats** - Text, JSON, and CSV export options
- **Real-time Display** - Colored output with packet information and statistics

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Administrator/root privileges (required for packet capture)
- Windows, Linux, or macOS

### Installation

1. **Clone the repository:**
```bash
cd sammtan.github.io-tools
cd packet-sniffer
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Install additional requirements for web interface:**
```bash
pip install flask flask-cors
```

### Basic Usage

#### Command Line Interface
```bash
# Interactive mode - select interface and start capture
python src/packet_sniffer.py

# Capture 100 TCP packets on specific interface
python src/packet_sniffer.py -i "Wi-Fi" -p tcp -c 100

# Filter UDP traffic and save to JSON
python src/packet_sniffer.py -p udp -o capture.json

# List available network interfaces
python src/packet_sniffer.py --list-interfaces
```

#### Web Interface
```bash
# Start the web server
python web/app.py

# Access the interface at:
http://localhost:5000
```

## 📋 Command Line Options

```
usage: packet_sniffer.py [-h] [-i INTERFACE] [-c COUNT] [-p {tcp,udp,icmp}] 
                          [-o OUTPUT] [--quiet] [--list-interfaces]

Packet Sniffer - Advanced Network Traffic Analyzer

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Network interface to capture on
  -c COUNT, --count COUNT
                        Number of packets to capture (0 = unlimited)
  -p {tcp,udp,icmp}, --protocol {tcp,udp,icmp}
                        Filter by protocol
  -o OUTPUT, --output OUTPUT
                        Output file (supports .json, .csv, .txt)
  --quiet               Disable real-time packet display
  --list-interfaces     List available network interfaces
```

## 🔧 Detailed Usage Examples

### 1. Basic Network Monitoring
Monitor all traffic on your Wi-Fi interface:
```bash
python src/packet_sniffer.py -i "Wi-Fi"
```

### 2. Protocol-Specific Analysis
Capture only HTTP/HTTPS traffic:
```bash
python src/packet_sniffer.py -i "Wi-Fi" -p tcp -c 500 -o web_traffic.json
```

### 3. DNS Query Monitoring
Monitor DNS requests and responses:
```bash
python src/packet_sniffer.py -i "Wi-Fi" -p udp -o dns_analysis.csv
```

### 4. Security Analysis
Capture ICMP traffic for network diagnostics:
```bash
python src/packet_sniffer.py -i "Wi-Fi" -p icmp -c 50 --quiet
```

### 5. Background Monitoring
Long-term traffic analysis with file output:
```bash
python src/packet_sniffer.py -i "Wi-Fi" -c 10000 -o network_analysis.json --quiet
```

## 🌐 Web Interface Guide

### Starting the Web Interface
1. Launch the web server: `python web/app.py`
2. Open browser to `http://localhost:5000`
3. Select your network interface from the dropdown
4. Configure protocol filter and packet limit (optional)
5. Click "Start Capture" to begin monitoring

### Interface Features

#### Live Packets Tab
- **Real-time packet stream** with protocol-colored display
- **Search functionality** - filter by IP, port, protocol, or content
- **Auto-scroll option** - automatically scroll to show newest packets
- **Packet details** - timestamp, source/destination, protocol, length, and info

#### Statistics Tab
- **Protocol Distribution** - breakdown of captured traffic by protocol
- **Top Source IPs** - most active source addresses
- **Top Destinations** - most contacted destination addresses  
- **Active Ports** - busiest network ports in the capture

#### Export Tab
- **JSON Export** - complete packet data with metadata and statistics
- **CSV Export** - tabular format suitable for spreadsheet analysis

## 🎯 Educational Use Cases

### Network Administration
- **Traffic Analysis** - Identify bandwidth usage patterns and top talkers
- **Protocol Distribution** - Understand network protocol usage
- **Performance Monitoring** - Analyze network latency and throughput

### Cybersecurity Learning
- **Packet Analysis** - Learn how different protocols work at the packet level
- **Network Forensics** - Practice analyzing network traffic for security incidents
- **Protocol Understanding** - Deep dive into TCP/IP, HTTP, DNS, and other protocols

### Development & Testing
- **API Testing** - Monitor HTTP requests and responses during development
- **Network Debugging** - Troubleshoot connectivity and protocol issues
- **Performance Analysis** - Identify network bottlenecks and optimization opportunities

## 🛡️ Security Considerations

### Ethical Usage
- **Authorization Required** - Only monitor networks you own or have permission to access
- **Privacy Awareness** - Be mindful of sensitive data in captured packets
- **Legal Compliance** - Ensure usage complies with local laws and regulations
- **Data Protection** - Securely handle and dispose of captured network data

### Technical Security
- **Encrypted Traffic** - Modern networks use encryption; you'll see encrypted packet contents
- **Switched Networks** - Modern switches limit visible traffic to your own communication
- **Wireless Limitations** - Wi-Fi adapters may not support full promiscuous mode

## 🔍 Understanding Packet Output

### Packet Information Fields
- **Timestamp** - When the packet was captured (HH:MM:SS.ms format)
- **Protocol** - Network protocol (TCP, UDP, ICMP, DNS, HTTP, etc.)
- **Source IP:Port** - Origin address and port number
- **Destination IP:Port** - Target address and port number
- **Length** - Packet size in bytes
- **Info** - Protocol-specific information and flags

### Protocol-Specific Details

#### TCP Packets
- **Flags** - SYN, ACK, FIN, RST, PSH, URG
- **Sequence Numbers** - TCP sequence and acknowledgment numbers
- **Window Size** - TCP window size for flow control

#### UDP Packets
- **Length** - UDP payload length
- **DNS Queries** - Domain name resolution requests and responses
- **Application Data** - Various UDP-based protocols

#### ICMP Packets
- **Type/Code** - ICMP message type and code
- **Ping Requests** - Echo request and reply messages
- **Network Diagnostics** - Various ICMP diagnostic messages

## 📊 Statistics and Analysis

### Real-time Metrics
- **Packet Rate** - Packets per second during capture
- **Protocol Distribution** - Percentage breakdown by protocol type
- **Traffic Volume** - Total bytes and average packet size
- **Active Connections** - Source and destination IP analysis

### Advanced Analysis
- **Port Activity** - Most active network ports
- **Traffic Patterns** - Temporal analysis of network activity
- **Anomaly Detection** - Identification of unusual traffic patterns
- **Performance Metrics** - Network utilization and efficiency analysis

## 🐛 Troubleshooting

### Common Issues

#### Permission Denied
**Problem:** "Permission denied" error when starting capture
**Solution:** Run as administrator (Windows) or with sudo (Linux/macOS)

#### No Interfaces Found
**Problem:** No network interfaces appear in the list
**Solution:** Ensure Scapy is installed and you have administrative privileges

#### Scapy Installation Issues
**Problem:** "Scapy not installed" error
**Solution:** Install with `pip install scapy` or `pip3 install scapy`

#### Limited Packet Capture
**Problem:** Only seeing your own traffic
**Solution:** This is normal on modern switched networks; use loopback for testing

### Performance Optimization
- **Packet Limits** - Use packet count limits for large captures
- **Protocol Filtering** - Filter specific protocols to reduce overhead
- **Output Files** - Save to files instead of real-time display for better performance
- **Memory Management** - Clear packets regularly during long captures

## 🧪 Testing and Validation

### Test Setup
1. **Loopback Testing** - Use localhost traffic for initial testing
2. **Generate Traffic** - Use ping, web browsing, or file downloads
3. **Protocol Testing** - Test different protocols (HTTP, DNS, ICMP)
4. **Filter Validation** - Verify protocol filters work correctly

### Test Commands
```bash
# Test with ping traffic
ping google.com  # Run in another terminal

# Test with web traffic
curl -I http://example.com  # Generate HTTP requests

# Test DNS resolution
nslookup github.com  # Generate DNS queries
```

## 🔧 Technical Architecture

### Core Components
- **PacketSniffer Class** - Main capture engine using Scapy
- **PacketInfo DataClass** - Structured packet information storage
- **PacketStatistics Class** - Real-time statistics calculation
- **Web Interface** - Flask-based web application with REST API

### Dependencies
- **Scapy** - Packet capture and parsing library
- **Flask** - Web framework for interface
- **Threading** - Concurrent packet processing
- **JSON/CSV** - Data export functionality

## 📈 Future Enhancements

### Planned Features
- **PCAP Export** - Wireshark-compatible capture file export
- **Advanced Filtering** - BPF (Berkeley Packet Filter) support
- **Geographical Analysis** - IP geolocation and mapping
- **Anomaly Detection** - Machine learning-based traffic analysis
- **Mobile App** - Mobile interface for remote monitoring

### Contribution
This project welcomes contributions! Feel free to submit issues, feature requests, or pull requests.

## 🔗 Combined Workflow Integration

### Real-World Security Analysis with DNS Resolver

The Packet Sniffer achieves maximum effectiveness when combined with DNS intelligence tools for comprehensive network security analysis:

#### **Complete Infrastructure Assessment Example**

```bash
# Step 1: DNS Intelligence (with DNS Resolver)
# Discover target infrastructure: github.com → 20.205.243.166

# Step 2: Real-time Traffic Monitoring
python src/packet_sniffer.py -i "Wi-Fi" -c 15 -o github_traffic.json
# Captures actual traffic showing different IPs due to load balancing

# Step 3: Correlation Analysis
# DNS: github.com → 20.205.243.166 (expected)
# Traffic: 192.168.1.5 ↔ 140.82.113.21 (actual)
# Reveals load balancing and CDN infrastructure
```

#### **Real Test Results from GitHub Analysis**

```bash
=== DNS INTELLIGENCE ===
Target Domain: github.com
Resolved IP: 20.205.243.166
API Endpoint: api.github.com → 20.205.243.168

=== LIVE TRAFFIC CAPTURE ===
Total Packets: 15 (0.16 seconds)
Protocol: 100% TCP (HTTPS on port 443)
Actual Endpoint: 140.82.113.21 (12 packets from GitHub)
Traffic Pattern: Heavy inbound (GitHub → You: 12, You → GitHub: 3)

=== REVERSE DNS VALIDATION ===
140.82.113.21 → lb-140-82-113-21-iad.github.com
Infrastructure: GitHub load balancer (Washington DC)
```

#### **Traffic Analysis Insights**

**What DNS Alone Misses**:
- **Load Balancer IPs**: Actual traffic goes to different IPs than DNS shows
- **Traffic Patterns**: Volume, timing, and protocol usage
- **Geographic Distribution**: Datacenter locations via reverse DNS

**What Packet Analysis Reveals**:
- **Real Communication**: 95.2 packets/second during API requests
- **Protocol Security**: 100% encrypted HTTPS traffic
- **Network Behavior**: TCP connection patterns and data flow
- **Performance Metrics**: Response times and packet sizes

#### **Integration Architecture**

```python
# Pseudo-code for combined security platform
class CombinedAnalyzer:
    def analyze_target(self, domain):
        # 1. DNS Discovery
        dns_info = dns_resolver.resolve_all(domain)
        ip_ranges = dns_info.get_all_ips()
        
        # 2. Live Monitoring
        sniffer.start_monitoring(ip_ranges)
        
        # 3. Real-time Correlation
        for packet in sniffer.stream():
            if packet.dest_ip not in ip_ranges:
                # Discovered new IP through traffic
                reverse_dns = dns_resolver.reverse(packet.dest_ip)
                self.log_discovery(packet.dest_ip, reverse_dns)
        
        # 4. Comprehensive Report
        return self.generate_intelligence_report()
```

#### **Combined Platform Benefits**

**Intelligence Gap Filling**:
- **DNS provides targets** → **Packet analysis shows reality**
- **Static infrastructure** → **Dynamic traffic patterns**
- **Potential endpoints** → **Active communication channels**

**Enhanced Security Analysis**:
- **Complete attack surface** identification
- **Real-time threat detection** capabilities
- **Comprehensive forensic data** collection
- **Automated correlation** of network activities

This integration creates a **unified network intelligence platform** providing insights neither tool could achieve independently.

## 📚 Additional Resources

### Learning Materials
- **Wireshark Documentation** - Learn about packet analysis techniques
- **Network Protocols** - Study TCP/IP, HTTP, DNS, and other protocols
- **Cybersecurity Training** - Apply packet analysis to security scenarios
- **Python Networking** - Learn Python network programming with Scapy

### Related Tools
- **Wireshark** - Professional network protocol analyzer
- **tcpdump** - Command-line packet analyzer
- **nmap** - Network discovery and security auditing
- **Burp Suite** - Web application security testing

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚖️ Disclaimer

This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring their use complies with applicable laws and regulations. The authors assume no liability for misuse of this software.

---

**Developed by Samuel Tan** | [GitHub Repository](https://github.com/sammtan/packet-sniffer)

*Part of the cybersecurity tools portfolio demonstrating advanced network analysis capabilities.*