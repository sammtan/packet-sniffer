#!/usr/bin/env python3
"""
Packet Sniffer Web Interface
Real-time network traffic monitoring with web-based visualization

Author: Samuel Tan
GitHub: https://github.com/sammtan/packet-sniffer
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from flask import Flask, render_template, jsonify, request, Response
from flask_cors import CORS
import json
import threading
import time
import queue
from datetime import datetime
from packet_sniffer import PacketSniffer, SCAPY_AVAILABLE

if SCAPY_AVAILABLE:
    from scapy.all import get_if_list, get_if_addr

app = Flask(__name__)
CORS(app)

# Global variables for packet capture
capture_thread = None
packet_queue = queue.Queue()
capture_statistics = {}
sniffer_instance = None
capture_active = False

class WebPacketSniffer(PacketSniffer):
    """Extended packet sniffer for web interface"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.web_packet_queue = queue.Queue()
    
    def packet_handler(self, packet):
        """Override packet handler for web interface"""
        packet_info = self.parse_packet_scapy(packet)
        if not packet_info:
            return
        
        # Apply protocol filter
        if self.filter_protocol and packet_info.protocol.lower() != self.filter_protocol.lower():
            return
        
        # Store packet
        self.captured_packets.append(packet_info)
        self.statistics.update(packet_info)
        
        # Add to web queue for real-time updates
        try:
            packet_data = {
                'timestamp': packet_info.timestamp,
                'source_ip': packet_info.source_ip,
                'dest_ip': packet_info.dest_ip,
                'source_port': packet_info.source_port,
                'dest_port': packet_info.dest_port,
                'protocol': packet_info.protocol,
                'length': packet_info.length,
                'info': packet_info.info
            }
            self.web_packet_queue.put_nowait(packet_data)
        except queue.Full:
            pass  # Skip if queue is full
        
        # Check packet count limit
        if self.packet_count > 0 and len(self.captured_packets) >= self.packet_count:
            self.stop_capture()

@app.route('/')
def index():
    """Main web interface"""
    return render_template('index.html')

@app.route('/api/interfaces')
def get_interfaces():
    """Get available network interfaces"""
    if not SCAPY_AVAILABLE:
        return jsonify({'error': 'Scapy not available'}), 500
    
    try:
        interfaces = []
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                interfaces.append({
                    'name': iface,
                    'ip': ip
                })
            except:
                interfaces.append({
                    'name': iface,
                    'ip': 'Unknown'
                })
        
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/start', methods=['POST'])
def start_capture():
    """Start packet capture"""
    global capture_thread, sniffer_instance, capture_active
    
    if not SCAPY_AVAILABLE:
        return jsonify({'error': 'Scapy not available'}), 500
    
    if capture_active:
        return jsonify({'error': 'Capture already running'}), 400
    
    data = request.json
    interface = data.get('interface')
    protocol_filter = data.get('protocol')
    packet_count = data.get('packet_count', 0)
    
    if not interface:
        return jsonify({'error': 'Interface required'}), 400
    
    try:
        # Create sniffer instance
        sniffer_instance = WebPacketSniffer(
            interface=interface,
            filter_protocol=protocol_filter,
            packet_count=packet_count,
            real_time=False
        )
        
        # Start capture in background thread
        def capture_worker():
            global capture_active
            capture_active = True
            try:
                sniffer_instance.start_capture()
            finally:
                capture_active = False
        
        capture_thread = threading.Thread(target=capture_worker)
        capture_thread.daemon = True
        capture_thread.start()
        
        return jsonify({
            'status': 'started',
            'interface': interface,
            'filter': protocol_filter or 'all'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    global capture_active, sniffer_instance
    
    if not capture_active or not sniffer_instance:
        return jsonify({'error': 'No active capture'}), 400
    
    try:
        sniffer_instance.stop_capture()
        capture_active = False
        
        return jsonify({
            'status': 'stopped',
            'total_packets': len(sniffer_instance.captured_packets)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/status')
def get_status():
    """Get current capture status"""
    global capture_active, sniffer_instance
    
    status = {
        'active': capture_active,
        'total_packets': len(sniffer_instance.captured_packets) if sniffer_instance else 0,
        'statistics': sniffer_instance.statistics.get_summary() if sniffer_instance else {}
    }
    
    return jsonify(status)

@app.route('/api/packets/stream')
def stream_packets():
    """Server-sent events for real-time packet streaming"""
    def event_stream():
        while True:
            if sniffer_instance and capture_active:
                try:
                    # Get packet from queue with timeout
                    packet_data = sniffer_instance.web_packet_queue.get(timeout=1)
                    yield f"data: {json.dumps(packet_data)}\n\n"
                except queue.Empty:
                    # Send heartbeat to keep connection alive
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
            else:
                time.sleep(1)
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
    
    return Response(event_stream(), mimetype='text/event-stream')

@app.route('/api/packets')
def get_packets():
    """Get captured packets (paginated)"""
    global sniffer_instance
    
    if not sniffer_instance:
        return jsonify({'packets': [], 'total': 0})
    
    # Pagination parameters
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    
    packets = []
    for packet_info in sniffer_instance.captured_packets[start_idx:end_idx]:
        packets.append({
            'timestamp': packet_info.timestamp,
            'source_ip': packet_info.source_ip,
            'dest_ip': packet_info.dest_ip,
            'source_port': packet_info.source_port,
            'dest_port': packet_info.dest_port,
            'protocol': packet_info.protocol,
            'length': packet_info.length,
            'info': packet_info.info
        })
    
    return jsonify({
        'packets': packets,
        'total': len(sniffer_instance.captured_packets),
        'page': page,
        'per_page': per_page
    })

@app.route('/api/statistics')
def get_statistics():
    """Get detailed packet statistics"""
    global sniffer_instance
    
    if not sniffer_instance:
        return jsonify({'error': 'No active capture'}), 400
    
    return jsonify(sniffer_instance.statistics.get_summary())

@app.route('/api/export/<format>')
def export_packets(format):
    """Export captured packets in various formats"""
    global sniffer_instance
    
    if not sniffer_instance or not sniffer_instance.captured_packets:
        return jsonify({'error': 'No packets to export'}), 400
    
    try:
        if format == 'json':
            data = {
                'capture_info': {
                    'timestamp': datetime.now().isoformat(),
                    'interface': sniffer_instance.interface,
                    'total_packets': len(sniffer_instance.captured_packets),
                    'filter': sniffer_instance.filter_protocol
                },
                'statistics': sniffer_instance.statistics.get_summary(),
                'packets': []
            }
            
            for packet_info in sniffer_instance.captured_packets:
                data['packets'].append({
                    'timestamp': packet_info.timestamp,
                    'source_ip': packet_info.source_ip,
                    'dest_ip': packet_info.dest_ip,
                    'source_port': packet_info.source_port,
                    'dest_port': packet_info.dest_port,
                    'protocol': packet_info.protocol,
                    'length': packet_info.length,
                    'info': packet_info.info
                })
            
            response = Response(
                json.dumps(data, indent=2),
                mimetype='application/json',
                headers={'Content-Disposition': 'attachment; filename=packet_capture.json'}
            )
            return response
            
        elif format == 'csv':
            import io
            import csv
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Header
            writer.writerow(['Timestamp', 'Source IP', 'Dest IP', 'Source Port', 
                           'Dest Port', 'Protocol', 'Length', 'Info'])
            
            # Data
            for packet in sniffer_instance.captured_packets:
                writer.writerow([
                    packet.timestamp, packet.source_ip, packet.dest_ip,
                    packet.source_port, packet.dest_port, packet.protocol,
                    packet.length, packet.info
                ])
            
            output.seek(0)
            response = Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment; filename=packet_capture.csv'}
            )
            return response
        
        else:
            return jsonify({'error': 'Unsupported format'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'scapy_available': SCAPY_AVAILABLE,
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("Starting Packet Sniffer Web Interface...")
    print("WARNING: This tool captures network traffic. Use only on networks you own.")
    print("Access the interface at: http://localhost:5000")
    
    if not SCAPY_AVAILABLE:
        print("Error: Scapy is not installed. Install with: pip install scapy")
        sys.exit(1)
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)