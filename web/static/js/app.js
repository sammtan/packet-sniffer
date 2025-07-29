// Packet Sniffer Web Interface JavaScript
class PacketSnifferApp {
    constructor() {
        this.isCapturing = false;
        this.eventSource = null;
        this.packetCount = 0;
        this.packets = [];
        this.currentTab = 'live';
        this.autoScroll = true;
        this.searchQuery = '';
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.loadInterfaces();
        this.setupTabs();
        this.startStatusPolling();
    }
    
    setupEventListeners() {
        // Control buttons
        document.getElementById('start-btn').addEventListener('click', () => this.startCapture());
        document.getElementById('stop-btn').addEventListener('click', () => this.stopCapture());
        document.getElementById('clear-btn').addEventListener('click', () => this.clearPackets());
        
        // Search functionality
        document.getElementById('packet-search').addEventListener('input', (e) => {
            this.searchQuery = e.target.value.toLowerCase();
            this.filterPackets();
        });
        
        // Auto-scroll toggle
        document.getElementById('auto-scroll').addEventListener('change', (e) => {
            this.autoScroll = e.target.checked;
        });
    }
    
    setupTabs() {
        const tabButtons = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');
        
        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const tabName = button.dataset.tab;
                
                // Update active tab button
                tabButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
                
                // Update active tab content
                tabContents.forEach(content => content.classList.remove('active'));
                document.getElementById(`${tabName}-tab`).classList.add('active');
                
                this.currentTab = tabName;
                
                // Load statistics when switching to stats tab
                if (tabName === 'statistics') {
                    this.loadStatistics();
                }
            });
        });
    }
    
    async loadInterfaces() {
        try {
            console.log('Loading interfaces...');
            const response = await fetch('/api/interfaces');
            console.log('Response status:', response.status);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            console.log('Interface data:', data);
            
            if (data.error) {
                this.showError('Failed to load interfaces: ' + data.error);
                return;
            }
            
            const select = document.getElementById('interface-select');
            if (!select) {
                console.error('Interface select element not found!');
                return;
            }
            
            select.innerHTML = '<option value="">Select interface...</option>';
            
            if (data.interfaces && Array.isArray(data.interfaces)) {
                data.interfaces.forEach(iface => {
                    const option = document.createElement('option');
                    option.value = iface.name;
                    // Shorten long interface names for better display
                    const displayName = iface.name.length > 50 ? 
                        iface.name.substring(0, 47) + '...' : iface.name;
                    option.textContent = `${displayName} (${iface.ip})`;
                    select.appendChild(option);
                });
                
                select.disabled = false;
                console.log(`Loaded ${data.interfaces.length} interfaces`);
            } else {
                throw new Error('No interfaces data received');
            }
            
        } catch (error) {
            console.error('Error loading interfaces:', error);
            this.showError('Failed to load interfaces: ' + error.message);
            
            // Set fallback option
            const select = document.getElementById('interface-select');
            if (select) {
                select.innerHTML = '<option value="">Error loading interfaces</option>';
                select.disabled = true;
            }
        }
    }
    
    async startCapture() {
        const interface = document.getElementById('interface-select').value;
        const protocol = document.getElementById('protocol-filter').value;
        const packetLimit = parseInt(document.getElementById('packet-limit').value) || 0;
        
        if (!interface) {
            this.showError('Please select a network interface');
            return;
        }
        
        try {
            this.showLoading(true);
            
            const response = await fetch('/api/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    interface: interface,
                    protocol: protocol,
                    packet_count: packetLimit
                })
            });
            
            const data = await response.json();
            
            if (data.error) {
                this.showError('Failed to start capture: ' + data.error);
                return;
            }
            
            this.isCapturing = true;
            this.updateCaptureStatus('Running');
            this.updateButtons();
            this.startPacketStream();
            this.showSuccess('Packet capture started successfully');
            
        } catch (error) {
            this.showError('Failed to start capture: ' + error.message);
        } finally {
            this.showLoading(false);
        }
    }
    
    async stopCapture() {
        try {
            this.showLoading(true);
            
            const response = await fetch('/api/stop', {
                method: 'POST'
            });
            
            const data = await response.json();
            
            if (data.error) {
                this.showError('Failed to stop capture: ' + data.error);
                return;
            }
            
            this.isCapturing = false;
            this.updateCaptureStatus('Stopped');
            this.updateButtons();
            this.stopPacketStream();
            this.showSuccess(`Capture stopped. Total packets: ${data.total_packets}`);
            
        } catch (error) {
            this.showError('Failed to stop capture: ' + error.message);
        } finally {
            this.showLoading(false);
        }
    }
    
    clearPackets() {
        this.packets = [];
        this.packetCount = 0;
        document.getElementById('packets-list').innerHTML = 
            '<div class="no-packets">No packets captured yet. Start capture to begin monitoring.</div>';
        document.getElementById('packet-count').textContent = '0';
        this.showSuccess('Packet list cleared');
    }
    
    startPacketStream() {
        if (this.eventSource) {
            this.eventSource.close();
        }
        
        this.eventSource = new EventSource('/api/packets/stream');
        
        this.eventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                
                if (data.type === 'heartbeat') {
                    return; // Ignore heartbeat messages
                }
                
                this.addPacket(data);
            } catch (error) {
                console.error('Error parsing packet data:', error);
            }
        };
        
        this.eventSource.onerror = (error) => {
            console.error('EventSource error:', error);
            if (this.isCapturing) {
                // Try to reconnect after a delay
                setTimeout(() => {
                    if (this.isCapturing) {
                        this.startPacketStream();
                    }
                }, 5000);
            }
        };
    }
    
    stopPacketStream() {
        if (this.eventSource) {
            this.eventSource.close();
            this.eventSource = null;
        }
    }
    
    addPacket(packetData) {
        this.packets.unshift(packetData); // Add to beginning for newest first
        this.packetCount++;
        
        // Limit stored packets to prevent memory issues
        if (this.packets.length > 1000) {
            this.packets = this.packets.slice(0, 1000);
        }
        
        this.updatePacketCount();
        
        if (this.currentTab === 'live') {
            this.updatePacketDisplay();
        }
    }
    
    updatePacketDisplay() {
        const container = document.getElementById('packets-list');
        
        // Filter packets based on search query
        const filteredPackets = this.filterPacketsBySearch();
        
        if (filteredPackets.length === 0) {
            container.innerHTML = '<div class="no-packets">No packets match the current filter.</div>';
            return;
        }
        
        // Show only the latest 100 packets for performance
        const displayPackets = filteredPackets.slice(0, 100);
        
        container.innerHTML = displayPackets.map(packet => this.createPacketRow(packet)).join('');
        
        // Auto-scroll to top if enabled
        if (this.autoScroll) {
            container.scrollTop = 0;
        }
    }
    
    createPacketRow(packet) {
        const protocolClass = `protocol-${packet.protocol.toLowerCase()}`;
        const sourcePort = packet.source_port ? `:${packet.source_port}` : '';
        const destPort = packet.dest_port ? `:${packet.dest_port}` : '';
        
        return `
            <div class="packet-row new">
                <div class="packet-column">${packet.timestamp}</div>
                <div class="packet-column">
                    <span class="protocol-badge ${protocolClass}">${packet.protocol}</span>
                </div>
                <div class="packet-column" title="${packet.source_ip}${sourcePort}">
                    ${packet.source_ip}${sourcePort}
                </div>
                <div class="packet-column" title="${packet.dest_ip}${destPort}">
                    ${packet.dest_ip}${destPort}
                </div>
                <div class="packet-column">${packet.length}B</div>
                <div class="packet-column" title="${packet.info}">
                    ${packet.info}
                </div>
            </div>
        `;
    }
    
    filterPacketsBySearch() {
        if (!this.searchQuery) {
            return this.packets;
        }
        
        return this.packets.filter(packet => {
            return packet.source_ip.includes(this.searchQuery) ||
                   packet.dest_ip.includes(this.searchQuery) ||
                   packet.protocol.toLowerCase().includes(this.searchQuery) ||
                   (packet.source_port && packet.source_port.toString().includes(this.searchQuery)) ||
                   (packet.dest_port && packet.dest_port.toString().includes(this.searchQuery)) ||
                   packet.info.toLowerCase().includes(this.searchQuery);
        });
    }
    
    filterPackets() {
        if (this.currentTab === 'live') {
            this.updatePacketDisplay();
        }
    }
    
    async loadStatistics() {
        try {
            const response = await fetch('/api/statistics');
            const stats = await response.json();
            
            if (stats.error) {
                this.showStatsError('No statistics available');
                return;
            }
            
            this.updateStatisticsDisplay(stats);
            
        } catch (error) {
            this.showStatsError('Failed to load statistics');
        }
    }
    
    updateStatisticsDisplay(stats) {
        // Protocol distribution
        this.updateStatSection('protocol-stats', stats.protocols, 'No protocol data');
        
        // Top sources
        this.updateStatSection('source-stats', stats.top_sources, 'No source data');
        
        // Top destinations
        this.updateStatSection('dest-stats', stats.top_destinations, 'No destination data');
        
        // Active ports
        this.updateStatSection('port-stats', stats.active_ports, 'No port data');
    }
    
    updateStatSection(elementId, data, noDataMessage) {
        const element = document.getElementById(elementId);
        
        if (!data || Object.keys(data).length === 0) {
            element.innerHTML = `<div class="no-data">${noDataMessage}</div>`;
            return;
        }
        
        const items = Object.entries(data)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 10)
            .map(([key, value]) => `
                <div class="stat-item">
                    <span class="stat-label">${key}</span>
                    <span class="stat-value">${value}</span>
                </div>
            `).join('');
        
        element.innerHTML = items;
    }
    
    showStatsError(message) {
        ['protocol-stats', 'source-stats', 'dest-stats', 'port-stats'].forEach(id => {
            document.getElementById(id).innerHTML = `<div class="no-data">${message}</div>`;
        });
    }
    
    startStatusPolling() {
        setInterval(async () => {
            try {
                const response = await fetch('/api/status');
                const status = await response.json();
                
                this.updatePacketCount(status.total_packets);
                
                if (status.statistics) {
                    this.updateStatusStats(status.statistics);
                }
                
            } catch (error) {
                console.error('Status polling error:', error);
            }
        }, 2000); // Poll every 2 seconds
    }
    
    updateStatusStats(stats) {
        document.getElementById('packet-rate').textContent = `${stats.packets_per_second || 0}/s`;
        document.getElementById('runtime').textContent = `${stats.runtime_seconds || 0}s`;
    }
    
    updatePacketCount(count = null) {
        if (count !== null) {
            this.packetCount = count;
        }
        document.getElementById('packet-count').textContent = this.packetCount.toString();
    }
    
    updateCaptureStatus(status) {
        const statusElement = document.getElementById('capture-status');
        statusElement.textContent = status;
        statusElement.className = `status-value ${status.toLowerCase()}`;
    }
    
    updateButtons() {
        const startBtn = document.getElementById('start-btn');
        const stopBtn = document.getElementById('stop-btn');
        
        startBtn.disabled = this.isCapturing;
        stopBtn.disabled = !this.isCapturing;
    }
    
    showLoading(show) {
        const overlay = document.getElementById('loading-overlay');
        if (show) {
            overlay.classList.add('show');
        } else {
            overlay.classList.remove('show');
        }
    }
    
    showError(message) {
        this.showNotification(message, 'error');
    }
    
    showSuccess(message) {
        this.showNotification(message, 'success');
    }
    
    showNotification(message, type) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        // Style the notification
        Object.assign(notification.style, {
            position: 'fixed',
            top: '20px',
            right: '20px',
            padding: '12px 20px',
            borderRadius: '8px',
            color: 'white',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: '0.9rem',
            zIndex: '9999',
            maxWidth: '400px',
            wordWrap: 'break-word',
            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
            background: type === 'error' 
                ? 'oklch(0.6 0.2 0)' 
                : 'oklch(0.6 0.2 150)',
            transform: 'translateX(100%)',
            transition: 'transform 0.3s ease'
        });
        
        document.body.appendChild(notification);
        
        // Animate in
        setTimeout(() => {
            notification.style.transform = 'translateX(0)';
        }, 10);
        
        // Remove after delay
        setTimeout(() => {
            notification.style.transform = 'translateX(100%)';
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.parentNode.removeChild(notification);
                }
            }, 300);
        }, 5000);
    }
}

// Export functions
window.exportPackets = async function(format) {
    try {
        const response = await fetch(`/api/export/${format}`);
        
        if (!response.ok) {
            const error = await response.json();
            app.showError(error.error || 'Export failed');
            return;
        }
        
        // Create download link
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `packet_capture.${format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
        app.showSuccess(`Packets exported as ${format.toUpperCase()}`);
        
    } catch (error) {
        app.showError('Export failed: ' + error.message);
    }
};

// Initialize app when DOM is loaded
let app;
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing Packet Sniffer App...');
    app = new PacketSnifferApp();
});

// Fallback initialization if DOMContentLoaded already fired
if (document.readyState === 'loading') {
    // DOM not ready yet
} else {
    // DOM is ready
    console.log('DOM already loaded, initializing Packet Sniffer App...');
    if (!app) {
        app = new PacketSnifferApp();
    }
}