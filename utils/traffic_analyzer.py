#!/usr/bin/env python3
"""
Dynamic/Static Traffic Analysis Module
Used to analyze DLP (Data Loss Prevention) and L7 (Application Layer) protocol statistics
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, get_if_list
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    # If HTTP layer unavailable, use fallback
    HTTPRequest = None
    HTTPResponse = None
import threading
import time
import re
import json
from collections import defaultdict
from datetime import datetime

# Import ML analyzer
try:
    from utils.ml_analyzer import MLAnalyzer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[!] Warning: ML analyzer not available")

class TrafficAnalyzer:
    def __init__(self, enable_ml=True):
        """Initialize traffic analyzer"""
        self.analyzing = False
        self.analysis_thread = None
        self.interface = None
        
        # ML/DL Analyzer
        self.enable_ml = enable_ml and ML_AVAILABLE
        self.ml_analyzer = MLAnalyzer() if self.enable_ml else None
        
        # Flow tracking for ML features
        self.flows = defaultdict(lambda: {
            'packets': [],
            'bytes_sent': 0,
            'bytes_received': 0,
            'start_time': None,
            'last_packet_time': None
        })
        self.last_packet_time = None
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'start_time': None,
            'end_time': None,
            'l7_protocols': defaultdict(int),  # L7 protocol statistics
            'dlp_events': [],  # DLP events
            'top_talkers': defaultdict(int),  # Top traffic hosts
            'protocol_distribution': defaultdict(int),  # Protocol distribution
            'port_statistics': defaultdict(int),  # Port statistics
            'http_requests': [],  # HTTP requests
            'dns_queries': [],  # DNS queries
            'suspicious_activities': []  # Suspicious activities
        }
        
        # DLP sensitive data patterns
        self.dlp_patterns = {
            'credit_card': [
                r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card number
                r'\b\d{13,19}\b'  # Long numeric sequence
            ],
            'email': [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'  # Email address
            ],
            'ssn': [
                r'\b\d{3}-\d{2}-\d{4}\b',  # US SSN format
                r'\b\d{9}\b'  # 9-digit number
            ],
            'password': [
                r'(?:password|passwd|pwd)\s*[:=]\s*([^\s&<>"\']+)',  # Password field
                r'(?:password|passwd|pwd)\s*[:=]\s*([A-Za-z0-9!@#$%^&*()_+-=]+)'
            ],
            'api_key': [
                r'(?:api[_-]?key|apikey)\s*[:=]\s*([A-Za-z0-9_-]{20,})',  # API key
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key
                r'sk-[A-Za-z0-9]{32,}'  # OpenAI API Key format
            ],
            'ip_address': [
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # IP address
            ],
            'file_transfer': [
                r'(?:\.pdf|\.doc|\.docx|\.xls|\.xlsx|\.ppt|\.pptx|\.zip|\.rar|\.7z)',  # File extension
                r'(?:Content-Type:\s*(?:application|image|video|audio))'  # File type
            ]
        }
        
        # L7 protocol port mapping
        self.l7_ports = {
            80: 'HTTP',
            443: 'HTTPS',
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            110: 'POP3',
            143: 'IMAP',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            3389: 'RDP',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB',
            6379: 'Redis'
        }
    
    def _detect_dlp_patterns(self, data, src_ip, dst_ip, protocol=''):
        """Detect DLP sensitive data patterns"""
        detected = []
        data_str = data.decode('utf-8', errors='ignore') if isinstance(data, bytes) else str(data)
        
        for pattern_type, patterns in self.dlp_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, data_str, re.IGNORECASE)
                for match in matches:
                    # Avoid false positives (filter common false positives)
                    matched_text = match.group(0)
                    if self._is_false_positive(matched_text, pattern_type):
                        continue
                    
                    detected.append({
                        'type': pattern_type,
                        'pattern': pattern,
                        'matched_text': matched_text[:100],  # Limit length
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': protocol,
                        'timestamp': time.time()
                    })
        
        return detected
    
    def _is_false_positive(self, text, pattern_type):
        """Check if it's a false positive"""
        # Filter obvious false positives
        false_positives = {
            'ip_address': ['0.0.0.0', '127.0.0.1', '255.255.255.255'],
            'credit_card': ['0000-0000-0000-0000']
        }
        
        if pattern_type in false_positives:
            return text in false_positives[pattern_type]
        
        return False
    
    def _identify_l7_protocol(self, packet):
        """Identify L7 application layer protocol"""
        protocol = 'Unknown'
        
        if HTTPRequest and HTTPResponse:
            if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                protocol = 'HTTP'
        elif packet.haslayer(DNS):
            protocol = 'DNS'
        elif packet.haslayer(TCP):
            port = packet[TCP].dport or packet[TCP].sport
            if port in self.l7_ports:
                protocol = self.l7_ports[port]
            elif port == 443:
                protocol = 'HTTPS'
        elif packet.haslayer(UDP):
            port = packet[UDP].dport or packet[UDP].sport
            if port in self.l7_ports:
                protocol = self.l7_ports[port]
        
        return protocol
    
    def _extract_http_info(self, packet):
        """Extract HTTP request information"""
        http_info = None
        
        if not HTTPRequest or not HTTPResponse:
            # If HTTP layer unavailable, try parsing from Raw layer
            pass
        elif packet.haslayer(HTTPRequest):
            http_req = packet[HTTPRequest]
            http_info = {
                'method': http_req.Method.decode('utf-8', errors='ignore') if http_req.Method else 'Unknown',
                'host': http_req.Host.decode('utf-8', errors='ignore') if http_req.Host else 'Unknown',
                'path': http_req.Path.decode('utf-8', errors='ignore') if http_req.Path else 'Unknown',
                'src_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'Unknown',
                'timestamp': packet.time
            }
        elif packet.haslayer(HTTPResponse):
            http_resp = packet[HTTPResponse]
            http_info = {
                'method': 'RESPONSE',
                'status_code': http_resp.Status_Code.decode('utf-8', errors='ignore') if http_resp.Status_Code else 'Unknown',
                'src_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'Unknown',
                'timestamp': packet.time
            }
        elif packet.haslayer(Raw) and packet.haslayer(TCP):
            # Try parsing HTTP from Raw layer
            try:
                raw_data = packet[Raw].load
                if b'HTTP/' in raw_data or b'GET' in raw_data or b'POST' in raw_data:
                    http_str = raw_data.decode('utf-8', errors='ignore')
                    if 'GET' in http_str or 'POST' in http_str or 'PUT' in http_str or 'DELETE' in http_str:
                        lines = http_str.split('\r\n')
                        if lines:
                            first_line = lines[0]
                            parts = first_line.split()
                            if len(parts) >= 2:
                                method = parts[0]
                                path = parts[1]
                                host = None
                                for line in lines:
                                    if line.lower().startswith('host:'):
                                        host = line.split(':', 1)[1].strip()
                                        break
                                
                                http_info = {
                                    'method': method,
                                    'host': host or 'Unknown',
                                    'path': path,
                                    'src_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                                    'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'Unknown',
                                    'timestamp': packet.time
                                }
            except:
                pass
        
        return http_info
    
    def _extract_dns_info(self, packet):
        """Extract DNS query information"""
        dns_info = None
        
        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 0:  # DNS query
                query_name = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.') if dns.qd else 'Unknown'
                dns_info = {
                    'query': query_name,
                    'type': dns.qd.qtype if dns.qd else 0,
                    'src_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                    'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'Unknown',
                    'timestamp': packet.time
                }
            elif dns.qr == 1:  # DNS response
                query_name = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.') if dns.qd else 'Unknown'
                answers = []
                if dns.an:
                    if isinstance(dns.an, list):
                        for answer in dns.an:
                            if hasattr(answer, 'rdata'):
                                answers.append(str(answer.rdata))
                    else:
                        if hasattr(dns.an, 'rdata'):
                            answers.append(str(dns.an.rdata))
                
                dns_info = {
                    'query': query_name,
                    'answers': answers,
                    'src_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                    'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'Unknown',
                    'timestamp': packet.time
                }
        
        return dns_info
    
    def _process_packet(self, packet):
        """Process single packet"""
        if not self.analyzing:
            return
        
        try:
            # Update basic statistics
            self.stats['total_packets'] += 1
            if packet.haslayer(IP):
                self.stats['total_bytes'] += len(packet)
            
            # Identify L7 protocol
            l7_protocol = self._identify_l7_protocol(packet)
            self.stats['l7_protocols'][l7_protocol] += 1
            
            # Protocol distribution statistics
            if packet.haslayer(IP):
                proto = packet[IP].proto
                if proto == 6:
                    self.stats['protocol_distribution']['TCP'] += 1
                elif proto == 17:
                    self.stats['protocol_distribution']['UDP'] += 1
                elif proto == 1:
                    self.stats['protocol_distribution']['ICMP'] += 1
                else:
                    self.stats['protocol_distribution'][f'Other-{proto}'] += 1
                
                # Top Talkers statistics
                self.stats['top_talkers'][packet[IP].src] += len(packet)
                self.stats['top_talkers'][packet[IP].dst] += len(packet)
            
            # Port statistics
            if packet.haslayer(TCP):
                self.stats['port_statistics'][packet[TCP].dport] += 1
                self.stats['port_statistics'][packet[TCP].sport] += 1
            elif packet.haslayer(UDP):
                self.stats['port_statistics'][packet[UDP].dport] += 1
                self.stats['port_statistics'][packet[UDP].sport] += 1
            
            # Extract HTTP information
            http_info = self._extract_http_info(packet)
            if http_info:
                self.stats['http_requests'].append(http_info)
                # Limit HTTP request list size
                if len(self.stats['http_requests']) > 1000:
                    self.stats['http_requests'] = self.stats['http_requests'][-1000:]
            
            # Extract DNS information
            dns_info = self._extract_dns_info(packet)
            if dns_info:
                self.stats['dns_queries'].append(dns_info)
                # Limit DNS query list size
                if len(self.stats['dns_queries']) > 1000:
                    self.stats['dns_queries'] = self.stats['dns_queries'][-1000:]
            
            # DLP detection
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                src_ip = packet[IP].src if packet.haslayer(IP) else 'Unknown'
                dst_ip = packet[IP].dst if packet.haslayer(IP) else 'Unknown'
                
                dlp_events = self._detect_dlp_patterns(raw_data, src_ip, dst_ip, l7_protocol)
                if dlp_events:
                    self.stats['dlp_events'].extend(dlp_events)
                    # Limit DLP event list size
                    if len(self.stats['dlp_events']) > 500:
                        self.stats['dlp_events'] = self.stats['dlp_events'][-500:]
            
            # Detect suspicious activities
            self._detect_suspicious_activity(packet)
            
            # ML/DL Analysis
            if self.enable_ml and self.ml_analyzer:
                packet_info = self._prepare_packet_info_for_ml(packet, l7_protocol)
                self.ml_analyzer.analyze_packet(packet_info)
            
        except Exception as e:
            # Silently handle errors to avoid affecting capture
            pass
    
    def _detect_suspicious_activity(self, packet):
        """Detect suspicious activities"""
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Detect large number of connection attempts
        if packet.haslayer(TCP):
            if packet[TCP].flags == 2:  # SYN packet
                # Can add more detection logic
                pass
        
        # Detect abnormal port scanning
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            # Can add port scanning detection logic
            pass
    
    def _prepare_packet_info_for_ml(self, packet, l7_protocol):
        """Prepare packet information for ML analysis"""
        packet_info = {
            'packet_size': len(packet),
            'protocol': packet[IP].proto if packet.haslayer(IP) else 0,
            'is_http': l7_protocol == 'HTTP',
            'is_https': l7_protocol == 'HTTPS',
            'is_dns': l7_protocol == 'DNS',
            'is_ftp': l7_protocol == 'FTP',
            'time_delta': 0,
            'packet_rate': 0,
            'flow_duration': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0,
            'mean_packet_size': 0,
            'std_packet_size': 0,
            'mean_inter_arrival_time': 0,
            'is_well_known_port': False,
            'is_ephemeral_port': False
        }
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Port information
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                packet_info['src_port'] = src_port
                packet_info['dst_port'] = dst_port
                packet_info['is_well_known_port'] = dst_port < 1024
                packet_info['is_ephemeral_port'] = 49152 <= src_port <= 65535
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                packet_info['src_port'] = src_port
                packet_info['dst_port'] = dst_port
                packet_info['is_well_known_port'] = dst_port < 1024
                packet_info['is_ephemeral_port'] = 49152 <= src_port <= 65535
            
            # Flow tracking
            flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            flow = self.flows[flow_key]
            
            current_time = time.time()
            if flow['start_time'] is None:
                flow['start_time'] = current_time
                flow['last_packet_time'] = current_time
            
            packet_info['time_delta'] = current_time - (flow['last_packet_time'] or current_time)
            flow['last_packet_time'] = current_time
            packet_info['flow_duration'] = current_time - flow['start_time']
            
            # Update flow statistics
            flow['packets'].append(len(packet))
            if len(flow['packets']) > 100:
                flow['packets'].pop(0)
            
            if src_ip == flow_key.split(':')[0]:
                flow['bytes_sent'] += len(packet)
                flow['packets_sent'] += 1
            else:
                flow['bytes_received'] += len(packet)
                flow['packets_received'] += 1
            
            packet_info['bytes_sent'] = flow['bytes_sent']
            packet_info['bytes_received'] = flow['bytes_received']
            packet_info['packets_sent'] = flow['packets_sent']
            packet_info['packets_received'] = flow['packets_received']
            
            # Statistical features
            if len(flow['packets']) > 0:
                packet_info['mean_packet_size'] = sum(flow['packets']) / len(flow['packets'])
                if len(flow['packets']) > 1:
                    mean = packet_info['mean_packet_size']
                    variance = sum((x - mean) ** 2 for x in flow['packets']) / len(flow['packets'])
                    packet_info['std_packet_size'] = variance ** 0.5
            
            # Packet rate calculation
            if self.last_packet_time:
                time_diff = current_time - self.last_packet_time
                if time_diff > 0:
                    packet_info['packet_rate'] = 1.0 / time_diff
            
            self.last_packet_time = current_time
        
        return packet_info
    
    def _capture_packets(self, interface=None, filter_str=""):
        """Capture packets"""
        try:
            if interface:
                sniff(iface=interface, prn=self._process_packet, 
                      filter=filter_str, stop_filter=lambda x: not self.analyzing, store=False)
            else:
                sniff(prn=self._process_packet, 
                      filter=filter_str, stop_filter=lambda x: not self.analyzing, store=False)
        except PermissionError:
            print("[!] Permission error: Root privileges required to capture network traffic")
            self.analyzing = False
        except Exception as e:
            print(f"[!] Error capturing packets: {e}")
            self.analyzing = False
    
    def start_analysis(self, interface=None, filter_str=""):
        """Start dynamic analysis"""
        if self.analyzing:
            return False
        
        self.analyzing = True
        self.stats['start_time'] = time.time()
        self.stats['total_packets'] = 0
        self.stats['total_bytes'] = 0
        self.stats['l7_protocols'].clear()
        self.stats['dlp_events'].clear()
        self.stats['top_talkers'].clear()
        self.stats['protocol_distribution'].clear()
        self.stats['port_statistics'].clear()
        self.stats['http_requests'].clear()
        self.stats['dns_queries'].clear()
        self.stats['suspicious_activities'].clear()
        
        # Start ML analysis if enabled
        if self.enable_ml and self.ml_analyzer:
            self.ml_analyzer.start_analysis()
        
        self.interface = interface
        self.analysis_thread = threading.Thread(
            target=self._capture_packets,
            args=(interface, filter_str),
            daemon=True
        )
        self.analysis_thread.start()
        
        print(f"[+] Traffic analysis started")
        if self.enable_ml and self.ml_analyzer:
            print(f"[*] ML/DL analysis enabled")
        if interface:
            print(f"[*] Using network interface: {interface}")
        if filter_str:
            print(f"[*] Filter: {filter_str}")
        
        return True
    
    def stop_analysis(self):
        """Stop analysis"""
        if not self.analyzing:
            return False
        
        self.analyzing = False
        self.stats['end_time'] = time.time()
        
        # Stop ML analysis if enabled
        if self.enable_ml and self.ml_analyzer:
            self.ml_analyzer.stop_analysis()
        
        if self.analysis_thread:
            self.analysis_thread.join(timeout=2)
        
        print("[+] Traffic analysis stopped")
        return True
    
    def get_statistics(self):
        """Get statistics"""
        stats = dict(self.stats)
        
        # Calculate runtime
        if stats['start_time']:
            end_time = stats['end_time'] or time.time()
            stats['duration'] = end_time - stats['start_time']
        else:
            stats['duration'] = 0
        
        # Calculate traffic rate
        if stats['duration'] > 0:
            stats['packets_per_second'] = stats['total_packets'] / stats['duration']
            stats['bytes_per_second'] = stats['total_bytes'] / stats['duration']
        else:
            stats['packets_per_second'] = 0
            stats['bytes_per_second'] = 0
        
        # Convert to regular dict (remove defaultdict)
        stats['l7_protocols'] = dict(stats['l7_protocols'])
        stats['top_talkers'] = dict(sorted(stats['top_talkers'].items(), 
                                          key=lambda x: x[1], reverse=True)[:10])
        stats['protocol_distribution'] = dict(stats['protocol_distribution'])
        stats['port_statistics'] = dict(sorted(stats['port_statistics'].items(), 
                                               key=lambda x: x[1], reverse=True)[:20])
        
        # Add ML statistics if available
        if self.enable_ml and self.ml_analyzer:
            ml_stats = self.ml_analyzer.get_statistics()
            stats['ml_analysis'] = ml_stats
        
        return stats
    
    def analyze_static_packets(self, packets):
        """Statically analyze captured packets"""
        print(f"[*] Starting static analysis of {len(packets)} packets...")
        
        # Reset statistics
        self.stats['total_packets'] = 0
        self.stats['total_bytes'] = 0
        self.stats['start_time'] = time.time()
        self.stats['l7_protocols'].clear()
        self.stats['dlp_events'].clear()
        self.stats['top_talkers'].clear()
        self.stats['protocol_distribution'].clear()
        self.stats['port_statistics'].clear()
        self.stats['http_requests'].clear()
        self.stats['dns_queries'].clear()
        
        # Process each packet
        for packet in packets:
            self._process_packet(packet)
        
        self.stats['end_time'] = time.time()
        print(f"[+] Static analysis completed")
        
        return self.get_statistics()
    
    def export_statistics(self, filename):
        """Export statistics to JSON file"""
        stats = self.get_statistics()
        
        # Convert timestamps to readable format
        export_stats = stats.copy()
        if export_stats['start_time']:
            export_stats['start_time'] = datetime.fromtimestamp(export_stats['start_time']).isoformat()
        if export_stats['end_time']:
            export_stats['end_time'] = datetime.fromtimestamp(export_stats['end_time']).isoformat()
        
        # Convert packet timestamps
        for http_req in export_stats['http_requests']:
            if 'timestamp' in http_req:
                http_req['timestamp'] = datetime.fromtimestamp(http_req['timestamp']).isoformat()
        
        for dns_query in export_stats['dns_queries']:
            if 'timestamp' in dns_query:
                dns_query['timestamp'] = datetime.fromtimestamp(dns_query['timestamp']).isoformat()
        
        for dlp_event in export_stats['dlp_events']:
            if 'timestamp' in dlp_event:
                dlp_event['timestamp'] = datetime.fromtimestamp(dlp_event['timestamp']).isoformat()
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_stats, f, indent=2, ensure_ascii=False)
        
        print(f"[+] Statistics exported to: {filename}")

