import time
import struct
import socket
import random
import urllib.parse
import os
from datetime import datetime
from mitmproxy import ctx, http, tcp

# Configuration constants
MAX_TCP_SEGMENT_SIZE = 1460
MAX_FILE_SIZE_MB = 1024  # Split PCAP files when they exceed this size, if u want to limit memory usage otherwise defualt is 1GB
MAX_CONNECTIONS = 500   # Limit concurrent connections to prevent memory issues
BUFFER_SIZE = 8192      # Buffer for file writes

class Mitmproxy2Pcap:
    """
    Optimized Mitmproxy addon for TCP and HTTP traffic with automatic file rotation
    and improved performance.
    """
    def __init__(self):
        self.base_filename = "traffic"
        self.file_counter = 1
        self.current_filename = f"{self.base_filename}_{self.file_counter:03d}.pcap"
        self.file = None
        self.file_size = 0
        self.connections = {}
        self.write_buffer = []
        self.last_cleanup = time.time()
        
    def running(self):
        """Initialize the first PCAP file."""
        self._create_new_pcap_file()
        ctx.log.info(f"[Mitmproxy2Pcap] Started. Writing to {self.current_filename}")

    def done(self):
        """Clean up and close all files."""
        self._flush_buffer()
        self._close_all_connections()
        if self.file:
            self.file.close()
            self.file = None
            ctx.log.info(f"[Mitmproxy2Pcap] File {self.current_filename} closed.")

    def request(self, flow: http.HTTPFlow):
        """Handle HTTP requests with optimized processing."""
        if not self._should_capture_http(flow):
            return
            
        conn = self._get_or_create_connection(flow)
        if not conn or not conn.get("open"):
            return
            
        raw_request = self._build_http_request_bytes(flow.request)
        if raw_request:
            self._write_data_packet(conn, is_client=True, payload=raw_request)

    def response(self, flow: http.HTTPFlow):
        """Handle HTTP responses with optimized processing."""
        if not self._should_capture_http(flow):
            return
            
        conn = self._get_or_create_connection(flow)
        if not conn or not conn.get("open"):
            return
            
        raw_response = self._build_http_response_bytes(flow.response)
        if raw_response:
            self._write_data_packet(conn, is_client=False, payload=raw_response)

    def tcp_start(self, flow: tcp.TCPFlow):
        """Initialize TCP connection."""
        self._get_or_create_connection(flow)

    def tcp_message(self, flow: tcp.TCPFlow):
        """Process TCP messages with size limits."""
        conn = self._get_or_create_connection(flow)
        if not conn or not conn.get("open"):
            return
            
        message = flow.messages[-1]
        if message.content and len(message.content) <= MAX_TCP_SEGMENT_SIZE * 2:  # Skip very large payloads
            self._write_data_packet(conn, is_client=message.from_client, payload=message.content)

    def tcp_end(self, flow: tcp.TCPFlow):
        """Handle TCP connection end."""
        key = self._flow_key(flow)
        if key in self.connections:
            conn = self.connections[key]
            if conn.get("open"):
                self._write_fin_packets(conn)
            del self.connections[key]

    def _should_capture_http(self, flow: http.HTTPFlow) -> bool:
        """Determine if HTTP flow should be captured based on filters."""
        # Skip very large requests/responses to save space
        if flow.request.content and len(flow.request.content) > 1024 * 1024:  # 1MB limit
            return False
        if flow.response and flow.response.content and len(flow.response.content) > 1024 * 1024:
            return False
            
        # Skip common static resources unless specifically needed
        path = flow.request.path.lower()
        static_extensions = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2')
        if any(path.endswith(ext) for ext in static_extensions):
            return False
            
        return True

    def _periodic_cleanup(self):
        """Periodic cleanup to prevent memory issues."""
        current_time = time.time()
        if current_time - self.last_cleanup < 300:  # Cleanup every 5 minutes
            return
            
        self.last_cleanup = current_time
        
        # Remove old closed connections
        closed_connections = [k for k, v in self.connections.items() if not v.get("open")]
        for key in closed_connections:
            del self.connections[key]
            
        # Limit total connections
        if len(self.connections) > MAX_CONNECTIONS:
            oldest_keys = list(self.connections.keys())[:len(self.connections) - MAX_CONNECTIONS]
            for key in oldest_keys:
                if key in self.connections:
                    conn = self.connections[key]
                    if conn.get("open"):
                        self._write_fin_packets(conn)
                    del self.connections[key]
        
        # Flush buffer and check file size
        self._flush_buffer()
        self._check_file_rotation()
        
        ctx.log.info(f"[Mitmproxy2Pcap] Cleanup: {len(self.connections)} active connections")

    def _check_file_rotation(self):
        """Check if we need to rotate to a new PCAP file."""
        if self.file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
            ctx.log.info(f"[Mitmproxy2Pcap] Rotating file. Current size: {self.file_size / 1024 / 1024:.1f}MB")
            self._close_all_connections()
            if self.file:
                self.file.close()
            self.file_counter += 1
            self.current_filename = f"{self.base_filename}_{self.file_counter:03d}.pcap"
            self._create_new_pcap_file()

    def _create_new_pcap_file(self):
        """Create a new PCAP file with proper header."""
        self.file = open(self.current_filename, "wb", buffering=BUFFER_SIZE)
        self.file_size = 0
        pcap_global_header = struct.pack(
            "<IHHIIII",
            0xa1b2c3d4,  # Magic number
            2,           # Major version
            4,           # Minor version
            0,           # Time zone
            0,           # Accuracy of timestamps
            65535,       # Snapshot length
            1            # Linktype (Ethernet)
        )
        self.file.write(pcap_global_header)
        self.file_size += len(pcap_global_header)
        self.file.flush()

    def _flow_key(self, flow):
        """Generate unique key for flow."""
        c_ip, c_port = flow.client_conn.address
        s_ip, s_port = flow.server_conn.address
        return (c_ip, c_port, s_ip, s_port)

    def _get_or_create_connection(self, flow):
        """Get existing connection or create new one with validation."""
        self._periodic_cleanup()
        
        key = self._flow_key(flow)
        if key in self.connections:
            return self.connections[key]
            
        c_ip, c_port, s_ip, s_port = key
        
        # Validate IPv4 addresses
        try:
            socket.inet_pton(socket.AF_INET, c_ip)
            socket.inet_pton(socket.AF_INET, s_ip)
        except OSError:
            return None
            
        # Check connection limits
        if len(self.connections) >= MAX_CONNECTIONS:
            return None
            
        # Create new connection
        client_seq = random.randint(1000, 50000)
        server_seq = random.randint(50001, 100000)
        
        conn = {
            "client_ip": c_ip,
            "client_port": c_port,
            "server_ip": s_ip,
            "server_port": s_port,
            "client_seq": client_seq,
            "server_seq": server_seq,
            "open": True
        }
        
        self.connections[key] = conn
        
        # Write TCP handshake
        self._write_tcp_handshake(conn)
        
        return conn

    def _write_tcp_handshake(self, conn):
        """Write TCP 3-way handshake packets."""
        # SYN
        self._write_tcp_packet(conn, is_client=True, flags=0x02, payload=b"")
        conn["client_seq"] += 1
        
        # SYN-ACK
        self._write_tcp_packet(conn, is_client=False, flags=0x12, 
                              ack_num=conn["client_seq"], payload=b"")
        conn["server_seq"] += 1
        
        # ACK
        self._write_tcp_packet(conn, is_client=True, flags=0x10,
                              ack_num=conn["server_seq"], payload=b"")

    def _write_fin_packets(self, conn):
        """Write FIN packets to close connection."""
        if not conn.get("open"):
            return
        conn["open"] = False
        
        # FIN from client
        self._write_tcp_packet(conn, is_client=True, flags=0x11,
                              ack_num=conn["server_seq"], payload=b"")
        
        # FIN from server
        self._write_tcp_packet(conn, is_client=False, flags=0x11,
                              ack_num=conn["client_seq"], payload=b"")

    def _close_all_connections(self):
        """Close all open connections."""
        for conn in list(self.connections.values()):
            if conn.get("open"):
                self._write_fin_packets(conn)
        self.connections.clear()

    def _write_data_packet(self, conn, is_client, payload):
        """Write data packet with segmentation if needed."""
        if not conn.get("open") or not payload:
            return
            
        # Split large payloads into segments
        offset = 0
        while offset < len(payload):
            chunk = payload[offset:offset + MAX_TCP_SEGMENT_SIZE]
            offset += len(chunk)
            
            self._write_tcp_packet(conn, is_client=is_client, flags=0x18, payload=chunk)
            
            # Update sequence numbers
            if is_client:
                conn["client_seq"] += len(chunk)
            else:
                conn["server_seq"] += len(chunk)

    def _write_tcp_packet(self, conn, is_client, flags, payload=b"", ack_num=None):
        """Write a TCP packet to the buffer."""
        if is_client:
            seq = conn["client_seq"]
            if ack_num is None:
                ack_num = conn["server_seq"]
            src_ip, src_port = conn["client_ip"], conn["client_port"]
            dst_ip, dst_port = conn["server_ip"], conn["server_port"]
        else:
            seq = conn["server_seq"]
            if ack_num is None:
                ack_num = conn["client_seq"]
            src_ip, src_port = conn["server_ip"], conn["server_port"]
            dst_ip, dst_port = conn["client_ip"], conn["client_port"]

        packet = self._build_packet(src_ip, dst_ip, src_port, dst_port,
                                  seq, ack_num, flags, payload)
        self._buffer_packet(packet)

    def _build_packet(self, src_ip, dst_ip, src_port, dst_port, seq_num, ack_num, flags, payload):
        """Build complete Ethernet/IP/TCP packet."""
        # Ethernet header (14 bytes)
        eth_header = (
            b"\x00\x00\x00\x00\x00\x00"  # Dst MAC
            b"\x11\x11\x11\x11\x11\x11"  # Src MAC  
            b"\x08\x00"                  # EtherType IPv4
        )
        
        # IP header (20 bytes)
        ip_len = 20 + 20 + len(payload)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, ip_len, 0, 0, 64, 6, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
        )
        
        # TCP header (20 bytes)
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            src_port, dst_port, seq_num, ack_num,
            0x50, flags, 8192, 0, 0
        )
        
        return eth_header + ip_header + tcp_header + payload

    def _buffer_packet(self, packet):
        """Add packet to write buffer."""
        self.write_buffer.append(packet)
        if len(self.write_buffer) >= 50:  # Flush buffer every 50 packets
            self._flush_buffer()

    def _flush_buffer(self):
        """Flush write buffer to file."""
        if not self.file or not self.write_buffer:
            return
            
        for packet in self.write_buffer:
            record = self._create_pcap_record(packet)
            self.file.write(record)
            self.file_size += len(record)
            
        self.file.flush()
        self.write_buffer.clear()

    def _create_pcap_record(self, packet_bytes):
        """Create PCAP record with timestamp."""
        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1e6)
        header = struct.pack("<IIII", sec, usec, len(packet_bytes), len(packet_bytes))
        return header + packet_bytes

    def _build_http_request_bytes(self, req):
        """Build HTTP request bytes with minimal processing."""
        if not req:
            return b""
            
        lines = [f"{req.method} {req.path} HTTP/1.1"]
        
        # Only include essential headers
        essential_headers = ['host', 'content-type', 'content-length', 'authorization']
        for name, value in req.headers.items():
            if name.lower() in essential_headers:
                lines.append(f"{name}: {value}")
                
        lines.append("")
        header = "\r\n".join(lines) + "\r\n"
        
        # Limit content size
        content = req.content[:4096] if req.content else b""
        
        return header.encode("utf-8", errors="replace") + content

    def _build_http_response_bytes(self, resp):
        """Build HTTP response bytes with minimal processing."""
        if not resp:
            return b""
            
        lines = [f"HTTP/1.1 {resp.status_code} {resp.reason}"]
        
        # Only include essential headers
        essential_headers = ['content-type', 'content-length', 'set-cookie']
        for name, value in resp.headers.items():
            if name.lower() in essential_headers:
                lines.append(f"{name}: {value}")
                
        lines.append("")
        header = "\r\n".join(lines) + "\r\n"
        
        # Limit content size
        content = resp.content[:4096] if resp.content else b""
        
        return header.encode("utf-8", errors="replace") + content

addons = [Mitmproxy2Pcap()]