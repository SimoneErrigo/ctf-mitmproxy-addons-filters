import time
import struct
import socket
import random
import urllib.parse
import re
from mitmproxy import ctx, http, tcp

MAX_TCP_SEGMENT_SIZE = 1460

def extract_grpc_values(payload: bytes) -> bytes:
    """
    Extracts and concatenates payloads from gRPC frames.
    Each frame consists of:
      - 1 byte: compression flag (ignored)
      - 4 bytes: frame length (big-endian)
      - 'length' bytes: payload
    """
    result = b""
    offset = 0
    while offset + 5 <= len(payload):
        # Ignore the compression flag
        length = int.from_bytes(payload[offset + 1:offset + 5], byteorder="big")
        if offset + 5 + length > len(payload):
            break  # Incomplete frame
        result += payload[offset + 5:offset + 5 + length]
        offset += 5 + length
    return result

def format_grpc_message(payload: bytes) -> str:
    # If the payload follows gRPC framing (1 byte flag + 4 bytes length)
    if len(payload) >= 5 and payload[0] in (0, 1):
        messages = []
        offset = 0
        while offset + 5 <= len(payload):
            length = int.from_bytes(payload[offset+1:offset+5], byteorder="big")
            if offset + 5 + length > len(payload):
                break  # Incomplete frame
            messages.append(payload[offset+5:offset+5+length])
            offset += 5 + length

        output_lines = ["[message]    2"]
        string_index = 1
        for msg in messages:
            try:
                msg_text = msg.decode("utf-8", errors="ignore")
            except Exception:
                msg_text = str(msg)
            msg_text = msg_text.strip()
            # Split text using control characters (ASCII 0-31)
            parts = re.split(r'[\x00-\x1F]+', msg_text)
            for part in parts:
                part = part.strip().rstrip('"+*')
                if not part:
                    continue
                if len(part) == 1 and not re.search(r'[A-Za-z]', part):
                    continue
                # Remove leading '$' if the rest is a valid UUID
                if part.startswith("$"):
                    candidate = part[1:]
                    if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", candidate):
                        part = candidate
                output_lines.append(f"[string]     2.{string_index}  {part}")
                string_index += 1
        return "\n".join(output_lines)
    else:
        # Fallback: treat entire payload as a raw message
        try:
            msg_text = payload.decode("utf-8", errors="ignore")
        except Exception:
            msg_text = str(payload)
        msg_text = msg_text.strip()
        parts = re.split(r'[\x00-\x1F]+', msg_text)
        output_lines = ["[message]    2"]
        string_index = 1
        for part in parts:
            part = part.strip().rstrip('"+*')
            if not part:
                continue
            if len(part) == 1 and not re.search(r'[A-Za-z]', part):
                continue
            if part.startswith("$"):
                candidate = part[1:]
                if re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", candidate):
                    part = candidate
            output_lines.append(f"[string]     2.{string_index}  {part}")
            string_index += 1
        return "\n".join(output_lines)


class Mitmproxy2Pcap:
    """
    Unified Mitmproxy addon for TCP, HTTP, and gRPC traffic.
    """
    def __init__(self):
        self.filename = "traffic.pcap"
        self.file = None
        # Connections are stored with key (client_ip, client_port, server_ip, server_port)
        self.connections = {}

    def running(self):
        """Initializes the PCAP file by writing the global header."""
        self.file = open(self.filename, "wb")
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
        self.file.flush()
        ctx.log.info(f"[Mitmproxy2Pcap] Started. Writing to {self.filename}")

    def done(self):
        """Sends FIN packets for all open connections and closes the PCAP file."""
        for conn in self.connections.values():
            if conn.get("open"):
                self._write_fin_packets(conn)
        if self.file:
            self.file.close()
            self.file = None
            ctx.log.info(f"[Mitmproxy2Pcap] File {self.filename} closed.")

    def request(self, flow: http.HTTPFlow):
        """Handles HTTP requests. Applies formatted parsing for gRPC content."""
        conn = self._get_or_create_connection(flow)
        if not conn.get("open"):
            return
        raw_request = self._build_http_request_bytes(flow.request)
        if raw_request:
            self._write_pcap_data_packet(conn, is_client=True, payload=raw_request)

    def response(self, flow: http.HTTPFlow):
        """Handles HTTP responses. Applies formatted parsing for gRPC content."""
        conn = self._get_or_create_connection(flow)
        if not conn.get("open"):
            return
        raw_response = self._build_http_response_bytes(flow.response)
        if raw_response:
            self._write_pcap_data_packet(conn, is_client=False, payload=raw_response)

    def tcp_start(self, flow: tcp.TCPFlow):
        """Initiates a new TCP connection."""
        self._get_or_create_connection(flow)

    def tcp_message(self, flow: tcp.TCPFlow):
        """Processes TCP data chunks."""
        conn = self._get_or_create_connection(flow)
        if not conn.get("open"):
            return
        message = flow.messages[-1]
        if message.content:
            self._write_pcap_data_packet(conn, is_client=message.from_client, payload=message.content)

    def tcp_end(self, flow: tcp.TCPFlow):
        """Sends FIN packets when the TCP connection ends."""
        key = self._flow_key(flow)
        if key in self.connections:
            conn = self.connections[key]
            if conn.get("open"):
                self._write_fin_packets(conn)

    def _flow_key(self, flow):
        c_ip, c_port = flow.client_conn.address
        s_ip, s_port = flow.server_conn.address
        return (c_ip, c_port, s_ip, s_port)

    def _get_or_create_connection(self, flow):
        key = self._flow_key(flow)
        if key in self.connections:
            conn = self.connections[key]
            if conn.get("open"):
                return conn
            else:
                del self.connections[key]
        c_ip, c_port, s_ip, s_port = key
        try:
            socket.inet_pton(socket.AF_INET, c_ip)
            socket.inet_pton(socket.AF_INET, s_ip)
        except OSError:
            ctx.log.warn(f"[Mitmproxy2Pcap] Connection {c_ip}:{c_port} -> {s_ip}:{s_port} is not IPv4. Skipping PCAP.")
            new_conn = {"open": False}
            self.connections[key] = new_conn
            return new_conn
        client_seq_init = random.randint(1, 50000)
        server_seq_init = random.randint(50001, 100000)
        new_conn = {
            "client_ip": c_ip,
            "client_port": c_port,
            "server_ip": s_ip,
            "server_port": s_port,
            "client_seq": client_seq_init,
            "server_seq": server_seq_init,
            "open": True
        }
        self.connections[key] = new_conn
        # Simulate the 3-way handshake: SYN, SYN/ACK, ACK
        self._write_syn_packet(new_conn, is_client=True)
        self._write_syn_ack_packet(new_conn)
        self._write_ack_after_syn(new_conn, is_client=True)
        return new_conn

    def _write_fin_packets(self, conn):
        if not conn.get("open"):
            return
        conn["open"] = False
        self._write_fin(conn, is_client=True)
        self._write_fin(conn, is_client=False)

    def _write_syn_packet(self, conn, is_client=True):
        if not conn.get("open"):
            return
        if is_client:
            seq = conn["client_seq"]
            src_ip, src_port = conn["client_ip"], conn["client_port"]
            dst_ip, dst_port = conn["server_ip"], conn["server_port"]
            conn["client_seq"] += 1
        else:
            seq = conn["server_seq"]
            src_ip, src_port = conn["server_ip"], conn["server_port"]
            dst_ip, dst_port = conn["client_ip"], conn["client_port"]
            conn["server_seq"] += 1
        flags = 0x02  # SYN flag
        pkt = self._build_packet_ether_ip_tcp(
            src_ip, dst_ip, src_port, dst_port,
            seq_num=seq, ack_num=0, flags=flags, payload=b""
        )
        self._write_pcap_record(pkt)

    def _write_syn_ack_packet(self, conn):
        if not conn.get("open"):
            return
        seq = conn["server_seq"]
        conn["server_seq"] += 1
        ack = conn["client_seq"]
        src_ip, src_port = conn["server_ip"], conn["server_port"]
        dst_ip, dst_port = conn["client_ip"], conn["client_port"]
        flags = 0x12  # SYN + ACK flags
        pkt = self._build_packet_ether_ip_tcp(
            src_ip, dst_ip, src_port, dst_port,
            seq_num=seq, ack_num=ack, flags=flags, payload=b""
        )
        self._write_pcap_record(pkt)

    def _write_ack_after_syn(self, conn, is_client=True):
        if not conn.get("open"):
            return
        if is_client:
            seq = conn["client_seq"]
            ack = conn["server_seq"]
            src_ip, src_port = conn["client_ip"], conn["client_port"]
            dst_ip, dst_port = conn["server_ip"], conn["server_port"]
        else:
            seq = conn["server_seq"]
            ack = conn["client_seq"]
            src_ip, src_port = conn["server_ip"], conn["server_port"]
            dst_ip, dst_port = conn["client_ip"], conn["client_port"]
        flags = 0x10  # ACK flag
        pkt = self._build_packet_ether_ip_tcp(
            src_ip, dst_ip, src_port, dst_port,
            seq_num=seq, ack_num=ack, flags=flags, payload=b""
        )
        self._write_pcap_record(pkt)

    def _write_fin(self, conn, is_client=True):
        if is_client:
            seq = conn["client_seq"]
            ack = conn["server_seq"]
            src_ip, src_port = conn["client_ip"], conn["client_port"]
            dst_ip, dst_port = conn["server_ip"], conn["server_port"]
            conn["client_seq"] += 1
        else:
            seq = conn["server_seq"]
            ack = conn["client_seq"]
            src_ip, src_port = conn["server_ip"], conn["server_port"]
            dst_ip, dst_port = conn["client_ip"], conn["client_port"]
            conn["server_seq"] += 1
        flags = 0x11  # FIN + ACK flags
        pkt = self._build_packet_ether_ip_tcp(
            src_ip, dst_ip, src_port, dst_port,
            seq_num=seq, ack_num=ack, flags=flags, payload=b""
        )
        self._write_pcap_record(pkt)

    def _write_pcap_data_packet(self, conn, is_client, payload):
        """
        Splits the payload into segments (if needed) and writes them to the PCAP file.
        """
        if not conn.get("open"):
            return
        offset = 0
        while offset < len(payload):
            chunk = payload[offset:offset + MAX_TCP_SEGMENT_SIZE]
            offset += len(chunk)
            if is_client:
                seq = conn["client_seq"]
                ack_num = conn["server_seq"]
                src_ip, src_port = conn["client_ip"], conn["client_port"]
                dst_ip, dst_port = conn["server_ip"], conn["server_port"]
                conn["client_seq"] += len(chunk)
            else:
                seq = conn["server_seq"]
                ack_num = conn["client_seq"]
                src_ip, src_port = conn["server_ip"], conn["server_port"]
                dst_ip, dst_port = conn["client_ip"], conn["client_port"]
                conn["server_seq"] += len(chunk)
            flags = 0x18  # PSH + ACK flags
            pkt = self._build_packet_ether_ip_tcp(
                src_ip, dst_ip, src_port, dst_port,
                seq_num=seq, ack_num=ack_num, flags=flags, payload=chunk
            )
            self._write_pcap_record(pkt)

    def _build_packet_ether_ip_tcp(self, src_ip, dst_ip, src_port, dst_port,
                                   seq_num, ack_num, flags, payload):
        """
        Constructs a complete Ethernet/IP/TCP packet.
        """
        # Ethernet header (14 bytes) with dummy MAC addresses
        eth_header = (
            b"\x00\x00\x00\x00\x00\x00"  # Destination MAC
            b"\x11\x11\x11\x11\x11\x11"  # Source MAC
            b"\x08\x00"                  # EtherType = IPv4
        )
        # IP header (20 bytes)
        version_ihl = 0x45
        ip_header_len = 20
        tcp_header_len = 20
        total_length = ip_header_len + tcp_header_len + len(payload)
        tos = 0
        identification = 0
        flags_fragment = 0
        ttl = 64
        protocol = 6  # TCP
        ip_checksum = 0
        src_ip_bin = socket.inet_aton(src_ip)
        dst_ip_bin = socket.inet_aton(dst_ip)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl, tos, total_length, identification,
            flags_fragment, ttl, protocol, ip_checksum,
            src_ip_bin, dst_ip_bin
        )
        # TCP header (20 bytes)
        data_offset = 5
        offset_and_reserved = (data_offset << 4) | 0
        window = 8192
        tcp_checksum = 0
        urgent_ptr = 0
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            src_port, dst_port, seq_num, ack_num,
            offset_and_reserved, flags, window, tcp_checksum, urgent_ptr
        )
        return eth_header + ip_header + tcp_header + payload

    def _write_pcap_record(self, packet_bytes: bytes):
        """
        Writes a record (header + packet) to the PCAP file.
        """
        if not self.file:
            return
        now = time.time()
        sec = int(now)
        usec = int((now - sec) * 1e6)
        record_header = struct.pack("<IIII", sec, usec, len(packet_bytes), len(packet_bytes))
        self.file.write(record_header)
        self.file.write(packet_bytes)
        self.file.flush()

    def _build_http_request_bytes(self, req: http.Request) -> bytes:
        if not req:
            return b""
        decoded_path = urllib.parse.unquote(req.path)
        lines = [f"{req.method} {decoded_path} HTTP/1.1"]
        for name, value in req.headers.items(multi=True):
            decoded_value = urllib.parse.unquote(value)
            lines.append(f"{name}: {decoded_value}")
        lines.append("")
        raw_request = "\r\n".join(lines) + "\r\n"
        content_type = req.headers.get("content-type", "").lower()
        if req.content:
            if "grpc" in content_type:
                # Use formatted parsing for gRPC
                formatted = format_grpc_message(req.content)
                return raw_request.encode("utf-8") + formatted.encode("utf-8")
            elif "application/x-www-form-urlencoded" in content_type:
                body_str = req.content.decode("utf-8", errors="replace")
                body_decoded_str = urllib.parse.unquote(body_str)
                return raw_request.encode("utf-8", errors="replace") + body_decoded_str.encode("utf-8", errors="replace")
            else:
                return raw_request.encode("utf-8", errors="replace") + req.content
        else:
            return raw_request.encode("utf-8", errors="replace")

    def _build_http_response_bytes(self, resp: http.Response) -> bytes:
        if not resp:
            return b""
        lines = [f"HTTP/1.1 {resp.status_code} {resp.reason}"]
        for name, value in resp.headers.items(multi=True):
            decoded_value = urllib.parse.unquote(value)
            lines.append(f"{name}: {decoded_value}")
        lines.append("")
        raw_response = "\r\n".join(lines) + "\r\n"
        content_type = resp.headers.get("content-type", "").lower()
        if resp.content:
            if "grpc" in content_type:
                formatted = format_grpc_message(resp.content)
                return raw_response.encode("utf-8") + formatted.encode("utf-8")
            else:
                return raw_response.encode("utf-8", errors="replace") + resp.content
        else:
            return raw_response.encode("utf-8", errors="replace")

addons = [Mitmproxy2Pcap()]