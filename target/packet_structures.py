"""
Packet structures using dataclasses for the protocol analyzer.
Defines the data models for Ethernet, IP, TCP, UDP, HTTP, DNS, TLS, FTP, and SSH packets.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Union
from datetime import datetime


@dataclass
class EthernetFrame:
    """Represents an Ethernet II frame."""
    destination_mac: str
    source_mac: str
    ether_type: int
    payload: bytes
    timestamp: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Validate MAC addresses after initialization."""
        if not self._is_valid_mac(self.destination_mac):
            raise ValueError(f"Invalid destination MAC: {self.destination_mac}")
        if not self._is_valid_mac(self.source_mac):
            raise ValueError(f"Invalid source MAC: {self.source_mac}")
        if not (0 <= self.ether_type <= 0xFFFF):
            raise ValueError(f"Invalid ether type: {self.ether_type}")
    
    @staticmethod
    def _is_valid_mac(mac: str) -> bool:
        """Validate a MAC address in format XX:XX:XX:XX:XX:XX."""
        import re
        pattern = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
        return bool(re.match(pattern, mac))


@dataclass
class IPHeader:
    """Represents an IPv4 header."""
    version: int
    ihl: int
    dscp: int
    ecn: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    header_checksum: int
    source_ip: str
    destination_ip: str
    options: bytes = b''
    
    def __post_init__(self):
        """Validate IP header fields."""
        if self.version != 4:
            raise ValueError(f"Only IPv4 supported, got version {self.version}")
        if not (5 <= self.ihl <= 15):
            raise ValueError(f"Invalid IHL: {self.ihl}")
        if not self._is_valid_ip(self.source_ip):
            raise ValueError(f"Invalid source IP: {self.source_ip}")
        if not self._is_valid_ip(self.destination_ip):
            raise ValueError(f"Invalid destination IP: {self.destination_ip}")
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate an IPv4 address."""
        import socket
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False


@dataclass
class IPv6Header:
    """Represents an IPv6 header (Base header, no extension headers)."""
    version: int
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int
    hop_limit: int
    source_ip: str
    destination_ip: str
    
    def __post_init__(self):
        """Validate IPv6 header fields."""
        if self.version != 6:
            raise ValueError(f"Only IPv6 supported, got version {self.version}")
        # Basic validation for IP strings (format only)
        if ':' not in self.source_ip or ':' not in self.destination_ip:
            raise ValueError(f"Invalid IPv6 address format")

    @property
    def protocol(self) -> int:
        """Alias for next_header to match IPv4 API."""
        return self.next_header


@dataclass
class TCPHeader:
    """Represents a TCP header."""
    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgment_number: int
    data_offset: int
    flags: int
    window_size: int
    checksum: int
    urgent_pointer: int
    options: bytes = b''
    
    # TCP flag bit masks
    FLAG_FIN = 0x01
    FLAG_SYN = 0x02
    FLAG_RST = 0x04
    FLAG_PSH = 0x08
    FLAG_ACK = 0x10
    FLAG_URG = 0x20
    
    def __post_init__(self):
        """Validate TCP header fields."""
        if not (0 <= self.source_port <= 65535):
            raise ValueError(f"Invalid source port: {self.source_port}")
        if not (0 <= self.destination_port <= 65535):
            raise ValueError(f"Invalid destination port: {self.destination_port}")
        if not (5 <= self.data_offset <= 15):
            raise ValueError(f"Invalid data offset: {self.data_offset}")
    
    def is_flag_set(self, flag: int) -> bool:
        """Check if a specific TCP flag is set."""
        return bool(self.flags & flag)
    
    @property
    def flag_names(self) -> List[str]:
        """Get list of set flag names."""
        names = []
        if self.is_flag_set(self.FLAG_FIN): names.append("FIN")
        if self.is_flag_set(self.FLAG_SYN): names.append("SYN")
        if self.is_flag_set(self.FLAG_RST): names.append("RST")
        if self.is_flag_set(self.FLAG_PSH): names.append("PSH")
        if self.is_flag_set(self.FLAG_ACK): names.append("ACK")
        if self.is_flag_set(self.FLAG_URG): names.append("URG")
        return names


@dataclass
class UDPHeader:
    """Represents a UDP header."""
    source_port: int
    destination_port: int
    length: int
    checksum: int
    
    def __post_init__(self):
        """Validate UDP header fields."""
        if not (0 <= self.source_port <= 65535):
            raise ValueError(f"Invalid source port: {self.source_port}")
        if not (0 <= self.destination_port <= 65535):
            raise ValueError(f"Invalid destination port: {self.destination_port}")
        if self.length < 8:
            raise ValueError(f"UDP length too small: {self.length}")


@dataclass
class HTTPRequest:
    """Represents an HTTP Request."""
    method: str
    path: str
    version: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b''


@dataclass
class HTTPResponse:
    """Represents an HTTP Response."""
    version: str
    status_code: int
    status_text: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b''


@dataclass
class DNSHeader:
    """Represents a DNS message header."""
    id: int
    flags: int
    qd_count: int
    an_count: int
    ns_count: int
    ar_count: int

    @property
    def is_response(self) -> bool:
        """True if QR (Query/Response) flag is set (1)."""
        return bool(self.flags & 0x8000)

    @property
    def opcode(self) -> int:
        """Opcode (4 bits)."""
        return (self.flags >> 11) & 0x0F

    @property
    def is_authoritative(self) -> bool:
        """True if AA (Authoritative Answer) flag is set."""
        return bool(self.flags & 0x0400)

    @property
    def is_truncated(self) -> bool:
        """True if TC (Truncated) flag is set."""
        return bool(self.flags & 0x0200)

    @property
    def recursion_desired(self) -> bool:
        """True if RD (Recursion Desired) flag is set."""
        return bool(self.flags & 0x0100)

    @property
    def recursion_available(self) -> bool:
        """True if RA (Recursion Available) flag is set."""
        return bool(self.flags & 0x0080)

    @property
    def response_code(self) -> int:
        """Response Code (RCODE) - 4 bits."""
        return self.flags & 0x000F


@dataclass
class DNSQuestion:
    """Represents a DNS Question section entry."""
    qname: str  # e.g., "www.example.com"
    qtype: int  # Type of record (A=1, AAAA=28, etc.)
    qclass: int # Class (usually IN=1)


@dataclass
class DNSResourceRecord:
    """Represents a DNS Resource Record (Answer, Authority, Additional)."""
    name: str
    type: int
    class_: int
    ttl: int
    rdlength: int
    rdata: bytes # Raw data of the record (e.g. IP address)


@dataclass
class DNSMessage:
    """Represents a complete DNS message."""
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSResourceRecord]
    authorities: List[DNSResourceRecord]
    additionals: List[DNSResourceRecord]


@dataclass
class TLSRecord:
    """Represents a TLS Record Layer header."""
    content_type: int
    version: int
    length: int
    payload: bytes

    # Content Types
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23

    def get_content_type_name(self) -> str:
        names = {
            20: "Change Cipher Spec",
            21: "Alert",
            22: "Handshake",
            23: "Application Data"
        }
        return names.get(self.content_type, f"Unknown({self.content_type})")

    def get_version_name(self) -> str:
        if self.version == 0x0300: return "SSL 3.0"
        if self.version == 0x0301: return "TLS 1.0"
        if self.version == 0x0302: return "TLS 1.1"
        if self.version == 0x0303: return "TLS 1.2"
        if self.version == 0x0304: return "TLS 1.3"
        return f"Unknown(0x{self.version:04x})"


@dataclass
class TLSHandshake:
    """Represents a TLS Handshake message."""
    handshake_type: int
    length: int
    payload: bytes
    sni: Optional[str] = None # Extracted if ClientHello

    # Handshake Types
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    SERVER_HELLO_DONE = 14
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20

    def get_handshake_type_name(self) -> str:
        names = {
            0: "Hello Request",
            1: "Client Hello",
            2: "Server Hello",
            11: "Certificate",
            12: "Server Key Exchange",
            14: "Server Hello Done",
            16: "Client Key Exchange",
            20: "Finished"
        }
        return names.get(self.handshake_type, f"Unknown({self.handshake_type})")


@dataclass
class FTPCommand:
    """Represents an FTP Command."""
    command: str
    args: str


@dataclass
class FTPResponse:
    """Represents an FTP Response."""
    code: int
    message: str


@dataclass
class SSHMessage:
    """Represents an SSH packet (Banner or Binary)."""
    protocol_version: Optional[str] = None  # e.g., "SSH-2.0-OpenSSH"
    packet_length: Optional[int] = None
    padding_length: Optional[int] = None
    message_code: Optional[int] = None
    payload: bytes = b''

    @property
    def is_banner(self) -> bool:
        return self.protocol_version is not None

    @property
    def is_binary_packet(self) -> bool:
        return self.packet_length is not None


@dataclass
class Packet:
    """Represents a fully parsed packet with all layers."""
    ethernet: Optional[EthernetFrame] = None
    ip: Optional[IPHeader] = None
    ipv6: Optional[IPv6Header] = None
    tcp: Optional[TCPHeader] = None
    udp: Optional[UDPHeader] = None
    http_request: Optional[HTTPRequest] = None
    http_response: Optional[HTTPResponse] = None
    dns: Optional[DNSMessage] = None
    tls_record: Optional[TLSRecord] = None
    tls_handshake: Optional[TLSHandshake] = None
    ftp_command: Optional[FTPCommand] = None
    ftp_response: Optional[FTPResponse] = None
    ssh: Optional[SSHMessage] = None
    raw_data: bytes = b''
    
    @property
    def is_tcp(self) -> bool:
        """Check if packet contains TCP header."""
        return self.tcp is not None
    
    @property
    def is_udp(self) -> bool:
        """Check if packet contains UDP header."""
        return self.udp is not None
    
    @property
    def protocol_type(self) -> str:
        """Get the highest layer protocol type."""
        if self.ssh:
            return "SSH"
        if self.ftp_command or self.ftp_response:
            return "FTP"
        if self.tls_handshake:
            return "TLS"
        if self.tls_record:
            return "TLS"
        if self.dns:
            return "DNS"
        if self.http_request or self.http_response:
            return "HTTP"
        if self.tcp:
            return "TCP"
        elif self.udp:
            return "UDP"
        elif self.ipv6:
            return "IPv6"
        elif self.ip:
            return "IPv4"
        elif self.ethernet:
            return "Ethernet"
        return "Unknown"
    
    def summary(self) -> str:
        """Generate a human-readable summary of the packet."""
        parts = []
        
        if self.ethernet:
            parts.append(f"Eth: {self.ethernet.source_mac} -> {self.ethernet.destination_mac}")
        
        # Handle IPv4
        if self.ip:
            parts.append(f"IP: {self.ip.source_ip} -> {self.ip.destination_ip}")
        
        # Handle IPv6
        if self.ipv6:
            # Shorten IPv6 for display if possible
            src = self.ipv6.source_ip
            dst = self.ipv6.destination_ip
            parts.append(f"IPv6: {src} -> {dst}")
        
        if self.tcp:
            parts.append(f"TCP: {self.tcp.source_port} -> {self.tcp.destination_port}")
            if self.tcp.flag_names:
                parts.append(f"Flags: {' '.join(self.tcp.flag_names)}")
        elif self.udp:
            parts.append(f"UDP: {self.udp.source_port} -> {self.udp.destination_port}")

        if self.ssh:
            if self.ssh.is_banner:
                parts.append(f"SSH: {self.ssh.protocol_version}")
            elif self.ssh.is_binary_packet:
                parts.append(f"SSH: Binary Packet (Code: {self.ssh.message_code})")

        if self.tls_record:
            if self.tls_handshake:
                h_type = self.tls_handshake.get_handshake_type_name()
                parts.append(f"TLS: {self.tls_record.get_version_name()} | {h_type}")
                if self.tls_handshake.sni:
                    parts.append(f"SNI: {self.tls_handshake.sni}")
            else:
                parts.append(f"TLS: {self.tls_record.get_version_name()} | {self.tls_record.get_content_type_name()}")

        if self.dns:
            q_type = "Query" if not self.dns.header.is_response else "Response"
            qname = ""
            if self.dns.questions:
                qname = f" {self.dns.questions[0].qname}"
            parts.append(f"DNS {q_type}:{qname}")
            
        if self.http_request:
            parts.append(f"HTTP Request: {self.http_request.method} {self.http_request.path}")
            if "Host" in self.http_request.headers:
                parts.append(f"Host: {self.http_request.headers['Host']}")
        
        if self.http_response:
            parts.append(f"HTTP Response: {self.http_response.version} {self.http_response.status_code} {self.http_response.status_text}")

        if self.ftp_command:
            parts.append(f"FTP Command: {self.ftp_command.command} {self.ftp_command.args}")

        if self.ftp_response:
            parts.append(f"FTP Response: {self.ftp_response.code} {self.ftp_response.message}")
        
        return " | ".join(parts)
    
    def __str__(self) -> str:
        """String representation of the packet."""
        return f"Packet({self.protocol_type}) [{self.summary()}]"
