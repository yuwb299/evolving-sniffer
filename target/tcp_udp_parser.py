"""
TCP and UDP header parser module.
Parses raw bytes into TCPHeader and UDPHeader dataclass instances.
"""

import struct
from typing import Optional
from packet_structures import TCPHeader, UDPHeader


def parse_tcp_header(data: bytes) -> Optional[TCPHeader]:
    """
    Parse raw bytes into a TCPHeader.
    
    TCP header format (without options):
    - Source Port: 2 bytes
    - Destination Port: 2 bytes
    - Sequence Number: 4 bytes
    - Acknowledgment Number: 4 bytes
    - Data Offset (4 bits) + Reserved (4 bits): 1 byte
    - Flags: 1 byte
    - Window Size: 2 bytes
    - Checksum: 2 bytes
    - Urgent Pointer: 2 bytes
    - Options: variable (data_offset - 5) * 4 bytes
    
    Args:
        data: Raw bytes containing the TCP header
        
    Returns:
        TCPHeader instance or None if parsing fails
    """
    if len(data) < 20:
        return None  # Header too short (minimum 20 bytes)
    
    try:
        source_port = struct.unpack('!H', data[0:2])[0]
        destination_port = struct.unpack('!H', data[2:4])[0]
        sequence_number = struct.unpack('!I', data[4:8])[0]
        acknowledgment_number = struct.unpack('!I', data[8:12])[0]
        
        # Data offset (high 4 bits) and reserved (low 4 bits)
        data_offset_reserved = data[12]
        data_offset = (data_offset_reserved >> 4) & 0x0F
        
        # Flags
        flags = data[13]
        
        window_size = struct.unpack('!H', data[14:16])[0]
        checksum = struct.unpack('!H', data[16:18])[0]
        urgent_pointer = struct.unpack('!H', data[18:20])[0]
        
        # Parse options if present
        options = b''
        header_length = data_offset * 4
        if header_length > 20 and len(data) >= header_length:
            options = data[20:header_length]
        
        return TCPHeader(
            source_port=source_port,
            destination_port=destination_port,
            sequence_number=sequence_number,
            acknowledgment_number=acknowledgment_number,
            data_offset=data_offset,
            flags=flags,
            window_size=window_size,
            checksum=checksum,
            urgent_pointer=urgent_pointer,
            options=options
        )
    except (struct.error, IndexError):
        return None


def parse_udp_header(data: bytes) -> Optional[UDPHeader]:
    """
    Parse raw bytes into a UDPHeader.
    
    UDP header format:
    - Source Port: 2 bytes
    - Destination Port: 2 bytes
    - Length: 2 bytes
    - Checksum: 2 bytes
    
    Args:
        data: Raw bytes containing the UDP header
        
    Returns:
        UDPHeader instance or None if parsing fails
    """
    if len(data) < 8:
        return None  # Header too short
    
    try:
        source_port = struct.unpack('!H', data[0:2])[0]
        destination_port = struct.unpack('!H', data[2:4])[0]
        length = struct.unpack('!H', data[4:6])[0]
        checksum = struct.unpack('!H', data[6:8])[0]
        
        return UDPHeader(
            source_port=source_port,
            destination_port=destination_port,
            length=length,
            checksum=checksum
        )
    except (struct.error, IndexError):
        return None


def get_tcp_flag_names(flags: int) -> list:
    """
    Get list of human-readable TCP flag names from a flags byte.
    
    Args:
        flags: TCP flags byte (8 bits)
        
    Returns:
        List of flag name strings (e.g., ['SYN', 'ACK'])
    """
    names = []
    if flags & TCPHeader.FLAG_FIN:
        names.append("FIN")
    if flags & TCPHeader.FLAG_SYN:
        names.append("SYN")
    if flags & TCPHeader.FLAG_RST:
        names.append("RST")
    if flags & TCPHeader.FLAG_PSH:
        names.append("PSH")
    if flags & TCPHeader.FLAG_ACK:
        names.append("ACK")
    if flags & TCPHeader.FLAG_URG:
        names.append("URG")
    return names


def get_port_service_name(port: int) -> str:
    """
    Get common service name for a well-known port number.
    
    Args:
        port: Port number (0-65535)
        
    Returns:
        Service name string or empty string if unknown
    """
    services = {
        20: "FTP-Data",
        21: "FTP-Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP-Server",
        68: "DHCP-Client",
        69: "TFTP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP-Trap",
        179: "BGP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "Syslog",
        587: "SMTP-Submission",
        631: "IPP",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle-DB",
        2049: "NFS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        5901: "VNC-1",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
    }
    return services.get(port, "")

# === test_tcp_udp_parser.py ===
"""
Tests for tcp_udp_parser module.
"""

import pytest
from tcp_udp_parser import (
    parse_tcp_header,
    parse_udp_header,
    get_tcp_flag_names,
    get_port_service_name
)
from packet_structures import TCPHeader, UDPHeader


class TestParseTcpHeader:
    """Tests for parse_tcp_header function."""
    
    def test_syn_packet(self):
        """Test parsing a TCP SYN packet."""
        # Build minimal TCP header with SYN flag
        data = (
            bytes([0x04, 0x00]) +  # Source port: 1024
            bytes([0x00, 0x50]) +  # Dest port: 80
            bytes([0x00, 0x00, 0x00, 0x01]) +  # Seq: 1
            bytes([0x00, 0x00, 0x00, 0x00]) +  # Ack: 0
            bytes([0x50]) +  # Data offset: 5 (20 bytes), reserved: 0
            bytes([0x02]) +  # Flags: SYN
            bytes([0xFF, 0xFF]) +  # Window: 65535
            bytes([0x00, 0x00]) +  # Checksum: 0
            bytes([0x00, 0x00])  # Urgent pointer: 0
        )
        
        tcp = parse_tcp_header(data)
        assert tcp is not None
        assert isinstance(tcp, TCPHeader)
        assert tcp.source_port == 1024
        assert tcp.destination_port == 80
        assert tcp.sequence_number == 1
        assert tcp.acknowledgment_number == 0
        assert tcp.data_offset == 5
        assert tcp.flags == TCPHeader.FLAG_SYN
        assert tcp.window_size == 65535
        assert tcp.checksum == 0
        assert tcp.urgent_pointer == 0
        assert tcp.options == b''
    
    def test_syn_ack_packet(self):
        """Test parsing a TCP SYN-ACK packet."""
        data = (
            bytes([0x00, 0x50]) +  # Source port: 80
            bytes([0x04, 0x00]) +  # Dest port: 1024
            bytes([0x00, 0x00, 0x00, 0x0A]) +  # Seq: 10
            bytes([0x00, 0x00, 0x00, 0x01]) +  # Ack: 1
            bytes([0x50]) +  # Data offset: 5
            bytes([0x12]) +  # Flags: SYN | ACK
            bytes([0x10, 0x00]) +  # Window: 4096
            bytes([0x12, 0x34]) +  # Checksum: 0x1234
            bytes([0x00, 0x00])  # Urgent pointer: 0
        )
        
        tcp = parse_tcp_header(data)
        assert tcp is not None
        assert tcp.source_port == 80
        assert tcp.destination_port == 1024
        assert tcp.sequence_number == 10
        assert tcp.acknowledgment_number == 1
        assert tcp.flags == (TCPHeader.FLAG_SYN | TCPHeader.FLAG_ACK)
        assert tcp.checksum == 0x1234
    
    def test_fin_ack_packet(self):
        """Test parsing a TCP FIN-ACK packet."""
        data = (
            bytes([0x00, 0x50]) +  # Source port: 80
            bytes([0x04, 0x00]) +  # Dest port: 1024
            bytes([0x00, 0x00, 0x00, 0x0A]) +  # Seq: 10
            bytes([0x00, 0x00, 0x00, 0x01]) +  # Ack: 1
            bytes([0x50]) +  # Data offset: 5
            bytes([0x11]) +  # Flags: FIN | ACK
            bytes([0x10, 0x00]) +  # Window: 4096
            bytes([0x00, 0x00]) +  # Checksum: 0
            bytes([0x00, 0x00])  # Urgent pointer: 0
        )
        
        tcp = parse_tcp_header(data)
        assert tcp is not None
        assert tcp.is_flag_set(TCPHeader.FLAG_FIN)
        assert tcp.is_flag_set(TCPHeader.FLAG_ACK)
        assert not tcp.is_flag_set(TCPHeader.FLAG_SYN)
    
    def test_header_with_options(self):
        """Test parsing a TCP header with options (MSS)."""
        # Data offset = 6 (24 bytes header), with MSS option
        data = (
            bytes([0x04, 0x00]) +  # Source port: 1024
            bytes([0x00, 0x50]) +  # Dest port: 80
            bytes([0x00, 0x00, 0x00, 0x01]) +  # Seq: 1
            bytes([0x00, 0x00, 0x00, 0x00]) +  # Ack: 0
            bytes([0x60]) +  # Data offset: 6, reserved: 0
            bytes([0x02]) +  # Flags: SYN
            bytes([0xFF, 0xFF]) +  # Window: 65535
            bytes([0x00, 0x00]) +  # Checksum: 0
            bytes([0x00, 0x00]) +  # Urgent pointer: 0
            bytes([0x02, 0x04, 0x05, 0xB4])  # MSS option: 1460
        )
        
        tcp = parse_tcp_header(data)
        assert tcp is not None
        assert tcp.data_offset == 6
        assert len(tcp.options) == 4
        assert tcp.options == bytes([0x02, 0x04, 0x05, 0xB4])
    
    def test_header_too_short(self):
        """Test that headers shorter than 20 bytes return None."""
        data = bytes([0x00] * 19)
        result = parse_tcp_header(data)
        assert result is None
    
    def test_empty_data(self):
        """Test that empty data returns None."""
        result = parse_tcp_header(b'')
        assert result is None
    
    def test_exact_minimum_header(self):
        """Test parsing a header with exactly 20 bytes."""
        data = (
            bytes([0x00, 0x50]) +  # Source port: 80
            bytes([0x01, 0xBB]) +  # Dest port: 443
            bytes([0x00, 0x00, 0x00, 0x00]) +  # Seq: 0
            bytes([0x00, 0x00, 0x00, 0x00]) +  # Ack: 0
            bytes([0x50]) +  # Data offset: 5
            bytes([0x00]) +  # Flags: 0
            bytes([0x00, 0x00]) +  # Window: 0
            bytes([0x00, 0x00]) +  # Checksum: 0
            bytes([0x00, 0x00])  # Urgent pointer: 0
        )
        
        tcp = parse_tcp_header(data)
        assert tcp is not None
        assert tcp.source_port == 80
        assert tcp.destination_port == 443
    
    def test_invalid_data_offset(self):
        """Test that invalid data offset still parses (validation in dataclass)."""
        data = (
            bytes([0x00, 0x50]) +  # Source port: 80
            bytes([0x01, 0xBB]) +  # Dest port: 443
            bytes([0x00, 0x00, 0x00, 0x00]) +  # Seq: 0
            bytes([0x00, 0x00, 0x00, 0x00]) +  # Ack: 0
            bytes([0x40]) +  # Data offset: 4 (invalid, but parser should still return)
            bytes([0x00]) +  # Flags: 0
            bytes([0x00, 0x00]) +  # Window: 0
            bytes([0x00, 0x00]) +  # Checksum: 0
            bytes([0x00, 0x00])  # Urgent pointer: 0
        )
        
        tcp = parse_tcp_header(data)
        assert tcp is not None
        assert tcp.data_offset == 4


class TestParseUdpHeader:
    """Tests for parse_udp_header function."""
    
    def test_valid_udp_header(self):
        """Test parsing a valid UDP header."""
        data = (
            bytes([0x04, 0x00]) +  # Source port: 1024
            bytes([0x00, 0x35]) +  # Dest port: 53 (DNS)
            bytes([0x00, 0x20]) +  # Length: 32
            bytes([0x12, 0x34])  # Checksum: 0x1234
        )
        
        udp = parse_udp_header(data)
        assert udp is not None
        assert isinstance(udp, UDPHeader)
        assert udp.source_port == 1024
        assert udp.destination_port == 53
        assert udp.length == 32
        assert udp.checksum == 0x1234
    
    def test_dhcp_header(self):
        """Test parsing a DHCP (port 67/68) UDP header."""
        data = (
            bytes([0x00, 0x44]) +  # Source port: 68 (DHCP client)
            bytes([0x00, 0x43]) +  # Dest port: 67 (DHCP server)
            bytes([0x01, 0x00]) +  # Length: 256
            bytes([0x00, 0x00])  # Checksum: 0
        )
        
        udp = parse_udp_header(data)
        assert udp is not None
        assert udp.source_port == 68
        assert udp.destination_port == 67
        assert udp.length == 256
    
    def test_header_too_short(self):
        """Test that headers shorter than 8 bytes return None."""
        data = bytes([0x00] * 7)
        result = parse_udp_header(data)
        assert result is None
    
    def test_empty_data(self):
        """Test that empty data returns None."""
        result = parse_udp_header(b'')
        assert result is None
    
    def test_exact_minimum_header(self):
        """Test parsing a header with exactly 8 bytes."""
        data = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00])
        udp = parse_udp_header(data)
        assert udp is not None
        assert udp.length == 8


class TestGetTcpFlagNames:
    """Tests for get_tcp_flag_names function."""
    
    def test_syn_only(self):
        """Test SYN flag returns ['SYN']."""
        assert get_tcp_flag_names(TCPHeader.FLAG_SYN) == ["SYN"]
    
    def test_syn_ack(self):
        """Test SYN|ACK flags returns ['SYN', 'ACK']."""
        flags = TCPHeader.FLAG_SYN | TCPHeader.FLAG_ACK
        names = get_tcp_flag_names(flags)
        assert "SYN" in names
        assert "ACK" in names
        assert len(names) == 2
    
    def test_fin_ack(self):
        """Test FIN|ACK flags returns ['FIN', 'ACK']."""
        flags = TCPHeader.FLAG_FIN | TCPHeader.FLAG_ACK
        names = get_tcp_flag_names(flags)
        assert "FIN" in names
        assert "ACK" in names
        assert len(names) == 2
    
    def test_all_flags(self):
        """Test all flags set returns all 6 names."""
        flags = (TCPHeader.FLAG_FIN | TCPHeader.FLAG_SYN | 
                 TCPHeader.FLAG_RST | TCPHeader.FLAG_PSH |
                 TCPHeader.FLAG_ACK | TCPHeader.FLAG_URG)
        names = get_tcp_flag_names(flags)
        assert len(names) == 6
        assert "FIN" in names
        assert "SYN" in names
        assert "RST" in names
        assert "PSH" in names
        assert "ACK" in names
        assert "URG" in names
    
    def test_no_flags(self):
        """Test no flags set returns empty list."""
        assert get_tcp_flag_names(0) == []


class TestGetPortServiceName:
    """Tests for get_port_service_name function."""
    
    def test_http(self):
        """Test port 80 returns 'HTTP'."""
        assert get_port_service_name(80) == "HTTP"
    
    def test_https(self):
        """Test port 443 returns 'HTTPS'."""
        assert get_port_service_name(443) == "HTTPS"
    
    def test_dns(self):
        """Test port 53 returns 'DNS'."""
        assert get_port_service_name(53) == "DNS"
    
    def test_ssh(self):
        """Test port 22 returns 'SSH'."""
        assert get_port_service_name(22) == "SSH"
    
    def test_unknown_port(self):
        """Test unknown port returns empty string."""
        assert get_port_service_name(9999) == ""
    
    def test_zero_port(self):
        """Test port 0 returns empty string."""
        assert get_port_service_name(0) == ""
    
    def test_ephemeral_port(self):
        """Test ephemeral port returns empty string."""
        assert get_port_service_name(49152) == ""
    
    def test_mysql(self):
        """Test port 3306 returns 'MySQL'."""
        assert get_port_service_name(3306) == "MySQL"
    
    def test_rdp(self):
        """Test port 3389 returns 'RDP'."""
        assert get_port_service_name(3389) == "RDP"