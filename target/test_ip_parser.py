"""
Tests for ip_parser module.
"""

import pytest
from ip_parser import (
    ip_bytes_to_str,
    parse_ip_header,
    get_protocol_name
)
from packet_structures import IPHeader


class TestIpBytesToStr:
    """Tests for ip_bytes_to_str function."""
    
    def test_valid_ip(self):
        """Test converting valid IP bytes to string."""
        ip_bytes = bytes([192, 168, 1, 1])
        result = ip_bytes_to_str(ip_bytes)
        assert result == "192.168.1.1"
    
    def test_localhost(self):
        """Test localhost IP."""
        ip_bytes = bytes([127, 0, 0, 1])
        result = ip_bytes_to_str(ip_bytes)
        assert result == "127.0.0.1"
    
    def test_broadcast(self):
        """Test broadcast IP."""
        ip_bytes = bytes([255, 255, 255, 255])
        result = ip_bytes_to_str(ip_bytes)
        assert result == "255.255.255.255"
    
    def test_too_short(self):
        """Test with fewer than 4 bytes raises ValueError."""
        with pytest.raises(ValueError, match="IP address must be 4 bytes"):
            ip_bytes_to_str(bytes([192, 168, 1]))
    
    def test_too_long(self):
        """Test with more than 4 bytes raises ValueError."""
        with pytest.raises(ValueError, match="IP address must be 4 bytes"):
            ip_bytes_to_str(bytes([192, 168, 1, 1, 1]))
    
    def test_empty_bytes(self):
        """Test with empty bytes raises ValueError."""
        with pytest.raises(ValueError, match="IP address must be 4 bytes"):
            ip_bytes_to_str(b'')


class TestParseIpHeader:
    """Tests for parse_ip_header function."""
    
    def test_valid_ip_header(self):
        """Test parsing a valid IPv4 header."""
        # Build minimal IPv4 header (20 bytes, no options)
        data = (
            bytes([0x45]) +  # Version: 4, IHL: 5
            bytes([0x00]) +  # DSCP: 0, ECN: 0
            bytes([0x00, 0x28]) +  # Total length: 40
            bytes([0x12, 0x34]) +  # Identification: 0x1234
            bytes([0x40, 0x00]) +  # Flags: 2 (DF), Fragment offset: 0
            bytes([0x40]) +  # TTL: 64
            bytes([0x06]) +  # Protocol: 6 (TCP)
            bytes([0xAB, 0xCD]) +  # Header checksum: 0xABCD
            bytes([192, 168, 1, 1]) +  # Source IP
            bytes([10, 0, 0, 1])  # Destination IP
        )
        
        ip = parse_ip_header(data)
        assert ip is not None
        assert isinstance(ip, IPHeader)
        assert ip.version == 4
        assert ip.ihl == 5
        assert ip.total_length == 40
        assert ip.identification == 0x1234
        assert ip.flags == 2  # DF set
        assert ip.fragment_offset == 0
        assert ip.ttl == 64
        assert ip.protocol == 6
        assert ip.header_checksum == 0xABCD
        assert ip.source_ip == "192.168.1.1"
        assert ip.destination_ip == "10.0.0.1"
        assert ip.options == b''
    
    def test_ipv6_rejected(self):
        """Test that IPv6 headers return None."""
        data = (
            bytes([0x60]) +  # Version: 6, IHL: 0 (not valid but version check first)
            bytes([0x00]) * 19  # Rest of header
        )
        result = parse_ip_header(data)
        assert result is None
    
    def test_header_with_options(self):
        """Test parsing an IP header with options (IHL=6)."""
        data = (
            bytes([0x46]) +  # Version: 4, IHL: 6 (24 bytes)
            bytes([0x00]) +  # DSCP: 0, ECN: 0
            bytes([0x00, 0x30]) +  # Total length: 48
            bytes([0x00, 0x00]) +  # Identification: 0
            bytes([0x00, 0x00]) +  # Flags: 0, Fragment offset: 0
            bytes([0x40]) +  # TTL: 64
            bytes([0x11]) +  # Protocol: 17 (UDP)
            bytes([0x00, 0x00]) +  # Header checksum: 0
            bytes([10, 0, 0, 1]) +  # Source IP
            bytes([192, 168, 1, 1]) +  # Destination IP
            bytes([0x01, 0x02, 0x03, 0x04])  # 4 bytes of options
        )
        
        ip = parse_ip_header(data)
        assert ip is not None
        assert ip.ihl == 6
        assert len(ip.options) == 4
        assert ip.options == bytes([0x01, 0x02, 0x03, 0x04])
    
    def test_header_too_short(self):
        """Test that headers shorter than 20 bytes return None."""
        data = bytes([0x00] * 19)
        result = parse_ip_header(data)
        assert result is None
    
    def test_empty_data(self):
        """Test that empty data returns None."""
        result = parse_ip_header(b'')
        assert result is None
    
    def test_exact_minimum_header(self):
        """Test parsing a header with exactly 20 bytes."""
        data = (
            bytes([0x45]) +  # Version: 4, IHL: 5
            bytes([0x00]) +  # DSCP: 0, ECN: 0
            bytes([0x00, 0x14]) +  # Total length: 20
            bytes([0x00, 0x00]) +  # Identification: 0
            bytes([0x00, 0x00]) +  # Flags: 0, Fragment offset: 0
            bytes([0xFF]) +  # TTL: 255
            bytes([0x01]) +  # Protocol: 1 (ICMP)
            bytes([0x00, 0x00]) +  # Header checksum: 0
            bytes([0, 0, 0, 0]) +  # Source IP: 0.0.0.0
            bytes([0, 0, 0, 0])  # Destination IP: 0.0.0.0
        )
        
        ip = parse_ip_header(data)
        assert ip is not None
        assert ip.ttl == 255
        assert ip.protocol == 1


class TestGetProtocolName:
    """Tests for get_protocol_name function."""
    
    def test_tcp(self):
        """Test protocol 6 returns 'TCP'."""
        assert get_protocol_name(6) == "TCP"
    
    def test_udp(self):
        """Test protocol 17 returns 'UDP'."""
        assert get_protocol_name(17) == "UDP"
    
    def test_icmp(self):
        """Test protocol 1 returns 'ICMP'."""
        assert get_protocol_name(1) == "ICMP"
    
    def test_unknown(self):
        """Test unknown protocol returns formatted string."""
        result = get_protocol_name(255)
        assert result == "Protocol-255"
    
    def test_zero(self):
        """Test protocol 0 returns formatted string."""
        result = get_protocol_name(0)
        assert result == "Protocol-0"