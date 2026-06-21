"""
Tests for ipv6_parser module.
"""

import pytest
import struct
from ipv6_parser import (
    ipv6_bytes_to_str,
    parse_ipv6_header,
    get_protocol_name
)
from packet_structures import IPv6Header


class TestIpv6BytesToStr:
    """Tests for ipv6_bytes_to_str function."""
    
    def test_valid_ipv6(self):
        """Test converting valid IPv6 bytes to string."""
        # ::1
        ip_bytes = bytes([0x00] * 15) + bytes([0x01])
        result = ipv6_bytes_to_str(ip_bytes)
        assert result == "0000:0000:0000:0000:0000:0000:0000:0001"
    
    def test_google_dns(self):
        """Test Google DNS IPv6 address 2001:4860:4860::8888."""
        ip_bytes = bytes([0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88])
        result = ipv6_bytes_to_str(ip_bytes)
        assert result == "2001:4860:4860:0000:0000:0000:0000:8888"
    
    def test_full_bytes(self):
        """Test with non-zero bytes in all groups."""
        ip_bytes = bytes([0xFF, 0xFF, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03,
                          0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07])
        result = ipv6_bytes_to_str(ip_bytes)
        assert result == "ffff:0001:0002:0003:0004:0005:0006:0007"
    
    def test_too_short(self):
        """Test with fewer than 16 bytes raises ValueError."""
        with pytest.raises(ValueError, match="IPv6 address must be 16 bytes"):
            ipv6_bytes_to_str(bytes([0x00] * 10))
    
    def test_too_long(self):
        """Test with more than 16 bytes raises ValueError."""
        with pytest.raises(ValueError, match="IPv6 address must be 16 bytes"):
            ipv6_bytes_to_str(bytes([0x00] * 20))


class TestParseIpv6Header:
    """Tests for parse_ipv6_header function."""
    
    def test_valid_header_tcp(self):
        """Test parsing a valid IPv6 header with TCP payload."""
        # Build minimal IPv6 header (40 bytes)
        data = (
            bytes([0x60]) +  # Version: 6, TC: 0, FL: 0 (first 4 bits)
            bytes([0x00, 0x00, 0x00]) +  # Rest of TC/FL
            bytes([0x00, 0x14]) +  # Payload Length: 20
            bytes([0x06]) +  # Next Header: 6 (TCP)
            bytes([0x40]) +  # Hop Limit: 64
            bytes([0x20, 0x01, 0x0D, 0xB8]) + # Src Prefix
            bytes([0x00, 0x00, 0x00, 0x00]) +
            bytes([0x00, 0x00, 0x00, 0x00]) +
            bytes([0x00, 0x00, 0x00, 0x01]) + # Src Suffix (::1)
            bytes([0x20, 0x01, 0x0D, 0xB8]) + # Dst Prefix
            bytes([0x00, 0x00, 0x00, 0x00]) +
            bytes([0x00, 0x00, 0x00, 0x00]) +
            bytes([0x00, 0x00, 0x00, 0x02])  # Dst Suffix (::2)
        )
        
        ip = parse_ipv6_header(data)
        assert ip is not None
        assert isinstance(ip, IPv6Header)
        assert ip.version == 6
        assert ip.traffic_class == 0
        assert ip.flow_label == 0
        assert ip.payload_length == 20
        assert ip.next_header == 6 # TCP
        assert ip.hop_limit == 64
        assert ip.source_ip == "2001:0db8:0000:0000:0000:0000:0000:0001"
        assert ip.destination_ip == "2001:0db8:0000:0000:0000:0000:0000:0002"
    
    def test_header_with_flow_label(self):
        """Test parsing header with flow label set."""
        # Ver(4)=6, TC(8)=0, FL(20)=0x12345
        first_4_bytes = struct.pack('!I', (6 << 28) | 0x12345)
        
        data = (
            first_4_bytes +
            bytes([0x00, 0x00]) +  # Payload Len
            bytes([0x11]) +  # Next Header: UDP
            bytes([0xFF]) +  # Hop Limit
            bytes([0x00] * 32) # Addrs
        )
        
        ip = parse_ipv6_header(data)
        assert ip is not None
        assert ip.flow_label == 0x12345
        assert ip.next_header == 17

    def test_header_too_short(self):
        """Test that headers shorter than 40 bytes return None."""
        data = bytes([0x00] * 39)
        result = parse_ipv6_header(data)
        assert result is None
    
    def test_empty_data(self):
        """Test that empty data returns None."""
        result = parse_ipv6_header(b'')
        assert result is None

    def test_invalid_version(self):
        """Test that a header with a version other than 6 returns None."""
        # Version 4 in the top 4 bits
        data = (
            bytes([0x40]) +  # Ver 4
            bytes([0x00] * 39)
        )
        result = parse_ipv6_header(data)
        assert result is None

    def test_next_header_icmpv6(self):
        """Test parsing Next Header for ICMPv6 (58)."""
        data = (
            bytes([0x60, 0x00, 0x00, 0x00]) +
            bytes([0x00, 0x10]) + # Length
            bytes([0x3A]) + # Next Header: 58 (ICMPv6)
            bytes([0x40]) +
            bytes([0x00] * 32)
        )
        ip = parse_ipv6_header(data)
        assert ip is not None
        assert ip.next_header == 58


class TestGetProtocolName:
    """Tests for get_protocol_name function."""
    
    def test_icmpv6(self):
        """Test protocol 58 returns 'ICMPv6'."""
        assert get_protocol_name(58) == "ICMPv6"
    
    def test_tcp(self):
        """Test protocol 6 returns 'TCP'."""
        assert get_protocol_name(6) == "TCP"
    
    def test_udp(self):
        """Test protocol 17 returns 'UDP'."""
        assert get_protocol_name(17) == "UDP"
    
    def test_unknown(self):
        """Test unknown protocol returns formatted string."""
        result = get_protocol_name(255)
        assert result == "Protocol-255"
    
    def test_zero(self):
        """Test protocol 0 returns formatted string."""
        result = get_protocol_name(0)
        assert result == "Protocol-0"