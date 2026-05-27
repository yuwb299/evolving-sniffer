"""
Tests for ethernet_parser module.
"""

import pytest
from ethernet_parser import (
    mac_bytes_to_str,
    parse_ethernet_frame,
    get_ether_type_name
)
from packet_structures import EthernetFrame


class TestMacBytesToStr:
    """Tests for mac_bytes_to_str function."""
    
    def test_valid_mac(self):
        """Test converting valid MAC bytes to string."""
        mac_bytes = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
        result = mac_bytes_to_str(mac_bytes)
        assert result == "00:11:22:33:44:55"
    
    def test_all_zeros(self):
        """Test MAC with all zero bytes."""
        mac_bytes = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        result = mac_bytes_to_str(mac_bytes)
        assert result == "00:00:00:00:00:00"
    
    def test_all_ones(self):
        """Test MAC with all FF bytes (broadcast)."""
        mac_bytes = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
        result = mac_bytes_to_str(mac_bytes)
        assert result == "FF:FF:FF:FF:FF:FF"
    
    def test_too_short(self):
        """Test with fewer than 6 bytes raises ValueError."""
        with pytest.raises(ValueError, match="MAC address must be 6 bytes"):
            mac_bytes_to_str(bytes([0x00, 0x11, 0x22]))
    
    def test_too_long(self):
        """Test with more than 6 bytes raises ValueError."""
        with pytest.raises(ValueError, match="MAC address must be 6 bytes"):
            mac_bytes_to_str(bytes([0x00] * 7))
    
    def test_empty_bytes(self):
        """Test with empty bytes raises ValueError."""
        with pytest.raises(ValueError, match="MAC address must be 6 bytes"):
            mac_bytes_to_str(b'')


class TestParseEthernetFrame:
    """Tests for parse_ethernet_frame function."""
    
    def test_ipv4_frame(self):
        """Test parsing a valid IPv4 Ethernet frame."""
        # Build a minimal Ethernet frame with IPv4 EtherType
        data = (
            bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) +  # Destination: broadcast
            bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) +  # Source
            bytes([0x08, 0x00]) +  # EtherType: IPv4
            bytes([0x45, 0x00, 0x00, 0x14])  # Minimal IP header start (payload)
        )
        
        frame = parse_ethernet_frame(data)
        assert frame is not None
        assert isinstance(frame, EthernetFrame)
        assert frame.destination_mac == "FF:FF:FF:FF:FF:FF"
        assert frame.source_mac == "00:11:22:33:44:55"
        assert frame.ether_type == 0x0800
        assert len(frame.payload) == 4
    
    def test_arp_frame(self):
        """Test parsing an ARP Ethernet frame."""
        data = (
            bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) +  # Destination
            bytes([0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB]) +  # Source
            bytes([0x08, 0x06]) +  # EtherType: ARP
            bytes([0x00, 0x01, 0x08, 0x00])  # ARP payload
        )
        
        frame = parse_ethernet_frame(data)
        assert frame is not None
        assert frame.ether_type == 0x0806
    
    def test_frame_too_short(self):
        """Test that frames shorter than 14 bytes return None."""
        data = bytes([0x00] * 13)
        result = parse_ethernet_frame(data)
        assert result is None
    
    def test_empty_data(self):
        """Test that empty data returns None."""
        result = parse_ethernet_frame(b'')
        assert result is None
    
    def test_exact_minimum_frame(self):
        """Test parsing a frame with exactly 14 bytes (no payload)."""
        data = (
            bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) +  # Destination
            bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) +  # Source
            bytes([0x08, 0x00])  # EtherType
        )
        
        frame = parse_ethernet_frame(data)
        assert frame is not None
        assert frame.payload == b''
    
    def test_vlan_tagged_frame(self):
        """Test parsing a VLAN tagged frame (EtherType 0x8100)."""
        data = (
            bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) +  # Destination
            bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) +  # Source
            bytes([0x81, 0x00]) +  # EtherType: VLAN tagged
            bytes([0x00, 0x01, 0x08, 0x00])  # VLAN tag + next EtherType
        )
        
        frame = parse_ethernet_frame(data)
        assert frame is not None
        assert frame.ether_type == 0x8100
        assert len(frame.payload) == 4


class TestGetEtherTypeName:
    """Tests for get_ether_type_name function."""
    
    def test_ipv4(self):
        """Test IPv4 EtherType returns 'IPv4'."""
        assert get_ether_type_name(0x0800) == "IPv4"
    
    def test_arp(self):
        """Test ARP EtherType returns 'ARP'."""
        assert get_ether_type_name(0x0806) == "ARP"
    
    def test_ipv6(self):
        """Test IPv6 EtherType returns 'IPv6'."""
        assert get_ether_type_name(0x86DD) == "IPv6"
    
    def test_vlan(self):
        """Test VLAN tagged EtherType returns correct name."""
        assert get_ether_type_name(0x8100) == "VLAN tagged"
    
    def test_unknown(self):
        """Test unknown EtherType returns hex string."""
        result = get_ether_type_name(0x1234)
        assert result == "0x1234"
    
    def test_zero(self):
        """Test EtherType 0 returns hex string."""
        result = get_ether_type_name(0x0000)
        assert result == "0x0000"