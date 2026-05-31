"""
Tests for packet_processor module.
"""

import pytest
from packet_processor import process_packet
from packet_structures import EthernetFrame, IPHeader, TCPHeader, UDPHeader


class TestProcessPacket:
    """Tests for process_packet function."""
    
    def test_empty_data(self):
        """Test processing empty data."""
        packet = process_packet(b'')
        assert packet.raw_data == b''
        assert packet.ethernet is None
        assert packet.ip is None
        assert packet.tcp is None
        assert packet.udp is None
    
    def test_too_short_data(self):
        """Test processing data too short for Ethernet header."""
        packet = process_packet(b'\x00\x01')
        assert packet.ethernet is None
    
    def test_ethernet_only_arp(self):
        """Test processing an ARP packet (Ethernet only)."""
        # ARP frame: Dest MAC, Src MAC, EtherType 0x0806
        raw_data = (
            bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) +  # Dest
            bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) +  # Src
            bytes([0x08, 0x06]) +  # EtherType: ARP
            bytes([0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01])  # Payload start
        )
        
        packet = process_packet(raw_data)
        
        assert packet.raw_data == raw_data
        assert packet.ethernet is not None
        assert packet.ethernet.ether_type == 0x0806
        assert packet.ip is None  # Not IP
        assert packet.tcp is None
        assert packet.udp is None
    
    def test_ethernet_ipv4_malformed_ip(self):
        """Test processing IPv4 EtherType but malformed IP header."""
        raw_data = (
            bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) +  # Dest
            bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) +  # Src
            bytes([0x08, 0x00]) +  # EtherType: IPv4
            bytes([0x45]) +  # Ver/IHL
            bytes([0x00]) +  # DSCP/ECN
            bytes([0x00, 0x14]) +  # Total Len: 20
            bytes([0x00, 0x00]) +  # ID
            bytes([0x00, 0x00]) +  # Flags/Offset
            bytes([0xFF]) +  # TTL
            bytes([0x01]) +  # Proto: ICMP
            bytes([0x00, 0x00]) +  # Checksum
            bytes([192, 168, 1, 1]) +  # Src
            bytes([10, 0, 0, 1])  # Dest
        )
        
        packet = process_packet(raw_data)
        assert packet.ethernet is not None
        assert packet.ip is not None
        assert packet.ip.protocol == 1  # ICMP
        assert packet.tcp is None
        assert packet.udp is None
    
    def test_full_tcp_packet(self):
        """Test processing a full TCP packet stack."""
        # Construct a synthetic packet
        # Ethernet (14) + IP (20) + TCP (20) + Payload
        raw_data = (
            bytes([0x00, 0x0C, 0x29, 0x12, 0x34, 0x56]) +  # Eth Dest
            bytes([0x00, 0x0C, 0x29, 0xAA, 0xBB, 0xCC]) +  # Eth Src
            bytes([0x08, 0x00]) +  # Eth Type: IPv4
            
            # IP Header
            bytes([0x45]) +  # Ver: 4, IHL: 5 (20 bytes)
            bytes([0x00]) +  # DSCP/ECN
            bytes([0x00, 0x3C]) +  # Total Length: 60 (20 IP + 20 TCP + 20 Payload)
            bytes([0x00, 0x01]) +  # ID
            bytes([0x40, 0x00]) +  # Flags, Offset
            bytes([0x40]) +  # TTL: 64
            bytes([0x06]) +  # Protocol: TCP
            bytes([0x00, 0x00]) +  # Checksum
            bytes([192, 168, 1, 100]) +  # Src IP
            bytes([192, 168, 1, 200]) +  # Dest IP
            
            # TCP Header
            bytes([0x04, 0x01]) +  # Src Port: 1025
            bytes([0x00, 0x50]) +  # Dest Port: 80
            bytes([0x00, 0x00, 0x00, 0x01]) +  # Seq No
            bytes([0x00, 0x00, 0x00, 0x00]) +  # Ack No
            bytes([0x50]) +  # Data Offset: 5, Res: 0
            bytes([0x02]) +  # Flags: SYN
            bytes([0x72, 0x10]) +  # Window
            bytes([0x00, 0x00]) +  # Checksum
            bytes([0x00, 0x00]) +  # Urgent Pointer
            
            # TCP Payload
            bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                   0x11, 0x12, 0x13, 0x14])
        )
        
        packet = process_packet(raw_data)
        
        assert packet.ethernet is not None
        assert packet.ethernet.ether_type == 0x0800
        assert packet.ethernet.source_mac == "00:0C:29:AA:BB:CC"
        
        assert packet.ip is not None
        assert packet.ip.source_ip == "192.168.1.100"
        assert packet.ip.protocol == 6
        
        assert packet.tcp is not None
        assert packet.tcp.source_port == 1025
        assert packet.tcp.destination_port == 80
        assert packet.tcp.is_flag_set(TCPHeader.FLAG_SYN)
        
        assert packet.udp is None
    
    def test_full_udp_packet(self):
        """Test processing a full UDP packet stack."""
        raw_data = (
            bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) +  # Eth Dest
            bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) +  # Eth Src
            bytes([0x08, 0x00]) +  # Eth Type: IPv4
            
            # IP Header
            bytes([0x45]) +  # Ver: 4, IHL: 5
            bytes([0x00]) +  # DSCP/ECN
            bytes([0x00, 0x20]) +  # Total Length: 32 (20 IP + 8 UDP + 4 Payload)
            bytes([0x00, 0x00]) +  # ID
            bytes([0x00, 0x00]) +  # Flags, Offset
            bytes([0x40]) +  # TTL: 64
            bytes([0x11]) +  # Protocol: UDP
            bytes([0x00, 0x00]) +  # Checksum
            bytes([10, 0, 0, 1]) +  # Src IP
            bytes([10, 0, 0, 2]) +  # Dest IP
            
            # UDP Header
            bytes([0x1F, 0x90]) +  # Src Port: 8080
            bytes([0x00, 0x35]) +  # Dest Port: 53
            bytes([0x00, 0x0C]) +  # Length: 12 (8 Header + 4 Payload)
            bytes([0x00, 0x00]) +  # Checksum
            
            # UDP Payload
            bytes([0xAA, 0xBB, 0xCC, 0xDD])
        )
        
        packet = process_packet(raw_data)
        
        assert packet.ethernet is not None
        assert packet.ip is not None
        assert packet.ip.protocol == 17
        
        assert packet.udp is not None
        assert packet.udp.source_port == 8080
        assert packet.udp.destination_port == 53
        assert packet.udp.length == 12
        
        assert packet.tcp is None
    
    def test_ipv6_packet_ignored_at_layer2(self):
        """Test that IPv6 packets (EtherType 0x86DD) stop parsing at Ethernet."""
        raw_data = (
            bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) +  # Eth Dest
            bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) +  # Eth Src
            bytes([0x86, 0xDD]) +  # Eth Type: IPv6
            bytes([0x60, 0x00, 0x00, 0x00, 0x00, 0x00])  # IPv6 header start
        )
        
        packet = process_packet(raw_data)
        
        assert packet.ethernet is not None
        assert packet.ethernet.ether_type == 0x86DD
        assert packet.ip is None  # We only support IPv4 in this implementation
        
    def test_ip_with_options(self):
        """Test processing an IP packet with options."""
        # IP Header length 24 bytes (IHL = 6)
        raw_data = (
            bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) +  # Eth Dest
            bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) +  # Eth Src
            bytes([0x08, 0x00]) +  # Eth Type
            
            # IP Header
            bytes([0x46]) +  # Ver: 4, IHL: 6 (24 bytes)
            bytes([0x00]) +  # DSCP/ECN
            bytes([0x00, 0x28]) +  # Total Length: 40 (24 IP + 16 TCP)
            bytes([0x00, 0x00]) +  # ID
            bytes([0x00, 0x00]) +  # Flags, Offset
            bytes([0x40]) +  # TTL
            bytes([0x06]) +  # Protocol: TCP
            bytes([0x00, 0x00]) +  # Checksum
            bytes([192, 168, 1, 1]) +  # Src IP
            bytes([192, 168, 1, 2]) +  # Dest IP
            bytes([0x01, 0x02, 0x03, 0x04]) +  # Options (4 bytes)
            
            # TCP Header
            bytes([0x00, 0x50]) +  # Src Port: 80
            bytes([0x04, 0x00]) +  # Dest Port: 1024
            bytes([0x00, 0x00, 0x00, 0x01]) +  # Seq
            bytes([0x00, 0x00, 0x00, 0x00]) +  # Ack
            bytes([0x50]) +  # Offset: 5
            bytes([0x02]) +  # Flags: SYN
            bytes([0xFF, 0xFF]) +  # Window
            bytes([0x00, 0x00]) +  # Checksum
            bytes([0x00, 0x00])  # Urgent
        )
        
        packet = process_packet(raw_data)
        
        assert packet.ip is not None
        assert packet.ip.ihl == 6
        assert len(packet.ip.options) == 4
        
        # Check that TCP payload is calculated correctly despite options
        assert packet.tcp is not None
        assert packet.tcp.source_port == 80