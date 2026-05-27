"""
Tests for packet structures module.
"""

import pytest
from packet_structures import (
    EthernetFrame, IPHeader, TCPHeader, UDPHeader, Packet
)


class TestEthernetFrame:
    """Tests for EthernetFrame dataclass."""
    
    def test_valid_ethernet_frame(self):
        """Test creating a valid Ethernet frame."""
        frame = EthernetFrame(
            destination_mac="FF:FF:FF:FF:FF:FF",
            source_mac="00:11:22:33:44:55",
            ether_type=0x0800,
            payload=b"hello"
        )
        assert frame.destination_mac == "FF:FF:FF:FF:FF:FF"
        assert frame.source_mac == "00:11:22:33:44:55"
        assert frame.ether_type == 0x0800
        assert frame.payload == b"hello"
    
    def test_invalid_destination_mac(self):
        """Test that invalid destination MAC raises ValueError."""
        with pytest.raises(ValueError, match="Invalid destination MAC"):
            EthernetFrame(
                destination_mac="invalid",
                source_mac="00:11:22:33:44:55",
                ether_type=0x0800,
                payload=b""
            )
    
    def test_invalid_source_mac(self):
        """Test that invalid source MAC raises ValueError."""
        with pytest.raises(ValueError, match="Invalid source MAC"):
            EthernetFrame(
                destination_mac="FF:FF:FF:FF:FF:FF",
                source_mac="not-a-mac",
                ether_type=0x0800,
                payload=b""
            )
    
    def test_mac_with_lowercase(self):
        """Test MAC addresses with lowercase hex digits."""
        frame = EthernetFrame(
            destination_mac="aa:bb:cc:dd:ee:ff",
            source_mac="00:11:22:33:44:55",
            ether_type=0x0800,
            payload=b""
        )
        assert frame.destination_mac == "aa:bb:cc:dd:ee:ff"
    
    def test_invalid_ether_type_negative(self):
        """Test negative ether type raises ValueError."""
        with pytest.raises(ValueError, match="Invalid ether type"):
            EthernetFrame(
                destination_mac="FF:FF:FF:FF:FF:FF",
                source_mac="00:11:22:33:44:55",
                ether_type=-1,
                payload=b""
            )
    
    def test_invalid_ether_type_too_large(self):
        """Test ether type > 0xFFFF raises ValueError."""
        with pytest.raises(ValueError, match="Invalid ether type"):
            EthernetFrame(
                destination_mac="FF:FF:FF:FF:FF:FF",
                source_mac="00:11:22:33:44:55",
                ether_type=0x10000,
                payload=b""
            )


class TestIPHeader:
    """Tests for IPHeader dataclass."""
    
    def test_valid_ip_header(self):
        """Test creating a valid IP header."""
        ip = IPHeader(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=40,
            identification=0x1234,
            flags=0,
            fragment_offset=0,
            ttl=64,
            protocol=6,
            header_checksum=0xABCD,
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1"
        )
        assert ip.version == 4
        assert ip.ihl == 5
        assert ip.source_ip == "192.168.1.1"
        assert ip.destination_ip == "10.0.0.1"
        assert ip.protocol == 6
    
    def test_invalid_version(self):
        """Test non-IPv4 version raises ValueError."""
        with pytest.raises(ValueError, match="Only IPv4 supported"):
            IPHeader(
                version=6,
                ihl=5,
                dscp=0,
                ecn=0,
                total_length=40,
                identification=0,
                flags=0,
                fragment_offset=0,
                ttl=64,
                protocol=6,
                header_checksum=0,
                source_ip="192.168.1.1",
                destination_ip="10.0.0.1"
            )
    
    def test_invalid_ihl(self):
        """Test IHL < 5 raises ValueError."""
        with pytest.raises(ValueError, match="Invalid IHL"):
            IPHeader(
                version=4,
                ihl=4,
                dscp=0,
                ecn=0,
                total_length=40,
                identification=0,
                flags=0,
                fragment_offset=0,
                ttl=64,
                protocol=6,
                header_checksum=0,
                source_ip="192.168.1.1",
                destination_ip="10.0.0.1"
            )
    
    def test_invalid_source_ip(self):
        """Test invalid source IP raises ValueError."""
        with pytest.raises(ValueError, match="Invalid source IP"):
            IPHeader(
                version=4,
                ihl=5,
                dscp=0,
                ecn=0,
                total_length=40,
                identification=0,
                flags=0,
                fragment_offset=0,
                ttl=64,
                protocol=6,
                header_checksum=0,
                source_ip="not-an-ip",
                destination_ip="10.0.0.1"
            )
    
    def test_invalid_destination_ip(self):
        """Test invalid destination IP raises ValueError."""
        with pytest.raises(ValueError, match="Invalid destination IP"):
            IPHeader(
                version=4,
                ihl=5,
                dscp=0,
                ecn=0,
                total_length=40,
                identification=0,
                flags=0,
                fragment_offset=0,
                ttl=64,
                protocol=6,
                header_checksum=0,
                source_ip="192.168.1.1",
                destination_ip="256.0.0.1"
            )


class TestTCPHeader:
    """Tests for TCPHeader dataclass."""
    
    def test_valid_tcp_header(self):
        """Test creating a valid TCP header."""
        tcp = TCPHeader(
            source_port=12345,
            destination_port=80,
            sequence_number=1000,
            acknowledgment_number=2000,
            data_offset=5,
            flags=TCPHeader.FLAG_SYN | TCPHeader.FLAG_ACK,
            window_size=65535,
            checksum=0x1234,
            urgent_pointer=0
        )
        assert tcp.source_port == 12345
        assert tcp.destination_port == 80
        assert tcp.is_flag_set(TCPHeader.FLAG_SYN)
        assert tcp.is_flag_set(TCPHeader.FLAG_ACK)
        assert not tcp.is_flag_set(TCPHeader.FLAG_FIN)
        assert "SYN" in tcp.flag_names
        assert "ACK" in tcp.flag_names
        assert "FIN" not in tcp.flag_names
    
    def test_invalid_source_port(self):
        """Test invalid source port raises ValueError."""
        with pytest.raises(ValueError, match="Invalid source port"):
            TCPHeader(
                source_port=70000,
                destination_port=80,
                sequence_number=0,
                acknowledgment_number=0,
                data_offset=5,
                flags=0,
                window_size=0,
                checksum=0,
                urgent_pointer=0
            )
    
    def test_invalid_destination_port(self):
        """Test invalid destination port raises ValueError."""
        with pytest.raises(ValueError, match="Invalid destination port"):
            TCPHeader(
                source_port=80,
                destination_port=-1,
                sequence_number=0,
                acknowledgment_number=0,
                data_offset=5,
                flags=0,
                window_size=0,
                checksum=0,
                urgent_pointer=0
            )
    
    def test_invalid_data_offset(self):
        """Test data offset < 5 raises ValueError."""
        with pytest.raises(ValueError, match="Invalid data offset"):
            TCPHeader(
                source_port=80,
                destination_port=443,
                sequence_number=0,
                acknowledgment_number=0,
                data_offset=4,
                flags=0,
                window_size=0,
                checksum=0,
                urgent_pointer=0
            )
    
    def test_syn_only_flag(self):
        """Test TCP header with only SYN flag."""
        tcp = TCPHeader(
            source_port=80,
            destination_port=443,
            sequence_number=0,
            acknowledgment_number=0,
            data_offset=5,
            flags=TCPHeader.FLAG_SYN,
            window_size=65535,
            checksum=0,
            urgent_pointer=0
        )
        assert tcp.is_flag_set(TCPHeader.FLAG_SYN)
        assert not tcp.is_flag_set(TCPHeader.FLAG_ACK)
        assert tcp.flag_names == ["SYN"]


class TestUDPHeader:
    """Tests for UDPHeader dataclass."""
    
    def test_valid_udp_header(self):
        """Test creating a valid UDP header."""
        udp = UDPHeader(
            source_port=12345,
            destination_port=53,
            length=32,
            checksum=0xABCD
        )
        assert udp.source_port == 12345
        assert udp.destination_port == 53
        assert udp.length == 32
    
    def test_invalid_source_port(self):
        """Test invalid source port raises ValueError."""
        with pytest.raises(ValueError, match="Invalid source port"):
            UDPHeader(
                source_port=70000,
                destination_port=53,
                length=8,
                checksum=0
            )
    
    def test_invalid_length(self):
        """Test length < 8 raises ValueError."""
        with pytest.raises(ValueError, match="UDP length too small"):
            UDPHeader(
                source_port=12345,
                destination_port=53,
                length=7,
                checksum=0
            )


class TestPacket:
    """Tests for Packet dataclass."""
    
    def test_empty_packet(self):
        """Test empty packet has correct default values."""
        pkt = Packet()
        assert pkt.ethernet is None
        assert pkt.ip is None
        assert pkt.tcp is None
        assert pkt.udp is None
        assert pkt.raw_data == b''
        assert not pkt.is_tcp
        assert not pkt.is_udp
        assert pkt.protocol_type == "Unknown"
    
    def test_tcp_packet(self):
        """Test packet with TCP header."""
        tcp = TCPHeader(
            source_port=12345,
            destination_port=80,
            sequence_number=0,
            acknowledgment_number=0,
            data_offset=5,
            flags=TCPHeader.FLAG_SYN,
            window_size=65535,
            checksum=0,
            urgent_pointer=0
        )
        pkt = Packet(tcp=tcp)
        assert pkt.is_tcp
        assert not pkt.is_udp
        assert pkt.protocol_type == "TCP"
    
    def test_udp_packet(self):
        """Test packet with UDP header."""
        udp = UDPHeader(
            source_port=12345,
            destination_port=53,
            length=8,
            checksum=0
        )
        pkt = Packet(udp=udp)
        assert pkt.is_udp
        assert not pkt.is_tcp
        assert pkt.protocol_type == "UDP"
    
    def test_full_packet_summary(self):
        """Test summary of a fully populated packet."""
        eth = EthernetFrame(
            destination_mac="FF:FF:FF:FF:FF:FF",
            source_mac="00:11:22:33:44:55",
            ether_type=0x0800,
            payload=b""
        )
        ip = IPHeader(
            version=4, ihl=5, dscp=0, ecn=0,
            total_length=40, identification=0,
            flags=0, fragment_offset=0, ttl=64,
            protocol=6, header_checksum=0,
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1"
        )
        tcp = TCPHeader(
            source_port=12345, destination_port=80,
            sequence_number=0, acknowledgment_number=0,
            data_offset=5, flags=TCPHeader.FLAG_SYN,
            window_size=65535, checksum=0, urgent_pointer=0
        )
        pkt = Packet(ethernet=eth, ip=ip, tcp=tcp, raw_data=b"test")
        
        summary = pkt.summary()
        assert "00:11:22:33:44:55" in summary
        assert "FF:FF:FF:FF:FF:FF" in summary
        assert "192.168.1.1" in summary
        assert "10.0.0.1" in summary
        assert "12345" in summary
        assert "80" in summary
        assert "SYN" in summary
    
    def test_str_representation(self):
        """Test string representation of packet."""
        pkt = Packet()
        assert str(pkt).startswith("Packet(")