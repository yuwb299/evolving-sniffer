"""
Tests for packet structures module.
"""

import pytest
from packet_structures import (
    EthernetFrame, IPHeader, TCPHeader, UDPHeader, 
    PacketCapture, EtherType, IPProtocol
)


class TestEthernetFrame:
    """Tests for EthernetFrame dataclass."""

    def test_valid_ethernet_frame(self):
        """Test creating a valid Ethernet frame."""
        frame = EthernetFrame(
            destination_mac="ff:ff:ff:ff:ff:ff",
            source_mac="00:11:22:33:44:55",
            ether_type=0x0800,
            payload=b"test payload"
        )
        assert frame.destination_mac == "ff:ff:ff:ff:ff:ff"
        assert frame.source_mac == "00:11:22:33:44:55"
        assert frame.ether_type == 0x0800
        assert frame.payload == b"test payload"

    def test_invalid_destination_mac(self):
        """Test that invalid destination MAC raises ValueError."""
        with pytest.raises(ValueError, match="Invalid destination MAC"):
            EthernetFrame(
                destination_mac="invalid_mac",
                source_mac="00:11:22:33:44:55",
                ether_type=0x0800,
                payload=b""
            )

    def test_invalid_source_mac(self):
        """Test that invalid source MAC raises ValueError."""
        with pytest.raises(ValueError, match="Invalid source MAC"):
            EthernetFrame(
                destination_mac="ff:ff:ff:ff:ff:ff",
                source_mac="invalid_mac",
                ether_type=0x0800,
                payload=b""
            )

    def test_has_ipv4_true(self):
        """Test has_ipv4 returns True for IPv4 EtherType."""
        frame = EthernetFrame(
            destination_mac="ff:ff:ff:ff:ff:ff",
            source_mac="00:11:22:33:44:55",
            ether_type=EtherType.IPV4,
            payload=b""
        )
        assert frame.has_ipv4() is True
        assert frame.has_ipv6() is False

    def test_has_ipv4_false(self):
        """Test has_ipv4 returns False for non-IPv4 EtherType."""
        frame = EthernetFrame(
            destination_mac="ff:ff:ff:ff:ff:ff",
            source_mac="00:11:22:33:44:55",
            ether_type=EtherType.ARP,
            payload=b""
        )
        assert frame.has_ipv4() is False

    def test_has_ipv6_true(self):
        """Test has_ipv6 returns True for IPv6 EtherType."""
        frame = EthernetFrame(
            destination_mac="ff:ff:ff:ff:ff:ff",
            source_mac="00:11:22:33:44:55",
            ether_type=EtherType.IPV6,
            payload=b""
        )
        assert frame.has_ipv6() is True
        assert frame.has_ipv4() is False

    def test_is_valid_mac_valid(self):
        """Test valid MAC address formats."""
        assert EthernetFrame._is_valid_mac("00:11:22:33:44:55") is True
        assert EthernetFrame._is_valid_mac("FF:FF:FF:FF:FF:FF") is True
        assert EthernetFrame._is_valid_mac("aa:bb:cc:dd:ee:ff") is True
        assert EthernetFrame._is_valid_mac("01:23:45:67:89:ab") is True

    def test_is_valid_mac_invalid(self):
        """Test invalid MAC address formats."""
        assert EthernetFrame._is_valid_mac("") is False
        assert EthernetFrame._is_valid_mac("00:11:22:33:44:55:66") is False
        assert EthernetFrame._is_valid_mac("00:11:22:33:44") is False
        assert EthernetFrame._is_valid_mac("00:11:22:33:44:5G") is False
        assert EthernetFrame._is_valid_mac("001122334455") is False
        assert EthernetFrame._is_valid_mac("00-11-22-33-44-55") is False


class TestIPHeader:
    """Tests for IPHeader dataclass."""

    def test_valid_ip_header(self):
        """Test creating a valid IP header."""
        header = IPHeader(
            version=4,
            ihl=5,
            dscp=0,
            ecn=0,
            total_length=40,
            identification=12345,
            flags=0,
            fragment_offset=0,
            ttl=64,
            protocol=6,
            header_checksum=0x1a2b,
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1"
        )
        assert header.version == 4
        assert header.ihl == 5
        assert header.header_length == 20
        assert header.source_ip == "192.168.1.1"
        assert header.destination_ip == "10.0.0.1"
        assert header.is_tcp is True
        assert header.is_udp is False

    def test_invalid_version(self):
        """Test that invalid version raises ValueError."""
        with pytest.raises(ValueError, match="Invalid IP version"):
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
        """Test that invalid IHL raises ValueError."""
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
        """Test that invalid source IP raises ValueError."""
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
                source_ip="invalid_ip",
                destination_ip="10.0.0.1"
            )

    def test_invalid_destination_ip(self):
        """Test that invalid destination IP raises ValueError."""
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
                destination_ip="invalid_ip"
            )

    def test_is_tcp(self):
        """Test is_tcp property."""
        header = IPHeader(
            version=4, ihl=5, dscp=0, ecn=0, total_length=40,
            identification=0, flags=0, fragment_offset=0, ttl=64,
            protocol=IPProtocol.TCP, header_checksum=0,
            source_ip="192.168.1.1", destination_ip="10.0.0.1"
        )
        assert header.is_tcp is True
        assert header.is_udp is False

    def test_is_udp(self):
        """Test is_udp property."""
        header = IPHeader(
            version=4, ihl=5, dscp=0, ecn=0, total_length=40,
            identification=0, flags=0, fragment_offset=0, ttl=64,
            protocol=IPProtocol.UDP, header_checksum=0,
            source_ip="192.168.1.1", destination_ip="10.0.0.1"
        )
        assert header.is_tcp is False
        assert header.is_udp is True


class TestTCPHeader:
    """Tests for TCPHeader dataclass."""

    def test_valid_tcp_header(self):
        """Test creating a valid TCP header."""
        header = TCPHeader(
            source_port=80,
            destination_port=12345,
            sequence_number=1000,
            acknowledgment_number=2000,
            data_offset=5,
            flags=0x10,  # ACK flag
            window_size=65535,
            checksum=0x1234,
            urgent_pointer=0
        )
        assert header.source_port == 80
        assert header.destination_port == 12345
        assert header.header_length == 20
        assert header.flag_ack is True
        assert header.flag_syn is False
        assert header.flag_fin is False

    def test_invalid_source_port(self):
        """Test that invalid source port raises ValueError."""
        with pytest.raises(ValueError, match="Invalid source port"):
            TCPHeader(
                source_port=-1,
                destination_port=80,
                sequence_number=0,
                acknowledgment_number=0,
                data_offset=5,
                flags=0,
                window_size=65535,
                checksum=0,
                urgent_pointer=0
            )

    def test_invalid_destination_port(self):
        """Test that invalid destination port raises ValueError."""
        with pytest.raises(ValueError, match="Invalid destination port"):
            TCPHeader(
                source_port=80,
                destination_port=70000,
                sequence_number=0,
                acknowledgment_number=0,
                data_offset=5,
                flags=0,
                window_size=65535,
                checksum=0,
                urgent_pointer=0
            )

    def test_invalid_data_offset(self):
        """Test that invalid data offset raises ValueError."""
        with pytest.raises(ValueError, match="Invalid data offset"):
            TCPHeader(
                source_port=80,
                destination_port=12345,
                sequence_number=0,
                acknowledgment_number=0,
                data_offset=4,
                flags=0,
                window_size=65535,
                checksum=0,
                urgent_pointer=0
            )

    def test_tcp_flags(self):
        """Test TCP flag properties."""
        # SYN flag only
        header = TCPHeader(
            source_port=80, destination_port=12345,
            sequence_number=0, acknowledgment_number=0,
            data_offset=5, flags=0x02,  # SYN
            window_size=65535, checksum=0, urgent_pointer=0
        )
        assert header.flag_syn is True
        assert header.flag_ack is False
        assert header.flag_fin is False
        assert header.flag_rst is False
        assert header.flag_psh is False

        # Multiple flags (SYN-ACK)
        header = TCPHeader(
            source_port=80, destination_port=12345,
            sequence_number=0, acknowledgment_number=0,
            data_offset=5, flags=0x12,  # SYN + ACK
            window_size=65535, checksum=0, urgent_pointer=0
        )
        assert header.flag_syn is True
        assert header.flag_ack is True
        assert header.flag_fin is False


class TestUDPHeader:
    """Tests for UDPHeader dataclass."""

    def test_valid_udp_header(self):
        """Test creating a valid UDP header."""
        header = UDPHeader(
            source_port=53,
            destination_port=12345,
            length=30,
            checksum=0x5678
        )
        assert header.source_port == 53
        assert header.destination_port == 12345
        assert header.length == 30
        assert header.checksum == 0x5678

    def test_invalid_source_port(self):
        """Test that invalid source port raises ValueError."""
        with pytest.raises(ValueError, match="Invalid source port"):
            UDPHeader(
                source_port=-1,
                destination_port=53,
                length=20,
                checksum=0
            )

    def test_invalid_length(self):
        """Test that invalid length raises ValueError."""
        with pytest.raises(ValueError, match="Invalid UDP length"):
            UDPHeader(
                source_port=53,
                destination_port=12345,
                length=7,
                checksum=0
            )


class TestPacketCapture:
    """Tests for PacketCapture dataclass."""

    def test_valid_packet_capture(self):
        """Test creating a valid packet capture."""
        frame = EthernetFrame(
            destination_mac="ff:ff:ff:ff:ff:ff",
            source_mac="00:11:22:33:44:55",
            ether_type=0x0800,
            payload=b"test"
        )
        capture = PacketCapture(
            timestamp=1234567890.123,
            frame=frame,
            raw_data=b"raw packet data",
            interface_name="eth0"
        )
        assert capture.timestamp == 1234567890.123
        assert capture.frame == frame
        assert capture.raw_data == b"raw packet data"
        assert capture.interface_name == "eth0"
        assert capture.packet_length == 15  # len(b"raw packet data")

    def test_packet_capture_with_length(self):
        """Test packet capture with explicit length."""
        frame = EthernetFrame(
            destination_mac="ff:ff:ff:ff:ff:ff",
            source_mac="00:11:22:33:44:55",
            ether_type=0x0800,
            payload=b"test"
        )
        capture = PacketCapture(
            timestamp=0.0,
            frame=frame,
            raw_data=b"data",
            packet_length=100
        )
