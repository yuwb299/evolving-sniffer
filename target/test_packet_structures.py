"""
Tests for packet structures module.
"""

import pytest
from packet_structures import (
    EthernetFrame, IPHeader, TCPHeader, UDPHeader, Packet,
    DNSHeader, DNSQuestion, DNSResourceRecord, DNSMessage,
    HTTPRequest, HTTPResponse
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
        assert ip.source_ip == "192.168.1.1"


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
        assert tcp.is_flag_set(TCPHeader.FLAG_SYN)
        assert tcp.is_flag_set(TCPHeader.FLAG_ACK)
        assert "SYN" in tcp.flag_names


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


class TestDNSHeader:
    """Tests for DNSHeader dataclass."""
    
    def test_header_flags_parsing(self):
        """Test parsing flags bits."""
        # Standard Query
        dns = DNSHeader(id=12345, flags=0x0100, qd_count=1, an_count=0, ns_count=0, ar_count=0)
        assert not dns.is_response
        assert dns.recursion_desired
        assert not dns.recursion_available
        
        # Standard Response
        dns_resp = DNSHeader(id=12345, flags=0x8180, qd_count=0, an_count=1, ns_count=0, ar_count=0)
        assert dns_resp.is_response
        assert dns_resp.recursion_available
        assert dns_resp.response_code == 0 # No Error

    def test_opcode(self):
        """Test opcode extraction."""
        # Opcode 4 (Notify)
        dns = DNSHeader(id=1, flags=0x2400, qd_count=0, an_count=0, ns_count=0, ar_count=0)
        assert dns.opcode == 4

    def test_response_code(self):
        """Test RCODE extraction."""
        # NXDOMAIN (3)
        dns = DNSHeader(id=1, flags=0x8183, qd_count=0, an_count=0, ns_count=0, ar_count=0)
        assert dns.response_code == 3


class TestDNSQuestion:
    """Tests for DNSQuestion dataclass."""
    
    def test_question_creation(self):
        q = DNSQuestion(qname="example.com", qtype=1, qclass=1)
        assert q.qname == "example.com"
        assert q.qtype == 1 # A record
        assert q.qclass == 1 # IN


class TestDNSResourceRecord:
    """Tests for DNSResourceRecord dataclass."""
    
    def test_rr_creation(self):
        r = DNSResourceRecord(name="example.com", type=1, class_=1, ttl=300, rdlength=4, rdata=b"\x7f\x00\x00\x01")
        assert r.name == "example.com"
        assert r.ttl == 300
        assert r.rdata == b"\x7f\x00\x00\x01"


class TestDNSMessage:
    """Tests for DNSMessage dataclass."""
    
    def test_message_creation(self):
        hdr = DNSHeader(id=1, flags=0x0100, qd_count=1, an_count=0, ns_count=0, ar_count=0)
        q = DNSQuestion("example.com", 1, 1)
        msg = DNSMessage(header=hdr, questions=[q], answers=[], authorities=[], additionals=[])
        
        assert len(msg.questions) == 1
        assert msg.questions[0].qname == "example.com"


class TestPacket:
    """Tests for Packet dataclass."""
    
    def test_empty_packet(self):
        """Test empty packet has correct default values."""
        pkt = Packet()
        assert pkt.protocol_type == "Unknown"
        
    def test_dns_packet_type(self):
        """Test DNS packet detection."""
        dns = DNSMessage(
            header=DNSHeader(id=1, flags=0x0100, qd_count=1, an_count=0, ns_count=0, ar_count=0),
            questions=[], answers=[], authorities=[], additionals=[]
        )
        pkt = Packet(dns=dns)
        assert pkt.protocol_type == "DNS"

    def test_packet_summary_dns(self):
        """Test summary generation includes DNS info."""
        hdr = DNSHeader(id=1, flags=0x0100, qd_count=1, an_count=0, ns_count=0, ar_count=0)
        q = DNSQuestion("google.com", 1, 1)
        dns = DNSMessage(header=hdr, questions=[q], answers=[], authorities=[], additionals=[])
        
        pkt = Packet(dns=dns)
        summ = pkt.summary()
        assert "DNS Query" in summ
        assert "google.com" in summ
        
    def test_packet_summary_dns_response(self):
        """Test summary generation for DNS Response."""
        hdr = DNSHeader(id=1, flags=0x8180, qd_count=0, an_count=1, ns_count=0, ar_count=0)
        dns = DNSMessage(header=hdr, questions=[], answers=[], authorities=[], additionals=[])
        
        pkt = Packet(dns=dns)
        summ = pkt.summary()
        assert "DNS Response" in summ
