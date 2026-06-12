"""
Tests for statistics module.
"""

import pytest
from packet_structures import (
    Packet, EthernetFrame, IPHeader, TCPHeader, UDPHeader, HTTPRequest, HTTPResponse,
    TLSRecord, TLSHandshake, FTPCommand, FTPResponse
)
from statistics import PacketStatistics


class TestPacketStatistics:
    """Tests for PacketStatistics class."""

    def test_init(self):
        """Test initialization of statistics."""
        stats = PacketStatistics()
        assert stats.total_packets == 0
        assert stats.ipv4_packets == 0
        assert stats.tcp_packets == 0
        assert stats.tls_packets == 0
        assert stats.ftp_packets == 0

    def test_update_empty_packet(self):
        """Test updating with a completely empty/unknown packet."""
        stats = PacketStatistics()
        packet = Packet(raw_data=b'\x00\x01') # Too short for Ethernet
        stats.update(packet)
        
        assert stats.total_packets == 1
        assert stats.ethernet_frames == 0
        assert stats.other_protocols == 1

    def test_update_ethernet_only(self):
        """Test updating with a packet that has only Ethernet layer (e.g., ARP)."""
        stats = PacketStatistics()
        eth = EthernetFrame(
            destination_mac="FF:FF:FF:FF:FF:FF",
            source_mac="00:11:22:33:44:55",
            ether_type=0x0806,
            payload=b"ARP_DATA"
        )
        packet = Packet(ethernet=eth)
        stats.update(packet)
        
        assert stats.total_packets == 1
        assert stats.ethernet_frames == 1
        assert stats.ipv4_packets == 0
        assert stats.tcp_packets == 0

    def test_update_ipv4_only(self):
        """Test updating with a packet that has IP but no transport layer (e.g., ICMP)."""
        stats = PacketStatistics()
        eth = EthernetFrame(
            destination_mac="FF:FF:FF:FF:FF:FF",
            source_mac="00:11:22:33:44:55",
            ether_type=0x0800,
            payload=b"IP_DATA"
        )
        ip = IPHeader(
            version=4, ihl=5, dscp=0, ecn=0, total_length=20, 
            identification=0, flags=0, fragment_offset=0, ttl=64, 
            protocol=1, header_checksum=0, source_ip="192.168.1.1", 
            destination_ip="192.168.1.2"
        )
        packet = Packet(ethernet=eth, ip=ip)
        stats.update(packet)
        
        assert stats.total_packets == 1
        assert stats.ipv4_packets == 1
        assert stats.tcp_packets == 0
        assert stats.udp_packets == 0

    def test_update_tcp_packet(self):
        """Test updating with a standard TCP packet."""
        stats = PacketStatistics()
        tcp = TCPHeader(
            source_port=12345, destination_port=80, sequence_number=0,
            acknowledgment_number=0, data_offset=5, flags=0x02,
            window_size=65535, checksum=0, urgent_pointer=0
        )
        eth = EthernetFrame("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00", 0x0800, b"")
        ip = IPHeader(4,5,0,0,40,0,0,0,64,6,0,"10.0.0.1","10.0.0.2")
        
        packet = Packet(ethernet=eth, ip=ip, tcp=tcp)
        stats.update(packet)
        
        assert stats.total_packets == 1
        assert stats.ipv4_packets == 1
        assert stats.tcp_packets == 1

    def test_update_udp_packet(self):
        """Test updating with a standard UDP packet."""
        stats = PacketStatistics()
        udp = UDPHeader(source_port=53, destination_port=53234, length=32, checksum=0)
        eth = EthernetFrame("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00", 0x0800, b"")
        ip = IPHeader(4,5,0,0,40,0,0,0,64,17,0,"10.0.0.1","10.0.0.2")
        
        packet = Packet(ethernet=eth, ip=ip, udp=udp)
        stats.update(packet)
        
        assert stats.total_packets == 1
        assert stats.ipv4_packets == 1
        assert stats.udp_packets == 1

    def test_update_http_packet(self):
        """Test updating with an HTTP packet."""
        stats = PacketStatistics()
        http_req = HTTPRequest(method="GET", path="/", version="HTTP/1.1")
        tcp = TCPHeader(12345, 80, 0, 0, 5, 0x18, 65535, 0, 0)
        eth = EthernetFrame("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00", 0x0800, b"")
        ip = IPHeader(4,5,0,0,100,0,0,0,64,6,0,"10.0.0.1","10.0.0.2")
        
        packet = Packet(ethernet=eth, ip=ip, tcp=tcp, http_request=http_req)
        stats.update(packet)
        
        assert stats.total_packets == 1
        assert stats.tcp_packets == 1
        assert stats.http_packets == 1

    def test_update_tls_packet(self):
        """Test updating with a TLS packet."""
        stats = PacketStatistics()
        tls_rec = TLSRecord(content_type=22, version=0x0303, length=10, payload=b"handshake")
        tcp = TCPHeader(12345, 443, 0, 0, 5, 0x18, 65535, 0, 0)
        eth = EthernetFrame("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00", 0x0800, b"")
        ip = IPHeader(4,5,0,0,100,0,0,0,64,6,0,"10.0.0.1","10.0.0.2")
        
        packet = Packet(ethernet=eth, ip=ip, tcp=tcp, tls_record=tls_rec)
        stats.update(packet)
        
        assert stats.total_packets == 1
        assert stats.tcp_packets == 1
        assert stats.tls_packets == 1

    def test_update_ftp_packet_command(self):
        """Test updating with an FTP command packet."""
        stats = PacketStatistics()
        ftp_cmd = FTPCommand(command="USER", args="admin")
        tcp = TCPHeader(12345, 21, 0, 0, 5, 0x18, 65535, 0, 0)
        eth = EthernetFrame("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00", 0x0800, b"")
        ip = IPHeader(4,5,0,0,100,0,0,0,64,6,0,"10.0.0.1","10.0.0.2")
        
        packet = Packet(ethernet=eth, ip=ip, tcp=tcp, ftp_command=ftp_cmd)
        stats.update(packet)
        
        assert stats.total_packets == 1
        assert stats.tcp_packets == 1
        assert stats.ftp_packets == 1

    def test_update_ftp_packet_response(self):
        """Test updating with an FTP response packet."""
        stats = PacketStatistics()
        ftp_resp = FTPResponse(code=220, message="Service ready")
        tcp = TCPHeader(21, 12345, 0, 0, 5, 0x18, 65535, 0, 0)
        eth = EthernetFrame("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00", 0x0800, b"")
        ip = IPHeader(4,5,0,0,100,0,0,0,64,6,0,"10.0.0.1","10.0.0.2")
        
        packet = Packet(ethernet=eth, ip=ip, tcp=tcp, ftp_response=ftp_resp)
        stats.update(packet)
        
        assert stats.total_packets == 1
        assert stats.tcp_packets == 1
        assert stats.ftp_packets == 1

    def test_report_generation(self):
        """Test that report generation returns a string with expected content."""
        stats = PacketStatistics()
        
        eth = EthernetFrame("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00", 0x0800, b"")
        ip = IPHeader(4,5,0,0,40,0,0,0,64,6,0,"10.0.0.1","10.0.0.2")
        tcp = TCPHeader(12345, 80, 0, 0, 5, 0, 65535, 0, 0)
        
        packet = Packet(ethernet=eth, ip=ip, tcp=tcp)
        stats.update(packet)
        
        report = stats.get_report()
        
        assert "Capture Statistics" in report
        assert "Total Packets Captured : 1" in report
        assert "Ethernet Frames        : 1" in report
        assert "-> IPv4" in report
        assert "-> TCP" in report

    def test_report_generation_tls(self):
        """Test report generation includes TLS stats."""
        stats = PacketStatistics()
        
        # 1 TLS Packet
        tls_rec = TLSRecord(22, 0x0303, 10, b"x")
        packet = Packet(
            ethernet=EthernetFrame("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", 0x0800, b""),
            ip=IPHeader(4,5,0,0,40,0,0,0,64,6,0,"10.0.0.1","10.0.0.2"),
            tcp=TCPHeader(1234, 443, 0, 0, 5, 0, 65535, 0, 0),
            tls_record=tls_rec
        )
        stats.update(packet)
        
        report = stats.get_report()
        assert "-> TLS" in report
        assert "TLS       : 1" in report

    def test_report_generation_ftp(self):
        """Test report generation includes FTP stats."""
        stats = PacketStatistics()
        
        # 1 FTP Packet
        ftp_cmd = FTPCommand("LIST", "")
        packet = Packet(
            ethernet=EthernetFrame("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", 0x0800, b""),
            ip=IPHeader(4,5,0,0,40,0,0,0,64,6,0,"10.0.0.1","10.0.0.2"),
            tcp=TCPHeader(1234, 21, 0, 0, 5, 0, 65535, 0, 0),
            ftp_command=ftp_cmd
        )
        stats.update(packet)
        
        report = stats.get_report()
        assert "-> FTP" in report
        assert "FTP       : 1" in report

    def test_multiple_packets(self):
        """Test stats aggregation across multiple packets."""
        stats = PacketStatistics()
        
        # 1 TCP
        p1 = Packet(ethernet=EthernetFrame("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", 0x0800, b""),
                    ip=IPHeader(4,5,0,0,40,0,0,0,64,6,0,"10.0.0.1","10.0.0.2"),
                    tcp=TCPHeader(1234, 80, 0, 0, 5, 0, 65535, 0, 0))
        
        # 1 UDP
        p2 = Packet(ethernet=EthernetFrame("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", 0x0800, b""),
                    ip=IPHeader(4,5,0,0,40,0,0,0,64,17,0,"10.0.0.1","10.0.0.2"),
                    udp=UDPHeader(53, 1234, 32, 0))
        
        # 1 TLS
        p3 = Packet(ethernet=EthernetFrame("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", 0x0800, b""),
                    ip=IPHeader(4,5,0,0,40,0,0,0,64,6,0,"10.0.0.1","10.0.0.2"),
                    tcp=TCPHeader(1235, 443, 0, 0, 5, 0, 65535, 0, 0),
                    tls_record=TLSRecord(22, 0x0301, 5, b"data"))

        # 1 Other (Ethernet only)
        p4 = Packet(ethernet=EthernetFrame("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", 0x0806, b""))
        
        stats.update(p1)
        stats.update(p2)
        stats.update(p3)
        stats.update(p4)
        
        assert stats.total_packets == 4
        assert stats.ethernet_frames == 4
        assert stats.ipv4_packets == 3
        assert stats.tcp_packets == 2
        assert stats.udp_packets == 1
        assert stats.tls_packets == 1
        assert stats.ftp_packets == 0
        assert stats.other_protocols == 0 # p4 has Ethernet, so not 'other'
        
        report = stats.get_report()
        assert "Total Packets Captured : 4" in report