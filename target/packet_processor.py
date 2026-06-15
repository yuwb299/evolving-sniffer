"""
Packet Processor Module.
Orchestrates the parsing of raw bytes into fully populated Packet objects.
"""

from typing import Optional
from packet_structures import Packet, TLSRecord
from ethernet_parser import parse_ethernet_frame
from ip_parser import parse_ip_header
from ipv6_parser import parse_ipv6_header
from tcp_udp_parser import parse_tcp_header, parse_udp_header
from http_parser import parse_http_request, parse_http_response, is_http_payload
from dns_parser import parse_dns_message
from tls_parser import parse_tls_record, parse_tls_handshake
from ftp_parser import parse_ftp_command, parse_ftp_response, is_ftp_payload


def process_packet(raw_data: bytes) -> Packet:
    """
    Process raw packet bytes through the parsing stack (Ethernet -> IP/IPv6 -> TCP/UDP -> HTTP/DNS/TLS/FTP).
    
    Args:
        raw_data: Raw bytes captured from the network interface or pcap file.
        
    Returns:
        A Packet object populated with parsed headers. If parsing fails at a certain
        layer, the packet object will contain data from the successfully parsed layers.
    """
    packet = Packet(raw_data=raw_data)
    
    # 1. Parse Ethernet Layer
    eth_frame = parse_ethernet_frame(raw_data)
    if eth_frame is None:
        # Not a valid Ethernet frame, return raw packet
        return packet
    
    packet.ethernet = eth_frame
    
    # Determine Network Layer (IPv4 or IPv6)
    ip_payload = b''
    
    # Check for IPv4 (0x0800)
    if eth_frame.ether_type == 0x0800:
        ip_header = parse_ip_header(eth_frame.payload)
        if ip_header is None:
            return packet
        packet.ip = ip_header
        
        # Calculate IP payload start (skip IP header and options)
        ip_header_length = ip_header.ihl * 4
        if len(eth_frame.payload) < ip_header_length:
            return packet # Malformed
        ip_payload = eth_frame.payload[ip_header_length:]
        
        transport_protocol = ip_header.protocol
        
    # Check for IPv6 (0x86DD)
    elif eth_frame.ether_type == 0x86DD:
        ipv6_header = parse_ipv6_header(eth_frame.payload)
        if ipv6_header is None:
            return packet
        packet.ipv6 = ipv6_header
        
        # IPv6 header is fixed 40 bytes. Payload starts immediately.
        # Note: This does not handle extension headers.
        if len(eth_frame.payload) < 40:
            return packet # Malformed
        ip_payload = eth_frame.payload[40:]
        
        transport_protocol = ipv6_header.next_header
    else:
        # Other EtherTypes (ARP, etc.)
        return packet

    # 3. Parse Transport Layer (TCP or UDP)
    # Logic is shared for IPv4 and IPv6 payload extraction
    if transport_protocol == 6:  # TCP
        tcp_header = parse_tcp_header(ip_payload)
        packet.tcp = tcp_header
        
        if tcp_header:
            tcp_header_length = tcp_header.data_offset * 4
            if len(ip_payload) >= tcp_header_length:
                tcp_payload = ip_payload[tcp_header_length:]
                
                # 4. Parse TLS (Phase 4) - Check for HTTPS (Port 443) or TLS Record Header
                is_tls_port = tcp_header.destination_port == 443 or tcp_header.source_port == 443
                is_tls_magic = len(tcp_payload) > 3 and tcp_payload[0] == 0x16 and tcp_payload[1] == 0x03
                
                if is_tls_port or is_tls_magic:
                    packet.tls_record = parse_tls_record(tcp_payload)
                    if packet.tls_record and packet.tls_record.content_type == TLSRecord.HANDSHAKE:
                        packet.tls_handshake = parse_tls_handshake(packet.tls_record.payload)

                # 4. Parse HTTP (Phase 2) if TLS is not present
                if not packet.tls_record:
                    is_http_port = tcp_header.destination_port in [80, 8080, 8000] or \
                                   tcp_header.source_port in [80, 8080, 8000]
                    
                    if is_http_port or is_http_payload(tcp_payload):
                        if tcp_header.destination_port in [80, 8080, 8000] or \
                           (tcp_payload.startswith(b"GET ") or tcp_payload.startswith(b"POST")):
                            packet.http_request = parse_http_request(tcp_payload)
                        
                        elif tcp_header.source_port in [80, 8080, 8000] or \
                             tcp_payload.startswith(b"HTTP/"):
                            packet.http_response = parse_http_response(tcp_payload)

                # 5. Parse FTP (Phase 5)
                if not packet.tls_record and not packet.http_request and not packet.http_response:
                    is_ftp_port = tcp_header.destination_port == 21 or tcp_header.source_port == 21
                    
                    if is_ftp_port or is_ftp_payload(tcp_payload):
                        if tcp_header.source_port == 21:
                            packet.ftp_response = parse_ftp_response(tcp_payload)
                        elif tcp_header.destination_port == 21:
                            packet.ftp_command = parse_ftp_command(tcp_payload)
                        
                        if not packet.ftp_command and not packet.ftp_response:
                            cmd = parse_ftp_command(tcp_payload)
                            if cmd:
                                packet.ftp_command = cmd
                            else:
                                packet.ftp_response = parse_ftp_response(tcp_payload)
                        
    elif transport_protocol == 17:  # UDP
        udp_header = parse_udp_header(ip_payload)
        packet.udp = udp_header
        
        if udp_header:
            if len(ip_payload) >= 8:
                udp_payload = ip_payload[8:]
                
                is_dns_port = udp_header.destination_port == 53 or udp_header.source_port == 53
                
                if is_dns_port:
                    packet.dns = parse_dns_message(udp_payload)
    
    return packet