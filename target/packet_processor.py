"""
Packet Processor Module.
Orchestrates the parsing of raw bytes into fully populated Packet objects.
"""

from typing import Optional
from packet_structures import Packet
from ethernet_parser import parse_ethernet_frame
from ip_parser import parse_ip_header
from tcp_udp_parser import parse_tcp_header, parse_udp_header


def process_packet(raw_data: bytes) -> Packet:
    """
    Process raw packet bytes through the parsing stack (Ethernet -> IP -> TCP/UDP).
    
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
    
    # Check for IPv4 (0x0800). For this phase, we primarily focus on IPv4.
    # Other EtherTypes (ARP, IPv6, etc.) are currently ignored beyond the Ethernet layer.
    if eth_frame.ether_type != 0x0800:
        return packet
    
    # 2. Parse IP Layer
    # The payload of the Ethernet frame is the IP packet (header + data)
    ip_header = parse_ip_header(eth_frame.payload)
    if ip_header is None:
        # Ethernet payload was not a valid IP header
        return packet
    
    packet.ip = ip_header
    
    # Calculate IP payload start (skip IP header and options)
    ip_header_length = ip_header.ihl * 4
    if len(eth_frame.payload) < ip_header_length:
        # Malformed packet: payload shorter than header claims
        return packet
    
    ip_payload = eth_frame.payload[ip_header_length:]
    
    # 3. Parse Transport Layer (TCP or UDP)
    if ip_header.protocol == 6:  # TCP
        tcp_header = parse_tcp_header(ip_payload)
        packet.tcp = tcp_header
    elif ip_header.protocol == 17:  # UDP
        udp_header = parse_udp_header(ip_payload)
        packet.udp = udp_header
    
    return packet