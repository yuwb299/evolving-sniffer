"""
IPv6 header parser module.
Parses raw bytes into IPv6Header dataclass instances.
"""

import struct
from typing import Optional
from packet_structures import IPv6Header


def ipv6_bytes_to_str(ip_bytes: bytes) -> str:
    """
    Convert 16 bytes of IPv6 address to string format.
    Simple implementation without compression (::).
    
    Args:
        ip_bytes: 16 bytes representing an IPv6 address
        
    Returns:
        IP address string in format XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX
        
    Raises:
        ValueError: If ip_bytes is not exactly 16 bytes
    """
    if len(ip_bytes) != 16:
        raise ValueError(f"IPv6 address must be 16 bytes, got {len(ip_bytes)}")
    
    groups = []
    for i in range(0, 16, 2):
        group_val = struct.unpack('!H', ip_bytes[i:i+2])[0]
        groups.append(f"{group_val:04x}")
        
    return ':'.join(groups)


def parse_ipv6_header(data: bytes) -> Optional[IPv6Header]:
    """
    Parse raw bytes into an IPv6Header.
    
    IPv6 header format (fixed 40 bytes):
    - Version (4 bits) | Traffic Class (8 bits) | Flow Label (20 bits): 4 bytes
    - Payload Length: 2 bytes
    - Next Header: 1 byte (maps to IP protocol numbers)
    - Hop Limit: 1 byte
    - Source IP: 16 bytes
    - Destination IP: 16 bytes
    
    Note: This parser does not handle extension headers. It assumes the next header
    field points directly to the transport layer protocol (TCP, UDP, etc.).
    
    Args:
        data: Raw bytes containing the IPv6 header
        
    Returns:
        IPv6Header instance or None if parsing fails
    """
    if len(data) < 40:
        return None  # Header too short (fixed 40 bytes)
    
    try:
        # First 4 bytes: Ver (4), TC (8), FL (20)
        # Unpack as 32-bit int first to shift bits easily
        ver_tc_fl = struct.unpack('!I', data[0:4])[0]
        
        version = (ver_tc_fl >> 28) & 0x0F
        traffic_class = (ver_tc_fl >> 20) & 0xFF
        flow_label = ver_tc_fl & 0x000FFFFF
        
        # Payload Length (bytes 4-5)
        payload_length = struct.unpack('!H', data[4:6])[0]
        
        # Next Header (byte 6)
        next_header = data[6]
        
        # Hop Limit (byte 7)
        hop_limit = data[7]
        
        # Source IP (bytes 8-23)
        source_ip = ipv6_bytes_to_str(data[8:24])
        
        # Destination IP (bytes 24-39)
        destination_ip = ipv6_bytes_to_str(data[24:40])
        
        # Only support IPv6
        if version != 6:
            return None
        
        return IPv6Header(
            version=version,
            traffic_class=traffic_class,
            flow_label=flow_label,
            payload_length=payload_length,
            next_header=next_header,
            hop_limit=hop_limit,
            source_ip=source_ip,
            destination_ip=destination_ip
        )
    except (struct.error, ValueError, IndexError):
        return None


def get_protocol_name(protocol: int) -> str:
    """
    Get the human-readable name for an IP protocol number.
    Re-used from IPv4 logic as numbers are shared.
    
    Common IP protocols:
    - 1: ICMP
    - 6: TCP
    - 17: UDP
    - 58: ICMPv6
    
    Args:
        protocol: IP protocol number
        
    Returns:
        Human-readable protocol name or hex string if unknown
    """
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        58: "ICMPv6",
    }
    return protocols.get(protocol, f"Protocol-{protocol}")