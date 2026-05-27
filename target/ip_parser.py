"""
IP header parser module.
Parses raw bytes into IPHeader dataclass instances.
"""

import struct
from typing import Optional
from packet_structures import IPHeader


def ip_bytes_to_str(ip_bytes: bytes) -> str:
    """
    Convert 4 bytes of IPv4 address to dotted decimal string.
    
    Args:
        ip_bytes: 4 bytes representing an IPv4 address
        
    Returns:
        IP address string in format XXX.XXX.XXX.XXX
        
    Raises:
        ValueError: If ip_bytes is not exactly 4 bytes
    """
    if len(ip_bytes) != 4:
        raise ValueError(f"IP address must be 4 bytes, got {len(ip_bytes)}")
    return '.'.join(str(b) for b in ip_bytes)


def parse_ip_header(data: bytes) -> Optional[IPHeader]:
    """
    Parse raw bytes into an IPHeader.
    
    IPv4 header format (without options):
    - Version/IHL: 1 byte (4 bits each)
    - DSCP/ECN: 1 byte (6 bits DSCP, 2 bits ECN)
    - Total Length: 2 bytes
    - Identification: 2 bytes
    - Flags/Fragment Offset: 2 bytes (3 bits flags, 13 bits offset)
    - TTL: 1 byte
    - Protocol: 1 byte
    - Header Checksum: 2 bytes
    - Source IP: 4 bytes
    - Destination IP: 4 bytes
    
    Args:
        data: Raw bytes containing the IP header
        
    Returns:
        IPHeader instance or None if parsing fails
    """
    if len(data) < 20:
        return None  # Header too short (minimum 20 bytes)
    
    try:
        # First byte: version (high 4 bits) and IHL (low 4 bits)
        version_ihl = data[0]
        version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F
        
        # Only support IPv4
        if version != 4:
            return None
        
        # Second byte: DSCP (high 6 bits) and ECN (low 2 bits)
        dscp_ecn = data[1]
        dscp = (dscp_ecn >> 2) & 0x3F
        ecn = dscp_ecn & 0x03
        
        # Total length (bytes 2-3)
        total_length = struct.unpack('!H', data[2:4])[0]
        
        # Identification (bytes 4-5)
        identification = struct.unpack('!H', data[4:6])[0]
        
        # Flags and fragment offset (bytes 6-7)
        flags_offset = struct.unpack('!H', data[6:8])[0]
        flags = (flags_offset >> 13) & 0x07
        fragment_offset = flags_offset & 0x1FFF
        
        # TTL (byte 8)
        ttl = data[8]
        
        # Protocol (byte 9)
        protocol = data[9]
        
        # Header checksum (bytes 10-11)
        header_checksum = struct.unpack('!H', data[10:12])[0]
        
        # Source IP (bytes 12-15)
        source_ip = ip_bytes_to_str(data[12:16])
        
        # Destination IP (bytes 