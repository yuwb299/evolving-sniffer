"""
IP header parser - parses raw bytes into IPHeader dataclass.
Supports IPv4 headers with options.
"""

import struct
from packet_structures import IPHeader


class IPParserError(Exception):
    """Custom exception for IP parsing errors."""
    pass


class IPParser:
    """Parser for IPv4 headers."""

    # Minimum IPv4 header size without options (20 bytes)
    MIN_HEADER_SIZE = 20

    @staticmethod
    def parse(raw_data: bytes) -> IPHeader:
        """
        Parse raw bytes into an IPHeader.
        
        Args:
            raw_data: Raw bytes starting from IP header (after Ethernet header)
            
        Returns:
            IPHeader object with parsed fields
            
        Raises:
            IPParserError: If data is too short or invalid
        """
        if len(raw_data) < IPParser.MIN_HEADER_SIZE:
            raise IPParserError(
                f"Data too short for IP header: {len(raw_data)} bytes, "
                f"need at least {IPParser.MIN_HEADER_SIZE} bytes"
            )

        # Parse first byte: version (4 bits) and IHL (4 bits)
        version_ihl = raw_data[0]
        version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F

        if version != 4:
            raise IPParserError(f"Unsupported IP version: {version}, only IPv4 supported")

        if ihl < 5:
            raise IPParserError(f"Invalid IHL: {ihl}, minimum is 5 (20 bytes)")

        header_length = ihl * 4
        if len(raw_data) < header_length:
            raise IPParserError(
                f"Data too short for IP header with options: {len(raw_data)} bytes, "
                f"need {header_length} bytes"
            )

        # Parse DSCP (6 bits) and ECN (2 bits) from second byte
        dscp_ecn = raw_data[1]
        dscp = (dscp_ecn >> 2) & 0x3F
        ecn = dscp_ecn & 0x03

        # Parse total length (2 bytes)
        total_length = struct.unpack('!H', raw_data[2:4])[0]

        # Parse identification (2 bytes)
        identification = struct.unpack('!H', raw_data[4:6])[0]

        # Parse flags (3 bits) and fragment offset (13 bits)
        flags_offset = struct.unpack('!H', raw_data[6:8])[0]
        flags = (flags_offset >> 13) & 0x07
        fragment_offset = flags_offset & 0x1FFF

        # Parse TTL (1 byte)
        ttl = raw_data[8]

        # Parse protocol (1 byte)
        protocol = raw_data[9]

        # Parse header checksum (2 bytes)
        header_checksum = struct.unpack('!H', raw_data[10:12])[0]

        # Parse source IP (4 bytes)
        source_ip = IPParser._bytes_to_ip(raw_data[12:16])

        # Parse destination IP (4 bytes)
        destination_ip = IPParser._bytes_to_ip(raw_data[16:20])

        # Parse options if present
        options = b''
        if header_length > IPParser.MIN_HEADER_SIZE:
            options = raw_data[20:header_length]

        try:
            return IPHeader(
                version=version,
                ihl=ihl,
                dscp=dscp,
                ecn=ecn,
                total_length=total_length,
                identification=identification,
                flags=flags,
                fragment_offset=fragment_offset,
                ttl=ttl,
                protocol=protocol,
                header_checksum=header_checksum,
                source_ip=source_ip,
                destination_ip=destination_ip,
                options=options
            )
        except ValueError as e:
            raise IPParserError(f"Invalid IP header: {e}")

    @staticmethod
    def _bytes_to_ip(ip_bytes: bytes) -> str:
        """
        Convert 4 bytes to IPv4 address string.
        
        Args:
            ip_bytes: 4 bytes representing IPv4 address
            
        Returns:
            IP address in dotted decimal format
            
        Raises:
            IPParserError: If input is not exactly 4 bytes
        """
        if len(ip_bytes) != 4:
            raise IPParserError(
                f"IP address must be 4 bytes, got {len(ip_bytes)}"
            )
        
        return '.'.join(str(b) for b in ip_bytes)

    @staticmethod
    def is_fragmented(ip_header: IPHeader) -> bool:
        """Check if the IP packet is fragmented."""
        return (ip_header.flags & 0x01) != 0 or ip_header.fragment_offset > 0

    @staticmethod
    def get_protocol_name(protocol: int) -> str:
        """Get human-readable protocol name."""
        from packet_structures import IPProtocol
        try:
            return IPProtocol(protocol).name
        except ValueError:
            return f"UNKNOWN ({protocol})"


def parse_ip_header(raw_data: bytes) -> IPHeader:
    """
    Convenience function to parse an IP header.
    
    Args:
        raw_data: Raw bytes starting from IP header
        
    Returns:
        IPHeader object
    """
    parser = IPParser()
    return parser.parse(raw_data)