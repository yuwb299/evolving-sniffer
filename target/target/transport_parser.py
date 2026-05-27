"""
Transport layer parser - parses TCP and UDP headers from raw bytes.
"""

import struct
from packet_structures import TCPHeader, UDPHeader, IPHeader


class TransportParserError(Exception):
    """Custom exception for transport layer parsing errors."""
    pass


class TransportParser:
    """Parser for TCP and UDP headers."""

    # TCP header minimum size (without options) = 20 bytes
    TCP_MIN_HEADER_SIZE = 20
    # UDP header size = 8 bytes
    UDP_HEADER_SIZE = 8

    @staticmethod
    def parse_tcp(raw_data: bytes) -> TCPHeader:
        """
        Parse raw bytes into a TCPHeader.
        
        Args:
            raw_data: Raw bytes starting from TCP header
            
        Returns:
            TCPHeader object with parsed fields
            
        Raises:
            TransportParserError: If data is too short or invalid
        """
        if len(raw_data) < TransportParser.TCP_MIN_HEADER_SIZE:
            raise TransportParserError(
                f"Data too short for TCP header: {len(raw_data)} bytes, "
                f"need at least {TransportParser.TCP_MIN_HEADER_SIZE} bytes"
            )

        # Parse source port (2 bytes)
        source_port = struct.unpack('!H', raw_data[0:2])[0]

        # Parse destination port (2 bytes)
        destination_port = struct.unpack('!H', raw_data[2:4])[0]

        # Parse sequence number (4 bytes)
        sequence_number = struct.unpack('!I', raw_data[4:8])[0]

        # Parse acknowledgment number (4 bytes)
        acknowledgment_number = struct.unpack('!I', raw_data[8:12])[0]

        # Parse data offset (4 bits) and reserved (4 bits)
        data_offset_byte = raw_data[12]
        data_offset = (data_offset_byte >> 4) & 0x0F

        if data_offset < 5:
            raise TransportParserError(
                f"Invalid TCP data offset: {data_offset}, minimum is 5"
            )

        header_length = data_offset * 4
        if len(raw_data) < header_length:
            raise TransportParserError(
                f"Data too short for TCP header with options: {len(raw_data)} bytes, "
                f"need {header_length} bytes"
            )

        # Parse flags (1 byte - but we also read the reserved bits)
        flags = raw_data[13] & 0x3F  # Lower 6 bits are actual flags

        # Parse window size (2 bytes)
        window_size = struct.unpack('!H', raw_data[14:16])[0]

        # Parse checksum (2 bytes)
        checksum = struct.unpack('!H', raw_data[16:18])[0]

        # Parse urgent pointer (2 bytes)
        urgent_pointer = struct.unpack('!H', raw_data[18:20])[0]

        # Parse options if present
        options = b''
        if header_length > TransportParser.TCP_MIN_HEADER_SIZE:
            options = raw_data[20:header_length]

        try:
            return TCPHeader(
                source_port=source_port,
                destination_port=destination_port,
                sequence_number=sequence_number,
                acknowledgment_number=acknowledgment_number,
                data_offset=data_offset,
                flags=flags,
                window_size=window_size,
                checksum=checksum,
                urgent_pointer=urgent_pointer,
                options=options
            )
        except ValueError as e:
            raise TransportParserError(f"Invalid TCP header: {e}")

    @staticmethod
    def parse_udp(raw_data: bytes) -> UDPHeader:
        """
        Parse raw bytes into a UDPHeader.
        
        Args:
            raw_data: Raw bytes starting from UDP header
            
        Returns:
            UDPHeader object with parsed fields
            
        Raises:
            TransportParserError: If data is too short or invalid
        """
        if len(raw_data) < TransportParser.UDP_HEADER_SIZE:
            raise TransportParserError(
                f"Data too short for UDP header: {len(raw_data)} bytes, "
                f"need at least {TransportParser.UDP_HEADER_SIZE} bytes"
            )

        # Parse source port (2 bytes)
        source_port = struct.unpack('!H', raw_data[0:2])[0]

        # Parse destination port (2 bytes)
        destination_port = struct.unpack('!H', raw_data[2:4])[0]

        # Parse length (2 bytes)
        length = struct.unpack('!H', raw_data[4:6])[0]

        # Parse checksum (2 bytes)
        checksum = struct.unpack('!H', raw_data[6:8])[0]

        try:
            return UDPHeader(
                source_port=source_port,
                destination_port=destination_port,
                length=length,
                checksum=checksum
            )
        except ValueError as e:
            raise TransportParserError(f"Invalid UDP header: {e}")

    @staticmethod
    def parse_transport(ip_header: IPHeader, raw_data: bytes) -> object:
        """
        Parse transport layer based on IP protocol.
        
        Args:
            ip_header: Parsed IP header to determine protocol
            raw_data: Raw bytes starting from transport header
            
        Returns:
            TCPHeader or UDPHeader object
            
        Raises:
            TransportParserError: If protocol is not TCP or UDP
        """
        if ip_header.is_tcp:
            return TransportParser.parse_tcp(raw_data)
        elif ip_header.is_udp:
            return TransportParser.parse_udp(raw_data)
        else:
            raise TransportParserError(
                f"Unsupported transport protocol: {ip_header.protocol}"
            )


def parse_tcp_header(raw_data: bytes) -> TCPHeader:
    """Convenience function to parse a TCP header."""
    return TransportParser.parse_tcp(raw_data)


def parse_udp_header(raw_data: bytes) -> UDPHeader:
    """Convenience function to parse a UDP header."""
    return TransportParser.parse_udp(raw_data)