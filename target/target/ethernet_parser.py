"""
Ethernet frame parser - parses raw bytes into EthernetFrame dataclass.
Supports standard Ethernet II frames.
"""

import struct
from packet_structures import EthernetFrame, EtherType


class EthernetParserError(Exception):
    """Custom exception for Ethernet parsing errors."""
    pass


class EthernetParser:
    """Parser for Ethernet II frames."""

    # Size of Ethernet header without payload (14 bytes)
    HEADER_SIZE = 14
    # Size of MAC address in bytes
    MAC_ADDRESS_SIZE = 6
    # Size of EtherType field in bytes
    ETHERTYPE_SIZE = 2

    @staticmethod
    def parse(raw_data: bytes) -> EthernetFrame:
        """
        Parse raw bytes into an EthernetFrame.
        
        Args:
            raw_data: Raw bytes starting from Ethernet header
            
        Returns:
            EthernetFrame object with parsed fields
            
        Raises:
            EthernetParserError: If data is too short or invalid
        """
        if len(raw_data) < EthernetParser.HEADER_SIZE:
            raise EthernetParserError(
                f"Data too short for Ethernet frame: {len(raw_data)} bytes, "
                f"need at least {EthernetParser.HEADER_SIZE} bytes"
            )

        # Parse destination MAC (6 bytes)
        dest_mac = EthernetParser._bytes_to_mac(raw_data[0:6])
        
        # Parse source MAC (6 bytes)
        src_mac = EthernetParser._bytes_to_mac(raw_data[6:12])
        
        # Parse EtherType (2 bytes) - big endian
        ether_type = struct.unpack('!H', raw_data[12:14])[0]
        
        # Payload is everything after header
        payload = raw_data[14:]

        try:
            return EthernetFrame(
                destination_mac=dest_mac,
                source_mac=src_mac,
                ether_type=ether_type,
                payload=payload
            )
        except ValueError as e:
            raise EthernetParserError(f"Invalid Ethernet frame: {e}")

    @staticmethod
    def _bytes_to_mac(mac_bytes: bytes) -> str:
        """
        Convert 6 bytes to MAC address string format.
        
        Args:
            mac_bytes: 6 bytes representing MAC address
            
        Returns:
            MAC address in format XX:XX:XX:XX:XX:XX
            
        Raises:
            EthernetParserError: If input is not exactly 6 bytes
        """
        if len(mac_bytes) != EthernetParser.MAC_ADDRESS_SIZE:
            raise EthernetParserError(
                f"MAC address must be {EthernetParser.MAC_ADDRESS_SIZE} bytes, "
                f"got {len(mac_bytes)}"
            )
        
        return ':'.join(f'{b:02x}' for b in mac_bytes)

    @staticmethod
    def is_broadcast(mac: str) -> bool:
        """Check if MAC address is broadcast (FF:FF:FF:FF:FF:FF)."""
        return mac.upper() == 'FF:FF:FF:FF:FF:FF'

    @staticmethod
    def is_multicast(mac: str) -> bool:
        """Check if MAC address is multicast (first byte LSB set)."""
        first_byte = int(mac.split(':')[0], 16)
        return bool(first_byte & 0x01)

    @staticmethod
    def get_ether_type_name(ether_type: int) -> str:
        """
        Get human-readable name for EtherType.
        
        Args:
            ether_type: EtherType value
            
        Returns:
            String name of the EtherType
        """
        try:
            return EtherType(ether_type).name
        except ValueError:
            return f"UNKNOWN (0x{ether_type:04x})"


def parse_ethernet_frame(raw_data: bytes) -> EthernetFrame:
    """
    Convenience function to parse an Ethernet frame.
    
    Args:
        raw_data: Raw bytes starting from Ethernet header
        
    Returns:
        EthernetFrame object
    """
    parser = EthernetParser()
    return parser.parse(raw_data)