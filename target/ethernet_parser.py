"""
Ethernet frame parser module.
Parses raw bytes into EthernetFrame dataclass instances.
"""

import struct
from typing import Optional
from packet_structures import EthernetFrame


def mac_bytes_to_str(mac_bytes: bytes) -> str:
    """
    Convert 6 bytes of MAC address to string format.
    
    Args:
        mac_bytes: 6 bytes representing a MAC address
        
    Returns:
        MAC address string in format XX:XX:XX:XX:XX:XX
        
    Raises:
        ValueError: If mac_bytes is not exactly 6 bytes
    """
    if len(mac_bytes) != 6:
        raise ValueError(f"MAC address must be 6 bytes, got {len(mac_bytes)}")
    return ':'.join(f'{b:02X}' for b in mac_bytes)


def parse_ethernet_frame(data: bytes) -> Optional[EthernetFrame]:
    """
    Parse raw bytes into an EthernetFrame.
    
    Ethernet II frame format:
    - Destination MAC: 6 bytes
    - Source MAC: 6 bytes
    - EtherType: 2 bytes (big-endian)
    - Payload: remaining bytes
    
    Args:
        data: Raw bytes of the Ethernet frame
        
    Returns:
        EthernetFrame instance or None if parsing fails
    """
    if len(data) < 14:
        return None  # Frame too short
    
    try:
        destination_mac = mac_bytes_to_str(data[0:6])
        source_mac = mac_bytes_to_str(data[6:12])
        ether_type = struct.unpack('!H', data[12:14])[0]
        payload = data[14:]
        
        return EthernetFrame(
            destination_mac=destination_mac,
            source_mac=source_mac,
            ether_type=ether_type,
            payload=payload
        )
    except (struct.error, ValueError, IndexError):
        return None


def get_ether_type_name(ether_type: int) -> str:
    """
    Get the human-readable name for an EtherType value.
    
    Common EtherTypes:
    - 0x0800: IPv4
    - 0x0806: ARP
    - 0x86DD: IPv6
    - 0x8100: VLAN tagged
    - 0x8847: MPLS unicast
    - 0x8863: PPPoE Discovery
    - 0x8864: PPPoE Session
    
    Args:
        ether_type: 16-bit EtherType value
        
    Returns:
        Human-readable protocol name or hex string if unknown
    """
    ether_types = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x0835: "RARP",
        0x0842: "Wake-on-LAN",
        0x22F3: "IETF TRILL",
        0x6003: "DECnet Phase IV",
        0x8035: "Reverse ARP",
        0x809B: "AppleTalk",
        0x80F3: "AppleTalk ARP",
        0x8100: "VLAN tagged",
        0x8137: "IPX",
        0x814C: "SNMP",
        0x86DD: "IPv6",
        0x880B: "PPP",
        0x8847: "MPLS unicast",
        0x8848: "MPLS multicast",
        0x8863: "PPPoE Discovery",
        0x8864: "PPPoE Session",
        0x8870: "Jumbo Frames",
        0x888E: "EAP over LAN",
        0x8892: "PROFINET",
        0x88A4: "EtherCAT",
        0x88A8: "Q-in-Q",
        0x88B8: "White Space",
        0x88CC: "LLDP",
        0x88CD: "SERCOS III",
        0x88E5: "MACsec",
        0x8902: "IEEE 802.1ag",
        0x8906: "FCoE",
        0x8914: "FIP",
        0x8915: "RoCE",
        0x891D: "TTEthernet",
        0x892F: "HSR",
        0x9000: "Loopback",
        0x9100: "Q-in-Q",
    }
    return ether_types.get(ether_type, f"0x{ether_type:04X}")