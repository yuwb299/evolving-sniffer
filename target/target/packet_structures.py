"""
Packet structures module - defines dataclasses for network protocol headers.
Supports Ethernet, IP, TCP, and UDP protocols.
"""

from dataclasses import dataclass, field
from typing import Optional, List
from enum import IntEnum


class EtherType(IntEnum):
    """EtherType values for Ethernet frames."""
    IPV4 = 0x0800
    IPV6 = 0x86DD
    ARP = 0x0806


class IPProtocol(IntEnum):
    """IP protocol numbers."""
    TCP = 6
    UDP = 17
    ICMP = 1


@dataclass
class EthernetFrame:
    """Represents an Ethernet frame."""
    destination_mac: str
    source_mac: str
    ether_type: int
    payload: bytes
    # Optional parsed headers
    ip_header: Optional['IPHeader'] = None
    transport_header: Optional[object] = None

    def __post_init__(self):
        """Validate MAC addresses are in correct format."""
        if not self._is_valid_mac(self.destination_mac):
            raise ValueError(f"Invalid destination MAC: {self.destination_mac}")
        if not self._is_valid_mac(self.source_mac):
            raise ValueError(f"Invalid source MAC: {self.source_mac}")

    @staticmethod
    def _is_valid_mac(mac: str) -> bool:
        """Check if MAC address is in XX:XX:XX:XX:XX:XX format."""
        import re
        pattern = r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
        return bool(re.match(pattern, mac))

    def has_ipv4(self) -> bool:
        """Check if frame contains IPv4 packet."""
        return self.ether_type == EtherType.IPV4

    def has_ipv6(self) -> bool:
        """Check if frame contains IPv6 packet."""
        return self.ether_type == EtherType.IPV6


@dataclass
class IPHeader:
    """Represents an IPv4 header."""
    version: int
    ihl: int
    dscp: int
    ecn: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    header_checksum: int
    source_ip: str
    destination_ip: str
    options: bytes = field(default_factory=bytes)

    def __post_init__(self):
        """Validate IP header fields."""
        if self.version != 4:
            raise ValueError(f"Invalid IP version: {self.version}, expected 4")
        if self.ihl < 5:
            raise ValueError(f"Invalid IHL: {self.ihl}, minimum is 5")
        if not self._is_valid_ip(self.source_ip):
            raise ValueError(f"Invalid source IP: {self.source_ip}")
        if not self._is_valid_ip(self.destination_ip):
            raise ValueError(f"Invalid destination IP: {self.destination_ip}")

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        import socket
        try:
            socket.inet_aton(ip)
            return True
        except (socket.error, OSError):
            return False

    @property
    def header_length(self) -> int:
        """Get header length in bytes."""
        return self.ihl * 4

    @property
    def is_tcp(self) -> bool:
        """Check if protocol is TCP."""
        return self.protocol == IPProtocol.TCP

    @property
    def is_udp(self) -> bool:
        """Check if protocol is UDP."""
        return self.protocol == IPProtocol.UDP


@dataclass
class TCPHeader:
    """Represents a TCP header."""
    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgment_number: int
    data_offset: int
    flags: int
    window_size: int
    checksum: int
    urgent_pointer: int
    options: bytes = field(default_factory=bytes)

    def __post_init__(self):
        """Validate TCP header fields."""
        if not (0 <= self.source_port <= 65535):
            raise ValueError(f"Invalid source port: {self.source_port}")
        if not (0 <= self.destination_port <= 65535):
            raise ValueError(f"Invalid destination port: {self.destination_port}")
        if self.data_offset < 5:
            raise ValueError(f"Invalid data offset: {self.data_offset}")

    @property
    def header_length(self) -> int:
        """Get header length in bytes."""
        return self.data_offset * 4

    @property
    def flag_syn(self) -> bool:
        """Check if SYN flag is set."""
        return bool(self.flags & 0x02)

    @property
    def flag_ack(self) -> bool:
        """Check if ACK flag is set."""
        return bool(self.flags & 0x10)

    @property
    def flag_fin(self) -> bool:
        """Check if FIN flag is set."""
        return bool(self.flags & 0x01)

    @property
    def flag_rst(self) -> bool:
        """Check if RST flag is set."""
        return bool(self.flags & 0x04)

    @property
    def flag_psh(self) -> bool:
        """Check if PSH flag is set."""
        return bool(self.flags & 0x08)


@dataclass
class UDPHeader:
    """Represents a UDP header."""
    source_port: int
    destination_port: int
    length: int
    checksum: int

    def __post_init__(self):
        """Validate UDP header fields."""
        if not (0 <= self.source_port <= 65535):
            raise ValueError(f"Invalid source port: {self.source_port}")
        if not (0 <= self.destination_port <= 65535):
            raise ValueError(f"Invalid destination port: {self.destination_port}")
        if self.length < 8:
            raise ValueError(f"Invalid UDP length: {self.length}")


@dataclass
class PacketCapture:
    """Represents a complete captured packet with timestamp."""
    timestamp: float
    frame: EthernetFrame
    raw_data: bytes
    interface_name: str = ""
    packet_length: int = 0

    def __post_init__(self):
        """Set packet length from raw data if not provided."""
        if self.packet_length == 0:
            self.packet_length = len(self.raw_data)