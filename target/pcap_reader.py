"""
PCAP File Reader Module.
Provides functionality to read network packet data from .pcap files.
"""

import struct
from typing import Iterator, Optional


class PcapReaderError(Exception):
    """Base exception for PCAP reader errors."""
    pass


class PcapReader:
    """
    Reads network packets from a PCAP file.
    
    Supports the standard PCAP format (Global Header followed by
    Packet Records).
    """
    
    # PCAP Global Header Magic Number
    MAGIC_NUMBER = 0xA1B2C3D4
    
    # PCAP Global Header format (24 bytes)
    # Magic (4), Major (2), Minor (2), Thiszone (4), Sigfigs (4),
    # Snaplen (4), Network (4)
    GLOBAL_HEADER_FORMAT = '!IHHiIII'
    GLOBAL_HEADER_SIZE = 24
    
    # Packet Record Header format (16 bytes)
    # Timestamp Sec (4), Timestamp Usec (4), Incl Len (4), Orig Len (4)
    PACKET_HEADER_FORMAT = '!IIII'
    PACKET_HEADER_SIZE = 16
    
    def __init__(self, filename: str):
        """
        Initialize the reader with a PCAP file.
        
        Args:
            filename: Path to the .pcap file
            
        Raises:
            FileNotFoundError: If the file does not exist
            PcapReaderError: If the file is not a valid PCAP file
        """
        self.filename = filename
        self.file = open(filename, 'rb')
        self._read_global_header()
        
    def _read_global_header(self):
        """Read and validate the global PCAP header."""
        header_data = self.file.read(self.GLOBAL_HEADER_SIZE)
        if len(header_data) < self.GLOBAL_HEADER_SIZE:
            raise PcapReaderError("File too short to be a valid PCAP file")
            
        try:
            unpacked = struct.unpack(self.GLOBAL_HEADER_FORMAT, header_data)
            self.magic_number = unpacked[0]
            self.version_major = unpacked[1]
            self.version_minor = unpacked[2]
            self.thiszone = unpacked[3]
            self.sigfigs = unpacked[4]
            self.snaplen = unpacked[5]
            self.network = unpacked[6]
        except struct.error as e:
            raise PcapReaderError(f"Failed to parse global header: {e}")
            
        if self.magic_number != self.MAGIC_NUMBER:
            raise PcapReaderError(
                f"Invalid magic number: {hex(self.magic_number)}. "
                f"Expected {hex(self.MAGIC_NUMBER)}. "
                "Is this a valid PCAP file (not PCAPNG)?"
            )
            
        if self.version_major != 2 or self.version_minor != 4:
            # Usually we support 2.4, warn if different but don't strictly fail unless it's totally off
            pass

    def read_packet(self) -> Optional[bytes]:
        """
        Read the next packet from the file.
        
        Returns:
            Raw bytes of the next packet (link layer payload), or None if EOF.
            
        Raises:
            PcapReaderError: If the packet header is malformed
        """
        header_data = self.file.read(self.PACKET_HEADER_SIZE)
        
        # Check for EOF
        if len(header_data) == 0:
            return None
            
        if len(header_data) < self.PACKET_HEADER_SIZE:
            raise PcapReaderError("Incomplete packet header at end of file")
            
        try:
            # Unpack packet header
            (ts_sec, ts_usec, incl_len, orig_len) = struct.unpack(
                self.PACKET_HEADER_FORMAT, header_data
            )
        except struct.error as e:
            raise PcapReaderError(f"Failed to parse packet header: {e}")
            
        # Read packet data
        # We read incl_len bytes (captured length)
        packet_data = self.file.read(incl_len)
        
        if len(packet_data) < incl_len:
            raise PcapReaderError(
                f"Incomplete packet data: expected {incl_len} bytes, "
                f"got {len(packet_data)}"
            )
            
        return packet_data

    def close(self):
        """Close the file."""
        if self.file:
            self.file.close()
            self.file = None

    def __iter__(self) -> Iterator[bytes]:
        """Iterate over packets in the PCAP file."""
        return self

    def __next__(self) -> bytes:
        """Get the next packet."""
        packet = self.read_packet()
        if packet is None:
            self.close()
            raise StopIteration
        return packet

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()