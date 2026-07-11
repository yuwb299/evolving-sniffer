"""
PCAP File Writer Module.
Provides functionality to write network packet data to .pcap files.
"""

import struct
import time
import os
from typing import Optional


class PcapWriterError(Exception):
    """Base exception for PCAP writer errors."""
    pass


class PcapWriter:
    """
    Writes network packets to a PCAP file.
    
    Supports writing the standard PCAP format (Global Header followed by
    Packet Records).
    """
    
    # PCAP Global Header Magic Number
    MAGIC_NUMBER = 0xA1B2C3D4
    
    # PCAP Global Header format (24 bytes)
    GLOBAL_HEADER_FORMAT = '!IHHiIII'
    GLOBAL_HEADER_SIZE = 24
    
    # Packet Record Header format (16 bytes)
    PACKET_HEADER_FORMAT = '!IIII'
    PACKET_HEADER_SIZE = 16
    
    # Link Types
    LINKTYPE_NULL = 0
    LINKTYPE_ETHERNET = 1
    LINKTYPE_RAW = 101
    
    def __init__(self, filename: str, link_type: int = LINKTYPE_ETHERNET):
        """
        Initialize the writer with a PCAP file.
        
        Args:
            filename: Path to the .pcap file to create/overwrite.
            link_type: Data link type (e.g., 1 for Ethernet).
            
        Raises:
            PcapWriterError: If the file cannot be opened or written to.
        """
        self.filename = filename
        self.link_type = link_type
        self.file = None
        self._is_open = False
        
    def open(self):
        """Open the file and write the global header."""
        try:
            self.file = open(self.filename, 'wb')
            self._write_global_header()
            self._is_open = True
        except OSError as e:
            raise PcapWriterError(f"Failed to open file {self.filename} for writing: {e}")

    def _write_global_header(self):
        """Write the global PCAP header."""
        if not self.file:
            raise PcapWriterError("File is not open")
            
        # Magic: 0xa1b2c3d4
        # Version: 2.4
        # Thiszone: 0
        # Sigfigs: 0
        # Snaplen: 65535
        # Network: link_type
        header_data = struct.pack(
            self.GLOBAL_HEADER_FORMAT,
            self.MAGIC_NUMBER, 2, 4, 0, 0, 65535, self.link_type
        )
        self.file.write(header_data)
        
    def write_packet(self, data: bytes, ts_sec: Optional[int] = None, ts_usec: Optional[int] = None):
        """
        Write a packet to the PCAP file.
        
        Args:
            data: Raw bytes of the packet data.
            ts_sec: Timestamp seconds (Unix time). If None, uses current time.
            ts_usec: Timestamp microseconds. If None, uses current time.
            
        Raises:
            PcapWriterError: If the file is not open or writing fails.
        """
        if not self._is_open or not self.file:
            raise PcapWriterError("Writer is not open. Call open() first.")
            
        # Get current time if not provided
        if ts_sec is None or ts_usec is None:
            now = time.time()
            ts_sec = int(now)
            ts_usec = int((now - ts_sec) * 1_000_000)
            
        incl_len = len(data)
        orig_len = len(data)
        
        # Packet Header
        pkt_header = struct.pack(
            self.PACKET_HEADER_FORMAT,
            ts_sec, ts_usec, incl_len, orig_len
        )
        
        try:
            self.file.write(pkt_header)
            self.file.write(data)
        except OSError as e:
            raise PcapWriterError(f"Failed to write packet: {e}")

    def close(self):
        """Close the file."""
        if self.file:
            try:
                self.file.flush()
                self.file.close()
            except OSError:
                pass
            finally:
                self.file = None
                self._is_open = False

    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()