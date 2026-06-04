"""
Tests for pcap_reader module.
"""

import pytest
import struct
import os
import tempfile
from pcap_reader import PcapReader, PcapReaderError


def create_pcap_buffer(packets_data):
    """
    Helper to create a valid PCAP file byte buffer from a list of raw packet bytes.
    This mimics the structure of a .pcap file for testing without external dependencies.
    """
    buffer = bytearray()
    
    # Global Header
    # Magic: 0xa1b2c3d4
    # Version: 2.4
    # Thiszone: 0
    # Sigfigs: 0
    # Snaplen: 65535
    # Network: 1 (Ethernet)
    global_header = struct.pack(
        '!IHHiIII',
        0xa1b2c3d4, 2, 4, 0, 0, 65535, 1
    )
    buffer.extend(global_header)
    
    # Packet Headers and Data
    ts_sec = 1234567890
    ts_usec = 0
    
    for pkt in packets_data:
        incl_len = len(pkt)
        orig_len = len(pkt)
        pkt_header = struct.pack(
            '!IIII',
            ts_sec, ts_usec, incl_len, orig_len
        )
        buffer.extend(pkt_header)
        buffer.extend(pkt)
        ts_usec += 1  # Increment timestamp slightly for uniqueness
        
    return bytes(buffer)


class TestPcapReaderInit:
    """Tests for PcapReader initialization and global header parsing."""
    
    def test_valid_pcap_file(self):
        """Test opening a valid PCAP file."""
        data = create_pcap_buffer([b'\x00' * 20])
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            fname = f.name
        
        try:
            reader = PcapReader(fname)
            assert reader.magic_number == 0xa1b2c3d4
            assert reader.version_major == 2
            assert reader.version_minor == 4
            assert reader.snaplen == 65535
            assert reader.network == 1  # Ethernet
            reader.close()
        finally:
            os.unlink(fname)
    
    def test_invalid_magic_number(self):
        """Test that opening a file with wrong magic number raises error."""
        # Create a file with wrong magic
        bad_header = struct.pack('!I', 0xDEADBEEF) + (b'\x00' * 20)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(bad_header)
            fname = f.name
            
        try:
            with pytest.raises(PcapReaderError, match="Invalid magic number"):
                PcapReader(fname)
        finally:
            os.unlink(fname)
            
    def test_file_too_short(self):
        """Test that a file shorter than global header raises error."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'\x00' * 10)
            fname = f.name
            
        try:
            with pytest.raises(PcapReaderError, match="File too short"):
                PcapReader(fname)
        finally:
            os.unlink(fname)

    def test_context_manager(self):
        """Test using PcapReader as a context manager."""
        data = create_pcap_buffer([])
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            fname = f.name
            
        try:
            with PcapReader(fname) as reader:
                assert reader is not None
            # File should be closed now, but checking implicitly by ensuring no errors
        finally:
            os.unlink(fname)


class TestReadPacket:
    """Tests for reading individual packets."""
    
    def test_read_single_packet(self):
        """Test reading one packet from a file."""
        # Minimal Ethernet frame: 14 bytes
        packet_payload = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) + \
                         bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]) + \
                         bytes([0x08, 0x00]) + \
                         bytes([0x45]) # Start of IP
        
        data = create_pcap_buffer([packet_payload])
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            fname = f.name
            
        try:
            reader = PcapReader(fname)
            pkt = reader.read_packet()
            assert pkt is not None
            assert pkt == packet_payload
            
            # Second read should return None (EOF)
            pkt2 = reader.read_packet()
            assert pkt2 is None
            reader.close()
        finally:
            os.unlink(fname)
            
    def test_read_multiple_packets(self):
        """Test reading multiple packets sequentially."""
        p1 = b'\x00' * 14
        p2 = b'\xFF' * 14
        p3 = b'\xAA' * 14
        
        data = create_pcap_buffer([p1, p2, p3])
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            fname = f.name
            
        try:
            reader = PcapReader(fname)
            assert reader.read_packet() == p1
            assert reader.read_packet() == p2
            assert reader.read_packet() == p3
            assert reader.read_packet() is None
            reader.close()
        finally:
            os.unlink(fname)
            
    def test_incomplete_packet_header(self):
        """Test handling of a file that cuts off mid-packet-header."""
        # Global header is valid
        gh = struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        # Packet header is incomplete (only 10 bytes instead of 16)
        bad_pkt_header = b'\x00' * 10
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(gh + bad_pkt_header)
            fname = f.name
            
        try:
            reader = PcapReader(fname)
            with pytest.raises(PcapReaderError, match="Incomplete packet header"):
                reader.read_packet()
            reader.close()
        finally:
            os.unlink(fname)
            
    def test_incomplete_packet_data(self):
        """Test handling of a file that claims X bytes but provides Y (< X)."""
        p1 = b'\x00' * 14
        # Start creating buffer for p2
        pkt_header_p2 = struct.pack('!IIII', 0, 0, 100, 100) # Claims 100 bytes
        incomplete_data = b'\xAA' * 10 # Only provides 10 bytes
        
        # Manually construct buffer to ensure this specific malformed scenario
        buffer = bytearray()
        buffer.extend(struct.pack('!IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        
        # Add packet 1 (valid)
        buffer.extend(struct.pack('!IIII', 0, 0, 14, 14))
        buffer.extend(p1)
        
        # Add packet 2 (malformed)
        buffer.extend(pkt_header_p2)
        buffer.extend(incomplete_data)
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(buffer)
            fname = f.name
            
        try:
            reader = PcapReader(fname)
            assert reader.read_packet() == p1
            with pytest.raises(PcapReaderError, match="Incomplete packet data"):
                reader.read_packet()
            reader.close()
        finally:
            os.unlink(fname)


class TestIteration:
    """Tests for iterating over the PcapReader."""
    
    def test_for_loop(self):
        """Test iterating over packets using a for loop."""
        packets = [b'P1', b'P2', b'P3', b'P4']
        data = create_pcap_buffer(packets)
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            fname = f.name
            
        try:
            results = []
            with PcapReader(fname) as reader:
                for packet in reader:
                    results.append(packet)
            
            assert results == packets
        finally:
            os.unlink(fname)
            
    def test_empty_file(self):
        """Test iterating over a PCAP file with no packets (only header)."""
        data = create_pcap_buffer([])
        
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            fname = f.name
            
        try:
            results = []
            with PcapReader(fname) as reader:
                for packet in reader:
                    results.append(packet)
            
            assert results == []
        finally:
            os.unlink(fname)