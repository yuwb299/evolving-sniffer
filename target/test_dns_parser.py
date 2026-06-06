"""
Tests for dns_parser module.
"""

import pytest
import struct
from dns_parser import (
    parse_dns_header,
    parse_dns_name,
    parse_dns_question,
    parse_dns_rr,
    parse_dns_message
)
from packet_structures import DNSHeader, DNSQuestion, DNSResourceRecord


def build_dns_query_packet(name="example.com"):
    """Helper to build a simple DNS query packet."""
    # ID=1234, Flags=0x0100 (RD), QD=1
    header = struct.pack('!HHHHHH', 1234, 0x0100, 1, 0, 0, 0)
    
    # Question
    qname_parts = name.split('.')
    qname = b''
    for part in qname_parts:
        qname += bytes([len(part)]) + part.encode('ascii')
    qname += b'\x00'
    qtype_qclass = struct.pack('!HH', 1, 1) # Type A, Class IN
    
    return header + qname + qtype_qclass


def build_dns_response_packet():
    """Helper to build a simple DNS response packet."""
    # ID=1234, Flags=0x8180 (QR, RD, RA), QD=1, AN=1
    header = struct.pack('!HHHHHH', 1234, 0x8180, 1, 1, 0, 0)
    
    # Question (example.com)
    qname = b'\x07example\x03com\x00'
    qtype_qclass = struct.pack('!HH', 1, 1)
    
    # Answer (example.com A 93.184.216.34)
    # Name pointer to 0x0C (start of qname)
    rname = struct.pack('!H', 0xC00C) 
    rtype = struct.pack('!H', 1)
    rclass = struct.pack('!H', 1)
    rttl = struct.pack('!I', 3600)
    rdlength = struct.pack('!H', 4)
    rdata = b'\x5d\xb8\xd8\x22' # 93.184.216.34
    
    return header + qname + qtype_qclass + rname + rtype + rclass + rttl + rdlength + rdata


class TestParseDnsHeader:
    """Tests for parse_dns_header."""
    
    def test_valid_header(self):
        data = struct.pack('!HHHHHH', 1234, 0x0100, 1, 0, 0, 0)
        hdr = parse_dns_header(data)
        assert hdr is not None
        assert hdr.id == 1234
        assert hdr.flags == 0x0100
        assert hdr.qd_count == 1
        assert hdr.an_count == 0
        
    def test_too_short(self):
        data = b'\x00' * 11
       