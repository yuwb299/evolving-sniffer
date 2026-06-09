"""
Tests for tls_parser module.
"""

import pytest
import struct
from tls_parser import (
    parse_tls_record,
    parse_tls_handshake,
    parse_client_hello,
    parse_extensions
)
from packet_structures import TLSRecord, TLSHandshake


def build_tls_client_hello_raw(version=0x0303, sni=b"example.com"):
    """
    Helper to build a raw ClientHello message.
    Returns: bytes (Handshake Message: Type + Length + Body)
    """
    # Handshake Header
    hs_type = 0x01 # ClientHello
    
    # Body
    # Version (2)
    body = struct.pack('!H', version)
    # Random (32)
    body += b'\x00' * 32
    # Session ID (1 len + 0 data)
    body += b'\x00'
    # Cipher Suites (2 len + 2 data)
    body += struct.pack('!HH', 2, 0x002F) # TLS_RSA_WITH_AES_128_CBC_SHA
    # Compression (1 len + 1 data)
    body += struct.pack('!BB', 1, 0x00) # NULL
    
    # Extensions
    ext_data = b''
    if sni:
        # Build SNI Extension
        sni_entry = b'\x00' # Name Type (host_name)
        sni_entry += struct.pack('!H', len(sni))
        sni_entry += sni
        
        sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
        
        sni_ext = struct.pack('!HH', 0x0000, len(sni_list)) + sni_list # Type 0, Length
        ext_data = sn