"""
TLS Parser Module.
Parses raw bytes from TCP payload into TLSRecord and TLSHandshake objects.
Supports basic TLS 1.0-1.3 parsing, specifically extracting SNI from ClientHello.
"""

import struct
from typing import Optional, Tuple
from packet_structures import TLSRecord, TLSHandshake


def parse_tls_record(data: bytes) -> Optional[TLSRecord]:
    """
    Parse the TLS Record Layer header (5 bytes).
    
    Structure:
    - Content Type: 1 byte
    - Version: 2 bytes (major, minor)
    - Length: 2 bytes
    
    Args:
        data: Raw bytes of the TCP payload (should start with TLS record).
        
    Returns:
        TLSRecord instance or None if parsing fails.
    """
    if len(data) < 5:
        return None
        
    try:
        content_type = data[0]
        version = struct.unpack('!H', data[1:3])[0]
        length = struct.unpack('!H', data[3:5])[0]
        
        # Payload follows header. 
        # If the available data is shorter than length, we just take what we have (truncated capture)
        available_payload_len = len(data) - 5
        payload_len = min(length, available_payload_len)
        payload = data[5:5+payload_len]
            
        return TLSRecord(
            content_type=content_type,
            version=version,
            length=length,
            payload=payload
        )
    except struct.error:
        return None


def parse_extensions(data: bytes) -> Tuple[Optional[str], bytes]:
    """
    Parse TLS Extensions block to find Server Name Indication (SNI).
    
    Args:
        data: Bytes of the extensions block.
        
    Returns:
        Tuple of (SNI string or None, remaining bytes).
    """
    if len(data) < 2:
        return None, data
        
    extensions_length = struct.unpack('!H', data[0:2])[0]
    if len(data) < 2 + extensions_length:
        return None, data
        
    offset = 2
    sni = None
    
    # Loop through extensions
    # Format: Type(2) | Length(2) | Data(Length)
    while offset < 2 + extensions_length:
        if offset + 4 > len(data):
            break
            
        ext_type = struct.unpack('!H', data[offset:offset+2])[0]
        ext_len = struct.unpack('!H', data[offset+2:offset+4])[0]
        
        offset += 4
        
        # SNI Extension Type is 0x0000
        if ext_type == 0x0000 and sni is None:
            # Parse SNI from the extension data
            # SNI Extension Data:
            #   List Length (2 bytes)
            #   Entry Type (1 byte, 0 = hostname)
            #   Name Length (2 bytes)
            #   Name Data
            ext_data_start = offset
            if ext_data_start + 2 <= len(data):
                sni_list_len = struct.unpack('!H', data[ext_data_start:ext_data_start+2])[0]
                name_offset = ext_data_start + 2
                
                if name_offset + 3 <= len(data):
                    # Entry Type (1 byte)
                    name_type = data[name_offset]
                    name_len = struct.unpack('!H', data[name_offset+1:name_offset+3])[0]
                    name_start = name_offset + 3
                    name_end = name_start + name_len
                    
                    if name_end <= len(data) and name_type == 0:
                        try:
                            sni = data[name_start:name_end].decode('ascii')
                        except UnicodeDecodeError:
                            pass  # Invalid ASCII, ignore
                                
        offset += ext_len
        
    return sni, data[2 + extensions_length:]


def parse_client_hello(data: bytes) -> Optional[TLSHandshake]:
    """
    Parse a TLS ClientHello message to extract basic info and SNI.
    
    Args:
        data: Raw bytes of the Handshake payload (excluding Handshake header).
        
    Returns:
        TLSHandshake instance populated with SNI if found, or None.
    """
    # ClientHello Structure:
    # Version (2)
    # Random (32)
    # Session ID (1 len + data)
    # Cipher Suites (2 len + data)
    # Compression Methods (1 len + data)
    # Extensions (2 len + data)
    
    # Minimal check for version + random + session_id_len
    if len(data) < 38:
        return None
        
    try:
        # Skip Version (2) and Random (32)
        offset = 34
        
        # Session ID
        if offset >= len(data): 
            return None
        sid_len = data[offset]
        offset += 1 + sid_len
        
        # Cipher Suites
        if offset + 2 > len(data): 
            return None
        cipher_len = struct.unpack('!H', data[offset:offset+2])[0]
        offset += 2 + cipher_len
        
        # Compression Methods
        if offset >= len(data): 
            return None
        comp_len = data[offset]
        offset += 1 + comp_len
        
        # Extensions (optional - may not be present)
        sni = None
        if offset < len(data):
            if offset + 2 > len(data): 
                return None
            # The data from here onwards is the extensions block
            ext_data = data[offset:]
            sni, _ = parse_extensions(ext_data)
        
        return TLSHandshake(
            handshake_type=TLSHandshake.CLIENT_HELLO,
            length=len(data),
            payload=data,
            sni=sni
        )
        
    except (struct.error, IndexError):
        return None


def parse_tls_handshake(data: bytes) -> Optional[TLSHandshake]:
    """
    Parse a generic TLS Handshake message header.
    
    Args:
        data: Raw bytes of the Handshake message (Type + Length + Payload).
        
    Returns:
        TLSHandshake instance or None.
    """
    if len(data) < 4:
        return None
        
    try:
        msg_type = data[0]
        # Length is 3 bytes
        length = (data[1] << 16) | (data[2] << 8) | data[3]
        payload = data[4:]
        
        handshake = TLSHandshake(
            handshake_type=msg_type,
            length=length,
            payload=payload
        )
        
        # If ClientHello, try to parse deeper for SNI
        if msg_type == TLSHandshake.CLIENT_HELLO:
            client_hello = parse_client_hello(payload)
            if client_hello:
                handshake.sni = client_hello.sni
                
        return handshake
        
    except (struct.error, IndexError):
        return None