"""
SSH Parser Module.
Parses raw bytes from TCP payload into SSHMessage objects.
Supports identification of SSH banners (text) and binary packet headers.
"""

import struct
from typing import Optional
from packet_structures import SSHMessage


def parse_ssh_banner(data: bytes) -> Optional[SSHMessage]:
    """
    Parse the initial SSH identification string (Banner).
    Format: SSH-protoversion-softwareversion SP comments CR LF
    
    Args:
        data: Raw bytes of the TCP payload.
        
    Returns:
        SSHMessage instance if a banner is found, else None.
    """
    if not data.startswith(b"SSH-"):
        return None
        
    try:
        # Find the end of the banner line (CRLF or LF)
        idx = data.find(b"\r\n")
        if idx == -1:
            idx = data.find(b"\n")
        
        if idx == -1:
            # Incomplete banner, but we can still try to decode what we have
            banner_str = data.decode('ascii', errors='ignore').strip()
        else:
            banner_str = data[:idx].decode('ascii', errors='ignore')
            
        return SSHMessage(protocol_version=banner_str, payload=data)
    except UnicodeDecodeError:
        return None


def parse_ssh_binary_packet(data: bytes) -> Optional[SSHMessage]:
    """
    Parse the header of a binary SSH packet.
    
    Binary Packet Format:
    - Packet Length (uint32): 4 bytes
    - Padding Length (byte): 1 byte
    - Message Code (byte): 1 byte
    - Payload: variable
    
    Args:
        data: Raw bytes of the TCP payload.
        
    Returns:
        SSHMessage instance with binary header info, or None if too short.
    """
    if len(data) < 6:
        return None
        
    try:
        packet_length = struct.unpack('!I', data[0:4])[0]
        padding_length = data[4]
        message_code = data[5]
        
        return SSHMessage(
            packet_length=packet_length,
            padding_length=padding_length,
            message_code=message_code,
            payload=data
        )
    except struct.error:
        return None


def parse_ssh_message(data: bytes) -> Optional[SSHMessage]:
    """
    Attempt to parse an SSH message, trying banner first, then binary.
    
    Args:
        data: Raw bytes of the TCP payload.
        
    Returns:
        SSHMessage instance or None.
    """
    if not data:
        return None
        
    # 1. Check for Banner
    if data.startswith(b"SSH-"):
        return parse_ssh_banner(data)
    
    # 2. Check for Binary Packet
    # Binary packets usually start with a length. Since we are capturing streams,
    # we might see the start of a packet. Minimum binary header size is 6 bytes.
    return parse_ssh_binary_packet(data)
