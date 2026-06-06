"""
DNS Parser Module.
Parses raw bytes from UDP payload into DNSMessage objects.
Supports basic parsing of DNS Queries and Responses including name compression.
"""

import struct
from typing import Optional, List, Tuple
from packet_structures import DNSHeader, DNSQuestion, DNSResourceRecord, DNSMessage


def parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Parse a DNS domain name from the byte array.
    Handles compression pointers (0xC0) and standard labels.
    
    Args:
        data: The full packet bytes.
        offset: Starting offset of the name.
        
    Returns:
        Tuple of (name_string, new_offset).
        
    Raises:
        ValueError: If parsing fails.
    """
    labels = []
    original_offset = offset
    jumped = False
    max_loops = 10 # Safety break for circular pointers
    
    while max_loops > 0:
        if offset >= len(data):
            raise ValueError("Offset out of bounds while parsing DNS name")
            
        length = data[offset]
        
        # Check for end of name (0x00)
        if length == 0:
            if not jumped:
                offset += 1
            break
            
        # Check for compression pointer (top 2 bits are 11)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Incomplete compression pointer")
                
            # Read the pointer offset (lower 14 bits)
            pointer = struct.unpack('!H', data[offset:offset+2])[0]
            pointer &= 0x3FFF
            
            if not jumped:
                # Only update the return offset if we haven't jumped yet
                offset += 2
                
            # Continue parsing from the new pointer
            offset = pointer
            jumped = True
            max_loops -= 1
            continue
            
        # Standard label
        if offset + 1 + length > len(data):
            raise ValueError("Label extends beyond packet data")
            
        label_bytes = data[offset+1:offset+1+length]
        try:
            labels.append(label_bytes.decode('ascii'))
        except UnicodeDecodeError:
            labels.append("<binary>")
            
        offset += 1 + length
        
    if max_loops == 0:
        raise ValueError("Max compression jumps exceeded")
        
    return '.'.join(labels), offset


def parse_dns_header(data: bytes) -> Optional[DNSHeader]:
    """
    Parse the first 12 bytes of a DNS message.
    
    Args:
        data: Raw bytes of the DNS message.
        
    Returns:
        DNSHeader instance or None if data is too short.
    """
    if len(data) < 12:
        return None
        
    try:
        dns_id = struct.unpack('!H', data[0:2])[0]
        flags = struct.unpack('!H', data[2:4])[0]
        qdcount = struct.unpack('!H', data[4:6])[0]
        ancount = struct.unpack('!H', data[6:8])[0]
        nscount = struct.unpack('!H', data[8:10])[0]
        arcount = struct.unpack('!H', data[10:12])[0]
        
        return DNSHeader(
            id=dns_id,
            flags=flags,
            qd_count=qdcount,
            an_count=ancount,
            ns_count=nscount,
            ar_count=arcount
        )
    except struct.error:
        return None


def parse_dns_question(data: bytes, offset: int) -> Tuple[Optional[DNSQuestion], int]:
    """
    Parse a DNS Question section entry.
    
    Args:
        data: Raw bytes of the DNS message.
        offset: Starting offset.
        
    Returns:
        Tuple of (DNSQuestion or None, new_offset).
    """
    try:
        qname, offset = parse_dns_name(data, offset)
        
        if offset + 4 > len(data):
            return None, offset
            
        qtype = struct.unpack('!H', data[offset:offset+2])[0]
        qclass = struct.unpack('!H', data[offset+2:offset+4])[0]
        
        return DNSQuestion(
            qname=qname,
            qtype=qtype,
            qclass=qclass
        ), offset + 4
    except (ValueError, struct.error):
        return None, offset


def parse_dns_rr(data: bytes, offset: int) -> Tuple[Optional[DNSResourceRecord], int]:
    """
    Parse a DNS Resource Record.
    
    Args:
        data: Raw bytes of the DNS message.
        offset: Starting offset.
        
    Returns:
        Tuple of (DNSResourceRecord or None, new_offset).
    """
    try:
        name, offset = parse_dns_name(data, offset)
        
        if offset + 10 > len(data):
            return None, offset
            
        type_ = struct.unpack('!H', data[offset:offset+2])[0]
        class_ = struct.unpack('!H', data[offset+2:offset+4])[0]
        ttl = struct.unpack('!I', data[offset+4:offset+8])[0]
        rdlength = struct.unpack('!H', data[offset+8:offset+10])[0]
        
        offset += 10
        
        if offset + rdlength > len(data):
            return None, offset
            
        rdata = data[offset:offset+rdlength]
        
        return DNSResourceRecord(
            name=name,
            type=type_,
            class_=class_,
            ttl=ttl,
            rdlength=rdlength,
            rdata=rdata
        ), offset + rdlength
    except (ValueError, struct.error):
        return None, offset


def parse_dns_message(data: bytes) -> Optional[DNSMessage]:
    """
    Parse a complete DNS message from UDP payload.
    
    Args:
        data: Raw bytes of the DNS payload (starts with header).
        
    Returns:
        DNSMessage instance or None if parsing fails.
    """
    if len(data) < 12:
        return None
        
    header = parse_dns_header(data)
    if header is None:
        return None
        
    offset = 12
    
    # Parse Questions
    questions = []
    for _ in range(header.qd_count):
        if offset >= len(data):
            break
        q, offset = parse_dns_question(data, offset)
        if q:
            questions.append(q)
        else:
            # Malformed, stop processing
            return None
            
    # Parse Answers
    answers = []
    for _ in range(header.an_count):
        if offset >= len(data):
            break
        a, offset = parse_dns_rr(data, offset)
        if a:
            answers.append(a)
            
    # Parse Authorities
    authorities = []
    for _ in range(header.ns_count):
        if offset >= len(data):
            break
        a, offset = parse_dns_rr(data, offset)
        if a:
            authorities.append(a)
            
    # Parse Additionals
    additionals = []
    for _ in range(header.ar_count):
        if offset >= len(data):
            break
        a, offset = parse_dns_rr(data, offset)
        if a:
            additionals.append(a)
            
    return DNSMessage(
        header=header,
        questions=questions,
        answers=answers,
        authorities=authorities,
        additionals=additionals
    )