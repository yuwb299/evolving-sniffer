"""
HTTP Parser Module.
Parses raw bytes from TCP payload into HTTPRequest or HTTPResponse objects.
Supports basic HTTP/1.x parsing.
"""

import re
from typing import Optional, Dict, Tuple
from packet_structures import HTTPRequest, HTTPResponse


def parse_http_headers(lines: list) -> Dict[str, str]:
    """
    Parse header lines into a dictionary.
    
    Args:
        lines: List of strings representing header lines.
        
    Returns:
        Dictionary of headers.
    """
    headers = {}
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    return headers


def parse_http_request(data: bytes) -> Optional[HTTPRequest]:
    """
    Parse raw bytes into an HTTPRequest.
    
    Args:
        data: Raw bytes of the TCP payload.
        
    Returns:
        HTTPRequest instance or None if parsing fails.
    """
    try:
        # Decode to string (UTF-8 is standard for HTTP headers, though technically ISO-8859-1)
        text = data.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        return None

    # Split headers from body
    # HTTP headers end with \r\n\r\n
    header_end = text.find('\r\n\r\n')
    if header_end == -1:
        return None  # Malformed or incomplete request
    
    header_block = text[:header_end]
    body = data[header_end + 4:]  # Body remains as bytes
    
    lines = header_block.split('\r\n')
    if len(lines) < 1:
        return None
        
    # Parse Request Line: METHOD PATH VERSION
    request_line = lines[0].strip()
    parts = request_line.split(' ')
    
    if len(parts) != 3:
        return None
        
    method, path, version = parts
    
    # Validate method loosely
    valid_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']
    if method not in valid_methods:
        return None
        
    # Parse headers
    headers = parse_http_headers(lines[1:])
    
    try:
        return HTTPRequest(
            method=method,
            path=path,
            version=version,
            headers=headers,
            body=body
        )
    except ValueError:
        return None


def parse_http_response(data: bytes) -> Optional[HTTPResponse]:
    """
    Parse raw bytes into an HTTPResponse.
    
    Args:
        data: Raw bytes of the TCP payload.
        
    Returns:
        HTTPResponse instance or None if parsing fails.
    """
    try:
        text = data.decode('utf-8', errors='ignore')
    except UnicodeDecodeError:
        return None

    header_end = text.find('\r\n\r\n')
    if header_end == -1:
        return None
        
    header_block = text[:header_end]
    body = data[header_end + 4:]
    
    lines = header_block.split('\r\n')
    if len(lines) < 1:
        return None
        
    # Parse Status Line: VERSION STATUS_CODE STATUS_TEXT
    status_line = lines[0].strip()
    
    # Use regex to be robust against extra spaces
    match = re.match(r'^HTTP/(\d\.\d)\s+(\d{3})\s+(.*)$', status_line, re.IGNORECASE)
    if not match:
        return None
        
    version = f"HTTP/{match.group(1)}"
    status_code = int(match.group(2))
    status_text = match.group(3)
    
    headers = parse_http_headers(lines[1:])
    
    try:
        return HTTPResponse(
            version=version,
            status_code=status_code,
            status_text=status_text,
            headers=headers,
            body=body
        )
    except ValueError:
        return None


def is_http_payload(data: bytes) -> bool:
    """
    Heuristic check to see if data looks like HTTP.
    
    Args:
        data: Raw bytes.
        
    Returns:
        True if likely HTTP, False otherwise.
    """
    if len(data) < 4:
        return False
        
    try:
        text = data[:4].decode('ascii')
    except UnicodeDecodeError:
        return False
        
    # Check for common HTTP methods or version strings
    http_prefixes = ['GET ', 'POST', 'PUT ', 'HEAD', 'DELE', 'OPTI', 'PATC', 'TRAC', 'CONN', 'HTTP']
    return any(text.startswith(prefix) for prefix in http_prefixes)
