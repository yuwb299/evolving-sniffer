"""
FTP Parser Module.
Parses raw bytes from TCP payload into FTPCommand or FTPResponse objects.
FTP is a text-based protocol running over TCP (usually port 21).
"""

import re
from typing import Optional
from packet_structures import FTPCommand, FTPResponse


def parse_ftp_command(data: bytes) -> Optional[FTPCommand]:
    """
    Parse raw bytes into an FTPCommand.
    
    FTP Command format: <verb> <parameters>\r\n
    Common verbs: USER, PASS, LIST, RETR, STOR, QUIT, CWD, PWD, PASV, PORT, SYST, TYPE.
    
    Args:
        data: Raw bytes of the TCP payload.
        
    Returns:
        FTPCommand instance or None if parsing fails.
    """
    try:
        # FTP is ASCII
        text = data.decode('ascii', errors='ignore')
    except UnicodeDecodeError:
        return None

    # Remove trailing whitespace (CRLF or LF)
    text = text.strip()
    
    if not text:
        return None

    # Split by whitespace to get command and arguments
    parts = text.split(None, 1) # Split on first whitespace
    
    if not parts:
        return None
        
    cmd = parts[0].upper()
    
    # Check if it looks like a valid FTP command (3-4 chars, alpha)
    # Allow some flexibility for extensions, but strict length helps avoid false positives
    if not re.match(r'^[A-Z]{3,4}$', cmd):
        # Common extensions might be longer, but basic commands are short.
        # If it's very long, maybe not a command. Let's say max 10 chars.
        if len(cmd) > 10:
            return None
            
    args = parts[1] if len(parts) > 1 else ""
    
    try:
        return FTPCommand(command=cmd, args=args)
    except ValueError:
        return None


def parse_ftp_response(data: bytes) -> Optional[FTPResponse]:
    """
    Parse raw bytes into an FTPResponse.
    
    FTP Response format: <code> <message>\r\n
    Code is a 3-digit number.
    
    Args:
        data: Raw bytes of the TCP payload.
        
    Returns:
        FTPResponse instance or None if parsing fails.
    """
    try:
        text = data.decode('ascii', errors='ignore')
    except UnicodeDecodeError:
        return None

    text = text.strip()
    
    if len(text) < 3:
        return None
        
    # Check first 3 characters are digits
    code_str = text[:3]
    if not code_str.isdigit():
        return None
        
    try:
        code = int(code_str)
        message = text[3:].strip()
        
        # Ensure code is in valid FTP range (100-599 approx)
        if not (100 <= code <= 599):
            return None
            
        return FTPResponse(code=code, message=message)
    except ValueError:
        return None


def is_ftp_payload(data: bytes) -> bool:
    """
    Heuristic check to see if data looks like FTP.
    
    Args:
        data: Raw bytes.
        
    Returns:
        True if likely FTP, False otherwise.
    """
    if len(data) < 3:
        return False
        
    try:
        text = data[:10].decode('ascii')
    except UnicodeDecodeError:
        return False
        
    # Check for response codes (e.g. 220, 226, 230)
    if text[0:3].isdigit() and (text[3] == ' ' or text[3] == '-'):
        return True
        
    # Check for common commands
    ftp_commands = ['USER', 'PASS', 'LIST', 'RETR', 'STOR', 'QUIT', 'CWD', 'PWD', 'PASV', 'PORT', 'SYST', 'TYPE', 'NOOP', 'FEAT']
    parts = text.split()
    if parts and parts[0] in ftp_commands:
        return True
        
    return False