"""
Live Capture Engine Module.
Provides functionality to capture raw packets from network interfaces on Linux
using raw sockets.
"""

import socket
import struct
import sys
from typing import Iterator, Optional


class CaptureError(Exception):
    """Base exception for capture engine errors."""
    pass


class LiveCapture:
    """
    Captures live network packets from a specified interface on Linux.
    
    This class uses raw sockets (AF_PACKET) to sniff packets. It requires
    root privileges to run.
    """
    
    # ETH_P_ALL: Capture all packets
    ETH_P_ALL = 0x0003
    
    def __init__(self, interface: str):
        """
        Initialize the live capture engine.
        
        Args:
            interface: The name of the network interface (e.g., 'eth0', 'wlan0').
            
        Raises:
            ValueError: If the interface name is empty.
            OSError: If the system is not Linux.
        """
        if not interface:
            raise ValueError("Interface name cannot be empty")
            
        if sys.platform != "linux":
            raise OSError("LiveCapture is only supported on Linux")
            
        self.interface = interface
        self.socket: Optional[socket.socket] = None
        
    def __enter__(self):
        """Start the capture session (Context Manager)."""
        self.start()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop the capture session (Context Manager)."""
        self.stop()
        
    def start(self):
        """
        Open the raw socket and bind to the interface.
        
        Raises:
            CaptureError: If socket creation or binding fails.
            PermissionError: If the user does not have root privileges.
        """
        try:
            # Create a raw socket to capture at the Ethernet layer
            # socket.AF_PACKET: Packet interface on Linux
            # socket.SOCK_RAW: Raw packets
            # socket.htons(0x0003): All protocols (ETH_P_ALL)
            self.socket = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(self.ETH_P_ALL)
            )
            
            # Bind the socket to the specific interface
            # The 0 in the tuple (proto) is ignored for SOCK_RAW, but required by bind
            self.socket.bind((self.interface, 0))
            
        except PermissionError:
            raise PermissionError(
                "Raw socket requires root privileges. Please run as root or with sudo."
            )
        except OSError as e:
            raise CaptureError(f"Failed to start capture on {self.interface}: {e}")
            
    def stop(self):
        """Close the raw socket."""
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
            finally:
                self.socket = None
                
    def __iter__(self) -> Iterator[bytes]:
        """Return the iterator object."""
        return self
        
    def __next__(self) -> bytes:
        """
        Capture the next packet.
        
        This method blocks until a packet is received.
        
        Returns:
            Raw bytes of the captured packet (including Ethernet header).
            
        Raises:
            RuntimeError: If the capture has not been started.
            CaptureError: If receiving data fails.
        """
        if not self.socket:
            raise RuntimeError("Capture is not started. Call start() or use 'with' statement.")
            
        try:
            # Buffer size 65535 is the maximum possible IP packet size
            packet_data, _ = self.socket.recvfrom(65535)
            return packet_data
        except OSError as e:
            raise CaptureError(f"Failed to receive packet: {e}")

    def recv(self, bufsize: int = 65535) -> Optional[bytes]:
        """
        Receive a single packet. Non-iterative alternative to next().
        
        Args:
            bufsize: Maximum amount of data to be received at once.
            
        Returns:
            Raw bytes of the packet or None if an error occurs.
        """
        try:
            return self.__next__()
        except (CaptureError, RuntimeError):
            return None
