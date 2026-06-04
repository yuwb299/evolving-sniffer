"""
Tests for capture_engine module.
"""

import pytest
import socket
import sys
from unittest.mock import MagicMock, patch, call
from capture_engine import LiveCapture, CaptureError


# Skip tests on non-Linux platforms as the module itself is Linux-specific,
# though we mock the internals, the logic guards exist.
@pytest.mark.skipif(sys.platform != "linux", reason="Module is Linux specific only")
class TestLiveCaptureInit:
    """Tests for LiveCapture initialization."""
    
    def test_valid_interface(self):
        """Test initialization with a valid interface name."""
        cap = LiveCapture("eth0")
        assert cap.interface == "eth0"
        assert cap.socket is None
    
    def test_empty_interface(self):
        """Test that empty interface raises ValueError."""
        with pytest.raises(ValueError, match="Interface name cannot be empty"):
            LiveCapture("")
    
    @patch('sys.platform', 'win32')
    def test_unsupported_platform(self):
        """Test that initialization on Windows raises OSError."""
        with pytest.raises(OSError, match="LiveCapture is only supported on Linux"):
            LiveCapture("eth0")


@pytest.mark.skipif(sys.platform != "linux", reason="Module is Linux specific only")
class TestLiveCaptureStart:
    """Tests for starting the capture session."""
    
    @patch('socket.socket')
    def test_successful_start(self, mock_socket_class):
        """Test successful socket creation and binding."""
        mock_sock_instance = MagicMock()
        mock_socket_class.return_value = mock_sock_instance
        
        cap = LiveCapture("eth0")
        cap.start()
        
        # Verify socket creation arguments
        # AF_PACKET, SOCK_RAW, htons(0x0003)
        mock_socket_class.assert_called_once_with(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003)
        )
        
        # Verify bind arguments
        mock_sock_instance.bind.assert_called_once_with(("eth0", 0))
        
        assert cap.socket is not None
        
        cap.stop()

    @patch('socket.socket')
    def test_permission_error(self, mock_socket_class):
        """Test that PermissionError is wrapped/re-raised correctly."""
        mock_socket_class.side_effect = PermissionError("Operation not permitted")
        
        cap = LiveCapture("eth0")
        with pytest.raises(PermissionError, match="root privileges"):
            cap.start()

    @patch('socket.socket')
    def test_os_error(self, mock_socket_class):
        """Test that OSError during socket creation is wrapped."""
        mock_socket_class.side_effect = OSError("Network unreachable")
        
        cap = LiveCapture("eth0")
        with pytest.raises(CaptureError, match="Failed to start capture"):
            cap.start()
            
    @patch('socket.socket')
    def test_bind_os_error(self, mock_socket_class):
        """Test that OSError during bind is wrapped."""
        mock_sock_instance = MagicMock()
        mock_sock_instance.bind.side_effect = OSError("No such device")
        mock_socket_class.return_value = mock_sock_instance
        
        cap = LiveCapture("nonexistent")
        with pytest.raises(CaptureError, match="Failed to start capture"):
            cap.start()


@pytest.mark.skipif(sys.platform != "linux", reason="Module is Linux specific only")
class TestLiveCaptureIteration:
    """Tests for packet iteration and receiving."""
    
    @patch('socket.socket')
    def test_context_manager(self, mock_socket_class):
        """Test using LiveCapture as a context manager."""
        mock_sock_instance = MagicMock()
        mock_socket_class.return_value = mock_sock_instance
        
        with LiveCapture("eth0") as cap:
            assert cap.socket is not None
            mock_sock_instance.bind.assert_called_once()
            
        # Verify close is called after exiting context
        mock_sock_instance.close.assert_called_once()

    @patch('socket.socket')
    def test_next_packet(self, mock_socket_class):
        """Test capturing a packet using next()."""
        fake_packet = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
                             0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                             0x08, 0x00])
        
        mock_sock_instance = MagicMock()
        mock_sock_instance.recvfrom.return_value = (fake_packet, None)
        mock_socket_class.return_value = mock_sock_instance
        
        cap = LiveCapture("eth0")
        cap.start()
        
        # Capture one packet
        packet = next(cap)
        
        assert packet == fake_packet
        mock_sock_instance.recvfrom.assert_called_once_with(65535)
        
        cap.stop()

    @patch('socket.socket')
    def test_multiple_packets(self, mock_socket_class):
        """Test capturing multiple packets in a loop."""
        packets_data = [
            b"PACKET_1_DATA",
            b"PACKET_2_DATA",
            b"PACKET_3_DATA"
        ]
        
        mock_sock_instance = MagicMock()
        # Side effect allows returning different values on subsequent calls
        mock_sock_instance.recvfrom.side_effect = [(p, None) for p in packets_data]
        mock_socket_class.return_value = mock_sock_instance
        
        results = []
        with LiveCapture("eth0") as cap:
            for i in range(3):
                results.append(next(cap))
                
        assert results == packets_data

    @patch('socket.socket')
    def test_recv_method(self, mock_socket_class):
        """Test using the recv() wrapper method."""
        fake_packet = b"DATA"
        mock_sock_instance = MagicMock()
        mock_sock_instance.recvfrom.return_value = (fake_packet, None)
        mock_socket_class.return_value = mock_sock_instance
        
        with LiveCapture("eth0") as cap:
            data = cap.recv()
            
        assert data == fake_packet

    @patch('socket.socket')
    def test_next_without_start(self, mock_socket_class):
        """Test calling next() without starting raises RuntimeError."""
        # We don't patch socket creation here, we just init and call next
        cap = LiveCapture("eth0")
        # Don't call start()
        
        with pytest.raises(RuntimeError, match="Capture is not started"):
            next(cap)

    @patch('socket.socket')
    def test_recv_os_error(self, mock_socket_class):
        """Test that OSError during recv is wrapped."""
        mock_sock_instance = MagicMock()
        mock_sock_instance.recvfrom.side_effect = OSError("Socket closed")
        mock_socket_class.return_value = mock_sock_instance
        
        with LiveCapture("eth0") as cap:
            with pytest.raises(CaptureError, match="Failed to receive packet"):
                next(cap)
                
    @patch('socket.socket')
    def test_custom_bufsize(self, mock_socket_class):
        """Test that recv can be called with a custom bufsize if implemented (not in next, but conceptually)."""
        # Current implementation of __next__ is hardcoded, but recv() calls next()
        # This test verifies the default behavior is maintained
        mock_sock_instance = MagicMock()
        mock_sock_instance.recvfrom.return_value = (b"X", None)
        mock_socket_class.return_value = mock_sock_instance
        
        with LiveCapture("eth0") as cap:
            cap.recv(1024) # Argument ignored in current impl, but ensures it doesn't crash
            mock_sock_instance.recvfrom.assert_called() # Called with default 65535 in next()
