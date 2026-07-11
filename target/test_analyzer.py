"""
Tests for analyzer module (Main Controller).
"""

import pytest
import sys
from unittest.mock import MagicMock, patch, call, mock_open
from io import StringIO

from analyzer import AnalyzerController, main
from packet_structures import Packet, IPHeader, TCPHeader, UDPHeader, DNSHeader, DNSMessage, DNSQuestion


class TestAnalyzerController:
    """Tests for AnalyzerController class logic."""

    def test_init_mutually_exclusive(self):
        """Test that providing both or neither interface/pcap raises ValueError."""
        with pytest.raises(ValueError, match="Please specify either"):
            AnalyzerController(interface="eth0", pcap_file="test.pcap")

        with pytest.raises(ValueError, match="Please specify either"):
            AnalyzerController()

    def test_init_valid_interface(self):
        """Test initialization with interface only."""
        ctrl = AnalyzerController(interface="eth0")
        assert ctrl.interface == "eth0"
        assert ctrl.pcap_file is None
        assert ctrl.running is True
        assert ctrl.protocol_filter is None
        assert ctrl.write_file is None

    def test_init_valid_pcap(self):
        """Test initialization with pcap only."""
        ctrl = AnalyzerController(pcap_file="test.pcap")
        assert ctrl.interface is None
        assert ctrl.pcap_file == "test.pcap"
        assert ctrl.running is True
        assert ctrl.protocol_filter is None
        assert ctrl.write_file is None

    def test_init_with_filter(self):
        """Test initialization with a protocol filter."""
        ctrl = AnalyzerController(interface="eth0", protocol_filter="HTTP")
        assert ctrl.protocol_filter == "HTTP"

    def test_init_with_write_file(self):
        """Test initialization with a write file."""
        ctrl = AnalyzerController(interface="eth0", write_file="out.pcap")
        assert ctrl.write_file == "out.pcap"

    @patch('builtins.print')
    def test_handle_signal(self, mock_print):
        """Test signal handler sets running to False."""
        ctrl = AnalyzerController(interface="eth0")
        
        # Simulate signal handler call
        ctrl._handle_signal(2, None) # SIGINT is usually 2
        
        assert ctrl.running is False
        mock_print.assert_called_with("\n[!] Stopping capture...")

    def test_matches_filter_none(self):
        """Test that _matches_filter returns True when no filter is set."""
        ctrl = AnalyzerController(interface="eth0")
        packet = MagicMock()
        packet.protocol_type = "TCP"
        assert ctrl._matches_filter(packet) is True

    def test_matches_filter_positive(self):
        """Test that _matches_filter returns True for matching protocol."""
        ctrl = AnalyzerController(interface="eth0", protocol_filter="DNS")
        packet = MagicMock()
        packet.protocol_type = "DNS"
        assert ctrl._matches_filter(packet) is True

    def test_matches_filter_negative(self):
        """Test that _matches_filter returns False for non-matching protocol."""
        ctrl = AnalyzerController(interface="eth0", protocol_filter="HTTP")
        packet = MagicMock()
        packet.protocol_type = "TCP"
        assert ctrl._matches_filter(packet) is False

    def test_matches_filter_case_insensitive(self):
        """Test that protocol filtering is case-insensitive."""
        ctrl = AnalyzerController(interface="eth0", protocol_filter="http")
        packet = MagicMock()
        packet.protocol_type = "HTTP"
        assert ctrl._matches_filter(packet) is True
        
        packet.protocol_type = "http"
        assert ctrl._matches_filter(packet) is True

    @patch('analyzer.process_packet')
    @patch('analyzer.LiveCapture')
    @patch('builtins.print')
    def test_live_capture_loop(self, mock_print, mock_live_capture_class, mock_process_packet):
        """Test the live capture iteration loop."""
        # Setup mocks
        mock_capture_instance = MagicMock()
        mock_live_capture_class.return_value.__enter__.return_value = mock_capture_instance
        
        # Create two fake packets
        raw_pkt_1 = b"PACKET_1"
        raw_pkt_2 = b"PACKET_2"
        
        # Define sequence of returns: Packet 1, Packet 2, then raise StopIteration or RuntimeError
        mock_capture_instance.__next__.side_effect = [raw_pkt_1, raw_pkt_2, RuntimeError("Socket closed")]
        
        # Mock process_packet to return a dummy object with a summary method
        mock_pkt_obj_1 = MagicMock()
        mock_pkt_obj_1.summary.return_value = "Summary 1"
        mock_pkt_obj_1.protocol_type = "TCP"
        
        mock_pkt_obj_2 = MagicMock()
        mock_pkt_obj_2.summary.return_value = "Summary 2"
        mock_pkt_obj_2.protocol_type = "UDP"
        
        mock_process_packet.side_effect = [mock_pkt_obj_1, mock_pkt_obj_2]
        
        # Run
        ctrl = AnalyzerController(interface="eth0")
        ctrl.start_live_capture()
        
        # Assertions
        assert mock_process_packet.call_count == 2
        mock_process_packet.assert_any_call(raw_pkt_1)
        mock_process_packet.assert_any_call(raw_pkt_2)
        
        # Verify summaries were printed
        assert mock_print.call_count >= 2 # Plus the header prints
        print_calls = [str(c) for c in mock_print.call_args_list]
        assert any("Summary 1" in c for c in print_calls)
        assert any("Summary 2" in c for c in print_calls)

    @patch('analyzer.process_packet')
    @patch('analyzer.LiveCapture')
    @patch('builtins.print')
    @patch('analyzer.PcapWriter')
    def test_live_capture_with_write(self, mock_writer_class, mock_print, mock_live_capture_class, mock_process_packet):
        """Test that writing works in live capture."""
        mock_capture_instance = MagicMock()
        mock_live_capture_class.return_value.__enter__.return_value = mock_capture_instance
        
        raw_pkt_1 = b"PACKET_TCP"
        raw_pkt_2 = b"PACKET_UDP"
        
        mock_capture_instance.__next__.side_effect = [raw_pkt_1, raw_pkt_2, RuntimeError("Done")]
        
        pkt_1 = MagicMock()
        pkt_1.summary.return_value = "TCP Packet"
        pkt_1.protocol_type = "TCP"
        
        pkt_2 = MagicMock()
        pkt_2.summary.return_value = "UDP Packet"
        pkt_2.protocol_type = "UDP"
        
        mock_process_packet.side_effect = [pkt_1, pkt_2]
        
        mock_writer_instance = MagicMock()
        mock_writer_class.return_value = mock_writer_instance
        
        # Run with write file
        ctrl = AnalyzerController(interface="eth0", write_file="out.pcap")
        ctrl.start_live_capture()
        
        # Verify writer was instantiated and opened
        mock_writer_class.assert_called_once_with("out.pcap")
        mock_writer_instance.open.assert_called_once()
        
        # Verify write_packet was called for each packet
        assert mock_writer_instance.write_packet.call_count == 2
        mock_writer_instance.write_packet.assert_any_call(raw_pkt_1)
        mock_writer_instance.write_packet.assert_any_call(raw_pkt_2)
        
        # Verify writer was closed
        mock_writer_instance.close.assert_called_once()

    @patch('analyzer.process_packet')
    @patch('analyzer.PcapReader')
    @patch('builtins.print')
    def test_pcap_analysis_loop(self, mock_print, mock_pcap_reader_class, mock_process_packet):
        """Test the pcap analysis iteration loop."""
        # Setup mocks
        mock_reader_instance = MagicMock()
        mock_pcap_reader_class.return_value.__enter__.return_value = mock_reader_instance
        
        raw_pkt_1 = b"PCAP_PKT_1"
        raw_pkt_2 = b"PCAP_PKT_2"
        raw_pkt_3 = b"PCAP_PKT_3"
        
        # Reader iterator
        mock_reader_instance.__iter__.return_value = iter([raw_pkt_1, raw_pkt_2, raw_pkt_3])
        
        # Mock process_packet
        mock_pkt_obj = MagicMock()
        mock_pkt_obj.summary.return_value = "Packet Summary"
        mock_pkt_obj.protocol_type = "IP"
        mock_process_packet.return_value = mock_pkt_obj
        
        # Run
        ctrl = AnalyzerController(pcap_file="test.pcap")
        ctrl.start_pcap_analysis()
        
        # Assertions
        assert mock_process_packet.call_count == 3
        
        # Check for summary output
        print_calls = [str(c) for c in mock_print.call_args_list]
        assert sum("Packet Summary" in c for c in print_calls) == 3
        assert any("Total packets processed: 3" in c for c in print_calls)

    @patch('builtins.print')
    def test_pcap_file_not_found(self, mock_print):
        """Test FileNotFoundError handling."""
        with patch('analyzer.PcapReader') as mock_pr:
            mock_pr.side_effect = FileNotFoundError("No such file")
            
            with pytest.raises(SystemExit):
                ctrl = AnalyzerController(pcap_file="missing.pcap")
                ctrl.start_pcap_analysis()
                
            # Check error message was printed to stderr (mocked print here catches stdout)
            # In actual implementation it goes to stderr, but print mock captures both if not configured
            # We check the controller logic stops execution

    @patch('builtins.print')
    def test_live_capture_permission_error(self, mock_print):
        """Test PermissionError handling (needs root)."""
        with patch('analyzer.LiveCapture') as mock_lc:
            mock_lc.side_effect = PermissionError("Root required")
            
            with pytest.raises(SystemExit):
                ctrl = AnalyzerController(interface="eth0")
                ctrl.start_live_capture()


class TestMainEntry:
    """Tests for the main() function and CLI argument parsing."""

    @patch('sys.argv', ['analyzer.py', '-i', 'eth0'])
    @patch('analyzer.AnalyzerController')
    def test_main_interface_mode(self, mock_ctrl_class):
        """Test main() with interface argument."""
        mock_ctrl_instance = MagicMock()
        mock_ctrl_class.return_value = mock_ctrl_instance
        
        main()
        
        mock_ctrl_class.assert_called_once_with(interface="eth0", pcap_file=None, protocol_filter=None, write_file=None)
        mock_ctrl_instance.run.assert_called_once()

    @patch('sys.argv', ['analyzer.py', '-r', 'capture.pcap'])
    @patch('analyzer.AnalyzerController')
    def test_main_pcap_mode(self, mock_ctrl_class):
        """Test main() with pcap argument."""
        mock_ctrl_instance = MagicMock()
        mock_ctrl_class.return_value = mock_ctrl_instance
        
        main()
        
        mock_ctrl_class.assert_called_once_with(interface=None, pcap_file="capture.pcap", protocol_filter=None, write_file=None)
        mock_ctrl_instance.run.assert_called_once()

    @patch('sys.argv', ['analyzer.py', '-i', 'eth0', '-f', 'DNS'])
    @patch('analyzer.AnalyzerController')
    def test_main_filter_mode(self, mock_ctrl_class):
        """Test main() with filter argument."""
        mock_ctrl_instance = MagicMock()
        mock_ctrl_class.return_value = mock_ctrl_instance
        
        main()
        
        mock_ctrl_class.assert_called_once_with(interface="eth0", pcap_file=None, protocol_filter="DNS", write_file=None)
        mock_ctrl_instance.run.assert_called_once()

    @patch('sys.argv', ['analyzer.py', '-i', 'eth0', '-w', 'out.pcap'])
    @patch('analyzer.AnalyzerController')
    def test_main_write_mode(self, mock_ctrl_class):
        """Test main() with write file argument."""
        mock_ctrl_instance = MagicMock()
        mock_ctrl_class.return_value = mock_ctrl_instance
        
        main()
        
        mock_ctrl_class.assert_called_once_with(interface="eth0", pcap_file=None, protocol_filter=None, write_file="out.pcap")
        mock_ctrl_instance.run.assert_called_once()

    @patch('sys.argv', ['analyzer.py'])
    @patch('builtins.print')
    def test_main_no_args(self, mock_print):
        """Test main() with no arguments (exits with help)."""
        with pytest.raises(SystemExit):
            main()
        
        # Should print help because required args missing

    @patch('sys.argv', ['analyzer.py', '-i', 'eth0', '-r', 'test.pcap'])
    @patch('builtins.print')
    def test_main_both_args(self, mock_print):
        """Test main() with both arguments (conflict)."""
        with pytest.raises(SystemExit):
            main()