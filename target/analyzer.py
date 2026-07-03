"""
Main Program (Controller) CLI.
Provides the user interface to capture packets live or read from PCAP files,
process them, and display summaries.
"""

import argparse
import sys
import signal
from typing import Optional

from capture_engine import LiveCapture, CaptureError
from pcap_reader import PcapReader, PcapReaderError
from packet_processor import process_packet
from statistics import PacketStatistics
from packet_structures import Packet


class AnalyzerController:
    """
    Controller for the protocol analyzer.
    Manages the capture loop, statistics gathering, and user display.
    """
    
    def __init__(self, interface: Optional[str] = None, pcap_file: Optional[str] = None, 
                 protocol_filter: Optional[str] = None):
        """
        Initialize the controller.
        
        Args:
            interface: Network interface for live capture (Linux only).
            pcap_file: Path to a .pcap file for offline analysis.
            protocol_filter: Optional string to filter packets by protocol type (e.g., "HTTP", "DNS").
            
        Raises:
            ValueError: If neither interface nor pcap_file is provided, or both are provided.
        """
        if (interface and pcap_file) or (not interface and not pcap_file):
            raise ValueError("Please specify either 'interface' for live capture or 'pcap_file' for offline analysis.")
            
        self.interface = interface
        self.pcap_file = pcap_file
        self.protocol_filter = protocol_filter
        self.running = True
        self.stats = PacketStatistics()
        
        # Setup signal handler for graceful exit (Ctrl+C)
        signal.signal(signal.SIGINT, self._handle_signal)
        # Ignore SIGPIPE (can occur when piping output to another process like head)
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)

    def _handle_signal(self, signum, frame):
        """Handle Ctrl+C to stop the capture loop gracefully."""
        print("\n[!] Stopping capture...")
        self.running = False

    def _matches_filter(self, packet: Packet) -> bool:
        """
        Check if the packet matches the configured protocol filter.
        
        Args:
            packet: The parsed Packet object.
            
        Returns:
            True if the packet matches the filter or if no filter is set, False otherwise.
        """
        if self.protocol_filter is None:
            return True
            
        # Case-insensitive comparison
        target_proto = self.protocol_filter.upper()
        packet_proto = packet.protocol_type.upper()
        
        return target_proto == packet_proto

    def start_live_capture(self):
        """Start live packet capture and analysis."""
        print(f"[*] Starting live capture on interface: {self.interface}")
        if self.protocol_filter:
            print(f"[*] Filtering for protocol: {self.protocol_filter}")
        print("[*] Press Ctrl+C to stop.")
        
        try:
            with LiveCapture(self.interface) as capture:
                print(f"[*] Listening on {self.interface}...")
                print("-" * 80)
                
                while self.running:
                    try:
                        # Capture raw packet
                        raw_data = next(capture)
                        
                        # Process packet
                        packet = process_packet(raw_data)
                        
                        # Update statistics (always update stats regardless of filter)
                        self.stats.update(packet)
                        
                        # Display summary if matches filter
                        if self._matches_filter(packet):
                            self._display_packet(packet)
                        
                    except CaptureError as e:
                        print(f"[!] Error capturing packet: {e}", file=sys.stderr)
                        # Continue capturing despite occasional errors
                    except RuntimeError:
                        # Socket closed
                        break

                # Display statistics at the end
                print(self.stats.get_report())
                        
        except PermissionError:
            print("[!] Permission denied. Please run with sudo/root privileges.", file=sys.stderr)
            sys.exit(1)
        except OSError as e:
            print(f"[!] OS Error: {e}", file=sys.stderr)
            sys.exit(1)
            
    def start_pcap_analysis(self):
        """Start offline PCAP file analysis."""
        print(f"[*] Analyzing PCAP file: {self.pcap_file}")
        if self.protocol_filter:
            print(f"[*] Filtering for protocol: {self.protocol_filter}")
        print("-" * 80)
        
        try:
            with PcapReader(self.pcap_file) as reader:
                packet_count = 0
                displayed_count = 0
                for raw_data in reader:
                    if not self.running:
                        break
                        
                    packet = process_packet(raw_data)
                    self.stats.update(packet)
                    
                    if self._matches_filter(packet):
                        self._display_packet(packet)
                        displayed_count += 1
                    
                    packet_count += 1
                
                # Display statistics
                print(self.stats.get_report())
                print(f"[*] Analysis complete. Total packets processed: {packet_count}")
                if self.protocol_filter:
                    print(f"[*] Packets matching filter '{self.protocol_filter}': {displayed_count}")
                
        except FileNotFoundError:
            print(f"[!] File not found: {self.pcap_file}", file=sys.stderr)
            sys.exit(1)
        except PcapReaderError as e:
            print(f"[!] PCAP Error: {e}", file=sys.stderr)
            sys.exit(1)

    def _display_packet(self, packet):
        """Print a summary of the packet to stdout."""
        # Using the summary method from the Packet dataclass
        # We can add more formatting here if needed in the future
        print(packet.summary())

    def run(self):
        """Run the analyzer based on the initialized configuration."""
        if self.interface:
            self.start_live_capture()
        elif self.pcap_file:
            self.start_pcap_analysis()


def main():
    """Main entry point for the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Cross-platform Network Protocol Analyzer (Phase 1: Ethernet/IP/TCP/UDP)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    
    group.add_argument(
        "-i", "--interface",
        help="Network interface for live capture (e.g., eth0, wlan0).\n"
             "Note: Requires root privileges and Linux OS."
    )
    
    group.add_argument(
        "-r", "--read-file",
        help="Read packets from a PCAP file."
    )
    
    parser.add_argument(
        "-f", "--filter",
        dest="protocol_filter",
        help="Filter output by specific protocol name (e.g., HTTP, DNS, TCP, TLS)."
    )
    
    args = parser.parse_args()
    
    try:
        controller = AnalyzerController(
            interface=args.interface,
            pcap_file=args.read_file,
            protocol_filter=args.protocol_filter
        )
        controller.run()
    except ValueError as e:
        print(f"Configuration Error: {e}", file=sys.stderr)
        parser.print_help()
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()