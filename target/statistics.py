"""
Packet Statistics Module.
Tracks and reports protocol distribution during a capture session.
"""

from dataclasses import dataclass, field
from typing import Dict
from packet_structures import Packet


@dataclass
class PacketStatistics:
    """
    Accumulates statistics about captured packets.
    """
    total_packets: int = 0
    ethernet_frames: int = 0
    ipv4_packets: int = 0
    ipv6_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    http_packets: int = 0
    dns_packets: int = 0
    tls_packets: int = 0
    ftp_packets: int = 0
    
    # Track other EtherTypes if desired, currently just keeping basic counters
    other_protocols: int = 0

    def update(self, packet: Packet):
        """
        Update statistics based on the content of a parsed packet.
        
        Args:
            packet: The fully or partially parsed Packet object.
        """
        self.total_packets += 1
        
        if packet.ethernet:
            self.ethernet_frames += 1
        else:
            # If no ethernet header, we can't parse deeper in this current architecture stack
            self.other_protocols += 1
            return

        if packet.ip:
            self.ipv4_packets += 1
        elif packet.ipv6:
            self.ipv6_packets += 1
        else:
            # Has Ethernet but no IP (e.g., ARP, raw LLC)
            pass

        if packet.tcp:
            self.tcp_packets += 1
        
        if packet.udp:
            self.udp_packets += 1
            
        if packet.http_request or packet.http_response:
            self.http_packets += 1
            
        if packet.dns:
            self.dns_packets += 1

        if packet.tls_record:
            self.tls_packets += 1

        if packet.ftp_command or packet.ftp_response:
            self.ftp_packets += 1

    def get_report(self) -> str:
        """
        Generate a formatted text report of the captured statistics.
        
        Returns:
            A formatted string containing the statistics summary.
        """
        lines = []
        lines.append("\n" + "=" * 40)
        lines.append("       Capture Statistics")
        lines.append("=" * 40)
        lines.append(f"Total Packets Captured : {self.total_packets}")
        lines.append("-" * 40)
        lines.append(f"Ethernet Frames        : {self.ethernet_frames}")
        
        if self.ethernet_frames > 0:
            total_ip = self.ipv4_packets + self.ipv6_packets
            ip_percent = (total_ip / self.ethernet_frames) * 100
            lines.append(f"  -> IP Packets       : {total_ip} ({ip_percent:.1f}%)")
            
            if total_ip > 0:
                lines.append(f"     -> IPv4          : {self.ipv4_packets}")
                lines.append(f"     -> IPv6          : {self.ipv6_packets}")
                
                tcp_percent = (self.tcp_packets / total_ip) * 100 if total_ip > 0 else 0
                udp_percent = (self.udp_packets / total_ip) * 100 if total_ip > 0 else 0
                lines.append(f"     -> TCP           : {self.tcp_packets} ({tcp_percent:.1f}%)")
                lines.append(f"     -> UDP           : {self.udp_packets} ({udp_percent:.1f}%)")
                
                if self.udp_packets > 0:
                    dns_percent = (self.dns_packets / self.udp_packets) * 100
                    lines.append(f"        -> DNS       : {self.dns_packets} ({dns_percent:.1f}%)")
                
                if self.tcp_packets > 0:
                    http_count = self.http_packets
                    if http_count > 0:
                        http_percent = (http_count / self.tcp_packets) * 100
                        lines.append(f"        -> HTTP      : {http_count} ({http_percent:.1f}%)")
                    
                    if self.tls_packets > 0:
                        tls_percent = (self.tls_packets / self.tcp_packets) * 100
                        lines.append(f"        -> TLS       : {self.tls_packets} ({tls_percent:.1f}%)")

                    if self.ftp_packets > 0:
                        ftp_percent = (self.ftp_packets / self.tcp_packets) * 100
                        lines.append(f"        -> FTP       : {self.ftp_packets} ({ftp_percent:.1f}%)")
        
        if self.other_protocols > 0:
            lines.append(f"Other/Unknown Protocols : {self.other_protocols}")
            
        lines.append("=" * 40 + "\n")
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.get_report()