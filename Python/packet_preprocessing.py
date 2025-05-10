#!/usr/bin/env python3
"""
Packet Preprocessing Module for CryptoMining Detection System

This module handles:
1. Extracting intervals from packet timestamps
2. Organizing packets by flow/connection
3. Calculating metrics needed for KS test
"""
import logging
from typing import List, Dict, Any, Tuple
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('packet_preprocessing')

class PacketPreprocessor:
    """Class for preprocessing packets to extract intervals and organize by connection."""
    def __init__(self):
        """Initialize the packet preprocessor."""
        pass
        
    def extract_intervals(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract time intervals from a list of packets.
        Args:
            packets: List of packet dictionaries from PacketCapture
        Returns:
            Dictionary with:
                - 'all': List of all intervals
                - 'connections': Dictionary of connections with their intervals
        """
        if not packets:
            logger.warning("No packets to extract intervals from")
            return {'all': [], 'connections': {}}
        
        sorted_packets = sorted(packets, key=lambda p: p['timestamp'])
        connections = defaultdict(list)
        for packet in sorted_packets:
            conn_id = packet.get('conn_id')
            if conn_id:
                connections[conn_id].append(packet)
        
        connection_data = {}
        all_intervals = []
        
        for conn_id, conn_packets in connections.items():
            if len(conn_packets) <= 1:
                continue
                
            first_packet = conn_packets[0]
            conn_metadata = {
                'src_ip': first_packet.get('src_ip', 'unknown'),
                'dst_ip': first_packet.get('dst_ip', 'unknown'),
                'src_port': first_packet.get('src_port', 0),
                'dst_port': first_packet.get('dst_port', 0),
                'proto': first_packet.get('protocol', 'unknown'),
                'packet_count': len(conn_packets)
            }
            
            intervals = []
            for i in range(1, len(conn_packets)):
                interval = conn_packets[i]['timestamp'] - conn_packets[i-1]['timestamp']
                intervals.append(interval)
            
            conn_metadata['intervals'] = intervals
            connection_data[conn_id] = conn_metadata
            all_intervals.extend(intervals)
        
        logger.info(f"Extracted {len(all_intervals)} intervals from {len(connections)} connections")
        return {
            'all': all_intervals,
            'connections': connection_data
        }
    
    def get_connection_stats(self, interval_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get statistics about connections in the interval data.
        Args:
            interval_data: Dictionary from extract_intervals
        Returns:
            List of connection statistics dictionaries
        """
        stats = []
        for conn_id, conn_data in interval_data.get('connections', {}).items():
            intervals = conn_data.get('intervals', [])
            if not intervals:
                continue
                
            min_interval = min(intervals)
            max_interval = max(intervals)
            avg_interval = sum(intervals) / len(intervals)
            
            conn_stats = {
                'conn_id': conn_id,
                'src_ip': conn_data.get('src_ip', 'unknown'),
                'dst_ip': conn_data.get('dst_ip', 'unknown'),
                'src_port': conn_data.get('src_port', 0),
                'dst_port': conn_data.get('dst_port', 0),
                'protocol': conn_data.get('proto', 'unknown'),
                'packet_count': conn_data.get('packet_count', 0),
                'interval_count': len(intervals),
                'min_interval': min_interval,
                'max_interval': max_interval,
                'avg_interval': avg_interval
            }
            stats.append(conn_stats)
        return stats

if __name__ == "__main__":
    print("This module is meant to be imported, not run directly.")
    print("Example usage:")
    print("  from packet_capture import PacketCapture")
    print("  from packet_preprocessing import PacketPreprocessor")
    print("  ")
    print("  # Capture or read packets")
    print("  packets = PacketCapture.read_pcap('example.pcap')")
    print("  ")
    print("  # Preprocess packets")
    print("  preprocessor = PacketPreprocessor()")
    print("  interval_data = preprocessor.extract_intervals(packets)")
    print("  ")
    print("  # Use the intervals for KS test")
