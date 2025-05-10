#!/usr/bin/env python3
"""
Packet Capture Module for CryptoMining Detection System
"""

import os
import time
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

os.environ['TSHARK_PATH'] = r'D:\Installation\Wireshark\tshark.exe'

try:
    import pyshark
    pyshark.config.TSHARK_PATH = r'D:\Installation\Wireshark\tshark.exe'
except ImportError:
    print("Warning: pyshark not installed. Live capture won't work.")
    print("Install with: pip install pyshark")

logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('packet_capture')

class PacketCapture:
    @staticmethod
    def read_pcap(pcap_file: str) -> List[Dict[str, Any]]:
        if not os.path.exists(pcap_file):
            logger.error(f"PCAP file not found: {pcap_file}")
            return []
            
        try:
            logger.info(f"Reading PCAP file: {pcap_file}")
            cap = pyshark.FileCapture(pcap_file, display_filter='tcp or udp', 
                                    tshark_path=r'D:\Installation\Wireshark\tshark.exe')
            
            packets = []
            for packet in cap:
                packet_info = PacketCapture._extract_packet_info(packet)
                if packet_info:
                    packets.append(packet_info)
            
            cap.close()
            logger.info(f"Read {len(packets)} packets from {pcap_file}")
            return packets
            
        except Exception as e:
            logger.error(f"Error reading PCAP file {pcap_file}: {str(e)}")
            return []
    
    @staticmethod
    def live_capture(interface: str, timeout: int = 0, 
                     ip_filter: Optional[str] = None, 
                     port_filter: Optional[str] = None,
                     packet_count: int = 0) -> List[Dict[str, Any]]:
        capture_filter = PacketCapture._build_capture_filter(ip_filter, port_filter)
        
        try:
            logger.info(f"Starting live capture on interface {interface} with filter: {capture_filter}")
            cap = pyshark.LiveCapture(interface=interface, bpf_filter=capture_filter if capture_filter else None)
            
            if timeout > 0:
                end_time = time.time() + timeout
            else:
                end_time = None
                
            packets = []
            packet_counter = 0
            
            for packet in cap.sniff_continuously(packet_count=packet_count if packet_count > 0 else None):
                packet_info = PacketCapture._extract_packet_info(packet)
                if packet_info:
                    packets.append(packet_info)
                    packet_counter += 1
                
                if end_time and time.time() >= end_time:
                    logger.info(f"Capture timeout reached after {timeout} seconds")
                    break
                    
                if packet_count > 0 and packet_counter >= packet_count:
                    logger.info(f"Captured {packet_count} packets")
                    break
            
            cap.close()
            logger.info(f"Live capture complete, {len(packets)} packets captured")
            return packets
            
        except Exception as e:
            logger.error(f"Error during live capture: {str(e)}")
            return []
    
    @staticmethod
    def _extract_packet_info(packet) -> Optional[Dict[str, Any]]:
        try:
            packet_info = {
                'timestamp': float(packet.sniff_timestamp),
                'length': int(packet.length)
            }
            
            if hasattr(packet, 'ip'):
                packet_info['src_ip'] = packet.ip.src
                packet_info['dst_ip'] = packet.ip.dst
                packet_info['protocol'] = packet.transport_layer.lower() if hasattr(packet, 'transport_layer') else 'other'
                
                if hasattr(packet, 'tcp'):
                    packet_info['src_port'] = int(packet.tcp.srcport)
                    packet_info['dst_port'] = int(packet.tcp.dstport)
                    packet_info['proto'] = 'tcp'
                elif hasattr(packet, 'udp'):
                    packet_info['src_port'] = int(packet.udp.srcport)
                    packet_info['dst_port'] = int(packet.udp.dstport)
                    packet_info['proto'] = 'udp'
                else:
                    return None
                
                packet_info['conn_id'] = f"{packet_info['src_ip']}:{packet_info['src_port']}-{packet_info['dst_ip']}:{packet_info['dst_port']}-{packet_info['proto']}"
                return packet_info
            else:
                return None
                
        except Exception as e:
            logger.debug(f"Error extracting packet info: {str(e)}")
            return None
    
    @staticmethod
    def _build_capture_filter(ip_filter: Optional[str], port_filter: Optional[str]) -> str:
        filter_parts = []
        
        if ip_filter:
            ip_addresses = ip_filter.split(',')
            ip_conditions = [f"host {ip.strip()}" for ip in ip_addresses if ip.strip()]
            if ip_conditions:
                filter_parts.append(f"({' or '.join(ip_conditions)})")
        
        if port_filter:
            ports = port_filter.split(',')
            port_conditions = [f"port {port.strip()}" for port in ports if port.strip() and port.isdigit()]
            if port_conditions:
                filter_parts.append(f"({' or '.join(port_conditions)})")
        
        if not filter_parts:
            filter_parts.append("(tcp or udp)")
        
        return " and ".join(filter_parts)