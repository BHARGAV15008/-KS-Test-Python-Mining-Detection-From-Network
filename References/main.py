import argparse
import os
import sys
import time
from datetime import datetime
import json
import numpy as np
import asyncio

from packet_capture import PacketCapture
from packet_preprocessing import PacketPreprocessor
from data_storage import DataStorage
from ks_test import KSTest
from dashboard import Dashboard
from report import Reporter
from performance_metrics import PerformanceMetrics

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='CryptoMining Detection using KS Test',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Live capture mode
  python main.py --live --interface eth0 --use-stored-reference --dashboard
  python main.py --live --interface eth0 --mining-reference known-mining.pcap --dashboard


  # Analyze single pcap file
  python main.py --pcap capture.pcap --mining-reference mining.pcap

  # Performance analysis with normal and mining traffic add output files
  python main.py --normal-traffic normal.pcap --mining-traffic mining.pcap --mining-reference miningfile.pcap --optimize-alpha --plot-performance
  python main.py --normal-traffic normal.pcap --mining-traffic mining.pcap --use-stored-reference --optimize-alpha --plot-performance
  python main.py --normal-traffic normal.pcap --mining-reference miningfile.pcap --optimize-alpha --plot-performance
  python main.py --mining-traffic mining.pcap  --mining-reference miningfile.pcap --optimize-alpha --plot-performance
  python main.py --normal-traffic normal.pcap --use-stored-reference --optimize-alpha --plot-performance
  python main.py --mining-traffic mining.pcap  --use-stored-reference --optimize-alpha --plot-performance

  # Optimize alpha value and generate performance plots also we gives multiple files in its in references as well
  python main.py --normal-traffic normal.pcap --mining-traffic mining.pcap --mining-reference miningfile.pcap --optimize-alpha --plot-performance
  python main.py --normal-traffic normal.pcap --mining-traffic mining.pcap --use-stored-reference --optimize-alpha --plot-performance
  python main.py --normal-traffic normal.pcap --mining-reference miningfile.pcap --optimize-alpha --plot-performance
  python main.py --mining-traffic mining.pcap  --mining-reference miningfile.pcap --optimize-alpha --plot-performance
  python main.py --normal-traffic normal.pcap --use-stored-reference --optimize-alpha --plot-performance
  python main.py --mining-traffic mining.pcap  --use-stored-reference --optimize-alpha --plot-performance

  # Analyze multiple pcap files and references as well
  python main.py --pcap-files file1.pcap file2.pcap --mining-reference mining_ref.pcap

  # Generate detailed report with suspicious connections
  python main.py --pcap capture.pcap --mining-reference mining.pcap --detailed-report report.json

  # Run with custom alpha value
  python main.py --pcap capture.pcap --mining-reference mining.pcap --alpha 0.1

  # Dashboard with live visualization
  python main.py --live --interface eth0 --mining-reference mining.pcap --dashboard --dashboard-port 8080
        """
    )
    
    # Capture mode arguments
    capture_group = parser.add_mutually_exclusive_group(required=False)
    capture_group.add_argument('--live', action='store_true', help='Capture live network traffic')
    capture_group.add_argument('--pcap', type=str, help='Path to pcap file for analysis')
    capture_group.add_argument('--pcap-files', type=str, nargs='+', help='Multiple pcap files for analysis')
    
    # Performance analysis arguments
    parser.add_argument('--normal-traffic', type=str, help='Path to normal traffic pcap file for performance analysis')
    parser.add_argument('--mining-traffic', type=str, help='Path to mining traffic pcap file for performance analysis')
    parser.add_argument('--alpha', type=float, default=0.1, help='Significance level for KS test (default: 0.1)')
    parser.add_argument('--alpha-range', type=str, default='0.01,0.05,0.1,0.15,0.2', 
                        help='Comma-separated list of alpha values to test (default: 0.01,0.05,0.1,0.15,0.2)')
    parser.add_argument('--optimize-alpha', action='store_true', 
                        help='Find optimal alpha value using performance metrics')
    parser.add_argument('--performance-report', type=str, 
                        help='Generate detailed performance report and save to specified file')
    parser.add_argument('--plot-performance', action='store_true', 
                        help='Generate performance visualization plots')
    
    # Network interface for live capture
    parser.add_argument('--interface', type=str, default='eth0', 
                        help='Network interface for live capture (default: eth0)')
    parser.add_argument('--port-filter', type=str, help='Comma-separated list of ports to filter')
    parser.add_argument('--ip-filter', type=str, help='Comma-separated list of IPs to filter')
    parser.add_argument('--interval', type=int, default=0,
                        help='Interval between capture batches in seconds (default: 0)')
    
    # Reporting arguments
    parser.add_argument('--detailed-report', type=str, help='Generate detailed report with suspicious connections')
    parser.add_argument('--report-format', choices=['json', 'html', 'pdf', 'tabular'], default='json',
                        help='Format for the detailed report (default: json)')
    parser.add_argument('--dashboard', action='store_true', help='Show interactive dashboard')
    parser.add_argument('--dashboard-port', type=int, default=8050,
                        help='Port for the dashboard server (default: 8050)')
    
    # Reference data arguments
    parser.add_argument('--mining-reference', type=str, nargs='+', help='Path(s) to reference mining traffic file(s)')
    parser.add_argument('--use-stored-reference', action='store_true', 
                        help='Use stored mining reference data instead of providing new files')
    parser.add_argument('--save-mining-reference', action='store_true',
                        help='Save mining traffic reference data for future use')
    
    # Advanced options
    parser.add_argument('--k-points', type=int, default=100,
                        help='Number of points for CDF comparison (default: 100)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    
    return parser.parse_args()
