#!/usr/bin/env python3

"""

CryptoMining Detector using KS Test

Main entry point for the application

"""



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

from kstest import KSTest

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



  # Analyze single pcap file

  python main.py --pcap suspicious.pcap --mining-reference mining1.pcap mining2.pcap

        """

    )

    

    capture_group = parser.add_mutually_exclusive_group(required=False)

    capture_group.add_argument('--live', action='store_true', help='Capture live network traffic')

    capture_group.add_argument('--pcap', type=str, help='Path to pcap file for analysis')

    capture_group.add_argument('--pcap-files', type=str, nargs='+', help='Multiple pcap files for analysis')

    

    parser.add_argument('--normal-traffic', type=str, nargs='+', help='Path to normal traffic pcap file(s)')

    parser.add_argument('--mining-traffic', type=str, nargs='+', help='Path to mining traffic pcap file(s)')

    parser.add_argument('--calculate-metrics', action='store_true', help='Calculate performance metrics')

    parser.add_argument('--alpha', type=float, default=0.1, help='Significance level for KS test (default: 0.1)')

    parser.add_argument('--interface', type=str, default='eth0', help='Network interface for live capture')

    parser.add_argument('--timeout', type=int, default=0, help='Timeout in seconds for live capture')

    parser.add_argument('--output-json', type=str, help='Save results to JSON file')

    parser.add_argument('--output-txt', type=str, help='Save results to text file')

    parser.add_argument('--dashboard', action='store_true', help='Show interactive dashboard')

    parser.add_argument('--dashboard-port', type=int, default=8050, help='Port for dashboard server')

    parser.add_argument('--mining-reference', type=str, nargs='+', help='Path to reference mining traffic file(s)')

    parser.add_argument('--use-stored-reference', action='store_true', help='Use stored mining reference data')

    parser.add_argument('--save-mining-reference', action='store_true', help='Save mining traffic reference data')

    parser.add_argument('--window-size', type=int, default=500, help='Window size for packet analysis')

    parser.add_argument('--k-points', type=int, default=100, help='Number of points for CDF comparison')

    parser.add_argument('--batch-size', type=int, default=1000, help='Number of packets to process in each batch')

    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')

    

    return parser.parse_args()



def setup_mining_reference(args):

    """Setup mining reference data"""

    print("Setting up mining reference data...")

    storage = DataStorage()

    

    if args.mining_reference:

        preprocessor = PacketPreprocessor()

        reference_intervals = {}

        combined_intervals = []

        

        for ref_file in args.mining_reference:

            print(f"Processing mining reference file: {ref_file}")

            packets = PacketCapture.read_pcap(ref_file)

            if not packets or len(packets) == 0:

                print(f"Warning: No packets found in {ref_file}, skipping")

                continue

                

            intervals_data = preprocessor.extract_intervals(packets)

            if 'all' in intervals_data and intervals_data['all']:

                file_intervals = intervals_data['all']

                reference_intervals[ref_file] = file_intervals

                combined_intervals.extend(file_intervals)

                print(f"  - Extracted {len(file_intervals)} intervals from {ref_file}")

            else:

                print(f"Warning: No valid intervals extracted from {ref_file}, skipping")

        

        if not reference_intervals:

            print("Error: No valid packets found in mining reference files.")

            sys.exit(1)

            

        print(f"Collected {len(combined_intervals)} intervals from {len(args.mining_reference)} mining reference files")

        

        if args.save_mining_reference:

            storage.save_mining_reference(combined_intervals)

            print("Mining reference data has been saved for future use.")

        

        min_val = min(min(intervals) for intervals in reference_intervals.values() if intervals)

        max_val = max(max(intervals) for intervals in reference_intervals.values() if intervals)

        range_info = {'min': min_val, 'max': max_val, 'range': max_val - min_val}

        

        print(f"Global range: {min_val:.6f} to {max_val:.6f} (range: {max_val - min_val:.6f})")

        

        return {'combined': combined_intervals, 'per_file': reference_intervals, 'range_info': range_info}

    

    elif args.use_stored_reference:

        intervals = storage.load_mining_reference()

        if not intervals:

            print("Error: No stored mining reference data found.")

            sys.exit(1)

        

        print(f"Loaded {len(intervals)} intervals from stored mining reference data.")

        return {'combined': intervals, 'per_file': {}, 'range_info': {}}

    

    else:

        print("Error: No mining reference data specified.")

        sys.exit(1)



def process_pcap_file(args, mining_intervals=None):

    """Process a single pcap file"""

    if not args.pcap:

        print("Error: No pcap file specified.")

        return None

    

    print(f"Processing pcap file: {args.pcap}")

    

    if mining_intervals is None:

        mining_intervals = setup_mining_reference(args)

    

    preprocessor = PacketPreprocessor()

    ks_test = KSTest(mining_intervals, alpha=args.alpha, k_points=args.k_points)

    reporter = Reporter()

    

    packets = PacketCapture.read_pcap(args.pcap)

    if not packets:

        print(f"Error: No packets found in {args.pcap}")

        return None

    

    print(f"Read {len(packets)} packets from {args.pcap}")

    

    intervals_data = preprocessor.extract_intervals(packets)

    results = ks_test.test_traffic(intervals_data)

    

    if args.output_json:

        reporter.generate_json_report(results['standard_result'], args.output_json)

        print(f"Results saved to {args.output_json}")

    

    if args.output_txt:

        reporter.generate_text_report(results['standard_result'], args.output_txt)

        print(f"Results saved to {args.output_txt}")

    

    print("\n" + reporter.generate_tabular_report(results['standard_result']))

    

    return results



def process_live_capture(args, mining_intervals=None):

    """Process live network traffic"""

    if mining_intervals is None:

        mining_intervals = setup_mining_reference(args)

    

    preprocessor = PacketPreprocessor()

    ks_test = KSTest(mining_intervals, alpha=args.alpha, k_points=args.k_points)

    reporter = Reporter()

    

    dashboard = Dashboard(port=args.dashboard_port) if args.dashboard else None

    if dashboard:

        dashboard.start()

    

    print(f"Starting live capture on interface {args.interface}...")

    print("Press Ctrl+C to stop")

    

    try:

        while True:

            packets = PacketCapture.live_capture(

                interface=args.interface,

                timeout=args.timeout,

                packet_count=args.batch_size

            )

            

            if not packets:

                print("No packets captured. Waiting...")

                time.sleep(5)

                continue

            

            print(f"Processing batch of {len(packets)} packets...")

            

            intervals_data = preprocessor.extract_intervals(packets)

            results = ks_test.test_traffic(intervals_data)

            

            if dashboard:

                dashboard.update_data(results['standard_result'])

            

            print("\n" + reporter.generate_tabular_report(results['standard_result']))

            

            if args.output_json:

                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

                output_file = args.output_json.replace('.json', f'_{timestamp}.json')

                reporter.generate_json_report(results['standard_result'], output_file)

    

    except KeyboardInterrupt:

        print("\nLive capture stopped by user")

        if dashboard:

            dashboard.stop()



def main():

    """Main entry point"""

    args = parse_arguments()

    

    if len(sys.argv) == 1:

        print_help()

        return

    

    if args.normal_traffic and args.mining_traffic and args.calculate_metrics:

        analyze_performance(args)

        return

    

    if args.live:

        mining_intervals = setup_mining_reference(args)

        process_live_capture(args, mining_intervals)

        return

    

    if args.pcap:

        mining_intervals = setup_mining_reference(args)

        process_pcap_file(args, mining_intervals)

        return

    

    if args.pcap_files:

        mining_intervals = setup_mining_reference(args)

        for pcap_file in args.pcap_files:

            args.pcap = pcap_file

            print(f"\nProcessing file: {pcap_file}")

            process_pcap_file(args, mining_intervals)

        return

    

    print("Error: No valid mode specified.")

    print("Run with --help for more information.")



if __name__ == "__main__":

    main()