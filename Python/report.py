#!/usr/bin/env python3
"""
Report Generation Module for CryptoMining Detection System
"""
import os
import json
import logging
from typing import Dict, Any
from datetime import datetime
import tabulate

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('report')

class Reporter:
    def __init__(self, output_dir: str = None):
        if output_dir is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            self.output_dir = os.path.join(script_dir, 'reports')
        else:
            self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            logger.info(f"Created reports directory: {self.output_dir}")
    
    def generate_json_report(self, data: Dict[str, Any], filename: str = None) -> str:
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{timestamp}.json"
        if not filename.endswith('.json'):
            filename += '.json'
        file_path = os.path.join(self.output_dir, filename)
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Generated JSON report: {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Error generating JSON report: {str(e)}")
            return ""
    
    def generate_text_report(self, data: Dict[str, Any], filename: str = None) -> str:
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{timestamp}.txt"
        if not filename.endswith('.txt'):
            filename += '.txt'
        file_path = os.path.join(self.output_dir, filename)
        try:
            with open(file_path, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("CRYPTOMINING DETECTION REPORT\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Generated: {data.get('timestamp', datetime.now().isoformat())}\n\n")
                f.write(f"VERDICT: {data.get('verdict', 'UNKNOWN')}\n\n")
                f.write("STATISTICS:\n")
                f.write("-" * 80 + "\n")
                f.write(f"Window Size: {data.get('window_size', 'N/A')}\n")
                f.write(f"Mining Statistic: {data.get('mining_stat', 'N/A')}\n")
                f.write(f"Threshold: {data.get('threshold', 'N/A')}\n")
                f.write(f"Confidence: {data.get('confidence', 'N/A')}\n\n")
                network_metrics = data.get('network_metrics', {})
                if network_metrics:
                    f.write("NETWORK METRICS:\n")
                    f.write("-" * 80 + "\n")
                    for key, value in network_metrics.items():
                        f.write(f"{key}: {value}\n")
                    f.write("\n")
                suspicious_conns = data.get('suspicious_connections', [])
                if suspicious_conns:
                    f.write("SUSPICIOUS CONNECTIONS:\n")
                    f.write("-" * 80 + "\n")
                    for i, conn in enumerate(suspicious_conns):
                        f.write(f"Connection {i+1}:\n")
                        f.write(f"  Source: {conn.get('src_ip', 'Unknown')}:{conn.get('src_port', 'Unknown')}\n")
                        f.write(f"  Destination: {conn.get('dst_ip', 'Unknown')}:{conn.get('dst_port', 'Unknown')}\n")
                        f.write(f"  Protocol: {conn.get('proto', 'Unknown')}\n")
                        f.write(f"  KS Statistic: {conn.get('ks_stat', 'N/A')}\n")
                        f.write(f"  Threshold: {conn.get('threshold', 'N/A')}\n")
                        f.write(f"  Verdict: {conn.get('verdict', 'UNKNOWN')}\n")
                        f.write("\n")
                per_file_results = data.get('per_file_results', {})
                if per_file_results:
                    f.write("PER-FILE DETECTION RESULTS:\n")
                    f.write("-" * 80 + "\n")
                    for file, result in per_file_results.items():
                        f.write(f"Reference File: {file}\n")
                        f.write(f"  Verdict: {result.get('result_text', 'UNKNOWN')}\n")
                        f.write(f"  KS Statistic: {result.get('ks_stat', 'N/A')}\n")
                        f.write(f"  Threshold: {result.get('threshold', 'N/A')}\n")
                        f.write("\n")
                f.write("=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
            logger.info(f"Generated text report: {file_path}")
            return file_path
        except Exception as e:
            logger.error(f"Error generating text report: {str(e)}")
            return ""
    
    def generate_tabular_report(self, data: Dict[str, Any]) -> str:
        report = []
        report.append("=" * 80)
        report.append("CRYPTOMINING DETECTION REPORT")
        report.append("=" * 80)
        report.append("")
        timestamp = data.get('timestamp', datetime.now().isoformat())
        verdict = data.get('verdict', 'UNKNOWN')
        confidence = data.get('confidence', 'N/A')
        report.append(f"Generated: {timestamp}")
        report.append(f"VERDICT: {verdict} (Confidence: {confidence}%)")
        report.append("")
        stats_table = [
            ["Metric", "Value"],
            ["Window Size", data.get('window_size', 'N/A')],
            ["Mining Statistic", data.get('mining_stat', 'N/A')],
            ["Threshold", data.get('threshold', 'N/A')]
        ]
        report.append("STATISTICS:")
        report.append(tabulate.tabulate(stats_table, headers="firstrow", tablefmt="grid"))
        report.append("")
        network_metrics = data.get('network_metrics', {})
        if network_metrics:
            metrics_table = [["Metric", "Value"]]
            for key, value in network_metrics.items():
                metrics_table.append([key, value])
            report.append("NETWORK METRICS:")
            report.append(tabulate.tabulate(metrics_table, headers="firstrow", tablefmt="grid"))
            report.append("")
        suspicious_conns = data.get('suspicious_connections', [])
        if suspicious_conns:
            conn_table = [["Source", "Destination", "Protocol", "KS Stat", "Threshold", "Verdict"]]
            for conn in suspicious_conns:
                source = f"{conn.get('src_ip', 'Unknown')}:{conn.get('src_port', 'Unknown')}"
                dest = f"{conn.get('dst_ip', 'Unknown')}:{conn.get('dst_port', 'Unknown')}"
                protocol = conn.get('proto', 'Unknown')
                ks_stat = conn.get('ks_stat', 'N/A')
                threshold = conn.get('threshold', 'N/A')
                verdict = conn.get('verdict', 'UNKNOWN')
                conn_table.append([source, dest, protocol, ks_stat, threshold, verdict])
            report.append("SUSPICIOUS CONNECTIONS:")
            report.append(tabulate.tabulate(conn_table, headers="firstrow", tablefmt="grid"))
            report.append("")
        per_file_results = data.get('per_file_results', {})
        if per_file_results:
            per_file_table = [["Reference File", "Verdict", "KS Stat", "Threshold"]]
            for file, result in per_file_results.items():
                per_file_table.append([
                    file,
                    result.get('result_text', 'UNKNOWN'),
                    result.get('ks_stat', 'N/A'),
                    result.get('threshold', 'N/A')
                ])
            report.append("PER-FILE DETECTION RESULTS:")
            report.append(tabulate.tabulate(per_file_table, headers="firstrow", tablefmt="grid"))
            report.append("")
        report.append("=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        return "\n".join(report)
    
    def generate_report(self, data: Dict[str, Any], format: str = 'text', filename: str = None) -> str:
        if format == 'json':
            return self.generate_json_report(data, filename)
        elif format == 'text':
            return self.generate_text_report(data, filename)
        elif format == 'tabular':
            return self.generate_tabular_report(data)
        else:
            logger.error(f"Unsupported report format: {format}")
            return ""