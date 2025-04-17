#!/usr/bin/env python3
"""
Enhanced Kolmogorov-Smirnov Test Module with Integrated CryptoMiningDetector Logic
"""

import numpy as np
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import os
from scipy.stats import ks_2samp

logging.basicConfig(level=logging.DEBUG, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('kstest')

class KSTest:
    def __init__(self, mining_intervals, alpha: float = 0.05, k_points: int = 50):
        self.alpha = alpha
        self.k_points = k_points
        
        # Whitelist configuration
        self.whitelist = {
            'ips': ['192.168.1.1', '8.8.8.8', '1.1.1.1'],
            'ports': [53, 80, 443, 22, 3389],  # DNS, HTTP, HTTPS, SSH, RDP
            'protocols': ['dns', 'http', 'https', 'ssh', 'rdp']
        }
        
        if isinstance(mining_intervals, dict) and 'combined' in mining_intervals:
            self.mining_intervals = mining_intervals['combined']
            self.per_file_intervals = mining_intervals.get('per_file', {})
            self.range_info = mining_intervals.get('range_info', {})
            self.has_per_file_data = bool(self.per_file_intervals)
            logger.info(f"Initialized KS Test with {len(self.mining_intervals)} combined intervals from {len(self.per_file_intervals)} files")
        else:
            self.mining_intervals = mining_intervals
            self.per_file_intervals = {}
            self.range_info = {}
            self.has_per_file_data = False
            logger.info(f"Initialized KS Test with {len(self.mining_intervals)} mining intervals")
        
        self.reference_threshold = self._calculate_threshold(len(self.mining_intervals))

    def is_whitelisted(self, conn_data: Dict[str, Any]) -> bool:
        """Check if connection matches whitelist criteria"""
        src_ip = conn_data.get('src_ip', '')
        dst_ip = conn_data.get('dst_ip', '')
        src_port = conn_data.get('src_port', 0)
        dst_port = conn_data.get('dst_port', 0)
        proto = conn_data.get('proto', '').lower()
        
        whitelisted = (
            src_ip in self.whitelist['ips'] or dst_ip in self.whitelist['ips'] or
            src_port in self.whitelist['ports'] or dst_port in self.whitelist['ports'] or
            proto in self.whitelist['protocols']
        )
        logger.debug(f"Connection {src_ip}:{src_port}->{dst_ip}:{dst_port} ({proto}) whitelisted: {whitelisted}")
        return whitelisted

    def _normalize_intervals(self, intervals: List[float]) -> List[float]:
        """Normalize intervals using robust statistics"""
        if len(intervals) < 2:
            return intervals
        intervals = np.array(intervals, dtype=float)
        median = np.median(intervals)
        mad = np.median(np.abs(intervals - median))
        if mad == 0:
            return intervals
        normalized = (intervals - median) / mad
        return normalized

    def _calculate_threshold(self, n: int, m: int = None) -> float:
        """Calculate KS threshold"""
        if m is None:
            m = n
        c_alpha = np.sqrt(-0.5 * np.log(self.alpha / 2))
        return c_alpha * np.sqrt((n + m) / (n * m))

    def test_traffic(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Main detection method integrating CryptoMiningDetector logic"""
        all_intervals = traffic_data.get('all', [])
        if not all_intervals or not self.mining_intervals:
            logger.warning("Insufficient data for analysis")
            return {
                'standard_result': {
                    'verdict': 'INSUFFICIENT_DATA',
                    'confidence': 0,
                    'mining_stat': 0,
                    'threshold': 0,
                    'mining_score': 0,
                    'suspicious_connections': 0,
                    'total_connections': 0,
                    'timestamp': datetime.now().isoformat()
                }
            }

        # Aggregate KS test
        ks_stat, p_value = ks_2samp(
            self._normalize_intervals(all_intervals),
            self._normalize_intervals(self.mining_intervals)
        )
        threshold = self._calculate_threshold(len(all_intervals), len(self.mining_intervals))
        confidence = 100 * (1 - p_value)
        logger.info(f"Aggregate KS test: stat={ks_stat:.4f}, threshold={threshold:.4f}, confidence={confidence:.2f}%")

        # Connection-level analysis
        connections = traffic_data.get('connections', {})
        logger.info(f"Analyzing {len(connections)} connections")
        suspicious_conns = 0
        total_conns = 0
        conn_details = {}
        is_perfect_match = (ks_stat == 0)

        for conn_id, conn_data in connections.items():
            intervals = conn_data.get('intervals', [])
            logger.debug(f"Connection {conn_id}: {len(intervals)} intervals")
            if len(intervals) < 10:
                logger.debug(f"Skipping {conn_id}: insufficient intervals (< 10)")
                continue
            if self.is_whitelisted(conn_data):
                logger.debug(f"Skipping {conn_id}: whitelisted")
                continue
            
            total_conns += 1
            norm_intervals = self._normalize_intervals(intervals)
            conn_ks_stat, conn_p_value = ks_2samp(norm_intervals, self._normalize_intervals(self.mining_intervals))
            conn_threshold = self._calculate_threshold(len(norm_intervals))
            conn_confidence = 100 * (1 - conn_p_value)
            
            # Detection criteria
            if is_perfect_match:
                is_suspicious = True
            else:
                is_suspicious = conn_confidence >= 85 and conn_ks_stat > conn_threshold * 0.9
            
            if is_suspicious:
                suspicious_conns += 1
            conn_details[conn_id] = {
                'ks_stat': float(conn_ks_stat),
                'threshold': float(conn_threshold),
                'confidence': float(conn_confidence),
                'verdict': 'MINING_DETECTED' if is_suspicious else 'NORMAL'
            }
            logger.debug(f"Connection {conn_id}: ks_stat={conn_ks_stat:.4f}, threshold={conn_threshold:.4f}, confidence={conn_confidence:.2f}%, verdict={conn_details[conn_id]['verdict']}")

        # Verdict logic
        detection_percentage = (suspicious_conns / total_conns * 100) if total_conns > 0 else 0
        mining_score = min(100, detection_percentage * 2)
        if is_perfect_match:
            verdict = 'MINING_DETECTED'
            confidence = 100
        elif mining_score >= 40 and confidence >= 85 and ks_stat > threshold:
            verdict = 'MINING_DETECTED'
        elif mining_score >= 20 or (confidence >= 85 and ks_stat > threshold):
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'NORMAL'
        logger.info(f"Final verdict: {verdict}, mining_score={mining_score:.2f}, suspicious={suspicious_conns}/{total_conns}")

        # Standard result
        standard_result = {
            'timestamp': datetime.now().isoformat(),
            'window_size': len(all_intervals),
            'mining_stat': float(ks_stat),
            'confidence': float(confidence),
            'threshold': float(threshold),
            'verdict': verdict,
            'network_metrics': {
                'packet_rate': len(all_intervals) / (max(all_intervals) - min(all_intervals)) if len(all_intervals) > 1 else 0,
                'detection_percentage': detection_percentage,
                'suspicious_connections': suspicious_conns,
                'total_connections': total_conns
            },
            'suspicious_connections': [
                {
                    'src_ip': conn_data.get('src_ip', 'Unknown'),
                    'dst_ip': conn_data.get('dst_ip', 'Unknown'),
                    'src_port': conn_data.get('src_port', 0),
                    'dst_port': conn_data.get('dst_port', 0),
                    'proto': conn_data.get('proto', 'unknown'),
                    'ks_stat': conn_details[conn_id]['ks_stat'],
                    'threshold': conn_details[conn_id]['threshold'],
                    'verdict': conn_details[conn_id]['verdict'],
                    'confidence': conn_details[conn_id]['confidence']
                } for conn_id, conn_data in connections.items() if conn_details.get(conn_id, {}).get('verdict') == 'MINING_DETECTED'
            ],
            'mining_score': mining_score
        }

        final_results = {
            'standard_result': standard_result,
            'connections': conn_details,
            'per_file_results': self.test_per_file(all_intervals) if self.has_per_file_data else {}
        }
        return final_results

    def test(self, test_intervals: List[float], reference_intervals: List[float] = None) -> Dict[str, Any]:
        """Simplified test method for per-file comparison"""
        ref_intervals = reference_intervals if reference_intervals is not None else self.mining_intervals
        if not test_intervals or not ref_intervals:
            return {'verdict': 'INSUFFICIENT_DATA', 'ks_stat': 0, 'threshold': 0, 'confidence': 0}
        
        ks_stat, p_value = ks_2samp(self._normalize_intervals(test_intervals), self._normalize_intervals(ref_intervals))
        threshold = self._calculate_threshold(len(test_intervals), len(ref_intervals))
        confidence = 100 * (1 - p_value)
        verdict = 'MINING_DETECTED' if ks_stat > threshold else 'NORMAL'
        return {
            'verdict': 1 if verdict == 'MINING_DETECTED' else 0,
            'ks_stat': float(ks_stat),
            'threshold': float(threshold),
            'confidence': float(confidence),
            'result_text': verdict
        }

    def test_per_file(self, test_intervals: List[float]) -> Dict[str, Any]:
        """Test against per-file reference intervals"""
        if not self.has_per_file_data or not self.per_file_intervals:
            return {'combined': self.test(test_intervals)}
        
        per_file_results = {}
        for file_path, ref_intervals in self.per_file_intervals.items():
            file_name = os.path.basename(file_path)
            per_file_results[file_name] = self.test(test_intervals, ref_intervals)
        per_file_results['combined'] = self.test(test_intervals)
        return per_file_results