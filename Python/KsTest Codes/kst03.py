#!/usr/bin/env python3
"""
Enhanced Kolmogorov-Smirnov Test Module with Reduced False Positives
"""

import numpy as np
import logging
from typing import List, Dict, Any, Union, Optional
from datetime import datetime
import os
from scipy.stats import ks_2samp

logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('kstest')

class KSTest:
    def __init__(self, mining_intervals, alpha: float = 0.05, k_points: int = 50):
        self.alpha = alpha
        self.k_points = k_points
        
        # Whitelist configuration
        self.whitelist = {
            'ips': ['192.168.1.1', '8.8.8.8', '1.1.1.1'],  # Common trusted IPs
            'ports': [53, 80, 443, 22, 3389],  # Common service ports
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
    
    def is_whitelisted(self, conn_data: Dict[str, Any]) -> bool:
        """Check if connection matches whitelist criteria"""
        # Check IP whitelist
        if conn_data.get('src_ip') in self.whitelist['ips'] or \
           conn_data.get('dst_ip') in self.whitelist['ips']:
            return True
        
        # Check port whitelist
        if conn_data.get('dst_port') in self.whitelist['ports'] or \
           conn_data.get('src_port') in self.whitelist['ports']:
            return True
            
        # Check protocol whitelist
        if conn_data.get('proto', '').lower() in self.whitelist['protocols']:
            return True
            
        return False
    
    def _normalize_intervals(self, intervals: List[float]) -> List[float]:
        """Robust normalization with outlier handling and smoothing"""
        if not intervals or len(intervals) < 2:
            return intervals
            
        # Handle zeros and negative values
        min_val = max(min(intervals), 1e-9)
        
        # Apply smoothing transformation
        smoothed = []
        for x in intervals:
            # Smooth extreme values while preserving order
            smoothed_val = np.log(x) if x > min_val * 10 else np.log(min_val) + (x - min_val)/(min_val * 9)
            smoothed.append(smoothed_val)
        
        # Standardize with robust statistics
        median = np.median(smoothed)
        mad = np.median([abs(x - median) for x in smoothed])
        if mad < 1e-9:
            return [0.5] * len(intervals)
            
        return [(x - median) / mad for x in smoothed]
    
    def _calculate_ks_statistic(self, test_data: List[float], ref_data: List[float]) -> float:
        """Calculate robust KS statistic with normalized data"""
        norm_test = self._normalize_intervals(test_data)
        norm_ref = self._normalize_intervals(ref_data)
        
        if len(norm_test) < 10 or len(norm_ref) < 10:
            return self._basic_ks_test(norm_test, norm_ref)['ks_stat']
        return ks_2samp(norm_test, norm_ref).statistic
    
    def _calculate_threshold(self, n: int, m: int) -> float:
        """More conservative threshold calculation with dynamic adjustment"""
        base_threshold = np.sqrt(-np.log(self.alpha/2) * (1 + n/m) / (2*n))
        
        # Dynamic adjustment factors
        size_factor = 1.0 / np.log(max(n, 20))  # More conservative for small samples
        confidence_factor = 1.8  # Increased general conservativeness
        
        # Additional factor based on data distribution
        if hasattr(self, 'range_info') and self.range_info:
            data_range = self.range_info.get('range', 1.0)
            range_factor = min(1.5, 1.0 + (1.0 / (1.0 + data_range)))
        else:
            range_factor = 1.2
            
        return base_threshold * size_factor * confidence_factor * range_factor
    
    def _basic_ks_test(self, test_intervals: List[float], reference_intervals: List[float]) -> Dict[str, Any]:
        """Basic KS test implementation for small samples"""
        l_P = sorted(test_intervals)
        l_Q = sorted(reference_intervals)
        
        n = len(l_P)
        m = len(l_Q)
        i = j = 0
        d_max = 0
        fn1 = fn2 = 0
        
        while i < n and j < m:
            if l_P[i] < l_Q[j]:
                fn1 = (i+1)/n
                i += 1
            elif l_P[i] > l_Q[j]:
                fn2 = (j+1)/m
                j += 1
            else:
                fn1 = (i+1)/n
                fn2 = (j+1)/m
                i += 1
                j += 1
            d_current = abs(fn1 - fn2)
            if d_current > d_max:
                d_max = d_current
        
        return {
            'ks_stat': d_max,
            'threshold': self._calculate_threshold(n, m)
        }
    
    def test(self, test_intervals: List[float], reference_intervals: List[float] = None) -> Dict[str, Any]:
        ref_intervals = reference_intervals if reference_intervals is not None else self.mining_intervals
        
        if not test_intervals or not ref_intervals:
            return {
                'verdict': 0,
                'ks_stat': 0,
                'threshold': 0,
                'error': 'Insufficient data'
            }
        
        n = len(test_intervals)
        m = len(ref_intervals)
        
        # Calculate robust KS statistic
        D_m_n = self._calculate_ks_statistic(test_intervals, ref_intervals)
        threshold = self._calculate_threshold(n, m)
        
        # More stringent verdict criteria
        verdict = 1 if D_m_n > threshold else 0
        
        # Improved confidence calculation
        if verdict == 1:
            confidence = min(100, 90 + 10 * (D_m_n - threshold) / (1 - threshold))
        else:
            confidence = min(100, 100 * (1 - (D_m_n / (threshold * 0.8))))
        
        return {
            'verdict': verdict,
            'ks_stat': D_m_n,
            'threshold': threshold,
            'intervals_count': n,
            'mining_intervals_count': m,
            'result_text': 'MINING_DETECTED' if verdict == 1 else 'NORMAL',
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        }
    
    def test_per_file(self, test_intervals: List[float]) -> Dict[str, Any]:
        if not self.has_per_file_data or not self.per_file_intervals:
            return {'combined': self.test(test_intervals)}
        
        per_file_results = {}
        for file_path, ref_intervals in self.per_file_intervals.items():
            file_name = os.path.basename(file_path)
            per_file_results[file_name] = self.test(test_intervals, ref_intervals)
        
        per_file_results['combined'] = self.test(test_intervals)
        return per_file_results
    
    def test_traffic(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        all_intervals = traffic_data.get('all', [])
        overall_result = self.test(all_intervals)
        per_file_results = self.test_per_file(all_intervals)
        
        connections_results = {}
        per_file_connections_results = {}
        suspicious_connections = []
        total_connections = len(traffic_data.get('connections', {}))
        mining_connections = 0
        
        # Stricter connection analysis requirements
        min_intervals_for_analysis = 15
        min_confidence_for_mining = 90
        
        for conn_id, conn_data in traffic_data.get('connections', {}).items():
            # Skip whitelisted connections
            if self.is_whitelisted(conn_data):
                continue
                
            conn_intervals = conn_data.get('intervals', [])
            if len(conn_intervals) < min_intervals_for_analysis:
                continue
                
            conn_result = self.test(conn_intervals)
            connections_results[conn_id] = conn_result
            
            if self.has_per_file_data:
                per_file_connections_results[conn_id] = self.test_per_file(conn_intervals)
            
            # More strict mining connection criteria
            if (conn_result['verdict'] == 1 and 
                conn_result['confidence'] >= min_confidence_for_mining and
                conn_result['ks_stat'] > conn_result['threshold'] * 1.2):
                
                mining_connections += 1
                suspicious_conn = {
                    'src_ip': conn_data.get('src_ip', 'Unknown'),
                    'dst_ip': conn_data.get('dst_ip', 'Unknown'),
                    'src_port': conn_data.get('src_port', 0),
                    'dst_port': conn_data.get('dst_port', 0),
                    'proto': conn_data.get('proto', 'unknown'),
                    'ks_stat': conn_result['ks_stat'],
                    'threshold': conn_result['threshold'],
                    'verdict': conn_result['result_text'],
                    'confidence': conn_result['confidence']
                }
                suspicious_connections.append(suspicious_conn)
        
        detection_percentage = (mining_connections / max(total_connections, 1)) * 100
        
        # Calculate packet rate
        packet_rate = 0
        if len(all_intervals) > 1:
            time_range = max(all_intervals) - min(all_intervals)
            packet_rate = len(all_intervals) / time_range if time_range > 0 else 0
        
        # Interval consistency check
        interval_std = np.std(all_intervals) if len(all_intervals) > 1 else 0
        
        # Enhanced verdict logic
        verdict_reasons = []
        mining_score = 0
        
        # 1. Primary KS test condition (very strict)
        primary_ks_condition = (
            overall_result['verdict'] == 1 and 
            overall_result['confidence'] >= 97 and 
            overall_result['ks_stat'] > overall_result['threshold'] * 1.5
        )
        
        if primary_ks_condition:
            mining_score += 40
            verdict_reasons.append("Strong overall KS test result")
        
        # 2. Secondary connection-based condition (strict)
        connection_condition = (
            mining_connections >= 3 and 
            detection_percentage > 25 and
            all(c['confidence'] >= 90 for c in suspicious_connections)
        )
        
        if connection_condition:
            mining_score += 30
            verdict_reasons.append(f"{detection_percentage:.1f}% high-confidence mining connections")
        
        # 3. Packet rate analysis
        if packet_rate > 500:  # High packet rate increases suspicion
            mining_score += 10
            verdict_reasons.append(f"High packet rate ({packet_rate:.1f} packets/sec)")
        
        # 4. Interval consistency check
        if interval_std < 0.001:  # Very consistent intervals are suspicious
            mining_score += 20
            verdict_reasons.append(f"Highly consistent intervals (std={interval_std:.6f})")
        
        # Final verdict based on accumulated score
        if mining_score >= 60:
            final_verdict = 'MINING_DETECTED'
        elif mining_score >= 30:
            final_verdict = 'SUSPICIOUS'
        else:
            final_verdict = 'NORMAL'
            if mining_connections > 0:
                verdict_reasons.append(f"Only {mining_connections} suspicious connections (insufficient for mining verdict)")
            else:
                verdict_reasons.append("No mining patterns detected")
        
        standard_result = {
            'timestamp': datetime.now().isoformat(),
            'window_size': len(all_intervals),
            'mining_stat': overall_result['ks_stat'],
            'nonmining_stat': overall_result['ks_stat'] if final_verdict == 'NORMAL' else 0,
            'confidence': overall_result['confidence'],
            'threshold': overall_result['threshold'],
            'verdict': final_verdict,
            'verdict_reasons': verdict_reasons,
            'network_metrics': {
                'packet_rate': round(packet_rate, 2),
                'detection_percentage': round(detection_percentage, 2),
                'suspicious_connections': len(suspicious_connections),
                'interval_std': round(interval_std, 6),
                'mining_score': mining_score
            },
            'suspicious_connections': suspicious_connections,
            'per_file_results': per_file_results
        }
        
        final_results = {
            'aggregate': overall_result,
            'connections': connections_results,
            'suspicious_connections': suspicious_connections,
            'standard_result': standard_result,
            'per_file_results': per_file_results,
            'per_file_connections': per_file_connections_results if self.has_per_file_data else {}
        }
        
        return final_results