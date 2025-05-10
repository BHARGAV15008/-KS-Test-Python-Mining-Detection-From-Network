#!/usr/bin/env python3
"""
Ultra-Robust KS Test Module with Minimal False Positives
"""

import numpy as np
import logging
from typing import List, Dict, Any, Union, Optional
from datetime import datetime
import os
from scipy.stats import ks_2samp, anderson_ksamp

logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('kstest')

class KSTest:
    def __init__(self, mining_intervals, alpha: float = 0.01, k_points: int = 100):
        self.alpha = alpha
        self.k_points = k_points
        
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
        
        # Pre-compute reference statistics
        self.ref_mean = np.mean(self.mining_intervals)
        self.ref_std = np.std(self.mining_intervals)
        self.ref_median = np.median(self.mining_intervals)
        self.ref_iqr = np.percentile(self.mining_intervals, 75) - np.percentile(self.mining_intervals, 25)
    
    def _robust_normalize(self, intervals: List[float]) -> List[float]:
        """Advanced normalization with outlier rejection"""
        if len(intervals) < 5:
            return intervals
            
        # Log transform with epsilon to avoid zeros
        logged = [np.log(max(x, 1e-9)) for x in intervals]
        
        # Winsorize (clip extreme values)
        q1, q3 = np.percentile(logged, [25, 75])
        iqr = q3 - q1
        lower_bound = q1 - 1.5*iqr
        upper_bound = q3 + 1.5*iqr
        clipped = [max(min(x, upper_bound), lower_bound) for x in logged]
        
        # Standardize
        mean = np.mean(clipped)
        std = max(np.std(clipped), 1e-9)
        return [(x - mean)/std for x in clipped]
    
    def _calculate_combined_score(self, test_data: List[float], ref_data: List[float]) -> float:
        """Calculate combined statistical score using multiple tests"""
        # Normalize both datasets
        norm_test = self._robust_normalize(test_data)
        norm_ref = self._robust_normalize(ref_data)
        
        # KS Test (weight: 40%)
        ks_stat = ks_2samp(norm_test, norm_ref).statistic
        
        # Anderson-Darling Test (weight: 30%)
        try:
            ad_result = anderson_ksamp([norm_test, norm_ref])
            ad_stat = ad_result.statistic
        except Exception as e:
            logger.debug(f"Anderson-Darling test failed: {str(e)}")
            ad_stat = 0
        
        # Mean/IQR comparison (weight: 20%)
        test_mean = np.mean(norm_test)
        test_iqr = np.percentile(norm_test, 75) - np.percentile(norm_test, 25)
        ref_mean = np.mean(norm_ref)
        ref_iqr = np.percentile(norm_ref, 75) - np.percentile(norm_ref, 25)
        dist_stat = abs(test_mean - ref_mean) + abs(test_iqr - ref_iqr)
        
        # Combine scores
        combined = 0.4*ks_stat + 0.3*ad_stat + 0.2*dist_stat
        
        # Apply size correction
        n = len(test_data)
        size_correction = min(1.0, np.log(n)/np.log(100))  # Full weight only for n >= 100
        return combined * size_correction
    
    def _calculate_dynamic_threshold(self, n: int) -> float:
        """Dynamic threshold based on sample size and alpha"""
        base = np.sqrt(-np.log(self.alpha) * (1/n))
        
        # More conservative for small samples
        if n < 50:
            return base * 1.5
        elif n < 100:
            return base * 1.3
        elif n < 200:
            return base * 1.1
        return base
    
    def test(self, test_intervals: List[float], reference_intervals: List[float] = None) -> Dict[str, Any]:
        ref_intervals = reference_intervals if reference_intervals is not None else self.mining_intervals
        
        if not test_intervals or not ref_intervals or len(test_intervals) < 10:
            return {
                'verdict': 0,
                'ks_stat': 0,
                'threshold': 0,
                'error': 'Insufficient data',
                'confidence': 0
            }
        
        n = len(test_intervals)
        m = len(ref_intervals)
        
        # Calculate combined score
        score = self._calculate_combined_score(test_intervals, ref_intervals)
        threshold = self._calculate_dynamic_threshold(n)
        
        # Enhanced verdict logic
        if score > threshold * 1.5:  # Strong signal required
            verdict = 1
            confidence = min(99, 80 + 20*(score - threshold*1.5)/(threshold*0.5))
        elif score > threshold:
            verdict = 1
            confidence = min(90, 70 + 20*(score - threshold)/threshold)
        else:
            verdict = 0
            confidence = min(100, 100*(1 - score/threshold))
        
        # Additional checks to reduce false positives
        if verdict == 1:
            # Check if distributions are fundamentally different
            test_median = np.median(test_intervals)
            ref_median = np.median(ref_intervals)
            median_ratio = max(test_median, ref_median)/min(test_median, ref_median)
            
            if median_ratio < 1.5:  # Too similar to be mining
                verdict = 0
                confidence = max(confidence, 80)  # High confidence it's normal
        
        return {
            'verdict': verdict,
            'ks_stat': score,
            'threshold': threshold,
            'intervals_count': n,
            'mining_intervals_count': m,
            'result_text': 'MINING_DETECTED' if verdict == 1 else 'NORMAL',
            'confidence': confidence,
            'timestamp': datetime.now().isoformat()
        }
    
    def test_per_file(self, test_intervals: List[float]) -> Dict[str, Any]:
        """Test against each reference file separately"""
        if not self.has_per_file_data:
            return {'combined': self.test(test_intervals)}
        
        results = {}
        for file_name, ref_intervals in self.per_file_intervals.items():
            results[file_name] = self.test(test_intervals, ref_intervals)
        
        results['combined'] = self.test(test_intervals)
        return results
    
    def test_traffic(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        all_intervals = traffic_data.get('all', [])
        if len(all_intervals) < 50:  # Require minimum data
            return {
                'verdict': 0,
                'confidence': 0,
                'error': 'Insufficient data (need at least 50 intervals)'
            }
        
        overall_result = self.test(all_intervals)
        per_file_results = self.test_per_file(all_intervals) if self.has_per_file_data else {}
        
        # Connection analysis with strict criteria
        suspicious_connections = []
        total_connections = len(traffic_data.get('connections', {}))
        
        for conn_id, conn_data in traffic_data.get('connections', {}).items():
            intervals = conn_data.get('intervals', [])
            if len(intervals) < 20:  # Minimum intervals per connection
                continue
                
            result = self.test(intervals)
            if (result['verdict'] == 1 and 
                result['confidence'] > 90 and 
                result['ks_stat'] > result['threshold'] * 2.0):
                
                suspicious_conn = {
                    'src_ip': conn_data.get('src_ip', 'Unknown'),
                    'dst_ip': conn_data.get('dst_ip', 'Unknown'),
                    'src_port': conn_data.get('src_port', 0),
                    'dst_port': conn_data.get('dst_port', 0),
                    'proto': conn_data.get('proto', 'unknown'),
                    'ks_stat': result['ks_stat'],
                    'threshold': result['threshold'],
                    'verdict': result['result_text'],
                    'confidence': result['confidence']
                }
                suspicious_connections.append(suspicious_conn)
        
        # Final verdict with multiple checks
        final_verdict = 'NORMAL'
        verdict_reasons = []
        
        # Condition 1: Very strong overall signal
        if (overall_result['verdict'] == 1 and 
            overall_result['confidence'] > 95 and 
            len(suspicious_connections) > max(5, total_connections*0.3)):
            final_verdict = 'MINING_DETECTED'
            verdict_reasons.append("Strong statistical evidence with multiple suspicious connections")
        
        # Condition 2: Multiple high-confidence mining connections
        elif (len(suspicious_connections) > max(10, total_connections*0.5) and
              all(c['confidence'] > 85 for c in suspicious_connections)):
            final_verdict = 'MINING_DETECTED'
            verdict_reasons.append(f"{len(suspicious_connections)} high-confidence mining connections")
        
        # Default to normal with explanation
        else:
            if suspicious_connections:
                verdict_reasons.append(f"Found {len(suspicious_connections)} suspicious connections but insufficient for mining verdict")
            else:
                verdict_reasons.append("No mining patterns detected")
        
        return {
            'verdict': final_verdict,
            'confidence': overall_result['confidence'],
            'suspicious_connections': suspicious_connections,
            'verdict_reasons': verdict_reasons,
            'per_file_results': per_file_results,
            'standard_result': {
                'timestamp': datetime.now().isoformat(),
                'window_size': len(all_intervals),
                'mining_stat': overall_result['ks_stat'],
                'threshold': overall_result['threshold'],
                'network_metrics': {
                    'packet_rate': len(all_intervals)/(max(all_intervals) - min(all_intervals)) if len(all_intervals) > 1 else 0,
                    'suspicious_connections': len(suspicious_connections)
                }
            }
        }