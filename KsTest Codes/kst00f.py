#!/usr/bin/env python3

"""

Kolmogorov-Smirnov Test Module for CryptoMining Detection System

"""



import numpy as np

import logging

from typing import List, Dict, Any, Union, Optional

from datetime import datetime

import json

import os

from scipy.stats import ks_2samp



logging.basicConfig(level=logging.INFO, 

                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

logger = logging.getLogger('kstest')



class KSTest:

    def __init__(self, mining_intervals, alpha: float = 0.05, k_points: int = 100):

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

    

    def _calculate_ks_statistic(self, test_data: List[float], ref_data: List[float]) -> float:

        """Calculate KS statistic using scipy's more robust implementation"""

        if len(test_data) < 10 or len(ref_data) < 10:

            # For small samples, use our own implementation

            return self._basic_ks_test(test_data, ref_data)['ks_stat']

        return ks_2samp(test_data, ref_data).statistic

    

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

            'threshold': np.sqrt(-np.log(self.alpha/2) * (1 + n/m) / (2*n))

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

        

        # Use scipy's KS test for larger samples, our implementation for small ones

        if len(test_intervals) >= 10 and len(ref_intervals) >= 10:

            ks_result = ks_2samp(test_intervals, ref_intervals)

            D_m_n = ks_result.statistic

            threshold = np.sqrt(-np.log(self.alpha/2) * (1 + len(test_intervals)/len(ref_intervals)) / (2*len(test_intervals)))

        else:

            basic_result = self._basic_ks_test(test_intervals, ref_intervals)

            D_m_n = basic_result['ks_stat']

            threshold = basic_result['threshold']

        

        # More conservative threshold adjustment

        adjusted_threshold = threshold * 1.5  # Increase threshold to reduce false positives

        

        # Verdict: 1 for mining, 0 for normal

        verdict = 1 if D_m_n > adjusted_threshold else 0

        

        # Calculate confidence more carefully

        if verdict == 1:

            confidence = min(100, max(0, (D_m_n - adjusted_threshold) / (1 - adjusted_threshold) * 100))

        else:

            confidence = min(100, max(0, (adjusted_threshold - D_m_n) / adjusted_threshold * 100))

        

        return {

            'verdict': verdict,

            'ks_stat': D_m_n,

            'threshold': adjusted_threshold,

            'intervals_count': len(test_intervals),

            'mining_intervals_count': len(ref_intervals),

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

        

        # Only consider connections with enough intervals

        min_intervals_for_analysis = 5

        

        for conn_id, conn_data in traffic_data.get('connections', {}).items():

            conn_intervals = conn_data.get('intervals', [])

            if len(conn_intervals) < min_intervals_for_analysis:

                continue

                

            conn_result = self.test(conn_intervals)

            connections_results[conn_id] = conn_result

            

            if self.has_per_file_data:

                per_file_connections_results[conn_id] = self.test_per_file(conn_intervals)

            

            if conn_result['verdict'] == 1 and conn_result['confidence'] > 70:  # Only count high-confidence mining connections

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

        

        detection_percentage = (mining_connections / total_connections * 100) if total_connections > 0 else 0

        

        # Calculate packet rate only if we have enough data

        if len(all_intervals) > 1:

            time_range = max(all_intervals) - min(all_intervals)

            packet_rate = len(all_intervals) / time_range if time_range > 0 else 0

        else:

            packet_rate = 0

        

        # Final verdict logic - more conservative

        if overall_result['verdict'] == 1 and overall_result['confidence'] > 80:

            final_verdict = 'MINING_DETECTED'

        elif mining_connections > 0 and detection_percentage > 30:

            final_verdict = 'MINING_DETECTED'

        else:

            final_verdict = 'NORMAL'

        

        standard_result = {

            'timestamp': datetime.now().isoformat(),

            'window_size': len(all_intervals),

            'mining_stat': overall_result['ks_stat'],

            'nonmining_stat': overall_result['ks_stat'] if final_verdict == 'NORMAL' else 0,

            'confidence': overall_result['confidence'],

            'threshold': overall_result['threshold'],

            'verdict': final_verdict,

            'network_metrics': {

                'packet_rate': round(packet_rate, 2),

                'detection_percentage': round(detection_percentage, 2),

                'suspicious_connections': len(suspicious_connections)

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