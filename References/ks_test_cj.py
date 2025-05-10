#!/usr/bin/env python3
"""
Kolmogorov-Smirnov Test Module for CryptoMining Detection System

This module implements the Kolmogorov-Smirnov (KS) test strictly according to
the algorithm described for detecting cryptocurrency mining traffic patterns.
"""

import numpy as np
import logging
from typing import List, Dict, Any, Union, Optional
import time
from datetime import datetime
import json

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ks_test')

class KSTest:
    """
    Implementation of Kolmogorov-Smirnov test following the algorithm exactly.
    
    Attributes:
        alpha (float): Significance level for the KS test
        k_points (int): Number of points for CDF comparison
        mining_intervals (list): Time intervals from mining traffic
    """
    
    def __init__(self, mining_intervals: List[float], alpha: float = 0.10, k_points: int = 100):
        """
        Initialize the KS test with reference mining traffic patterns.
        
        Args:
            mining_intervals: Time intervals from mining traffic
            alpha: Significance level for KS test
            k_points: Number of points for CDF comparison
        """
        self.alpha = alpha
        self.k_points = k_points
        self.mining_intervals = mining_intervals
        
        logger.info(f"Initialized KS Test with {len(self.mining_intervals)} mining intervals")
    
    def _calculate_g_x(self, x: float) -> float:
        """
        Calculate G(x) - the cumulative distribution function of Q at point x.
        
        Args:
            x: The point at which to calculate G(x)
            
        Returns:
            The CDF value at point x
        """
        # Count how many elements in mining_intervals are <= x
        count = sum(1 for interval in self.mining_intervals if interval <= x)
        return count / len(self.mining_intervals)
    
    def test(self, test_intervals: List[float]) -> Dict[str, Any]:
        """
        Test intervals against mining reference using the KS test algorithm.
        
        Args:
            test_intervals: Time intervals from test traffic
            
        Returns:
            Dictionary containing test results
        """
        # Following the algorithm steps exactly
        
        # Step 1: Input is P (test_intervals), m (len of test_intervals), 
        # Q (mining_intervals), n (len of mining_intervals), etc.
        
        # Step 2: Output will be 1 for cryptomining, 0 for other traffic
        
        # Step 3-4: l_P and l_Q - we already have these as test_intervals and mining_intervals
        l_P = test_intervals
        l_Q = self.mining_intervals
        
        # Handle insufficient data
        if not l_P or not l_Q:
            return {
                'verdict': 0,
                'ks_stat': 0,
                'threshold': 0,
                'error': 'Insufficient data'
            }
        
        # Step 5: Calculate range of G(x)
        r = max(l_Q) - min(l_Q)
        
        # Step 6: Initialize list for differences between CDFs
        l_d = []
        
        # Step 7-15: Loop k times and calculate differences
        for i in range(self.k_points):
            # Step 8: Calculate current x value
            x = (i * r / self.k_points) + min(l_Q)
            
            # Step 9: Get elements in l_P less than or equal to x
            l = [j for j in l_P if j <= x]
            
            # Step 10: Calculate CDF value at x for P
            f = len(l) / len(l_P)
            
            # Step 11: Append absolute difference to l_d
            g_x = self._calculate_g_x(x)
            l_d.append(abs(f - g_x))
            
            # Step 12-14: Break if we've reached CDF=1
            if f == 1:
                break
        
        # Step 16: Calculate KS statistic D_m,n
        D_m_n = max(l_d)
        
        # Step 17-21: Make decision based on threshold
        m = len(l_P)
        n = len(l_Q)
        threshold = np.sqrt((-np.log(self.alpha/2) * (1 + m/n)) / (2*m))
        
        # Decision: 1 for mining, 0 for normal
        verdict = 1 if D_m_n <= threshold else 0
        
        # Return results
        return {
            'verdict': verdict,
            'ks_stat': D_m_n,
            'threshold': threshold,
            'intervals_count': m,
            'mining_intervals_count': n,
            'result_text': 'MINING_DETECTED' if verdict == 1 else 'NORMAL',
            'timestamp': datetime.now().isoformat()
        }
    
    def test_traffic(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test network traffic against mining reference.
        
        Args:
            traffic_data: Dictionary containing packet intervals
                Keys: 'all', 'connections'
                    'all' (list): All intervals
                    'connections' (dict): Connection intervals
        
        Returns:
            Dictionary containing test results
        """
        # Get all intervals
        all_intervals = traffic_data.get('all', [])
        
        # Test all intervals
        overall_result = self.test(all_intervals)
        
        # Test individual connections
        connections_results = {}
        for conn_id, conn_data in traffic_data.get('connections', {}).items():
            conn_intervals = conn_data.get('intervals', [])
            conn_result = self.test(conn_intervals)
            connections_results[conn_id] = conn_result
        
        # Get suspicious connections (those with verdict=1)
        suspicious_connections = []
        for conn_id, conn_result in connections_results.items():
            if conn_result['verdict'] == 1:
                conn_data = traffic_data['connections'][conn_id]
                suspicious_connections.append({
                    'src_ip': conn_data.get('src_ip', 'Unknown'),
                    'dst_ip': conn_data.get('dst_ip', 'Unknown'),
                    'src_port': conn_data.get('src_port', 0),
                    'dst_port': conn_data.get('dst_port', 0),
                    'proto': conn_data.get('proto', 'unknown'),
                    'ks_stat': conn_result['ks_stat'],
                    'threshold': conn_result['threshold'],
                    'verdict': conn_result['result_text']
                })
        
        # Create standard format result
        standard_result = {
            'timestamp': datetime.now().isoformat(),
            'mining_stat': overall_result['ks_stat'],
            'threshold': overall_result['threshold'],
            'verdict': overall_result['result_text'],
            'suspicious_connections': suspicious_connections
        }
        
        # Compile final results
        final_results = {
            'aggregate': overall_result,
            'connections': connections_results,
            'suspicious_connections': suspicious_connections,
            'standard_result': standard_result
        }
        
        return final_results
    
    def generate_json_report(self, result: Dict[str, Any]) -> str:
        """
        Generate a JSON report with the standard format.
        
        Args:
            result: Detection result
            
        Returns:
            JSON report as string
        """
        # Use standard result if available, otherwise create one
        report_data = result.get('standard_result', {})
        
        # Return JSON string
        return json.dumps(report_data, indent=2)