import numpy as np
from scipy import stats
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

class CryptoMiningDetector:
    def __init__(self, reference_pcap, alpha=0.1, k_points=50):
        self.alpha = alpha
        self.k_points = k_points
        self.reference_intervals = self._extract_intervals(reference_pcap)
        self.reference_cdf = self._precompute_reference_cdf()
        self.reference_range = (min(self.reference_intervals), max(self.reference_intervals))

    def _extract_intervals(self, pcap_file):
        packets = rdpcap(pcap_file)
        intervals = defaultdict(lambda: {'inbound': [], 'outbound': []})
        for pkt in packets:
            if IP in pkt and (TCP in pkt or UDP in pkt):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = 'tcp' if TCP in pkt else 'udp'
                port = pkt[TCP].dport if proto == 'tcp' else pkt[UDP].dport
                conn_key = (src_ip, dst_ip, proto, port)
                
                # Determine direction (inbound: dst is local IP; adjust as needed)
                # For simplicity, assume dst_ip is local. Replace 'local_ips' with actual IPs.
                local_ips = {"192.168.1.1"}  
                if dst_ip in local_ips:
                    intervals[conn_key]['inbound'].append(float(pkt.time))
                else:
                    intervals[conn_key]['outbound'].append(float(pkt.time))
        
        all_inbound_intervals = []
        for conn_key, directions in intervals.items():
            inbound_times = sorted(directions['inbound'])
            if len(inbound_times) < 10:
                continue
            diffs = np.diff(inbound_times).astype(float)
            all_inbound_intervals.extend(diffs)
        return all_inbound_intervals

    def _precompute_reference_cdf(self):
        sorted_ref = np.sort(self.reference_intervals)
        cdf = np.arange(1, len(sorted_ref)+1) / len(sorted_ref)
        return (sorted_ref, cdf)

    def _calculate_threshold(self, m, n):
        return np.sqrt(-np.log(self.alpha/2) * (1 + m/n) / (2*m))

    def _compute_ks_statistic(self, test_intervals):
        if len(test_intervals) < 10:
            return 0, 0
        sorted_test = np.sort(test_intervals)
        test_cdf = np.arange(1, len(sorted_test)+1 / len(sorted_test))
        
        ref_sorted, ref_cdf = self.reference_cdf
        min_ref, max_ref = self.reference_range
        step = (max_ref - min_ref) / self.k_points
        max_diff = 0
        
        for i in range(self.k_points):
            x = min_ref + i * step
            # Find proportion of test intervals <= x
            test_prop = np.searchsorted(sorted_test, x, side='right') / len(sorted_test)
            # Find ref CDF at x
            ref_prop = np.searchsorted(ref_sorted, x, side='right') / len(ref_sorted)
            diff = abs(test_prop - ref_prop)
            if diff > max_diff:
                max_diff = diff
        return max_diff

    def test_traffic(self, test_pcap):
        test_intervals = self._extract_intervals(test_pcap)
        if not test_intervals or not self.reference_intervals:
            return {"verdict": "INSUFFICIENT_DATA", "confidence": 0}
        
        ks_stat = self._compute_ks_statistic(test_intervals)
        m = len(test_intervals)
        n = len(self.reference_intervals)
        threshold = self._calculate_threshold(m, n)
        p_value = stats.kstwo.sf(ks_stat, m + n)
        confidence = 100 * (1 - p_value)
        
        verdict = "MINING_DETECTED" if ks_stat > threshold else "NORMAL"
        return {
            "verdict": verdict,
            "ks_stat": ks_stat,
            "threshold": threshold,
            "confidence": confidence
        }

# Example usage
if __name__ == "__main__":
    detector = CryptoMiningDetector("../pcap-files/unenc_mining/xmr/capture-tun0_gulf.moneroocean.stream_10128_2025-02-22_08-21-35.pcap")
    result = detector.test_traffic("../pcap-files/output_flows/flow_1.pcap")
    print(result)