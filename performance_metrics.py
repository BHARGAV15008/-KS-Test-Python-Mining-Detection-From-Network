#!/usr/bin/env python3
"""
Performance Metrics Module for CryptoMining Detection System

This module handles:
1. Calculation of performance metrics (TP, FP, TN, FN, accuracy, etc.)
2. ROC curve and AUC calculation
3. Alpha value optimization
4. Performance visualization
"""

import numpy as np
import logging
from typing import List, Dict, Any, Tuple, Optional
import json
from datetime import datetime
import matplotlib.pyplot as plt
from sklearn.metrics import precision_recall_curve, roc_curve, auc, roc_auc_score

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('performance_metrics')

class PerformanceMetrics:
    """
    Class for calculating and reporting performance metrics.
    """
    
    def __init__(self):
        """
        Initialize the performance metrics calculator.
        """
        self.metrics_history = []
    
    def calculate_basic_metrics(self, y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
        """
        Calculate basic classification metrics.
        
        Args:
            y_true: List of true labels (0 for normal, 1 for mining)
            y_pred: List of predicted labels (0 for normal, 1 for mining)
            
        Returns:
            Dictionary with metrics (TP, FP, TN, FN, accuracy, etc.)
        """
        # Initialize counters
        tp = fp = tn = fn = 0
        
        # Count TP, FP, TN, FN
        for true, pred in zip(y_true, y_pred):
            if true == 1 and pred == 1:
                tp += 1
            elif true == 0 and pred == 1:
                fp += 1
            elif true == 0 and pred == 0:
                tn += 1
            elif true == 1 and pred == 0:
                fn += 1
        
        # Calculate metrics
        accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        tnr = tn / (tn + fp) if (tn + fp) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        
        # Store in a dictionary
        metrics = {
            'tp': tp,
            'fp': fp,
            'tn': tn,
            'fn': fn,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'fpr': fpr,
            'tnr': tnr,
            'fnr': fnr,
            'total_samples': tp + fp + tn + fn
        }
        
        return metrics
    
    def calculate_roc(self, y_true: List[int], y_scores: List[float]) -> Tuple[np.ndarray, np.ndarray, float]:
        """
        Calculate ROC curve and AUC.
        
        Args:
            y_true: List of true labels (0 for normal, 1 for mining)
            y_scores: List of scores/probabilities
            
        Returns:
            Tuple of (fpr, tpr, auc)
        """
        # Calculate ROC curve
        fpr, tpr, _ = roc_curve(y_true, y_scores)
        
        # Calculate AUC
        roc_auc = auc(fpr, tpr)
        
        return fpr, tpr, roc_auc
    
    def calculate_pr(self, y_true: List[int], y_scores: List[float]) -> Tuple[np.ndarray, np.ndarray, float]:
        """
        Calculate precision-recall curve and average precision.
        
        Args:
            y_true: List of true labels (0 for normal, 1 for mining)
            y_scores: List of scores/probabilities
            
        Returns:
            Tuple of (precision, recall, average_precision)
        """
        # Calculate precision-recall curve
        precision, recall, _ = precision_recall_curve(y_true, y_scores)
        
        # Calculate average precision
        ap = auc(recall, precision)
        
        return precision, recall, ap
    
    def analyze_alpha_impact(self, alpha_values: List[float], y_true: List[int], scores: List[float]) -> Dict[float, Dict[str, float]]:
        """
        Analyze the impact of different alpha values on performance.
        
        Args:
            alpha_values: List of alpha values to test
            y_true: List of true labels (0 for normal, 1 for mining)
            scores: List of KS statistics
            
        Returns:
            Dictionary with alpha values as keys and metrics dictionaries as values
        """
        results = {}
        
        # Test each alpha value
        for alpha in alpha_values:
            # Calculate thresholds for each sample
            thresholds = []
            for i in range(len(scores)):
                m = 1  # Number of intervals in current sample (assume 1 for simplicity)
                n = 1  # Number of intervals in reference (assume 1 for simplicity)
                threshold = np.sqrt((-np.log(alpha/2) * (1 + m/n)) / (2*m))
                thresholds.append(threshold)
            
            # Make predictions based on KS test logic (D <= threshold means mining)
            y_pred = [1 if score <= threshold else 0 for score, threshold in zip(scores, thresholds)]
            
            # Calculate metrics
            metrics = self.calculate_basic_metrics(y_true, y_pred)
            
            # Store results
            results[alpha] = metrics
        
        # Store in history
        self.metrics_history.append({
            'timestamp': datetime.now().isoformat(),
            'alpha_results': results
        })
        
        return results
    
    def get_optimal_alpha(self, alpha_results: Dict[float, Dict[str, float]]) -> float:
        """
        Determine the optimal alpha value based on F1 score.
        
        Args:
            alpha_results: Dictionary from analyze_alpha_impact
            
        Returns:
            Optimal alpha value
        """
        # Find alpha with highest F1 score
        best_alpha = None
        best_f1 = -1
        
        for alpha, metrics in alpha_results.items():
            if metrics['f1_score'] > best_f1:
                best_f1 = metrics['f1_score']
                best_alpha = alpha
        
        return best_alpha
    
    def plot_performance_curves(self, y_true: List[int], y_scores: List[float]) -> Dict[str, plt.Figure]:
        """
        Plot performance curves (ROC, PR, etc.).
        
        Args:
            y_true: List of true labels (0 for normal, 1 for mining)
            y_scores: List of scores/probabilities
            
        Returns:
            Dictionary of matplotlib figures
        """
        figures = {}
        
        # Calculate ROC curve
        fpr, tpr, roc_auc = self.calculate_roc(y_true, y_scores)
        
        # Plot ROC curve
        fig_roc = plt.figure(figsize=(10, 8))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC) Curve')
        plt.legend(loc="lower right")
        plt.grid(True)
        figures['roc_curve'] = fig_roc
        
        # Calculate precision-recall curve
        precision, recall, ap = self.calculate_pr(y_true, y_scores)
        
        # Plot precision-recall curve
        fig_pr = plt.figure(figsize=(10, 8))
        plt.plot(recall, precision, color='blue', lw=2, label=f'PR curve (AP = {ap:.2f})')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('Recall')
        plt.ylabel('Precision')
        plt.title('Precision-Recall Curve')
        plt.legend(loc="lower left")
        plt.grid(True)
        figures['pr_curve'] = fig_pr
        
        return figures
    
    def generate_performance_report(self, metrics: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate a performance report.
        
        Args:
            metrics: Optional metrics dictionary (uses last calculated otherwise)
            
        Returns:
            Dictionary with performance report
        """
        if not metrics and not self.metrics_history:
            logger.warning("No metrics available for report")
            return {}
        
        # Use provided metrics or last calculated
        if metrics:
            report_metrics = metrics
        else:
            report_metrics = self.metrics_history[-1]
        
        # Create report
        report = {
            'timestamp': datetime.now().isoformat(),
            'metrics': report_metrics,
            'optimal_alpha': self.get_optimal_alpha(report_metrics.get('alpha_results', {})) 
                            if 'alpha_results' in report_metrics else None
        }
        
        return report

# Simple test if run directly
if __name__ == "__main__":
    # Test with some sample data
    metrics = PerformanceMetrics()
    
    # Create sample data
    y_true = [0, 0, 1, 1, 0, 1, 0, 1, 1, 0]
    y_pred = [0, 1, 1, 1, 0, 0, 0, 1, 0, 0]
    y_scores = [0.1, 0.7, 0.8, 0.9, 0.2, 0.3, 0.1, 0.8, 0.4, 0.2]
    
    # Calculate basic metrics
    basic_metrics = metrics.calculate_basic_metrics(y_true, y_pred)
    print("Basic metrics:")
    for k, v in basic_metrics.items():
        print(f"  {k}: {v}")
        
    # Calculate ROC curve
    fpr, tpr, roc_auc = metrics.calculate_roc(y_true, y_scores)
    print(f"\nROC AUC: {roc_auc:.4f}")
    
    # Test alpha impact
    alpha_values = [0.01, 0.05, 0.1, 0.2]
    alpha_results = metrics.analyze_alpha_impact(alpha_values, y_true, y_scores)
    print("\nAlpha impact:")
    for alpha, alpha_metrics in alpha_results.items():
        print(f"  Alpha {alpha}: F1={alpha_metrics['f1_score']:.4f}, Accuracy={alpha_metrics['accuracy']:.4f}") 