#!/usr/bin/env python3
"""
Dashboard Module
Handles visualization of detection results in a web-based dashboard
"""

import os
import sys
import json
import logging
from datetime import datetime
import threading
import webbrowser
from collections import deque

try:
    import dash
    from dash import dcc, html, dash_table
    from dash.dependencies import Input, Output
    import plotly.graph_objs as go
    import plotly.express as px
    import pandas as pd
    import numpy as np
    DASH_AVAILABLE = True
except ImportError:
    print("Warning: dash, plotly, or pandas not found. Dashboard will not be available.")
    print("Install required packages using: pip install dash plotly pandas")
    DASH_AVAILABLE = False

class Dashboard:
    """Class for creating and updating a web-based dashboard"""
    
    def __init__(self, port=8050):
        """Initialize dashboard
        
        Args:
            port (int): Port to run the dashboard server on
        """
        self.port = port
        self.app = None
        self.server_thread = None
        self.running = False
        
        # Data storage
        self.detection_results = deque(maxlen=100)  # Store last 100 detection results
        self.timeline_data = {
            'time': [],
            'confidence': [],
            'state': [],
            'action': []
        }
        self.connection_data = []  # Store connection data
        self.alpha_results = {}  # Store alpha analysis results
        self.roc_data = None  # Store ROC curve data
        self.pr_data = None  # Store PR curve data
        self.distribution_data = None  # Store distribution data for normal vs mining traffic
        
        # Configure logging
        logging.basicConfig(level=logging.INFO, 
                           format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger('Dashboard')
        
        # Initialize dashboard if available
        if DASH_AVAILABLE:
            self._initialize_dashboard()
    
    def _initialize_dashboard(self):
        """Initialize Dash dashboard"""
        try:
            # Create Dash app
            self.app = dash.Dash(__name__, 
                               title='Cryptocurrency Mining Detection',
                               update_title='Updating...')
            
            # Define layout
            self.app.layout = html.Div([
                # Header
                html.Div([
                    html.H1('Cryptocurrency Mining Detection Dashboard'),
                    html.P('Real-time monitoring and analysis of network traffic for cryptocurrency mining activity'),
                    html.Div([
                        html.Button('Refresh', id='refresh-button', n_clicks=0),
                        dcc.Dropdown(
                            id='graph-selector',
                            options=[
                                {'label': 'Confidence Timeline', 'value': 'confidence'},
                                {'label': 'Connection Analysis', 'value': 'connections'},
                                {'label': 'Protocol Distribution', 'value': 'protocols'},
                                {'label': 'Alpha Analysis', 'value': 'alpha'},
                                {'label': 'ROC Curve', 'value': 'roc'},
                                {'label': 'Precision-Recall Curve', 'value': 'pr'},
                                {'label': 'KS Statistic Distribution', 'value': 'distribution'}
                            ],
                            value='confidence',
                            style={'width': '300px', 'display': 'inline-block', 'margin-left': '20px'}
                        )
                    ], style={'display': 'flex', 'align-items': 'center'}),
                ], style={'padding': '20px', 'backgroundColor': '#f8f9fa', 'marginBottom': '20px'}),
                
                # Main content
                html.Div([
                    # Left column - Detection summary
                    html.Div([
                        html.H3('Detection Summary'),
                        html.Div(id='detection-summary'),
                        
                        html.H3('Timeline'),
                        html.Div(id='timeline-table')
                    ], style={'width': '40%', 'display': 'inline-block', 'verticalAlign': 'top', 'padding': '10px'}),
                    
                    # Right column - Graphs
                    html.Div([
                        html.H3('Visualization'),
                        dcc.Graph(id='main-graph')
                    ], style={'width': '60%', 'display': 'inline-block', 'verticalAlign': 'top', 'padding': '10px'})
                ]),
                
                # Suspicious connections
                html.Div([
                    html.H3('Suspicious Connections'),
                    html.Div(id='connections-table')
                ], style={'padding': '20px', 'marginTop': '20px'}),
                
                # Footer
                html.Div([
                    html.Hr(),
                    html.P('KS Test Cryptocurrency Mining Detection System'),
                    html.P('Updates automatically every 5 seconds')
                ], style={'padding': '10px', 'textAlign': 'center', 'marginTop': '20px'}),
                
                # Interval for auto-refresh
                dcc.Interval(
                    id='interval-component',
                    interval=5*1000,  # in milliseconds (5 seconds)
                    n_intervals=0
                )
            ])
            
            # Define callbacks
            self._define_callbacks()
            
            self.logger.info("Dashboard initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing dashboard: {e}")
            self.app = None
    
    def _define_callbacks(self):
        """Define Dash callbacks"""
        if not self.app:
            return
        
        # Callback to update detection summary
        @self.app.callback(
            Output('detection-summary', 'children'),
            [Input('interval-component', 'n_intervals'),
             Input('refresh-button', 'n_clicks')]
        )
        def update_detection_summary(n_intervals, n_clicks):
            if not self.detection_results:
                return html.Div([html.P("No detection results available")])
            
            # Get latest result
            result = self.detection_results[-1]
            
            # Determine verdict class
            verdict = result.get('verdict', 'Unknown')
            verdict_color = '#28a745'  # Green for normal
            if verdict == 'SUSPICIOUS':
                verdict_color = '#ffc107'  # Yellow for suspicious
            elif verdict == 'MINING_DETECTED':
                verdict_color = '#dc3545'  # Red for mining detected
            
            # Create summary table
            summary_table = html.Table([
                html.Tr([html.Th('Parameter'), html.Th('Value')]),
                html.Tr([html.Td('Timestamp'), html.Td(result.get('timestamp', 'N/A'))]),
                html.Tr([html.Td('Verdict'), html.Td(verdict, style={'color': verdict_color, 'fontWeight': 'bold'})]),
                html.Tr([html.Td('Confidence'), html.Td(f"{result.get('confidence', 0):.4f}")]),
                html.Tr([html.Td('KS Statistic'), html.Td(f"{result.get('mining_stat', 0):.4f}")]),
                html.Tr([html.Td('Threshold'), html.Td(f"{result.get('threshold', 0):.4f}")]),
                html.Tr([html.Td('Window Size'), html.Td(f"{result.get('window_size', 0)} packets")])
            ], style={'width': '100%', 'border': '1px solid #ddd', 'borderCollapse': 'collapse'})
            
            # Add network metrics if available
            if 'network_metrics' in result:
                metrics = result['network_metrics']
                network_metrics = html.Div([
                    html.H4('Network Metrics'),
                    html.Table([
                        html.Tr([html.Th('Metric'), html.Th('Value')]),
                        html.Tr([html.Td('Packet Rate'), html.Td(f"{metrics.get('packet_rate', 0):.2f} packets/second")]),
                        html.Tr([html.Td('Latency'), html.Td(f"{metrics.get('latency', 0):.6f} seconds")]),
                        html.Tr([html.Td('Jitter'), html.Td(f"{metrics.get('jitter', 0):.6f} seconds")]),
                        html.Tr([html.Td('Average Packet Size'), html.Td(f"{metrics.get('packet_size_mean', 0):.2f} bytes")])
                    ], style={'width': '100%', 'border': '1px solid #ddd', 'borderCollapse': 'collapse'})
                ])
            else:
                network_metrics = html.Div()
            
            # Add protocols if available
            if 'used_protocols' in result and result['used_protocols']:
                protocols = html.Div([
                    html.H4('Protocols Used'),
                    html.P(", ".join(result['used_protocols']))
                ])
            else:
                protocols = html.Div()
            
            return html.Div([summary_table, network_metrics, protocols])
        
        # Callback to update timeline table
        @self.app.callback(
            Output('timeline-table', 'children'),
            [Input('interval-component', 'n_intervals'),
             Input('refresh-button', 'n_clicks')]
        )
        def update_timeline_table(n_intervals, n_clicks):
            if not self.timeline_data['time']:
                return html.Div([html.P("No timeline data available")])
            
            # Create timeline table
            rows = []
            for i in range(len(self.timeline_data['time'])):
                # Determine state color
                state = self.timeline_data['state'][i]
                state_color = '#28a745'  # Green for normal
                if state == 'SUSPICIOUS' or state == 'Suspicious':
                    state_color = '#ffc107'  # Yellow for suspicious
                elif state == 'MINING_DETECTED' or state == 'Mining Detected':
                    state_color = '#dc3545'  # Red for mining detected
                
                rows.append(html.Tr([
                    html.Td(self.timeline_data['time'][i]),
                    html.Td(self.timeline_data['confidence'][i]),
                    html.Td(state, style={'color': state_color}),
                    html.Td(self.timeline_data['action'][i])
                ]))
            
            timeline_table = html.Table(
                [html.Tr([html.Th('Time'), html.Th('Confidence'), html.Th('State'), html.Th('Action')])] + rows,
                style={'width': '100%', 'border': '1px solid #ddd', 'borderCollapse': 'collapse'}
            )
            
            return timeline_table
        
        # Callback to update connections table
        @self.app.callback(
            Output('connections-table', 'children'),
            [Input('interval-component', 'n_intervals'),
             Input('refresh-button', 'n_clicks')]
        )
        def update_connections_table(n_intervals, n_clicks):
            if not self.connection_data:
                return html.Div([html.P("No suspicious connections detected")])
            
            # Create connections table
            rows = []
            for conn in self.connection_data:
                # Determine verdict color
                verdict = conn.get('verdict', 'Unknown')
                verdict_color = '#28a745'  # Green for normal
                if verdict == 'SUSPICIOUS':
                    verdict_color = '#ffc107'  # Yellow for suspicious
                elif verdict == 'MINING_DETECTED':
                    verdict_color = '#dc3545'  # Red for mining detected
                
                rows.append(html.Tr([
                    html.Td(conn.get('src_ip', 'Unknown')),
                    html.Td(conn.get('dst_ip', 'Unknown')),
                    html.Td(str(conn.get('src_port', 'Unknown'))),
                    html.Td(str(conn.get('dst_port', 'Unknown'))),
                    html.Td(conn.get('proto', 'Unknown')),
                    html.Td(f"{conn.get('confidence', 0):.4f}"),
                    html.Td(verdict, style={'color': verdict_color})
                ]))
            
            connections_table = html.Table(
                [html.Tr([html.Th('Source IP'), html.Th('Destination IP'), html.Th('Source Port'), 
                         html.Th('Destination Port'), html.Th('Protocol'), html.Th('Confidence'), html.Th('Verdict')])]
                + rows,
                style={'width': '100%', 'border': '1px solid #ddd', 'borderCollapse': 'collapse'}
            )
            
            return connections_table
        
        # Callback to update main graph
        @self.app.callback(
            Output('main-graph', 'figure'),
            [Input('interval-component', 'n_intervals'),
             Input('refresh-button', 'n_clicks'),
             Input('graph-selector', 'value')]
        )
        def update_main_graph(n_intervals, n_clicks, graph_type):
            if graph_type == 'confidence':
                return self._create_confidence_graph()
            elif graph_type == 'connections':
                return self._create_connections_graph()
            elif graph_type == 'protocols':
                return self._create_protocols_graph()
            elif graph_type == 'alpha':
                return self._create_alpha_graph()
            elif graph_type == 'roc':
                return self._create_roc_graph()
            elif graph_type == 'pr':
                return self._create_pr_graph()
            elif graph_type == 'distribution':
                return self._create_distribution_graph()
            else:
                return self._create_confidence_graph()
    
    def _create_confidence_graph(self):
        """Create confidence timeline graph"""
        if not self.timeline_data['time']:
            return go.Figure().update_layout(title="No timeline data available")
        
        # Create figure
        fig = go.Figure()
        
        # Add confidence line
        confidence_values = [float(c) for c in self.timeline_data['confidence']]
        fig.add_trace(go.Scatter(
            x=self.timeline_data['time'],
            y=confidence_values,
            mode='lines+markers',
            name='Confidence',
            line=dict(color='blue', width=2),
            marker=dict(size=8)
        ))
        
        # Add threshold line if we have detection results
        if self.detection_results:
            threshold = self.detection_results[-1].get('threshold', 0.5)
            fig.add_trace(go.Scatter(
                x=self.timeline_data['time'],
                y=[threshold] * len(self.timeline_data['time']),
                mode='lines',
                name='Threshold',
                line=dict(color='red', width=2, dash='dash')
            ))
        
        # Update layout
        fig.update_layout(
            title="Confidence Timeline",
            xaxis_title="Time",
            yaxis_title="Confidence Level",
            yaxis=dict(range=[0, 1]),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=40, r=40, t=40, b=40),
            hovermode="closest"
        )
        
        return fig
    
    def _create_connections_graph(self):
        """Create connections analysis graph"""
        if not self.connection_data:
            return go.Figure().update_layout(title="No connection data available")
        
        # Extract data
        ips = [f"{conn.get('src_ip', 'Unknown')} → {conn.get('dst_ip', 'Unknown')}" for conn in self.connection_data]
        confidences = [conn.get('confidence', 0) for conn in self.connection_data]
        protocols = [conn.get('proto', 'Unknown') for conn in self.connection_data]
        
        # Create color map for protocols
        protocol_colors = {
            'TCP': 'blue',
            'UDP': 'green',
            'ICMP': 'orange',
            'Unknown': 'gray'
        }
        colors = [protocol_colors.get(p, 'gray') for p in protocols]
        
        # Create figure
        fig = go.Figure()
        
        # Add bars
        fig.add_trace(go.Bar(
            x=ips,
            y=confidences,
            marker_color=colors,
            text=protocols,
            hovertemplate="%{x}<br>Confidence: %{y:.4f}<br>Protocol: %{text}<extra></extra>"
        ))
        
        # Add threshold line if we have detection results
        if self.detection_results:
            threshold = self.detection_results[-1].get('threshold', 0.5)
            fig.add_shape(
                type="line",
                x0=-0.5,
                y0=threshold,
                x1=len(ips) - 0.5,
                y1=threshold,
                line=dict(color="red", width=2, dash="dash")
            )
        
        # Update layout
        fig.update_layout(
            title="Connection Analysis",
            xaxis_title="Connection",
            yaxis_title="Confidence Level",
            yaxis=dict(range=[0, 1]),
            margin=dict(l=40, r=40, t=40, b=40),
            hovermode="closest"
        )
        
        return fig
    
    def _create_protocols_graph(self):
        """Create protocols distribution graph"""
        if not self.detection_results or 'used_protocols' not in self.detection_results[-1]:
            return go.Figure().update_layout(title="No protocol data available")
        
        # Extract protocols from all detection results
        all_protocols = []
        for result in self.detection_results:
            if 'used_protocols' in result:
                all_protocols.extend(result['used_protocols'])
        
        if not all_protocols:
            return go.Figure().update_layout(title="No protocol data available")
        
        # Count protocol occurrences
        protocol_counts = {}
        for protocol in all_protocols:
            if protocol in protocol_counts:
                protocol_counts[protocol] += 1
            else:
                protocol_counts[protocol] = 1
        
        # Create figure
        labels = list(protocol_counts.keys())
        values = list(protocol_counts.values())
        
        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            hole=.3,
            textinfo='label+percent',
            insidetextorientation='radial'
        )])
        
        # Update layout
        fig.update_layout(
            title="Protocol Distribution",
            margin=dict(l=40, r=40, t=40, b=40)
        )
        
        return fig
    
    def _create_alpha_graph(self):
        """Create alpha analysis graph"""
        if not self.alpha_results:
            return go.Figure().update_layout(title="No alpha analysis data available")
        
        # Extract data
        alphas = sorted(self.alpha_results.keys())
        accuracy = [self.alpha_results[a]['accuracy'] for a in alphas]
        precision = [self.alpha_results[a]['precision'] for a in alphas]
        recall = [self.alpha_results[a]['recall'] for a in alphas]
        f1 = [self.alpha_results[a]['f1_score'] for a in alphas]
        fpr = [self.alpha_results[a]['fpr'] for a in alphas]
        
        # Create figure
        fig = go.Figure()
        
        # Add traces
        fig.add_trace(go.Scatter(
            x=alphas,
            y=accuracy,
            mode='lines+markers',
            name='Accuracy',
            line=dict(color='blue', width=2),
            marker=dict(size=8)
        ))
        
        fig.add_trace(go.Scatter(
            x=alphas,
            y=precision,
            mode='lines+markers',
            name='Precision',
            line=dict(color='green', width=2),
            marker=dict(size=8)
        ))
        
        fig.add_trace(go.Scatter(
            x=alphas,
            y=recall,
            mode='lines+markers',
            name='Recall',
            line=dict(color='red', width=2),
            marker=dict(size=8)
        ))
        
        fig.add_trace(go.Scatter(
            x=alphas,
            y=f1,
            mode='lines+markers',
            name='F1 Score',
            line=dict(color='purple', width=2),
            marker=dict(size=8)
        ))
        
        fig.add_trace(go.Scatter(
            x=alphas,
            y=fpr,
            mode='lines+markers',
            name='False Positive Rate',
            line=dict(color='orange', width=2),
            marker=dict(size=8)
        ))
        
        # Update layout
        fig.update_layout(
            title="Impact of Alpha Value on Performance Metrics",
            xaxis_title="Alpha Value",
            yaxis_title="Metric Value",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=40, r=40, t=40, b=40),
            hovermode="closest"
        )
        
        return fig
    
    def _create_roc_graph(self):
        """Create ROC curve graph"""
        if not self.roc_data:
            return go.Figure().update_layout(title="No ROC curve data available")
        
        # Extract data
        fpr, tpr, roc_auc = self.roc_data
        
        # Create figure
        fig = go.Figure()
        
        # Add ROC curve
        fig.add_trace(go.Scatter(
            x=fpr,
            y=tpr,
            mode='lines',
            name=f'ROC curve (area = {roc_auc:.2f})',
            line=dict(color='darkorange', width=2)
        ))
        
        # Add diagonal line (random classifier)
        fig.add_trace(go.Scatter(
            x=[0, 1],
            y=[0, 1],
            mode='lines',
            name='Random',
            line=dict(color='navy', width=2, dash='dash')
        ))
        
        # Update layout
        fig.update_layout(
            title="Receiver Operating Characteristic (ROC) Curve",
            xaxis_title="False Positive Rate",
            yaxis_title="True Positive Rate",
            xaxis=dict(range=[0, 1]),
            yaxis=dict(range=[0, 1.05]),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=40, r=40, t=40, b=40),
            hovermode="closest"
        )
        
        return fig
    
    def _create_pr_graph(self):
        """Create precision-recall curve graph"""
        if not self.pr_data:
            return go.Figure().update_layout(title="No precision-recall curve data available")
        
        # Extract data
        precision, recall, average_precision = self.pr_data
        
        # Create figure
        fig = go.Figure()
        
        # Add precision-recall curve
        fig.add_trace(go.Scatter(
            x=recall,
            y=precision,
            mode='lines',
            name=f'PR curve (AP = {average_precision:.2f})',
            line=dict(color='blue', width=2)
        ))
        
        # Update layout
        fig.update_layout(
            title="Precision-Recall Curve",
            xaxis_title="Recall",
            yaxis_title="Precision",
            xaxis=dict(range=[0, 1]),
            yaxis=dict(range=[0, 1.05]),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=40, r=40, t=40, b=40),
            hovermode="closest"
        )
        
        return fig
    
    def _create_distribution_graph(self):
        """Create KS statistic distribution graph"""
        if not self.distribution_data:
            return go.Figure().update_layout(title="No distribution data available")
        
        # Extract data
        normal_scores, mining_scores = self.distribution_data
        
        # Create figure
        fig = go.Figure()
        
        # Add normal traffic histogram
        fig.add_trace(go.Histogram(
            x=normal_scores,
            name='Normal Traffic',
            opacity=0.7,
            marker_color='blue',
            nbinsx=30
        ))
        
        # Add mining traffic histogram
        fig.add_trace(go.Histogram(
            x=mining_scores,
            name='Mining Traffic',
            opacity=0.7,
            marker_color='red',
            nbinsx=30
        ))
        
        # Add threshold line if we have detection results
        if self.detection_results:
            threshold = self.detection_results[-1].get('threshold', 0.5)
            fig.add_shape(
                type="line",
                x0=threshold,
                y0=0,
                x1=threshold,
                y1=1,
                yref="paper",
                line=dict(color="green", width=2, dash="dash")
            )
            
            # Add annotation for threshold
            fig.add_annotation(
                x=threshold,
                y=1,
                yref="paper",
                text=f"Threshold: {threshold:.4f}",
                showarrow=True,
                arrowhead=1,
                ax=40,
                ay=-40
            )
        
        # Update layout
        fig.update_layout(
            title="KS Statistic Distribution",
            xaxis_title="KS Statistic",
            yaxis_title="Frequency",
            barmode='overlay',
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=40, r=40, t=40, b=40),
            hovermode="closest"
        )
        
        return fig
    
    def start(self):
        """Start the dashboard server"""
        if not DASH_AVAILABLE or not self.app:
            self.logger.warning("Dashboard not available. Required packages not installed.")
            return False
        
        if self.running:
            self.logger.warning("Dashboard already running")
            return True
        
        try:
            # Start server in a separate thread
            self.server_thread = threading.Thread(
                target=self._run_server,
                daemon=True
            )
            self.server_thread.start()
            
            # Wait a moment for server to start
            import time
            time.sleep(1)
            
            # Open browser if server started successfully
            if self.running:
                webbrowser.open(f"http://localhost:{self.port}")
            
            return self.running
            
        except Exception as e:
            self.logger.error(f"Error starting dashboard: {e}")
            return False
    
    def _run_server(self):
        """Run the Dash server"""
        try:
            self.running = True
            self.app.run_server(debug=False, port=self.port, host='0.0.0.0')
        except Exception as e:
            self.logger.error(f"Error running dashboard server: {e}")
            self.running = False
    
    def stop(self):
        """Stop the dashboard server"""
        self.running = False
        # Note: There's no clean way to stop a Dash server from code
        # The thread will be terminated when the main program exits
    
    def update(self, result):
        """Update dashboard with new detection result
        
        Args:
            result (dict): Detection result
        """
        if not DASH_AVAILABLE or not self.app or not self.running:
            return
        
        try:
            # Add result to detection results
            self.detection_results.append(result)
            
            # Update timeline data
            if 'timeline' in result and result['timeline']['time']:
                self.timeline_data = result['timeline']
            
            # Update connection data
            if 'suspicious_connections' in result and result['suspicious_connections']:
                self.connection_data = result['suspicious_connections']
            
        except Exception as e:
            self.logger.error(f"Error updating dashboard: {e}")
    
    def update_alpha_results(self, results):
        """Update dashboard with alpha analysis results
        
        Args:
            results (dict): Alpha analysis results
        """
        if not DASH_AVAILABLE or not self.app or not self.running:
            return
        
        try:
            self.alpha_results = results
        except Exception as e:
            self.logger.error(f"Error updating alpha results: {e}")
    
    def update_roc_data(self, fpr, tpr, roc_auc):
        """Update dashboard with ROC curve data
        
        Args:
            fpr (list): False positive rates
            tpr (list): True positive rates
            roc_auc (float): Area under ROC curve
        """
        if not DASH_AVAILABLE or not self.app or not self.running:
            return
        
        try:
            self.roc_data = (fpr, tpr, roc_auc)
        except Exception as e:
            self.logger.error(f"Error updating ROC data: {e}")
    
    def update_pr_data(self, precision, recall, average_precision):
        """Update dashboard with precision-recall curve data
        
        Args:
            precision (list): Precision values
            recall (list): Recall values
            average_precision (float): Average precision
        """
        if not DASH_AVAILABLE or not self.app or not self.running:
            return
        
        try:
            self.pr_data = (precision, recall, average_precision)
        except Exception as e:
            self.logger.error(f"Error updating PR data: {e}")
            
    def update_distribution_data(self, normal_scores, mining_scores):
        """Update KS statistic distribution data
        
        Args:
            normal_scores (list): KS statistics for normal traffic
            mining_scores (list): KS statistics for mining traffic
        """
        if not DASH_AVAILABLE or not self.app or not self.running:
            return
        
        try:
            self.distribution_data = (normal_scores, mining_scores)
        except Exception as e:
            self.logger.error(f"Error updating distribution data: {e}")

# Example usage
if __name__ == "__main__":
    if not DASH_AVAILABLE:
        print("Dashboard requires dash, plotly, and pandas packages.")
        print("Install using: pip install dash plotly pandas")