#!/usr/bin/env python3
"""
Dashboard Module for CryptoMining Detection System

This module handles:
1. Web dashboard creation using Dash
2. Real-time visualization of detection results
3. Display of performance metrics and statistics
"""

import os
import logging
import threading
import webbrowser
from typing import List, Dict, Any, Optional
import json
import time
from datetime import datetime
import pathlib
from collections import deque

# Dash imports for web dashboard
try:
    import dash
    from dash import dcc, html, dash_table
    from dash.dependencies import Input, Output
    import dash_bootstrap_components as dbc
    import plotly.graph_objs as go
    import plotly.express as px
    import pandas as pd
    import numpy as np
    DASH_AVAILABLE = True
except ImportError:
    print("Warning: Dash or plotly not installed. Dashboard won't work.")
    print("Install with: pip install dash dash-bootstrap-components plotly pandas")
    DASH_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('dashboard')

class Dashboard:
    """
    Class for creating and managing the web dashboard.
    """
    
    def __init__(self, port: int = 8050):
        """
        Initialize the dashboard.
        
        Args:
            port: Port to run the dashboard server on
        """
        self.port = port
        self.app = None
        self.server_thread = None
        self.is_running = False
        
        # Data storage
        self.detection_results = deque(maxlen=100)  # Store last 100 detection results
        self.latest_results = {}
        self.history = []
        self.connection_history = {}
        self.timeline_data = {
            'time': [],
            'confidence': [],
            'state': [],
            'action': []
        }
        self.alpha_results = {}
        self.roc_data = {'fpr': [], 'tpr': [], 'auc': 0}
        self.pr_data = {'precision': [], 'recall': [], 'ap': 0}
        self.distribution_data = None  # Store distribution data for normal vs mining traffic
        
        # Set up the dashboard assets folder
        self.assets_folder = self._create_assets_folder()
        
        # Initialize dashboard if available
        if DASH_AVAILABLE:
            self._setup_dashboard()
    
    def _create_assets_folder(self) -> str:
        """
        Create the assets folder for dashboard static files.
        
        Returns:
            Path to assets folder
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        assets_folder = os.path.join(script_dir, 'dashboard', 'assets')
        
        # Create folders if they don't exist
        if not os.path.exists(os.path.join(script_dir, 'dashboard')):
            os.makedirs(os.path.join(script_dir, 'dashboard'))
            
        if not os.path.exists(assets_folder):
            os.makedirs(assets_folder)
        
        # Create CSS file
        css_file = os.path.join(assets_folder, 'style.css')
        if not os.path.exists(css_file):
            with open(css_file, 'w') as f:
                f.write("""
                /* Dashboard CSS styles */
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                }
                
                body {
                    background-color: #f5f5f5;
                    color: #333;
                    padding: 20px;
                }
                
                .header {
                    background-color: #2c3e50;
                    color: white;
                    padding: 20px;
                    margin-bottom: 20px;
                    border-radius: 5px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }
                
                .card {
                    margin-bottom: 20px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                    border-radius: 5px;
                    background-color: white;
                }
                
                .card-header {
                    background-color: #2c3e50;
                    color: white;
                    font-weight: bold;
                    padding: 10px 15px;
                    border-top-left-radius: 5px;
                    border-top-right-radius: 5px;
                }
                
                .card-body {
                    padding: 15px;
                }
                
                .status-normal {
                    color: #27ae60;
                    font-weight: bold;
                }
                
                .status-suspicious {
                    color: #f39c12;
                    font-weight: bold;
                }
                
                .status-mining {
                    color: #e74c3c;
                    font-weight: bold;
                }
                
                .tab-content {
                    padding: 15px;
                }
                
                .graph-container {
                    background-color: white;
                    padding: 15px;
                    border-radius: 5px;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                    margin-bottom: 20px;
                }
                
                .alert-mining {
                    background-color: #fadbd8;
                    color: #721c24;
                    border-color: #f5c6cb;
                }
                
                .alert-normal {
                    background-color: #d5f5e3;
                    color: #155724;
                    border-color: #c3e6cb;
                }
                
                .alert-suspicious {
                    background-color: #fef9e7;
                    color: #8a6d3b;
                    border-color: #faebcc;
                }
                
                .connection-table {
                    width: 100%;
                    border-collapse: collapse;
                }
                
                .connection-table th, .connection-table td {
                    padding: 10px;
                    text-align: left;
                    border-bottom: 1px solid #ecf0f1;
                }
                
                .connection-table tr:hover {
                    background-color: #f5f5f5;
                }
                
                .connection-table th {
                    background-color: #2c3e50;
                    color: white;
                }
                
                .metrics-grid {
                    display: grid;
                    grid-template-columns: repeat(3, 1fr);
                    gap: 15px;
                    margin-bottom: 15px;
                }
                
                .metric-card {
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    text-align: center;
                }
                
                .metric-title {
                    font-size: 0.9rem;
                    color: #7f8c8d;
                    margin-bottom: 5px;
                }
                
                .metric-card .metric-value {
                    font-size: 1.3rem;
                    font-weight: bold;
                    color: #2c3e50;
                }
                
                /* Responsive adjustments */
                @media (max-width: 1024px) {
                    .metrics-grid {
                        grid-template-columns: 1fr;
                    }
                }
                """)
        
        return os.path.join(script_dir, 'dashboard')
    
    def _setup_dashboard(self):
        """Set up the Dash dashboard."""
        try:
            # Check if Dash is installed
            if not DASH_AVAILABLE:
                logger.warning("Dash libraries not available. Dashboard not created.")
                return
            
            # Create Dash app
            self.app = dash.Dash(
                __name__,
                assets_folder=self.assets_folder,
                external_stylesheets=[dbc.themes.BOOTSTRAP]
            )
            
            # Set up app layout
            self.app.layout = html.Div([
                # Header
                html.Div([
                    html.H2("क्रिप्टोमाइनिंग डिटेक्शन डैशबोर्ड", className="text-center"),
                    html.P("नेटवर्क ट्रैफिक में क्रिप्टोमाइनिंग गतिविधियों की निगरानी के लिए", 
                           className="text-center")
                ], className="header"),
                
                # Main content
                dbc.Container([
                    # Status and details section
                    dbc.Row([
                        # Status card
                        dbc.Col([
                            dbc.Card([
                                dbc.CardHeader("डिटेक्शन स्टेटस"),
                                dbc.CardBody([
                                    html.H4(id="status-text", className="status-normal"),
                                    html.P(id="status-description"),
                                    html.Hr(),
                                    html.Div([
                                        html.P([html.Strong("आखिरी अपडेट: "), html.Span(id="last-update")]),
                                        html.P([html.Strong("विंडो साइज: "), html.Span(id="window-size")]),
                                        html.P([html.Strong("कॉन्फिडेंस: "), html.Span(id="confidence-level")]),
                                    ])
                                ])
                            ])
                        ], md=4),
                        
                        # Quick stats
                        dbc.Col([
                            dbc.Card([
                                dbc.CardHeader("डिटेक्शन मेट्रिक्स"),
                                dbc.CardBody([
                                    dbc.Row([
                                        dbc.Col([
                                            html.P([html.Strong("KS स्टैटिस्टिक: "), html.Span(id="ks-stat")]),
                                            html.P([html.Strong("थ्रेशोल्ड: "), html.Span(id="threshold")]),
                                        ]),
                                        dbc.Col([
                                            html.P([html.Strong("पैकेट रेट: "), html.Span(id="packet-rate")]),
                                            html.P([html.Strong("संदिग्ध कनेक्शन: "), 
                                                   html.Span(id="suspicious-count")]),
                                        ])
                                    ])
                                ])
                            ]),
                            html.Br(),
                            dbc.Card([
                                dbc.CardHeader("रीयल-टाइम एक्शन"),
                                dbc.CardBody([
                                    dcc.Interval(id='interval-component', interval=5000, n_intervals=0),
                                    dbc.Button("डेटा रिफ्रेश करें", id="refresh-button", color="primary", 
                                               className="mr-2"),
                                    dbc.Button("हिस्ट्री क्लियर करें", id="clear-button", color="secondary")
                                ])
                            ])
                        ], md=8)
                    ]),
                    
                    html.Br(),
                    
                    # Tabs for different views
                    dbc.Tabs([
                        # Graph view tab
                        dbc.Tab(label="CDF कम्पैरिज़न", children=[
                            dbc.Row([
                                dbc.Col([
                                    html.Div([
                                        dcc.Graph(id="cdf-graph")
                                    ], className="graph-container")
                                ], md=12)
                            ])
                        ]),
                        
                        # Detection timeline tab
                        dbc.Tab(label="डिटेक्शन टाइमलाइन", children=[
                            dbc.Row([
                                dbc.Col([
                                    html.Div([
                                        dcc.Graph(id="timeline-graph")
                                    ], className="graph-container")
                                ], md=12)
                            ])
                        ]),
                        
                        # Suspicious connections tab
                        dbc.Tab(label="संदिग्ध कनेक्शन", children=[
                            dbc.Row([
                                dbc.Col([
                                    html.Div(id="connections-table", className="graph-container")
                                ], md=12)
                            ])
                        ]),
                        
                        # Performance metrics tab
                        dbc.Tab(label="प्रदर्शन मेट्रिक्स", children=[
                            dbc.Row([
                                dbc.Col([
                                    html.Div([
                                        dbc.Row([
                                            dbc.Col([
                                                html.H5("ROC कर्व", className="text-center"),
                                                dcc.Graph(id="roc-curve")
                                            ], md=6),
                                            dbc.Col([
                                                html.H5("प्रिसिजन-रिकॉल कर्व", className="text-center"),
                                                dcc.Graph(id="pr-curve")
                                            ], md=6)
                                        ]),
                                        html.Br(),
                                        html.H5("अल्फा वैल्यू का प्रभाव", className="text-center"),
                                        dcc.Graph(id="alpha-impact")
                                    ], className="graph-container")
                                ], md=12)
                            ])
                        ])
                    ])
                ])
            ])
            
            # Set up callbacks
            self._setup_callbacks()
            
            logger.info("Dashboard setup complete")
            
        except Exception as e:
            logger.error(f"Error setting up dashboard: {str(e)}")
            self.app = None
    
    def _setup_callbacks(self):
        """Set up Dash callbacks for updating the dashboard."""
        if not self.app:
            return
            
        # Update status
        @self.app.callback(
            [Output("status-text", "children"),
             Output("status-text", "className"),
             Output("status-description", "children"),
             Output("last-update", "children"),
             Output("window-size", "children"),
             Output("confidence-level", "children"),
             Output("ks-stat", "children"),
             Output("threshold", "children"),
             Output("packet-rate", "children"),
             Output("suspicious-count", "children")],
            [Input("interval-component", "n_intervals"),
             Input("refresh-button", "n_clicks")]
        )
        def update_status(n_intervals, n_clicks):
            if not self.detection_results:
                return (
                    "कोई डेटा नहीं", "status-normal", "डिटेक्शन डेटा का इंतज़ार...",
                    "उपलब्ध नहीं", "उपलब्ध नहीं", "उपलब्ध नहीं", "उपलब्ध नहीं", "उपलब्ध नहीं", "उपलब्ध नहीं", "उपलब्ध नहीं"
                )
                
            # Get latest result
            latest_result = self.detection_results[-1]
            
            verdict = latest_result.get('verdict', 'UNKNOWN')
            timestamp = latest_result.get('timestamp', 'N/A')
            window_size = str(latest_result.get('window_size', 'N/A'))
            confidence = f"{latest_result.get('confidence', 0):.2f}%"
            ks_stat = f"{latest_result.get('mining_stat', 0):.4f}"
            threshold = f"{latest_result.get('threshold', 0):.4f}"
            
            # Network metrics
            network_metrics = latest_result.get('network_metrics', {})
            packet_rate = f"{network_metrics.get('packet_rate', 0)} packets/s"
            
            # Suspicious connections
            suspicious_conns = latest_result.get('suspicious_connections', [])
            suspicious_count = str(len(suspicious_conns))
            
            # Set status class and description
            if verdict == 'MINING_DETECTED':
                status_class = "status-mining"
                description = "नेटवर्क ट्रैफिक में क्रिप्टोमाइनिंग गतिविधि मिली!"
            elif verdict == 'SUSPICIOUS':
                status_class = "status-suspicious"
                description = "संदिग्ध पैटर्न मिले, निगरानी जारी है."
            else:
                status_class = "status-normal"
                description = "कोई क्रिप्टोमाइनिंग गतिविधि नहीं मिली."
            
            return (
                verdict, status_class, description,
                timestamp, window_size, confidence,
                ks_stat, threshold, packet_rate, suspicious_count
            )
        
        # Update CDF graph
        @self.app.callback(
            Output("cdf-graph", "figure"),
            [Input("interval-component", "n_intervals"),
             Input("refresh-button", "n_clicks")]
        )
        def update_cdf_graph(n_intervals, n_clicks):
            if not self.detection_results:
                return {
                    'data': [],
                    'layout': {
                        'title': 'CDF कम्पैरिज़न - डेटा उपलब्ध नहीं',
                        'xaxis': {'title': 'इंटरवल वैल्यू'},
                        'yaxis': {'title': 'क्यूमुलेटिव प्रोबेबिलिटी'}
                    }
                }
            
            # In a real implementation, we would use actual CDF data
            # Here we're just creating a placeholder
            x1 = list(range(10))
            y1 = [i/9 for i in range(10)]
            
            x2 = list(range(10))
            y2 = [(i/9)**2 for i in range(10)]
            
            return {
                'data': [
                    go.Scatter(
                        x=x1,
                        y=y1,
                        mode='lines',
                        name='टेस्ट ट्रैफिक'
                    ),
                    go.Scatter(
                        x=x2,
                        y=y2,
                        mode='lines',
                        name='माइनिंग रेफरेंस'
                    )
                ],
                'layout': {
                    'title': 'CDF कम्पैरिज़न',
                    'xaxis': {'title': 'इंटरवल वैल्यू'},
                    'yaxis': {'title': 'क्यूमुलेटिव प्रोबेबिलिटी'},
                    'legend': {'x': 0, 'y': 1}
                }
            }
        
        # Update timeline graph
        @self.app.callback(
            Output("timeline-graph", "figure"),
            [Input("interval-component", "n_intervals"),
             Input("refresh-button", "n_clicks")]
        )
        def update_timeline_graph(n_intervals, n_clicks):
            if not self.history and not self.detection_results:
                return {
                    'data': [],
                    'layout': {
                        'title': 'डिटेक्शन टाइमलाइन - डेटा उपलब्ध नहीं',
                        'xaxis': {'title': 'समय'},
                        'yaxis': {'title': 'कॉन्फिडेंस'}
                    }
                }
            
            # Extract data from history
            timestamps = []
            confidences = []
            states = []
            
            # Use detection_results if history is empty
            data_source = self.history if self.history else list(self.detection_results)
            
            for entry in data_source[-20:]:  # Show last 20 entries
                timestamps.append(entry.get('timestamp', ''))
                confidences.append(entry.get('confidence', 0))
                
                # Determine state
                verdict = entry.get('verdict', '')
                if verdict == 'MINING_DETECTED':
                    states.append('माइनिंग मिली')
                elif verdict == 'SUSPICIOUS':
                    states.append('संदिग्ध')
                else:
                    states.append('सामान्य')
            
            return {
                'data': [
                    go.Scatter(
                        x=timestamps,
                        y=confidences,
                        mode='lines+markers',
                        name='कॉन्फिडेंस',
                        text=states,
                        hovertemplate='समय: %{x}<br>कॉन्फिडेंस: %{y:.2f}%<br>स्थिति: %{text}'
                    )
                ],
                'layout': {
                    'title': 'डिटेक्शन कॉन्फिडेंस टाइमलाइन',
                    'xaxis': {'title': 'समय'},
                    'yaxis': {'title': 'कॉन्फिडेंस (%)'},
                    'showlegend': False
                }
            }
        
        # Update connections table
        @self.app.callback(
            Output("connections-table", "children"),
            [Input("interval-component", "n_intervals"),
             Input("refresh-button", "n_clicks")]
        )
        def update_connections_table(n_intervals, n_clicks):
            if not self.detection_results:
                return html.P("कोई संदिग्ध कनेक्शन नहीं मिले.")
                
            # Get latest result
            latest_result = self.detection_results[-1]
            suspicious_conns = latest_result.get('suspicious_connections', [])
            
            if not suspicious_conns:
                return html.P("कोई संदिग्ध कनेक्शन नहीं मिले.")
                
            # Create table header
            table = html.Table([
                html.Thead(
                    html.Tr([
                        html.Th("स्रोत"),
                        html.Th("गंतव्य"),
                        html.Th("प्रोटोकॉल"),
                        html.Th("KS स्टैट"),
                        html.Th("थ्रेशोल्ड"),
                        html.Th("कॉन्फिडेंस"),
                        html.Th("निर्णय")
                    ])
                ),
                html.Tbody([
                    html.Tr([
                        html.Td(f"{conn.get('src_ip', 'अज्ञात')}:{conn.get('src_port', 'अज्ञात')}"),
                        html.Td(f"{conn.get('dst_ip', 'अज्ञात')}:{conn.get('dst_port', 'अज्ञात')}"),
                        html.Td(conn.get('proto', 'अज्ञात')),
                        html.Td(f"{conn.get('ks_stat', 0):.4f}"),
                        html.Td(f"{conn.get('threshold', 0):.4f}"),
                        html.Td(f"{conn.get('confidence', 0):.2f}%"),
                        html.Td(conn.get('verdict', 'अज्ञात'))
                    ]) for conn in suspicious_conns
                ])
            ], className="connection-table")
            
            return table
        
        # Update ROC curve
        @self.app.callback(
            Output("roc-curve", "figure"),
            [Input("interval-component", "n_intervals")]
        )
        def update_roc_curve(n_intervals):
            if not self.roc_data['fpr'] or not self.roc_data['tpr']:
                return {
                    'data': [],
                    'layout': {
                        'title': 'ROC कर्व - डेटा उपलब्ध नहीं',
                        'xaxis': {'title': 'फॉल्स पॉजिटिव रेट'},
                        'yaxis': {'title': 'ट्रू पॉजिटिव रेट'}
                    }
                }
                
            return {
                'data': [
                    go.Scatter(
                        x=self.roc_data['fpr'],
                        y=self.roc_data['tpr'],
                        mode='lines',
                        name=f"ROC कर्व (AUC = {self.roc_data['auc']:.2f})",
                        line=dict(color='darkorange', width=2)
                    ),
                    go.Scatter(
                        x=[0, 1],
                        y=[0, 1],
                        mode='lines',
                        name='रैंडम',
                        line=dict(color='navy', width=2, dash='dash')
                    )
                ],
                'layout': {
                    'title': 'रिसीवर ऑपरेटिंग कैरेक्टरिस्टिक (ROC) कर्व',
                    'xaxis': {'title': 'फॉल्स पॉजिटिव रेट'},
                    'yaxis': {'title': 'ट्रू पॉजिटिव रेट'},
                    'legend': {'x': 0.1, 'y': 0.9}
                }
            }
        
        # Update PR curve
        @self.app.callback(
            Output("pr-curve", "figure"),
            [Input("interval-component", "n_intervals")]
        )
        def update_pr_curve(n_intervals):
            if not self.pr_data['precision'] or not self.pr_data['recall']:
                return {
                    'data': [],
                    'layout': {
                        'title': 'प्रिसिजन-रिकॉल कर्व - डेटा उपलब्ध नहीं',
                        'xaxis': {'title': 'रिकॉल'},
                        'yaxis': {'title': 'प्रिसिजन'}
                    }
                }
                
            return {
                'data': [
                    go.Scatter(
                        x=self.pr_data['recall'],
                        y=self.pr_data['precision'],
                        mode='lines',
                        name=f"PR कर्व (AP = {self.pr_data['ap']:.2f})",
                        line=dict(color='green', width=2)
                    )
                ],
                'layout': {
                    'title': 'प्रिसिजन-रिकॉल कर्व',
                    'xaxis': {'title': 'रिकॉल'},
                    'yaxis': {'title': 'प्रिसिजन'},
                    'legend': {'x': 0.1, 'y': 0.1}
                }
            }
        
        # Update alpha impact graph
        @self.app.callback(
            Output("alpha-impact", "figure"),
            [Input("interval-component", "n_intervals")]
        )
        def update_alpha_impact(n_intervals):
            if not self.alpha_results:
                return {
                    'data': [],
                    'layout': {
                        'title': 'अल्फा प्रभाव - डेटा उपलब्ध नहीं',
                        'xaxis': {'title': 'अल्फा वैल्यू'},
                        'yaxis': {'title': 'मेट्रिक वैल्यू'}
                    }
                }
                
            alphas = list(self.alpha_results.keys())
            accuracy = [self.alpha_results[a]['accuracy'] for a in alphas]
            precision = [self.alpha_results[a]['precision'] for a in alphas]
            recall = [self.alpha_results[a]['recall'] for a in alphas]
            f1_score = [self.alpha_results[a]['f1_score'] for a in alphas]
            fpr = [self.alpha_results[a]['fpr'] for a in alphas]
                
            return {
                'data': [
                    go.Scatter(x=alphas, y=accuracy, mode='lines+markers', name='एक्युरेसी'),
                    go.Scatter(x=alphas, y=precision, mode='lines+markers', name='प्रिसिजन'),
                    go.Scatter(x=alphas, y=recall, mode='lines+markers', name='रिकॉल'),
                    go.Scatter(x=alphas, y=f1_score, mode='lines+markers', name='F1 स्कोर'),
                    go.Scatter(x=alphas, y=fpr, mode='lines+markers', name='FPR')
                ],
                'layout': {
                    'title': 'प्रदर्शन मेट्रिक्स पर अल्फा वैल्यू का प्रभाव',
                    'xaxis': {'title': 'अल्फा वैल्यू'},
                    'yaxis': {'title': 'मेट्रिक वैल्यू'},
                    'legend': {'x': 0, 'y': 1}
                }
            }
        
        # Handle clear history button
        @self.app.callback(
            Output("clear-button", "n_clicks"),
            [Input("clear-button", "n_clicks")]
        )
        def clear_history(n_clicks):
            if n_clicks:
                self.detection_results.clear()
                self.history = []
                self.connection_history = {}
                self.timeline_data = {
                    'time': [],
                    'confidence': [],
                    'state': [],
                    'action': []
                }
            return None
    
    def update_data(self, results: Dict[str, Any]) -> None:
        """
        Update dashboard with new detection results.
        
        Args:
            results: Dictionary with detection results
        """
        if not results:
            return
            
        # Store the latest results
        self.detection_results.append(results)
        
        # Add to history
        self.history.append(results)
        
        # Keep history at a reasonable size
        if len(self.history) > 100:
            self.history = self.history[-100:]
            
        # Add to timeline data
        self.timeline_data['time'].append(results.get('timestamp', datetime.now().isoformat()))
        self.timeline_data['confidence'].append(results.get('confidence', 0))
            
        # Determine state
        verdict = results.get('verdict', 'UNKNOWN')
        if verdict == 'MINING_DETECTED':
            state = 'माइनिंग मिली'
            action = 'अलर्ट जारी किया गया'
        elif verdict == 'SUSPICIOUS':
            state = 'संदिग्ध'
            action = 'मॉनिटरिंग बढ़ाई गई'
        else:
            state = 'सामान्य'
            action = 'कोई कार्रवाई नहीं'
            
        self.timeline_data['state'].append(state)
        self.timeline_data['action'].append(action)
        
        # Keep timeline data at a reasonable size
        if len(self.timeline_data['time']) > 100:
            for key in self.timeline_data:
                self.timeline_data[key] = self.timeline_data[key][-100:]
            
        # Update connection history
        suspicious_conns = results.get('suspicious_connections', [])
        for conn in suspicious_conns:
            src = conn.get('src_ip', 'अज्ञात')
            dst = conn.get('dst_ip', 'अज्ञात')
            conn_id = f"{src}->{dst}"
            
            if conn_id not in self.connection_history:
                self.connection_history[conn_id] = []
                
            self.connection_history[conn_id].append({
                'timestamp': results.get('timestamp', datetime.now().isoformat()),
                'ks_stat': conn.get('ks_stat', 0),
                'threshold': conn.get('threshold', 0),
                'verdict': conn.get('verdict', 'अज्ञात')
            })
    
    def update_alpha_results(self, alpha_results: Dict[float, Dict[str, float]]) -> None:
        """
        Update performance metrics for different alpha values.
        
        Args:
            alpha_results: Dictionary with alpha values and their metrics
        """
        self.alpha_results = alpha_results
        logger.info(f"अपडेटेड अल्फा रिजल्ट्स फॉर {len(alpha_results)} अल्फा वैल्यूज़")
    
    def update_roc_data(self, fpr: List[float], tpr: List[float], auc: float) -> None:
        """
        Update ROC curve data.
        
        Args:
            fpr: False positive rates
            tpr: True positive rates
            auc: Area under curve
        """
        self.roc_data = {
            'fpr': fpr,
            'tpr': tpr,
            'auc': auc
        }
        logger.info(f"अपडेटेड ROC डेटा विद AUC = {auc:.4f}")
    
    def update_pr_data(self, precision: List[float], recall: List[float], ap: float) -> None:
        """
        Update precision-recall curve data.
        
        Args:
            precision: Precision values
            recall: Recall values
            ap: Average precision
        """
        self.pr_data = {
            'precision': precision,
            'recall': recall,
            'ap': ap
        }
        logger.info(f"अपडेटेड प्रिसिजन-रिकॉल डेटा विद AP = {ap:.4f}")
        
    def update_distribution_data(self, normal_scores: List[float], mining_scores: List[float]) -> None:
        """
        Update distribution data for normal and mining traffic scores.
        
        Args:
            normal_scores: KS statistics for normal traffic
            mining_scores: KS statistics for mining traffic
        """
        self.distribution_data = {
            'normal': normal_scores,
            'mining': mining_scores
        }
        logger.info(f"अपडेटेड डिस्ट्रिब्यूशन डेटा: {len(normal_scores)} नॉर्मल, {len(mining_scores)} माइनिंग सैंपल्स")
    
    def start(self, open_browser: bool = True) -> bool:
        """
        Start the dashboard server.
        
        Args:
            open_browser: Whether to open the browser automatically
            
        Returns:
            True if started successfully, False otherwise
        """
        if not self.app:
            logger.error("डैशबोर्ड शुरू नहीं किया जा सकता: Dash ऐप इनिशियलाइज़ नहीं हुआ")
            return False
            
        if self.is_running:
            logger.warning("डैशबोर्ड पहले से ही चल रहा है")
            return True
            
        try:
            # Create and start server thread
            def run_server():
                logger.info(f"डैशबोर्ड सर्वर पोर्ट {self.port} पर शुरू हो रहा है")
                self.app.run_server(port=self.port, debug=False)
            
            self.server_thread = threading.Thread(target=run_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            # Give the server a moment to start
            time.sleep(2)
            
            # Open browser if requested
            if open_browser:
                webbrowser.open(f"http://localhost:{self.port}")
            
            self.is_running = True
            logger.info(f"डैशबोर्ड पोर्ट {self.port} पर शुरू हो गया")
            return True
            
        except Exception as e:
            logger.error(f"डैशबोर्ड शुरू करने में त्रुटि: {str(e)}")
            return False
    
    def stop(self) -> None:
        """Stop the dashboard server."""
        if not self.is_running:
            return
            
        # In a real implementation, we would shut down the server properly
        # For Dash, this is a bit complex as there's no simple shutdown method
        self.is_running = False
        logger.info("डैशबोर्ड बंद कर दिया गया")

# Simple test if run directly
if __name__ == "__main__":
    # Create and start dashboard
    dashboard = Dashboard(port=8050)
    
    # Generate sample data
    sample_data = {
        'timestamp': datetime.now().isoformat(),
        'window_size': 500,
        'mining_stat': 0.043,
        'nonmining_stat': 0.215,
        'confidence': 89.1,
        'threshold': 0.823,
        'verdict': 'MINING_DETECTED',
        'network_metrics': {
            'packet_rate': 1234.5,
            'detection_percentage': 75.0,
            'suspicious_connections': 3,
            'latency': 0.001,
            'jitter': 0.0002,
            'packet_size_mean': 128.5
        },
        'suspicious_connections': [
            {
                'src_ip': '192.168.1.100',
                'dst_ip': '35.158.12.5',
                'src_port': 49123,
                'dst_port': 8080,
                'proto': 'tcp',
                'ks_stat': 0.043,
                'threshold': 0.823,
                'verdict': 'MINING_DETECTED',
                'confidence': 89.1
            },
            {
                'src_ip': '192.168.1.100',
                'dst_ip': '54.12.45.87',
                'src_port': 49125,
                'dst_port': 3333,
                'proto': 'tcp',
                'ks_stat': 0.039,
                'threshold': 0.823,
                'verdict': 'MINING_DETECTED',
                'confidence': 91.5
            }
        ],
        'used_protocols': ['TCP', 'UDP', 'HTTP', 'TLS']
    }
    
    # Update dashboard with sample data
    dashboard.update_data(sample_data)
    
    # Generate some fake ROC data
    fpr = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    tpr = [0, 0.4, 0.6, 0.7, 0.8, 0.85, 0.9, 0.93, 0.95, 0.98, 1.0]
    dashboard.update_roc_data(fpr, tpr, 0.88)
    
    # Generate some fake PR data
    precision = [1, 0.9, 0.85, 0.8, 0.75, 0.7, 0.65, 0.6, 0.55, 0.5, 0.45]
    recall = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    dashboard.update_pr_data(precision, recall, 0.75)
    
    # Generate some fake alpha results
    alpha_values = [0.01, 0.05, 0.1, 0.15, 0.2]
    alpha_results = {}
    for alpha in alpha_values:
        alpha_results[alpha] = {
            'accuracy': 0.8 + alpha / 5,
            'precision': 0.85 - alpha / 3,
            'recall': 0.7 + alpha / 2,
            'f1_score': 0.75 + alpha / 4,
            'fpr': 0.1 + alpha
        }
    dashboard.update_alpha_results(alpha_results)
    
    # Start dashboard
    if dashboard.start():
        print(f"डैशबोर्ड http://localhost:{dashboard.port} पर शुरू हो गया है")
        print("बंद करने के लिए Ctrl+C दबाएँ")
        
        try:
            # Keep running until interrupted
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            dashboard.stop()
            print("डैशबोर्ड बंद कर दिया गया है") 