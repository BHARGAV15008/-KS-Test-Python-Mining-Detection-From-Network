// Dashboard JavaScript

// Variables to store charts
let timelineChart = null;
let networkMetricsChart = null;
let protocolChart = null;
let cdfChart = null;

// Function to fetch and update dashboard
async function updateDashboard() {
    try {
        const response = await fetch('data.json');
        const data = await response.json();
        
        // Update last update time
        document.getElementById('lastUpdate').textContent = 
            new Date(data.last_update).toLocaleString();
        
        // Update status and metrics
        updateStatusAndMetrics(data);
        
        // Update timeline chart and table
        updateTimeline(data);
        
        // Update connection table
        updateConnectionTable(data);
        
        // Update network metrics
        updateNetworkMetrics(data);
        
        // Update protocol distribution
        updateProtocolDistribution(data);
        
        // Update CDF comparison chart
        updateCdfChart(data);
        
    } catch (error) {
        console.error('Error fetching dashboard data:', error);
    }
}

// Update status and top metrics
function updateStatusAndMetrics(data) {
    const latestResult = data.results.length > 0 ? data.results[data.results.length - 1] : null;
    
    if (latestResult) {
        // Update status
        const statusElement = document.getElementById('status');
        const verdict = latestResult.verdict || 'UNKNOWN';
        
        statusElement.textContent = `Status: ${verdict}`;
        statusElement.className = 'status';
        
        if (verdict === 'MINING_DETECTED') {
            statusElement.classList.add('mining');
        } else if (verdict === 'SUSPICIOUS') {
            statusElement.classList.add('suspicious');
        } else {
            statusElement.classList.add('normal');
        }
        
        // Update metrics
        document.getElementById('confidence').textContent = 
            (latestResult.confidence * 100).toFixed(2) + '%';
        document.getElementById('ksStatistic').textContent = 
            latestResult.mining_stat ? latestResult.mining_stat.toFixed(4) : '-';
        document.getElementById('threshold').textContent = 
            latestResult.threshold ? latestResult.threshold.toFixed(4) : '-';
    }
}

// Update timeline chart and table
function updateTimeline(data) {
    // Update timeline table
    const timelineTableBody = document.querySelector('#timelineTable tbody');
    timelineTableBody.innerHTML = '';
    
    if (data.timeline.length > 0) {
        data.timeline.forEach(entry => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${entry.time}</td>
                <td>${entry.confidence}</td>
                <td>${entry.state}</td>
                <td>${entry.action}</td>
            `;
            timelineTableBody.appendChild(row);
        });
    } else {
        timelineTableBody.innerHTML = '<tr><td colspan="4">No timeline data available</td></tr>';
    }
    
    // Update timeline chart
    const timelineContext = document.getElementById('timelineChart').getContext('2d');
    
    // Extract data for chart
    const detectionHistory = data.detection_history || [];
    const times = detectionHistory.map(entry => new Date(entry.time).toLocaleTimeString());
    const confidences = detectionHistory.map(entry => entry.confidence);
    const thresholds = detectionHistory.map(entry => entry.threshold);
    const verdicts = detectionHistory.map(entry => entry.verdict);
    
    // Create color array based on verdicts
    const backgroundColors = verdicts.map(verdict => 
        verdict === 'MINING_DETECTED' ? 'rgba(231, 76, 60, 0.2)' : 
        'rgba(39, 174, 96, 0.2)');
    
    const borderColors = verdicts.map(verdict => 
        verdict === 'MINING_DETECTED' ? 'rgb(231, 76, 60)' : 
        'rgb(39, 174, 96)');
    
    if (timelineChart) {
        timelineChart.destroy();
    }
    
    timelineChart = new Chart(timelineContext, {
        type: 'line',
        data: {
            labels: times,
            datasets: [
                {
                    label: 'Confidence',
                    data: confidences,
                    backgroundColor: backgroundColors,
                    borderColor: borderColors,
                    borderWidth: 2,
                    pointRadius: 4,
                    fill: false,
                    tension: 0.1
                },
                {
                    label: 'Threshold',
                    data: thresholds,
                    borderColor: 'rgba(44, 62, 80, 0.5)',
                    borderWidth: 2,
                    pointRadius: 0,
                    fill: false,
                    borderDash: [5, 5]
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 1.0
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                },
                title: {
                    display: true,
                    text: 'Detection Confidence Timeline'
                }
            }
        }
    });
}

// Update connection table
function updateConnectionTable(data) {
    const connectionTableBody = document.querySelector('#connectionTable tbody');
    connectionTableBody.innerHTML = '';
    
    const latestResult = data.results.length > 0 ? data.results[data.results.length - 1] : null;
    
    if (latestResult && latestResult.suspicious_connections && latestResult.suspicious_connections.length > 0) {
        latestResult.suspicious_connections.forEach(conn => {
            const row = document.createElement('tr');
            
            // Determine status class based on confidence
            let statusClass = 'normal';
            let statusText = 'NORMAL';
            
            if (conn.confidence >= 0.9) {
                statusClass = 'mining';
                statusText = 'MINING_DETECTED';
            } else if (conn.confidence >= 0.7) {
                statusClass = 'suspicious';
                statusText = 'SUSPICIOUS';
            }
            
            row.className = statusClass;
            row.innerHTML = `
                <td>${conn.src_ip || 'Unknown'}</td>
                <td>${conn.dst_ip || 'Unknown'}</td>
                <td>${conn.src_port || '?'} to ${conn.dst_port || '?'}</td>
                <td>${(conn.proto || 'Unknown').toUpperCase()}</td>
                <td>${(conn.confidence * 100).toFixed(2)}%</td>
                <td>${statusText}</td>
            `;
            connectionTableBody.appendChild(row);
        });
    } else {
        connectionTableBody.innerHTML = '<tr><td colspan="6">No suspicious connections detected</td></tr>';
    }
}

// Update network metrics
function updateNetworkMetrics(data) {
    const latestResult = data.results.length > 0 ? data.results[data.results.length - 1] : null;
    
    if (latestResult && latestResult.network_metrics) {
        const metrics = latestResult.network_metrics;
        
        // Update metric cards
        document.querySelector('#packetRate .metric-value').textContent = 
            `${metrics.packet_rate ? metrics.packet_rate.toFixed(2) : 0} pkt/s`;
        document.querySelector('#latency .metric-value').textContent = 
            `${metrics.latency ? (metrics.latency * 1000).toFixed(2) : 0} ms`;
        document.querySelector('#jitter .metric-value').textContent = 
            `${metrics.jitter ? (metrics.jitter * 1000).toFixed(2) : 0} ms`;
        
        // Set card classes based on verdict
        const cardClass = latestResult.verdict === 'MINING_DETECTED' ? 'mining' : 
                         (latestResult.verdict === 'SUSPICIOUS' ? 'suspicious' : 'normal');
        
        document.querySelectorAll('.metric-card').forEach(card => {
            card.className = 'metric-card';
            card.classList.add(cardClass);
        });
    }
    
    // Update network metrics chart
    // Extract historical network metrics for visualization
    const networkMetricsContext = document.getElementById('networkMetricsChart').getContext('2d');
    
    // Prepare historical data
    const times = [];
    const packetRates = [];
    const latencies = [];
    const jitters = [];
    
    data.results.forEach(result => {
        if (result.network_metrics) {
            times.push(new Date(result.timestamp || result.time).toLocaleTimeString());
            packetRates.push(result.network_metrics.packet_rate || 0);
            latencies.push((result.network_metrics.latency || 0) * 1000); // Convert to ms
            jitters.push((result.network_metrics.jitter || 0) * 1000); // Convert to ms
        }
    });
    
    if (networkMetricsChart) {
        networkMetricsChart.destroy();
    }
    
    networkMetricsChart = new Chart(networkMetricsContext, {
        type: 'line',
        data: {
            labels: times,
            datasets: [
                {
                    label: 'Packet Rate (pkt/s)',
                    data: packetRates,
                    borderColor: 'rgba(52, 152, 219, 1)',
                    backgroundColor: 'rgba(52, 152, 219, 0.2)',
                    borderWidth: 2,
                    pointRadius: 2,
                    yAxisID: 'y'
                },
                {
                    label: 'Latency (ms)',
                    data: latencies,
                    borderColor: 'rgba(155, 89, 182, 1)',
                    backgroundColor: 'rgba(155, 89, 182, 0.2)',
                    borderWidth: 2,
                    pointRadius: 2,
                    yAxisID: 'y1'
                },
                {
                    label: 'Jitter (ms)',
                    data: jitters,
                    borderColor: 'rgba(46, 204, 113, 1)',
                    backgroundColor: 'rgba(46, 204, 113, 0.2)',
                    borderWidth: 2,
                    pointRadius: 2,
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    title: {
                        display: true,
                        text: 'Packet Rate (pkt/s)'
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    title: {
                        display: true,
                        text: 'Time (ms)'
                    },
                    grid: {
                        drawOnChartArea: false
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Network Performance Metrics'
                }
            }
        }
    });
}

// Update protocol distribution
function updateProtocolDistribution(data) {
    const protocolContext = document.getElementById('protocolChart').getContext('2d');
    
    // Prepare protocol distribution data
    const protocols = Object.keys(data.protocol_distribution || {});
    const counts = protocols.map(proto => data.protocol_distribution[proto]);
    
    // Define colors for protocols
    const colors = [
        'rgba(52, 152, 219, 0.7)',  // Blue
        'rgba(46, 204, 113, 0.7)',  // Green
        'rgba(155, 89, 182, 0.7)',  // Purple
        'rgba(230, 126, 34, 0.7)',  // Orange
        'rgba(231, 76, 60, 0.7)',   // Red
        'rgba(241, 196, 15, 0.7)'   // Yellow
    ];
    
    if (protocolChart) {
        protocolChart.destroy();
    }
    
    protocolChart = new Chart(protocolContext, {
        type: 'pie',
        data: {
            labels: protocols,
            datasets: [{
                data: counts,
                backgroundColor: colors.slice(0, protocols.length)
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                },
                title: {
                    display: true,
                    text: 'Protocol Distribution'
                }
            }
        }
    });
}

// Update CDF comparison chart
function updateCdfChart(data) {
    const latestResult = data.results.length > 0 ? data.results[data.results.length - 1] : null;
    
    if (latestResult && latestResult.aggregate && latestResult.aggregate.cdf_data) {
        const cdfContext = document.getElementById('cdfChart').getContext('2d');
        const cdfData = latestResult.aggregate.cdf_data;
        
        if (cdfChart) {
            cdfChart.destroy();
        }
        
        cdfChart = new Chart(cdfContext, {
            type: 'line',
            data: {
                labels: cdfData.x,
                datasets: [
                    {
                        label: 'Test Traffic CDF',
                        data: cdfData.test_cdf,
                        borderColor: 'rgba(52, 152, 219, 1)',
                        backgroundColor: 'rgba(52, 152, 219, 0.2)',
                        borderWidth: 2,
                        pointRadius: 0,
                        fill: false
                    },
                    {
                        label: 'Mining Traffic CDF',
                        data: cdfData.mining_cdf,
                        borderColor: 'rgba(231, 76, 60, 1)',
                        backgroundColor: 'rgba(231, 76, 60, 0.2)',
                        borderWidth: 2,
                        pointRadius: 0,
                        fill: false
                    },
                    {
                        label: 'Difference',
                        data: cdfData.diff,
                        borderColor: 'rgba(241, 196, 15, 1)',
                        backgroundColor: 'rgba(241, 196, 15, 0.2)',
                        borderWidth: 1,
                        pointRadius: 0,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 1.0
                    }
                },
                plugins: {
                    title: {
                        display: true,
                        text: 'CDF Comparison'
                    }
                }
            }
        });
    }
}

// Update connection list
function updateConnectionList(connections) {
    const container = document.getElementById('connection-list');
    
    if (!connections || connections.length === 0) {
        container.innerHTML = '<div class="no-connections">No suspicious connections detected</div>';
        return;
    }
    
    container.innerHTML = connections.map(conn => `
        <div class="connection">
            <div class="connection-path">
                ${conn.src} to ${conn.dst} (${conn.proto})
            </div>
            <div class="connection-confidence">
                ${Math.round(conn.detection_percentage)}%
            </div>
        </div>
    `).join('');
}

// Initial update
updateDashboard();

// Set interval to update dashboard
setInterval(updateDashboard, 5000);
