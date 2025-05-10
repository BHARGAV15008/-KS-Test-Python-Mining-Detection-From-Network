// Dashboard update interval (ms)
const UPDATE_INTERVAL = 2000;

// Chart objects
let cdfChart = null;
let confidenceChart = null;

// Initialize dashboard
function initDashboard() {
    // Initialize charts
    initCDFChart();
    initConfidenceChart();
    
    // Start data polling
    setInterval(fetchData, UPDATE_INTERVAL);
    fetchData();
}

// Initialize CDF comparison chart
function initCDFChart() {
    const ctx = document.getElementById('cdf-chart').getContext('2d');
    cdfChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Mining Traffic',
                    data: [],
                    borderColor: '#e74c3c',
                    backgroundColor: 'rgba(231, 76, 60, 0.1)',
                    borderWidth: 2,
                    fill: true
                },
                {
                    label: 'Current Traffic',
                    data: [],
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    borderWidth: 2,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Packet Interval (s)'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Cumulative Probability'
                    },
                    min: 0,
                    max: 1
                }
            }
        }
    });
}

// Initialize confidence trend chart
function initConfidenceChart() {
    const ctx = document.getElementById('confidence-chart').getContext('2d');
    confidenceChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Confidence',
                data: [],
                borderColor: '#3498db',
                backgroundColor: 'rgba(52, 152, 219, 0.1)',
                borderWidth: 2,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Confidence'
                    },
                    min: 0,
                    max: 1
                }
            }
        }
    });
}

// Fetch data from server
function fetchData() {
    fetch('/data')
        .then(response => response.json())
        .then(data => {
            updateDashboard(data);
        })
        .catch(error => {
            console.error('Error fetching data:', error);
        });
}

// Update dashboard with new data
function updateDashboard(data) {
    if (!data.results || data.results.length === 0) {
        return;
    }
    
    // Get latest result
    const latestResult = data.results[data.results.length - 1];
    
    // Update status
    updateStatus(latestResult);
    
    // Update confidence meter
    updateConfidenceMeter(latestResult.confidence);
    
    // Update detection details
    document.getElementById('ks-stat').textContent = latestResult.mining_stat;
    document.getElementById('threshold').textContent = latestResult.threshold;
    document.getElementById('window-size').textContent = latestResult.window_size;
    
    // Update network metrics
    if (latestResult.network_metrics) {
        document.getElementById('packet-rate').textContent = `${latestResult.network_metrics.packet_rate} pkt/s`;
        document.getElementById('latency').textContent = `${latestResult.network_metrics.latency} s`;
        document.getElementById('jitter').textContent = `${latestResult.network_metrics.jitter} s`;
    }
    
    // Update timeline
    updateTimeline(data.timeline);
    
    // Update charts
    updateCharts(data);
    
    // Update last update time
    if (data.last_update) {
        document.getElementById('last-update').textContent = `Last update: ${new Date(data.last_update).toLocaleTimeString()}`;
    }
}

// Update status indicator
function updateStatus(result) {
    const statusElement = document.getElementById('status');
    
    if (result.verdict === 'MINING_DETECTED') {
        statusElement.textContent = 'Status: Mining Detected';
        statusElement.className = 'status mining';
    } else {
        statusElement.textContent = 'Status: Monitoring';
        statusElement.className = 'status';
    }
}

// Update confidence meter
function updateConfidenceMeter(confidence) {
    const confidenceValue = document.getElementById('confidence-value');
    const confidenceBar = document.getElementById('confidence-bar');
    
    // Update value
    confidenceValue.textContent = `${Math.round(confidence * 100)}%`;
    
    // Update bar
    confidenceBar.style.width = `${confidence * 100}%`;
    
    // Update color based on confidence
    if (confidence >= 0.8) {
        confidenceBar.className = 'bar danger';
    } else if (confidence >= 0.5) {
        confidenceBar.className = 'bar warning';
    } else {
        confidenceBar.className = 'bar';
    }
}

// Update timeline table
function updateTimeline(timeline) {
    const timelineBody = document.getElementById('timeline-body');
    
    // Clear existing rows
    timelineBody.innerHTML = '';
    
    // Add new rows
    timeline.forEach(entry => {
        const row = document.createElement('tr');
        
        // Time column
        const timeCell = document.createElement('td');
        timeCell.textContent = new Date(entry.time).toLocaleTimeString();
        row.appendChild(timeCell);
        
        // Confidence column
        const confidenceCell = document.createElement('td');
        confidenceCell.textContent = entry.confidence.toFixed(2);
        row.appendChild(confidenceCell);
        
        // State column
        const stateCell = document.createElement('td');
        stateCell.textContent = entry.state;
        row.appendChild(stateCell);
        
        // Action column
        const actionCell = document.createElement('td');
        actionCell.textContent = entry.action;
        row.appendChild(actionCell);
        
        timelineBody.appendChild(row);
    });
}

// Update charts with new data
function updateCharts(data) {
    // Update CDF chart if data is available
    if (data.cdf_data && cdfChart) {
        cdfChart.data.labels = data.cdf_data.x;
        cdfChart.data.datasets[0].data = data.cdf_data.mining_cdf;
        cdfChart.data.datasets[1].data = data.cdf_data.test_cdf;
        cdfChart.update();
    }
    
    // Update confidence chart
    if (data.results && data.results.length > 0 && confidenceChart) {
        // Get last 10 results for the chart
        const recentResults = data.results.slice(-10);
        
        confidenceChart.data.labels = recentResults.map(result => {
            const date = new Date(result.timestamp);
            return date.toLocaleTimeString();
        });
        
        confidenceChart.data.datasets[0].data = recentResults.map(result => result.confidence);
        confidenceChart.update();
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', initDashboard);
