<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetSentinel - Security Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container">
            <span class="navbar-brand mb-0 h1">🛡️ NetSentinel Security Dashboard</span>
        </div>
    </nav>

    <div class="container mt-4">
        <!-- Stats Cards -->
        <div class="row mb-4">
            <div class="col-md-3">
                <div class="card text-white bg-primary">
                    <div class="card-body">
                        <h5 class="card-title">Active Agents</h5>
                        <h2 id="agent-count">0</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-white bg-danger">
                    <div class="card-body">
                        <h5 class="card-title">Vulnerabilities</h5>
                        <h2 id="vuln-count">0</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-white bg-success">
                    <div class="card-body">
                        <h5 class="card-title">Secure Agents</h5>
                        <h2 id="secure-count">0</h2>
                    </div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card text-white bg-info">
                    <div class="card-body">
                        <h5 class="card-title">Alerts (24h)</h5>
                        <h2 id="alert-count">0</h2>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts -->
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        Top Vulnerabilities
                    </div>
                    <div class="card-body">
                        <canvas id="vulnChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        Agent Health Status
                    </div>
                    <div class="card-body">
                        <canvas id="healthChart"></canvas>
                    </div>
                </div>
            </div>
        </div>

        <!-- Recent Alerts Table -->
        <div class="card">
            <div class="card-header">
                Recent Security Alerts
            </div>
            <div class="card-body">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Agent</th>
                            <th>Alert Type</th>
                            <th>Severity</th>
                        </tr>
                    </thead>
                    <tbody id="alerts-table">
                        <tr>
                            <td colspan="4" class="text-center">No alerts yet</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        let vulnChart, healthChart;
        
        $(document).ready(function() {
            const vulnCtx = document.getElementById('vulnChart').getContext('2d');
            vulnChart = new Chart(vulnCtx, {
                type: 'bar',
                data: {
                    labels: ['Open Ports', 'Outdated OS', 'Disabled Firewall', 'No Antivirus', 'Weak Password'],
                    datasets: [{
                        label: 'Vulnerabilities',
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: 'rgba(220, 53, 69, 0.7)'
                    }]
                },
                options: { responsive: true }
            });
            
            const healthCtx = document.getElementById('healthChart').getContext('2d');
            healthChart = new Chart(healthCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Secure', 'At Risk', 'Critical'],
                    datasets: [{
                        data: [0, 0, 0],
                        backgroundColor: ['#28a745', '#ffc107', '#dc3545']
                    }]
                },
                options: { responsive: true }
            });
            
            refreshData();
            setInterval(refreshData, 30000);
        });
        
        function refreshData() {
            $.get('api/stats.php', function(data) {
                $('#agent-count').text(data.agents || 0);
                $('#vuln-count').text(data.vulnerabilities || 0);
                $('#secure-count').text(data.secure || 0);
                $('#alert-count').text(data.alerts || 0);
                
                if (data.vuln_data) {
                    vulnChart.data.datasets[0].data = data.vuln_data;
                    vulnChart.update();
                }
                
                if (data.health_data) {
                    healthChart.data.datasets[0].data = data.health_data;
                    healthChart.update();
                }
                
                if (data.alerts) {
                    let html = '';
                    data.alerts.forEach(alert => {
                        html += `<tr>
                                    <td>${alert.timestamp}</td>
                                    <td>${alert.agent}</td>
                                    <td>${alert.type}</td>
                                    <td><span class="badge bg-danger">${alert.severity}</span></td>
                                </tr>`;
                    });
                    $('#alerts-table').html(html);
                }
            });
        }
    </script>
</body>
</html>
