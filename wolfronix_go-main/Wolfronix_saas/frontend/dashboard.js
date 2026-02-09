async function loadDashboardMetrics() {
    const token = localStorage.getItem("token");
    if (!token) return;

    try {
        const res = await fetch(`${API_BASE}/dashboard/metrics`, {
            headers: {
                Authorization: `Bearer ${token}`
            }
        });

        if (!res.ok) {
            console.error("Failed to fetch metrics:", await res.text());
            return;
        }

        const m = await res.json();

        document.getElementById("protectedRecords").textContent = m.protectedRecords;
        document.getElementById("activeLayers").textContent = m.activeLayers;

        document.getElementById("avgResponseTime").textContent =
            `${m.avgResponseTimeMs}ms`;
        document.getElementById("securityAlerts").textContent = m.securityAlerts;

        if (m.protectedRecordsChangePercent !== undefined) {
            document.getElementById("protectedRecordsChange").textContent =
                `${m.protectedRecordsChangePercent}% increase`;
        }

        if (m.activeLayersStatus) {
            document.getElementById("activeLayersStatus").textContent = m.activeLayersStatus;
        }

        if (m.responseTimeImprovementPercent !== undefined) {
            document.getElementById("responseTimeChange").textContent =
                `${m.responseTimeImprovementPercent}% faster`;
        }

        if (m.securityAlertsStatus) {
            document.getElementById("securityAlertsStatus").textContent = m.securityAlertsStatus;
        }

        // Cryptographic Metrics
        if (m.encryptionCount !== undefined) {
            document.getElementById("encryptionCount").textContent = m.encryptionCount.toLocaleString();
            document.getElementById("encryptionTime").textContent = `${Math.round(m.avgEncryptionTimeMs)}ms`;
        }
        if (m.decryptionCount !== undefined) {
            document.getElementById("decryptionCount").textContent = m.decryptionCount.toLocaleString();
            document.getElementById("decryptionTime").textContent = `${Math.round(m.avgDecryptionTimeMs)}ms`;
        }

        updateCharts(m);
    } catch (error) {
        console.error("Dashboard metrics error:", error);
    }
}

let activityChartInstance = null;
let layerChartInstance = null;

function updateCharts(metrics) {
    console.log("Updating charts with metrics:", metrics);
    if (!metrics.activityHistory) {
        console.warn("Missing activityHistory");
        return;
    }

    // Prepare Activity Data
    const activityLabels = metrics.activityHistory.map(h => h.date);
    const encryptedData = metrics.activityHistory.map(h => h.encryptedRecords);
    const maskedData = metrics.activityHistory.map(h => h.maskedData);

    // Initialize Activity Chart
    const ctx1 = document.getElementById('activityChart').getContext('2d');

    if (activityChartInstance) {
        activityChartInstance.destroy();
    }

    const gradientEncrypted = ctx1.createLinearGradient(0, 0, 0, 400);
    gradientEncrypted.addColorStop(0, 'rgba(59, 130, 246, 0.2)'); // Blue
    gradientEncrypted.addColorStop(1, 'rgba(59, 130, 246, 0)');

    const gradientMasked = ctx1.createLinearGradient(0, 0, 0, 400);
    gradientMasked.addColorStop(0, 'rgba(148, 163, 184, 0.1)'); // Slate-400
    gradientMasked.addColorStop(1, 'rgba(148, 163, 184, 0)');

    activityChartInstance = new Chart(ctx1, {
        type: 'line',
        data: {
            labels: activityLabels,
            datasets: [{
                label: 'Encrypted Records',
                data: encryptedData,
                borderColor: '#3B82F6', // Blue-500
                backgroundColor: (context) => {
                    const ctx = context.chart.ctx;
                    const gradient = ctx.createLinearGradient(0, 0, 0, 300);
                    gradient.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
                    gradient.addColorStop(1, 'rgba(59, 130, 246, 0.0)');
                    return gradient;
                },
                tension: 0.4,
                fill: true,
                borderWidth: 2,
                pointBackgroundColor: '#1E293B',
                pointBorderColor: '#3B82F6',
                pointBorderWidth: 2,
                pointRadius: 3, // Make points visible to show "change" better
                pointHoverRadius: 6
            }, {
                label: 'Masked Data',
                data: maskedData,
                borderColor: '#94A3B8', // Slate-400
                borderDash: [5, 5], // Dashed line for contrast
                backgroundColor: 'transparent',
                tension: 0.4,
                fill: false,
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index',
            },
            plugins: {
                legend: {
                    display: false // Hide legend for cleaner look, or style it if needed
                },
                tooltip: {
                    backgroundColor: '#1E293B',
                    titleColor: '#F8FAFC',
                    bodyColor: '#CBD5E1',
                    borderColor: '#334155',
                    borderWidth: 1,
                    padding: 10,
                    displayColors: true,
                    usePointStyle: true
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#64748B',
                        font: { family: "'Inter', sans-serif", size: 11 }
                    },
                    grid: {
                        color: '#1E2530',
                        drawBorder: false
                    },
                    border: { display: false }
                },
                x: {
                    ticks: {
                        color: '#64748B',
                        font: { family: "'Inter', sans-serif", size: 11 }
                    },
                    grid: { display: false },
                    border: { display: false }
                }
            }
        }
    });

    // Initialize Layer Chart
    const ctx2 = document.getElementById('layerChart').getContext('2d');

    if (layerChartInstance) {
        layerChartInstance.destroy();
    }

    // Default stats if missing
    let ld = metrics.layerDistribution || {
        staticMasking: 25,
        dynamicMasking: 30,
        encryption: 35,
        zeroTrust: 10
    };

    // Check if empty values
    const total = Object.values(ld).reduce((a, b) => a + (Number(b) || 0), 0);

    if (total === 0) {
        console.warn("Layer distribution is zero, using defaults based on activeCount");
        const activeCount = metrics.activeLayers || 4;

        ld = {
            staticMasking: 0,
            dynamicMasking: 0,
            encryption: 0,
            zeroTrust: 0
        };

        if (activeCount >= 1) ld.staticMasking = 25;
        if (activeCount >= 2) ld.dynamicMasking = 30;
        if (activeCount >= 3) ld.encryption = 35;
        if (activeCount >= 4) ld.zeroTrust = 10;
    }

    // Strict Visual Enforcement based on Active Count
    // This ensures the chart ALWAYS matches the number shown
    const activeCount = Number(metrics.activeLayers) || 4;

    if (activeCount < 4) ld.zeroTrust = 0;
    if (activeCount < 3) ld.encryption = 0;
    if (activeCount < 2) ld.dynamicMasking = 0;
    if (activeCount < 1) ld.staticMasking = 0;

    // Ensure we have values
    const dataValues = [
        Number(ld.staticMasking) || 0,
        Number(ld.dynamicMasking) || 0,
        Number(ld.encryption) || 0,
        Number(ld.zeroTrust) || 0
    ];

    layerChartInstance = new Chart(ctx2, {
        type: 'pie',
        data: {
            labels: ['Static Masking', 'Dynamic Masking', 'AES-256 Encryption', 'Zero-Trust'],
            datasets: [{
                data: dataValues,
                backgroundColor: ['#3B82F6', '#64748B', '#10B981', '#F59E0B'], // Blue, Slate, Green, Yellow
                borderColor: '#151A21', // Matches card bg
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false // Hide default legend, relying on UI or custom if needed
                },
                tooltip: {
                    backgroundColor: '#1E293B',
                    bodyColor: '#CBD5E1',
                    borderColor: '#334155',
                    borderWidth: 1
                }
            }
        }
    });
}
