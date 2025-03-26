const reports = {
    state: {
        currentRange: 'daily',
        charts: {
            practiceTime: null,
            instrumentBreakdown: null,
            categoryBreakdown: null
        }
    },

    init() {
        this.setupEventListeners();
        this.updateCharts();
    },

    setupEventListeners() {
        const timeRangeButtons = document.querySelectorAll('.time-range-selector .btn');
        timeRangeButtons.forEach(button => {
            button.addEventListener('click', () => {
                timeRangeButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
                this.state.currentRange = button.dataset.range;
                this.updateCharts();
            });
        });
    },

    getDateRange() {
        const now = new Date();
        let startDate;

        switch (this.state.currentRange) {
            case 'daily':
                startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
                break;
            case 'weekly':
                startDate = new Date(now.setDate(now.getDate() - 7));
                break;
            case 'monthly':
                startDate = new Date(now.getFullYear(), now.getMonth() - 1, now.getDate());
                break;
            case 'yearly':
                startDate = new Date(now.getFullYear() - 1, now.getMonth(), now.getDate());
                break;
        }

        return { startDate, endDate: new Date() };
    },

    getFilteredSessions() {
        const { startDate, endDate } = this.getDateRange();
        return app.state.practiceSessions.filter(session => {
            const sessionDate = new Date(session.date);
            return sessionDate >= startDate && sessionDate <= endDate;
        });
    },

    updateCharts() {
        this.updatePracticeTimeChart();
        this.updateInstrumentBreakdownChart();
        this.updateCategoryBreakdownChart();
    },

    updatePracticeTimeChart() {
        const ctx = document.getElementById('practiceTimeChart').getContext('2d');
        const sessions = this.getFilteredSessions();
        
        // Group sessions by date
        const groupedData = {};
        sessions.forEach(session => {
            const date = new Date(session.date).toLocaleDateString();
            groupedData[date] = (groupedData[date] || 0) + session.duration;
        });

        // Sort dates
        const sortedDates = Object.keys(groupedData).sort();

        if (this.state.charts.practiceTime) {
            this.state.charts.practiceTime.destroy();
        }

        this.state.charts.practiceTime = new Chart(ctx, {
            type: 'line',
            data: {
                labels: sortedDates,
                datasets: [{
                    label: 'Practice Time (minutes)',
                    data: sortedDates.map(date => Math.round(groupedData[date] / 60)),
                    borderColor: '#4a90e2',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Practice Time Over Time'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    },

    updateInstrumentBreakdownChart() {
        const ctx = document.getElementById('instrumentBreakdownChart').getContext('2d');
        const sessions = this.getFilteredSessions();
        
        // Group sessions by instrument
        const groupedData = {};
        sessions.forEach(session => {
            groupedData[session.instrument] = (groupedData[session.instrument] || 0) + session.duration;
        });

        if (this.state.charts.instrumentBreakdown) {
            this.state.charts.instrumentBreakdown.destroy();
        }

        this.state.charts.instrumentBreakdown = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: Object.keys(groupedData),
                datasets: [{
                    data: Object.values(groupedData).map(duration => Math.round(duration / 60)),
                    backgroundColor: [
                        '#4a90e2',
                        '#2ecc71',
                        '#e74c3c',
                        '#f1c40f',
                        '#9b59b6'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Practice Time by Instrument'
                    }
                }
            }
        });
    },

    updateCategoryBreakdownChart() {
        const ctx = document.getElementById('categoryBreakdownChart').getContext('2d');
        const sessions = this.getFilteredSessions();
        
        // Group sessions by category
        const groupedData = {};
        sessions.forEach(session => {
            groupedData[session.category] = (groupedData[session.category] || 0) + session.duration;
        });

        if (this.state.charts.categoryBreakdown) {
            this.state.charts.categoryBreakdown.destroy();
        }

        this.state.charts.categoryBreakdown = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: Object.keys(groupedData),
                datasets: [{
                    label: 'Practice Time (minutes)',
                    data: Object.values(groupedData).map(duration => Math.round(duration / 60)),
                    backgroundColor: '#4a90e2'
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Practice Time by Category'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
}; 