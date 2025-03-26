// Main App Configuration
const app = {
    state: {
        instruments: [],
        categories: [],
        practiceSessions: [],
        user: null
    },
    
    init() {
        this.setupEventListeners();
        this.loadUserData();
    },

    setupEventListeners() {
        // Auth tab switching
        const authTabs = document.querySelectorAll('.auth-tab');
        authTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                authTabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');
                
                const loginForm = document.getElementById('loginForm');
                const registerForm = document.getElementById('registerForm');
                
                if (tab.dataset.tab === 'login') {
                    loginForm.style.display = 'block';
                    registerForm.style.display = 'none';
                } else {
                    loginForm.style.display = 'none';
                    registerForm.style.display = 'block';
                }
            });
        });

        // Navigation
        const navButtons = document.querySelectorAll('.nav-btn');
        navButtons.forEach(button => {
            button.addEventListener('click', () => {
                const section = button.dataset.section;
                this.showSection(section);
            });
        });
    },

    async loadUserData() {
        if (!auth.state.user) return;

        try {
            const response = await fetch(`${config.backendUrl}/api/user`, {
                headers: {
                    'Authorization': `Bearer ${auth.state.token}`
                }
            });

            if (response.ok) {
                const userData = await response.json();
                auth.state.user = userData;
                
                // Update UI with user data
                this.updateHistory();
                this.updateReports();
            }
        } catch (error) {
            console.error('Error loading user data:', error);
        }
    },

    async saveUserData() {
        if (!auth.state.isAuthenticated) return;

        try {
            const response = await fetch(`${config.backendUrl}/api/user`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.state.token}`
                },
                body: JSON.stringify({
                    instruments: this.state.instruments,
                    categories: this.state.categories,
                    practiceSessions: this.state.practiceSessions
                })
            });

            if (!response.ok) {
                throw new Error('Failed to save user data');
            }
        } catch (error) {
            console.error('Error saving user data:', error);
            alert('Error saving data. Please try again.');
        }
    },

    showSection(sectionId) {
        // Hide all sections
        document.querySelectorAll('.section').forEach(section => {
            section.style.display = 'none';
        });

        // Show selected section
        const selectedSection = document.getElementById(sectionId);
        if (selectedSection) {
            selectedSection.style.display = 'block';
        }

        // Update active nav button
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.section === sectionId) {
                btn.classList.add('active');
            }
        });

        // Refresh data when showing history or reports
        if (sectionId === 'history' || sectionId === 'reports') {
            this.loadUserData();
        }
    },

    updateUI() {
        // Update instruments and categories in forms
        this.updateSelects();
        
        // Update history table
        this.updateHistoryTable();
        
        // Update reports
        this.updateReports();
    },

    updateSelects() {
        // Update instrument select
        const instrumentSelect = document.getElementById('instrument');
        if (instrumentSelect) {
            instrumentSelect.innerHTML = '<option value="">Select an instrument</option>';
            this.state.instruments.forEach(instrument => {
                const option = document.createElement('option');
                option.value = instrument;
                option.textContent = instrument;
                instrumentSelect.appendChild(option);
            });
        }

        // Update category select
        const categorySelect = document.getElementById('category');
        if (categorySelect) {
            categorySelect.innerHTML = '<option value="">Select a category</option>';
            this.state.categories.forEach(category => {
                const option = document.createElement('option');
                option.value = category;
                option.textContent = category;
                categorySelect.appendChild(option);
            });
        }
    },

    updateHistoryTable() {
        const tbody = document.getElementById('historyTableBody');
        if (!tbody) return;

        tbody.innerHTML = '';
        this.state.practiceSessions.forEach(session => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${new Date(session.date).toLocaleDateString()}</td>
                <td>${Math.floor(session.duration / 60)}:${(session.duration % 60).toString().padStart(2, '0')}</td>
                <td>${session.instrument}</td>
                <td>${session.category}</td>
                <td>${session.notes || ''}</td>
                <td>
                    <button class="btn secondary btn-sm" onclick="app.deleteSession(${session.id})">Delete</button>
                </td>
            `;
            tbody.appendChild(row);
        });
    },

    updateHistory() {
        const historyTableBody = document.getElementById('historyTableBody');
        if (!historyTableBody || !auth.state.user) return;

        // Sort practice sessions by date (most recent first)
        const sortedSessions = [...auth.state.user.practiceSessions].sort((a, b) => 
            new Date(b.date) - new Date(a.date)
        );

        // Create table rows
        historyTableBody.innerHTML = sortedSessions.map(session => {
            const date = new Date(session.date).toLocaleDateString();
            const duration = this.formatDuration(session.duration);
            return `
                <tr>
                    <td>${date}</td>
                    <td>${duration}</td>
                    <td>${session.instrument}</td>
                    <td>${session.category}</td>
                    <td>${session.notes || ''}</td>
                    <td>
                        <button class="btn secondary delete-btn" data-id="${session._id}">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        // Add delete event listeners
        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', () => this.deleteSession(btn.dataset.id));
        });
    },

    updateReports() {
        if (!auth.state.user) return;

        // Total practice time
        const totalSeconds = auth.state.user.practiceSessions.reduce((total, session) => 
            total + session.duration, 0
        );
        
        // Practice time by instrument
        const instrumentTimes = {};
        auth.state.user.practiceSessions.forEach(session => {
            instrumentTimes[session.instrument] = (instrumentTimes[session.instrument] || 0) + session.duration;
        });

        // Practice time by category
        const categoryTimes = {};
        auth.state.user.practiceSessions.forEach(session => {
            categoryTimes[session.category] = (categoryTimes[session.category] || 0) + session.duration;
        });

        // Update total practice time display
        const totalTimeElement = document.getElementById('totalPracticeTime');
        if (totalTimeElement) {
            totalTimeElement.textContent = this.formatDuration(totalSeconds);
        }

        // Update instrument breakdown
        this.updateBreakdownChart('instrumentBreakdown', instrumentTimes);

        // Update category breakdown
        this.updateBreakdownChart('categoryBreakdown', categoryTimes);
    },

    updateBreakdownChart(elementId, data) {
        const element = document.getElementById(elementId);
        if (!element) return;

        const total = Object.values(data).reduce((sum, time) => sum + time, 0);
        
        element.innerHTML = Object.entries(data).map(([label, time]) => {
            const percentage = ((time / total) * 100).toFixed(1);
            return `
                <div class="breakdown-item">
                    <div class="breakdown-label">${label}</div>
                    <div class="breakdown-bar">
                        <div class="bar" style="width: ${percentage}%"></div>
                    </div>
                    <div class="breakdown-value">${this.formatDuration(time)} (${percentage}%)</div>
                </div>
            `;
        }).join('');
    },

    formatDuration(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const remainingSeconds = seconds % 60;

        const parts = [];
        if (hours > 0) parts.push(`${hours}h`);
        if (minutes > 0) parts.push(`${minutes}m`);
        if (remainingSeconds > 0 || parts.length === 0) parts.push(`${remainingSeconds}s`);

        return parts.join(' ');
    },

    async deleteSession(sessionId) {
        if (!confirm('Are you sure you want to delete this practice session?')) return;

        try {
            const response = await fetch(`${config.backendUrl}/api/user/practice/${sessionId}`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${auth.state.token}`
                }
            });

            if (response.ok) {
                const updatedUser = await response.json();
                auth.state.user = updatedUser;
                this.updateHistory();
                this.updateReports();
                alert('Practice session deleted successfully!');
            } else {
                alert('Error deleting practice session');
            }
        } catch (error) {
            console.error('Error deleting practice session:', error);
            alert('Error deleting practice session');
        }
    }
};

// Initialize the app when the script loads
app.init(); 