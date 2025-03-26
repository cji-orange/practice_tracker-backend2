const history = {
    state: {
        filters: {
            date: '',
            instrument: '',
            category: ''
        }
    },

    init() {
        this.setupEventListeners();
        this.updateFilters();
        this.displaySessions();
    },

    setupEventListeners() {
        const dateFilter = document.getElementById('dateFilter');
        const instrumentFilter = document.getElementById('instrumentFilter');
        const categoryFilter = document.getElementById('categoryFilter');

        dateFilter.addEventListener('change', () => {
            this.state.filters.date = dateFilter.value;
            this.displaySessions();
        });

        instrumentFilter.addEventListener('change', () => {
            this.state.filters.instrument = instrumentFilter.value;
            this.displaySessions();
        });

        categoryFilter.addEventListener('change', () => {
            this.state.filters.category = categoryFilter.value;
            this.displaySessions();
        });
    },

    updateFilters() {
        // Update instrument filter options
        const instrumentFilter = document.getElementById('instrumentFilter');
        instrumentFilter.innerHTML = '<option value="">All Instruments</option>';
        app.state.instruments.forEach(instrument => {
            const option = document.createElement('option');
            option.value = instrument.name;
            option.textContent = instrument.name;
            instrumentFilter.appendChild(option);
        });

        // Update category filter options
        const categoryFilter = document.getElementById('categoryFilter');
        categoryFilter.innerHTML = '<option value="">All Categories</option>';
        app.state.categories.forEach(category => {
            const option = document.createElement('option');
            option.value = category.name;
            option.textContent = category.name;
            categoryFilter.appendChild(option);
        });
    },

    filterSessions() {
        return app.state.practiceSessions.filter(session => {
            const matchesDate = !this.state.filters.date || 
                session.date.startsWith(this.state.filters.date);
            const matchesInstrument = !this.state.filters.instrument || 
                session.instrument === this.state.filters.instrument;
            const matchesCategory = !this.state.filters.category || 
                session.category === this.state.filters.category;

            return matchesDate && matchesInstrument && matchesCategory;
        });
    },

    formatDuration(seconds) {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
    },

    formatDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    },

    displaySessions() {
        const tbody = document.getElementById('historyTableBody');
        tbody.innerHTML = '';

        const filteredSessions = this.filterSessions();
        
        if (filteredSessions.length === 0) {
            const row = document.createElement('tr');
            const cell = document.createElement('td');
            cell.colSpan = 6;
            cell.textContent = 'No practice sessions found.';
            cell.style.textAlign = 'center';
            row.appendChild(cell);
            tbody.appendChild(row);
            return;
        }

        filteredSessions.sort((a, b) => new Date(b.date) - new Date(a.date))
            .forEach(session => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${this.formatDate(session.date)}</td>
                    <td>${this.formatDuration(session.duration)}</td>
                    <td>${session.instrument}</td>
                    <td>${session.category}</td>
                    <td>${session.notes || ''}</td>
                    <td>
                        <button class="btn secondary" onclick="history.deleteSession(${session.id})">
                            Delete
                        </button>
                    </td>
                `;
                tbody.appendChild(row);
            });
    },

    deleteSession(id) {
        if (confirm('Are you sure you want to delete this practice session?')) {
            app.state.practiceSessions = app.state.practiceSessions.filter(session => session.id !== id);
            app.saveData();
            this.displaySessions();
        }
    }
}; 