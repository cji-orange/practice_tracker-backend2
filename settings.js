const settings = {
    state: {
        timezone: 'America/Los_Angeles'
    },

    init() {
        this.setupEventListeners();
        this.loadSettings();
    },

    setupEventListeners() {
        // Add Instrument
        const addInstrumentBtn = document.getElementById('addInstrumentBtn');
        const addInstrumentForm = document.getElementById('addInstrumentForm');
        const cancelAddInstrumentBtn = document.getElementById('cancelAddInstrument');
        const addInstrumentModal = document.getElementById('addInstrumentModal');

        // Add Category
        const addCategoryBtn = document.getElementById('addCategoryBtn');
        const addCategoryForm = document.getElementById('addCategoryForm');
        const cancelAddCategoryBtn = document.getElementById('cancelAddCategory');
        const addCategoryModal = document.getElementById('addCategoryModal');

        if (addInstrumentBtn) {
            addInstrumentBtn.addEventListener('click', () => this.showModal(addInstrumentModal));
        }

        if (cancelAddInstrumentBtn) {
            cancelAddInstrumentBtn.addEventListener('click', () => this.hideModal(addInstrumentModal));
        }

        if (addInstrumentForm) {
            addInstrumentForm.addEventListener('submit', (e) => this.handleAddInstrument(e));
        }

        if (addCategoryBtn) {
            addCategoryBtn.addEventListener('click', () => this.showModal(addCategoryModal));
        }

        if (cancelAddCategoryBtn) {
            cancelAddCategoryBtn.addEventListener('click', () => this.hideModal(addCategoryModal));
        }

        if (addCategoryForm) {
            addCategoryForm.addEventListener('submit', (e) => this.handleAddCategory(e));
        }
    },

    showModal(modal) {
        modal.style.display = 'block';
    },

    hideModal(modal) {
        modal.style.display = 'none';
    },

    async loadSettings() {
        try {
            const response = await fetch(`${config.backendUrl}/api/user`, {
                headers: {
                    'Authorization': `Bearer ${auth.state.token}`
                }
            });

            if (response.ok) {
                const userData = await response.json();
                this.updateSettingsDisplay(userData);
                this.populateTimezoneSelect();
            }
        } catch (error) {
            console.error('Error loading settings:', error);
        }
    },

    updateSettingsDisplay(userData) {
        // Update instruments list
        const instrumentList = document.querySelector('.instrument-list');
        if (instrumentList) {
            instrumentList.innerHTML = userData.instruments.map(instrument => `
                <div class="list-item">
                    <span>${instrument}</span>
                    <button class="btn secondary delete-btn" data-type="instrument" data-value="${instrument}">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            `).join('');
        }

        // Update categories list
        const categoryList = document.querySelector('.category-list');
        if (categoryList) {
            categoryList.innerHTML = userData.categories.map(category => `
                <div class="list-item">
                    <span>${category}</span>
                    <button class="btn secondary delete-btn" data-type="category" data-value="${category}">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            `).join('');
        }

        // Update dropdowns
        this.updateDropdowns(userData);

        // Add delete event listeners
        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', (e) => this.handleDelete(e));
        });
    },

    updateDropdowns(userData) {
        // Update instrument dropdown
        const instrumentSelect = document.getElementById('instrument');
        if (instrumentSelect) {
            instrumentSelect.innerHTML = '<option value="">Select an instrument</option>';
            userData.instruments.forEach(instrument => {
                const option = document.createElement('option');
                option.value = instrument;
                option.textContent = instrument;
                instrumentSelect.appendChild(option);
            });
        }

        // Update category dropdown
        const categorySelect = document.getElementById('category');
        if (categorySelect) {
            categorySelect.innerHTML = '<option value="">Select a category</option>';
            userData.categories.forEach(category => {
                const option = document.createElement('option');
                option.value = category;
                option.textContent = category;
                categorySelect.appendChild(option);
            });
        }

        // Update filters
        const instrumentFilter = document.getElementById('instrumentFilter');
        if (instrumentFilter) {
            instrumentFilter.innerHTML = '<option value="">All Instruments</option>';
            userData.instruments.forEach(instrument => {
                const option = document.createElement('option');
                option.value = instrument;
                option.textContent = instrument;
                instrumentFilter.appendChild(option);
            });
        }

        const categoryFilter = document.getElementById('categoryFilter');
        if (categoryFilter) {
            categoryFilter.innerHTML = '<option value="">All Categories</option>';
            userData.categories.forEach(category => {
                const option = document.createElement('option');
                option.value = category;
                option.textContent = category;
                categoryFilter.appendChild(option);
            });
        }
    },

    async handleAddInstrument(e) {
        e.preventDefault();
        const name = document.getElementById('newInstrumentName').value;
        const description = document.getElementById('newInstrumentDescription').value;

        try {
            const response = await fetch(`${config.backendUrl}/api/user`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.state.token}`
                },
                body: JSON.stringify({
                    instruments: [...auth.state.user.instruments, name]
                })
            });

            if (response.ok) {
                const updatedUser = await response.json();
                auth.state.user = updatedUser;
                this.updateSettingsDisplay(updatedUser);
                this.hideModal(document.getElementById('addInstrumentModal'));
                e.target.reset();
            } else {
                alert('Error adding instrument');
            }
        } catch (error) {
            console.error('Error adding instrument:', error);
            alert('Error adding instrument');
        }
    },

    async handleAddCategory(e) {
        e.preventDefault();
        const name = document.getElementById('newCategoryName').value;
        const description = document.getElementById('newCategoryDescription').value;

        try {
            const response = await fetch(`${config.backendUrl}/api/user`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.state.token}`
                },
                body: JSON.stringify({
                    categories: [...auth.state.user.categories, name]
                })
            });

            if (response.ok) {
                const updatedUser = await response.json();
                auth.state.user = updatedUser;
                this.updateSettingsDisplay(updatedUser);
                this.hideModal(document.getElementById('addCategoryModal'));
                e.target.reset();
            } else {
                alert('Error adding category');
            }
        } catch (error) {
            console.error('Error adding category:', error);
            alert('Error adding category');
        }
    },

    async handleDelete(e) {
        const type = e.target.closest('.delete-btn').dataset.type;
        const value = e.target.closest('.delete-btn').dataset.value;

        try {
            const updatedUser = { ...auth.state.user };
            if (type === 'instrument') {
                updatedUser.instruments = updatedUser.instruments.filter(i => i !== value);
            } else {
                updatedUser.categories = updatedUser.categories.filter(c => c !== value);
            }

            const response = await fetch(`${config.backendUrl}/api/user`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.state.token}`
                },
                body: JSON.stringify(updatedUser)
            });

            if (response.ok) {
                auth.state.user = updatedUser;
                this.updateSettingsDisplay(updatedUser);
            } else {
                alert('Error deleting item');
            }
        } catch (error) {
            console.error('Error deleting item:', error);
            alert('Error deleting item');
        }
    },

    displayInstruments() {
        const instrumentList = document.querySelector('.instrument-list');
        instrumentList.innerHTML = '';

        app.state.instruments.forEach(instrument => {
            const div = document.createElement('div');
            div.className = 'instrument-item';
            div.innerHTML = `
                <div class="item-content">
                    <h3>${instrument.name}</h3>
                    <p>${instrument.description || 'No description'}</p>
                </div>
                <div class="item-actions">
                    <button class="btn secondary" onclick="settings.editInstrument(${instrument.id})">
                        Edit
                    </button>
                    <button class="btn secondary" onclick="settings.deleteInstrument(${instrument.id})">
                        Delete
                    </button>
                </div>
            `;
            instrumentList.appendChild(div);
        });
    },

    displayCategories() {
        const categoryList = document.querySelector('.category-list');
        categoryList.innerHTML = '';

        app.state.categories.forEach(category => {
            const div = document.createElement('div');
            div.className = 'category-item';
            div.innerHTML = `
                <div class="item-content">
                    <h3>${category.name}</h3>
                    <p>${category.description || 'No description'}</p>
                </div>
                <div class="item-actions">
                    <button class="btn secondary" onclick="settings.editCategory(${category.id})">
                        Edit
                    </button>
                    <button class="btn secondary" onclick="settings.deleteCategory(${category.id})">
                        Delete
                    </button>
                </div>
            `;
            categoryList.appendChild(div);
        });
    },

    populateTimezoneSelect() {
        const timezoneSelect = document.getElementById('timezone');
        if (!timezoneSelect) return;

        // Clear existing options
        timezoneSelect.innerHTML = '';

        // Add timezone options
        const timezones = Intl.supportedValuesOf('timeZone');
        timezones.forEach(timezone => {
            const option = document.createElement('option');
            option.value = timezone;
            option.textContent = timezone;
            if (timezone === this.state.timezone) {
                option.selected = true;
            }
            timezoneSelect.appendChild(option);
        });

        // Ensure America/Los_Angeles is selected
        timezoneSelect.value = 'America/Los_Angeles';
    },

    editInstrument(id) {
        const instrument = app.state.instruments.find(i => i.id === id);
        if (!instrument) return;

        const name = prompt('Enter new instrument name:', instrument.name);
        if (!name) return;

        const description = prompt('Enter new instrument description:', instrument.description || '');
        
        instrument.name = name;
        instrument.description = description;
        app.saveData();
        this.displayInstruments();
        app.updateInstrumentSelects();
    },

    deleteInstrument(id) {
        if (!confirm('Are you sure you want to delete this instrument? This will also delete all associated practice sessions.')) {
            return;
        }

        app.state.instruments = app.state.instruments.filter(i => i.id !== id);
        app.state.practiceSessions = app.state.practiceSessions.filter(session => {
            const instrument = app.state.instruments.find(i => i.name === session.instrument);
            return instrument !== undefined;
        });

        app.saveData();
        this.displayInstruments();
        app.updateInstrumentSelects();
    },

    editCategory(id) {
        const category = app.state.categories.find(c => c.id === id);
        if (!category) return;

        const name = prompt('Enter new category name:', category.name);
        if (!name) return;

        const description = prompt('Enter new category description:', category.description || '');
        
        category.name = name;
        category.description = description;
        app.saveData();
        this.displayCategories();
        app.updateCategorySelects();
    },

    deleteCategory(id) {
        if (!confirm('Are you sure you want to delete this category? This will also delete all associated practice sessions.')) {
            return;
        }

        app.state.categories = app.state.categories.filter(c => c.id !== id);
        app.state.practiceSessions = app.state.practiceSessions.filter(session => {
            const category = app.state.categories.find(c => c.name === session.category);
            return category !== undefined;
        });

        app.saveData();
        this.displayCategories();
        app.updateCategorySelects();
    }
};

// Initialize settings when the script loads
settings.init(); 