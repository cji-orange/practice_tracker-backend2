const auth = {
    state: {
        token: localStorage.getItem('token'),
        user: null,
        isAuthenticated: false
    },

    init() {
        if (this.state.token) {
            this.fetchUserData();
        }
        this.setupEventListeners();
    },

    setupEventListeners() {
        // Login form
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        // Register form
        const registerForm = document.getElementById('registerForm');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => this.handleRegister(e));
        }

        // Logout button
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => this.handleLogout());
        }

        // Delete account button
        const deleteAccountBtn = document.getElementById('deleteAccountBtn');
        if (deleteAccountBtn) {
            deleteAccountBtn.addEventListener('click', () => this.handleDeleteAccount());
        }

        // Tab switching
        const loginTab = document.getElementById('loginTab');
        const registerTab = document.getElementById('registerTab');
        if (loginTab && registerTab) {
            loginTab.addEventListener('click', () => this.switchTab('login'));
            registerTab.addEventListener('click', () => this.switchTab('register'));
        }
    },

    async handleLogin(e) {
        e.preventDefault();
        const email = document.getElementById('loginEmail').value;
        const password = document.getElementById('loginPassword').value;

        try {
            const response = await fetch(`${config.backendUrl}/api/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });

            if (response.ok) {
                const data = await response.json();
                this.state.token = data.token;
                localStorage.setItem('token', data.token);
                await this.fetchUserData();
                this.showMainContent();
                alert('Login successful!');
            } else {
                const error = await response.json();
                alert(error.message || 'Login failed');
            }
        } catch (error) {
            console.error('Login error:', error);
            alert('Error logging in');
        }
    },

    async handleRegister(e) {
        e.preventDefault();
        const username = document.getElementById('registerUsername').value;
        const email = document.getElementById('registerEmail').value;
        const password = document.getElementById('registerPassword').value;

        try {
            const response = await fetch(`${config.backendUrl}/api/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email, password })
            });

            if (response.ok) {
                const data = await response.json();
                this.state.token = data.token;
                localStorage.setItem('token', data.token);
                await this.fetchUserData();
                this.showMainContent();
                alert('Registration successful!');
            } else {
                const error = await response.json();
                alert(error.message || 'Registration failed');
            }
        } catch (error) {
            console.error('Registration error:', error);
            alert('Error registering');
        }
    },

    handleLogout() {
        this.state.token = null;
        this.state.user = null;
        this.state.isAuthenticated = false;
        localStorage.removeItem('token');
        this.showAuthContent();
    },

    async fetchUserData() {
        try {
            const response = await fetch(`${config.backendUrl}/api/user`, {
                headers: {
                    'Authorization': `Bearer ${this.state.token}`
                }
            });

            if (response.ok) {
                const userData = await response.json();
                this.state.user = userData;
                this.state.isAuthenticated = true;
                this.showMainContent();
            } else {
                this.handleLogout();
            }
        } catch (error) {
            console.error('Error fetching user data:', error);
            this.handleLogout();
        }
    },

    showAuthContent() {
        document.getElementById('authContent').style.display = 'block';
        document.getElementById('mainContent').style.display = 'none';
    },

    showMainContent() {
        document.getElementById('authContent').style.display = 'none';
        document.getElementById('mainContent').style.display = 'block';
        if (this.state.user) {
            document.getElementById('userInfo').textContent = this.state.user.username;
        }
    },

    switchTab(tab) {
        const loginForm = document.getElementById('loginForm');
        const registerForm = document.getElementById('registerForm');
        const loginTab = document.getElementById('loginTab');
        const registerTab = document.getElementById('registerTab');

        if (tab === 'login') {
            loginForm.style.display = 'block';
            registerForm.style.display = 'none';
            loginTab.classList.add('active');
            registerTab.classList.remove('active');
        } else {
            loginForm.style.display = 'none';
            registerForm.style.display = 'block';
            loginTab.classList.remove('active');
            registerTab.classList.add('active');
        }
    },

    async handleDeleteAccount() {
        if (!confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
            return;
        }

        try {
            const response = await fetch(`${config.backendUrl}/api/user`, {
                method: 'DELETE',
                headers: {
                    'Authorization': `Bearer ${this.state.token}`
                }
            });

            if (response.ok) {
                alert('Account deleted successfully');
                this.handleLogout();
            } else {
                const error = await response.json();
                alert(error.message || 'Error deleting account');
            }
        } catch (error) {
            console.error('Error deleting account:', error);
            alert('Error deleting account');
        }
    }
};

// Initialize auth when the script loads
auth.init(); 