const timer = {
    state: {
        isRunning: false,
        startTime: null,
        elapsedTime: 0,
        intervalId: null,
        mode: 'timer', // 'timer' or 'manual'
        isManualMode: false
    },

    init() {
        // Ensure DOM is loaded before setting up event listeners
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.setupEventListeners();
                this.populateSelects();
            });
        } else {
            this.setupEventListeners();
            this.populateSelects();
        }
        this.updateDisplay();
    },

    populateSelects() {
        // Populate instrument select
        const instrumentSelect = document.getElementById('instrument');
        if (instrumentSelect) {
            instrumentSelect.innerHTML = '<option value="">Select an instrument</option>';
            auth.state.user.instruments.forEach(instrument => {
                const option = document.createElement('option');
                option.value = instrument;
                option.textContent = instrument;
                instrumentSelect.appendChild(option);
            });
        }

        // Populate category select
        const categorySelect = document.getElementById('category');
        if (categorySelect) {
            categorySelect.innerHTML = '<option value="">Select a category</option>';
            auth.state.user.categories.forEach(category => {
                const option = document.createElement('option');
                option.value = category;
                option.textContent = category;
                categorySelect.appendChild(option);
            });
        }
    },

    setupEventListeners() {
        // Timer controls
        const startBtn = document.getElementById('startTimer');
        const stopBtn = document.getElementById('stopTimer');
        const resetBtn = document.getElementById('resetTimer');
        const saveBtn = document.getElementById('saveBtn');
        
        if (startBtn) startBtn.addEventListener('click', () => this.start());
        if (stopBtn) stopBtn.addEventListener('click', () => this.stop());
        if (resetBtn) resetBtn.addEventListener('click', () => this.reset());
        if (saveBtn) saveBtn.addEventListener('click', (e) => {
            e.preventDefault();
            this.handleSave();
        });

        // Practice form
        const practiceForm = document.getElementById('practiceForm');
        if (practiceForm) {
            practiceForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleSave();
            });
        }

        // Mode selector
        const modeButtons = document.querySelectorAll('.timer-mode-selector .btn');
        modeButtons.forEach(button => {
            button.addEventListener('click', () => {
                modeButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
                this.switchMode(button.dataset.mode === 'manual');
            });
        });

        // Manual time entry
        const setManualTimeBtn = document.getElementById('setManualTime');
        if (setManualTimeBtn) {
            setManualTimeBtn.addEventListener('click', () => this.setManualTime());
        }

        // Initialize display
        this.updateDisplay();
    },

    switchMode(mode) {
        this.state.mode = mode ? 'manual' : 'timer';
        const manualEntry = document.querySelector('.manual-entry');
        const timerControls = document.querySelector('.timer-controls');

        if (mode) {
            if (manualEntry) manualEntry.style.display = 'block';
            if (timerControls) timerControls.style.display = 'none';
            this.stop();
        } else {
            if (manualEntry) manualEntry.style.display = 'none';
            if (timerControls) timerControls.style.display = 'flex';
        }
    },

    start() {
        if (!this.state.isRunning && this.state.mode === 'timer') {
            this.state.isRunning = true;
            this.state.startTime = Date.now() - this.state.elapsedTime;
            this.state.intervalId = setInterval(() => this.updateDisplay(), 1000);
        }
    },

    stop() {
        if (this.state.isRunning) {
            this.state.isRunning = false;
            if (this.state.intervalId) {
                clearInterval(this.state.intervalId);
                this.state.intervalId = null;
            }
        }
    },

    reset() {
        this.stop();
        this.state.elapsedTime = 0;
        this.updateDisplay();
    },

    setManualTime() {
        const minutesInput = document.getElementById('manualMinutes');
        const secondsInput = document.getElementById('manualSeconds');
        
        if (!minutesInput || !secondsInput) return;

        const minutes = parseInt(minutesInput.value) || 0;
        const seconds = parseInt(secondsInput.value) || 0;
        
        if (seconds >= 60) {
            alert('Seconds must be less than 60');
            return;
        }

        this.state.elapsedTime = (minutes * 60 + seconds) * 1000;
        this.updateDisplay();
    },

    updateDisplay() {
        const minutes = document.getElementById('minutes');
        const seconds = document.getElementById('seconds');

        if (!minutes || !seconds) return;

        if (this.state.isRunning) {
            this.state.elapsedTime = Date.now() - this.state.startTime;
        }

        const totalSeconds = Math.floor(this.state.elapsedTime / 1000);
        const displayMinutes = Math.floor(totalSeconds / 60);
        const displaySeconds = totalSeconds % 60;

        minutes.textContent = displayMinutes.toString().padStart(2, '0');
        seconds.textContent = displaySeconds.toString().padStart(2, '0');
    },

    async handleSave() {
        const instrument = document.getElementById('instrument').value;
        const category = document.getElementById('category').value;
        const notes = document.getElementById('notes').value;

        // Validate selections
        if (!instrument || !category) {
            alert('Please select both an instrument and a category');
            return;
        }

        // Check if the selected instrument and category exist in the user's data
        if (!auth.state.user.instruments.includes(instrument) || !auth.state.user.categories.includes(category)) {
            alert('Invalid instrument or category selection');
            return;
        }

        // Calculate duration based on mode
        let duration;
        if (this.state.mode === 'manual') {
            const minutes = parseInt(document.getElementById('manualMinutes').value) || 0;
            const seconds = parseInt(document.getElementById('manualSeconds').value) || 0;
            duration = (minutes * 60) + seconds;
        } else {
            if (!this.state.startTime) {
                alert('Please start the timer before saving');
                return;
            }
            duration = Math.floor((Date.now() - this.state.startTime) / 1000);
        }

        try {
            const response = await fetch(`${config.backendUrl}/api/user/practice`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.state.token}`
                },
                body: JSON.stringify({
                    instrument,
                    category,
                    duration,
                    notes,
                    date: new Date().toISOString()
                })
            });

            if (response.ok) {
                const updatedUser = await response.json();
                auth.state.user = updatedUser;
                
                // Reset timer and form
                this.reset();
                document.getElementById('practiceForm').reset();
                if (this.state.mode === 'manual') {
                    document.getElementById('manualMinutes').value = '';
                    document.getElementById('manualSeconds').value = '';
                }

                // Reload user data to update history and reports
                await app.loadUserData();
                
                alert('Practice session saved successfully!');
            } else {
                const error = await response.json();
                console.error('Server error:', error);
                alert(error.message || 'Error saving practice session');
            }
        } catch (error) {
            console.error('Error saving practice session:', error);
            alert('Error saving practice session. Please make sure you are logged in and the server is running.');
        }
    }
};

// Initialize the timer when the script loads
timer.init(); 