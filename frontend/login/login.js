// Login page with behavioral data collection
class LoginBehavioralCollector {
    constructor() {
        this.keystrokeData = [];
        this.mouseData = [];
        this.sessionId = this.generateSessionId();
        this.socket = null;
        this.currentRiskScore = 0;
        this.isCollecting = false;
        this.sessionTerminated = false;

        this.init();
    }

    init() {
        this.setupEventListeners();
        this.connectWebSocket();
        this.startDataCollection();
    }

    getWebSocketToken() {
        if (window.RUNTIME_CONFIG && window.RUNTIME_CONFIG.wsAuthToken) {
            return window.RUNTIME_CONFIG.wsAuthToken;
        }
        return localStorage.getItem('ws_auth_token') || localStorage.getItem('auth_token');
    }

    generateSessionId() {
        return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    setupEventListeners() {
        // Form submission
        document.getElementById('loginForm').addEventListener('submit', (e) => this.handleLogin(e));

        // Register button
        const registerButton = document.getElementById('registerButton');
        if (registerButton) {
            registerButton.addEventListener('click', () => this.handleRegister());
        }

        // Password toggle
        document.getElementById('togglePassword').addEventListener('click', () => this.togglePassword());

        // Behavioral data collection
        document.addEventListener('keydown', (e) => this.recordKeyDown(e));
        document.addEventListener('keyup', (e) => this.recordKeyUp(e));
        document.addEventListener('mousemove', (e) => this.recordMouseMove(e));
        document.addEventListener('click', (e) => this.recordClick(e));
    }

    connectWebSocket() {
        const wsHost = 'localhost';
        const wsPort = 8765;
        const wsToken = this.getWebSocketToken();

        if (!wsToken) {
            this.updateStatus('WebSocket token missing', 'error');
            this.showAlert('Set WebSocket token in localStorage key "ws_auth_token".', 'error');
            return;
        }

        try {
            this.socket = new WebSocket(`ws://${wsHost}:${wsPort}`);

            this.socket.onopen = () => {
                console.log('WebSocket connected');
                this.updateStatus('Connected', 'success');

                // Send authentication token
                this.socket.send(JSON.stringify({
                    token: wsToken
                }));
            };

            this.socket.onmessage = (event) => {
                this.handleWebSocketMessage(event);
            };

            this.socket.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateStatus('Connection error', 'error');
            };

            this.socket.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateStatus('Disconnected', 'warning');

                // Attempt to reconnect after 3 seconds
                if (!this.sessionTerminated) {
                    setTimeout(() => this.connectWebSocket(), 3000);
                }
            };
        } catch (error) {
            console.error('Failed to connect WebSocket:', error);
            this.updateStatus('Failed to connect', 'error');
        }
    }

    handleWebSocketMessage(event) {
        try {
            const data = JSON.parse(event.data);

            switch (data.type) {
                case 'analysis_result':
                    this.updateRiskScore(data.riskScore);
                    if (data.alert) {
                        this.showAlert(data.alert.message, data.alert.level.toLowerCase());
                    }
                    break;

                case 'authentication_success':
                    console.log('User authenticated:', data.userId);
                    break;

                case 'error':
                    this.showAlert(data.message, 'error');
                    break;

                case 'session_terminated':
                    this.terminateSession(data.reason || 'Session terminated due to anomaly detection');
                    break;
            }
        } catch (error) {
            console.error('Error parsing WebSocket message:', error);
        }
    }

    terminateSession(reason) {
        this.sessionTerminated = true;
        this.isCollecting = false;
        this.keystrokeData = [];
        this.mouseData = [];
        this.updateStatus('Session terminated', 'error');
        this.showAlert(reason, 'error');
        localStorage.removeItem('user_id');
        localStorage.removeItem('username');
        localStorage.removeItem('session_id');
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.close();
        }
    }

    recordKeyDown(event) {
        if (!this.isCollecting) return;

        const timestamp = performance.now();
        this.keystrokeData.push({
            type: 'keydown',
            keyCode: event.keyCode,
            key: event.key,
            timestamp: timestamp,
            sessionId: this.sessionId
        });
    }

    recordKeyUp(event) {
        if (!this.isCollecting) return;

        const timestamp = performance.now();
        const keyDownEvent = this.keystrokeData.find(
            k => k.keyCode === event.keyCode && k.type === 'keydown' && !k.matched
        );

        if (keyDownEvent) {
            keyDownEvent.matched = true;
            this.keystrokeData.push({
                type: 'keyup',
                keyCode: event.keyCode,
                key: event.key,
                timestamp: timestamp,
                dwellTime: timestamp - keyDownEvent.timestamp,
                sessionId: this.sessionId
            });
        }
    }

    recordMouseMove(event) {
        if (!this.isCollecting) return;

        // Throttle mouse move events
        if (this.mouseData.length > 0) {
            const lastEvent = this.mouseData[this.mouseData.length - 1];
            if (performance.now() - lastEvent.timestamp < 50) {
                return; // Skip if less than 50ms since last event
            }
        }

        const timestamp = performance.now();
        this.mouseData.push({
            type: 'mousemove',
            x: event.clientX,
            y: event.clientY,
            timestamp: timestamp,
            sessionId: this.sessionId
        });
    }

    recordClick(event) {
        if (!this.isCollecting) return;

        const timestamp = performance.now();
        this.mouseData.push({
            type: 'click',
            x: event.clientX,
            y: event.clientY,
            button: event.button,
            timestamp: timestamp,
            sessionId: this.sessionId
        });
    }

    startDataCollection() {
        this.isCollecting = true;
        this.updateStatus('Collecting behavioral data...', 'success');

        // Send behavioral data every 2 seconds
        setInterval(() => {
            this.sendBehavioralData();
        }, 2000);
    }

    sendBehavioralData() {
        if (this.sessionTerminated) {
            return;
        }

        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
            return;
        }

        if (this.keystrokeData.length === 0 && this.mouseData.length === 0) {
            return;
        }

        const payload = {
            type: 'behavioral_data',
            userId: document.getElementById('username').value || 'guest',
            sessionId: this.sessionId,
            keystrokeData: this.keystrokeData,
            mouseData: this.mouseData,
            timestamp: Date.now()
        };

        this.socket.send(JSON.stringify(payload));

        // Clear data after sending
        this.keystrokeData = [];
        this.mouseData = [];
    }

    async handleLogin(event) {
        event.preventDefault();

        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        if (!username || !password) {
            this.showAlert('Please enter both username and password', 'error');
            return;
        }

        // Disable login button
        const loginButton = document.getElementById('loginButton');
        loginButton.disabled = true;
        loginButton.querySelector('.button-text').textContent = 'Authenticating...';

        try {
            const response = await fetch('http://localhost:5000/api/start-session', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });

            const result = await response.json();

            if (result.success) {
                this.showAlert('Session started! Redirecting to calibration...', 'success');

                // Store user info
                localStorage.setItem('user_id', result.user_id);
                localStorage.setItem('username', result.username);
                localStorage.setItem('session_id', this.sessionId);
                if (result.access_token) {
                    localStorage.setItem('auth_token', result.access_token);
                    localStorage.setItem('ws_auth_token', result.access_token);
                }

                // Send user authentication event via WebSocket
                if (this.socket && this.socket.readyState === WebSocket.OPEN) {
                    this.socket.send(JSON.stringify({
                        type: 'user_authentication',
                        userId: username,
                        sessionId: this.sessionId
                    }));
                }

                // Redirect to calibration after 1 second
                setTimeout(() => {
                    window.location.href = '../calibration/calibration.html';
                }, 1000);
            } else {
                this.showAlert(result.detail || result.error || 'Failed to start session', 'error');
                loginButton.disabled = false;
                loginButton.querySelector('.button-text').textContent = 'Start Session';
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showAlert('Network error. Please try again.', 'error');
            loginButton.disabled = false;
            loginButton.querySelector('.button-text').textContent = 'Start Session';
        }
    }

    handleRegister() {
        // Redirect to registration page or show registration form
        this.showAlert('Registration feature coming soon!', 'warning');
        // window.location.href = 'register.html';
    }

    togglePassword() {
        const passwordInput = document.getElementById('password');
        const type = passwordInput.type === 'password' ? 'text' : 'password';
        passwordInput.type = type;
    }

    updateRiskScore(score) {
        this.currentRiskScore = score;
        const riskValue = document.getElementById('riskValue');
        const riskFill = document.getElementById('riskFill');

        // Update value
        riskValue.textContent = (score * 100).toFixed(1) + '%';

        // Update bar
        riskFill.style.width = (score * 100) + '%';

        // Update color based on risk level
        riskFill.classList.remove('low', 'medium', 'high');
        if (score < 0.3) {
            riskFill.classList.add('low');
        } else if (score < 0.7) {
            riskFill.classList.add('medium');
        } else {
            riskFill.classList.add('high');
        }
    }

    updateStatus(message, type) {
        const statusText = document.getElementById('statusText');
        const statusDot = document.getElementById('statusDot');

        statusText.textContent = message;

        // Update dot color
        statusDot.style.background = {
            'success': 'var(--success-color)',
            'warning': 'var(--warning-color)',
            'error': 'var(--danger-color)'
        }[type] || 'var(--success-color)';
    }

    showAlert(message, type) {
        const alertBox = document.getElementById('alertBox');
        const alertMessage = document.getElementById('alertMessage');

        alertMessage.textContent = message;
        alertBox.className = `alert ${type}`;
        alertBox.style.display = 'flex';

        // Auto-hide after 5 seconds
        setTimeout(() => {
            alertBox.style.display = 'none';
        }, 5000);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    const collector = new LoginBehavioralCollector();
});
