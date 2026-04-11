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
        this.pendingAuthPayload = null;
        this.wsReconnectTimer = null;
        this.wsTokenInUse = null;
        this.lastKeyEventTimestamp = 0;
        this.collectionTimer = null;
        this.behaviorListenersEnabled = false;
        this.boundBehaviorHandlers = {
            keydown: (event) => this.recordKeyDown(event),
            keyup: (event) => this.recordKeyUp(event),
            mousemove: (event) => this.recordMouseMove(event),
            click: (event) => this.recordClick(event),
            input: (event) => this.recordInputFallback(event),
            change: (event) => this.recordInputFallback(event),
        };
        this.deviceFingerprint = localStorage.getItem('device_fingerprint') || this.generateDeviceFingerprint();
        localStorage.setItem('device_fingerprint', this.deviceFingerprint);

        this.init();
    }

    init() {
        this.setupEventListeners();
        this.hideRiskWidget();
        this.resetRiskScoreDisplay();
        this.updateStatus('Ready. Login to start secure monitoring.', 'warning');
        this.checkBackendHealth();
    }

    getWebSocketToken() {
        if (window.RUNTIME_CONFIG && window.RUNTIME_CONFIG.wsAuthToken) {
            return window.RUNTIME_CONFIG.wsAuthToken;
        }
        return localStorage.getItem('ws_auth_token') || localStorage.getItem('auth_token');
    }

    getApiBaseUrl() {
        if (window.RUNTIME_CONFIG && window.RUNTIME_CONFIG.apiBaseUrl) {
            const configured = window.RUNTIME_CONFIG.apiBaseUrl.replace(/\/$/, '');
            try {
                const parsed = new URL(configured);
                if (parsed.hostname === '0.0.0.0') {
                    parsed.hostname = (window.location && window.location.hostname && window.location.hostname !== '0.0.0.0')
                        ? window.location.hostname
                        : 'localhost';
                    return parsed.toString().replace(/\/$/, '');
                }
            } catch (error) {
                // Keep configured value if it is not a valid absolute URL.
            }
            return configured;
        }
        if (window.location && window.location.origin && window.location.origin !== 'null') {
            return window.location.origin;
        }
        return 'http://localhost:5000';
    }

    getWebSocketUrl() {
        if (window.RUNTIME_CONFIG && window.RUNTIME_CONFIG.wsUrl) {
            return window.RUNTIME_CONFIG.wsUrl;
        }
        const protocol = (window.location && window.location.protocol === 'https:') ? 'wss:' : 'ws:';
        let host = (window.location && window.location.hostname) ? window.location.hostname : 'localhost';
        if (host === '0.0.0.0') {
            host = 'localhost';
        }
        const portPart = window.location && window.location.port ? `:${window.location.port}` : '';
        return `${protocol}//${host}${portPart}/ws/behavioral`;
    }

    generateSessionId() {
        return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    generateDeviceFingerprint() {
        const parts = [
            navigator.userAgent || 'na',
            navigator.language || 'na',
            navigator.platform || 'na',
            String(navigator.hardwareConcurrency || 0),
            String(navigator.maxTouchPoints || 0),
            String(screen.width || 0),
            String(screen.height || 0),
            String(screen.colorDepth || 0),
            Intl.DateTimeFormat().resolvedOptions().timeZone || 'na',
        ];
        return parts.join('|').slice(0, 240);
    }

    deviceClass() {
        const width = window.innerWidth || screen.width || 0;
        return width <= 768 ? 'mobile' : 'desktop';
    }

    buildContext(sessionType = 'login') {
        return {
            device_class: this.deviceClass(),
            session_type: sessionType,
            device_fingerprint: this.deviceFingerprint,
        };
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
    }

    enableBehavioralListeners() {
        if (this.behaviorListenersEnabled) {
            return;
        }
        document.addEventListener('keydown', this.boundBehaviorHandlers.keydown);
        document.addEventListener('keyup', this.boundBehaviorHandlers.keyup);
        document.addEventListener('mousemove', this.boundBehaviorHandlers.mousemove);
        document.addEventListener('click', this.boundBehaviorHandlers.click);
        document.addEventListener('input', this.boundBehaviorHandlers.input, true);
        document.addEventListener('change', this.boundBehaviorHandlers.change, true);
        this.behaviorListenersEnabled = true;
    }

    disableBehavioralListeners() {
        if (!this.behaviorListenersEnabled) {
            return;
        }
        document.removeEventListener('keydown', this.boundBehaviorHandlers.keydown);
        document.removeEventListener('keyup', this.boundBehaviorHandlers.keyup);
        document.removeEventListener('mousemove', this.boundBehaviorHandlers.mousemove);
        document.removeEventListener('click', this.boundBehaviorHandlers.click);
        document.removeEventListener('input', this.boundBehaviorHandlers.input, true);
        document.removeEventListener('change', this.boundBehaviorHandlers.change, true);
        this.behaviorListenersEnabled = false;
    }

    enableBehaviorCollection() {
        this.enableBehavioralListeners();
        this.startDataCollection();
        this.showRiskWidget();
    }

    disableBehaviorCollection() {
        this.stopDataCollection();
        this.disableBehavioralListeners();
        this.keystrokeData = [];
        this.mouseData = [];
    }

    connectWebSocket(forceReconnect = false) {
        const wsUrl = this.getWebSocketUrl();
        const wsToken = this.getWebSocketToken();
        const riskSignal = document.getElementById('riskSignal');

        if (this.wsReconnectTimer) {
            clearTimeout(this.wsReconnectTimer);
            this.wsReconnectTimer = null;
        }

        if (this.socket) {
            const isOpenOrConnecting = this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING;
            const tokenChanged = Boolean(wsToken && this.wsTokenInUse && wsToken !== this.wsTokenInUse);
            if (forceReconnect || tokenChanged) {
                try {
                    this.socket.close(1000, 'token refresh');
                } catch (error) {
                    // no-op
                }
            } else if (isOpenOrConnecting) {
                return;
            }
        }

        if (!wsToken) {
            this.updateStatus('Waiting for login token', 'warning');
            if (riskSignal) {
                riskSignal.textContent = 'Signal: websocket not authenticated yet';
            }
            return;
        }

        try {
            const wsUrlWithToken = `${wsUrl}${wsUrl.includes('?') ? '&' : '?'}token=${encodeURIComponent(wsToken)}`;
            localStorage.setItem('ws_url', wsUrlWithToken);
            const socket = new WebSocket(wsUrlWithToken);
            this.socket = socket;

            socket.onopen = () => {
                if (this.socket !== socket) {
                    return;
                }
                console.log('WebSocket connected');
                this.updateStatus('Connected', 'success');
                this.wsTokenInUse = wsToken;
                if (riskSignal) {
                    riskSignal.textContent = 'Signal: connected, waiting for activity';
                }

                // Send authentication token
                socket.send(JSON.stringify({
                    token: wsToken
                }));

                if (this.pendingAuthPayload) {
                    socket.send(JSON.stringify(this.pendingAuthPayload));
                    this.pendingAuthPayload = null;
                }
            };

            socket.onmessage = (event) => {
                if (this.socket !== socket) {
                    return;
                }
                this.handleWebSocketMessage(event);
            };

            socket.onerror = (error) => {
                if (this.socket !== socket) {
                    return;
                }
                console.error('WebSocket error:', error);
                this.updateStatus('Connection error', 'error');
                this.showAlert(`WebSocket connection failed: ${wsUrl}`, 'error');
                if (riskSignal) {
                    riskSignal.textContent = 'Signal: websocket error';
                }
            };

            socket.onclose = (event) => {
                if (this.socket !== socket) {
                    return;
                }
                console.log('WebSocket disconnected');
                this.socket = null;
                this.wsTokenInUse = null;
                this.updateStatus('Disconnected', 'warning');
                if (riskSignal) {
                    if (event && event.code === 1008) {
                        riskSignal.textContent = 'Signal: websocket auth rejected';
                    } else {
                        riskSignal.textContent = 'Signal: websocket disconnected';
                    }
                }
                if (!this.sessionTerminated && !(event && event.code === 1008) && this.getWebSocketToken()) {
                    this.wsReconnectTimer = setTimeout(() => this.connectWebSocket(), 1500);
                }
            };
        } catch (error) {
            console.error('Failed to connect WebSocket:', error);
            this.updateStatus('Failed to connect', 'error');
            if (riskSignal) {
                riskSignal.textContent = 'Signal: websocket connection failed';
            }
        }
    }

    handleWebSocketMessage(event) {
        try {
            const data = JSON.parse(event.data);

            switch (data.type) {
                case 'analysis_result':
                    this.handleRealtimeAnalysis(data);
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
        this.disableBehaviorCollection();
        this.hideRiskWidget();
        this.resetRiskScoreDisplay();
        if (this.wsReconnectTimer) {
            clearTimeout(this.wsReconnectTimer);
            this.wsReconnectTimer = null;
        }
        this.updateStatus('Session terminated', 'error');
        this.showAlert(reason, 'error');
        localStorage.removeItem('user_id');
        localStorage.removeItem('username');
        localStorage.removeItem('session_id');
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            this.socket.close();
        }
    }

    showRiskWidget() {
        const riskContainer = document.getElementById('riskScoreContainer');
        if (riskContainer) {
            riskContainer.classList.remove('hidden');
        }
    }

    hideRiskWidget() {
        const riskContainer = document.getElementById('riskScoreContainer');
        if (riskContainer) {
            riskContainer.classList.add('hidden');
        }
    }

    resetRiskScoreDisplay() {
        const riskValue = document.getElementById('riskValue');
        const riskFill = document.getElementById('riskFill');
        const riskSignal = document.getElementById('riskSignal');
        this.currentRiskScore = 0;
        if (riskValue) {
            riskValue.textContent = '--';
        }
        if (riskFill) {
            riskFill.style.width = '0%';
            riskFill.classList.remove('low', 'medium', 'high');
        }
        if (riskSignal) {
            riskSignal.textContent = 'Signal: waiting for authenticated session';
        }
    }

    recordKeyDown(event) {
        if (!this.isCollecting) return;

        const timestamp = performance.now();
        this.lastKeyEventTimestamp = timestamp;
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
        this.lastKeyEventTimestamp = timestamp;
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

    recordInputFallback(event) {
        if (!this.isCollecting) return;
        const target = event && event.target ? event.target : null;
        const isTextInput = target && (
            target.tagName === 'INPUT' ||
            target.tagName === 'TEXTAREA' ||
            target.isContentEditable
        );
        if (!isTextInput) return;

        const now = performance.now();
        if ((now - this.lastKeyEventTimestamp) < 180) {
            return;
        }
        this.lastKeyEventTimestamp = now;
        this.keystrokeData.push({
            type: 'keydown',
            keyCode: 0,
            key: 'InputEvent',
            timestamp: now,
            sessionId: this.sessionId
        });
        this.keystrokeData.push({
            type: 'keyup',
            keyCode: 0,
            key: 'InputEvent',
            timestamp: now + 12,
            dwellTime: 12,
            sessionId: this.sessionId
        });
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
        if (this.collectionTimer) {
            clearInterval(this.collectionTimer);
            this.collectionTimer = null;
        }
        this.isCollecting = true;
        this.updateStatus('Collecting behavioral data...', 'success');

        // Send behavioral data every 1 second for faster demo feedback.
        this.collectionTimer = setInterval(() => {
            this.sendBehavioralData();
        }, 1000);
    }

    stopDataCollection() {
        this.isCollecting = false;
        if (this.collectionTimer) {
            clearInterval(this.collectionTimer);
            this.collectionTimer = null;
        }
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
            sessionId: this.sessionId,
            keystrokeData: this.keystrokeData,
            mouseData: this.mouseData,
            context: this.buildContext('login_monitoring'),
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
            const startSessionResponse = await fetch(`${this.getApiBaseUrl()}/api/start-session`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password, device_fingerprint: this.deviceFingerprint })
            });

            const startSessionResult = await startSessionResponse.json();
            if (!startSessionResponse.ok || !startSessionResult.success) {
                this.showAlert(startSessionResult.detail || startSessionResult.error || 'Failed to start session', 'error');
                loginButton.disabled = false;
                loginButton.querySelector('.button-text').textContent = 'Start Session';
                return;
            }

            const loginResponse = await fetch(`${this.getApiBaseUrl()}/api/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username,
                    password,
                    risk_score: this.currentRiskScore || 0,
                    device_fingerprint: this.deviceFingerprint
                })
            });
            const loginResult = await loginResponse.json();
            if (!loginResponse.ok || !loginResult.success) {
                this.showAlert(loginResult.detail || loginResult.error || 'Login failed', 'error');
                loginButton.disabled = false;
                loginButton.querySelector('.button-text').textContent = 'Start Session';
                return;
            }

            const accessToken = loginResult.access_token || null;
            const resolvedRole = loginResult.role || startSessionResult.role || 'user';
            if (!accessToken) {
                this.showAlert('Login succeeded but no access token was returned. Restart backend services and try again.', 'error');
                loginButton.disabled = false;
                loginButton.querySelector('.button-text').textContent = 'Start Session';
                return;
            }

            this.showAlert('Session started! Redirecting to dashboard...', 'success');

            // Store user info
            localStorage.setItem('user_id', loginResult.user_id || startSessionResult.user_id);
            localStorage.setItem('username', loginResult.username || startSessionResult.username || username);
            localStorage.setItem('user_role', resolvedRole);
            localStorage.setItem('session_id', this.sessionId);
            localStorage.setItem('auth_token', accessToken);
            localStorage.setItem('ws_auth_token', accessToken);
            localStorage.setItem('device_fingerprint', this.deviceFingerprint);

            this.enableBehaviorCollection();
            this.connectWebSocket(true);

            // Redirect to dashboard after 1 second
            setTimeout(() => {
                window.location.href = '../dashboard/index.html';
            }, 1000);
        } catch (error) {
            console.error('Login error:', error);
            const apiBaseUrl = this.getApiBaseUrl();
            if (error instanceof TypeError) {
                this.showAlert(`API unreachable at ${apiBaseUrl}. Start backend server and open app via http://localhost:5000/login/login.html`, 'error');
            } else {
                this.showAlert('Network error. Please try again.', 'error');
            }
            loginButton.disabled = false;
            loginButton.querySelector('.button-text').textContent = 'Start Session';
        }
    }

    async checkBackendHealth() {
        const apiBaseUrl = this.getApiBaseUrl();
        try {
            const response = await fetch(`${apiBaseUrl}/health`, { method: 'GET' });
            if (!response.ok) {
                this.updateStatus('Backend unavailable', 'error');
                return;
            }
            this.updateStatus('Backend connected', 'success');
        } catch (error) {
            this.updateStatus('Backend unreachable', 'error');
        }
    }

    async handleRegister() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        if (!username || !password) {
            this.showAlert('Enter username and password to register.', 'warning');
            return;
        }

        try {
            const response = await fetch(`${this.getApiBaseUrl()}/api/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            const result = await response.json();
            if (response.ok && result.success) {
                this.showAlert('Registration successful. You can now start session.', 'success');
                return;
            }
            this.showAlert(result.detail || result.error || 'Registration failed.', 'error');
        } catch (error) {
            this.showAlert('Registration failed due to network error.', 'error');
        }
    }

    togglePassword() {
        const passwordInput = document.getElementById('password');
        const type = passwordInput.type === 'password' ? 'text' : 'password';
        passwordInput.type = type;
    }

    updateRiskScore(score, explanation = {}) {
        this.currentRiskScore = score;
        const riskValue = document.getElementById('riskValue');
        const riskFill = document.getElementById('riskFill');
        const riskSignal = document.getElementById('riskSignal');

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

        if (riskSignal) {
            const components = (explanation && typeof explanation === 'object') ? (explanation.components || {}) : {};
            const coverage = Number(components.modality_coverage);
            if (!Number.isFinite(coverage)) {
                riskSignal.textContent = 'Signal: unknown coverage';
            } else if (coverage >= 0.99) {
                riskSignal.textContent = `Signal: full (typing + mouse) ${Math.round(coverage * 100)}%`;
            } else if (coverage >= 0.49) {
                riskSignal.textContent = `Signal: partial (typing-only or mouse-only) ${Math.round(coverage * 100)}%`;
            } else {
                riskSignal.textContent = `Signal: sparse ${Math.round(coverage * 100)}%`;
            }
        }
    }

    handleRealtimeAnalysis(data) {
        const effectiveUser = String(data.effectiveUser || '').trim();
        const typedUsername = String((document.getElementById('username') || {}).value || '').trim();
        if (typedUsername && effectiveUser && typedUsername !== effectiveUser) {
            const riskSignal = document.getElementById('riskSignal');
            if (riskSignal) {
                riskSignal.textContent = `Signal: stream is bound to ${effectiveUser}`;
            }
            this.updateStatus(`Realtime stream is currently mapped to ${effectiveUser}`, 'warning');
            return;
        }
        this.updateRiskScore(data.riskScore, data.riskExplanation || {});
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
