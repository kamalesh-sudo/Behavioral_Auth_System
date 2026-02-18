class CalibrationHandler {
    constructor() {
        this.targetText = document.getElementById('targetText').innerText.trim();
        this.inputArea = document.getElementById('typingInput');
        this.completeButton = document.getElementById('completeButton');
        this.progressFill = document.getElementById('progressFill');
        this.charCount = document.getElementById('charCount');
        this.totalChars = document.getElementById('totalChars');

        this.keystrokeData = [];
        this.mouseData = [];
        this.sessionId = localStorage.getItem('session_id');
        this.userId = localStorage.getItem('user_id');
        this.username = localStorage.getItem('username');

        if (!this.username) {
            window.location.href = '../login/login.html';
            return;
        }

        this.init();
    }

    init() {
        this.totalChars.textContent = this.targetText.length;

        this.setupEventListeners();
        this.connectWebSocket();
    }

    connectWebSocket() {
        const wsHost = 'localhost';
        const wsPort = 8765;

        try {
            this.socket = new WebSocket(`ws://${wsHost}:${wsPort}`);

            this.socket.onopen = () => {
                console.log('WebSocket connected');
                document.getElementById('statusText').textContent = 'Connected. Start typing.';
                document.getElementById('statusDot').style.background = 'var(--success-color)';

                this.socket.send(JSON.stringify({
                    token: 'your-secret-auth-token'
                }));
            };

            this.socket.onerror = (error) => {
                console.error('WebSocket error:', error);
                document.getElementById('statusText').textContent = 'Connection error';
                document.getElementById('statusDot').style.background = 'var(--danger-color)';
            };

        } catch (error) {
            console.error('Failed to connect WebSocket:', error);
        }
    }

    setupEventListeners() {
        this.inputArea.addEventListener('input', (e) => this.handleInput(e));
        this.inputArea.addEventListener('keydown', (e) => this.recordKeyDown(e));
        this.inputArea.addEventListener('keyup', (e) => this.recordKeyUp(e));

        this.completeButton.addEventListener('click', () => this.finishCalibration());

        // Mouse tracking
        document.addEventListener('mousemove', (e) => this.recordMouseMove(e));
        document.addEventListener('click', (e) => this.recordClick(e));

        // Prevent pasting
        this.inputArea.addEventListener('paste', (e) => {
            e.preventDefault();
            alert('Please type the text manually.');
        });
    }

    handleInput(e) {
        const currentText = this.inputArea.value;
        const progress = Math.min(100, (currentText.length / this.targetText.length) * 100);

        this.progressFill.style.width = `${progress}%`;
        this.charCount.textContent = currentText.length;

        if (currentText.length >= this.targetText.length * 0.9) {
            this.completeButton.disabled = false;
        } else {
            this.completeButton.disabled = true;
        }
    }

    recordKeyDown(event) {
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

    finishCalibration() {
        // Send data to backend
        if (this.socket && this.socket.readyState === WebSocket.OPEN) {
            const payload = {
                type: 'behavioral_data',
                userId: this.username,
                sessionId: this.sessionId,
                keystrokeData: this.keystrokeData,
                mouseData: this.mouseData,
                timestamp: Date.now()
            };

            this.socket.send(JSON.stringify(payload));

            // Also notify that user is "authenticated" (session started)
            this.socket.send(JSON.stringify({
                type: 'user_authentication',
                userId: this.username,
                sessionId: this.sessionId
            }));

            // Redirect to dashboard
            setTimeout(() => {
                window.location.href = '../dashboard/index.html';
            }, 1000);
        } else {
            alert('Connection lost. Please refresh and try again.');
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new CalibrationHandler();
});
