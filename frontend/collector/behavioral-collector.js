
// behavioral-collector.js
class BehavioralDataCollector {
    constructor(userId) {
        this.userId = userId;
        this.keystrokeData = [];
        this.mouseData = [];
        this.eyeData = [];
        this.sessionId = this.generateSessionId();
        this.startTime = performance.now();
        this.setupEventListeners();
    }

    setupEventListeners() {
        // Keystroke dynamics
        document.addEventListener('keydown', (e) => this.recordKeyDown(e));
        document.addEventListener('keyup', (e) => this.recordKeyUp(e));
        
        // Mouse dynamics
        document.addEventListener('mousemove', (e) => this.recordMouseMove(e));
        document.addEventListener('click', (e) => this.recordClick(e));
        document.addEventListener('scroll', (e) => this.recordScroll(e));
        
        // Behavioral Eye/Focus tracking (Proxy)
        document.addEventListener('mouseover', (e) => this.recordEyeFocus(e));
    }

    recordKeyDown(event) {
        console.log('Key down:', event.key);
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
            k => k.keyCode === event.keyCode && k.type === 'keydown'
        );
        
        if (keyDownEvent) {
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
        console.log('Mouse move:', event.clientX, event.clientY);
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

    recordScroll(event) {
        const timestamp = performance.now();
        this.mouseData.push({
            type: 'scroll',
            timestamp: timestamp,
            sessionId: this.sessionId
        });
    }

    recordEyeFocus(event) {
        // Using element hover as a proxy for gaze fixation
        const timestamp = performance.now();
        this.eyeData.push({
            x: event.clientX,
            y: event.clientY,
            timestamp: timestamp,
            isBlink: false, // Blink simulation or actual eye tracking API
            sessionId: this.sessionId
        });
        
        // Simulate a blink occasionally for diversity in data
        if (Math.random() < 0.01) {
            this.eyeData.push({
                x: event.clientX,
                y: event.clientY,
                timestamp: timestamp + 50,
                isBlink: true,
                blinkDuration: 150,
                sessionId: this.sessionId
            });
        }
    }

    // Send data to backend every 1 second for faster demo detection.
    sendDataToBackend() {
        if (!window.socket) {
            console.warn("Collector: window.socket not found. Data not sent.");
            return;
        }
        console.log('Collector: Attempting to send data. WebSocket state:', window.socket.readyState);
        const payload = {
            type: 'behavioral_data',
            userId: this.userId,
            sessionId: this.sessionId,
            keystrokeData: this.keystrokeData,
            mouseData: this.mouseData,
            eyeData: this.eyeData,
            timestamp: Date.now()
        };

        // Send data through the existing websocket
        if (window.socket.readyState === WebSocket.OPEN) {
            window.socket.send(JSON.stringify(payload));

            // Clear the data after sending
            this.keystrokeData = [];
            this.mouseData = [];
            this.eyeData = [];
        } else {
            console.warn("WebSocket not open. Data not sent.");
        }
    }

    generateSessionId() {
        return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    startSendingData() {
        console.log("Collector: Starting data transmission interval.");
        setInterval(() => this.sendDataToBackend(), 1000); // Send data every 1 second
    }
}

// Initialize collector only when userId is available globally.
if (typeof userId !== 'undefined' && userId) {
    const collector = new BehavioralDataCollector(userId);
    collector.startSendingData();
}
