class WorkspaceApp {
    constructor() {
        this.apiBase = window.location.origin;
        this.token = localStorage.getItem("auth_token");
        this.username = localStorage.getItem("username");
        this.userId = localStorage.getItem("user_id");
        this.userRole = localStorage.getItem("user_role") || "user";
        this.hasSecurityAccess = false;
        this.sessionId = localStorage.getItem("session_id") || `session_${Date.now()}`;
        this.deviceFingerprint = localStorage.getItem("device_fingerprint") || this.generateDeviceFingerprint();
        this.projects = [];
        this.tasks = [];
        this.currentProjectId = null;
        this.socket = null;
        this.keystrokeData = [];
        this.mouseData = [];
        this.riskScore = 0;
        this.flushTimer = null;
        this.wsReconnectTimer = null;
        this.wsManuallyClosed = false;
        this.behaviorCollectionEnabled = true;
        this.behaviorFlushIntervalMs = 500;
        this.lastKeyEventTimestamp = 0;
        this.taskSearchQuery = "";
        this.taskPriorityFilter = "all";
        this.taskStatusFilter = "all";
        this.taskSortBy = "newest";
        this.editingTaskId = null;

        if (!this.token || !this.username) {
            window.location.href = "../login/login.html";
            return;
        }

        document.getElementById("usernameText").textContent = this.username;
        document.getElementById("roleText").textContent = this.userRole;
        localStorage.setItem("device_fingerprint", this.deviceFingerprint);
        this.bindUI();
        this.initSecurityPanel();
        this.refreshUserRole();
        this.initRealtime();
        this.loadProjects();
        this.initStatusCard();
    }

    generateDeviceFingerprint() {
        const parts = [
            navigator.userAgent || "na",
            navigator.language || "na",
            navigator.platform || "na",
            String(navigator.hardwareConcurrency || 0),
            String(navigator.maxTouchPoints || 0),
            String(screen.width || 0),
            String(screen.height || 0),
            String(screen.colorDepth || 0),
            Intl.DateTimeFormat().resolvedOptions().timeZone || "na",
        ];
        return parts.join("|").slice(0, 240);
    }

    deviceClass() {
        const width = window.innerWidth || screen.width || 0;
        return width <= 768 ? "mobile" : "desktop";
    }

    buildContext(sessionType = "workspace") {
        return {
            device_class: this.deviceClass(),
            session_type: sessionType,
            device_fingerprint: this.deviceFingerprint,
        };
    }

    bindUI() {
        document.getElementById("newProjectBtn").addEventListener("click", () => this.openProjectModal());
        document.getElementById("cancelProjectBtn").addEventListener("click", () => this.closeProjectModal());
        document.getElementById("saveProjectBtn").addEventListener("click", () => this.createProject());
        document.getElementById("createTaskBtn").addEventListener("click", () => this.createTask());
        document.getElementById("taskSearchInput").addEventListener("input", (event) => {
            this.taskSearchQuery = event.target.value.trim().toLowerCase();
            this.renderBoard();
        });
        document.getElementById("taskPriorityFilter").addEventListener("change", (event) => {
            this.taskPriorityFilter = event.target.value;
            this.renderBoard();
        });
        document.getElementById("taskStatusFilter").addEventListener("change", (event) => {
            this.taskStatusFilter = event.target.value;
            this.renderBoard();
        });
        document.getElementById("taskSortSelect").addEventListener("change", (event) => {
            this.taskSortBy = event.target.value;
            this.renderBoard();
        });
        document.getElementById("clearTaskFiltersBtn").addEventListener("click", () => this.resetTaskFilters());
        document.getElementById("cancelEditTaskBtn").addEventListener("click", () => this.closeEditTaskModal());
        document.getElementById("saveEditTaskBtn").addEventListener("click", () => this.saveEditedTask());
        document.getElementById("refreshSecurityBtn").addEventListener("click", () => this.refreshSecurityLists());
        document.getElementById("refreshUsersBtn").addEventListener("click", () => this.loadAdminUsers());
        document.getElementById("blockIpBtn").addEventListener("click", () => this.blockIp());
        document.getElementById("blockDeviceBtn").addEventListener("click", () => this.blockDevice());
        document.getElementById("refreshSecurityEventsBtn").addEventListener("click", () => this.loadSecurityEvents());
        document.getElementById("refreshRealtimeBtn").addEventListener("click", () => this.loadRealtimeMonitor());
        document.getElementById("logoutBtn").addEventListener("click", () => this.logout());
        document.getElementById("taskTitleInput").addEventListener("keydown", (event) => {
            if (event.key === "Enter") {
                event.preventDefault();
                this.createTask();
            }
        });
        document.getElementById("projectNameInput").addEventListener("keydown", (event) => {
            if (event.key === "Enter") {
                event.preventDefault();
                this.createProject();
            }
        });

        document.addEventListener("keydown", (e) => this.recordKeyDown(e));
        document.addEventListener("keyup", (e) => this.recordKeyUp(e));
        document.addEventListener("mousemove", (e) => this.recordMouseMove(e));
        document.addEventListener("click", (e) => this.recordClick(e));
        document.addEventListener("input", (e) => this.recordInputFallback(e), true);
        document.addEventListener("change", (e) => this.recordInputFallback(e), true);
    }

    canManageSecurity() {
        return this.userRole === "admin" || this.userRole === "analyst" || this.hasSecurityAccess;
    }

    async refreshUserRole() {
        if (!this.token || !this.username) return;
        try {
            const response = await fetch(`${this.apiBase}/api/user/${encodeURIComponent(this.username)}`, {
                headers: this.authHeaders(),
            });
            if (response.ok) {
                const data = await response.json();
                if (data.success && data.user) {
                    const role = data.user.role || "user";
                    this.userRole = role;
                    localStorage.setItem("user_role", role);
                    document.getElementById("roleText").textContent = role;
                    this.initSecurityPanel();
                    return;
                }
            }
            await this.probeSecurityAccess();
        } catch (error) {
            await this.probeSecurityAccess();
        }
    }

    async probeSecurityAccess() {
        try {
            const response = await fetch(`${this.apiBase}/api/security-events?limit=1`, {
                headers: this.authHeaders(),
            });
            this.hasSecurityAccess = response.ok;
            if (this.hasSecurityAccess && this.userRole === "user") {
                document.getElementById("roleText").textContent = "analyst/admin";
            }
            this.initSecurityPanel();
        } catch (error) {
            this.hasSecurityAccess = false;
        }
    }

    initSecurityPanel() {
        const panel = document.getElementById("securityPanel");
        if (!this.canManageSecurity()) {
            panel.classList.add("hidden");
            return;
        }
        panel.classList.remove("hidden");
        this.refreshSecurityLists();
    }

    setStatus(message) {
        document.getElementById("statusBar").textContent = message;
    }

    initStatusCard() {
        this.statusCard = document.getElementById("statusCard");
        this.statusIcon = document.getElementById("statusIcon");
        this.statusTitle = document.getElementById("statusTitle");
        this.statusDesc = document.getElementById("statusDesc");
        this.statusBtn = document.getElementById("statusActionBtn");

        this.statusBtn.addEventListener("click", () => {
            const securityPanel = document.getElementById("securityPanel");
            if (securityPanel) {
                securityPanel.scrollIntoView({ behavior: "smooth" });
                securityPanel.classList.add("highlight-panel");
                setTimeout(() => securityPanel.classList.remove("highlight-panel"), 2000);
            }
        });
    }

    updateStatusUI(isAnomaly, metadata = {}) {
        if (!this.statusCard) return;

        if (isAnomaly) {
            this.statusCard.classList.remove("status-normal");
            this.statusCard.classList.add("status-anomaly");
            this.statusTitle.textContent = "Anomaly Detected";
            this.statusDesc.textContent = metadata.reason || "Behavioral mismatch detected";
            this.statusBtn.classList.remove("hidden");
            this.statusIcon.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                    <line x1="12" y1="9" x2="12" y2="13"></line>
                    <line x1="12" y1="17" x2="12.01" y2="17"></line>
                </svg>`;
        } else {
            this.statusCard.classList.remove("status-anomaly");
            this.statusCard.classList.add("status-normal");
            this.statusTitle.textContent = "System Normal";
            this.statusDesc.textContent = "Identity verified via behavior";
            this.statusBtn.classList.add("hidden");
            this.statusIcon.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                </svg>`;
        }
    }

    setRiskCoverageText(message) {
        if (message) {
            console.log("[Signal Status]", message);
        }
        const el = document.getElementById("riskCoverageText");
        if (!el) return;
        el.textContent = message;
    }

    resetRiskDisplay() {
        this.riskScore = 0;
        const scoreEl = document.getElementById("riskScore");
        if (scoreEl) {
            scoreEl.textContent = "0.00";
        }
        this.setRiskCoverageText("Signal: waiting for data");
    }

    cleanupRealtime() {
        this.behaviorCollectionEnabled = false;
        this.keystrokeData = [];
        this.mouseData = [];
        if (this.wsReconnectTimer) {
            clearTimeout(this.wsReconnectTimer);
            this.wsReconnectTimer = null;
        }
        if (this.flushTimer) {
            clearInterval(this.flushTimer);
            this.flushTimer = null;
        }
        if (this.socket) {
            try {
                this.socket.close(1000, "logout");
            } catch (error) {
                // ignore cleanup close errors
            }
        }
        this.socket = null;
        this.resetRiskDisplay();
    }

    clearSessionState() {
        localStorage.removeItem("auth_token");
        localStorage.removeItem("ws_auth_token");
        localStorage.removeItem("user_id");
        localStorage.removeItem("username");
        localStorage.removeItem("user_role");
        localStorage.removeItem("session_id");
        document.cookie = "auth_token=; Max-Age=0; path=/";
        document.cookie = "ws_auth_token=; Max-Age=0; path=/";
    }

    logout() {
        this.wsManuallyClosed = true;
        this.cleanupRealtime();
        this.clearSessionState();
        this.setStatus("Logged out");
        window.location.href = "../login/login.html";
    }

    updateRiskCoverage(explanation = {}) {
        const components = explanation && typeof explanation === "object" ? (explanation.components || {}) : {};
        const coverage = Number(components.modality_coverage);
        if (!Number.isFinite(coverage)) {
            this.setRiskCoverageText("Signal: unknown coverage");
            return;
        }
        const pct = Math.round(coverage * 100);
        if (coverage >= 0.95) {
            this.setRiskCoverageText(`Signal: full (typing + mouse + eye) ${pct}%`);
        } else if (coverage >= 0.5) {
            this.setRiskCoverageText(`Signal: partial (any 2 modes active) ${pct}%`);
        } else if (coverage > 0.05) {
            this.setRiskCoverageText(`Signal: sparse (single mode active) ${pct}%`);
        } else {
            this.setRiskCoverageText("Signal: waiting for data");
        }
    }

    async refreshSecurityLists() {
        if (!this.canManageSecurity()) return;
        await Promise.all([
            this.loadBlockedIps(),
            this.loadBlockedDevices(),
            this.loadAdminUsers(),
            this.loadSecurityEvents(),
            this.loadRealtimeMonitor(),
        ]);
    }

    canManageUsers() {
        return this.userRole === "admin";
    }

    async loadAdminUsers() {
        if (!this.canManageSecurity()) return;
        const response = await fetch(`${this.apiBase}/api/admin/users`, {
            headers: this.authHeaders(),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to load users");
            return;
        }
        this.renderUsers(data.users || []);
    }

    async updateUserRole(username, role) {
        if (!this.canManageUsers()) return;
        const response = await fetch(`${this.apiBase}/api/admin/users/${encodeURIComponent(username)}/role`, {
            method: "POST",
            headers: this.authHeaders(),
            body: JSON.stringify({ role }),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to update user role");
            return;
        }
        this.setStatus(`Updated ${username} role to ${role}`);
        await this.loadAdminUsers();
    }

    async updateUserStatus(username, isActive) {
        if (!this.canManageUsers()) return;
        const response = await fetch(`${this.apiBase}/api/admin/users/${encodeURIComponent(username)}/status`, {
            method: "POST",
            headers: this.authHeaders(),
            body: JSON.stringify({ is_active: isActive }),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to update user status");
            return;
        }
        this.setStatus(`Updated ${username} status`);
        await this.loadAdminUsers();
    }

    renderUsers(users) {
        const container = document.getElementById("usersAdminList");
        container.innerHTML = "";
        if (!users.length) {
            const empty = document.createElement("div");
            empty.className = "empty-column";
            empty.textContent = "No users found.";
            container.appendChild(empty);
            return;
        }
        users.forEach((user) => {
            const row = document.createElement("div");
            row.className = "security-item";

            const text = document.createElement("div");
            const title = document.createElement("strong");
            title.textContent = `${user.username} (${user.role})`;
            const meta = document.createElement("div");
            meta.className = "security-meta";
            meta.textContent = user.is_active ? "Active" : "Disabled";
            text.appendChild(title);
            text.appendChild(meta);
            row.appendChild(text);

            const actions = document.createElement("div");
            actions.className = "security-item-actions";

            if (this.canManageUsers() && user.username !== this.username) {
                const roleSelect = document.createElement("select");
                roleSelect.className = "role-select";
                ["user", "analyst", "admin"].forEach((role) => {
                    const option = document.createElement("option");
                    option.value = role;
                    option.textContent = role;
                    if (user.role === role) option.selected = true;
                    roleSelect.appendChild(option);
                });
                roleSelect.addEventListener("change", () => this.updateUserRole(user.username, roleSelect.value));
                actions.appendChild(roleSelect);

                const statusBtn = document.createElement("button");
                statusBtn.className = "secondary-btn";
                statusBtn.textContent = user.is_active ? "Disable" : "Enable";
                statusBtn.addEventListener("click", () => this.updateUserStatus(user.username, !Boolean(user.is_active)));
                actions.appendChild(statusBtn);
            }

            row.appendChild(actions);
            container.appendChild(row);
        });
    }

    async loadSecurityEvents() {
        if (!this.canManageSecurity()) return;
        const response = await fetch(`${this.apiBase}/api/security-events?limit=50`, {
            headers: this.authHeaders(),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to load security events");
            return;
        }
        this.renderSecurityEvents(data.events || []);
    }

    renderSecurityEvents(events) {
        const container = document.getElementById("securityEventsList");
        container.innerHTML = "";
        if (!events.length) {
            const empty = document.createElement("div");
            empty.className = "empty-column";
            empty.textContent = "No events.";
            container.appendChild(empty);
            return;
        }
        events.forEach((event) => {
            const row = document.createElement("div");
            row.className = "security-item";

            const text = document.createElement("div");
            const title = document.createElement("strong");
            title.textContent = `${event.event_type} (${event.username})`;
            const meta = document.createElement("div");
            meta.className = "security-meta";
            meta.textContent = event.reason || "No reason";
            text.appendChild(title);
            text.appendChild(meta);
            row.appendChild(text);

            const timestamp = document.createElement("div");
            timestamp.className = "security-meta";
            timestamp.textContent = event.timestamp || "";
            row.appendChild(timestamp);

            container.appendChild(row);
        });
    }

    async loadRealtimeMonitor() {
        if (!this.canManageSecurity()) return;
        const output = document.getElementById("realtimeMonitorData");
        const response = await fetch(`${this.apiBase}/api/realtime-monitor`, {
            headers: this.authHeaders(),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to load realtime monitor");
            output.textContent = "Failed to load realtime monitor";
            return;
        }
        output.textContent = JSON.stringify(data, null, 2);
    }

    async loadBlockedIps() {
        const response = await fetch(`${this.apiBase}/api/admin/security/blocked-ips`, {
            headers: this.authHeaders(),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to load blocked IPs");
            return;
        }
        this.renderBlockedIps(data.blocked_ips || []);
    }

    async loadBlockedDevices() {
        const response = await fetch(`${this.apiBase}/api/admin/security/blocked-devices`, {
            headers: this.authHeaders(),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to load blocked devices");
            return;
        }
        this.renderBlockedDevices(data.blocked_devices || []);
    }

    async blockIp() {
        const ipAddress = document.getElementById("blockIpInput").value.trim();
        const reason = document.getElementById("blockIpReasonInput").value.trim() || "Manual admin block";
        if (!ipAddress) return;
        const response = await fetch(`${this.apiBase}/api/admin/security/block-ip`, {
            method: "POST",
            headers: this.authHeaders(),
            body: JSON.stringify({ ip_address: ipAddress, reason }),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to block IP");
            return;
        }
        this.setStatus(`Blocked IP ${ipAddress}`);
        document.getElementById("blockIpInput").value = "";
        document.getElementById("blockIpReasonInput").value = "";
        await this.loadBlockedIps();
    }

    async unblockIp(ipAddress) {
        const response = await fetch(`${this.apiBase}/api/admin/security/unblock-ip`, {
            method: "POST",
            headers: this.authHeaders(),
            body: JSON.stringify({ ip_address: ipAddress }),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to unblock IP");
            return;
        }
        this.setStatus(`Unblocked IP ${ipAddress}`);
        await this.loadBlockedIps();
    }

    async blockDevice() {
        const fingerprint = document.getElementById("blockDeviceInput").value.trim();
        const reason = document.getElementById("blockDeviceReasonInput").value.trim() || "Manual admin block";
        if (!fingerprint) return;
        const response = await fetch(`${this.apiBase}/api/admin/security/block-device`, {
            method: "POST",
            headers: this.authHeaders(),
            body: JSON.stringify({ device_fingerprint: fingerprint, reason }),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to block device");
            return;
        }
        this.setStatus("Blocked device fingerprint");
        document.getElementById("blockDeviceInput").value = "";
        document.getElementById("blockDeviceReasonInput").value = "";
        await this.loadBlockedDevices();
    }

    async unblockDevice(fingerprintHash) {
        const response = await fetch(`${this.apiBase}/api/admin/security/unblock-device`, {
            method: "POST",
            headers: this.authHeaders(),
            body: JSON.stringify({ device_fingerprint: fingerprintHash }),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to unblock device");
            return;
        }
        this.setStatus("Unblocked device fingerprint");
        await this.loadBlockedDevices();
    }

    renderBlockedIps(entries) {
        const container = document.getElementById("blockedIpsList");
        container.innerHTML = "";
        if (!entries.length) {
            const empty = document.createElement("div");
            empty.className = "empty-column";
            empty.textContent = "No blocked IPs.";
            container.appendChild(empty);
            return;
        }
        entries.forEach((entry) => {
            const row = document.createElement("div");
            row.className = "security-item";

            const text = document.createElement("div");
            const title = document.createElement("strong");
            title.textContent = entry.ip_address;
            const meta = document.createElement("div");
            meta.className = "security-meta";
            meta.textContent = entry.reason || "No reason";
            text.appendChild(title);
            text.appendChild(meta);
            row.appendChild(text);

            const button = document.createElement("button");
            button.className = "secondary-btn";
            button.textContent = "Unblock";
            button.addEventListener("click", () => this.unblockIp(entry.ip_address));
            row.appendChild(button);

            container.appendChild(row);
        });
    }

    renderBlockedDevices(entries) {
        const container = document.getElementById("blockedDevicesList");
        container.innerHTML = "";
        if (!entries.length) {
            const empty = document.createElement("div");
            empty.className = "empty-column";
            empty.textContent = "No blocked devices.";
            container.appendChild(empty);
            return;
        }
        entries.forEach((entry) => {
            const row = document.createElement("div");
            row.className = "security-item";

            const text = document.createElement("div");
            const shortHash = `${(entry.fingerprint_hash || "").slice(0, 16)}...`;
            const title = document.createElement("strong");
            title.textContent = shortHash;
            const meta = document.createElement("div");
            meta.className = "security-meta";
            meta.textContent = entry.reason || "No reason";
            text.appendChild(title);
            text.appendChild(meta);
            row.appendChild(text);

            const button = document.createElement("button");
            button.className = "secondary-btn";
            button.textContent = "Unblock";
            button.addEventListener("click", () => this.unblockDevice(entry.fingerprint_hash));
            row.appendChild(button);

            container.appendChild(row);
        });
    }

    resetTaskFilters() {
        this.taskSearchQuery = "";
        this.taskPriorityFilter = "all";
        this.taskStatusFilter = "all";
        this.taskSortBy = "newest";
        document.getElementById("taskSearchInput").value = "";
        document.getElementById("taskPriorityFilter").value = "all";
        document.getElementById("taskStatusFilter").value = "all";
        document.getElementById("taskSortSelect").value = "newest";
        this.renderBoard();
    }

    openEditTaskModal(task) {
        this.editingTaskId = task.id;
        document.getElementById("editTaskTitleInput").value = task.title || "";
        document.getElementById("editTaskDescriptionInput").value = task.description || "";
        document.getElementById("editTaskPriorityInput").value = task.priority || "medium";
        document.getElementById("editTaskDueDateInput").value = task.due_date || "";
        document.getElementById("editTaskAssigneeInput").value = task.assignee_username || "";
        document.getElementById("editTaskModal").classList.remove("hidden");
    }

    closeEditTaskModal() {
        this.editingTaskId = null;
        document.getElementById("editTaskModal").classList.add("hidden");
    }

    async saveEditedTask() {
        if (!this.editingTaskId) return;
        const title = document.getElementById("editTaskTitleInput").value.trim();
        if (!title) {
            this.setStatus("Task title is required");
            return;
        }

        const payload = {
            title,
            description: document.getElementById("editTaskDescriptionInput").value.trim() || null,
            priority: document.getElementById("editTaskPriorityInput").value,
            due_date: document.getElementById("editTaskDueDateInput").value || null,
            assignee_username: document.getElementById("editTaskAssigneeInput").value.trim() || null,
        };
        const response = await fetch(`${this.apiBase}/api/tasks/${this.editingTaskId}`, {
            method: "PATCH",
            headers: this.authHeaders(),
            body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to save task edits");
            return;
        }
        this.setStatus(`Task ${this.editingTaskId} updated`);
        this.closeEditTaskModal();
        await this.loadTasks(this.currentProjectId);
    }

    async duplicateTask(task) {
        if (!this.currentProjectId) return;
        const payload = {
            title: `${task.title} (Copy)`,
            description: task.description || "",
            priority: task.priority || "medium",
            due_date: task.due_date || null,
            assignee_username: task.assignee_username || null,
            status: "todo",
        };
        const response = await fetch(`${this.apiBase}/api/projects/${this.currentProjectId}/tasks`, {
            method: "POST",
            headers: this.authHeaders(),
            body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to duplicate task");
            return;
        }
        this.setStatus(`Task duplicated as #${data.task_id}`);
        await this.loadTasks(this.currentProjectId);
    }

    authHeaders() {
        return {
            "Content-Type": "application/json",
            Authorization: `Bearer ${this.token}`,
        };
    }

    wsUrl() {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const base = `${protocol}//${window.location.host}/ws/behavioral`;
        if (!this.token) {
            return base;
        }
        return `${base}?token=${encodeURIComponent(this.token)}`;
    }

    initRealtime() {
        if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
            return;
        }
        if (this.wsReconnectTimer) {
            clearTimeout(this.wsReconnectTimer);
            this.wsReconnectTimer = null;
        }
        const socket = new WebSocket(this.wsUrl());
        this.socket = socket;
        socket.onopen = () => {
            if (this.socket !== socket) {
                return;
            }
            socket.send(JSON.stringify({ token: this.token }));
            socket.send(
                JSON.stringify({
                    type: "user_authentication",
                    sessionId: this.sessionId,
                    context: this.buildContext("workspace_auth"),
                })
            );
            this.setStatus("Realtime monitoring active");
            this.setRiskCoverageText("Signal: connected, waiting for activity");
        };
        socket.onmessage = (event) => {
            if (this.socket !== socket) {
                return;
            }
            const data = JSON.parse(event.data);
            if (data.type === "analysis_result") {
                const effectiveUser = String(data.effectiveUser || "").trim();
                if (effectiveUser && effectiveUser !== String(this.username || "").trim()) {
                    this.setStatus(`Identity mismatch (${effectiveUser}). Reconnecting stream...`);
                    this.setRiskCoverageText("Signal: identity mismatch");
                    if (socket.readyState === WebSocket.OPEN) {
                        socket.close(1000, "identity_mismatch");
                    }
                    return;
                }
                this.riskScore = data.riskScore;
                console.log("[Risk Score]", Number(this.riskScore).toFixed(2));
                document.getElementById("riskScore").textContent = Number(this.riskScore).toFixed(2);
                this.updateRiskCoverage(data.riskExplanation || {});
                
                // Update Status Card based on risk
                if (data.alert || Number(this.riskScore) > 0.45) {
                    this.updateStatusUI(true, { reason: data.alert ? data.alert.message : "High behavioral risk" });
                } else if (Number(this.riskScore) < 0.25) {
                    this.updateStatusUI(false);
                }

                if (data.alert) {
                    this.setStatus(`Risk alert: ${data.alert.message}`);
                }
            } else if (data.type === "error") {
                this.setStatus(data.message || "Realtime error");
                this.setRiskCoverageText("Signal: realtime error");
            } else if (data.type === "session_terminated") {
                alert(data.reason || "Session terminated by security policy.");
                this.logout();
            }
        };
        socket.onerror = () => {
            if (this.socket !== socket) {
                return;
            }
            this.setStatus("Realtime monitoring disconnected");
            this.setRiskCoverageText("Signal: websocket error");
        };
        socket.onclose = (event) => {
            if (this.socket !== socket) {
                return;
            }
            this.socket = null;
            this.setStatus("Realtime monitoring disconnected");
            if (event && event.code === 1008) {
                this.setRiskCoverageText("Signal: websocket auth rejected");
                return;
            }
            this.setRiskCoverageText("Signal: disconnected, reconnecting...");
            if (!this.wsManuallyClosed) {
                this.wsReconnectTimer = setTimeout(() => this.initRealtime(), 1500);
            }
        };

        if (!this.flushTimer) {
            this.flushTimer = setInterval(() => this.flushBehaviorData(), this.behaviorFlushIntervalMs);
        }
    }

    recordKeyDown(event) {
        if (!this.behaviorCollectionEnabled) return;
        this.lastKeyEventTimestamp = performance.now();
        this.keystrokeData.push({
            type: "keydown",
            keyCode: event.keyCode,
            key: event.key,
            timestamp: performance.now(),
            sessionId: this.sessionId,
        });
    }

    recordKeyUp(event) {
        if (!this.behaviorCollectionEnabled) return;
        const timestamp = performance.now();
        this.lastKeyEventTimestamp = timestamp;
        this.keystrokeData.push({
            type: "keyup",
            keyCode: event.keyCode,
            key: event.key,
            timestamp,
            sessionId: this.sessionId,
        });
    }

    recordInputFallback(event) {
        if (!this.behaviorCollectionEnabled) return;
        const target = event && event.target ? event.target : null;
        const isTextInput = target && (
            target.tagName === "INPUT" ||
            target.tagName === "TEXTAREA" ||
            target.isContentEditable
        );
        if (!isTextInput) return;

        const now = performance.now();
        if ((now - this.lastKeyEventTimestamp) < 180) {
            return;
        }
        this.lastKeyEventTimestamp = now;
        this.keystrokeData.push({
            type: "keydown",
            keyCode: 0,
            key: "InputEvent",
            timestamp: now,
            sessionId: this.sessionId,
        });
        this.keystrokeData.push({
            type: "keyup",
            keyCode: 0,
            key: "InputEvent",
            timestamp: now + 12,
            dwellTime: 12,
            sessionId: this.sessionId,
        });
    }

    recordMouseMove(event) {
        if (!this.behaviorCollectionEnabled) return;
        if (this.mouseData.length > 0) {
            const last = this.mouseData[this.mouseData.length - 1];
            if (performance.now() - last.timestamp < 50) {
                return;
            }
        }
        this.mouseData.push({
            type: "mousemove",
            x: event.clientX,
            y: event.clientY,
            timestamp: performance.now(),
            sessionId: this.sessionId,
        });
    }

    recordClick(event) {
        if (!this.behaviorCollectionEnabled) return;
        this.mouseData.push({
            type: "click",
            x: event.clientX,
            y: event.clientY,
            button: event.button,
            timestamp: performance.now(),
            sessionId: this.sessionId,
        });
    }

    flushBehaviorData() {
        if (!this.behaviorCollectionEnabled) return;
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
        if (this.keystrokeData.length === 0 && this.mouseData.length === 0) return;

        this.socket.send(
            JSON.stringify({
                type: "behavioral_data",
                sessionId: this.sessionId,
                keystrokeData: this.keystrokeData,
                mouseData: this.mouseData,
                context: this.buildContext("workspace_monitoring"),
                timestamp: Date.now(),
            })
        );
        this.keystrokeData = [];
        this.mouseData = [];
    }

    async loadProjects() {
        const response = await fetch(`${this.apiBase}/api/projects`, { headers: this.authHeaders() });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to load projects");
            return;
        }
        this.projects = data.projects;
        this.renderProjects();
        if (this.projects.length > 0) {
            this.selectProject(this.projects[0].id);
        } else {
            this.setStatus("Create your first project to get started.");
        }
    }

    renderProjects() {
        const list = document.getElementById("projectList");
        list.innerHTML = "";
        this.projects.forEach((project) => {
            const item = document.createElement("li");
            item.textContent = project.name;
            if (project.id === this.currentProjectId) item.classList.add("active");
            item.addEventListener("click", () => this.selectProject(project.id));
            list.appendChild(item);
        });
    }

    async selectProject(projectId) {
        this.currentProjectId = projectId;
        const project = this.projects.find((p) => p.id === projectId);
        document.getElementById("projectTitle").textContent = project ? project.name : "Project";
        this.renderProjects();
        await this.loadTasks(projectId);
    }

    openProjectModal() {
        document.getElementById("modal").classList.remove("hidden");
    }

    closeProjectModal() {
        document.getElementById("modal").classList.add("hidden");
        document.getElementById("projectNameInput").value = "";
        document.getElementById("projectDescriptionInput").value = "";
    }

    async createProject() {
        const name = document.getElementById("projectNameInput").value.trim();
        const description = document.getElementById("projectDescriptionInput").value.trim();
        if (!name) return;

        const response = await fetch(`${this.apiBase}/api/projects`, {
            method: "POST",
            headers: this.authHeaders(),
            body: JSON.stringify({ name, description }),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to create project");
            return;
        }
        this.closeProjectModal();
        await this.loadProjects();
        this.selectProject(data.project_id);
    }

    async loadTasks(projectId) {
        const response = await fetch(`${this.apiBase}/api/projects/${projectId}/tasks`, {
            headers: this.authHeaders(),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to load tasks");
            return;
        }
        this.tasks = data.tasks;
        this.refreshInsights();
        this.renderBoard();
    }

    refreshInsights() {
        const now = new Date();
        const weekFromNow = new Date(now);
        weekFromNow.setDate(now.getDate() + 7);

        const highPriority = this.tasks.filter((task) => task.priority === "high").length;
        const overdue = this.tasks.filter((task) => {
            if (!task.due_date || task.status === "done") return false;
            return new Date(task.due_date) < now;
        }).length;
        const dueSoon = this.tasks.filter((task) => {
            if (!task.due_date || task.status === "done") return false;
            const dueDate = new Date(task.due_date);
            return dueDate >= now && dueDate <= weekFromNow;
        }).length;

        document.getElementById("totalTasksCount").textContent = this.tasks.length;
        document.getElementById("highPriorityCount").textContent = highPriority;
        document.getElementById("dueSoonCount").textContent = dueSoon;
        document.getElementById("overdueCount").textContent = overdue;
    }

    filteredTasks() {
        const filtered = this.tasks.filter((task) => {
            const matchesPriority =
                this.taskPriorityFilter === "all" || task.priority === this.taskPriorityFilter;
            if (!matchesPriority) return false;
            const matchesStatus =
                this.taskStatusFilter === "all" || task.status === this.taskStatusFilter;
            if (!matchesStatus) return false;

            if (!this.taskSearchQuery) return true;
            const searchableText = `${task.title || ""} ${task.description || ""} ${task.assignee_username || ""}`.toLowerCase();
            return searchableText.includes(this.taskSearchQuery);
        });

        const priorityRank = { high: 3, medium: 2, low: 1 };
        const dateValue = (value) => {
            if (!value) return null;
            const parsed = new Date(value).getTime();
            return Number.isNaN(parsed) ? null : parsed;
        };

        return filtered.sort((a, b) => {
            if (this.taskSortBy === "oldest") return a.id - b.id;
            if (this.taskSortBy === "priority") return (priorityRank[b.priority] || 0) - (priorityRank[a.priority] || 0);
            if (this.taskSortBy === "due_soon") {
                const dueA = dateValue(a.due_date);
                const dueB = dateValue(b.due_date);
                if (dueA === null && dueB === null) return 0;
                if (dueA === null) return 1;
                if (dueB === null) return -1;
                return dueA - dueB;
            }
            return b.id - a.id;
        });
    }

    async createTask() {
        if (!this.currentProjectId) return;
        const title = document.getElementById("taskTitleInput").value.trim();
        if (!title) return;

        const payload = {
            title,
            description: document.getElementById("taskDescriptionInput").value.trim(),
            priority: document.getElementById("taskPriorityInput").value,
            due_date: document.getElementById("taskDueDateInput").value || null,
            assignee_username: document.getElementById("taskAssigneeInput").value.trim() || null,
            status: "todo",
        };
        const response = await fetch(`${this.apiBase}/api/projects/${this.currentProjectId}/tasks`, {
            method: "POST",
            headers: this.authHeaders(),
            body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to create task");
            return;
        }
        this.setStatus(`Task ${data.task_id} created`);
        document.getElementById("taskTitleInput").value = "";
        document.getElementById("taskDescriptionInput").value = "";
        document.getElementById("taskDueDateInput").value = "";
        document.getElementById("taskAssigneeInput").value = "";
        await this.loadTasks(this.currentProjectId);
    }

    async moveTask(taskId, nextStatus) {
        const response = await fetch(`${this.apiBase}/api/tasks/${taskId}`, {
            method: "PATCH",
            headers: this.authHeaders(),
            body: JSON.stringify({ status: nextStatus }),
        });
        const data = await response.json();
        if (!response.ok) {
            this.setStatus(data.detail || "Failed to update task");
            return;
        }
        this.setStatus(`Task ${taskId} moved to ${nextStatus}`);
        await this.loadTasks(this.currentProjectId);
    }

    statusLabel(status) {
        const labels = {
            todo: "To Do",
            in_progress: "In Progress",
            review: "Review",
            done: "Done",
        };
        return labels[status] || status;
    }

    formattedDueDate(value) {
        if (!value) return null;
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return value;
        return date.toLocaleDateString();
    }

    priorityLabel(priority) {
        const labels = {
            low: "Low",
            medium: "Medium",
            high: "High",
        };
        return labels[priority] || priority;
    }

    renderBoard() {
        const columns = {
            todo: document.getElementById("todoColumn"),
            in_progress: document.getElementById("inProgressColumn"),
            review: document.getElementById("reviewColumn"),
            done: document.getElementById("doneColumn"),
        };
        Object.values(columns).forEach((el) => {
            el.innerHTML = "";
        });

        const visibleTasks = this.filteredTasks();
        const counts = { todo: 0, in_progress: 0, review: 0, done: 0 };
        visibleTasks.forEach((task) => {
            const card = document.createElement("div");
            card.className = "task-card";
            card.dataset.priority = task.priority || "medium";
            card.dataset.status = task.status || "todo";

            const title = document.createElement("strong");
            title.textContent = task.title || "Untitled task";
            card.appendChild(title);

            if (task.description) {
                const description = document.createElement("div");
                description.className = "task-description";
                description.textContent = task.description;
                card.appendChild(description);
            }

            const badges = document.createElement("div");
            badges.className = "task-badges";

            const priorityBadge = document.createElement("span");
            priorityBadge.className = `badge badge-${task.priority || "medium"}`;
            priorityBadge.textContent = `${this.priorityLabel(task.priority)} priority`;
            badges.appendChild(priorityBadge);

            if (task.due_date) {
                const dueBadge = document.createElement("span");
                dueBadge.className = "badge badge-neutral";
                dueBadge.textContent = `Due ${this.formattedDueDate(task.due_date)}`;
                badges.appendChild(dueBadge);
            }
            card.appendChild(badges);

            const meta = document.createElement("div");
            meta.className = "meta";
            meta.textContent = task.assignee_username
                ? `Assignee: ${task.assignee_username}`
                : "Unassigned";
            card.appendChild(meta);

            const actions = document.createElement("div");
            actions.className = "actions";
            ["todo", "in_progress", "review", "done"].forEach((status) => {
                if (status === task.status) return;
                const button = document.createElement("button");
                button.className = "secondary-btn";
                button.textContent = this.statusLabel(status);
                button.addEventListener("click", () => this.moveTask(task.id, status));
                actions.appendChild(button);
            });

            const editButton = document.createElement("button");
            editButton.className = "secondary-btn";
            editButton.textContent = "Edit";
            editButton.addEventListener("click", () => this.openEditTaskModal(task));
            actions.appendChild(editButton);

            const duplicateButton = document.createElement("button");
            duplicateButton.className = "secondary-btn";
            duplicateButton.textContent = "Duplicate";
            duplicateButton.addEventListener("click", () => this.duplicateTask(task));
            actions.appendChild(duplicateButton);

            card.appendChild(actions);
            const column = columns[task.status] || columns.todo;
            counts[task.status] = (counts[task.status] || 0) + 1;
            column.appendChild(card);
        });

        Object.entries(columns).forEach(([, el]) => {
            if (!el.hasChildNodes()) {
                const empty = document.createElement("div");
                empty.className = "empty-column";
                empty.textContent = visibleTasks.length
                    ? "No tasks in this stage."
                    : "No tasks match current filters.";
                el.appendChild(empty);
            }
        });

        document.getElementById("todoCount").textContent = counts.todo;
        document.getElementById("inProgressCount").textContent = counts.in_progress;
        document.getElementById("reviewCount").textContent = counts.review;
        document.getElementById("doneCount").textContent = counts.done;
    }
}

document.addEventListener("DOMContentLoaded", () => {
    new WorkspaceApp();
});
