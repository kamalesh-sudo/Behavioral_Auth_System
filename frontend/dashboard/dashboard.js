class WorkspaceApp {
    constructor() {
        this.apiBase = window.location.origin;
        this.token = localStorage.getItem("auth_token");
        this.username = localStorage.getItem("username");
        this.userId = localStorage.getItem("user_id");
        this.sessionId = localStorage.getItem("session_id") || `session_${Date.now()}`;
        this.projects = [];
        this.tasks = [];
        this.currentProjectId = null;
        this.socket = null;
        this.keystrokeData = [];
        this.mouseData = [];
        this.riskScore = 0;
        this.flushTimer = null;

        if (!this.token || !this.username) {
            window.location.href = "../login/login.html";
            return;
        }

        document.getElementById("usernameText").textContent = this.username;
        this.bindUI();
        this.initRealtime();
        this.loadProjects();
    }

    bindUI() {
        document.getElementById("newProjectBtn").addEventListener("click", () => this.openProjectModal());
        document.getElementById("cancelProjectBtn").addEventListener("click", () => this.closeProjectModal());
        document.getElementById("saveProjectBtn").addEventListener("click", () => this.createProject());
        document.getElementById("createTaskBtn").addEventListener("click", () => this.createTask());

        document.addEventListener("keydown", (e) => this.recordKeyDown(e));
        document.addEventListener("keyup", (e) => this.recordKeyUp(e));
        document.addEventListener("mousemove", (e) => this.recordMouseMove(e));
        document.addEventListener("click", (e) => this.recordClick(e));
    }

    setStatus(message) {
        document.getElementById("statusBar").textContent = message;
    }

    authHeaders() {
        return {
            "Content-Type": "application/json",
            Authorization: `Bearer ${this.token}`,
        };
    }

    wsUrl() {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        return `${protocol}//${window.location.host}/ws/behavioral`;
    }

    initRealtime() {
        this.socket = new WebSocket(this.wsUrl());
        this.socket.onopen = () => {
            this.socket.send(JSON.stringify({ token: this.token }));
            this.socket.send(
                JSON.stringify({ type: "user_authentication", userId: this.username, sessionId: this.sessionId })
            );
            this.setStatus("Realtime monitoring active");
        };
        this.socket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.type === "analysis_result") {
                this.riskScore = data.riskScore;
                document.getElementById("riskScore").textContent = Number(this.riskScore).toFixed(2);
                if (data.alert) {
                    this.setStatus(`Risk alert: ${data.alert.message}`);
                }
            } else if (data.type === "session_terminated") {
                alert(data.reason || "Session terminated by security policy.");
                window.location.href = "../login/login.html";
            }
        };
        this.socket.onerror = () => {
            this.setStatus("Realtime monitoring disconnected");
        };

        this.flushTimer = setInterval(() => this.flushBehaviorData(), 2000);
    }

    recordKeyDown(event) {
        this.keystrokeData.push({
            type: "keydown",
            keyCode: event.keyCode,
            key: event.key,
            timestamp: performance.now(),
            sessionId: this.sessionId,
        });
    }

    recordKeyUp(event) {
        const timestamp = performance.now();
        this.keystrokeData.push({
            type: "keyup",
            keyCode: event.keyCode,
            key: event.key,
            timestamp,
            sessionId: this.sessionId,
        });
    }

    recordMouseMove(event) {
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
        if (!this.socket || this.socket.readyState !== WebSocket.OPEN) return;
        if (this.keystrokeData.length === 0 && this.mouseData.length === 0) return;

        this.socket.send(
            JSON.stringify({
                type: "behavioral_data",
                userId: this.username,
                sessionId: this.sessionId,
                keystrokeData: this.keystrokeData,
                mouseData: this.mouseData,
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
        this.renderBoard();
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

        this.tasks.forEach((task) => {
            const card = document.createElement("div");
            card.className = "task-card";
            card.innerHTML = `
                <strong>${task.title}</strong>
                <div>${task.description || ""}</div>
                <div class="meta">Priority: ${task.priority} ${task.assignee_username ? `| Assignee: ${task.assignee_username}` : ""}</div>
            `;

            const actions = document.createElement("div");
            actions.className = "actions";
            ["todo", "in_progress", "review", "done"].forEach((status) => {
                if (status === task.status) return;
                const button = document.createElement("button");
                button.className = "secondary-btn";
                button.textContent = status.replace("_", " ");
                button.addEventListener("click", () => this.moveTask(task.id, status));
                actions.appendChild(button);
            });
            card.appendChild(actions);
            columns[task.status].appendChild(card);
        });
    }
}

document.addEventListener("DOMContentLoaded", () => {
    new WorkspaceApp();
});
