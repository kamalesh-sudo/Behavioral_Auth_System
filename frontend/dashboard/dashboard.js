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
        this.taskSearchQuery = "";
        this.taskPriorityFilter = "all";
        this.taskStatusFilter = "all";

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
        document.getElementById("clearTaskFiltersBtn").addEventListener("click", () => this.resetTaskFilters());
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
    }

    setStatus(message) {
        document.getElementById("statusBar").textContent = message;
    }

    resetTaskFilters() {
        this.taskSearchQuery = "";
        this.taskPriorityFilter = "all";
        this.taskStatusFilter = "all";
        document.getElementById("taskSearchInput").value = "";
        document.getElementById("taskPriorityFilter").value = "all";
        document.getElementById("taskStatusFilter").value = "all";
        this.renderBoard();
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
        return this.tasks.filter((task) => {
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
            card.appendChild(actions);
            const column = columns[task.status] || columns.todo;
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
    }
}

document.addEventListener("DOMContentLoaded", () => {
    new WorkspaceApp();
});
