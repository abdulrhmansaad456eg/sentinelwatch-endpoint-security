class SentinelApp {
    constructor() {
        this.apiBase = '';
        this.ws = null;
        this.reconnectInterval = 3000;
        this.currentTab = 'dashboard';
        this.refreshInterval = null;
        this.processes = [];
        this.events = [];
        this.alerts = [];
        this.threatChart = null;
        
        this.init();
    }
    
    init() {
        this.setupNavigation();
        this.setupEventListeners();
        this.connectWebSocket();
        this.threatChart = new ThreatChart('threat-chart', 'threat-legend');
        
        this.loadDashboard();
        this.startAutoRefresh();
    }
    
    setupNavigation() {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const tab = item.dataset.tab;
                this.switchTab(tab);
            });
        });
    }
    
    setupEventListeners() {
        document.getElementById('refresh-btn')?.addEventListener('click', () => {
            this.loadCurrentTab();
            this.showToast('Dashboard refreshed', 'success');
        });
        
        document.getElementById('export-btn')?.addEventListener('click', () => {
            this.exportData();
        });
        
        document.getElementById('view-all-events')?.addEventListener('click', () => {
            this.switchTab('events');
        });
        
        document.getElementById('modal-close')?.addEventListener('click', () => {
            this.closeModal();
        });
        
        document.getElementById('start-training-btn')?.addEventListener('click', () => {
            this.startBaselineTraining();
        });
        
        document.querySelectorAll('.sim-card').forEach(card => {
            const btn = card.querySelector('button');
            const threat = card.dataset.threat;
            btn?.addEventListener('click', () => this.runSimulation(threat));
        });
        
        document.getElementById('process-search')?.addEventListener('input', (e) => {
            this.filterProcesses(e.target.value);
        });
        
        document.getElementById('process-filter')?.addEventListener('change', () => {
            this.loadProcesses();
        });
        
        document.getElementById('refresh-connections')?.addEventListener('click', () => {
            this.loadNetwork();
        });
        
        document.getElementById('event-severity')?.addEventListener('change', () => {
            this.loadEvents();
        });
        
        document.getElementById('event-status')?.addEventListener('change', () => {
            this.loadEvents();
        });
        
        document.getElementById('ack-all-btn')?.addEventListener('click', () => {
            this.acknowledgeAllAlerts();
        });
        
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeModal();
            }
        });
    }
    
    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        try {
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onopen = () => {
                this.updateConnectionStatus(true);
                this.showToast('Real-time connection established', 'success');
            };
            
            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleWebSocketMessage(data);
            };
            
            this.ws.onclose = () => {
                this.updateConnectionStatus(false);
                setTimeout(() => this.connectWebSocket(), this.reconnectInterval);
            };
            
            this.ws.onerror = () => {
                this.updateConnectionStatus(false);
            };
        } catch (e) {
            this.updateConnectionStatus(false);
        }
    }
    
    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'threat_detected':
                this.showToast(`Threat detected: ${data.data.threat_type}`, 'error');
                this.loadDashboard();
                break;
            case 'analysis_complete':
                this.showToast(`Analysis complete - Risk: ${data.data.risk_level}`, 'warning');
                break;
            case 'monitor_alert':
                this.showToast(`Alert: ${data.data.type}`, 'warning');
                break;
            case 'event_resolved':
                this.showToast('Event resolved', 'success');
                break;
        }
    }
    
    updateConnectionStatus(connected) {
        const dot = document.getElementById('ws-status');
        const text = document.getElementById('ws-text');
        
        if (connected) {
            dot?.classList.add('connected');
            if (text) text.textContent = t('connected');
        } else {
            dot?.classList.remove('connected');
            if (text) text.textContent = t('disconnected');
        }
    }
    
    switchTab(tab) {
        this.currentTab = tab;
        
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.tab === tab);
        });
        
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.toggle('active', content.id === tab);
        });
        
        const tabNames = {
            dashboard: 'Dashboard',
            processes: 'Processes',
            network: 'Network',
            events: 'Security Events',
            alerts: 'Alerts',
            baseline: 'Baseline Training',
            simulation: 'Threat Simulation'
        };
        
        const pageTitle = document.getElementById('current-page');
        if (pageTitle && tabNames[tab]) {
            pageTitle.textContent = tabNames[tab];
        }
        
        this.loadCurrentTab();
    }
    
    loadCurrentTab() {
        const loaders = {
            dashboard: () => this.loadDashboard(),
            processes: () => this.loadProcesses(),
            network: () => this.loadNetwork(),
            events: () => this.loadEvents(),
            alerts: () => this.loadAlerts(),
            baseline: () => this.loadBaselineStatus()
        };
        
        if (loaders[this.currentTab]) {
            loaders[this.currentTab]();
        }
    }
    
    async loadDashboard() {
        try {
            const [stats, resources, events, alerts] = await Promise.all([
                this.api('/api/stats'),
                this.api('/api/system/resources'),
                this.api('/api/events?limit=5'),
                this.api('/api/alerts?limit=5&acknowledged=false')
            ]);
            
            this.updateStats(stats);
            this.updateResources(resources);
            this.updateThreatChart(stats);
            this.updateActivity(events);
            this.updateAlertsPreview(alerts);
            this.updateBadges(stats, alerts);
        } catch (e) {
            console.error('Failed to load dashboard:', e);
        }
    }
    
    updateStats(stats) {
        if (!stats?.overview) return;
        
        const threats = document.getElementById('stat-threats');
        const processes = document.getElementById('stat-processes');
        const connections = document.getElementById('stat-connections');
        const risk = document.getElementById('stat-risk');
        
        if (threats) threats.textContent = stats.overview.active_threats || 0;
        if (processes) processes.textContent = stats.overview.monitored_processes || 0;
        if (connections) connections.textContent = stats.overview.network_connections || 0;
        if (risk) risk.textContent = (stats.overview.avg_risk_score || 0).toFixed(1);
        
        const trend = document.getElementById('threat-trend');
        if (trend) {
            const active = stats.overview.active_threats;
            trend.textContent = active === 0 ? 'No active threats' : 
                               active === 1 ? '1 active threat' : 
                               `${active} active threats`;
            trend.style.color = active > 0 ? 'var(--danger)' : 'var(--text-muted)';
        }
    }
    
    updateResources(data) {
        if (!data?.resources) return;
        
        const cpu = data.resources.cpu_percent || 0;
        const mem = data.resources.memory_percent || 0;
        const disk = data.resources.disk_percent || 0;
        
        this.updateResourceBar('cpu', cpu);
        this.updateResourceBar('mem', mem);
        this.updateResourceBar('disk', disk);
    }
    
    updateResourceBar(type, value) {
        const bar = document.getElementById(`${type}-bar`);
        const label = document.getElementById(`${type}-value`);
        
        if (bar) {
            bar.style.width = `${Math.min(value, 100)}%`;
            if (value > 80) bar.classList.add('high');
            else bar.classList.remove('high');
        }
        
        if (label) label.textContent = `${Math.round(value)}%`;
    }
    
    updateThreatChart(stats) {
        if (stats?.severity_distribution) {
            this.threatChart.updateData(stats.severity_distribution);
        }
    }
    
    updateActivity(data) {
        const container = document.getElementById('activity-list');
        if (!container || !data?.events) return;
        
        if (data.events.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                    <p>${t('no_activity')}</p>
                </div>`;
            return;
        }
        
        container.innerHTML = data.events.map(event => {
            const severity = event.severity;
            const iconClass = severity === 'critical' || severity === 'high' ? 'critical' : 
                             severity === 'medium' ? 'warning' : 'info';
            
            return `
                <div class="activity-item" onclick="app.showEventDetails(${event.id})">
                    <div class="activity-icon ${iconClass}">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                        </svg>
                    </div>
                    <div class="activity-content">
                        <div class="activity-title">${event.type}</div>
                        <div class="activity-desc">${event.description}</div>
                    </div>
                    <div class="activity-time">${event.timestamp}</div>
                </div>
            `;
        }).join('');
    }
    
    updateAlertsPreview(data) {
        const container = document.getElementById('alerts-list');
        if (!container || !data?.alerts) return;
        
        if (data.alerts.length === 0) {
            container.innerHTML = `<div class="empty-state"><p>${t('no_alerts')}</p></div>`;
            return;
        }
        
        container.innerHTML = data.alerts.map(alert => `
            <div class="activity-item">
                <div class="activity-icon ${alert.severity === 'critical' ? 'critical' : 'warning'}">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
                    </svg>
                </div>
                <div class="activity-content">
                    <div class="activity-title">${alert.title}</div>
                    <div class="activity-desc">${alert.message}</div>
                </div>
            </div>
        `).join('');
    }
    
    updateBadges(stats, alerts) {
        const eventBadge = document.getElementById('event-badge');
        const alertBadge = document.getElementById('alert-badge');
        
        if (eventBadge) {
            const count = stats?.overview?.active_threats || 0;
            eventBadge.textContent = count;
            eventBadge.style.display = count > 0 ? 'flex' : 'none';
        }
        
        if (alertBadge) {
            const count = alerts?.unacknowledged_count || 0;
            alertBadge.textContent = count;
            alertBadge.style.display = count > 0 ? 'flex' : 'none';
        }
    }
    
    async loadProcesses() {
        try {
            const data = await this.api('/api/processes');
            this.processes = data.processes || [];
            this.renderProcesses();
        } catch (e) {
            console.error('Failed to load processes:', e);
        }
    }
    
    renderProcesses() {
        const tbody = document.getElementById('processes-tbody');
        if (!tbody) return;
        
        const filter = document.getElementById('process-filter')?.value || 'all';
        const search = document.getElementById('process-search')?.value.toLowerCase() || '';
        
        let filtered = this.processes;
        
        if (filter === 'anomaly') {
            filtered = filtered.filter(p => p.is_anomaly);
        } else if (filter === 'high-cpu') {
            filtered = filtered.filter(p => p.cpu_percent > 50);
        } else if (filter === 'network') {
            filtered = filtered.filter(p => p.connections > 0);
        }
        
        if (search) {
            filtered = filtered.filter(p => 
                p.name.toLowerCase().includes(search) || 
                p.pid.toString().includes(search)
            );
        }
        
        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No processes found</td></tr>`;
            return;
        }
        
        tbody.innerHTML = filtered.map(proc => `
            <tr>
                <td>${proc.pid}</td>
                <td>${proc.name}</td>
                <td>${proc.username}</td>
                <td>${proc.cpu_percent.toFixed(1)}%</td>
                <td>${proc.memory_mb.toFixed(1)} MB</td>
                <td>${proc.connections}</td>
                <td><span class="risk-indicator risk-${proc.is_anomaly ? 'high' : 'low'}">${proc.status}</span></td>
                <td>
                    ${proc.is_anomaly ? 
                        `<span class="risk-indicator risk-high">High (${proc.anomaly_confidence.toFixed(2)})</span>` :
                        `<span class="risk-indicator risk-low">Low</span>`
                    }
                </td>
            </tr>
        `).join('');
    }
    
    filterProcesses(query) {
        this.renderProcesses();
    }
    
    async loadNetwork() {
        try {
            const data = await this.api('/api/network');
            this.renderNetwork(data.connections || []);
        } catch (e) {
            console.error('Failed to load network:', e);
        }
    }
    
    renderNetwork(connections) {
        const tbody = document.getElementById('network-tbody');
        if (!tbody) return;
        
        if (connections.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No active connections</td></tr>`;
            return;
        }
        
        tbody.innerHTML = connections.map(conn => `
            <tr>
                <td>${conn.local}</td>
                <td>
                    ${conn.suspicious ? '<span style="color: var(--danger)">⚠</span> ' : ''}
                    ${conn.remote}
                </td>
                <td>${conn.protocol}</td>
                <td>${conn.process}</td>
                <td>${conn.status}</td>
            </tr>
        `).join('');
    }
    
    async loadEvents() {
        try {
            const severity = document.getElementById('event-severity')?.value;
            const status = document.getElementById('event-status')?.value;
            
            let url = '/api/events?limit=50';
            if (severity && severity !== 'all') url += `&severity=${severity}`;
            if (status && status !== 'all') url += `&resolved=${status === 'resolved'}`;
            
            const data = await this.api(url);
            this.renderEvents(data.events || []);
        } catch (e) {
            console.error('Failed to load events:', e);
        }
    }
    
    renderEvents(events) {
        const container = document.getElementById('events-list');
        if (!container) return;
        
        if (events.length === 0) {
            container.innerHTML = `<div class="empty-state"><p>${t('no_events')}</p></div>`;
            return;
        }
        
        container.innerHTML = events.map(event => `
            <div class="event-card" onclick="app.showEventDetails(${event.id})">
                <div class="event-severity ${event.severity}"></div>
                <div class="event-content">
                    <div class="event-header">
                        <span class="event-type">${event.type}</span>
                        <span class="event-severity-badge ${event.severity}">${event.severity}</span>
                    </div>
                    <div class="event-desc">${event.description}</div>
                    <div class="event-meta">
                        <span>${event.process || 'Unknown'}</span>
                        <span>${event.timestamp}</span>
                        <span>PID: ${event.pid || 'N/A'}</span>
                    </div>
                </div>
                <div class="event-score">
                    <div class="score-value">${event.risk_score.toFixed(0)}</div>
                    <div class="score-label">Risk</div>
                </div>
            </div>
        `).join('');
    }
    
    async loadAlerts() {
        try {
            const data = await this.api('/api/alerts');
            this.renderAlerts(data.alerts || []);
        } catch (e) {
            console.error('Failed to load alerts:', e);
        }
    }
    
    renderAlerts(alerts) {
        const container = document.getElementById('alerts-full-list');
        if (!container) return;
        
        if (alerts.length === 0) {
            container.innerHTML = `<div class="empty-state"><p>${t('no_alerts')}</p></div>`;
            return;
        }
        
        container.innerHTML = alerts.map(alert => `
            <div class="event-card ${alert.acknowledged ? 'acknowledged' : ''}">
                <div class="event-severity ${alert.severity}"></div>
                <div class="event-content">
                    <div class="event-header">
                        <span class="event-type">${alert.title}</span>
                        <span class="event-severity-badge ${alert.severity}">${alert.severity}</span>
                    </div>
                    <div class="event-desc">${alert.message}</div>
                    <div class="event-meta">
                        <span>ID: ${alert.incident_id}</span>
                        <span>${alert.created_at}</span>
                    </div>
                </div>
                ${!alert.acknowledged ? `
                    <button class="btn btn-sm btn-secondary" onclick="app.acknowledgeAlert(${alert.id}, event)">
                        Acknowledge
                    </button>
                ` : '<span style="color: var(--text-muted); font-size: 0.8rem;">Acknowledged</span>'}
            </div>
        `).join('');
    }
    
    async acknowledgeAlert(alertId, event) {
        event.stopPropagation();
        
        try {
            await this.api(`/api/alerts/${alertId}/acknowledge`, 'POST');
            this.showToast('Alert acknowledged', 'success');
            this.loadAlerts();
            this.loadDashboard();
        } catch (e) {
            this.showToast('Failed to acknowledge alert', 'error');
        }
    }
    
    async acknowledgeAllAlerts() {
        try {
            const data = await this.api('/api/alerts?acknowledged=false');
            const alerts = data.alerts || [];
            
            for (const alert of alerts) {
                await this.api(`/api/alerts/${alert.id}/acknowledge`, 'POST');
            }
            
            this.showToast(`Acknowledged ${alerts.length} alerts`, 'success');
            this.loadAlerts();
            this.loadDashboard();
        } catch (e) {
            this.showToast('Failed to acknowledge alerts', 'error');
        }
    }
    
    async loadBaselineStatus() {
        try {
            const data = await this.api('/api/baseline/status');
            this.updateBaselineUI(data);
        } catch (e) {
            console.error('Failed to load baseline status:', e);
        }
    }
    
    updateBaselineUI(data) {
        const icon = document.getElementById('baseline-icon');
        const text = document.getElementById('baseline-status-text');
        const desc = document.getElementById('baseline-desc');
        
        if (data.model_trained) {
            icon?.classList.add('trained');
            if (text) text.textContent = 'Baseline Trained';
            if (desc) desc.textContent = 'The system has learned normal behavior patterns and is ready to detect anomalies.';
        } else {
            icon?.classList.remove('trained');
        }
    }
    
    async startBaselineTraining() {
        const duration = document.getElementById('train-duration')?.value || 60;
        const progressDiv = document.getElementById('training-progress');
        const controls = document.querySelector('.baseline-controls');
        
        try {
            controls?.classList.add('hidden');
            progressDiv?.classList.remove('hidden');
            
            document.getElementById('baseline-icon')?.classList.add('training');
            document.getElementById('baseline-status-text').textContent = 'Training in Progress...';
            
            let progress = 0;
            const interval = setInterval(() => {
                progress += 100 / (duration / 5);
                if (progress > 100) progress = 100;
                
                const fill = document.getElementById('train-progress-fill');
                const text = document.getElementById('train-progress-text');
                if (fill) fill.style.width = `${progress}%`;
                if (text) text.textContent = `${Math.round(progress)}%`;
            }, 5000);
            
            await this.api(`/api/baseline/train?duration=${duration}`, 'POST');
            
            clearInterval(interval);
            
            document.getElementById('baseline-icon')?.classList.remove('training');
            this.showToast('Baseline training completed', 'success');
            this.loadBaselineStatus();
        } catch (e) {
            this.showToast('Training failed', 'error');
            controls?.classList.remove('hidden');
        }
    }
    
    async runSimulation(threatType) {
        try {
            this.showToast('Running simulation...', 'info');
            const data = await this.api(`/api/simulate/${threatType}`, 'POST');
            this.showToast(`Simulation complete: ${data.simulation.threat_category}`, 'success');
            this.loadDashboard();
        } catch (e) {
            this.showToast('Simulation failed', 'error');
        }
    }
    
    async showEventDetails(eventId) {
        try {
            const data = await this.api(`/api/events/${eventId}`);
            const event = data.event;
            
            const modal = document.getElementById('event-modal');
            const title = document.getElementById('modal-title');
            const body = document.getElementById('modal-body');
            const footer = document.getElementById('modal-footer');
            
            title.textContent = `Event #${event.id} - ${event.type}`;
            
            body.innerHTML = `
                <div style="margin-bottom: 16px;">
                    <strong>Severity:</strong> 
                    <span class="risk-indicator risk-${event.severity}">${event.severity}</span>
                </div>
                <div style="margin-bottom: 16px;">
                    <strong>Risk Score:</strong> ${event.risk_score.toFixed(1)}
                </div>
                <div style="margin-bottom: 16px;">
                    <strong>Timestamp:</strong> ${event.timestamp}
                </div>
                <div style="margin-bottom: 16px;">
                    <strong>Process:</strong> ${event.process_name} (PID: ${event.pid})
                </div>
                <div style="margin-bottom: 16px;">
                    <strong>Description:</strong><br>${event.description}
                </div>
                ${event.command_line ? `
                    <div style="margin-bottom: 16px;">
                        <strong>Command Line:</strong>
                        <pre style="background: var(--bg-tertiary); padding: 12px; border-radius: 4px; overflow-x: auto;">${event.command_line}</pre>
                    </div>
                ` : ''}
                ${event.network_dst ? `
                    <div style="margin-bottom: 16px;">
                        <strong>Network Destination:</strong> ${event.network_dst}
                    </div>
                ` : ''}
                ${event.file_path ? `
                    <div style="margin-bottom: 16px;">
                        <strong>File Path:</strong> ${event.file_path}
                    </div>
                ` : ''}
            `;
            
            footer.innerHTML = event.resolved ? 
                '<span style="color: var(--success)">✓ Resolved</span>' :
                `<button class="btn btn-primary" onclick="app.resolveEvent(${eventId})">Mark as Resolved</button>`;
            
            modal?.classList.add('active');
        } catch (e) {
            this.showToast('Failed to load event details', 'error');
        }
    }
    
    async resolveEvent(eventId) {
        try {
            await this.api(`/api/events/${eventId}/resolve`, 'POST');
            this.showToast('Event resolved', 'success');
            this.closeModal();
            this.loadEvents();
            this.loadDashboard();
        } catch (e) {
            this.showToast('Failed to resolve event', 'error');
        }
    }
    
    closeModal() {
        document.getElementById('event-modal')?.classList.remove('active');
    }
    
    async exportData() {
        try {
            const [events, alerts, stats] = await Promise.all([
                this.api('/api/events?limit=1000'),
                this.api('/api/alerts?limit=1000'),
                this.api('/api/stats')
            ]);
            
            const exportData = {
                export_date: new Date().toISOString(),
                system_stats: stats,
                events: events.events,
                alerts: alerts.alerts
            };
            
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `sentinelwatch_export_${Date.now()}.json`;
            a.click();
            URL.revokeObjectURL(url);
            
            this.showToast('Data exported successfully', 'success');
        } catch (e) {
            this.showToast('Export failed', 'error');
        }
    }
    
    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }
    
    async api(endpoint, method = 'GET', body = null) {
        const options = {
            method,
            headers: { 'Content-Type': 'application/json' }
        };
        
        if (body) {
            options.body = JSON.stringify(body);
        }
        
        const response = await fetch(`${this.apiBase}${endpoint}`, options);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        return response.json();
    }
    
    startAutoRefresh() {
        this.refreshInterval = setInterval(() => {
            if (this.currentTab === 'dashboard') {
                this.loadDashboard();
            }
        }, 10000);
    }
}

let app;

document.addEventListener('DOMContentLoaded', () => {
    app = new SentinelApp();
});
