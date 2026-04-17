class ThreatChart {
    constructor(canvasId, legendId) {
        this.canvas = document.getElementById(canvasId);
        this.legendId = legendId;
        this.ctx = this.canvas?.getContext('2d');
        this.data = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        this.colors = {
            critical: '#ef4444',
            high: '#f59e0b',
            medium: '#06b6d4',
            low: '#10b981',
            info: '#3b82f6'
        };
        this.animationProgress = 0;
        
        if (this.canvas) {
            this.resize();
            window.addEventListener('resize', () => this.resize());
        }
    }
    
    resize() {
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.canvas.width = rect.width;
        this.canvas.height = 280;
        this.draw();
    }
    
    updateData(data) {
        this.data = { ...this.data, ...data };
        this.animationProgress = 0;
        this.animate();
        this.updateLegend();
    }
    
    animate() {
        if (this.animationProgress < 1) {
            this.animationProgress += 0.05;
            this.draw();
            requestAnimationFrame(() => this.animate());
        } else {
            this.draw();
        }
    }
    
    draw() {
        if (!this.ctx) return;
        
        const ctx = this.ctx;
        const width = this.canvas.width;
        const height = this.canvas.height;
        const centerX = width / 2;
        const centerY = height / 2;
        const radius = Math.min(width, height) / 3;
        
        ctx.clearRect(0, 0, width, height);
        
        const total = Object.values(this.data).reduce((a, b) => a + b, 0);
        if (total === 0) {
            this.drawEmptyState(ctx, centerX, centerY);
            return;
        }
        
        let currentAngle = -Math.PI / 2;
        
        Object.entries(this.data).forEach(([key, value]) => {
            if (value > 0) {
                const sliceAngle = (value / total) * 2 * Math.PI * this.animationProgress;
                
                ctx.beginPath();
                ctx.moveTo(centerX, centerY);
                ctx.arc(centerX, centerY, radius, currentAngle, currentAngle + sliceAngle);
                ctx.closePath();
                
                ctx.fillStyle = this.colors[key];
                ctx.fill();
                
                ctx.strokeStyle = '#11121a';
                ctx.lineWidth = 2;
                ctx.stroke();
                
                currentAngle += sliceAngle;
            }
        });
        
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius * 0.6, 0, 2 * Math.PI);
        ctx.fillStyle = '#11121a';
        ctx.fill();
        
        ctx.fillStyle = '#e8e9ed';
        ctx.font = 'bold 24px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(total.toString(), centerX, centerY - 5);
        
        ctx.font = '12px Inter';
        ctx.fillStyle = '#8b8fa8';
        ctx.fillText('Events', centerX, centerY + 15);
    }
    
    drawEmptyState(ctx, centerX, centerY) {
        ctx.beginPath();
        ctx.arc(centerX, centerY, 80, 0, 2 * Math.PI);
        ctx.strokeStyle = '#2a2d3e';
        ctx.lineWidth = 2;
        ctx.stroke();
        
        ctx.fillStyle = '#5a5f7a';
        ctx.font = '14px Inter';
        ctx.textAlign = 'center';
        ctx.fillText('No Data', centerX, centerY);
    }
    
    updateLegend() {
        const container = document.getElementById(this.legendId);
        if (!container) return;
        
        const total = Object.values(this.data).reduce((a, b) => a + b, 0);
        
        container.innerHTML = Object.entries(this.data)
            .filter(([_, v]) => v > 0)
            .map(([key, value]) => `
                <div class="legend-item">
                    <span class="legend-dot" style="background: ${this.colors[key]}"></span>
                    <span>${key.charAt(0).toUpperCase() + key.slice(1)}: ${value}</span>
                </div>
            `).join('');
    }
}

class ResourceChart {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        this.ctx = this.canvas?.getContext('2d');
        this.history = [];
        this.maxPoints = 60;
        
        if (this.canvas) {
            this.resize();
            window.addEventListener('resize', () => this.resize());
        }
    }
    
    resize() {
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.canvas.width = rect.width;
        this.canvas.height = 200;
    }
    
    addPoint(cpu, memory) {
        this.history.push({ cpu, memory, time: Date.now() });
        
        if (this.history.length > this.maxPoints) {
            this.history.shift();
        }
        
        this.draw();
    }
    
    draw() {
        if (!this.ctx || this.history.length < 2) return;
        
        const ctx = this.ctx;
        const width = this.canvas.width;
        const height = this.canvas.height;
        
        ctx.clearRect(0, 0, width, height);
        
        this.drawGrid(ctx, width, height);
        
        this.drawLine(ctx, width, height, 'cpu', '#3b82f6');
        this.drawLine(ctx, width, height, 'memory', '#10b981');
    }
    
    drawGrid(ctx, width, height) {
        ctx.strokeStyle = '#2a2d3e';
        ctx.lineWidth = 1;
        
        for (let i = 0; i <= 4; i++) {
            const y = (height / 4) * i;
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(width, y);
            ctx.stroke();
        }
    }
    
    drawLine(ctx, width, height, key, color) {
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.beginPath();
        
        this.history.forEach((point, index) => {
            const x = (index / (this.maxPoints - 1)) * width;
            const y = height - (point[key] / 100) * height;
            
            if (index === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        });
        
        ctx.stroke();
    }
}
