from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import asyncio
import json
import os
import uuid

from database import init_db, get_db, SecurityEvent, Alert, SystemStats, ProcessBaseline
from monitor import SystemMonitor
from analyzer import BehaviorAnalyzer
from risk_engine import RiskScoringEngine, RiskLevel
from utils import (
    generate_incident_id, format_timestamp, sanitize_command_line,
    risk_level_to_color, calculate_uptime, generate_response_recommendation
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = FastAPI(title="SentinelWatch", version="1.0.0")

monitor = SystemMonitor()
analyzer = BehaviorAnalyzer()
risk_engine = RiskScoringEngine()
active_connections: List[WebSocket] = []
app_start_time = datetime.utcnow()

@app.on_event("startup")
async def startup_event():
    init_db()
    monitor.start_monitoring(interval=2.0)

@app.on_event("shutdown")
async def shutdown_event():
    monitor.stop_monitoring()

async def broadcast_message(message: Dict[str, Any]):
    disconnected = []
    for connection in active_connections:
        try:
            await connection.send_json(message)
        except:
            disconnected.append(connection)
    
    for conn in disconnected:
        if conn in active_connections:
            active_connections.remove(conn)

def handle_monitor_alert(alert_data: Dict):
    asyncio.create_task(broadcast_message({
        "type": "monitor_alert",
        "data": alert_data,
        "timestamp": datetime.utcnow().isoformat()
    }))

monitor.alert_callback = handle_monitor_alert

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return HTMLResponse(content="<h1>SentinelWatch Dashboard Not Found</h1>", status_code=404)

@app.get("/api/status")
async def get_status():
    return {
        "status": "operational",
        "version": "1.0.0",
        "uptime": calculate_uptime(app_start_time),
        "monitoring_active": monitor.monitoring,
        "baseline_trained": analyzer.is_trained,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/system/resources")
async def get_system_resources():
    resources = monitor.get_system_resources()
    processes = monitor.get_active_processes()
    connections = monitor.get_network_connections()
    
    return {
        "resources": resources,
        "process_count": len(processes),
        "connection_count": len(connections),
        "monitored_since": app_start_time.isoformat()
    }

@app.get("/api/processes")
async def get_processes(limit: int = 50):
    processes = monitor.get_active_processes()
    process_list = []
    
    for proc in sorted(processes, key=lambda x: x.cpu_percent, reverse=True)[:limit]:
        is_anomaly, confidence, details = analyzer.analyze_process({
            "cpu_percent": proc.cpu_percent,
            "memory_mb": proc.memory_mb,
            "connection_count": proc.connections,
            "thread_count": proc.threads
        })
        
        process_list.append({
            "pid": proc.pid,
            "name": proc.name,
            "cpu_percent": round(proc.cpu_percent, 2),
            "memory_mb": round(proc.memory_mb, 2),
            "connections": proc.connections,
            "threads": proc.threads,
            "username": proc.username,
            "status": proc.status,
            "is_anomaly": is_anomaly,
            "anomaly_confidence": round(confidence, 3)
        })
    
    return {"processes": process_list, "total_count": len(processes)}

@app.get("/api/network")
async def get_network_connections():
    connections = monitor.get_network_connections()
    
    conn_list = []
    for conn in connections:
        suspicious = False
        if conn.remote_addr:
            try:
                port = int(conn.remote_addr.split(":")[-1])
                if port in risk_engine.SUSPICIOUS_PORTS:
                    suspicious = True
            except:
                pass
        
        conn_list.append({
            "local": conn.local_addr,
            "remote": conn.remote_addr,
            "status": conn.status,
            "pid": conn.pid,
            "process": conn.process_name,
            "protocol": conn.protocol,
            "suspicious": suspicious
        })
    
    return {"connections": conn_list, "count": len(conn_list)}

@app.get("/api/events")
async def get_events(
    db: Session = Depends(get_db),
    limit: int = 100,
    severity: Optional[str] = None,
    resolved: Optional[bool] = None
):
    query = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc())
    
    if severity:
        query = query.filter(SecurityEvent.severity == severity.lower())
    if resolved is not None:
        query = query.filter(SecurityEvent.resolved == resolved)
    
    events = query.limit(limit).all()
    
    return {
        "events": [
            {
                "id": e.id,
                "timestamp": format_timestamp(e.timestamp),
                "type": e.event_type,
                "severity": e.severity,
                "risk_score": e.risk_score,
                "source": e.source,
                "description": e.description,
                "process": e.process_name,
                "pid": e.pid,
                "resolved": e.resolved
            }
            for e in events
        ],
        "count": len(events)
    }

@app.post("/api/analyze")
async def analyze_process(process_data: Dict[str, Any], db: Session = Depends(get_db)):
    is_anomaly, confidence, details = analyzer.analyze_process(process_data)
    
    risk_score, risk_level, reasons = risk_engine.calculate_risk_score(process_data)
    threat_category = analyzer.classify_threat_category(process_data, details)
    
    response_action = risk_engine.get_recommended_action(risk_level, reasons)
    recommendations = generate_response_recommendation(risk_level.value.name, threat_category)
    
    event = SecurityEvent(
        event_type=process_data.get("event_type", "process_analysis"),
        severity=risk_level.value.name.lower(),
        risk_score=risk_score,
        source="sentinel_analyzer",
        description=f"Process analysis: {process_data.get('process_name', 'unknown')} - {threat_category}",
        process_name=process_data.get("process_name", "unknown"),
        pid=process_data.get("pid", 0),
        command_line=sanitize_command_line(process_data.get("command_line", "")),
        network_dst=process_data.get("network_dst"),
        file_path=process_data.get("file_path"),
        response_action=response_action
    )
    
    db.add(event)
    db.commit()
    
    await broadcast_message({
        "type": "analysis_complete",
        "data": {
            "event_id": event.id,
            "risk_score": risk_score,
            "risk_level": risk_level.value.name,
            "threat_category": threat_category,
            "is_anomaly": is_anomaly,
            "recommendations": recommendations
        }
    })
    
    return {
        "analysis": {
            "is_anomaly": is_anomaly,
            "confidence": confidence,
            "details": details,
            "risk_score": risk_score,
            "risk_level": risk_level.value.name,
            "threat_category": threat_category,
            "reasons": reasons,
            "recommended_action": response_action,
            "response_recommendations": recommendations
        },
        "event_id": event.id
    }

@app.post("/api/simulate/{threat_type}")
async def simulate_threat(threat_type: str, db: Session = Depends(get_db)):
    valid_types = ["ransomware_sim", "backdoor_sim", "trojan_sim"]
    
    if threat_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid threat type. Valid: {valid_types}")
    
    simulated_data = monitor.simulate_threat_event(threat_type)
    simulated_data["timestamp"] = datetime.utcnow()
    
    is_anomaly, confidence, details = analyzer.analyze_process(simulated_data)
    risk_score, risk_level, reasons = risk_engine.calculate_risk_score(simulated_data)
    threat_category = analyzer.classify_threat_category(simulated_data, details)
    
    incident_id = generate_incident_id()
    
    event = SecurityEvent(
        event_type=simulated_data.get("event_type", "simulated_threat"),
        severity=risk_level.value.name.lower(),
        risk_score=risk_score,
        source="simulation_engine",
        description=f"[SIMULATION] {threat_type} detected on {simulated_data.get('process_name')}",
        process_name=simulated_data.get("process_name"),
        pid=simulated_data.get("pid", 0),
        command_line=sanitize_command_line(simulated_data.get("command_line", "")),
        network_dst=simulated_data.get("network_dst"),
        file_path=simulated_data.get("file_path")
    )
    
    db.add(event)
    db.commit()
    
    alert = Alert(
        title=f"[SIMULATION] {threat_type.replace('_', ' ').upper()}",
        message=f"Simulated threat detected: {threat_category}. Risk score: {risk_score:.1f}",
        severity=risk_level.value.name.lower(),
        category="simulation",
        incident_id=incident_id
    )
    
    db.add(alert)
    db.commit()
    
    await broadcast_message({
        "type": "threat_detected",
        "data": {
            "threat_type": threat_type,
            "incident_id": incident_id,
            "risk_score": risk_score,
            "risk_level": risk_level.value.name,
            "category": threat_category,
            "timestamp": datetime.utcnow().isoformat()
        }
    })
    
    return {
        "simulation": {
            "threat_type": threat_type,
            "incident_id": incident_id,
            "event_id": event.id,
            "risk_score": risk_score,
            "risk_level": risk_level.value.name,
            "threat_category": threat_category,
            "details": simulated_data
        }
    }

@app.get("/api/alerts")
async def get_alerts(
    db: Session = Depends(get_db),
    acknowledged: Optional[bool] = None,
    limit: int = 50
):
    query = db.query(Alert).order_by(Alert.created_at.desc())
    
    if acknowledged is not None:
        query = query.filter(Alert.acknowledged == acknowledged)
    
    alerts = query.limit(limit).all()
    
    return {
        "alerts": [
            {
                "id": a.id,
                "created_at": format_timestamp(a.created_at),
                "title": a.title,
                "message": a.message,
                "severity": a.severity,
                "category": a.category,
                "acknowledged": a.acknowledged,
                "incident_id": a.incident_id
            }
            for a in alerts
        ],
        "unacknowledged_count": sum(1 for a in alerts if not a.acknowledged)
    }

@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.acknowledged = True
    db.commit()
    
    return {"status": "acknowledged", "alert_id": alert_id}

@app.post("/api/baseline/train")
async def train_baseline(duration: int = 60, background_tasks: BackgroundTasks = None):
    def train_task():
        baseline_data = monitor.collect_baseline_data(duration)
        success = analyzer.train_baseline(baseline_data)
        return {"success": success, "samples_collected": len(baseline_data)}
    
    if background_tasks:
        background_tasks.add_task(train_task)
        return {"status": "training_started", "duration_seconds": duration}
    
    result = train_task()
    return result

@app.get("/api/baseline/status")
async def get_baseline_status():
    return analyzer.generate_baseline_report()

@app.get("/api/stats")
async def get_stats(db: Session = Depends(get_db)):
    total_events = db.query(SecurityEvent).count()
    active_threats = db.query(SecurityEvent).filter(
        SecurityEvent.resolved == False,
        SecurityEvent.severity.in_(["high", "critical"])
    ).count()
    resolved = db.query(SecurityEvent).filter(SecurityEvent.resolved == True).count()
    unack_alerts = db.query(Alert).filter(Alert.acknowledged == False).count()
    
    processes = monitor.get_active_processes()
    connections = monitor.get_network_connections()
    
    severity_counts = {}
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = db.query(SecurityEvent).filter(SecurityEvent.severity == sev).count()
        severity_counts[sev] = count
    
    return {
        "overview": {
            "total_events": total_events,
            "active_threats": active_threats,
            "resolved_incidents": resolved,
            "unacknowledged_alerts": unack_alerts,
            "monitored_processes": len(processes),
            "network_connections": len(connections)
        },
        "severity_distribution": severity_counts,
        "system_health": "healthy" if active_threats == 0 else "at_risk",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/events/{event_id}")
async def get_event_details(event_id: int, db: Session = Depends(get_db)):
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    return {
        "event": {
            "id": event.id,
            "timestamp": format_timestamp(event.timestamp),
            "type": event.event_type,
            "severity": event.severity,
            "risk_score": event.risk_score,
            "source": event.source,
            "description": event.description,
            "process_name": event.process_name,
            "pid": event.pid,
            "command_line": event.command_line,
            "network_dst": event.network_dst,
            "file_path": event.file_path,
            "resolved": event.resolved,
            "response_action": event.response_action
        }
    }

@app.post("/api/events/{event_id}/resolve")
async def resolve_event(event_id: int, db: Session = Depends(get_db)):
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    event.resolved = True
    db.commit()
    
    await broadcast_message({
        "type": "event_resolved",
        "data": {"event_id": event_id}
    })
    
    return {"status": "resolved", "event_id": event_id}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            if message.get("action") == "ping":
                await websocket.send_json({"type": "pong"})
            
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
