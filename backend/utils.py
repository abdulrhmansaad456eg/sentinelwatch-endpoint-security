import hashlib
import secrets
import string
from datetime import datetime
from typing import Dict, Any

def generate_incident_id() -> str:
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    random_part = secrets.token_hex(4)
    return f"INC-{timestamp}-{random_part.upper()}"

def calculate_hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()

def format_timestamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

def truncate_string(s: str, max_length: int = 100) -> str:
    if len(s) <= max_length:
        return s
    return s[:max_length-3] + "..."

def sanitize_command_line(cmd: str) -> str:
    sensitive_patterns = ["password", "passwd", "secret", "key", "token", "credential"]
    cmd_lower = cmd.lower()
    
    for pattern in sensitive_patterns:
        if pattern in cmd_lower:
            return "[REDACTED - contains sensitive data]"
    
    return cmd

def risk_level_to_color(risk_level: str) -> str:
    colors = {
        "critical": "#ff4444",
        "high": "#ff8800",
        "medium": "#ffcc00",
        "low": "#44aa44",
        "info": "#4488ff"
    }
    return colors.get(risk_level.lower(), "#888888")

def bytes_to_human_readable(size_bytes: int) -> str:
    if size_bytes == 0:
        return "0 B"
    
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    size = float(size_bytes)
    
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    
    return f"{size:.2f} {units[unit_index]}"

def calculate_uptime(start_time: datetime) -> str:
    now = datetime.utcnow()
    diff = now - start_time
    
    hours = int(diff.total_seconds() // 3600)
    minutes = int((diff.total_seconds() % 3600) // 60)
    seconds = int(diff.total_seconds() % 60)
    
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"

def merge_event_data(existing: Dict[str, Any], new_data: Dict[str, Any]) -> Dict[str, Any]:
    result = existing.copy()
    
    for key, value in new_data.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_event_data(result[key], value)
        else:
            result[key] = value
    
    return result

def is_system_process(process_name: str) -> bool:
    system_procs = [
        "system", "svchost.exe", "csrss.exe", "smss.exe",
        "services.exe", "lsass.exe", "winlogon.exe", "wininit.exe",
        "dwm.exe", "explorer.exe", "taskhostw.exe", "registry"
    ]
    return process_name.lower() in [p.lower() for p in system_procs]

def validate_ip_address(ip: str) -> bool:
    parts = ip.split(".")
    
    if len(parts) != 4:
        return False
    
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    
    return True

def extract_domain_from_endpoint(endpoint: str) -> str:
    if ":" in endpoint:
        domain = endpoint.split(":")[0]
    else:
        domain = endpoint
    
    return domain

def generate_response_recommendation(risk_level: str, threat_category: str) -> Dict[str, Any]:
    recommendations = {
        "critical": {
            "immediate_action": "Terminate process and isolate system",
            "investigation_priority": "Immediate - within 15 minutes",
            "escalation": "Security team and incident response",
            "forensic_collection": "Full memory dump and disk image"
        },
        "high": {
            "immediate_action": "Suspend process and alert security team",
            "investigation_priority": "High - within 1 hour",
            "escalation": "Security analyst review required",
            "forensic_collection": "Process memory dump and relevant logs"
        },
        "medium": {
            "immediate_action": "Enable enhanced monitoring",
            "investigation_priority": "Medium - within 4 hours",
            "escalation": "Log for analyst review during next shift",
            "forensic_collection": "Standard logging and process information"
        },
        "low": {
            "immediate_action": "Continue monitoring",
            "investigation_priority": "Low - routine review",
            "escalation": "None required",
            "forensic_collection": "Standard logs only"
        }
    }
    
    base_rec = recommendations.get(risk_level.lower(), recommendations["medium"])
    
    threat_specific = {
        "ransomware": {
            "immediate_action": "ISOLATE SYSTEM IMMEDIATELY - Disconnect from network",
            "additional_notes": "Check for file encryption indicators"
        },
        "backdoor": {
            "immediate_action": "Block network connections and investigate persistence",
            "additional_notes": "Check for scheduled tasks and registry run keys"
        },
        "cryptominer": {
            "immediate_action": "Terminate process and check for other miners",
            "additional_notes": "Review resource consumption history"
        },
        "trojan": {
            "immediate_action": "Quarantine and analyze dropped files",
            "additional_notes": "Check for credential theft attempts"
        }
    }
    
    if threat_category in threat_specific:
        base_rec.update(threat_specific[threat_category])
    
    return base_rec
