import hashlib
from datetime import datetime
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum

class RiskLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

@dataclass
class RiskFactors:
    process_anomaly: float = 0.0
    network_suspicion: float = 0.0
    file_operation_risk: float = 0.0
    privilege_escalation: float = 0.0
    time_anomaly: float = 0.0

class RiskScoringEngine:
    
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 31337, 8080, 1080}
    SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".wsf"}
    KNOWN_THREAT_HASHES = set()
    
    CRITICAL_PROCESSES = ["lsass.exe", "csrss.exe", "services.exe", "winlogon.exe"]
    
    def __init__(self):
        self.baseline_cache = {}
        self.recent_events = []
        self.max_cache_size = 1000
    
    def calculate_risk_score(self, event_data: Dict) -> Tuple[float, RiskLevel, List[str]]:
        factors = RiskFactors()
        reasons = []
        
        raw_score = self._analyze_process_behavior(event_data, factors, reasons)
        raw_score += self._analyze_network_activity(event_data, factors, reasons)
        raw_score += self._analyze_file_operations(event_data, factors, reasons)
        raw_score += self._analyze_privilege_context(event_data, factors, reasons)
        raw_score += self._analyze_temporal_patterns(event_data, factors, reasons)
        
        final_score = min(100.0, max(0.0, raw_score))
        risk_level = self._score_to_level(final_score)
        
        return final_score, risk_level, reasons
    
    def _analyze_process_behavior(self, event_data: Dict, factors: RiskFactors, reasons: List[str]) -> float:
        score = 0.0
        process_name = event_data.get("process_name", "").lower()
        command_line = event_data.get("command_line", "").lower()
        
        if process_name in self.CRITICAL_PROCESSES:
            if "injection" in command_line or "-encoded" in command_line:
                score += 35.0
                factors.process_anomaly = 0.9
                reasons.append("Suspicious activity in critical system process")
        
        suspicious_patterns = [
            ("powershell", ["-enc", "-encoded", "bypass", "noprofile", "windowstyle hidden"]),
            ("cmd.exe", ["/c", "del", "format", "regsvr32", "rundll32"]),
            ("wscript", [".js", ".vbs", ".wsf"]),
            ("cscript", [".js", ".vbs", ".wsf"]),
        ]
        
        for proc, patterns in suspicious_patterns:
            if proc in process_name:
                for pattern in patterns:
                    if pattern in command_line:
                        score += 25.0
                        factors.process_anomaly = max(factors.process_anomaly, 0.75)
                        reasons.append(f"Suspicious pattern '{pattern}' in command line")
                        break
        
        encoded_patterns = ["base64", "frombase64", "gzip", "stream", "invoke-expression"]
        for pattern in encoded_patterns:
            if pattern in command_line:
                score += 20.0
                factors.process_anomaly = max(factors.process_anomaly, 0.7)
                reasons.append("Encoded or obfuscated command detected")
                break
        
        return score
    
    def _analyze_network_activity(self, event_data: Dict, factors: RiskFactors, reasons: List[str]) -> float:
        score = 0.0
        dst_ip = event_data.get("network_dst", "")
        dst_port = event_data.get("dst_port", 0)
        
        if dst_port in self.SUSPICIOUS_PORTS:
            score += 30.0
            factors.network_suspicion = 0.85
            reasons.append(f"Connection to suspicious port {dst_port}")
        
        suspicious_ips = ["tor", "proxy", "dark", "pastebin", "ghostbin"]
        dst_lower = dst_ip.lower()
        for indicator in suspicious_ips:
            if indicator in dst_lower:
                score += 25.0
                factors.network_suspicion = max(factors.network_suspicion, 0.7)
                reasons.append("Connection to suspicious destination")
                break
        
        return score
    
    def _analyze_file_operations(self, event_data: Dict, factors: RiskFactors, reasons: List[str]) -> float:
        score = 0.0
        file_path = event_data.get("file_path", "").lower()
        file_hash = event_data.get("hash_value", "")
        
        if file_hash and file_hash in self.KNOWN_THREAT_HASHES:
            score += 50.0
            factors.file_operation_risk = 1.0
            reasons.append("File matches known threat signature")
        
        sensitive_paths = [
            "\\windows\\system32", "\\windows\\syswow64", 
            "\\program files", "\\programdata", "\\temp\\",
            "\\appdata\\local\\temp", "\\users\\public"
        ]
        
        sensitive_extensions = [".exe", ".dll", ".sys", ".drv"]
        
        if any(path in file_path for path in sensitive_paths):
            if any(ext in file_path for ext in sensitive_extensions):
                if "created" in event_data.get("event_type", ""):
                    score += 20.0
                    factors.file_operation_risk = max(factors.file_operation_risk, 0.6)
                    reasons.append("Executable file created in sensitive system directory")
        
        ransomware_indicators = [".encrypted", ".locked", ".crypto", "readme_decrypt", "how_to_recover"]
        for indicator in ransomware_indicators:
            if indicator in file_path:
                score += 45.0
                factors.file_operation_risk = 0.95
                reasons.append("Potential ransomware activity detected")
                break
        
        return score
    
    def _analyze_privilege_context(self, event_data: Dict, factors: RiskFactors, reasons: List[str]) -> float:
        score = 0.0
        
        if event_data.get("elevated", False):
            if factors.process_anomaly > 0.5 or factors.network_suspicion > 0.5:
                score += 15.0
                factors.privilege_escalation = 0.6
                reasons.append("Elevated privilege context with suspicious behavior")
        
        if "uac_bypass" in event_data.get("event_type", "").lower():
            score += 40.0
            factors.privilege_escalation = 0.9
            reasons.append("UAC bypass technique detected")
        
        return score
    
    def _analyze_temporal_patterns(self, event_data: Dict, factors: RiskFactors, reasons: List[str]) -> float:
        score = 0.0
        timestamp = event_data.get("timestamp")
        
        if timestamp:
            hour = timestamp.hour if hasattr(timestamp, 'hour') else datetime.utcnow().hour
            
            if 0 <= hour <= 5:
                if factors.process_anomaly > 0.4 or factors.network_suspicion > 0.4:
                    score += 10.0
                    factors.time_anomaly = 0.5
                    reasons.append("Suspicious activity during off-hours")
        
        recent_count = sum(1 for e in self.recent_events[-50:] 
                          if e.get("process_name") == event_data.get("process_name"))
        if recent_count > 20:
            score += 15.0
            factors.time_anomaly = max(factors.time_anomaly, 0.6)
            reasons.append("Unusual frequency of events from same process")
        
        return score
    
    def _score_to_level(self, score: float) -> RiskLevel:
        if score >= 80:
            return RiskLevel.CRITICAL
        elif score >= 60:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 20:
            return RiskLevel.LOW
        return RiskLevel.INFO
    
    def get_recommended_action(self, risk_level: RiskLevel, reasons: List[str]) -> str:
        actions = {
            RiskLevel.CRITICAL: "immediate_termination",
            RiskLevel.HIGH: "suspend_and_alert",
            RiskLevel.MEDIUM: "monitor_closely",
            RiskLevel.LOW: "log_and_continue",
            RiskLevel.INFO: "record_only"
        }
        
        base_action = actions.get(risk_level, "log_and_continue")
        
        if "ransomware" in " ".join(reasons).lower():
            return "isolate_system"
        if "injection" in " ".join(reasons).lower():
            return "memory_forensics"
        
        return base_action
    
    def update_baseline(self, process_name: str, metrics: Dict):
        self.baseline_cache[process_name] = {
            "avg_cpu": metrics.get("cpu_percent", 0),
            "avg_memory": metrics.get("memory_mb", 0),
            "connections": metrics.get("connections", 0),
            "last_update": datetime.utcnow()
        }
