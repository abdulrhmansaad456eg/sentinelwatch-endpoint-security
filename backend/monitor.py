import psutil
import threading
import time
from datetime import datetime
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field
import asyncio
import socket

@dataclass
class ProcessSnapshot:
    pid: int
    name: str
    cpu_percent: float
    memory_mb: float
    connections: int
    threads: int
    command_line: str
    create_time: float
    username: str
    status: str
    hash_value: str = ""

@dataclass
class NetworkConnection:
    local_addr: str
    remote_addr: str
    status: str
    pid: int
    process_name: str
    protocol: str

@dataclass
class FileOperationEvent:
    timestamp: datetime
    process_name: str
    pid: int
    operation: str
    file_path: str
    size_delta: int

class SystemMonitor:
    
    def __init__(self, alert_callback: Optional[Callable] = None):
        self.alert_callback = alert_callback
        self.monitoring = False
        self.monitor_thread = None
        self.process_cache = {}
        self.network_cache = set()
        self.file_watch_paths = []
        self.baseline_data = {}
        self.lock = threading.Lock()
        
        self.suspicious_extensions = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs"}
        self.critical_system_paths = [
            "C:\\Windows\\System32",
            "C:\\Windows\\SysWOW64",
            "C:\\Program Files",
            "C:\\ProgramData"
        ]
    
    def start_monitoring(self, interval: float = 2.0):
        if self.monitoring:
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def _monitor_loop(self, interval: float):
        while self.monitoring:
            try:
                self._scan_processes()
                self._scan_network_connections()
                time.sleep(interval)
            except Exception as e:
                time.sleep(interval)
    
    def _scan_processes(self):
        current_pids = set()
        process_snapshots = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 
                                        'num_threads', 'create_time', 'username', 'status', 'cmdline']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                
                snapshot = ProcessSnapshot(
                    pid=pid,
                    name=proc.info['name'] or "unknown",
                    cpu_percent=proc.info['cpu_percent'] or 0.0,
                    memory_mb=(proc.info['memory_info'].rss / 1024 / 1024) if proc.info['memory_info'] else 0.0,
                    connections=0,
                    threads=proc.info['num_threads'] or 0,
                    command_line=" ".join(proc.info['cmdline']) if proc.info['cmdline'] else "",
                    create_time=proc.info['create_time'] or 0,
                    username=proc.info['username'] or "unknown",
                    status=proc.info['status'] or "unknown"
                )
                
                try:
                    snapshot.connections = len(proc.connections())
                except:
                    pass
                
                process_snapshots.append(snapshot)
                
                with self.lock:
                    if pid in self.process_cache:
                        old = self.process_cache[pid]
                        if (snapshot.cpu_percent > old.cpu_percent * 5 and 
                            snapshot.cpu_percent > 50):
                            if self.alert_callback:
                                self.alert_callback({
                                    "type": "cpu_spike",
                                    "pid": pid,
                                    "process": snapshot.name,
                                    "cpu_percent": snapshot.cpu_percent,
                                    "timestamp": datetime.utcnow()
                                })
                
                with self.lock:
                    self.process_cache[pid] = snapshot
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        with self.lock:
            terminated = set(self.process_cache.keys()) - current_pids
            for pid in terminated:
                del self.process_cache[pid]
    
    def _scan_network_connections(self):
        current_connections = set()
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    conn_key = f"{conn.laddr.ip}:{conn.laddr.port}-{conn.raddr.ip}:{conn.raddr.port}"
                    current_connections.add(conn_key)
                    
                    if conn_key not in self.network_cache:
                        process_name = "unknown"
                        try:
                            if conn.pid:
                                process_name = psutil.Process(conn.pid).name()
                        except:
                            pass
                        
                        if self.alert_callback and self._is_suspicious_connection(conn):
                            self.alert_callback({
                                "type": "suspicious_connection",
                                "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                                "remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                                "process": process_name,
                                "timestamp": datetime.utcnow()
                            })
        except Exception:
            pass
        
        with self.lock:
            self.network_cache = current_connections
    
    def _is_suspicious_connection(self, conn) -> bool:
        suspicious_ports = {4444, 5555, 6666, 31337, 8080, 1080, 9050, 9150}
        
        if conn.raddr and conn.raddr.port in suspicious_ports:
            return True
        
        try:
            remote_ip = conn.raddr.ip if conn.raddr else None
            if remote_ip:
                ip_parts = remote_ip.split(".")
                if len(ip_parts) == 4:
                    first_octet = int(ip_parts[0])
                    if first_octet in [10, 172, 192]:
                        if conn.raddr.port > 50000:
                            return True
        except:
            pass
        
        return False
    
    def get_active_processes(self) -> List[ProcessSnapshot]:
        with self.lock:
            return list(self.process_cache.values())
    
    def get_network_connections(self) -> List[NetworkConnection]:
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    process_name = "unknown"
                    try:
                        if conn.pid:
                            process_name = psutil.Process(conn.pid).name()
                    except:
                        pass
                    
                    connections.append(NetworkConnection(
                        local_addr=f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown",
                        remote_addr=f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "unknown",
                        status=conn.status,
                        pid=conn.pid or 0,
                        process_name=process_name,
                        protocol="TCP"
                    ))
        except Exception:
            pass
        
        return connections
    
    def get_system_resources(self) -> Dict:
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024**3),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024**3),
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
        except Exception as e:
            return {
                "cpu_percent": 0,
                "memory_percent": 0,
                "error": str(e)
            }
    
    def collect_baseline_data(self, duration_seconds: int = 300) -> List[Dict]:
        baseline_samples = []
        start_time = time.time()
        
        while time.time() - start_time < duration_seconds:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 
                                            'num_threads', 'connections']):
                try:
                    info = proc.info
                    baseline_samples.append({
                        "process_name": info['name'],
                        "cpu_percent": info['cpu_percent'] or 0,
                        "memory_mb": (info['memory_info'].rss / 1024 / 1024) if info['memory_info'] else 0,
                        "thread_count": info['num_threads'] or 0,
                        "connection_count": len(proc.connections()) if hasattr(proc, 'connections') else 0,
                        "timestamp": datetime.utcnow().isoformat()
                    })
                except:
                    continue
            
            time.sleep(5)
        
        return baseline_samples
    
    def simulate_threat_event(self, threat_type: str) -> Dict:
        threats = {
            "ransomware_sim": {
                "process_name": "svchost.exe",
                "command_line": "svchost.exe -k netsvcs --encrypt-files C:\\Users\\Documents",
                "cpu_percent": 85.5,
                "memory_mb": 2048,
                "connection_count": 1,
                "file_path": "C:\\Users\\Documents\\file.docx.encrypted",
                "event_type": "file_operation"
            },
            "backdoor_sim": {
                "process_name": "powershell.exe",
                "command_line": "powershell -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAw",
                "cpu_percent": 12.3,
                "memory_mb": 156,
                "connection_count": 15,
                "network_dst": "185.220.101.42:4444",
                "event_type": "network_connection"
            },
            "trojan_sim": {
                "process_name": "chrome_update.exe",
                "command_line": "chrome_update.exe /silent /inject",
                "cpu_percent": 45.2,
                "memory_mb": 512,
                "connection_count": 8,
                "file_path": "C:\\Windows\\Temp\\payload.dll",
                "event_type": "process_injection"
            }
        }
        
        return threats.get(threat_type, threats["trojan_sim"])
