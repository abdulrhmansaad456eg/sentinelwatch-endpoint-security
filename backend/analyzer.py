import numpy as np
import pickle
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings("ignore")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "baseline_model.pkl")

class BehaviorAnalyzer:
    
    FEATURE_COLUMNS = [
        "cpu_percent", "memory_mb", "connection_count", 
        "file_ops_per_min", "thread_count", "handle_count"
    ]
    
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.training_data = []
        self.is_trained = False
        self.load_model()
    
    def load_model(self):
        try:
            if os.path.exists(MODEL_PATH):
                with open(MODEL_PATH, "rb") as f:
                    saved = pickle.load(f)
                    self.model = saved.get("model")
                    self.scaler = saved.get("scaler", StandardScaler())
                    self.is_trained = saved.get("trained", False)
        except Exception as e:
            self.model = None
            self.is_trained = False
    
    def save_model(self):
        try:
            os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
            with open(MODEL_PATH, "wb") as f:
                pickle.dump({
                    "model": self.model,
                    "scaler": self.scaler,
                    "trained": self.is_trained,
                    "saved_at": datetime.utcnow()
                }, f)
        except Exception as e:
            pass
    
    def extract_features(self, process_data: Dict) -> np.ndarray:
        features = [
            process_data.get("cpu_percent", 0.0),
            process_data.get("memory_mb", 0.0),
            process_data.get("connection_count", 0),
            process_data.get("file_ops_per_min", 0),
            process_data.get("thread_count", 0),
            process_data.get("handle_count", 0)
        ]
        return np.array(features).reshape(1, -1)
    
    def train_baseline(self, normal_processes: List[Dict]):
        if len(normal_processes) < 10:
            return False
        
        feature_matrix = []
        for proc in normal_processes:
            features = [
                proc.get("cpu_percent", 0.0),
                proc.get("memory_mb", 0.0),
                proc.get("connection_count", 0),
                proc.get("file_ops_per_min", 0),
                proc.get("thread_count", 0),
                proc.get("handle_count", 0)
            ]
            feature_matrix.append(features)
        
        X = np.array(feature_matrix)
        
        try:
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            
            contamination = min(0.1, max(0.01, 5.0 / len(normal_processes)))
            
            self.model = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100,
                max_samples="auto"
            )
            self.model.fit(X_scaled)
            self.is_trained = True
            self.save_model()
            return True
        except Exception as e:
            return False
    
    def analyze_process(self, process_data: Dict) -> Tuple[bool, float, Dict]:
        if not self.is_trained or self.model is None:
            return False, 0.0, {"status": "baseline_not_ready"}
        
        try:
            features = self.extract_features(process_data)
            features_scaled = self.scaler.transform(features)
            
            prediction = self.model.predict(features_scaled)[0]
            anomaly_score = self.model.decision_function(features_scaled)[0]
            
            is_anomaly = prediction == -1
            confidence = abs(anomaly_score)
            
            analysis_details = {
                "is_anomaly": is_anomaly,
                "anomaly_score": float(anomaly_score),
                "confidence": float(confidence),
                "status": "anomaly_detected" if is_anomaly else "normal",
                "deviation_factors": self._calculate_deviations(process_data, features_scaled[0])
            }
            
            return is_anomaly, confidence, analysis_details
            
        except Exception as e:
            return False, 0.0, {"status": "analysis_error", "error": str(e)}
    
    def _calculate_deviations(self, process_data: Dict, scaled_features: np.ndarray) -> Dict:
        deviations = {}
        
        threshold_checks = [
            ("cpu_percent", 2.0, "High CPU usage deviation"),
            ("memory_mb", 2.5, "High memory usage deviation"),
            ("connection_count", 2.0, "Unusual network activity"),
            ("file_ops_per_min", 3.0, "Excessive file operations")
        ]
        
        for idx, (field, threshold, description) in enumerate(threshold_checks):
            if abs(scaled_features[idx]) > threshold:
                deviations[field] = {
                    "severity": "high" if abs(scaled_features[idx]) > threshold * 1.5 else "medium",
                    "description": description,
                    "z_score": float(scaled_features[idx])
                }
        
        return deviations
    
    def detect_process_injection_indicators(self, process_data: Dict) -> List[Dict]:
        indicators = []
        
        mem_alloc = process_data.get("memory_allocations", [])
        if len(mem_alloc) > 10:
            large_allocs = [a for a in mem_alloc if a.get("size", 0) > 1048576]
            if len(large_allocs) > 3:
                indicators.append({
                    "type": "suspicious_memory_allocation",
                    "severity": "high",
                    "description": f"Process made {len(large_allocs)} large memory allocations"
                })
        
        threads = process_data.get("thread_states", [])
        suspended = [t for t in threads if t.get("state") == "suspended"]
        if len(suspended) > len(threads) * 0.5 and len(threads) > 5:
            indicators.append({
                "type": "thread_manipulation",
                "severity": "medium",
                "description": f"High percentage of suspended threads ({len(suspended)}/{len(threads)})"
            })
        
        modules = process_data.get("loaded_modules", [])
        unsigned = [m for m in modules if not m.get("signed", True)]
        if len(unsigned) > 0:
            indicators.append({
                "type": "unsigned_modules",
                "severity": "medium",
                "description": f"Process loaded {len(unsigned)} unsigned modules"
            })
        
        return indicators
    
    def classify_threat_category(self, process_data: Dict, anomaly_result: Dict) -> str:
        indicators = self.detect_process_injection_indicators(process_data)
        cmd_line = process_data.get("command_line", "").lower()
        
        category_scores = {
            "ransomware": 0,
            "trojan": 0,
            "backdoor": 0,
            "cryptominer": 0,
            "generic_malware": 0
        }
        
        for indicator in indicators:
            if indicator["type"] == "suspicious_memory_allocation":
                category_scores["trojan"] += 30
                category_scores["backdoor"] += 20
            elif indicator["type"] == "unsigned_modules":
                category_scores["generic_malware"] += 20
        
        crypto_patterns = ["crypto", "mine", "monero", "xmr", "pool", "stratum", "wallet"]
        if any(pattern in cmd_line for pattern in crypto_patterns):
            category_scores["cryptominer"] += 50
        
        ransom_patterns = ["encrypt", "decrypt", "bitcoin", "wallet", "recovery", "locked"]
        if any(pattern in cmd_line for pattern in ransom_patterns):
            category_scores["ransomware"] += 40
        
        conn_count = process_data.get("connection_count", 0)
        if conn_count > 20:
            category_scores["backdoor"] += 25
            category_scores["trojan"] += 15
        
        cpu_usage = process_data.get("cpu_percent", 0)
        if cpu_usage > 80 and category_scores["cryptominer"] > 0:
            category_scores["cryptominer"] += 20
        
        max_category = max(category_scores, key=category_scores.get)
        if category_scores[max_category] > 30:
            return max_category
        
        if anomaly_result.get("is_anomaly", False):
            return "suspicious_behavior"
        
        return "normal"
    
    def generate_baseline_report(self) -> Dict:
        return {
            "model_trained": self.is_trained,
            "model_path": MODEL_PATH if os.path.exists(MODEL_PATH) else None,
            "feature_columns": self.FEATURE_COLUMNS,
            "anomaly_threshold": 0.5,
            "last_updated": datetime.utcnow().isoformat()
        }
