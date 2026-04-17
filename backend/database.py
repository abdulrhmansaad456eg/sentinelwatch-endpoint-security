from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "sentinel.db")

engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class SecurityEvent(Base):
    __tablename__ = "security_events"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(50), index=True)
    severity = Column(String(20), default="low")
    risk_score = Column(Float, default=0.0)
    source = Column(String(100))
    description = Column(Text)
    process_name = Column(String(200))
    pid = Column(Integer)
    command_line = Column(Text)
    network_dst = Column(String(100))
    file_path = Column(String(500))
    hash_value = Column(String(64))
    resolved = Column(Boolean, default=False)
    response_action = Column(String(50))

class ProcessBaseline(Base):
    __tablename__ = "process_baselines"
    
    id = Column(Integer, primary_key=True, index=True)
    process_name = Column(String(200), unique=True, index=True)
    avg_cpu_percent = Column(Float, default=0.0)
    avg_memory_mb = Column(Float, default=0.0)
    typical_connections = Column(Integer, default=0)
    typical_file_ops = Column(Integer, default=0)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    occurrence_count = Column(Integer, default=1)
    trusted = Column(Boolean, default=False)

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    title = Column(String(200))
    message = Column(Text)
    severity = Column(String(20))
    category = Column(String(50))
    acknowledged = Column(Boolean, default=False)
    incident_id = Column(String(32), unique=True)

class SystemStats(Base):
    __tablename__ = "system_stats"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    total_events = Column(Integer, default=0)
    active_threats = Column(Integer, default=0)
    resolved_incidents = Column(Integer, default=0)
    avg_risk_score = Column(Float, default=0.0)
    system_uptime_hours = Column(Float, default=0.0)
    monitored_processes = Column(Integer, default=0)
    network_connections = Column(Integer, default=0)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
