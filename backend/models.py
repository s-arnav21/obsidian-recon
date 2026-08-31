from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey, DateTime, JSON
from sqlalchemy.orm import relationship
from database import Base
import datetime

class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=True)
    added_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_scanned_at = Column(DateTime, nullable=True)
    overall_risk_score = Column(Float, default=0.0)
    total_findings = Column(Integer, default=0)
    scan_status = Column(String, default="idle")
    scans = relationship("Scan", back_populates="target")
    findings = relationship("Finding", back_populates="target")
    risk_history = relationship("RiskHistory", back_populates="target")
    attack_paths = relationship("AttackPath", back_populates="target")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    started_at = Column(DateTime, default=datetime.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    triggered_by = Column(String, default="manual")
    tool_used = Column(String, nullable=True)
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    template_id = Column(String)
    vulnerability_name = Column(String)
    category = Column(String, nullable=True)
    severity = Column(String)
    status = Column(String, default="pending")
    confidence_score = Column(Float, nullable=True)
    confidence_level = Column(String, nullable=True)
    cve = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    parameter_affected = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    target = relationship("Target", back_populates="findings")
    scan = relationship("Scan", back_populates="findings")
    evidence = relationship("Evidence", back_populates="finding")
    queue_entry = relationship("ManualQueue", back_populates="finding", uselist=False)

class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    validator = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    payload_used = Column(String, nullable=True)
    request_snapshot = Column(String, nullable=True)
    response_snapshot = Column(String, nullable=True)
    signals = Column(JSON, nullable=True)
    recommendation = Column(String, nullable=True)
    finding = relationship("Finding", back_populates="evidence")

class ManualQueue(Base):
    __tablename__ = "manual_queue"
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("findings.id"))
    reason = Column(String)
    queued_at = Column(DateTime, default=datetime.datetime.utcnow)
    reviewed = Column(Boolean, default=False)
    reviewer_notes = Column(String, nullable=True)
    reviewer_name = Column(String, nullable=True)
    finding = relationship("Finding", back_populates="queue_entry")

class AttackPath(Base):
    __tablename__ = "attack_paths"
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    path_json = Column(JSON)
    classification = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    target = relationship("Target", back_populates="attack_paths")

class RiskHistory(Base):
    __tablename__ = "risk_history"
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    score = Column(Float)
    recorded_at = Column(DateTime, default=datetime.datetime.utcnow)
    target = relationship("Target", back_populates="risk_history")