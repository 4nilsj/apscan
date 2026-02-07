from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func
import uuid
import datetime

class Base(DeclarativeBase):
    pass

class DBScan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="pending")  # pending, running, completed, failed
    message = Column(String)
    input_config = Column(JSON)  # Stores the full configuration payload
    endpoints_count = Column(Integer, default=0)
    
    findings = relationship("DBFinding", back_populates="scan", cascade="all, delete-orphan")

class DBFinding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String, ForeignKey("scans.id"))
    
    severity = Column(String)
    rule_id = Column(String)
    name = Column(String)
    description = Column(Text)
    endpoint = Column(String)
    method = Column(String)
    evidence = Column(Text)
    recommendation = Column(Text)
    
    # Detailed Evidence
    reproduce_curl = Column(String)
    request_details = Column(JSON)
    response_details = Column(JSON)
    
    scan = relationship("DBScan", back_populates="findings")
