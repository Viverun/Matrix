"""
Scan database model.
"""
from datetime import datetime
from enum import Enum
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import relationship
from core.database import Base


class ScanStatus(str, Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    """Security scan model."""
    
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Target information
    target_url = Column(String(2048), nullable=False)
    target_name = Column(String(255), nullable=True)
    
    # Scan configuration
    scan_type = Column(String(50), default="full")  # full, quick, custom
    agents_enabled = Column(JSON, default=list)  # List of enabled agent types
    
    # Status tracking
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    progress = Column(Integer, default=0)  # 0-100 percentage
    
    # Results summary
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    # Detected technology stack
    technology_stack = Column(JSON, default=list)
    
    # Error tracking
    error_message = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Relationships
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Scan {self.id} - {self.target_url}>"
    
    @property
    def duration_seconds(self) -> int:
        """Calculate scan duration in seconds."""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return 0
