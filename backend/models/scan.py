"""
Scan Model for CyberMatrix Security Scanner
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from enum import Enum
import math
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, JSON, Boolean, 
    Float, Index, CheckConstraint, event
)
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property
from core.database import Base


# ============================================================================
# AUDIT MIXIN WITH SOFT DELETE SUPPORT
# ============================================================================

class AuditMixin:
    """Enhanced mixin with soft delete and audit capabilities."""
    
    # Soft delete support
    deleted_at = Column(DateTime, nullable=True, index=True)
    
    # Audit timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), 
                       onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    
    @hybrid_property
    def is_deleted(self) -> bool:
        """Check if record is soft-deleted."""
        return self.deleted_at is not None
    
    def soft_delete(self):
        """Soft delete this record."""
        self.deleted_at = datetime.now(timezone.utc)
    
    def restore(self):
        """Restore a soft-deleted record."""
        self.deleted_at = None
    
    def to_dict(self, include_relationships: bool = False) -> Dict[str, Any]:
        """
        Convert model to dictionary.
        
        Args:
            include_relationships: Whether to include related objects
            
        Returns:
            Dictionary representation
        """
        result = {}
        
        # Get all columns
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            
            # Handle different types
            if isinstance(value, datetime):
                result[column.name] = value.isoformat() if value else None
            elif isinstance(value, Enum):
                result[column.name] = value.value
            elif isinstance(value, (list, dict)):
                result[column.name] = value
            else:
                result[column.name] = value
        
        return result


# ============================================================================
# ENUMERATIONS
# ============================================================================

class ScanStatus(str, Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    QUEUED = "queued"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"


class ScanType(str, Enum):
    """Scan type enumeration."""
    FULL = "full"
    QUICK = "quick"
    CUSTOM = "custom"
    TARGETED = "targeted"
    COMPLIANCE = "compliance"
    RETEST = "retest"
    GITHUB_SAST = "github_sast"


# ============================================================================
# SCAN MODEL
# ============================================================================

class Scan(Base, AuditMixin):
    """Enhanced security scan model with comprehensive tracking."""
    
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Target information
    target_url = Column(String(2048), nullable=False, index=True)
    target_name = Column(String(255), nullable=True)
    target_domain = Column(String(255), nullable=True, index=True)
    
    # Scan configuration
    scan_type = Column(SQLEnum(ScanType), default=ScanType.FULL, index=True)
    
    # Enhanced agent configuration (structured JSON)
    agents_config = Column(JSON, default=dict)  # {"sql_injection": {"depth": 3, "timeout": 30}, ...}
    agents_enabled = Column(JSON, default=list)  # Legacy support
    
    # Target analysis link
    analysis_snapshot = Column(JSON, nullable=True)  # Stores TargetAnalysis results
    analysis_id = Column(String(64), nullable=True, index=True)  # Link to separate analysis store
    
    # Status tracking
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, index=True)
    progress = Column(Integer, default=0)  # 0-100 percentage
    current_phase = Column(String(100), nullable=True)  # "reconnaissance", "scanning", etc.
    
    # Results summary
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    
    # Advanced metrics
    risk_score = Column(Float, default=0.0, index=True)
    owasp_coverage = Column(JSON, default=dict)  # {"A01:2021": 3, "A03:2021": 5, ...}
    
    # Detected technology stack
    technology_stack = Column(JSON, default=list)
    endpoints_discovered = Column(Integer, default=0)
    forms_discovered = Column(Integer, default=0)
    
    # Performance metrics
    requests_sent = Column(Integer, default=0)
    avg_response_time_ms = Column(Float, nullable=True)
    
    # Error tracking
    error_message = Column(Text, nullable=True)
    error_count = Column(Integer, default=0)
    warnings = Column(JSON, default=list)
    
    # Timestamps
    started_at = Column(DateTime, nullable=True, index=True)
    completed_at = Column(DateTime, nullable=True, index=True)
    paused_at = Column(DateTime, nullable=True)
    resumed_at = Column(DateTime, nullable=True)
    
    # Compliance & Reporting
    compliance_frameworks = Column(JSON, default=list)  # ["OWASP", "PCI-DSS", ...]
    report_generated = Column(Boolean, default=False)
    report_path = Column(String(512), nullable=True)
    
    # Relationships
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    user = relationship("User", back_populates="scans")
    vulnerabilities = relationship(
        "Vulnerability", 
        back_populates="scan", 
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    
    # Constraints
    __table_args__ = (
        CheckConstraint('progress >= 0 AND progress <= 100', name='check_progress_range'),
        CheckConstraint('risk_score >= 0 AND risk_score <= 10', name='check_risk_score_range'),
        Index('idx_scan_status_created', "status", "created_at"),
        Index('idx_scan_user_status', "user_id", "status"),
        Index('idx_scan_completed', "completed_at"),
    )
    
    # ========================================================================
    # STATE TRANSITION METHODS
    # ========================================================================
    
    def initialize_scan(self):
        """Initialize scan and set status to running."""
        if self.status != ScanStatus.PENDING:
            raise ValueError(f"Cannot initialize scan in {self.status.value} state")
        
        self.status = ScanStatus.INITIALIZING
        self.started_at = datetime.now(timezone.utc)
        self.progress = 0
        self.current_phase = "initialization"
    
    def start_scan(self):
        """Start the scan."""
        if self.status not in [ScanStatus.PENDING, ScanStatus.INITIALIZING, ScanStatus.PAUSED]:
            raise ValueError(f"Cannot start scan in {self.status.value} state")
        
        self.status = ScanStatus.RUNNING
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc)
        if self.status == ScanStatus.PAUSED:
            self.resumed_at = datetime.now(timezone.utc)
        self.current_phase = "scanning"
    
    def pause_scan(self):
        """Pause the scan."""
        if self.status != ScanStatus.RUNNING:
            raise ValueError(f"Cannot pause scan in {self.status.value} state")
        
        self.status = ScanStatus.PAUSED
        self.paused_at = datetime.now(timezone.utc)
    
    def complete_scan(self):
        """Complete the scan successfully."""
        if self.status not in [ScanStatus.RUNNING, ScanStatus.PAUSED]:
            raise ValueError(f"Cannot complete scan in {self.status.value} state")
        
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.now(timezone.utc)
        self.progress = 100
        self.current_phase = "completed"
        
        # Calculate final metrics
        self.calculate_risk_score()
        self.calculate_owasp_coverage()
    
    def fail_scan(self, error_message: str):
        """Mark scan as failed with error message."""
        self.status = ScanStatus.FAILED
        self.completed_at = datetime.now(timezone.utc)
        self.error_message = error_message
        self.error_count += 1
        self.current_phase = "failed"
    
    def cancel_scan(self):
        """Cancel the scan."""
        if self.status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
            raise ValueError(f"Cannot cancel scan in {self.status.value} state")
        
        self.status = ScanStatus.CANCELLED
        self.completed_at = datetime.now(timezone.utc)
        self.current_phase = "cancelled"
    
    def timeout_scan(self):
        """Mark scan as timed out."""
        self.status = ScanStatus.TIMED_OUT
        self.completed_at = datetime.now(timezone.utc)
        self.error_message = "Scan exceeded maximum execution time"
        self.current_phase = "timed_out"
    
    def update_progress(self, progress: int, phase: Optional[str] = None):
        """Update scan progress."""
        if not 0 <= progress <= 100:
            raise ValueError("Progress must be between 0 and 100")
        
        self.progress = progress
        if phase:
            self.current_phase = phase
    
    def add_warning(self, warning: str):
        """Add a warning message."""
        if self.warnings is None:
            self.warnings = []
        self.warnings.append({
            "message": warning,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    
    # ========================================================================
    # METRICS CALCULATION
    # ========================================================================
    
    def calculate_risk_score(self) -> float:
        """
        Calculate overall risk score based on vulnerabilities.
        """
        if self.total_vulnerabilities == 0:
            self.risk_score = 0.0
            return 0.0
        
        # Weighted scoring
        weights = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 5.0,
            "low": 3.0,
            "info": 1.0
        }
        
        total_score = (
            self.critical_count * weights["critical"] +
            self.high_count * weights["high"] +
            self.medium_count * weights["medium"] +
            self.low_count * weights["low"] +
            self.info_count * weights["info"]
        )
        
        if total_score > 0:
            normalized = min(10.0, math.log10(total_score + 1) * 3)
            self.risk_score = round(normalized, 2)
        else:
            self.risk_score = 0.0
        
        return self.risk_score
    
    def calculate_owasp_coverage(self):
        """Calculate OWASP Top 10 coverage based on vulnerabilities."""
        coverage = {}
        
        for vuln in self.vulnerabilities:
            if getattr(vuln, 'is_false_positive', False) or getattr(vuln, 'is_deleted', False):
                continue
            
            # Using hasattr/getattr to handle cases where vulnerability model might be slightly different
            v_type = getattr(vuln, 'vulnerability_type', None)
            if v_type and hasattr(v_type, 'owasp_category'):
                owasp_cat = v_type.owasp_category
                coverage[owasp_cat] = coverage.get(owasp_cat, 0) + 1
        
        self.owasp_coverage = coverage
    
    def increment_vulnerability_count(self, severity_value: str):
        """Increment vulnerability count for specific severity."""
        self.total_vulnerabilities += 1
        
        if severity_value == "critical":
            self.critical_count += 1
        elif severity_value == "high":
            self.high_count += 1
        elif severity_value == "medium":
            self.medium_count += 1
        elif severity_value == "low":
            self.low_count += 1
        elif severity_value == "info":
            self.info_count += 1
    
    def decrement_vulnerability_count(self, severity_value: str):
        """Decrement vulnerability count for specific severity."""
        self.total_vulnerabilities = max(0, self.total_vulnerabilities - 1)
        
        if severity_value == "critical":
            self.critical_count = max(0, self.critical_count - 1)
        elif severity_value == "high":
            self.high_count = max(0, self.high_count - 1)
        elif severity_value == "medium":
            self.medium_count = max(0, self.medium_count - 1)
        elif severity_value == "low":
            self.low_count = max(0, self.low_count - 1)
        elif severity_value == "info":
            self.info_count = max(0, self.info_count - 1)
    
    # ========================================================================
    # PROPERTIES & HELPERS
    # ========================================================================
    
    @property
    def duration_seconds(self) -> int:
        """Calculate scan duration in seconds."""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        elif self.started_at:
            return int((datetime.now(timezone.utc) - self.started_at).total_seconds())
        return 0
    
    @property
    def duration_human(self) -> str:
        """Get human-readable duration."""
        seconds = self.duration_seconds
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m {seconds % 60}s"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    
    @property
    def is_active(self) -> bool:
        """Check if scan is currently active."""
        return self.status in [ScanStatus.RUNNING, ScanStatus.INITIALIZING, ScanStatus.PAUSED]
    
    @property
    def is_complete(self) -> bool:
        """Check if scan is complete."""
        return self.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED, ScanStatus.TIMED_OUT]
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.requests_sent == 0:
            return 0.0
        return round((1 - (self.error_count / self.requests_sent)) * 100, 2)
    
    @validates('target_url')
    def validate_target_url(self, key, url):
        """Validate target URL."""
        if not url or len(url) > 2048:
            raise ValueError("Invalid target URL")
        
        import re
        url_pattern = re.compile(
            r'^https?://'
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
            r'localhost|'
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            r'(?::\d+)?'
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(url):
            raise ValueError("Invalid URL format")
        
        from urllib.parse import urlparse
        parsed = urlparse(url)
        self.target_domain = parsed.netloc
        
        return url
    
    def to_dict(self, include_relationships: bool = False) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = super().to_dict(include_relationships)
        result['duration_seconds'] = self.duration_seconds
        result['duration_human'] = self.duration_human
        result['is_active'] = self.is_active
        result['is_complete'] = self.is_complete
        result['success_rate'] = self.success_rate
        
        if include_relationships:
            result['vulnerabilities'] = [
                v.to_dict() for v in self.vulnerabilities 
                if not getattr(v, 'is_deleted', False)
            ]
        
        return result
    
    def __repr__(self):
        return f"<Scan {self.id} - {self.target_url} ({self.status.value})>"


# ============================================================================
# EVENT LISTENERS
# ============================================================================

@event.listens_for(Scan, 'before_update')
def update_scan_timestamp(mapper, connection, target):
    """Update timestamp on scan modification."""
    target.updated_at = datetime.now(timezone.utc)