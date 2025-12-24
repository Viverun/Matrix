"""
Scan schemas.
"""
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List
from datetime import datetime
from models.scan import ScanStatus


class ScanCreate(BaseModel):
    """Schema for creating a new scan."""
    target_url: str = Field(..., description="URL of the target to scan")
    target_name: Optional[str] = Field(None, description="Friendly name for the target")
    scan_type: str = Field("full", description="Type of scan: full, quick, or custom")
    agents_enabled: List[str] = Field(
        default=["sql_injection", "xss", "auth", "api_security"],
        description="List of agent types to enable"
    )


class ScanResponse(BaseModel):
    """Schema for scan response."""
    id: int
    target_url: str
    target_name: Optional[str] = None
    scan_type: str
    status: ScanStatus
    progress: int
    
    # Results summary
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    technology_stack: List[str] = []
    agents_enabled: List[str] = []
    
    error_message: Optional[str] = None
    
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class ScanUpdate(BaseModel):
    """Schema for updating scan status."""
    status: Optional[ScanStatus] = None
    progress: Optional[int] = Field(None, ge=0, le=100)
    error_message: Optional[str] = None


class ScanListResponse(BaseModel):
    """Schema for paginated scan list."""
    items: List[ScanResponse]
    total: int
    page: int
    size: int
    pages: int
