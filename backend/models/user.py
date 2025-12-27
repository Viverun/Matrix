"""
Enhanced User Model for CyberMatrix Security Scanner

Features:
- Role-based access control (RBAC)
- Multi-factor authentication (MFA)
- API token management with expiration
- Subscription and quota tracking
- Team/organization support
- Comprehensive security audit trail
- OAuth provider integration
- Rate limiting and abuse prevention
"""

from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from enum import Enum
import secrets
import hashlib
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, JSON, Text, Float,
    ForeignKey, Index, CheckConstraint, event
)
from sqlalchemy import Enum as SQLEnum
from sqlalchemy.orm import relationship, validates
from sqlalchemy.ext.hybrid import hybrid_property
from core.database import Base


# ============================================================================
# ENUMERATIONS
# ============================================================================

class UserRole(str, Enum):
    """User role enumeration for RBAC."""
    ADMIN = "admin"              # Full system access
    MANAGER = "manager"          # Team management, all scans
    SECURITY_ANALYST = "analyst" # Run scans, view all results
    DEVELOPER = "developer"      # Run scans, view own results
    VIEWER = "viewer"            # Read-only access
    API_USER = "api_user"        # API access only
    GUEST = "guest"              # Limited trial access


class SubscriptionTier(str, Enum):
    """Subscription tier enumeration."""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class MFAMethod(str, Enum):
    """Multi-factor authentication methods."""
    TOTP = "totp"               # Time-based OTP (Google Authenticator)
    SMS = "sms"                 # SMS verification
    EMAIL = "email"             # Email verification
    BACKUP_CODES = "backup_codes"  # Recovery codes
    WEBAUTHN = "webauthn"       # Hardware keys (YubiKey, etc.)


class OAuthProvider(str, Enum):
    """OAuth provider enumeration."""
    GOOGLE = "google"
    GITHUB = "github"
    MICROSOFT = "microsoft"
    OKTA = "okta"
    GITLAB = "gitlab"


class ActivityType(str, Enum):
    """User activity types for audit logging."""
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGED = "password_changed"
    EMAIL_CHANGED = "email_changed"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    API_KEY_CREATED = "api_key_created"
    API_KEY_DELETED = "api_key_deleted"
    SCAN_CREATED = "scan_created"
    SCAN_DELETED = "scan_deleted"
    SETTINGS_CHANGED = "settings_changed"
    TEAM_JOINED = "team_joined"
    TEAM_LEFT = "team_left"
    ROLE_CHANGED = "role_changed"


# ============================================================================
# ORGANIZATION/TEAM MODEL
# ============================================================================

class Organization(Base):
    """Organization/team model for multi-tenancy."""
    
    __tablename__ = "organizations"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Basic info
    name = Column(String(255), nullable=False, index=True)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Settings
    settings = Column(JSON, default=dict)
    
    # Subscription
    subscription_tier = Column(SQLEnum(SubscriptionTier), default=SubscriptionTier.FREE)
    subscription_start = Column(DateTime, nullable=True)
    subscription_end = Column(DateTime, nullable=True)
    
    # Quotas
    max_users = Column(Integer, default=5)
    max_scans_per_month = Column(Integer, default=100)
    max_concurrent_scans = Column(Integer, default=3)
    
    # Usage tracking
    current_users = Column(Integer, default=0)
    scans_this_month = Column(Integer, default=0)
    total_scans = Column(Integer, default=0)
    
    # Billing
    billing_email = Column(String(255), nullable=True)
    stripe_customer_id = Column(String(255), nullable=True, index=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Soft delete
    deleted_at = Column(DateTime, nullable=True)
    
    # Relationships
    members = relationship("OrganizationMember", back_populates="organization", cascade="all, delete-orphan")
    
    @validates('slug')
    def validate_slug(self, key, slug):
        """Validate organization slug."""
        import re
        if not re.match(r'^[a-z0-9-]+$', slug):
            raise ValueError("Slug must contain only lowercase letters, numbers, and hyphens")
        return slug
    
    @property
    def is_subscription_active(self) -> bool:
        """Check if subscription is active."""
        if not self.subscription_end:
            return False
        return datetime.now(timezone.utc) < self.subscription_end
    
    @property
    def users_remaining(self) -> int:
        """Calculate remaining user slots."""
        return max(0, self.max_users - self.current_users)
    
    @property
    def scans_remaining(self) -> int:
        """Calculate remaining scans for current month."""
        return max(0, self.max_scans_per_month - self.scans_this_month)
    
    def can_add_user(self) -> bool:
        """Check if organization can add more users."""
        return self.current_users < self.max_users
    
    def can_run_scan(self) -> bool:
        """Check if organization can run more scans."""
        return self.scans_this_month < self.max_scans_per_month
    
    def reset_monthly_quota(self):
        """Reset monthly scan quota."""
        self.scans_this_month = 0
    
    def __repr__(self):
        return f"<Organization {self.name}>"


class OrganizationMember(Base):
    """Organization membership with role."""
    
    __tablename__ = "organization_members"
    
    id = Column(Integer, primary_key=True, index=True)
    
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    role = Column(SQLEnum(UserRole), default=UserRole.DEVELOPER)
    
    # Timestamps
    joined_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    organization = relationship("Organization", back_populates="members")
    user = relationship("User", back_populates="organization_memberships")
    
    __table_args__ = (
        Index('idx_org_member_org_user', organization_id, user_id, unique=True),
    )
    
    def __repr__(self):
        return f"<OrganizationMember org={self.organization_id} user={self.user_id}>"


# ============================================================================
# API TOKEN MODEL
# ============================================================================

class APIToken(Base):
    """API token model for programmatic access."""
    
    __tablename__ = "api_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Token info
    name = Column(String(255), nullable=False)
    token_hash = Column(String(128), unique=True, nullable=False, index=True)
    token_prefix = Column(String(10), nullable=False)  # For display: "cm_abc..."
    
    # Permissions
    scopes = Column(JSON, default=list)  # ["scans:read", "scans:write", "vulnerabilities:read"]
    
    # Rate limiting
    rate_limit_per_hour = Column(Integer, default=1000)
    requests_this_hour = Column(Integer, default=0)
    last_request_at = Column(DateTime, nullable=True)
    
    # Usage tracking
    total_requests = Column(Integer, default=0)
    last_used_at = Column(DateTime, nullable=True)
    last_used_ip = Column(String(45), nullable=True)
    
    # Expiration
    expires_at = Column(DateTime, nullable=True, index=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Relationships
    user = relationship("User", back_populates="api_tokens")
    
    __table_args__ = (
        Index('idx_token_user_active', user_id, is_active),
        Index('idx_token_expires', expires_at),
    )
    
    @staticmethod
    def generate_token() -> tuple[str, str, str]:
        """
        Generate a new API token.
        
        Returns:
            tuple: (token, token_hash, token_prefix)
        """
        # Generate random token
        token = f"cm_{secrets.token_urlsafe(32)}"
        
        # Hash for storage
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Prefix for display
        token_prefix = token[:10]
        
        return token, token_hash, token_prefix
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if token is valid (active and not expired)."""
        return self.is_active and not self.is_expired
    
    def can_make_request(self) -> bool:
        """Check if token can make another request (rate limit)."""
        if not self.is_valid:
            return False
        
        # Check rate limit
        return self.requests_this_hour < self.rate_limit_per_hour
    
    def record_request(self, ip_address: str):
        """Record an API request."""
        now = datetime.now(timezone.utc)
        
        # Reset hourly counter if needed
        if self.last_request_at:
            time_diff = (now - self.last_request_at).total_seconds()
            if time_diff >= 3600:  # 1 hour
                self.requests_this_hour = 0
        
        self.requests_this_hour += 1
        self.total_requests += 1
        self.last_request_at = now
        self.last_used_at = now
        self.last_used_ip = ip_address
    
    def revoke(self):
        """Revoke the token."""
        self.is_active = False
    
    def __repr__(self):
        return f"<APIToken {self.token_prefix}... ({self.name})>"


# ============================================================================
# USER ACTIVITY LOG MODEL
# ============================================================================

class UserActivity(Base):
    """User activity audit log."""
    
    __tablename__ = "user_activities"
    
    id = Column(Integer, primary_key=True, index=True)
    
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Activity details
    activity_type = Column(SQLEnum(ActivityType), nullable=False, index=True)
    description = Column(Text, nullable=True)
    
    # Context
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    activity_metadata = Column(JSON, default=dict)  # Additional context
    
    # Timestamp
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    # Relationships
    user = relationship("User", back_populates="activities")
    
    __table_args__ = (
        Index('idx_activity_user_type', user_id, activity_type),
        Index('idx_activity_created', created_at),
    )
    
    def __repr__(self):
        return f"<UserActivity {self.activity_type.value} by user {self.user_id}>"


# ============================================================================
# ENHANCED USER MODEL
# ============================================================================

class User(Base):
    """Enhanced user model with comprehensive security and management features."""
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # ========================================================================
    # AUTHENTICATION
    # ========================================================================
    
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    
    # Email verification
    email_verified = Column(Boolean, default=False)
    email_verification_token = Column(String(128), nullable=True, index=True)
    email_verification_sent_at = Column(DateTime, nullable=True)
    
    # Password reset
    password_reset_token = Column(String(128), nullable=True, index=True)
    password_reset_expires = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, nullable=True)
    
    # Multi-factor authentication
    mfa_enabled = Column(Boolean, default=False, index=True)
    mfa_method = Column(SQLEnum(MFAMethod), nullable=True)
    mfa_secret = Column(String(255), nullable=True)  # TOTP secret
    mfa_backup_codes = Column(JSON, default=list)  # Encrypted backup codes
    mfa_phone = Column(String(20), nullable=True)  # For SMS
    
    # ========================================================================
    # PROFILE
    # ========================================================================
    
    full_name = Column(String(255), nullable=True)
    company = Column(String(255), nullable=True)
    job_title = Column(String(255), nullable=True)
    avatar_url = Column(String(512), nullable=True)
    bio = Column(Text, nullable=True)
    location = Column(String(255), nullable=True)
    website = Column(String(512), nullable=True)
    
    # Contact
    phone = Column(String(20), nullable=True)
    
    # ========================================================================
    # ROLE & PERMISSIONS
    # ========================================================================
    
    role = Column(SQLEnum(UserRole), default=UserRole.DEVELOPER, index=True)
    custom_permissions = Column(JSON, default=list)  # Additional granular permissions
    
    # Legacy admin flags (for backward compatibility)
    is_admin = Column(Boolean, default=False)
    
    # ========================================================================
    # STATUS & SECURITY
    # ========================================================================
    
    is_active = Column(Boolean, default=True, index=True)
    is_verified = Column(Boolean, default=False)  # Manual verification by admin
    
    # Account locking
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True, index=True)
    lock_reason = Column(String(500), nullable=True)
    
    # Session management
    current_session_token = Column(String(128), nullable=True, index=True)
    session_expires_at = Column(DateTime, nullable=True)
    
    # Login tracking
    last_login_at = Column(DateTime, nullable=True, index=True)
    last_login_ip = Column(String(45), nullable=True)
    last_login_user_agent = Column(String(500), nullable=True)
    login_count = Column(Integer, default=0)
    
    # Security events
    last_password_change = Column(DateTime, nullable=True)
    suspicious_activity_count = Column(Integer, default=0)
    
    # ========================================================================
    # OAUTH INTEGRATION
    # ========================================================================
    
    oauth_provider = Column(SQLEnum(OAuthProvider), nullable=True)
    oauth_id = Column(String(255), nullable=True, index=True)
    oauth_access_token = Column(String(512), nullable=True)
    oauth_refresh_token = Column(String(512), nullable=True)
    oauth_token_expires = Column(DateTime, nullable=True)
    
    # ========================================================================
    # SUBSCRIPTION & QUOTAS
    # ========================================================================
    
    subscription_tier = Column(SQLEnum(SubscriptionTier), default=SubscriptionTier.FREE, index=True)
    subscription_start = Column(DateTime, nullable=True)
    subscription_end = Column(DateTime, nullable=True)
    trial_ends_at = Column(DateTime, nullable=True)
    
    # Individual quotas (overrides organization quotas if set)
    max_scans_per_month = Column(Integer, nullable=True)
    max_concurrent_scans = Column(Integer, nullable=True)
    max_api_calls_per_hour = Column(Integer, nullable=True)
    
    # Usage tracking
    scans_this_month = Column(Integer, default=0)
    api_calls_this_hour = Column(Integer, default=0)
    total_scans = Column(Integer, default=0)
    total_api_calls = Column(Integer, default=0)
    
    # Storage
    storage_used_mb = Column(Float, default=0.0)
    storage_limit_mb = Column(Float, default=1000.0)  # 1GB default
    
    # ========================================================================
    # PREFERENCES & SETTINGS
    # ========================================================================
    
    # Notification preferences
    notification_preferences = Column(JSON, default=dict)
    # Example: {"email_on_scan_complete": true, "slack_webhook": "...", ...}
    
    # Scan preferences
    scan_preferences = Column(JSON, default=dict)
    # Example: {"default_scan_type": "full", "auto_retest": false, ...}
    
    # UI preferences
    ui_preferences = Column(JSON, default=dict)
    # Example: {"theme": "dark", "language": "en", "timezone": "UTC", ...}
    
    # ========================================================================
    # BILLING
    # ========================================================================
    
    stripe_customer_id = Column(String(255), nullable=True, index=True)
    stripe_subscription_id = Column(String(255), nullable=True)
    billing_email = Column(String(255), nullable=True)
    
    # ========================================================================
    # TIMESTAMPS
    # ========================================================================
    
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    # Soft delete
    deleted_at = Column(DateTime, nullable=True, index=True)
    
    # ========================================================================
    # RELATIONSHIPS
    # ========================================================================
    
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    api_tokens = relationship("APIToken", back_populates="user", cascade="all, delete-orphan")
    activities = relationship("UserActivity", back_populates="user", cascade="all, delete-orphan")
    organization_memberships = relationship("OrganizationMember", back_populates="user", cascade="all, delete-orphan")
    
    # ========================================================================
    # INDEXES & CONSTRAINTS
    # ========================================================================
    
    __table_args__ = (
        CheckConstraint('failed_login_attempts >= 0', name='check_failed_attempts'),
        CheckConstraint('login_count >= 0', name='check_login_count'),
        CheckConstraint('storage_used_mb >= 0', name='check_storage_used'),
        Index('idx_user_email_active', email, is_active),
        Index('idx_user_subscription', subscription_tier, subscription_end),
        Index('idx_user_oauth', oauth_provider, oauth_id),
    )
    
    # ========================================================================
    # VALIDATION
    # ========================================================================
    
    @validates('email')
    def validate_email(self, key, email):
        """Validate email format."""
        import re
        if not email or not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ValueError("Invalid email format")
        return email.lower()
    
    @validates('username')
    def validate_username(self, key, username):
        """Validate username format."""
        import re
        if not username or not re.match(r'^[a-zA-Z0-9_-]{3,100}$', username):
            raise ValueError("Username must be 3-100 characters and contain only letters, numbers, underscores, and hyphens")
        return username.lower()
    
    @validates('website')
    def validate_website(self, key, website):
        """Validate website URL."""
        if website:
            import re
            url_pattern = re.compile(
                r'^https?://'
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
                r'localhost|'
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                r'(?::\d+)?'
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            if not url_pattern.match(website):
                raise ValueError("Invalid website URL")
        return website
    
    # ========================================================================
    # AUTHENTICATION METHODS
    # ========================================================================
    
    def record_login(self, ip_address: str, user_agent: str = None):
        """Record successful login."""
        self.last_login_at = datetime.now(timezone.utc)
        self.last_login_ip = ip_address
        self.last_login_user_agent = user_agent
        self.login_count += 1
        self.failed_login_attempts = 0
        self.locked_until = None
        self.lock_reason = None
    
    def record_failed_login(self, max_attempts: int = 5, lockout_minutes: int = 30):
        """Record failed login attempt and lock if needed."""
        self.failed_login_attempts += 1
        
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)
            self.lock_reason = f"Too many failed login attempts ({self.failed_login_attempts})"
    
    def unlock_account(self):
        """Manually unlock account."""
        self.locked_until = None
        self.lock_reason = None
        self.failed_login_attempts = 0
    
    def generate_session_token(self, expires_hours: int = 24) -> str:
        """Generate new session token."""
        token = secrets.token_urlsafe(32)
        self.current_session_token = hashlib.sha256(token.encode()).hexdigest()
        self.session_expires_at = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
        return token
    
    def verify_session_token(self, token: str) -> bool:
        """Verify session token."""
        if not self.current_session_token or not self.session_expires_at:
            return False
        
        if datetime.now(timezone.utc) > self.session_expires_at:
            return False
        
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return token_hash == self.current_session_token
    
    def invalidate_session(self):
        """Invalidate current session."""
        self.current_session_token = None
        self.session_expires_at = None
    
    # ========================================================================
    # MFA METHODS
    # ========================================================================
    
    def enable_mfa(self, method: MFAMethod, secret: str = None):
        """Enable multi-factor authentication."""
        self.mfa_enabled = True
        self.mfa_method = method
        if secret:
            self.mfa_secret = secret
    
    def disable_mfa(self):
        """Disable multi-factor authentication."""
        self.mfa_enabled = False
        self.mfa_method = None
        self.mfa_secret = None
        self.mfa_backup_codes = []
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate MFA backup codes."""
        codes = [secrets.token_hex(4) for _ in range(count)]
        # Hash codes for storage
        self.mfa_backup_codes = [hashlib.sha256(code.encode()).hexdigest() for code in codes]
        return codes
    
    def verify_backup_code(self, code: str) -> bool:
        """Verify and consume a backup code."""
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        if code_hash in self.mfa_backup_codes:
            self.mfa_backup_codes.remove(code_hash)
            return True
        return False
    
    # ========================================================================
    # PASSWORD MANAGEMENT
    # ========================================================================
    
    def generate_password_reset_token(self, expires_hours: int = 24) -> str:
        """Generate password reset token."""
        token = secrets.token_urlsafe(32)
        self.password_reset_token = hashlib.sha256(token.encode()).hexdigest()
        self.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
        return token
    
    def verify_password_reset_token(self, token: str) -> bool:
        """Verify password reset token."""
        if not self.password_reset_token or not self.password_reset_expires:
            return False
        
        if datetime.now(timezone.utc) > self.password_reset_expires:
            return False
        
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return token_hash == self.password_reset_token
    
    def reset_password(self, new_hashed_password: str):
        """Reset password and clear reset token."""
        self.hashed_password = new_hashed_password
        self.password_reset_token = None
        self.password_reset_expires = None
        self.password_changed_at = datetime.now(timezone.utc)
        self.last_password_change = datetime.now(timezone.utc)
        
        # Invalidate session for security
        self.invalidate_session()
    
    # ========================================================================
    # EMAIL VERIFICATION
    # ========================================================================
    
    def generate_email_verification_token(self) -> str:
        """Generate email verification token."""
        token = secrets.token_urlsafe(32)
        self.email_verification_token = hashlib.sha256(token.encode()).hexdigest()
        self.email_verification_sent_at = datetime.now(timezone.utc)
        return token
    
    def verify_email_token(self, token: str) -> bool:
        """Verify email verification token."""
        if not self.email_verification_token:
            return False
        
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        if token_hash == self.email_verification_token:
            self.email_verified = True
            self.email_verification_token = None
            return True
        return False
    
    # ========================================================================
    # ROLE & PERMISSIONS
    # ========================================================================
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        # Admin has all permissions
        if self.role == UserRole.ADMIN:
            return True
        
        # Check role-based permissions
        role_permissions = {
            UserRole.ADMIN: ["*"],
            UserRole.MANAGER: ["scans:*", "users:read", "reports:*"],
            UserRole.SECURITY_ANALYST: ["scans:*", "vulnerabilities:*", "reports:read"],
            UserRole.DEVELOPER: ["scans:create", "scans:read", "vulnerabilities:read"],
            UserRole.VIEWER: ["scans:read", "vulnerabilities:read"],
            UserRole.API_USER: ["api:*"],
            UserRole.GUEST: ["scans:read"],
        }
        
        perms = role_permissions.get(self.role, [])
        
        # Check wildcard
        if "*" in perms:
            return True
        
        # Check specific permission
        if permission in perms:
            return True
        
        # Check custom permissions
        if permission in self.custom_permissions:
            return True
        
        # Check wildcard categories
        category = permission.split(":")[0]
        if f"{category}:*" in perms or f"{category}:*" in self.custom_permissions:
            return True
        
        return False
    
    def add_permission(self, permission: str):
        """Add custom permission."""
        if permission not in self.custom_permissions:
            self.custom_permissions.append(permission)
    
    def remove_permission(self, permission: str):
        """Remove custom permission."""
        if permission in self.custom_permissions:
            self.custom_permissions.remove(permission)
    
    def change_role(self, new_role: UserRole):
        """Change user role."""
        old_role = self.role
        self.role = new_role
        
        # Log activity would happen in application layer
        return old_role, new_role
    
    # ========================================================================
    # QUOTA & USAGE MANAGEMENT
    # ========================================================================
    
    def can_run_scan(self) -> tuple[bool, str]:
        """
        Check if user can run a scan.
        
        Returns:
            tuple: (can_run, reason)
        """
        if not self.is_active:
            return False, "Account is not active"
        
        if self.is_locked:
            return False, "Account is locked"
        
        # Check subscription
        if not self.is_subscription_active and not self.is_trial_active:
            return False, "Subscription expired"
        
        # Check quota
        if self.max_scans_per_month:
            if self.scans_this_month >= self.max_scans_per_month:
                return False, "Monthly scan quota exceeded"
        
        return True, ""
    
    def increment_scan_count(self):
        """Increment scan usage counters."""
        self.scans_this_month += 1
        self.total_scans += 1
    
    def reset_monthly_quota(self):
        """Reset monthly usage quotas."""
        self.scans_this_month = 0
        self.api_calls_this_hour = 0
    
    def can_make_api_call(self) -> bool:
        """Check if user can make API call."""
        if not self.max_api_calls_per_hour:
            return True
        return self.api_calls_this_hour < self.max_api_calls_per_hour
    
    def increment_api_call(self):
        """Increment API call counter."""
        self.api_calls_this_hour += 1
        self.total_api_calls += 1
    
    def check_storage_limit(self, additional_mb: float) -> bool:
        """Check if storage limit allows additional data."""
        return (self.storage_used_mb + additional_mb) <= self.storage_limit_mb
    
    def update_storage_used(self, mb_change: float):
        """Update storage usage."""
        self.storage_used_mb = max(0, self.storage_used_mb + mb_change)
    
    # ========================================================================
    # SUBSCRIPTION MANAGEMENT
    # ========================================================================
    
    def upgrade_subscription(self, tier: SubscriptionTier, duration_days: int = 30):
        """Upgrade subscription tier."""
        self.subscription_tier = tier
        self.subscription_start = datetime.now(timezone.utc)
        self.subscription_end = datetime.now(timezone.utc) + timedelta(days=duration_days)
        
        # Update quotas based on tier
        tier_quotas = {
            SubscriptionTier.FREE: {"scans": 10, "concurrent": 1, "storage": 500},
            SubscriptionTier.STARTER: {"scans": 100, "concurrent": 3, "storage": 5000},
            SubscriptionTier.PROFESSIONAL: {"scans": 500, "concurrent": 10, "storage": 25000},
            SubscriptionTier.ENTERPRISE: {"scans": None, "concurrent": 50, "storage": 100000},
        }
        
        if tier in tier_quotas:
            quotas = tier_quotas[tier]
            self.max_scans_per_month = quotas["scans"]
            self.max_concurrent_scans = quotas["concurrent"]
            self.storage_limit_mb = quotas["storage"]
    
    def start_trial(self, duration_days: int = 14):
        """Start trial period."""
        self.trial_ends_at = datetime.now(timezone.utc) + timedelta(days=duration_days)
        self.subscription_tier = SubscriptionTier.PROFESSIONAL
    
    # ========================================================================
    # ACTIVITY LOGGING
    # ========================================================================
    
    def log_activity(self, activity_type: ActivityType, description: str = None,
                    ip_address: str = None, user_agent: str = None, metadata: dict = None):
        """
        Log user activity.
        
        Note: This creates a UserActivity object that must be added to the session.
        """
        return UserActivity(
            user_id=self.id,
            activity_type=activity_type,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {}
        )
    
    # ========================================================================
    # PROPERTIES
    # ========================================================================
    
    @property
    def is_locked(self) -> bool:
        """Check if account is locked."""
        if self.locked_until and datetime.now(timezone.utc) < self.locked_until:
            return True
        return False
    
    @property
    def is_subscription_active(self) -> bool:
        """Check if subscription is active."""
        if not self.subscription_end:
            return False
        return datetime.now(timezone.utc) < self.subscription_end
    
    @property
    def is_trial_active(self) -> bool:
        """Check if trial is active."""
        if not self.trial_ends_at:
            return False
        return datetime.now(timezone.utc) < self.trial_ends_at
    
    @property
    def subscription_status(self) -> str:
        """Get subscription status."""
        if self.is_trial_active:
            return "trial"
        elif self.is_subscription_active:
            return "active"
        elif self.subscription_end and datetime.now(timezone.utc) > self.subscription_end:
            return "expired"
        else:
            return "none"
    
    @property
    def days_until_expiry(self) -> Optional[int]:
        """Get days until subscription expires."""
        if self.subscription_end:
            delta = self.subscription_end - datetime.now(timezone.utc)
            return max(0, delta.days)
        return None
    
    @property
    def storage_percentage(self) -> float:
        """Get storage usage percentage."""
        if self.storage_limit_mb == 0:
            return 0.0
        return round((self.storage_used_mb / self.storage_limit_mb) * 100, 2)
    
    @property
    def primary_organization(self) -> Optional[Organization]:
        """Get user's primary organization."""
        if self.organization_memberships:
            return self.organization_memberships[0].organization
        return None
    
    @hybrid_property
    def is_deleted(self) -> bool:
        """Check if user is soft-deleted."""
        return self.deleted_at is not None
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def soft_delete(self):
        """Soft delete user account."""
        self.deleted_at = datetime.now(timezone.utc)
        self.is_active = False
        self.invalidate_session()
    
    def restore(self):
        """Restore soft-deleted account."""
        self.deleted_at = None
        self.is_active = True
    
    def to_dict(self, include_sensitive: bool = False, include_relationships: bool = False) -> Dict[str, Any]:
        """
        Convert user to dictionary.
        
        Args:
            include_sensitive: Include sensitive fields (for admin only)
            include_relationships: Include related objects
            
        Returns:
            Dictionary representation
        """
        result = {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'full_name': self.full_name,
            'company': self.company,
            'job_title': self.job_title,
            'avatar_url': self.avatar_url,
            'role': self.role.value,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'email_verified': self.email_verified,
            'mfa_enabled': self.mfa_enabled,
            'subscription_tier': self.subscription_tier.value,
            'subscription_status': self.subscription_status,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None,
        }
        
        # Add usage stats
        result['usage'] = {
            'scans_this_month': self.scans_this_month,
            'total_scans': self.total_scans,
            'storage_used_mb': self.storage_used_mb,
            'storage_limit_mb': self.storage_limit_mb,
            'storage_percentage': self.storage_percentage,
        }
        
        # Add sensitive fields if requested (admin only)
        if include_sensitive:
            result['last_login_ip'] = self.last_login_ip
            result['failed_login_attempts'] = self.failed_login_attempts
            result['is_locked'] = self.is_locked
            result['lock_reason'] = self.lock_reason
            result['suspicious_activity_count'] = self.suspicious_activity_count
        
        # Add relationships if requested
        if include_relationships:
            result['api_tokens'] = [
                {'name': t.name, 'prefix': t.token_prefix, 'created_at': t.created_at.isoformat()}
                for t in self.api_tokens if t.is_active
            ]
            result['organizations'] = [
                {'id': m.organization.id, 'name': m.organization.name, 'role': m.role.value}
                for m in self.organization_memberships
            ]
        
        return result
    
    def __repr__(self):
        return f"<User {self.username} ({self.email})>"


# ============================================================================
# EVENT LISTENERS
# ============================================================================

@event.listens_for(User, 'before_update')
def update_user_timestamp(mapper, connection, target):
    """Update timestamp on user modification."""
    target.updated_at = datetime.now(timezone.utc)


@event.listens_for(Organization, 'before_update')
def update_org_timestamp(mapper, connection, target):
    """Update timestamp on organization modification."""
    target.updated_at = datetime.now(timezone.utc)