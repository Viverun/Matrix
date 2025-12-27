"""
Structured logging configuration for the Matrix security scanner.

This module provides a centralized logging setup with consistent formatting,
context tags, and appropriate log levels for all core components.
"""
import logging
import sys
from typing import Optional
from datetime import datetime, timezone


class ColoredFormatter(logging.Formatter):
    """
    Custom formatter that adds colors to log levels for better readability.
    """
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with colors and structured information.
        
        Args:
            record: The log record to format.
            
        Returns:
            A formatted, colored log string.
        """
        # Add color to level name
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{self.BOLD}{levelname}{self.RESET}"
        
        # Format timestamp in UTC
        record.timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        
        # Add module context in brackets
        record.context = f"[{record.name}]"
        
        return super().format(record)


class StructuredLogger(logging.Logger):
    """
    Enhanced logger with additional utility methods for structured logging.
    """
    
    def log_api_request(
        self, 
        provider: str, 
        endpoint: str, 
        status_code: Optional[int] = None,
        duration_ms: Optional[float] = None
    ) -> None:
        """
        Log an API request with structured information.
        
        Args:
            provider: The API provider name (e.g., "Hugging Face II", "Hugging Face").
            endpoint: The API endpoint being called.
            status_code: HTTP status code if available.
            duration_ms: Request duration in milliseconds if available.
        """
        parts = [f"API Request: {provider} -> {endpoint}"]
        
        if status_code is not None:
            parts.append(f"Status: {status_code}")
        
        if duration_ms is not None:
            parts.append(f"Duration: {duration_ms:.2f}ms")
        
        self.info(" | ".join(parts))
    
    def log_security_event(
        self, 
        event_type: str, 
        severity: str, 
        details: str
    ) -> None:
        """
        Log a security-related event with appropriate severity.
        
        Args:
            event_type: Type of security event (e.g., "VULN_DETECTED", "SCAN_COMPLETE").
            severity: Security severity level.
            details: Additional event details.
        """
        message = f"Security Event: {event_type} | Severity: {severity} | {details}"
        
        # Route to appropriate log level based on severity
        if severity.upper() in ('CRITICAL', 'HIGH'):
            self.warning(message)
        else:
            self.info(message)
    
    def log_scan_progress(
        self, 
        step: str, 
        progress: Optional[int] = None,
        total: Optional[int] = None
    ) -> None:
        """
        Log scan progress information.
        
        Args:
            step: Description of the current scan step.
            progress: Current progress count if applicable.
            total: Total items to process if applicable.
        """
        parts = [f"Scan Progress: {step}"]
        
        if progress is not None and total is not None:
            percentage = (progress / total * 100) if total > 0 else 0
            parts.append(f"({progress}/{total} - {percentage:.1f}%)")
        
        self.info(" ".join(parts))


# Configure the logging system
def setup_logging(level: str = "INFO") -> None:
    """
    Configure the global logging system with structured formatting.
    
    Args:
        level: The minimum log level to display (DEBUG, INFO, WARNING, ERROR, CRITICAL).
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)
    
    # Create and set formatter
    formatter = ColoredFormatter(
        fmt='%(timestamp)s | %(levelname)s | %(context)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    root_logger.handlers = []  # Clear existing handlers
    root_logger.addHandler(handler)
    
    # Reduce noise from third-party libraries
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('httpcore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)


def get_logger(name: str) -> StructuredLogger:
    """
    Get or create a structured logger for a module.
    
    Args:
        name: The logger name, typically __name__ of the calling module.
        
    Returns:
        A configured StructuredLogger instance.
    """
    # Set the custom logger class
    logging.setLoggerClass(StructuredLogger)
    
    # Get the logger
    logger = logging.getLogger(name)
    
    # Ensure it's using our custom class
    if not isinstance(logger, StructuredLogger):
        # Re-create with correct class
        logging.setLoggerClass(StructuredLogger)
        logger = logging.getLogger(name)
    
    return logger


# Auto-setup logging when module is imported
setup_logging()