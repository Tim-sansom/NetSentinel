"""
Base Check Class
All security health checks inherit from this base class.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class CheckResult:
    """Result of a security health check."""
    
    check_name: str
    status: str  # 'pass', 'fail', 'warning', 'error'
    message: str
    severity: str = 'info'  # 'low', 'medium', 'high', 'critical'
    timestamp: datetime = field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for JSON serialization."""
        return {
            'check_name': self.check_name,
            'status': self.status,
            'message': self.message,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details
        }


class BaseCheck(ABC):
    """
    Abstract base class for all security health checks.
    
    Each check should:
    1. Inherit from BaseCheck
    2. Implement the check() method
    3. Return a CheckResult instance
    """
    
    def __init__(self, name: str, description: str):
        """
        Initialize the check.
        
        Args:
            name: Short name of the check.
            description: Human-readable description.
        """
        self.name = name
        self.description = description
    
    @abstractmethod
    def check(self) -> CheckResult:
        """
        Perform the security check.
        
        Returns:
            CheckResult with status, message, and optional details.
        """
        pass
    
    def get_metadata(self) -> Dict[str, str]:
        """Return metadata about this check."""
        return {
            'name': self.name,
            'description': self.description
        }