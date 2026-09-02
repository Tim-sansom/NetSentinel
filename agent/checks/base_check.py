"""
Base Check Class & Result Dataclass

Defines the foundational contract for all security health checks.
By using the Strategy Pattern via an Abstract Base Class (ABC), we ensure 
that every new check added to the agent follows a strict, predictable 
structure. This makes the main agent loop simple, robust, and easy to extend.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict


@dataclass
class CheckResult:
    """
    Standardized data structure for the outcome of a security check.
    
    Using a dataclass ensures that results are lightweight, easy to instantiate,
    and automatically support clean dictionary conversion for JSON serialisation.
    """
    check_name: str
    status: str  # Expected values: 'pass', 'fail', 'warning', 'error'
    message: str
    severity: str = 'info'  # Expected values: 'low', 'medium', 'high', 'critical'
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the CheckResult instance to a dictionary for JSON serialisation.
        
        Returns:
            A dictionary representation of the check result, with the timestamp 
            formatted as an ISO 8601 string for PHP/MySQL compatibility.
        """
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
    
    Any new security check added to NetSentinel must:
    1. Inherit from BaseCheck.
    2. Call super().__init__() with a name and description.
    3. Implement the abstract check() method.
    4. Return a CheckResult instance (never raw lists or dicts).
    """

    def __init__(self, name: str, description: str):
        """
        Initialize the base check with metadata.
        
        Args:
            name: A short, snake_case identifier for the check (e.g., 'port_check').
            description: A human-readable explanation of what the check does.
        """
        self.name = name
        self.description = description

    @abstractmethod
    def check(self) -> CheckResult:
        """
        Perform the actual security inspection.
        
        This method must be implemented by all subclasses. It should execute 
        quickly and handle its own internal exceptions, returning a CheckResult 
        with status='error' if it fails, rather than crashing the main agent.
        
        Returns:
            A CheckResult object containing the telemetry data.
        """
        pass

    def get_metadata(self) -> Dict[str, str]:
        """
        Return a dictionary of metadata about this check.
        
        Useful for logging or for the API to understand what checks 
        are available on a specific endpoint.
        
        Returns:
            Dictionary containing 'name' and 'description'.
        """
        return {
            'name': self.name,
            'description': self.description
        }