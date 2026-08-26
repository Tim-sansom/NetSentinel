"""
NetSentinel Security Checks Module

This package contains the modular security health checks executed by the 
NetSentinel agent. Each check inherits from BaseCheck and returns a 
standardized CheckResult object, ensuring a consistent contract between 
the agent orchestrator and the individual telemetry collectors.
"""

from .base_check import BaseCheck, CheckResult

# Explicitly define the public API of this module
__all__ = ['BaseCheck', 'CheckResult']