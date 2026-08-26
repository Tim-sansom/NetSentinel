"""
NetSentinel Agent Logging Subsystem

Configures a centralized, structured logging system for the agent.
Uses Python's built-in logging module with a RotatingFileHandler to
ensure that log files do not consume all available disk space on the
endpoint, a critical requirement for lightweight SME agents (NFR1).
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Optional


def setup_logger(
    name: str = "netsentinel",
    log_level: str = "INFO",
    log_dir: Optional[Path] = None
) -> logging.Logger:
    """
    Set up and return a configured logger with both console and file outputs.
    
    Args:
        name: The name of the logger (used to identify the source in log records).
        log_level: The minimum severity level to log (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_dir: The directory where log files will be stored. Defaults to a 'logs' folder 
                 in the same directory as this script.
                 
    Returns:
        A configured Python logging.Logger instance.
    """
    # Create or retrieve the logger instance
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    # Guard clause: If handlers are already attached, return the existing logger.
    # This prevents duplicate log entries if the function is called multiple times.
    if logger.handlers:
        return logger
        
    # Set log directory and ensure it exists
    if log_dir is None:
        log_dir = Path(__file__).parent / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Define a consistent, readable log format
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # --- Console Handler ---
    # Outputs logs to stdout so they can be seen when running the agent manually
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG) # Capture everything for the console
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # --- File Handler (Rotating) ---
    # Rotates the log file when it reaches 10MB, keeping 5 backup files.
    # This prevents the agent from filling up the endpoint's hard drive over time.
    file_handler = RotatingFileHandler(
        log_dir / 'agent.log',
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    return logger