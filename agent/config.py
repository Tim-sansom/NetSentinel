"""
NetSentinel Agent Configuration Manager

Handles the loading, parsing, and validation of agent settings.
Configuration is primarily driven by environment variables or a .env file,
ensuring that sensitive credentials (like API tokens) are never hardcoded
into the source code. This aligns with the 12-Factor App methodology
and basic security best practices for endpoint agents.
"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv


class AgentConfig:
    """
    Central configuration object for the NetSentinel agent.
    
    Parses environment variables and provides sensible defaults for
    optional settings, allowing the agent to run 'out of the box'
    in standard SME environments without complex setup.
    """

    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize configuration by loading the .env file and parsing variables.
        
        Args:
            config_dir: Directory containing the .env file. 
                        Defaults to the directory where this script resides.
        """
        if config_dir is None:
            config_dir = Path(__file__).parent
            
        # Load environment variables from .env file if it exists
        env_file = config_dir / '.env'
        if env_file.exists():
            load_dotenv(env_file)
            
        # --- Required configuration (Must be present for the agent to function) ---
        self.api_url: str = os.getenv('NETSENTINEL_API_URL', '').strip()
        self.api_token: str = os.getenv('NETSENTINEL_API_TOKEN', '').strip()
        self.device_uuid: str = os.getenv('NETSENTINEL_DEVICE_UUID', '').strip()
        
        # --- Optional configuration with sensible defaults for SMEs ---
        # 300 seconds = 5 minutes, a standard interval for lightweight monitoring
        self.check_interval: int = int(os.getenv('NETSENTINEL_CHECK_INTERVAL', '300'))
        self.timeout: int = int(os.getenv('NETSENTINEL_REQUEST_TIMEOUT', '30'))
        self.log_level: str = os.getenv('NETSENTINEL_LOG_LEVEL', 'INFO').upper()
        
        # SSL verification is enabled by default for production, but can be 
        # disabled for local lab environments using self-signed certificates.
        self.verify_ssl: bool = os.getenv('NETSENTINEL_VERIFY_SSL', 'true').lower() == 'true'
        
        # --- Check module toggles ---
        # Allows SME admins to disable specific checks to save CPU/RAM (NFR1 compliance)
        self.enable_system_check: bool = os.getenv('NETSENTINEL_ENABLE_SYSTEM_CHECK', 'true').lower() == 'true'
        self.enable_port_check: bool = os.getenv('NETSENTINEL_ENABLE_PORT_CHECK', 'true').lower() == 'true'
        self.enable_firewall_check: bool = os.getenv('NETSENTINEL_ENABLE_FIREWALL_CHECK', 'true').lower() == 'true'
        self.enable_latency_check: bool = os.getenv('NETSENTINEL_ENABLE_LATENCY_CHECK', 'true').lower() == 'true'
        self.enable_log_check: bool = os.getenv('NETSENTINEL_ENABLE_LOG_CHECK', 'true').lower() == 'true'
        self.enable_anomaly_check: bool = os.getenv('NETSENTINEL_ENABLE_ANOMALY_CHECK', 'true').lower() == 'true'
        self.enable_software_check: bool = os.getenv('NETSENTINEL_ENABLE_SOFTWARE_CHECK', 'true').lower() == 'true'
        
        # --- Derived configuration (Calculated at runtime) ---
        self.agent_version: str = "1.0.0"
        self.agent_platform: str = self._detect_platform()

    def _detect_platform(self) -> str:
        """
        Detect the operating system platform of the endpoint.
        
        Returns:
            A lowercase string representing the OS ('windows', 'linux', 'macos', or 'unknown').
        """
        import platform
        system = platform.system().lower()
        
        if system == 'windows':
            return 'windows'
        elif system == 'linux':
            return 'linux'
        elif system == 'darwin':
            return 'macos'
        else:
            return 'unknown'

    def validate(self) -> bool:
        """
        Validate that all required configuration parameters are present and correctly formatted.
        
        Returns:
            True if configuration is valid.
            
        Raises:
            ValueError: If required configuration is missing or the API URL is malformed.
        """
        missing = []
        if not self.api_url:
            missing.append('NETSENTINEL_API_URL')
        if not self.api_token:
            missing.append('NETSENTINEL_API_TOKEN')
        if not self.device_uuid:
            missing.append('NETSENTINEL_DEVICE_UUID')
            
        if missing:
            raise ValueError(f"Missing required configuration: {', '.join(missing)}")
            
        # Validate API URL format to prevent malformed requests or SSRF attempts
        if not self.api_url.startswith(('http://', 'https://')):
            raise ValueError("NETSENTINEL_API_URL must start with http:// or https://")
            
        return True

    def __repr__(self) -> str:
        """
        Return a string representation of the configuration for debugging purposes.
        Note: Intentionally excludes the api_token to prevent accidental logging of secrets.
        """
        return (f"AgentConfig(api_url='{self.api_url}', device_uuid='{self.device_uuid}', "
                f"platform='{self.agent_platform}', interval={self.check_interval}s)")