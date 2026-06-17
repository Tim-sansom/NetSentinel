"""
NetSentinel Agent Configuration
Loads and validates configuration from environment variables and config file.
"""
import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv


class AgentConfig:
    """Configuration manager for the NetSentinel agent."""
    
    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize configuration.
        
        Args:
            config_dir: Directory containing .env file. Defaults to agent directory.
        """
        if config_dir is None:
            config_dir = Path(__file__).parent
        
        # Load environment variables from .env file
        env_file = config_dir / '.env'
        if env_file.exists():
            load_dotenv(env_file)
        
        # Required configuration
        self.api_url: str = os.getenv('NETSENTINEL_API_URL', '').strip()
        self.api_token: str = os.getenv('NETSENTINEL_API_TOKEN', '').strip()
        self.device_uuid: str = os.getenv('NETSENTINEL_DEVICE_UUID', '').strip()
        
        # Optional configuration with sensible defaults
        self.check_interval: int = int(os.getenv('NETSENTINEL_CHECK_INTERVAL', '300'))  # 5 minutes
        self.timeout: int = int(os.getenv('NETSENTINEL_REQUEST_TIMEOUT', '30'))  # seconds
        self.log_level: str = os.getenv('NETSENTINEL_LOG_LEVEL', 'INFO').upper()
        self.verify_ssl: bool = os.getenv('NETSENTINEL_VERIFY_SSL', 'true').lower() == 'true'
        
        # Derived configuration
        self.agent_version: str = "1.0.0"
        self.agent_platform: str = self._detect_platform()
    
    def _detect_platform(self) -> str:
        """Detect the operating system platform."""
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
        Validate that all required configuration is present.
        
        Returns:
            True if configuration is valid.
            
        Raises:
            ValueError: If required configuration is missing.
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
        
        # Validate API URL format
        if not self.api_url.startswith(('http://', 'https://')):
            raise ValueError("NETSENTINEL_API_URL must start with http:// or https://")
        
        return True
    
    def __repr__(self) -> str:
        return (f"AgentConfig(api_url='{self.api_url}', device_uuid='{self.device_uuid}', "
                f"platform='{self.agent_platform}', interval={self.check_interval}s)")