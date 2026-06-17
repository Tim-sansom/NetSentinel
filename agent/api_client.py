"""
NetSentinel API Client
Handles secure HTTPS communication with the backend API.
"""
import requests
from typing import Dict, Any, Optional
from datetime import datetime
import json


class ApiClient:
    """Client for communicating with the NetSentinel backend API."""
    
    def __init__(self, api_url: str, api_token: str, timeout: int = 30, verify_ssl: bool = True):
        """
        Initialize the API client.
        
        Args:
            api_url: Base URL of the API (e.g., 'https://example.com/api').
            api_token: Bearer token for authentication.
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.api_url = api_url.rstrip('/')
        self.api_token = api_token
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Set up session with common headers
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json',
            'User-Agent': 'NetSentinel-Agent/1.0.0'
        })
        
        if not verify_ssl:
            # Disable SSL verification warnings if configured
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def submit_check_results(
        self,
        device_uuid: str,
        check_results: list[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Submit security check results to the API.
        
        Args:
            device_uuid: Unique identifier for the endpoint device.
            check_results: List of check result dictionaries.
        
        Returns:
            API response as dictionary.
        
        Raises:
            requests.RequestException: If the request fails.
            ValueError: If the API returns an error response.
        """
        payload = {
            'device_uuid': device_uuid,
            'timestamp': datetime.utcnow().isoformat(),
            'checks': check_results
        }
        
        url = f'{self.api_url}/submit.php'
        
        try:
            response = self.session.post(
                url,
                json=payload,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            # Raise exception for HTTP error codes
            response.raise_for_status()
            
            # Parse JSON response
            try:
                result = response.json()
            except json.JSONDecodeError:
                raise ValueError(f"Invalid JSON response from API: {response.text[:200]}")
            
            # Check for application-level errors
            if result.get('success') is False:
                error_msg = result.get('error', 'Unknown API error')
                raise ValueError(f"API error: {error_msg}")
            
            return result
            
        except requests.exceptions.SSLError as e:
            raise requests.exceptions.SSLError(
                f"SSL certificate verification failed. "
                f"Ensure the server has a valid certificate or set verify_ssl=False for testing. "
                f"Details: {str(e)}"
            )
        except requests.exceptions.ConnectionError as e:
            raise requests.exceptions.ConnectionError(
                f"Cannot connect to API at {url}. "
                f"Check that the server is running and reachable. "
                f"Details: {str(e)}"
            )
        except requests.exceptions.Timeout:
            raise requests.exceptions.Timeout(
                f"Request to API timed out after {self.timeout} seconds"
            )
    
    def test_connection(self) -> bool:
        """
        Test basic connectivity to the API.
        
        Returns:
            True if connection is successful.
        
        Raises:
            requests.RequestException: If connection fails.
        """
        url = f'{self.api_url}/submit.php'
        
        # Send a minimal test request
        response = self.session.get(
            url,
            timeout=10,
            verify=self.verify_ssl
        )
        
        # We expect either 200 (success) or 405 (method not allowed for GET)
        if response.status_code in [200, 405]:
            return True
        
        response.raise_for_status()
        return False