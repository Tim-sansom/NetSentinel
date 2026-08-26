"""
NetSentinel API Client

Manages all outbound HTTPS communication between the endpoint agent 
and the NetSentinel backend API. 

Handles session management, authentication headers, SSL verification 
toggling (for lab environments), and robust error translation so the 
main agent knows exactly why a request failed.
"""

import requests
import json
from typing import Dict, Any
from datetime import datetime, timezone


class ApiClient:
    """
    A robust HTTP client for communicating with the NetSentinel backend.
    
    Uses a persistent requests.Session to reuse TCP connections and 
    automatically inject authentication headers into every request.
    """

    def __init__(self, api_url: str, api_token: str, timeout: int = 30, verify_ssl: bool = True):
        """
        Initialize the API client.
        
        Args:
            api_url: The base URL of the backend API (e.g., 'https://192.168.1.10/api').
            api_token: The bearer token for authenticating the agent.
            timeout: The maximum time in seconds to wait for a server response.
            verify_ssl: If False, disables SSL certificate verification. 
                        Used primarily for local lab environments with self-signed certs.
        """
        self.api_url = api_url.rstrip('/')
        self.api_token = api_token
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Set up a persistent session with standard headers
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json',
            'User-Agent': 'NetSentinel-Agent/1.0.0'
        })
        
        # Suppress the noisy InsecureRequestWarning if the user has disabled SSL verification
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def submit_check_results(
        self,
        device_uuid: str,
        check_results: list[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Submit a batch of security check results to the backend API.
        
        Args:
            device_uuid: The unique identifier for the endpoint device.
            check_results: A list of dictionaries containing the telemetry data.
            
        Returns:
            The parsed JSON response from the API.
            
        Raises:
            requests.RequestException: If there is a network-level failure.
            ValueError: If the API returns a logical error or malformed JSON.
        """
        payload = {
            'device_uuid': device_uuid,
            'timestamp': datetime.now(timezone.utc).isoformat(),
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
            
            # Raise an exception for 4xx or 5xx HTTP status codes
            response.raise_for_status()
            
            # Parse the JSON response
            try:
                result = response.json()
            except json.JSONDecodeError:
                raise ValueError(f"Invalid JSON response from API: {response.text[:200]}")
                
            # Check for application-level errors (e.g., API returns 200 but success=False)
            if result.get('success') is False:
                error_msg = result.get('error', 'Unknown API error')
                raise ValueError(f"API error: {error_msg}")
                
            return result
            
        except requests.exceptions.SSLError as e:
            # Provide a helpful hint if SSL fails, as this is common in lab setups
            raise requests.exceptions.SSLError(
                f"SSL certificate verification failed. "
                f"Ensure the server has a valid certificate or set verify_ssl=False in config. "
                f"Details: {str(e)}"
            )
        except requests.exceptions.ConnectionError as e:
            raise requests.exceptions.ConnectionError(
                f"Cannot connect to API at {url}. "
                f"Check that the server is running and reachable. Details: {str(e)}"
            )
        except requests.exceptions.Timeout:
            raise requests.exceptions.Timeout(
                f"Request to API timed out after {self.timeout} seconds."
            )

    def test_connection(self) -> bool:
        """
        Perform a lightweight health check against the API endpoint.
        
        Returns:
            True if the server responds with a 200 (OK) or 405 (Method Not Allowed).
        """
        url = f'{self.api_url}/submit.php'
        
        # We use GET here just to test connectivity; the endpoint expects POST, 
        # so a 405 Method Not Allowed actually means the server is alive.
        response = self.session.get(
            url,
            timeout=10,
            verify=self.verify_ssl
        )
        
        if response.status_code in [200, 405]:
            return True
            
        response.raise_for_status()
        return False