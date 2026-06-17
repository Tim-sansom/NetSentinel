"""
NetSentinel Agent - Main Entry Point
Orchestrates security checks and submits results to the backend API.
"""
import sys
import time
import signal
import argparse
from pathlib import Path
from typing import Optional
from datetime import datetime

from config import AgentConfig
from logger import setup_logger
from api_client import ApiClient
from checks.base_check import CheckResult


class NetSentinelAgent:
    """Main agent class that orchestrates security health checks."""
    
    def __init__(self, config: AgentConfig):
        """
        Initialize the agent.
        
        Args:
            config: Validated agent configuration.
        """
        self.config = config
        self.logger = setup_logger(
            name="netsentinel.agent",
            log_level=config.log_level
        )
        self.api_client = ApiClient(
            api_url=config.api_url,
            api_token=config.api_token,
            timeout=config.timeout,
            verify_ssl=config.verify_ssl
        )
        
        # Flag for graceful shutdown
        self.running = False
        
        # Import checks dynamically
        self.checks = self._load_checks()
    
    def _load_checks(self) -> list:
        """
        Load all available security checks.
        
        Returns:
            List of check instances.
        """
        from checks.system_info import SystemInfoCheck
        from checks.port_check import PortCheck
        from checks.firewall_check import FirewallCheck
        from checks.latency_check import LatencyCheck
        
        checks = [
            SystemInfoCheck(),
            PortCheck(),
            FirewallCheck(),
            LatencyCheck(target=self.config.api_url)
        ]
        
        self.logger.info(f"Loaded {len(checks)} security checks")
        return checks
    
    def run_checks(self) -> list[CheckResult]:
        """
        Execute all security checks.
        
        Returns:
            List of check results.
        """
        results = []
        
        self.logger.info("Starting security health checks...")
        
        for check in self.checks:
            try:
                self.logger.debug(f"Running check: {check.name}")
                result = check.check()
                results.append(result)
                
                # Log result summary
                status_emoji = {
                    'pass': '✓',
                    'fail': '✗',
                    'warning': '⚠',
                    'error': '⚠'
                }.get(result.status, '?')
                
                self.logger.info(
                    f"{status_emoji} {check.name}: {result.status} - {result.message}"
                )
                
            except Exception as e:
                # Catch any unexpected errors in checks
                self.logger.error(f"Check {check.name} failed with exception: {str(e)}")
                results.append(CheckResult(
                    check_name=check.name,
                    status='error',
                    message=f"Check execution failed: {str(e)}",
                    severity='high',
                    details={'exception': str(e)}
                ))
        
        self.logger.info(f"Completed {len(results)} checks")
        return results
    
    def submit_results(self, results: list[CheckResult]) -> bool:
        """
        Submit check results to the backend API.
        
        Args:
            results: List of check results to submit.
        
        Returns:
            True if submission was successful.
        """
        try:
            # Convert CheckResult objects to dictionaries
            results_dict = [result.to_dict() for result in results]
            
            response = self.api_client.submit_check_results(
                device_uuid=self.config.device_uuid,
                check_results=results_dict
            )
            
            self.logger.info(f"Successfully submitted results to API: {response.get('message', '')}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to submit results to API: {str(e)}")
            return False
    
    def run_once(self) -> bool:
        """
        Run a single check cycle.
        
        Returns:
            True if the cycle completed successfully.
        """
        start_time = datetime.utcnow()
        self.logger.info(f"=== Check cycle started at {start_time.isoformat()} ===")
        
        try:
            # Run all checks
            results = self.run_checks()
            
            # Submit results to API
            success = self.submit_results(results)
            
            # Calculate duration
            duration = (datetime.utcnow() - start_time).total_seconds()
            self.logger.info(f"=== Check cycle completed in {duration:.2f}s ===")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Check cycle failed: {str(e)}")
            return False
    
    def run_continuous(self):
        """Run the agent continuously at configured intervals."""
        self.running = True
        self.logger.info(f"Agent started in continuous mode (interval: {self.config.check_interval}s)")
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        try:
            while self.running:
                cycle_start = datetime.utcnow()
                
                # Run one check cycle
                self.run_once()
                
                # Calculate sleep time
                cycle_duration = (datetime.utcnow() - cycle_start).total_seconds()
                sleep_time = max(0, self.config.check_interval - cycle_duration)
                
                if self.running and sleep_time > 0:
                    self.logger.debug(f"Sleeping for {sleep_time:.0f}s until next check...")
                    time.sleep(sleep_time)
                    
        except Exception as e:
            self.logger.error(f"Agent encountered fatal error: {str(e)}")
            raise
        finally:
            self.logger.info("Agent shutdown complete")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False


def main():
    """Main entry point for the agent."""
    parser = argparse.ArgumentParser(
        description='NetSentinel Security Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --once          Run a single check cycle
  python agent.py --continuous    Run continuously (default)
  python agent.py --config /path/to/.env
        """
    )
    
    parser.add_argument(
        '--once',
        action='store_true',
        help='Run a single check cycle and exit'
    )
    
    parser.add_argument(
        '--continuous',
        action='store_true',
        help='Run continuously at configured intervals (default)'
    )
    
    parser.add_argument(
        '--config-dir',
        type=Path,
        default=None,
        help='Directory containing .env configuration file'
    )
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        config = AgentConfig(config_dir=args.config_dir)
        
        # Validate configuration
        config.validate()
        
        # Create and run agent
        agent = NetSentinelAgent(config)
        
        if args.once:
            # Run once and exit
            success = agent.run_once()
            sys.exit(0 if success else 1)
        else:
            # Run continuously (default)
            agent.run_continuous()
            
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAgent interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()