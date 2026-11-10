"""
NetSentinel Agent - Main Entry Point
This module acts as the central orchestrator for the NetSentinel endpoint agent.
It is responsible for loading security checks based on the configuration,
executing them in a controlled environment, and securely submitting the
aggregated results to the backend API.
Designed to be lightweight and resilient, ensuring that a failure in one
check does not prevent the rest of the telemetry from being reported.
"""
import sys
import time
import signal
import argparse
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone
from config import AgentConfig
from logger import setup_logger
from api_client import ApiClient
from checks.base_check import CheckResult

class NetSentinelAgent:
    """
    The core orchestrator for the NetSentinel agent.
    Manages the lifecycle of security checks, handles API communication, 
    and ensures the agent runs continuously or as a single shot based 
    on CLI arguments.
    """
    def __init__(self, config: AgentConfig):
        """
        Initialize the agent with the provided configuration.
        Args:
            config: A validated AgentConfig object containing API URLs, 
                    tokens, and feature toggles.
        """
        self.config = config
        # Initialize the centralized logger
        self.logger = setup_logger(
            name="netsentinel.agent",
            log_level=config.log_level
        )
        # Initialize the secure API client
        self.api_client = ApiClient(
            api_url=config.api_url,
            api_token=config.api_token,
            timeout=config.timeout,
            verify_ssl=config.verify_ssl
        )
        # Flag used for graceful shutdown via OS signals
        self.running = False
        # Dynamically load the checks enabled in the config
        self.checks = self._load_checks()

    def _load_checks(self) -> list:
        """
        Load and instantiate the security checks based on the configuration.
        Uses dynamic imports to keep the agent modular. If a specific check 
        module is missing or fails to import, it logs a warning and continues 
        rather than crashing the entire agent.
        Returns:
            A list of instantiated check objects inheriting from BaseCheck.
        """
        checks = []
        # --- Core Checks (Always enabled for MVP) ---
        from checks.system_info import SystemInfoCheck
        from checks.port_check import PortCheck
        from checks.firewall_check import FirewallCheck
        from checks.latency_check import LatencyCheck
        from checks.patch_check import PatchCheck
        
        checks.append(SystemInfoCheck())
        checks.append(PortCheck())
        checks.append(FirewallCheck())
        # Latency check needs the API URL to ping the backend
        checks.append(LatencyCheck(target=self.config.api_url))
        checks.append(PatchCheck())

        # --- Optional: Log Anomaly Check (Lightweight SIEM) ---
        if self.config.enable_log_check:
            try:
                from checks.log_check import LogCheck
                checks.append(LogCheck())
                self.logger.info("LogCheck enabled successfully.")
            except ImportError:
                self.logger.warning("LogCheck module not found, skipping.")

        # --- Optional: Anomaly/Persistence Check ---
        if self.config.enable_anomaly_check:
            try:
                from checks.anomaly_check import AnomalyCheck
                checks.append(AnomalyCheck())
                self.logger.info("AnomalyCheck enabled successfully.")
            except ImportError:
                self.logger.warning("AnomalyCheck module not found, skipping.")

        self.logger.info(f"Loaded {len(checks)} security checks.")
        return checks

    def run_checks(self) -> list[CheckResult]:
        """
        Execute all loaded security checks sequentially.
        Wraps each check in a try-except block to ensure that if one check 
        fails unexpectedly, the agent can still report the results of the 
        other checks and log the error.
        Returns:
            A list of CheckResult objects containing the telemetry data.
        """
        results = []
        self.logger.info("Starting security health checks...")
        for check in self.checks:
            try:
                self.logger.debug(f"Running check: {check.name}")
                result = check.check()
                results.append(result)
                # Format a clean, readable log line for the console
                status_emoji = {
                    'pass': '[PASS]',
                    'fail': '[FAIL]',
                    'warning': '[WARN]',
                    'error': '[ERR]'
                }.get(result.status, '[?]')
                self.logger.info(
                    f"{status_emoji} {check.name}: {result.status.upper()} - {result.message}"
                )
            except Exception as e:
                # Catch unexpected errors to prevent the agent from crashing
                self.logger.error(f"Check {check.name} failed with exception: {str(e)}")
                results.append(CheckResult(
                    check_name=check.name,
                    status='error',
                    message=f"Check execution failed: {str(e)}",
                    severity='high',
                    details={'exception': str(e)}
                ))
        self.logger.info(f"Completed {len(results)} checks.")
        return results

    def submit_results(self, results: list[CheckResult]) -> bool:
        """
        Serialize and submit the check results to the backend API.
        Args:
            results: The list of CheckResult objects to send.
        Returns:
            True if the API acknowledged the submission successfully.
        """
        try:
            # Convert our custom objects into JSON-serializable dictionaries
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
        Execute a single full cycle of checks and submission.
        Returns:
            True if the cycle completed and submitted successfully.
        """
        # Use timezone-aware UTC time to ensure consistency with the PHP backend
        start_time = datetime.now(timezone.utc)
        self.logger.info(f"=== Check cycle started at {start_time.isoformat()} ===")
        try:
            results = self.run_checks()
            success = self.submit_results(results)
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            self.logger.info(f"=== Check cycle completed in {duration:.2f}s ===")
            return success
        except Exception as e:
            self.logger.error(f"Check cycle failed catastrophically: {str(e)}")
            return False

    def run_continuous(self):
        """
        Run the agent in an infinite loop, sleeping between cycles.
        Calculates the exact sleep time needed to maintain a fixed interval 
        (e.g., 300 seconds), regardless of how long the checks actually took to run.
        """
        self.running = True
        self.logger.info(f"Agent started in continuous mode (interval: {self.config.check_interval}s)")
        # Register OS signal handlers for graceful shutdown (Ctrl+C or kill command)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        try:
            while self.running:
                cycle_start = datetime.now(timezone.utc)
                # Execute the telemetry cycle
                self.run_once()
                # Calculate how long we need to sleep to hit the exact interval
                cycle_duration = (datetime.now(timezone.utc) - cycle_start).total_seconds()
                sleep_time = max(0, self.config.check_interval - cycle_duration)
                if self.running and sleep_time > 0:
                    self.logger.debug(f"Sleeping for {sleep_time:.0f}s until next check...")
                    time.sleep(sleep_time)
        except Exception as e:
            self.logger.error(f"Agent encountered fatal error in continuous loop: {str(e)}")
            raise
        finally:
            self.logger.info("Agent shutdown complete.")

    def _signal_handler(self, signum, frame):
        """
        Handle OS shutdown signals gracefully.
        Instead of crashing, this sets the running flag to False, allowing 
        the current check cycle to finish before the agent exits cleanly.
        """
        self.logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        self.running = False

def main():
    """
    Main entry point for the NetSentinel agent CLI.
    Parses command-line arguments, loads the configuration, and starts 
    the agent in either single-shot or continuous mode.
    """
    parser = argparse.ArgumentParser(
        description='NetSentinel Security Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --once          Run a single check cycle and exit
  python agent.py --continuous    Run continuously at configured intervals (default)
  python agent.py --config-dir /path/to/config
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
        help='Directory containing the .env configuration file'
    )
    args = parser.parse_args()
    
    try:
        # Load and validate configuration before doing anything else
        config = AgentConfig(config_dir=args.config_dir)
        config.validate()
        
        # Instantiate and run the agent
        agent = NetSentinelAgent(config)
        
        if args.once:
            success = agent.run_once()
            sys.exit(0 if success else 1)
        else:
            agent.run_continuous()
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAgent interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()