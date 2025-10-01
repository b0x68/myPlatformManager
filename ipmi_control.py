#!/usr/bin/python3.12
"""
IPMI Control Script for Cluster Nodes
-------------------------------------

This script provides IPMI management capabilities for cluster nodes, including:
- Power control (on/off/status/reset/cycle)
- Boot device configuration (PXE, disk, BIOS)
- Automatic network discovery (via nmap)
- Manual targeting via command line or stdin
- Parallel execution support
- Configuration file support (YAML/JSON)
- Error handling and retries

Requirements:
- nmap
- ipmitool

Example usage:
  ipmi_control.py --action status
  ipmi_control.py --action power_on --hosts node001
  echo "node001-lom" | ipmi_control.py --action status
  ipmi_control.py --action power_off --hosts node00 node01 --parallel
  ipmi_control.py --config /path/to/config.yaml
"""

import argparse
import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import time
import yaml
import tempfile
import atexit
import stat
from getpass import getpass
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------

DEFAULT_CONFIG = {
    "subnet": "192.168.28.0/24",
    "node_pattern": r"node[0-9]{3}-lom",
    "usernames": ["root", "administrator", "admin"],
    "timeout": 10,
    "retries": 2,
    "parallel_workers": 5,
    "nmap_timeout": 60,
}

IPMI_ACTIONS = {
    "status": ["chassis", "power", "status"],
    "power_on": ["chassis", "power", "on"],
    "power_off": ["chassis", "power", "soft"],
    "power_off_hard": ["chassis", "power", "off"],
    "power_reset": ["chassis", "power", "reset"],
    "power_cycle": ["chassis", "power", "cycle"],
    "force_pxe": ["chassis", "bootdev", "pxe", "options=persistent"],
    "boot_disk": ["chassis", "bootdev", "disk", "options=persistent"],
    "boot_bios": ["chassis", "bootdev", "bios", "options=persistent"],
    "boot_safe": ["chassis", "bootdev", "safe", "options=persistent"],
    "identify_on": ["chassis", "identify", "30"],
    "identify_off": ["chassis", "identify", "0"],
    "sel_clear": ["sel", "clear"],
    "sel_list": ["sel", "list"],
}

@dataclass #dataclass adds __init__, __repr__, etc. automatically
class Config:
    subnet: str = DEFAULT_CONFIG["subnet"]
    node_pattern: str = DEFAULT_CONFIG["node_pattern"]
    usernames: List[str] = None
    timeout: int = DEFAULT_CONFIG["timeout"]
    retries: int = DEFAULT_CONFIG["retries"]
    parallel_workers: int = DEFAULT_CONFIG["parallel_workers"]
    nmap_timeout: int = DEFAULT_CONFIG["nmap_timeout"]
    # runtime-only (populated after prompt; not loaded from env/config):
    password: Optional[str] = None

    def __post_init__(self):
        if self.usernames is None:
            self.usernames = DEFAULT_CONFIG["usernames"].copy()

# ----------------------------------------------------------------------
# Logging Setup
# ----------------------------------------------------------------------

def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> logging.Logger:
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    format_str = "%(asctime)s - %(levelname)s - %(message)s"

    handlers = []
    handlers.append(logging.StreamHandler(sys.stdout))

    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format=format_str,
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=handlers
    )

    return logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Exceptions
# ----------------------------------------------------------------------

class IPMIControlError(Exception):
    """Base exception for IPMI control operations."""
    pass

class NetworkDiscoveryError(IPMIControlError):
    """Network discovery specific error."""
    pass

class IPMICommandError(IPMIControlError):
    """IPMI command execution error."""
    pass

class ConfigurationError(IPMIControlError):
    """Configuration related error."""
    pass

# ----------------------------------------------------------------------
# Configuration Manager
# ----------------------------------------------------------------------

class ConfigManager:
    """Manage configuration from files."""

    @staticmethod
    def load_config(config_path: Optional[str] = None) -> Config:
        """Load configuration from file or use defaults. (Ignores any password entries.)"""
        config_data = DEFAULT_CONFIG.copy()

        if config_path and Path(config_path).exists():
            try:
                with open(config_path, 'r') as f:
                    if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                        file_config = yaml.safe_load(f) or {}
                    else:
                        file_config = json.load(f) or {}
                # Never load secrets from config files
                file_config.pop("password", None)
                config_data.update(file_config)
            except Exception as e:
                raise ConfigurationError(f"Failed to load config file {config_path}: {e}")

        return Config(**config_data)

    @staticmethod
    def validate_config(config: Config) -> None:
        """Validate configuration parameters."""
        try:
            ipaddress.ip_network(config.subnet, strict=False)
        except ValueError as e:
            raise ConfigurationError(f"Invalid subnet format: {config.subnet}: {e}")

        try:
            re.compile(config.node_pattern)
        except re.error as e:
            raise ConfigurationError(f"Invalid node pattern regex: {config.node_pattern}: {e}")

# ----------------------------------------------------------------------
# Network Discovery
# ----------------------------------------------------------------------

class NetworkDiscovery:
    """Discover cluster nodes on the network via nmap."""

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.pattern = re.compile(config.node_pattern)

    def discover_nodes(self) -> List[str]:
        """Run nmap discovery and return node hostnames."""
        self.logger.info(f"Scanning subnet {self.config.subnet} for nodes matching pattern: {self.config.node_pattern}")

        try:
            result = subprocess.run(
                ["nmap", "-sn", self.config.subnet],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=self.config.nmap_timeout
            )
        except subprocess.CalledProcessError as e:
            raise NetworkDiscoveryError(f"nmap scan failed: {e.stderr}") from e
        except subprocess.TimeoutExpired:
            raise NetworkDiscoveryError(f"nmap scan timed out after {self.config.nmap_timeout} seconds")
        except FileNotFoundError:
            raise NetworkDiscoveryError("nmap is not installed or not in PATH")

        nodes = self._parse_nmap_output(result.stdout)
        nodes = sorted(set(nodes))

        self.logger.info(f"Discovered {len(nodes)} nodes")
        if self.logger.isEnabledFor(logging.DEBUG):
            for node in nodes:
                self.logger.debug(f"Found node: {node}")

        return nodes

    def _parse_nmap_output(self, output: str) -> List[str]:
        """Parse nmap output and extract matching hostnames."""
        nodes = []
        for line in output.splitlines():
            patterns = [
                r"Nmap scan report for (\S+) \(",  # "Nmap scan report for node001-lom (192.168.28.11)"
                r"Nmap scan report for (\S+)$",    # "Nmap scan report for node001-lom"
            ]

            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    hostname = match.group(1)
                    if self.pattern.search(hostname):
                        nodes.append(hostname)
                    break

        return nodes

    def validate_nodes(self, nodes: List[str]) -> List[str]:
        """Validate that nodes are reachable."""
        validated_nodes = []

        for node in nodes:
            if self._ping_node(node):
                validated_nodes.append(node)
            else:
                self.logger.warning(f"Node {node} is not reachable")

        return validated_nodes

    def _ping_node(self, node: str) -> bool:
        """Quick ping test to validate node reachability."""
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", node],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

# ----------------------------------------------------------------------
# Node Targeting
# ----------------------------------------------------------------------

class NodeTargeting:
    """Resolver for target nodes (args, stdin, discovery)."""

    def __init__(self, discovery: NetworkDiscovery, logger: logging.Logger):
        self.discovery = discovery
        self.logger = logger

    def determine_target_nodes(self, args: argparse.Namespace) -> List[str]:
        """Determine target nodes from various sources."""
        if args.hosts:
            return self._process_host_args(args.hosts)
        elif not sys.stdin.isatty():
            return self._read_stdin_hosts()
        else:
            return self.discovery.discover_nodes()

    def _process_host_args(self, hosts: List[str]) -> List[str]:
        """Process host arguments, supporting patterns and full hostnames."""
        if all(self._is_full_hostname(h) for h in hosts):
            self.logger.info(f"Using specified hosts: {hosts}")
            return hosts

        self.logger.info(f"Treating host arguments as patterns: {hosts}")
        all_nodes = self.discovery.discover_nodes()
        return self._match_patterns(hosts, all_nodes)

    def _is_full_hostname(self, hostname: str) -> bool:
        return (("." in hostname or "-" in hostname) and
                not any(char in hostname for char in ['*', '?', '[', ']']))

    def _match_patterns(self, patterns: List[str], all_nodes: List[str]) -> List[str]:
        matched = set()

        for pattern in patterns:
            pattern_matched = False
            for node in all_nodes:
                if pattern in node:
                    matched.add(node)
                    pattern_matched = True
                    self.logger.debug(f"Pattern '{pattern}' matched node {node}")

            if not pattern_matched:
                self.logger.warning(f"Pattern '{pattern}' matched no nodes")

        result = sorted(matched)
        self.logger.info(f"Pattern matching found {len(result)} nodes")
        return result

    def _read_stdin_hosts(self) -> List[str]:
        hosts = []
        try:
            for line in sys.stdin:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    hosts.append(stripped)
        except KeyboardInterrupt:
            self.logger.info("Stdin reading interrupted")

        self.logger.info(f"Read {len(hosts)} hosts from stdin")
        return hosts

# ----------------------------------------------------------------------
# IPMI Controller
# ----------------------------------------------------------------------

class IPMIController:
    """Execute IPMI commands against nodes."""

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self._password_file: Optional[str] = None
        if self.config.password:
            self._password_file = self._create_password_file(self.config.password)
            atexit.register(self._cleanup_password_file)

    def _create_password_file(self, password: str) -> str:
        """Create a secure temp file containing the password and return its path."""
        # Use delete=False so multiple ipmitool invocations can read it
        tmp = tempfile.NamedTemporaryFile(prefix=".ipmi_pass_", delete=False, mode="w", encoding="utf-8")
        try:
            # Restrict permissions to 0600
            os.fchmod(tmp.fileno(), stat.S_IRUSR | stat.S_IWUSR)
            tmp.write(password + "\n")
            tmp.flush()
            return tmp.name
        finally:
            tmp.close()

    def _cleanup_password_file(self) -> None:
        if self._password_file and os.path.exists(self._password_file):
            try:
                os.remove(self._password_file)
            except Exception:
                # Best-effort cleanup
                pass

    def execute_action(self, node: str, action: str) -> Tuple[bool, str]:
        """Execute IPMI action on a node with retry logic."""
        if action not in IPMI_ACTIONS:
            return False, f"Unknown action: {action}"

        self.logger.debug(f"Executing {action} on {node}")

        for attempt in range(self.config.retries + 1):
            for username in self.config.usernames:
                try:
                    success, output = self._try_ipmi_command(node, action, username)
                    if success:
                        return True, self._format_success(node, action, username, output)
                except IPMICommandError as e:
                    self.logger.debug(f"IPMI attempt {attempt + 1} failed for {username}@{node}: {e}")
                    continue
                except Exception as e:
                    self.logger.debug(f"Unexpected error on attempt {attempt + 1} for {username}@{node}: {e}")
                    continue

            if attempt < self.config.retries:
                time.sleep(1)

        return False, f"All authentication attempts failed for {node} after {self.config.retries + 1} attempts"

    def _try_ipmi_command(self, node: str, action: str, username: str) -> Tuple[bool, str]:
        """Try executing an IPMI command with specific credentials."""
        # Always use -f with the secure temp file if available; otherwise fall back to ipmitool prompt (-a)
        auth_args = ["-f", self._password_file] if self._password_file else ["-a"]

        cmd = [
            "ipmitool", "-I", "lanplus",
            "-H", node,
            "-U", username,
            *auth_args,
            *IPMI_ACTIONS[action],
        ]

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.config.timeout
            )
        except subprocess.TimeoutExpired:
            raise IPMICommandError(f"Command timed out after {self.config.timeout} seconds")
        except FileNotFoundError:
            raise IPMICommandError("ipmitool not installed or not in PATH")

        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            stderr = result.stderr.strip().lower()
            if any(err in stderr for err in ["authentication", "password", "privilege"]):
                raise IPMICommandError(f"Authentication failed: {result.stderr.strip()}")
            else:
                raise IPMICommandError(f"Command failed: {result.stderr.strip()}")

    def _format_success(self, node: str, action: str, username: str, output: str) -> str:
        if action == "status":
            return f"{node}: {output} (authenticated as {username})"
        elif action == "sel_list":
            lines = output.split('\n') if output else []
            return f"{node}: {len(lines)} SEL entries (authenticated as {username})"
        else:
            action_name = action.replace('_', ' ').title()
            return f"{node}: {action_name} successful (authenticated as {username})"

    def execute_parallel(self, nodes: List[str], action: str) -> Dict[str, Tuple[bool, str]]:
        results = {}

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.parallel_workers) as executor:
            future_to_node = {
                executor.submit(self.execute_action, node, action): node
                for node in nodes
            }

            for future in concurrent.futures.as_completed(future_to_node):
                node = future_to_node[future]
                try:
                    results[node] = future.result()
                except Exception as e:
                    results[node] = (False, f"Execution error: {e}")
                    self.logger.error(f"Unexpected error processing {node}: {e}")

        return results

# ----------------------------------------------------------------------
# Utility Functions
# ----------------------------------------------------------------------

def setup_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="IPMI control for cluster nodes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --action status
  %(prog)s --action power_on --hosts node001
  echo "node001-lom" | %(prog)s --action status
  %(prog)s --hosts node00 node01 --action power_off --parallel
  %(prog)s --config /etc/ipmi_control.yaml --action status
  %(prog)s --action sel_list --hosts node001 --output json
        """
    )

    parser.add_argument(
        "--action", choices=list(IPMI_ACTIONS.keys()), default="status",
        help="Action to perform (default: %(default)s)"
    )
    parser.add_argument(
        "--hosts", nargs='+',
        help="List of nodes or patterns to target"
    )
    parser.add_argument(
        "--config", "-c",
        help="Configuration file path (YAML or JSON)"
    )
    parser.add_argument(
        "--parallel", "-p", action="store_true",
        help="Execute commands in parallel"
    )
    parser.add_argument(
        "--output", "-o", choices=["text", "json"], default="text",
        help="Output format (default: %(default)s)"
    )
    parser.add_argument(
        "--log-file",
        help="Log file path"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--validate-nodes", action="store_true",
        help="Validate node reachability before executing commands"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be done without executing"
    )

    return parser


def prompt_for_password_if_needed(config: Config, logger: logging.Logger, will_execute: bool) -> None:
    """Prompt once for password when we actually intend to run ipmitool."""
    if config.password or not will_execute:
        return

    # Try to prompt on a TTY; getpass handles /dev/tty when stdin is piped.
    try:
        pwd = getpass("IPMI password: ")
    except Exception as e:
        raise ConfigurationError(
            "Unable to prompt for IPMI password (no TTY?). Run interactively."
        ) from e

    if not pwd:
        raise ConfigurationError("Empty password not allowed. Aborting.")

    config.password = pwd


def process_nodes_sequential(nodes: List[str], action: str, controller: IPMIController,
                           logger: logging.Logger, output_format: str = "text",
                           dry_run: bool = False) -> None:
    if not nodes:
        logger.warning("No nodes found to process")
        return

    logger.info(f"Processing {len(nodes)} nodes sequentially with action: {action}")

    if dry_run:
        logger.info("DRY RUN - Would execute the following:")
        for node in nodes:
            print(f"Would execute '{action}' on {node}")
        return

    results = {}
    success_count = 0

    for node in nodes:
        success, message = controller.execute_action(node, action)
        results[node] = (success, message)

        if success:
            success_count += 1
            if output_format == "text":
                print(message)
        else:
            logger.error(f"Failed on {node}: {message}")

    if output_format == "json":
        output_results = {
            node: {"success": success, "message": message}
            for node, (success, message) in results.items()
        }
        print(json.dumps(output_results, indent=2))

    logger.info(f"Processed {success_count}/{len(nodes)} nodes successfully")


def process_nodes_parallel(nodes: List[str], action: str, controller: IPMIController,
                         logger: logging.Logger, output_format: str = "text",
                         dry_run: bool = False) -> None:
    if not nodes:
        logger.warning("No nodes found to process")
        return

    logger.info(f"Processing {len(nodes)} nodes in parallel with action: {action}")

    if dry_run:
        logger.info("DRY RUN - Would execute the following in parallel:")
        for node in nodes:
            print(f"Would execute '{action}' on {node}")
        return

    results = controller.execute_parallel(nodes, action)
    success_count = sum(1 for success, _ in results.values() if success)

    if output_format == "text":
        for node in sorted(results.keys()):
            success, message = results[node]
            if success:
                print(message)
            else:
                logger.error(f"Failed on {node}: {message}")
    else:
        output_results = {
            node: {"success": success, "message": message}
            for node, (success, message) in results.items()
        }
        print(json.dumps(output_results, indent=2))

    logger.info(f"Processed {success_count}/{len(nodes)} nodes successfully")

# ----------------------------------------------------------------------
# Main Entry
# ----------------------------------------------------------------------

def main() -> None:
    parser = setup_argument_parser()
    args = parser.parse_args()

    logger = setup_logging(verbose=args.verbose, log_file=args.log_file)

    try:
        # Load and validate configuration (no secrets)
        config = ConfigManager.load_config(args.config)
        ConfigManager.validate_config(config)

        # Initialize components not requiring secrets
        discovery = NetworkDiscovery(config, logger)
        targeting = NodeTargeting(discovery, logger)

        # Determine target nodes first (doesn't require auth)
        nodes = targeting.determine_target_nodes(args)

        if args.validate_nodes:
            logger.info("Validating node reachability...")
            nodes = discovery.validate_nodes(nodes)

        # Decide if we will actually execute ipmitool (not in dry-run and there are nodes)
        will_execute = (not args.dry_run) and bool(nodes)

        # Prompt once for password if we will execute
        prompt_for_password_if_needed(config, logger, will_execute)

        # Now that we have (or don't have) a password, construct the controller (creates temp file if needed)
        controller = IPMIController(config, logger)

        # Process nodes
        if args.parallel:
            process_nodes_parallel(nodes, args.action, controller, logger,
                                   args.output, args.dry_run)
        else:
            process_nodes_sequential(nodes, args.action, controller, logger,
                                     args.output, args.dry_run)

    except (IPMIControlError, ConfigurationError) as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            logger.exception("Full traceback")
        sys.exit(1)

if __name__ == "__main__":
    main()
