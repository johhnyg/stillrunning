#!/usr/bin/env python3
"""
docker_agent.py - Docker container security monitor for stillrunning.

Watches Docker containers the same way guard watches processes.
Pure Python - no docker SDK, uses Unix socket HTTP directly.

Usage: python3 docker_agent.py (runs as daemon)
"""

import os
import sys
import json
import time
import socket
import traceback
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

# ─── Configuration ────────────────────────────────────────────────────────────

DOCKER_SOCKET = "/var/run/docker.sock"
POLL_INTERVAL = 10  # seconds
STATUS_FILE = os.path.expanduser("~/my-app/docker_status.json")
THREAT_CACHE = os.path.expanduser("~/my-app/threat_cache.json")

# Known bad images (from threat feed)
KNOWN_BAD_IMAGES = {
    "cryptominer",
    "xmrig",
    "malicious",
}

# Sensitive mount paths
SENSITIVE_PATHS = ["/", "/etc", "/root", "/home", "/.ssh", "/var/run/docker.sock"]

# ─── Colors ───────────────────────────────────────────────────────────────────

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ─── Docker Socket HTTP ───────────────────────────────────────────────────────

class DockerClient:
    """Minimal Docker client using Unix socket HTTP."""

    def __init__(self, socket_path: str = DOCKER_SOCKET):
        self.socket_path = socket_path

    def _request(self, method: str, path: str) -> Dict[str, Any]:
        """Make HTTP request to Docker socket."""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(self.socket_path)

            request = f"{method} {path} HTTP/1.0\r\nHost: localhost\r\n\r\n"
            sock.send(request.encode())

            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk

            sock.close()

            # Parse HTTP response
            parts = response.split(b"\r\n\r\n", 1)
            if len(parts) < 2:
                return {"error": "Invalid response"}

            headers, body = parts
            status_line = headers.split(b"\r\n")[0].decode()

            if "200" not in status_line:
                return {"error": f"HTTP {status_line}"}

            return json.loads(body.decode())

        except FileNotFoundError:
            return {"error": "Docker socket not found"}
        except ConnectionRefusedError:
            return {"error": "Docker not running"}
        except Exception as e:
            return {"error": str(e)}

    def list_containers(self, all_containers: bool = False) -> List[Dict]:
        """List running containers."""
        path = "/containers/json"
        if all_containers:
            path += "?all=true"
        result = self._request("GET", path)
        if isinstance(result, list):
            return result
        return []

    def inspect_container(self, container_id: str) -> Dict:
        """Get detailed container info."""
        return self._request("GET", f"/containers/{container_id}/json")

    def list_images(self) -> List[Dict]:
        """List local images."""
        result = self._request("GET", "/images/json")
        if isinstance(result, list):
            return result
        return []

    def is_available(self) -> bool:
        """Check if Docker is available."""
        result = self._request("GET", "/version")
        return "error" not in result


# ─── Security Checks ──────────────────────────────────────────────────────────

class ContainerSecurityAnalyzer:
    """Analyze containers for security risks."""

    def __init__(self):
        self.alerts: List[Dict] = []
        self.threats_blocked = 0

    def analyze_container(self, container: Dict, details: Dict) -> List[Dict]:
        """Analyze a container for security issues."""
        findings = []
        container_name = container.get("Names", ["unknown"])[0].lstrip("/")
        image = container.get("Image", "unknown")

        # Check privileged mode
        if details.get("HostConfig", {}).get("Privileged", False):
            findings.append({
                "severity": "CRITICAL",
                "type": "PRIVILEGED_CONTAINER",
                "container": container_name,
                "message": f"Container '{container_name}' running with --privileged flag"
            })

        # Check host network mode
        network_mode = details.get("HostConfig", {}).get("NetworkMode", "")
        if network_mode == "host":
            findings.append({
                "severity": "HIGH",
                "type": "HOST_NETWORK",
                "container": container_name,
                "message": f"Container '{container_name}' using host network mode"
            })

        # Check running as root
        user = details.get("Config", {}).get("User", "")
        if not user or user == "root" or user == "0":
            findings.append({
                "severity": "MEDIUM",
                "type": "ROOT_USER",
                "container": container_name,
                "message": f"Container '{container_name}' running as root"
            })

        # Check sensitive mounts
        mounts = details.get("Mounts", [])
        for mount in mounts:
            source = mount.get("Source", "")
            for sensitive in SENSITIVE_PATHS:
                if source == sensitive or source.startswith(sensitive + "/"):
                    findings.append({
                        "severity": "CRITICAL",
                        "type": "SENSITIVE_MOUNT",
                        "container": container_name,
                        "message": f"Container '{container_name}' mounting sensitive path: {source}"
                    })
                    break

        # Check image against known bad list
        image_lower = image.lower()
        for bad in KNOWN_BAD_IMAGES:
            if bad in image_lower:
                findings.append({
                    "severity": "CRITICAL",
                    "type": "MALICIOUS_IMAGE",
                    "container": container_name,
                    "message": f"Container '{container_name}' using known malicious image: {image}"
                })
                self.threats_blocked += 1
                break

        return findings

    def check_resource_usage(self, container: Dict) -> Optional[Dict]:
        """Check for resource abuse patterns."""
        # Note: Full stats require streaming API, simplified for polling
        state = container.get("State", "")
        if state != "running":
            return None
        return None  # Would need /containers/{id}/stats for real monitoring


# ─── Alert System ─────────────────────────────────────────────────────────────

def send_telegram_alert(message: str, severity: str = "INFO"):
    """Send alert via Telegram."""
    env_path = os.path.expanduser("~/my-app/.env")
    bot_token = None
    chat_id = None

    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith("TELEGRAM_BOT_TOKEN="):
                    bot_token = line.split("=", 1)[1].strip().strip('"').strip("'")
                elif line.startswith("TELEGRAM_CHAT_ID="):
                    chat_id = line.split("=", 1)[1].strip().strip('"').strip("'")

    if not bot_token or not chat_id:
        return

    emoji = {"CRITICAL": "\U0001F6A8", "HIGH": "\U000026A0", "MEDIUM": "\U0001F7E1", "INFO": "\U0001F4E2"}.get(severity, "")

    import urllib.request
    import urllib.parse

    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        data = urllib.parse.urlencode({
            "chat_id": chat_id,
            "text": f"{emoji} *Docker Agent Alert*\n\n{message}",
            "parse_mode": "Markdown"
        }).encode()

        req = urllib.request.Request(url, data=data)
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception:
        pass


# ─── State Management ─────────────────────────────────────────────────────────

class DockerAgentState:
    """Track agent state and container history."""

    def __init__(self):
        self.known_containers: set = set()
        self.alerts_today = 0
        self.threats_blocked = 0
        self.privileged_containers: List[str] = []
        self.last_container_started = ""
        self.started_at = datetime.now(timezone.utc).isoformat()

    def write_status(self, containers_watched: int, running: bool = True):
        """Write status file."""
        status = {
            "running": running,
            "containers_watched": containers_watched,
            "alerts_today": self.alerts_today,
            "threats_blocked": self.threats_blocked,
            "last_container_started": self.last_container_started,
            "privileged_containers": self.privileged_containers,
            "started_at": self.started_at,
            "last_update": datetime.now(timezone.utc).isoformat()
        }

        try:
            with open(STATUS_FILE + ".tmp", "w") as f:
                json.dump(status, f, indent=2)
            os.replace(STATUS_FILE + ".tmp", STATUS_FILE)
        except Exception as e:
            print(f"{RED}[ERROR]{RESET} Failed to write status: {e}")


# ─── Main Loop ────────────────────────────────────────────────────────────────

def main():
    """Main agent loop."""
    print(f"{BOLD}Docker Security Agent{RESET}")
    print(f"{'='*40}")

    docker = DockerClient()
    analyzer = ContainerSecurityAnalyzer()
    state = DockerAgentState()

    # Check Docker availability
    if not docker.is_available():
        print(f"{YELLOW}[WARN]{RESET} Docker not available - agent will poll until available")

    print(f"Polling every {POLL_INTERVAL}s")
    print(f"Status file: {STATUS_FILE}")
    print()

    while True:
        try:
            # List containers
            containers = docker.list_containers()

            if not containers and not docker.is_available():
                state.write_status(0, running=True)
                time.sleep(POLL_INTERVAL)
                continue

            # Track new containers
            current_ids = {c.get("Id", "")[:12] for c in containers}
            new_containers = current_ids - state.known_containers

            for container in containers:
                cid = container.get("Id", "")[:12]
                if cid in new_containers:
                    name = container.get("Names", ["unknown"])[0].lstrip("/")
                    image = container.get("Image", "unknown")
                    state.last_container_started = name
                    print(f"{GREEN}[NEW]{RESET} Container started: {name} ({image})")

                    # Inspect new container
                    details = docker.inspect_container(container.get("Id", ""))
                    if "error" not in details:
                        findings = analyzer.analyze_container(container, details)

                        for finding in findings:
                            severity = finding["severity"]
                            msg = finding["message"]

                            if severity == "CRITICAL":
                                print(f"{RED}[CRITICAL]{RESET} {msg}")
                                send_telegram_alert(msg, "CRITICAL")
                                state.alerts_today += 1

                                if finding["type"] == "PRIVILEGED_CONTAINER":
                                    state.privileged_containers.append(name)

                            elif severity == "HIGH":
                                print(f"{YELLOW}[HIGH]{RESET} {msg}")
                                state.alerts_today += 1

                            elif severity == "MEDIUM":
                                print(f"{CYAN}[MEDIUM]{RESET} {msg}")

            state.known_containers = current_ids
            state.threats_blocked = analyzer.threats_blocked

            # Write status
            state.write_status(len(containers))

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            print(f"\n{YELLOW}Shutting down...{RESET}")
            state.write_status(0, running=False)
            break

        except Exception as e:
            print(f"{RED}[ERROR]{RESET} {e}")
            traceback.print_exc()
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
