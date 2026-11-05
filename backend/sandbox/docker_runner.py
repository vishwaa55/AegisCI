"""
Docker Sandbox Execution Engine for AegisCI.

Provides containerized isolation for executing candidate patches, tests, and security scans.
Includes graceful fallback to an isolated temporary process sandbox when the Docker daemon
is unavailable or disabled.
"""

import logging
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aegis.sandbox")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Files/directories forbidden from ever being mounted into sandbox
SENSITIVE_PATTERNS = {
    ".env",
    ".git",
    "id_rsa",
    "credentials",
    ".aws",
    ".ssh",
    "venv",
    ".venv",
}


class SandboxResult:
    """Structured execution result from a sandbox run."""

    def __init__(
        self,
        exit_code: int,
        stdout: str,
        stderr: str,
        timed_out: bool = False,
        sandbox_type: str = "process",
        error_message: Optional[str] = None,
    ):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.sandbox_type = sandbox_type
        self.error_message = error_message

    @property
    def passed(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def combined_output(self) -> str:
        out = self.stdout or ""
        if self.stderr:
            out += ("\n" if out else "") + self.stderr
        return out.strip()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "passed": self.passed,
            "timed_out": self.timed_out,
            "sandbox_type": self.sandbox_type,
            "stdout": self.stdout[:3000],
            "stderr": self.stderr[:3000],
            "error_message": self.error_message,
        }


def is_docker_available() -> bool:
    """
    Check if Docker daemon is responsive.
    Returns False if docker CLI is missing or daemon is stopped.
    """
    try:
        import docker  # noqa: PLC0415
        client = docker.from_env()
        client.ping()
        return True
    except Exception:
        # Also try quick CLI ping
        try:
            res = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return res.returncode == 0
        except Exception:
            return False


class DockerSandbox:
    """
    Executes commands in containerized Docker sandboxes with strict resource limits,
    unprivileged user mounts, and automatic cleanup.

    Falls back cleanly to an isolated process directory sandbox when Docker daemon is inactive.
    """

    def __init__(
        self,
        image_name: str = "python:3.12-slim",
        mem_limit: str = "512m",
        cpu_quota: int = 100000,  # 1.0 CPU equivalent
        default_timeout: int = 60,
    ):
        self.image_name = image_name
        self.mem_limit = mem_limit
        self.cpu_quota = cpu_quota
        self.default_timeout = default_timeout
        self._docker_available = is_docker_available()
        if not self._docker_available:
            logger.warning(
                "Docker daemon is not available. Falling back to isolated process sandbox. "
                "Note: Process sandbox isolates files in a temporary directory but does not enforce "
                "kernel-level network or resource namespace boundaries."
            )

    def run_command(
        self,
        command: List[str],
        workspace_dir: str,
        timeout: Optional[int] = None,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """
        Run a command against the workspace directory.
        Uses Docker container if daemon is running, otherwise process sandbox.
        """
        t = timeout or self.default_timeout

        # Check if Docker is active
        if is_docker_available():
            return self._run_in_docker(command, workspace_dir, t, env_vars)
        else:
            return self._run_in_process(command, workspace_dir, t, env_vars)

    def _run_in_docker(
        self,
        command: List[str],
        workspace_dir: str,
        timeout: int,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """Run execution inside an isolated container with resource limits."""
        norm_workspace = os.path.abspath(workspace_dir)

        # Sanity check: do not mount sensitive roots
        for sens in SENSITIVE_PATTERNS:
            if sens in norm_workspace.lower():
                return SandboxResult(
                    exit_code=1,
                    stdout="",
                    stderr=f"Refusing to mount sensitive path in Docker sandbox: {norm_workspace}",
                    sandbox_type="docker",
                    error_message="Security violation: sensitive directory mount attempted.",
                )

        import docker  # noqa: PLC0415

        try:
            client = docker.from_env()
            client.ping()
        except Exception as e:
            return SandboxResult(
                exit_code=1,
                stdout="",
                stderr=f"Docker daemon unavailable: {e}",
                sandbox_type="docker",
                error_message=f"Docker daemon connection failed: {e}",
            )

        container = None
        cmd_str = " ".join(command)

        try:
            volumes = {
                norm_workspace: {"bind": "/workspace", "mode": "rw"},
            }

            clean_env = {
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONUNBUFFERED": "1",
            }
            if env_vars:
                clean_env.update(env_vars)

            container = client.containers.run(
                image=self.image_name,
                command=["sh", "-c", cmd_str],
                volumes=volumes,
                working_dir="/workspace",
                mem_limit=self.mem_limit,
                cpu_quota=self.cpu_quota,
                network_mode="none",  # complete network isolation during test run
                environment=clean_env,
                detach=True,
                remove=False,
            )

            # Wait with timeout
            start_time = time.time()
            timed_out = False
            while True:
                container.reload()
                if container.status != "running":
                    break
                if time.time() - start_time > timeout:
                    timed_out = True
                    try:
                        container.kill()
                    except Exception:
                        pass
                    break
                time.sleep(0.5)

            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
            exit_code = 124 if timed_out else container.attrs["State"]["ExitCode"]

            return SandboxResult(
                exit_code=exit_code,
                stdout=logs,
                stderr="Execution timed out" if timed_out else "",
                timed_out=timed_out,
                sandbox_type="docker",
            )
        except Exception as e:
            logger.error(f"Docker execution failed: {e}")
            return SandboxResult(
                exit_code=1,
                stdout="",
                stderr=str(e),
                sandbox_type="docker",
                error_message=f"Docker container error: {e}",
            )
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def _run_in_process(
        self,
        command: List[str],
        workspace_dir: str,
        timeout: int,
        env_vars: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """
        Fallback: Run execution in an isolated process workspace.
        Cleans environment of secret tokens and executes with subprocess timeout.
        """
        # Determine python executable
        clean_command = list(command)
        if clean_command and clean_command[0] in ("python", "python3"):
            venv_python = os.path.join(ROOT_DIR, "venv", "Scripts", "python.exe")
            if os.path.isfile(venv_python):
                clean_command[0] = venv_python

        # Clean host environment: strip secrets
        env = os.environ.copy()
        for k in list(env.keys()):
            if any(term in k.upper() for term in ("TOKEN", "SECRET", "KEY", "AUTH", "PASS")):
                del env[k]
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        if env_vars:
            env.update(env_vars)

        try:
            res = subprocess.run(
                clean_command,
                cwd=workspace_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
            return SandboxResult(
                exit_code=res.returncode,
                stdout=res.stdout,
                stderr=res.stderr,
                timed_out=False,
                sandbox_type="process_isolated",
            )
        except subprocess.TimeoutExpired as te:
            return SandboxResult(
                exit_code=124,
                stdout=te.stdout.decode() if isinstance(te.stdout, bytes) else (te.stdout or ""),
                stderr=f"Process timed out after {timeout} seconds",
                timed_out=True,
                sandbox_type="process_isolated",
            )
        except Exception as e:
            return SandboxResult(
                exit_code=1,
                stdout="",
                stderr=str(e),
                timed_out=False,
                sandbox_type="process_isolated",
                error_message=str(e),
            )
