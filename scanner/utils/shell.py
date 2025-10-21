"""Shell execution helpers with explicit timeout handling."""
from __future__ import annotations

import os
import subprocess
from typing import Mapping, Sequence

DEFAULT_TIMEOUT = 600


class ShellCommandError(RuntimeError):
    """Raised when a subprocess cannot be executed successfully."""

    def __init__(
        self,
        *,
        command: Sequence[str],
        message: str,
        returncode: int | None,
        stdout: str,
        stderr: str,
    ) -> None:
        super().__init__(message)
        self.command = list(command)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def run(
    command: Sequence[str],
    *,
    timeout: int = DEFAULT_TIMEOUT,
    env: Mapping[str, str] | None = None,
) -> tuple[int, str, str]:
    """Execute a shell command and return (returncode, stdout, stderr)."""
    process_env = os.environ.copy()
    if env:
        process_env.update(env)

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=process_env,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ShellCommandError(
            command=command,
            message=f"Executable '{command[0]}' not found in PATH. Install it or adjust PATH.",
            returncode=None,
            stdout="",
            stderr="",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise ShellCommandError(
            command=command,
            message=f"Command '{command[0]}' timed out after {timeout} seconds.",
            returncode=None,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
        ) from exc
    except OSError as exc:
        raise ShellCommandError(
            command=command,
            message=f"Failed to execute command '{command[0]}': {exc}",
            returncode=None,
            stdout="",
            stderr=str(exc),
        ) from exc

    return completed.returncode, completed.stdout, completed.stderr


__all__ = ["ShellCommandError", "run", "DEFAULT_TIMEOUT"]
