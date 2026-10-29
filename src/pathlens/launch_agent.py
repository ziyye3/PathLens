"""Generate an optional macOS launchd configuration without installing it."""

from __future__ import annotations

import os
import plistlib
from pathlib import Path


def make_launch_agent(python: Path, directory: Path, interval: int) -> dict:
    if not python.is_absolute() or not python.is_file():
        raise ValueError("Python executable must be an existing absolute path")
    if not directory.is_absolute() or not directory.is_dir():
        raise ValueError("Feed directory must be an existing absolute path")
    if interval < 300:
        raise ValueError("interval must be at least 300 seconds")
    return {
        "Label": "org.pathlens.feodo-refresh",
        "ProgramArguments": [
            str(python),
            "-m",
            "pathlens.cli",
            "watch-feodo",
            "--directory",
            str(directory),
            "--interval",
            str(interval),
            "--cycles",
            "1",
        ],
        "StartInterval": interval,
        "RunAtLoad": False,
    }


def write_launch_agent(output: Path, python: Path, directory: Path, interval: int) -> None:
    config = make_launch_agent(python, directory, interval)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        plistlib.dump(config, handle)
