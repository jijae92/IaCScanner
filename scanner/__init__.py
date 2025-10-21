"""Top-level package for the IaC security scanner."""
from importlib import metadata

try:
    __version__ = metadata.version("iac-scanner")
except metadata.PackageNotFoundError:  # type: ignore[attr-defined]
    __version__ = "0.0.0"

__all__ = ["__version__"]
