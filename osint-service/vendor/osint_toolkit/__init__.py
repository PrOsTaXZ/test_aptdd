"""Personal OSINT Toolkit — modular, local, privacy-first open-source intelligence."""

from importlib.metadata import PackageNotFoundError, version

APP_NAME = "osint-toolkit"

try:
    __version__ = version(APP_NAME)
except PackageNotFoundError:  # pragma: no cover - running from a source tree without install
    __version__ = "0.0.0+unknown"

__all__ = ["APP_NAME", "__version__"]
