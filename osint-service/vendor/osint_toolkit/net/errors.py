"""Network error hierarchy with user-facing (Russian) messages."""

from __future__ import annotations


class NetworkError(Exception):
    """A network operation failed. ``str(exc)`` is safe to show to the user."""


class NetworkTimeoutError(NetworkError):
    pass


class HttpStatusError(NetworkError):
    def __init__(
        self, message: str, status_code: int, headers: dict[str, str] | None = None
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.retry_after: float | None = None


class ResponseTooLargeError(NetworkError):
    pass


class NetworkDisabledError(NetworkError):
    """Raised when code without network permission tries to use the network."""
