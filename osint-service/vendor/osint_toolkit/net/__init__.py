"""Network layer used by modules that declared external services and received consent.

* :class:`HttpClient` — httpx with total and per-host concurrency limits, timeouts, size caps,
  bounded retries and user-facing error messages.
* :class:`SystemDnsClient` — dnspython async resolver with a concurrency limit and a precise
  distinction between NXDOMAIN, NODATA and failures (a failure never means "no record").
* :class:`NetworkServices` — lazy container handed to modules; :data:`DISABLED_NETWORK` raises
  on any use and is given to every module that did not declare network access or was not allowed.
"""

from osint_toolkit.net.dns import DnsClient, DnsResult, DnsStatus, SystemDnsClient
from osint_toolkit.net.errors import (
    HttpStatusError,
    NetworkDisabledError,
    NetworkError,
    NetworkTimeoutError,
    ResponseTooLargeError,
)
from osint_toolkit.net.http import HttpClient, HttpResponse
from osint_toolkit.net.services import DISABLED_NETWORK, NetworkServices

__all__ = [
    "DISABLED_NETWORK",
    "DnsClient",
    "DnsResult",
    "DnsStatus",
    "HttpClient",
    "HttpResponse",
    "HttpStatusError",
    "NetworkDisabledError",
    "NetworkError",
    "NetworkServices",
    "NetworkTimeoutError",
    "ResponseTooLargeError",
    "SystemDnsClient",
]
