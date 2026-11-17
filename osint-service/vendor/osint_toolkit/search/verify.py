"""Open a search hit and check that the identifier is really on the page.

* robots.txt is honoured (RFC 9309): fetched once per host; 4xx → everything allowed,
  5xx/unreachable → everything disallowed; our product token is ``osint-toolkit``.
* Pages are downloaded without executing JavaScript, with the application's honest User-Agent,
  timeouts, a size cap and at most 5 redirects. Hosts in private/loopback networks are never
  contacted (a search hit must not make the tool probe your LAN).
* HTML → text with the stdlib parser (scripts, styles and templates dropped); documents are
  handed to :mod:`osint_toolkit.search.documents`.
* Only the downloaded text counts: a search snippet alone is never reported as "confirmed".
"""

from __future__ import annotations

import asyncio
import enum
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib import robotparser
from urllib.parse import urlsplit

from osint_toolkit.analysis.entities import Entity, extract_near
from osint_toolkit.config import Settings
from osint_toolkit.core.models import Target
from osint_toolkit.integrations.search import is_local_host
from osint_toolkit.net import HttpStatusError, NetworkError, NetworkServices
from osint_toolkit.search import documents
from osint_toolkit.search.matching import Match, find_identifier
from osint_toolkit.search.resources import Resource, classify, document_type, manual_only

META_KEYS = frozenset(
    {"og:title", "og:description", "description", "twitter:title", "twitter:description"}
)
ROBOTS_TOKEN = "osint-toolkit"  # noqa: S105 - robots.txt product token, not a secret
HTML_TYPES = ("text/html", "application/xhtml+xml", "text/plain", "")
_META_CHARSET = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?([\w-]+)""", re.IGNORECASE)


class Check(enum.StrEnum):
    CONFIRMED = "confirmed"  # identifier found in the downloaded text
    ABSENT = "absent"  # page downloaded, identifier not in its (static) text
    ROBOTS = "robots"  # robots.txt forbids automated access to this URL
    BLOCKED = "blocked"  # HTTP error (403, 404, 429…), timeout, too large
    UNSUPPORTED = "unsupported"  # format we do not parse
    SKIPPED = "skipped"  # not checked: page budget exhausted
    MANUAL = "manual"  # platform shows nothing without JavaScript/sign-in: check by hand
    UNCHECKED = "unchecked"  # reported by an external plugin, not opened
    LOCAL = "local"  # private/loopback host: never contacted

    @property
    def label(self) -> str:
        return CHECK_LABELS[self]


CHECK_LABELS = {
    Check.CONFIRMED: "подтверждено на странице",
    Check.ABSENT: "на странице не найдено",
    Check.ROBOTS: "запрещено robots.txt",
    Check.BLOCKED: "страница недоступна",
    Check.UNSUPPORTED: "формат не поддерживается",
    Check.SKIPPED: "не проверялось (лимит страниц)",
    Check.MANUAL: "требует ручной проверки",
    Check.UNCHECKED: "не проверялось (данные плагина)",
    Check.LOCAL: "локальный адрес — не открывался",
}


@dataclass(frozen=True, slots=True)
class Verification:
    url: str
    status: Check
    resource: Resource
    final_url: str | None = None
    http_status: int | None = None
    match: Match | None = None
    location: str | None = None  # page/slide/sheet of a document
    detail: str | None = None  # error or reason
    entities: tuple[Entity, ...] = ()  # recognised around the identifier (confirmed pages only)


class _TextExtractor(HTMLParser):
    SKIP = frozenset({"script", "style", "noscript", "template", "svg", "iframe"})
    BLOCK = frozenset(
        {"p", "div", "br", "li", "tr", "td", "h1", "h2", "h3", "h4", "section", "title", "body"}
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.meta: list[str] = []  # Open Graph / description: often the post text itself
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self.SKIP:
            self._skip += 1
        elif tag in self.BLOCK:
            self.parts.append("\n")
        if tag == "meta":
            fields = dict(attrs)
            key = (fields.get("property") or fields.get("name") or "").lower()
            if key in META_KEYS and fields.get("content"):
                self.meta.append(str(fields["content"]))
        if tag == "a":  # mailto:/tel: links often hold the identifier itself
            for name, value in attrs:
                if name == "href" and value and value.startswith(("mailto:", "tel:")):
                    self.parts.append(f" {value.split(':', 1)[1]} ")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.SKIP and self._skip:
            self._skip -= 1
        elif tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


_LOGIN_HOST = re.compile(r"^(sso|passport|login|auth|accounts|id|signin)\.")
_LOGIN_PATH = re.compile(r"/(login|signin|sign_in|auth|authorize|sso|captcha)(/|\?|$)")


def is_login_redirect(url: str, final_url: str) -> bool:
    """The hit redirected to a sign-in or check page: its content is not the page itself."""
    if final_url == url:
        return False
    final = urlsplit(final_url)
    host = (final.hostname or "").lower().removeprefix("www.")
    return bool(_LOGIN_HOST.match(host) or _LOGIN_PATH.search(final.path.lower()))


def _parse(html: str) -> _TextExtractor:
    parser = _TextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, ValueError):  # malformed markup: keep what was parsed
        pass
    return parser


def html_to_text(html: str) -> str:
    return re.sub(r"[ \t\r\f\v]+", " ", "".join(_parse(html).parts))


def html_meta_text(html: str) -> str:
    """Open Graph / Twitter / description meta contents (the page's own summary)."""
    return "\n".join(dict.fromkeys(_parse(html).meta))


def decode_html(body: bytes, content_type: str) -> str:
    charset = None
    if "charset=" in content_type.lower():
        charset = content_type.lower().split("charset=", 1)[1].split(";")[0].strip(" \"'")
    if not charset:
        found = _META_CHARSET.search(body[:4096])
        charset = found.group(1).decode("ascii", "ignore") if found else None
    return documents.decode_text(body, charset)


def manual_verification(url: str) -> Verification:
    """No request: the platform serves nothing useful without JavaScript or signing in."""
    return Verification(
        url,
        Check.MANUAL,
        classify(url),
        detail="площадка показывает содержимое только с JavaScript или после входа — "
        "откройте ссылку в браузере",
    )


class PageVerifier:
    """Per-investigation verifier: robots.txt cache, page/document limits."""

    def __init__(self, net: NetworkServices, settings: Settings) -> None:
        self.net = net
        self.settings = settings
        self._robots: dict[str, robotparser.RobotFileParser | None] = {}
        self._robots_lock = asyncio.Lock()

    async def _robots_for(self, url: str) -> robotparser.RobotFileParser | None:
        """Parser for the URL's origin; None means "everything disallowed" (5xx/unreachable)."""
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        async with self._robots_lock:
            if origin in self._robots:
                return self._robots[origin]
            parser = robotparser.RobotFileParser()
            try:
                response = await self.net.http.fetch(
                    f"{origin}/robots.txt",
                    request_timeout=10,
                    max_bytes=512 * 1024,
                    retries=0,
                    accept_status=frozenset(range(200, 500)),
                )
            except NetworkError:
                self._robots[origin] = None
                return None
            if 400 <= response.status < 500:
                parser.parse([])  # RFC 9309 §2.3.1.3: unavailable → no restrictions
            else:
                parser.parse(decode_html(response.body, "").splitlines())
            self._robots[origin] = parser
            return parser

    async def allowed(self, url: str) -> bool:
        """robots.txt verdict for ``url`` (unreachable robots.txt → disallowed)."""
        robots = await self._robots_for(url)
        return robots is not None and robots.can_fetch(ROBOTS_TOKEN, url)

    def _entities(self, target: Target, text: str, *, whole: bool = False) -> tuple[Entity, ...]:
        return tuple(extract_near(target, text, region=self.settings.default_region, whole=whole))

    async def verify(self, target: Target, url: str) -> Verification:
        resource = classify(url)
        if is_local_host(url):
            return Verification(url, Check.LOCAL, resource)
        if manual_only(url):
            return manual_verification(url)
        robots = await self._robots_for(url)
        if robots is None or not robots.can_fetch(ROBOTS_TOKEN, url):
            detail = "robots.txt недоступен (5xx/таймаут)" if robots is None else None
            return Verification(url, Check.ROBOTS, resource, detail=detail)
        is_doc = resource.kind == "document"
        limit = (self.settings.doc_max_mb if is_doc else self.settings.page_max_kb / 1024) * 2**20
        try:
            response = await self.net.http.fetch(
                url,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/pdf,"
                    "application/vnd.openxmlformats-officedocument.*,text/plain,*/*;q=0.3",
                    "Accept-Language": "ru,en;q=0.8",
                },
                request_timeout=self.settings.page_timeout,
                max_bytes=int(limit),
                retries=0,
            )
        except HttpStatusError as exc:
            return Verification(url, Check.BLOCKED, resource, http_status=exc.status_code,
                                detail=str(exc))  # fmt: skip
        except NetworkError as exc:
            return Verification(url, Check.BLOCKED, resource, detail=str(exc))
        final_url = response.final_url or url
        if is_local_host(final_url):
            return Verification(url, Check.LOCAL, resource, final_url=final_url)
        headers = {k.lower(): v for k, v in response.headers.items()}
        content_type = headers.get("content-type", "")
        doc_type = document_type(final_url, content_type) or resource.doc_type
        resource = classify(url, content_type)  # the site the hit belongs to, not a login host
        final, code = final_url, response.status
        if is_login_redirect(url, final_url):
            return Verification(url, Check.BLOCKED, resource, final, code,
                                detail="перенаправление на страницу входа")  # fmt: skip
        if doc_type:
            document = await documents.extract(self.settings, doc_type, response.body)
            if document.error:
                return Verification(url, Check.UNSUPPORTED, resource, final, code,
                                    detail=document.error)  # fmt: skip
            for label, part in document.parts:
                found = find_identifier(target, part)
                if found:
                    return Verification(url, Check.CONFIRMED, resource, final, code, found, label,
                                        entities=self._entities(target, part))  # fmt: skip
            note = "текст извлечён частично" if document.truncated else None
            return Verification(url, Check.ABSENT, resource, final, code, detail=note)
        mime = content_type.split(";", 1)[0].strip().lower()
        if mime not in HTML_TYPES:
            return Verification(url, Check.UNSUPPORTED, resource, final, code, detail=mime)
        html = decode_html(response.body, content_type)
        text = html_to_text(html)
        match = find_identifier(target, text)
        if match:
            return Verification(url, Check.CONFIRMED, resource, final, code, match,
                                entities=self._entities(target, text))  # fmt: skip
        meta = html_meta_text(html)
        meta_match = find_identifier(target, meta)
        if meta_match:
            return Verification(url, Check.CONFIRMED, resource, final, code, meta_match,
                                "мета-описание страницы",
                                entities=self._entities(target, meta, whole=True))  # fmt: skip
        return Verification(
            url,
            Check.ABSENT,
            resource,
            final,
            code,
            detail="в HTML без JavaScript идентификатора нет (контент может подгружаться "
            "скриптами или быть доступен только после входа)",
        )
