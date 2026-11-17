"""Telegram public channel web preview (``https://t.me/s/<channel>?q=<text>``), no account.

The preview is plain server-rendered HTML: each post is a ``tgme_widget_message`` block with
``data-post="<channel>/<id>"``, its text in ``tgme_widget_message_text`` and a ``<time
datetime>``. Only public *channels* with the preview enabled have it; for groups, users and
unknown names Telegram redirects from ``/s/<name>`` to ``/<name>`` — we treat that as
"no public preview". Checked 2026-11-16; ``t.me/robots.txt`` answered 404 (no restrictions).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import quote, urlsplit

USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")
# t.me paths that are not channel names
RESERVED = frozenset(
    {
        "s",
        "c",
        "joinchat",
        "addstickers",
        "addemoji",
        "share",
        "proxy",
        "socks",
        "iv",
        "contact",
        "boost",
        "login",
        "setlanguage",
        "addtheme",
        "invoice",
        "confirmphone",
        "bg",
        "i",
    }
)
TELEGRAM_HOSTS = ("t.me", "telegram.me", "telegram.dog")


@dataclass(frozen=True, slots=True)
class Post:
    channel: str
    post_id: str
    text: str
    date: str | None

    @property
    def url(self) -> str:
        return f"https://t.me/{self.channel}/{self.post_id}"


@dataclass(slots=True)
class PreviewPage:
    channel: str
    title: str | None = None
    posts: list[Post] = field(default_factory=list)


def channel_from_url(url: str) -> str | None:
    """Channel username from a t.me link (``t.me/name``, ``t.me/s/name``, ``t.me/name/123``)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().removeprefix("www.")
    if host not in TELEGRAM_HOSTS:
        return None
    segments = [s for s in parts.path.split("/") if s]
    if segments and segments[0] == "s":
        segments = segments[1:]
    if not segments or segments[0].lower() in RESERVED or segments[0].startswith("+"):
        return None
    name = segments[0]
    return name if USERNAME_RE.match(name) else None


def preview_url(channel: str, query: str) -> str:
    return f"https://t.me/s/{channel}?q={quote(query)}"


def has_preview(final_url: str) -> bool:
    """False when Telegram redirected away from /s/ (group, user, unknown name)."""
    return urlsplit(final_url).path.startswith("/s/")


class _PreviewParser(HTMLParser):
    def __init__(self, channel: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page = PreviewPage(channel)
        self._post: str | None = None
        self._date: str | None = None
        self._text: list[str] = []
        self._text_depth = 0  # >0 while inside the message text div (nested tags counted)
        self._title_depth = 0
        self._title: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        classes = (a.get("class") or "").split()
        if tag == "div" and "tgme_widget_message" in classes and a.get("data-post"):
            self._flush()
            self._post = a["data-post"]
        elif tag == "div" and "tgme_widget_message_text" in classes and self._post:
            self._text_depth = 1
            return
        elif tag == "div" and "tgme_channel_info_header_title" in classes:
            self._title_depth = 1
            return
        if tag == "time" and self._post and a.get("datetime"):
            self._date = a["datetime"]
        if self._text_depth:
            if tag == "br":
                self._text.append("\n")
            elif tag == "div":
                self._text_depth += 1
        if self._title_depth and tag == "div":
            self._title_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag == "div" and self._text_depth:
            self._text_depth -= 1
        if tag == "div" and self._title_depth:
            self._title_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._text_depth:
            self._text.append(data)
        elif self._title_depth:
            self._title.append(data)

    def _flush(self) -> None:
        if self._post and "/" in self._post:
            channel, _, post_id = self._post.partition("/")
            text = " ".join("".join(self._text).split())
            if text and post_id.isdigit():
                self.page.posts.append(Post(channel, post_id, text, self._date))
        self._post, self._date, self._text = None, None, []

    def result(self) -> PreviewPage:
        self._flush()
        title = " ".join("".join(self._title).split())
        self.page.title = title or None
        return self.page


def parse_preview(channel: str, html: str) -> PreviewPage:
    parser = _PreviewParser(channel)
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, ValueError):  # malformed markup: keep what was parsed
        pass
    return parser.result()
