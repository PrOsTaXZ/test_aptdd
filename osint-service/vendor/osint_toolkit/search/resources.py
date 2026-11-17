"""What kind of resource a URL is: social network, document, classifieds, forum, code, paste."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import urlsplit

SOCIAL: dict[str, str] = {
    "vk.com": "ВКонтакте",
    "m.vk.com": "ВКонтакте",
    "vk.ru": "ВКонтакте",
    "ok.ru": "Одноклассники",
    "t.me": "Telegram",
    "telegram.me": "Telegram",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "linkedin.com": "LinkedIn",
    "tiktok.com": "TikTok",
    "x.com": "X (Twitter)",
    "twitter.com": "X (Twitter)",
    "youtube.com": "YouTube",
    "reddit.com": "Reddit",
    "threads.net": "Threads",
    "pinterest.com": "Pinterest",
    "my.mail.ru": "Мой Мир",
    "habr.com": "Хабр",
    "dzen.ru": "Дзен",
    "livejournal.com": "LiveJournal",
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
}
CLASSIFIEDS = (
    "avito.ru",
    "youla.ru",
    "drom.ru",
    "auto.ru",
    "cian.ru",
    "olx.kz",
    "krisha.kz",
    "kolesa.kz",
    "market.kz",
    "hh.ru",
    "hh.kz",
)
PHONEBOOKS = ("neberitrubku.ru", "zvonili.com", "tellows.ru", "kto-zvonil.ru")
PASTE = ("pastebin.com", "paste.ee", "rentry.co", "ghostbin.co")
CODE = ("github.com", "gitlab.com", "bitbucket.org", "gist.github.com")
DOCUMENT_EXTENSIONS = {
    ".pdf": "pdf",
    ".docx": "docx",
    ".xlsx": "xlsx",
    ".pptx": "pptx",
    ".odt": "odt",
    ".ods": "ods",
    ".odp": "odp",
    ".txt": "txt",
    ".csv": "csv",
    ".doc": "doc",
    ".xls": "xls",
    ".ppt": "ppt",
    ".rtf": "rtf",
}
DOCUMENT_MIME = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
    "application/vnd.oasis.opendocument.text": "odt",
    "application/vnd.oasis.opendocument.spreadsheet": "ods",
    "application/vnd.oasis.opendocument.presentation": "odp",
    "text/csv": "csv",
    "application/msword": "doc",
    "application/vnd.ms-excel": "xls",
    "application/vnd.ms-powerpoint": "ppt",
    "application/rtf": "rtf",
}
# Platforms that serve no post/profile text without JavaScript or signing in: opening them only
# burns the page budget (checked 2026-11: VK answers with an empty m.vk.com shell).
MANUAL_ONLY = (
    "vk.com",
    "vk.ru",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "tiktok.com",
    "x.com",
    "twitter.com",
    "threads.net",
)
KIND_LABELS = {
    "social": "Соцсеть",
    "document": "Документ",
    "classifieds": "Объявления",
    "phonebook": "«Кто звонил»",
    "paste": "Paste-сайт",
    "code": "Код",
    "forum": "Форум",
    "web": "Веб-страница",
}


@dataclass(frozen=True, slots=True)
class Resource:
    kind: str  # key of KIND_LABELS
    platform: str  # human name of the site / platform
    doc_type: str | None = None

    @property
    def label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind)


def _host(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    return host.removeprefix("www.")


def _matches(host: str, domains: tuple[str, ...] | dict[str, str]) -> str | None:
    for domain in domains:
        if host == domain or host.endswith("." + domain):
            return domain
    return None


def manual_only(url: str) -> bool:
    return _matches(_host(url), MANUAL_ONLY) is not None


def document_type(url: str, content_type: str | None = None) -> str | None:
    if content_type:
        mime = content_type.split(";", 1)[0].strip().lower()
        if mime in DOCUMENT_MIME:
            return DOCUMENT_MIME[mime]
        if mime == "text/plain" and PurePosixPath(urlsplit(url).path).suffix.lower() == ".txt":
            return "txt"
    return DOCUMENT_EXTENSIONS.get(PurePosixPath(urlsplit(url).path).suffix.lower())


def classify(url: str, content_type: str | None = None) -> Resource:
    host = _host(url)
    doc = document_type(url, content_type)
    if doc:
        return Resource("document", host, doc)
    social = _matches(host, SOCIAL)
    if social and social not in CODE:
        return Resource("social", SOCIAL[social])
    for kind, domains in (
        ("code", CODE),
        ("classifieds", CLASSIFIEDS),
        ("phonebook", PHONEBOOKS),
        ("paste", PASTE),
    ):
        if _matches(host, domains):
            return Resource(kind, host)
    path = urlsplit(url).path.lower()
    if "forum" in host or any(p in path for p in ("/forum", "viewtopic", "/thread", "showthread")):
        return Resource("forum", host)
    return Resource("web", host)
