"""Application settings.

Sources (highest priority first): explicit constructor arguments → ``OSINT_*`` environment
variables → ``~/.config/osint-toolkit/.env``. Directories follow the XDG Base Directory spec, so
the toolkit only touches its own folders and never scans the rest of the home directory.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import AnyHttpUrl, Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from osint_toolkit import APP_NAME

log = logging.getLogger(__name__)

SECRET_FIELDS = ("brave_api_key", "ipinfo_token", "tineye_api_key")


def _xdg(var: str, fallback: str) -> Path:
    value = os.environ.get(var)
    base = Path(value) if value and Path(value).is_absolute() else Path.home() / fallback
    return base / APP_NAME


def config_dir() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config")


def default_env_file() -> Path:
    return config_dir() / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="OSINT_",
        env_file_encoding="utf-8",
        extra="ignore",
        validate_default=True,
    )

    offline: bool = False
    store_targets: bool = True
    module_timeout: float = Field(default=60.0, gt=0, le=3600)
    max_concurrency: int = Field(default=4, ge=1, le=32)
    default_region: str | None = None
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    report_formats: str = "txt,json,html,md"  # comma list; "none" disables auto reports
    report_classification: str = Field(default="Конфиденциально", max_length=60)  # PDF marking
    report_organization: str = Field(default="", max_length=200)  # PDF title page
    report_author: str = Field(default="", max_length=200)  # "Исполнитель" on the title page

    # Network (used only by modules the user consented to)
    http_timeout: float = Field(default=20.0, gt=0, le=300)
    http_concurrency: int = Field(default=4, ge=1, le=32)  # simultaneous HTTP requests, total
    http_per_host: int = Field(default=2, ge=1, le=8)  # simultaneous requests per host
    http_proxy: AnyHttpUrl | None = None  # e.g. http://127.0.0.1:8080
    dns_timeout: float = Field(default=5.0, gt=0, le=60)
    dns_concurrency: int = Field(default=8, ge=1, le=64)

    # Public mention search (email / phone / name)
    search_provider: Literal["auto", "searxng", "brave"] = "auto"  # auto: SearXNG if configured
    search_max_queries: int = Field(default=40, ge=1, le=200)  # dork queries per identifier
    dork_groups: str = "all"  # all | comma list: exact,social,classifieds_ru,classifieds_kz,…
    search_results: int = Field(default=20, ge=1, le=20)  # results per query
    brave_min_interval: float = Field(default=1.1, ge=0, le=60)  # seconds between Brave calls
    searxng_min_interval: float = Field(default=2.0, ge=0, le=60)
    # Verification of search hits: open pages/documents and look for the identifier
    verify_pages: int = Field(default=40, ge=0, le=300)  # 0 = do not open pages
    verify_documents: int = Field(default=15, ge=0, le=100)  # documents opened in addition
    verify_social: int = Field(default=20, ge=0, le=100)  # social pages, own budget
    # Telegram public channel preview (t.me/s/<channel>?q=…), no account
    tg_channels: str = ""  # comma list of public channel usernames to always search
    tg_max_channels: int = Field(default=20, ge=0, le=100)
    tg_discovery_queries: int = Field(default=2, ge=0, le=10)  # "site:t.me" searches
    tg_variants: int = Field(default=2, ge=1, le=6)  # spellings searched in each channel
    tg_min_interval: float = Field(default=3.0, ge=1, le=60)
    verify_concurrency: int = Field(default=4, ge=1, le=16)
    page_timeout: float = Field(default=15.0, gt=0, le=120)
    page_max_kb: int = Field(default=3072, ge=64, le=20480)
    doc_max_mb: int = Field(default=15, ge=1, le=100)
    doc_extract_timeout: float = Field(default=60.0, ge=5, le=600)
    own_emails: str = ""  # comma list of YOUR addresses — Gravatar is checked only for these

    # Optional adapters (stage 6)
    tineye_store_results: bool = False  # keep TinEye matches in history/reports (check terms)
    tineye_max_matches: int = Field(default=30, ge=1, le=100)
    harvester_sources: str = "crtsh,certspotter,hackertarget,otx,rapiddns,urlscan,waybackarchive"
    harvester_limit: int = Field(default=200, ge=10, le=1000)
    harvester_total_timeout: float = Field(default=300.0, ge=30, le=3600)
    holehe_timeout: float = Field(default=10.0, gt=0, le=60)
    holehe_max_connections: int = Field(default=8, ge=1, le=40)
    holehe_total_timeout: float = Field(default=300.0, ge=30, le=3600)

    # Maigret (username search) — runs in a bwrap sandbox
    maigret_top_sites: int = Field(default=0, ge=0, le=10000)  # 0 = whole database
    maigret_timeout: float = Field(default=10.0, gt=0, le=120)  # per-site request timeout
    maigret_retries: int = Field(default=1, ge=0, le=3)
    maigret_max_connections: int = Field(default=20, ge=1, le=100)
    maigret_total_timeout: float = Field(default=1800.0, ge=30, le=7200)

    data_dir: Path = Field(default_factory=lambda: _xdg("XDG_DATA_HOME", ".local/share"))
    state_dir: Path = Field(default_factory=lambda: _xdg("XDG_STATE_HOME", ".local/state"))
    reports_dir: Path | None = None  # defaults to <data_dir>/reports

    brave_api_key: SecretStr | None = None
    searxng_url: AnyHttpUrl | None = None
    ipinfo_token: SecretStr | None = None
    tineye_api_key: SecretStr | None = None

    @field_validator("report_formats")
    @classmethod
    def _formats(cls, value: str) -> str:
        allowed = {"txt", "json", "html", "md", "markdown", "pdf", "all", "none"}
        names = {v.strip().lower() for v in value.split(",") if v.strip()}
        if not names <= allowed:
            raise ValueError(f"unknown report formats: {sorted(names - allowed)}")
        return value

    @field_validator("dork_groups")
    @classmethod
    def _dork_groups(cls, value: str) -> str:
        from osint_toolkit.dorks.builder import GROUP_KEYS

        names = {v.strip() for v in value.split(",") if v.strip()}
        if names != {"all"} and not names <= GROUP_KEYS:
            raise ValueError(f"unknown dork groups: {sorted(names - GROUP_KEYS)}")
        return value

    def enabled_dork_groups(self) -> frozenset[str] | None:
        names = {v.strip() for v in self.dork_groups.split(",") if v.strip()}
        return None if "all" in names or not names else frozenset(names)

    @field_validator("default_region", mode="before")
    @classmethod
    def _region(cls, value: object) -> object:
        if value in (None, ""):
            return None
        if not isinstance(value, str) or len(value) != 2 or not value.isalpha():
            raise ValueError("default_region must be a two-letter ISO 3166 code, e.g. RU")
        return value.upper()

    @field_validator(
        "brave_api_key",
        "ipinfo_token",
        "tineye_api_key",
        "searxng_url",
        "reports_dir",
        "http_proxy",
        mode="before",
    )
    @classmethod
    def _empty_to_none(cls, value: object) -> object:
        return None if value == "" else value

    @property
    def db_path(self) -> Path:
        return self.data_dir / "history.sqlite3"

    @property
    def log_dir(self) -> Path:
        return self.state_dir / "logs"

    @property
    def geo_dir(self) -> Path:
        return self.data_dir / "geo"

    def is_own_email(self, address: str) -> bool:
        own = {e.strip().lower() for e in self.own_emails.split(",") if e.strip()}
        return address.strip().lower() in own

    @property
    def tools_dir(self) -> Path:
        return self.data_dir / "tools"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def effective_reports_dir(self) -> Path:
        return self.reports_dir or self.data_dir / "reports"

    def has(self, name: str) -> bool:
        """True when an optional setting (API key, URL) is configured."""
        value = getattr(self, name, None)
        if isinstance(value, SecretStr):
            return bool(value.get_secret_value())
        return value not in (None, "")

    def secret_values(self) -> list[str]:
        values = []
        for name in SECRET_FIELDS:
            secret = getattr(self, name)
            if secret is not None and secret.get_secret_value():
                values.append(secret.get_secret_value())
        return values

    def masked(self) -> dict[str, str]:
        """All settings as display strings with secrets masked."""
        out: dict[str, str] = {}
        for name in type(self).model_fields:
            value = getattr(self, name)
            if isinstance(value, SecretStr):
                raw = value.get_secret_value()
                out[name] = f"••••{raw[-4:]}" if len(raw) > 8 else "••••"
            else:
                out[name] = "—" if value is None else str(value)
        return out


def load_settings(env_file: Path | None = None) -> Settings:
    path = env_file if env_file is not None else default_env_file()
    if path.exists():
        warn_if_insecure(path)
    return Settings(_env_file=path if path.exists() else None)


def load_settings_lenient(env_file: Path | None = None) -> tuple[Settings, list[str]]:
    """Settings for maintenance commands (``osint update``).

    A value written for a newer version (e.g. ``OSINT_MAIGRET_TOP_SITES=0`` before 0 was
    allowed) must not lock the user out of updating to that version: fields this version
    cannot accept fall back to their defaults and are returned so the caller can warn.
    """
    try:
        return load_settings(env_file), []
    except ValidationError as exc:
        invalid = sorted({str(e["loc"][0]) for e in exc.errors() if e.get("loc")})
    path = env_file if env_file is not None else default_env_file()
    defaults = {
        name: Settings.model_fields[name].get_default(call_default_factory=True)
        for name in invalid
        if name in Settings.model_fields
    }
    return Settings(_env_file=path if path.exists() else None, **defaults), invalid


def warn_if_insecure(path: Path) -> bool:
    """Log a warning when the .env file is readable by group/others. Returns True if insecure."""
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        log.warning("%s is accessible by other users; run: chmod 600 %s", path, path)
        return True
    return False


def ensure_private_dir(path: Path) -> Path:
    """Create a directory readable only by the current user."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def init_env_file(path: Path | None = None) -> tuple[Path, bool]:
    """Create the user .env from the bundled template (mode 0600). Returns (path, created)."""
    target = path or default_env_file()
    if target.exists():
        return target, False
    ensure_private_dir(target.parent)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(ENV_TEMPLATE)
    return target, True


def update_env_values(values: dict[str, str], path: Path | None = None) -> Path:
    """Set ``KEY=value`` lines in the user .env, leaving every other line untouched.

    Existing (uncommented) lines for a key are replaced in place, missing keys are appended.
    The file stays ``0600`` and is replaced atomically, so a crash never leaves it half written.
    """
    for key, value in values.items():
        if not re.fullmatch(r"OSINT_[A-Z0-9_]+", key) or "\n" in value or "\r" in value:
            raise ValueError(f"недопустимый параметр: {key}")
    target = path or default_env_file()
    if not target.exists():
        init_env_file(target)
    lines = target.read_text(encoding="utf-8").splitlines()
    pending = dict(values)
    out: list[str] = []
    for line in lines:
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key in values and not line.lstrip().startswith("#"):
            if key in pending:
                out.append(f"{key}={pending.pop(key)}")
            continue  # a duplicate line for the same key would override ours: drop it
        out.append(line)
    out.extend(f"{key}={value}" for key, value in pending.items())
    fd, name = tempfile.mkstemp(prefix=".env.", dir=target.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(out) + "\n")
        tmp.chmod(0o600)
        tmp.replace(target)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    return target


ENV_TEMPLATE = """\
# osint-toolkit settings. Keep this file private (chmod 600). Never commit it.
OSINT_OFFLINE=false
OSINT_STORE_TARGETS=true
OSINT_MODULE_TIMEOUT=60
OSINT_MAX_CONCURRENCY=4
OSINT_DEFAULT_REGION=
OSINT_LOG_LEVEL=INFO
# Reports written after every run: txt,json,html,md | all | none
OSINT_REPORT_FORMATS=txt,json,html,md
OSINT_REPORT_CLASSIFICATION=Конфиденциально
OSINT_REPORT_ORGANIZATION=
OSINT_REPORT_AUTHOR=

# Network limits (only for modules you allow)
OSINT_HTTP_TIMEOUT=20
OSINT_HTTP_CONCURRENCY=4
OSINT_HTTP_PER_HOST=2
OSINT_HTTP_PROXY=
OSINT_DNS_TIMEOUT=5
OSINT_DNS_CONCURRENCY=8

# Mention search: auto | searxng | brave
OSINT_SEARCH_PROVIDER=auto
OSINT_SEARCH_MAX_QUERIES=40
OSINT_DORK_GROUPS=all
OSINT_SEARCH_RESULTS=20
OSINT_BRAVE_MIN_INTERVAL=1.1
OSINT_SEARXNG_MIN_INTERVAL=2
# Open found pages/documents (robots.txt, no JavaScript) and confirm the identifier is there
OSINT_VERIFY_PAGES=40
OSINT_VERIFY_DOCUMENTS=15
OSINT_VERIFY_SOCIAL=20
# Telegram public channels (t.me/s web preview, no account): your channel list (comma
# separated usernames) plus channels found by "site:t.me" searches
OSINT_TG_CHANNELS=
OSINT_TG_MAX_CHANNELS=20
OSINT_TG_MIN_INTERVAL=3
OSINT_DOC_MAX_MB=15
# Your own addresses (Gravatar is checked only for these, or with --own)
OSINT_OWN_EMAILS=

# Optional adapters
OSINT_TINEYE_STORE_RESULTS=false
OSINT_TINEYE_MAX_MATCHES=30
OSINT_HARVESTER_SOURCES=crtsh,certspotter,hackertarget,otx,rapiddns,urlscan,waybackarchive
OSINT_HARVESTER_LIMIT=200
OSINT_HARVESTER_TOTAL_TIMEOUT=300
OSINT_HOLEHE_TIMEOUT=10
OSINT_HOLEHE_MAX_CONNECTIONS=8
OSINT_HOLEHE_TOTAL_TIMEOUT=300

# Maigret username search (sandboxed; install: osint tools install maigret)
OSINT_MAIGRET_TOP_SITES=0
OSINT_MAIGRET_TIMEOUT=10
OSINT_MAIGRET_RETRIES=1
OSINT_MAIGRET_MAX_CONNECTIONS=20
OSINT_MAIGRET_TOTAL_TIMEOUT=1800

# Optional API keys
OSINT_BRAVE_API_KEY=
OSINT_SEARXNG_URL=
OSINT_IPINFO_TOKEN=
OSINT_TINEYE_API_KEY=
"""
