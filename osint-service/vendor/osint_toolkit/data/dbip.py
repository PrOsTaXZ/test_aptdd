"""DB-IP Lite databases (CC BY 4.0): local IP → country/city and IP → ASN lookups.

Downloads happen only through ``osint data update`` after confirmation. Only your own IP address
is visible to download.db-ip.com; no investigation data is sent. Files are size-capped,
decompressed with a ratio/size limit, validated with ``maxminddb`` and atomically replaced.
"""

from __future__ import annotations

import asyncio
import contextlib
import enum
import gzip
import hashlib
import io
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import maxminddb

from osint_toolkit.config import ensure_private_dir
from osint_toolkit.net.errors import HttpStatusError, NetworkError
from osint_toolkit.net.http import HttpClient

BASE_URL = "https://download.db-ip.com/free/"
ATTRIBUTION = "IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"
LICENSE_URL = "https://db-ip.com/db/lite.php"


class DbipKind(enum.StrEnum):
    COUNTRY = "country"
    CITY = "city"
    ASN = "asn"


# Hard caps protect against truncated/hostile downloads and gzip bombs.
MAX_DOWNLOAD = {DbipKind.COUNTRY: 40 << 20, DbipKind.ASN: 40 << 20, DbipKind.CITY: 250 << 20}
MAX_UNPACKED = {DbipKind.COUNTRY: 200 << 20, DbipKind.ASN: 200 << 20, DbipKind.CITY: 1500 << 20}
EXPECTED_TYPE = {DbipKind.COUNTRY: "country", DbipKind.CITY: "city", DbipKind.ASN: "asn"}


@dataclass(frozen=True, slots=True)
class DbipStatus:
    kind: DbipKind
    path: Path
    present: bool
    version: str | None = None
    downloaded_at: str | None = None
    build_date: str | None = None
    size: int = 0


def db_path(geo_dir: Path, kind: DbipKind) -> Path:
    return geo_dir / f"dbip-{kind.value}-lite.mmdb"


def _meta_path(geo_dir: Path, kind: DbipKind) -> Path:
    return geo_dir / f"dbip-{kind.value}-lite.json"


def status(geo_dir: Path, kind: DbipKind) -> DbipStatus:
    path = db_path(geo_dir, kind)
    if not path.is_file():
        return DbipStatus(kind, path, False)
    meta: dict[str, Any] = {}
    with contextlib.suppress(OSError, ValueError):
        meta = json.loads(_meta_path(geo_dir, kind).read_text(encoding="utf-8"))
    build = None
    try:
        with maxminddb.open_database(str(path)) as reader:
            build = datetime.fromtimestamp(reader.metadata().build_epoch, UTC).date().isoformat()
    except (OSError, ValueError, maxminddb.InvalidDatabaseError):
        pass
    return DbipStatus(
        kind, path, True, meta.get("version"), meta.get("downloaded_at"), build, path.stat().st_size
    )


def candidate_versions(today: date | None = None) -> list[str]:
    """Current month first, then the previous one (new files appear early each month)."""
    today = today or datetime.now(UTC).date()
    previous = date(today.year - (today.month == 1), (today.month - 2) % 12 + 1, 1)
    return [f"{today:%Y-%m}", f"{previous:%Y-%m}"]


def file_url(kind: DbipKind, version: str) -> str:
    return f"{BASE_URL}dbip-{kind.value}-lite-{version}.mmdb.gz"


@dataclass(frozen=True, slots=True)
class RemoteFile:
    kind: DbipKind
    version: str
    url: str
    size: int | None


async def find_remote(http: HttpClient, kind: DbipKind, today: date | None = None) -> RemoteFile:
    """Locate the newest published file (HEAD requests only)."""
    for version in candidate_versions(today):
        url = file_url(kind, version)
        response = await http.head(url)
        if response.status_code == 200:
            length = response.headers.get("Content-Length", "")
            return RemoteFile(kind, version, url, int(length) if length.isdigit() else None)
        if response.status_code not in (403, 404):
            raise HttpStatusError(
                f"db-ip.com ответил HTTP {response.status_code}", response.status_code
            )
    raise NetworkError(
        f"Файл DB-IP {kind.value} не найден для {', '.join(candidate_versions(today))}"
    )


async def download(http: HttpClient, remote: RemoteFile, geo_dir: Path) -> DbipStatus:
    _, compressed = await http.get_bytes(
        remote.url, max_bytes=MAX_DOWNLOAD[remote.kind], request_timeout=300, retries=1
    )
    # Decompression, validation and file replacement are blocking: keep them off the event loop.
    return await asyncio.to_thread(_install, compressed, remote, geo_dir)


def _install(compressed: bytes, remote: RemoteFile, geo_dir: Path) -> DbipStatus:
    ensure_private_dir(geo_dir)
    target = db_path(geo_dir, remote.kind)
    fd, tmp_name = tempfile.mkstemp(prefix=".dbip-", suffix=".mmdb", dir=geo_dir)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            unpacked = _gunzip_capped(compressed, handle, MAX_UNPACKED[remote.kind])
        validate(tmp, remote.kind)
        tmp.chmod(0o600)
        tmp.replace(target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    meta = {
        "version": remote.version,
        "source": remote.url,
        "downloaded_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
        "unpacked_bytes": unpacked,
        "license": ATTRIBUTION,
    }
    meta_path = _meta_path(geo_dir, remote.kind)
    fd = os.open(meta_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(meta, handle, indent=2)
    return status(geo_dir, remote.kind)


def _gunzip_capped(data: bytes, out: Any, limit: int) -> int:
    total = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            while chunk := stream.read(1 << 20):
                total += len(chunk)
                if total > limit:
                    raise NetworkError("Распакованный файл превышает допустимый размер")
                out.write(chunk)
    except (OSError, EOFError) as exc:
        raise NetworkError(f"Повреждённый архив DB-IP: {exc}") from exc
    return total


def validate(path: Path, kind: DbipKind) -> None:
    try:
        with maxminddb.open_database(str(path)) as reader:
            database_type = reader.metadata().database_type.lower()
    except (OSError, ValueError, maxminddb.InvalidDatabaseError) as exc:
        raise NetworkError(f"Файл не является корректной базой MaxMind DB: {exc}") from exc
    if EXPECTED_TYPE[kind] not in database_type:
        raise NetworkError(f"Неожиданный тип базы «{database_type}» для {kind.value}")


def lookup(path: Path, ip: str) -> tuple[dict[str, Any] | None, int | None]:
    """Record and prefix length for ``ip``. Raises ValueError for invalid addresses."""
    with maxminddb.open_database(str(path)) as reader:
        record, prefix = reader.get_with_prefix_len(ip)
    return (record if isinstance(record, dict) else None), prefix
