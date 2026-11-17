"""Дополнительные модули OSINT Service (вне vendor/): поиск по локальным файлам и веб-поиск через DuckDuckGo.

Написано по заданию 18.11.2026. Отличия от присланного кода — только там, где он не совпадал
с настоящим API инструмента друга или нарушал правила платформы:
  * импорты — из osint_toolkit.core.models / osint_toolkit.modules.base (vendor/ подключён через sys.path);
  * Confidence.POSSIBLE в инструменте нет — веб-находки помечаются Confidence.UNVERIFIED;
  * availability() возвращает Availability, applicability() — None («подходит»);
  * сеть проверяется как ctx.net.enabled (ctx.net — объект, он всегда «истинный»);
  * без подмены User-Agent: один честный заголовок; обход капчи и блокировок не делаем;
  * локальные файлы — из отдельной папки (OSINT_LOCAL_DIR, по умолчанию services/osint/local_data/),
    а не из рабочей папки процесса, где лежат файлы самой платформы.
"""
import asyncio
import csv
import io
import logging
import os
import random
import re
import sqlite3
import urllib.parse
import zipfile
from pathlib import Path

import httpx

try:
    import chardet
except ImportError:
    chardet = None

try:
    from openpyxl import load_workbook
except ImportError:
    load_workbook = None

try:
    from docx import Document
except ImportError:
    Document = None

from osint_toolkit.core.models import Confidence, TargetType
from osint_toolkit.modules.base import Availability, BaseModule, ModuleOutput

log = logging.getLogger(__name__)

MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_ZIP_MEMBER_BYTES = 50 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 200 * 1024 * 1024
MAX_FINDINGS_PER_MODULE = 500
REQUEST_TIMEOUT = httpx.Timeout(20.0, connect=5.0)
SUPPORTED_EXTENSIONS = {".csv", ".xlsx", ".docx", ".db", ".sqlite", ".sqlite3", ".zip"}
LOCAL_DIR = Path(os.environ.get("OSINT_LOCAL_DIR", str(Path(__file__).resolve().parent / "local_data")))

# Один честный заголовок: представляемся своим сервисом, а не браузером.
HEADERS = {
    "User-Agent": "tip-osint/0.1 (threat intelligence platform)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
}

SOCIAL_SITES = [
    ("site:tiktok.com", "TikTok"),
    ("site:instagram.com", "Instagram"),
    ("site:t.me", "Telegram"),
    ("site:vk.com", "VK"),
    ("site:ok.ru", "OK"),
]

REGISTRY_SITES = [
    ("site:remarka.city", "Remarka"),
    ("site:list-org.com", "List-Org"),
    ("site:rusprofile.ru", "Rusprofile"),
    ("site:zachestnyibiznes.ru", "ЗаЧестныйБизнес"),
]

NEWS_SITES = [
    ("site:tass.ru", "ТАСС"),
    ("site:ria.ru", "РИА"),
    ("site:inform.kz", "Inform.kz"),
    ("site:sputnik.by", "Sputnik.by"),
]


def _target_to_string(target):
    if hasattr(target, "normalized"):
        return str(target.normalized)
    if hasattr(target, "value"):
        return str(target.value)
    return str(target)


def _decode_bytes(raw_data, forced_encoding=None):
    if not raw_data:
        return ""
    encoding = forced_encoding or "utf-8-sig"
    if forced_encoding is None and chardet is not None:
        try:
            detected = chardet.detect(raw_data[:200_000])
            encoding = detected.get("encoding") or encoding
        except Exception:
            log.exception("chardet failed")
    try:
        return raw_data.decode(encoding, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return raw_data.decode("utf-8", errors="replace")


def _normalize(value):
    return str(value if value is not None else "").casefold().strip()


def _unique_headers(headers):
    result, counts = [], {}
    for h in headers:
        base = str(h or "Без названия")
        counts[base] = counts.get(base, 0) + 1
        result.append(base if counts[base] == 1 else f"{base} ({counts[base]})")
    return result


def _row_to_dict(headers, row):
    return {str(h): (str(v) if v is not None else "") for h, v in zip(headers, row)}


def _row_matches(row, query):
    q = _normalize(query)
    return bool(q) and any(q in _normalize(v) for v in row if v is not None)


def _clean_html(value):
    return re.sub(r"\s+", " ", value or "").strip()


def _decode_ddg_url(url):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    return params["uddg"][0] if "uddg" in params else url


def _search_csv_stream(stream, query, collector, source_info, default_delimiter=";"):
    sample = stream.read(200_000)
    if hasattr(stream, "seek"):
        stream.seek(0)
    text_sample = _decode_bytes(sample)
    delimiter = default_delimiter
    candidates = [";", ",", "\t", "|"]
    try:
        dialect = csv.Sniffer().sniff(text_sample[:20_000], delimiters=";,\t|")
        delimiter = dialect.delimiter
    except csv.Error:
        first_line = text_sample.splitlines()[0] if text_sample.splitlines() else ""
        if first_line:
            delimiter = max(candidates, key=first_line.count)
            if first_line.count(delimiter) == 0:
                delimiter = default_delimiter
    encoding = "utf-8-sig"
    if chardet is not None:
        try:
            detected = chardet.detect(sample[:200_000])
            encoding = detected.get("encoding") or encoding
        except Exception:
            pass
    wrapper = io.TextIOWrapper(stream, encoding=encoding, errors="replace", newline="")
    try:
        reader = csv.reader(wrapper, delimiter=delimiter)
        headers_raw = next(reader, None)
        if headers_raw is None:
            return
        headers = _unique_headers([str(h or "") for h in headers_raw])
        for row_number, row in enumerate(reader, start=2):
            if _row_matches(row, query):
                found = _row_to_dict(headers, row)
                found.update(source_info or {})
                found["Строка"] = str(row_number)
                collector(found)
    finally:
        wrapper.detach()  # закрывает поток тот, кто его открыл


def _search_xlsx_stream(stream, query, collector, source_info):
    if load_workbook is None:
        raise RuntimeError("Установите openpyxl для чтения XLSX")
    wb = load_workbook(stream, read_only=True, data_only=True)
    try:
        for ws in wb.worksheets:
            rows = ws.iter_rows(values_only=True)
            headers_raw = next(rows, None)
            if headers_raw is None:
                continue
            headers = _unique_headers([str(h or "") for h in headers_raw])
            for row_number, row in enumerate(rows, start=2):
                if _row_matches(row, query):
                    found = _row_to_dict(headers, row)
                    found.update(source_info or {})
                    found["Лист"] = ws.title
                    found["Строка"] = str(row_number)
                    collector(found)
    finally:
        wb.close()


def _search_docx_stream(stream, query, collector, source_info):
    if Document is None:
        raise RuntimeError("Установите python-docx для чтения DOCX")
    doc = Document(stream)
    blocks = []
    for p in doc.paragraphs:
        if p.text.strip():
            blocks.append(p.text.strip())
    for ti, table in enumerate(doc.tables, start=1):
        for ri, row in enumerate(table.rows, start=1):
            cells = [c.text.strip() for c in row.cells]
            text = " | ".join(c for c in cells if c)
            if text:
                blocks.append(f"Таблица {ti}, строка {ri}: {text}")
    for idx, block in enumerate(blocks, start=1):
        if _normalize(query) in _normalize(block):
            found = {"Тип источника": "Word", "Содержимое": block, "Блок": str(idx)}
            found.update(source_info or {})
            collector(found)


def _search_sqlite(file_path, query, collector, source_info):
    uri = Path(file_path).resolve().as_uri() + "?mode=ro"
    conn = None
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        for (table_name,) in cur.fetchall():
            try:
                quoted = '"' + table_name.replace('"', '""') + '"'
                cur.execute(f"SELECT * FROM {quoted}")
                headers = _unique_headers([d[0] for d in cur.description or []])
                row_number = 0
                while True:
                    batch = cur.fetchmany(500)
                    if not batch:
                        break
                    for row in batch:
                        row_number += 1
                        if _row_matches(row, query):
                            found = _row_to_dict(headers, row)
                            found.update(source_info or {})
                            found["Таблица БД"] = table_name
                            found["Строка"] = str(row_number)
                            collector(found)
            except sqlite3.Error as exc:
                log.warning("Пропущена таблица %r: %s", table_name, exc)
    finally:
        if conn is not None:
            conn.close()


def _search_zip(file_path, query, collector, source_info):
    allowed = {".csv", ".xlsx", ".docx"}
    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            total = 0
            for member in archive.infolist():
                suffix = Path(member.filename).suffix.lower()
                if member.is_dir() or suffix not in allowed:
                    continue
                if member.file_size > MAX_ZIP_MEMBER_BYTES:
                    continue
                total += member.file_size
                if total > MAX_ZIP_TOTAL_BYTES:
                    log.warning("Превышен общий лимит ZIP %s", file_path)
                    break
                try:
                    with archive.open(member, "r") as ms:
                        data = ms.read(MAX_ZIP_MEMBER_BYTES + 1)
                    if len(data) > MAX_ZIP_MEMBER_BYTES:
                        continue
                    stream = io.BytesIO(data)
                    info = dict(source_info or {})
                    info.update({"Архив": str(file_path), "Файл внутри": member.filename})
                    if suffix == ".csv":
                        _search_csv_stream(stream, query, collector, info)
                    elif suffix == ".xlsx":
                        _search_xlsx_stream(stream, query, collector, info)
                    elif suffix == ".docx":
                        _search_docx_stream(stream, query, collector, info)
                except Exception as exc:
                    log.warning("Ошибка члена ZIP %s: %s", member.filename, exc)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        log.warning("Ошибка ZIP %s: %s", file_path, exc)


class LocalFilesSearchModule(BaseModule):
    name = "local.files"
    title = "Поиск по локальным файлам (CSV/XLSX/DOCX/SQLite/ZIP)"
    target_types = frozenset({
        TargetType.NAME, TargetType.USERNAME, TargetType.PHONE, TargetType.EMAIL
    })
    limitations = (
        "Ищет только в файлах папки локальных данных сервиса, без рекурсии",
        "Поддерживаются CSV, XLSX, DOCX, SQLite, ZIP",
        "Совпадение подстроки не подтверждает принадлежность данных объекту",
    )

    def __init__(self, base_dir=None):
        super().__init__()
        self.base_dir = Path(base_dir) if base_dir else LOCAL_DIR

    def availability(self, settings):
        return Availability(True)

    def applicability(self, target, settings):
        return None

    async def run(self, target, ctx):
        query = _target_to_string(target)
        return await asyncio.to_thread(self._run_sync, query, target)

    def _run_sync(self, query, original_target):
        out = ModuleOutput()
        if not self.base_dir.is_dir():
            out.limitations.append(f"Папка не найдена: {self.base_dir}")
            return out
        files = [
            p for p in self.base_dir.iterdir()
            if p.is_file()
            and p.suffix.lower() in SUPPORTED_EXTENSIONS
            and p.name != "app.log"
        ]
        if not files:
            out.limitations.append("В папке локальных данных нет поддерживаемых файлов")
            return out

        def collector(row):
            if len(out.findings) >= MAX_FINDINGS_PER_MODULE:
                return
            source = row.get("Источник") or row.get("Архив") or "локальный файл"
            value = "; ".join(f"{k}={v}" for k, v in row.items() if k not in {"Источник"})
            # source_url у находки обязателен (file://, https:// …) — ссылка на сам файл.
            url = Path(str(source)).resolve().as_uri() if source != "локальный файл" else self.base_dir.resolve().as_uri()
            out.findings.append(self.finding(
                original_target, self.name, value, Confidence.CONFIRMED,
                str(source), url, "Точное совпадение в локальном файле"))

        for path in files:
            if len(out.findings) >= MAX_FINDINGS_PER_MODULE:
                out.limitations.append(f"Достигнут лимит {MAX_FINDINGS_PER_MODULE} находок")
                break
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    out.errors.append(f"{path.name}: файл превышает {MAX_FILE_BYTES} байт")
                    continue
                suffix = path.suffix.lower()
                info = {"Источник": str(path)}
                if suffix == ".csv":
                    with path.open("rb") as s:
                        _search_csv_stream(s, query, collector, info)
                elif suffix == ".xlsx":
                    with path.open("rb") as s:
                        _search_xlsx_stream(s, query, collector, info)
                elif suffix == ".docx":
                    with path.open("rb") as s:
                        _search_docx_stream(s, query, collector, info)
                elif suffix in {".db", ".sqlite", ".sqlite3"}:
                    _search_sqlite(path, query, collector, info)
                elif suffix == ".zip":
                    _search_zip(path, query, collector, info)
            except Exception as exc:
                out.errors.append(f"{path.name}: {exc}")
        return out


class WebCascadeSearchModule(BaseModule):
    name = "web.cascade"
    title = "Каскадный веб-поиск (DuckDuckGo + реестры + соцсети + СМИ)"
    target_types = frozenset({
        TargetType.NAME, TargetType.USERNAME, TargetType.PHONE, TargetType.EMAIL
    })
    limitations = (
        "Результаты поисковика не верифицированы",
        "DuckDuckGo может блокировать автоматические запросы (429) или показывать проверку на робота — её не обходим",
        "Охватываются только верхние выдачи",
    )
    search_url = "https://html.duckduckgo.com/html/"

    def availability(self, settings):
        return Availability(True)

    def applicability(self, target, settings):
        return None

    async def run(self, target, ctx):
        query = _target_to_string(target)
        out = ModuleOutput()
        if not ctx.net.enabled:
            out.limitations.append("Сетевой доступ отключён в контексте")
            return out

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, headers=HEADERS) as client:
            for search_query in self._build_search_targets(query):
                if len(out.findings) >= MAX_FINDINGS_PER_MODULE:
                    out.limitations.append(f"Достигнут лимит {MAX_FINDINGS_PER_MODULE} находок")
                    break
                try:
                    results = await self._search_ddg(client, search_query)
                    platform = self._classify(search_query)
                    query_url = self.search_url + "?" + urllib.parse.urlencode({"q": search_query})
                    for r in results:
                        if len(out.findings) >= MAX_FINDINGS_PER_MODULE:
                            break
                        link = r["link"] if r["link"].startswith(("https://", "http://")) else query_url
                        out.findings.append(self.finding(
                            target, self.name, r["desc"], Confidence.UNVERIFIED,
                            f"DDG: {platform}", link,
                            "Результат поисковой выдачи DuckDuckGo"))
                except Exception as exc:
                    out.errors.append(f"{search_query}: {exc}")
                await asyncio.sleep(random.uniform(0.8, 1.6))
        return out

    def _build_search_targets(self, q):
        targets = [f"{prefix} {q}" for prefix, _ in REGISTRY_SITES]
        targets += [f"{prefix} {q}" for prefix, _ in SOCIAL_SITES]
        targets.append(f"{q} новости СМИ")
        targets += [f"{prefix} {q}" for prefix, _ in NEWS_SITES]
        targets.append(q)
        targets.append(f'"{q}"')
        return targets

    def _classify(self, sq):
        if any(k in sq for k in ("remarka", "rusprofile", "list-org", "zachestnyibiznes")):
            return "Реестр / База данных"
        if any(k in sq for k in ("tiktok", "instagram", "t.me", "vk.com", "ok.ru")):
            return "Социальные сети"
        if any(k in sq for k in ("tass", "ria", "inform", "sputnik")):
            return "Новости и СМИ СНГ"
        return "Глобальный веб"

    async def _search_ddg(self, client, search_query):
        url = self.search_url + "?" + urllib.parse.urlencode({"q": search_query})
        response = await client.get(url)
        if response.status_code != 200:
            # 202 — DuckDuckGo показал проверку на робота, 429 — слишком много запросов.
            raise RuntimeError(f"HTTP {response.status_code}")
        html = response.text
        snippets = re.findall(r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', html, re.DOTALL)
        titles = re.findall(r'<a[^>]+class="result__a"[^>]*>(.*?)</a>', html, re.DOTALL)
        links = re.findall(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', html)
        results = []
        for i in range(max(len(snippets), len(titles))):
            desc = _clean_html(re.sub(r"<.*?>", "", snippets[i])) if i < len(snippets) else ""
            if len(desc) < 3:
                continue
            title = _clean_html(re.sub(r"<.*?>", "", titles[i])) if i < len(titles) else ""
            link = _decode_ddg_url(links[i]) if i < len(links) else ""
            results.append({"title": title, "desc": desc, "link": link})
        return results


class SocialMediaSearchModule(WebCascadeSearchModule):
    name = "web.social"
    title = "Поиск по социальным сетям (TikTok / Instagram / TG / VK / OK)"
    limitations = (
        "Охватываются только публичные упоминания",
        "DuckDuckGo может блокировать автоматические запросы",
    )

    def _build_search_targets(self, q):
        return [f"{prefix} {q}" for prefix, _ in SOCIAL_SITES] + [f'"{q}"']
