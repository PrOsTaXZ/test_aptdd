#!/usr/bin/env python3
"""OSINT Service: проверка телефонов модулями Personal OSINT Toolkit (vendor/osint_toolkit).

POST /api/v1/phone/analyze  {"phone": "+7..."} -> сведения о номерном диапазоне (офлайн, без сети)
POST /api/v1/phone/mentions {"phone": "+7..."} -> упоминания номера: поисковик и публичные
                                                  Telegram-каналы (внешние запросы)
GET  /api/v1/health -> состояние и что доступно

Какие номера проверять и когда, решает ядро: сервис сам ничего не ищет и номеров не хранит.
Находки, которые условия поискового провайдера запрещают хранить (ephemeral), наружу не отдаются.
Правила те же, что у остальных сервисов: токен X-Service-Token, регистрация в ядре, единый формат ошибок.
"""
import asyncio
import hmac
import json
import logging
import os
import re
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "vendor"))

from osint_toolkit.config import Settings  # noqa: E402
from osint_toolkit.core.detector import parse_as  # noqa: E402
from osint_toolkit.core.models import TargetType  # noqa: E402
from osint_toolkit.modules.base import ModuleContext  # noqa: E402
from osint_toolkit.modules.email.disposable import DisposableEmailModule  # noqa: E402
from osint_toolkit.modules.email.syntax import EmailSyntaxModule  # noqa: E402
from osint_toolkit.modules.domain.mx import MxModule  # noqa: E402
from osint_toolkit.modules.mentions.identifiers import EmailMentionsModule, NameMentionsModule, PhoneMentionsModule  # noqa: E402
from osint_toolkit.modules.mentions.telegram import TelegramMentionsModule  # noqa: E402
from osint_toolkit.modules.phone.numbering import PhoneNumberingModule  # noqa: E402
from osint_toolkit.net.services import NetworkServices  # noqa: E402
from osint_toolkit.modules.username.maigret import DISCLAIMER, parse_report  # noqa: E402

# Свои модули (вне vendor/): локальные файлы и веб-поиск через DuckDuckGo.
from osint_modules import LocalFilesSearchModule, SocialMediaSearchModule, WebCascadeSearchModule  # noqa: E402

NAME = "osint-service"
TOKEN = os.environ.get("TIP_SERVICE_TOKEN", "")
ADDR = os.environ.get("SERVICE_ADDR", "127.0.0.1:8105")
OWN_URL = os.environ.get("SERVICE_URL", "http://" + ADDR)
CORE_URL = os.environ.get("TIP_CORE_URL", "http://127.0.0.1:8080").rstrip("/")
LOG = logging.getLogger(NAME)


class KzTelegramMentions(TelegramMentionsModule):
    """Поиск номера в публичных Telegram-каналах с записями, принятыми в Казахстане.

    Поиск Telegram ищет по словам: пост с «+7(708) 382-13-76» находится по «382-13-76»
    или «708 382 13 76», но не по «77083821376» и не по «+7 708 382 1376», которые даёт
    инструмент. Код инструмента не меняем — добавляем свои варианты в начало списка."""

    @staticmethod
    def spellings(target, settings):
        digits = re.sub(r"\D", "", target.normalized)
        own = []
        if target.type == TargetType.PHONE and len(digits) == 11 and digits.startswith("7"):
            code, a, b, c = digits[1:4], digits[4:7], digits[7:9], digits[9:11]
            own = ["%s-%s-%s" % (a, b, c), "%s %s %s %s" % (code, a, b, c)]
        base = TelegramMentionsModule.spellings(target, settings)
        return list(dict.fromkeys(own + base))[: max(settings.tg_variants, len(own))]


CHANNEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{3,31}$")


def channel_names(raw):
    """«@name», «t.me/name», «https://t.me/s/name» -> «name»; неверные имена отбрасываются."""
    out = []
    for r in raw if isinstance(raw, list) else []:
        name = re.sub(r"^(?:https?://)?(?:t\.me|telegram\.me)/(?:s/)?", "", str(r).strip(), flags=re.I).lstrip("@").split("/")[0]
        if CHANNEL_RE.match(name) and name not in out:
            out.append(name)
    return out[:50]


def settings(channels=None):
    # Настройки инструмента берутся из переменных OSINT_* (OSINT_SEARXNG_URL и др.).
    # Номера в платформе уже в формате +7…, регион по умолчанию — Казахстан.
    # Каналы Telegram ядро передаёт в запросе — те же, что администратор задал для Collector Service.
    os.environ.setdefault("OSINT_DEFAULT_REGION", "KZ")
    extra = {}
    if channels:
        extra = {"tg_channels": ",".join(channels), "tg_max_channels": max(len(channels), 20), "tg_variants": 4}
    return Settings(_env_file=None, **extra)


def finding_json(f):
    return {
        "module": f.module, "attribute": f.attribute, "value": f.value,
        "confidence": f.confidence.value, "source": f.source_name, "url": f.source_url,
        "evidence": f.evidence, "observed_at": f.observed_at.strftime("%Y-%m-%d %H:%M:%S"),
    }


async def run_modules(value, modules, network, channels=None, kind=TargetType.PHONE):
    s = settings(channels)
    target = parse_as(value, kind, default_region=s.default_region)
    net = NetworkServices(s) if network else None
    found, limits, errors, ran, skipped, hidden = [], [], [], [], [], 0
    try:
        for module in modules:
            reason = module.availability(s)
            why = None if reason.available else reason.reason
            why = why or module.applicability(target, s)
            if why:
                skipped.append({"module": module.name, "reason": why})
                continue
            ctx = ModuleContext(settings=s, logger=LOG, **({"net": net} if net else {}))
            try:
                out = await asyncio.wait_for(module.run(target, ctx), module.effective_timeout(s))
            except TimeoutError:
                errors.append("%s: не уложился во время" % module.name)
                continue
            except Exception as exc:  # сетевые сбои источника — в отчёт, остальные модули продолжают
                errors.append("%s: %s" % (module.name, exc))
                continue
            ran.append(module.name)
            for f in out.findings:
                if f.ephemeral or f.is_helper:
                    hidden += f.ephemeral
                    continue
                found.append(finding_json(f))
            limits += [x for x in list(out.limitations) + list(module.limitations) if x not in limits]
            errors += ["%s: %s" % (module.name, e) for e in out.errors]
    finally:
        if net:
            await net.aclose()
    return {"phone": target.normalized, "value": target.normalized, "findings": found, "limitations": limits, "errors": errors,
            "ran": ran, "skipped": skipped, "hidden_ephemeral": hidden}


def mentions_available():
    s = settings()
    reasons = [m.availability(s).reason for m in (PhoneMentionsModule(), TelegramMentionsModule())]
    ok = any(r is None for r in reasons)
    return ok, None if ok else "; ".join(r for r in reasons if r)


# Какие проверки для какого типа индикатора. «analyze» — без поиска по сайтам
# (для почты — ещё DNS-запрос MX к домену), «mentions» — по кнопке: поисковик, Telegram-каналы,
# локальные файлы (osint_modules.LocalFilesSearchModule) и каскадный поиск DuckDuckGo.
# Новый тип — добавить строку сюда (и тип в ядре); новый модуль — в нужный список.
CHECKS = {
    "phone": {"target": TargetType.PHONE, "analyze": lambda: [PhoneNumberingModule()], "analyze_net": False,
              "mentions": lambda: [PhoneMentionsModule(), KzTelegramMentions(), LocalFilesSearchModule(), WebCascadeSearchModule()]},
    "email": {"target": TargetType.EMAIL, "analyze": lambda: [EmailSyntaxModule(), DisposableEmailModule(), MxModule()],
              "analyze_net": True, "mentions": lambda: [EmailMentionsModule(), KzTelegramMentions(), LocalFilesSearchModule(), WebCascadeSearchModule()]},
    "name": {"target": TargetType.NAME, "analyze": lambda: [], "analyze_net": False,
             "mentions": lambda: [NameMentionsModule(), KzTelegramMentions(), LocalFilesSearchModule(), WebCascadeSearchModule()]},
}


def check_of(body):
    kind = str(body.get("type", "phone"))
    if kind not in CHECKS:
        raise ValueError("тип «%s» не поддерживается: %s" % (kind, ", ".join(CHECKS)))
    value = str(body.get("value", body.get("phone", ""))).strip()
    if not value:
        raise ValueError("пустое значение")
    return CHECKS[kind], value


def handle_indicator_analyze(body):
    c, value = check_of(body)
    return asyncio.run(run_modules(value, c["analyze"](), network=c["analyze_net"], kind=c["target"]))


def handle_indicator_mentions(body):
    c, value = check_of(body)
    channels = channel_names(body.get("tg_channels"))
    return asyncio.run(run_modules(value, c["mentions"](), network=True, channels=channels, kind=c["target"]))


def handle_analyze(body):
    return asyncio.run(run_modules(str(body.get("phone", "")), [PhoneNumberingModule()], network=False))


def handle_mentions(body):
    channels = channel_names(body.get("tg_channels"))
    return asyncio.run(run_modules(str(body.get("phone", "")), [PhoneMentionsModule(), KzTelegramMentions()], network=True, channels=channels))


# ---------- ник: Maigret ----------
# Maigret (MIT, github.com/soxoj/maigret) стоит в своём окружении .venv-maigret: у него много
# зависимостей. Запускаем отдельным процессом без окружения пользователя, во временной папке.
MAIGRET_PY = Path(os.environ.get("OSINT_MAIGRET_PYTHON", str(Path(__file__).resolve().parent / ".venv-maigret/bin/python")))
MAIGRET_TOP_SITES = int(os.environ.get("OSINT_MAIGRET_TOP_SITES", "500"))
MAIGRET_LIMIT_S = 900
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]{1,63}$")


def maigret_available():
    return (True, None) if MAIGRET_PY.exists() else (False, "не установлен Maigret (./run.sh ставит его сам)")


def maigret_argv(username, workdir):
    # Те же ограничения, что в инструменте друга: без рекурсии, без сбора данных из профилей,
    # без скачивания базы сайтов из интернета.
    return [str(MAIGRET_PY), "-I", "-u", "-m", "maigret", "--no-autoupdate", "--no-recursion", "--no-extracting",
            "--no-color", "--no-progressbar", "--timeout", "10", "--retries", "1", "--max-connections", "20",
            "--top-sites", str(MAIGRET_TOP_SITES), "--json", "simple", "--folderoutput", workdir, "--", username]


def handle_username(body):
    """Ник: Maigret (профили на сайтах) + свои модули — локальные файлы и поиск по соцсетям.
    Ошибки своих модулей идут в extra_errors: они не должны помечать всю проверку неудачной."""
    result = maigret_check(body)  # неверный ник — ValueError раньше любых запросов
    extra = asyncio.run(run_modules(result["username"], [LocalFilesSearchModule(), SocialMediaSearchModule()],
                                    network=True, kind=TargetType.USERNAME))
    result["findings"] = extra["findings"]
    result["extra_errors"] = extra["errors"]
    result["limitations"] = result["limitations"] + [x for x in extra["limitations"] if x not in result["limitations"]]
    return result


def maigret_check(body):
    username = str(body.get("username", "")).strip().lstrip("@").lower()
    if not USERNAME_RE.match(username):
        raise ValueError("ник должен быть из латиницы, цифр, «_», «.», «-»")
    ok, why = maigret_available()
    if not ok:
        return {"username": username, "profiles": [], "sites_checked": 0, "errors": [why], "limitations": []}
    import shutil
    import subprocess
    import tempfile
    work = tempfile.mkdtemp(prefix="maigret-")
    try:
        try:
            proc = subprocess.run(maigret_argv(username, work), cwd=work, capture_output=True, timeout=MAIGRET_LIMIT_S,
                                  env={"HOME": work, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        except subprocess.TimeoutExpired:
            return {"username": username, "profiles": [], "sites_checked": 0, "limitations": [],
                    "errors": ["Maigret не уложился в %d минут" % (MAIGRET_LIMIT_S // 60)]}
        reports = sorted(Path(work).glob("report_*_simple.json"))
        if proc.returncode != 0 or not reports:
            tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()[-2:]
            return {"username": username, "profiles": [], "sites_checked": 0, "limitations": [],
                    "errors": ["Maigret завершился с ошибкой: %s" % (" ".join(tail) or proc.returncode)]}
        hits = parse_report(json.loads(reports[0].read_text(encoding="utf-8")))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    m = re.search(r"search on (?:top )?(\d+) sites", proc.stdout.decode("utf-8", "replace"))
    profiles = [{"site": h["site"], "url": h["url"], "tags": h["tags"], "check": h["check"], "similar": h["similar"]} for h in hits]
    return {"username": username, "profiles": profiles, "sites_checked": int(m.group(1)) if m else MAIGRET_TOP_SITES,
            "errors": [], "limitations": [DISCLAIMER,
            "Отсутствие сайта в списке не значит, что аккаунта нет: сайт мог не ответить или заблокировать запрос."]}


ROUTES = {"/api/v1/indicator/analyze": handle_indicator_analyze, "/api/v1/indicator/mentions": handle_indicator_mentions,
          "/api/v1/phone/analyze": handle_analyze, "/api/v1/phone/mentions": handle_mentions,
          "/api/v1/username/check": handle_username}


class Handler(BaseHTTPRequestHandler):
    server_version = "tip-osint"

    def reply(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def fail(self, status, code, message):
        self.reply(status, {"success": False, "error": {"code": code, "message": message}})

    def do_GET(self):
        if self.path == "/api/v1/health":
            ok, why = mentions_available()
            mok, mwhy = maigret_available()
            self.reply(200, {"success": True, "service": NAME, "mentions_available": ok, "mentions_reason": why,
                             "username_available": mok, "username_reason": mwhy})
        else:
            self.fail(404, "not_found", "Маршрут API: не найдено")

    def do_POST(self):
        handler = ROUTES.get(self.path)
        if handler is None:
            return self.fail(404, "not_found", "Маршрут API: не найдено")
        sent = self.headers.get("X-Service-Token", "")
        if not TOKEN or not hmac.compare_digest(sent.encode(), TOKEN.encode()):
            return self.fail(401, "unauthorized", "Нужен токен ядра")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) if 0 < length <= 65536 else b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except ValueError:
            return self.fail(400, "bad_request", "Нужен JSON-объект")
        try:
            self.reply(200, {"success": True, **handler(body)})
        except ValueError as e:  # номер или ник не разобрался
            self.fail(400, "bad_request", "Не разобрано: %s" % e)
        except Exception as e:  # сбой модуля не должен ронять сервис
            print("[%s] ошибка в %s: %r" % (NAME, self.path, e), file=sys.stderr, flush=True)
            self.fail(500, "internal", "Внутренняя ошибка")

    def log_message(self, *args):
        pass


def register_loop():
    body = json.dumps({"name": NAME, "url": OWN_URL, "api_version": "v1"}).encode()
    registered = False
    while True:
        ok = False
        try:
            req = urllib.request.Request(CORE_URL + "/api/v1/internal/services/register", body,
                                         {"Content-Type": "application/json", "X-Service-Token": TOKEN})
            with urllib.request.urlopen(req, timeout=2) as r:
                ok = r.status == 200
        except OSError:
            pass
        if ok and not registered:
            print("%s: зарегистрирован в ядре %s" % (NAME, CORE_URL), flush=True)
        registered = ok
        time.sleep(30 if ok else 3)


def main():
    if not TOKEN:
        sys.exit("%s: не задан TIP_SERVICE_TOKEN (общий токен ядра и сервисов)" % NAME)
    host, port = ADDR.rsplit(":", 1)
    server = ThreadingHTTPServer((host, int(port)), Handler)
    ok, why = mentions_available()
    print("%s запущен: http://%s (поиск упоминаний: %s)" % (NAME, ADDR, "доступен" if ok else "недоступен — " + why), flush=True)
    threading.Thread(target=register_loop, daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
