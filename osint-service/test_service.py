"""Тесты OSINT Service: офлайн-анализ и поиск упоминаний через поддельный SearXNG на этом компьютере."""
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import service


class FakeWeb(BaseHTTPRequestHandler):
    """Поддельный SearXNG и сайт: поисковик возвращает одну ссылку, на странице есть номер."""
    pages = {}

    def do_GET(self):
        if self.path.startswith("/search"):
            body = json.dumps({"results": [{
                "url": "http://%s/ads/1" % self.headers["Host"], "title": "Объявление",
                "content": "Звоните 8 701 234 56 78, предоплата", "engine": "fake"}]}).encode()
            kind = "application/json"
        elif self.path == "/robots.txt":
            body, kind = b"User-agent: *\nAllow: /\n", "text/plain"
        else:
            body = "<html><body>Квартира посуточно. Звоните +7 (701) 234-56-78</body></html>".encode()
            kind = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class ServiceTest(unittest.TestCase):
    def setUp(self):
        for k in [k for k in os.environ if k.startswith("OSINT_")]:
            del os.environ[k]

    def test_offline_analysis_of_a_kazakh_number(self):
        r = service.handle_analyze({"phone": "+77012345678"})
        facts = {f["attribute"]: f["value"] for f in r["findings"]}
        self.assertEqual(facts["phone.valid"], True)
        self.assertEqual(facts["phone.region"]["code"], "KZ")
        self.assertEqual(facts["phone.number_type"], "мобильный")
        self.assertIn("phone.allocated_carrier", facts)
        self.assertEqual(r["ran"], ["phone.numbering"])
        self.assertTrue(all(f["confidence"] == "confirmed" for f in r["findings"]))

    def test_mentions_without_provider_are_skipped(self):
        ok, why = service.mentions_available()
        self.assertFalse(ok)
        self.assertIn("OSINT_SEARXNG_URL", why)
        r = service.handle_mentions({"phone": "+77012345678"})
        self.assertEqual((r["ran"], r["findings"]), ([], []))
        self.assertEqual({s["module"] for s in r["skipped"]}, {"mentions.phone", "mentions.telegram"})

    def test_channels_from_the_platform_enable_telegram_search_without_a_provider(self):
        from osint_toolkit.modules.mentions.telegram import TelegramMentionsModule
        self.assertFalse(TelegramMentionsModule().availability(service.settings()).available)
        names = service.channel_names(["@police_kz", "https://t.me/s/abc_def", "t.me/xyz_123/5", "bad name", "x"])
        self.assertEqual(names, ["police_kz", "abc_def", "xyz_123"])
        s = service.settings(names)
        self.assertTrue(TelegramMentionsModule().availability(s).available)
        self.assertEqual(TelegramMentionsModule.configured_channels(s), names)

    def test_kazakh_spellings_come_first_in_telegram_search(self):
        from osint_toolkit.core.detector import parse_as
        from osint_toolkit.core.models import TargetType
        target = parse_as("+77083821376", TargetType.PHONE, default_region="KZ")
        got = service.KzTelegramMentions.spellings(target, service.settings(["egov_kz"]))
        self.assertEqual(got[:2], ["382-13-76", "708 382 13 76"])
        self.assertIn("77083821376", got)

    def test_username_check_validates_and_reports_missing_maigret(self):
        with self.assertRaises(ValueError):
            service.handle_username({"username": "плохой ник"})  # ValueError до любых запросов
        saved = service.MAIGRET_PY
        try:
            service.MAIGRET_PY = service.Path("/nonexistent/python")
            r = service.maigret_check({"username": "@Bank_Support_KZ"})  # без сетевых модулей
        finally:
            service.MAIGRET_PY = saved
        self.assertEqual(r["username"], "bank_support_kz")
        self.assertIn("Maigret", r["errors"][0])
        argv = service.maigret_argv("nick", "/tmp/w")
        for flag in ("--no-recursion", "--no-extracting", "--no-autoupdate"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[-2:], ["--", "nick"])

    def test_email_offline_checks_find_disposable_mailboxes(self):
        import asyncio
        r = asyncio.run(service.run_modules("Ivan.Petrov@Mailinator.com",
                        [service.EmailSyntaxModule(), service.DisposableEmailModule()], network=False,
                        kind=service.TargetType.EMAIL))
        got = {f["attribute"]: f["value"] for f in r["findings"]}
        self.assertEqual((got["email.valid"], got["email.disposable"]), (True, True))
        self.assertEqual(r["errors"], [])

    def test_phones_of_any_country_are_analyzed(self):
        for phone, code, region in [("+998901234567", "+998", "UZ"), ("+79161234567", "+7", "RU"), ("+14155552671", "+1", "US")]:
            r = service.handle_indicator_analyze({"type": "phone", "value": phone})
            got = {f["attribute"]: f["value"] for f in r["findings"]}
            self.assertEqual((got["phone.country_code"], got["phone.region"]["code"]), (code, region), phone)

    def test_unknown_types_and_empty_values_are_rejected(self):
        with self.assertRaises(ValueError):
            service.handle_indicator_analyze({"type": "car", "value": "x"})
        with self.assertRaises(ValueError):
            service.handle_indicator_analyze({"type": "email", "value": " "})
        self.assertEqual(service.handle_indicator_analyze({"type": "name", "value": "Иванов Иван"})["ran"], [])

    def test_names_and_emails_use_the_toolkit_spellings_in_telegram(self):
        from osint_toolkit.core.detector import parse_as
        name = parse_as("Иванов Иван Иванович", service.TargetType.NAME, default_region="KZ")
        got = service.KzTelegramMentions.spellings(name, service.settings(["c_name"]))
        self.assertIn("Иванов Иван Иванович", got)
        self.assertFalse(any("-" in g and g[0].isdigit() for g in got), "казахстанская запись — только для номеров")

    def test_mentions_through_a_search_provider(self):
        web = ThreadingHTTPServer(("127.0.0.1", 0), FakeWeb)
        threading.Thread(target=web.serve_forever, daemon=True).start()
        try:
            os.environ["OSINT_SEARXNG_URL"] = "http://127.0.0.1:%d" % web.server_port
            os.environ["OSINT_SEARXNG_MIN_INTERVAL"] = "0"
            os.environ["OSINT_TG_DISCOVERY_QUERIES"] = "0"
            self.assertTrue(service.mentions_available()[0])
            r = service.handle_mentions({"phone": "+77012345678"})
            self.assertIn("mentions.phone", r["ran"])
            mentions = [f for f in r["findings"] if f["attribute"].startswith("mention.")]
            self.assertTrue(mentions, r)
            self.assertTrue(any("/ads/1" in json.dumps(f["value"], ensure_ascii=False) + f["url"] for f in mentions), mentions)
        finally:
            web.shutdown()


if __name__ == "__main__":
    unittest.main()
