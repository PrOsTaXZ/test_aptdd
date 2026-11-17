"""Тесты osint_modules.py: локальные файлы всех форматов, лимиты, веб-поиск через поддельный сервер."""
import asyncio
import io
import sqlite3
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "vendor"))

import osint_modules as M  # noqa: E402
from osint_toolkit.core.detector import parse_as  # noqa: E402
from osint_toolkit.core.models import Confidence, TargetType  # noqa: E402
from osint_toolkit.modules.base import ModuleContext  # noqa: E402
from osint_toolkit.net.services import NetworkServices  # noqa: E402

import service  # noqa: E402


def target(value, kind=TargetType.PHONE):
    return parse_as(value, kind, default_region="KZ")


def ctx(network=False):
    s = service.settings()
    return ModuleContext(settings=s, logger=M.log, **({"net": NetworkServices(s)} if network else {}))


class LocalFiles(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def run_module(self, value, kind=TargetType.PHONE):
        return asyncio.run(M.LocalFilesSearchModule(self.dir).run(target(value, kind), ctx()))

    def test_all_formats_are_searched_with_file_sheet_table_and_row(self):
        # CSV в Windows-1251 с «;» — как выгружают банки.
        (self.dir / "bank.csv").write_bytes("ФИО;Телефон\nИванов Иван;+77071234567\nПетров;+77000000000\n".encode("cp1251"))
        from openpyxl import Workbook
        wb = Workbook()
        wb.active.title = "Звонки"
        wb.active.append(["Дата", "Номер"])
        wb.active.append(["2026-11-01", "+77071234567"])
        wb.save(self.dir / "calls.xlsx")
        from docx import Document
        doc = Document()
        doc.add_paragraph("Звонил с номера +77071234567, представился банком.")
        doc.save(self.dir / "report.docx")
        con = sqlite3.connect(self.dir / "leads.db")
        con.execute("CREATE TABLE contacts (name TEXT, phone TEXT)")
        con.executemany("INSERT INTO contacts VALUES (?, ?)", [("A", "1"), ("B", "+77071234567")])
        con.commit()
        con.close()
        with zipfile.ZipFile(self.dir / "pack.zip", "w") as z:
            z.writestr("inner/list.csv", "phone,comment\n+77071234567,из архива\n")
            z.writestr("skip.exe", b"MZ")
        (self.dir / "notes.txt").write_text("+77071234567")  # формат не поддерживается

        out = self.run_module("+77071234567")
        self.assertEqual(out.errors, [])
        values = [f.value for f in out.findings]
        self.assertEqual(len(values), 5, values)
        self.assertTrue(all(f.confidence == Confidence.CONFIRMED for f in out.findings))
        self.assertTrue(all(f.source_url.startswith("file://") for f in out.findings))
        joined = "\n".join(values)
        for part in ("ФИО=Иванов Иван", "Строка=2", "Лист=Звонки", "Таблица БД=contacts", "Файл внутри=inner/list.csv",
                     "Тип источника=Word"):
            self.assertIn(part, joined)
        self.assertIn("Совпадение подстроки не подтверждает принадлежность данных объекту", M.LocalFilesSearchModule.limitations)

    def test_search_is_case_insensitive_substring(self):
        (self.dir / "people.csv").write_text("name,city\nИВАНОВ ИВАН,Алматы\n", encoding="utf-8")
        out = self.run_module("Иванов Иван", TargetType.NAME)
        self.assertEqual(len(out.findings), 1)

    def test_findings_are_capped(self):
        rows = "\n".join("+77071234567,%d" % i for i in range(M.MAX_FINDINGS_PER_MODULE + 50))
        (self.dir / "big.csv").write_text("phone,n\n" + rows, encoding="utf-8")
        (self.dir / "more.csv").write_text("phone,n\n+77071234567,1\n", encoding="utf-8")
        out = self.run_module("+77071234567")
        self.assertEqual(len(out.findings), M.MAX_FINDINGS_PER_MODULE)

    def test_broken_file_does_not_stop_others_and_big_files_are_skipped(self):
        (self.dir / "broken.xlsx").write_bytes(b"not a workbook")
        (self.dir / "ok.csv").write_text("phone\n+77071234567\n", encoding="utf-8")
        saved = M.MAX_FILE_BYTES
        try:
            M.MAX_FILE_BYTES = 10_000
            (self.dir / "huge.csv").write_text("phone\n" + "x" * 20_000, encoding="utf-8")
            out = self.run_module("+77071234567")
        finally:
            M.MAX_FILE_BYTES = saved
        self.assertEqual(len(out.findings), 1)
        self.assertTrue(any("broken.xlsx" in e for e in out.errors))
        self.assertTrue(any("huge.csv" in e for e in out.errors))

    def test_sqlite_is_opened_read_only(self):
        path = self.dir / "ro.sqlite"
        con = sqlite3.connect(path)
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute("INSERT INTO t VALUES ('+77071234567')")
        con.commit()
        con.close()
        before = path.read_bytes()
        self.assertEqual(len(self.run_module("+77071234567").findings), 1)
        self.assertEqual(path.read_bytes(), before, "файл базы не изменён")

    def test_missing_or_empty_folder(self):
        out = asyncio.run(M.LocalFilesSearchModule(self.dir / "nope").run(target("+77071234567"), ctx()))
        self.assertTrue(out.limitations and not out.findings)
        out = self.run_module("+77071234567")
        self.assertIn("нет поддерживаемых файлов", out.limitations[0])

    def test_csv_stream_is_not_closed_by_the_reader(self):
        stream = io.BytesIO("a;b\n1;+77071234567\n".encode("utf-8"))
        rows = []
        M._search_csv_stream(stream, "+77071234567", rows.append, {})
        self.assertFalse(stream.closed)
        self.assertEqual(rows[0]["b"], "+77071234567")


class FakeDDG(BaseHTTPRequestHandler):
    queries = []
    status = 200

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = parse_qs(urlparse(self.path).query)["q"][0]
        FakeDDG.queries.append((q, self.headers.get("User-Agent")))
        body = ("<div><a class=\"result__a\" href=\"//duckduckgo.com/l/?uddg=https%3A%2F%2Fvk.com%2Fid1\">Иван <b>Иванов</b></a>"
                "<a class=\"result__snippet\" href=\"x\">Профиль Иван Иванов, Алматы</a></div>").encode()
        self.send_response(FakeDDG.status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class WebSearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeDDG)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d/html/" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        FakeDDG.queries, FakeDDG.status = [], 200
        self.sleep = M.asyncio.sleep
        M.asyncio.sleep = lambda *_: self.sleep(0)

    def tearDown(self):
        M.asyncio.sleep = self.sleep

    def make(self, cls):
        m = cls()
        m.search_url = self.url
        return m

    def test_cascade_queries_and_unverified_findings(self):
        out = asyncio.run(self.make(M.WebCascadeSearchModule).run(target("Иванов Иван", TargetType.NAME), ctx(network=True)))
        sent = [q for q, _ in FakeDDG.queries]
        self.assertEqual(len(sent), 4 + 5 + 1 + 4 + 2)
        self.assertIn("site:rusprofile.ru Иванов Иван", sent)
        self.assertIn('"Иванов Иван"', sent)
        self.assertTrue(all(f.confidence == Confidence.UNVERIFIED for f in out.findings))
        self.assertEqual(out.findings[0].source_url, "https://vk.com/id1")
        self.assertEqual(out.findings[0].value, "Профиль Иван Иванов, Алматы")
        self.assertEqual({ua for _, ua in FakeDDG.queries}, {M.HEADERS["User-Agent"]}, "один честный User-Agent")

    def test_social_module_uses_only_social_sites(self):
        asyncio.run(self.make(M.SocialMediaSearchModule).run(target("bank_support", TargetType.USERNAME), ctx(network=True)))
        sent = [q for q, _ in FakeDDG.queries]
        self.assertEqual(sent, ["site:tiktok.com bank_support", "site:instagram.com bank_support", "site:t.me bank_support",
                                "site:vk.com bank_support", "site:ok.ru bank_support", '"bank_support"'])

    def test_blocked_search_is_reported_not_bypassed(self):
        FakeDDG.status = 202  # так DuckDuckGo отвечает проверкой на робота
        out = asyncio.run(self.make(M.SocialMediaSearchModule).run(target("bank_support", TargetType.USERNAME), ctx(network=True)))
        self.assertEqual(out.findings, [])
        self.assertEqual(len(out.errors), 6)
        self.assertIn("HTTP 202", out.errors[0])

    def test_no_network_no_requests(self):
        out = asyncio.run(self.make(M.WebCascadeSearchModule).run(target("Иванов Иван", TargetType.NAME), ctx(network=False)))
        self.assertEqual(FakeDDG.queries, [])
        self.assertIn("Сетевой доступ отключён", out.limitations[0])

    def test_modules_are_not_skipped_by_run_modules(self):
        # availability/applicability должны пропускать модуль к запуску (в присланном коде он бы пропускался).
        r = asyncio.run(service.run_modules("+77071234567", [M.LocalFilesSearchModule(tempfile.mkdtemp())], network=False))
        self.assertEqual((r["ran"], r["skipped"]), (["local.files"], []))


class WiredIntoService(unittest.TestCase):
    """Модули подключены к проверкам сервиса: номер/почта/ФИО — каскад, ник — соцсети; везде локальные файлы."""

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FakeDDG)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        FakeDDG.queries, FakeDDG.status = [], 200
        self.saved = (M.LOCAL_DIR, M.WebCascadeSearchModule.search_url, M.asyncio.sleep, service.MAIGRET_PY)
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "leads.csv").write_text("ФИО;Телефон\nИванов Иван;+77071234567\nbank_support;x\n", encoding="utf-8")
        M.LOCAL_DIR = self.dir
        M.WebCascadeSearchModule.search_url = "http://127.0.0.1:%d/html/" % self.server.server_address[1]
        sleep = self.saved[2]
        M.asyncio.sleep = lambda *_: sleep(0)

    def tearDown(self):
        M.LOCAL_DIR, M.WebCascadeSearchModule.search_url, M.asyncio.sleep, service.MAIGRET_PY = self.saved

    def test_checks_table_lists_the_new_modules(self):
        for kind in ("phone", "email", "name"):
            names = [m.name for m in service.CHECKS[kind]["mentions"]()]
            self.assertIn("local.files", names)
            self.assertIn("web.cascade", names)

    def test_name_check_runs_local_files_and_web_cascade(self):
        r = service.handle_indicator_mentions({"type": "name", "value": "Иванов Иван"})
        self.assertIn("local.files", r["ran"])
        self.assertIn("web.cascade", r["ran"])
        by = {}
        for f in r["findings"]:
            by.setdefault(f["module"], []).append(f)
        self.assertIn("ФИО=Иванов Иван", by["local.files"][0]["value"])
        self.assertEqual(by["web.cascade"][0]["confidence"], "unverified")
        self.assertEqual(len([q for q, _ in FakeDDG.queries]), 16)

    def test_username_check_adds_local_files_and_social_search(self):
        service.MAIGRET_PY = Path("/nonexistent/python")  # Maigret не установлен — свои модули всё равно работают
        r = service.handle_username({"username": "@Bank_Support"})
        mods = {f["module"] for f in r["findings"]}
        self.assertEqual(mods, {"local.files", "web.social"})
        self.assertEqual(len(FakeDDG.queries), 6, "только соцсети, без всего каскада")
        FakeDDG.status = 202
        r = service.handle_username({"username": "bank_support"})
        self.assertEqual(len(r["extra_errors"]), 6)
        self.assertTrue(any("Maigret" in e for e in r["errors"]))


if __name__ == "__main__":
    unittest.main()
