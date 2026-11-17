"""Text of downloaded documents, extracted in the bwrap sandbox (no network).

TXT/CSV are decoded in-process (no parser involved). PDF and OOXML/OpenDocument files are parsed
by ``tools/runners/doc_text.py`` running in the sandbox with the application's own interpreter:
the document is mapped read-only as ``/input/doc.<ext>``, nothing else of $HOME is visible,
there is no network, and time/size limits apply. Legacy binary formats (DOC, XLS, PPT) and RTF
are not parsed — they are reported as unsupported, never guessed.
"""

from __future__ import annotations

import json
import sys
import tempfile
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from osint_toolkit.config import Settings, ensure_private_dir
from osint_toolkit.sandbox import SandboxError, SandboxPolicy, run_sandboxed, sandbox_status
from osint_toolkit.tools.manager import sandbox_mounts

SANDBOXED = frozenset({"pdf", "docx", "xlsx", "pptx", "odt", "ods", "odp"})
PLAIN = frozenset({"txt", "csv"})
UNSUPPORTED = {
    "doc": "старый формат Word (.doc) не разбирается — откройте файл вручную",
    "xls": "старый формат Excel (.xls) не разбирается — откройте файл вручную",
    "ppt": "старый формат PowerPoint (.ppt) не разбирается — откройте файл вручную",
    "rtf": "RTF не разбирается — откройте файл вручную",
}
RUNNER_DEST = "/opt/osint/doc_text.py"


@dataclass(slots=True)
class DocumentText:
    parts: list[tuple[str, str]] = field(default_factory=list)  # (page/slide/sheet label, text)
    error: str | None = None
    truncated: bool = False


def runner_path() -> Path:
    return Path(str(resources.files("osint_toolkit.tools.runners") / "doc_text.py"))


def decode_text(body: bytes, charset: str | None = None) -> str:
    for encoding in filter(None, (charset, "utf-8")):
        try:
            return body.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return body.decode("cp1251", errors="replace")


async def extract(settings: Settings, doc_type: str, body: bytes) -> DocumentText:
    if doc_type in PLAIN:
        return DocumentText([("файл", decode_text(body))])
    if doc_type in UNSUPPORTED:
        return DocumentText(error=UNSUPPORTED[doc_type])
    if doc_type not in SANDBOXED:
        return DocumentText(error=f"формат {doc_type} не поддерживается")
    status = sandbox_status()
    if not status.available:
        return DocumentText(error=f"песочница недоступна: {status.reason}")
    ensure_private_dir(settings.cache_dir)
    with tempfile.TemporaryDirectory(prefix="doc-", dir=settings.cache_dir) as work:
        path = Path(work) / f"doc.{doc_type}"
        path.write_bytes(body)
        venv = Path(sys.prefix)
        policy = SandboxPolicy(
            network=False,
            read_only=sandbox_mounts(venv),
            mapped_read_only=((path, f"/input/doc.{doc_type}"), (runner_path(), RUNNER_DEST)),
        )
        python = venv / "bin" / "python"
        argv = [str(python), "-I", RUNNER_DEST, doc_type, f"/input/doc.{doc_type}"]
        try:
            result = await run_sandboxed(
                policy, argv, limit_s=settings.doc_extract_timeout, max_output=6 * 1024 * 1024
            )
        except SandboxError as exc:
            return DocumentText(error=f"извлечение текста не удалось: {exc}")
    try:
        data = json.loads(result.stdout or b"null")
    except ValueError:
        return DocumentText(error=f"извлечение текста не удалось (код {result.returncode})")
    if not isinstance(data, dict):
        return DocumentText(error="извлечение текста вернуло неожиданный формат")
    if data.get("error"):
        return DocumentText(error=str(data["error"]))
    parts = [
        (str(p.get("label", "")), str(p.get("text", "")))
        for p in data.get("parts") or []
        if isinstance(p, dict)
    ]
    return DocumentText(parts, truncated=bool(data.get("truncated")))
