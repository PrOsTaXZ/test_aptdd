"""Extract text from one untrusted document. Runs INSIDE the bwrap sandbox without network.

Usage: python -I doc_text.py TYPE /input/doc.EXT   →  JSON on stdout:
    {"parts": [{"label": "стр. 1", "text": "..."}, ...], "truncated": false}

Supported: pdf (pypdf; one part per page), docx, pptx (one part per slide), xlsx (one part per
sheet), odt/ods/odp (OpenDocument content.xml). Protections: zip entry count and total
uncompressed size limits, XML with DOCTYPE/ENTITY is rejected (no entity expansion, no external
entities), total text and page caps. This file must not import osint_toolkit.
"""

import json
import re
import sys
import zipfile
from xml.etree import ElementTree as ET

MAX_TEXT = 4_000_000
MAX_PAGES = 600
MAX_ZIP_ENTRIES = 3000
MAX_ZIP_TOTAL = 200 * 1024 * 1024
MAX_XML = 60 * 1024 * 1024


class Limit(Exception):
    pass


def safe_xml(data: bytes) -> ET.Element:
    head = data[:4096].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in data.upper():
        raise ValueError("XML с DOCTYPE/ENTITY отклонён")
    return ET.fromstring(data)  # noqa: S314 - DTDs rejected above, no entity expansion possible


def text_of(element: ET.Element, breaks: tuple[str, ...]) -> str:
    out: list[str] = []
    for node in element.iter():
        tag = node.tag.rsplit("}", 1)[-1]
        if node.text and tag in ("t", "v", "p", "span", "h", "s", "a", "text"):
            out.append(node.text)
        if tag in breaks:
            out.append("\n")
        if node.tail and tag in ("span", "s", "a", "tab", "line-break"):
            out.append(node.tail)
    return re.sub(r"[ \t]+", " ", "".join(out))


def open_zip(path: str) -> zipfile.ZipFile:
    archive = zipfile.ZipFile(path)
    infos = archive.infolist()
    if len(infos) > MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > MAX_ZIP_TOTAL:
        raise Limit("архив слишком большой (защита от zip-бомбы)")
    return archive


def read_member(archive: zipfile.ZipFile, name: str) -> bytes:
    info = archive.getinfo(name)
    if info.file_size > MAX_XML:
        raise Limit(f"{name} слишком большой")
    return archive.read(info)


def pdf(path: str) -> list[tuple[str, str]]:
    from pypdf import PdfReader

    reader = PdfReader(path, strict=False)
    parts = []
    for index, page in enumerate(reader.pages[:MAX_PAGES], 1):
        try:
            parts.append((f"стр. {index}", page.extract_text() or ""))
        except Exception as exc:  # noqa: BLE001 - one broken page must not stop the rest
            parts.append((f"стр. {index}", f"[ошибка страницы: {type(exc).__name__}]"))
    return parts


def docx(path: str) -> list[tuple[str, str]]:
    archive = open_zip(path)
    extra = r"word/(header|footer|footnotes)\d*\.xml$"
    names = ["word/document.xml", *sorted(n for n in archive.namelist() if re.match(extra, n))]
    return [
        (name.split("/")[-1], text_of(safe_xml(read_member(archive, name)), ("p", "br", "tab")))
        for name in names
        if name in archive.namelist()
    ]


def pptx(path: str) -> list[tuple[str, str]]:
    archive = open_zip(path)
    slides = sorted(
        (n for n in archive.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n)),
        key=lambda n: int(re.findall(r"\d+", n)[-1]),
    )
    return [
        (f"слайд {re.findall(r'\d+', n)[-1]}", text_of(safe_xml(read_member(archive, n)), ("p",)))
        for n in slides[:MAX_PAGES]
    ]


def xlsx(path: str) -> list[tuple[str, str]]:
    archive = open_zip(path)
    shared: list[str] = []
    if "xl/sharedStrings.xml" in archive.namelist():
        root = safe_xml(read_member(archive, "xl/sharedStrings.xml"))
        for si in root:
            shared.append("".join(t.text or "" for t in si.iter() if t.tag.endswith("}t")))
    parts = []
    sheets = sorted(n for n in archive.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml$", n))
    for name in sheets[:MAX_PAGES]:
        root = safe_xml(read_member(archive, name))
        cells = []
        for cell in root.iter():
            if not cell.tag.endswith("}c"):
                continue
            value = next((v.text for v in cell if v.tag.endswith("}v")), None)
            inline = "".join(t.text or "" for t in cell.iter() if t.tag.endswith("}t"))
            if cell.get("t") == "s" and value is not None and value.isdigit():
                index = int(value)
                cells.append(shared[index] if index < len(shared) else "")
            else:
                cells.append(inline or value or "")
        parts.append((f"лист {re.findall(r'\d+', name)[-1]}", " | ".join(c for c in cells if c)))
    return parts


def opendocument(path: str) -> list[tuple[str, str]]:
    archive = open_zip(path)
    root = safe_xml(read_member(archive, "content.xml"))
    return [("документ", text_of(root, ("p", "h", "table-row", "line-break")))]


HANDLERS = {
    "pdf": pdf,
    "docx": docx,
    "pptx": pptx,
    "xlsx": xlsx,
    "odt": opendocument,
    "ods": opendocument,
    "odp": opendocument,
}


def main() -> int:
    kind, path = sys.argv[1], sys.argv[2]
    handler = HANDLERS.get(kind)
    if handler is None:
        print(json.dumps({"error": f"формат {kind} не поддерживается"}))
        return 2
    try:
        parts = handler(path)
    except Limit as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 3
    except Exception as exc:  # noqa: BLE001 - report any parser failure as JSON
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"[:300]}, ensure_ascii=False))
        return 4
    out, size, truncated = [], 0, False
    for label, text in parts:
        if size + len(text) > MAX_TEXT:
            text, truncated = text[: max(0, MAX_TEXT - size)], True
        size += len(text)
        out.append({"label": label, "text": text})
        if truncated:
            break
    print(json.dumps({"parts": out, "truncated": truncated}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
