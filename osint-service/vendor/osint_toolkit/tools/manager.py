"""Install, inspect and remove isolated tools.

Every tool lives in ``<data_dir>/tools/<name>/`` and is pinned:

* ``python`` tools — a virtual environment created by ``uv`` with the application's base
  interpreter; the requirement is a pinned PyPI version or a git URL pinned to a commit (verified
  after installation via ``direct_url.json``). Installation runs *inside the sandbox*: package
  build scripts can write only to the tool environment and a throw-away cache.
* ``archive`` tools — an official release archive downloaded over HTTPS, verified against a
  SHA-256 pinned in code, and unpacked with :mod:`tarfile`'s ``data`` filter (no absolute paths,
  no ``..``, no links outside the tree). Nothing from the archive is executed during install.

Upgrading means changing the pin in code — never an implicit "latest".
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import re
import shutil
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from osint_toolkit.config import Settings, ensure_private_dir
from osint_toolkit.net import HttpClient, NetworkError
from osint_toolkit.sandbox import (
    SandboxError,
    SandboxPolicy,
    run_sandboxed,
    sandbox_status,
)

MARKER = ".osint-tool.json"


class ToolError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    package: str
    version: str
    license: str
    homepage: str
    module: str = ""  # python -m <module> (python tools that support it)
    kind: Literal["python", "archive"] = "python"
    requirement: str = ""  # default: "<package>==<version>"
    git_commit: str | None = None  # expected commit for git requirements
    archive_urls: tuple[str, ...] = ()
    archive_sha256: str | None = None
    size_hint: str = ""
    note: str = ""  # shown before installation (e.g. maintenance status)

    @property
    def pip_requirement(self) -> str:
        return self.requirement or f"{self.package}=={self.version}"


MAIGRET = ToolSpec(
    name="maigret",
    package="maigret",
    version="0.6.6",
    module="maigret",
    license="MIT",
    homepage="https://github.com/soxoj/maigret",
    size_hint="~180 МБ",
)
THEHARVESTER = ToolSpec(
    name="theharvester",
    package="theHarvester",
    version="4.11.1",
    license="GPL-2.0",
    homepage="https://github.com/laramies/theHarvester",
    requirement="theHarvester @ git+https://github.com/laramies/theHarvester"
    "@fd832dee7936458a4f6e2029bf37ba6797228676",
    git_commit="fd832dee7936458a4f6e2029bf37ba6797228676",
    size_hint="~220 МБ",
    note="Устанавливается из git-коммита релиза 4.11.1 (на PyPI актуальной версии нет).",
)
HOLEHE = ToolSpec(
    name="holehe",
    package="holehe",
    version="1.61",
    license="GPL-3.0",
    homepage="https://github.com/megadose/holehe",
    size_hint="~7 МБ",
    note="holehe не обновлялся с 2022 года (репозиторий — с 2024): часть проверок устарела. "
    "Запускается собственным адаптером без самообновления и без восстановления пароля.",
)
EXIFTOOL = ToolSpec(
    name="exiftool",
    package="Image-ExifTool",
    version="13.63",
    license="Perl Artistic / GPL",
    homepage="https://exiftool.org",
    kind="archive",
    archive_urls=(
        "https://exiftool.org/Image-ExifTool-13.63.tar.gz",
        "https://sourceforge.net/projects/exiftool/files/Image-ExifTool-13.63.tar.gz/download",
    ),
    archive_sha256="c6438851b971886f2eb35426ea5bc8960f34ae4eddeca3198a57af5b0ad49cbd",
    size_hint="~30 МБ",
    note="Для запуска нужен системный Perl (/usr/bin/perl).",
)
TOOLS = {spec.name: spec for spec in (MAIGRET, THEHARVESTER, HOLEHE, EXIFTOOL)}
MAX_ARCHIVE = 80 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ToolStatus:
    spec: ToolSpec
    path: Path
    installed: bool
    version: str | None = None
    python: Path | None = None
    sandbox_ok: bool = False
    sandbox_reason: str | None = None

    @property
    def ready(self) -> bool:
        runnable = self.python is not None if self.spec.kind == "python" else True
        return self.installed and self.sandbox_ok and runnable

    @property
    def problem(self) -> str | None:
        if not self.sandbox_ok:
            return self.sandbox_reason or "песочница bwrap недоступна"
        if not self.installed:
            return f"{self.spec.name} не установлен: osint tools install {self.spec.name}"
        return None

    @property
    def outdated(self) -> bool:
        """An installed version differs from the pin (reinstall to switch to the pin)."""
        return self.version is not None and self.version != self.spec.version

    @property
    def summary(self) -> str:
        """Short state label for status tables."""
        if not self.sandbox_ok:
            return "нет песочницы"
        if self.outdated:
            return (
                f"версия {self.version} ≠ {self.spec.version}: osint tools install {self.spec.name}"
            )
        if self.ready:
            return "готов"
        return f"не установлен: osint tools install {self.spec.name}"


def venv_path(settings: Settings, spec: ToolSpec) -> Path:
    return settings.tools_dir / spec.name


def get_spec(name: str) -> ToolSpec:
    try:
        return TOOLS[name.lower()]
    except KeyError:
        raise ToolError(f"Неизвестный инструмент: {name} (доступны: {', '.join(TOOLS)})") from None


def install_summary(settings: Settings, spec: ToolSpec) -> str:
    """Human-readable description of what installing ``spec`` downloads and where it goes."""
    size = f" ({spec.size_hint})" if spec.size_hint else ""
    target = venv_path(settings, spec)
    if spec.kind == "archive":
        hosts = ", ".join(dict.fromkeys(u.split("/")[2] for u in spec.archive_urls))
        lines = [
            f"{spec.package} {spec.version} ({spec.license}, {spec.homepage}){size}: "
            f"официальный архив с {hosts} → {target}.",
            f"SHA-256 архива сверяется с закреплённым {spec.archive_sha256}; при установке "
            "ничего из архива не выполняется. Сервер увидит ваш IP-адрес.",
        ]
    else:
        source = f"git-коммит {spec.git_commit[:12]} (GitHub)" if spec.git_commit else "PyPI"
        lines = [
            f"{spec.package} {spec.version} ({spec.license}, {spec.homepage}){size} с "
            f"зависимостями из {source}" + (" и PyPI" if spec.git_commit else "") + f" → {target}.",
            "Установка выполняется в песочнице bwrap без доступа к домашнему каталогу; "
            "серверы увидят ваш IP-адрес.",
        ]
    if spec.note:
        lines.append(spec.note)
    return "\n".join(lines)


def _site_packages(venv: Path) -> list[Path]:
    return sorted(venv.glob("lib/python3*/site-packages"))


def _dist_info(venv: Path, package: str) -> Path | None:
    normalized = re.sub(r"[-_.]+", "_", package).lower()
    for site in _site_packages(venv):
        for meta in site.glob("*.dist-info/METADATA"):
            if re.sub(r"[-_.]+", "_", meta.parent.name.split("-")[0]).lower() == normalized:
                return meta.parent
    return None


def installed_version(venv: Path, package: str) -> str | None:
    dist = _dist_info(venv, package)
    if dist is None:
        return None
    for line in (dist / "METADATA").read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("Version:"):
            return line.split(":", 1)[1].strip()
    return None


def installed_commit(venv: Path, package: str) -> str | None:
    dist = _dist_info(venv, package)
    if dist is None or not (dist / "direct_url.json").is_file():
        return None
    try:
        data = json.loads((dist / "direct_url.json").read_text(encoding="utf-8"))
    except ValueError:
        return None
    commit = (data.get("vcs_info") or {}).get("commit_id")
    return str(commit) if commit else None


def base_interpreter_prefix(venv: Path) -> Path | None:
    """Prefix of the base interpreter (from pyvenv.cfg) that must be visible in the sandbox."""
    cfg = venv / "pyvenv.cfg"
    if not cfg.is_file():
        return None
    for line in cfg.read_text(encoding="utf-8").splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "home" and value.strip():
            return Path(value.strip()).resolve().parent
    return None


def sandbox_mounts(venv: Path) -> tuple[Path, ...]:
    """Read-only mounts needed to run the tool: its dir and (if outside /usr) the interpreter."""
    mounts = [venv]
    prefix = base_interpreter_prefix(venv)
    if prefix is not None and not prefix.is_relative_to("/usr"):
        mounts.append(prefix)
    return tuple(mounts)


def _archive_version(path: Path) -> str | None:
    marker = path / MARKER
    if not marker.is_file():
        return None
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except ValueError:
        return None
    return str(data.get("version")) if data.get("version") else None


def tool_status(settings: Settings, spec: ToolSpec = MAIGRET) -> ToolStatus:
    path = venv_path(settings, spec)
    sandbox = sandbox_status()
    if spec.kind == "archive":
        version = _archive_version(path) if path.is_dir() else None
        return ToolStatus(
            spec=spec,
            path=path,
            installed=version == spec.version,
            version=version,
            sandbox_ok=sandbox.available,
            sandbox_reason=sandbox.reason,
        )
    python = path / "bin" / "python"
    version = installed_version(path, spec.package) if path.is_dir() else None
    return ToolStatus(
        spec=spec,
        path=path,
        installed=version is not None,
        version=version,
        python=python if python.exists() else None,
        sandbox_ok=sandbox.available,
        sandbox_reason=sandbox.reason,
    )


def _locate_uv() -> Path | None:
    found = shutil.which("uv")
    return Path(found).resolve() if found else None


def _base_python() -> Path:
    """Interpreter for new tool environments: the application's own base interpreter."""
    candidate = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    if not candidate.exists():
        raise ToolError(f"Не найден интерпретатор Python: {candidate}")
    return candidate


async def install_tool(
    settings: Settings, spec: ToolSpec = MAIGRET, *, limit_s: float = 900
) -> ToolStatus:
    """Install the pinned version of ``spec`` (python tools inside the sandbox)."""
    if settings.offline:
        raise ToolError("Офлайн-режим: установка запрещена")
    sandbox = sandbox_status()
    if not sandbox.available:
        raise ToolError(sandbox.reason or "песочница недоступна")
    ensure_private_dir(settings.tools_dir)
    if spec.kind == "archive":
        return await _install_archive(settings, spec)
    uv_path = _locate_uv()
    if uv_path is None:
        raise ToolError(
            "Нужен uv (https://docs.astral.sh/uv/) — он используется для изолированной "
            "установки инструментов"
        )
    python = _base_python()
    venv = venv_path(settings, spec)
    fresh = not venv.exists()
    venv.mkdir(mode=0o700, exist_ok=True)
    # Mount only the uv binary itself — never its directory (e.g. ~/.local/bin).
    ro = [uv_path] if not uv_path.is_relative_to("/usr") else []
    if not python.is_relative_to("/usr"):
        ro.append(python.parent.parent)
    env = {
        "UV_NO_CONFIG": "1",
        "UV_PYTHON_DOWNLOADS": "never",
        "UV_CACHE_DIR": "/work/cache",
        "UV_NO_PROGRESS": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    if settings.http_proxy:
        env["HTTPS_PROXY"] = env["HTTP_PROXY"] = str(settings.http_proxy)
    ensure_private_dir(settings.cache_dir)
    with tempfile.TemporaryDirectory(prefix="tool-install-", dir=settings.cache_dir) as work:
        policy = SandboxPolicy(
            network=True, read_only=tuple(ro), read_write=(venv,), workdir=Path(work), env=env
        )
        steps = [
            [
                str(uv_path),
                "venv",
                "--quiet",
                "--allow-existing",
                "--python",
                str(python),
                str(venv),
            ],
            [
                str(uv_path),
                "pip",
                "install",
                "--quiet",
                "--python",
                str(venv / "bin" / "python"),
                spec.pip_requirement,
            ],
        ]
        try:
            for argv in steps:
                result = await run_sandboxed(policy, argv, limit_s=limit_s)
                if result.returncode != 0:
                    raise ToolError(f"Установка {spec.name} не удалась:\n{result.stderr_tail()}")
            status = tool_status(settings, spec)
            if status.version != spec.version:
                raise ToolError(
                    f"После установки найдена версия {status.version}, ожидалась {spec.version}"
                )
            if spec.git_commit and installed_commit(venv, spec.package) != spec.git_commit:
                raise ToolError("Установленный коммит не совпадает с закреплённым")
        except (SandboxError, ToolError):
            if fresh:
                shutil.rmtree(venv, ignore_errors=True)
            raise
    return status


async def _install_archive(settings: Settings, spec: ToolSpec) -> ToolStatus:
    http = HttpClient(settings)
    data: bytes | None = None
    errors: list[str] = []
    try:
        for url in spec.archive_urls:
            try:
                _, data = await http.get_bytes(url, max_bytes=MAX_ARCHIVE, request_timeout=300)
                break
            except NetworkError as exc:
                errors.append(f"{url}: {exc}")
    finally:
        await http.aclose()
    if data is None:
        raise ToolError("Не удалось скачать архив:\n" + "\n".join(errors))
    digest = hashlib.sha256(data).hexdigest()
    if digest != spec.archive_sha256:
        raise ToolError(
            f"Контрольная сумма архива не совпадает (получено {digest[:16]}…) — установка отменена"
        )
    return await asyncio.to_thread(_unpack_archive, settings, spec, data, digest)


def _unpack_archive(settings: Settings, spec: ToolSpec, data: bytes, digest: str) -> ToolStatus:
    target = venv_path(settings, spec)
    staging = Path(tempfile.mkdtemp(prefix=f".{spec.name}-", dir=settings.tools_dir))
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            members = []
            for member in archive.getmembers():
                parts = Path(member.name).parts
                if len(parts) < 2:
                    continue
                member.name = str(Path(*parts[1:]))  # strip "Image-ExifTool-13.63/"
                members.append(member)
            archive.extractall(staging, members=members, filter="data")
        marker = {"version": spec.version, "sha256": digest, "source": spec.archive_urls[0]}
        (staging / MARKER).write_text(json.dumps(marker), encoding="utf-8")
        staging.chmod(0o700)
    except (tarfile.TarError, OSError) as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise ToolError(f"Не удалось распаковать архив: {exc}") from exc
    _swap_into_place(settings, spec, staging, target)
    return tool_status(settings, spec)


def _swap_into_place(settings: Settings, spec: ToolSpec, staging: Path, target: Path) -> None:
    """Replace ``target`` with ``staging``; the previous installation survives any failure."""
    backup: Path | None = None
    try:
        if target.exists() or target.is_symlink():
            if target.is_symlink() or not target.resolve().is_relative_to(
                settings.tools_dir.resolve()
            ):
                raise ToolError(f"Отказ: {target} вне каталога инструментов")
            backup = Path(tempfile.mkdtemp(prefix=f".{spec.name}-old-", dir=settings.tools_dir))
            backup.rmdir()
            target.replace(backup)
        staging.replace(target)
    except (OSError, ToolError) as exc:
        if backup is not None and not target.exists():
            backup.replace(target)
            backup = None
        shutil.rmtree(staging, ignore_errors=True)
        if isinstance(exc, ToolError):
            raise
        raise ToolError(f"Не удалось установить {spec.name}: {exc}") from exc
    finally:
        if backup is not None:
            shutil.rmtree(backup, ignore_errors=True)


def remove_tool(settings: Settings, spec: ToolSpec = MAIGRET) -> bool:
    path = venv_path(settings, spec)
    if not path.exists() and not path.is_symlink():
        return False
    if path.is_symlink() or not path.resolve().is_relative_to(settings.tools_dir.resolve()):
        raise ToolError(f"Отказ: {path} вне каталога инструментов")
    shutil.rmtree(path)
    return True
