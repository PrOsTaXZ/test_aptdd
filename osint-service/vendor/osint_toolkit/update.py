"""Self-update of the application from the git checkout it runs from (``osint update``).

The application is installed as a git clone (``install.sh``) with its own virtual environment
created from ``uv.lock``. An update is:

1. ``git fetch`` of the tracked upstream branch — network only after consent through the
   :class:`~osint_toolkit.core.privacy.PrivacyGate` (a local-path remote needs no network);
2. a report: current/available version, new ``CHANGELOG.md`` lines, commits, changed files,
   whether dependencies or tool pins change;
3. after explicit confirmation: a **fast-forward only** merge (local edits or local commits make
   the update refuse — nothing is overwritten), ``uv sync --frozen`` from the lockfile and a
   self-check of the new version in a subprocess;
4. if syncing or the self-check fails, the previous commit and environment are restored
   automatically; ``osint update --rollback`` returns to the previous version later.

Only the checkout and its ``.venv`` change. User data lives in XDG directories outside the
checkout — settings and API keys (``~/.config/osint-toolkit``), history, reports, DB-IP bases,
installed tools (``~/.local/share/osint-toolkit``) — and is never touched. git runs with hooks
disabled and without credential prompts; uv never downloads a Python interpreter on its own.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from osint_toolkit.config import Settings, ensure_private_dir

UPDATE_MODULE = "app.update"
STATE_FILE = "update-state.json"
LOCK_FILE = "update.lock"
GIT_TIMEOUT = 180
SYNC_TIMEOUT = 900
MAX_COMMITS = 200
DEPENDENCY_FILES = ("uv.lock",)  # uv sync --frozen installs exactly the lockfile
TOOL_PIN_FILES = ("src/osint_toolkit/tools/manager.py",)
PYPI_HOSTS = "pypi.org, files.pythonhosted.org"

# Executed by the *updated* environment: imports every built-in module and the TUI.
VERIFY_CODE = """
import osint_toolkit, osint_toolkit.cli, osint_toolkit.tui.app
from osint_toolkit.core.registry import load_registry
registry = load_registry(entry_points_enabled=False, plugins_enabled=False)
assert registry.all(), "no modules"
assert not registry.load_errors, "broken modules: " + "; ".join(
    f"{name}: {error}" for name, error in registry.load_errors.items()
)
print(osint_toolkit.__version__, len(registry.all()))
"""


class UpdateError(Exception):
    pass


# --------------------------------------------------------------------------- git helpers
def _git_binary() -> str:
    found = shutil.which("git")
    if found is None:
        raise UpdateError("Не найден git — он нужен для обновления")
    return found


def git(root: Path, *args: str, timeout: float = GIT_TIMEOUT) -> str:
    """Run git in ``root`` with hooks disabled and no interactive prompts; return stdout."""
    argv = [_git_binary(), "-C", str(root), "-c", "core.hooksPath=/dev/null", *args]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0"}
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, git from PATH
            argv, capture_output=True, text=True, timeout=timeout, env=env, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise UpdateError(f"git {args[0]} не завершился за {timeout:g} с") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()[-3:]
        raise UpdateError(f"git {args[0]}: " + (" ".join(detail) or f"код {result.returncode}"))
    return result.stdout.rstrip("\n")  # keep leading spaces: porcelain status starts with one


def _git_ok(root: Path, *args: str) -> bool:
    try:
        git(root, *args)
    except UpdateError:
        return False
    return True


def is_network_url(url: str) -> bool:
    """True for remotes reached over the network (https, ssh, scp-like ``host:path``)."""
    if "://" in url:
        return urlsplit(url).scheme.lower() != "file"
    return bool(re.match(r"^[^/\\]+:", url)) and not Path(url).exists()


def display_url(url: str) -> str:
    """URL without credentials (``https://user:token@host`` → ``https://host``)."""
    if "://" not in url:
        return url
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port:
        host += f":{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def remote_host(url: str) -> str:
    if "://" in url:
        return urlsplit(url).hostname or url
    match = re.match(r"^(?:[^@/]+@)?([^:/]+):", url)
    return match.group(1) if match else url


# --------------------------------------------------------------------------- checkout
@dataclass(frozen=True, slots=True)
class Checkout:
    root: Path
    branch: str
    remote: str
    remote_branch: str
    remote_url: str
    managed: bool  # installed by install.sh (git config osint.managed=true)

    @property
    def upstream(self) -> str:
        return f"refs/remotes/{self.remote}/{self.remote_branch}"

    @property
    def network(self) -> bool:
        return is_network_url(self.remote_url)

    @property
    def venv(self) -> Path:
        return self.root / ".venv"


def package_root() -> Path:
    import osint_toolkit

    return Path(osint_toolkit.__file__).resolve().parents[2]


def locate_checkout(root: Path | None = None) -> Checkout:
    """The git checkout the application runs from, with its upstream branch."""
    root = (root or package_root()).resolve()
    pyproject = root / "pyproject.toml"
    if not (root / ".git").exists() or not pyproject.is_file():
        raise UpdateError(
            f"Программа установлена не из git-клона ({root}): обновление через osint update "
            "недоступно. Установите её через install.sh."
        )
    try:
        name = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["name"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        raise UpdateError(f"Не удалось прочитать {pyproject}: {exc}") from exc
    if name != "osint-toolkit":
        raise UpdateError(f"{root} — не каталог osint-toolkit")
    try:
        branch = git(root, "symbolic-ref", "--quiet", "--short", "HEAD")
    except UpdateError:
        raise UpdateError("HEAD не указывает на ветку (detached HEAD): обновите вручную") from None
    try:
        remote = git(root, "config", "--get", f"branch.{branch}.remote")
        merge = git(root, "config", "--get", f"branch.{branch}.merge")
    except UpdateError:
        raise UpdateError(
            f"У ветки {branch} нет отслеживаемой удалённой ветки. Это рабочая копия "
            "разработчика? Обновляйте её через git, а установленную копию — через osint update."
        ) from None
    if remote == ".":
        raise UpdateError(f"Ветка {branch} отслеживает локальную ветку — обновите вручную")
    url = git(root, "remote", "get-url", remote)
    managed = _git_ok(root, "config", "--get", "--type=bool", "osint.managed") and (
        git(root, "config", "--get", "--type=bool", "osint.managed") == "true"
    )
    return Checkout(
        root=root,
        branch=branch,
        remote=remote,
        remote_branch=merge.removeprefix("refs/heads/"),
        remote_url=url,
        managed=managed,
    )


def fetch(checkout: Checkout) -> None:
    git(
        checkout.root,
        "fetch",
        "--quiet",
        "--no-write-fetch-head",
        checkout.remote,
        f"+refs/heads/{checkout.remote_branch}:{checkout.upstream}",
    )


# --------------------------------------------------------------------------- update info
@dataclass(frozen=True, slots=True)
class Commit:
    sha: str
    date: str
    subject: str


@dataclass(frozen=True, slots=True)
class UpdateInfo:
    current: str
    target: str
    current_version: str
    target_version: str
    ahead: int  # local commits not in upstream
    behind: int  # upstream commits not in HEAD
    dirty: list[str] = field(default_factory=list)  # modified tracked files
    commits: list[Commit] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)  # "M path" lines
    changelog: list[str] = field(default_factory=list)  # lines added to CHANGELOG.md
    deps_changed: bool = False
    tool_pins_changed: bool = False

    @property
    def available(self) -> bool:
        return self.behind > 0

    @property
    def downgrade(self) -> bool:
        """The upstream version number is lower than the installed one."""
        current, target = version_key(self.current_version), version_key(self.target_version)
        return current is not None and target is not None and target < current

    @property
    def blocker(self) -> str | None:
        """Why the update cannot be applied automatically."""
        if not self.available:
            return None
        if self.ahead:
            return (
                f"в установленной копии {self.ahead} локальных коммитов, которых нет в "
                "источнике: обновление без перемотки (fast-forward) невозможно"
            )
        if self.dirty:
            return "в установленной копии изменены файлы: " + ", ".join(self.dirty[:5])
        return None


def version_key(version: str) -> tuple[int, ...] | None:
    """Numeric release part of a version ("0.10.2rc1" → (0, 10, 2)); None if not numeric."""
    match = re.match(r"^(\d+(?:\.\d+)*)", version.strip())
    if not match:
        return None
    parts = [int(p) for p in match.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == 0:  # 1.0 == 1.0.0
        parts.pop()
    return tuple(parts)


def _version_at(root: Path, rev: str) -> str:
    try:
        data = tomllib.loads(git(root, "show", f"{rev}:pyproject.toml"))
        return str(data["project"]["version"])
    except (UpdateError, KeyError, tomllib.TOMLDecodeError):
        return "?"


def inspect(checkout: Checkout) -> UpdateInfo:
    """Compare HEAD with the (already fetched) upstream branch. No network."""
    root = checkout.root
    current = git(root, "rev-parse", "HEAD")
    try:
        target = git(root, "rev-parse", "--verify", f"{checkout.upstream}^{{commit}}")
    except UpdateError:
        raise UpdateError(
            f"Нет данных о ветке {checkout.remote}/{checkout.remote_branch}: сначала git fetch"
        ) from None
    ahead, behind = (
        int(n) for n in git(root, "rev-list", "--left-right", "--count", f"HEAD...{target}").split()
    )
    dirty = [
        line[3:]
        for line in git(root, "status", "--porcelain", "--untracked-files=no").splitlines()
        if line.strip()
    ]
    info: dict[str, Any] = {
        "current": current,
        "target": target,
        "current_version": _version_at(root, current),
        "target_version": _version_at(root, target),
        "ahead": ahead,
        "behind": behind,
        "dirty": dirty,
    }
    if behind:
        log = git(
            root, "log", f"--max-count={MAX_COMMITS}", "--format=%H%x1f%cs%x1f%s", f"HEAD..{target}"
        )
        info["commits"] = [Commit(*line.split("\x1f", 2)) for line in log.splitlines() if line]
        names = git(root, "diff", "--name-status", "--no-renames", f"HEAD...{target}")
        info["changes"] = [" ".join(line.split("\t", 1)) for line in names.splitlines() if line]
        changed = {line.split(" ", 1)[1] for line in info["changes"]}
        info["deps_changed"] = any(f in changed for f in DEPENDENCY_FILES)
        info["tool_pins_changed"] = any(f in changed for f in TOOL_PIN_FILES)
        diff = git(root, "diff", "--unified=0", f"HEAD...{target}", "--", "CHANGELOG.md")
        info["changelog"] = [
            line[1:]
            for line in diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
    return UpdateInfo(**info)


# --------------------------------------------------------------------------- environment
def _locate_uv() -> Path:
    for candidate in (
        shutil.which("uv"),
        Path.home() / ".local/bin/uv",
        Path.home() / ".cargo/bin/uv",
    ):
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    raise UpdateError("Не найден uv (https://docs.astral.sh/uv/) — он нужен для обновления")


def check_environment(checkout: Checkout) -> None:
    """The running interpreter must be the checkout's own ``.venv`` (what uv sync updates)."""
    prefix = Path(sys.prefix).resolve()
    if prefix != checkout.venv.resolve():
        raise UpdateError(
            f"Программа запущена не из окружения {checkout.venv} (а из {prefix}): "
            "обновление этой установки через osint update невозможно"
        )


Sync = Callable[[Checkout, bool], None]
Verify = Callable[[Checkout], str]


def uv_sync(checkout: Checkout, offline: bool) -> None:
    """Install exactly the dependencies from uv.lock into the checkout's .venv."""
    argv = [str(_locate_uv()), "sync", "--frozen", "--quiet", "--project", str(checkout.root)]
    if checkout.managed:
        argv.append("--no-dev")  # installed copies carry no test/lint tools
    if offline:
        argv.append("--offline")
    env = {
        k: v for k, v in os.environ.items() if k not in ("VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT")
    }
    env["UV_PYTHON_DOWNLOADS"] = "never"
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv
            argv, capture_output=True, text=True, timeout=SYNC_TIMEOUT, env=env, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise UpdateError(f"uv sync не завершился за {SYNC_TIMEOUT} с") from exc
    if result.returncode != 0:
        tail = result.stderr.strip().splitlines()[-4:]
        raise UpdateError("uv sync: " + (" ".join(tail) or f"код {result.returncode}"))


def self_check(checkout: Checkout) -> str:
    """Import the updated application in a fresh interpreter; return '<version> <modules>'."""
    python = checkout.venv / "bin" / "python"
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, interpreter of the checkout
            [str(python), "-I", "-c", VERIFY_CODE],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdateError(f"Проверка новой версии не запустилась: {exc}") from exc
    if result.returncode != 0:
        lines = result.stderr.strip().splitlines() or [f"код {result.returncode}"]
        raise UpdateError("Проверка новой версии не прошла: " + lines[-1].strip())
    return result.stdout.strip()


# --------------------------------------------------------------------------- state & lock
def state_path(settings: Settings) -> Path:
    return settings.state_dir / STATE_FILE


def load_state(settings: Settings) -> dict[str, Any] | None:
    path = state_path(settings)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _save_state(settings: Settings, data: dict[str, Any]) -> None:
    ensure_private_dir(settings.state_dir)
    path = state_path(settings)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    tmp.replace(path)


@contextlib.contextmanager
def update_lock(settings: Settings) -> Iterator[None]:
    ensure_private_dir(settings.state_dir)
    fd = os.open(settings.state_dir / LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise UpdateError("Обновление уже выполняется в другом процессе") from None
        yield
    finally:
        os.close(fd)


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- apply / rollback
@dataclass(frozen=True, slots=True)
class UpdateResult:
    previous: str
    current: str
    check: str  # self-check output of the new version


def _move_to(checkout: Checkout, commit: str) -> None:
    # --keep refuses (instead of discarding) if a tracked file has local modifications.
    git(checkout.root, "reset", "--quiet", "--keep", commit)


def apply_update(
    checkout: Checkout,
    info: UpdateInfo,
    settings: Settings,
    *,
    offline: bool,
    sync: Sync | None = None,
    verify: Verify | None = None,
) -> UpdateResult:
    """Fast-forward to ``info.target``; restore the previous version if anything fails."""
    sync = sync or uv_sync
    verify = verify or self_check
    if not info.available:
        raise UpdateError("Обновлений нет")
    if info.blocker:
        raise UpdateError(f"Обновление невозможно: {info.blocker}")
    with update_lock(settings):
        fresh = inspect(checkout)
        if fresh.current != info.current or fresh.target != info.target or fresh.blocker:
            raise UpdateError("Состояние копии изменилось после проверки — запустите снова")
        prior = load_state(settings)  # rollback point of the previous successful update
        state: dict[str, Any] = {
            "root": str(checkout.root),
            "branch": checkout.branch,
            "previous": info.current,
            "previous_version": info.current_version,
            "target": info.target,
            "target_version": info.target_version,
            "started_at": _now(),
            "status": "applying",
        }
        _save_state(settings, state)
        git(checkout.root, "merge", "--ff-only", "--quiet", info.target)
        try:
            sync(checkout, offline)
            output = verify(checkout)
        except UpdateError as exc:
            restored = _restore(checkout, info.current, sync)
            failure = {
                "target": info.target,
                "target_version": info.target_version,
                "at": _now(),
                "error": str(exc),
            }
            # Keep the previous rollback point usable: the failed attempt changed nothing.
            base = prior if prior and restored is None else {**state, "status": "rolled_back"}
            _save_state(settings, {**base, "last_failure": failure})
            raise UpdateError(
                f"{exc}\nПрежняя версия восстановлена"
                + ("." if restored is None else f", но: {restored}")
            ) from exc
        _save_state(settings, {**state, "status": "applied", "applied_at": _now()})
        return UpdateResult(info.current, info.target, output)


def _restore(checkout: Checkout, commit: str, sync: Sync) -> str | None:
    """Return the checkout and its environment to ``commit``. Returns a problem or None."""
    try:
        _move_to(checkout, commit)
    except UpdateError as exc:
        return f"код не возвращён ({exc}); выполните: git -C {checkout.root} reset --keep {commit}"
    try:
        sync(checkout, True)  # the previous dependencies are in uv's cache
    except UpdateError as exc:
        return f"окружение не восстановлено ({exc}); выполните: uv sync --frozen --project " + str(
            checkout.root
        )
    return None


def rollback(
    checkout: Checkout,
    settings: Settings,
    *,
    sync: Sync | None = None,
    verify: Verify | None = None,
) -> UpdateResult:
    """Return to the version before the last successful ``osint update``."""
    sync = sync or uv_sync
    verify = verify or self_check
    with update_lock(settings):
        state = load_state(settings)
        if not state or state.get("status") != "applied":
            raise UpdateError("Нет применённого обновления, к которому можно откатиться")
        if Path(str(state.get("root"))).resolve() != checkout.root:
            raise UpdateError("Последнее обновление относится к другой установке")
        head = git(checkout.root, "rev-parse", "HEAD")
        if head != state["target"]:
            raise UpdateError(
                "После обновления копия изменилась (HEAD не совпадает с установленной "
                "версией) — откатитесь вручную через git"
            )
        if git(checkout.root, "status", "--porcelain", "--untracked-files=no"):
            raise UpdateError("В установленной копии изменены файлы — откат отменён")
        previous = str(state["previous"])
        _move_to(checkout, previous)
        try:
            sync(checkout, True)
            output = verify(checkout)
        except UpdateError as exc:
            _save_state(settings, {**state, "status": "rollback_failed", "error": str(exc)})
            raise UpdateError(
                f"Код возвращён к {previous[:12]}, но окружение не прошло проверку: {exc}. "
                f"Выполните: uv sync --frozen --project {checkout.root}"
            ) from exc
        _save_state(settings, {**state, "status": "rolled_back", "rolled_back_at": _now()})
        return UpdateResult(head, previous, output)
