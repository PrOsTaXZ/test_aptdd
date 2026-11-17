"""Run external programs inside a bubblewrap (bwrap) sandbox.

Isolation applied to every run:

* new user, PID, IPC, UTS, cgroup and (unless ``network=True``) network namespaces;
  ``--disable-userns`` forbids nested namespaces, ``--cap-drop ALL`` drops capabilities;
* an empty read-only root: only ``/usr`` (read-only), the ``/etc`` files needed for DNS/TLS
  when networking is allowed, fresh ``/proc``, ``/dev`` and ``/tmp``, plus explicitly listed
  paths. The home directory, ``/`` and their parents can never be mounted (checked in code);
* a cleared environment (``--clearenv``) with ``HOME=/work`` — no API keys, tokens, proxies or
  user configuration leak into the tool; ``--new-session`` blocks terminal input injection;
* ``--die-with-parent`` + killing the process group on timeout or cancellation, so no orphan
  processes survive; output is size-capped.

If bwrap is missing or cannot create namespaces, :func:`sandbox_status` reports why and callers
must refuse to run the tool — there is no unsandboxed fallback.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

SANDBOX_WORKDIR = "/work"
MAPPED_ROOTS = ("/input/", "/opt/osint/")
DEFAULT_MAX_OUTPUT = 2 * 1024 * 1024

# Files needed for name resolution and TLS verification (only mounted with network access).
NETWORK_ETC = (
    "/etc/resolv.conf",
    "/run/systemd/resolve",
    "/etc/hosts",
    "/etc/host.conf",
    "/etc/nsswitch.conf",
    "/etc/gai.conf",
    "/etc/ssl",
    "/etc/ca-certificates",
    "/etc/pki",
)
BASE_ETC = ("/etc/localtime", "/etc/mime.types")
ENV_ALLOWLIST_DEFAULTS = {
    "PATH": "/usr/bin:/bin",
    "HOME": SANDBOX_WORKDIR,
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TMPDIR": "/tmp",  # noqa: S108 - the sandbox's private tmpfs, not the host /tmp
    "PYTHONNOUSERSITE": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONIOENCODING": "utf-8",
}


class SandboxError(Exception):
    """The sandbox could not be set up or the sandboxed program failed to start."""


class SandboxTimeoutError(SandboxError):
    pass


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    network: bool = False
    read_only: tuple[Path, ...] = ()  # mounted at the same path, read-only
    read_write: tuple[Path, ...] = ()  # mounted at the same path, writable
    workdir: Path | None = None  # host dir mounted writable at /work
    # host file/dir → sandbox path (read-only); hides the host path, e.g. image → /input/image.jpg
    mapped_read_only: tuple[tuple[Path, str], ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SandboxResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_s: float
    truncated: bool = False

    def stderr_tail(self, lines: int = 8) -> str:
        text = self.stderr.decode("utf-8", errors="replace").strip().splitlines()
        return "\n".join(text[-lines:])


@dataclass(frozen=True, slots=True)
class SandboxStatus:
    available: bool
    reason: str | None = None
    version: str | None = None


# --------------------------------------------------------------------------- policy checks
def _forbidden_roots() -> list[Path]:
    home = Path.home().resolve()
    return [Path("/"), Path("/home"), Path("/root"), home, *home.parents]


def check_mount(path: Path) -> Path:
    """Resolve and validate a host path to be mounted into the sandbox."""
    resolved = path.expanduser().resolve()
    if not resolved.is_absolute():
        raise SandboxError(f"Путь должен быть абсолютным: {path}")
    if resolved in _forbidden_roots():
        raise SandboxError(
            f"Запрещено монтировать в песочницу {resolved} (домашний каталог, "
            "корень или их родители)"
        )
    if not resolved.exists():
        raise SandboxError(f"Путь для песочницы не существует: {resolved}")
    return resolved


def build_command(policy: SandboxPolicy, argv: Sequence[str], bwrap: str = "bwrap") -> list[str]:
    if not argv:
        raise SandboxError("Пустая команда")
    cmd = [
        bwrap,
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--hostname",
        "osint-sandbox",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/sbin",
        "/sbin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",  # noqa: S108 - private tmpfs inside the sandbox
        "--dir",
        "/etc",
    ]
    if policy.network:
        cmd.insert(2, "--share-net")
        for etc in NETWORK_ETC:
            cmd += ["--ro-bind-try", etc, etc]
    for etc in BASE_ETC:
        cmd += ["--ro-bind-try", etc, etc]
    for path in policy.read_only:
        resolved = check_mount(path)
        cmd += ["--ro-bind", str(resolved), str(resolved)]
    for path in policy.read_write:
        resolved = check_mount(path)
        cmd += ["--bind", str(resolved), str(resolved)]
    for host, dest in policy.mapped_read_only:
        if not dest.startswith(MAPPED_ROOTS) or ".." in dest.split("/"):
            raise SandboxError(f"Недопустимый путь в песочнице: {dest}")
        cmd += ["--ro-bind", str(check_mount(host)), dest]
    if policy.workdir is not None:
        work = check_mount(policy.workdir)
        cmd += ["--bind", str(work), SANDBOX_WORKDIR, "--chdir", SANDBOX_WORKDIR]
    else:
        cmd += ["--dir", SANDBOX_WORKDIR, "--chdir", SANDBOX_WORKDIR]
    cmd += ["--remount-ro", "/"]  # root is read-only; only /tmp and /work stay writable
    env = {**ENV_ALLOWLIST_DEFAULTS, **policy.env}
    for key, value in sorted(env.items()):
        cmd += ["--setenv", key, value]
    cmd += ["--", *argv]
    return cmd


# --------------------------------------------------------------------------- availability
@cache
def sandbox_status() -> SandboxStatus:
    """Probe once per process whether bwrap can create an isolated sandbox here."""
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        return SandboxStatus(False, "bwrap не установлен (sudo apt install bubblewrap)")
    try:
        version = subprocess.run(  # noqa: S603 - fixed argv, absolute path from which()
            [bwrap, "--version"], capture_output=True, text=True, timeout=5, check=False
        ).stdout.strip()
        probe = subprocess.run(  # noqa: S603
            build_command(SandboxPolicy(), ["/usr/bin/true"], bwrap=bwrap),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return SandboxStatus(False, f"bwrap не запускается: {exc}")
    if probe.returncode != 0:
        detail = probe.stderr.strip().splitlines()[-1:] or ["неизвестная ошибка"]
        return SandboxStatus(False, f"bwrap не может создать песочницу: {detail[0]}", version)
    return SandboxStatus(True, None, version)


# --------------------------------------------------------------------------- execution
async def _read_capped(stream: asyncio.StreamReader | None, limit: int) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False
    chunks: list[bytes] = []
    size = 0
    truncated = False
    while chunk := await stream.read(65536):
        if size < limit:
            chunks.append(chunk[: limit - size])
        size += len(chunk)
        truncated = truncated or size > limit
    return b"".join(chunks), truncated


async def _read_lines(
    stream: asyncio.StreamReader | None, limit: int, on_line: Callable[[str], None]
) -> tuple[bytes, bool]:
    """Like :func:`_read_capped`, but hands every complete line to ``on_line`` as it arrives
    (live progress); the callback sees lines even after the stored output hits the cap."""
    if stream is None:
        return b"", False
    chunks: list[bytes] = []
    size = 0
    truncated = False
    pending = b""
    while chunk := await stream.read(65536):
        if size < limit:
            chunks.append(chunk[: limit - size])
        size += len(chunk)
        truncated = truncated or size > limit
        pending += chunk
        *lines, pending = pending.split(b"\n")
        pending = pending[-65536:]  # an endless line cannot grow memory
        for line in lines:
            try:
                on_line(line.decode("utf-8", errors="replace").rstrip("\r"))
            except Exception:  # noqa: BLE001, S112 - a progress callback must not stop reading
                continue
    return b"".join(chunks), truncated


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)


async def run_sandboxed(
    policy: SandboxPolicy,
    argv: Sequence[str],
    *,
    limit_s: float,
    max_output: int = DEFAULT_MAX_OUTPUT,
    on_stdout_line: Callable[[str], None] | None = None,
) -> SandboxResult:
    """Run ``argv`` in the sandbox. Raises SandboxTimeoutError; on cancellation the process
    group is killed before CancelledError propagates."""
    status = sandbox_status()
    if not status.available:
        raise SandboxError(status.reason or "песочница недоступна")
    bwrap = shutil.which("bwrap") or "bwrap"
    cmd = build_command(policy, argv, bwrap=bwrap)
    started = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,  # own process group → reliable kill
            env={"PATH": "/usr/bin:/bin"},  # bwrap itself gets no user environment either
        )
    except OSError as exc:
        raise SandboxError(f"Не удалось запустить bwrap: {exc}") from exc
    try:
        async with asyncio.timeout(limit_s):
            stdout = (
                _read_lines(proc.stdout, max_output, on_stdout_line)
                if on_stdout_line is not None
                else _read_capped(proc.stdout, max_output)
            )
            (out, out_cut), (err, err_cut) = await asyncio.gather(
                stdout, _read_capped(proc.stderr, max_output)
            )
            returncode = await proc.wait()
    except TimeoutError:
        _kill_group(proc)
        await proc.wait()
        raise SandboxTimeoutError(
            f"Инструмент не завершился за {limit_s:g} с и был остановлен"
        ) from None
    except asyncio.CancelledError:
        _kill_group(proc)
        with contextlib.suppress(Exception):
            await asyncio.shield(proc.wait())
        raise
    return SandboxResult(
        returncode, out, err, round(time.monotonic() - started, 3), out_cut or err_cut
    )
