"""Persistent PTY terminal sessions for Kali Linux."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

TERMINAL_SESSIONS: dict[str, dict[str, Any]] = {}


def _require_posix() -> None:
    if os.name == "nt":
        raise RuntimeError("PTY terminal sessions require Kali/Linux; use shell_exec on Windows.")


def _set_winsize(fd: int, rows: int, cols: int) -> None:
    import fcntl
    import struct
    import termios

    packed = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)


def _set_nonblocking(fd: int) -> None:
    import fcntl

    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def start_terminal_session(
    command: str = "bash",
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    rows: int = 30,
    cols: int = 120,
    transcript_path: str | None = None,
) -> dict[str, Any]:
    """Start a persistent interactive PTY session."""

    _require_posix()
    import pty

    master_fd, slave_fd = pty.openpty()
    _set_winsize(slave_fd, rows, cols)
    _set_nonblocking(master_fd)
    proc_env = os.environ.copy()
    if env:
        proc_env.update({str(key): str(value) for key, value in env.items()})
    process = subprocess.Popen(
        command,
        shell=True,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        cwd=cwd,
        env=proc_env,
        preexec_fn=os.setsid,
        close_fds=True,
    )
    os.close(slave_fd)
    session_id = uuid4().hex
    session = {
        "session_id": session_id,
        "pid": process.pid,
        "process": process,
        "fd": master_fd,
        "command": command,
        "cwd": cwd or os.getcwd(),
        "rows": rows,
        "cols": cols,
        "started_at": time.time(),
        "status": "running",
        "bytes_read": 0,
        "transcript_path": transcript_path,
    }
    if transcript_path:
        path = Path(transcript_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# ExnoKaliMCP terminal transcript\n# command: {command}\n\n", encoding="utf-8")
        session["transcript_path"] = str(path)
    TERMINAL_SESSIONS[session_id] = session
    return _public_session(session)


def send_terminal_input(session_id: str, text: str, newline: bool = False) -> dict[str, Any]:
    """Send raw input to a PTY terminal session."""

    session = _get_session(session_id)
    payload = text + ("\n" if newline else "")
    written = os.write(int(session["fd"]), payload.encode())
    return {"session": _public_session(session), "bytes_sent": written}


def read_terminal_output(session_id: str, max_bytes: int = 65536) -> dict[str, Any]:
    """Read available output from a PTY terminal session."""

    _require_posix()
    import select

    session = _get_session(session_id)
    fd = int(session["fd"])
    chunks: list[bytes] = []
    remaining = max(1, int(max_bytes))
    while remaining > 0:
        ready, _, _ = select.select([fd], [], [], 0)
        if not ready:
            break
        try:
            chunk = os.read(fd, min(remaining, 4096))
        except BlockingIOError:
            break
        except OSError as exc:
            session["status"] = "closed"
            return {"session": _public_session(session), "data": "", "error": str(exc)}
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    data = b"".join(chunks).decode(errors="replace")
    session["bytes_read"] = int(session.get("bytes_read", 0)) + len(data.encode())
    if data and session.get("transcript_path"):
        with Path(str(session["transcript_path"])).open("a", encoding="utf-8", errors="replace") as handle:
            handle.write(data)
    process = session["process"]
    if process.poll() is not None:
        session["status"] = "exited"
        session["exit_code"] = process.returncode
    return {"session": _public_session(session), "data": data}


def resize_terminal_session(session_id: str, rows: int = 30, cols: int = 120) -> dict[str, Any]:
    """Resize a PTY terminal session."""

    session = _get_session(session_id)
    _set_winsize(int(session["fd"]), rows, cols)
    session["rows"] = rows
    session["cols"] = cols
    return _public_session(session)


def list_terminal_sessions() -> list[dict[str, Any]]:
    """List known PTY terminal sessions."""

    for session in TERMINAL_SESSIONS.values():
        process = session["process"]
        if session.get("status") == "running" and process.poll() is not None:
            session["status"] = "exited"
            session["exit_code"] = process.returncode
    return [_public_session(session) for session in TERMINAL_SESSIONS.values()]


def stop_terminal_session(session_id: str) -> bool:
    """Stop a PTY terminal session."""

    if session_id not in TERMINAL_SESSIONS:
        return False
    session = TERMINAL_SESSIONS[session_id]
    process = session["process"]
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        session["status"] = "missing"
    time.sleep(0.5)
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        os.close(int(session["fd"]))
    except OSError:
        pass
    session["status"] = "stopped"
    return True


def _get_session(session_id: str) -> dict[str, Any]:
    if session_id not in TERMINAL_SESSIONS:
        raise KeyError(f"unknown terminal session: {session_id}")
    session = TERMINAL_SESSIONS[session_id]
    if session.get("status") not in {"running", "exited"}:
        raise RuntimeError(f"terminal session is not active: {session.get('status')}")
    return session


def _public_session(session: dict[str, Any]) -> dict[str, Any]:
    public = {key: value for key, value in session.items() if key not in {"process", "fd"}}
    public["age_seconds"] = round(time.time() - float(public.get("started_at", time.time())), 3)
    return public
