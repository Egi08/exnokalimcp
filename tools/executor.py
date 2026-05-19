"""Async subprocess execution with streaming and process management."""

from __future__ import annotations

import asyncio
import os
import shlex
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, AsyncGenerator, Awaitable, Callable
from uuid import uuid4

SUDO_PASSWORD = ""
RUNNING_PROCESSES: dict[int, dict[str, Any]] = {}
BACKGROUND_JOBS: dict[str, dict[str, Any]] = {}


@dataclass
class CommandResult:
    """Completed command execution result."""

    command: str
    exit_code: int | None
    output: str
    timed_out: bool
    duration_seconds: float
    pid: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def configure_executor(config: dict[str, Any]) -> None:
    """Configure executor-wide settings from the MCP config."""

    global SUDO_PASSWORD
    SUDO_PASSWORD = str(config.get("security", {}).get("sudo_password", "") or "")


def _sudo_command(cmd: str) -> str:
    stripped = cmd.strip()
    if not SUDO_PASSWORD or not stripped.startswith("sudo "):
        return cmd
    rest = stripped[5:]
    password = shlex.quote(SUDO_PASSWORD + "\n")
    return f"printf %s {password} | sudo -S -p '' {rest}"


async def run_command(cmd: str, timeout: int = 3600, stream: bool = True) -> AsyncGenerator[str, None]:
    """
    Execute a shell command asynchronously and yield stdout/stderr lines.

    The final yielded line is a JSON-compatible status string in the form
    ``[exnokalimcp-exit] code=<exit_code> timed_out=<true|false>``.
    """

    command = _sudo_command(cmd)
    start = time.monotonic()
    process = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        stdin=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    RUNNING_PROCESSES[process.pid] = {
        "pid": process.pid,
        "command": cmd,
        "started_at": time.time(),
        "cwd": os.getcwd(),
    }
    timed_out = False
    deadline = start + timeout
    try:
        assert process.stdout is not None
        while True:
            remaining = max(0.001, deadline - time.monotonic())
            try:
                line = await asyncio.wait_for(process.stdout.readline(), timeout=remaining)
            except asyncio.TimeoutError:
                timed_out = True
                await _terminate_process(process)
                break
            if not line:
                break
            yield line.decode(errors="replace").rstrip("\n")
        if not timed_out:
            remaining = max(0.001, deadline - time.monotonic())
            try:
                await asyncio.wait_for(process.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                timed_out = True
                await _terminate_process(process)
    finally:
        RUNNING_PROCESSES.pop(process.pid, None)
    yield f"[exnokalimcp-exit] code={process.returncode} timed_out={str(timed_out).lower()}"


async def run_command_collect(
    cmd: str,
    timeout: int = 3600,
    stream: bool = True,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    on_line: Callable[[str], Awaitable[None]] | None = None,
) -> CommandResult:
    """Execute a shell command and return the complete result."""

    start = time.monotonic()
    command = _sudo_command(cmd)
    proc_env = os.environ.copy()
    if env:
        proc_env.update({str(k): str(v) for k, v in env.items()})

    process = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        stdin=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=proc_env,
        start_new_session=True,
    )
    RUNNING_PROCESSES[process.pid] = {
        "pid": process.pid,
        "command": cmd,
        "started_at": time.time(),
        "cwd": cwd or os.getcwd(),
    }
    output_parts: list[str] = []
    timed_out = False

    async def _read_output() -> None:
        assert process.stdout is not None
        while True:
            line = await process.stdout.readline()
            if not line:
                break
            text = line.decode(errors="replace")
            output_parts.append(text)
            if on_line is not None:
                await on_line(text.rstrip("\n"))

    reader = asyncio.create_task(_read_output())
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
        await reader
    except asyncio.TimeoutError:
        timed_out = True
        await _terminate_process(process)
        if not reader.done():
            reader.cancel()
            try:
                await reader
            except asyncio.CancelledError:
                pass
    finally:
        RUNNING_PROCESSES.pop(process.pid, None)

    duration = time.monotonic() - start
    return CommandResult(
        command=cmd,
        exit_code=process.returncode,
        output="".join(output_parts),
        timed_out=timed_out,
        duration_seconds=round(duration, 3),
        pid=process.pid,
    )


async def start_background_command(
    cmd: str,
    output_path: str,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Start a long-running command and persist output as it is produced."""

    command = _sudo_command(cmd)
    proc_env = os.environ.copy()
    if env:
        proc_env.update({str(k): str(v) for k, v in env.items()})

    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    process = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        stdin=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=proc_env,
        start_new_session=True,
    )
    job_id = uuid4().hex
    job = {
        "job_id": job_id,
        "pid": process.pid,
        "process": process,
        "stdin": process.stdin,
        "command": cmd,
        "output_path": str(path),
        "cwd": cwd or os.getcwd(),
        "started_at": time.time(),
        "status": "running",
        "exit_code": None,
        "lines": 0,
        "last_offset": 0,
    }
    BACKGROUND_JOBS[job_id] = job
    RUNNING_PROCESSES[process.pid] = {
        "pid": process.pid,
        "command": cmd,
        "started_at": job["started_at"],
        "cwd": job["cwd"],
        "job_id": job_id,
    }
    job["reader_task"] = asyncio.create_task(_background_reader(job_id, process, path))
    return _public_job(job)


async def _background_reader(job_id: str, process: asyncio.subprocess.Process, output_path: Path) -> None:
    job = BACKGROUND_JOBS[job_id]
    try:
        assert process.stdout is not None
        with output_path.open("a", encoding="utf-8", errors="replace") as handle:
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                text = line.decode(errors="replace")
                handle.write(text)
                handle.flush()
                job["lines"] = int(job.get("lines", 0)) + 1
        await process.wait()
        job["exit_code"] = process.returncode
        job["status"] = "completed"
        job["completed_at"] = time.time()
    except asyncio.CancelledError:
        job["status"] = "cancelled"
        raise
    except Exception as exc:
        job["status"] = "error"
        job["error"] = str(exc)
    finally:
        RUNNING_PROCESSES.pop(process.pid, None)


def list_background_jobs() -> list[dict[str, Any]]:
    """List known background jobs without internal task objects."""

    return [_public_job(job) for job in BACKGROUND_JOBS.values()]


def read_background_output(job_id: str, offset: int = 0, max_bytes: int = 65536) -> dict[str, Any]:
    """Read output from a background job starting at a byte offset."""

    if job_id not in BACKGROUND_JOBS:
        raise KeyError(f"unknown background job: {job_id}")
    job = BACKGROUND_JOBS[job_id]
    path = Path(str(job["output_path"]))
    if not path.exists():
        data = ""
        next_offset = offset
    else:
        with path.open("rb") as handle:
            handle.seek(max(0, offset))
            raw = handle.read(max(1, max_bytes))
            next_offset = handle.tell()
        data = raw.decode(errors="replace")
    job["last_offset"] = next_offset
    return {"job": _public_job(job), "offset": offset, "next_offset": next_offset, "data": data}


async def send_background_input(job_id: str, text: str, newline: bool = True) -> dict[str, Any]:
    """Send input to a running background job."""

    if job_id not in BACKGROUND_JOBS:
        raise KeyError(f"unknown background job: {job_id}")
    job = BACKGROUND_JOBS[job_id]
    if job.get("status") != "running":
        raise RuntimeError(f"background job is not running: {job.get('status')}")
    stdin = job.get("stdin")
    if stdin is None:
        raise RuntimeError("background job has no stdin pipe")
    payload = text + ("\n" if newline else "")
    stdin.write(payload.encode())
    await stdin.drain()
    return {"job": _public_job(job), "bytes_sent": len(payload.encode())}


async def stop_background_job(job_id: str) -> bool:
    """Terminate a background job by job id."""

    if job_id not in BACKGROUND_JOBS:
        return False
    job = BACKGROUND_JOBS[job_id]
    pid = int(job["pid"])
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        job["status"] = "missing"
        return False
    await asyncio.sleep(1)
    if job.get("status") == "running":
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        job["status"] = "killed"
    return True


def _public_job(job: dict[str, Any]) -> dict[str, Any]:
    public = {key: value for key, value in job.items() if key not in {"reader_task", "process", "stdin"}}
    public["age_seconds"] = round(time.time() - float(public.get("started_at", time.time())), 3)
    return public


async def run_interactive(cmd: str, inputs: list[str]) -> str:
    """
    Execute an interactive command and feed newline-terminated inputs.

    This is intended for legitimate tools that ask for confirmation prompts
    during authorized assessments.
    """

    process = await asyncio.create_subprocess_shell(
        _sudo_command(cmd),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        stdin=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    RUNNING_PROCESSES[process.pid] = {
        "pid": process.pid,
        "command": cmd,
        "started_at": time.time(),
        "cwd": os.getcwd(),
    }
    assert process.stdin is not None
    for item in inputs:
        process.stdin.write((item + "\n").encode())
        await process.stdin.drain()
    process.stdin.close()

    assert process.stdout is not None
    output = await process.stdout.read()
    await process.wait()
    RUNNING_PROCESSES.pop(process.pid, None)
    return output.decode(errors="replace")


async def kill_process(pid: int) -> bool:
    """Kill a running MCP-spawned process."""

    if pid not in RUNNING_PROCESSES:
        return False
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        RUNNING_PROCESSES.pop(pid, None)
        return False
    await asyncio.sleep(1)
    if pid in RUNNING_PROCESSES:
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        RUNNING_PROCESSES.pop(pid, None)
    return True


def get_running_processes() -> list[dict[str, Any]]:
    """List all MCP-spawned processes known to the executor."""

    now = time.time()
    processes: list[dict[str, Any]] = []
    for item in RUNNING_PROCESSES.values():
        copy = dict(item)
        copy["age_seconds"] = round(now - float(copy.get("started_at", now)), 3)
        processes.append(copy)
    return processes


async def _terminate_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    if os.name == "nt":
        try:
            killer = await asyncio.create_subprocess_exec(
                "taskkill",
                "/PID",
                str(process.pid),
                "/T",
                "/F",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            await asyncio.wait_for(killer.wait(), timeout=5)
        except (FileNotFoundError, ProcessLookupError, asyncio.TimeoutError):
            try:
                process.terminate()
            except ProcessLookupError:
                return
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            try:
                process.kill()
            except ProcessLookupError:
                return
            await process.wait()
        return

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (AttributeError, ProcessLookupError):
        try:
            process.terminate()
        except ProcessLookupError:
            return
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
        return
    except asyncio.TimeoutError:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except AttributeError:
        try:
            process.kill()
        except ProcessLookupError:
            return
    except ProcessLookupError:
        return
    await process.wait()
