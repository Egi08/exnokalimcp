"""Raw shell, file, workspace, and reporting MCP tools."""

from __future__ import annotations

import html
import base64
import difflib
import hashlib
import json
import os
import platform
import re
import shutil
import zipfile
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Context

from tools import DISCLAIMER, join_flags, option_string, quote
from tools.executor import (
    get_running_processes,
    kill_process,
    list_background_jobs,
    read_background_output,
    run_interactive,
    send_background_input,
    stop_background_job,
)
from tools.terminal_sessions import (
    list_terminal_sessions,
    read_terminal_output,
    resize_terminal_session,
    send_terminal_input,
    start_terminal_session,
    stop_terminal_session,
)


def _expand(path: str) -> Path:
    return Path(path).expanduser().resolve()


def _redacted_server_config(config: dict[str, Any]) -> dict[str, Any]:
    server = dict(config.get("server", {}))
    if isinstance(server.get("auth"), dict):
        auth = dict(server["auth"])
        keys = auth.get("api_keys")
        if isinstance(keys, list):
            auth["api_keys"] = ["***REDACTED***"] * len(keys)
        elif keys:
            auth["api_keys"] = "***REDACTED***"
        server["auth"] = auth
    return server


def _is_hidden(path: Path) -> bool:
    return any(part.startswith(".") for part in path.parts if part not in {".", ".."})


def _refuse_dangerous_delete(path: Path) -> None:
    dangerous = {
        Path("/"),
        Path.home(),
        Path("/bin"),
        Path("/boot"),
        Path("/dev"),
        Path("/etc"),
        Path("/home"),
        Path("/lib"),
        Path("/lib64"),
        Path("/proc"),
        Path("/root"),
        Path("/sbin"),
        Path("/sys"),
        Path("/usr"),
        Path("/var"),
    }
    if path in dangerous:
        raise PermissionError(f"refusing to delete high-risk path: {path}")


def _backup_file(path: Path, backup_dir: Path | None = None) -> Path:
    stamp = __import__("datetime").datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    if backup_dir:
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / f"{path.name}.{stamp}.bak"
    else:
        backup = path.with_name(f"{path.name}.{stamp}.bak")
    shutil.copy2(path, backup)
    return backup


def _apply_unified_diff(original: str, diff_text: str) -> str:
    original_lines = original.splitlines(keepends=True)
    diff_lines = diff_text.splitlines(keepends=True)
    output: list[str] = []
    source_index = 0
    hunk_re = re.compile(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
    index = 0
    while index < len(diff_lines):
        line = diff_lines[index]
        if line.startswith("--- ") or line.startswith("+++ "):
            index += 1
            continue
        match = hunk_re.match(line)
        if not match:
            index += 1
            continue
        start = int(match.group(1)) - 1
        output.extend(original_lines[source_index:start])
        source_index = start
        index += 1
        while index < len(diff_lines) and not diff_lines[index].startswith("@@ "):
            hunk_line = diff_lines[index]
            if hunk_line.startswith("\\ No newline"):
                index += 1
                continue
            if not hunk_line:
                index += 1
                continue
            marker = hunk_line[0]
            content = hunk_line[1:]
            if marker == " ":
                if source_index >= len(original_lines) or original_lines[source_index] != content:
                    raise ValueError("patch context does not match target file")
                output.append(original_lines[source_index])
                source_index += 1
            elif marker == "-":
                if source_index >= len(original_lines) or original_lines[source_index] != content:
                    raise ValueError("patch deletion does not match target file")
                source_index += 1
            elif marker == "+":
                output.append(content)
            index += 1
    output.extend(original_lines[source_index:])
    return "".join(output)


def _windows_to_wsl(path: str) -> str:
    normalized = path.replace("\\", "/")
    if len(normalized) >= 2 and normalized[1] == ":":
        drive = normalized[0].lower()
        rest = normalized[2:].lstrip("/")
        return f"/mnt/{drive}/{rest}"
    return normalized


def _wsl_to_windows(path: str) -> str:
    if path.startswith("/mnt/") and len(path) >= 7 and path[6] == "/":
        drive = path[5].upper()
        rest = path[7:].replace("/", "\\")
        return f"{drive}:\\{rest}"
    return path


def _png_dimensions(path: Path) -> dict[str, int]:
    """Read PNG width and height without adding an image dependency."""

    try:
        with path.open("rb") as handle:
            header = handle.read(24)
        if len(header) >= 24 and header[:8] == b"\x89PNG\r\n\x1a\n":
            return {
                "width": int.from_bytes(header[16:20], "big"),
                "height": int.from_bytes(header[20:24], "big"),
            }
    except OSError:
        pass
    return {"width": 0, "height": 0}


def _powershell_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _wsl_windows_path(path: Path) -> str:
    raw = str(path).replace("\\", "/")
    drive_match = re.match(r"^/mnt/([a-zA-Z])(?:/(.*))?$", raw)
    if drive_match:
        drive = drive_match.group(1).upper()
        rest = (drive_match.group(2) or "").replace("/", "\\")
        return f"{drive}:\\{rest}" if rest else f"{drive}:\\"
    distro = os.environ.get("WSL_DISTRO_NAME", "kali-linux")
    return "\\\\wsl.localhost\\" + distro + raw.replace("/", "\\")


def _powershell_screenshot_script(output_path: str, active_window: bool, delay_ms: int) -> str:
    """Return a PowerShell screen capture script for WSL interop."""

    active_literal = "$true" if active_window else "$false"
    script = r'''
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$out = __OUTPUT_PATH__
$delayMs = __DELAY_MS__
if ($delayMs -gt 0) { Start-Sleep -Milliseconds $delayMs }
$active = __ACTIVE_WINDOW__

function Use-VirtualScreen {
  $bounds = [System.Windows.Forms.SystemInformation]::VirtualScreen
  return @($bounds.X, $bounds.Y, $bounds.Width, $bounds.Height)
}

try {
  $coords = $null
  if ($active) {
    $code = @"
using System;
using System.Runtime.InteropServices;
public struct EXNORECT { public int Left; public int Top; public int Right; public int Bottom; }
public class EXNOWIN32 {
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out EXNORECT rect);
}
"@
    Add-Type $code -ErrorAction SilentlyContinue | Out-Null
    $rect = New-Object EXNORECT
    $hwnd = [EXNOWIN32]::GetForegroundWindow()
    [EXNOWIN32]::GetWindowRect($hwnd, [ref]$rect) | Out-Null
    $w = $rect.Right - $rect.Left
    $h = $rect.Bottom - $rect.Top
    if ($w -gt 0 -and $h -gt 0) {
      $coords = @($rect.Left, $rect.Top, $w, $h)
    }
  }
  if ($null -eq $coords) { $coords = Use-VirtualScreen }

  $x = [int]$coords[0]
  $y = [int]$coords[1]
  $w = [int]$coords[2]
  $h = [int]$coords[3]
  $dir = [System.IO.Path]::GetDirectoryName($out)
  if ($dir) { [System.IO.Directory]::CreateDirectory($dir) | Out-Null }
  $bitmap = New-Object System.Drawing.Bitmap $w, $h
  $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
  $graphics.CopyFromScreen($x, $y, 0, 0, $bitmap.Size)
  $bitmap.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
  $graphics.Dispose()
  $bitmap.Dispose()
  (@{ok=$true; backend="windows"; output=$out; width=$w; height=$h; active_window=$active} | ConvertTo-Json -Compress)
  exit 0
} catch {
  (@{ok=$false; backend="windows"; output=$out; error=$_.Exception.Message} | ConvertTo-Json -Compress)
  exit 1
}
'''
    return (
        script.replace("__OUTPUT_PATH__", _powershell_string(output_path))
        .replace("__DELAY_MS__", str(delay_ms))
        .replace("__ACTIVE_WINDOW__", active_literal)
    )


def _linux_screenshot_shell() -> str:
    """Return a POSIX shell fragment that tries common Linux screenshot tools."""

    return """
if command -v grim >/dev/null 2>&1; then
  grim "$OUT"
elif command -v gnome-screenshot >/dev/null 2>&1; then
  gnome-screenshot -f "$OUT"
elif command -v spectacle >/dev/null 2>&1; then
  spectacle -b -n -o "$OUT"
elif command -v scrot >/dev/null 2>&1; then
  scrot "$OUT"
elif command -v maim >/dev/null 2>&1; then
  maim "$OUT"
elif command -v import >/dev/null 2>&1; then
  import -window root "$OUT"
else
  echo "No Linux screenshot tool found. Try mode=windows on WSL, or install grim/gnome-screenshot/scrot/maim." >&2
  false
fi
"""


def _desktop_screenshot_command(output_path: Path, mode: str, active_window: bool, delay_seconds: float) -> str:
    """Build the shell command used by screenshot_desktop."""

    delay_ms = max(0, int(float(delay_seconds) * 1000))
    linux_capture = _linux_screenshot_shell()
    output = quote(output_path)
    output_win = _wsl_windows_path(output_path)
    encoded_ps = base64.b64encode(
        _powershell_screenshot_script(output_win, active_window, delay_ms).encode("utf-16le")
    ).decode("ascii")
    windows_capture = (
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {quote(encoded_ps)}"
    )
    if mode == "linux":
        return f"OUT={output}; export OUT; {linux_capture}"
    if mode == "windows":
        return f"OUT={output}; export OUT; {windows_capture}"
    return (
        f"OUT={output}; export OUT; "
        'if [ -n "${WAYLAND_DISPLAY:-}${DISPLAY:-}" ]; then '
        f"( {linux_capture} ) || true; "
        "fi; "
        'if [ -s "$OUT" ]; then printf \'{"ok":true,"backend":"linux","output":"%s"}\\n\' "$OUT"; '
        "elif command -v powershell.exe >/dev/null 2>&1; then "
        f"{windows_capture}; "
        "else echo 'No screenshot backend available. WSL interop or a Linux GUI screenshot tool is required.' >&2; exit 127; fi"
    )


def register(mcp: Any, services: Any) -> None:
    """Register shell and system management tools."""

    @mcp.tool()
    async def shell_exec(
        command: str,
        cwd: str = "",
        env: dict[str, str] | None = None,
        timeout: int = 3600,
        workspace: str = "default",
        confirm_authorized: bool = False,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Execute an arbitrary shell command after explicit authorization confirmation."""

        return await services.run_command_tool(
            "shell_exec",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
            cwd=cwd or None,
            env=env,
            check_binary=False,
            ctx=ctx,
        )

    @mcp.tool()
    async def shell_script(
        script_content: str,
        interpreter: str = "bash",
        workspace: str = "default",
        timeout: int = 3600,
        confirm_authorized: bool = False,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Write and execute a script after explicit authorization confirmation."""

        suffix = ".py" if "python" in interpreter else ".sh"
        script_file = services.write_input_file(workspace, "shell_script", script_content, suffix)
        if "bash" in interpreter or "sh" in interpreter:
            os.chmod(script_file, 0o700)
        command = join_flags([quote(interpreter), quote(script_file)])
        return await services.run_command_tool(
            "shell_script",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
            ctx=ctx,
        )

    @mcp.tool()
    async def shell_interactive(
        command: str,
        inputs: list[str],
        workspace: str = "default",
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Execute an interactive command and feed prompt responses after confirmation."""

        services.ensure_allowed("shell_interactive", locals(), confirm_authorized=confirm_authorized)
        output = await run_interactive(command, inputs)
        output_path = services.sessions.output_path(workspace, "shell_interactive")
        output_path.write_text(output, encoding="utf-8", errors="replace")
        result_id = services.store.add_result(
            workspace,
            "shell_interactive",
            None,
            command,
            0,
            str(output_path),
            {"line_count": len(output.splitlines())},
            {"inputs_count": len(inputs)},
        )
        return {
            "ok": True,
            "result_id": result_id,
            "workspace": workspace,
            "output_path": str(output_path),
            "output_preview": output[: int(services.config.get("security", {}).get("max_output_chars", 20000))],
        }

    @mcp.tool()
    async def terminal_start(
        command: str = "bash",
        cwd: str = "",
        env: dict[str, str] | None = None,
        rows: int = 30,
        cols: int = 120,
        workspace: str = "default",
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Start a persistent Kali PTY terminal session."""

        services.ensure_allowed("terminal_start", locals(), confirm_authorized=confirm_authorized)
        services.ensure_command_policy("terminal_start", command, confirm_authorized=confirm_authorized)
        transcript = services.sessions.output_path(workspace, "terminal_session", ".log")
        session = start_terminal_session(
            command=command,
            cwd=cwd or None,
            env=env,
            rows=rows,
            cols=cols,
            transcript_path=str(transcript),
        )
        services.audit_log("terminal_start", locals(), status="started", message=f"session_id={session['session_id']}")
        return {"ok": True, "session": session, "transcript_path": str(transcript)}

    @mcp.tool()
    async def terminal_send(
        session_id: str,
        text: str,
        newline: bool = False,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Send input to a persistent Kali PTY terminal session."""

        services.ensure_allowed("terminal_send", locals(), confirm_authorized=confirm_authorized)
        return {"ok": True, **send_terminal_input(session_id, text, newline=newline)}

    @mcp.tool()
    async def terminal_read(session_id: str, max_bytes: int = 65536) -> dict[str, Any]:
        """Read available output from a persistent Kali PTY terminal session."""

        services.ensure_allowed("terminal_read", locals())
        return {"ok": True, **read_terminal_output(session_id, max_bytes=max_bytes)}

    @mcp.tool()
    async def terminal_resize(session_id: str, rows: int = 30, cols: int = 120) -> dict[str, Any]:
        """Resize a persistent Kali PTY terminal session."""

        services.ensure_allowed("terminal_resize", locals())
        return {"ok": True, "session": resize_terminal_session(session_id, rows=rows, cols=cols)}

    @mcp.tool()
    async def terminal_list() -> dict[str, Any]:
        """List persistent Kali PTY terminal sessions."""

        services.ensure_allowed("terminal_list", locals())
        return {"ok": True, "sessions": list_terminal_sessions()}

    @mcp.tool()
    async def terminal_stop(session_id: str, confirm_authorized: bool = False) -> dict[str, Any]:
        """Stop a persistent Kali PTY terminal session."""

        services.ensure_allowed("terminal_stop", locals(), confirm_authorized=confirm_authorized)
        return {"ok": stop_terminal_session(session_id), "session_id": session_id}

    @mcp.tool()
    async def file_read(path: str, max_lines: int = 200) -> dict[str, Any]:
        """Read a bounded number of lines from a local file."""

        services.ensure_allowed("file_read", locals())
        file_path = _expand(path)
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        selected = lines[: max(1, int(max_lines))]
        return {"ok": True, "path": str(file_path), "line_count": len(lines), "content": "\n".join(selected)}

    @mcp.tool()
    async def file_diff(
        path: str,
        new_content: str,
        from_label: str = "current",
        to_label: str = "proposed",
    ) -> dict[str, Any]:
        """Generate a unified diff between a file and proposed content."""

        services.ensure_allowed("file_diff", locals())
        file_path = _expand(path)
        old_lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        new_lines = new_content.splitlines(keepends=True)
        diff = "".join(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=f"{from_label}:{file_path}",
                tofile=f"{to_label}:{file_path}",
            )
        )
        return {"ok": True, "path": str(file_path), "diff": diff, "changed": bool(diff)}

    @mcp.tool()
    async def file_backup(
        path: str,
        workspace: str = "default",
    ) -> dict[str, Any]:
        """Create a timestamped backup copy of a file in the workspace."""

        services.ensure_allowed("file_backup", locals())
        file_path = _expand(path)
        backup_dir = services.sessions.workspace_path(workspace) / "backups"
        services.ensure_path_policy("file_backup", backup_dir, write=True)
        backup = _backup_file(file_path, backup_dir)
        return {"ok": True, "path": str(file_path), "backup_path": str(backup)}

    @mcp.tool()
    async def file_patch(
        path: str,
        unified_diff: str,
        backup: bool = True,
        workspace: str = "default",
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Apply a unified diff patch to a file, optionally creating a backup first."""

        services.ensure_allowed("file_patch", locals(), confirm_authorized=confirm_authorized)
        file_path = _expand(path)
        services.ensure_path_policy("file_patch", file_path, write=True)
        original = file_path.read_text(encoding="utf-8", errors="replace")
        backup_path = ""
        if backup:
            backup_path = str(_backup_file(file_path, services.sessions.workspace_path(workspace) / "backups"))
        patched = _apply_unified_diff(original, unified_diff)
        file_path.write_text(patched, encoding="utf-8")
        return {
            "ok": True,
            "path": str(file_path),
            "backup_path": backup_path,
            "old_bytes": len(original.encode()),
            "new_bytes": len(patched.encode()),
        }

    @mcp.tool()
    async def file_restore(
        backup_path: str,
        destination: str,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Restore a file from a backup after confirmation."""

        services.ensure_allowed("file_restore", locals(), confirm_authorized=confirm_authorized)
        src = _expand(backup_path)
        dst = _expand(destination)
        services.ensure_path_policy("file_restore", dst, write=True)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return {"ok": True, "backup_path": str(src), "destination": str(dst)}

    @mcp.tool()
    async def file_download_chunk(
        path: str,
        offset: int = 0,
        max_bytes: int = 65536,
        encoding: str = "base64",
    ) -> dict[str, Any]:
        """Read a binary-safe file chunk from Kali Linux."""

        services.ensure_allowed("file_download_chunk", locals())
        file_path = _expand(path)
        size = file_path.stat().st_size
        with file_path.open("rb") as handle:
            handle.seek(max(0, int(offset)))
            data = handle.read(max(1, int(max_bytes)))
            next_offset = handle.tell()
        if encoding == "base64":
            payload = base64.b64encode(data).decode()
        elif encoding == "text":
            payload = data.decode(errors="replace")
        else:
            raise ValueError("encoding must be base64 or text")
        return {
            "ok": True,
            "path": str(file_path),
            "offset": offset,
            "next_offset": next_offset,
            "size": size,
            "eof": next_offset >= size,
            "encoding": encoding,
            "data": payload,
        }

    @mcp.tool()
    async def file_upload_chunk(
        path: str,
        data: str,
        offset: int = 0,
        encoding: str = "base64",
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Write a binary-safe file chunk to Kali Linux."""

        services.ensure_allowed("file_upload_chunk", locals(), confirm_authorized=confirm_authorized)
        file_path = _expand(path)
        services.ensure_path_policy("file_upload_chunk", file_path, write=True)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        if encoding == "base64":
            raw = base64.b64decode(data)
        elif encoding == "text":
            raw = data.encode()
        else:
            raise ValueError("encoding must be base64 or text")
        with file_path.open("r+b" if file_path.exists() else "wb") as handle:
            handle.seek(max(0, int(offset)))
            handle.write(raw)
        return {"ok": True, "path": str(file_path), "offset": offset, "bytes_written": len(raw)}

    @mcp.tool()
    async def file_checksum(
        path: str,
        algorithm: str = "sha256",
        chunk_size: int = 1048576,
    ) -> dict[str, Any]:
        """Calculate a checksum for a Kali Linux file."""

        services.ensure_allowed("file_checksum", locals())
        if algorithm not in hashlib.algorithms_available:
            raise ValueError(f"unsupported hash algorithm: {algorithm}")
        digest = hashlib.new(algorithm)
        file_path = _expand(path)
        total = 0
        with file_path.open("rb") as handle:
            while True:
                chunk = handle.read(max(1, int(chunk_size)))
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
        return {"ok": True, "path": str(file_path), "algorithm": algorithm, "hexdigest": digest.hexdigest(), "bytes": total}

    @mcp.tool()
    async def file_tail(path: str, lines: int = 100) -> dict[str, Any]:
        """Read the last lines from a local file."""

        services.ensure_allowed("file_tail", locals())
        file_path = _expand(path)
        content = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        selected = content[-max(1, int(lines)) :]
        return {"ok": True, "path": str(file_path), "line_count": len(content), "content": "\n".join(selected)}

    @mcp.tool()
    async def file_stat(path: str) -> dict[str, Any]:
        """Return metadata for a local file or directory."""

        services.ensure_allowed("file_stat", locals())
        file_path = _expand(path)
        stat = file_path.stat()
        return {
            "ok": True,
            "path": str(file_path),
            "exists": file_path.exists(),
            "is_file": file_path.is_file(),
            "is_dir": file_path.is_dir(),
            "size": stat.st_size,
            "mode": oct(stat.st_mode & 0o7777),
            "mtime": stat.st_mtime,
            "ctime": stat.st_ctime,
        }

    @mcp.tool()
    async def file_list(
        path: str = ".",
        recursive: bool = False,
        include_hidden: bool = True,
        limit: int = 500,
    ) -> dict[str, Any]:
        """List files and directories from Kali Linux filesystem."""

        services.ensure_allowed("file_list", locals())
        base = _expand(path)
        iterator = base.rglob("*") if recursive else base.iterdir()
        items = []
        for item in iterator:
            if not include_hidden and _is_hidden(item.relative_to(base) if item != base else item):
                continue
            try:
                stat = item.stat()
                items.append(
                    {
                        "path": str(item),
                        "name": item.name,
                        "is_file": item.is_file(),
                        "is_dir": item.is_dir(),
                        "size": stat.st_size,
                        "mode": oct(stat.st_mode & 0o7777),
                        "mtime": stat.st_mtime,
                    }
                )
            except OSError as exc:
                items.append({"path": str(item), "error": str(exc)})
            if len(items) >= max(1, int(limit)):
                break
        return {"ok": True, "path": str(base), "recursive": recursive, "count": len(items), "items": items}

    @mcp.tool()
    async def file_tree(
        path: str = ".",
        max_depth: int = 3,
        include_hidden: bool = False,
        limit: int = 500,
    ) -> dict[str, Any]:
        """Return a compact directory tree for a Kali Linux path."""

        services.ensure_allowed("file_tree", locals())
        base = _expand(path)
        max_depth = max(0, int(max_depth))
        rows = []
        for item in base.rglob("*"):
            rel = item.relative_to(base)
            if len(rel.parts) > max_depth:
                continue
            if not include_hidden and _is_hidden(rel):
                continue
            rows.append(
                {
                    "path": str(item),
                    "relative": str(rel),
                    "depth": len(rel.parts),
                    "type": "dir" if item.is_dir() else "file",
                }
            )
            if len(rows) >= max(1, int(limit)):
                break
        return {"ok": True, "path": str(base), "max_depth": max_depth, "count": len(rows), "tree": rows}

    @mcp.tool()
    async def file_write(
        path: str,
        content: str,
        append: bool = False,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Write content to a local file after confirmation."""

        services.ensure_allowed("file_write", locals(), confirm_authorized=confirm_authorized)
        file_path = _expand(path)
        services.ensure_path_policy("file_write", file_path, write=True)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        with file_path.open(mode, encoding="utf-8") as handle:
            handle.write(content)
        return {"ok": True, "path": str(file_path), "bytes": len(content.encode("utf-8"))}

    @mcp.tool()
    async def file_mkdir(
        path: str,
        parents: bool = True,
        exist_ok: bool = True,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Create a directory on Kali Linux after confirmation."""

        services.ensure_allowed("file_mkdir", locals(), confirm_authorized=confirm_authorized)
        directory = _expand(path)
        services.ensure_path_policy("file_mkdir", directory, write=True)
        directory.mkdir(parents=parents, exist_ok=exist_ok)
        return {"ok": True, "path": str(directory), "is_dir": directory.is_dir()}

    @mcp.tool()
    async def file_copy(
        source: str,
        destination: str,
        overwrite: bool = False,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Copy a file or directory on Kali Linux after confirmation."""

        services.ensure_allowed("file_copy", locals(), confirm_authorized=confirm_authorized)
        src = _expand(source)
        dst = _expand(destination)
        services.ensure_path_policy("file_copy", dst, write=True)
        if dst.exists() and not overwrite:
            raise FileExistsError(f"destination exists: {dst}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            if dst.exists() and overwrite:
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
        return {"ok": True, "source": str(src), "destination": str(dst)}

    @mcp.tool()
    async def file_move(
        source: str,
        destination: str,
        overwrite: bool = False,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Move or rename a file or directory on Kali Linux after confirmation."""

        services.ensure_allowed("file_move", locals(), confirm_authorized=confirm_authorized)
        src = _expand(source)
        dst = _expand(destination)
        services.ensure_path_policy("file_move", src, write=True)
        services.ensure_path_policy("file_move", dst, write=True)
        if dst.exists():
            if not overwrite:
                raise FileExistsError(f"destination exists: {dst}")
            if dst.is_dir():
                shutil.rmtree(dst)
            else:
                dst.unlink()
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return {"ok": True, "source": str(src), "destination": str(dst)}

    @mcp.tool()
    async def file_delete(
        path: str,
        recursive: bool = False,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Delete a file or directory on Kali Linux after confirmation."""

        services.ensure_allowed("file_delete", locals(), confirm_authorized=confirm_authorized)
        target = _expand(path)
        services.ensure_path_policy("file_delete", target, write=True)
        _refuse_dangerous_delete(target)
        if target.is_dir():
            if not recursive:
                raise IsADirectoryError(f"{target} is a directory; set recursive=True")
            shutil.rmtree(target)
        else:
            target.unlink()
        return {"ok": True, "deleted": str(target)}

    @mcp.tool()
    async def file_replace(
        path: str,
        old: str,
        new: str,
        count: int = 0,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Replace text inside a local file after confirmation."""

        services.ensure_allowed("file_replace", locals(), confirm_authorized=confirm_authorized)
        file_path = _expand(path)
        services.ensure_path_policy("file_replace", file_path, write=True)
        text = file_path.read_text(encoding="utf-8", errors="replace")
        occurrences = text.count(old)
        if occurrences == 0:
            return {"ok": True, "path": str(file_path), "replacements": 0}
        replaced = text.replace(old, new, count if count > 0 else -1)
        file_path.write_text(replaced, encoding="utf-8")
        applied = occurrences if count <= 0 else min(count, occurrences)
        return {"ok": True, "path": str(file_path), "replacements": applied}

    @mcp.tool()
    async def file_chmod(
        path: str,
        mode: str,
        recursive: bool = False,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Change file permissions on Kali Linux after confirmation."""

        services.ensure_allowed("file_chmod", locals(), confirm_authorized=confirm_authorized)
        target = _expand(path)
        services.ensure_path_policy("file_chmod", target, write=True)
        parsed_mode = int(mode, 8)
        changed = []
        if recursive and target.is_dir():
            for item in [target, *target.rglob("*")]:
                os.chmod(item, parsed_mode)
                changed.append(str(item))
        else:
            os.chmod(target, parsed_mode)
            changed.append(str(target))
        return {"ok": True, "mode": oct(parsed_mode), "changed_count": len(changed), "changed": changed[:500]}

    @mcp.tool()
    async def file_search(
        pattern: str,
        directory: str = ".",
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Find local files matching a glob pattern."""

        services.ensure_allowed("file_search", locals())
        options = options or {}
        base = _expand(directory)
        limit = int(options.get("limit", 500))
        matches = []
        for path in base.rglob(pattern):
            matches.append(str(path))
            if len(matches) >= limit:
                break
        return {"ok": True, "directory": str(base), "pattern": pattern, "count": len(matches), "matches": matches}

    @mcp.tool()
    async def wsl_path_convert(path: str, direction: str = "auto") -> dict[str, Any]:
        """Convert paths between Windows and WSL/Kali formats."""

        services.ensure_allowed("wsl_path_convert", locals())
        direction = direction.lower()
        if direction == "windows_to_wsl":
            converted = _windows_to_wsl(path)
        elif direction == "wsl_to_windows":
            converted = _wsl_to_windows(path)
        elif direction == "auto":
            converted = _wsl_to_windows(path) if path.startswith("/mnt/") else _windows_to_wsl(path)
        else:
            raise ValueError("direction must be auto, windows_to_wsl, or wsl_to_windows")
        return {"ok": True, "input": path, "direction": direction, "converted": converted}

    @mcp.tool()
    async def resolve_tool(
        tool_name: str,
        install_if_missing: bool = False,
        method: str = "auto",
        workspace: str = "default",
        timeout: int = 7200,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Resolve a Kali tool from WSL PATH and optionally install it on demand."""

        services.ensure_allowed("resolve_tool", locals(), confirm_authorized=confirm_authorized)
        info = services.tool_resolver.check(tool_name)
        if info["installed"] or not install_if_missing:
            return {"ok": True, "tool": info, "installed": info["installed"], "installed_now": False}
        if not confirm_authorized:
            raise PermissionError("install_if_missing requires confirm_authorized=True")
        plan = services.tool_resolver.install_plan(tool_name, method)
        command = plan.get("command", "")
        if not command:
            return {
                "ok": False,
                "status": "no_install_command",
                "tool": info,
                "install_plan": plan,
                "resolver": services.tool_resolver.resolve(tool_name),
            }
        result = await services.run_command_tool(
            "install_tool",
            str(command),
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
            check_binary=False,
        )
        result["tool"] = services.tool_resolver.check(tool_name)
        result["installed_now"] = result["tool"]["installed"]
        result["install_plan"] = plan
        return result

    @mcp.tool()
    async def tool_inventory(category: str = "", only_missing: bool = False) -> dict[str, Any]:
        """List known Kali tools with installed/missing status and install guidance."""

        services.ensure_allowed("tool_inventory", locals())
        return {
            "ok": True,
            "category": category or "all",
            "only_missing": only_missing,
            "tools": services.tool_resolver.inventory(category=category, only_missing=only_missing),
        }

    @mcp.tool()
    async def suggest_tool_for_task(task: str, target_type: str = "") -> dict[str, Any]:
        """Suggest Kali tools for a task and show whether each one exists in WSL."""

        services.ensure_allowed("suggest_tool_for_task", locals())
        return {"ok": True, **services.tool_resolver.suggest(task, target_type=target_type)}

    @mcp.tool()
    async def install_tool(
        tool_name: str,
        method: str = "auto",
        workspace: str = "default",
        timeout: int = 7200,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Install a missing Kali tool using resolver metadata after confirmation."""

        method = method.lower()
        if method not in {"auto", "apt", "pipx", "pip", "go"}:
            raise ValueError("method must be auto, apt, pipx, pip, or go")
        plan = services.tool_resolver.install_plan(tool_name, method)
        command = plan.get("command", "")
        if not command:
            return {
                "ok": False,
                "status": "no_install_command",
                "install_plan": plan,
                "resolver": services.tool_resolver.resolve(tool_name),
            }
        result = await services.run_command_tool(
            "install_tool",
            str(command),
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
            check_binary=False,
        )
        result["tool"] = services.tool_resolver.check(tool_name)
        result["resolver"] = services.tool_resolver.resolve(tool_name)
        result["install_plan"] = plan
        return result

    @mcp.tool()
    async def update_tools(
        tool_list: list[str] | None = None,
        workspace: str = "default",
        timeout: int = 7200,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Update specified apt tools or all apt packages after confirmation."""

        if tool_list:
            command = "sudo apt-get update && sudo apt-get install --only-upgrade -y " + " ".join(
                quote(tool) for tool in tool_list
            )
        else:
            command = "sudo apt-get update && sudo apt-get upgrade -y"
        return await services.run_command_tool(
            "update_tools",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
            check_binary=False,
        )

    @mcp.tool()
    async def check_tool_installed(tool_name: str) -> dict[str, Any]:
        """Verify whether a tool is installed and capture a best-effort version string."""

        services.ensure_allowed("check_tool_installed", locals())
        return services.check_tool(tool_name)

    @mcp.tool()
    async def doctor_check() -> dict[str, Any]:
        """Run ExnoKaliMCP runtime, Kali tool, WSL, and path diagnostics."""

        services.ensure_allowed("doctor_check", locals())
        runtime_tools = ["python3", "git", "curl"]
        commonly_used_tools = ["nmap", "ffuf", "nuclei", "sqlmap", "subfinder", "httpx", "dnsx", "go", "pipx"]
        paths = {
            "workspace_dir": services.sessions.workspace_dir,
            "scope_file": services.sessions.scope_file,
            "results_db": services.store.db_path,
            "audit_file": services.audit_file,
            "wordlists_dir": Path(services.config.get("paths", {}).get("wordlists_dir", "/usr/share/wordlists")).expanduser(),
            "nuclei_templates": Path(
                services.config.get("tools", {}).get("nuclei", {}).get("templates_dir", "~/nuclei-templates")
            ).expanduser(),
        }
        checks = {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "is_wsl": "microsoft" in platform.release().lower() or bool(os.environ.get("WSL_DISTRO_NAME")),
            "runtime_tools": {tool: services.check_tool(tool) for tool in runtime_tools},
            "optional_tools": {tool: services.check_tool(tool) for tool in commonly_used_tools},
            "tool_resolver": services.config.get("tool_resolver", {}),
            "paths": {
                name: {
                    "path": str(path),
                    "exists": path.exists(),
                    "is_dir": path.is_dir(),
                    "writable": os.access(path if path.is_dir() else path.parent, os.W_OK),
                }
                for name, path in paths.items()
            },
            "scope_rules": services.sessions.list_scope(),
        }
        issues = []
        for tool, info in checks["runtime_tools"].items():
            if not info["installed"]:
                issues.append(f"missing runtime tool: {tool}")
        for name, info in checks["paths"].items():
            if name in {"workspace_dir", "scope_file", "results_db", "audit_file"} and not info["writable"]:
                issues.append(f"path is not writable: {name}")
        optional_missing = [tool for tool, info in checks["optional_tools"].items() if not info["installed"]]
        return {"ok": not issues, "issues": issues, "optional_missing": optional_missing, "checks": checks}

    @mcp.tool()
    async def doctor_fix(
        action: str = "create_dirs",
        confirm_authorized: bool = False,
        workspace: str = "default",
        timeout: int = 7200,
    ) -> dict[str, Any]:
        """Apply a limited doctor fix such as creating dirs or updating nuclei templates."""

        services.ensure_allowed("doctor_fix", locals(), confirm_authorized=confirm_authorized)
        action = action.lower()
        if action == "create_dirs":
            services.sessions.workspace_dir.mkdir(parents=True, exist_ok=True)
            services.sessions.scope_file.parent.mkdir(parents=True, exist_ok=True)
            services.sessions.scope_file.touch(exist_ok=True)
            services.audit_file.parent.mkdir(parents=True, exist_ok=True)
            return {"ok": True, "action": action}
        if action == "install_minimal":
            command = "sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip git curl wget jq unzip"
        elif action == "update_nuclei_templates":
            command = "nuclei -update-templates"
        else:
            raise ValueError("action must be create_dirs, install_minimal, or update_nuclei_templates")
        return await services.run_command_tool(
            "doctor_fix",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=True,
            check_binary=False,
        )

    @mcp.tool()
    async def command_history(workspace: str = "", limit: int = 50) -> dict[str, Any]:
        """Return recent command-backed results for replay or audit."""

        services.ensure_allowed("command_history", locals())
        results = services.store.list_results(workspace or None, None, limit)
        commands = [
            {
                "result_id": item.get("id"),
                "timestamp": item.get("timestamp"),
                "workspace": item.get("workspace"),
                "tool": item.get("tool"),
                "target": item.get("target"),
                "command": item.get("command"),
                "exit_code": item.get("exit_code"),
                "output_path": item.get("output_path"),
            }
            for item in results
            if item.get("command")
        ]
        return {"ok": True, "count": len(commands), "commands": commands}

    @mcp.tool()
    async def rerun_command(
        command: str,
        workspace: str = "default",
        timeout: int = 3600,
        confirm_authorized: bool = False,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Rerun a command from command_history or user input after confirmation."""

        return await services.run_command_tool(
            "rerun_command",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
            check_binary=False,
            ctx=ctx,
        )

    @mcp.tool()
    async def save_command_as_script(
        command: str,
        path: str,
        shell: str = "bash",
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Save a command as an executable script after confirmation."""

        services.ensure_allowed("save_command_as_script", locals(), confirm_authorized=confirm_authorized)
        services.ensure_command_policy("save_command_as_script", command, confirm_authorized=confirm_authorized)
        script_path = _expand(path)
        services.ensure_path_policy("save_command_as_script", script_path, write=True)
        script_path.parent.mkdir(parents=True, exist_ok=True)
        script_path.write_text(f"#!/usr/bin/env {shell}\nset -euo pipefail\n{command}\n", encoding="utf-8")
        os.chmod(script_path, 0o700)
        return {"ok": True, "path": str(script_path), "mode": "700"}

    @mcp.tool()
    async def export_audit_log(
        max_lines: int = 500,
        workspace: str = "default",
    ) -> dict[str, Any]:
        """Export the tail of the audit log into a workspace report file."""

        services.ensure_allowed("export_audit_log", locals())
        lines = services.audit_file.read_text(encoding="utf-8", errors="replace").splitlines()[-max(1, int(max_lines)) :]
        output = services.sessions.output_path(workspace, "audit_log_export", ".jsonl", folder="reports")
        output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return {"ok": True, "path": str(output), "line_count": len(lines)}

    @mcp.tool()
    async def apt_update(workspace: str = "default", timeout: int = 3600, confirm_authorized: bool = False) -> dict[str, Any]:
        """Run apt-get update after confirmation."""

        return await services.run_command_tool(
            "apt_update",
            "sudo apt-get update",
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
            check_binary=False,
        )

    @mcp.tool()
    async def which_tool(tool_name: str) -> dict[str, Any]:
        """Locate an executable in Kali PATH."""

        services.ensure_allowed("which_tool", locals())
        return services.check_tool(tool_name)

    @mcp.tool()
    async def service_status(
        service: str,
        workspace: str = "default",
        timeout: int = 120,
    ) -> dict[str, Any]:
        """Check a systemd service status."""

        return await services.run_command_tool(
            "service_status",
            f"systemctl status {quote(service)} --no-pager",
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def network_interfaces(workspace: str = "default", timeout: int = 120) -> dict[str, Any]:
        """List Kali network interfaces and addresses."""

        return await services.run_command_tool(
            "network_interfaces",
            "ip -brief address",
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def open_port_listeners(workspace: str = "default", timeout: int = 120) -> dict[str, Any]:
        """List local listening TCP/UDP sockets."""

        return await services.run_command_tool(
            "open_port_listeners",
            "ss -tulpen",
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def disk_usage(path: str = ".", workspace: str = "default", timeout: int = 120) -> dict[str, Any]:
        """Show filesystem and directory disk usage."""

        return await services.run_command_tool(
            "disk_usage",
            f"df -h {quote(path)} && du -sh {quote(path)}",
            locals(),
            workspace=workspace,
            timeout=timeout,
            check_binary=False,
        )

    @mcp.tool()
    async def process_list(workspace: str = "default", timeout: int = 120) -> dict[str, Any]:
        """List running processes."""

        return await services.run_command_tool(
            "process_list",
            "ps auxww",
            locals(),
            workspace=workspace,
            timeout=timeout,
        )

    @mcp.tool()
    async def system_info() -> dict[str, Any]:
        """Return Kali/WSL system information visible to the MCP server."""

        services.ensure_allowed("system_info", locals())
        return {
            "ok": True,
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cwd": os.getcwd(),
            "home": str(Path.home()),
            "user": os.environ.get("USER") or os.environ.get("USERNAME"),
            "shell": os.environ.get("SHELL"),
            "path": os.environ.get("PATH", ""),
            "wsl_distro": os.environ.get("WSL_DISTRO_NAME"),
        }

    @mcp.tool()
    async def server_health() -> dict[str, Any]:
        """Return ExnoKaliMCP health, storage, auth, and scope status."""

        services.ensure_allowed("server_health", locals())
        paths = services.config.get("paths", {})
        core_tools = ["nmap", "ffuf", "nuclei", "sqlmap", "subfinder", "httpx", "dnsx"]
        installed = {tool: bool(shutil.which(tool)) for tool in core_tools}
        return {
            "ok": True,
            "server": _redacted_server_config(services.config),
            "paths": {
                "workspace_dir": str(services.sessions.workspace_dir),
                "scope_file": str(services.sessions.scope_file),
                "results_db": str(services.store.db_path),
                "logs_dir": str(Path(paths.get("logs_dir", "~/.exnokalimcp/logs")).expanduser()),
            },
            "scope": {
                "enabled": services.sessions.scope_enforcement,
                "rules": services.sessions.list_scope(),
            },
            "core_tools": installed,
            "background_jobs": list_background_jobs(),
        }

    @mcp.tool()
    async def tool_manifest() -> dict[str, Any]:
        """Return the registered MCP tool names and input schemas."""

        services.ensure_allowed("tool_manifest", locals())
        tools = await mcp.list_tools()
        return {
            "ok": True,
            "count": len(tools),
            "tools": [
                {
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.inputSchema,
                }
                for tool in tools
            ],
        }

    @mcp.tool()
    async def manage_wordlists(
        action: str,
        wordlist_name: str = "",
        url: str = "",
        workspace: str = "default",
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """List, download, install, or remove local wordlists."""

        base = Path(services.config.get("paths", {}).get("wordlists_dir", "/usr/share/wordlists")).expanduser()
        action = action.lower()
        if action == "list":
            services.ensure_allowed("manage_wordlists", locals(), confirm_authorized=confirm_authorized)
            items = [str(path) for path in base.rglob("*") if path.is_file()][:500] if base.exists() else []
            return {"ok": True, "wordlists_dir": str(base), "count": len(items), "items": items}
        if action == "download":
            if not confirm_authorized:
                raise PermissionError("download requires confirm_authorized=True")
            if not url:
                raise ValueError("url is required for download")
            destination = services.sessions.workspace_path(workspace) / "raw" / (wordlist_name or Path(url).name)
            command = join_flags(["curl", "-L", "-o", quote(destination), quote(url)])
            return await services.run_command_tool(
                "manage_wordlists",
                command,
                locals(),
                workspace=workspace,
                timeout=1800,
                confirm_authorized=True,
            )
        if action == "install_seclists":
            if not confirm_authorized:
                raise PermissionError("install_seclists requires confirm_authorized=True")
            command = "sudo apt-get update && sudo apt-get install -y seclists"
            return await services.run_command_tool(
                "manage_wordlists",
                command,
                locals(),
                workspace=workspace,
                timeout=7200,
                confirm_authorized=True,
                check_binary=False,
            )
        if action == "remove":
            services.ensure_allowed("manage_wordlists", locals(), confirm_authorized=confirm_authorized)
            if not confirm_authorized:
                raise PermissionError("remove requires confirm_authorized=True")
            candidate = (base / wordlist_name).resolve()
            if base not in candidate.parents and candidate != base:
                raise PermissionError("refusing to remove a path outside wordlists_dir")
            candidate.unlink()
            return {"ok": True, "removed": str(candidate)}
        raise ValueError("action must be list, download, install_seclists, or remove")

    @mcp.tool()
    async def manage_targets(action: str, target: str = "", scope_file: str = "") -> dict[str, Any]:
        """Manage the authorized target scope list."""

        services.ensure_allowed("manage_targets", locals())
        if scope_file:
            services.sessions.scope_file = _expand(scope_file)
            services.sessions.scope_file.parent.mkdir(parents=True, exist_ok=True)
            services.sessions.scope_file.touch(exist_ok=True)
        action = action.lower()
        if action == "add":
            services.sessions.add_scope(target)
        elif action == "remove":
            services.sessions.remove_scope(target)
        elif action == "import":
            imported = _expand(target).read_text(encoding="utf-8").splitlines()
            for item in imported:
                if item.strip() and not item.strip().startswith("#"):
                    services.sessions.add_scope(item.strip())
        elif action != "list":
            raise ValueError("action must be add, remove, import, or list")
        return {"ok": True, "scope_file": str(services.sessions.scope_file), "scope": services.sessions.list_scope()}

    @mcp.tool()
    async def create_workspace(name: str, target: str = "", description: str = "") -> dict[str, Any]:
        """Create an organized pentest workspace."""

        services.ensure_allowed("create_workspace", locals())
        return {"ok": True, "workspace": services.sessions.create_workspace(name, target, description)}

    @mcp.tool()
    async def list_workspaces() -> dict[str, Any]:
        """List all MCP workspaces."""

        services.ensure_allowed("list_workspaces", locals())
        return {"ok": True, "workspaces": services.sessions.list_workspaces()}

    @mcp.tool()
    async def workspace_tree(
        workspace: str = "default",
        max_depth: int = 4,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """List files under a workspace without leaving the workspace root."""

        services.ensure_allowed("workspace_tree", locals())
        root = services.sessions.workspace_path(workspace).resolve()
        rows = []
        for item in root.rglob("*"):
            rel = item.relative_to(root)
            if len(rel.parts) > max(0, int(max_depth)):
                continue
            rows.append(
                {
                    "relative": str(rel),
                    "path": str(item),
                    "type": "dir" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0,
                }
            )
            if len(rows) >= max(1, int(limit)):
                break
        return {"ok": True, "workspace": workspace, "root": str(root), "count": len(rows), "tree": rows}

    @mcp.tool()
    async def workspace_file_read(
        workspace: str,
        relative_path: str,
        max_lines: int = 500,
    ) -> dict[str, Any]:
        """Read a text file from inside a workspace."""

        services.ensure_allowed("workspace_file_read", locals())
        root = services.sessions.workspace_path(workspace).resolve()
        file_path = (root / relative_path).resolve()
        if file_path != root and root not in file_path.parents:
            raise PermissionError("relative_path escapes workspace root")
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        return {
            "ok": True,
            "workspace": workspace,
            "relative_path": relative_path,
            "line_count": len(lines),
            "content": "\n".join(lines[: max(1, int(max_lines))]),
        }

    @mcp.tool()
    async def workspace_export_zip(
        workspace: str = "default",
        output: str = "",
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Export a workspace as a zip archive after confirmation."""

        services.ensure_allowed("workspace_export_zip", locals(), confirm_authorized=confirm_authorized)
        root = services.sessions.workspace_path(workspace).resolve()
        if output:
            output_path = _expand(output)
            services.ensure_path_policy("workspace_export_zip", output_path, write=True)
        else:
            output_path = services.sessions.output_path(workspace, "workspace_export", ".zip", folder="reports")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for item in root.rglob("*"):
                if item == output_path:
                    continue
                archive.write(item, item.relative_to(root))
        return {"ok": True, "workspace": workspace, "zip_path": str(output_path)}

    @mcp.tool()
    async def get_scan_results(
        workspace: str = "",
        tool: str = "",
        limit: int = 50,
    ) -> dict[str, Any]:
        """Retrieve stored scan results from SQLite."""

        services.ensure_allowed("get_scan_results", locals())
        return {
            "ok": True,
            "results": services.store.list_results(workspace or None, tool or None, limit),
        }

    @mcp.tool()
    async def generate_report(
        workspace: str,
        format: str = "md",
        template: str = "",
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Generate a workspace report in markdown, HTML, JSON, or PDF."""

        results = services.store.get_workspace_results(workspace)
        report_dir = services.sessions.workspace_path(workspace) / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        fmt = format.lower()
        if fmt == "json":
            services.ensure_allowed("generate_report", locals())
            path = report_dir / "report.json"
            path.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
            return {"ok": True, "path": str(path), "format": fmt}

        markdown = _render_markdown_report(workspace, results, template)
        md_path = report_dir / "report.md"
        md_path.write_text(markdown, encoding="utf-8")
        if fmt == "md":
            services.ensure_allowed("generate_report", locals())
            return {"ok": True, "path": str(md_path), "format": "md"}
        if fmt == "html":
            services.ensure_allowed("generate_report", locals())
            html_path = report_dir / "report.html"
            html_path.write_text(_markdown_to_basic_html(markdown), encoding="utf-8")
            return {"ok": True, "path": str(html_path), "format": "html"}
        if fmt == "pdf":
            pdf_path = report_dir / "report.pdf"
            return await services.run_command_tool(
                "generate_report",
                join_flags(["pandoc", quote(md_path), "-o", quote(pdf_path)]),
                locals(),
                workspace=workspace,
                timeout=timeout,
            )
        raise ValueError("format must be md, html, json, or pdf")

    @mcp.tool()
    async def screenshot_desktop(
        output: str = "",
        mode: str = "auto",
        active_window: bool = False,
        delay_seconds: float = 0,
        workspace: str = "default",
        timeout: int = 60,
        include_base64: bool = False,
        max_inline_bytes: int = 2000000,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """
        Capture a Kali WSL desktop screenshot.

        In WSL, mode=auto first tries Linux GUI screenshot tools when DISPLAY or
        WAYLAND_DISPLAY exists, then falls back to Windows PowerShell screen
        capture through WSL interop. Use active_window=True to capture only the
        current foreground Windows window, such as a Kali terminal.
        """

        if not confirm_authorized:
            raise PermissionError("screenshot_desktop requires confirm_authorized=True because it can capture screen contents.")
        services.ensure_allowed("screenshot_desktop", locals(), confirm_authorized=confirm_authorized)
        mode = mode.lower()
        if mode not in {"auto", "linux", "windows"}:
            raise ValueError("mode must be auto, linux, or windows")
        if output:
            output_path = _expand(output)
            services.ensure_path_policy("screenshot_desktop", output_path, write=True)
        else:
            output_path = services.sessions.output_path(workspace, "screenshot_desktop", ".png", folder="screenshots")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        command = _desktop_screenshot_command(output_path, mode, active_window, delay_seconds)
        result = await services.run_command_tool(
            "screenshot_desktop",
            command,
            locals(),
            workspace=workspace,
            timeout=timeout,
            confirm_authorized=confirm_authorized,
            check_binary=False,
        )
        exists = output_path.exists()
        size = output_path.stat().st_size if exists else 0
        result["ok"] = bool(result.get("ok")) and exists and size > 0
        result.update(
            {
                "screenshot_path": str(output_path),
                "screenshot_exists": exists,
                "screenshot_size": size,
                "dimensions": _png_dimensions(output_path) if exists else {"width": 0, "height": 0},
                "capture_mode": mode,
                "active_window": active_window,
            }
        )
        if include_base64 and exists:
            size = output_path.stat().st_size
            if size <= max(1, int(max_inline_bytes)):
                result["image_base64"] = base64.b64encode(output_path.read_bytes()).decode("ascii")
                result["image_mime"] = "image/png"
            else:
                result["image_base64_omitted"] = f"file is {size} bytes; max_inline_bytes={max_inline_bytes}"
        return result

    @mcp.tool()
    async def screenshot_web(
        url: str,
        output: str = "",
        workspace: str = "default",
        timeout: int = 600,
    ) -> dict[str, Any]:
        """Take a screenshot of an authorized web page using gowitness."""

        output_dir = output or str(services.sessions.workspace_path(workspace) / "screenshots")
        effective_timeout, capped = services._foreground_timeout(timeout)
        gowitness_timeout = max(5, min(int(timeout), int(effective_timeout)) - 5)
        command = join_flags(
            [
                "gowitness",
                "scan",
                "single",
                "--url",
                quote(url),
                "--screenshot-path",
                quote(output_dir),
                "--screenshot-format",
                "png",
                "--write-none",
                "--threads",
                "1",
                "--timeout",
                str(gowitness_timeout),
            ]
        )
        result = await services.run_command_tool(
            "screenshot_web",
            command,
            locals(),
            target=url,
            workspace=workspace,
            timeout=timeout,
        )
        result["screenshot_dir"] = output_dir
        result["gowitness_timeout"] = gowitness_timeout
        result["foreground_timeout_capped"] = capped or result.get("foreground_timeout_capped", False)
        return result

    @mcp.tool()
    async def list_running_processes() -> dict[str, Any]:
        """List active MCP-spawned subprocesses."""

        services.ensure_allowed("list_running_processes", locals())
        return {"ok": True, "processes": get_running_processes()}

    @mcp.tool()
    async def start_background_process(
        command: str,
        workspace: str = "default",
        target: str = "",
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """
        Start a long-running command as a pollable background job.

        Use this for authorized scans that may run for minutes or hours, then
        call read_background_process_output with the returned job id.
        """

        return await services.start_background_tool(
            "start_background_process",
            command,
            locals(),
            target=target or None,
            workspace=workspace,
            confirm_authorized=confirm_authorized,
        )

    @mcp.tool()
    async def list_background_processes() -> dict[str, Any]:
        """List long-running background jobs started by ExnoKaliMCP."""

        services.ensure_allowed("list_background_processes", locals())
        return {"ok": True, "jobs": list_background_jobs()}

    @mcp.tool()
    async def read_background_process_output(
        job_id: str,
        offset: int = 0,
        max_bytes: int = 65536,
    ) -> dict[str, Any]:
        """Read incremental output from a background job using byte offsets."""

        services.ensure_allowed("read_background_process_output", locals())
        return {"ok": True, **read_background_output(job_id, offset=offset, max_bytes=max_bytes)}

    @mcp.tool()
    async def send_background_process_input(
        job_id: str,
        text: str,
        newline: bool = True,
        confirm_authorized: bool = False,
    ) -> dict[str, Any]:
        """Send stdin to a running background process."""

        services.ensure_allowed("send_background_process_input", locals(), confirm_authorized=confirm_authorized)
        return {"ok": True, **await send_background_input(job_id, text, newline=newline)}

    @mcp.tool()
    async def stop_background_process(job_id: str, confirm_authorized: bool = False) -> dict[str, Any]:
        """Terminate a background job after explicit confirmation."""

        services.ensure_allowed("stop_background_process", locals(), confirm_authorized=confirm_authorized)
        return {"ok": await stop_background_job(job_id), "job_id": job_id}

    @mcp.tool()
    async def kill_running_process(pid: int, confirm_authorized: bool = False) -> dict[str, Any]:
        """Terminate an MCP-spawned subprocess after confirmation."""

        services.ensure_allowed("kill_running_process", locals(), confirm_authorized=confirm_authorized)
        return {"ok": await kill_process(int(pid)), "pid": pid, "disclaimer": DISCLAIMER}


def _render_markdown_report(workspace: str, results: dict[str, Any], template: str = "") -> str:
    heading = template or f"# ExnoKaliMCP Report: {workspace}"
    lines = [heading, "", f"Result count: {results.get('count', 0)}", "", "## Results"]
    for item in results.get("results", []):
        lines.extend(
            [
                "",
                f"### {item.get('tool')} - {item.get('timestamp')}",
                f"- Target: {item.get('target') or 'local'}",
                f"- Exit code: {item.get('exit_code')}",
                f"- Output: `{item.get('output_path')}`",
            ]
        )
        summary = item.get("summary") or {}
        if summary:
            lines.append("- Summary:")
            lines.append("```json")
            lines.append(json.dumps(summary, indent=2, ensure_ascii=False)[:4000])
            lines.append("```")
    return "\n".join(lines) + "\n"


def _markdown_to_basic_html(markdown: str) -> str:
    escaped = html.escape(markdown)
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>ExnoKaliMCP Report</title>"
        "<style>body{font-family:system-ui;margin:2rem;max-width:1100px}"
        "pre{background:#f6f8fa;padding:1rem;overflow:auto}</style></head><body><pre>"
        + escaped
        + "</pre></body></html>"
    )
