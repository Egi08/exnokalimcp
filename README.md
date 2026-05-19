# ExnoKaliMCP Server for WSL

Python MCP server for Kali Linux on WSL, built for authorized bug bounty and penetration testing workflows. It exposes Kali tools through MCP, stores raw output in workspaces, persists metadata in SQLite, and enforces scope, confirmation, rate limiting, and audit logging.

## Legal Disclaimer

Use this server only on systems you own or have explicit written authorization to test. Unauthorized access, scanning, exploitation, credential attacks, packet injection, or traffic capture can be illegal. Every tool call is audit logged.

## Features

- MCP stdio transport for Claude Desktop.
- SSE transport for remote/local HTTP MCP use.
- Async subprocess execution with timeouts and process tracking.
- MCP progress logging for long-running foreground commands.
- Pollable background jobs for long scans and listeners.
- On-demand Kali tool resolver: checks WSL PATH first, suggests exact apt/go/pipx install commands, and can install only the tool needed when explicitly confirmed.
- Scope enforcement from `~/.exnokalimcp/scope.txt`.
- Confirmation gates for high-risk actions such as sqlmap, hydra, metasploit, wireless deauth, raw shell, and system installs.
- SQLite result store plus raw output files under `~/exnokalimcp-workspaces`.
- Resources for wordlists, installed tools, target scope, nuclei templates, exploit-db, and workspace results.

## Install On Kali WSL

Install the MCP server only. This is the recommended mode if you want ExnoKaliMCP to use whatever already exists in Kali WSL and install extra tools only when needed:

```bash
cd /path/to/exnokalimcp
chmod +x install.sh
./install.sh --server-only
```

`./install.sh` defaults to the same server-only profile.

Install runtime plus a few safe CLI utilities, but no Go or pipx recon tools:

```bash
./install.sh --minimal
```

Install the full Kali/bug bounty toolchain:

```bash
./install.sh --full
```

Reuse an existing Kali toolchain and skip apt/go/pipx entirely:

```bash
./install.sh --minimal --skip-apt --skip-go --skip-pipx
```

Optional on-demand installer helpers:

```bash
./install.sh --server-only --with-go
./install.sh --minimal --with-pipx
```

The installer creates:

- `~/.exnokalimcp/config.yaml`
- `~/.exnokalimcp/results.db`
- `~/.exnokalimcp/logs/audit.log`
- `~/.exnokalimcp/venv`
- `~/exnokalimcp-workspaces`
- `~/.exnokalimcp/claude_desktop_config.snippet.json`

## Claude Desktop Integration

On Windows, merge the generated snippet into:

```text
%APPDATA%\Claude\claude_desktop_config.json
```

WSL-aware configuration:

```json
{
  "mcpServers": {
    "exnokalimcp": {
      "command": "wsl.exe",
      "args": [
        "-d",
        "kali-linux",
        "--",
        "/bin/sh",
        "-lc",
        "cd \"/home/YOUR_USER/path/to/exnokalimcp\" && EXNOKALIMCP_CONFIG=\"/home/YOUR_USER/.exnokalimcp/config.yaml\" EXNOKALIMCP_AUTH_KEY=\"$(cat \"/home/YOUR_USER/.exnokalimcp/auth_key\")\" exec \"/home/YOUR_USER/.exnokalimcp/venv/bin/python\" \"/home/YOUR_USER/path/to/exnokalimcp/server.py\""
      ]
    }
  }
}
```

The WSL config reads the auth key inside Kali because environment variables set on the Windows `wsl.exe` process are not always forwarded into the Linux process by MCP clients.
The server also falls back to `server.auth.key_file` (`~/.exnokalimcp/auth_key` by default) when the environment variable is missing, which helps stdio clients that launch through `wsl.exe`.

Native Linux stdio configuration:

```json
{
  "mcpServers": {
    "exnokalimcp": {
      "command": "python3",
      "args": ["/path/to/exnokalimcp/server.py"],
      "env": {
        "EXNOKALIMCP_CONFIG": "/home/user/.exnokalimcp/config.yaml",
        "EXNOKALIMCP_AUTH_KEY": "your-secret-key"
      }
    }
  }
}
```

Restart Claude Desktop after editing the config.

## Manual Run

```bash
export EXNOKALIMCP_CONFIG="$HOME/.exnokalimcp/config.yaml"
export EXNOKALIMCP_AUTH_KEY="$(cat "$HOME/.exnokalimcp/auth_key")"
cd /path/to/exnokalimcp
"$HOME/.exnokalimcp/venv/bin/python" server.py
```

SSE mode:

```bash
export EXNOKALIMCP_CONFIG="$HOME/.exnokalimcp/config.yaml"
export EXNOKALIMCP_AUTH_KEY="$(cat "$HOME/.exnokalimcp/auth_key")"
cd /path/to/exnokalimcp
"$HOME/.exnokalimcp/venv/bin/python" server.py --transport sse
```

## Scope Setup

Add authorized targets before scanning:

```bash
mkdir -p ~/.exnokalimcp
cat > ~/.exnokalimcp/scope.txt <<'EOF'
example.com
*.example.com
192.168.56.0/24
EOF
```

Or use the MCP tool:

```text
manage_targets(action="add", target="example.com")
```

Scope supports domains, wildcard subdomains, IPs, and CIDR ranges. If `security.scope_enforcement` is `true` and the scope file is empty, network tools are blocked.

## Usage Examples

### Recon

```text
nmap_scan(target="scanme.nmap.org", ports="80,443", scan_type="default")
subfinder(domain="example.com", recursive=true)
amass_enum(domain="example.com", mode="passive")
dnsx(domains_list=["example.com", "www.example.com"], record_types=["a", "aaaa", "mx"])
httpx_probe(hosts_list=["example.com", "www.example.com"])
whois_lookup(domain_or_ip="example.com")
waybackurls(domain="example.com")
gau(domain="example.com")
shodan_query(query="ssl.cert.subject.cn:example.com")
```

### Web

```text
ffuf_fuzz(url="https://example.com/FUZZ", wordlist="/usr/share/wordlists/dirb/common.txt")
gobuster_dir(url="https://example.com", wordlist="/usr/share/wordlists/dirb/common.txt")
nikto_scan(target="https://example.com")
nuclei_scan(target="https://example.com", severity=["critical", "high"])
whatweb(url="https://example.com")
testssl(host="example.com")
wafw00f(url="https://example.com")
sqlmap_scan(url="https://example.com/item?id=1", confirm_authorized=true)
```

### Exploit Support

```text
searchsploit(query="apache 2.4")
auto_exploit_suggester(os_info="Ubuntu 20.04", service_info="OpenSSH 8.2")
msfconsole_command(commands_list=["version"], confirm_authorized=true)
msfvenom_payload(payload="linux/x64/shell_reverse_tcp", lhost="10.0.0.5", lport=4444, confirm_authorized=true)
```

### Password And Crypto

```text
hash_identify(hash_string="5f4dcc3b5aa765d61d8327deb882cf99")
hash_decode(hash="SGVsbG8=", hash_type="auto")
john_crack(hash_file="/tmp/hashes.txt", wordlist="/usr/share/wordlists/rockyou.txt")
hashcat_crack(hash="5f4dcc3b5aa765d61d8327deb882cf99", hash_type=0, wordlist="/usr/share/wordlists/rockyou.txt")
hydra_brute(target="192.168.56.10", service="ssh", username="test", wordlist="/tmp/passwords.txt", confirm_authorized=true)
```

### Network

```text
netdiscover(range="192.168.56.0/24")
arp_scan(range="192.168.56.0/24")
tcpdump_capture(interface="eth0", filter="host 192.168.56.10", duration=60)
netcat_connect(host="192.168.56.10", port=80, data="HEAD / HTTP/1.0\r\n\r\n")
curl_request(url="https://example.com", method="GET")
ssh_connect(host="192.168.56.10", user="kali", key_or_pass="/home/kali/.ssh/id_rsa", command_to_run="id")
```

### Wireless

```text
airmon_start(interface="wlan0", confirm_authorized=true)
airodump_capture(interface="wlan0mon", bssid="00:11:22:33:44:55", channel="6", duration=120, confirm_authorized=true)
aireplay_deauth(interface="wlan0mon", bssid="00:11:22:33:44:55", count=5, confirm_authorized=true)
aircrack_crack(capture_file="/tmp/capture.cap", wordlist="/usr/share/wordlists/rockyou.txt")
```

### Forensics

```text
strings_analysis(file_path="/tmp/sample.bin")
binwalk_analyze(file_path="/tmp/firmware.bin")
exiftool_analyze(file_path="/tmp/image.jpg")
file_identify(file_path="/tmp/blob")
hexdump_view(file_path="/tmp/blob", length=256, offset=0)
volatility_analyze(memory_dump="/tmp/memory.raw", plugin="windows.info")
foremost_recover(file_path="/tmp/disk.raw")
```

### Shell And Workspaces

```text
create_workspace(name="acme", target="example.com", description="Authorized test")
list_workspaces()
get_scan_results(workspace="acme", limit=20)
generate_report(workspace="acme", format="md")
screenshot_web(url="https://example.com", workspace="acme")
screenshot_desktop(mode="auto", active_window=true, workspace="acme", confirm_authorized=true)
check_tool_installed(tool_name="nmap")
resolve_tool(tool_name="nmap")
resolve_tool(tool_name="ffuf", install_if_missing=true, confirm_authorized=true)
tool_inventory(category="web", only_missing=true)
suggest_tool_for_task(task="directory fuzzing for a web app", target_type="url")
server_health()
tool_manifest()
shell_exec(command="id && uname -a", confirm_authorized=true)
```

### On-Demand Tool Resolver

ExnoKaliMCP does not need every Kali tool installed up front. Before a command runs, the server checks the executable from inside the Kali WSL PATH, including `~/.local/bin` and `~/go/bin`. If the binary is missing, the MCP response includes resolver metadata and a copyable install hint.

Use these tools to keep Kali lightweight:

```text
resolve_tool(tool_name="subfinder")
resolve_tool(tool_name="subfinder", install_if_missing=true, method="auto", confirm_authorized=true)
install_tool(tool_name="httpx", method="auto", confirm_authorized=true)
tool_inventory(category="recon", only_missing=true)
suggest_tool_for_task(task="subdomain enumeration and http probing")
doctor_check()
```

Runtime auto-install is disabled by default. To allow confirmed tool calls to install missing dependencies automatically, set this in `~/.exnokalimcp/config.yaml`:

```yaml
tool_resolver:
  enabled: true
  auto_install: true
  install_method: "auto"
```

Even with `auto_install: true`, installation only runs for calls that include `confirm_authorized=true`.

### Kali Linux File And System Control

These tools make the MCP useful as a Kali WSL filesystem and terminal control layer. Read-only tools run directly; tools that create, edit, move, delete, or chmod require `confirm_authorized=true`.

```text
system_info()
file_list(path="/home/kali", recursive=false, include_hidden=true)
file_tree(path="/home/kali/project", max_depth=3)
file_stat(path="/etc/os-release")
file_read(path="/etc/os-release", max_lines=50)
file_tail(path="/var/log/syslog", lines=100)
file_search(pattern="*.py", directory="/home/kali", options={"limit": 200})
file_checksum(path="/home/kali/archive.tar.gz")
file_download_chunk(path="/home/kali/archive.tar.gz", offset=0, max_bytes=65536)
file_upload_chunk(path="/home/kali/upload.bin", data="SGVsbG8=", encoding="base64", confirm_authorized=true)
file_diff(path="/home/kali/notes.txt", new_content="updated\n")
file_backup(path="/home/kali/notes.txt", workspace="default")
file_patch(path="/home/kali/notes.txt", unified_diff="--- current\n+++ proposed\n@@ -1 +1 @@\n-old\n+new\n", confirm_authorized=true)
file_restore(backup_path="/home/kali/exnokalimcp-workspaces/default/backups/notes.txt.20260101T000000Z.bak", destination="/home/kali/notes.txt", confirm_authorized=true)
file_write(path="/home/kali/notes.txt", content="hello\n", confirm_authorized=true)
file_write(path="/home/kali/notes.txt", content="append\n", append=true, confirm_authorized=true)
file_mkdir(path="/home/kali/lab/output", confirm_authorized=true)
file_copy(source="/home/kali/a.txt", destination="/home/kali/b.txt", overwrite=true, confirm_authorized=true)
file_move(source="/home/kali/b.txt", destination="/home/kali/archive/b.txt", confirm_authorized=true)
file_replace(path="/home/kali/notes.txt", old="hello", new="hi", confirm_authorized=true)
file_chmod(path="/home/kali/script.sh", mode="755", confirm_authorized=true)
file_delete(path="/home/kali/archive/b.txt", confirm_authorized=true)
wsl_path_convert(path="C:\\Users\\black\\Downloads\\payload.txt")
wsl_path_convert(path="/mnt/c/Users/black/Downloads/payload.txt", direction="wsl_to_windows")
```

Long-running jobs:

Foreground MCP calls are capped by `tools.foreground_timeout` so desktop clients
receive a structured timeout response instead of a client-side request timeout.
Use background jobs for scans or commands that need more than that cap.

```text
start_background_process(command="nmap -sV -p- 192.168.56.10", target="192.168.56.10", workspace="net", confirm_authorized=true)
list_background_processes()
read_background_process_output(job_id="RETURNED_JOB_ID", offset=0)
send_background_process_input(job_id="RETURNED_JOB_ID", text="y", confirm_authorized=true)
stop_background_process(job_id="RETURNED_JOB_ID", confirm_authorized=true)
```

Persistent Kali terminal sessions:

```text
terminal_start(command="bash", cwd="/home/kali", confirm_authorized=true)
terminal_read(session_id="RETURNED_SESSION_ID")
terminal_send(session_id="RETURNED_SESSION_ID", text="whoami", newline=true, confirm_authorized=true)
terminal_read(session_id="RETURNED_SESSION_ID")
terminal_stop(session_id="RETURNED_SESSION_ID", confirm_authorized=true)
```

Terminal sessions write transcripts to the selected workspace and return `transcript_path`.

Workspace artifact browser:

```text
workspace_tree(workspace="default")
workspace_file_read(workspace="default", relative_path="raw/output.txt")
workspace_export_zip(workspace="default", confirm_authorized=true)
```

Desktop screenshots from Kali WSL:

```text
screenshot_desktop(mode="auto", active_window=false, confirm_authorized=true)
screenshot_desktop(mode="windows", active_window=true, include_base64=true, confirm_authorized=true)
screenshot_desktop(output="/home/kali/screen.png", mode="linux", confirm_authorized=true)
```

`mode=auto` tries Linux GUI screenshot tools first when WSLg/X11 is available, then falls back to Windows PowerShell capture through WSL interop. `active_window=true` captures the current foreground Windows window, which is useful for Kali terminal screenshots.

Kali doctor, command replay, and system aliases:

```text
doctor_check()
doctor_fix(action="create_dirs", confirm_authorized=true)
command_history(limit=20)
save_command_as_script(command="nmap -sV example.com", path="/home/kali/scripts/recon.sh", confirm_authorized=true)
rerun_command(command="id && uname -a", confirm_authorized=true)
export_audit_log(max_lines=500)
apt_update(confirm_authorized=true)
which_tool(tool_name="nmap")
service_status(service="ssh")
network_interfaces()
open_port_listeners()
disk_usage(path="/home/kali")
process_list()
```

### Workflow Helpers

```text
bugbounty_recon(domain="example.com", scope=["example.com", "*.example.com"], workspace="example-recon")
web_app_assessment(url="https://example.com", options={"wordlist": "/usr/share/wordlists/dirb/common.txt"}, confirm_authorized=true)
network_pentest(target_range="192.168.56.0/24", options={"ports": "1-1000", "rate": 1000})
```

## MCP Resources

- `kali://wordlists`
- `kali://wordlists/{name}`
- `kali://tools/installed`
- `kali://targets/scope`
- `kali://workspaces/{name}/results`
- `kali://templates/nuclei`
- `kali://exploits/recent`
- `exnokalimcp://manifest`
- `exnokalimcp://health`

## Configuration

Main config lives at `~/.exnokalimcp/config.yaml`.

Important fields:

- `server.transport`: `stdio` or `sse`
- `server.auth.api_keys`: accepted API keys
- `server.auth.key_file`: local fallback auth key file for WSL stdio clients
- `security.scope_enforcement`: blocks network tools outside scope
- `security.require_confirmation`: tools that need `confirm_authorized=true`
- `security.permission_mode`: `full_control`, `pentest_safe`, `workspace_only`, or `read_only`
- `paths.workspace_dir`: raw output and reports
- `paths.results_db`: SQLite result database
- `tools.default_timeout`: default command timeout
- `tools.foreground_timeout`: MCP-safe cap for foreground command tools; use background jobs for longer runs
- `tool_resolver.auto_install`: disabled by default; if enabled, missing tools install only on confirmed calls
- `tool_resolver.extra_paths`: extra WSL PATH entries such as `~/.local/bin` and `~/go/bin`

## Troubleshooting

Auth error:

```bash
export EXNOKALIMCP_AUTH_KEY="$(cat ~/.exnokalimcp/auth_key)"
```

Scope error:

```bash
cat ~/.exnokalimcp/scope.txt
echo "example.com" >> ~/.exnokalimcp/scope.txt
```

Tool missing:

```text
check_tool_installed(tool_name="nmap")
resolve_tool(tool_name="nmap")
install_tool(tool_name="nmap", method="auto", confirm_authorized=true)
```

Claude cannot start WSL server:

- Confirm the distro name with `wsl.exe -l -v`.
- Confirm the paths in `claude_desktop_config.json` are Linux paths passed after `wsl.exe --`.
- Restart Claude Desktop after config changes.

Long process stuck:

```text
list_running_processes()
kill_running_process(pid=12345, confirm_authorized=true)
```

No output from GUI tools:

- Prefer CLI equivalents such as `tshark` over Wireshark GUI.
- WSL has limited direct wireless adapter support unless USB/IP passthrough is configured.

## Development

Run tests:

```bash
cd /path/to/exnokalimcp
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest -q
```

Run syntax check:

```bash
python3 -m compileall .
```
