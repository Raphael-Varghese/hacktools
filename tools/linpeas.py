#!/usr/bin/env python3
import click
import json
import os
import platform
import re
import stat
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
console = Console()
def run_cmd(cmd: str, shell: bool = True) -> Tuple[int, str]:
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout + r.stderr
    except Exception as e:
        return 1, str(e)
def now() -> str:
    return datetime.now().isoformat()
class Finding:
    def __init__(self, category: str, severity: str, message: str, detail: str = ""):
        self.category = category
        self.severity = severity
        self.message = message
        self.detail = detail
        self.time = now()
    def to_dict(self) -> dict:
        return {"category": self.category, "severity": self.severity, "message": self.message, "detail": self.detail, "time": self.time}
class PyLinpeas:
    def __init__(self, output: Optional[str], quick: bool, verbose: bool):
        self.output = output
        self.quick = quick
        self.verbose = verbose
        self.findings: List[Finding] = []
        self.user = os.getlogin() if hasattr(os, "getlogin") else os.environ.get("USER", "unknown")
        self.uid = os.getuid()
        self.hostname = platform.node()
        self.os_info = platform.platform()
        self.kernel = platform.release()
    def banner(self):
        console.print(Panel.fit("[bold #0e6b0e]PyLinpeas v1.0 - Linux Privilege Escalation Auditor[/bold #0e6b0e]", border_style="#0e6b0e"))
        console.print(f"[cyan]User: {self.user}  UID: {self.uid}  Host: {self.hostname}[/cyan]")
        console.print(f"[cyan]OS: {self.os_info}  Kernel: {self.kernel}[/cyan]")
        console.print("")
    def add(self, category: str, severity: str, message: str, detail: str = ""):
        f = Finding(category, severity, message, detail)
        self.findings.append(f)
        color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}.get(severity, "white")
        console.print(f"[{color}][{severity:8}] {category:20} {message}[/{color}]")
        if detail and self.verbose:
            console.print(f"[dim]    {detail}[/dim]")
    def run(self):
        self.banner()
        self.check_kernel()
        self.check_sudo()
        self.check_suid()
        self.check_capabilities()
        self.check_cron()
        self.check_path()
        self.check_env()
        self.check_writable_dirs()
        self.check_passwd_shadow()
        self.check_ssh()
        self.check_containers()
        self.check_processes()
        self.check_network()
        self.check_nfs()
        self.check_packages()
        self.check_config_files()
        self.check_history()
        self.check_home_dirs()
        self.check_log_files()
        self.check_timers()
        self.check_polkit()
        self.check_mounts()
        self.check_swap()
        self.check_apparmor_selinux()
        self.summary()
        self.save()
    def check_kernel(self):
        console.print("[bold #0e6b0e][*] Kernel & OS Information[/bold #0e6b0e]")
        self.add("Kernel", "INFO", f"Kernel: {self.kernel}")
        self.add("Kernel", "INFO", f"Distribution: {self.os_info}")
        code, out = run_cmd("uname -a")
        if out:
            self.add("Kernel", "INFO", out.strip())
        code, out = run_cmd("cat /proc/version")
        if out:
            self.add("Kernel", "INFO", out.strip())
        code, out = run_cmd("sysctl kernel.dmesg_restrict 2>/dev/null")
        if "1" in out:
            self.add("Kernel", "MEDIUM", "kernel.dmesg_restrict is enabled")
        known_vulns = ["4.4.0", "4.8.0", "5.4.0", "5.8.0", "5.11.0", "5.15.0", "6.1.0", "6.2.0"]
        for v in known_vulns:
            if v in self.kernel:
                self.add("Kernel", "MEDIUM", f"Kernel {v} may have known exploits", "Check exploit-db for CVEs")
                break
    def check_sudo(self):
        console.print("[bold #0e6b0e][*] Sudo Permissions[/bold #0e6b0e]")
        code, out = run_cmd("sudo -l 2>/dev/null")
        if code == 0 and out:
            lines = out.splitlines()
            for line in lines:
                line = line.strip()
                if "NOPASSWD" in line:
                    self.add("Sudo", "HIGH", f"NOPASSWD sudo entry: {line}")
                if "(ALL : ALL)" in line or "(ALL)" in line:
                    self.add("Sudo", "CRITICAL", f"ALL privileges: {line}")
                if any(x in line for x in ["vim", "nano", "less", "more", "man", "awk", "perl", "python", "ruby", "lua", "bash", "sh", "find", "xargs", "nc", "ncat", "netcat", "nmap", "tcpdump", "wget", "curl", "ftp", "ssh", "scp", "git", "docker", "lxc", "podman", "systemctl", "service", "mount", "umount", "dd", "mv", "cp", "tee", "cat", "tac", "rev", "sort", "uniq", "head", "tail", "cut", "paste", "join", "comm", "diff", "patch", "ed", "ex", "vi", "emacs", "pico", "jed", "joe", "mcedit", "hexedit", "setarch", "nice", "renice", "taskset", "stdbuf", "timeout", "script", "screen", "tmux", "expect", "tclsh", "wish", "tk", "rlwrap", "cowsay", "cowthink", "sl", "figlet", "toilet", "banner", "fortune", "yes", "rev", "factor", "seq", "shuf", "sort", "tsort", "tac", "nl", "od", "hexdump", "xxd", "base64", "uudecode", "uuencode", "gzip", "gunzip", "zcat", "bzcat", "lzcat", "xzcat", "zstdcat", "uncompress", "tar", "cpio", "ar", "pax", "zip", "unzip", "jar", "rar", "unrar", "7z", "lha", "cabextract", "rpm", "dpkg", "apt-get", "apt", "yum", "dnf", "pacman", "zypper", "snap", "flatpak", "appimage", "pip", "pip3", "gem", "npm", "yarn", "composer", "pecl", "cpan", "luarocks", "cargo", "go", "rustc", "javac", "java", "python", "python3", "ruby", "perl", "php", "node", "nodejs", "lua", "tcl", "tk", "wish", "expect", "bash", "sh", "dash", "zsh", "csh", "tcsh", "ksh", "mksh", "fish", "pwsh", "powershell", "cmd", "command", "cmd.exe", "powershell.exe", "wsl", "wsl.exe", "bash.exe"]):
                    self.add("Sudo", "HIGH", f"Potentially exploitable sudo binary: {line}")
        else:
            self.add("Sudo", "INFO", "No sudo access or password required")
    def check_suid(self):
        console.print("[bold #0e6b0e][*] SUID/SGID Binaries[/bold #0e6b0e]")
        code, out = run_cmd("find / -perm -4000 -type f 2>/dev/null")
        if out:
            bins = [b.strip() for b in out.splitlines() if b.strip()]
            for b in bins:
                name = os.path.basename(b)
                if name in ["bash", "sh", "dash", "zsh", "csh", "ksh", "tcsh", "fish", "ash", "mksh", "nu"]:
                    self.add("SUID", "CRITICAL", f"SUID shell: {b}")
                elif name in ["vim", "vi", "nano", "emacs", "ed", "ex", "pico", "joe", "mcedit", "hexedit"]:
                    self.add("SUID", "HIGH", f"SUID editor: {b}")
                elif name in ["nmap", "nc", "ncat", "netcat", "socat", "tcpdump", "wireshark", "tshark", "dumpcap"]:
                    self.add("SUID", "HIGH", f"SUID network tool: {b}")
                elif name in ["python", "python2", "python3", "perl", "ruby", "lua", "php", "node", "nodejs"]:
                    self.add("SUID", "CRITICAL", f"SUID interpreter: {b}")
                elif name in ["find", "xargs", "awk", "grep", "sed", "cut", "sort", "uniq", "head", "tail", "cat", "tac", "rev", "nl", "od", "hexdump", "xxd", "base64", "uudecode", "tar", "cpio", "ar", "zip", "unzip"]:
                    self.add("SUID", "HIGH", f"SUID utility: {b}")
                elif name in ["mount", "umount", "ping", "ping6", "su", "sudo", "passwd", "chsh", "chfn", "newgrp", "gpasswd", "pkexec", "mount.nfs", "mount.cifs"]:
                    self.add("SUID", "MEDIUM", f"Common SUID binary: {b}")
                else:
                    self.add("SUID", "LOW", f"SUID binary: {b}")
        code, out = run_cmd("find / -perm -2000 -type f 2>/dev/null")
        if out:
            for line in out.splitlines():
                line = line.strip()
                if line:
                    self.add("SGID", "LOW", f"SGID binary: {line}")
    def check_capabilities(self):
        console.print("[bold #0e6b0e][*] Linux Capabilities[/bold #0e6b0e]")
        code, out = run_cmd("getcap -r / 2>/dev/null")
        if out:
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                if any(x in line for x in ["python", "python3", "perl", "ruby", "php", "node", "vim", "vi", "nano", "tar", "gzip", "gunzip", "curl", "wget", "gcc", "g++"]):
                    self.add("Capabilities", "HIGH", f"Interesting capability: {line}")
                else:
                    self.add("Capabilities", "LOW", f"Capability: {line}")
    def check_cron(self):
        console.print("[bold #0e6b0e][*] Cron Jobs[/bold #0e6b0e]")
        cron_files = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"]
        for cf in cron_files:
            if os.path.exists(cf):
                if os.path.isdir(cf):
                    for f in os.listdir(cf):
                        path = os.path.join(cf, f)
                        if os.path.isfile(path):
                            self.add("Cron", "INFO", f"Cron file: {path}")
                            try:
                                with open(path, "r") as fh:
                                    content = fh.read()
                                    for line in content.splitlines():
                                        if line.strip() and not line.strip().startswith("#"):
                                            self.add("Cron", "INFO", f"  {line.strip()}")
                            except Exception:
                                pass
                else:
                    self.add("Cron", "INFO", f"Cron file: {cf}")
                    try:
                        with open(cf, "r") as fh:
                            content = fh.read()
                            for line in content.splitlines():
                                if line.strip() and not line.strip().startswith("#"):
                                    self.add("Cron", "INFO", f"  {line.strip()}")
                    except Exception:
                        pass
        code, out = run_cmd("crontab -l 2>/dev/null")
        if out:
            self.add("Cron", "INFO", "User crontab found")
            for line in out.splitlines():
                if line.strip() and not line.strip().startswith("#"):
                    self.add("Cron", "INFO", f"  {line.strip()}")
    def check_path(self):
        console.print("[bold #0e6b0e][*] PATH[/bold #0e6b0e]")
        path = os.environ.get("PATH", "")
        self.add("PATH", "INFO", f"PATH={path}")
        for p in path.split(":"):
            if os.path.isdir(p) and os.access(p, os.W_OK):
                self.add("PATH", "HIGH", f"Writable directory in PATH: {p}")
    def check_env(self):
        console.print("[bold #0e6b0e][*] Environment Variables[/bold #0e6b0e]")
        for k, v in os.environ.items():
            if any(x in k.upper() for x in ["PASS", "TOKEN", "KEY", "SECRET", "CRED", "AUTH", "PWD"]):
                masked = v[:2] + "*" * max(0, len(v) - 4) + v[-2:] if len(v) > 4 else "****"
                self.add("Env", "MEDIUM", f"Potential secret in env: {k}={masked}")
            elif self.verbose:
                self.add("Env", "INFO", f"{k}={v}")
    def check_writable_dirs(self):
        console.print("[bold #0e6b0e][*] Writable Directories[/bold #0e6b0e]")
        dirs = ["/tmp", "/var/tmp", "/dev/shm", "/home", "/opt", "/usr/local/bin", "/usr/local/sbin", "/srv"]
        for d in dirs:
            if os.path.isdir(d) and os.access(d, os.W_OK):
                self.add("Writable", "INFO", f"Writable: {d}")
        code, out = run_cmd("find / -maxdepth 3 -type d -writable 2>/dev/null")
        if out:
            for line in out.splitlines():
                line = line.strip()
                if line and line not in dirs:
                    self.add("Writable", "LOW", f"Writable directory: {line}")
    def check_passwd_shadow(self):
        console.print("[bold #0e6b0e][*] Password Files[/bold #0e6b0e]")
        if os.path.exists("/etc/passwd"):
            self.add("Passwd", "INFO", "/etc/passwd exists")
            try:
                with open("/etc/passwd", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split(":")
                            if len(parts) > 2 and parts[2] == "0":
                                self.add("Passwd", "HIGH", f"UID 0 user: {parts[0]}")
                            if len(parts) > 6 and parts[6] in ["/bin/bash", "/bin/sh", "/bin/zsh"]:
                                self.add("Passwd", "INFO", f"Shell user: {parts[0]} -> {parts[6]}")
            except Exception:
                pass
        if os.path.exists("/etc/shadow"):
            self.add("Shadow", "INFO", "/etc/shadow exists")
            try:
                with open("/etc/shadow", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split(":")
                            if len(parts) > 1 and parts[1] in ["", "*", "!", "!!", "x", "X"]:
                                continue
                            if len(parts) > 1 and parts[1]:
                                self.add("Shadow", "MEDIUM", f"Password hash for {parts[0]}")
            except PermissionError:
                self.add("Shadow", "INFO", "Cannot read /etc/shadow (permission denied)")
        if os.path.exists("/etc/group"):
            self.add("Group", "INFO", "/etc/group exists")
    def check_ssh(self):
        console.print("[bold #0e6b0e][*] SSH Configuration[/bold #0e6b0e]")
        ssh_dirs = ["/etc/ssh", os.path.expanduser("~/.ssh")]
        for d in ssh_dirs:
            if os.path.isdir(d):
                self.add("SSH", "INFO", f"SSH directory: {d}")
                for f in os.listdir(d):
                    path = os.path.join(d, f)
                    if os.path.isfile(path):
                        if "id_rsa" in f or "id_ecdsa" in f or "id_ed25519" in f or "id_dsa" in f:
                            self.add("SSH", "HIGH", f"Private key: {path}")
                        elif "authorized_keys" in f:
                            self.add("SSH", "MEDIUM", f"authorized_keys: {path}")
                        elif "known_hosts" in f:
                            self.add("SSH", "INFO", f"known_hosts: {path}")
                        elif "config" in f:
                            self.add("SSH", "INFO", f"SSH config: {path}")
    def check_containers(self):
        console.print("[bold #0e6b0e][*] Container / Virtualization[/bold #0e6b0e]")
        if os.path.exists("/.dockerenv"):
            self.add("Container", "HIGH", "Running inside Docker container")
        if os.path.exists("/proc/1/cgroup"):
            try:
                with open("/proc/1/cgroup", "r") as f:
                    content = f.read()
                    if "docker" in content or "lxc" in content or "containerd" in content:
                        self.add("Container", "HIGH", f"Container detected: {content.strip()}")
            except Exception:
                pass
        code, out = run_cmd("id")
        if "docker" in out:
            self.add("Container", "HIGH", "User is in docker group")
        if "lxc" in out:
            self.add("Container", "HIGH", "User is in lxc group")
        if os.path.exists("/run/systemd/container"):
            self.add("Container", "INFO", "systemd container detected")
    def check_processes(self):
        console.print("[bold #0e6b0e][*] Running Processes[/bold #0e6b0e]")
        code, out = run_cmd("ps aux 2>/dev/null | head -30")
        if out:
            for line in out.splitlines()[1:]:
                if line.strip():
                    self.add("Process", "INFO", line.strip())
        code, out = run_cmd("ps -eo user,group,comm,pid,ppid 2>/dev/null | head -30")
        if out:
            for line in out.splitlines()[1:]:
                if line.strip():
                    self.add("Process", "INFO", line.strip())
    def check_network(self):
        console.print("[bold #0e6b0e][*] Network Information[/bold #0e6b0e]")
        code, out = run_cmd("ip addr 2>/dev/null || ifconfig 2>/dev/null")
        if out:
            for line in out.splitlines():
                if line.strip():
                    self.add("Network", "INFO", line.strip())
        code, out = run_cmd("ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null")
        if out:
            for line in out.splitlines():
                if line.strip():
                    self.add("Network", "INFO", line.strip())
    def check_nfs(self):
        console.print("[bold #0e6b0e][*] NFS Exports[/bold #0e6b0e]")
        if os.path.exists("/etc/exports"):
            try:
                with open("/etc/exports", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self.add("NFS", "MEDIUM", f"NFS export: {line}")
            except Exception:
                pass
        code, out = run_cmd("showmount -e localhost 2>/dev/null")
        if out:
            for line in out.splitlines():
                if line.strip():
                    self.add("NFS", "MEDIUM", f"NFS: {line.strip()}")
    def check_packages(self):
        console.print("[bold #0e6b0e][*] Installed Packages[/bold #0e6b0e]")
        code, out = run_cmd("dpkg -l 2>/dev/null | head -20")
        if out:
            self.add("Packages", "INFO", "dpkg packages found")
        code, out = run_cmd("rpm -qa 2>/dev/null | head -20")
        if out:
            self.add("Packages", "INFO", "rpm packages found")
        code, out = run_cmd("pacman -Q 2>/dev/null | head -20")
        if out:
            self.add("Packages", "INFO", "pacman packages found")
    def check_config_files(self):
        console.print("[bold #0e6b0e][*] Interesting Config Files[/bold #0e6b0e]")
        files = [
            "/etc/nginx/nginx.conf", "/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf",
            "/etc/mysql/my.cnf", "/etc/postgresql/postgresql.conf", "/etc/redis/redis.conf",
            "/etc/mongodb.conf", "/etc/elasticsearch/elasticsearch.yml",
            "/etc/php.ini", "/etc/php/7.4/apache2/php.ini", "/etc/php/8.0/apache2/php.ini",
            "/etc/samba/smb.conf", "/etc/vsftpd.conf", "/etc/proftpd/proftpd.conf",
            "/etc/snmp/snmpd.conf", "/etc/openvpn/server.conf", "/etc/wireguard/wg0.conf",
            "/etc/hosts", "/etc/resolv.conf", "/etc/network/interfaces",
        ]
        for f in files:
            if os.path.exists(f):
                self.add("Config", "INFO", f"Config file exists: {f}")
                try:
                    with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                        for line in content.splitlines():
                            if any(x in line.lower() for x in ["pass", "secret", "token", "key", "cred", "auth"]):
                                self.add("Config", "HIGH", f"Potential secret in {f}: {line.strip()}")
                except Exception:
                    pass
    def check_history(self):
        console.print("[bold #0e6b0e][*] Shell History[/bold #0e6b0e]")
        hist_files = ["~/.bash_history", "~/.zsh_history", "~/.sh_history", "~/.mysql_history", "~/.psql_history", "~/.rediscli_history", "~/.lesshst"]
        for hf in hist_files:
            path = os.path.expanduser(hf)
            if os.path.exists(path):
                self.add("History", "INFO", f"History file: {path}")
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                        for line in lines[-20:]:
                            line = line.strip()
                            if any(x in line.lower() for x in ["pass", "ssh", "sudo", "su -", "mysql -u", "psql", "redis", "scp", "rsync", "curl", "wget"]):
                                self.add("History", "MEDIUM", f"Interesting command: {line}")
                except Exception:
                    pass
    def check_home_dirs(self):
        console.print("[bold #0e6b0e][*] Home Directories[/bold #0e6b0e]")
        if os.path.isdir("/home"):
            for d in os.listdir("/home"):
                path = os.path.join("/home", d)
                if os.path.isdir(path):
                    self.add("Home", "INFO", f"Home dir: {path}")
    def check_log_files(self):
        console.print("[bold #0e6b0e][*] Log Files[/bold #0e6b0e]")
        logs = ["/var/log/auth.log", "/var/log/syslog", "/var/log/messages", "/var/log/secure", "/var/log/audit/audit.log"]
        for log in logs:
            if os.path.exists(log):
                self.add("Logs", "INFO", f"Log file: {log}")
    def check_timers(self):
        console.print("[bold #0e6b0e][*] Systemd Timers[/bold #0e6b0e]")
        code, out = run_cmd("systemctl list-timers --all 2>/dev/null")
        if out:
            for line in out.splitlines():
                if line.strip():
                    self.add("Timers", "INFO", line.strip())
    def check_polkit(self):
        console.print("[bold #0e6b0e][*] Polkit[/bold #0e6b0e]")
        if os.path.exists("/usr/bin/pkexec"):
            self.add("Polkit", "INFO", "pkexec found")
            code, out = run_cmd("pkexec --version 2>/dev/null")
            if out:
                self.add("Polkit", "INFO", out.strip())
    def check_mounts(self):
        console.print("[bold #0e6b0e][*] Mount Points[/bold #0e6b0e]")
        code, out = run_cmd("mount 2>/dev/null")
        if out:
            for line in out.splitlines():
                if line.strip():
                    if "noexec" not in line and "nosuid" not in line and ("/dev" in line or "/tmp" in line or "/home" in line):
                        self.add("Mounts", "MEDIUM", f"Mount without hardening: {line.strip()}")
                    else:
                        self.add("Mounts", "INFO", line.strip())
    def check_swap(self):
        console.print("[bold #0e6b0e][*] Swap[/bold #0e6b0e]")
        code, out = run_cmd("swapon --show 2>/dev/null")
        if out:
            for line in out.splitlines():
                if line.strip():
                    self.add("Swap", "INFO", line.strip())
    def check_apparmor_selinux(self):
        console.print("[bold #0e6b0e][*] MAC Frameworks[/bold #0e6b0e]")
        code, out = run_cmd("aa-status 2>/dev/null")
        if out:
            self.add("AppArmor", "INFO", "AppArmor is enabled")
        code, out = run_cmd("sestatus 2>/dev/null")
        if out:
            self.add("SELinux", "INFO", out.strip())
    def summary(self):
        console.print("")
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        table = Table(title="Summary")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}[sev]
            table.add_row(f"[{color}]{sev}[/{color}]", str(counts[sev]))
        console.print(table)
    def save(self):
        if not self.output:
            return
        data = {
            "user": self.user,
            "uid": self.uid,
            "hostname": self.hostname,
            "os": self.os_info,
            "kernel": self.kernel,
            "findings": [f.to_dict() for f in self.findings],
        }
        ext = os.path.splitext(self.output)[1].lower()
        try:
            if ext == ".json":
                with open(self.output, "w") as f:
                    json.dump(data, f, indent=2)
            else:
                with open(self.output, "w") as f:
                    f.write(f"PyLinpeas Report for {self.hostname}\n")
                    f.write("=" * 50 + "\n")
                    for finding in self.findings:
                        f.write(f"[{finding.severity}] {finding.category}: {finding.message}\n")
            console.print(f"[green][+] Saved to {self.output}[/green]")
        except Exception as e:
            console.print(f"[red][!] Save failed: {e}[/red]")
@click.command()
@click.option("-o", "--output", help="Output file (json or txt)")
@click.option("-q", "--quick", is_flag=True, help="Quick mode (skip deep scans)")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def cli(output, quick, verbose):
    scanner = PyLinpeas(output, quick, verbose)
    scanner.run()
if __name__ == "__main__":
    cli()
