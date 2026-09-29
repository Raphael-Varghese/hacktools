#!/usr/bin/env python3
import base64
import binascii
import click
import json
import math
import os
import re
import string
from datetime import datetime
from typing import Dict, Iterator, List, Optional, Tuple
from rich.console import Console
from rich.table import Table
from tqdm import tqdm
console = Console()
try:
    from git import Repo
    HAS_GIT = True
except ImportError:
    HAS_GIT = False
SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Access Key": re.compile(r"['\"\s]([A-Za-z0-9/+=]{40})['\"\s]"),
    "GitHub Token": re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    "GitHub OAuth": re.compile(r"[0-9a-f]{40}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "Google OAuth": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "Heroku API Key": re.compile(r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"),
    "MailChimp API Key": re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"),
    "Mailgun API Key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "PayPal Braintree": re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    "Picatic API Key": re.compile(r"sk_live_[0-9a-z]{32}"),
    "SendGrid API Key": re.compile(r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}"),
    "Stripe API Key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}", re.IGNORECASE),
    "Stripe Restricted Key": re.compile(r"rk_live_[0-9a-zA-Z]{24,}", re.IGNORECASE),
    "Square Access Token": re.compile(r"sq0atp-[0-9A-Za-z_-]{22}"),
    "Square OAuth Secret": re.compile(r"sq0csp-[0-9A-Za-z_-]{43}"),
    "Twilio API Key": re.compile(r"SK[0-9a-f]{32}"),
    "Twitter Access Token": re.compile(r"[1-9][0-9]+-[0-9a-zA-Z]{40}"),
    "Twitter OAuth": re.compile(r"[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}"),
    "Private Key": re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "SSH DSA Key": re.compile(r"-----BEGIN DSA PRIVATE KEY-----"),
    "SSH EC Key": re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
    "PGP Private Key": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    "Facebook Access Token": re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+"),
    "Firebase URL": re.compile(r".*firebaseio\.com"),
    "JWT Token": re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"),
    "Basic Auth in URL": re.compile(r"[a-zA-Z]{3,10}://[^/\\s:@]*?:[^/\\s:@]*?@[^/\\s:@]*?"),
    "Cloudinary URL": re.compile(r"cloudinary://[0-9]{15}:[0-9A-Za-z_-]+@[0-9A-Za-z_-]+"),
    "Firebase API Key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "LinkedIn Client ID": re.compile(r"(?i)linkedin(.{0,20})?['\"][0-9a-z]{12}['\"]"),
    "LinkedIn Secret": re.compile(r"(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]"),
    "Twilio API SID": re.compile(r"SK[0-9a-f]{32}"),
    "Twilio Account SID": re.compile(r"AC[0-9a-f]{32}"),
    "NPM Token": re.compile(r"npm_[A-Za-z0-9]{36}"),
    "Docker Token": re.compile(r"dckr_pat_[A-Za-z0-9_-]{20,}"),
    "GitLab Token": re.compile(r"glpat-[A-Za-z0-9_-]{20}"),
    "Azure Key": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    "Azure Storage Key": re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net"),
    "MongoDB Connection String": re.compile(r"mongodb(\+srv)?://[^/\\s:@]*?:[^/\\s:@]*?@[^/\\s:@]*?"),
    "PostgreSQL Connection String": re.compile(r"postgres(ql)?://[^/\\s:@]*?:[^/\\s:@]*?@[^/\\s:@]*?"),
    "MySQL Connection String": re.compile(r"mysql://[^/\\s:@]*?:[^/\\s:@]*?@[^/\\s:@]*?"),
    "Redis Connection String": re.compile(r"redis://[^/\\s:@]*?:[^/\\s:@]*?@[^/\\s:@]*?"),
    "AMQP Connection String": re.compile(r"amqp://[^/\\s:@]*?:[^/\\s:@]*?@[^/\\s:@]*?"),
    "SMTP Password": re.compile(r"(?i)(smtp(_)?(password|pass|passwd|pwd))(.{0,20})?['\"].{4,120}['\"]"),
    "LDAP Password": re.compile(r"(?i)(ldap(_)?(password|pass|passwd|pwd))(.{0,20})?['\"].{4,120}['\"]"),
    "Database Password": re.compile(r"(?i)(db(_)?(password|pass|passwd|pwd))(.{0,20})?['\"].{4,120}['\"]"),
    "Secret Key": re.compile(r"(?i)(secret(_)?(key|token|string))(.{0,20})?['\"].{4,120}['\"]"),
    "API Key Generic": re.compile(r"(?i)(api(_)?(key|token|secret))(.{0,20})?['\"][0-9a-zA-Z_-]{16,64}['\"]"),
    "Password Assignment": re.compile(r"(?i)(password|passwd|pwd)\s*=\s*['\"].{4,120}['\"]"),
    "Connection String": re.compile(r"(?i)(connectionstring|connection_string)\s*=\s*['\"].{10,200}['\"]"),
    "Bearer Token": re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.]+"),
    "OAuth Token": re.compile(r"[a-zA-Z0-9_-]*token[a-zA-Z0-9_-]*\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]"),
    "Base64 High Entropy": re.compile(r"['\"][A-Za-z0-9+/]{40,}={0,2}['\"]"),
    "Hex High Entropy": re.compile(r"['\"][a-f0-9]{40,}['\"]"),
    "URL with Password": re.compile(r"[a-zA-Z]{3,10}://[^:]+:[^@]+@"),
    "Generic Secret": re.compile(r"(?i)(secret|token|key|password|passwd|pwd|api_key|apikey|access_token|auth_token)\s*[:=]\s*['\"][^'\"]{8,64}['\"]"),
}
EXCLUDED_PATHS = [
    ".git", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache",
    "venv", ".venv", "env", "dist", "build", ".egg-info", ".tox",
    ".idea", ".vscode", "target", "vendor", "bin", "obj", "out",
    ".next", ".nuxt", ".output", ".parcel-cache", ".grunt", ".gulp",
    "coverage", ".coverage", "htmlcov", "site-packages",
]
EXCLUDED_EXTENSIONS = [
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".sqlite", ".db", ".mdb", ".accdb",
    ".pyc", ".pyo", ".class", ".o", ".obj", ".elf",
    ".min.js", ".min.css", ".map",
]
class Finding:
    def __init__(self, detector: str, path: str, line: int, commit: str, text: str, raw: str):
        self.detector = detector
        self.path = path
        self.line = line
        self.commit = commit
        self.text = text
        self.raw = raw
        self.time = datetime.now().isoformat()
    def to_dict(self) -> dict:
        return {"detector": self.detector, "path": self.path, "line": self.line, "commit": self.commit, "text": self.text, "raw": self.raw, "time": self.time}
class PyTruffleHog:
    def __init__(self, path: str, output: Optional[str], regex: bool, entropy: bool, since_commit: Optional[str], max_depth: int, branch: Optional[str], only_verified: bool, json_out: bool, verbose: bool, include_paths: Optional[str], exclude_paths: Optional[str], allow_list: Optional[str]):
        self.path = path
        self.output = output
        self.regex = regex
        self.entropy = entropy
        self.since_commit = since_commit
        self.max_depth = max_depth
        self.branch = branch
        self.only_verified = only_verified
        self.json_out = json_out
        self.verbose = verbose
        self.include_paths = self._load_patterns(include_paths)
        self.exclude_paths = self._load_patterns(exclude_paths)
        self.allow_list = self._load_allow_list(allow_list)
        self.findings: List[Finding] = []
        self.scanned = 0
    def _load_patterns(self, path: Optional[str]) -> List[re.Pattern]:
        if not path or not os.path.exists(path):
            return []
        patterns = []
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(re.compile(line))
        return patterns
    def _load_allow_list(self, path: Optional[str]) -> List[str]:
        if not path or not os.path.exists(path):
            return []
        with open(path, "r") as f:
            return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    def banner(self):
        console.print("[bold #0e6b0e]PyTruffleHog v1.0 - Secret Scanner[/bold #0e6b0e]")
        console.print(f"[cyan]Target: {self.path}[/cyan]")
        console.print(f"[cyan]Regex: {self.regex} | Entropy: {self.entropy}[/cyan]")
        console.print("")
    def should_scan(self, path: str) -> bool:
        for ex in EXCLUDED_PATHS:
            if ex in path.split(os.sep):
                return False
        for ext in EXCLUDED_EXTENSIONS:
            if path.lower().endswith(ext):
                return False
        if self.include_paths:
            if not any(p.search(path) for p in self.include_paths):
                return False
        if self.exclude_paths:
            if any(p.search(path) for p in self.exclude_paths):
                return False
        return True
    def calc_entropy(self, s: str) -> float:
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        return -sum(p * math.log2(p) for p in prob)
    def is_high_entropy(self, s: str, threshold: float = 4.5) -> bool:
        return self.calc_entropy(s) > threshold
    def check_line(self, line: str, path: str, line_no: int, commit: str = "") -> List[Finding]:
        findings = []
        if self.regex:
            for detector, pattern in SECRET_PATTERNS.items():
                for match in pattern.finditer(line):
                    raw = match.group(0)
                    if raw in self.allow_list:
                        continue
                    masked = raw[:4] + "*" * max(0, len(raw) - 8) + raw[-4:] if len(raw) > 8 else "****"
                    findings.append(Finding(detector, path, line_no, commit, masked, raw))
        if self.entropy:
            tokens = re.findall(r"['\"]([A-Za-z0-9+/=_-]{20,})['\"]", line)
            for token in tokens:
                if token in self.allow_list:
                    continue
                if self.is_high_entropy(token):
                    masked = token[:4] + "*" * max(0, len(token) - 8) + token[-4:] if len(token) > 8 else "****"
                    findings.append(Finding("High Entropy", path, line_no, commit, masked, token))
        return findings
    def scan_file(self, path: str, content: str, commit: str = "") -> List[Finding]:
        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            findings.extend(self.check_line(line, path, i, commit))
        return findings
    def scan_directory(self):
        console.print("[bold #0e6b0e][*] Scanning directory...[/bold #0e6b0e]")
        files = []
        for root, _, filenames in os.walk(self.path):
            for f in filenames:
                full = os.path.join(root, f)
                if self.should_scan(full):
                    files.append(full)
        pbar = tqdm(total=len(files), unit="files", desc="scan", ncols=80)
        for f in files:
            try:
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
                findings = self.scan_file(f, content)
                for finding in findings:
                    self.add_finding(finding)
            except Exception:
                pass
            self.scanned += 1
            pbar.update(1)
        pbar.close()
    def scan_git_repo(self):
        if not HAS_GIT:
            console.print("[red][!] GitPython not installed. pip install GitPython[/red]")
            return
        console.print("[bold #0e6b0e][*] Scanning git repository...[/bold #0e6b0e]")
        repo = Repo(self.path)
        commits = list(repo.iter_commits(self.branch or "HEAD", max_count=self.max_depth))
        if self.since_commit:
            commits = [c for c in commits if c.hexsha != self.since_commit]
        pbar = tqdm(total=len(commits), unit="commits", desc="git", ncols=80)
        for commit in commits:
            if commit.parents:
                diffs = commit.parents[0].diff(commit, create_patch=True)
            else:
                diffs = commit.diff(git.NULL_TREE, create_patch=True)
            for diff in diffs:
                path = diff.a_path or diff.b_path or "unknown"
                if not self.should_scan(path):
                    continue
                try:
                    content = diff.diff.decode("utf-8", errors="ignore")
                    for i, line in enumerate(content.splitlines(), 1):
                        if line.startswith("+") or line.startswith("-"):
                            findings = self.check_line(line[1:], path, i, commit.hexsha[:12])
                            for finding in findings:
                                self.add_finding(finding)
                except Exception:
                    pass
            self.scanned += 1
            pbar.update(1)
        pbar.close()
    def add_finding(self, finding: Finding):
        for existing in self.findings:
            if existing.detector == finding.detector and existing.raw == finding.raw and existing.path == finding.path:
                return
        self.findings.append(finding)
        color = "red" if "Key" in finding.detector or "Token" in finding.detector or "Password" in finding.detector or "Secret" in finding.detector else "yellow"
        console.print(f"[{color}][{finding.detector}] {finding.path}:{finding.line} {finding.text}[/{color}]")
    def summary(self):
        console.print("")
        table = Table(title="Summary")
        table.add_column("Detector", style="bold")
        table.add_column("Count", justify="right")
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.detector] = counts.get(f.detector, 0) + 1
        for detector, count in sorted(counts.items(), key=lambda x: -x[1]):
            table.add_row(detector, str(count))
        console.print(table)
        console.print(f"[bold #0e6b0e]Total findings: {len(self.findings)} | Files/commits scanned: {self.scanned}[/bold #0e6b0e]")
    def save(self):
        if not self.output:
            return
        data = {"target": self.path, "findings": [f.to_dict() for f in self.findings]}
        try:
            if self.json_out or self.output.endswith(".json"):
                with open(self.output, "w") as f:
                    json.dump(data, f, indent=2)
            else:
                with open(self.output, "w") as f:
                    for finding in self.findings:
                        f.write(f"[{finding.detector}] {finding.path}:{finding.line} {finding.text}\n")
            console.print(f"[green][+] Saved to {self.output}[/green]")
        except Exception as e:
            console.print(f"[red][!] Save failed: {e}[/red]")
    def run(self):
        self.banner()
        if os.path.isdir(os.path.join(self.path, ".git")):
            self.scan_git_repo()
        elif os.path.isdir(self.path):
            self.scan_directory()
        elif os.path.isfile(self.path):
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            findings = self.scan_file(self.path, content)
            for finding in findings:
                self.add_finding(finding)
        self.summary()
        self.save()
@click.command()
@click.argument("path", required=True)
@click.option("-o", "--output", help="Output file")
@click.option("--regex/--no-regex", default=True, help="Enable regex detectors")
@click.option("--entropy/--no-entropy", default=True, help="Enable entropy analysis")
@click.option("--since-commit", help="Scan commits after this commit hash")
@click.option("--max-depth", default=50, help="Max commits to scan")
@click.option("--branch", help="Branch to scan")
@click.option("--only-verified", is_flag=True, help="Only verified secrets")
@click.option("--json", "json_out", is_flag=True, help="JSON output")
@click.option("-v", "--verbose", is_flag=True, help="Verbose")
@click.option("--include-paths", help="File with include regex patterns")
@click.option("--exclude-paths", help="File with exclude regex patterns")
@click.option("--allow", "allow_list", help="File with allowed secrets")
def cli(path, output, regex, entropy, since_commit, max_depth, branch, only_verified, json_out, verbose, include_paths, exclude_paths, allow_list):
    scanner = PyTruffleHog(path, output, regex, entropy, since_commit, max_depth, branch, only_verified, json_out, verbose, include_paths, exclude_paths, allow_list)
    scanner.run()
if __name__ == "__main__":
    cli()
