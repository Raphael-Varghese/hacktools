import asyncio
import base64
import click
import dns.resolver
import json
import os
import re
import socket
import ssl
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
import httpx
from rich.console import Console
from tqdm import tqdm
console = Console()
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0",
]
def now() -> str:
    return datetime.now().isoformat()
class Finding:
    def __init__(self, host: str, port: int, uri: str, method: str, msg: str, severity: str = "INFO", osvdb: str = ""):
        self.host = host
        self.port = port
        self.uri = uri
        self.method = method
        self.msg = msg
        self.severity = severity
        self.osvdb = osvdb
        self.time = now()
    def to_dict(self) -> dict:
        return {"host": self.host, "port": self.port, "uri": self.uri, "method": self.method, "message": self.msg, "severity": self.severity, "osvdb": self.osvdb, "time": self.time}
class PyNikto:
    def __init__(self, host: str, port: int, ssl: bool, uri: str, threads: int, timeout: float, useragent: str, random_agent: bool, cookies: str, headers: Tuple[str, ...], auth: str, follow_redirects: bool, mutate: Tuple[str, ...], output: str, fmt: str, verbose: bool, nofetch: bool, max_time: int, display: int):
        self.host = host
        self.port = port
        self.ssl = ssl
        self.uri = uri
        self.threads = threads
        self.timeout = timeout
        self.useragent = useragent
        self.random_agent = random_agent
        self.cookies = cookies
        self.headers = self._parse_headers(headers)
        self.auth = auth
        self.follow_redirects = follow_redirects
        self.mutate = list(mutate)
        self.output = output
        self.fmt = fmt
        self.verbose = verbose
        self.nofetch = nofetch
        self.max_time = max_time
        self.display = display
        self.findings: List[Finding] = []
        self.start_time = time.time()
        self.checked: Set[str] = set()
        self.server_header = ""
        self.target_ips: List[str] = []
        self.client = httpx.AsyncClient(http2=True, timeout=httpx.Timeout(timeout), verify=False, follow_redirects=follow_redirects, limits=httpx.Limits(max_keepalive_connections=50, max_connections=100))
        self.base_url = f"{'https' if ssl else 'http'}://{host}:{port}"
        self.lock = asyncio.Lock()
    def _parse_headers(self, hdrs: Tuple[str, ...]) -> Dict[str, str]:
        out = {}
        for h in hdrs:
            if ":" in h:
                k, v = h.split(":", 1)
                out[k.strip()] = v.strip()
        return out
    def _ua(self) -> str:
        if self.random_agent:
            return __import__("random").choice(USER_AGENTS)
        return self.useragent or USER_AGENTS[0]
    async def _req(self, path: str, method: str = "GET", data: bytes = None, extra_headers: Optional[Dict[str, str]] = None) -> Tuple[int, Dict[str, str], str]:
        url = f"{self.base_url}{path}"
        hdrs = dict(self.headers)
        hdrs["User-Agent"] = self._ua()
        hdrs["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        hdrs["Accept-Language"] = "en-US,en;q=0.5"
        hdrs["Accept-Encoding"] = "identity"
        hdrs["Connection"] = "keep-alive"
        if self.cookies:
            hdrs["Cookie"] = self.cookies
        if self.auth:
            hdrs["Authorization"] = f"Basic {base64.b64encode(self.auth.encode()).decode()}"
        if extra_headers:
            hdrs.update(extra_headers)
        try:
            resp = await self.client.request(method, url, headers=hdrs, content=data)
            body = resp.text if not self.nofetch else ""
            return resp.status_code, dict(resp.headers), body
        except httpx.HTTPStatusError as e:
            body = e.response.text if not self.nofetch else ""
            return e.response.status_code, dict(e.response.headers), body
        except Exception as e:
            return 0, {}, str(e)
    async def add(self, uri: str, method: str, msg: str, severity: str = "INFO", osvdb: str = ""):
        async with self.lock:
            f = Finding(self.host, self.port, uri, method, msg, severity, osvdb)
            self.findings.append(f)
            color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "green"}.get(severity, "green")
            console.print(f"[{color}]+ {severity:6} {osvdb:8} {method:6} {uri}: {msg}[/{color}]")
    async def run(self):
        self._banner()
        await self._resolve_target()
        await self._grab_banner()
        checks = self._build_checks()
        if self.max_time and self.max_time > 0:
            checks = checks[:500]
        pbar = tqdm(total=len(checks), unit="checks", desc="Scanning", ncols=80) if not self.verbose else None
        sem = asyncio.Semaphore(self.threads)
        tasks = [self._run_check(c, sem, pbar) for c in checks]
        await asyncio.gather(*tasks)
        if pbar:
            pbar.close()
        await self._post_checks()
        self._save_output()
        self._summary()
        await self.client.aclose()
    def _banner(self):
        console.print("[cyan]" + "-" * 60 + "[/cyan]")
        console.print("[bold cyan] PyNikto v3.0[/bold cyan]")
        console.print(f"[cyan]+ Target IP:          {self.host}[/cyan]")
        console.print(f"[cyan]+ Target Port:        {self.port}[/cyan]")
        console.print(f"[cyan]+ Target URI:         {self.uri}[/cyan]")
        console.print(f"[cyan]+ SSL:                {self.ssl}[/cyan]")
        console.print(f"[cyan]+ Threads:            {self.threads}[/cyan]")
        console.print(f"[cyan]+ Timeout:            {self.timeout}s[/cyan]")
        console.print("[cyan]" + "-" * 60 + "[/cyan]")
    async def _resolve_target(self):
        try:
            loop = asyncio.get_event_loop()
            info = await loop.run_in_executor(None, lambda: socket.gethostbyname_ex(self.host))
            self.target_ips = info[2]
            console.print(f"[green]+ Resolved to: {', '.join(self.target_ips)}[/green]")
        except socket.gaierror:
            self.target_ips = [self.host]
    async def _grab_banner(self):
        status, hdrs, body = await self._req(self.uri)
        self.server_header = hdrs.get("Server", "")
        if self.server_header:
            console.print(f"[green]+ Server: {self.server_header}[/green]")
        powered = hdrs.get("X-Powered-By", "")
        if powered:
            console.print(f"[green]+ X-Powered-By: {powered}[/green]")
        if status == 200 and len(body) > 0:
            title = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE)
            if title:
                console.print(f"[green]+ Title: {title.group(1).strip()}[/green]")
        await self._check_headers(hdrs, self.uri)
    async def _check_headers(self, hdrs: dict, uri: str):
        security_headers = {
            "X-Frame-Options": "Clickjacking protection",
            "X-Content-Type-Options": "MIME-sniffing protection",
            "Content-Security-Policy": "CSP policy",
            "Strict-Transport-Security": "HSTS policy",
            "X-XSS-Protection": "XSS filter",
            "Referrer-Policy": "Referrer policy",
            "Permissions-Policy": "Permissions policy",
        }
        for h, desc in security_headers.items():
            if h not in hdrs:
                await self.add(uri, "GET", f"Missing security header: {h} ({desc})", "LOW", "")
        if hdrs.get("X-Frame-Options", "").upper() in ("ALLOWALL", "*"):
            await self.add(uri, "GET", "X-Frame-Options set to ALLOWALL", "MEDIUM", "")
        server = hdrs.get("Server", "")
        if server and any(x in server.lower() for x in ["apache/2.2", "nginx/1.2", "iis/6", "iis/5"]):
            await self.add(uri, "GET", f"Potentially outdated server: {server}", "MEDIUM", "")
        if "php" in hdrs.get("X-Powered-By", "").lower():
            version = re.search(r"PHP/([\d.]+)", hdrs.get("X-Powered-By", ""), re.IGNORECASE)
            if version:
                ver = version.group(1)
                if ver.startswith("5.") or ver.startswith("4."):
                    await self.add(uri, "GET", f"Outdated PHP version: {ver}", "HIGH", "")
        if hdrs.get("Access-Control-Allow-Origin", "") == "*":
            await self.add(uri, "GET", "CORS allows any origin", "LOW", "")
    def _build_checks(self) -> List[dict]:
        checks = []
        common_paths = [
            "/admin", "/administrator", "/login", "/wp-admin", "/wp-login.php", "/phpmyadmin",
            "/mysql", "/dbadmin", "/admin.php", "/admin/login", "/admin/login.php",
            "/manage", "/manager", "/cms", "/panel", "/backend", "/console",
            "/api", "/api/v1", "/api/v2", "/swagger", "/swagger-ui.html", "/api-docs",
            "/.env", "/.git/config", "/.svn/entries", "/.htaccess", "/.htpasswd",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/backup", "/bak", "/old", "/temp", "/tmp", "/test", "/dev", "/development",
            "/.DS_Store", "/.well-known/security.txt", "/server-status", "/server-info",
            "/trace.axd", "/elmah.axd", "/actuator", "/actuator/health", "/actuator/env",
            "/config.php", "/config.inc", "/configuration.php", "/settings.php",
            "/phpinfo.php", "/info.php", "/_profiler", "/debug", "/.vscode",
            "/.idea", "/composer.json", "/package.json", "/web.config", "/docker-compose.yml",
            "/.github", "/.gitlab-ci.yml", "/Jenkinsfile", "/.env.local", "/.env.production",
            "/.env.development", "/.env.dist", "/.env.sample", "/.env.example",
            "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old",
            "/config.php.bak", "/config.php~", "/config.php.old",
            "/.sql", "/dump.sql", "/database.sql", "/backup.sql", "/db.sql",
            "/.htaccess.bak", "/.htaccess~", "/.htaccess.old",
            "/.ssh", "/id_rsa", "/id_rsa.pub", "/.ssh/id_rsa", "/.ssh/authorized_keys",
            "/.aws", "/.aws/credentials", "/.azure", "/.kube", "/.docker",
            "/cgi-bin", "/scripts", "/bin", "/cgi", "/fcgi-bin",
            "/install", "/setup", "/wizard", "/configure", "/config",
            "/portal", "/user", "/users", "/account", "/accounts",
            "/register", "/signup", "/signin", "/auth", "/oauth",
            "/graphql", "/graphiql", "/playground", "/altair",
            "/wp-content/backup", "/wp-content/uploads", "/wp-content/debug.log",
            "/xmlrpc.php", "/wlwmanifest.xml", "/wp-json", "/wp-json/wp/v2/users",
            "/fckeditor", "/ckeditor", "/tinymce", "/editor", "/upload",
            "/ws_ftp.log", "/wsFTP.log", "/FileZilla.xml", "/sftp-config.json",
            "/.svn", "/.git", "/.hg", "/.bzr", "/CVS",
            "/error", "/errors", "/log", "/logs", "/access.log", "/error.log",
            "/status", "/health", "/ping", "/ready", "/alive",
            "/metrics", "/prometheus", "/stats", "/statistics",
            "/v1", "/v2", "/version", "/versions", "/release", "/releases",
            "/internal", "/private", "/secret", "/hidden", "/restricted",
            "/.bash_history", "/.zsh_history", "/.mysql_history", "/.psql_history",
            "/phpMyAdmin", "/pma", "/myadmin", "/mysqladmin", "/sqladmin",
            "/db", "/database", "/sql", "/php-sql-admin", "/adminer",
            "/laravel", "/symfony", "/django", "/rails", "/spring",
            "/phpunit", "/tests", "/testing", "/phpunit.xml",
            "/.coverage", "/coverage", "/report", "/reports",
            "/.dockerignore", "/Dockerfile", "/docker", "/k8s", "/kubernetes",
            "/.travis.yml", "/.circleci", "/.github/workflows", "/azure-pipelines.yml",
            "/Makefile", "/makefile", "/CMakeLists.txt", "/build",
            "/node_modules", "/vendor", "/bower_components", "/.npmrc",
            "/.bowerrc", "/.jshintrc", "/.eslintrc", "/tsconfig.json",
            "/.htaccess.txt", "/webdav", "/dav", "/_vti_bin", "/_vti_cnf",
            "/MSOffice", "/_layouts", "/_vti_pvt", "/_vti_log",
            "/aspnet_client", "/iisstart.htm", "/welcome.png",
            "/phpmyadmin/scripts/setup.php", "/pma/scripts/setup.php",
            "/admin/scripts/setup.php", "/db/scripts/setup.php",
            "/.envrc", "/.localenv", "/.productionenv", "/.stagingenv",
            "/.htpasswd.txt", "/.htpasswd.bak", "/.htpasswd.old",
            "/passwords.txt", "/pass.txt", "/credentials.txt", "/creds.txt",
            "/secret.key", "/private.key", "/public.key", "/key.pem", "/cert.pem",
            "/id_dsa", "/id_ecdsa", "/id_ed25519", "/.ssh/known_hosts",
            "/.netrc", "/.pypirc", "/.npmrc", "/.gemrc", "/.condarc",
            "/.docker/config.json", "/.kube/config", "/.aws/config", "/.aws/credentials",
            "/.azure/credentials", "/.gcloud", "/.config/gcloud",
            "/.gnupg", "/.pki", "/.cert", "/.certs", "/certificates",
            "/.mozilla", "/.chrome", "/.config", "/.cache",
            "/.local", "/.share", "/.config", "/.themes", "/.icons",
            "/.viminfo", "/.lesshst", "/.wget-hsts", "/.curlrc",
            "/.subversion", "/.gitconfig", "/.git-credentials",
            "/.pip", "/.pipenv", "/.poetry", "/.tox", "/.nox",
            "/.mypy_cache", "/.pytest_cache", "/.hypothesis",
            "/.coverage", "/htmlcov", "/coverage.xml", "/.coveragerc",
            "/.tox", "/.venv", "/venv", "/env", "/virtualenv",
            "/requirements.txt", "/Pipfile", "/Pipfile.lock", "/poetry.lock",
            "/setup.py", "/setup.cfg", "/pyproject.toml",
            "/manage.py", "/app.py", "/main.py", "/wsgi.py", "/asgi.py",
            "/routes.php", "/Router.php", "/index.php", "/home.php",
            "/default.aspx", "/index.asp", "/index.jsp", "/index.cgi",
            "/.well-known", "/.well-known/acme-challenge", "/.well-known/change-password",
            "/.well-known/openid-configuration", "/.well-known/assetlinks.json",
            "/.well-known/dnt-policy.txt", "/.well-known/gpc.json",
            "/.well-known/mta-sts.txt", "/.well-known/terraform-module",
            "/.well-known/traffic-advice", "/.well-known/security.txt",
            "/.well-known/enterpriseregistration", "/.well-known/org.json",
            "/.well-known/pki-validation", "/.well-known/matrix",
            "/.well-known/ni", "/.well-known/posh",
        ]
        for path in common_paths:
            checks.append({"uri": path, "method": "GET", "check": "status", "args": {"ok": [200, 301, 302, 401, 403]}})
        if "1" in self.mutate or "all" in self.mutate:
            for sub in ["www", "admin", "test", "dev", "staging", "api", "mail", "ftp", "cdn"]:
                checks.append({"uri": f"/", "method": "GET", "check": "status", "args": {"ok": [200]}, "host": f"{sub}.{self.host}"})
        if "2" in self.mutate or "all" in self.mutate:
            for subdir in ["/admin", "/test", "/dev", "/staging", "/api", "/v1", "/v2", "/beta", "/old"]:
                checks.append({"uri": subdir, "method": "GET", "check": "status", "args": {"ok": [200, 301, 302, 401, 403]}})
        if "3" in self.mutate or "all" in self.mutate:
            for pg in ["php", "asp", "aspx", "jsp", "cgi", "pl", "py", "rb"]:
                checks.append({"uri": f"/index.{pg}", "method": "GET", "check": "status", "args": {"ok": [200]}})
        if "4" in self.mutate or "all" in self.mutate:
            for pg in ["php", "asp", "aspx", "jsp", "cgi", "pl", "py", "rb"]:
                checks.append({"uri": f"/admin.{pg}", "method": "GET", "check": "status", "args": {"ok": [200, 401, 403]}})
        if "5" in self.mutate or "all" in self.mutate:
            for pg in ["php", "asp", "aspx", "jsp", "cgi", "pl", "py", "rb"]:
                checks.append({"uri": f"/login.{pg}", "method": "GET", "check": "status", "args": {"ok": [200, 401, 403]}})
        if "6" in self.mutate or "all" in self.mutate:
            for ext in [".bak", ".~", ".old", ".orig", ".save", ".swp", ".tmp"]:
                checks.append({"uri": f"/index.php{ext}", "method": "GET", "check": "status", "args": {"ok": [200]}})
        return checks
    async def _run_check(self, check: dict, sem: asyncio.Semaphore, pbar: tqdm):
        uri = check["uri"]
        method = check["method"]
        cid = f"{method}:{uri}"
        async with self.lock:
            if cid in self.checked:
                return
            self.checked.add(cid)
        if self.max_time and (time.time() - self.start_time) > self.max_time:
            return
        async with sem:
            status, hdrs, body = await self._req(uri, method)
            if status == 0:
                if pbar:
                    pbar.update(1)
                return
            if check["check"] == "status":
                ok_codes = check["args"]["ok"]
                if status in ok_codes:
                    if uri in ["/.git/config", "/.svn/entries", "/.env", "/.htpasswd", "/id_rsa", "/.aws/credentials", "/.kube/config"]:
                        await self.add(uri, method, f"Sensitive file exposed ({status})", "HIGH", "")
                    elif "/admin" in uri or "/login" in uri or "/manager" in uri or "/panel" in uri or "/backend" in uri or "/console" in uri:
                        await self.add(uri, method, f"Admin interface found ({status})", "MEDIUM", "")
                    elif uri in ["/phpinfo.php", "/info.php"]:
                        await self.add(uri, method, f"PHP info page exposed ({status})", "HIGH", "")
                    elif uri in ["/server-status", "/server-info"]:
                        await self.add(uri, method, f"Server status page exposed ({status})", "HIGH", "")
                    elif uri in ["/trace.axd", "/elmah.axd"]:
                        await self.add(uri, method, f"Debug/trace handler exposed ({status})", "HIGH", "")
                    elif "/actuator" in uri:
                        await self.add(uri, method, f"Spring Boot actuator endpoint ({status})", "HIGH", "")
                    elif "/.git" in uri or "/.svn" in uri or "/.hg" in uri or "/CVS" in uri:
                        await self.add(uri, method, f"Version control exposed ({status})", "HIGH", "")
                    elif "/backup" in uri.lower() or "/bak" in uri.lower() or uri.endswith(".sql") or ".bak" in uri or ".~" in uri or ".old" in uri:
                        await self.add(uri, method, f"Backup/sensitive file found ({status})", "MEDIUM", "")
                    elif uri in ["/robots.txt", "/sitemap.xml", "/crossdomain.xml"]:
                        await self.add(uri, method, f"Discovery file found ({status})", "INFO", "")
                    elif "/api" in uri or "/swagger" in uri or "/graphql" in uri:
                        await self.add(uri, method, f"API endpoint found ({status})", "INFO", "")
                    elif uri in ["/wp-admin", "/wp-login.php", "/xmlrpc.php"]:
                        await self.add(uri, method, f"WordPress endpoint found ({status})", "INFO", "")
                    elif uri in ["/phpmyadmin", "/pma", "/myadmin", "/adminer"]:
                        await self.add(uri, method, f"Database admin interface found ({status})", "HIGH", "")
                    elif "/config" in uri.lower() or "/settings" in uri.lower() or ".env" in uri:
                        await self.add(uri, method, f"Config file found ({status})", "HIGH", "")
                    elif "/debug" in uri.lower() or "/test" in uri.lower() or "/dev" in uri.lower():
                        await self.add(uri, method, f"Development/debug endpoint found ({status})", "LOW", "")
                    elif "/upload" in uri.lower() or "/editor" in uri.lower() or "/fckeditor" in uri.lower():
                        await self.add(uri, method, f"Upload/editor interface found ({status})", "MEDIUM", "")
                    else:
                        await self.add(uri, method, f"Interesting path found ({status})", "INFO", "")
                if status == 401:
                    await self.add(uri, method, "Authentication required", "INFO", "")
                if status == 403:
                    await self.add(uri, method, "Forbidden (may indicate protected resource)", "INFO", "")
                if status == 405:
                    await self.add(uri, method, "Method not allowed (try other methods)", "INFO", "")
                if status == 500:
                    await self.add(uri, method, "Server error (potential issue)", "LOW", "")
            if body:
                await self._check_content(uri, method, body, hdrs)
            if pbar:
                pbar.update(1)
    async def _check_content(self, uri: str, method: str, body: str, hdrs: dict):
        patterns = [
            (r"(password\s*[=:]\s*['\"][^'\"]+['\"])", "Possible hardcoded password", "MEDIUM"),
            (r"(api[_-]?key\s*[=:]\s*['\"][^'\"]+['\"])", "Possible API key exposure", "HIGH"),
            (r"(aws_access_key_id\s*[=:]\s*['\"][^'\"]+['\"])", "AWS key exposure", "HIGH"),
            (r"(AKIA[0-9A-Z]{16})", "AWS Access Key ID pattern", "HIGH"),
            (r"(private[_-]?key|BEGIN\s+RSA\s+PRIVATE\s+KEY)", "Private key exposure", "HIGH"),
            (r"(DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD)\s*[=:]\s*['\"][^'\"]+['\"]", "Database password exposure", "HIGH"),
            (r"(phpinfo\(\)|PHP Version|zend_version|php_uname)", "PHP info leakage", "MEDIUM"),
            (r"(Debug\s*:\s*true|DEBUG\s*=\s*True)", "Debug mode enabled", "MEDIUM"),
            (r"(Stack trace|Traceback \(most recent call last\)|Exception in thread)", "Stack trace exposure", "MEDIUM"),
            (r"(root:.*?:0:0:)?", "Possible passwd file content", "HIGH"),
            (r"(\/bin\/bash|\/bin\/sh|\/usr\/bin\/python)", "System path leakage", "LOW"),
            (r"(sql syntax|mysql error|postgresql error|ora-\d+|sqlite_error)", "Database error leakage", "MEDIUM"),
            (r"(select\s+.*from|insert\s+into|update\s+.*set|delete\s+from)", "SQL query in response", "LOW"),
            (r"(jquery-[\d.]+|bootstrap\/[\d.]+|angular\/[\d.]+)", "Library version disclosure", "LOW"),
            (r"(wordpress|wp-content|wp-includes)", "WordPress detected", "INFO"),
            (r"(drupal|joomla|magento|prestashop)", "CMS detected", "INFO"),
            (r"(apache tomcat|jboss|weblogic|websphere|glassfish)", "Java app server detected", "INFO"),
            (r"(iis|asp\.net|aspnet|aspxerrorpath)", "IIS/ASP.NET detected", "INFO"),
            (r"(laravel|symfony|django|rails|express|flask)", "Framework detected", "INFO"),
            (r"(swagger|openapi|api-docs|graphql|playground)", "API documentation detected", "INFO"),
            (r"(cPanel|plesk|webmin|virtualmin|directadmin)", "Hosting panel detected", "INFO"),
            (r"(phpMyAdmin|myadmin|adminer|sqladmin)", "DB admin tool detected", "HIGH"),
            (r"(awstats|webalizer|goaccess|matomo|piwik)", "Analytics tool detected", "INFO"),
            (r"(crossdomain\.xml|clientaccesspolicy\.xml)", "Flash/Silverlight policy file", "LOW"),
            (r"(eval\(|system\(|exec\(|passthru\(|shell_exec\()", "Dangerous PHP function", "MEDIUM"),
            (r"(import\s+os|import\s+subprocess|__import__\(['\"]os['\"]\))", "Python system import", "LOW"),
            (r"(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Class\.forName)", "Java code execution", "LOW"),
            (r"(document\.cookie|window\.location|eval\(|innerHTML)", "Client-side JS pattern", "LOW"),
            (r"(aws_secret_access_key|aws_session_token|azure_password|gcp_key)", "Cloud credential pattern", "HIGH"),
            (r"(github_token|gitlab_token|npm_token|docker_token)", "Service token pattern", "HIGH"),
            (r"(jdbc:|mongodb:\/\/|redis:\/\/|postgres:\/\/|mysql:\/\/)", "Connection string", "MEDIUM"),
            (r"(smtp\.|imap\.|pop\.|mail\.|exchange\.|outlook\.)", "Mail server reference", "INFO"),
            (r"(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)", "Internal IP reference", "LOW"),
        ]
        for pattern, msg, severity in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                await self.add(uri, method, f"{msg} in response", severity, "")
                break
        if "text/html" in hdrs.get("Content-Type", ""):
            forms = len(re.findall(r"<form[^>]*>", body, re.IGNORECASE))
            inputs = len(re.findall(r"<input[^>]*>", body, re.IGNORECASE))
            if forms > 0 and self.verbose:
                await self.add(uri, method, f"Found {forms} form(s), {inputs} input(s)", "INFO", "")
    async def _post_checks(self):
        console.print("[cyan][*] Running post-scan checks...[/cyan]")
        methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"]
        for method in methods:
            if method == "GET":
                continue
            status, hdrs, body = await self._req(self.uri, method)
            if status not in (405, 501) and status > 0:
                sev = "INFO" if method in ["POST", "PUT", "DELETE"] else "LOW"
                await self.add(self.uri, method, f"Method {method} allowed ({status})", sev, "")
        status, hdrs, body = await self._req(self.uri, "TRACE")
        if status == 200:
            await self.add(self.uri, "TRACE", "TRACE method enabled (XST possible)", "MEDIUM", "")
        status, hdrs, body = await self._req(self.uri, "OPTIONS")
        if status == 200:
            allow = hdrs.get("Allow", "")
            if allow:
                await self.add(self.uri, "OPTIONS", f"Allowed methods: {allow}", "INFO", "")
        test_paths = ["/", "/../", "/./", "/%2e/", "/%2e%2e/", "/..;/", "/;/"]
        for tp in test_paths:
            status, hdrs, body = await self._req(tp)
            if status == 200 and tp != "/":
                await self.add(tp, "GET", f"Path normalization issue with {tp}", "LOW", "")
        bad_verbs = ["GET / HTTP/1.0", "GET / HTTP/0.9"]
        for bv in bad_verbs:
            try:
                sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
                if self.ssl:
                    sctx = ssl.create_default_context()
                    sctx.check_hostname = False
                    sctx.verify_mode = ssl.CERT_NONE
                    sock = sctx.wrap_socket(sock, server_hostname=self.host)
                sock.sendall(f"{bv}\\r\\nHost: {self.host}\\r\\n\\r\\n".encode())
                resp = sock.recv(4096).decode("utf-8", errors="ignore")
                sock.close()
                if "200" in resp or "HTTP" in resp:
                    await self.add("/", bv.split()[2], f"Server responds to {bv}", "INFO", "")
            except Exception:
                pass
    def _save_output(self):
        if not self.output:
            return
        data = {
            "host": self.host,
            "port": self.port,
            "ssl": self.ssl,
            "uri": self.uri,
            "server": self.server_header,
            "findings": [f.to_dict() for f in self.findings],
        }
        ext = self.fmt or os.path.splitext(self.output)[1].lower().replace(".", "")
        if ext not in ["json", "xml", "html", "csv", "txt"]:
            ext = "txt"
        try:
            if ext == "json":
                with open(self.output, "w") as f:
                    json.dump(data, f, indent=2)
            elif ext == "xml":
                with open(self.output, "w") as f:
                    f.write('<?xml version="1.0"?>\\n')
                    f.write(f'<niktoscan host="{self.host}" port="{self.port}">\\n')
                    for finding in self.findings:
                        f.write(f'  <finding method="{finding.method}" uri="{finding.uri}" severity="{finding.severity}">\\n')
                        esc = finding.msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        f.write(f"    <description>{esc}</description>\\n")
                        f.write("  </finding>\\n")
                    f.write("</niktoscan>\\n")
            elif ext == "html":
                with open(self.output, "w") as f:
                    f.write("<html><head><title>PyNikto Scan Report</title></head><body>\\n")
                    f.write("<h1>PyNikto Scan Report</h1>\\n")
                    f.write(f"<p>Target: {self.host}:{self.port}</p>\\n")
                    f.write(f"<p>Server: {self.server_header}</p>\\n")
                    f.write('<table border="1">\\n')
                    f.write("<tr><th>Severity</th><th>Method</th><th>URI</th><th>Message</th></tr>\\n")
                    for finding in self.findings:
                        esc = finding.msg.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        f.write(f"<tr><td>{finding.severity}</td><td>{finding.method}</td><td>{finding.uri}</td><td>{esc}</td></tr>\\n")
                    f.write("</table></body></html>\\n")
            elif ext == "csv":
                with open(self.output, "w") as f:
                    f.write("severity,method,uri,message,osvdb\\n")
                    for finding in self.findings:
                        f.write(f"{finding.severity},{finding.method},{finding.uri},{finding.msg.replace(',', ';')},{finding.osvdb}\\n")
            else:
                with open(self.output, "w") as f:
                    f.write("PyNikto Scan Report\\n")
                    f.write("=" * 50 + "\\n")
                    f.write(f"Target: {self.host}:{self.port}\\n")
                    f.write(f"Server: {self.server_header}\\n")
                    f.write(f"Findings: {len(self.findings)}\\n")
                    f.write("-" * 50 + "\\n")
                    for finding in self.findings:
                        f.write(f"[{finding.severity}] {finding.method} {finding.uri} {finding.osvdb}: {finding.msg}\\n")
            console.print(f"[green][+] Output saved to {self.output}[/green]")
        except Exception as e:
            console.print(f"[red][!] Failed to save output: {e}[/red]")
    def _summary(self):
        elapsed = time.time() - self.start_time
        high = len([f for f in self.findings if f.severity == "HIGH"])
        med = len([f for f in self.findings if f.severity == "MEDIUM"])
        low = len([f for f in self.findings if f.severity == "LOW"])
        info = len([f for f in self.findings if f.severity == "INFO"])
        console.print("[cyan]" + "-" * 60 + "[/cyan]")
        console.print(f"[bold cyan]+ {len(self.findings)} findings | HIGH: {high} | MEDIUM: {med} | LOW: {low} | INFO: {info}[/bold cyan]")
        console.print(f"[cyan]+ Scan completed in {elapsed:.2f}s[/cyan]")
        console.print("[cyan]" + "-" * 60 + "[/cyan]")
@click.command()
@click.option("-h", "--host", required=True, help="Target host")
@click.option("-p", "--port", default=80, help="Target port")
@click.option("-s", "--ssl", is_flag=True, help="Use SSL")
@click.option("-u", "--uri", default="/", help="Target URI")
@click.option("-t", "--threads", default=10, help="Concurrent threads")
@click.option("-T", "--timeout", default=30.0, help="Request timeout")
@click.option("-a", "--useragent", default="", help="User-Agent string")
@click.option("--random-agent", is_flag=True, help="Random User-Agent")
@click.option("-c", "--cookies", default="", help="Cookie string")
@click.option("-H", "--header", multiple=True, help="Custom header")
@click.option("-id", "--auth", default="", help="Basic auth user:pass")
@click.option("-r", "--follow-redirects", is_flag=True, help="Follow redirects")
@click.option("-m", "--mutate", multiple=True, help="Mutate: 1=subdomains,2=dirs,3=extensions,4=admin,5=login,6=backups,all")
@click.option("-o", "--output", help="Output file")
@click.option("-F", "--format", help="Output format: json,xml,html,csv,txt")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("-n", "--nofetch", is_flag=True, help="Do not fetch response body")
@click.option("-maxtime", "--max-time", default=0, help="Max scan time in seconds")
@click.option("-Display", "--display", default=1, help="Display level")
def cli(host, port, ssl, uri, threads, timeout, useragent, random_agent, cookies, header, auth, follow_redirects, mutate, output, format, verbose, nofetch, max_time, display):
    scanner = PyNikto(host, port, ssl, uri, threads, timeout, useragent, random_agent, cookies, header, auth, follow_redirects, mutate, output, format, verbose, nofetch, max_time, display)
    asyncio.run(scanner.run())
if __name__ == "__main__":
    cli()
