import asyncio
import base64
import click
import dns.resolver
import json
import os
import random
import re
import socket
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
import httpx
from rich.console import Console
from rich.table import Table
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


def read_wordlist(path: str):
    if path == "-":
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith("#"):
                yield line
    else:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    yield line


def count_words(path: str) -> int:
    if path == "-":
        return 0
    try:
        with open(path, "rb") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def parse_codes(val: Optional[str]) -> Optional[Set[int]]:
    if not val:
        return None
    out = set()
    for part in val.split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = part.split("-")
                for c in range(int(a), int(b) + 1):
                    out.add(c)
            except ValueError:
                pass
        else:
            try:
                out.add(int(part))
            except ValueError:
                pass
    return out if out else None


def parse_headers(hdrs: Tuple[str, ...]) -> Dict[str, str]:
    out = {}
    for h in hdrs:
        if ":" in h:
            k, v = h.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def build_client(proxy: Optional[str], timeout: float, verify: bool) -> httpx.AsyncClient:
    limits = httpx.Limits(max_keepalive_connections=50, max_connections=100)
    transport = None
    if proxy:
        transport = httpx.AsyncHTTPTransport(limits=limits, proxy=proxy)
    return httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout),
        verify=verify,
        http2=True,
        follow_redirects=False,
    )


class Result:
    def __init__(self, word: str, status: int = 0, length: int = 0, location: str = "", url: str = "", extra: str = ""):
        self.word = word
        self.status = status
        self.length = length
        self.location = location
        self.url = url
        self.extra = extra
        self.time = now()

    def to_dict(self) -> dict:
        return {"word": self.word, "status": self.status, "length": self.length, "location": self.location, "url": self.url, "extra": self.extra, "time": self.time}


class BaseScanner:
    def __init__(self, wordlist: str, threads: int, timeout: float, proxy: Optional[str], no_tls_verify: bool, quiet: bool, output: Optional[str], verbose: bool):
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.no_tls_verify = no_tls_verify
        self.quiet = quiet
        self.output = output
        self.verbose = verbose
        self.found: List[Result] = []
        self.start_time = time.time()
        self.lock = asyncio.Lock()
        self.client = None

    async def __aenter__(self):
        self.client = build_client(self.proxy, self.timeout, not self.no_tls_verify)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.client:
            await self.client.aclose()

    def print_banner(self, mode: str, **kwargs):
        if self.quiet:
            return
        console.print(f"[cyan]{'=' * 60}[/cyan]")
        console.print(f"[bold cyan] PyBuster v3.0 - {mode}[/bold cyan]")
        console.print(f"[cyan]{'=' * 60}[/cyan]")
        for k, v in kwargs.items():
            console.print(f"[cyan]{k:12}: {v}[/cyan]")
        console.print(f"[cyan]{'=' * 60}[/cyan]")

    def should_report(self, status: int, length: int = 0, positive: Optional[Set[int]] = None, negative: Optional[Set[int]] = None, exclude_len: Optional[Set[int]] = None) -> bool:
        if exclude_len and length in exclude_len:
            return False
        if negative and status in negative:
            return False
        if positive:
            return status in positive
        return status in (200, 201, 204, 301, 302, 307, 401, 403, 405, 500)

    def add_result(self, res: Result):
        self.found.append(res)
        color = "green"
        if res.status >= 500:
            color = "red"
        elif res.status == 403:
            color = "yellow"
        elif res.status in (301, 302, 307):
            color = "blue"
        loc = f" -> {res.location}" if res.location else ""
        extra = f" {res.extra}" if res.extra else ""
        console.print(f"[{color}]{res.status:3} | {res.length:8} | {res.url or res.word}{loc}{extra}[/{color}]")

    def save(self):
        if not self.output:
            return
        ext = os.path.splitext(self.output)[1].lower()
        try:
            if ext == ".json":
                with open(self.output, "w") as f:
                    json.dump({"results": [r.to_dict() for r in self.found]}, f, indent=2)
            else:
                with open(self.output, "w") as f:
                    for r in self.found:
                        f.write(f"{r.url or r.word} | {r.status} | {r.length}\n")
            console.print(f"[green][+] Output saved to {self.output}[/green]")
        except Exception as e:
            console.print(f"[red][!] Failed to write output: {e}[/red]")

    def summary(self):
        elapsed = time.time() - self.start_time
        if not self.quiet:
            console.print(f"[cyan]{'=' * 60}[/cyan]")
            console.print(f"[green][+] Finished in {elapsed:.2f}s | Found: {len(self.found)}[/green]")
            console.print(f"[cyan]{'=' * 60}[/cyan]")


class DirScanner(BaseScanner):
    def __init__(self, url: str, wordlist: str, extensions: List[str], add_slash: bool, discover_backup: bool, follow_redirect: bool, status_codes: Optional[str], blacklist: Optional[str], exclude_length: Optional[str], headers: Dict[str, str], cookies: Optional[str], useragent: Optional[str], random_agent: bool, auth: Optional[str], proxy: Optional[str], threads: int, timeout: float, no_tls_verify: bool, quiet: bool, output: Optional[str], verbose: bool, method: str = "GET", body: Optional[str] = None):
        super().__init__(wordlist, threads, timeout, proxy, no_tls_verify, quiet, output, verbose)
        self.base_url = url.rstrip("/")
        self.extensions = extensions
        self.add_slash = add_slash
        self.discover_backup = discover_backup
        self.follow_redirect = follow_redirect
        self.positive = parse_codes(status_codes)
        self.negative = parse_codes(blacklist)
        self.exclude_len = parse_codes(exclude_length)
        self.headers = headers
        self.cookies = cookies
        self.useragent = useragent
        self.random_agent = random_agent
        self.auth = auth
        self.method = method
        self.body = body
        if self.auth:
            creds = base64.b64encode(self.auth.encode()).decode()
            self.headers["Authorization"] = f"Basic {creds}"
        if self.cookies:
            self.headers["Cookie"] = self.cookies

    def build_urls(self, word: str) -> List[Tuple[str, str, Optional[str]]]:
        items = [(f"{self.base_url}/{word}", self.method, self.body)]
        if self.add_slash:
            items.append((f"{self.base_url}/{word}/", self.method, self.body))
        for ext in self.extensions:
            items.append((f"{self.base_url}/{word}.{ext}", self.method, self.body))
        if self.discover_backup:
            for suffix in ["~", ".bak", ".backup", ".old", ".swp", ".orig", ".save", ".tmp"]:
                items.append((f"{self.base_url}/{word}{suffix}", self.method, self.body))
        return items

    async def scan_word(self, word: str, sem: asyncio.Semaphore, pbar: tqdm):
        ua = random.choice(USER_AGENTS) if self.random_agent else (self.useragent or USER_AGENTS[0])
        hdrs = dict(self.headers)
        hdrs["User-Agent"] = ua
        async with sem:
            for url, method, body in self.build_urls(word):
                try:
                    resp = await self.client.request(method, url, headers=hdrs, content=body, follow_redirects=self.follow_redirect)
                    status = resp.status_code
                    length = len(resp.content)
                    location = str(resp.headers.get("location", ""))
                    if self.should_report(status, length, self.positive, self.negative, self.exclude_len):
                        await self.lock.acquire()
                        try:
                            self.add_result(Result(word, status, length, location, url))
                        finally:
                            self.lock.release()
                except Exception as e:
                    if self.verbose:
                        await self.lock.acquire()
                        try:
                            console.print(f"[red][!] Error on {url}: {e}[/red]")
                        finally:
                            self.lock.release()
                pbar.update(1)

    async def run(self):
        self.print_banner("Directory Mode", URL=self.base_url, Wordlist=self.wordlist, Threads=self.threads, Extensions=",".join(self.extensions) or "none")
        words = list(read_wordlist(self.wordlist))
        total = len(words) * len(self.build_urls("PROBE"))
        pbar = tqdm(total=total, unit="req", desc="dir", ncols=80, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]") if not self.quiet else None
        sem = asyncio.Semaphore(self.threads)
        tasks = [self.scan_word(w, sem, pbar) for w in words]
        await asyncio.gather(*tasks)
        if pbar:
            pbar.close()
        self.summary()
        self.save()


class DnsScanner(BaseScanner):
    def __init__(self, domain: str, wordlist: str, resolver: Optional[str], show_ips: bool, show_cname: bool, threads: int, timeout: float, proxy: Optional[str], no_tls_verify: bool, quiet: bool, output: Optional[str], verbose: bool):
        super().__init__(wordlist, threads, timeout, proxy, no_tls_verify, quiet, output, verbose)
        self.domain = domain
        self.resolver = resolver
        self.show_ips = show_ips
        self.show_cname = show_cname
        self.dns = dns.resolver.Resolver()
        if resolver:
            self.dns.nameservers = [resolver]
        self.dns.timeout = timeout
        self.dns.lifetime = timeout

    async def scan_word(self, word: str, sem: asyncio.Semaphore, pbar: tqdm):
        target = f"{word}.{self.domain}"
        async with sem:
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(None, lambda: self.dns.resolve(target, "A"))
                ips = [str(r) for r in answers]
                cname = ""
                try:
                    cnames = await loop.run_in_executor(None, lambda: self.dns.resolve(target, "CNAME"))
                    cname = str(list(cnames)[0])
                except Exception:
                    pass
                extra = ""
                if self.show_ips:
                    extra += f" IP: {', '.join(ips)}"
                if self.show_cname and cname:
                    extra += f" CNAME: {cname}"
                await self.lock.acquire()
                try:
                    self.add_result(Result(target, extra=extra.strip(), url=target))
                finally:
                    self.lock.release()
            except dns.resolver.NXDOMAIN:
                pass
            except Exception as e:
                if self.verbose:
                    await self.lock.acquire()
                    try:
                        console.print(f"[red][!] DNS error for {target}: {e}[/red]")
                    finally:
                        self.lock.release()
            pbar.update(1)

    async def run(self):
        self.print_banner("DNS Mode", Domain=self.domain, Wordlist=self.wordlist, Threads=self.threads, Resolver=self.resolver or "default")
        words = list(read_wordlist(self.wordlist))
        pbar = tqdm(total=len(words), unit="hosts", desc="dns", ncols=80) if not self.quiet else None
        sem = asyncio.Semaphore(self.threads)
        tasks = [self.scan_word(w, sem, pbar) for w in words]
        await asyncio.gather(*tasks)
        if pbar:
            pbar.close()
        self.summary()
        self.save()


class FuzzScanner(BaseScanner):
    def __init__(self, url: str, wordlist: str, body: Optional[str], headers: Dict[str, str], status_codes: Optional[str], exclude_length: Optional[str], follow_redirect: bool, proxy: Optional[str], threads: int, timeout: float, no_tls_verify: bool, quiet: bool, output: Optional[str], verbose: bool, method: str = "GET"):
        super().__init__(wordlist, threads, timeout, proxy, no_tls_verify, quiet, output, verbose)
        self.template_url = url
        self.fuzz_body = body
        self.headers = headers
        self.positive = parse_codes(status_codes)
        self.exclude_len = parse_codes(exclude_length)
        self.follow_redirect = follow_redirect
        self.method = method

    async def scan_word(self, word: str, sem: asyncio.Semaphore, pbar: tqdm):
        url = self.template_url.replace("FUZZ", word)
        body = self.fuzz_body.replace("FUZZ", word) if self.fuzz_body else None
        hdrs = {k: v.replace("FUZZ", word) for k, v in self.headers.items()}
        async with sem:
            try:
                resp = await self.client.request(self.method, url, headers=hdrs, content=body, follow_redirects=self.follow_redirect)
                status = resp.status_code
                length = len(resp.content)
                location = str(resp.headers.get("location", ""))
                if self.should_report(status, length, self.positive, None, self.exclude_len):
                    await self.lock.acquire()
                    try:
                        self.add_result(Result(word, status, length, location, url))
                    finally:
                        self.lock.release()
            except Exception as e:
                if self.verbose:
                    await self.lock.acquire()
                    try:
                        console.print(f"[red][!] Error on {url}: {e}[/red]")
                    finally:
                        self.lock.release()
            pbar.update(1)

    async def run(self):
        self.print_banner("Fuzz Mode", URL=self.template_url, Wordlist=self.wordlist, Threads=self.threads, Method=self.method)
        words = list(read_wordlist(self.wordlist))
        pbar = tqdm(total=len(words), unit="req", desc="fuzz", ncols=80) if not self.quiet else None
        sem = asyncio.Semaphore(self.threads)
        tasks = [self.scan_word(w, sem, pbar) for w in words]
        await asyncio.gather(*tasks)
        if pbar:
            pbar.close()
        self.summary()
        self.save()


class VhostScanner(BaseScanner):
    def __init__(self, url: str, domain: Optional[str], append_domain: bool, wordlist: str, exclude_length: Optional[str], follow_redirect: bool, proxy: Optional[str], threads: int, timeout: float, no_tls_verify: bool, quiet: bool, output: Optional[str], verbose: bool):
        super().__init__(wordlist, threads, timeout, proxy, no_tls_verify, quiet, output, verbose)
        self.base_url = url
        self.domain = domain
        self.append_domain = append_domain
        self.exclude_len = parse_codes(exclude_length)
        self.follow_redirect = follow_redirect

    async def scan_word(self, word: str, sem: asyncio.Semaphore, pbar: tqdm):
        host = word
        if self.append_domain and self.domain:
            host = f"{word}.{self.domain}"
        elif self.domain:
            host = f"{word}.{self.domain}"
        async with sem:
            try:
                resp = await self.client.get(self.base_url, headers={"Host": host}, follow_redirects=self.follow_redirect)
                status = resp.status_code
                length = len(resp.content)
                if self.should_report(status, length, None, None, self.exclude_len):
                    await self.lock.acquire()
                    try:
                        self.add_result(Result(host, status, length, url=self.base_url))
                    finally:
                        self.lock.release()
            except Exception as e:
                if self.verbose:
                    await self.lock.acquire()
                    try:
                        console.print(f"[red][!] Error for Host {host}: {e}[/red]")
                    finally:
                        self.lock.release()
            pbar.update(1)

    async def run(self):
        self.print_banner("VHost Mode", URL=self.base_url, Domain=self.domain or "none", Wordlist=self.wordlist, Threads=self.threads)
        words = list(read_wordlist(self.wordlist))
        pbar = tqdm(total=len(words), unit="hosts", desc="vhost", ncols=80) if not self.quiet else None
        sem = asyncio.Semaphore(self.threads)
        tasks = [self.scan_word(w, sem, pbar) for w in words]
        await asyncio.gather(*tasks)
        if pbar:
            pbar.close()
        self.summary()
        self.save()


class S3Scanner(BaseScanner):
    def __init__(self, wordlist: str, region: Optional[str], proxy: Optional[str], threads: int, timeout: float, no_tls_verify: bool, quiet: bool, output: Optional[str], verbose: bool):
        super().__init__(wordlist, threads, timeout, proxy, no_tls_verify, quiet, output, verbose)
        self.region = region

    def build_url(self, word: str) -> str:
        if self.region:
            return f"https://{word}.s3.{self.region}.amazonaws.com"
        return f"https://{word}.s3.amazonaws.com"

    async def scan_word(self, word: str, sem: asyncio.Semaphore, pbar: tqdm):
        url = self.build_url(word)
        async with sem:
            try:
                resp = await self.client.head(url)
                status = resp.status_code
                if status in (200, 301, 302, 307, 403, 404):
                    await self.lock.acquire()
                    try:
                        self.add_result(Result(word, status, url=url))
                    finally:
                        self.lock.release()
            except Exception:
                pass
            pbar.update(1)

    async def run(self):
        self.print_banner("S3 Mode", Wordlist=self.wordlist, Threads=self.threads, Region=self.region or "default")
        words = list(read_wordlist(self.wordlist))
        pbar = tqdm(total=len(words), unit="buckets", desc="s3", ncols=80) if not self.quiet else None
        sem = asyncio.Semaphore(self.threads)
        tasks = [self.scan_word(w, sem, pbar) for w in words]
        await asyncio.gather(*tasks)
        if pbar:
            pbar.close()
        self.summary()
        self.save()


class GcsScanner(BaseScanner):
    def __init__(self, wordlist: str, proxy: Optional[str], threads: int, timeout: float, no_tls_verify: bool, quiet: bool, output: Optional[str], verbose: bool):
        super().__init__(wordlist, threads, timeout, proxy, no_tls_verify, quiet, output, verbose)

    async def scan_word(self, word: str, sem: asyncio.Semaphore, pbar: tqdm):
        url = f"https://storage.googleapis.com/{word}"
        async with sem:
            try:
                resp = await self.client.head(url)
                status = resp.status_code
                if status in (200, 301, 302, 307, 403, 404):
                    await self.lock.acquire()
                    try:
                        self.add_result(Result(word, status, url=url))
                    finally:
                        self.lock.release()
            except Exception:
                pass
            pbar.update(1)

    async def run(self):
        self.print_banner("GCS Mode", Wordlist=self.wordlist, Threads=self.threads)
        words = list(read_wordlist(self.wordlist))
        pbar = tqdm(total=len(words), unit="buckets", desc="gcs", ncols=80) if not self.quiet else None
        sem = asyncio.Semaphore(self.threads)
        tasks = [self.scan_word(w, sem, pbar) for w in words]
        await asyncio.gather(*tasks)
        if pbar:
            pbar.close()
        self.summary()
        self.save()


class TftpScanner(BaseScanner):
    def __init__(self, server: str, wordlist: str, threads: int, timeout: float, quiet: bool, output: Optional[str], verbose: bool):
        super().__init__(wordlist, threads, timeout, None, False, quiet, output, verbose)
        self.server = server

    async def scan_word(self, word: str, sem: asyncio.Semaphore, pbar: tqdm):
        async with sem:
            try:
                loop = asyncio.get_event_loop()
                def _probe():
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.timeout)
                    req = b"\x00\x01" + word.encode() + b"\x00netascii\x00"
                    sock.sendto(req, (self.server, 69))
                    data, addr = sock.recvfrom(512)
                    sock.close()
                    return data
                data = await loop.run_in_executor(None, _probe)
                if data:
                    await self.lock.acquire()
                    try:
                        self.add_result(Result(word, extra=f"Found on {self.server}", url=f"tftp://{self.server}/{word}"))
                    finally:
                        self.lock.release()
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                if self.verbose:
                    await self.lock.acquire()
                    try:
                        console.print(f"[red][!] TFTP error: {e}[/red]")
                    finally:
                        self.lock.release()
            pbar.update(1)

    async def run(self):
        self.print_banner("TFTP Mode", Server=self.server, Wordlist=self.wordlist, Threads=self.threads)
        words = list(read_wordlist(self.wordlist))
        pbar = tqdm(total=len(words), unit="files", desc="tftp", ncols=80) if not self.quiet else None
        sem = asyncio.Semaphore(self.threads)
        tasks = [self.scan_word(w, sem, pbar) for w in words]
        await asyncio.gather(*tasks)
        if pbar:
            pbar.close()
        self.summary()
        self.save()


@click.group()
def cli():
    pass


@cli.command()
@click.option("-u", "--url", required=True, help="Target URL")
@click.option("-w", "--wordlist", required=True, help="Wordlist path")
@click.option("-x", "--extensions", default="", help="Extensions (comma-separated)")
@click.option("-s", "--status-codes", help="Positive status codes")
@click.option("-b", "--blacklist", help="Blacklisted status codes")
@click.option("-l", "--add-slash", is_flag=True, help="Append / to each request")
@click.option("--discover-backup", is_flag=True, help="Discover backup files")
@click.option("-r", "--follow-redirect", is_flag=True, help="Follow redirects")
@click.option("-e", "--expanded", is_flag=True, help="Print full URL")
@click.option("-c", "--cookies", help="Cookies")
@click.option("-H", "--header", multiple=True, help="Custom header")
@click.option("-a", "--useragent", help="User-Agent")
@click.option("-U", "--username", help="Username")
@click.option("-P", "--password", help="Password")
@click.option("-p", "--proxy", help="Proxy URL")
@click.option("--random-agent", is_flag=True, help="Random User-Agent")
@click.option("--exclude-length", help="Exclude by length")
@click.option("-k", "--no-tls-verify", is_flag=True, help="Skip TLS verification")
@click.option("-t", "--threads", default=10, help="Threads")
@click.option("--timeout", default=10.0, help="Timeout")
@click.option("-q", "--quiet", is_flag=True, help="Quiet mode")
@click.option("-o", "--output", help="Output file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose")
@click.option("-X", "--method", default="GET", help="HTTP method")
@click.option("-d", "--body", help="Request body")
def dir(url, wordlist, extensions, status_codes, blacklist, add_slash, discover_backup, follow_redirect, expanded, cookies, header, useragent, username, password, proxy, random_agent, exclude_length, no_tls_verify, threads, timeout, quiet, output, verbose, method, body):
    auth = None
    if username and password:
        auth = f"{username}:{password}"
    ext_list = [e.strip() for e in extensions.split(",") if e.strip()]
    hdrs = parse_headers(header)
    scanner = DirScanner(url, wordlist, ext_list, add_slash, discover_backup, follow_redirect, status_codes, blacklist, exclude_length, hdrs, cookies, useragent, random_agent, auth, proxy, threads, timeout, no_tls_verify, quiet, output, verbose, method, body)
    asyncio.run(scanner.run())


@cli.command()
@click.option("-do", "--domain", required=True, help="Target domain")
@click.option("-w", "--wordlist", required=True, help="Wordlist path")
@click.option("-r", "--resolver", help="DNS resolver")
@click.option("-i", "--show-ips", is_flag=True, help="Show IPs")
@click.option("--show-cname", is_flag=True, help="Show CNAME")
@click.option("-t", "--threads", default=10, help="Threads")
@click.option("--timeout", default=10.0, help="Timeout")
@click.option("-q", "--quiet", is_flag=True, help="Quiet mode")
@click.option("-o", "--output", help="Output file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose")
def dns(domain, wordlist, resolver, show_ips, show_cname, threads, timeout, quiet, output, verbose):
    scanner = DnsScanner(domain, wordlist, resolver, show_ips, show_cname, threads, timeout, None, False, quiet, output, verbose)
    asyncio.run(scanner.run())


@cli.command()
@click.option("-u", "--url", required=True, help="Target URL with FUZZ")
@click.option("-w", "--wordlist", required=True, help="Wordlist path")
@click.option("-b", "--body", help="POST body with FUZZ")
@click.option("-H", "--header", multiple=True, help="Custom header")
@click.option("-s", "--status-codes", help="Positive status codes")
@click.option("--exclude-length", help="Exclude by length")
@click.option("-r", "--follow-redirect", is_flag=True, help="Follow redirects")
@click.option("-k", "--no-tls-verify", is_flag=True, help="Skip TLS verification")
@click.option("-t", "--threads", default=10, help="Threads")
@click.option("--timeout", default=10.0, help="Timeout")
@click.option("-q", "--quiet", is_flag=True, help="Quiet mode")
@click.option("-o", "--output", help="Output file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose")
@click.option("-X", "--method", default="GET", help="HTTP method")
@click.option("-p", "--proxy", help="Proxy URL")
def fuzz(url, wordlist, body, header, status_codes, exclude_length, follow_redirect, no_tls_verify, threads, timeout, quiet, output, verbose, method, proxy):
    hdrs = parse_headers(header)
    scanner = FuzzScanner(url, wordlist, body, hdrs, status_codes, exclude_length, follow_redirect, proxy, threads, timeout, no_tls_verify, quiet, output, verbose, method)
    asyncio.run(scanner.run())


@cli.command()
@click.option("-u", "--url", required=True, help="Target URL")
@click.option("-w", "--wordlist", required=True, help="Wordlist path")
@click.option("--append-domain", is_flag=True, help="Append domain")
@click.option("--domain", help="Base domain")
@click.option("--exclude-length", help="Exclude by length")
@click.option("-r", "--follow-redirect", is_flag=True, help="Follow redirects")
@click.option("-k", "--no-tls-verify", is_flag=True, help="Skip TLS verification")
@click.option("-t", "--threads", default=10, help="Threads")
@click.option("--timeout", default=10.0, help="Timeout")
@click.option("-q", "--quiet", is_flag=True, help="Quiet mode")
@click.option("-o", "--output", help="Output file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose")
@click.option("-p", "--proxy", help="Proxy URL")
def vhost(url, wordlist, append_domain, domain, exclude_length, follow_redirect, no_tls_verify, threads, timeout, quiet, output, verbose, proxy):
    scanner = VhostScanner(url, domain, append_domain, wordlist, exclude_length, follow_redirect, proxy, threads, timeout, no_tls_verify, quiet, output, verbose)
    asyncio.run(scanner.run())


@cli.command()
@click.option("-w", "--wordlist", required=True, help="Wordlist path")
@click.option("--region", help="AWS region")
@click.option("-k", "--no-tls-verify", is_flag=True, help="Skip TLS verification")
@click.option("-t", "--threads", default=10, help="Threads")
@click.option("--timeout", default=10.0, help="Timeout")
@click.option("-q", "--quiet", is_flag=True, help="Quiet mode")
@click.option("-o", "--output", help="Output file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose")
@click.option("-p", "--proxy", help="Proxy URL")
def s3(wordlist, region, no_tls_verify, threads, timeout, quiet, output, verbose, proxy):
    scanner = S3Scanner(wordlist, region, proxy, threads, timeout, no_tls_verify, quiet, output, verbose)
    asyncio.run(scanner.run())


@cli.command()
@click.option("-w", "--wordlist", required=True, help="Wordlist path")
@click.option("-k", "--no-tls-verify", is_flag=True, help="Skip TLS verification")
@click.option("-t", "--threads", default=10, help="Threads")
@click.option("--timeout", default=10.0, help="Timeout")
@click.option("-q", "--quiet", is_flag=True, help="Quiet mode")
@click.option("-o", "--output", help="Output file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose")
@click.option("-p", "--proxy", help="Proxy URL")
def gcs(wordlist, no_tls_verify, threads, timeout, quiet, output, verbose, proxy):
    scanner = GcsScanner(wordlist, proxy, threads, timeout, no_tls_verify, quiet, output, verbose)
    asyncio.run(scanner.run())


@cli.command()
@click.option("-s", "--server", required=True, help="TFTP server")
@click.option("-w", "--wordlist", required=True, help="Wordlist path")
@click.option("-t", "--threads", default=10, help="Threads")
@click.option("--timeout", default=5.0, help="Timeout")
@click.option("-q", "--quiet", is_flag=True, help="Quiet mode")
@click.option("-o", "--output", help="Output file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose")
def tftp(server, wordlist, threads, timeout, quiet, output, verbose):
    scanner = TftpScanner(server, wordlist, threads, timeout, quiet, output, verbose)
    asyncio.run(scanner.run())


if __name__ == "__main__":
    cli()
