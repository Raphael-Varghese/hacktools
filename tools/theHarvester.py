import asyncio
import click
import dns.resolver
import json
import os
import re
import socket
import sys
import time
import urllib.parse
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
class ResultStore:
    def __init__(self):
        self.emails: Set[str] = set()
        self.hosts: Set[str] = set()
        self.ips: Set[str] = set()
        self.subdomains: Set[str] = set()
        self.urls: Set[str] = set()
        self.people: Set[str] = set()
        self.breaches: Set[str] = set()
        self.asns: Set[str] = set()
        self.lock = asyncio.Lock()
    async def add_email(self, e: str):
        async with self.lock:
            if e and "@" in e:
                self.emails.add(e.lower())
    async def add_host(self, h: str):
        async with self.lock:
            h = h.lower().strip(". ")
            if h and "." in h:
                self.hosts.add(h)
    async def add_ip(self, ip: str):
        async with self.lock:
            ip = ip.strip()
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                self.ips.add(ip)
    async def add_subdomain(self, s: str, domain: str):
        async with self.lock:
            s = s.lower().strip(". ")
            if s and domain in s and s != domain:
                self.subdomains.add(s)
            elif s and s.endswith("." + domain):
                self.subdomains.add(s)
    async def add_url(self, u: str):
        async with self.lock:
            u = u.strip()
            if u.startswith("http"):
                self.urls.add(u)
    async def add_person(self, p: str):
        async with self.lock:
            p = p.strip()
            if len(p) > 2:
                self.people.add(p)
    async def add_breach(self, b: str):
        async with self.lock:
            self.breaches.add(b.strip())
    async def add_asn(self, a: str):
        async with self.lock:
            a = a.strip().upper()
            if a.startswith("AS"):
                self.asns.add(a)
    def to_dict(self) -> dict:
        return {
            "emails": sorted(self.emails),
            "hosts": sorted(self.hosts),
            "ips": sorted(self.ips),
            "subdomains": sorted(self.subdomains),
            "urls": sorted(self.urls),
            "people": sorted(self.people),
            "breaches": sorted(self.breaches),
            "asns": sorted(self.asns),
        }
class Source:
    def __init__(self, name: str, domain: str, store: ResultStore, limit: int, client: httpx.AsyncClient):
        self.name = name
        self.domain = domain
        self.store = store
        self.limit = limit
        self.client = client
    async def get(self, url: str, headers=None, timeout=30.0):
        try:
            resp = await self.client.get(url, headers=headers, timeout=timeout)
            return resp.status_code, resp.text
        except Exception:
            return 0, ""
    async def run(self):
        raise NotImplementedError
class CrtshSource(Source):
    async def run(self):
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        status, body = await self.get(url, timeout=45.0)
        if status != 200:
            return
        try:
            data = json.loads(body)
            if not isinstance(data, list):
                return
            for entry in data[:self.limit]:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line and self.domain in line:
                        await self.store.add_subdomain(line, self.domain)
                        await self.store.add_host(line)
        except Exception:
            pass
class CertSpotterSource(Source):
    async def run(self):
        url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        status, body = await self.get(url, timeout=45.0)
        if status != 200:
            return
        try:
            data = json.loads(body)
            for entry in data[:self.limit]:
                for name in entry.get("dns_names", []):
                    name = name.strip().lower()
                    if name and self.domain in name:
                        await self.store.add_subdomain(name, self.domain)
                        await self.store.add_host(name)
        except Exception:
            pass
class HackerTargetSource(Source):
    async def run(self):
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        status, body = await self.get(url, timeout=45.0)
        if status != 200 or "error" in body.lower():
            return
        for line in body.splitlines():
            parts = line.split(",")
            if len(parts) >= 2:
                host = parts[0].strip().lower()
                ip = parts[1].strip()
                if host and self.domain in host:
                    await self.store.add_subdomain(host, self.domain)
                    await self.store.add_host(host)
                if ip:
                    await self.store.add_ip(ip)
class ThreatCrowdSource(Source):
    async def run(self):
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
        status, body = await self.get(url, timeout=45.0)
        if status != 200:
            return
        try:
            data = json.loads(body)
            for sub in data.get("subdomains", [])[:self.limit]:
                sub = sub.strip().lower()
                if sub and self.domain in sub:
                    await self.store.add_subdomain(sub, self.domain)
                    await self.store.add_host(sub)
            for e in data.get("emails", [])[:self.limit]:
                await self.store.add_email(e)
            for r in data.get("resolutions", [])[:self.limit]:
                ip = r.get("ip", "")
                if ip:
                    await self.store.add_ip(ip)
        except Exception:
            pass
class UrlscanSource(Source):
    async def run(self):
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
        status, body = await self.get(url, timeout=45.0)
        if status != 200:
            return
        try:
            data = json.loads(body)
            for result in data.get("results", [])[:self.limit]:
                page = result.get("page", {})
                domain = page.get("domain", "").lower()
                ip = page.get("ip", "")
                url = page.get("url", "")
                if domain and self.domain in domain:
                    await self.store.add_subdomain(domain, self.domain)
                    await self.store.add_host(domain)
                if ip:
                    await self.store.add_ip(ip)
                if url:
                    await self.store.add_url(url)
        except Exception:
            pass
class CommonCrawlSource(Source):
    async def run(self):
        index_url = "https://index.commoncrawl.org/collinfo.json"
        status, body = await self.get(index_url, timeout=45.0)
        if status != 200:
            return
        try:
            indexes = json.loads(body)
            if not indexes:
                return
            latest = indexes[0].get("cdx-api", "")
            if not latest:
                return
            search_url = f"{latest}?url=*.{self.domain}&output=json&fl=url"
            s2, b2 = await self.get(search_url, timeout=60.0)
            if s2 != 200:
                return
            count = 0
            for line in b2.splitlines():
                if count >= self.limit:
                    break
                try:
                    obj = json.loads(line)
                    u = obj.get("url", "")
                    if u:
                        await self.store.add_url(u)
                        parsed = urllib.parse.urlparse(u)
                        host = parsed.hostname
                        if host and self.domain in host:
                            await self.store.add_subdomain(host.lower(), self.domain)
                            await self.store.add_host(host.lower())
                        count += 1
                except Exception:
                    pass
        except Exception:
            pass
class DuckDuckGoSource(Source):
    async def run(self):
        query = f"site:{self.domain}"
        url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        status, body = await self.get(url, timeout=30.0)
        if status != 200:
            return
        pattern = re.compile(r'https?://([^/\s"<>]+)', re.IGNORECASE)
        found = 0
        for match in pattern.findall(body):
            if found >= self.limit:
                break
            host = match.lower().strip()
            if self.domain in host:
                await self.store.add_subdomain(host, self.domain)
                await self.store.add_host(host)
                found += 1
        email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]*" + re.escape(self.domain), re.IGNORECASE)
        for match in email_pattern.findall(body)[:self.limit]:
            await self.store.add_email(match.lower())
class BingSource(Source):
    async def run(self):
        query = f"domain:{self.domain}"
        url = f"https://www.bing.com/search?q={urllib.parse.quote(query)}&count=50"
        headers = {"Accept": "text/html", "Accept-Language": "en-US,en;q=0.9"}
        status, body = await self.get(url, headers=headers, timeout=30.0)
        if status != 200:
            return
        pattern = re.compile(r'https?://([^/\s"<>]+)', re.IGNORECASE)
        found = 0
        for match in pattern.findall(body):
            if found >= self.limit:
                break
            host = match.lower().strip()
            if self.domain in host and not host.startswith("bing."):
                await self.store.add_subdomain(host, self.domain)
                await self.store.add_host(host)
                found += 1
        email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]*" + re.escape(self.domain), re.IGNORECASE)
        for match in email_pattern.findall(body)[:self.limit]:
            await self.store.add_email(match.lower())
class OtxSource(Source):
    async def run(self):
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
        status, body = await self.get(url, timeout=45.0)
        if status != 200:
            return
        try:
            data = json.loads(body)
            for entry in data.get("passive_dns", [])[:self.limit]:
                hostname = entry.get("hostname", "").lower()
                ip = entry.get("address", "")
                if hostname and self.domain in hostname:
                    await self.store.add_subdomain(hostname, self.domain)
                    await self.store.add_host(hostname)
                if ip:
                    await self.store.add_ip(ip)
        except Exception:
            pass
class AnubisSource(Source):
    async def run(self):
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        status, body = await self.get(url, timeout=45.0)
        if status != 200:
            return
        try:
            data = json.loads(body)
            for sub in data[:self.limit]:
                sub = sub.strip().lower()
                if sub and self.domain in sub:
                    await self.store.add_subdomain(sub, self.domain)
                    await self.store.add_host(sub)
        except Exception:
            pass
class BufferOverSource(Source):
    async def run(self):
        url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
        status, body = await self.get(url, timeout=45.0)
        if status != 200:
            return
        try:
            data = json.loads(body)
            for entry in data.get("FDNS_A", [])[:self.limit]:
                if "," in entry:
                    ip, host = entry.split(",", 1)
                    host = host.strip().lower()
                    ip = ip.strip()
                    if host and self.domain in host:
                        await self.store.add_subdomain(host, self.domain)
                        await self.store.add_host(host)
                    if ip:
                        await self.store.add_ip(ip)
        except Exception:
            pass
class RiddlerSource(Source):
    async def run(self):
        url = f"https://riddler.io/search?q=host:{self.domain}&view=data"
        status, body = await self.get(url, timeout=45.0)
        if status != 200:
            return
        try:
            data = json.loads(body)
            for entry in data[:self.limit]:
                host = entry.get("host", "").lower()
                ip = entry.get("ip", "")
                if host and self.domain in host:
                    await self.store.add_subdomain(host, self.domain)
                    await self.store.add_host(host)
                if ip:
                    await self.store.add_ip(ip)
        except Exception:
            pass
class DnsDumpsterSource(Source):
    async def run(self):
        url = "https://dnsdumpster.com/"
        s1, b1 = await self.get(url, timeout=30.0)
        if s1 != 200:
            return
        csrf = ""
        for line in b1.splitlines():
            if "csrfmiddlewaretoken" in line:
                m = re.search(r'value="([^"]+)"', line)
                if m:
                    csrf = m.group(1)
                    break
        if not csrf:
            return
        data = urllib.parse.urlencode({"csrfmiddlewaretoken": csrf, "targetip": self.domain})
        try:
            resp = await self.client.post("https://dnsdumpster.com/", data=data.encode(), headers={"Referer": "https://dnsdumpster.com/", "Cookie": f"csrftoken={csrf}"}, timeout=45.0)
            body = resp.text
            pattern = re.compile(r'>([a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+\b)<', re.IGNORECASE)
            for match in pattern.findall(body):
                host = match.lower().strip()
                if self.domain in host and "dnsdumpster" not in host:
                    await self.store.add_subdomain(host, self.domain)
                    await self.store.add_host(host)
            ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
            for match in ip_pattern.findall(body)[:self.limit]:
                await self.store.add_ip(match)
        except Exception:
            pass
class PyHarvester:
    SOURCES = {
        "crtsh": CrtshSource,
        "certspotter": CertSpotterSource,
        "hackertarget": HackerTargetSource,
        "threatcrowd": ThreatCrowdSource,
        "urlscan": UrlscanSource,
        "commoncrawl": CommonCrawlSource,
        "duckduckgo": DuckDuckGoSource,
        "bing": BingSource,
        "otx": OtxSource,
        "anubis": AnubisSource,
        "bufferover": BufferOverSource,
        "riddler": RiddlerSource,
        "dnsdumpster": DnsDumpsterSource,
        "all": None,
    }
    def __init__(self, domain: str, source_names: List[str], limit: int, dns_lookup: bool, dns_brute: bool, takeover_check: bool, virtual_host_check: bool, output: Optional[str], threads: int, timeout: float, verbose: bool):
        self.domain = domain
        self.source_names = source_names
        self.limit = limit
        self.dns_lookup = dns_lookup
        self.dns_brute = dns_brute
        self.takeover_check = takeover_check
        self.virtual_host_check = virtual_host_check
        self.output = output
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.store = ResultStore()
        self.dns_results: Dict[str, List[str]] = {}
        self.client = httpx.AsyncClient(http2=True, timeout=httpx.Timeout(timeout), follow_redirects=True, limits=httpx.Limits(max_keepalive_connections=50, max_connections=100))
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        await self.client.aclose()
    def _parse_sources(self, s: str) -> List[str]:
        s = s.lower().strip()
        if s == "all":
            return [k for k in self.SOURCES.keys() if k != "all"]
        return [x.strip() for x in s.split(",") if x.strip() in self.SOURCES]
    async def run(self):
        self._banner()
        await self._run_sources()
        if self.dns_lookup:
            await self._do_dns_lookup()
        if self.dns_brute:
            await self._do_dns_brute()
        if self.takeover_check:
            await self._do_takeover_check()
        if self.virtual_host_check:
            await self._do_virtual_host_check()
        self._print_results()
        self._save_output()
        await self.client.aclose()
        console.print("[green][*] Done[/green]")
    def _banner(self):
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
        console.print("[bold cyan] PyHarvester v2.0 - OSINT Gathering Tool[/bold cyan]")
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
        console.print(f"[cyan]Target Domain: {self.domain}[/cyan]")
        console.print(f"[cyan]Sources: {', '.join(self.source_names)}[/cyan]")
        console.print(f"[cyan]Limit: {self.limit}[/cyan]")
        console.print(f"[cyan]Threads: {self.threads}[/cyan]")
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
    async def _run_sources(self):
        pbar = tqdm(total=len(self.source_names), unit="sources", desc="Harvesting", ncols=80) if not self.verbose else None
        sem = asyncio.Semaphore(self.threads)
        async def run_one(name: str):
            cls = self.SOURCES[name]
            if cls is None:
                return
            src = cls(name, self.domain, self.store, self.limit, self.client)
            try:
                await src.run()
                if self.verbose:
                    console.print(f"[green][+] {name} completed[/green]")
            except Exception as e:
                if self.verbose:
                    console.print(f"[red][-] {name} failed: {e}[/red]")
            if pbar:
                pbar.update(1)
        await asyncio.gather(*[run_one(n) for n in self.source_names])
        if pbar:
            pbar.close()
    async def _do_dns_lookup(self):
        console.print("[cyan][*] Performing DNS lookup...[/cyan]")
        hosts = list(self.store.hosts) + list(self.store.subdomains)
        if not hosts:
            hosts = [self.domain]
        hosts = list(dict.fromkeys(hosts))
        pbar = tqdm(total=len(hosts), unit="hosts", desc="DNS", ncols=80) if not self.verbose else None
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        for host in hosts:
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(None, lambda: resolver.resolve(host, "A"))
                ips = [str(r) for r in answers]
                self.dns_results[host] = ips
                for ip in ips:
                    await self.store.add_ip(ip)
            except Exception:
                pass
            if pbar:
                pbar.update(1)
        if pbar:
            pbar.close()
    async def _do_dns_brute(self):
        console.print("[cyan][*] DNS brute force...[/cyan]")
        sublist = ["www", "mail", "ftp", "localhost", "admin", "blog", "shop", "forum", "test", "dev", "api", "portal", "remote", "webmail", "ns1", "ns2", "vpn", "smtp", "webdisk", "cpanel", "whm"]
        found = []
        pbar = tqdm(total=len(sublist), unit="queries", desc="Brute", ncols=80) if not self.verbose else None
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        for sub in sublist:
            host = f"{sub}.{self.domain}"
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(None, lambda h=host: resolver.resolve(h, "A"))
                ips = [str(r) for r in answers]
                found.append((host, ips[0]))
                await self.store.add_subdomain(host, self.domain)
                await self.store.add_host(host)
                await self.store.add_ip(ips[0])
            except Exception:
                pass
            if pbar:
                pbar.update(1)
        if pbar:
            pbar.close()
        if found:
            console.print(f"[green][+] DNS brute found {len(found)} hosts[/green]")
    async def _do_takeover_check(self):
        console.print("[cyan][*] Checking for subdomain takeover...[/cyan]")
        takeover_indicators = {
            "github.io": "GitHub Pages",
            "herokuapp.com": "Heroku",
            "azurewebsites.net": "Azure",
            "cloudapp.azure.com": "Azure",
            "blob.core.windows.net": "Azure Blob",
            "s3.amazonaws.com": "AWS S3",
            "s3-website": "AWS S3",
            "fastly": "Fastly",
            "firebaseapp.com": "Firebase",
            "surge.sh": "Surge.sh",
            "bitbucket.io": "Bitbucket",
            "ghost.io": "Ghost",
            "myshopify.com": "Shopify",
            "readme.io": "Readme",
            "zendesk.com": "Zendesk",
        }
        for host in list(self.store.subdomains):
            for indicator, service in takeover_indicators.items():
                if indicator in host:
                    try:
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(None, lambda h=host: socket.gethostbyname(h))
                    except socket.gaierror:
                        console.print(f"[yellow][!] Potential takeover: {host} -> {service}[/yellow]")
    async def _do_virtual_host_check(self):
        console.print("[cyan][*] Virtual host check...[/cyan]")
        common_names = ["www", "admin", "portal", "mail", "remote", "vpn", "ftp"]
        for name in common_names:
            host = f"{name}.{self.domain}"
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, lambda h=host: socket.gethostbyname(h))
                if self.verbose:
                    console.print(f"[green][+] VHost {host} resolved[/green]")
            except socket.gaierror:
                pass
    def _print_results(self):
        console.print("[bold cyan]\n[*] Harvesting Results:[/bold cyan]")
        if self.store.emails:
            console.print(f"[green]\n[+] Emails ({len(self.store.emails)}):[/green]")
            for e in sorted(self.store.emails):
                console.print(f"    {e}")
        if self.store.subdomains:
            console.print(f"[green]\n[+] Subdomains ({len(self.store.subdomains)}):[/green]")
            for s in sorted(self.store.subdomains):
                ips = self.dns_results.get(s, [])
                ip_str = f" -> {', '.join(ips)}" if ips else ""
                console.print(f"    {s}{ip_str}")
        if self.store.hosts:
            console.print(f"[green]\n[+] Hosts ({len(self.store.hosts)}):[/green]")
            for h in sorted(self.store.hosts):
                ips = self.dns_results.get(h, [])
                ip_str = f" -> {', '.join(ips)}" if ips else ""
                console.print(f"    {h}{ip_str}")
        if self.store.ips:
            console.print(f"[green]\n[+] IPs ({len(self.store.ips)}):[/green]")
            for ip in sorted(self.store.ips):
                console.print(f"    {ip}")
        if self.store.urls:
            console.print(f"[green]\n[+] URLs ({len(self.store.urls)}):[/green]")
            for u in sorted(self.store.urls)[:self.limit]:
                console.print(f"    {u}")
        if self.store.people:
            console.print(f"[green]\n[+] People ({len(self.store.people)}):[/green]")
            for p in sorted(self.store.people):
                console.print(f"    {p}")
        if self.store.asns:
            console.print(f"[green]\n[+] ASNs ({len(self.store.asns)}):[/green]")
            for a in sorted(self.store.asns):
                console.print(f"    {a}")
        total = len(self.store.emails) + len(self.store.hosts) + len(self.store.ips) + len(self.store.subdomains) + len(self.store.urls) + len(self.store.people) + len(self.store.asns)
        console.print(f"[cyan]\n[*] Total findings: {total}[/cyan]")
    def _save_output(self):
        if not self.output:
            return
        data = self.store.to_dict()
        data["domain"] = self.domain
        data["dns_results"] = self.dns_results
        ext = os.path.splitext(self.output)[1].lower()
        try:
            if ext == ".json":
                with open(self.output, "w") as f:
                    json.dump(data, f, indent=2)
            elif ext == ".xml":
                with open(self.output, "w") as f:
                    f.write('<?xml version="1.0"?>\n')
                    f.write("<pyharvester>\n")
                    f.write(f"  <domain>{self.domain}</domain>\n")
                    for k, v in data.items():
                        if isinstance(v, list):
                            f.write(f"  <{k}>\n")
                            for item in v:
                                f.write(f"    <item>{item}</item>\n")
                            f.write(f"  </{k}>\n")
                    f.write("</pyharvester>\n")
            elif ext == ".html":
                with open(self.output, "w") as f:
                    f.write("<html><head><title>PyHarvester Report</title></head><body>\n")
                    f.write(f"<h1>PyHarvester Report for {self.domain}</h1>\n")
                    for k, v in data.items():
                        if isinstance(v, list) and v:
                            f.write(f"<h2>{k.upper()}</h2><ul>\n")
                            for item in v:
                                f.write(f"<li>{item}</li>\n")
                            f.write("</ul>\n")
                    f.write("</body></html>\n")
            elif ext == ".csv":
                with open(self.output, "w") as f:
                    f.write("type,value\n")
                    for k, v in data.items():
                        if isinstance(v, list):
                            for item in v:
                                f.write(f"{k},{item}\n")
            else:
                with open(self.output, "w") as f:
                    f.write(f"PyHarvester Report for {self.domain}\n")
                    f.write("=" * 50 + "\n")
                    for k, v in data.items():
                        if isinstance(v, list) and v:
                            f.write(f"\n{k.upper()}:\n")
                            for item in v:
                                f.write(f"  {item}\n")
            console.print(f"[green][+] Output saved to {self.output}[/green]")
        except Exception as e:
            console.print(f"[red][!] Failed to save output: {e}[/red]")
@click.command()
@click.option("-d", "--domain", required=True, help="Target domain")
@click.option("-b", "--source", default="all", help="Data sources (comma-separated or all)")
@click.option("-l", "--limit", default=500, help="Limit results per source")
@click.option("-r", "--dns-lookup", is_flag=True, help="Perform DNS lookup")
@click.option("-c", "--dns-brute", is_flag=True, help="Perform DNS brute force")
@click.option("-t", "--takeover-check", is_flag=True, help="Check for subdomain takeover")
@click.option("--virtual-host-check", is_flag=True, help="Find virtual hosts")
@click.option("-f", "--output", help="Output file")
@click.option("--threads", default=10, help="Concurrent threads")
@click.option("--timeout", default=30.0, help="Request timeout")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def cli(domain, source, limit, dns_lookup, dns_brute, takeover_check, virtual_host_check, output, threads, timeout, verbose):
    source_names = [x.strip() for x in source.lower().split(",") if x.strip()]
    if "all" in source_names:
        source_names = [k for k in PyHarvester.SOURCES.keys() if k != "all"]
    harvester = PyHarvester(domain, source_names, limit, dns_lookup, dns_brute, takeover_check, virtual_host_check, output, threads, timeout, verbose)
    asyncio.run(harvester.run())
if __name__ == "__main__":
    cli()
