#!/usr/bin/env python3
import asyncio
import hashlib
import os
import re
import zlib
from typing import Dict, List, Optional, Tuple
import click
import httpx
from rich.console import Console
from rich.progress import Progress, TaskID
console = Console()
GIT_KNOWN_FILES = [
    "HEAD", "config", "description", "index", "packed-refs", "shallow",
    "info/exclude", "info/refs", "logs/HEAD", "logs/refs/heads/main",
    "logs/refs/heads/master", "logs/refs/remotes/origin/HEAD",
    "objects/info/packs", "objects/info/alternates", "objects/info/http-alternates",
    "refs/heads/main", "refs/heads/master", "refs/remotes/origin/HEAD",
    "refs/remotes/origin/main", "refs/remotes/origin/master",
    "hooks/applypatch-msg.sample", "hooks/commit-msg.sample", "hooks/fsmonitor-watchman.sample",
    "hooks/post-update.sample", "hooks/pre-applypatch.sample", "hooks/pre-commit.sample",
    "hooks/pre-merge-commit.sample", "hooks/pre-push.sample", "hooks/pre-rebase.sample",
    "hooks/pre-receive.sample", "hooks/prepare-commit-msg.sample", "hooks/push-to-checkout.sample",
    "hooks/update.sample",
]
class PyGitDumper:
    def __init__(self, url: str, output: str, jobs: int, retry: int, timeout: float, proxy: Optional[str], verbose: bool, resume: bool):
        self.base_url = url.rstrip("/")
        if not self.base_url.endswith("/.git"):
            self.base_url += "/.git"
        self.output = output
        self.jobs = jobs
        self.retry = retry
        self.timeout = timeout
        self.proxy = proxy
        self.verbose = verbose
        self.resume = resume
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            limits=httpx.Limits(max_keepalive_connections=50, max_connections=100),
            proxy=proxy,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        self.queue: List[str] = []
        self.done: set = set()
        self.objects: Dict[str, str] = {}
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        await self.client.aclose()
    def banner(self):
        console.print("[bold #0e6b0e]PyGitDumper v1.0 - Exposed .git Directory Dumper[/bold #0e6b0e]")
        console.print(f"[cyan]Target: {self.base_url}[/cyan]")
        console.print(f"[cyan]Output: {self.output}[/cyan]")
        console.print(f"[cyan]Workers: {self.jobs}[/cyan]")
        console.print("")
    async def fetch(self, path: str) -> Tuple[int, bytes]:
        url = f"{self.base_url}/{path}"
        for attempt in range(self.retry + 1):
            try:
                r = await self.client.get(url)
                return r.status_code, r.content
            except Exception:
                if attempt == self.retry:
                    return 0, b""
                await asyncio.sleep(0.5 * (attempt + 1))
        return 0, b""
    async def download_file(self, path: str, progress: Progress, task: TaskID):
        if self.resume:
            out_path = os.path.join(self.output, path)
            if os.path.exists(out_path):
                self.done.add(path)
                progress.advance(task)
                return
        status, data = await self.fetch(path)
        if status == 200:
            out_path = os.path.join(self.output, path)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(data)
            self.done.add(path)
            if self.verbose:
                console.print(f"[green][+] {path} ({len(data)} bytes)[/green]")
        else:
            if self.verbose:
                console.print(f"[dim][-] {path} (HTTP {status})[/dim]")
        progress.advance(task)
    def parse_index(self, data: bytes):
        if len(data) < 12:
            return
        signature = data[:4]
        if signature != b"DIRC":
            return
        version = int.from_bytes(data[4:8], "big")
        entries = int.from_bytes(data[8:12], "big")
        offset = 12
        for _ in range(entries):
            if offset + 40 > len(data):
                break
            sha = data[offset + 40:offset + 60].hex()
            if sha:
                self.objects[sha] = f"objects/{sha[:2]}/{sha[2:]}"
            offset += 62
            while offset < len(data) and data[offset] != 0:
                offset += 1
            offset += 1
            while offset % 8 != 0:
                offset += 1
    def parse_packed_refs(self, data: bytes):
        text = data.decode("utf-8", errors="ignore")
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                sha = parts[0]
                if re.match(r"^[a-f0-9]{40}$", sha):
                    self.objects[sha] = f"objects/{sha[:2]}/{sha[2:]}"
    def parse_refs(self, data: bytes):
        text = data.decode("utf-8", errors="ignore")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(":")
            if len(parts) == 2:
                sha = parts[1].strip()
                if re.match(r"^[a-f0-9]{40}$", sha):
                    self.objects[sha] = f"objects/{sha[:2]}/{sha[2:]}"
    def parse_pack_file(self, data: bytes) -> List[str]:
        shas = []
        try:
            idx = data.find(b"PACK")
            if idx >= 0:
                pass
        except Exception:
            pass
        for match in re.finditer(rb"[a-f0-9]{40}", data):
            shas.append(match.group().decode())
        return shas
    def decompress_object(self, path: str, data: bytes) -> bytes:
        try:
            return zlib.decompress(data)
        except Exception:
            return b""
    def extract_shas_from_object(self, data: bytes):
        text = data.decode("utf-8", errors="ignore")
        for match in re.finditer(r"[a-f0-9]{40}", text):
            sha = match.group()
            self.objects[sha] = f"objects/{sha[:2]}/{sha[2:]}"
    async def discover_objects(self):
        console.print("[bold #0e6b0e][*] Discovering objects...[/bold #0e6b0e]")
        status, data = await self.fetch("index")
        if status == 200:
            self.parse_index(data)
            console.print(f"[green][+] Parsed index: {len(self.objects)} objects[/green]")
        status, data = await self.fetch("packed-refs")
        if status == 200:
            self.parse_packed_refs(data)
        for ref in ["HEAD", "refs/heads/main", "refs/heads/master", "refs/remotes/origin/HEAD"]:
            status, data = await self.fetch(ref)
            if status == 200:
                text = data.decode("utf-8", errors="ignore").strip()
                if text.startswith("ref:"):
                    ref_path = text[4:].strip()
                    status2, data2 = await self.fetch(ref_path)
                    if status2 == 200:
                        sha = data2.decode("utf-8", errors="ignore").strip()
                        if re.match(r"^[a-f0-9]{40}$", sha):
                            self.objects[sha] = f"objects/{sha[:2]}/{sha[2:]}"
                elif re.match(r"^[a-f0-9]{40}$", text):
                    sha = text
                    self.objects[sha] = f"objects/{sha[:2]}/{sha[2:]}"
        status, data = await self.fetch("objects/info/packs")
        if status == 200:
            text = data.decode("utf-8", errors="ignore")
            for line in text.splitlines():
                if line.startswith("P "):
                    pack_hash = line[2:].strip()
                    self.objects[pack_hash] = f"objects/pack/pack-{pack_hash}.pack"
                    self.queue.append(f"objects/pack/pack-{pack_hash}.idx")
        status, data = await self.fetch("logs/HEAD")
        if status == 200:
            text = data.decode("utf-8", errors="ignore")
            for match in re.finditer(r"[a-f0-9]{40}", text):
                sha = match.group()
                self.objects[sha] = f"objects/{sha[:2]}/{sha[2:]}"
        for sha, obj_path in list(self.objects.items()):
            self.queue.append(obj_path)
    async def recursive_object_fetch(self, progress: Progress, task: TaskID):
        visited = set()
        iteration = 0
        while self.queue and iteration < 20:
            iteration += 1
            batch = []
            for path in self.queue:
                if path not in visited:
                    visited.add(path)
                    batch.append(path)
            self.queue = []
            if not batch:
                break
            sem = asyncio.Semaphore(self.jobs)
            async def fetch_one(path: str):
                status, data = await self.fetch(path)
                if status == 200:
                    out_path = os.path.join(self.output, path)
                    os.makedirs(os.path.dirname(out_path), exist_ok=True)
                    with open(out_path, "wb") as f:
                        f.write(data)
                    decompressed = self.decompress_object(path, data)
                    if decompressed:
                        self.extract_shas_from_object(decompressed)
                        for sha in re.findall(r"[a-f0-9]{40}", decompressed.decode("utf-8", errors="ignore")):
                            obj_path = f"objects/{sha[:2]}/{sha[2:]}"
                            if obj_path not in visited:
                                self.queue.append(obj_path)
                    progress.advance(task)
            await asyncio.gather(*[fetch_one(p) for p in batch])
            for sha, obj_path in list(self.objects.items()):
                if obj_path not in visited:
                    self.queue.append(obj_path)
    async def run(self):
        self.banner()
        os.makedirs(self.output, exist_ok=True)
        await self.discover_objects()
        known = [f for f in GIT_KNOWN_FILES if f not in self.done]
        total = len(known) + len(self.objects)
        from rich.progress import TextColumn, BarColumn, MofNCompleteColumn
        with Progress(
            TextColumn("[bold #0e6b0e]{task.description}[/bold #0e6b0e]"),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Dumping .git", total=total)
            sem = asyncio.Semaphore(self.jobs)
            async def dl(path: str):
                await self.download_file(path, progress, task)
            await asyncio.gather(*[dl(f) for f in known])
            await self.recursive_object_fetch(progress, task)
        console.print(f"\n[bold #0e6b0e]Done. Downloaded {len(self.done)} files to {self.output}[/bold #0e6b0e]")
@click.command()
@click.argument("url", required=True)
@click.argument("output", required=True)
@click.option("-j", "--jobs", default=10, help="Concurrent workers")
@click.option("-r", "--retry", default=3, help="Retry attempts")
@click.option("-t", "--timeout", default=30.0, help="Request timeout")
@click.option("--proxy", help="Proxy URL")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--resume", is_flag=True, help="Resume partial download")
def cli(url, output, jobs, retry, timeout, proxy, verbose, resume):
    dumper = PyGitDumper(url, output, jobs, retry, timeout, proxy, verbose, resume)
    asyncio.run(dumper.run())
if __name__ == "__main__":
    cli()
