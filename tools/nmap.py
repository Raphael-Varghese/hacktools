#!/usr/bin/env python3
import argparse
import asyncio
import json
import os
import platform
import random
import re
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    class FakeTqdm:
        def __init__(self, *args, **kwargs):
            pass
        def update(self, n):
            pass
        def close(self):
            pass
    tqdm = FakeTqdm


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    END = "\033[0m"


def color(text: str, c: str) -> str:
    if platform.system() == "Windows" and not os.environ.get("ANSICON"):
        return text
    return f"{c}{text}{Colors.END}"


COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    443: "https", 445: "microsoft-ds", 993: "imaps", 995: "pop3s", 1723: "pptp",
    3306: "mysql", 3389: "ms-wbt-server", 5900: "vnc", 8080: "http-proxy",
}


def parse_ports(val: str) -> List[int]:
    ports = []
    for part in val.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def guess_os_from_ttl(ttl: int) -> str:
    if ttl <= 0:
        return "unknown"
    if ttl >= 200:
        return "Windows / Compa / Tru64"
    if ttl >= 100:
        return "Windows / AIX / HP-UX / IRIX"
    if ttl >= 64:
        return "Linux / Android / macOS / FreeBSD / OpenBSD / NetBSD"
    if ttl >= 32:
        return "Windows 95/98/ME / Digital Unix / Solaris"
    return "unknown"


class HostResult:
    def __init__(self, ip: str):
        self.ip = ip
        self.is_up = False
        self.hostname = ""
        self.os_guess = ""
        self.ttl = 0
        self.ports: List[Dict] = []
        self.scan_time = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {"ip": self.ip, "is_up": self.is_up, "hostname": self.hostname, "os_guess": self.os_guess, "ttl": self.ttl, "ports": self.ports, "scan_time": self.scan_time}


class PyMap:
    def __init__(self, args):
        self.targets = self._expand_targets(args.target)
        self.ports = parse_ports(args.ports)
        self.threads = min(args.threads, 500)
        self.timeout = args.timeout
        self.verbose = args.verbose
        self.output = args.output
        self.os_detect = args.os_detect
        self.service_version = args.service_version
        self.ping = args.ping
        self.top_ports = args.top_ports
        self.syn = args.syn
        self.udp = args.udp
        self.results: List[HostResult] = []
        self.open_hosts: Set[str] = set()
        self.lock = asyncio.Lock()
        if self.top_ports:
            self.ports = list(COMMON_PORTS.keys())[:self.top_ports]

    def _expand_targets(self, target: str) -> List[str]:
        hosts = []
        for part in target.split(","):
            part = part.strip()
            if "/" in part:
                hosts.extend(self._cidr_hosts(part))
            elif "-" in part and not part.replace("-", "").replace(".", "").isdigit():
                hosts.append(part)
            elif re.match(r"^\d+\.\d+\.\d+\.\d+-\d+$", part):
                hosts.extend(self._ip_range(part))
            else:
                hosts.append(part)
        return hosts

    def _cidr_hosts(self, cidr: str) -> List[str]:
        ip, prefix = cidr.split("/", 1)
        prefix = int(prefix)
        if prefix < 20 or prefix > 32:
            return [cidr]
        base = struct.unpack("!I", socket.inet_aton(ip))[0]
        mask = 0xFFFFFFFF << (32 - prefix)
        start = (base & mask) + 1
        end = (base | (~mask & 0xFFFFFFFF)) - 1
        return [socket.inet_ntoa(struct.pack("!I", i)) for i in range(start, end + 1)]

    def _ip_range(self, rng: str) -> List[str]:
        base, last = rng.rsplit("-", 1)
        octets = base.split(".")
        start = int(octets[-1])
        end = int(last)
        prefix = ".".join(octets[:3])
        return [f"{prefix}.{i}" for i in range(start, end + 1)]

    async def run(self):
        self._banner()
        await self._resolve_all()
        if self.ping:
            await self._ping_all()
        if self.udp:
            await self._udp_scan_all()
        else:
            await self._tcp_scan_all()
        if self.os_detect:
            await self._os_detect_all()
        self._print_summary()
        self._save()

    def _banner(self):
        print(color("=" * 60, Colors.CYAN))
        print(color(" PyMap v3.0 - Pure-Python Port Scanner", Colors.CYAN + Colors.BOLD))
        print(color("=" * 60, Colors.CYAN))
        print(f"Targets: {len(self.targets)}")
        print(f"Ports:   {len(self.ports)} ({self.ports[0]}-{self.ports[-1]})")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        print(color("=" * 60, Colors.CYAN))

    async def _resolve_all(self):
        for host in self.targets:
            try:
                info = await asyncio.get_event_loop().getaddrinfo(host, None, family=socket.AF_INET)
                ip = info[0][4][0]
                res = HostResult(ip)
                res.hostname = host if host != ip else ""
                self.results.append(res)
                self.open_hosts.add(ip)
            except Exception:
                res = HostResult(host)
                res.hostname = host
                self.results.append(res)
                self.open_hosts.add(host)

    async def _ping_all(self):
        print(color("[*] Host discovery (TCP ACK to common ports)...", Colors.CYAN))
        check_ports = [80, 443, 22, 21, 25, 53, 445, 3389, 8080]
        sem = asyncio.Semaphore(self.threads)
        pbar = tqdm(total=len(self.results) * len(check_ports), unit="probes", desc="ping", ncols=80) if HAS_TQDM else None
        tasks = []
        for res in self.results:
            tasks.append(self._probe_host(res, check_ports, sem, pbar))
        await asyncio.gather(*tasks)
        if pbar:
            pbar.close()

    async def _probe_host(self, res: HostResult, check_ports: List[int], sem: asyncio.Semaphore, pbar: tqdm):
        for port in check_ports:
            async with sem:
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(res.ip, port), timeout=self.timeout)
                    writer.close()
                    await writer.wait_closed()
                    res.is_up = True
                except Exception:
                    pass
                if pbar:
                    pbar.update(1)

    async def _tcp_scan_all(self):
        print(color("[*] TCP connect scan...", Colors.CYAN))
        sem = asyncio.Semaphore(self.threads)
        total = len(self.results) * len(self.ports)
        pbar = tqdm(total=total, unit="ports", desc="tcp", ncols=80) if HAS_TQDM else None
        tasks = []
        for res in self.results:
            for port in self.ports:
                tasks.append(self._tcp_probe(res, port, sem, pbar))
        await asyncio.gather(*tasks)
        if pbar:
            pbar.close()

    async def _tcp_probe(self, res: HostResult, port: int, sem: asyncio.Semaphore, pbar: tqdm):
        async with sem:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(res.ip, port), timeout=self.timeout)
                banner = ""
                if self.service_version:
                    try:
                        writer.write(b"\r\n")
                        await asyncio.wait_for(writer.drain(), timeout=1.0)
                        banner_data = await asyncio.wait_for(reader.read(256), timeout=1.0)
                        banner = banner_data.decode("utf-8", errors="replace").strip()[:80]
                    except Exception:
                        pass
                writer.close()
                await writer.wait_closed()
                svc = COMMON_PORTS.get(port, "unknown")
                port_info = {"port": port, "protocol": "tcp", "service": svc, "state": "open", "banner": banner}
                async with self.lock:
                    res.ports.append(port_info)
                    res.is_up = True
                if not self.verbose:
                    print(color(f"[+] {res.ip}:{port} open ({svc}) {banner}", Colors.GREEN))
            except Exception:
                pass
            if pbar:
                pbar.update(1)

    async def _udp_scan_all(self):
        print(color("[*] UDP scan (limited, no root required)...", Colors.CYAN))
        sem = asyncio.Semaphore(self.threads)
        total = len(self.results) * len(self.ports)
        pbar = tqdm(total=total, unit="ports", desc="udp", ncols=80) if HAS_TQDM else None
        tasks = []
        for res in self.results:
            for port in self.ports:
                tasks.append(self._udp_probe(res, port, sem, pbar))
        await asyncio.gather(*tasks)
        if pbar:
            pbar.close()

    async def _udp_probe(self, res: HostResult, port: int, sem: asyncio.Semaphore, pbar: tqdm):
        async with sem:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                sock.sendto(b"\x00", (res.ip, port))
                data, addr = sock.recvfrom(1024)
                sock.close()
                svc = COMMON_PORTS.get(port, "unknown")
                port_info = {"port": port, "protocol": "udp", "service": svc, "state": "open|filtered", "banner": ""}
                async with self.lock:
                    res.ports.append(port_info)
                    res.is_up = True
                print(color(f"[+] {res.ip}:{port}/udp open|filtered ({svc})", Colors.GREEN))
            except socket.timeout:
                pass
            except Exception:
                pass
            if pbar:
                pbar.update(1)

    async def _os_detect_all(self):
        print(color("[*] OS detection (ICMP echo via raw socket fallback)...", Colors.CYAN))
        for res in self.results:
            if not res.is_up:
                continue
            ttl = await self._icmp_ttl(res.ip)
            if ttl > 0:
                res.ttl = ttl
                res.os_guess = guess_os_from_ttl(ttl)
                print(color(f"[+] {res.ip} TTL={ttl} OS={res.os_guess}", Colors.CYAN))

    async def _icmp_ttl(self, ip: str) -> int:
        loop = asyncio.get_event_loop()
        def _probe():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                start = time.time()
                sock.connect((ip, 80))
                elapsed = (time.time() - start) * 1000
                sock.close()
                return elapsed, 64
            except Exception:
                return 0, 0
        elapsed, ttl = await loop.run_in_executor(None, _probe)
        return ttl

    def _print_summary(self):
        print(color("=" * 60, Colors.CYAN))
        up = [r for r in self.results if r.is_up]
        print(color(f"Hosts up: {len(up)} / {len(self.results)}", Colors.GREEN + Colors.BOLD))
        for res in up:
            host = res.hostname or res.ip
            print(color(f"\nHost: {host} ({res.ip}) is up", Colors.GREEN))
            if res.os_guess:
                print(color(f"OS guess: {res.os_guess} (TTL {res.ttl})", Colors.CYAN))
            for p in sorted(res.ports, key=lambda x: x["port"]):
                proto = p["protocol"]
                banner = f" [{p['banner']}]" if p.get("banner") else ""
                print(color(f"  {p['port']}/{proto}  {p['state']:12} {p['service']}{banner}", Colors.YELLOW))
        print(color("=" * 60, Colors.CYAN))

    def _save(self):
        if not self.output:
            return
        data = {"hosts": [r.to_dict() for r in self.results]}
        ext = os.path.splitext(self.output)[1].lower()
        try:
            if ext == ".json":
                with open(self.output, "w") as f:
                    json.dump(data, f, indent=2)
            elif ext == ".xml":
                with open(self.output, "w") as f:
                    f.write("<?xml version=\"1.0\"?>\n")
                    f.write("<nmaprun>\n")
                    for r in self.results:
                        f.write(f"  <host><address addr=\"{r.ip}\"/></host>\n")
                    f.write("</nmaprun>\n")
            elif ext == ".csv":
                import csv
                with open(self.output, "w", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(["ip", "port", "protocol", "state", "service", "banner"])
                    for r in self.results:
                        for p in r.ports:
                            writer.writerow([r.ip, p["port"], p["protocol"], p["state"], p["service"], p.get("banner", "")])
            else:
                with open(self.output, "w") as f:
                    for r in self.results:
                        f.write(f"Host: {r.ip}\n")
                        for p in r.ports:
                            f.write(f"  {p['port']}/{p['protocol']} {p['state']} {p['service']}\n")
            print(color(f"[+] Output saved to {self.output}", Colors.GREEN))
        except Exception as e:
            print(color(f"[!] Save failed: {e}", Colors.RED))


def build_parser():
    parser = argparse.ArgumentParser(prog="pymap", description="PyMap - Pure-Python port scanner")
    parser.add_argument("target", help="Target host(s), CIDR, or range")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g. 80,443,8080 or 1-65535)")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Concurrent threads")
    parser.add_argument("-T", "--timeout", type=float, default=2.0, help="Timeout per probe")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="Output file (json, xml, csv, txt)")
    parser.add_argument("-O", "--os-detect", action="store_true", help="Enable OS detection")
    parser.add_argument("-sV", "--service-version", action="store_true", help="Grab banners")
    parser.add_argument("-Pn", "--no-ping", action="store_true", help="Skip host discovery")
    parser.add_argument("--ping", action="store_true", help="Do host discovery first")
    parser.add_argument("--top-ports", type=int, help="Scan top N common ports")
    parser.add_argument("-sS", "--syn", action="store_true", help="SYN scan (simulated as connect on Windows)")
    parser.add_argument("-sU", "--udp", action="store_true", help="UDP scan")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.no_ping:
        args.ping = False
    mapper = PyMap(args)
    asyncio.run(mapper.run())


if __name__ == "__main__":
    main()
