import argparse, ipaddress, json, os, platform, random, re, socket, string, subprocess, sys, threading, time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
try:
    import colorama
    colorama.just_fix_windows_console()
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
try:
    from scapy.all import conf
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
def colorize(text: str, color: str, use_color: bool) -> str:
    if not use_color or (platform.system() == "Windows" and not HAS_COLORAMA):
        return text
    return f"{color}{text}{Colors.ENDC}"
def is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False
class PortInfo:
    __slots__ = ("port", "state", "reason", "service", "version", "banner", "protocol")
    def __init__(self, port: int, state: str, reason: str = "", service: str = "",
                 version: str = "", banner: str = "", protocol: str = "tcp"):
        self.port = port
        self.state = state
        self.reason = reason
        self.service = service
        self.version = version
        self.banner = banner
        self.protocol = protocol
    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state,
            "reason": self.reason,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "protocol": self.protocol,
        }
class HostInfo:
    def __init__(self, ip: str, hostname: str = ""):
        self.ip = ip
        self.hostname = hostname
        self.ports: List[PortInfo] = []
        self.is_up = False
        self.latency_ms: float = 0.0
        self.os_guess: str = ""
        self.os_details: str = ""
        self.trace_route: List[str] = []
        self.status_reason: str = ""
    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "is_up": self.is_up,
            "latency_ms": round(self.latency_ms, 3),
            "os_guess": self.os_guess,
            "os_details": self.os_details,
            "status_reason": self.status_reason,
            "trace_route": self.trace_route,
            "ports": [p.to_dict() for p in self.ports],
        }
class ServiceProbe:
    PROBES: Dict[int, bytes] = {
        21: b"",
        22: b"SSH-2.0-PyMap\\r\\n",
        25: b"EHLO pymap\\r\\n",
        80: b"HEAD / HTTP/1.0\\r\\n\\r\\n",
        110: b"",
        143: b"",
        443: b"HEAD / HTTP/1.0\\r\\n\\r\\n",
        587: b"EHLO pymap\\r\\n",
        8080: b"HEAD / HTTP/1.0\\r\\n\\r\\n",
        9200: b"GET / HTTP/1.0\\r\\n\\r\\n",
    }
    @staticmethod
    def grab(ip: str, port: int, timeout: float) -> Tuple[str, str]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            probe = ServiceProbe.PROBES.get(port, b"")
            if probe:
                sock.send(probe)
                time.sleep(0.2)
            banner = b""
            try:
                banner = sock.recv(1024)
            except Exception:
                pass
            sock.close()
            text = banner.decode("utf-8", errors="ignore").strip()
            version = ServiceProbe._extract_version(text, port)
            return text, version
        except Exception:
            return "", ""
    @staticmethod
    def _extract_version(banner: str, port: int) -> str:
        if not banner:
            return ""
        lower = banner.lower()
        if port == 22 and "ssh" in lower:
            m = re.search(r"ssh-[^\\s]+", banner, re.I)
            return m.group(0) if m else "SSH"
        if port in (80, 443, 8080, 8443) and ("server:" in lower or "http" in lower):
            m = re.search(r"server:\\s*([^\\r\\n]+)", banner, re.I)
            return m.group(1).strip() if m else ""
        if port == 21 and ("ftp" in lower or "220" in banner):
            m = re.search(r"220[-\\s]([^\\r\\n]+)", banner, re.I)
            return m.group(1).strip() if m else "FTP"
        if port in (25, 587) and "smtp" in lower:
            m = re.search(r"220[-\\s]([^\\r\\n]+)", banner, re.I)
            return m.group(1).strip() if m else "SMTP"
        if "mysql" in lower:
            return re.search(r"[^\\r\\n]{1,40}", banner).group(0) if banner else "MySQL"
        if "postgresql" in lower:
            return "PostgreSQL"
        return ""
class ServiceMap:
    COMMON_SERVICES: Dict[int, str] = {
        1: "tcpmux", 5: "rje", 7: "echo", 9: "discard", 11: "systat",
        13: "daytime", 17: "qotd", 18: "msp", 19: "chargen", 20: "ftp-data",
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 37: "time",
        39: "rlp", 42: "nameserver", 43: "whois", 49: "tacacs", 53: "domain",
        67: "dhcps", 68: "dhcpc", 69: "tftp", 70: "gopher", 79: "finger",
        80: "http", 88: "kerberos-sec", 102: "iso-tsap", 110: "pop3",
        111: "rpcbind", 113: "ident", 119: "nntp", 135: "msrpc",
        137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
        143: "imap", 161: "snmp", 162: "snmptrap", 177: "xdmcp",
        179: "bgp", 194: "irc", 201: "at-rtmp", 264: "bgpps", 318: "tsp",
        381: "hp-opac", 383: "hp-alarm-mgr", 443: "https", 445: "microsoft-ds",
        464: "kpasswd5", 497: "retrospect", 500: "isakmp", 512: "exec",
        513: "login", 514: "shell", 515: "printer", 517: "talk",
        518: "ntalk", 520: "efs", 521: "ripng", 525: "timed",
        530: "courier", 531: "conference", 532: "netnews", 540: "uucp",
        548: "afp", 554: "rtsp", 556: "remotefs", 563: "nntps",
        587: "submission", 631: "ipp", 636: "ldaps", 989: "ftps-data",
        990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks",
        1110: "nfsd-status", 1433: "ms-sql-s", 1434: "ms-sql-m",
        1720: "h323q931", 1723: "pptp", 1755: "wms", 1900: "upnp",
        2000: "cisco-sccp", 2001: "dc", 2049: "nfs", 2121: "ccproxy-ftp",
        2717: "pn-requester", 3000: "ppp", 3128: "squid-http",
        3306: "mysql", 3389: "ms-wbt-server", 3986: "mapper-ws_ethd",
        4899: "radmin", 5000: "upnp", 5001: "commplex-link",
        5002: "rfe", 5003: "filemaker", 5004: "avt-profile-1",
        5005: "avt-profile-2", 5432: "postgresql", 5900: "vnc",
        6000: "x11", 6001: "x11", 6379: "redis", 6667: "irc",
        7001: "afs3-callback", 7002: "afs3-prserver", 8080: "http-proxy",
        8443: "https-alt", 8888: "sun-answerbook", 9200: "wap-wsp",
        10000: "snet-sqleen", 27017: "mongodb", 27018: "mongodb",
        27019: "mongodb", 28017: "mongodb",
    }
    @classmethod
    def get_service_name(cls, port: int, protocol: str = "tcp") -> str:
        return cls.COMMON_SERVICES.get(port, "unknown")
class OSSignature:
    @staticmethod
    def guess_os(ttl: int) -> Tuple[str, str]:
        if ttl <= 64:
            return "Linux/Unix", "TTL <= 64 suggests Linux, Unix, or recent macOS"
        elif ttl <= 128:
            return "Windows", "TTL <= 128 suggests Windows"
        elif ttl <= 255:
            return "Cisco/Network", "TTL > 128 suggests network gear or older Unix"
        return "Unknown", ""
class TargetParser:
    @staticmethod
    def parse(targets: List[str], exclude: Optional[List[str]] = None,
              excludefile: Optional[str] = None, randomize: bool = False) -> List[str]:
        ips: Set[str] = set()
        for target in targets:
            ips.update(TargetParser._expand(target))
        excludes: Set[str] = set()
        if exclude:
            for e in exclude:
                excludes.update(TargetParser._expand(e))
        if excludefile and os.path.exists(excludefile):
            with open(excludefile, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        excludes.update(TargetParser._expand(line))
        ips -= excludes
        result = sorted(ips, key=lambda x: ipaddress.ip_address(x))
        if randomize:
            random.shuffle(result)
        return result
    @staticmethod
    def _expand(target: str) -> Set[str]:
        out: Set[str] = set()
        target = target.strip()
        if not target or target.startswith("#"):
            return out
        if "/" in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                for h in network.hosts():
                    out.add(str(h))
                return out
            except ValueError:
                pass
        if "-" in target:
            parts = target.split("-")
            if len(parts) == 2:
                try:
                    start = ipaddress.ip_address(parts[0].strip())
                    end_str = parts[1].strip()
                    if "." not in end_str:
                        base = parts[0].strip().rsplit(".", 1)[0]
                        end = ipaddress.ip_address(f"{base}.{end_str}")
                    else:
                        end = ipaddress.ip_address(end_str)
                    current = int(start)
                    while current <= int(end):
                        out.add(str(ipaddress.ip_address(current)))
                        current += 1
                    return out
                except Exception:
                    pass
        try:
            socket.inet_aton(target)
            out.add(target)
        except socket.error:
            try:
                resolved = socket.gethostbyname(target)
                out.add(resolved)
            except socket.gaierror:
                print(f"[!] Could not resolve {target}")
        return out
class PortParser:
    TOP_PORTS = [
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
        143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
        1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
        10000, 514, 5060, 179, 1026, 2000, 2049, 1110, 2001,
        515, 5432, 1521, 5000, 5600, 7001, 8081, 9200, 5800,
        5050, 6446,
    ]
    @classmethod
    def parse(cls, port_str: str, top_ports: int = 0) -> List[int]:
        if top_ports > 0:
            return cls.TOP_PORTS[:top_ports]
        if port_str == "-" or port_str == "1-65535":
            return list(range(1, 65536))
        ports: Set[int] = set()
        protocol = "tcp"
        for part in port_str.split(","):
            part = part.strip()
            if not part:
                continue
            proto_prefix = ""
            if part.startswith("T:") or part.startswith("U:"):
                proto_prefix = part[0]
                part = part[2:]
            if "-" in part:
                try:
                    start, end = part.split("-")
                    for p in range(int(start), int(end) + 1):
                        if 1 <= p <= 65535:
                            ports.add(p)
                except ValueError:
                    pass
            else:
                try:
                    p = int(part)
                    if 1 <= p <= 65535:
                        ports.add(p)
                except ValueError:
                    pass
        return sorted(ports)
class Tracerouter:
    @staticmethod
    def trace(ip: str, max_hops: int = 30, timeout: float = 2.0) -> List[str]:
        route: List[str] = []
        if platform.system() == "Windows":
            try:
                cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), ip]
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=60)
                for line in output.splitlines():
                    m = re.search(r"\\d+\\s+([\\d.]+)", line)
                    if m:
                        hop = m.group(1)
                        if hop not in route:
                            route.append(hop)
            except Exception:
                pass
        else:
            try:
                cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(int(timeout)), ip]
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=60)
                for line in output.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 2 and re.match(r"\\d+\\.", parts[1]):
                        route.append(parts[1])
            except Exception:
                pass
        return route
class PyMap:
    def __init__(self, args):
        self.args = args
        self.use_color = not args.no_color and not args.oA and not args.oN and not args.oG and not args.oX
        self.start_time = time.time()
        self.results: List[HostInfo] = []
        self.lock = threading.Lock()
        self.stats = {"total": 0, "done": 0, "up": 0}
        timing_profiles = {
            0: {"timeout": 5.0, "threads": 10, "delay": 5.0,   "retries": 10},
            1: {"timeout": 3.0, "threads": 20, "delay": 1.5,   "retries": 5},
            2: {"timeout": 2.0, "threads": 50, "delay": 0.4,   "retries": 3},
            3: {"timeout": 1.0, "threads": 100, "delay": 0.0,  "retries": 2},
            4: {"timeout": 0.5, "threads": 200, "delay": 0.0,  "retries": 1},
            5: {"timeout": 0.3, "threads": 300, "delay": 0.0,  "retries": 0},
        }
        t = timing_profiles.get(args.timing, timing_profiles[3])
        self.timeout = args.max_rtt_timeout or t["timeout"]
        self.threads = min(args.max_parallelism or t["threads"], 500)
        self.delay = args.scan_delay or t["delay"]
        self.retries = args.max_retries if args.max_retries is not None else t["retries"]
        if self.threads > 400:
            self.threads = 400
        self.targets = TargetParser.parse(
            args.targets,
            exclude=args.exclude,
            excludefile=args.excludefile,
            randomize=args.randomize_hosts,
        )
        if args.top_ports:
            self.ports = PortParser.parse("", top_ports=args.top_ports)
        else:
            self.ports = PortParser.parse(args.ports)
        self.scan_type = self._determine_scan_type()
    def _warn(self, msg: str):
        print(colorize(f"[!] {msg}", Colors.WARNING, self.use_color))
    def _info(self, msg: str):
        print(colorize(f"[*] {msg}", Colors.OKBLUE, self.use_color))
    def _determine_scan_type(self) -> str:
        scan_type = "connect"
        if self.args.syn:
            scan_type = "syn"
        elif self.args.udp:
            scan_type = "udp"
        elif self.args.ack:
            scan_type = "ack"
        elif self.args.null:
            scan_type = "null"
        elif self.args.fin:
            scan_type = "fin"
        elif self.args.xmas:
            scan_type = "xmas"
        elif self.args.window:
            scan_type = "window"
        elif self.args.maimon:
            scan_type = "maimon"
        elif self.args.cookie_ping:
            scan_type = "cookie"
        elif self.args.init_ping:
            scan_type = "init"
        elif self.args.ip_proto_scan:
            scan_type = "ipproto"
        admin_scans = {"syn", "udp", "ack", "null", "fin", "xmas", "window", "maimon",
                       "cookie", "init", "ipproto"}
        if scan_type in admin_scans:
            if not is_admin():
                self._warn(f"{scan_type.upper()} scan requires admin/root. Falling back to connect scan.")
                scan_type = "connect"
            elif not SCAPY_AVAILABLE:
                self._warn(f"{scan_type.upper()} scan requires scapy. Falling back to connect scan.")
                scan_type = "connect"
        return scan_type
    def _resolve_hostname(self, ip: str) -> str:
        if self.args.n:
            return ""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ""
    def _ping_host(self, ip: str) -> Tuple[bool, float, int]:
        if platform.system() == "Windows":
            cmd = f'ping -n 1 -w {int(self.timeout * 1000)} {ip} > nul 2>&1'
        else:
            cmd = f'ping -c 1 -W {int(self.timeout)} {ip} > /dev/null 2>&1'
        start = time.time()
        ret = os.system(cmd) == 0
        elapsed = (time.time() - start) * 1000
        return ret, elapsed, 0
    def _tcp_connect_scan(self, ip: str, port: int) -> PortInfo:
        for attempt in range(self.retries + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    banner, version = "", ""
                    if self.args.version_detection or self.args.banner:
                        banner, version = ServiceProbe.grab(ip, port, min(self.timeout, 2.0))
                    sock.close()
                    service = ServiceMap.get_service_name(port)
                    return PortInfo(port, "open", reason="syn-ack", service=service,
                                    version=version, banner=banner, protocol="tcp")
                sock.close()
            except Exception:
                pass
            if self.delay > 0:
                time.sleep(self.delay)
        return PortInfo(port, "closed", reason="conn-refused", protocol="tcp")
    def _scan_port(self, ip: str, port: int) -> PortInfo:
        if self.scan_type in ("syn", "udp", "ack", "null", "fin", "xmas", "window", "maimon",
                              "cookie", "init", "ipproto"):
            pass
        return self._tcp_connect_scan(ip, port)
    def _scan_host(self, ip: str) -> HostInfo:
        host = HostInfo(ip)
        if not self.args.n:
            host.hostname = self._resolve_hostname(ip)
        if not self.args.Pn:
            is_up, latency, ttl = self._ping_host(ip)
            host.is_up = is_up
            host.latency_ms = latency
            host.status_reason = "echo-reply" if is_up else "no-response"
            if not is_up and not self.args.open_only:
                if self.args.verbose:
                    self._warn(f"Host {ip} appears down")
                return host
        else:
            host.is_up = True
            host.status_reason = "user-set"
        if self.args.os_detection and ttl > 0:
            host.os_guess, host.os_details = OSSignature.guess_os(ttl)
        if self.args.sn:
            return host
        if self.args.verbose:
            self._info(f"Scanning {ip} ({host.hostname or 'no hostname'})")
        port_threads = min(self.threads, len(self.ports), 200)
        with ThreadPoolExecutor(max_workers=port_threads) as executor:
            future_to_port = {executor.submit(self._scan_port, ip, port): port for port in self.ports}
            for future in as_completed(future_to_port):
                port_info = future.result()
                if port_info.state in ("open", "open|filtered"):
                    host.ports.append(port_info)
                    if self.args.verbose:
                        banner_disp = f" | {port_info.banner[:50]}" if port_info.banner else ""
                        print(colorize(
                            f"  Discovered open port {port_info.port}/tcp on {ip} ({port_info.service}){banner_disp}",
                            Colors.OKGREEN, self.use_color))
        host.ports.sort(key=lambda x: x.port)
        if self.args.traceroute and host.is_up:
            host.trace_route = Tracerouter.trace(ip)
        with self.lock:
            self.stats["done"] += 1
            if host.is_up:
                self.stats["up"] += 1
            if self.stats["total"] > 0 and self.stats["done"] % 10 == 0:
                pct = self.stats["done"] * 100 // self.stats["total"]
                print(colorize(f"[*] Scan progress: {pct}% ({self.stats['done']}/{self.stats['total']})",
                               Colors.OKCYAN, self.use_color))
        return host
    def run(self) -> List[HostInfo]:
        self.stats["total"] = len(self.targets)
        print(colorize("=" * 60, Colors.HEADER, self.use_color))
        print(colorize(" PyMap - Python Network Scanner ", Colors.HEADER + Colors.BOLD, self.use_color))
        print(colorize("=" * 60, Colors.HEADER, self.use_color))
        print(f"Target(s) : {', '.join(self.args.targets[:3])}{'...' if len(self.args.targets) > 3 else ''}")
        print(f"Hosts     : {len(self.targets)}")
        print(f"Ports     : {len(self.ports)}")
        print(f"Scan type : {self.scan_type}")
        print(f"Threads   : {self.threads}")
        print(f"Timeout   : {self.timeout}s")
        print(f"Admin     : {is_admin()}")
        print(f"Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(colorize("=" * 60, Colors.HEADER, self.use_color))
        host_threads = min(self.threads, len(self.targets), 50)  # Limit concurrent host scans
        with ThreadPoolExecutor(max_workers=host_threads) as executor:
            future_to_ip = {executor.submit(self._scan_host, ip): ip for ip in self.targets}
            for future in as_completed(future_to_ip):
                host = future.result()
                self.results.append(host)
        self.results.sort(key=lambda x: ipaddress.ip_address(x.ip))
        self._print_summary()
        return self.results
    def _print_summary(self):
        elapsed = time.time() - self.start_time
        print("\n" + colorize("=" * 60, Colors.HEADER, self.use_color))
        print(colorize(" SCAN RESULTS ", Colors.HEADER + Colors.BOLD, self.use_color))
        print(colorize("=" * 60, Colors.HEADER, self.use_color))
        shown = 0
        for host in self.results:
            if self.args.open_only and not host.ports:
                continue
            if not host.is_up and not host.ports and not self.args.verbose:
                continue
            shown += 1
            status_color = Colors.OKGREEN if host.is_up else Colors.FAIL
            status = "Up" if host.is_up else "Down"
            host_line = f"\\nHost: {host.ip} ({host.hostname or 'unknown'})"
            host_line += f"\\nStatus: {status} ({host.latency_ms:.2f}s latency)"
            print(colorize(host_line, status_color, self.use_color))
            if host.os_guess:
                print(f"OS guess: {host.os_guess}")
                if host.os_details:
                    print(f"  Details: {host.os_details}")
            if host.trace_route:
                print(f"TRACEROUTE: {' -> '.join(host.trace_route[:15])}")
            if host.ports:
                print(f"{'PORT':<10} {'STATE':<12} {'SERVICE':<18} {'VERSION'}")
                print("-" * 60)
                for p in host.ports:
                    ver = p.version or p.banner[:30] or ""
                    print(f"{p.port}/{p.protocol:<5} {p.state:<12} {p.service:<18} {ver}")
            elif not self.args.sn:
                print("  All scanned ports on this host are closed or filtered.")
        if shown == 0:
            print("No hosts found up or with open ports.")
        print("\n" + colorize("=" * 60, Colors.HEADER, self.use_color))
        print(f"Scan completed in {elapsed:.2f} seconds ({len(self.targets)} hosts, {len(self.ports)} ports)")
        print(colorize("=" * 60, Colors.HEADER, self.use_color))
    def _to_dict(self) -> dict:
        return {
            "scanner": "pymap",
            "args": " ".join(sys.argv[1:]),
            "start": datetime.now().isoformat(),
            "version": "1.0",
            "hosts": [h.to_dict() for h in self.results],
        }
    def export_json(self, filename: str):
        with open(filename, "w") as f:
            json.dump(self._to_dict(), f, indent=2)
        print(f"[+] Wrote JSON output to {filename}")
    def export_xml(self, filename: str):
        root = ET.Element("nmaprun",
                          {"scanner": "pymap", "args": " ".join(sys.argv[1:]),
                           "start": datetime.now().isoformat()})
        for h in self.results:
            host_elem = ET.SubElement(root, "host", {"ip": h.ip})
            status_elem = ET.SubElement(host_elem, "status", {"state": "up" if h.is_up else "down",
                                                               "reason": h.status_reason})
            if h.hostname:
                ET.SubElement(host_elem, "hostname", {"name": h.hostname})
            if h.os_guess:
                ET.SubElement(host_elem, "osmatch", {"name": h.os_guess, "accuracy": "80"})
            ports_elem = ET.SubElement(host_elem, "ports")
            for p in h.ports:
                port_elem = ET.SubElement(ports_elem, "port", {"protocol": p.protocol, "portid": str(p.port)})
                ET.SubElement(port_elem, "state", {"state": p.state, "reason": p.reason})
                svc = ET.SubElement(port_elem, "service", {"name": p.service})
                if p.version:
                    svc.set("version", p.version)
        tree = ET.ElementTree(root)
        if hasattr(ET, "indent"):
            ET.indent(tree, space="  ", level=0)
        tree.write(filename, encoding="utf-8", xml_declaration=True)
        print(f"[+] Wrote XML output to {filename}")
    def export_grepable(self, filename: str):
        with open(filename, "w") as f:
            f.write(f"# PyMap Grepable Output\\n")
            f.write(f"# Args: {' '.join(sys.argv[1:])}\\n")
            for h in self.results:
                if not h.ports:
                    continue
                ports_str = "/,".join([f"{p.port}/open/{p.protocol}//{p.service}" for p in h.ports])
                f.write(f"Host: {h.ip} ({h.hostname or ''})\\tPorts: {ports_str}\\n")
        print(f"[+] Wrote grepable output to {filename}")
    def export_normal(self, filename: str):
        old_stdout = sys.stdout
        with open(filename, "w") as f:
            sys.stdout = f
            self.use_color = False
            self._print_summary()
        sys.stdout = old_stdout
        self.use_color = not self.args.no_color
        print(f"[+] Wrote normal output to {filename}")
    def export_all(self, base: str):
        self.export_normal(base + ".nmap")
        self.export_xml(base + ".xml")
        self.export_grepable(base + ".gnmap")
        self.export_json(base + ".json")
def positive_int_or_zero(value: str) -> int:
    iv = int(value)
    if iv < 0:
        raise argparse.ArgumentTypeError(f"{value} is not a positive integer")
    return iv
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pymap",
        description="PyMap - An nmap-compatible Python network scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  pymap 192.168.1.0/24
  pymap target.com -p 22,80,443 -sV --open
  pymap 10.0.0.1-50 -p 1-65535 -T4 -oA scan_results
  pymap -iL targets.txt --top-ports 100 -oX output.xml
        """
    )
    parser.add_argument("targets", nargs="*", help="Target hosts/CIDR/ranges")
    parser.add_argument("-iL", dest="input_file", help="Input from list of hosts/networks")
    parser.add_argument("-iR", type=int, dest="random_targets", help="Choose random targets")
    parser.add_argument("--exclude", dest="exclude", nargs="+", help="Exclude hosts/networks")
    parser.add_argument("--excludefile", dest="excludefile", help="Exclude list from file")
    parser.add_argument("--randomize-hosts", dest="randomize_hosts", action="store_true",
                        help="Randomize target scan order")
    parser.add_argument("-sL", dest="list_scan", action="store_true", help="List scan")
    parser.add_argument("-sn", dest="sn", action="store_true", help="Ping scan (no port scan)")
    parser.add_argument("-Pn", dest="Pn", action="store_true", help="Treat all hosts as online")
    parser.add_argument("-PS", dest="syn_ping", nargs="?", const="80", help="TCP SYN discovery")
    parser.add_argument("-PA", dest="ack_ping", nargs="?", const="80", help="TCP ACK discovery")
    parser.add_argument("-PU", dest="udp_ping", nargs="?", const="40125", help="UDP discovery")
    parser.add_argument("-PY", dest="sctp_ping", nargs="?", const="80", help="SCTP discovery")
    parser.add_argument("-PE", dest="icmp_echo", action="store_true", help="ICMP echo discovery")
    parser.add_argument("-PP", dest="icmp_timestamp", action="store_true", help="ICMP timestamp discovery")
    parser.add_argument("-PM", dest="icmp_netmask", action="store_true", help="ICMP netmask discovery")
    parser.add_argument("-PO", dest="ip_proto_ping", nargs="?", const="1", help="IP protocol ping")
    parser.add_argument("-n", action="store_true", help="Never do DNS resolution")
    parser.add_argument("-R", dest="always_resolve", action="store_true", help="Always resolve DNS")
    parser.add_argument("--dns-servers", dest="dns_servers", help="Specify custom DNS servers")
    parser.add_argument("--system-dns", dest="system_dns", action="store_true", help="Use OS DNS resolver")
    parser.add_argument("--traceroute", dest="traceroute", action="store_true", help="Trace hop path")
    parser.add_argument("-sS", dest="syn", action="store_true", help="TCP SYN scan")
    parser.add_argument("-sT", dest="connect", action="store_true", help="TCP connect scan")
    parser.add_argument("-sA", dest="ack", action="store_true", help="TCP ACK scan")
    parser.add_argument("-sU", dest="udp", action="store_true", help="UDP scan")
    parser.add_argument("-sN", dest="null", action="store_true", help="TCP Null scan")
    parser.add_argument("-sF", dest="fin", action="store_true", help="TCP FIN scan")
    parser.add_argument("-sX", dest="xmas", action="store_true", help="TCP Xmas scan")
    parser.add_argument("-sW", dest="window", action="store_true", help="TCP Window scan")
    parser.add_argument("-sM", dest="maimon", action="store_true", help="TCP Maimon scan")
    parser.add_argument("-sI", dest="idle_scan", help="Idle scan (zombie host)")
    parser.add_argument("-sY", dest="init_ping", action="store_true", help="SCTP INIT scan")
    parser.add_argument("-sZ", dest="cookie_ping", action="store_true", help="SCTP COOKIE-ECHO scan")
    parser.add_argument("-sO", dest="ip_proto_scan", action="store_true", help="IP protocol scan")
    parser.add_argument("-b", dest="ftp_bounce", help="FTP bounce scan")
    parser.add_argument("-p", dest="ports", default="1-1024", help="Ports (e.g. -p 1-1024, -p U:53,T:80)")
    parser.add_argument("--exclude-ports", dest="exclude_ports", help="Exclude ports")
    parser.add_argument("-F", dest="fast_mode", action="store_true", help="Fast mode (top 100 ports)")
    parser.add_argument("-r", dest="dont_randomize_ports", action="store_true", help="Scan ports sequentially")
    parser.add_argument("--top-ports", dest="top_ports", type=int, help="Scan <n> top ports")
    parser.add_argument("--port-ratio", dest="port_ratio", type=float, help="Scan ports more common than <ratio>")
    parser.add_argument("-sV", dest="version_detection", action="store_true", help="Probe open ports for version")
    parser.add_argument("--version-intensity", dest="version_intensity", type=int, default=7,
                        help="Intensity 0-9")
    parser.add_argument("--version-light", dest="version_light", action="store_true", help="Light probe")
    parser.add_argument("--version-all", dest="version_all", action="store_true", help="Try all probes")
    parser.add_argument("--version-trace", dest="version_trace", action="store_true", help="Trace version scanning")
    parser.add_argument("--banner", dest="banner", action="store_true", help="Grab banners")
    parser.add_argument("-sC", dest="script_default", action="store_true", help="Run default scripts")
    parser.add_argument("--script", dest="scripts", help="Run scripts")
    parser.add_argument("--script-args", dest="script_args", help="Script arguments")
    parser.add_argument("-O", dest="os_detection", action="store_true", help="Enable OS detection")
    parser.add_argument("--osscan-limit", dest="osscan_limit", action="store_true",
                        help="Limit OS detection to promising targets")
    parser.add_argument("--osscan-guess", dest="osscan_guess", action="store_true", help="Guess OS more aggressively")
    parser.add_argument("-T", type=int, dest="timing", default=3, choices=range(0, 6),
                        metavar="0-5", help="Timing template (higher is faster)")
    parser.add_argument("--min-hostgroup", dest="min_hostgroup", type=int)
    parser.add_argument("--max-hostgroup", dest="max_hostgroup", type=int)
    parser.add_argument("--min-parallelism", dest="min_parallelism", type=int)
    parser.add_argument("--max-parallelism", dest="max_parallelism", type=int)
    parser.add_argument("--min-rtt-timeout", dest="min_rtt_timeout", type=float)
    parser.add_argument("--max-rtt-timeout", dest="max_rtt_timeout", type=float)
    parser.add_argument("--initial-rtt-timeout", dest="initial_rtt_timeout", type=float)
    parser.add_argument("--max-retries", dest="max_retries", type=int)
    parser.add_argument("--host-timeout", dest="host_timeout", type=float)
    parser.add_argument("--scan-delay", dest="scan_delay", type=float)
    parser.add_argument("--max-scan-delay", dest="max_scan_delay", type=float)
    parser.add_argument("--min-rate", dest="min_rate", type=int)
    parser.add_argument("--max-rate", dest="max_rate", type=int)
    parser.add_argument("--defeat-rst-ratelimit", dest="defeat_rst_ratelimit", action="store_true")
    parser.add_argument("--defeat-icmp-ratelimit", dest="defeat_icmp_ratelimit", action="store_true")
    parser.add_argument("--max-os-tries", dest="max_os_tries", type=int)
    parser.add_argument("-f", dest="frag", action="store_true", help="Fragment packets")
    parser.add_argument("--mtu", dest="mtu", type=int, help="Fragment offset")
    parser.add_argument("-D", dest="decoys", help="Decoy addresses")
    parser.add_argument("-S", dest="source_ip", help="Spoof source address")
    parser.add_argument("-e", dest="interface", help="Use specified interface")
    parser.add_argument("-g", "--source-port", dest="source_port", type=int, help="Use given port number")
    parser.add_argument("--proxies", dest="proxies", help="Relay connections through proxies")
    parser.add_argument("--data", dest="data_string", help="Append custom payload")
    parser.add_argument("--data-string", dest="data_string2", help="Append custom string")
    parser.add_argument("--data-length", dest="data_length", type=int, help="Append random data")
    parser.add_argument("--ip-options", dest="ip_options", help="Send packets with specified IP options")
    parser.add_argument("--ttl", dest="ttl", type=int, help="Set IP time-to-live field")
    parser.add_argument("--spoof-mac", dest="spoof_mac", help="Spoof MAC address")
    parser.add_argument("--badsum", dest="badsum", action="store_true", help="Send packets with bogus checksum")
    parser.add_argument("-ff", dest="frag_twice", action="store_true", help="Fragment twice")
    parser.add_argument("-oN", dest="oN", help="Normal output")
    parser.add_argument("-oX", dest="oX", help="XML output")
    parser.add_argument("-oS", dest="oS", help="s|<rIpt kIddi3 output")
    parser.add_argument("-oG", dest="oG", help="Grepable output")
    parser.add_argument("-oA", dest="oA", help="Output in all formats")
    parser.add_argument("-v", dest="verbose", action="count", default=0, help="Verbose")
    parser.add_argument("-d", dest="debug", action="count", default=0, help="Debug")
    parser.add_argument("--reason", dest="reason", action="store_true", help="Display reason")
    parser.add_argument("--open", dest="open_only", action="store_true", help="Only show open ports")
    parser.add_argument("--packet-trace", dest="packet_trace", action="store_true", help="Trace packets")
    parser.add_argument("--iflist", dest="iflist", action="store_true", help="List interfaces")
    parser.add_argument("--append-output", dest="append_output", action="store_true", help="Append to output")
    parser.add_argument("--resume", dest="resume", help="Resume aborted scan")
    parser.add_argument("--stylesheet", dest="stylesheet", help="XSL stylesheet")
    parser.add_argument("--no-stylesheet", dest="no_stylesheet", action="store_true", help="No XSL")
    parser.add_argument("--webxml", dest="webxml", action="store_true", help="Web XML")
    parser.add_argument("-6", dest="ipv6", action="store_true", help="Enable IPv6 scanning")
    parser.add_argument("-A", dest="aggressive", action="store_true", help="Aggressive scan (OS + version + traceroute)")
    parser.add_argument("--privileged", dest="privileged", action="store_true", help="Assume fully privileged")
    parser.add_argument("--unprivileged", dest="unprivileged", action="store_true", help="Assume unprivileged")
    parser.add_argument("--send-eth", dest="send_eth", action="store_true", help="Send raw Ethernet")
    parser.add_argument("--send-ip", dest="send_ip", action="store_true", help="Send raw IP")
    parser.add_argument("-V", "--version", action="version", version="%(prog)s 1.0", help="Show version")
    parser.add_argument("--no-color", dest="no_color", action="store_true", help="Disable colored output")
    return parser
def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.aggressive:
        args.os_detection = True
        args.version_detection = True
        args.traceroute = True
        if not args.scripts:
            args.script_default = True
    if args.fast_mode and not args.top_ports:
        args.top_ports = 100
    targets: List[str] = []
    if args.input_file:
        if os.path.exists(args.input_file):
            with open(args.input_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.append(line)
        else:
            print(f"[!] Input file not found: {args.input_file}")
            sys.exit(1)
    targets.extend(args.targets or [])
    if not targets:
        parser.print_help()
        sys.exit(1)
    args.targets = targets
    if args.list_scan:
        parsed = TargetParser.parse(targets, exclude=args.exclude, excludefile=args.excludefile)
        for ip in parsed:
            print(ip)
        sys.exit(0)
    if args.iflist:
        print("Interfaces (stub): default OS interface will be used.")
        sys.exit(0)
    scanner = PyMap(args)
    scanner.run()
    if args.oA:
        scanner.export_all(args.oA)
    else:
        if args.oN:
            scanner.export_normal(args.oN)
        if args.oX:
            scanner.export_xml(args.oX)
        if args.oG:
            scanner.export_grepable(args.oG)
        if args.oS:
            scanner.export_normal(args.oS)
        if not args.oN and not args.oX and not args.oG and not args.oS and not args.oA:
            pass
if __name__ == "__main__":
    main()
