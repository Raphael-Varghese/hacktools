#!/usr/bin/env python3
import asyncio
import os
import random
import shlex
import sys
import time
from rich.console import Console
from rich.text import Text
from rich.align import Align
from promptsetup import prompt, init
init()
console = Console()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(BASE_DIR, "tools")
TOOLS = {
    "nmap": {
        "file": "nmap.py",
        "desc": "Network exploration and vulnerability scanner",
    },
    "gobuster": {
        "file": "gobuster.py",
        "desc": "Directory and DNS subdomain brute-forcer",
    },
    "theHarvester": {
        "file": "theHarvester.py",
        "desc": "Open source intelligence gathering tool",
    },
    "nikto": {
        "file": "nikto.py",
        "desc": "Web server vulnerability assessment scanner",
    },
    "sqlmap": {
        "file": "sqlmap.py",
        "desc": "Automatic SQL injection vulnerability scanner",
    },
    "hydra": {
        "file": "hydra.py",
        "desc": "Network logon credential testing tool",
    },
    "john": {
        "file": "john.py",
        "desc": "Fast password hash auditing tool",
    },
    "hashcat": {
        "file": "hashcat.py",
        "desc": "Advanced password hash recovery tool",
    },
    "aircrack": {
        "file": "aircrack.py",
        "desc": "Wireless network analysis framework",
    },
    "burpsuite": {
        "file": "burpsuite.py",
        "desc": "Web application security testing platform",
    },
    "pwncat": {
        "file": "pwncat.py",
        "desc": "Advanced reverse shell and listener tool",
    },
    "linpeas": {
        "file": "linpeas.py",
        "desc": "Automated privilege escalation reconnaissance tool",
    },
    "sherlock": {
        "file": "sherlock.py",
        "desc": "Finds usernames across social networks",
    },
    "trufflehog": {
        "file": "trufflehog.py",
        "desc": "Searches for exposed keys and secrets",
    },
    "git-dumper": {
        "file": "git-dumper.py",
        "desc": "Dumps exposed .git repositories from servers",
    },
}
FUNNY_QUOTES = [
    "My other computer is your computer.",
    "The intern ran rm -rf / and suddenly the office got really, really quiet.",
    "Password123? Bold strategy. Let's see if it pays off.",
    "I came, I saw, I grep'd.",
    "You shall not parse!",
    "With great power comes great responsibility, which is weird because root access usually skips that second part.",
    "I find your lack of encryption disturbing.",
    "Talk is cheap. Show me the packet capture.",
    "I am root. Resistance is futile.",
    "There's a brute force joke here, but my wordlist is too small and your patience is too short.",
    "My password is the last 8 digits of pi. I'll wait.",
    "Hello World is how it starts. Hello Root is how it ends.",
    "The S in IoT stands for security.",
    "I asked my firewall for emotional support. It just dropped me.",
    "Hack the planet. (Legal says we can reclassify it as 'unexpected system behavior.')",
    "I tried to explain SQL injection to my barista. Now my coffee order returns every item on the menu.",
    "My love life is like TLS 1.0. Deprecated, unsupported, and honestly, everyone saw the warnings.",
    "I don't always exploit vulnerabilities, but when I do, they're zero-day and your patch cycle is 'we'll get to it.'",
    "There's no place like ~, which is exactly why your secrets shouldn't be there in a file called old_config.bak.",
    "My SSL certificate is self-signed, just like all my major life decisions.",
    "I put the 'fun' in 'no fun was had during this incident response.'",
    "My threat model assumes the attacker has infinite time, infinite money, and my browser history.",
    "I don't trust atoms. They make up everything, kind of like my alibi for that outage.",
    "My backups are like Schrödinger's cat. They simultaneously exist and don't exist until I actually need them.",
    "I told my boss we needed defense in depth. He bought a second firewall and put it directly behind the first one.",
    "My code is like a fractal. The closer you look, the more problems you find.",
    "I used to think my router was secure. Then I checked the default credentials and realized my router thinks it's secure too.",
    "Social engineering is just hacking people, which explains why I can't get past the receptionist but I can own the domain controller.",
    "My incident response plan is mostly just refreshing the page and hoping the error goes away before anyone tags me.",
    "I asked my SIEM for a summary of today's events. It said 'yes.'",
    "My threat intelligence feed is just a Twitter list and a gut feeling.",
    "I don't always test in production, but when I do, it's because staging was 'too expensive.'",
    "My code compiles on the first try about as often as my passwords pass the first audit.",
    "I told the developer his code had a race condition. He asked who was winning.",
    "My security policy is written in blood. Mostly mine. From paper cuts.",
    "I tried to explain the cloud to my mom. She asked why we don't just use a bigger hard drive.",
    "My pentest report is just a list of things I found and a longer list of things that are 'out of scope.'",
    "I don't always read the Terms of Service, but when I do, I find out I've already agreed to them.",
    "My DevOps pipeline is just a series of increasingly desperate bash scripts held together by cron jobs and denial.",
    "I asked my IDS if it detected any intrusions. It said no, but it also didn't detect me asking.",
    "My disaster recovery plan assumes the disaster is 'mild inconvenience' and the recovery is 'lunch break.'",
    "I put the 'try' in 'try-except' and the 'except' in 'we'll fix it in the next sprint.'",
    "My API is RESTful because it's been sleeping on proper authentication for three years.",
    "I don't always use encryption, but when I do, I forget where I put the keys.",
    "My zero-trust architecture trusts exactly one thing: that someone will email a password in plaintext.",
    "I told the scrum master we had a critical vulnerability. He moved it to the backlog and gave it three story points.",
    "My malware analysis sandbox is just a Windows VM I sacrifice to the gods every Tuesday.",
    "I don't always follow best practices, but when I do, they're from a Stack Overflow answer from 2009.",
    "My network diagram is accurate in the same way a horoscope is accurate. Vaguely, and only if you don't look too close.",
    "I asked the AI to write secure code. It gave me a regex and a false sense of confidence.",
    "My bug bounty program pays in exposure. Unfortunately, that's also what the attackers are getting.",
    "My DevOps pipeline is just three bash scripts in a trenchcoat pretending to be a CI/CD platform, and one of them is actively plotting my murder.",
    "I asked my SIEM for a summary of the breach. It said 'lol.' I asked my IDS. It said 'same.' I asked my EDR. It bluescreened and took the secret to its grave.",
]
RAPHOS_ASCII = [
    "██████╗  █████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗",
    "██╔══██╗██╔══██╗██╔══██╗██║  ██║██╔═══██╗██╔════╝",
    "██████╔╝███████║██████╔╝███████║██║   ██║███████╗",
    "██╔══██╗██╔══██║██╔═══╝ ██╔══██║██║   ██║╚════██║",
    "██║  ██║██║  ██║██║     ██║  ██║╚██████╔╝███████║",
    "╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚══════╝"
]
USERNAME = "llmhacker"
IPADDR = "192.88.917.19"
def draw_gleam(frame: int, max_frames: int):
    width = 12
    pos = int((frame / max_frames) * 70) - width
    for line in RAPHOS_ASCII:
        styled = Text()
        for j, ch in enumerate(line):
            if pos <= j <= pos + width:
                intensity = 1.0 - abs(j - (pos + width / 2)) / (width / 2)
                if intensity > 0.8:
                    styled.append(ch, "bold bright_white on #0e6b0e")
                elif intensity > 0.5:
                    styled.append(ch, "bold white")
                else:
                    styled.append(ch, "#aadd55")
            else:
                styled.append(ch, "#0e6b0e")
        console.print(styled, justify="center")
def gleam_animation():
    max_frames = 15
    for frame in range(max_frames + 10):
        console.clear()
        draw_gleam(frame, max_frames)
        time.sleep(0.08)
def boot_sequence():
    console.clear()
    console.print("[bold #0e6b0e]RaphOS PyArsenal Boot Sequence[/bold #0e6b0e]\n")
    base = os.path.dirname(os.path.abspath(__file__))
    console.print(f"[dim]Core Python {sys.version.split()[0]}[/dim]")
    console.print(f"[dim]Base Directory {base}[/dim]")
    console.print("[dim]Loading arsenal modules...[/dim]")
    time.sleep(0.2)
    for name, filename in TOOLS.items():
        path = os.path.join(TOOLS_DIR, filename)
        exists = os.path.exists(path)
        status = "[green]OK[/green]" if exists else "[red]MISSING[/red]"
        console.print(f"  [{name:12}] {filename:20} {status}")
        time.sleep(0.008)
    console.print("\n[green]All systems operational.[/green]\n")
    time.sleep(0.5)
    console.clear()
async def run_tool(cmd: list):
    base = os.path.dirname(os.path.abspath(__file__))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=base
        )
        stdout, stderr = await proc.communicate()
        if stdout:
            for line in stdout.decode("utf-8", errors="replace").splitlines():
                console.print(line)
        if stderr:
            for line in stderr.decode("utf-8", errors="replace").splitlines():
                console.print(line, style="red")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
def show_help():
    console.print("[bold #0e6b0e]RaphOS PyArsenal Terminal[/bold #0e6b0e]\n")
    console.print("[green]Commands:[/green]")
    console.print("  help, ?       Show this help")
    console.print("  tools         List all available tools")
    console.print("  clear         Clear terminal")
    console.print("  ls, dir       List files")
    console.print("  cat <file>    Display file contents")
    console.print("  pwd           Show current directory")
    console.print("  cd <dir>      Change directory")
    console.print("  exit, quit    Exit RaphOS")
    console.print("")
    console.print("[green]Tools:[/green]")
    console.print("  Run any tool by name: nmap 127.0.0.1")
    console.print("  Or: sqlmap --url http://target.com")
    console.print("")
async def main():
    gleam_animation()
    boot_sequence()
    console.print(f"[bold #0e6b0e]{random.choice(FUNNY_QUOTES)}[/bold #0e6b0e]\n")
    base = os.path.dirname(os.path.abspath(__file__))
    while True:
        p = prompt(IPADDR, USERNAME, "linux", "kali")
        print(p, end="", flush=True)
        try:
            raw = input()
        except (EOFError, KeyboardInterrupt):
            break
        raw = raw.strip()
        if not raw:
            continue
        parts = shlex.split(raw)
        cmd0 = parts[0].lower()
        if cmd0 in ("exit", "quit"):
            break
        elif cmd0 in ("help", "?"):
            show_help()
        elif cmd0 == "tools":
            for name, data in TOOLS.items():
                console.print(f"  [green]{name:14}[/] - [dim]{data['desc']}[/dim]")
        elif cmd0 == "clear":
            console.clear()
        elif cmd0 in TOOLS:
            filename = TOOLS[cmd0]["file"]
            cmd = [sys.executable, os.path.join(TOOLS_DIR, filename)] + parts[1:]
            await run_tool(cmd)
        elif cmd0.endswith(".py") and os.path.exists(os.path.join(TOOLS_DIR, cmd0)):
            cmd = [sys.executable, os.path.join(TOOLS_DIR, cmd0)] + parts[1:]
            await run_tool(cmd)
        elif cmd0 in ("ls", "dir"):
            for f in sorted(os.listdir(base)):
                console.print(f)
        elif cmd0 in ("cat", "type"):
            if len(parts) < 2:
                console.print("[red][!] Usage: cat <file>[/red]")
            else:
                try:
                    with open(os.path.join(base, parts[1]), "r", encoding="utf-8", errors="ignore") as f:
                        console.print(f.read())
                except Exception as e:
                    console.print(f"[red]Error: {e}[/red]")
        elif cmd0 == "pwd":
            console.print(os.getcwd(), style="cyan")
        elif cmd0 == "cd":
            if len(parts) > 1:
                os.chdir(parts[1])
            console.print(os.getcwd(), style="cyan")
        else:
            console.print(f"[red][!] Unknown command: {cmd0}[/red]")
            console.print("[yellow]    Try: help, tools, clear, exit, or any tool name.[/yellow]")
if __name__ == "__main__":
    asyncio.run(main())
