# HackTools PyArsenal

A modular collection of Python security tools with a unified terminal dashboard. Everything runs from a single interactive shell, styled as a stylized Kali-like terminal.

> **For authorized security testing only.** Use these tools only on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.



> **Problem:** Currently, pwncat.py is flagged as *VERY DANGEROUS* by many different antiviruses. If you download the file and it says not found or missing, then disable your antivirus or the file checking part of it. **I PROMISE**, ***IT IS NOT ANY TYPE OF MALWARE***. The code is here, so feel free to look over it.

---

## Features

- Single TUI dashboard that launches every tool
- Animated ASCII boot sequence with module health checks
- Kali-style prompt integration
- Async I/O throughout (httpx) for speed
- Consistent CLI flags across all tools
- JSON / CSV / HTML report output where applicable

---

## Included Tools

| Tool | Script | Description |
|---|---|---|
| **nmap** | `nmap.py` | Network exploration and port scanner |
| **gobuster** | `gobuster.py` | Directory, DNS, vhost, fuzz, S3, GCS, TFTP brute-forcer |
| **theHarvester** | `theHarvester.py` | OSINT gathering from public sources |
| **nikto** | `nikto.py` | Web server vulnerability scanner |
| **sqlmap** | `sqlmap.py` | SQL injection detection |
| **hydra** | `hydra.py` | Login credential testing (HTTP, SSH, FTP) |
| **john** | `john.py` | Password hash auditing |
| **hashcat** | `hashcat.py` | Password hash recovery |
| **aircrack** | `aircrack.py` | Wireless handshake capture analysis |
| **burpsuite** | `burpsuite.py` | Web proxy with intercept, repeater, decoder (GUI) |
| **pwncat** | `pwncat.py` | Reverse shell listener and payload generator |
| **linpeas** | `linpeas.py` | Linux privilege escalation enumeration |
| **sherlock** | `sherlock.py` | Username search across social networks |
| **trufflehog** | `trufflehog.py` | Secret and credential scanner |
| **git-dumper** | `git-dumper.py` | Exposed `.git` repository dumper |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Raphael-Varghese/hacktools.git
cd hacktools
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Wordlists included:
`wordlist.txt ` for hydra and passwords
`webwords.txt` for gobuster and other directory enumeration tools

### 4. Launch the dashboard

```bash
python main.py
```

---

## Dashboard Usage

The dashboard boots into a stylized terminal. Type commands directly, or run any tool by name.

```
nmap 127.0.0.1
gobuster dir --url http://target.com --wordlist webwords.txt
sherlock johndoe
```

**Built-in commands:**

| Command | Description |
|---|---|
| `help` | Show help |
| `tools` | List all available tools with descriptions |
| `clear` | Clear the terminal |
| `ls` / `dir` | List files |
| `cat <file>` | Display file contents |
| `pwd` / `cd` | Directory navigation |
| `exit` / `quit` | Exit the dashboard |

---

## Standalone Usage

Every tool also runs independently:

```bash
python nmap.py 192.168.1.1 -p 1-1024
python gobuster.py dir --url http://target.com --wordlist wordlist.txt
python theHarvester.py --domain example.com --source all
python nikto.py --host example.com --port 80
python sqlmap.py --url "http://target.com?id=1"
python hydra.py --target example.com --service http-post --login admin --password passwords.txt
python john.py --hash-file hashes.txt --wordlist rockyou.txt --format md5
python hashcat.py --hash-file hashes.txt --wordlist rockyou.txt --hash-type sha256
python sherlock.py johndoe janedoe
python trufflehog.py /path/to/repo --json -o secrets.json
python git-dumper.py http://target.com/.git ./dumped
```

Run any tool with `--help` for its full option list.

---

## Burp Suite GUI

The `burpsuite.py` tool is a graphical intercepting proxy built with PySide6.

```bash
python burpsuite.py
```

- Local proxy on `127.0.0.1:8080`
- Self-signed CA generated automatically for HTTPS interception
- Tabs: Intercept, Proxy History, Target, Repeater, Decoder, Scanner
- Export the CA cert from the **Proxy → Export CA Cert** menu and install it in your browser

---

## Requirements

All dependencies are listed in `requirements.txt`. The main ones:

```
httpx[http2]     async HTTP with HTTP/2
click            CLI framework
rich             terminal formatting
tqdm             progress bars
dnspython        DNS resolution
PySide6          Burp Suite GUI
passlib, bcrypt  hash support
paramiko         SSH (hydra)
scapy            pcap parsing (aircrack)
GitPython        git history scanning (trufflehog)
```

---

## Legal Notice

These tools are intended **strictly for authorized security testing, education, and research**. Using them against systems without explicit permission is illegal and unethical. The authors assume no liability for misuse.

**Do not use these tools on:**
- Systems you do not own
- Systems you lack written authorization to test
- Public infrastructure or third-party services

Always test in lab environments, your own infrastructure, or engagements with a signed scope agreement.

---

## License

MIT License. See `LICENSE` for details.

---

## Contributing

Pull requests are welcome. Please give credit to me.

---

## Disclaimer

This project is not affiliated with, endorsed by, or derived from the official tools named nmap, gobuster, theHarvester, nikto, sqlmap, Hydra, John the Ripper, Hashcat, Aircrack-ng, Burp Suite, pwncat, linPEAS, Sherlock, TruffleHog, or git-dumper. Those names are referenced only to describe functionality. This is an independent Python implementation.


---

## Request a Tool

> **We all have that one hacking tool we want.**
> Mine is nmap. What is yours?

If a tool you need is not in the list above, open a GitHub issue with:
1. The tool name
2. What it does
3. The original tool it replaces (if any)

I will try to build it within 1 to 2 weekdays.
