import hashlib
import binascii
import click
import json
import os
import re
import string
import sys
import time
import multiprocessing
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Iterator
from tqdm import tqdm
HASH_ALIASES = {
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "ntlm": "ntlm",
    "lm": "lm",
    "bcrypt": "bcrypt",
    "md5crypt": "md5crypt",
    "sha256crypt": "sha256crypt",
    "sha512crypt": "sha512crypt",
    "descrypt": "descrypt",
    "mysql": "mysql",
    "mssql": "mssql",
    "postgres": "postgres",
    "oracle": "oracle",
    "ldap": "ldap",
    "apr1": "apr1",
    "django": "django",
    "pbkdf2-sha256": "pbkdf2-sha256",
    "pbkdf2-sha512": "pbkdf2-sha512",
    "scrypt": "scrypt",
    "argon2": "argon2",
}
POT_FILE = os.path.expanduser("~/.pyjohn/john.pot")
def ensure_pot():
    os.makedirs(os.path.dirname(POT_FILE), exist_ok=True)
    if not os.path.exists(POT_FILE):
        open(POT_FILE, "a").close()
def load_pot() -> Dict[str, str]:
    ensure_pot()
    out = {}
    with open(POT_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                h, p = line.split(":", 1)
                out[h] = p
    return out
def save_pot(h: str, plaintext: str):
    ensure_pot()
    with open(POT_FILE, "a", encoding="utf-8") as f:
        f.write(f"{h}:{plaintext}\n")
def detect_hash_type(hash_str: str) -> List[str]:
    h = hash_str.strip()
    out = []
    if re.match(r"^[a-f0-9]{32}$", h):
        out.extend(["md5", "ntlm", "mysql", "lm"])
    if re.match(r"^[a-f0-9]{40}$", h):
        out.append("sha1")
    if re.match(r"^[a-f0-9]{64}$", h):
        out.append("sha256")
    if re.match(r"^[a-f0-9]{128}$", h):
        out.append("sha512")
    if h.startswith("$2") and len(h) == 60:
        out.append("bcrypt")
    if h.startswith("$1$"):
        out.append("md5crypt")
    if h.startswith("$5$"):
        out.append("sha256crypt")
    if h.startswith("$6$"):
        out.append("sha512crypt")
    if h.startswith("$apr1$"):
        out.append("apr1")
    if re.match(r"^[a-zA-Z0-9./]{13}$", h) and not h.startswith("$"):
        out.append("descrypt")
    if h.startswith("pbkdf2_sha256$"):
        out.append("pbkdf2-sha256")
    if h.startswith("pbkdf2_sha512$"):
        out.append("pbkdf2-sha512")
    if h.startswith("scrypt$"):
        out.append("scrypt")
    if h.startswith("argon2"):
        out.append("argon2")
    if "=" in h and h.endswith("="):
        out.append("ldap")
    return out
def hash_word(word: str, htype: str) -> str:
    try:
        if htype == "md5":
            return hashlib.md5(word.encode("utf-8", errors="ignore")).hexdigest()
        if htype == "sha1":
            return hashlib.sha1(word.encode("utf-8", errors="ignore")).hexdigest()
        if htype == "sha256":
            return hashlib.sha256(word.encode("utf-8", errors="ignore")).hexdigest()
        if htype == "sha512":
            return hashlib.sha512(word.encode("utf-8", errors="ignore")).hexdigest()
        if htype == "ntlm":
            return hashlib.new("md4", word.encode("utf-16le", errors="ignore")).hexdigest()
        if htype == "lm":
            return _lm_hash(word)
        if htype == "mysql":
            return hashlib.sha1(hashlib.sha1(word.encode()).digest()).hexdigest()
        if htype in ("md5crypt", "sha256crypt", "sha512crypt", "descrypt", "apr1", "pbkdf2-sha256", "pbkdf2-sha512", "scrypt", "argon2", "bcrypt"):
            return _passlib_hash(word, htype)
    except Exception:
        pass
    return ""
def _lm_hash(word: str) -> str:
    try:
        from passlib.hash import lmhash
        return lmhash.hash(word.upper())
    except Exception:
        return ""
def _passlib_hash(word: str, htype: str) -> str:
    try:
        import passlib.hash as ph
        m = {
            "md5crypt": ph.md5_crypt,
            "sha256crypt": ph.sha256_crypt,
            "sha512crypt": ph.sha512_crypt,
            "descrypt": ph.des_crypt,
            "apr1": ph.apr_md5_crypt,
            "pbkdf2-sha256": ph.pbkdf2_sha256,
            "pbkdf2-sha512": ph.pbkdf2_sha512,
            "scrypt": ph.scrypt,
            "argon2": ph.argon2,
            "bcrypt": ph.bcrypt,
        }
        return m[htype].hash(word)
    except Exception:
        return ""
def check_hash(word: str, target: str, htype: str) -> bool:
    if htype in ("md5", "sha1", "sha256", "sha512", "ntlm", "lm", "mysql"):
        return hash_word(word, htype).lower() == target.lower()
    if htype in ("bcrypt", "md5crypt", "sha256crypt", "sha512crypt", "descrypt", "apr1", "pbkdf2-sha256", "pbkdf2-sha512", "scrypt", "argon2"):
        try:
            import passlib.hash as ph
            m = {
                "md5crypt": ph.md5_crypt,
                "sha256crypt": ph.sha256_crypt,
                "sha512crypt": ph.sha512_crypt,
                "descrypt": ph.des_crypt,
                "apr1": ph.apr_md5_crypt,
                "pbkdf2-sha256": ph.pbkdf2_sha256,
                "pbkdf2-sha512": ph.pbkdf2_sha512,
                "scrypt": ph.scrypt,
                "argon2": ph.argon2,
                "bcrypt": ph.bcrypt,
            }
            return m[htype].verify(word, target)
        except Exception:
            return False
    return False
def read_wordlist(path: str) -> Iterator[str]:
    if path == "-":
        for line in sys.stdin:
            line = line.strip()
            if line:
                yield line
    else:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    yield line
def apply_rules(word: str, rules: List[str]) -> List[str]:
    out = [word]
    if "lower" in rules:
        out.append(word.lower())
    if "upper" in rules:
        out.append(word.upper())
    if "capitalize" in rules:
        out.append(word.capitalize())
    if "reverse" in rules:
        out.append(word[::-1])
    if "leet" in rules:
        out.append(word.replace("a", "4").replace("e", "3").replace("i", "1").replace("o", "0").replace("s", "5").replace("t", "7").replace("A", "4").replace("E", "3").replace("I", "1").replace("O", "0").replace("S", "5").replace("T", "7"))
    if "append1" in rules:
        out.extend([word + "1", word + "12", word + "123", word + "1234", word + "!", word + "?", word + ".", word + "0"])
    if "prepend1" in rules:
        out.extend(["1" + word, "123" + word])
    if "double" in rules:
        out.append(word + word)
    if "toggle" in rules:
        out.append(word.swapcase())
    return list(dict.fromkeys(out))
def brute_generator(min_len: int, max_len: int, charset: str) -> Iterator[str]:
    import itertools
    chars = list(charset)
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(chars, repeat=length):
            yield "".join(combo)
def worker_task(args) -> Optional[Tuple[str, str, str]]:
    words, targets, htype = args
    for word in words:
        for target in targets:
            if check_hash(word, target, htype):
                return (target, word, htype)
    return None
class PyJohn:
    def __init__(self, hash_file: str, wordlist: Optional[str], hash_type: Optional[str], brute: bool, single: bool, min_len: int, max_len: int, charset: str, threads: int, output: Optional[str], rules: List[str], verbose: bool, show: bool, pot: str, limit: int, users_file: Optional[str]):
        self.hash_file = hash_file
        self.wordlist = wordlist
        self.hash_type = hash_type
        self.brute = brute
        self.single = single
        self.min_len = min_len
        self.max_len = max_len
        self.charset = charset
        self.threads = threads
        self.output = output
        self.rules = rules
        self.verbose = verbose
        self.show = show
        self.pot = pot
        self.limit = limit
        self.users_file = users_file
        self.targets: List[str] = []
        self.found: Dict[str, Tuple[str, str]] = {}
        self.checked = 0
        self.start_time = time.time()
        if pot:
            global POT_FILE
            POT_FILE = pot
    def run(self):
        if self.show:
            self._do_show()
            return
        self._load_hashes()
        if not self.targets:
            print("[!] No hashes loaded")
            return
        if not self.hash_type:
            print("[*] Auto-detecting hash types...")
            for h in self.targets[:5]:
                detected = detect_hash_type(h)
                print(f"    {h[:50]}... -> {', '.join(detected) if detected else 'unknown'}")
            return
        if self.single:
            self._single_mode()
        elif self.brute:
            self._brute_mode()
        elif self.wordlist:
            self._wordlist_mode()
        else:
            print("[!] Provide --wordlist, --brute, --single, or --show")
    def _load_hashes(self):
        if os.path.exists(self.hash_file):
            with open(self.hash_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.targets.append(line)
        else:
            self.targets = [self.hash_file]
        pot = load_pot()
        self.targets = [h for h in self.targets if h not in pot]
        print(f"[*] Loaded {len(self.targets)} hash(es) to crack")
    def _do_show(self):
        pot = load_pot()
        if not pot:
            print("[*] No cracked hashes in pot file")
            return
        print(f"[*] {len(pot)} cracked hash(es):")
        for h, p in pot.items():
            print(f"    {h} -> {p}")
    def _single_mode(self):
        print(f"[*] Single crack mode | type={self.hash_type}")
        users = []
        if self.users_file and os.path.exists(self.users_file):
            with open(self.users_file, "r") as f:
                users = [line.strip() for line in f if line.strip()]
        elif self.wordlist:
            users = list(read_wordlist(self.wordlist))[:100]
        words = []
        for u in users:
            words.append(u)
            words.append(u.lower())
            words.append(u.upper())
            words.append(u.capitalize())
            words.append(u + u)
            words.append(u + "123")
            words.append(u + "!")
            words.append(u + "1")
            if " " in u:
                parts = u.split()
                words.extend(parts)
        words = list(dict.fromkeys(words))
        self._run_workers(words)
    def _wordlist_mode(self):
        print(f"[*] Wordlist mode | type={self.hash_type} | rules={','.join(self.rules)}")
        words = []
        for w in read_wordlist(self.wordlist):
            words.extend(apply_rules(w, self.rules))
        words = list(dict.fromkeys(words))
        print(f"[*] Expanded wordlist: {len(words)} candidates")
        self._run_workers(words)
    def _brute_mode(self):
        print(f"[*] Brute force mode | type={self.hash_type} | len={self.min_len}-{self.max_len} | charset={len(self.charset)}")
        print("[!] Warning: brute force in pure Python is very slow")
        gen = brute_generator(self.min_len, self.max_len, self.charset)
        batch = []
        batch_size = self.threads * 500
        pbar = tqdm(unit="words", desc="brute", ncols=80)
        pool = multiprocessing.Pool(processes=self.threads)
        results = []
        for word in gen:
            batch.append(word)
            if len(batch) >= batch_size:
                results.append(pool.apply_async(worker_task, ((batch, self.targets, self.hash_type),)))
                batch = []
                pbar.update(batch_size)
                if len(results) >= self.threads * 2:
                    self._collect(results, pool, pbar)
                    results = []
        if batch:
            results.append(pool.apply_async(worker_task, ((batch, self.targets, self.hash_type),)))
        self._collect(results, pool, pbar, final=True)
        pool.close()
        pool.join()
        pbar.close()
        self._summary()
        self._save()
    def _run_workers(self, words: List[str]):
        total = len(words)
        chunk_size = max(1, total // (self.threads * 4))
        chunks = [words[i:i + chunk_size] for i in range(0, total, chunk_size)]
        pbar = tqdm(total=total, unit="words", desc="crack", ncols=80)
        pool = multiprocessing.Pool(processes=self.threads)
        results = []
        for chunk in chunks:
            results.append(pool.apply_async(worker_task, ((chunk, self.targets, self.hash_type),)))
        remaining = set(range(len(results)))
        while remaining:
            done = set()
            for idx in remaining:
                if results[idx].ready():
                    done.add(idx)
                    res = results[idx].get()
                    if res:
                        target, word, htype = res
                        if target not in self.found:
                            self.found[target] = (word, htype)
                            save_pot(target, word)
                            print(f"[+] CRACKED: {target} -> {word}")
                            if self.limit and len(self.found) >= self.limit:
                                pool.terminate()
                                pool.join()
                                pbar.close()
                                self._summary()
                                self._save()
                                return
            remaining -= done
            pbar.update(chunk_size * len(done))
            time.sleep(0.05)
        pool.close()
        pool.join()
        pbar.close()
        self._summary()
        self._save()
    def _collect(self, results: list, pool, pbar, final: bool = False):
        for res in results:
            try:
                if final:
                    r = res.get(timeout=300)
                else:
                    r = res.get(timeout=1)
                if r:
                    target, word, htype = r
                    if target not in self.found:
                        self.found[target] = (word, htype)
                        save_pot(target, word)
                        print(f"[+] CRACKED: {target} -> {word}")
                        if self.limit and len(self.found) >= self.limit:
                            pool.terminate()
                            pool.join()
                            pbar.close()
                            self._summary()
                            self._save()
                            sys.exit(0)
            except Exception:
                pass
    def _summary(self):
        elapsed = time.time() - self.start_time
        print("=" * 60)
        if self.found:
            print(f"[+] Cracked {len(self.found)} hash(es) in {elapsed:.2f}s")
            for h, (w, t) in self.found.items():
                print(f"    {h} -> {w}")
        else:
            print(f"[-] No hashes cracked in {elapsed:.2f}s")
        print("=" * 60)
    def _save(self):
        if not self.output:
            return
        data = {"cracked": {h: {"plaintext": w, "type": t} for h, (w, t) in self.found.items()}, "uncracked": [h for h in self.targets if h not in self.found]}
        ext = os.path.splitext(self.output)[1].lower()
        try:
            if ext == ".json":
                with open(self.output, "w") as f:
                    json.dump(data, f, indent=2)
            else:
                with open(self.output, "w") as f:
                    for h, (w, t) in self.found.items():
                        f.write(f"{h}:{w}\n")
            print(f"[+] Saved to {self.output}")
        except Exception as e:
            print(f"[!] Save failed: {e}")
@click.command()
@click.option("--wordlist", "-w", help="Wordlist file")
@click.option("--hash-file", "-a", required=True, help="File with hashes or single hash")
@click.option("--format", "-f", "hash_type", help="Hash type (md5, sha1, sha256, sha512, ntlm, lm, bcrypt, md5crypt, sha256crypt, sha512crypt, descrypt, apr1, pbkdf2-sha256, pbkdf2-sha512, scrypt, argon2)")
@click.option("--brute", is_flag=True, help="Enable brute force mode")
@click.option("--single", is_flag=True, help="Single crack mode (use usernames as passwords)")
@click.option("--min-len", default=1, help="Minimum password length for brute force")
@click.option("--max-len", default=4, help="Maximum password length for brute force")
@click.option("--charset", default=string.ascii_lowercase, help="Character set for brute force")
@click.option("--threads", "-t", default=0, help="Worker processes (0 = auto)")
@click.option("--output", "-o", help="Output file")
@click.option("--rules", multiple=True, default=["lower", "upper", "capitalize", "append1"], help="Rules to apply")
@click.option("-v", "--verbose", is_flag=True, help="Verbose")
@click.option("--show", is_flag=True, help="Show cracked hashes from pot file")
@click.option("--pot", help="Custom pot file path")
@click.option("--limit", "-l", default=0, help="Stop after N cracks")
@click.option("--users", help="Users file for single crack mode")
def cli(wordlist, hash_file, hash_type, brute, single, min_len, max_len, charset, threads, output, rules, verbose, show, pot, limit, users):
    if threads == 0:
        threads = multiprocessing.cpu_count()
    john = PyJohn(hash_file, wordlist, hash_type, brute, single, min_len, max_len, charset, threads, output, list(rules), verbose, show, pot, limit, users)
    john.run()
if __name__ == "__main__":
    cli()
