import hashlib
import binascii
import click
import json
import os
import sys
import time
import string
import multiprocessing
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Iterator
from tqdm import tqdm
import itertools
import re
HASH_TYPES = {
    "md5": ("md5", 32),
    "sha1": ("sha1", 40),
    "sha256": ("sha256", 64),
    "sha512": ("sha512", 128),
    "ntlm": ("ntlm", 32),
    "md5crypt": ("md5crypt", 34),
    "sha256crypt": ("sha256crypt", None),
    "sha512crypt": ("sha512crypt", None),
    "bcrypt": ("bcrypt", 60),
}
def now() -> str:
    return datetime.now().isoformat()
def detect_hash_type(hash_str: str) -> List[str]:
    h = hash_str.strip()
    results = []
    if re.match(r"^[a-f0-9]{32}$", h):
        results.append("md5")
        results.append("ntlm")
    if re.match(r"^[a-f0-9]{40}$", h):
        results.append("sha1")
    if re.match(r"^[a-f0-9]{64}$", h):
        results.append("sha256")
    if re.match(r"^[a-f0-9]{128}$", h):
        results.append("sha512")
    if h.startswith("$2") and len(h) == 60:
        results.append("bcrypt")
    if h.startswith("$1$"):
        results.append("md5crypt")
    if h.startswith("$5$"):
        results.append("sha256crypt")
    if h.startswith("$6$"):
        results.append("sha512crypt")
    return results
def hash_word(word: str, htype: str) -> str:
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
    if htype == "md5crypt":
        try:
            import passlib.hash as ph
            return ph.md5_crypt.hash(word)
        except Exception:
            return ""
    if htype == "sha256crypt":
        try:
            import passlib.hash as ph
            return ph.sha256_crypt.hash(word)
        except Exception:
            return ""
    if htype == "sha512crypt":
        try:
            import passlib.hash as ph
            return ph.sha512_crypt.hash(word)
        except Exception:
            return ""
    if htype == "bcrypt":
        try:
            import bcrypt
            return bcrypt.hashpw(word.encode(), bcrypt.gensalt()).decode()
        except Exception:
            return ""
    return ""
def check_hash(word: str, target: str, htype: str) -> bool:
    if htype in ("md5", "sha1", "sha256", "sha512", "ntlm"):
        return hash_word(word, htype).lower() == target.lower()
    if htype == "bcrypt":
        try:
            import bcrypt
            return bcrypt.checkpw(word.encode(), target.encode())
        except Exception:
            return False
    if htype in ("md5crypt", "sha256crypt", "sha512crypt"):
        try:
            import passlib.hash as ph
            hmap = {"md5crypt": ph.md5_crypt, "sha256crypt": ph.sha256_crypt, "sha512crypt": ph.sha512_crypt}
            return hmap[htype].verify(word, target)
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
def brute_generator(min_len: int, max_len: int, charset: str) -> Iterator[str]:
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
class PyHash:
    def __init__(self, hash_file: str, wordlist: Optional[str], hash_type: Optional[str], brute: bool, min_len: int, max_len: int, charset: str, threads: int, output: Optional[str], rules: List[str], verbose: bool, stdout: bool, limit: int):
        self.hash_file = hash_file
        self.wordlist = wordlist
        self.hash_type = hash_type
        self.brute = brute
        self.min_len = min_len
        self.max_len = max_len
        self.charset = charset
        self.threads = threads
        self.output = output
        self.rules = rules
        self.verbose = verbose
        self.stdout = stdout
        self.limit = limit
        self.targets: List[str] = []
        self.found: Dict[str, Tuple[str, str]] = {}
        self.checked = 0
        self.start_time = time.time()
    def run(self):
        self._load_hashes()
        if not self.targets:
            print("[!] No hashes loaded")
            return
        if not self.hash_type:
            print("[*] Auto-detecting hash types...")
            for h in self.targets[:5]:
                detected = detect_hash_type(h)
                print(f"    {h[:40]}... -> {', '.join(detected) if detected else 'unknown'}")
            return
        if self.brute:
            self._brute_mode()
        elif self.wordlist:
            self._wordlist_mode()
        else:
            print("[!] Provide --wordlist or --brute")
    def _load_hashes(self):
        if os.path.exists(self.hash_file):
            with open(self.hash_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.targets.append(line)
        else:
            self.targets = [self.hash_file]
        print(f"[*] Loaded {len(self.targets)} hash(es)")
    def _apply_rules(self, word: str) -> List[str]:
        variants = [word]
        if "lower" in self.rules:
            variants.append(word.lower())
        if "upper" in self.rules:
            variants.append(word.upper())
        if "capitalize" in self.rules:
            variants.append(word.capitalize())
        if "reverse" in self.rules:
            variants.append(word[::-1])
        if "leet" in self.rules:
            variants.append(word.replace("a", "4").replace("e", "3").replace("i", "1").replace("o", "0").replace("s", "5").replace("t", "7"))
        if "append1" in self.rules:
            variants.append(word + "1")
            variants.append(word + "123")
            variants.append(word + "!")
        return list(dict.fromkeys(variants))
    def _wordlist_mode(self):
        print(f"[*] Wordlist mode | type={self.hash_type} | threads={self.threads}")
        words = list(read_wordlist(self.wordlist))
        total = len(words)
        print(f"[*] Wordlist size: {total}")
        if self.rules:
            print(f"[*] Applying rules: {', '.join(self.rules)}")
        chunk_size = max(1, len(words) // (self.threads * 4))
        chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]
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
                            print(f"[+] CRACKED: {target} -> {word}")
                            if self.stdout:
                                print(word)
                            if len(self.found) >= len(self.targets) or (self.limit and len(self.found) >= self.limit):
                                pool.terminate()
                                pool.join()
                                pbar.close()
                                self._summary()
                                self._save()
                                return
            remaining -= done
            pbar.update(chunk_size * len(done))
            time.sleep(0.1)
        pool.close()
        pool.join()
        pbar.close()
        self._summary()
        self._save()
    def _brute_mode(self):
        print(f"[*] Brute force mode | type={self.hash_type} | length={self.min_len}-{self.max_len} | charset len={len(self.charset)} | threads={self.threads}")
        print(f"[!] Warning: brute force is very slow in pure Python")
        gen = brute_generator(self.min_len, self.max_len, self.charset)
        batch = []
        pbar = tqdm(unit="words", desc="brute", ncols=80)
        pool = multiprocessing.Pool(processes=self.threads)
        results = []
        batch_size = self.threads * 500
        for word in gen:
            batch.append(word)
            if len(batch) >= batch_size:
                results.append(pool.apply_async(worker_task, ((batch, self.targets, self.hash_type),)))
                batch = []
                pbar.update(batch_size)
                if len(results) >= self.threads * 2:
                    self._collect_results(results, pool, pbar)
                    results = []
        if batch:
            results.append(pool.apply_async(worker_task, ((batch, self.targets, self.hash_type),)))
        self._collect_results(results, pool, pbar, final=True)
        pool.close()
        pool.join()
        pbar.close()
        self._summary()
        self._save()
    def _collect_results(self, results: list, pool, pbar, final: bool = False):
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
                        print(f"[+] CRACKED: {target} -> {word}")
                        if self.stdout:
                            print(word)
                        if len(self.found) >= len(self.targets) or (self.limit and len(self.found) >= self.limit):
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
            print(f"[+] Cracked {len(self.found)}/{len(self.targets)} hash(es) in {elapsed:.2f}s")
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
                        f.write(f"{h}:{w}\\n")
            print(f"[+] Saved to {self.output}")
        except Exception as e:
            print(f"[!] Save failed: {e}")
@click.command()
@click.option("-m", "--hash-type", help="Hash type (md5, sha1, sha256, sha512, ntlm, bcrypt, md5crypt, sha256crypt, sha512crypt)")
@click.option("-a", "--hash-file", required=True, help="File with hashes or single hash string")
@click.option("-w", "--wordlist", help="Wordlist file")
@click.option("--brute", is_flag=True, help="Enable brute force mode")
@click.option("--min-len", default=1, help="Minimum password length for brute force")
@click.option("--max-len", default=4, help="Maximum password length for brute force")
@click.option("--charset", default=string.ascii_lowercase, help="Character set for brute force")
@click.option("-t", "--threads", default=0, help="Number of worker processes (0 = auto)")
@click.option("-o", "--output", help="Output file")
@click.option("--rules", multiple=True, default=["lower", "upper", "capitalize", "append1"], help="Rules to apply to wordlist words")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("--stdout", is_flag=True, help="Print cracked passwords to stdout")
@click.option("-l", "--limit", default=0, help="Stop after N cracks (0 = all)")
def cli(hash_type, hash_file, wordlist, brute, min_len, max_len, charset, threads, output, rules, verbose, stdout, limit):
    if threads == 0:
        threads = multiprocessing.cpu_count()
    pyhash = PyHash(hash_file, wordlist, hash_type, brute, min_len, max_len, charset, threads, output, list(rules), verbose, stdout, limit)
    pyhash.run()
if __name__ == "__main__":
    cli()
