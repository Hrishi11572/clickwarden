#!/usr/bin/env python3
"""
ClickWarden Downloads watcher
============================
Watches your Downloads folder. Every new file is hashed (SHA-256) and looked up in
MalwareBazaar and VirusTotal (plus ClamAV if it's installed). Files that are known
malware are moved to a quarantine folder and you get a desktop notification.

Usage:
    python clickwarden_watcher.py setup              # save your API keys
    python clickwarden_watcher.py watch              # watch ~/Downloads (default)
    python clickwarden_watcher.py watch --dir D:\\Dl  # watch another folder
    python clickwarden_watcher.py scan FILE_OR_DIR   # one-off scan
    python clickwarden_watcher.py quarantine         # list / restore quarantined files

Keys can also come from env vars ABUSECH_AUTH_KEY and VT_API_KEY.
Only the Python standard library is required; `pip install watchdog` makes
watching instant instead of polling every 2 s.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

HOME = Path.home()
APP_DIR = HOME / ".clickwarden"
CONFIG = APP_DIR / "config.json"
CACHE = APP_DIR / "hash_cache.json"
LOG = APP_DIR / "watcher.log"
QUARANTINE = APP_DIR / "quarantine"

TEMP_SUFFIXES = (".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload", ".!ut", ".aria2")
EXECUTABLE_EXTS = {
    "exe", "msi", "msix", "appx", "scr", "bat", "cmd", "com", "pif", "ps1", "psm1", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "jar", "lnk", "dll", "cpl", "msc", "reg", "iso", "img", "vhd", "vhdx", "apk", "dmg",
    "pkg", "app", "sh", "run", "bin", "deb", "rpm", "appimage", "xll", "docm", "xlsm", "pptm", "one", "chm", "url",
}
DOC_LIKE = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif",
            "mp3", "mp4", "mov", "avi", "mkv", "zip", "html", "htm"}
HIDDEN_CHARS = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200b\u200c\u200d\u200e\u200f")

VT_MIN_INTERVAL = 15.5  # free tier: 4 requests / minute


# --------------------------------------------------------------------------- utils

def log(msg: str) -> None:
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line, flush=True)
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        with LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_json(path: Path, data) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)
    if path == CONFIG and os.name != "nt":
        os.chmod(path, 0o600)


def load_config() -> dict:
    cfg = load_json(CONFIG, {})
    cfg["abuse_key"] = os.environ.get("ABUSECH_AUTH_KEY") or cfg.get("abuse_key", "")
    cfg["vt_key"] = os.environ.get("VT_API_KEY") or cfg.get("vt_key", "")
    return cfg


def default_downloads_dir() -> Path:
    if os.name != "nt":
        try:  # honour XDG user-dirs on Linux
            out = subprocess.run(["xdg-user-dir", "DOWNLOAD"], capture_output=True, text=True, timeout=2)
            if out.returncode == 0 and out.stdout.strip():
                return Path(out.stdout.strip())
        except (OSError, subprocess.SubprocessError):
            pass
    return HOME / "Downloads"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def notify(title: str, message: str) -> None:
    """Best-effort desktop notification on Windows / macOS / Linux."""
    try:
        from plyer import notification  # type: ignore
        notification.notify(title=title, message=message[:250], app_name="ClickWarden", timeout=15)
        return
    except Exception:
        pass
    system = platform.system()
    try:
        if system == "Darwin":
            script = f'display notification {json.dumps(message[:250])} with title {json.dumps(title)}'
            subprocess.run(["osascript", "-e", script], timeout=5)
        elif system == "Windows":
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms;"
                "$n=New-Object System.Windows.Forms.NotifyIcon;"
                "$n.Icon=[System.Drawing.SystemIcons]::Warning;$n.Visible=$true;"
                f"$n.ShowBalloonTip(15000,{ps_quote(title)},{ps_quote(message[:250])},'Warning');"
                "Start-Sleep -Seconds 16;$n.Dispose()"
            )
            subprocess.Popen(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        else:
            subprocess.run(["notify-send", "-u", "critical", "-a", "ClickWarden", title, message[:250]], timeout=5)
    except Exception as e:  # never let notifications crash the watcher
        log(f"(notification failed: {e})")


def ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


# ---------------------------------------------------------------- file heuristics

def filename_flags(name: str) -> list[str]:
    flags = []
    if any(c in HIDDEN_CHARS for c in name):
        flags.append("File name contains hidden Unicode characters that disguise its real type")
    parts = name.lower().split(".")
    ext = parts[-1].strip() if len(parts) > 1 else ""
    prev = parts[-2].strip() if len(parts) > 2 else ""
    if ext in EXECUTABLE_EXTS and prev in DOC_LIKE:
        flags.append(f'Double extension ".{prev}.{ext}" — pretends to be a {prev.upper()} file')
    if "   ." in name:
        flags.append("Lots of spaces before the extension to hide it")
    return flags


def zone_identifier(path: Path) -> dict:
    """On Windows, read the Mark-of-the-Web to learn which site the file came from."""
    if os.name != "nt":
        return {}
    try:
        with open(str(path) + ":Zone.Identifier", "r", encoding="utf-8", errors="ignore") as f:
            info = {}
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    info[k] = v
            return info
    except OSError:
        return {}


# ------------------------------------------------------------- threat intel

@dataclass
class Finding:
    source: str
    status: str  # malicious | suspicious | clean | unknown | error
    detail: str = ""


@dataclass
class Report:
    path: str
    sha256: str
    size: int
    verdict: str = "unknown"
    findings: list[Finding] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    origin: str = ""


class Intel:
    def __init__(self, cfg: dict):
        self.abuse_key = cfg.get("abuse_key", "")
        self.vt_key = cfg.get("vt_key", "")
        self._vt_last = 0.0
        self._vt_lock = threading.Lock()
        self.clam = shutil.which("clamdscan") or shutil.which("clamscan")

    def _post_form(self, url: str, data: dict, headers: dict) -> dict:
        req = urllib.request.Request(url, data=urllib.parse.urlencode(data).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())

    def malwarebazaar(self, sha: str) -> Finding:
        try:
            j = self._post_form("https://mb-api.abuse.ch/api/v1/", {"query": "get_info", "hash": sha},
                                {"Auth-Key": self.abuse_key, "User-Agent": "ClickWarden/1.0"})
        except urllib.error.HTTPError as e:
            return Finding("MalwareBazaar", "error", "API key rejected" if e.code in (401, 403) else f"HTTP {e.code}")
        except Exception as e:
            return Finding("MalwareBazaar", "error", str(e))
        status = j.get("query_status")
        if status == "ok" and j.get("data"):
            d = j["data"][0]
            tags = ", ".join((d.get("tags") or [])[:5])
            return Finding("MalwareBazaar", "malicious",
                           f"Known malware: {d.get('signature') or 'unclassified'} ({d.get('file_type', 'file')})"
                           + (f" — tags: {tags}" if tags else ""))
        if status in ("hash_not_found", "no_results"):
            return Finding("MalwareBazaar", "unknown", "Not in database")
        return Finding("MalwareBazaar", "error", str(status))

    def urlhaus(self, url: str) -> Finding:
        try:
            j = self._post_form("https://urlhaus-api.abuse.ch/v1/url/", {"url": url},
                                {"Auth-Key": self.abuse_key, "User-Agent": "ClickWarden/1.0"})
        except Exception as e:
            return Finding("URLhaus", "error", str(e))
        if j.get("query_status") == "ok":
            return Finding("URLhaus", "malicious", f"Downloaded from a known malware URL ({j.get('threat', 'malware')})")
        return Finding("URLhaus", "clean" if j.get("query_status") == "no_results" else "error", "")

    def virustotal(self, sha: str) -> Finding:
        with self._vt_lock:  # respect the free-tier rate limit
            wait = VT_MIN_INTERVAL - (time.time() - self._vt_last)
            if wait > 0:
                time.sleep(wait)
            self._vt_last = time.time()
        req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha}",
                                     headers={"x-apikey": self.vt_key, "User-Agent": "ClickWarden/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                j = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return Finding("VirusTotal", "unknown", "Never seen this file")
            if e.code == 429:
                return Finding("VirusTotal", "error", "Rate limit / daily quota reached")
            return Finding("VirusTotal", "error", "API key rejected" if e.code in (401, 403) else f"HTTP {e.code}")
        except Exception as e:
            return Finding("VirusTotal", "error", str(e))
        a = j.get("data", {}).get("attributes", {})
        st = a.get("last_analysis_stats", {})
        mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
        total = sum(v for v in st.values() if isinstance(v, int))
        label = (a.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
        lbl = f" ({label})" if label else ""
        if mal >= 3:
            return Finding("VirusTotal", "malicious", f"{mal}/{total} antivirus engines detect it{lbl}")
        if mal >= 1 or sus >= 2:
            return Finding("VirusTotal", "suspicious", f"{mal}/{total} engines detect it — may be a false positive{lbl}")
        return Finding("VirusTotal", "clean", f"0/{total} engines detect it")

    def clamav(self, path: Path) -> Finding:
        try:
            out = subprocess.run([self.clam, "--no-summary", str(path)], capture_output=True, text=True, timeout=300)
        except Exception as e:
            return Finding("ClamAV", "error", str(e))
        if out.returncode == 1:
            sig = out.stdout.strip().rsplit(":", 1)[-1].replace("FOUND", "").strip()
            return Finding("ClamAV", "malicious", f"Detected: {sig}")
        if out.returncode == 0:
            return Finding("ClamAV", "clean", "No detection")
        return Finding("ClamAV", "error", (out.stderr or out.stdout).strip()[:120])


# ------------------------------------------------------------------ scanner

class Scanner:
    def __init__(self, cfg: dict, quarantine: bool = True):
        self.intel = Intel(cfg)
        self.quarantine = quarantine
        self.cache = load_json(CACHE, {})
        self._lock = threading.Lock()
        if not (self.intel.abuse_key or self.intel.vt_key or self.intel.clam):
            log("WARNING: no API keys and no ClamAV — only file-name checks will run. Run `setup` first.")

    def scan(self, path: Path) -> Report | None:
        try:
            size = path.stat().st_size
            sha = sha256_of(path)
        except OSError as e:
            log(f"Can't read {path.name}: {e}")
            return None
        rep = Report(str(path), sha, size, flags=filename_flags(path.name))
        zi = zone_identifier(path)
        rep.origin = zi.get("HostUrl", "")

        cached = self.cache.get(sha)
        if cached and time.time() - cached["t"] < 7 * 86400 and cached["verdict"] != "unknown":
            rep.verdict = cached["verdict"]
            rep.findings = [Finding(**f) for f in cached["findings"]]
        else:
            if self.intel.abuse_key:
                rep.findings.append(self.intel.malwarebazaar(sha))
                if rep.origin.startswith("http"):
                    rep.findings.append(self.intel.urlhaus(rep.origin))
            if self.intel.vt_key:
                rep.findings.append(self.intel.virustotal(sha))
            if self.intel.clam:
                rep.findings.append(self.intel.clamav(path))
            statuses = {f.status for f in rep.findings}
            rep.verdict = ("malicious" if "malicious" in statuses else
                           "suspicious" if "suspicious" in statuses else
                           "clean" if "clean" in statuses else "unknown")
            with self._lock:
                self.cache[sha] = {"t": time.time(), "verdict": rep.verdict,
                                   "findings": [asdict(f) for f in rep.findings if f.status != "error"]}
                save_json(CACHE, self.cache)

        if rep.flags and rep.verdict in ("clean", "unknown"):
            rep.verdict = "suspicious"
        self.report(path, rep)
        return rep

    def report(self, path: Path, rep: Report) -> None:
        icon = {"malicious": "⛔", "suspicious": "⚠️ ", "clean": "✅", "unknown": "❔"}[rep.verdict]
        log(f"{icon} {rep.verdict.upper():10} {path.name}  ({rep.size:,} bytes, sha256 {rep.sha256[:16]}…)")
        if rep.origin:
            log(f"      from: {rep.origin}")
        for f in rep.findings:
            log(f"      {f.source}: {f.status} {('— ' + f.detail) if f.detail else ''}")
        for fl in rep.flags:
            log(f"      name check: {fl}")

        if rep.verdict == "malicious":
            why = next((f.detail for f in rep.findings if f.status == "malicious"), "")
            moved = self.move_to_quarantine(path) if self.quarantine else None
            notify("⛔ Malware downloaded" + (" — quarantined" if moved else ""),
                   f"{path.name}\n{why}" + ("" if moved else "\nDelete this file — don't open it."))
        elif rep.verdict == "suspicious":
            why = next((f.detail for f in rep.findings if f.status == "suspicious"), rep.flags[0] if rep.flags else "")
            notify("⚠️ Suspicious download", f"{path.name}\n{why}")

    def move_to_quarantine(self, path: Path) -> Path | None:
        QUARANTINE.mkdir(parents=True, exist_ok=True)
        dest = QUARANTINE / f"{datetime.now():%Y%m%d-%H%M%S}__{path.name}.quarantined"
        try:
            shutil.move(str(path), dest)
            os.chmod(dest, 0o400)  # read-only, not executable
            index = load_json(QUARANTINE / "index.json", {})
            index[dest.name] = {"original": str(path), "t": time.time()}
            save_json(QUARANTINE / "index.json", index)
            log(f"      moved to quarantine: {dest}")
            return dest
        except OSError as e:
            log(f"      could not quarantine ({e}) — delete it manually!")
            return None


# ------------------------------------------------------------------ watching

def is_candidate(p: Path) -> bool:
    n = p.name.lower()
    return p.is_file() and not n.startswith(".") and not n.endswith(TEMP_SUFFIXES) and n != "desktop.ini"


def wait_until_stable(p: Path, checks: int = 3, interval: float = 1.0, timeout: float = 3600) -> bool:
    """Wait until the file stops growing (browsers write in chunks / rename at the end)."""
    last, same, start = -1, 0, time.time()
    while time.time() - start < timeout:
        try:
            size = p.stat().st_size
        except OSError:
            return False
        same = same + 1 if size == last else 0
        if same >= checks:
            return True
        last = size
        time.sleep(interval)
    return False


class Watcher:
    def __init__(self, folder: Path, scanner: Scanner):
        self.folder = folder
        self.scanner = scanner
        self.in_flight: set[str] = set()
        self.done: dict[str, float] = {}  # path -> mtime already scanned
        self.lock = threading.Lock()

    def submit(self, p: Path) -> None:
        if not is_candidate(p):
            return
        key = str(p)
        with self.lock:
            try:
                mtime = p.stat().st_mtime
            except OSError:
                return
            if key in self.in_flight or self.done.get(key) == mtime:
                return
            self.in_flight.add(key)
        threading.Thread(target=self._process, args=(p, mtime), daemon=True).start()

    def _process(self, p: Path, mtime: float) -> None:
        try:
            if wait_until_stable(p) and p.exists():
                self.scanner.scan(p)
                try:
                    mtime = p.stat().st_mtime if p.exists() else mtime
                except OSError:
                    pass
                self.done[str(p)] = mtime
        finally:
            with self.lock:
                self.in_flight.discard(str(p))

    def run(self) -> None:
        log(f"Watching {self.folder}  (Ctrl+C to stop)")
        # Don't rescan what's already there; only new arrivals.
        for p in self.folder.iterdir():
            try:
                if p.is_file():
                    self.done[str(p)] = p.stat().st_mtime
            except OSError:
                pass
        try:
            from watchdog.observers import Observer  # type: ignore
            from watchdog.events import FileSystemEventHandler  # type: ignore
        except ImportError:
            log("(watchdog not installed — polling every 2 s; `pip install watchdog` for instant detection)")
            self._poll()
            return

        outer = self

        class Handler(FileSystemEventHandler):
            def on_created(self, e):
                if not e.is_directory:
                    outer.submit(Path(e.src_path))

            def on_moved(self, e):  # Chrome/Firefox rename .crdownload/.part -> final name
                if not e.is_directory:
                    outer.submit(Path(e.dest_path))

            def on_modified(self, e):
                if not e.is_directory:
                    outer.submit(Path(e.src_path))

        obs = Observer()
        obs.schedule(Handler(), str(self.folder), recursive=False)
        obs.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            obs.stop()
            obs.join()

    def _poll(self) -> None:
        try:
            while True:
                for p in self.folder.iterdir():
                    self.submit(p)
                time.sleep(2)
        except KeyboardInterrupt:
            pass


# ------------------------------------------------------------------ CLI

def cmd_setup(_args) -> None:
    cfg = load_json(CONFIG, {})
    print("ClickWarden setup — press Enter to keep the current value.\n")
    print("abuse.ch Auth-Key (free: https://auth.abuse.ch/) — used for MalwareBazaar + URLhaus")
    v = getpass.getpass(f"  key [{'set' if cfg.get('abuse_key') else 'not set'}]: ").strip()
    if v:
        cfg["abuse_key"] = v
    print("VirusTotal API key (free: https://www.virustotal.com/ → your profile → API key)")
    v = getpass.getpass(f"  key [{'set' if cfg.get('vt_key') else 'not set'}]: ").strip()
    if v:
        cfg["vt_key"] = v
    save_json(CONFIG, cfg)
    print(f"\nSaved to {CONFIG}")
    if shutil.which("clamscan") or shutil.which("clamdscan"):
        print("ClamAV found — it will be used as an extra offline scanner.")
    else:
        print("Tip: install ClamAV for an extra offline scanner (optional).")


def cmd_watch(args) -> None:
    folder = (Path(args.dir).expanduser() if args.dir else default_downloads_dir()).resolve()
    if not folder.is_dir():
        sys.exit(f"Folder not found: {folder}")
    Watcher(folder, Scanner(load_config(), quarantine=not args.no_quarantine)).run()


def cmd_scan(args) -> None:
    target = Path(args.path).expanduser().resolve()
    scanner = Scanner(load_config(), quarantine=args.quarantine)
    files = [target] if target.is_file() else [p for p in target.rglob("*") if is_candidate(p)]
    if not files:
        sys.exit("Nothing to scan.")
    results = [r for r in (scanner.scan(f) for f in files) if r]
    bad = [r for r in results if r.verdict == "malicious"]
    print(f"\nScanned {len(results)} file(s): {len(bad)} malicious, "
          f"{sum(r.verdict == 'suspicious' for r in results)} suspicious.")
    sys.exit(1 if bad else 0)


def cmd_quarantine(args) -> None:
    index = load_json(QUARANTINE / "index.json", {})
    if args.restore:
        entry = index.get(args.restore)
        if not entry:
            sys.exit("No such quarantined file. Run `quarantine` to list them.")
        src, dst = QUARANTINE / args.restore, Path(entry["original"])
        os.chmod(src, 0o600)
        shutil.move(str(src), dst)
        del index[args.restore]
        save_json(QUARANTINE / "index.json", index)
        print(f"Restored to {dst}")
        return
    if not index:
        print("Quarantine is empty.")
    for name, e in index.items():
        print(f"{datetime.fromtimestamp(e['t']):%Y-%m-%d %H:%M}  {name}\n    was: {e['original']}")
    if index:
        print("\nRestore with:  quarantine --restore <name>   (only if you're sure it's a false positive)")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="ClickWarden — scan downloaded files for known malware.")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("setup", help="save API keys").set_defaults(fn=cmd_setup)
    w = sub.add_parser("watch", help="watch the Downloads folder (default)")
    w.add_argument("--dir", help="folder to watch (default: your Downloads folder)")
    w.add_argument("--no-quarantine", action="store_true", help="only warn, don't move malware away")
    w.set_defaults(fn=cmd_watch)
    s = sub.add_parser("scan", help="scan a file or folder once")
    s.add_argument("path")
    s.add_argument("--quarantine", action="store_true", help="move detected malware to quarantine")
    s.set_defaults(fn=cmd_scan)
    q = sub.add_parser("quarantine", help="list or restore quarantined files")
    q.add_argument("--restore", metavar="NAME")
    q.set_defaults(fn=cmd_quarantine)
    args = ap.parse_args()
    if not args.cmd:
        args = ap.parse_args(["watch"])
    args.fn(args)


if __name__ == "__main__":
    main()
