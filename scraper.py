import aiohttp
import asyncio
import errno
import ipaddress
import json
import logging
import os
import re
import signal
import sys
import time

from aiohttp import ClientTimeout, TCPConnector
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from random import uniform
from typing import List, Dict, Set, Optional, Tuple

# ---------------- CONFIGURATION ----------------

PROXY_SOURCES: Dict[str, List[str]] = {
    "http": [
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt",
        "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/master/http.txt",
        "https://raw.githubusercontent.com/noctiro/getproxy/refs/heads/master/file/http.txt",
        "https://raw.githubusercontent.com/ALIILAPRO/Proxy/refs/heads/main/http.txt",
        "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/refs/heads/main/http.txt",
        "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/refs/heads/master/proxies/http.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/http.txt",
        "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/http.txt",
    ],
    "https": [
        "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt",
        "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/master/https.txt",
        "https://raw.githubusercontent.com/noctiro/getproxy/refs/heads/master/file/https.txt",
        "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/refs/heads/master/proxies/https.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/https.txt",
        "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/https.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/https/data.txt",
    ],
    "socks4": [
        "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS4_RAW.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks4.txt",
        "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/master/socks4.txt",
        "https://raw.githubusercontent.com/noctiro/getproxy/refs/heads/master/file/socks4.txt",
        "https://raw.githubusercontent.com/ALIILAPRO/Proxy/refs/heads/main/socks4.txt",
        "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/refs/heads/main/socks4.txt",
        "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/refs/heads/master/proxies/socks4.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/socks4.txt",
        "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/socks4.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks4/data.txt",
    ],
    "socks5": [
        "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS5_RAW.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/socks5.txt",
        "https://raw.githubusercontent.com/zloi-user/hideip.me/refs/heads/master/socks5.txt",
        "https://raw.githubusercontent.com/noctiro/getproxy/refs/heads/master/file/socks5.txt",
        "https://raw.githubusercontent.com/ALIILAPRO/Proxy/refs/heads/main/socks5.txt",
        "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/refs/heads/main/socks5.txt",
        "https://raw.githubusercontent.com/Tsprnay/Proxy-lists/refs/heads/master/proxies/socks5.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/socks5.txt",
        "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/refs/heads/master/socks5.txt",
        "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt",
    ],
}

FETCH_CONCURRENCY = 20
MAX_SOURCE_RETRIES = 3
BASE_BACKOFF = 0.3
MAX_BACKOFF = 5.0 
REQUEST_TIMEOUT = 10.0
OUTPUT_MAPPING = {
    "http": "http.txt",
    "https": "https.txt",
    "socks4": "socks4.txt",
    "socks5": "socks5.txt",
}
OUTPUT_DIR = Path(".")
LOCKFILE = OUTPUT_DIR / ".scraper.lock"
SUMMARY_FILE = OUTPUT_DIR / "summary.json"
HISTORY_LIMIT = 10

# ---------------- LOGGING SETUP ----------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("[SCRAPER]")

# ---------------- HELPERS ----------------

def process_alive(pid: int) -> bool:
    """
    Check if a process with the given PID is alive (POSIX). On Windows, os.kill with 0 behaves differently;
    this implementation is best-effort and may need adaptation per platform.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False
    return True

def acquire_lock(path: Path) -> None:
    if path.exists():
        try:
            content = path.read_text().strip()
            pid = int(content) if content.isdigit() else None
            if pid and process_alive(pid):
                logger.error("Another instance (pid=%s) is running; exiting.", pid)
                sys.exit(1)
            else:
                logger.warning("Stale or invalid lockfile detected (pid=%s); reclaiming.", pid)
                path.unlink()
        except Exception:
            logger.warning("Failed to parse existing lockfile; removing and continuing.")
            try:
                path.unlink()
            except Exception:
                pass
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        with os.fdopen(fd, "w") as f:
            f.write(str(os.getpid()))
    except FileExistsError:
        logger.error("Race condition: lockfile appeared during acquisition; exiting.")
        sys.exit(1)

def release_lock(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass

def normalize_entry_to_hostport(raw: str) -> Optional[str]:
    s = raw.strip()
    s = re.sub(r'^\s*(?:http|https|socks4|socks5)://', '', s, flags=re.IGNORECASE)
    if ' ' in s:
        s = s.split(None, 1)[0]
    parts = s.split(':')
    if len(parts) >= 2:
        host = parts[0].strip()
        port = parts[1].strip()
        if port.isdigit():
            return f"{host}:{port}"
    return None

def is_public_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local)
    except ValueError:
        return True

def atomic_write(path: Path, lines: List[str]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as f:
        for l in lines:
            f.write(f"{l}\n")
    tmp.replace(path)

def atomic_write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(path)

def cleanup_stale(expected: Set[str]) -> None:
    for f in OUTPUT_DIR.iterdir():
        if f.is_file() and f.suffix == ".txt" and f.name not in expected:
            try:
                f.unlink()
                logger.info("[cleanup] removed stale file %s", f.name)
            except Exception:
                pass

def load_previous_set(path: Path) -> Set[str]:
    if not path.is_file():
        return set()
    try:
        return {line.strip() for line in path.read_text(errors="ignore").splitlines() if line.strip()}
    except Exception:
        return set()

def summarize_changes(old: Set[str], new: Set[str]) -> Tuple[List[str], List[str]]:
    added = sorted(list(new - old))
    removed = sorted(list(old - new))
    return added, removed

def compute_backoff(attempt: int, base: float = BASE_BACKOFF, cap: float = MAX_BACKOFF) -> float:
    exp = min(base * (2 ** (attempt - 1)), cap)
    jittered = exp * uniform(0.8, 1.2)
    return jittered

# ---------------- FETCHING ----------------

async def fetch_with_backoff(session: aiohttp.ClientSession, url: str) -> List[str]:
    attempt = 0
    while attempt < MAX_SOURCE_RETRIES:
        attempt += 1
        try:
            timeout = ClientTimeout(
                total=REQUEST_TIMEOUT,
                sock_connect=5,
                sock_read=5,
            )
            async with session.get(url, timeout=timeout) as resp:
                if resp.status != 200:
                    if 400 <= resp.status < 500:
                        logger.warning("[fetch] %s returned %s (client error); skipping further retries.", url, resp.status)
                        return []
                    raise RuntimeError(f"HTTP {resp.status}")
                text = await resp.text(errors="ignore")
                result = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    hp = normalize_entry_to_hostport(line)
                    if not hp:
                        continue
                    host, _ = hp.rsplit(":", 1)
                    if not is_public_ip(host):
                        continue
                    result.append(hp)
                return result
        except Exception as e:
            if attempt >= MAX_SOURCE_RETRIES:
                logger.error("[fetch] %s failed after %d attempts: %s", url, attempt, e)
                break
            wait = compute_backoff(attempt)
            logger.warning("[fetch] %s attempt %d failed: %s; retrying in %.2fs", url, attempt, e, wait)
            await asyncio.sleep(wait)
    return []

async def _fetch_and_accumulate(sem: asyncio.Semaphore, session: aiohttp.ClientSession, proto: str, url: str, out: Dict[str, Set[str]]):
    async with sem:
        entries = await fetch_with_backoff(session, url)
        for e in entries:
            out[proto].add(e)

async def gather_all_proxies() -> Dict[str, Set[str]]:
    sem = asyncio.Semaphore(FETCH_CONCURRENCY)
    out: Dict[str, Set[str]] = defaultdict(set)
    conn = TCPConnector(limit_per_host=10)
    async with aiohttp.ClientSession(connector=conn) as session:
        async with asyncio.TaskGroup() as tg:
            for proto, urls in PROXY_SOURCES.items():
                for url in urls:
                    tg.create_task(_fetch_and_accumulate(sem, session, proto, url, out))
    return out

# ---------------- SUMMARY WRITING ----------------

def write_summary_file(path: Path, summary: dict, history_limit: int = HISTORY_LIMIT) -> None:
    existing = {}
    if path.is_file():
        try:
            existing = json.loads(path.read_text())
        except Exception:
            existing = {}
    history = existing.get("history", [])
    history.append(summary)
    existing["history"] = history[-history_limit:]
    existing["last_run"] = summary
    atomic_write_json(path, existing)

# ---------------- GRACEFUL SHUTDOWN ----------------

class Shutdown:
    def __init__(self):
        self._event = asyncio.Event()

    def trigger(self):
        self._event.set()

    @property
    def event(self):
        return self._event

shutdown = Shutdown()

def _setup_signal_handlers():
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown.trigger)
        except NotImplementedError:
            signal.signal(sig, lambda *_: shutdown.trigger())

# ---------------- MAIN ----------------

async def main():
    start = time.monotonic()
    timestamp = datetime.utcnow().isoformat() + "Z"
    acquire_lock(LOCKFILE)
    summary: Dict = {
        "run_at": timestamp,
        "protocols": {},
        "duration_seconds": None,
        "any_present": False,
    }

    _setup_signal_handlers()

    try:
        raw = await gather_all_proxies()
        any_present = False
        for proto, current_set in raw.items():
            prev_path = OUTPUT_DIR / OUTPUT_MAPPING[proto]
            previous_set = load_previous_set(prev_path)
            added, removed = summarize_changes(previous_set, current_set)
            summary["protocols"][proto] = {
                "count": len(current_set),
                "added": len(added),
                "removed": len(removed),
                "added_list": added[:50],
                "removed_list": removed[:50],
            }

        expected_files: Set[str] = set()
        for proto, new_set in raw.items():
            filename = OUTPUT_MAPPING.get(proto)
            if not filename:
                continue
            expected_files.add(filename)
            out_path = OUTPUT_DIR / filename
            previous_set = load_previous_set(out_path)
            if new_set != previous_set:
                atomic_write(out_path, sorted(new_set))
                logger.info(
                    "[write] %s: updated (%d total, +%d -%d)",
                    filename,
                    len(new_set),
                    summary["protocols"][proto]["added"],
                    summary["protocols"][proto]["removed"],
                )
            else:
                logger.info("[skip] %s: no change (%d entries)", filename, len(new_set))
            if new_set:
                any_present = True

        cleanup_stale(expected_files)

        summary["any_present"] = any_present
        summary["duration_seconds"] = round(time.monotonic() - start, 3)

        write_summary_file(SUMMARY_FILE, summary)

        if not any_present:
            logger.warning("[warn] no proxies collected for any protocol")
            sys.exit(1)
        logger.info("[done] total time: %ss", summary["duration_seconds"])
    finally:
        release_lock(LOCKFILE)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logger.exception("Fatal error in run: %s", e)
        sys.exit(1)
