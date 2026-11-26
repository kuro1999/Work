"""Download controllati e cache: regole, README Vulhub e PoC.

Permette --offline e limita le sorgenti GitHub autorizzate. I download
servono solo a leggere testo, mai ad eseguire exploit.
"""
from __future__ import annotations
import hashlib
import os
import threading
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

from .utils import (MAX_BYTES, POC_MAX_BYTES, POC_API_BUDGET_DEFAULT,
                    USER_AGENT, github_raw_url, safe_vulhub_readme_url)


class RuleCache:
    def __init__(self, folder, *, offline=False, refresh=False, timeout=15):
        self.folder = folder
        self.folder.mkdir(parents=True, exist_ok=True)
        self.offline = offline
        self.refresh = refresh
        self.timeout = timeout
        self.memo = {}
        self.stats = Counter()
        self.lock = threading.Lock()

    def get(self, url, repo):
        try:
            raw_url = github_raw_url(url, repo)
        except ValueError as exc:
            return None, "invalid_url: " + str(exc), ""
        with self.lock:
            if raw_url in self.memo:
                return self.memo[raw_url]
        key = hashlib.sha256(raw_url.encode("utf-8")).hexdigest()
        suffix = ".toml" if raw_url.endswith(".toml") else ".yaml"
        path = self.folder / (key + suffix)
        if path.is_file() and not self.refresh:
            try:
                content = path.read_bytes()
                if len(content) > MAX_BYTES:
                    raise ValueError("cache troppo grande")
                with self.lock: self.stats["from_cache"] += 1
                out = (content.decode("utf-8-sig"), "", hashlib.sha256(content).hexdigest())
            except (UnicodeError, OSError, ValueError) as exc:
                out = (None, "cache_error: " + str(exc), "")
        elif self.offline:
            with self.lock: self.stats["cache_miss"] += 1
            out = (None, "offline_cache_missing", "")
        else:
            try:
                req = urllib.request.Request(raw_url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    # Non seguire redirect verso host sconosciuti: ricontrolliamo il finale.
                    final = urlsplit(response.url)
                    if final.scheme != "https" or final.netloc.lower() != "raw.githubusercontent.com":
                        raise ValueError("Redirect verso host non autorizzato")
                    content = response.read(MAX_BYTES + 1)
                if len(content) > MAX_BYTES:
                    raise ValueError("File remoto troppo grande")
                text = content.decode("utf-8-sig")
                path.write_bytes(content)
                with self.lock: self.stats["downloaded"] += 1
                out = (text, "", hashlib.sha256(content).hexdigest())
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, ValueError, UnicodeError) as exc:
                with self.lock: self.stats["fetch_error"] += 1
                out = (None, "fetch_error: " + str(exc)[:220], "")
        with self.lock:
            self.memo[raw_url] = out
        return out

    def prefetch(self, rule_sources):
        """Scarica una volta per URL e in parallelo (rapido anche se GitHub non risponde)."""
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda pair: self.get(*pair), rule_sources))


class VulhubCache:
    def __init__(self, folder: Path, *, offline=False, refresh=False, timeout=12):
        self.folder = folder
        self.folder.mkdir(parents=True, exist_ok=True)
        self.offline, self.refresh, self.timeout = offline, refresh, timeout
        self.memo = {}
        self.stats = Counter()
        self.lock = threading.Lock()

    def get(self, path):
        try:
            url = safe_vulhub_readme_url(path)
        except ValueError as exc:
            return None, f"invalid_path: {exc}", ""
        with self.lock:
            if url in self.memo:
                return self.memo[url]
        key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        cache_file = self.folder / (key + ".md")
        if cache_file.is_file() and not self.refresh:
            try:
                body = cache_file.read_bytes()
                if len(body) > MAX_BYTES:
                    raise ValueError("README in cache troppo grande")
                value = (body.decode("utf-8-sig"), "", hashlib.sha256(body).hexdigest())
                with self.lock:
                    self.stats["from_cache"] += 1
            except (OSError, ValueError, UnicodeError) as exc:
                value = (None, "cache_error: " + str(exc), "")
        elif self.offline:
            with self.lock:
                self.stats["cache_miss"] += 1
            value = (None, "offline_cache_missing", "")
        else:
            try:
                request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    final_url = urlsplit(response.url)
                    if final_url.scheme != "https" or final_url.netloc.lower() != "raw.githubusercontent.com":
                        raise ValueError("Redirect verso host non autorizzato")
                    body = response.read(MAX_BYTES + 1)
                if len(body) > MAX_BYTES:
                    raise ValueError("README remoto troppo grande")
                decoded = body.decode("utf-8-sig")
                cache_file.write_bytes(body)
                with self.lock:
                    self.stats["downloaded"] += 1
                value = (decoded, "", hashlib.sha256(body).hexdigest())
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
                    OSError, ValueError, UnicodeError) as exc:
                with self.lock:
                    self.stats["fetch_error"] += 1
                value = (None, "fetch_error: " + str(exc)[:200], "")
        with self.lock:
            self.memo[url] = value
        return value

    def prefetch(self, paths):
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(self.get, paths))


class PocCache:
    def __init__(self, folder, *, offline=False, refresh=False, api_budget=POC_API_BUDGET_DEFAULT, timeout=12):
        self.folder = folder
        self.folder.mkdir(parents=True, exist_ok=True)
        self.offline, self.refresh, self.timeout = offline, refresh, timeout
        self.api_budget = max(0, api_budget)
        self.api_used = 0
        self.rate_limited = False
        self.stats = Counter()

    def get(self, url, api=False):
        p = urlsplit(url)
        if p.scheme != 'https' or p.netloc.lower() not in ('api.github.com', 'raw.githubusercontent.com'):
            return None, 'invalid_host'
        if api != (p.netloc.lower() == 'api.github.com'):
            return None, 'invalid_api_kind'
        key = hashlib.sha256(url.encode('utf-8')).hexdigest()
        path = self.folder / (key + ('.json' if api else '.txt'))
        if path.is_file() and not self.refresh:
            try:
                b = path.read_bytes()
                if len(b) > (800_000 if api else POC_MAX_BYTES):
                    raise ValueError('cached_file_too_large')
                self.stats['from_cache'] += 1
                return b.decode('utf-8-sig'), ''
            except (OSError, UnicodeError, ValueError):
                return None, 'cache_error'
        if self.offline:
            self.stats['cache_miss'] += 1
            return None, 'offline_cache_missing'
        if api:
            if self.rate_limited:
                self.stats['api_limit_skipped'] += 1
                return None, 'github_rate_limited'
            if self.api_used >= self.api_budget:
                self.stats['api_budget_skipped'] += 1
                return None, 'api_budget_exhausted'
            self.api_used += 1
        try:
            h = {'User-Agent': USER_AGENT, 'Accept': 'application/vnd.github+json' if api else 'text/plain'}
            # Token facoltativo, mai scritto in cache o output.
            if api and os.environ.get('GITHUB_TOKEN'):
                h['Authorization'] = 'Bearer ' + os.environ['GITHUB_TOKEN']
            request = urllib.request.Request(url, headers=h)
            with urllib.request.urlopen(request, timeout=self.timeout) as r:
                f = urlsplit(r.url)
                if f.scheme != 'https' or f.netloc.lower() != p.netloc.lower():
                    return None, 'unsafe_redirect'
                b = r.read((800_000 if api else POC_MAX_BYTES)+1)
            if len(b) > (800_000 if api else POC_MAX_BYTES):
                return None, 'file_too_large'
            text = b.decode('utf-8-sig')
            path.write_bytes(b)
            self.stats['api_downloaded' if api else 'files_downloaded'] += 1
            return text, ''
        except urllib.error.HTTPError as e:
            if api and (e.code == 429 or (e.code == 403 and e.headers.get('x-ratelimit-remaining') == '0')):
                self.rate_limited = True
                self.stats['rate_limit_reached'] += 1
                return None, 'github_rate_limited'
            self.stats['http_error'] += 1
            return None, f'http_{e.code}'
        except (urllib.error.URLError, TimeoutError, OSError, UnicodeError, ValueError):
            self.stats['fetch_error'] += 1
            return None, 'download_error'
