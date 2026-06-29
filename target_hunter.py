#!/usr/bin/env python3
"""
Target Hunter v2.0 — VPS Target Acquisition
Fixed & optimized by CAT 🐱
"""

import argparse
import json
import asyncio
import aiohttp
import ipaddress
import re
import sys
import time
import random
import string
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Any, Iterator
from pathlib import Path
import xml.etree.ElementTree as ET
import logging

# ─── Colors ──────────────────────────────────────────────────
class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    B = "\033[94m"; M = "\033[95m"; C = "\033[96m"
    W = "\033[97m"; D = "\033[2m"; BOLD = "\033[1m"; X = "\033[0m"

def p(color, msg): print(f"{color}{msg}{C.X}")

# ─── Configuration ───────────────────────────────────────────
HOSTING_ASNS = {
    "DigitalOcean": ["AS14061"],
    "Linode": ["AS63949"],
    "Vultr": ["AS20473"],
    "Hetzner": ["AS24940", "AS213549"],
    "OVH": ["AS16276"],
    "AWS": ["AS16509", "AS14618", "AS57686"],
    "Azure": ["AS8075", "AS12076"],
    "GCP": ["AS396982", "AS15169"],
    "Oracle Cloud": ["AS31898"],
    "Contabo": ["AS51167"],
    "BuyVM": ["AS53667"],
    "RackNerd": ["AS63473"],
    "HostHatch": ["AS209603"],
    "BandwagonHost": ["AS40065", "AS55329"],
    "RamNode": ["AS54456"],
    "Hostwinds": ["AS36351"],
    "AlphaRacks": ["AS62639"],
    "InceptionHosting": ["AS205112"],
    "ExtraVM": ["AS208952"],
    "Netcup": ["AS197540"],
    "Scaleway": ["AS12876"],
    "UpCloud": ["AS202286"],
    "Kamatera": ["AS47583"],
    "CloudSigma": ["AS50837"],
    "LeaseWeb": ["AS16265"],
    "WorldStream": ["AS49981"],
    "Serverius": ["AS50673"],
    "Datacamp": ["AS60068"],
    "Psychz": ["AS40676"],
    "QuadraNet": ["AS8100"],
    "ColoCrossing": ["AS36351"],
    "Mochahost": ["AS328145"],
    "A2Hosting": ["AS55293"],
    "Namecheap": ["AS22612"],
    "DreamHost": ["AS26347"],
    "Ionos": ["AS8560"],
    "Aliyun": ["AS37963", "AS45102"],
    "Tencent Cloud": ["AS45090", "AS132203"],
    "Baidu Cloud": ["AS55967"],
    "Huawei Cloud": ["AS55990"],
    "GreenCloud": ["AS394368"],
    "LunaNode": ["AS62838"],
    "HostEons": ["AS400653"],
    "RuVDS": ["AS48276"],
    "Timeweb": ["AS9123"],
    "Selectel": ["AS49505"],
    "FirstVDS": ["AS43690"],
    "Aeza": ["AS214836"],
    "Iran": ["AS49581", "AS49100", "AS44244", "AS58224", "AS31549", "AS50810"],
}

# ─── Shodan Hunter ──────────────────────────────────────────
class ShodanHunter:
    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = None
        self._retry_count = 0

    async def _get_session(self):
        if self.session is None:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=False)
            )
        return self.session

    async def _request(self, endpoint: str, params: dict = None) -> Optional[dict]:
        session = await self._get_session()
        params = params or {}
        params["key"] = self.api_key
        url = f"{self.BASE_URL}{endpoint}"

        try:
            async with session.get(url, params=params) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 401:
                    p(C.R, "  [!] Invalid Shodan API key")
                    return None
                elif resp.status == 429:
                    wait = min(60, 5 * (2 ** self._retry_count))
                    p(C.Y, f"  [!] Rate limit, waiting {wait}s...")
                    await asyncio.sleep(wait)
                    self._retry_count += 1
                    return await self._request(endpoint, params)
                else:
                    text = await resp.text()
                    p(C.R, f"  [!] Shodan error {resp.status}: {text[:100]}")
                    return None
        except Exception as e:
            p(C.R, f"  [!] Shodan request failed: {e}")
            return None

    async def search(self, query: str, limit: int = 100) -> List[dict]:
        results = []
        page = 1
        per_page = min(100, limit)
        while len(results) < limit:
            data = await self._request("/shodan/host/search", {
                "query": query, "page": page, "limit": per_page
            })
            if not data or "matches" not in data:
                break
            matches = data.get("matches", [])
            results.extend(matches)
            p(C.D, f"    Shodan page {page}: {len(matches)} (total {len(results)})")
            if len(matches) < per_page:
                break
            page += 1
            await asyncio.sleep(1)
        return results[:limit]

    async def search_vps(self, provider: str = None, country: str = None,
                         limit: int = 100) -> List[dict]:
        queries = []
        if provider and provider in HOSTING_ASNS:
            for asn in HOSTING_ASNS[provider]:
                q = f"asn:{asn} port:22"
                if country: q += f" country:{country}"
                queries.append(q)
        else:
            base = "port:22"
            if country: base += f" country:{country}"
            queries = [
                f'{base} "OpenSSH"', f'{base} "Ubuntu"', f'{base} "Debian"',
                f'{base} org:"DigitalOcean"', f'{base} org:"Linode"',
                f'{base} org:"Hetzner"', f'{base} org:"OVH"',
                f'{base} org:"Vultr Holdings"',
            ]
        all_results = []
        per_query = max(10, limit // len(queries))
        for q in queries:
            if len(all_results) >= limit: break
            res = await self.search(q, per_query)
            all_results.extend(res)
            await asyncio.sleep(2)
        # Dedup by IP
        seen = set()
        unique = []
        for r in all_results:
            ip = r.get("ip_str")
            if ip and ip not in seen:
                seen.add(ip)
                unique.append(r)
        return unique[:limit]

    async def close(self):
        if self.session:
            await self.session.close()

# ─── Censys Hunter (fixed v2) ──────────────────────────────
class CensysHunter:
    BASE_URL = "https://search.censys.io/api/v2"

    def __init__(self, api_id: str, api_secret: str):
        self.api_id = api_id
        self.api_secret = api_secret
        self.session = None

    async def _get_session(self):
        if self.session is None:
            auth = aiohttp.BasicAuth(self.api_id, self.api_secret)
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=False),
                auth=auth
            )
        return self.session

    async def search(self, query: str, limit: int = 100) -> List[dict]:
        session = await self._get_session()
        results = []
        cursor = None
        while len(results) < limit:
            params = {
                "q": query,
                "per_page": min(100, limit - len(results))
            }
            if cursor: params["cursor"] = cursor
            try:
                async with session.get(f"{self.BASE_URL}/hosts/search", params=params) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        hits = data.get("result", {}).get("hits", [])
                        results.extend(hits)
                        cursor = data.get("result", {}).get("links", {}).get("next")
                        p(C.D, f"    Censys: {len(hits)} results (total {len(results)})")
                        if not cursor: break
                    else:
                        text = await resp.text()
                        p(C.R, f"  [!] Censys error {resp.status}: {text[:100]}")
                        break
            except Exception as e:
                p(C.R, f"  [!] Censys request failed: {e}")
                break
            await asyncio.sleep(1)
        return results[:limit]

    async def search_vps(self, provider: str = None, country: str = None,
                         limit: int = 100) -> List[dict]:
        # Proper Censys v2 query syntax
        parts = ['services.service_name: SSH']
        if provider and provider in HOSTING_ASNS:
            asn_list = HOSTING_ASNS[provider]
            asn_q = " OR ".join(f'autonomous_system.asn:{asn}' for asn in asn_list)
            parts.append(f"({asn_q})")
        if country:
            parts.append(f"location.country_code:{country.upper()}")
        query = " AND ".join(parts)
        return await self.search(query, limit)

    async def close(self):
        if self.session:
            await self.session.close()

# ─── ASN Expander (memory‑efficient) ──────────────────────
class ASNExpander:
    def __init__(self):
        self.session = None
        self.cache: Dict[str, List[str]] = {}

    async def _get_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=20),
                connector=aiohttp.TCPConnector(ssl=False)
            )
        return self.session

    async def get_asn_prefixes(self, asn: str) -> List[str]:
        asn_clean = asn.replace("AS", "")
        if asn_clean in self.cache:
            return self.cache[asn_clean]
        prefixes = []
        session = await self._get_session()
        sources = [
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_clean}",
            f"https://api.bgpview.io/asn/{asn_clean}/prefixes",
        ]
        for url in sources:
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if "data" in data and "prefixes" in data["data"]:
                            # RIPE format
                            for p in data["data"]["prefixes"]:
                                pref = p.get("prefix")
                                if pref: prefixes.append(pref)
                            break
                        elif "data" in data and "ipv4_prefixes" in data["data"]:
                            # BGPView
                            for p in data["data"]["ipv4_prefixes"]:
                                pref = p.get("prefix")
                                if pref: prefixes.append(pref)
                            break
            except:
                continue
            await asyncio.sleep(0.5)
        prefixes = list(set(prefixes))
        self.cache[asn_clean] = prefixes
        return prefixes

    async def expand_asns_to_ips(self, asns: List[str], sample_rate: float = 0.001) -> List[str]:
        """Stream IPs without materialising full /16s."""
        all_ips = set()
        for asn in asns:
            prefixes = await self.get_asn_prefixes(asn)
            for pref in prefixes:
                try:
                    net = ipaddress.ip_network(pref, strict=False)
                    # Iterate hosts lazily
                    host_iter = net.hosts()
                    # If sample_rate < 1, take random sample without building list
                    if sample_rate < 1.0:
                        # Use reservoir sampling to avoid storing all hosts
                        # But we need to know total count for uniform sampling; instead we'll just take first N? 
                        # Better: take every K-th host (systematic sampling)
                        step = int(1 / sample_rate) if sample_rate > 0 else 1
                        count = 0
                        for ip in host_iter:
                            if count % step == 0:
                                all_ips.add(str(ip))
                            count += 1
                            if len(all_ips) > 100000:  # safety limit
                                break
                    else:
                        # Take all
                        for ip in host_iter:
                            all_ips.add(str(ip))
                except Exception:
                    continue
            await asyncio.sleep(0.3)
        return list(all_ips)

    async def get_provider_ips(self, provider: str, sample_rate: float = 0.001) -> List[str]:
        if provider not in HOSTING_ASNS:
            p(C.Y, f"  [!] Unknown provider: {provider}")
            return []
        return await self.expand_asns_to_ips(HOSTING_ASNS[provider], sample_rate)

    async def close(self):
        if self.session:
            await self.session.close()

# ─── Masscan Parser ──────────────────────────────────────────
class MasscanParser:
    @staticmethod
    def parse_xml(filepath: str) -> List[dict]:
        results = []
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            for host in root.findall("host"):
                ip = host.get("addr", "")
                ports = []
                for port in host.findall("ports/port"):
                    ports.append({
                        "port": int(port.get("portid")),
                        "protocol": port.get("protocol", "tcp"),
                        "state": port.get("state", "open"),
                    })
                if ip and ports:
                    results.append({"ip": ip, "ports": ports})
        except Exception as e:
            p(C.R, f"  [!] XML parse error: {e}")
        return results

    @staticmethod
    def parse_json(filepath: str) -> List[dict]:
        results = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    try:
                        entry = json.loads(line)
                        results.append({
                            "ip": entry.get("ip", ""),
                            "ports": [{
                                "port": entry.get("port", 0),
                                "protocol": entry.get("proto", "tcp"),
                                "state": "open",
                            }]
                        })
                    except: pass
        except Exception as e:
            p(C.R, f"  [!] JSON parse error: {e}")
        return results

    @staticmethod
    def parse_list(filepath: str) -> List[dict]:
        ips = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ':' in line and not '::' in line:
                            ip = line.split(':')[0]
                        else:
                            ip = line
                        ips.append({"ip": ip, "ports": []})
        except Exception as e:
            p(C.R, f"  [!] List parse error: {e}")
        return ips

    @staticmethod
    def parse(filepath: str) -> List[dict]:
        if not Path(filepath).exists():
            p(C.R, f"  [!] File not found: {filepath}")
            return []
        if filepath.endswith('.xml'):
            return MasscanParser.parse_xml(filepath)
        elif filepath.endswith('.json'):
            return MasscanParser.parse_json(filepath)
        else:
            return MasscanParser.parse_list(filepath)

# ─── Live Prober (collects all ports) ──────────────────────
class LiveProber:
    def __init__(self, ports: List[int] = None, timeout: float = 2.0,
                 concurrent: int = 500):
        self.ports = ports or [22, 80, 443]
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrent)

    async def probe(self, ip: str) -> Optional[dict]:
        async with self.semaphore:
            open_ports = []
            for port in self.ports:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=self.timeout
                    )
                    open_ports.append(port)
                    writer.close()
                    await writer.wait_closed()
                except:
                    continue
            if open_ports:
                return {"ip": ip, "ports": open_ports, "alive": True}
            return None

    async def filter_alive(self, targets: List[str]) -> List[dict]:
        p(C.B, f"[*] Probing {len(targets)} targets...")
        tasks = [self.probe(ip) for ip in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        alive = [r for r in results if r is not None and isinstance(r, dict)]
        p(C.G, f"[+] {len(alive)}/{len(targets)} hosts alive")
        return alive

# ─── Output Manager ──────────────────────────────────────────
class OutputManager:
    def __init__(self, base_name: str = "targets"):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base = f"{base_name}_{ts}"

    def save_ips(self, targets: List[dict], filename: str = None):
        fname = filename or f"{self.base}.txt"
        with open(fname, 'w') as f:
            for t in targets:
                f.write(t["ip"] + "\n")
        p(C.G, f"[+] Saved {len(targets)} IPs to {fname}")
        return fname

    def save_with_ports(self, targets: List[dict], filename: str = None):
        fname = filename or f"{self.base}_ports.txt"
        with open(fname, 'w') as f:
            for t in targets:
                ip = t["ip"]
                ports = t.get("ports", [])
                if ports:
                    for port_info in ports:
                        port = port_info.get("port", port_info) if isinstance(port_info, dict) else port_info
                        f.write(f"{ip}:{port}\n")
                else:
                    f.write(ip + "\n")
        p(C.G, f"[+] Saved with ports to {fname}")
        return fname

    def save_json(self, targets: List[dict], filename: str = None):
        fname = filename or f"{self.base}.json"
        with open(fname, 'w') as f:
            json.dump(targets, f, indent=2, default=str)
        p(C.G, f"[+] Saved JSON to {fname}")
        return fname

    def save_masscan_input(self, targets: List[dict], filename: str = None):
        fname = filename or f"{self.base}_masscan.txt"
        with open(fname, 'w') as f:
            for t in targets:
                f.write(t["ip"] + "\n")
        p(C.G, f"[+] Masscan input saved to {fname}")
        return fname

# ─── Target Hunter Orchestrator ────────────────────────────
class TargetHunter:
    def __init__(self, args):
        self.args = args
        self.output = OutputManager("targets")
        self.shodan = None
        self.censys = None
        self.asn_expander = ASNExpander()
        self.all_targets: List[dict] = []

    def _extract_ips_from_shodan(self, results: List[dict]) -> List[dict]:
        targets = []
        for r in results:
            ip = r.get("ip_str")
            if not ip: continue
            ports = [{"port": p, "protocol": "tcp", "state": "open"} for p in r.get("ports", [])]
            targets.append({
                "ip": ip, "ports": ports,
                "hostname": r.get("hostnames", [""])[0] if r.get("hostnames") else "",
                "org": r.get("org", ""), "isp": r.get("isp", ""),
                "location": r.get("location", {}).get("country_name", ""),
                "os": r.get("os", ""), "product": r.get("product", ""),
                "source": "shodan",
            })
        return targets

    def _extract_ips_from_censys(self, results: List[dict]) -> List[dict]:
        targets = []
        for r in results:
            ip = r.get("ip")
            if not ip: continue
            ports = []
            services = r.get("services", [])
            if isinstance(services, list):
                for svc in services:
                    port = svc.get("port")
                    if port:
                        ports.append({"port": port, "protocol": svc.get("transport_protocol", "tcp"), "state": "open"})
            targets.append({
                "ip": ip, "ports": ports,
                "hostname": "",
                "org": r.get("autonomous_system", {}).get("name", ""),
                "isp": "",
                "location": r.get("location", {}).get("country", ""),
                "os": "", "product": "",
                "source": "censys",
            })
        return targets

    async def run_shodan(self) -> List[dict]:
        if not self.args.shodan_key:
            return []
        p(C.BOLD, "\n[*] Source: Shodan")
        p(C.D, "─" * 40)
        self.shodan = ShodanHunter(self.args.shodan_key)
        raw = []
        if self.args.shodan_query:
            p(C.B, f"  [*] Query: {self.args.shodan_query}")
            raw = await self.shodan.search(self.args.shodan_query, self.args.limit)
        elif self.args.provider:
            p(C.B, f"  [*] Provider: {self.args.provider}")
            raw = await self.shodan.search_vps(self.args.provider, self.args.country, self.args.limit)
        else:
            p(C.B, f"  [*] General VPS (country: {self.args.country or 'any'})")
            raw = await self.shodan.search_vps(None, self.args.country, self.args.limit)
        await self.shodan.close()
        targets = self._extract_ips_from_shodan(raw)
        p(C.G, f"  [+] Shodan: {len(targets)} unique targets")
        return targets

    async def run_censys(self) -> List[dict]:
        if not self.args.censys_id or not self.args.censys_secret:
            return []
        p(C.BOLD, "\n[*] Source: Censys")
        p(C.D, "─" * 40)
        self.censys = CensysHunter(self.args.censys_id, self.args.censys_secret)
        raw = await self.censys.search_vps(self.args.provider, self.args.country, self.args.limit)
        await self.censys.close()
        targets = self._extract_ips_from_censys(raw)
        p(C.G, f"  [+] Censys: {len(targets)} unique targets")
        return targets

    async def run_asn(self) -> List[dict]:
        if not self.args.asn and not self.args.provider:
            return []
        p(C.BOLD, "\n[*] Source: ASN Expansion")
        p(C.D, "─" * 40)
        asns = []
        if self.args.asn:
            for a in self.args.asn.split(','):
                a = a.strip().upper()
                if not a.startswith("AS"): a = "AS" + a
                asns.append(a)
        elif self.args.provider and self.args.provider in HOSTING_ASNS:
            asns = HOSTING_ASNS[self.args.provider]
        if not asns:
            return []
        p(C.B, f"  [*] Expanding {len(asns)} ASNs...")
        ips = await self.asn_expander.expand_asns_to_ips(asns, self.args.sample_rate)
        targets = [{"ip": ip, "ports": [], "source": "asn"} for ip in ips]
        p(C.G, f"  [+] ASN: {len(targets)} IPs")
        return targets

    def run_file(self) -> List[dict]:
        if not self.args.input:
            return []
        p(C.BOLD, "\n[*] Source: Input File")
        p(C.D, "─" * 40)
        targets = MasscanParser.parse(self.args.input)
        p(C.G, f"  [+] Parsed {len(targets)} entries from {self.args.input}")
        return targets

    async def run(self):
        # Banner
        p(f"{C.C}{C.BOLD}", """
    ╦ ╦┌─┐┬  ┬┌─┐┌┐  ╔╦╗┌─┐┌┐ ╔═╗┬┬  ┌─┐
    ║║║├┤ └┐┌┘├┤ ├┴┐  ║ ├┤ ├┴┐║ ╦││  ├┤ 
    ╚╩╝└─┘ └┘ └─┘└─┘  ╩ └─┘└─┘╚═╝┴┴─┘└─┘
    ─────────────────────────────────────
    Target Hunter v2.0 | Fixed by CAT 🐱
    ─────────────────────────────────────
""")

        all_targets = []
        seen_ips: Set[str] = set()

        sources = []
        file_t = self.run_file()
        if file_t: sources.append(file_t)
        asn_t = await self.run_asn()
        if asn_t: sources.append(asn_t)
        shodan_t = await self.run_shodan()
        if shodan_t: sources.append(shodan_t)
        censys_t = await self.run_censys()
        if censys_t: sources.append(censys_t)

        if not sources:
            p(C.Y, """
  No target sources specified! Use:
    -i, --input FILE         IP list or masscan output
    --shodan-key KEY         Shodan API key
    --shodan-query QUERY     Custom Shodan query
    --censys-id ID           Censys API ID
    --censys-secret SECRET   Censys API Secret
    --provider NAME          Known provider
    --asn ASN1,ASN2,...      Custom ASN list
    --country CC             Country code
    --limit N                Max results per source
    --sample-rate FLOAT      ASN sample rate
    --probe                  Verify alive
    --probe-ports PORTS      Ports for probing
  Examples:
    python target_hunter.py --shodan-key KEY --country DE --limit 500
    python target_hunter.py --provider Hetzner --sample-rate 0.01 --probe
""")
            return

        # Merge and deduplicate, merging port lists
        for source in sources:
            for t in source:
                ip = t.get("ip")
                if not ip: continue
                if ip in seen_ips:
                    # Merge ports
                    existing = next(x for x in all_targets if x["ip"] == ip)
                    existing_ports = {p.get("port", p) if isinstance(p, dict) else p for p in existing.get("ports", [])}
                    new_ports = [p for p in t.get("ports", []) if (p.get("port", p) if isinstance(p, dict) else p) not in existing_ports]
                    existing["ports"].extend(new_ports)
                    # Merge other fields? Keep first source info, but update if missing
                    for key in ["org", "isp", "location", "os", "product", "hostname"]:
                        if not existing.get(key) and t.get(key):
                            existing[key] = t[key]
                else:
                    seen_ips.add(ip)
                    # Ensure ports list exists
                    if "ports" not in t:
                        t["ports"] = []
                    all_targets.append(t)

        p(C.BOLD, f"\n[*] Total unique targets: {len(all_targets)}")

        # Optional probing
        if self.args.probe and all_targets:
            probe_ports = []
            if self.args.probe_ports:
                probe_ports = [int(p.strip()) for p in self.args.probe_ports.split(',')]
            prober = LiveProber(ports=probe_ports, timeout=2.0, concurrent=500)
            alive = await prober.filter_alive([t["ip"] for t in all_targets])
            alive_ips = {t["ip"] for t in alive}
            all_targets = [t for t in all_targets if t["ip"] in alive_ips]
            p(C.G, f"[+] After probing: {len(all_targets)} alive hosts")

        # Save
        if all_targets:
            self.output.save_ips(all_targets)
            self.output.save_with_ports(all_targets)
            self.output.save_json(all_targets)
            self.output.save_masscan_input(all_targets)
            p(C.D, "\n[*] Sample targets:")
            for t in all_targets[:10]:
                ip = t["ip"]
                ports = [str(p.get("port", p)) if isinstance(p, dict) else str(p) for p in t.get("ports", [])]
                port_str = f":{','.join(ports)}" if ports else ""
                info = " | ".join(filter(None, [t.get("source",""), t.get("org",""), t.get("location","")]))
                p(C.D, f"    {ip}{port_str}  {C.DIM}({info}){C.X}")
            if len(all_targets) > 10:
                p(C.D, f"    ... and {len(all_targets)-10} more")

        await self.asn_expander.close()
        p(C.G, f"\n[+] Done! Feed the .txt to VPS Hunter for scanning.")

# ─── CLI ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Target Hunter v2.0")
    parser.add_argument("-i", "--input", help="Input file")
    parser.add_argument("--shodan-key", help="Shodan API key")
    parser.add_argument("--shodan-query", help="Custom Shodan query")
    parser.add_argument("--censys-id", help="Censys API ID")
    parser.add_argument("--censys-secret", help="Censys API Secret")
    parser.add_argument("--provider", help="Provider name")
    parser.add_argument("--asn", help="ASN list")
    parser.add_argument("--country", help="Country code")
    parser.add_argument("--limit", type=int, default=100, help="Max per source")
    parser.add_argument("--sample-rate", type=float, default=0.001, help="ASN sample rate")
    parser.add_argument("--probe", action="store_true", help="Verify alive")
    parser.add_argument("--probe-ports", default="22,80,443", help="Probe ports")
    args = parser.parse_args()

    hunter = TargetHunter(args)
    try:
        asyncio.run(hunter.run())
    except KeyboardInterrupt:
        p(C.Y, "\n[!] Interrupted")
    except Exception as e:
        p(C.R, f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()