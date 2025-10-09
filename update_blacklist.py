#!/usr/bin/env python3
"""
ip_collector_simple.py

- Verilen URL listesinden sadece IP'leri toplar.
- Tekil IP'leri kaydeder.
- Aynı IP birden fazla kaynakta bulunuyorsa, level dosyalarına kaydeder.
"""

import re
import time
import requests
import ipaddress
from tqdm import tqdm
from collections import defaultdict

# ---------- AYARLAR ----------
URLS = [
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt",
    "https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/siem-black-list.txt",
    "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-30d.ipv4"
    "https://lists.blocklist.de/lists/all.txt",
    "https://cinsscore.com/list/ci-badguys.txt",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
    "https://list.rtbh.com.tr/output.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/abuse.ch-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/alienvault-precisionsec-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/cert.ssi.gouv.fr-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/cybercrime-tracker.net-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/cybercure.ai-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/digitalside.it-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/drb-ra-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/inquest.net-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/malwarebytes-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/mattyroberts.io-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/sicehice-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/sslbl.abuse.ch-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/threatview.io-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/urlabuse.com-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/urlhaus.abuse.ch-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/ut1-fr-aa.txt",
    "https://raw.githubusercontent.com/romainmarcoux/malicious-outgoing-ip/refs/heads/main/sources/viriback.com-aa.txt",
]

OUTPUT_FILE = "black-list.txt"
REQUEST_TIMEOUT = 20
SLEEP_BETWEEN = 0.5
USER_AGENT = "Mozilla/5.0 (compatible; ip-collector/1.0)"

# sadece IPv4 regex
IPv4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b'
)

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

def fetch_url(url: str) -> str | None:
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[!] Download error: {url} -> {e}")
        return None

def extract_ips(text: str) -> set:
    ips = set()
    for m in IPv4_RE.findall(text):
        try:
            ipaddress.IPv4Address(m)
            ips.add(m)
        except Exception:
            continue
    return ips

def collect_ips(urls: list) -> tuple[set, dict]:
    all_ips = set()
    ip_sources = defaultdict(set)

    for url in tqdm(urls, desc="Sources"):
        text = fetch_url(url)
        if text:
            ips = extract_ips(text)
            print(f"[+] {url} -> {len(ips)} IP found")
            for ip in ips:
                ip_sources[ip].add(url)
            all_ips.update(ips)
        time.sleep(SLEEP_BETWEEN)

    return all_ips, ip_sources

def save_ips(ips: set, base_filename: str, chunk_size: int = 130000):
    ips_sorted = sorted(ips)
    total = len(ips_sorted)
    
    if total <= chunk_size:
        with open(base_filename, "w", encoding="utf-8") as f:
            for ip in ips_sorted:
                f.write(ip + "\n")
        print(f"[+] Saved IPs: {base_filename} ({total})")
    else:
        parts = (total // chunk_size) + (1 if total % chunk_size else 0)
        for i in range(parts):
            start = i * chunk_size
            end = start + chunk_size
            part_ips = ips_sorted[start:end]
            filename = f"{base_filename.rsplit('.',1)[0]}-part{i+1}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                for ip in part_ips:
                    f.write(ip + "\n")
            print(f"[+] Saved IPs: {filename} ({len(part_ips)})")

def save_level_files(ip_sources: dict):
    files = {
        2: open("black-list-level2.txt", "w", encoding="utf-8"),
        3: open("black-list-level3.txt", "w", encoding="utf-8"),
        4: open("black-list-level4.txt", "w", encoding="utf-8"),
        5: open("black-list-level5.txt", "w", encoding="utf-8"),
    }

    try:
        for ip, sources in sorted(ip_sources.items()):
            count = len(sources)
            if count == 2:
                files[2].write(f"{ip}\n")
            elif count == 3:
                files[3].write(f"{ip}\n")
            elif count == 4:
                files[4].write(f"{ip}\n")
            elif count >= 5:
                files[5].write(f"{ip}\n")
    finally:
        for f in files.values():
            f.close()

# ---------------- MAIN ----------------
def main():
    print("[*] Starting IP collection...")
    all_ips, ip_sources = collect_ips(URLS)
    save_ips(all_ips, OUTPUT_FILE)
    save_level_files(ip_sources)
    print(f"[+] Total IP count: {len(all_ips)}")

if __name__ == "__main__":
    main()



