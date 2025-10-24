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
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt",
    "https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/siem-black-list.txt",
    "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-30d.ipv4",
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
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/7777%20Botnet%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Ares%20RAT%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/AsyncRAT%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/BitRAT%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Brute%20Ratel%20C4%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/BurpSuite%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Caldera%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Cobalt%20Strike%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Covenant%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/DarkComet%20Trojan%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/DcRAT%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Deimos%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Gh0st%20RAT%20Trojan%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/GoPhish%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Hak5%20Cloud%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Havoc%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Hookbot%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Metasploit%20Framework%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/MobSF%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Mozi%20Botnet%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Mythic%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/NanoCore%20RAT%20Trojan%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/NetBus%20Trojan%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/NimPlant%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Orcus%20RAT%20Trojan%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Oyster%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/PANDA%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Quasar%20RAT%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Pantegana%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/RedGuard%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Remcos%20RAT%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Sectop%20RAT%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/ShadowPad%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Sliver%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/SpiceRAT%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/SpyAgent%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Supershell%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Unam%20Web%20Panel%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Villain%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Viper%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/Vshell%20C2%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/XMRig%20Monero%20Cryptominer%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/XtremeRAT%20Trojan%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/all.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/refs/heads/main/data/njRAT%20Trojan%20IPs.txt"
    
    
    
    
    
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
        # Tek dosya yeterli
        with open(base_filename, "w", encoding="utf-8") as f:
            for ip in ips_sorted:
                f.write(ip + "\n")
        print(f"[+] Saved IPs: {base_filename} ({total})")
    else:
        # Parçalara böl ve kaydet
        parts = (total // chunk_size) + (1 if total % chunk_size else 0)
        filenames = []

        for i in range(parts):
            start = i * chunk_size
            end = start + chunk_size
            part_ips = ips_sorted[start:end]

            # "black-list-level1.txt" → "black-list" → "black"
            filename = f"{base_filename.rsplit('.',1)[0]}-part{i+1}.txt"
            filenames.append(filename)

            with open(filename, "w", encoding="utf-8") as f:
                for ip in part_ips:
                    f.write(ip + "\n")
            print(f"[+] Saved IPs: {filename} ({len(part_ips)})")

        # Parçaları birleştir
        with open(base_filename, "w", encoding="utf-8") as merged:
            for file in filenames:
                with open(file, "r", encoding="utf-8") as f:
                    merged.write(f.read())
        print(f"[+] Combined file created: {base_filename} ({total})")



def save_level_files(ip_sources: dict):
    files = {
        1: open("black-list-level1.txt", "w", encoding="utf-8"),
        2: open("black-list-level2.txt", "w", encoding="utf-8"),
        3: open("black-list-level3.txt", "w", encoding="utf-8"),
        4: open("black-list-level4.txt", "w", encoding="utf-8"),
        5: open("black-list-level5.txt", "w", encoding="utf-8"),
    }

    try:
        for ip, sources in sorted(ip_sources.items()):
            count = len(sources)
            if count == 1:
                files[1].write(f"{ip}\n")                
            elif count == 2:
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






