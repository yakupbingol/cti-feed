#!/usr/bin/env python3
"""
ip_collector_simple.py

- Verilen URL listesinden sadece IP'leri toplar.
- Tekil IP'leri kaydeder ve her 5 dakikada bir günceller.
- Aynı IP birden fazla kaynakta bulunuyorsa, hem ortak listeye hem de kaç kaynakta geçtiğine göre level dosyalarına kaydeder.
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
    "https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/black-list.txt",
    "https://lists.blocklist.de/lists/all.txt",
    "https://cinsscore.com/list/ci-badguys.txt",
    "https://www.spamhaus.org/drop/drop.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
    "https://list.rtbh.com.tr/output.txt",
    "https://raw.githubusercontent.com/securewanltd/cti-feed/refs/heads/main/siem-black-list.txt",
    "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main/abuseipdb-s100-30d.ipv4",

]

OUTPUT_FILE = "black-list-level1.txt"
#ORTAK_FILE = "ortak_ips.txt"
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


# ---------------- MODÜLLER ----------------
def fetch_url(url: str) -> str | None:
    """URL'den içerik indirir, hata varsa None döner."""
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[!] İndirme hatası: {url} -> {e}")
        return None


def extract_ips(text: str) -> set:
    """Verilen metin içerisindeki IPv4 adreslerini bulur."""
    ips = set()
    for m in IPv4_RE.findall(text):
        try:
            ipaddress.IPv4Address(m)
            ips.add(m)
        except Exception:
            continue
    return ips


def collect_ips(urls: list) -> tuple[set, dict]:
    """
    Tüm URL'lerden tekil IP'leri toplar.
    Ayrıca her IP'nin hangi kaynaklarda bulunduğunu kaydeder.
    """
    all_ips = set()
    ip_sources = defaultdict(set)  # IP -> {url1, url2, ...}

    #progress bar oluşturarak gösterir
    for url in tqdm(urls, desc="Kaynaklar"):
        text = fetch_url(url)
        if text:
            ips = extract_ips(text)
            print(f"[+] {url} -> {len(ips)} IP bulundu")
            for ip in ips:
                ip_sources[ip].add(url)
            all_ips.update(ips)
        time.sleep(SLEEP_BETWEEN)

    return all_ips, ip_sources


# ------------------ TEKİL IP KAYDETME ------------------
def save_ips(ips: set, base_filename: str, chunk_size: int = 130000):
    """
    Tekil IP'leri dosyalara kaydeder.
    Eğer IP sayısı chunk_size'dan fazla ise, birden fazla dosya oluşturur:
    base_filename-part1.txt, base_filename-part2.txt, ...
    """
    ips_sorted = sorted(ips)
    total = len(ips_sorted)
    
    if total <= chunk_size:
        # Tek dosya
        with open(base_filename, "w", encoding="utf-8") as f:
            for ip in ips_sorted:
                f.write(ip + "\n")
        print(f"[+] Tekil IP'ler kaydedildi: {base_filename} ({total})")
    else:
        # Bölmeli kaydetme
        parts = (total // chunk_size) + (1 if total % chunk_size else 0)
        for i in range(parts):
            start = i * chunk_size
            end = start + chunk_size
            part_ips = ips_sorted[start:end]
            filename = f"{base_filename.rsplit('.',1)[0]}-part{i+1}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                for ip in part_ips:
                    f.write(ip + "\n")
            print(f"[+] Tekil IP'ler kaydedildi: {filename} ({len(part_ips)})")


# ------------------ ORTAK IP KAYDETME ------------------
def save_ortak_ips(ip_sources: dict, filename: str):
    """Birden fazla kaynakta geçen IP'leri ve kaynaklarını dosyaya yazar."""
    #with open(filename, "w", encoding="utf-8") as f:
     #   for ip, sources in sorted(ip_sources.items()):
      #      if len(sources) > 1:
       #         f.write(f"{ip} -> {', '.join(sorted(sources))}\n")
   # print(f"[+] Ortak IP'ler kaydedildi: {filename}")


# ------------------ LEVEL DOSYALARI ------------------
def save_level_files(ip_sources: dict):
    """IP kaç kaynakta geçmişse ona göre level2–level5 dosyalarına yazar."""
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
                files[2].write(f"{ip} \n")
            elif count == 3:
                files[3].write(f"{ip} \n")
            elif count == 4:
                files[4].write(f"{ip} \n")
            elif count >= 5:
                files[5].write(f"{ip} \n")

        #print("[+] Level2–5 dosyaları kaydedildi.")
    finally:
        for f in files.values():
            f.close()


# ---------------- ANA DÖNGÜ ----------------
def main_loop():
    print("[*] IP toplama baslatildi...")
    while True:
        try:
            all_ips, ip_sources = collect_ips(URLS)

            #ortak_count = sum(1 for s in ip_sources.values() if len(s) > 1)
            #print(f"[=] Ortak IP sayısı (birden fazla kaynakta geçen): {ortak_count}")

            # Tekil IP'leri part dosyalarıyla kaydet
            save_ips(all_ips, OUTPUT_FILE)
            #save_ortak_ips(ip_sources, ORTAK_FILE)
            save_level_files(ip_sources)

        except KeyboardInterrupt:
            print("Calisma durduruldu (CTRL+C).")
            break
        except Exception as e:
            print(f"[!] Beklenmeyen hata: {e}")

        # 5 dakika bekle
        time.sleep(300)


if __name__ == "__main__":
    main_loop()
