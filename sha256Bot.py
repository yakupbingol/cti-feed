#!/usr/bin/env python3
"""
sha256Bot.py
GitHub Actions için sadeleştirilmiş sürüm.
"""
import re
import time
import requests
from tqdm import tqdm

# ---------- AYARLAR ----------
URLS = [
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/zumanek/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/xdspy/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/worok/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/winter_vivern/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/winnti_group/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/windigo/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/virtual_invaders/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/vajraspy/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/vadokrist/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/ua_wipers/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/turla/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/toolshell/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/GhostRedirector/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/GhostRedirector/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/PlushDaemon/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/ace_cryptor/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/agrius/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/amavaldo/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/apt_c_60/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/aridspy/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/asylum_ambuscade/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/asyncrat/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/attor/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/backdoordiplomacy/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/badiis/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/ballisticbobcat/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/bandook/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/blacklotus/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/blackwood/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/bootkitty/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/buhtrap/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/casbaneiro/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/cdrthief/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/ceranakeeper/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/cloudmensis/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/cosmicbeetle/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/danabot/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/dark_iot/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/dazzlespy/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/deceptivedevelopment/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/deprimon/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/dnsbirthday/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/donot/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/dukes/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/embargo/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/emotet/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/especter/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/evasive_panda/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/evilnum/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/evilvideo/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/exchange_exploitation/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/exchange_exploitation/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/famoussparrow/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/fishmonger/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/gamaredon/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/gamarue/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/gelsemium/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/glupteba/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/gmera/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/goldenjackal/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/grandoreiro/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/gravityrat/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/gref/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/greyenergy/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/groundbait/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/guildma/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/hamkombat/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/hotpage/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/hotpage/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/hybridpetya/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/industroyer/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/interception/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/invisimole/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/janeleiro/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/kamran/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/kasidet/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/keydnap/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/mirrorface/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/mispadu/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/modiloader/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/moose/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/moustachedbouncer/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/mozi/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/mustang_panda/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/ngate/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/nightscout/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/nukesped_lazarus/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/numando/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/oceanlotus/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/oilrig/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/okrum_ke3chang/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/operation_jacana/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/operation_roundpress/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/operation_texonto/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/polonium/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/potao/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/powerpool/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/prospytospy/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/pwa_phishing/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/pypi_backdoor/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/quarterly_reports/2020_Q2/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/quarterly_reports/2020_Q3/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/quarterly_reports/2020_Q4/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/quarterly_reports/2021_T1/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/quarterly_reports/2021_T2/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/quarterly_reports/2021_T3/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/rakos/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/ramsay/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/ransomhub/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/redline/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/romcom/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/rtm/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/scarcruft/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/sednit/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/signsight/samples.sha256",
    "https://raw.githubusercontent.com/eset/malware-ioc/refs/heads/master/spalax/samples.sha256"

]
OUTPUT_UNIQUE = "malware_sha256.txt"
REQUEST_TIMEOUT = 20
SLEEP_BETWEEN = 0.5
USER_AGENT = "Mozilla/5.0 (compatible; sha256-collector/1.0)"
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

def fetch_url_text(url):
    try:
        r = session.get(url, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[!] İndirme hatası: {url} -> {e}")
        return None

def extract_sha256(text):
    return set(m.lower() for m in SHA256_RE.findall(text or ""))

def collect_and_save_unique(urls, out_file):
    seen = set()
    all_hashes = set()
    for u in tqdm(urls, desc="Kaynaklar"):
        if u in seen:
            continue
        seen.add(u)
        text = fetch_url_text(u)
        hs = extract_sha256(text)
        print(f"[+] {u} -> {len(hs)} SHA256 bulundu")
        all_hashes.update(hs)
        time.sleep(SLEEP_BETWEEN)
    with open(out_file, "w", encoding="utf-8") as f:
        for h in sorted(all_hashes):
            f.write(h + "\n")
    print(f"[+] Tekil SHA256 kaydedildi: {out_file} ({len(all_hashes)})")

if __name__ == "__main__":
    collect_and_save_unique(URLS, OUTPUT_UNIQUE)



