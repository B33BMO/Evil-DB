import requests
import sqlite3
from datetime import datetime

DB_PATH = "evil-db/db/threats.db"

def insert_ip(ip, category, source, severity="high", notes=""):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO threat_indicators (type, value, category, source, first_seen, severity, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "ip",
            ip,
            category,
            source,
            datetime.utcnow().strftime("%Y-%m-%d"),
            severity,
            notes
        ))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

def firehol_level1():
    print("🔥 FireHOL...")
    url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    r = requests.get(url)
    for line in r.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            insert_ip(line, "malicious", "firehol_level1", "high", "Auto-imported")

def blocklist_de():
    print("💣 blocklist.de...")
    url = "https://lists.blocklist.de/lists/all.txt"
    r = requests.get(url)
    for line in r.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            insert_ip(line, "ssh_brute", "blocklist_de", "medium", "Aggressive brute force")

def artillery_banlist():
    print("🛡️  Artillery banlist...")
    url = "https://raw.githubusercontent.com/trustedsec/artillery/master/banlist.txt"
    r = requests.get(url)
    for line in r.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            insert_ip(line, "honeypot", "artillery", "medium", "Honeypot caught")

def malwaredomainlist():
    print("🦠 MalwareDomainList...")
    url = "http://www.malwaredomainlist.com/hostslist/hosts.txt"
    r = requests.get(url)
    for line in r.text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            insert_ip(ip, "malware", "malwaredomainlist", "medium", "Malware-serving domain")

def binarydefense_artillery():
    print("⚔️  Binary Defense Artillery...")
    url = "https://raw.githubusercontent.com/trustedsec/artillery/master/banlist.txt"
    r = requests.get(url)
    for line in r.text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            insert_ip(line, "honeypot", "binarydefense_artillery", "medium", "Caught by honeypot")

def run_all_feeds():
    print("🚀 Starting EvilWatch Feed Importer")
    firehol_level1() 
    blocklist_de()
    artillery_banlist()
    malwaredomainlist()
    binarydefense_artillery()
    print("✅ Done.")

if __name__ == "__main__":
    run_all_feeds()