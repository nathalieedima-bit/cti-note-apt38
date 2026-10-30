"""Vérifie les empreintes SHA-256 du fichier d'IoC sur VirusTotal (API gratuite : 4 requêtes/minute).
Usage : définir la variable d'environnement VT_API_KEY puis lancer  python scripts/vt_check.py
"""
import csv, os, time, requests

API_KEY = os.environ.get("VT_API_KEY")  # la clé ne doit JAMAIS être écrite dans le code
URL = "https://www.virustotal.com/api/v3/files/{}"

if not API_KEY:
    raise SystemExit("Définis d'abord VT_API_KEY (ex. PowerShell : $env:VT_API_KEY='ta_cle')")

with open("iocs/iocs-apt38.csv", newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        if row["type"] != "sha256":
            continue
        r = requests.get(URL.format(row["valeur"]), headers={"x-apikey": API_KEY})
        if r.status_code == 200:
            a = r.json()["data"]["attributes"]
            stats = a["last_analysis_stats"]
            print(f'{row["valeur"][:16]}… -> {stats["malicious"]} moteurs malveillants')
        else:
            print(f'{row["valeur"][:16]}… -> inconnu de VirusTotal ({r.status_code})')
        time.sleep(16)
