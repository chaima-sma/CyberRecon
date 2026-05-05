import requests
import logging
import os
from dotenv import load_dotenv
from colorama import Fore, Style, init

init(autoreset=True)
load_dotenv()

SHODAN_KEY = os.getenv("SHODAN_API_KEY")
HIBP_KEY   = os.getenv("HIBP_API_KEY")

logging.basicConfig(
    filename="logs/osint.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    encoding="utf-8"
)
logger = logging.getLogger(__name__)


def shodan_lookup(ip):
    """
    Interroge ip-api.com (gratuit, sans clé).
    Retourne organisation, pays, région, FAI, coordonnées GPS.
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,org,isp,lat,lon,query"
    try:
        response = requests.get(url, timeout=10)
        logger.info(f"IP lookup : {ip} | Statut : {response.status_code}")

        if response.status_code != 200:
            return {"status": "erreur", "data": {}, "errors": [f"Erreur HTTP {response.status_code}"]}

        data = response.json()

        if data.get("status") == "fail":
            return {"status": "erreur", "data": {}, "errors": [data.get("message", "IP invalide")]}

        resultat = {
            "ip":           ip,
            "organisation": data.get("org", "Inconnue"),
            "isp":          data.get("isp", "Inconnu"),
            "pays":         data.get("country", "Inconnu"),
            "region":       data.get("regionName", "Inconnue"),
            "ville":        data.get("city", "Inconnue"),
            "latitude":     data.get("lat", 0),
            "longitude":    data.get("lon", 0),
            "ports":        [],
            "cves":         []
        }
        return {"status": "ok", "data": resultat, "errors": []}

    except requests.exceptions.Timeout:
        return {"status": "erreur", "data": {}, "errors": ["Timeout"]}
    except requests.exceptions.ConnectionError:
        return {"status": "erreur", "data": {}, "errors": ["Pas de connexion internet"]}
    except Exception as e:
        return {"status": "erreur", "data": {}, "errors": [str(e)]}


def hibp_check(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"User-Agent": "CyberRecon-Suite-Educational-Tool"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        logger.info(f"HIBP check : {email} | Statut : {response.status_code}")

        if response.status_code == 404:
            return {"status": "ok", "data": {"email": email, "compromis": False, "nb_fuites": 0, "fuites": []}, "errors": []}
        if response.status_code == 401:
            return {"status": "erreur", "data": {}, "errors": ["Clé HIBP requise"]}
        if response.status_code == 429:
            return {"status": "erreur", "data": {}, "errors": ["Trop de requêtes - attends 1 minute"]}
        if response.status_code == 200:
            breaches = response.json()
            return {"status": "ok", "data": {"email": email, "compromis": True, "nb_fuites": len(breaches), "fuites": [b.get("Name") for b in breaches]}, "errors": []}

        return {"status": "erreur", "data": {}, "errors": [f"Erreur HTTP {response.status_code}"]}

    except requests.exceptions.Timeout:
        return {"status": "erreur", "data": {}, "errors": ["Timeout HIBP"]}
    except Exception as e:
        return {"status": "erreur", "data": {}, "errors": [str(e)]}


def run_osint():
    print(Fore.CYAN + "\n=== MODULE OSINT ===")
    resultats = {}

    ip = input(Fore.YELLOW + "Entrez une IP à analyser : ").strip()
    if ip:
        print(Fore.WHITE + f"Interrogation Shodan pour {ip}...")
        res = shodan_lookup(ip)
        if res["status"] == "ok":
            d = res["data"]
            print(Fore.GREEN + f"  IP           : {d.get('ip')}")
            print(Fore.GREEN + f"  Organisation : {d.get('organisation')}")
            print(Fore.GREEN + f"  Pays         : {d.get('pays')}")
            print(Fore.GREEN + f"  Ports ouverts: {d.get('ports')}")
            if d.get("cves"):
                print(Fore.RED + f"  CVEs         : {d.get('cves')}")
            else:
                print(Fore.GREEN + "  CVEs         : Aucune détectée")
            resultats["shodan"] = d
        else:
            print(Fore.RED + f"  Erreur : {res['errors']}")

    email = input(Fore.YELLOW + "Email à vérifier (Entrée pour ignorer) : ").strip()
    if email:
        res = hibp_check(email)
        if res["status"] == "ok":
            d = res["data"]
            if d["compromis"]:
                print(Fore.RED + f"  COMPROMIS ! {d['nb_fuites']} fuite(s) : {d['fuites']}")
            else:
                print(Fore.GREEN + "  Email propre - Aucune fuite détectée")
            resultats["hibp"] = d
        else:
            print(Fore.RED + f"  Erreur : {res['errors']}")

    print(Fore.CYAN + "=== FIN MODULE OSINT ===")
    return resultats