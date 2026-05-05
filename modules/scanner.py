import requests
import logging
from bs4 import BeautifulSoup
from colorama import Fore, init

init(autoreset=True)

logging.basicConfig(
    filename="logs/scanner.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    encoding="utf-8"
)
logger = logging.getLogger(__name__)

HEADERS_SECURITE = [
    "X-Frame-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-XSS-Protection",
]

def check_headers(url):
    try:
        response = requests.get(url, timeout=10, verify=False)
        logger.info(f"Check headers : {url} | Statut : {response.status_code}")
        resultats = {}
        for header in HEADERS_SECURITE:
            present = header in response.headers
            resultats[header] = present
            statut = "OK" if present else "MANQUANT"
            logger.info(f"  {header} : {statut}")
        return {"status": "ok", "data": resultats, "errors": []}
    except requests.exceptions.ConnectionError:
        return {"status": "erreur", "data": {}, "errors": ["Impossible de se connecter à la cible"]}
    except requests.exceptions.Timeout:
        return {"status": "erreur", "data": {}, "errors": ["Timeout"]}
    except Exception as e:
        return {"status": "erreur", "data": {}, "errors": [str(e)]}

def check_cookies(url):
    try:
        response = requests.get(url, timeout=10, verify=False)
        cookies = response.cookies
        resultats = []
        for cookie in cookies:
            info = {
                "nom":      cookie.name,
                "httponly": cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly"),
                "secure":   cookie.secure,
                "samesite": cookie.has_nonstandard_attr("SameSite"),
            }
            resultats.append(info)
            logger.info(f"Cookie '{cookie.name}' | HttpOnly:{info['httponly']} Secure:{info['secure']}")
        return {"status": "ok", "data": resultats, "errors": []}
    except Exception as e:
        return {"status": "erreur", "data": [], "errors": [str(e)]}

def check_xss(url):
    payload = "<script>alert('XSS-CyberRecon')</script>"
    try:
        response = requests.get(url, params={"q": payload}, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, "html.parser")
        scripts = soup.find_all("script")
        reflechi = payload in response.text
        logger.info(f"XSS test sur {url} | Réfléchi : {reflechi}")
        return {
            "status": "ok",
            "data": {
                "url":       url,
                "payload":   payload,
                "reflechi":  reflechi,
                "nb_scripts": len(scripts)
            },
            "errors": []
        }
    except Exception as e:
        return {"status": "erreur", "data": {}, "errors": [str(e)]}

def calculer_score(headers, cookies, xss):
    score = 100
    if headers["status"] == "ok":
        manquants = sum(1 for v in headers["data"].values() if not v)
        score -= manquants * 12
    if xss["status"] == "ok" and xss["data"].get("reflechi"):
        score -= 20
    if cookies["status"] == "ok":
        for c in cookies["data"]:
            if not c["httponly"]:
                score -= 5
    return max(score, 0)

def run_scan(url):
    print(Fore.CYAN + f"\n=== SCANNER WEB : {url} ===")

    print(Fore.WHITE + "  Vérification des headers de sécurité...")
    headers = check_headers(url)
    if headers["status"] == "ok":
        for h, present in headers["data"].items():
            if present:
                print(Fore.GREEN + f"  ✓ {h}")
            else:
                print(Fore.RED + f"  ✗ {h} — MANQUANT")
    else:
        print(Fore.RED + f"  Erreur : {headers['errors']}")

    print(Fore.WHITE + "\n  Vérification des cookies...")
    cookies = check_cookies(url)
    if cookies["status"] == "ok":
        if not cookies["data"]:
            print(Fore.YELLOW + "  Aucun cookie détecté")
        for c in cookies["data"]:
            flags = []
            if c["httponly"]: flags.append("HttpOnly")
            if c["secure"]:   flags.append("Secure")
            if c["samesite"]: flags.append("SameSite")
            couleur = Fore.GREEN if flags else Fore.RED
            print(couleur + f"  Cookie '{c['nom']}' — flags : {', '.join(flags) if flags else 'AUCUN'}")

    print(Fore.WHITE + "\n  Test XSS réfléchi...")
    xss = check_xss(url)
    if xss["status"] == "ok":
        if xss["data"]["reflechi"]:
            print(Fore.RED + "  ✗ XSS réfléchi DÉTECTÉ — payload reflété dans la réponse !")
        else:
            print(Fore.GREEN + "  ✓ Pas de XSS réfléchi détecté")

    score = calculer_score(headers, cookies, xss)
    couleur_score = Fore.GREEN if score >= 70 else Fore.YELLOW if score >= 40 else Fore.RED
    print(couleur_score + f"\n  Score de sécurité : {score}/100")
    print(Fore.CYAN + "=== FIN SCANNER ===\n")

    return {
        "status": "ok",
        "data": {
            "url":     url,
            "headers": headers["data"],
            "cookies": cookies["data"],
            "xss":     xss["data"],
            "score":   score
        },
        "errors": []
    }