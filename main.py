import os
import sys
from colorama import Fore, Back, Style, init

init(autoreset=True)

session = {}

def banniere():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.CYAN + r"""
  ____      _               ____                      
 / ___|   _| |__   ___ _ __|  _ \ ___  ___ ___  _ __  
| |  | | | | '_ \ / _ \ '__| |_) / _ \/ __/ _ \| '_ \ 
| |__| |_| | |_) |  __/ |  |  _ <  __/ (_| (_) | | | |
 \____\__, |_.__/ \___|_|  |_| \_\___|\___\___/|_| |_|
      |___/                                             
    """)
    print(Fore.CYAN + "=" * 55)
    print(Fore.WHITE + "   Outil de sécurité Python — OSINT + Scanner + Analyzer")
    print(Fore.CYAN + "=" * 55)
    print(Fore.YELLOW + "   Projet académique — Usage éducatif uniquement")
    print(Fore.CYAN + "=" * 55 + "\n")

def menu():
    print(Fore.CYAN + "  ┌─────────────────────────────────┐")
    print(Fore.CYAN + "  │        MENU PRINCIPAL           │")
    print(Fore.CYAN + "  ├─────────────────────────────────┤")
    print(Fore.WHITE + "  │  " + Fore.YELLOW + "[1]" + Fore.WHITE + "  Module OSINT            │")
    print(Fore.WHITE + "  │  " + Fore.YELLOW + "[2]" + Fore.WHITE + "  Scanner Web             │")
    print(Fore.WHITE + "  │  " + Fore.YELLOW + "[3]" + Fore.WHITE + "  Analyzer de fichiers    │")
    print(Fore.WHITE + "  │  " + Fore.YELLOW + "[4]" + Fore.WHITE + "  Générer rapport PDF     │")
    print(Fore.WHITE + "  │  " + Fore.YELLOW + "[5]" + Fore.WHITE + "  Ouvrir Dashboard        │")
    print(Fore.WHITE + "  │  " + Fore.RED   + "[0]" + Fore.WHITE + "  Quitter                 │")
    print(Fore.CYAN + "  └─────────────────────────────────┘")
    print()

def afficher_session():
    if not session:
        return
    print(Fore.CYAN + "\n  Résultats en session :")
    if "osint" in session:
        print(Fore.GREEN + "  ✓ OSINT collecté")
    if "scanner" in session:
        print(Fore.GREEN + "  ✓ Scanner web effectué")
    if "analyzer" in session:
        print(Fore.GREEN + "  ✓ Analyse de fichiers faite")
    print()

def lancer_osint():
    from modules.osint import run_osint
    print(Fore.CYAN + "\n" + "=" * 55)
    resultats = run_osint()
    if resultats:
        session["osint"] = resultats
        print(Fore.GREEN + "\n  ✓ Résultats OSINT sauvegardés en session.")
    input(Fore.WHITE + "\n  Appuie sur Entrée pour revenir au menu...")

def lancer_scanner():
    try:
        from modules.scanner import run_scan
        print(Fore.CYAN + "\n" + "=" * 55)
        url = input(Fore.YELLOW + "  URL cible (ex: http://localhost) : ").strip()
        if url:
            resultats = run_scan(url)
            if resultats:
                session["scanner"] = resultats
                print(Fore.GREEN + "\n  ✓ Résultats Scanner sauvegardés en session.")
    except ImportError:
        print(Fore.RED + "\n  Module scanner.py pas encore créé — Partenaire B !")
    input(Fore.WHITE + "\n  Appuie sur Entrée pour revenir au menu...")

def lancer_analyzer():
    try:
        from modules.analyzer import analyze_file
        print(Fore.CYAN + "\n" + "=" * 55)
        chemin = input(Fore.YELLOW + "  Chemin du fichier .py à analyser : ").strip()
        if chemin:
            resultats = analyze_file(chemin)
            if resultats:
                session["analyzer"] = resultats
                print(Fore.GREEN + "\n  ✓ Résultats Analyzer sauvegardés en session.")
    except ImportError:
        print(Fore.RED + "\n  Module analyzer.py pas encore créé — Partenaire B !")
    input(Fore.WHITE + "\n  Appuie sur Entrée pour revenir au menu...")

def generer_rapport():
    try:
        from reports.report_generator import ReportGenerator
        if not session:
            print(Fore.RED + "\n  Aucun résultat en session. Lance d'abord les modules.")
            input(Fore.WHITE + "\n  Appuie sur Entrée pour revenir au menu...")
            return
        print(Fore.WHITE + "\n  Génération du rapport PDF...")
        rg = ReportGenerator()
        rg.page_garde()
        if "osint" in session:
            rg.add_osint_results(session["osint"])
        if "scanner" in session:
            rg.add_scan_results(session["scanner"])
        if "analyzer" in session:
            rg.add_analysis_results(session["analyzer"])
        fichier = rg.export("rapport_cyberrecon.pdf")
        print(Fore.GREEN + f"\n  ✓ Rapport généré : {fichier}")
    except Exception as e:
        print(Fore.RED + f"\n  Erreur : {e}")
    input(Fore.WHITE + "\n  Appuie sur Entrée pour revenir au menu...")
    

def main():
    while True:
        banniere()
        afficher_session()
        menu()
        choix = input(Fore.YELLOW + "  Ton choix : " + Style.RESET_ALL).strip()

        if choix == "1":
            lancer_osint()
        elif choix == "2":
            lancer_scanner()
        elif choix == "3":
            lancer_analyzer()
        elif choix == "4":
            generer_rapport()
        elif choix == "0":
            print(Fore.CYAN + "\n  Au revoir !\n")
            sys.exit(0)
        else:
            print(Fore.RED + "\n  Choix invalide. Réessaie.")
            input(Fore.WHITE + "  Appuie sur Entrée...")

if __name__ == "__main__":
    main()