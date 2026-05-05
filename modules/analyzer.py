import ast
import re
import os
import hashlib
import logging
from colorama import Fore, init

init(autoreset=True)

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/analyzer.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    encoding="utf-8"
)
logger = logging.getLogger(__name__)

PATTERNS_DANGEREUX = {
    "exec_call":    (r"\bexec\s*\(",    30, "Appel exec() détecté"),
    "eval_call":    (r"\beval\s*\(",    30, "Appel eval() détecté"),
    "os_system":    (r"os\.system\(",   25, "os.system() détecté"),
    "subprocess":   (r"subprocess\.",   25, "Module subprocess utilisé"),
    "socket_raw":   (r"socket\.socket", 20, "Socket brut créé"),
    "compile_call": (r"\bcompile\s*\(", 15, "compile() détecté"),
    "base64_enc":   (r"base64\.",       10, "Encodage base64 utilisé"),
    "import_dyn":   (r"__import__\(",   20, "Import dynamique détecté"),
}

IMPORTS_SUSPECTS = ["socket", "subprocess", "ctypes", "winreg", "paramiko", "ftplib"]

def md5_fichier(chemin):
    h = hashlib.md5()
    with open(chemin, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

def analyser_ast(code):
    findings = []
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ("exec", "eval", "compile", "__import__"):
                        findings.append({
                            "type":    "ast",
                            "pattern": node.func.id + "()",
                            "ligne":   node.lineno,
                            "points":  30,
                            "message": f"Appel dangereux : {node.func.id}()"
                        })
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in IMPORTS_SUSPECTS:
                        findings.append({
                            "type":    "ast",
                            "pattern": f"import {alias.name}",
                            "ligne":   node.lineno,
                            "points":  20,
                            "message": f"Import suspect : {alias.name}"
                        })
            if isinstance(node, ast.ImportFrom):
                if node.module in IMPORTS_SUSPECTS:
                    findings.append({
                        "type":    "ast",
                        "pattern": f"from {node.module}",
                        "ligne":   node.lineno,
                        "points":  20,
                        "message": f"Import suspect : {node.module}"
                    })
    except SyntaxError as e:
        findings.append({
            "type": "erreur", "pattern": "SyntaxError",
            "ligne": 0, "points": 0,
            "message": f"Erreur syntaxe : {e}"
        })
    return findings

def analyser_regex(code):
    findings = []
    lignes = code.split("\n")
    for nom, (pattern, points, message) in PATTERNS_DANGEREUX.items():
        for i, ligne in enumerate(lignes, 1):
            if re.search(pattern, ligne):
                findings.append({
                    "type":    "regex",
                    "pattern": pattern,
                    "ligne":   i,
                    "points":  points,
                    "message": message
                })
    return findings

def niveau_danger(score):
    if score == 0:
        return "SÛR", Fore.GREEN
    elif score <= 30:
        return "FAIBLE", Fore.YELLOW
    elif score <= 60:
        return "SUSPECT", Fore.YELLOW
    else:
        return "DANGEREUX", Fore.RED

def analyze_file(chemin):
    if not os.path.exists(chemin):
        return {"status": "erreur", "data": {}, "errors": [f"Fichier introuvable : {chemin}"]}
    if not chemin.endswith(".py"):
        return {"status": "erreur", "data": {}, "errors": ["Seulement les fichiers .py sont supportés"]}

    with open(chemin, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()

    md5 = md5_fichier(chemin)
    logger.info(f"Analyse de : {chemin} | MD5 : {md5}")

    findings_ast   = analyser_ast(code)
    findings_regex = analyser_regex(code)
    tous_findings  = findings_ast + findings_regex
    score_total    = sum(f["points"] for f in tous_findings)
    niveau, couleur = niveau_danger(score_total)

    print(Fore.CYAN + f"\n=== ANALYZER : {os.path.basename(chemin)} ===")
    print(Fore.WHITE + f"  MD5      : {md5}")
    print(Fore.WHITE + f"  Findings : {len(tous_findings)}")
    print(couleur   + f"  Score    : {score_total} pts — {niveau}")
    print()

    if not tous_findings:
        print(Fore.GREEN + "  ✓ Aucun pattern dangereux — fichier propre")
    else:
        for f in tous_findings:
            print(couleur + f"  ✗ Ligne {f['ligne']:3d} | {f['message']}")
        logger.warning(f"{chemin} | Score : {score_total} | Niveau : {niveau}")

    print(Fore.CYAN + "=== FIN ANALYZER ===\n")

    return {
        "status": "ok",
        "data": {
            "fichier":  chemin,
            "md5":      md5,
            "findings": tous_findings,
            "score":    score_total,
            "niveau":   niveau
        },
        "errors": []
    }

def analyze_folder(dossier):
    if not os.path.exists(dossier):
        return {"status": "erreur", "data": [], "errors": [f"Dossier introuvable : {dossier}"]}

    resultats = []
    for root, _, files in os.walk(dossier):
        for fichier in files:
            if fichier.endswith(".py"):
                chemin = os.path.join(root, fichier)
                res = analyze_file(chemin)
                if res["status"] == "ok":
                    resultats.append(res["data"])

    return {"status": "ok", "data": resultats, "errors": []}

def run_analyzer():
    print(Fore.CYAN + "\n=== MODULE ANALYZER ===")
    print(Fore.WHITE + "  [1] Analyser un fichier")
    print(Fore.WHITE + "  [2] Analyser un dossier entier")
    choix = input(Fore.YELLOW + "  Ton choix : ").strip()

    if choix == "1":
        chemin = input(Fore.YELLOW + "  Chemin du fichier .py : ").strip()
        return analyze_file(chemin)
    elif choix == "2":
        dossier = input(Fore.YELLOW + "  Chemin du dossier : ").strip()
        return analyze_folder(dossier)
    else:
        print(Fore.RED + "  Choix invalide")
        return {}