# CyberRecon Suite

Outil de securite Python modulaire combine OSINT, Scanner Web et Analyseur de fichiers suspects.

> Projet academique — Usage educatif uniquement — Ne pas utiliser sans autorisation explicite.

---

## Modules

### Module 1 — OSINT (Projet 1)
- Reconnaissance d'adresse IP via ip-api.com (organisation, pays, ville, ISP)
- Verification d'email via HaveIBeenPwned (fuites de donnees)
- Logs automatiques dans `logs/osint.log`

### Module 2 — Scanner Web (Projet 5)
- Verification des headers de securite HTTP (X-Frame-Options, CSP, HSTS...)
- Analyse des attributs de cookies (HttpOnly, Secure, SameSite)
- Detection de XSS reflechi basique
- Score de securite sur 100

### Module 3 — Analyzer de fichiers (Projet 9)
- Analyse statique de fichiers Python suspects
- Detection via AST (exec, eval, compile, import dynamique)
- Detection via regex (os.system, socket, subprocess, base64)
- Scoring de dangerosite + hash MD5 du fichier

---

## Installation

### 1. Cloner le projet