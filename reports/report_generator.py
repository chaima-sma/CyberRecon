import os
from fpdf import FPDF
from datetime import datetime

os.makedirs("reports", exist_ok=True)

class ReportGenerator(FPDF):

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        self.add_page()

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(83, 74, 183)
        self.cell(0, 8, "CyberRecon Suite - Rapport de Securite", align="L")
        self.set_text_color(150, 150, 150)
        self.cell(0, 8, datetime.now().strftime("%d/%m/%Y %H:%M"), align="R")
        self.ln(4)
        self.set_draw_color(83, 74, 183)
        self.set_line_width(0.5)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(6)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Usage educatif uniquement - Page {self.page_no()}", align="C")

    def titre_section(self, titre, couleur=(83, 74, 183)):
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*couleur)
        self.ln(4)
        self.cell(0, 10, titre, ln=True)
        self.set_draw_color(*couleur)
        self.set_line_width(0.3)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)
        self.set_text_color(0, 0, 0)

    def champ(self, label, valeur, couleur_val=None):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(80, 80, 80)
        self.cell(55, 7, label + " :", ln=False)
        self.set_font("Helvetica", "", 10)
        if couleur_val:
            self.set_text_color(*couleur_val)
        else:
            self.set_text_color(0, 0, 0)
        valeur_propre = str(valeur).encode("latin-1", errors="replace").decode("latin-1")
        self.cell(0, 7, valeur_propre, ln=True)
        self.set_text_color(0, 0, 0)

    def badge_statut(self, texte, ok=True):
        couleur = (15, 110, 86) if ok else (153, 60, 29)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*couleur)
        texte_propre = str(texte).encode("latin-1", errors="replace").decode("latin-1")
        self.cell(0, 6, ("+ " if ok else "x ") + texte_propre, ln=True)
        self.set_text_color(0, 0, 0)

    def page_garde(self):
        self.set_font("Helvetica", "B", 22)
        self.set_text_color(83, 74, 183)
        self.ln(20)
        self.cell(0, 15, "CyberRecon Suite", align="C", ln=True)
        self.set_font("Helvetica", "", 13)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, "Rapport de Securite - Analyse Complete", align="C", ln=True)
        self.ln(6)
        self.set_font("Helvetica", "I", 10)
        self.set_text_color(150, 150, 150)
        self.cell(0, 8, f"Genere le {datetime.now().strftime('%d/%m/%Y a %H:%M')}", align="C", ln=True)
        self.ln(10)
        self.set_draw_color(83, 74, 183)
        self.set_line_width(1)
        self.line(30, self.get_y(), 180, self.get_y())
        self.ln(10)
        self.set_font("Helvetica", "", 10)
        self.set_text_color(80, 80, 80)
        self.multi_cell(0, 7,
            "Ce rapport a ete genere automatiquement par CyberRecon Suite.\n"
            "Il contient les resultats des modules OSINT, Scanner Web et Analyzer.\n"
            "Usage strictement educatif - ne pas utiliser sans autorisation.",
            align="C"
        )
        self.add_page()

    def add_osint_results(self, data):
        self.titre_section("MODULE 1 - OSINT", couleur=(83, 74, 183))

        if "shodan" in data:
            d = data["shodan"]
            self.set_font("Helvetica", "B", 11)
            self.set_text_color(50, 50, 50)
            self.cell(0, 8, "Analyse IP", ln=True)
            self.set_font("Helvetica", "", 10)
            self.champ("IP analysee",   d.get("ip", "-"))
            self.champ("Organisation",  d.get("organisation", "-"))
            self.champ("Pays",          d.get("pays", "-"))
            self.champ("Ville",         d.get("ville", "-"))
            self.champ("ISP",           d.get("isp", "-"))
            cves = d.get("cves", [])
            self.champ("CVEs",
                str(len(cves)) + " vulnerabilite(s)",
                couleur_val=(153, 60, 29) if cves else (15, 110, 86))
            self.ln(4)

        if "hibp" in data:
            d = data["hibp"]
            self.set_font("Helvetica", "B", 11)
            self.set_text_color(50, 50, 50)
            self.cell(0, 8, "Verification Email HIBP", ln=True)
            self.set_font("Helvetica", "", 10)
            self.champ("Email", d.get("email", "-"))
            compromis = d.get("compromis", False)
            self.champ("Statut",
                "COMPROMIS - " + str(d.get("nb_fuites", 0)) + " fuite(s)" if compromis else "Propre - aucune fuite",
                couleur_val=(153, 60, 29) if compromis else (15, 110, 86))
            if compromis and d.get("fuites"):
                self.champ("Services", ", ".join(d["fuites"][:5]))
            self.ln(4)

    def add_scan_results(self, data):
        self.titre_section("MODULE 2 - SCANNER WEB", couleur=(15, 110, 86))

        if "data" not in data:
            return
        d = data["data"]

        self.champ("URL analysee", d.get("url", "-"))
        score = d.get("score", 0)
        couleur_score = (15, 110, 86) if score >= 70 else (133, 79, 11) if score >= 40 else (153, 60, 29)
        self.champ("Score securite", f"{score}/100", couleur_val=couleur_score)
        self.ln(3)

        if d.get("headers"):
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(50, 50, 50)
            self.cell(0, 7, "Headers de securite :", ln=True)
            self.set_font("Helvetica", "", 10)
            for header, present in d["headers"].items():
                self.badge_statut(header, ok=present)

        self.ln(3)
        if d.get("xss", {}).get("reflechi"):
            self.badge_statut("XSS reflechi DETECTE", ok=False)
        else:
            self.badge_statut("Pas de XSS reflechi detecte", ok=True)
        self.ln(4)

    def add_analysis_results(self, data):
        self.titre_section("MODULE 3 - ANALYZER DE FICHIERS", couleur=(153, 60, 29))

        if "data" not in data:
            return
        d = data["data"]

        self.champ("Fichier", os.path.basename(d.get("fichier", "-")))
        self.champ("MD5", d.get("md5", "-"))
        self.champ("Niveau",
            d.get("niveau", "-"),
            couleur_val=(153, 60, 29) if d.get("niveau") == "DANGEREUX" else (15, 110, 86))
        self.champ("Score", str(d.get("score", 0)) + " pts")
        self.ln(3)

        findings = d.get("findings", [])
        if not findings:
            self.badge_statut("Aucun pattern dangereux detecte", ok=True)
        else:
            self.set_font("Helvetica", "B", 10)
            self.set_text_color(50, 50, 50)
            self.cell(0, 7, f"Findings ({len(findings)}) :", ln=True)
            for f in findings:
                self.badge_statut(
                    f"Ligne {f['ligne']} - {f['message']}",
                    ok=False
                )
        self.ln(4)

    def export(self, filename="rapport_cyberrecon.pdf"):
        chemin = os.path.join("reports", filename)
        self.output(chemin)
        return chemin