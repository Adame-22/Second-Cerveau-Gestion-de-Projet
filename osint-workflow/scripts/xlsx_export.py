#!/usr/bin/env python3
"""Export des resultats OSINT au format Excel (.xlsx) avec mise en forme professionnelle."""

import json
from pathlib import Path

try:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False


HEADER_FILL = PatternFill(start_color="2B6CB0", end_color="2B6CB0", fill_type="solid") if HAS_OPENPYXL else None
HEADER_FONT = Font(name="Calibri", bold=True, color="FFFFFF", size=11) if HAS_OPENPYXL else None
CRITICAL_FILL = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid") if HAS_OPENPYXL else None
WARN_FILL = PatternFill(start_color="FEF3C7", end_color="FEF3C7", fill_type="solid") if HAS_OPENPYXL else None
THIN_BORDER = Border(
    left=Side(style="thin"), right=Side(style="thin"),
    top=Side(style="thin"), bottom=Side(style="thin"),
) if HAS_OPENPYXL else None


def _style_header(ws, ncols):
    for col in range(1, ncols + 1):
        cell = ws.cell(row=1, column=col)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(horizontal="center", vertical="center")


def _auto_width(ws):
    for col in ws.columns:
        max_len = 0
        col_letter = col[0].column_letter
        for cell in col:
            val = str(cell.value or "")
            max_len = max(max_len, min(len(val), 60))
        ws.column_dimensions[col_letter].width = max_len + 3


def _add_borders(ws):
    for row in ws.iter_rows(min_row=1, max_row=ws.max_row, max_col=ws.max_column):
        for cell in row:
            cell.border = THIN_BORDER


def export_xlsx(json_path, xlsx_path=None):
    if not HAS_OPENPYXL:
        print("[!] openpyxl non installe. pip install openpyxl")
        return None
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    if xlsx_path is None:
        xlsx_path = str(json_path).replace(".json", ".xlsx")

    wb = Workbook()

    # --- Synthese ---
    ws = wb.active
    ws.title = "Synthese"
    ws.append(["Champ", "Valeur"])
    _style_header(ws, 2)
    ws.append(["Date", data.get("date", "")])
    ws.append(["Mandat", data.get("mandat", "")])
    ws.append(["Nom", data.get("nom", "")])
    ws.append(["Emails", ", ".join(data.get("emails", []))])
    ws.append(["Pseudos", ", ".join(data.get("pseudos", []))])
    ws.append(["Telephones", ", ".join(data.get("telephones", []))])
    ws.append(["Score de risque", f"{data.get('risk_score', 0)}/100"])
    ws.append(["Niveau", data.get("risk_level", "")])
    ws.append(["Comptes trouves", len(data.get("comptes", []))])
    ws.append(["Fuites", len(data.get("fuites", []))])
    ws.append(["Entreprises", len(data.get("entreprises", []))])
    ws.append(["Correlations", len(data.get("correlations", []))])
    if data.get("age_info"):
        ws.append(["Age estime", f"{data['age_info'].get('age', '?')} ans"])
    _auto_width(ws)
    _add_borders(ws)

    # --- Comptes ---
    ws2 = wb.create_sheet("Comptes")
    ws2.append(["Type", "Identifiant", "Site", "URL", "Outil"])
    _style_header(ws2, 5)
    for f in data.get("comptes", []):
        sources = f.get("sources", [])
        ws2.append([f.get("kind", ""), f.get("identifier", ""), f.get("site", ""),
                     f.get("url", ""), ", ".join(sources) if isinstance(sources, list) else str(sources)])
    _auto_width(ws2)
    _add_borders(ws2)

    # --- Fuites ---
    ws3 = wb.create_sheet("Fuites")
    ws3.append(["Email", "Fuite", "Date", "Types de donnees"])
    _style_header(ws3, 4)
    for b in data.get("fuites", []):
        row_idx = ws3.max_row + 1
        ws3.append([b.get("email", ""), b.get("breach_name", ""), b.get("breach_date", ""),
                     ", ".join(b.get("data_types", []))])
        if "Passwords" in b.get("data_types", []):
            for col in range(1, 5):
                ws3.cell(row=row_idx, column=col).fill = CRITICAL_FILL
    _auto_width(ws3)
    _add_borders(ws3)

    # --- Entreprises ---
    ws4 = wb.create_sheet("Entreprises")
    ws4.append(["Nom", "SIREN", "Role", "Adresse", "Source"])
    _style_header(ws4, 5)
    for c in data.get("entreprises", []):
        ws4.append([c.get("name", ""), c.get("siren", ""), c.get("role", ""),
                     c.get("address", ""), c.get("source", "")])
    _auto_width(ws4)
    _add_borders(ws4)

    # --- Telephone ---
    ws5 = wb.create_sheet("Telephones")
    ws5.append(["Numero", "Valide", "Pays", "Operateur", "Type"])
    _style_header(ws5, 5)
    for p in data.get("telephones_info", []):
        ws5.append([p.get("number", ""), "Oui" if p.get("valid") else "Non",
                     p.get("country", ""), p.get("carrier", ""), p.get("line_type", "")])
    _auto_width(ws5)
    _add_borders(ws5)

    # --- Risque ---
    ws6 = wb.create_sheet("Risque")
    ws6.append(["Categorie", "Valeur"])
    _style_header(ws6, 2)
    ba = data.get("breach_analysis", {})
    ws6.append(["Total fuites", ba.get("total", 0)])
    ws6.append(["Fuites critiques", ba.get("critical_count", 0)])
    ws6.append(["Mots de passe exposes", "Oui" if ba.get("password_exposed") else "Non"])
    ws6.append(["Donnees financieres", "Oui" if ba.get("financial_exposed") else "Non"])
    ws6.append(["Identite exposee", "Oui" if ba.get("identity_exposed") else "Non"])
    ws6.append(["Premiere fuite", ba.get("earliest_breach", "")])
    ws6.append(["Derniere fuite", ba.get("latest_breach", "")])
    _auto_width(ws6)
    _add_borders(ws6)

    def _sheet(title, headers, rows, fills=None):
        sh = wb.create_sheet(title)
        sh.append(headers)
        _style_header(sh, len(headers))
        for idx, row in enumerate(rows):
            sh.append([" - ".join(map(str, v)) if isinstance(v, (list, tuple)) else v for v in row])
            fill = fills[idx] if fills else None
            if fill:
                for col in range(1, len(headers) + 1):
                    sh.cell(row=sh.max_row, column=col).fill = fill
        _auto_width(sh)
        _add_borders(sh)

    df = data.get("digital_footprint") or {}
    if df.get("category_details"):
        _sheet("Empreinte", ["Categorie", "Score", "Nombre", "Exemples"],
               [[d["category"], d["score"], d["count"], ", ".join(d.get("examples", []))]
                for d in df["category_details"]])

    pr = data.get("password_reuse") or {}
    if pr.get("at_risk_emails"):
        rows = [[e["email"], e["breach_count"], ", ".join(e["breaches"])] for e in pr["at_risk_emails"]]
        fills = [CRITICAL_FILL if e["breach_count"] >= 2 else WARN_FILL for e in pr["at_risk_emails"]]
        _sheet("Mots de passe", ["Email", "Fuites avec mot de passe", "Fuites"], rows, fills)

    se = data.get("social_engineering_risk") or {}
    if se:
        rows = [["Niveau de risque", se.get("risk_level", "")]]
        rows += [["Info exposee", i] for i in se.get("exposed_info", [])]
        rows += [["Vecteur d'attaque", v] for v in se.get("attack_vectors", [])]
        rows += [["Question de securite a risque", q] for q in se.get("security_questions_at_risk", [])]
        rows += [["Recommandation", r] for r in se.get("recommendations", [])]
        _sheet("Ingenierie sociale", ["Type", "Detail"], rows)

    brokers = data.get("data_broker_urls") or []
    if brokers:
        _sheet("Courtiers donnees", ["Courtier", "Region", "Recherche", "Suppression"],
               [[b.get("broker", ""), b.get("region", ""), b.get("search_url", ""), b.get("removal_url", "")]
                for b in brokers])

    eh = data.get("exposure_heatmap") or {}
    if eh.get("vectors"):
        rows = sorted(eh["vectors"].items(), key=lambda x: -x[1])
        fills = [CRITICAL_FILL if v >= 70 else WARN_FILL if v >= 40 else None for _, v in rows]
        _sheet("Carte exposition", ["Vecteur", "Score /100"], [list(r) for r in rows] + [["GLOBAL", eh.get("overall", 0)]],
               fills + [None])

    wp = data.get("whois_privacy") or []
    if wp:
        _sheet("WHOIS vie privee", ["Domaine", "Protection", "Champs exposes", "Risque"],
               [[w["domain"], "Oui" if w["privacy_enabled"] else "Non", ", ".join(w["exposed_fields"]), w["risk"]]
                for w in wp],
               [CRITICAL_FILL if w["risk"] in ("CRITIQUE", "ELEVE") else None for w in wp])

    ap = data.get("action_priorities") or {}
    if any(ap.get(k) for k in ("urgent", "important", "recommended")):
        rows, fills = [], []
        for key, label, fill in (("urgent", "URGENT", CRITICAL_FILL), ("important", "IMPORTANT", WARN_FILL),
                                 ("recommended", "RECOMMANDE", None)):
            for a in ap.get(key, []):
                rows.append([label, a])
                fills.append(fill)
        _sheet("Plan action", ["Priorite", "Action"], rows, fills)

    wb.save(xlsx_path)
    print(f"[*] Excel genere : {xlsx_path}")
    return xlsx_path


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Convertir resultats.json en Excel")
    parser.add_argument("json_file", help="Chemin vers resultats.json")
    parser.add_argument("-o", "--output", help="Chemin de sortie .xlsx")
    args = parser.parse_args()
    export_xlsx(args.json_file, args.output)
