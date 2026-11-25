#!/usr/bin/env python3
"""Export des resultats en CSV pour exploitation tableur."""

import csv
from pathlib import Path


def export_accounts_csv(report_dir, findings):
    """Export all found accounts to a CSV file."""
    path = report_dir / "comptes.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Identifiant", "Type", "Site", "URL", "Sources", "Details"])
        for finding in findings:
            writer.writerow([
                finding.identifier,
                finding.kind,
                finding.site,
                finding.url,
                ", ".join(finding.sources),
                "; ".join(f"{k}={v}" for k, v in finding.details.items()) if finding.details else "",
            ])
    return path


def export_breaches_csv(report_dir, breaches):
    """Export breaches to CSV."""
    path = report_dir / "fuites.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Email", "Fuite", "Date", "Donnees exposees"])
        for b in breaches:
            writer.writerow([b.email, b.breach_name, b.breach_date, ", ".join(b.data_types)])
    return path


def export_companies_csv(report_dir, companies):
    """Export companies to CSV."""
    path = report_dir / "entreprises.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Nom", "SIREN", "Role", "Statut", "Adresse", "Date creation", "Source"])
        for c in companies:
            writer.writerow([c.name, c.siren, c.role, c.status, c.address, c.creation_date, c.source])
    return path


def export_summary_csv(report_dir, opts, findings, breaches, companies, phone_infos,
                       risk_score=None, risk_level=None):
    """Export a one-row summary CSV."""
    path = report_dir / "resume.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Mandat", "Nom", "Emails", "Pseudos", "Telephones",
                          "Nb comptes", "Nb fuites", "Nb entreprises",
                          "Score risque", "Niveau risque"])
        writer.writerow([
            opts.mandat,
            opts.nom or "",
            "; ".join(opts.email),
            "; ".join(opts.username),
            "; ".join(opts.phone),
            len(findings),
            len(breaches),
            len(companies),
            risk_score if risk_score is not None else "",
            risk_level or "",
        ])
    return path
