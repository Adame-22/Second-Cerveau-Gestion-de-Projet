#!/usr/bin/env python3
"""
OSINT Workflow Runner
Orchestre les outils OSINT pour retrouver les traces numeriques d'une cible.
Usage: python scripts/osint_runner.py --email x@y.com --username pseudo --phone +33612345678
"""

import argparse
import json
import os
import subprocess
import sys
import shutil
from datetime import datetime
from pathlib import Path

VENV_BIN = Path(__file__).resolve().parent.parent / "venv" / "bin"
REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def banner():
    print(r"""
  ___  ____ ___ _   _ _____  __        __         _    __ _
 / _ \/ ___|_ _| \ | |_   _| \ \      / /__  _ __| | _/ _| | _____      __
| | | \___ \| ||  \| | | |    \ \ /\ / / _ \| '__| |/ / |_| |/ _ \ \ /\ / /
| |_| |___) | || |\  | | |     \ V  V / (_) | |  |   <|  _|  | (_) \ V  V /
 \___/|____/___|_| \_| |_|      \_/\_/ \___/|_|  |_|\_\_| |_|\___/ \_/\_/
    """)


def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def run_cmd(cmd, label, output_file=None):
    print(f"\n{'='*60}")
    print(f"[*] {label}")
    print(f"{'='*60}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        output = result.stdout + result.stderr
        print(output[:2000] if len(output) > 2000 else output)
        if output_file:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(output, encoding="utf-8")
            print(f"[+] Resultat sauvegarde: {output_file}")
        return output
    except subprocess.TimeoutExpired:
        print(f"[!] Timeout apres 300s pour: {label}")
        return ""
    except FileNotFoundError:
        print(f"[!] Outil non trouve: {cmd[0]}")
        return ""


def run_holehe(email, report_dir):
    holehe_bin = VENV_BIN / "holehe"
    if not holehe_bin.exists():
        print("[!] holehe non installe")
        return
    out_file = report_dir / "holehe_results.txt"
    run_cmd(
        [str(holehe_bin), str(email)],
        f"HOLEHE - Comptes lies a l'email: {email}",
        out_file,
    )


def run_maigret(username, report_dir):
    maigret_bin = VENV_BIN / "maigret"
    if not maigret_bin.exists():
        print("[!] maigret non installe")
        return
    out_dir = report_dir / "maigret"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_cmd(
        [
            str(maigret_bin),
            str(username),
            "--timeout", "10",
            "--no-color",
            "--folderoutput", str(out_dir),
        ],
        f"MAIGRET - Recherche du pseudo: {username}",
        report_dir / "maigret_results.txt",
    )


def run_sherlock(username, report_dir):
    sherlock_bin = VENV_BIN / "sherlock"
    if not sherlock_bin.exists():
        print("[!] sherlock non installe")
        return
    out_file = report_dir / "sherlock_results.txt"
    run_cmd(
        [
            str(sherlock_bin),
            str(username),
            "--timeout", "10",
            "--print-found",
            "--no-color",
            "--output", str(out_file),
        ],
        f"SHERLOCK - Recherche du pseudo: {username}",
    )


def generate_summary(args, report_dir):
    summary = {
        "investigation": {
            "date": datetime.now().isoformat(),
            "cible": {},
            "outils_utilises": [],
            "fichiers_generes": [],
        }
    }

    if args.email:
        summary["investigation"]["cible"]["email"] = args.email
    if args.username:
        summary["investigation"]["cible"]["username"] = args.username
    if args.phone:
        summary["investigation"]["cible"]["phone"] = args.phone
    if args.nom:
        summary["investigation"]["cible"]["nom"] = args.nom

    for f in report_dir.rglob("*"):
        if f.is_file() and f.name != "summary.json":
            summary["investigation"]["fichiers_generes"].append(str(f.relative_to(report_dir)))
            tool_name = f.stem.split("_")[0]
            if tool_name not in summary["investigation"]["outils_utilises"]:
                summary["investigation"]["outils_utilises"].append(tool_name)

    summary_file = report_dir / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n[+] Resume de l'investigation: {summary_file}")
    return summary


def generate_report_md(args, report_dir):
    lines = [
        f"# Rapport OSINT",
        f"",
        f"**Date:** {datetime.now().strftime('%d/%m/%Y %H:%M')}",
        f"",
        f"## Cible",
        f"",
    ]
    if args.nom:
        lines.append(f"- **Nom:** {args.nom}")
    if args.email:
        lines.append(f"- **Email:** {args.email}")
    if args.username:
        lines.append(f"- **Username:** {args.username}")
    if args.phone:
        lines.append(f"- **Telephone:** {args.phone}")

    lines.append("")
    lines.append("## Resultats par outil")
    lines.append("")

    for result_file in sorted(report_dir.glob("*_results.txt")):
        tool_name = result_file.stem.replace("_results", "").upper()
        content = result_file.read_text(encoding="utf-8", errors="replace")
        found_lines = []

        skip_patterns = [
            "db auto-update", "maigret 0.", "using sites database",
            "support maigret", "donate", "patreon", "searching",
            "checking username", "starting a search", "run search",
        ]

        for line in content.splitlines():
            line_stripped = line.strip()
            line_lower = line_stripped.lower()
            if not line_stripped or len(line_stripped) < 5:
                continue
            if any(sp in line_lower for sp in skip_patterns):
                continue
            if "http" in line_lower and any(kw in line_lower for kw in [
                "claimed", "found", "exists", "[+]"
            ]):
                found_lines.append(line_stripped)
            elif tool_name == "HOLEHE" and any(kw in line_lower for kw in [
                "exists", "true", "registered", "[+]"
            ]):
                found_lines.append(line_stripped)
            elif tool_name == "SHERLOCK" and "http" in line_lower:
                found_lines.append(line_stripped)

        lines.append(f"### {tool_name}")
        lines.append("")
        if found_lines:
            lines.append(f"**{len(found_lines)} comptes/traces trouves:**")
            lines.append("")
            for fl in found_lines[:50]:
                lines.append(f"- {fl}")
        else:
            lines.append("Aucun resultat positif ou outil non execute.")
        lines.append("")

    lines.append("## Recommandations")
    lines.append("")
    lines.append("- Verifier manuellement chaque compte trouve")
    lines.append("- Croiser les informations entre les differentes sources")
    lines.append("- Documenter les chemins de decouverte pour le client")
    lines.append("")
    lines.append("---")
    lines.append("*Rapport genere automatiquement par OSINT Workflow Runner*")

    report_file = report_dir / "RAPPORT.md"
    report_file.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[+] Rapport Markdown: {report_file}")


def main():
    parser = argparse.ArgumentParser(
        description="OSINT Workflow Runner - Retrouve les traces numeriques"
    )
    parser.add_argument("--email", "-e", help="Adresse email cible")
    parser.add_argument("--username", "-u", help="Pseudo/username cible")
    parser.add_argument("--phone", "-p", help="Numero de telephone cible")
    parser.add_argument("--nom", "-n", help="Nom complet de la personne")
    parser.add_argument(
        "--all", "-a", action="store_true",
        help="Lancer tous les outils disponibles"
    )

    args = parser.parse_args()

    if not any([args.email, args.username, args.phone]):
        parser.print_help()
        print("\n[!] Il faut au moins un email, username ou telephone.")
        sys.exit(1)

    banner()

    ts = timestamp()
    target_label = args.nom or args.username or args.email or args.phone
    safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in target_label)
    report_dir = REPORTS_DIR / f"{ts}_{safe_label}"
    report_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Dossier du rapport: {report_dir}")
    print(f"[*] Debut de l'investigation: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")

    if args.email:
        run_holehe(args.email, report_dir)

    if args.username:
        run_sherlock(args.username, report_dir)
        run_maigret(args.username, report_dir)

    generate_summary(args, report_dir)
    generate_report_md(args, report_dir)

    print(f"\n{'='*60}")
    print(f"[*] INVESTIGATION TERMINEE")
    print(f"[*] Tous les resultats sont dans: {report_dir}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
