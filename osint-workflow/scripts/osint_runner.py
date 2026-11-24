#!/usr/bin/env python3
"""Audit d'exposition numerique : orchestre holehe, sherlock et maigret, puis produit un rapport client."""

import argparse
import csv
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV_BIN = ROOT / "venv" / "bin"
REPORTS_DIR = ROOT / "reports"

EMAIL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}$")
# Le premier caractere ne peut pas etre "-" : la valeur est passee telle quelle aux outils en ligne de commande.
USERNAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}$")
SHERLOCK_FOUND_RE = re.compile(r"^\[\+\]\s+(.+?):\s+(https?://\S+)\s*$")


@dataclass
class Finding:
    identifier: str
    kind: str
    site: str
    url: str = ""
    sources: list = field(default_factory=list)
    details: dict = field(default_factory=dict)


@dataclass
class ToolRun:
    tool: str
    identifier: str
    ok: bool
    note: str = ""
    findings: list = field(default_factory=list)
    leads: list = field(default_factory=list)


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9_\-]", "_", value)


def execute(cmd, log_file, cwd, timeout):
    """Lance un outil, journalise sa sortie, renvoie (code retour ou None si timeout, sortie)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        code, output = proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        code, output = None, partial if isinstance(partial, str) else partial.decode(errors="replace")
    log_file.write_text(output, encoding="utf-8")
    return code, output


def parse_holehe_csv(csv_path, email):
    """Renvoie (comptes trouves, nb de sites verifies, nb de sites non verifies pour cause de rate limit)."""
    findings, checked, rate_limited = [], 0, 0
    with open(csv_path, newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row.get("exists") == "True":
                details = {
                    label: row[key]
                    for key, label in (
                        ("emailrecovery", "email de secours (partiel)"),
                        ("phoneNumber", "telephone (partiel)"),
                        ("others", "autres"),
                    )
                    if row.get(key) and row[key] != "None"
                }
                findings.append(
                    Finding(email, "email", row["name"], f"https://{row['domain']}", ["holehe"], details)
                )
                checked += 1
            elif row.get("rateLimit") == "True":
                rate_limited += 1
            else:
                checked += 1
    return findings, checked, rate_limited


def parse_sherlock_output(output, username):
    findings = []
    for line in output.splitlines():
        match = SHERLOCK_FOUND_RE.match(line.strip())
        if match:
            findings.append(Finding(username, "username", match.group(1), match.group(2), ["sherlock"]))
    return findings


def parse_maigret_json(json_path, username):
    """Renvoie (comptes trouves, autres identifiants decouverts sur les profils)."""
    data = json.loads(Path(json_path).read_text(encoding="utf-8"))
    findings, leads = [], set()
    for site, entry in data.items():
        status = entry.get("status") or {}
        if status.get("status") != "Claimed":
            continue
        details = {
            key: str(value)
            for key, value in (status.get("ids") or {}).items()
            if value and isinstance(value, (str, int))
            and not key.startswith("_") and "image" not in key and "hash" not in key
        }
        findings.append(Finding(username, "username", site, entry.get("url_user", ""), ["maigret"], details))
        for other, id_type in (entry.get("ids_usernames") or {}).items():
            if other.lower() != username.lower():
                leads.add(f"{other} ({id_type}, vu sur {site})")
    return findings, sorted(leads)


def run_holehe(email, raw_dir, opts):
    work_dir = raw_dir / f"holehe_{safe_name(email)}"
    work_dir.mkdir(parents=True)
    code, _ = execute(
        # Pas de --timeout : holehe 1.61 le transmet comme chaine a httpx et toutes les requetes echouent.
        [str(VENV_BIN / "holehe"), email, "--only-used", "--no-color", "--no-clear", "--csv"],
        work_dir / "sortie.log", work_dir, opts.tool_timeout,
    )
    csv_files = list(work_dir.glob("holehe_*_results.csv"))
    if not csv_files:
        return ToolRun("holehe", email, False, "echec (timeout)" if code is None else f"echec (code {code})")
    findings, checked, rate_limited = parse_holehe_csv(csv_files[0], email)
    note = f"{checked} sites verifies"
    if rate_limited:
        note += f", {rate_limited} NON verifies (limitation de debit) : relancer plus tard ou depuis une autre connexion"
    return ToolRun("holehe", email, True, note, findings)


def run_sherlock(username, raw_dir, opts):
    work_dir = raw_dir / f"sherlock_{safe_name(username)}"
    work_dir.mkdir(parents=True)
    code, output = execute(
        [str(VENV_BIN / "sherlock"), username, "--print-found", "--no-color",
         "--timeout", str(opts.timeout), "--folderoutput", str(work_dir)],
        work_dir / "sortie.log", work_dir, opts.tool_timeout,
    )
    findings = parse_sherlock_output(output, username)
    if code != 0 and not findings:
        return ToolRun("sherlock", username, False, "echec (timeout)" if code is None else f"echec (code {code})")
    note = "scan interrompu par timeout, resultats partiels" if code is None else "scan complet"
    return ToolRun("sherlock", username, True, note, findings)


def run_maigret(username, raw_dir, opts):
    work_dir = raw_dir / f"maigret_{safe_name(username)}"
    work_dir.mkdir(parents=True)
    scope = ["--all-sites"] if opts.all_sites else ["--top-sites", str(opts.top_sites)]
    code, output = execute(
        [str(VENV_BIN / "maigret"), username, "--no-color", "--no-progressbar", "--no-recursion",
         "--timeout", str(opts.timeout), "--json", "simple", "--html", "--folderoutput", str(work_dir)] + scope,
        work_dir / "sortie.log", work_dir, opts.tool_timeout,
    )
    json_files = list(work_dir.glob("report_*_simple.json"))
    if not json_files:
        return ToolRun("maigret", username, False, "echec (timeout)" if code is None else f"echec (code {code})")
    findings, leads = parse_maigret_json(json_files[0], username)
    warnings = [line[4:].strip() for line in output.splitlines() if line.startswith("[!] Too many errors")]
    note = "tous les sites" if opts.all_sites else f"top {opts.top_sites} sites"
    if warnings:
        note += " ; couverture incomplete : " + " / ".join(w.split(". ")[0] for w in warnings)
    return ToolRun("maigret", username, True, note, findings, leads)


def merge_findings(runs):
    """Fusionne les comptes vus par plusieurs outils (meme identifiant, meme site)."""
    merged = {}
    for run in runs:
        for finding in run.findings:
            key = (finding.identifier.lower(), re.sub(r"[^a-z0-9]", "", finding.site.lower()))
            if key not in merged:
                merged[key] = Finding(**asdict(finding))
                continue
            existing = merged[key]
            existing.sources = sorted(set(existing.sources) | set(finding.sources))
            existing.details.update(finding.details)
            existing.url = existing.url or finding.url
    return sorted(merged.values(), key=lambda f: (f.kind, f.identifier.lower(), f.site.lower()))


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_report(opts, runs, findings, started):
    by_kind = {"username": [], "email": []}
    for finding in findings:
        by_kind[finding.kind].append(finding)
    leads = sorted({lead for run in runs for lead in run.leads})
    failed = [run for run in runs if not run.ok]

    out = [
        "# Rapport d'exposition numerique",
        "",
        f"- **Date :** {started.strftime('%d/%m/%Y %H:%M')}",
        f"- **Mandat / autorisation :** {opts.mandat}",
    ]
    if opts.nom:
        out.append(f"- **Personne concernee :** {opts.nom}")
    for email in opts.email:
        out.append(f"- **Email analyse :** {email}")
    for username in opts.username:
        out.append(f"- **Pseudo analyse :** {username}")

    out += ["", "## Synthese", ""]
    out.append(f"**{len(findings)} compte(s) public(s) relie(s) aux identifiants fournis.**")
    if failed:
        out.append("")
        out.append(f"Attention : {len(failed)} scan(s) en echec, le resultat est donc incomplet (voir tableau).")
    out += ["", "| Outil | Identifiant | Etat | Comptes | Couverture |", "|---|---|---|---|---|"]
    for run in runs:
        etat = "OK" if run.ok else "ECHEC"
        out.append(f"| {run.tool} | {cell(run.identifier)} | {etat} | {len(run.findings)} | {cell(run.note)} |")

    if by_kind["username"]:
        out += ["", "## Comptes trouves a partir des pseudos", "",
                "| Pseudo | Site | Lien | Vu par | Informations visibles |", "|---|---|---|---|---|"]
        for f in by_kind["username"]:
            infos = ", ".join(f"{k}: {v}" for k, v in f.details.items()) or "-"
            out.append(f"| {cell(f.identifier)} | {cell(f.site)} | {f.url} | {', '.join(f.sources)} | {cell(infos)} |")

    if by_kind["email"]:
        out += ["", "## Services ou l'email est inscrit", "",
                "| Email | Service | Indices divulgues par le service |", "|---|---|---|"]
        for f in by_kind["email"]:
            infos = ", ".join(f"{k}: {v}" for k, v in f.details.items()) or "-"
            out.append(f"| {cell(f.identifier)} | {cell(f.site)} ({f.url}) | {cell(infos)} |")

    if leads:
        out += ["", "## Autres identifiants reperes sur les profils", "",
                "A confirmer avec le client avant toute nouvelle recherche (ils peuvent appartenir a un tiers) :", ""]
        out += [f"- {lead}" for lead in leads]

    out += ["", "## Plan d'action", ""]
    if findings:
        out.append("Pour chaque compte, decider avec le client : conserver, passer en prive, ou supprimer.")
        out.append("")
        for f in findings:
            target = f.url or f.site
            out.append(f"- [ ] **{f.site}** ({f.identifier}) : {target}")
        out.append("")
    out += [
        "Mesures generales :",
        "",
        "- Verifier chaque email sur https://haveibeenpwned.com et changer tout mot de passe expose ou reutilise.",
        "- Activer la double authentification sur les comptes conserves.",
        "- Supprimer les comptes inutiles (liens directs de suppression : https://justdeleteme.xyz).",
        "- Pour les contenus qu'on ne peut pas supprimer soi-meme : demande d'effacement au site (RGPD, article 17),"
        " puis demande de dereferencement aupres des moteurs de recherche.",
        "- Utiliser a l'avenir un pseudo et un email differents par service pour casser les recoupements.",
        "",
        "## Limites",
        "",
        "- Un pseudo identique ne prouve pas qu'il s'agit de la meme personne : chaque compte doit etre confirme"
        " par le client avant d'etre considere comme le sien.",
        "- L'absence de resultat ne prouve pas l'absence de compte (sites non couverts, limitation de debit, blocages).",
        "- Seules des sources publiquement accessibles ont ete interrogees.",
        "",
    ]
    return "\n".join(out)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit d'exposition numerique a partir d'emails et de pseudos, avec rapport client."
    )
    parser.add_argument("--mandat", "-m", required=True,
                        help="Reference de l'accord ecrit de la personne concernee (ex: MANDAT-2026-014). "
                             "Elle figure dans le rapport et sert de nom au dossier.")
    parser.add_argument("--email", "-e", action="append", default=[], help="Email a analyser (repetable)")
    parser.add_argument("--username", "-u", action="append", default=[], help="Pseudo a analyser (repetable)")
    parser.add_argument("--nom", "-n", help="Nom de la personne concernee (affiche dans le rapport)")
    parser.add_argument("--all-sites", action="store_true", help="Maigret : tous les sites (long) au lieu du top N")
    parser.add_argument("--top-sites", type=int, default=500, help="Maigret : nombre de sites (defaut 500)")
    parser.add_argument("--skip", action="append", default=[], choices=["holehe", "sherlock", "maigret"],
                        help="Outil a ne pas lancer (repetable)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout par requete, en secondes (defaut 10)")
    parser.add_argument("--tool-timeout", type=int, default=1800,
                        help="Duree maximale d'un outil, en secondes (defaut 1800)")
    opts = parser.parse_args(argv)

    if not opts.email and not opts.username:
        parser.error("il faut au moins un --email ou un --username")
    for email in opts.email:
        if not EMAIL_RE.match(email):
            parser.error(f"email invalide : {email}")
    for username in opts.username:
        if not USERNAME_RE.match(username):
            parser.error(f"pseudo invalide : {username}")
    return opts


def main(argv=None):
    opts = parse_args(argv)
    started = datetime.now()
    report_dir = REPORTS_DIR / f"{started.strftime('%Y%m%d_%H%M%S')}_{safe_name(opts.mandat)}"
    raw_dir = report_dir / "brut"
    raw_dir.mkdir(parents=True)

    jobs = []
    if "holehe" not in opts.skip:
        jobs += [(run_holehe, email) for email in opts.email]
    if "sherlock" not in opts.skip:
        jobs += [(run_sherlock, username) for username in opts.username]
    if "maigret" not in opts.skip:
        jobs += [(run_maigret, username) for username in opts.username]
    if not jobs:
        sys.exit("Aucun scan a lancer avec ces options.")

    print(f"[*] {len(jobs)} scan(s) lances en parallele, dossier : {report_dir}")
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(func, identifier, raw_dir, opts) for func, identifier in jobs]
        runs = []
        for future in futures:
            run = future.result()
            runs.append(run)
            etat = "OK" if run.ok else "ECHEC"
            print(f"[{etat}] {run.tool} {run.identifier} : {len(run.findings)} compte(s) - {run.note}")

    findings = merge_findings(runs)
    (report_dir / "resultats.json").write_text(
        json.dumps(
            {
                "date": started.isoformat(timespec="seconds"),
                "mandat": opts.mandat,
                "nom": opts.nom,
                "emails": opts.email,
                "pseudos": opts.username,
                "scans": [{"outil": r.tool, "identifiant": r.identifier, "ok": r.ok, "note": r.note,
                           "pistes": r.leads} for r in runs],
                "comptes": [asdict(f) for f in findings],
            },
            indent=2, ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    report_file = report_dir / "RAPPORT.md"
    report_file.write_text(render_report(opts, runs, findings, started), encoding="utf-8")

    print(f"[*] {len(findings)} compte(s) au total. Rapport : {report_file}")
    if not any(run.ok for run in runs):
        sys.exit(1)


if __name__ == "__main__":
    main()
