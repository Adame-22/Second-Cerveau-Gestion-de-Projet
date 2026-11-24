#!/usr/bin/env python3
"""Audit d'exposition numerique complet : identifie les comptes, fuites, entreprises, presence pro et exposition."""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports"

EMAIL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._%+\-]*@[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,63}$")
PHONE_RE = re.compile(r"^\+?[0-9\s\-().]{7,20}$")
SHERLOCK_FOUND_RE = re.compile(r"^\[\+\]\s+(.+?):\s+(https?://\S+)\s*$")

CA_BUNDLE = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")

# --- Data classes ---

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


@dataclass
class BreachInfo:
    email: str
    breach_name: str
    breach_date: str = ""
    data_types: list = field(default_factory=list)


@dataclass
class CompanyInfo:
    name: str
    siren: str = ""
    role: str = ""
    status: str = ""
    address: str = ""
    creation_date: str = ""
    source: str = ""


@dataclass
class PhoneInfo:
    number: str
    valid: bool = False
    country: str = ""
    carrier: str = ""
    line_type: str = ""
    region: str = ""


# --- Helpers ---

def tool(name):
    return str(Path(sys.executable).parent / (name + (".exe" if os.name == "nt" else "")))


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9_\-]", "_", value)


def execute(cmd, log_file, cwd, timeout):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        code, output = proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        code, output = None, partial if isinstance(partial, str) else partial.decode(errors="replace")
    log_file.write_text(output, encoding="utf-8")
    return code, output


def http_get_json(url, timeout=15):
    """GET JSON from a URL, respecting proxy and CA bundle."""
    import ssl
    import urllib.request
    ctx = ssl.create_default_context()
    if CA_BUNDLE and os.path.exists(CA_BUNDLE):
        ctx.load_verify_locations(CA_BUNDLE)
    req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Workflow/1.0", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


# --- Existing tool parsers ---

def parse_holehe_csv(csv_path, email):
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


# --- Existing tool runners ---

def run_holehe(email, raw_dir, opts):
    work_dir = raw_dir / f"holehe_{safe_name(email)}"
    work_dir.mkdir(parents=True)
    code, _ = execute(
        [tool("holehe"), email, "--only-used", "--no-color", "--no-clear", "--csv"],
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
        [tool("sherlock"), username, "--print-found", "--no-color",
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
        [tool("maigret"), username, "--no-color", "--no-progressbar", "--no-recursion",
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


# --- NEW: Phone number analysis ---

def run_phone_lookup(phone):
    import phonenumbers
    try:
        parsed = phonenumbers.parse(phone)
    except phonenumbers.NumberParseException:
        return PhoneInfo(phone, valid=False)

    from phonenumbers import carrier as pn_carrier, geocoder, phonenumberutil
    valid = phonenumbers.is_valid_number(parsed)
    info = PhoneInfo(
        number=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        valid=valid,
        country=geocoder.country_name_for_number(parsed, "fr") or geocoder.country_name_for_number(parsed, "en") or "",
        carrier=pn_carrier.name_for_number(parsed, "fr") or pn_carrier.name_for_number(parsed, "en") or "",
        line_type={0: "fixe", 1: "mobile", 2: "fixe ou mobile", 5: "VOIP", 6: "pager",
                   }.get(phonenumberutil.number_type(parsed), "inconnu"),
        region=geocoder.description_for_number(parsed, "fr") or "",
    )
    return info


# --- NEW: Breach check via HIBP (free, no API key needed for breach names) ---

def run_breach_check(email, raw_dir):
    breaches = []
    work_dir = raw_dir / f"breaches_{safe_name(email)}"
    work_dir.mkdir(parents=True, exist_ok=True)

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false"
    import ssl
    ctx = ssl.create_default_context()
    if CA_BUNDLE and os.path.exists(CA_BUNDLE):
        ctx.load_verify_locations(CA_BUNDLE)
    req = urllib.request.Request(url, headers={
        "User-Agent": "OSINT-Workflow-Audit",
        "hibp-api-key": "",
    })

    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for entry in data:
                breaches.append(BreachInfo(
                    email=email,
                    breach_name=entry.get("Name", ""),
                    breach_date=entry.get("BreachDate", ""),
                    data_types=entry.get("DataClasses", []),
                ))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            pass
        elif exc.code == 401:
            # HIBP v3 needs an API key for this endpoint - try h8mail fallback
            breaches = _run_h8mail_fallback(email, work_dir)
        else:
            breaches = _run_h8mail_fallback(email, work_dir)
    except Exception:
        breaches = _run_h8mail_fallback(email, work_dir)

    (work_dir / "breaches.json").write_text(
        json.dumps([asdict(b) for b in breaches], indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return breaches


def _run_h8mail_fallback(email, work_dir):
    """h8mail checks multiple free breach databases."""
    breaches = []
    try:
        code, output = execute(
            [tool("h8mail"), "-t", email, "--loose", "-j", str(work_dir / "h8mail.json")],
            work_dir / "h8mail_sortie.log", work_dir, 60,
        )
        json_path = work_dir / "h8mail.json"
        if json_path.exists():
            data = json.loads(json_path.read_text(encoding="utf-8"))
            for target in data.get("targets", []):
                for entry in target.get("data", []):
                    src = entry.get("source", "")
                    if src and "not found" not in src.lower():
                        breaches.append(BreachInfo(
                            email=email,
                            breach_name=src,
                            data_types=list(entry.keys()),
                        ))
    except Exception:
        pass
    return breaches


# --- NEW: French company registry search (Pappers.fr free API) ---

def run_company_search(name, raw_dir):
    companies = []
    work_dir = raw_dir / "entreprises"
    work_dir.mkdir(parents=True, exist_ok=True)

    q = urllib.parse.quote(name)
    # Pappers free search endpoint (no API key needed for basic search)
    url = f"https://suggestions.pappers.fr/v2?q={q}&cibles=nom_entreprise,denomination,nom_complet,representant"
    data = http_get_json(url, timeout=15)
    if data and isinstance(data, dict):
        for item in data.get("resultats_nom_entreprise", []):
            companies.append(CompanyInfo(
                name=item.get("nom_entreprise", ""),
                siren=item.get("siren", ""),
                status=item.get("statut", ""),
                address=f"{item.get('siege', {}).get('adresse_ligne_1', '')} {item.get('siege', {}).get('code_postal', '')} {item.get('siege', {}).get('ville', '')}".strip(),
                creation_date=item.get("date_creation", ""),
                source="pappers.fr (nom d'entreprise)",
            ))
        for item in data.get("resultats_denomination", []):
            companies.append(CompanyInfo(
                name=item.get("nom_entreprise", ""),
                siren=item.get("siren", ""),
                status=item.get("statut", ""),
                address=f"{item.get('siege', {}).get('adresse_ligne_1', '')} {item.get('siege', {}).get('code_postal', '')} {item.get('siege', {}).get('ville', '')}".strip(),
                creation_date=item.get("date_creation", ""),
                source="pappers.fr (denomination)",
            ))
        for item in data.get("resultats_representant", []):
            companies.append(CompanyInfo(
                name=item.get("nom_entreprise", ""),
                siren=item.get("siren", ""),
                role=item.get("qualite", ""),
                status=item.get("statut", ""),
                address=f"{item.get('siege', {}).get('adresse_ligne_1', '')} {item.get('siege', {}).get('code_postal', '')} {item.get('siege', {}).get('ville', '')}".strip(),
                creation_date=item.get("date_creation", ""),
                source="pappers.fr (representant)",
            ))
        for item in data.get("resultats_nom_complet", []):
            companies.append(CompanyInfo(
                name=item.get("nom_entreprise", ""),
                siren=item.get("siren", ""),
                role=item.get("qualite", ""),
                status=item.get("statut", ""),
                address=f"{item.get('siege', {}).get('adresse_ligne_1', '')} {item.get('siege', {}).get('code_postal', '')} {item.get('siege', {}).get('ville', '')}".strip(),
                creation_date=item.get("date_creation", ""),
                source="pappers.fr (nom complet)",
            ))

    # Deduplicate by SIREN
    seen = set()
    unique = []
    for c in companies:
        key = c.siren or c.name
        if key not in seen:
            seen.add(key)
            unique.append(c)
    companies = unique

    (work_dir / "entreprises.json").write_text(
        json.dumps([asdict(c) for c in companies], indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return companies


# --- NEW: WHOIS on email domain (personal domain = exposed address info) ---

def run_whois_lookup(email, raw_dir):
    domain = email.split("@", 1)[1].lower()
    free_providers = {
        "gmail.com", "yahoo.com", "yahoo.fr", "hotmail.com", "hotmail.fr",
        "outlook.com", "outlook.fr", "live.com", "live.fr", "aol.com",
        "protonmail.com", "proton.me", "icloud.com", "me.com", "mac.com",
        "gmx.com", "gmx.fr", "mail.com", "laposte.net", "orange.fr",
        "free.fr", "sfr.fr", "wanadoo.fr", "bbox.fr",
    }
    if domain in free_providers:
        return None

    work_dir = raw_dir / "whois"
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        import whois
        w = whois.whois(domain)
        info = {
            "domain": domain,
            "registrar": w.registrar or "",
            "creation_date": str(w.creation_date) if w.creation_date else "",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "",
            "name_servers": w.name_servers if isinstance(w.name_servers, list) else [],
            "registrant_name": getattr(w, "name", "") or "",
            "registrant_org": getattr(w, "org", "") or "",
            "registrant_country": getattr(w, "country", "") or "",
            "registrant_state": getattr(w, "state", "") or "",
            "registrant_city": getattr(w, "city", "") or "",
            "registrant_address": getattr(w, "address", "") or "",
            "emails_in_whois": w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else []),
        }
        (work_dir / f"whois_{safe_name(domain)}.json").write_text(
            json.dumps(info, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
        )
        return info
    except Exception:
        return None


# --- NEW: Google dorking (extract dork URLs for the report) ---

def build_google_dorks(nom=None, emails=None, phones=None, usernames=None):
    dorks = []
    if nom:
        dorks.append({"label": "Nom complet", "query": f'"{nom}"', "url": f"https://www.google.com/search?q=%22{urllib.parse.quote(nom)}%22"})
        dorks.append({"label": "Nom + adresse", "query": f'"{nom}" adresse OR rue OR avenue', "url": f"https://www.google.com/search?q=%22{urllib.parse.quote(nom)}%22+adresse+OR+rue+OR+avenue"})
        dorks.append({"label": "Nom + telephone", "query": f'"{nom}" telephone OR tel OR phone', "url": f"https://www.google.com/search?q=%22{urllib.parse.quote(nom)}%22+telephone+OR+tel+OR+phone"})
        dorks.append({"label": "Nom + LinkedIn", "query": f'site:linkedin.com "{nom}"', "url": f"https://www.google.com/search?q=site%3Alinkedin.com+%22{urllib.parse.quote(nom)}%22"})
        dorks.append({"label": "Nom + Facebook", "query": f'site:facebook.com "{nom}"', "url": f"https://www.google.com/search?q=site%3Afacebook.com+%22{urllib.parse.quote(nom)}%22"})
        dorks.append({"label": "Nom + societe.com", "query": f'site:societe.com "{nom}"', "url": f"https://www.google.com/search?q=site%3Asociete.com+%22{urllib.parse.quote(nom)}%22"})
        dorks.append({"label": "Nom + Pages Blanches", "query": f'site:pagesjaunes.fr "{nom}"', "url": f"https://www.google.com/search?q=site%3Apagesjaunes.fr+%22{urllib.parse.quote(nom)}%22"})
        dorks.append({"label": "Nom + fichiers (PDF, XLS)", "query": f'"{nom}" filetype:pdf OR filetype:xls OR filetype:doc', "url": f"https://www.google.com/search?q=%22{urllib.parse.quote(nom)}%22+filetype%3Apdf+OR+filetype%3Axls+OR+filetype%3Adoc"})
    for email in (emails or []):
        dorks.append({"label": f"Email {email}", "query": f'"{email}"', "url": f"https://www.google.com/search?q=%22{urllib.parse.quote(email)}%22"})
        dorks.append({"label": f"Email + paste", "query": f'"{email}" site:pastebin.com OR site:ghostbin.com', "url": f"https://www.google.com/search?q=%22{urllib.parse.quote(email)}%22+site%3Apastebin.com+OR+site%3Aghostbin.com"})
    for phone in (phones or []):
        clean = phone.replace(" ", "").replace("-", "").replace(".", "")
        dorks.append({"label": f"Telephone {phone}", "query": f'"{clean}" OR "{phone}"', "url": f"https://www.google.com/search?q=%22{urllib.parse.quote(clean)}%22+OR+%22{urllib.parse.quote(phone)}%22"})
    for u in (usernames or []):
        dorks.append({"label": f"Pseudo {u} (web)", "query": f'"{u}" -site:github.com', "url": f"https://www.google.com/search?q=%22{urllib.parse.quote(u)}%22+-site%3Agithub.com"})
    return dorks


# --- NEW: Extract enriched profile data from Maigret ---

def extract_profile_details(runs):
    """Pull structured info (location, bio, real name, links) from Maigret findings."""
    profiles = {}
    for run in runs:
        if run.tool != "maigret":
            continue
        for f in run.findings:
            d = f.details
            for key in ("fullname", "bio", "location", "website", "gender", "age",
                        "country", "city", "occupation", "company", "education"):
                if d.get(key):
                    profiles.setdefault(key, set()).add(d[key])
    return {k: sorted(v) for k, v in profiles.items()}


# --- Merge ---

def merge_findings(runs):
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


# --- Report ---

def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_report(opts, runs, findings, started, breaches, companies, phone_infos, whois_results, dorks, profile_details):
    by_kind = {"username": [], "email": []}
    for finding in findings:
        by_kind[finding.kind].append(finding)
    leads = sorted({lead for run in runs for lead in run.leads})
    failed = [run for run in runs if not run.ok]

    out = [
        "# Rapport d'investigation OSINT",
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
    for phone in opts.phone:
        out.append(f"- **Telephone analyse :** {phone}")

    # --- Synthese executive ---
    out += ["", "---", "", "## 1. Synthese executive", ""]
    total_accounts = len(findings)
    total_breaches = len(breaches)
    total_companies = len(companies)
    risk_level = "ELEVE" if total_breaches > 3 or total_accounts > 20 else "MOYEN" if total_breaches > 0 or total_accounts > 5 else "FAIBLE"
    out.append(f"**Niveau d'exposition global : {risk_level}**")
    out.append("")
    out.append(f"| Indicateur | Nombre |")
    out.append(f"|---|---|")
    out.append(f"| Comptes en ligne detectes | {total_accounts} |")
    out.append(f"| Fuites de donnees confirmees | {total_breaches} |")
    out.append(f"| Entreprises liees | {total_companies} |")
    out.append(f"| Scans lances | {len(runs)} |")
    out.append(f"| Scans en echec | {len(failed)} |")

    if failed:
        out.append("")
        out.append(f"**Attention : {len(failed)} scan(s) en echec, le resultat est incomplet.**")

    # --- Profil synthetique (extracted from Maigret) ---
    if profile_details:
        out += ["", "## 2. Profil synthetique (extrait des comptes trouves)", ""]
        out.append("| Information | Valeurs trouvees |")
        out.append("|---|---|")
        labels = {
            "fullname": "Nom complet", "bio": "Bio / description", "location": "Localisation",
            "city": "Ville", "country": "Pays", "gender": "Genre", "age": "Age",
            "occupation": "Profession", "company": "Entreprise", "education": "Formation",
            "website": "Site web",
        }
        for key, label in labels.items():
            if key in profile_details:
                out.append(f"| {label} | {cell(', '.join(profile_details[key]))} |")
    else:
        out += ["", "## 2. Profil synthetique", "", "Aucune information de profil extraite des comptes trouves."]

    # --- Phone analysis ---
    if phone_infos:
        out += ["", "## 3. Analyse des numeros de telephone", ""]
        out.append("| Numero | Valide | Pays | Operateur | Type | Region |")
        out.append("|---|---|---|---|---|---|")
        for pi in phone_infos:
            out.append(f"| {cell(pi.number)} | {'oui' if pi.valid else 'non'} | {cell(pi.country)} | {cell(pi.carrier)} | {cell(pi.line_type)} | {cell(pi.region)} |")
    else:
        out += ["", "## 3. Analyse des numeros de telephone", "", "Aucun numero fourni."]

    # --- Breaches ---
    if breaches:
        out += ["", "## 4. Fuites de donnees (data breaches)", ""]
        out.append(f"**{len(breaches)} fuite(s) trouvee(s).** Les donnees suivantes ont ete exposees :")
        out.append("")
        out.append("| Email | Fuite | Date | Donnees exposees |")
        out.append("|---|---|---|---|")
        for b in breaches:
            types = ", ".join(b.data_types[:5]) if b.data_types else "-"
            out.append(f"| {cell(b.email)} | {cell(b.breach_name)} | {cell(b.breach_date)} | {cell(types)} |")
        out.append("")
        out.append("**Risques :** mots de passe potentiellement compromis, vol d'identite, usurpation, phishing cible.")
    else:
        out += ["", "## 4. Fuites de donnees", "", "Aucune fuite connue trouvee (via les sources gratuites interrogees)."]

    # --- Companies ---
    if companies:
        out += ["", "## 5. Entreprises et registres publics", ""]
        out.append(f"**{len(companies)} entreprise(s) liee(s) au nom fourni :**")
        out.append("")
        out.append("| Entreprise | SIREN | Role | Statut | Adresse | Creation | Source |")
        out.append("|---|---|---|---|---|---|---|")
        for c in companies:
            out.append(f"| {cell(c.name)} | {cell(c.siren)} | {cell(c.role)} | {cell(c.status)} | {cell(c.address)} | {cell(c.creation_date)} | {cell(c.source)} |")
        out.append("")
        out.append("**Risques :** l'adresse du siege peut reveler une adresse personnelle (domiciliation a domicile)."
                    " Les registres publics (Pappers, Infogreffe, societe.com) sont accessibles a tous.")
    else:
        out += ["", "## 5. Entreprises et registres publics", "", "Aucune entreprise trouvee au nom fourni (recherche France uniquement)."]

    # --- WHOIS ---
    whois_found = [w for w in whois_results if w is not None]
    if whois_found:
        out += ["", "## 6. Domaines email (WHOIS)", ""]
        for w in whois_found:
            out.append(f"### {w['domain']}")
            out.append("")
            out.append(f"| Champ | Valeur |")
            out.append(f"|---|---|")
            if w.get("registrant_name"):
                out.append(f"| Proprietaire | {cell(w['registrant_name'])} |")
            if w.get("registrant_org"):
                out.append(f"| Organisation | {cell(w['registrant_org'])} |")
            if w.get("registrant_address"):
                out.append(f"| Adresse | {cell(w['registrant_address'])} |")
            if w.get("registrant_city"):
                out.append(f"| Ville | {cell(w['registrant_city'])} |")
            if w.get("registrant_country"):
                out.append(f"| Pays | {cell(w['registrant_country'])} |")
            if w.get("registrar"):
                out.append(f"| Registrar | {cell(w['registrar'])} |")
            if w.get("creation_date"):
                out.append(f"| Creation | {cell(w['creation_date'])} |")
            if w.get("emails_in_whois"):
                out.append(f"| Emails WHOIS | {cell(', '.join(w['emails_in_whois']))} |")
            out.append("")
            out.append("**Risque :** un domaine personnel peut exposer le nom, l'adresse et le telephone du proprietaire via WHOIS.")
    else:
        out += ["", "## 6. Domaines email (WHOIS)", "", "Emails heberges sur des fournisseurs publics (aucun domaine personnel detecte)."]

    # --- Tool scan details ---
    out += ["", "## 7. Detail des scans", ""]
    out.append("| Outil | Identifiant | Etat | Comptes | Couverture |")
    out.append("|---|---|---|---|---|")
    for run in runs:
        etat = "OK" if run.ok else "ECHEC"
        out.append(f"| {run.tool} | {cell(run.identifier)} | {etat} | {len(run.findings)} | {cell(run.note)} |")

    # --- Accounts found ---
    if by_kind["username"]:
        out += ["", "## 8. Comptes trouves a partir des pseudos", "",
                "| Pseudo | Site | Lien | Vu par | Informations visibles |", "|---|---|---|---|---|"]
        for f in by_kind["username"]:
            infos = ", ".join(f"{k}: {v}" for k, v in f.details.items()) or "-"
            out.append(f"| {cell(f.identifier)} | {cell(f.site)} | {f.url} | {', '.join(f.sources)} | {cell(infos)} |")

    if by_kind["email"]:
        out += ["", "## 9. Services ou l'email est inscrit", "",
                "| Email | Service | Indices divulgues par le service |", "|---|---|---|"]
        for f in by_kind["email"]:
            infos = ", ".join(f"{k}: {v}" for k, v in f.details.items()) or "-"
            out.append(f"| {cell(f.identifier)} | {cell(f.site)} ({f.url}) | {cell(infos)} |")

    # --- Leads ---
    if leads:
        out += ["", "## 10. Autres identifiants / proches reperes", "",
                "Identifiants supplementaires trouves sur les profils. A confirmer avec le client :", ""]
        out += [f"- {lead}" for lead in leads]

    # --- Google dorks ---
    if dorks:
        out += ["", "## 11. Pistes de recherche manuelle (Google dorks)", "",
                "Liens a ouvrir manuellement pour approfondir l'investigation :", ""]
        out.append("| Recherche | Lien |")
        out.append("|---|---|")
        for d in dorks:
            out.append(f"| {cell(d['label'])} | [Ouvrir]({d['url']}) |")

    # --- Action plan ---
    out += ["", "---", "", "## Plan d'action", ""]

    if breaches:
        out += [
            "### Priorite 1 : Fuites de donnees",
            "",
            "- [ ] Changer immediatement les mots de passe des services concernes par les fuites.",
            "- [ ] Verifier sur https://haveibeenpwned.com si d'autres emails ont fuite.",
            "- [ ] Activer la double authentification (2FA) sur tous les comptes sensibles.",
            "- [ ] Surveiller les releves bancaires (risque d'usurpation d'identite).",
            "",
        ]

    if companies:
        out += [
            "### Priorite 2 : Exposition via les registres d'entreprise",
            "",
            "- [ ] Verifier si l'adresse du siege est l'adresse personnelle.",
            "- [ ] Si oui, envisager une domiciliation commerciale pour masquer l'adresse.",
            "- [ ] Contacter Pappers.fr et societe.com pour demander le masquage de certaines donnees.",
            "",
        ]

    if findings:
        out += [
            "### Priorite 3 : Comptes en ligne",
            "",
            "Pour chaque compte, decider avec le client : conserver, passer en prive, ou supprimer.",
            "",
        ]
        for f in findings:
            target = f.url or f.site
            out.append(f"- [ ] **{f.site}** ({f.identifier}) : {target}")
        out.append("")

    out += [
        "### Mesures generales",
        "",
        "- [ ] Utiliser un mot de passe unique par service (gestionnaire de mots de passe recommande).",
        "- [ ] Activer la double authentification sur les comptes conserves.",
        "- [ ] Supprimer les comptes inutiles (liens directs : https://justdeleteme.xyz).",
        "- [ ] Pour les contenus non supprimables : demande d'effacement (RGPD art. 17), puis dereferencement Google.",
        "- [ ] Utiliser a l'avenir un pseudo et un email differents par service.",
        "- [ ] Ouvrir les liens Google dorks de la section 11 pour trouver d'autres traces.",
        "",
        "## Limites",
        "",
        "- Un pseudo identique ne prouve pas qu'il s'agit de la meme personne.",
        "- L'absence de resultat ne prouve pas l'absence d'exposition.",
        "- Seules des sources publiques et gratuites ont ete interrogees.",
        "- La recherche d'entreprise couvre uniquement les registres francais (Pappers.fr).",
        "- Les fuites de donnees ne sont verifiees que via les bases gratuites (HIBP sans cle API, h8mail).",
        "- L'API HIBP v3 necessite une cle payante pour des resultats complets ; sans cle, les resultats peuvent etre partiels.",
        "",
    ]
    return "\n".join(out)


# --- CLI ---

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit d'exposition numerique complet : comptes, fuites, entreprises, telephone, WHOIS."
    )
    parser.add_argument("--mandat", "-m", required=True,
                        help="Reference de l'accord ecrit de la personne concernee")
    parser.add_argument("--email", "-e", action="append", default=[], help="Email a analyser (repetable)")
    parser.add_argument("--username", "-u", action="append", default=[], help="Pseudo a analyser (repetable)")
    parser.add_argument("--phone", "-p", action="append", default=[], help="Numero de telephone (repetable)")
    parser.add_argument("--nom", "-n", help="Nom complet de la personne (active la recherche d'entreprise et les dorks)")
    parser.add_argument("--all-sites", action="store_true", help="Maigret : tous les sites (long)")
    parser.add_argument("--top-sites", type=int, default=500, help="Maigret : nombre de sites (defaut 500)")
    parser.add_argument("--skip", action="append", default=[],
                        choices=["holehe", "sherlock", "maigret", "breach", "company", "whois", "phone"],
                        help="Module a ne pas lancer (repetable)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout par requete (defaut 10)")
    parser.add_argument("--tool-timeout", type=int, default=1800, help="Duree max par outil (defaut 1800)")
    opts = parser.parse_args(argv)

    if not opts.email and not opts.username and not opts.phone:
        parser.error("il faut au moins un --email, --username ou --phone")
    for email in opts.email:
        if not EMAIL_RE.match(email):
            parser.error(f"email invalide : {email}")
    for username in opts.username:
        if not USERNAME_RE.match(username):
            parser.error(f"pseudo invalide : {username}")
    for phone in opts.phone:
        if not PHONE_RE.match(phone):
            parser.error(f"telephone invalide : {phone}")
    return opts


def main(argv=None):
    opts = parse_args(argv)
    started = datetime.now()
    report_dir = REPORTS_DIR / f"{started.strftime('%Y%m%d_%H%M%S')}_{safe_name(opts.mandat)}"
    raw_dir = report_dir / "brut"
    raw_dir.mkdir(parents=True)

    # Phase 1: Account enumeration (parallel)
    jobs = []
    if "holehe" not in opts.skip:
        jobs += [(run_holehe, email) for email in opts.email]
    if "sherlock" not in opts.skip:
        jobs += [(run_sherlock, username) for username in opts.username]
    if "maigret" not in opts.skip:
        jobs += [(run_maigret, username) for username in opts.username]

    runs = []
    if jobs:
        print(f"[*] Phase 1 : {len(jobs)} scan(s) de comptes en parallele...")
        with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
            futures = [pool.submit(func, identifier, raw_dir, opts) for func, identifier in jobs]
            for future in futures:
                run = future.result()
                runs.append(run)
                etat = "OK" if run.ok else "ECHEC"
                print(f"  [{etat}] {run.tool} {run.identifier} : {len(run.findings)} compte(s) - {run.note}")

    # Phase 2: Deep analysis (parallel)
    print("[*] Phase 2 : analyse approfondie...")
    breaches = []
    companies = []
    phone_infos = []
    whois_results = []

    with ThreadPoolExecutor(max_workers=6) as pool:
        # Breach checks
        breach_futures = []
        if "breach" not in opts.skip:
            for email in opts.email:
                breach_futures.append(pool.submit(run_breach_check, email, raw_dir))

        # Company search
        company_future = None
        if opts.nom and "company" not in opts.skip:
            company_future = pool.submit(run_company_search, opts.nom, raw_dir)

        # Phone analysis
        phone_futures = []
        if "phone" not in opts.skip:
            for phone in opts.phone:
                phone_futures.append(pool.submit(run_phone_lookup, phone))

        # WHOIS
        whois_futures = []
        if "whois" not in opts.skip:
            for email in opts.email:
                whois_futures.append(pool.submit(run_whois_lookup, email, raw_dir))

        for f in breach_futures:
            result = f.result()
            breaches.extend(result)
            print(f"  [INFO] Fuites : {len(result)} trouvee(s)")

        if company_future:
            companies = company_future.result()
            print(f"  [INFO] Entreprises : {len(companies)} trouvee(s)")

        for f in phone_futures:
            pi = f.result()
            phone_infos.append(pi)
            print(f"  [INFO] Telephone {pi.number} : {'valide' if pi.valid else 'invalide'}, {pi.carrier or 'operateur inconnu'}")

        for f in whois_futures:
            w = f.result()
            whois_results.append(w)
            if w:
                print(f"  [INFO] WHOIS {w['domain']} : domaine personnel detecte")

    # Phase 3: Build report
    print("[*] Phase 3 : generation du rapport...")
    findings = merge_findings(runs)
    profile_details = extract_profile_details(runs)
    dorks = build_google_dorks(opts.nom, opts.email, opts.phone, opts.username)

    (report_dir / "resultats.json").write_text(
        json.dumps(
            {
                "date": started.isoformat(timespec="seconds"),
                "mandat": opts.mandat,
                "nom": opts.nom,
                "emails": opts.email,
                "pseudos": opts.username,
                "telephones": opts.phone,
                "scans": [{"outil": r.tool, "identifiant": r.identifier, "ok": r.ok, "note": r.note,
                           "pistes": r.leads} for r in runs],
                "comptes": [asdict(f) for f in findings],
                "fuites": [asdict(b) for b in breaches],
                "entreprises": [asdict(c) for c in companies],
                "telephones_info": [asdict(p) for p in phone_infos],
                "whois": [w for w in whois_results if w],
                "profil": profile_details,
                "dorks": dorks,
            },
            indent=2, ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    report_file = report_dir / "RAPPORT.md"
    report_file.write_text(
        render_report(opts, runs, findings, started, breaches, companies, phone_infos, whois_results, dorks, profile_details),
        encoding="utf-8",
    )

    print(f"[*] Resultat : {len(findings)} comptes, {len(breaches)} fuites, {len(companies)} entreprises")
    print(f"[*] Rapport : {report_file}")
    if runs and not any(run.ok for run in runs):
        sys.exit(1)


if __name__ == "__main__":
    main()
