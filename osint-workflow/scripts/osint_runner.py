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
CONFIG_PATH = ROOT / "config.json"


def load_config(path=None):
    p = Path(path) if path else CONFIG_PATH
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


CONFIG = load_config()

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


def _c(text, color=""):
    colors = {"green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m",
              "blue": "\033[94m", "bold": "\033[1m", "dim": "\033[2m"}
    if not sys.stdout.isatty() or not color:
        return str(text)
    return f"{colors.get(color, '')}{text}\033[0m"


def execute(cmd, log_file, cwd, timeout):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        code, output = proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        code, output = None, partial if isinstance(partial, str) else partial.decode(errors="replace")
    log_file.write_text(output, encoding="utf-8")
    return code, output


def http_get_json(url, timeout=15, retries=2):
    """GET JSON from a URL, respecting proxy and CA bundle. Retries with exponential backoff."""
    import ssl
    import time
    import urllib.request
    ctx = ssl.create_default_context()
    if CA_BUNDLE and os.path.exists(CA_BUNDLE):
        ctx.load_verify_locations(CA_BUNDLE)
    req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Workflow/1.0", "Accept": "application/json"})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            if attempt < retries:
                time.sleep(2 ** attempt)
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
    hibp_key = CONFIG.get("hibp_api_key", "")
    headers = {"User-Agent": "OSINT-Workflow-Audit"}
    if hibp_key:
        headers["hibp-api-key"] = hibp_key
    req = urllib.request.Request(url, headers=headers)

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

    # OpenCorporates search (international, free, no API key)
    oc_url = f"https://api.opencorporates.com/v0.4/companies/search?q={q}&per_page=5"
    oc_data = http_get_json(oc_url, timeout=15)
    if oc_data and isinstance(oc_data, dict):
        for item in (oc_data.get("results", {}).get("companies", []) or []):
            co = item.get("company", {})
            companies.append(CompanyInfo(
                name=co.get("name", ""),
                siren=co.get("company_number", ""),
                status=co.get("current_status", ""),
                address=co.get("registered_address_in_full", ""),
                creation_date=co.get("incorporation_date", ""),
                source=f"opencorporates.com ({co.get('jurisdiction_code', '')})",
            ))

    # Deduplicate by SIREN/company number
    seen = set()
    unique = []
    for c in companies:
        key = (c.siren or c.name).lower()
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


# --- NEW: Email reputation (emailrep.io free API) ---

def run_email_reputation(email, raw_dir):
    """Query emailrep.io for email reputation, breach exposure and profile presence."""
    work_dir = raw_dir / "reputation"
    work_dir.mkdir(parents=True, exist_ok=True)
    import ssl
    ctx = ssl.create_default_context()
    if CA_BUNDLE and os.path.exists(CA_BUNDLE):
        ctx.load_verify_locations(CA_BUNDLE)
    url = f"https://emailrep.io/{urllib.parse.quote(email)}"
    req = urllib.request.Request(url, headers={"User-Agent": "OSINT-Workflow", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        data = None

    if not data or "reputation" not in data:
        (work_dir / f"reputation_{safe_name(email)}.json").write_text(
            json.dumps({"email": email, "error": "unreachable"}, indent=2), encoding="utf-8"
        )
        return {"email": email, "error": "unreachable"}

    details = data.get("details", {})
    result = {
        "email": email,
        "reputation": data.get("reputation", ""),
        "suspicious": data.get("suspicious", False),
        "references": data.get("references", 0),
        "blacklisted": details.get("blacklisted", False),
        "malicious_activity": details.get("malicious_activity", False),
        "credentials_leaked": details.get("credentials_leaked", False),
        "data_breach": details.get("data_breach", False),
        "first_seen": details.get("first_seen", ""),
        "last_seen": details.get("last_seen", ""),
        "domain_reputation": details.get("domain_reputation", ""),
        "profiles": details.get("profiles", []),
        "spoofable": details.get("spoofable", False),
        "spam": details.get("spam", False),
    }
    (work_dir / f"reputation_{safe_name(email)}.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return result


# --- NEW: Paste / leak site search URLs ---

def build_paste_search_urls(emails=None, usernames=None, phones=None):
    """Build manual-check URLs for paste sites, GitHub gists, and leak databases."""
    urls = []
    for email in (emails or []):
        q = urllib.parse.quote(email)
        urls.append({"label": f"Pastebin ({email})", "url": f"https://www.google.com/search?q=site%3Apastebin.com+%22{q}%22"})
        urls.append({"label": f"GitHub Gists ({email})", "url": f"https://gist.github.com/search?q=%22{q}%22"})
        urls.append({"label": f"Dehashed ({email})", "url": f"https://www.dehashed.com/search?query=%22{q}%22"})
        urls.append({"label": f"IntelligenceX ({email})", "url": f"https://intelx.io/?s=%22{q}%22"})
    for u in (usernames or []):
        q = urllib.parse.quote(u)
        urls.append({"label": f"Pastebin ({u})", "url": f"https://www.google.com/search?q=site%3Apastebin.com+%22{q}%22"})
        urls.append({"label": f"GitHub Gists ({u})", "url": f"https://gist.github.com/search?q=%22{q}%22"})
        urls.append({"label": f"IntelligenceX ({u})", "url": f"https://intelx.io/?s=%22{q}%22"})
    for phone in (phones or []):
        clean = phone.replace(" ", "").replace("-", "").replace(".", "")
        q = urllib.parse.quote(clean)
        urls.append({"label": f"IntelligenceX ({phone})", "url": f"https://intelx.io/?s=%22{q}%22"})
    return urls


# --- NEW: Social media profile direct links ---

def build_social_profile_urls(usernames=None, emails=None, phones=None):
    """Generate direct profile URLs for major social networks and professional platforms."""
    urls = []
    for u in (usernames or []):
        q = urllib.parse.quote(u)
        urls.extend([
            {"platform": "LinkedIn", "url": f"https://www.linkedin.com/in/{q}", "type": "professionnel"},
            {"platform": "GitHub", "url": f"https://github.com/{q}", "type": "developpeur"},
            {"platform": "Twitter/X", "url": f"https://x.com/{q}", "type": "social"},
            {"platform": "Instagram", "url": f"https://www.instagram.com/{q}", "type": "social"},
            {"platform": "Facebook", "url": f"https://www.facebook.com/{q}", "type": "social"},
            {"platform": "TikTok", "url": f"https://www.tiktok.com/@{q}", "type": "social"},
            {"platform": "Reddit", "url": f"https://www.reddit.com/user/{q}", "type": "forum"},
            {"platform": "Pinterest", "url": f"https://www.pinterest.com/{q}", "type": "social"},
            {"platform": "YouTube", "url": f"https://www.youtube.com/@{q}", "type": "video"},
            {"platform": "Twitch", "url": f"https://www.twitch.tv/{q}", "type": "streaming"},
            {"platform": "Medium", "url": f"https://medium.com/@{q}", "type": "blog"},
            {"platform": "Viadeo", "url": f"https://www.viadeo.com/p/{q}", "type": "professionnel"},
            {"platform": "GitLab", "url": f"https://gitlab.com/{q}", "type": "developpeur"},
            {"platform": "Bitbucket", "url": f"https://bitbucket.org/{q}", "type": "developpeur"},
            {"platform": "Stack Overflow", "url": f"https://stackoverflow.com/users/?tab=accounts&SearchText={q}", "type": "developpeur"},
            {"platform": "Keybase", "url": f"https://keybase.io/{q}", "type": "securite"},
            {"platform": "Gravatar", "url": f"https://gravatar.com/{q}", "type": "avatar"},
            {"platform": "Flickr", "url": f"https://www.flickr.com/people/{q}", "type": "photo"},
            {"platform": "Snapchat", "url": f"https://www.snapchat.com/add/{q}", "type": "social"},
            {"platform": "Telegram", "url": f"https://t.me/{q}", "type": "messagerie"},
        ])
    for email in (emails or []):
        local = email.split("@")[0]
        q = urllib.parse.quote(local)
        urls.extend([
            {"platform": "Gravatar (email)", "url": f"https://gravatar.com/{q}", "type": "avatar"},
            {"platform": "About.me", "url": f"https://about.me/{q}", "type": "personnel"},
        ])
    return urls


def build_reverse_image_search_urls(usernames=None, emails=None):
    """Generate reverse image search URLs for Gravatar and known profile image patterns."""
    urls = []
    if not usernames and not emails:
        return urls
    import hashlib
    for email in (emails or []):
        md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{md5}?s=400&d=404"
        urls.append({"platform": "Gravatar", "image_url": gravatar_url,
                     "google_lens": f"https://lens.google.com/uploadbyurl?url={urllib.parse.quote(gravatar_url)}",
                     "tineye": f"https://tineye.com/search?url={urllib.parse.quote(gravatar_url)}",
                     "yandex": f"https://yandex.com/images/search?rpt=imageview&url={urllib.parse.quote(gravatar_url)}"})
    for username in (usernames or []):
        github_url = f"https://github.com/{username}.png"
        urls.append({"platform": "GitHub Avatar", "image_url": github_url,
                     "google_lens": f"https://lens.google.com/uploadbyurl?url={urllib.parse.quote(github_url)}",
                     "tineye": f"https://tineye.com/search?url={urllib.parse.quote(github_url)}",
                     "yandex": f"https://yandex.com/images/search?rpt=imageview&url={urllib.parse.quote(github_url)}"})
    return urls


def detect_address_leaks(breaches, whois_results, profile_details, companies):
    """Cross-reference all data sources to detect address/location exposure."""
    locations = []
    seen = set()
    for b in (breaches or []):
        if "Physical addresses" in b.data_types:
            key = f"breach:{b.breach_name}"
            if key not in seen:
                seen.add(key)
                locations.append({"source": f"Fuite: {b.breach_name}", "type": "adresse_physique",
                                  "detail": f"Adresse exposee dans la fuite {b.breach_name} ({b.breach_date})",
                                  "severity": "ELEVE"})
    for w in (whois_results or []):
        if w and w.get("registrant_name"):
            addr_parts = [w.get("registrant_address", ""), w.get("registrant_city", ""),
                          w.get("registrant_country", "")]
            addr = ", ".join(p for p in addr_parts if p)
            if addr:
                key = f"whois:{w['domain']}"
                if key not in seen:
                    seen.add(key)
                    locations.append({"source": f"WHOIS: {w['domain']}", "type": "adresse_whois",
                                      "detail": addr, "severity": "MOYEN"})
    for c in (companies or []):
        if c.address:
            key = f"company:{c.siren}"
            if key not in seen:
                seen.add(key)
                locations.append({"source": f"Entreprise: {c.name}", "type": "siege_social",
                                  "detail": c.address, "severity": "FAIBLE"})
    for key, vals in (profile_details or {}).items():
        if key in ("city", "location", "country"):
            for v in vals:
                nk = f"profile:{key}:{v}"
                if nk not in seen:
                    seen.add(nk)
                    locations.append({"source": "Profil en ligne", "type": "localisation_profil",
                                      "detail": v, "severity": "FAIBLE"})
    return locations


def build_exposure_timeline(breaches, wayback_results, findings, companies):
    """Build a chronological timeline of exposure events."""
    events = []
    for b in (breaches or []):
        if b.breach_date:
            events.append({"date": b.breach_date, "type": "fuite",
                           "detail": f"Fuite {b.breach_name} : {', '.join(b.data_types[:3])}",
                           "severity": "ELEVE" if any(t in b.data_types for t in ["Passwords", "Credit cards"]) else "MOYEN"})
    for w in (wayback_results or []):
        if w.oldest_snapshot:
            events.append({"date": w.oldest_snapshot[:10] if len(w.oldest_snapshot) >= 10 else w.oldest_snapshot,
                           "type": "archive", "detail": f"Premiere archive : {w.url[:60]}",
                           "severity": "FAIBLE"})
    for c in (companies or []):
        if c.creation_date:
            events.append({"date": c.creation_date, "type": "entreprise",
                           "detail": f"Creation {c.name} (SIREN {c.siren})",
                           "severity": "FAIBLE"})
    events.sort(key=lambda e: e["date"])
    return events


# --- NEW: Wayback Machine check (CDX API, free, no key) ---

@dataclass
class WaybackResult:
    url: str
    oldest_snapshot: str = ""
    newest_snapshot: str = ""
    total_snapshots: int = 0


def _parse_wayback_timestamp(ts):
    """Convert CDX timestamp '20060101120000' to 'YYYY-MM-DD'."""
    if len(ts) >= 8:
        return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
    return ts


def run_wayback_check(urls, raw_dir):
    work_dir = raw_dir / "wayback"
    work_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for url in urls:
        domain = re.sub(r"^https?://", "", url).split("/")[0]
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(domain)}"
            f"&output=json&fl=timestamp,original,statuscode&collapse=timestamp:6&limit=100"
        )
        data = http_get_json(cdx_url, timeout=20)
        if data and isinstance(data, list) and len(data) > 1:
            rows = data[1:]  # first row is header
            timestamps = [r[0] for r in rows if len(r) >= 1]
            results.append(WaybackResult(
                url=domain,
                oldest_snapshot=_parse_wayback_timestamp(timestamps[0]) if timestamps else "",
                newest_snapshot=_parse_wayback_timestamp(timestamps[-1]) if timestamps else "",
                total_snapshots=len(timestamps),
            ))
        else:
            results.append(WaybackResult(url=domain, total_snapshots=0))

    (work_dir / "wayback.json").write_text(
        json.dumps([asdict(r) for r in results], indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return results


# --- NEW: DNS enumeration for personal email domains ---

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "yahoo.fr", "hotmail.com", "hotmail.fr",
    "outlook.com", "outlook.fr", "live.com", "live.fr", "aol.com",
    "protonmail.com", "proton.me", "icloud.com", "me.com", "mac.com",
    "gmx.com", "gmx.fr", "mail.com", "laposte.net", "orange.fr",
    "free.fr", "sfr.fr", "wanadoo.fr", "bbox.fr",
}


@dataclass
class DnsResult:
    domain: str
    mx_records: list = field(default_factory=list)
    txt_records: list = field(default_factory=list)
    spf: str = ""
    dmarc: str = ""
    hosting_hints: list = field(default_factory=list)


def run_dns_lookup(domain, raw_dir):
    if domain in FREE_EMAIL_PROVIDERS:
        return None

    work_dir = raw_dir / "dns"
    work_dir.mkdir(parents=True, exist_ok=True)

    result = DnsResult(domain=domain)

    # MX records via dig
    try:
        proc = subprocess.run(
            ["dig", "+short", "MX", domain], capture_output=True, text=True, timeout=10
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().splitlines():
                parts = line.strip().rstrip(".").split()
                if len(parts) >= 2:
                    result.mx_records.append(parts[-1])
                    host = parts[-1].lower()
                    if "google" in host or "gmail" in host:
                        result.hosting_hints.append("Email heberge par Google Workspace")
                    elif "outlook" in host or "microsoft" in host:
                        result.hosting_hints.append("Email heberge par Microsoft 365")
                    elif "ovh" in host:
                        result.hosting_hints.append("Email heberge par OVH")
                    elif "gandi" in host:
                        result.hosting_hints.append("Email heberge par Gandi")
    except Exception:
        pass

    # TXT records (SPF)
    try:
        proc = subprocess.run(
            ["dig", "+short", "TXT", domain], capture_output=True, text=True, timeout=10
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().splitlines():
                txt = line.strip().strip('"')
                result.txt_records.append(txt)
                if txt.startswith("v=spf1"):
                    result.spf = txt
    except Exception:
        pass

    # DMARC
    try:
        proc = subprocess.run(
            ["dig", "+short", "TXT", f"_dmarc.{domain}"], capture_output=True, text=True, timeout=10
        )
        if proc.returncode == 0:
            for line in proc.stdout.strip().splitlines():
                txt = line.strip().strip('"')
                if txt.startswith("v=DMARC"):
                    result.dmarc = txt
    except Exception:
        pass

    # Deduplicate hosting hints
    result.hosting_hints = sorted(set(result.hosting_hints))

    (work_dir / f"dns_{safe_name(domain)}.json").write_text(
        json.dumps(asdict(result), indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return result


# --- Username permutation generator ---

def generate_username_permutations(nom=None, emails=None, usernames=None):
    """Generate likely username variations from a person's name and known identifiers."""
    perms = set()
    if nom:
        parts = nom.lower().split()
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            perms.update([
                first + last, last + first,
                first + "." + last, last + "." + first,
                first + "_" + last, last + "_" + first,
                first[0] + last, first[0] + "." + last, first[0] + "_" + last,
                last + first[0], last + "." + first[0], last + "_" + first[0],
                first + last[0], first + "." + last[0],
                first, last,
            ])
            for suffix in ["", "1", "123", "01", "75", "92", "33"]:
                if suffix:
                    perms.add(first + last + suffix)
                    perms.add(first + "." + last + suffix)
                    perms.add(last + first + suffix)

    for email in (emails or []):
        local = email.split("@")[0].lower()
        perms.add(local)
        perms.add(local.replace(".", "_"))
        perms.add(local.replace(".", ""))

    existing = {u.lower() for u in (usernames or [])}
    return sorted(perms - existing)


# --- Risk scoring (weighted) ---


def classify_exposed_data(breaches, whois_results, reputation_results, findings):
    """Classify all exposed data by sensitivity level for the report."""
    categories = {
        "CRITIQUE": [],
        "ELEVE": [],
        "MOYEN": [],
        "FAIBLE": [],
    }
    critical_types = {"Passwords", "Credit cards", "Bank account numbers",
                      "Social security numbers", "Passport numbers", "Government issued IDs",
                      "Security questions and answers", "Auth tokens"}
    high_types = {"Phone numbers", "Physical addresses", "IP addresses",
                  "Dates of birth", "Geographic locations", "Biometric data"}
    medium_types = {"Email addresses", "Names", "Employers", "Job titles",
                    "Genders", "Ages", "Education levels", "Income levels"}

    seen = set()
    for b in (breaches or []):
        for dt in b.data_types:
            if dt in seen:
                continue
            seen.add(dt)
            entry = {"type": dt, "source": f"Fuite: {b.breach_name}", "date": b.breach_date}
            if dt in critical_types:
                categories["CRITIQUE"].append(entry)
            elif dt in high_types:
                categories["ELEVE"].append(entry)
            elif dt in medium_types:
                categories["MOYEN"].append(entry)
            else:
                categories["FAIBLE"].append(entry)

    for w in (whois_results or []):
        if w and w.get("registrant_name"):
            if "whois_name" not in seen:
                seen.add("whois_name")
                categories["MOYEN"].append({"type": "Nom (WHOIS)", "source": f"WHOIS: {w['domain']}", "date": ""})
            if w.get("registrant_address") and "whois_address" not in seen:
                seen.add("whois_address")
                categories["ELEVE"].append({"type": "Adresse (WHOIS)", "source": f"WHOIS: {w['domain']}", "date": ""})

    for r in (reputation_results or []):
        if r.get("credentials_leaked") and "creds_leaked" not in seen:
            seen.add("creds_leaked")
            categories["CRITIQUE"].append({"type": "Credentials leaked (reputation)", "source": f"emailrep: {r.get('email', '')}", "date": ""})

    nb = len(findings or [])
    if nb > 0 and "public_accounts" not in seen:
        seen.add("public_accounts")
        categories["FAIBLE"].append({"type": f"{nb} comptes publics detectes", "source": "Scan de comptes", "date": ""})

    return categories

def compute_risk_score(findings, breaches, companies, phone_infos, whois_results,
                       reputation_results=None, dns_results=None):
    """Compute a weighted risk score (0-100) and level (FAIBLE/MOYEN/ELEVE/CRITIQUE)."""
    score = 0

    nb_accounts = len(findings)
    if nb_accounts > 20:
        score += 25
    elif nb_accounts > 10:
        score += 15
    elif nb_accounts > 5:
        score += 10
    elif nb_accounts > 0:
        score += 5

    nb_breaches = len(breaches)
    if nb_breaches > 5:
        score += 30
    elif nb_breaches > 2:
        score += 20
    elif nb_breaches > 0:
        score += 10

    sensitive_types = {"Passwords", "Credit cards", "Phone numbers", "Physical addresses",
                       "IP addresses", "Bank account numbers", "Social security numbers",
                       "Passport numbers", "Government issued IDs"}
    for b in breaches:
        if sensitive_types & set(b.data_types):
            score += 5

    if companies:
        for c in companies:
            if c.address and any(w in c.address.lower() for w in ["domicile", "personnel", "maison"]):
                score += 10
            else:
                score += 3

    whois_exposed = [w for w in (whois_results or []) if w and w.get("registrant_name")]
    score += len(whois_exposed) * 8

    rep_valid = [r for r in (reputation_results or []) if not r.get("error")]
    for r in rep_valid:
        if r.get("suspicious"):
            score += 10
        if r.get("credentials_leaked"):
            score += 8
        if r.get("blacklisted"):
            score += 5

    dns_list = dns_results or []
    for d in dns_list:
        if hasattr(d, "spf") and not d.spf:
            score += 3
        if hasattr(d, "dmarc") and not d.dmarc:
            score += 3

    score = min(score, 100)

    if score >= 70:
        level = "CRITIQUE"
    elif score >= 40:
        level = "ELEVE"
    elif score >= 15:
        level = "MOYEN"
    else:
        level = "FAIBLE"

    return score, level


# --- NEW: Google dorking (extract dork URLs for the report) ---

def _dork(label, query):
    return {"label": label, "query": query, "url": f"https://www.google.com/search?q={urllib.parse.quote(query)}"}


def build_google_dorks(nom=None, emails=None, phones=None, usernames=None):
    dorks = []
    if nom:
        q = nom
        dorks.append(_dork("Nom complet", f'"{q}"'))
        dorks.append(_dork("Nom + adresse", f'"{q}" adresse OR rue OR avenue OR boulevard'))
        dorks.append(_dork("Nom + telephone", f'"{q}" telephone OR tel OR phone'))
        dorks.append(_dork("Nom + LinkedIn", f'site:linkedin.com "{q}"'))
        dorks.append(_dork("Nom + Facebook", f'site:facebook.com "{q}"'))
        dorks.append(_dork("Nom + Instagram", f'site:instagram.com "{q}"'))
        dorks.append(_dork("Nom + Twitter/X", f'site:x.com OR site:twitter.com "{q}"'))
        dorks.append(_dork("Nom + societe.com", f'site:societe.com "{q}"'))
        dorks.append(_dork("Nom + Infogreffe", f'site:infogreffe.fr "{q}"'))
        dorks.append(_dork("Nom + Pages Blanches", f'site:pagesjaunes.fr "{q}"'))
        dorks.append(_dork("Nom + Copains d'Avant", f'site:copainsdavant.linternaute.com "{q}"'))
        dorks.append(_dork("Nom + 118712 (annuaire)", f'site:118712.fr "{q}"'))
        dorks.append(_dork("Nom + fichiers (PDF, XLS)", f'"{q}" filetype:pdf OR filetype:xls OR filetype:doc'))
        dorks.append(_dork("Nom + justice / tribunal", f'"{q}" tribunal OR jugement OR condamnation OR justice'))
        dorks.append(_dork("Nom + BODACCs (publications legales)", f'site:bodacc.fr "{q}"'))
        dorks.append(_dork("Nom + OpenCorporates (international)", f'site:opencorporates.com "{q}"'))
        dorks.append(_dork("Nom + Companies House (UK)", f'site:find-and-update.company-information.service.gov.uk "{q}"'))
        dorks.append(_dork("Nom + KBO (Belgique)", f'site:kbopub.economie.fgov.be "{q}"'))
        dorks.append(_dork("Nom + RCS Luxembourg", f'site:lbr.lu "{q}"'))
        dorks.append(_dork("Nom + Handelsregister (Suisse)", f'site:zefix.ch "{q}"'))
        dorks.append(_dork("Nom + Viadeo / Indeed / emploi", f'"{q}" site:viadeo.com OR site:indeed.fr OR site:pole-emploi.fr'))
        dorks.append(_dork("Nom + forum / avis", f'"{q}" forum OR avis OR commentaire OR review'))
    for email in (emails or []):
        dorks.append(_dork(f"Email {email}", f'"{email}"'))
        dorks.append(_dork(f"Email + paste", f'"{email}" site:pastebin.com OR site:ghostbin.com'))
        dorks.append(_dork(f"Email + forum", f'"{email}" forum OR inscription OR registered'))
    for phone in (phones or []):
        clean = phone.replace(" ", "").replace("-", "").replace(".", "")
        dorks.append(_dork(f"Telephone {phone}", f'"{clean}" OR "{phone}"'))
        dorks.append(_dork(f"Telephone + annuaire", f'"{clean}" site:118712.fr OR site:pagesjaunes.fr'))
    for u in (usernames or []):
        dorks.append(_dork(f"Pseudo {u} (web)", f'"{u}" -site:github.com'))
        dorks.append(_dork(f"Pseudo {u} (forum)", f'"{u}" forum OR profil OR profile OR membre'))
    return dorks


# --- Family / relatives search dorks ---

def build_family_search_dorks(nom=None, prenom=None, dob=None, phones=None):
    dorks = []
    if not nom:
        return dorks
    q = nom
    full = f"{prenom} {nom}" if prenom else nom

    dorks.append(_dork("Geneanet (genealogie)", f'site:geneanet.org "{q}"'))
    dorks.append(_dork("Filae (genealogie)", f'site:filae.com "{q}"'))
    dorks.append(_dork("118712 (annuaire inverse)", f'site:118712.fr "{q}"'))
    dorks.append(_dork("Copains d'Avant (camarades)", f'site:copainsdavant.linternaute.com "{q}"'))
    dorks.append(_dork("Famille / proches", f'"{full}" famille OR parent OR frere OR soeur OR conjoint OR epoux OR epouse'))
    dorks.append(_dork("Etat civil / actes", f'"{full}" acte OR naissance OR mariage OR deces OR etat-civil'))
    dorks.append(_dork("Avis de deces / necrologie", f'"{full}" "avis de deces" OR necrologie OR obseques'))
    dorks.append(_dork("Societe.com (dirigeant/associe)", f'site:societe.com "{q}" dirigeant OR associe'))
    dorks.append(_dork("Pages Blanches (foyer)", f'site:pagesjaunes.fr "{full}" OR site:pagesblanches.fr "{full}"'))
    dorks.append(_dork("Registre commerce (famille)", f'"{q}" SIREN OR SIRET OR "registre du commerce"'))

    if prenom:
        dorks.append(_dork(f"Prenom + nom complet", f'"{prenom} {nom}"'))
        dorks.append(_dork(f"Prenom + nom + adresse", f'"{prenom} {nom}" adresse OR domicile OR habite'))

    if dob:
        try:
            parts = dob.split("/")
            if len(parts) == 3:
                day, month, year = int(parts[0]), int(parts[1]), int(parts[2])
                birth_year = year
                age = 2026 - birth_year
                dorks.append(_dork(f"Annee de naissance ({birth_year})",
                                   f'"{full}" {birth_year} OR "ne en {birth_year}" OR "nee en {birth_year}"'))
                dorks.append(_dork(f"Age ({age} ans)", f'"{full}" "{age} ans"'))
                dorks.append(_dork(f"Date de naissance", f'"{full}" "{day:02d}/{month:02d}/{birth_year}"'))
        except (ValueError, IndexError):
            pass

    for phone in (phones or []):
        clean = phone.replace(" ", "").replace("-", "").replace(".", "")
        dorks.append(_dork(f"Telephone + annuaire ({phone})", f'"{clean}" annuaire OR "pages blanches" OR 118712'))

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


# --- Identity card (cross-reference consolidation) ---

def build_identity_card(opts, profile_details, phone_infos, companies, whois_results,
                        reputation_results=None, breaches=None, findings=None):
    """Consolidate all discovered data points into a single identity summary."""
    card = {}
    if opts.nom:
        card["nom"] = opts.nom
    if profile_details.get("fullname"):
        card["noms_detectes"] = profile_details["fullname"]
    card["emails"] = list(opts.email)
    card["pseudos"] = list(opts.username)
    card["telephones"] = list(opts.phone)

    if profile_details.get("location"):
        card["localisations"] = profile_details["location"]
    if profile_details.get("city"):
        card["villes"] = profile_details["city"]
    if profile_details.get("country"):
        card["pays"] = profile_details["country"]
    if profile_details.get("occupation"):
        card["professions"] = profile_details["occupation"]
    if profile_details.get("company"):
        card["entreprises_profil"] = profile_details["company"]
    if profile_details.get("education"):
        card["formation"] = profile_details["education"]
    if profile_details.get("bio"):
        card["bio"] = profile_details["bio"]
    if profile_details.get("website"):
        card["sites_web"] = profile_details["website"]

    if phone_infos:
        card["operateurs"] = list({p.carrier for p in phone_infos if p.carrier})
        card["pays_telephone"] = list({p.country for p in phone_infos if p.country})

    if companies:
        card["entreprises_registre"] = [
            {"nom": c.name, "siren": c.siren, "role": c.role, "adresse": c.address}
            for c in companies
        ]

    whois_found = [w for w in (whois_results or []) if w is not None]
    if whois_found:
        card["domaines_personnels"] = [w["domain"] for w in whois_found]
        for w in whois_found:
            if w.get("registrant_name"):
                card.setdefault("noms_whois", []).append(w["registrant_name"])
            if w.get("registrant_address") or w.get("registrant_city"):
                addr = " ".join(filter(None, [w.get("registrant_address"), w.get("registrant_city"), w.get("registrant_country")]))
                card.setdefault("adresses_whois", []).append(addr)

    rep_valid = [r for r in (reputation_results or []) if not r.get("error")]
    if rep_valid:
        all_profiles = set()
        for r in rep_valid:
            all_profiles.update(r.get("profiles", []))
        if all_profiles:
            card["profils_reputation"] = sorted(all_profiles)

    if breaches:
        card["nb_fuites"] = len(breaches)
        all_types = set()
        for b in breaches:
            all_types.update(b.data_types)
        if all_types:
            card["types_donnees_exposees"] = sorted(all_types)

    if findings:
        card["nb_comptes"] = len(findings)
        card["sites_principaux"] = [f.site for f in findings[:10]]

    return card


# --- Cross-reference correlation ---

def build_correlations(findings, profile_details, breaches, whois_results, reputation_results=None):
    """Detect links and patterns across all data sources."""
    correlations = []

    sites_by_identifier = {}
    for f in (findings or []):
        sites_by_identifier.setdefault(f.identifier, []).append(f.site)
    for ident, sites in sites_by_identifier.items():
        if len(sites) >= 3:
            correlations.append({
                "type": "pseudo_reutilise",
                "detail": f"Le pseudo '{ident}' est utilise sur {len(sites)} plateformes : {', '.join(sites[:8])}",
                "risk": "Le meme pseudo facilite le regroupement de comptes par un tiers.",
            })

    email_breach_map = {}
    for b in (breaches or []):
        email_breach_map.setdefault(b.email, []).append(b.breach_name)
    for email, bnames in email_breach_map.items():
        if len(bnames) >= 2:
            correlations.append({
                "type": "email_multi_fuites",
                "detail": f"L'email '{email}' apparait dans {len(bnames)} fuites : {', '.join(bnames[:5])}",
                "risk": "Un attaquant peut recouper les donnees de plusieurs fuites pour construire un profil complet.",
            })

    if profile_details:
        bio_values = profile_details.get("bio", [])
        if len(bio_values) >= 2:
            unique_bios = set(b.lower().strip() for b in bio_values if len(b) > 10)
            if len(unique_bios) == 1:
                correlations.append({
                    "type": "bio_identique",
                    "detail": "La meme bio est utilisee sur plusieurs plateformes.",
                    "risk": "Facilite la correlation automatique des comptes.",
                })

        names = profile_details.get("fullname", [])
        if names:
            correlations.append({
                "type": "nom_reel_expose",
                "detail": f"Le nom reel apparait sur des profils publics : {', '.join(names[:5])}",
                "risk": "Le nom reel est directement lie aux pseudos en ligne.",
            })

    whois_names = [w.get("registrant_name") for w in (whois_results or []) if w and w.get("registrant_name")]
    if whois_names:
        correlations.append({
            "type": "whois_identite",
            "detail": f"L'identite est exposee dans les WHOIS : {', '.join(whois_names)}",
            "risk": "Le WHOIS lie le nom reel a des domaines, donc potentiellement a des sites web personnels.",
        })

    rep_valid = [r for r in (reputation_results or []) if not r.get("error")]
    for r in rep_valid:
        if r.get("credentials_leaked") and r.get("data_breach"):
            correlations.append({
                "type": "reputation_credentials_et_breach",
                "detail": f"L'email '{r['email']}' : identifiants fuites ET fuite de donnees confirmee.",
                "risk": "Risque eleve de prise de controle de compte (credential stuffing).",
            })

    return correlations


def build_dark_web_check_urls(emails=None, usernames=None, phones=None):
    """Generate URLs for checking dark web / leak database exposure (manual verification links)."""
    urls = []
    for email in (emails or []):
        encoded = urllib.parse.quote(email)
        urls.append({"service": "Have I Been Pwned", "url": f"https://haveibeenpwned.com/account/{encoded}",
                     "type": "email", "identifier": email})
        urls.append({"service": "Firefox Monitor", "url": "https://monitor.firefox.com/breaches",
                     "type": "email", "identifier": email})
        urls.append({"service": "DeHashed", "url": f"https://dehashed.com/search?query={encoded}",
                     "type": "email", "identifier": email})
        urls.append({"service": "LeakCheck", "url": f"https://leakcheck.io/check/{encoded}",
                     "type": "email", "identifier": email})
        urls.append({"service": "IntelligenceX", "url": f"https://intelx.io/?s={encoded}",
                     "type": "email", "identifier": email})
        urls.append({"service": "Snusbase", "url": f"https://snusbase.com/search?q={encoded}",
                     "type": "email", "identifier": email})
    for phone in (phones or []):
        encoded = urllib.parse.quote(phone)
        urls.append({"service": "Phoneinfoga", "url": f"https://demo.phoneinfoga.crvx.fr/scan?number={encoded}",
                     "type": "phone", "identifier": phone})
        urls.append({"service": "Sync.me", "url": f"https://sync.me/search/?q={encoded}",
                     "type": "phone", "identifier": phone})
        urls.append({"service": "Truecaller", "url": f"https://www.truecaller.com/search/fr/{encoded.replace('+', '')}",
                     "type": "phone", "identifier": phone})
    for username in (usernames or []):
        encoded = urllib.parse.quote(username)
        urls.append({"service": "NameCheckr", "url": f"https://www.namecheckr.com/?q={encoded}",
                     "type": "username", "identifier": username})
        urls.append({"service": "KnowEm", "url": f"https://knowem.com/checkusernames.php?u={encoded}",
                     "type": "username", "identifier": username})
    return urls



# --- Report ---

def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_report(opts, runs, findings, started, breaches, companies, phone_infos, whois_results, dorks, profile_details,
                   reputation_results=None, wayback_results=None, dns_results=None, paste_urls=None, identity_card=None,
                   username_permutations=None, risk_score=None, correlations=None, family_dorks=None,
                   data_classification=None, dark_web_urls=None,
                   reverse_images=None, address_leaks=None, timeline=None):
    by_kind = {"username": [], "email": []}
    for finding in findings:
        by_kind[finding.kind].append(finding)
    leads = sorted({lead for run in runs for lead in run.leads})
    failed = [run for run in runs if not run.ok]

    _sec = [0]
    def S(title):
        _sec[0] += 1
        return f"## {_sec[0]}. {title}"

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
    risk_score, risk_level = compute_risk_score(findings, breaches, companies, phone_infos, whois_results,
                                                reputation_results=reputation_results, dns_results=dns_results)
    filled = risk_score // 5
    gauge = "[" + "#" * filled + "." * (20 - filled) + f"] {risk_score}/100"
    out.append(f"**Niveau d'exposition global : {risk_level}**")
    out.append("")
    out.append(f"```")
    out.append(f"Score de risque : {gauge}")
    out.append(f"```")
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

    # --- Identity card (consolidated) ---
    _card = identity_card or {}
    if _card:
        out += ["", "### Fiche d'identite numerique consolidee", ""]
        card_labels = {
            "nom": "Nom fourni", "noms_detectes": "Noms detectes sur les profils",
            "localisations": "Localisations", "villes": "Villes", "pays": "Pays",
            "professions": "Professions", "entreprises_profil": "Entreprises (profils)",
            "formation": "Formation", "bio": "Bio",
            "sites_web": "Sites web personnels", "operateurs": "Operateurs telephone",
            "pays_telephone": "Pays telephone", "domaines_personnels": "Domaines email personnels",
            "noms_whois": "Noms (WHOIS)", "adresses_whois": "Adresses (WHOIS)",
            "profils_reputation": "Profils detectes (reputation email)",
            "types_donnees_exposees": "Types de donnees exposees dans les fuites",
        }
        out.append("| Information | Valeur(s) |")
        out.append("|---|---|")
        for key, label in card_labels.items():
            val = _card.get(key)
            if val:
                if isinstance(val, list):
                    out.append(f"| {label} | {cell(', '.join(str(v) for v in val))} |")
                else:
                    out.append(f"| {label} | {cell(str(val))} |")
        if _card.get("entreprises_registre"):
            for ent in _card["entreprises_registre"]:
                out.append(f"| Entreprise (registre) | {cell(ent['nom'])} - SIREN {cell(ent['siren'])} - {cell(ent['role'])} |")
        counts = []
        if _card.get("nb_comptes"):
            counts.append(f"{_card['nb_comptes']} comptes en ligne")
        if _card.get("nb_fuites"):
            counts.append(f"{_card['nb_fuites']} fuites")
        if counts:
            out.append(f"| **Exposition** | **{', '.join(counts)}** |")
        out.append("")
        out.append("*Ce tableau consolide les informations trouvees par tous les modules. Verifier chaque element avec le client.*")

    # --- Correlations ---
    _corr = correlations or []
    if _corr:
        out += ["", "### Correlations detectees", ""]
        out.append("Points de recoupement entre les differentes sources :")
        out.append("")
        for c in _corr:
            out.append(f"- **{c['type'].replace('_', ' ').capitalize()}** : {c['detail']}")
            out.append(f"  - *Risque :* {c['risk']}")
        out.append("")

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

    # --- Email reputation ---
    rep_valid = [r for r in (reputation_results or []) if not r.get("error")]
    if rep_valid:
        out += ["", "## 7. Reputation des emails", ""]
        out.append("| Email | Reputation | Suspect | Credentials leaked | Data breach | Blacklisted | Profils detectes | Premiere apparition |")
        out.append("|---|---|---|---|---|---|---|---|")
        for r in rep_valid:
            profiles = ", ".join(r.get("profiles", [])) or "-"
            out.append(
                f"| {cell(r['email'])} | {cell(r.get('reputation', ''))} | {'oui' if r.get('suspicious') else 'non'}"
                f" | {'oui' if r.get('credentials_leaked') else 'non'} | {'oui' if r.get('data_breach') else 'non'}"
                f" | {'oui' if r.get('blacklisted') else 'non'} | {cell(profiles)} | {cell(r.get('first_seen', ''))} |"
            )
        out.append("")
        out.append("**Risque :** un email avec une mauvaise reputation ou marque comme suspect peut etre cible par des campagnes de phishing.")
    else:
        out += ["", "## 7. Reputation des emails", "", "Reputation non disponible (API emailrep.io non joignable ou module desactive)."]

    # --- Tool scan details ---
    out += ["", "## 8. Detail des scans", ""]
    out.append("| Outil | Identifiant | Etat | Comptes | Couverture |")
    out.append("|---|---|---|---|---|")
    for run in runs:
        etat = "OK" if run.ok else "ECHEC"
        out.append(f"| {run.tool} | {cell(run.identifier)} | {etat} | {len(run.findings)} | {cell(run.note)} |")

    # --- Accounts found ---
    if by_kind["username"]:
        out += ["", "## 9. Comptes trouves a partir des pseudos", "",
                "| Pseudo | Site | Lien | Vu par | Informations visibles |", "|---|---|---|---|---|"]
        for f in by_kind["username"]:
            infos = ", ".join(f"{k}: {v}" for k, v in f.details.items()) or "-"
            out.append(f"| {cell(f.identifier)} | {cell(f.site)} | {f.url} | {', '.join(f.sources)} | {cell(infos)} |")

    if by_kind["email"]:
        out += ["", "## 10. Services ou l'email est inscrit", "",
                "| Email | Service | Indices divulgues par le service |", "|---|---|---|"]
        for f in by_kind["email"]:
            infos = ", ".join(f"{k}: {v}" for k, v in f.details.items()) or "-"
            out.append(f"| {cell(f.identifier)} | {cell(f.site)} ({f.url}) | {cell(infos)} |")

    # --- Leads ---
    if leads:
        out += ["", "## 11. Autres identifiants / proches reperes", "",
                "Identifiants supplementaires trouves sur les profils. A confirmer avec le client :", ""]
        out += [f"- {lead}" for lead in leads]

    # --- Google dorks ---
    if dorks:
        out += ["", "## 12. Pistes de recherche manuelle (Google dorks)", "",
                "Liens a ouvrir manuellement pour approfondir l'investigation :", ""]
        out.append("| Recherche | Lien |")
        out.append("|---|---|")
        for d in dorks:
            out.append(f"| {cell(d['label'])} | [Ouvrir]({d['url']}) |")

    # --- Username permutations ---
    _perms = username_permutations or []
    if _perms:
        out += ["", "## 13. Pistes de pseudos supplementaires (permutations)", "",
                "Pseudos generes automatiquement a partir du nom et des identifiants connus. "
                "A verifier manuellement ou lors d'un approfondissement :", ""]
        for i in range(0, len(_perms), 5):
            chunk = _perms[i:i+5]
            out.append(f"  `{'`  `'.join(chunk)}`")
        out.append("")
        out.append(f"*{len(_perms)} permutations generees. Lancer Sherlock/Maigret sur les plus probables pour elargir la recherche.*")

    # --- Paste / leak search URLs ---
    _paste_urls = paste_urls or []
    if _paste_urls:
        out += ["", "## 14. Recherche dans les pastes et bases de fuites", "",
                "Liens a ouvrir manuellement pour chercher des traces dans les pastes et bases de fuites :", ""]
        out.append("| Recherche | Lien |")
        out.append("|---|---|")
        for p in _paste_urls:
            out.append(f"| {cell(p['label'])} | [Ouvrir]({p['url']}) |")

    # --- DNS enumeration ---
    _dns = dns_results or []
    if _dns:
        out += ["", "## 15. Analyse DNS des domaines email personnels", ""]
        for dr in _dns:
            out.append(f"### {dr.domain}")
            out.append("")
            if dr.mx_records:
                out.append(f"- **Serveurs MX :** {', '.join(dr.mx_records)}")
            if dr.hosting_hints:
                for hint in dr.hosting_hints:
                    out.append(f"- **Hebergement :** {hint}")
            if dr.spf:
                out.append(f"- **SPF :** `{cell(dr.spf)}`")
            if dr.dmarc:
                out.append(f"- **DMARC :** `{cell(dr.dmarc)}`")
            if not dr.spf:
                out.append("- **SPF :** non configure (risque d'usurpation d'email)")
            if not dr.dmarc:
                out.append("- **DMARC :** non configure (risque d'usurpation d'email)")
            out.append("")
        out.append("**Risque :** l'absence de SPF/DMARC facilite l'usurpation de l'adresse email du domaine. "
                    "Les enregistrements MX revelent l'hebergeur email.")

    # --- Wayback Machine ---
    _wb = wayback_results or []
    archived = [r for r in _wb if r.total_snapshots > 0]
    if archived:
        out += ["", "## 16. Historique web (Wayback Machine)", ""]
        out.append("Profils ayant des archives dans la Wayback Machine (web.archive.org) :")
        out.append("")
        out.append("| URL | Plus ancien | Plus recent | Nb snapshots |")
        out.append("|---|---|---|---|")
        for r in archived:
            out.append(f"| {cell(r.url)} | {cell(r.oldest_snapshot)} | {cell(r.newest_snapshot)} | {r.total_snapshots} |")
        out.append("")
        out.append("**Risque :** meme un profil supprime peut avoir ete archive. "
                    "Consulter https://web.archive.org pour voir les versions passees.")

    # --- Social profile direct links ---
    if "social" not in opts.skip:
        social_urls = build_social_profile_urls(opts.username, opts.email)
        if social_urls:
            out += ["", "## 17. Liens directs vers les profils (verification manuelle)", ""]
            out.append("Liens a ouvrir manuellement pour verifier l'existence de profils sur les plateformes majeures :")
            out.append("")
            types_order = ["professionnel", "social", "developpeur", "forum", "video", "streaming",
                           "blog", "photo", "messagerie", "securite", "avatar", "personnel"]
            for ptype in types_order:
                group = [u for u in social_urls if u["type"] == ptype]
                if group:
                    out.append(f"### {ptype.capitalize()}")
                    out.append("")
                    out.append("| Plateforme | Lien |")
                    out.append("|---|---|")
                    for u in group:
                        out.append(f"| {cell(u['platform'])} | [Verifier]({u['url']}) |")
                    out.append("")

    # --- Exposure matrix ---
    if findings or breaches:
        out += ["", "---", "", "## Matrice d'exposition", ""]
        out.append("| Source | Identifiant | Donnees exposees | Risque |")
        out.append("|---|---|---|---|")
        for b in breaches:
            types = ", ".join(b.data_types[:5]) if b.data_types else "inconnu"
            sensitive = {"Passwords", "Credit cards", "Phone numbers", "Physical addresses",
                         "Social security numbers", "Bank account numbers"}
            level = "CRITIQUE" if sensitive & set(b.data_types) else "ELEVE"
            out.append(f"| Fuite: {cell(b.breach_name)} | {cell(b.email)} | {cell(types)} | {level} |")
        whois_exposed = [w for w in (whois_results or []) if w and w.get("registrant_name")]
        for w in whois_exposed:
            out.append(f"| WHOIS | {cell(w['domain'])} | Nom, adresse du proprietaire | ELEVE |")
        rep_leaked = [r for r in (reputation_results or []) if not r.get("error") and r.get("credentials_leaked")]
        for r in rep_leaked:
            out.append(f"| Reputation | {cell(r['email'])} | Credentials leaked | ELEVE |")

    # --- Family search dorks ---
    _fam = family_dorks or []
    if _fam:
        out += ["", "## 18. Recherche famille et proches (Google dorks)", "",
                "Liens a ouvrir manuellement pour rechercher des proches, liens familiaux et registres civils :", ""]
        out.append("| Recherche | Lien |")
        out.append("|---|---|")
        for d in _fam:
            out.append(f"| {cell(d['label'])} | [Ouvrir]({d['url']}) |")

    # --- Data Classification ---
    _dc = data_classification or {}
    has_classified = any(_dc.get(k) for k in ("CRITIQUE", "ELEVE", "MOYEN", "FAIBLE"))
    if has_classified:
        out += ["", "## 19. Classification des donnees exposees", "",
                "Inventaire des types de donnees exposees, classes par niveau de sensibilite :", ""]
        out.append("| Niveau | Type de donnee | Source | Date |")
        out.append("|---|---|---|---|")
        for level in ("CRITIQUE", "ELEVE", "MOYEN", "FAIBLE"):
            for entry in _dc.get(level, []):
                out.append(f"| **{level}** | {cell(entry.get('type', ''))} | {cell(entry.get('source', ''))} | {cell(entry.get('date', ''))} |")

    # --- Dark web / leak database links ---
    _dw = dark_web_urls or []
    if _dw:
        out += ["", "## 20. Verification dark web / bases de fuites", "",
                "Liens a ouvrir manuellement pour verifier l'exposition dans les bases de donnees de fuites et le dark web :", ""]
        out.append("| Service | Identifiant | Type | Lien |")
        out.append("|---|---|---|---|")
        for entry in _dw:
            out.append(f"| {cell(entry['service'])} | {cell(entry['identifier'])} | {cell(entry['type'])} | [Verifier]({entry['url']}) |")

    # --- Address / location leak detection ---
    _addr = address_leaks or []
    if _addr:
        out += ["", "## 21. Detection d'exposition d'adresse / localisation", "",
                "Croisement de toutes les sources pour detecter les fuites d'adresse et de localisation :", ""]
        out.append("| Source | Type | Detail | Severite |")
        out.append("|---|---|---|---|")
        for loc in _addr:
            out.append(f"| {cell(loc['source'])} | {cell(loc['type'])} | {cell(loc['detail'])} | **{loc['severity']}** |")

    # --- Exposure timeline ---
    _tl = timeline or []
    if _tl:
        out += ["", "## 22. Chronologie d'exposition", "",
                "Evenements d'exposition classes par date :", ""]
        out.append("| Date | Type | Detail | Severite |")
        out.append("|---|---|---|---|")
        for ev in _tl:
            out.append(f"| {cell(ev['date'])} | {cell(ev['type'])} | {cell(ev['detail'])} | **{ev['severity']}** |")

    # --- Reverse image search ---
    _ri = reverse_images or []
    if _ri:
        out += ["", "## 23. Recherche d'image inversee", "",
                "Liens pour effectuer une recherche d'image inversee sur les avatars connus :", ""]
        out.append("| Plateforme | Image | Google Lens | TinEye | Yandex |")
        out.append("|---|---|---|---|---|")
        for img in _ri:
            out.append(f"| {cell(img['platform'])} | [Voir]({img['image_url']}) | [Rechercher]({img['google_lens']}) | [Rechercher]({img['tineye']}) | [Rechercher]({img['yandex']}) |")

    # --- Action plan ---
    _rs = risk_score if risk_score is not None else 0
    out += ["", "---", "", "## Plan d'action", ""]

    if _rs >= 70:
        out += ["**URGENCE : score de risque CRITIQUE ({}/100). Actions immediates requises.**".format(_rs), ""]
    elif _rs >= 40:
        out += ["**ATTENTION : score de risque ELEVE ({}/100). Actions correctives recommandees sous 7 jours.**".format(_rs), ""]

    if breaches:
        out += [
            "### Priorite 1 : Fuites de donnees",
            "",
            "- [ ] **IMMEDIAT** : Changer les mots de passe des services concernes par les fuites.",
            "- [ ] Verifier sur https://haveibeenpwned.com si d'autres emails ont fuite.",
            "- [ ] Activer la double authentification (2FA) sur tous les comptes sensibles.",
            "- [ ] Surveiller les releves bancaires (risque d'usurpation d'identite).",
        ]
        pwd_breaches = [b for b in breaches if "Passwords" in b.data_types]
        if pwd_breaches:
            out.append(f"- [ ] **CRITIQUE** : {len(pwd_breaches)} fuite(s) contiennent des mots de passe. "
                        "Changer TOUS les mots de passe identiques sur d'autres services.")
        out.append("")

    if companies:
        out += [
            "### Priorite 2 : Exposition via les registres d'entreprise",
            "",
            "- [ ] Verifier si l'adresse du siege est l'adresse personnelle.",
            "- [ ] Si oui, envisager une domiciliation commerciale pour masquer l'adresse.",
            "- [ ] Contacter Pappers.fr et societe.com pour demander le masquage de certaines donnees.",
            "",
        ]

    _dns_no_spf = [d for d in (dns_results or []) if hasattr(d, "spf") and not d.spf]
    _dns_no_dmarc = [d for d in (dns_results or []) if hasattr(d, "dmarc") and not d.dmarc]
    if _dns_no_spf or _dns_no_dmarc:
        out += ["### Priorite 2b : Securite email (DNS)", ""]
        for d in _dns_no_spf:
            out.append(f"- [ ] Configurer un enregistrement SPF sur **{d.domain}** pour empecher l'usurpation.")
        for d in _dns_no_dmarc:
            out.append(f"- [ ] Configurer un enregistrement DMARC sur **{d.domain}** pour proteger la reputation email.")
        out.append("")

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
        "- [ ] Ouvrir les liens Google dorks de la section 12 pour trouver d'autres traces.",
        "",
        "### Suivi",
        "",
        "- [ ] Planifier un audit de suivi dans 3 mois.",
        "- [ ] Mettre en place des alertes Google sur le nom et les pseudos du client.",
        "- [ ] S'inscrire aux notifications HIBP pour les emails surveilles.",
        "",
        "## Limites",
        "",
        "- Un pseudo identique ne prouve pas qu'il s'agit de la meme personne.",
        "- L'absence de resultat ne prouve pas l'absence d'exposition.",
        "- Seules des sources publiques et gratuites ont ete interrogees.",
        "- La recherche d'entreprise couvre les registres francais (Pappers.fr) et internationaux (OpenCorporates), mais de facon non exhaustive.",
        "- Les fuites de donnees ne sont verifiees que via les bases gratuites (HIBP sans cle API, h8mail).",
        "- L'API HIBP v3 necessite une cle payante pour des resultats complets ; sans cle, les resultats peuvent etre partiels.",
        "",
        "---",
        "",
        "## Confidentialite",
        "",
        "Ce rapport contient des donnees personnelles au sens du RGPD (Reglement General sur la Protection des Donnees).",
        "Il est destine exclusivement a la personne concernee et au mandataire identifie dans l'en-tete.",
        "",
        "- **Conservation** : ce rapport doit etre supprime a la fin de la mission.",
        "- **Diffusion** : toute diffusion a des tiers non autorises est interdite.",
        "- **Droit d'acces** : la personne concernee peut demander une copie ou la suppression de ce rapport (RGPD art. 15 et 17).",
        "",
        f"*Rapport genere automatiquement le {started.strftime('%d/%m/%Y a %H:%M')} — Mandat {opts.mandat}*",
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
    parser.add_argument("--prenom", help="Prenom de la personne (ameliore la recherche famille/proches)")
    parser.add_argument("--dob", help="Date de naissance (JJ/MM/AAAA, active les dorks par age)")
    parser.add_argument("--all-sites", action="store_true", help="Maigret : tous les sites (long)")
    parser.add_argument("--top-sites", type=int, default=500, help="Maigret : nombre de sites (defaut 500)")
    parser.add_argument("--skip", action="append", default=[],
                        choices=["holehe", "sherlock", "maigret", "breach", "company", "whois", "phone",
                                 "reputation", "wayback", "dns", "paste", "social", "family"],
                        help="Module a ne pas lancer (repetable)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout par requete (defaut 10)")
    parser.add_argument("--tool-timeout", type=int, default=1800, help="Duree max par outil (defaut 1800)")
    parser.add_argument("--pdf", action="store_true", default=None,
                        help="Generer un PDF en plus du Markdown (necessite weasyprint)")
    parser.add_argument("--config", help="Chemin vers un fichier config.json alternatif")
    parser.add_argument("--json-only", action="store_true",
                        help="Generer uniquement resultats.json (pas de Markdown/PDF/CSV)")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Mode silencieux : supprime les messages de progression")
    parser.add_argument("--output-dir", "-o",
                        help="Repertoire de sortie personnalise (defaut : reports/<timestamp>_<mandat>)")
    opts = parser.parse_args(argv)

    if opts.config:
        global CONFIG
        CONFIG = load_config(opts.config)
    if opts.pdf is None:
        opts.pdf = CONFIG.get("export_pdf", False)

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
    quiet = opts.quiet
    def log(msg):
        if not quiet:
            print(msg)

    if opts.output_dir:
        report_dir = Path(opts.output_dir)
    else:
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
        log(f"[*] Phase 1 : {len(jobs)} scan(s) de comptes en parallele...")
        with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
            futures = [pool.submit(func, identifier, raw_dir, opts) for func, identifier in jobs]
            for future in futures:
                run = future.result()
                runs.append(run)
                etat = "OK" if run.ok else "ECHEC"
                log(f"  [{etat}] {run.tool} {run.identifier} : {len(run.findings)} compte(s) - {run.note}")

    # Phase 2: Deep analysis (parallel)
    log("[*] Phase 2 : analyse approfondie...")
    breaches = []
    companies = []
    phone_infos = []
    whois_results = []
    reputation_results = []

    with ThreadPoolExecutor(max_workers=8) as pool:
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

        # Email reputation
        reputation_futures = []
        if "reputation" not in opts.skip:
            for email in opts.email:
                reputation_futures.append(pool.submit(run_email_reputation, email, raw_dir))

        # DNS enumeration on personal email domains
        dns_futures = []
        if "dns" not in opts.skip:
            seen_domains = set()
            for email in opts.email:
                domain = email.split("@", 1)[1].lower()
                if domain not in seen_domains:
                    seen_domains.add(domain)
                    dns_futures.append(pool.submit(run_dns_lookup, domain, raw_dir))

        for f in breach_futures:
            result = f.result()
            breaches.extend(result)
            log(f"  [INFO] Fuites : {len(result)} trouvee(s)")

        if company_future:
            companies = company_future.result()
            log(f"  [INFO] Entreprises : {len(companies)} trouvee(s)")

        for f in phone_futures:
            pi = f.result()
            phone_infos.append(pi)
            log(f"  [INFO] Telephone {pi.number} : {'valide' if pi.valid else 'invalide'}, {pi.carrier or 'operateur inconnu'}")

        for f in whois_futures:
            w = f.result()
            whois_results.append(w)
            if w:
                log(f"  [INFO] WHOIS {w['domain']} : domaine personnel detecte")

        for f in reputation_futures:
            rep = f.result()
            reputation_results.append(rep)
            if rep.get("error"):
                log(f"  [INFO] Reputation {rep['email']} : indisponible")
            else:
                log(f"  [INFO] Reputation {rep['email']} : {rep.get('reputation', '?')}, suspect={rep.get('suspicious', '?')}")

        dns_results = []
        for f in dns_futures:
            dr = f.result()
            if dr:
                dns_results.append(dr)
                hints = ", ".join(dr.hosting_hints) if dr.hosting_hints else "aucun indice"
                log(f"  [INFO] DNS {dr.domain} : MX={len(dr.mx_records)}, {hints}")

    # Wayback Machine (runs after Phase 2 pool, uses profile URLs found)
    wayback_results = []
    if "wayback" not in opts.skip:
        wb_urls = set()
        for f in merge_findings(runs):
            if f.url:
                wb_urls.add(f.url)
        if wb_urls:
            log(f"  [INFO] Wayback Machine : verification de {len(wb_urls)} URL(s)...")
            wayback_results = run_wayback_check(list(wb_urls)[:20], raw_dir)
            archived = [r for r in wayback_results if r.total_snapshots > 0]
            log(f"  [INFO] Wayback : {len(archived)}/{len(wayback_results)} URL(s) archivees")

    # Paste / leak site URLs
    paste_urls = []
    if "paste" not in opts.skip:
        paste_urls = build_paste_search_urls(opts.email, opts.username, opts.phone)

    # Phase 3: Build report
    log("[*] Phase 3 : generation du rapport...")
    findings = merge_findings(runs)
    profile_details = extract_profile_details(runs)
    dorks = build_google_dorks(opts.nom, opts.email, opts.phone, opts.username)

    family_dorks = []
    if opts.nom and "family" not in opts.skip:
        family_dorks = build_family_search_dorks(
            nom=opts.nom, prenom=getattr(opts, "prenom", None),
            dob=getattr(opts, "dob", None), phones=opts.phone)

    identity_card = build_identity_card(opts, profile_details, phone_infos, companies, whois_results,
                                         reputation_results=reputation_results, breaches=breaches, findings=findings)

    username_permutations = generate_username_permutations(
        nom=opts.nom, emails=opts.email, usernames=opts.username)

    risk_score, risk_level = compute_risk_score(findings, breaches, companies, phone_infos, whois_results,
                                                 reputation_results=reputation_results, dns_results=dns_results)

    correlations = build_correlations(findings, profile_details, breaches, whois_results,
                                       reputation_results=reputation_results)


    data_classification = classify_exposed_data(breaches, whois_results, reputation_results, findings)
    dark_web_urls = build_dark_web_check_urls(opts.email, opts.username, opts.phone)
    reverse_images = build_reverse_image_search_urls(opts.username, opts.email)
    address_leaks = detect_address_leaks(breaches, whois_results, profile_details, companies)
    timeline = build_exposure_timeline(breaches, wayback_results, findings, companies)

    elapsed = datetime.now() - started

    (report_dir / "resultats.json").write_text(
        json.dumps(
            {
                "meta": {
                    "version": "2.0.0",
                    "tool": "osint-workflow",
                    "duration_seconds": int(elapsed.total_seconds()),
                },
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
                "reputation": reputation_results,
                "wayback": [asdict(w) for w in wayback_results],
                "dns": [asdict(d) for d in dns_results],
                "profil": profile_details,
                "dorks": dorks,
                "paste_urls": paste_urls,
                "identity_card": identity_card,
                "username_permutations": username_permutations,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "correlations": correlations,
                "family_dorks": family_dorks,
                "data_classification": data_classification,
                "dark_web_urls": dark_web_urls,
                "reverse_images": reverse_images,
                "address_leaks": address_leaks,
                "timeline": timeline,
            },
            indent=2, ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    log(f"[*] Resultat : {len(findings)} comptes, {len(breaches)} fuites, {len(companies)} entreprises, "
          f"score={risk_score}/100 ({risk_level}), {len(correlations)} correlation(s)")

    if not opts.json_only:
        report_file = report_dir / "RAPPORT.md"
        report_file.write_text(
            render_report(opts, runs, findings, started, breaches, companies, phone_infos, whois_results, dorks, profile_details,
                          reputation_results=reputation_results, wayback_results=wayback_results,
                          dns_results=dns_results, paste_urls=paste_urls, identity_card=identity_card,
                          username_permutations=username_permutations, risk_score=risk_score,
                          correlations=correlations, family_dorks=family_dorks, data_classification=data_classification,
                          dark_web_urls=dark_web_urls, reverse_images=reverse_images,
                          address_leaks=address_leaks, timeline=timeline),
            encoding="utf-8",
        )
        log(f"[*] Rapport : {report_file}")

        # CSV exports
        try:
            from scripts.csv_export import export_accounts_csv, export_breaches_csv, export_summary_csv
        except ImportError:
            try:
                csv_dir = Path(__file__).resolve().parent
                sys.path.insert(0, str(csv_dir))
                from csv_export import export_accounts_csv, export_breaches_csv, export_summary_csv
            except ImportError:
                export_accounts_csv = export_breaches_csv = export_summary_csv = None
        if export_accounts_csv:
            export_accounts_csv(report_dir, findings)
            if breaches:
                export_breaches_csv(report_dir, breaches)
            export_summary_csv(report_dir, opts, findings, breaches, companies, phone_infos)
            log(f"[*] CSV : comptes.csv, resume.csv" + (", fuites.csv" if breaches else ""))

        if opts.pdf:
            try:
                from scripts.pdf_export import convert as pdf_convert
            except ImportError:
                try:
                    pdf_dir = Path(__file__).resolve().parent
                    sys.path.insert(0, str(pdf_dir))
                    from pdf_export import convert as pdf_convert
                except ImportError:
                    pdf_convert = None
            if pdf_convert:
                pdf_path = pdf_convert(report_file)
                log(f"[*] PDF : {pdf_path}")
            else:
                log("[!] weasyprint non installe, PDF non genere (pip install weasyprint)")
    else:
        log(f"[*] JSON uniquement : {report_dir / 'resultats.json'}")

    minutes, seconds = divmod(int(elapsed.total_seconds()), 60)
    log(f"[*] Termine en {minutes}m{seconds:02d}s")

    if runs and not any(run.ok for run in runs):
        sys.exit(1)


if __name__ == "__main__":
    main()
