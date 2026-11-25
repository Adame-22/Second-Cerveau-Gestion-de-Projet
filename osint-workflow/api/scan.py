"""Vercel function: runs an OSINT audit and returns the report. Nothing is stored server-side."""

import base64
import contextlib
import hmac
import io
import json
import os
import shutil
import sys
import tempfile
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import osint_runner as runner  # noqa: E402

MAX_BODY = 20_000
MAX_ITEMS = 5
WEB_SKIPS = ["maigret"]


def _list(value):
    if isinstance(value, str):
        value = value.replace(",", "\n").splitlines()
    return [v.strip() for v in (value or []) if str(v).strip()][:MAX_ITEMS]


def build_argv(payload, out_dir):
    mandat = str(payload.get("mandat", "")).strip()
    if not mandat:
        raise ValueError("La reference du mandat est obligatoire.")
    if payload.get("consent") is not True:
        raise ValueError("Confirmez que la personne concernee a donne son accord ecrit.")
    argv = ["--mandat", mandat, "--output-dir", str(out_dir), "--quiet", "--xlsx",
            "--tool-timeout", "170", "--timeout", "8"]
    nom = str(payload.get("nom", "")).strip()
    if nom:
        argv += ["--nom", nom]
    targets = 0
    for flag, key in (("--email", "emails"), ("--username", "usernames"), ("--phone", "phones")):
        for value in _list(payload.get(key)):
            argv += [flag, value]
            targets += 1
    if not targets and not nom:
        raise ValueError("Indiquez au moins un email, un pseudo, un telephone ou un nom.")
    skips = set(WEB_SKIPS)
    if payload.get("deep"):
        skips.discard("maigret")
    for skip in sorted(skips):
        argv += ["--skip", skip]
    return argv


def run_scan(payload):
    out_dir = Path(tempfile.mkdtemp(prefix="osint_"))
    try:
        argv = build_argv(payload, out_dir)
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                runner.main(argv)
            except SystemExit as exc:
                if exc.code == 2:
                    raise ValueError("Identifiants invalides : verifiez le format des emails, pseudos et telephones.")
        report = next(out_dir.rglob("RAPPORT.md"), None)
        if report is None:
            raise RuntimeError("Le rapport n'a pas ete genere.")
        result = {"report": report.read_text(encoding="utf-8")}
        data = next(out_dir.rglob("resultats.json"), None)
        if data:
            result["data"] = json.loads(data.read_text(encoding="utf-8"))
        xlsx = next(out_dir.rglob("resultats.xlsx"), None)
        if xlsx:
            result["xlsx_base64"] = base64.b64encode(xlsx.read_bytes()).decode()
        return result
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def authorized(key):
    expected = os.environ.get("OSINT_ACCESS_KEY", "")
    return bool(expected) and hmac.compare_digest(key.encode(), expected.encode())


class handler(BaseHTTPRequestHandler):
    def _send(self, status, body):
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if not authorized(self.headers.get("X-Access-Key", "")):
            return self._send(401, {"error": "Cle d'acces invalide."})
        return self._send(200, {"ok": True})

    def do_POST(self):
        if not authorized(self.headers.get("X-Access-Key", "")):
            return self._send(401, {"error": "Cle d'acces invalide."})
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return self._send(400, {"error": "Requete invalide."})
        try:
            payload = json.loads(self.rfile.read(length))
            return self._send(200, run_scan(payload))
        except ValueError as exc:
            return self._send(400, {"error": str(exc)})
        except Exception:
            return self._send(500, {"error": "Erreur interne pendant l'analyse."})

    def log_message(self, *args):
        pass
