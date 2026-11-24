#!/usr/bin/env python3
"""Convertit un RAPPORT.md en PDF professionnel avec mise en page et style."""

import argparse
import re
import sys
from pathlib import Path

try:
    from weasyprint import HTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False


CSS = """
@page {
    size: A4;
    margin: 20mm 15mm 20mm 15mm;
    @top-right { content: "CONFIDENTIEL"; font-size: 8pt; color: #999; }
    @bottom-center { content: "Page " counter(page) " / " counter(pages); font-size: 8pt; color: #999; }
}

body {
    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    font-size: 10pt;
    line-height: 1.5;
    color: #1a1a1a;
}

h1 {
    color: #1a365d;
    font-size: 20pt;
    border-bottom: 3px solid #2b6cb0;
    padding-bottom: 8px;
    margin-top: 0;
}

h2 {
    color: #2b6cb0;
    font-size: 14pt;
    border-bottom: 1px solid #bee3f8;
    padding-bottom: 4px;
    margin-top: 20px;
    page-break-after: avoid;
}

h3 {
    color: #2c5282;
    font-size: 12pt;
    margin-top: 15px;
    page-break-after: avoid;
}

table {
    width: 100%;
    border-collapse: collapse;
    margin: 10px 0;
    font-size: 9pt;
    page-break-inside: auto;
}

tr { page-break-inside: avoid; }

th {
    background-color: #2b6cb0;
    color: white;
    padding: 6px 8px;
    text-align: left;
    font-weight: 600;
}

td {
    padding: 5px 8px;
    border-bottom: 1px solid #e2e8f0;
    vertical-align: top;
}

tr:nth-child(even) td { background-color: #f7fafc; }

a { color: #2b6cb0; text-decoration: none; }
a:hover { text-decoration: underline; }

strong { color: #1a365d; }

hr {
    border: none;
    border-top: 2px solid #2b6cb0;
    margin: 20px 0;
}

ul { padding-left: 20px; }
li { margin-bottom: 3px; }

code {
    background: #edf2f7;
    padding: 1px 4px;
    border-radius: 3px;
    font-size: 9pt;
}

.risk-critique { color: #9b2c2c; font-weight: bold; font-size: 14pt; background: #fff5f5; padding: 2px 6px; border-radius: 3px; }
.risk-eleve { color: #e53e3e; font-weight: bold; font-size: 14pt; }
.risk-moyen { color: #dd6b20; font-weight: bold; font-size: 14pt; }
.risk-faible { color: #38a169; font-weight: bold; font-size: 14pt; }

.priority-urgent { background: #fff5f5; border-left: 3px solid #e53e3e; padding: 4px 8px; margin: 4px 0; }
.priority-important { background: #fffaf0; border-left: 3px solid #dd6b20; padding: 4px 8px; margin: 4px 0; }
.priority-recommended { background: #f0fff4; border-left: 3px solid #38a169; padding: 4px 8px; margin: 4px 0; }

blockquote {
    border-left: 3px solid #2b6cb0;
    padding: 8px 12px;
    margin: 10px 0;
    background: #ebf8ff;
    font-style: italic;
}
"""


def md_to_html(md_text):
    """Minimal Markdown-to-HTML for the report structure we generate."""
    lines = md_text.split("\n")
    html_parts = ['<!DOCTYPE html><html><head><meta charset="utf-8"><style>', CSS, '</style></head><body>']
    in_table = False
    in_ul = False
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Empty line
        if not stripped:
            if in_ul:
                html_parts.append("</ul>")
                in_ul = False
            if in_table:
                html_parts.append("</tbody></table>")
                in_table = False
            i += 1
            continue

        # Headings
        if stripped.startswith("# ") and not stripped.startswith("## "):
            if in_ul:
                html_parts.append("</ul>")
                in_ul = False
            html_parts.append(f"<h1>{_inline(stripped[2:])}</h1>")
            i += 1
            continue
        if stripped.startswith("## "):
            if in_ul:
                html_parts.append("</ul>")
                in_ul = False
            html_parts.append(f"<h2>{_inline(stripped[3:])}</h2>")
            i += 1
            continue
        if stripped.startswith("### "):
            if in_ul:
                html_parts.append("</ul>")
                in_ul = False
            html_parts.append(f"<h3>{_inline(stripped[4:])}</h3>")
            i += 1
            continue

        # Horizontal rule
        if stripped == "---":
            html_parts.append("<hr>")
            i += 1
            continue

        # Table
        if "|" in stripped and stripped.startswith("|"):
            if not in_table:
                # Header row
                cols = [c.strip() for c in stripped.split("|")[1:-1]]
                html_parts.append("<table><thead><tr>")
                for col in cols:
                    html_parts.append(f"<th>{_inline(col)}</th>")
                html_parts.append("</tr></thead><tbody>")
                in_table = True
                i += 1
                # Skip separator row
                if i < len(lines) and re.match(r"^\|[\s\-|]+\|$", lines[i].strip()):
                    i += 1
            else:
                cols = [c.strip() for c in stripped.split("|")[1:-1]]
                html_parts.append("<tr>")
                for col in cols:
                    html_parts.append(f"<td>{_inline(col)}</td>")
                html_parts.append("</tr>")
                i += 1
            continue

        # Blockquote
        if stripped.startswith("> "):
            content = stripped[2:]
            html_parts.append(f"<blockquote>{_inline(content)}</blockquote>")
            i += 1
            continue

        # List items
        if stripped.startswith("- "):
            if not in_ul:
                html_parts.append("<ul>")
                in_ul = True
            content = stripped[2:]
            if content.startswith("[ ] "):
                content = "&#9744; " + content[4:]
            elif content.startswith("[x] "):
                content = "&#9745; " + content[4:]
            html_parts.append(f"<li>{_inline(content)}</li>")
            i += 1
            continue

        # Paragraph
        if in_ul:
            html_parts.append("</ul>")
            in_ul = False
        html_parts.append(f"<p>{_inline(stripped)}</p>")
        i += 1

    if in_ul:
        html_parts.append("</ul>")
    if in_table:
        html_parts.append("</tbody></table>")
    html_parts.append("</body></html>")
    return "\n".join(html_parts)


def _inline(text):
    """Convert inline Markdown: bold, links, code."""
    # Risk level coloring
    text = re.sub(r"\*\*Niveau d'exposition global : (CRITIQUE)\*\*",
                  r'<span class="risk-critique">Niveau d\'exposition global : \1</span>', text)
    text = re.sub(r"\*\*Niveau d'exposition global : (ELEVE)\*\*",
                  r'<span class="risk-eleve">Niveau d\'exposition global : \1</span>', text)
    text = re.sub(r"\*\*Niveau d'exposition global : (MOYEN)\*\*",
                  r'<span class="risk-moyen">Niveau d\'exposition global : \1</span>', text)
    text = re.sub(r"\*\*Niveau d'exposition global : (FAIBLE)\*\*",
                  r'<span class="risk-faible">Niveau d\'exposition global : \1</span>', text)
    # Links: [text](url)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    # Bold
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    # Inline code
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    return text


def encrypt_pdf(pdf_path, password):
    """Encrypt an existing PDF with a password using pikepdf."""
    try:
        import pikepdf
    except ImportError:
        print("[!] pikepdf non installe. pip install pikepdf")
        return pdf_path
    pdf = pikepdf.open(pdf_path)
    pdf.save(pdf_path, encryption=pikepdf.Encryption(owner=password, user=password, R=6))
    pdf.close()
    print(f"[*] PDF chiffre avec mot de passe : {pdf_path}")
    return pdf_path


def convert(md_path, pdf_path=None, password=None):
    md_text = Path(md_path).read_text(encoding="utf-8")
    html_text = md_to_html(md_text)
    if pdf_path is None:
        pdf_path = str(md_path).replace(".md", ".pdf")

    html_intermediate = str(md_path).replace(".md", ".html")
    Path(html_intermediate).write_text(html_text, encoding="utf-8")

    if HAS_WEASYPRINT:
        HTML(string=html_text).write_pdf(pdf_path)
        if password:
            encrypt_pdf(pdf_path, password)
        else:
            print(f"[*] PDF genere : {pdf_path}")
        return pdf_path
    else:
        print(f"[!] weasyprint non installe, HTML genere a la place : {html_intermediate}")
        return html_intermediate


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convertir RAPPORT.md en PDF")
    parser.add_argument("rapport", help="Chemin vers RAPPORT.md")
    parser.add_argument("-o", "--output", help="Chemin de sortie PDF")
    parser.add_argument("--password", help="Chiffrer le PDF avec ce mot de passe")
    args = parser.parse_args()
    convert(args.rapport, args.output, args.password)
