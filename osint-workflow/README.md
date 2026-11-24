# OSINT Workflow

Workflow automatise pour retrouver les traces numeriques d'une personne.

## Installation

```bash
cd osint-workflow
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Investigation complete (avec rapport)

```bash
# A partir d'un email
./run.sh --email cible@example.com

# A partir d'un pseudo
./run.sh --username pseudo123

# Investigation complete
./run.sh --email cible@example.com --username pseudo123 --phone +33612345678 --nom "Jean Dupont"
```

### Scans rapides

```bash
# Scan rapide email
./scripts/quick_email.sh cible@example.com

# Scan rapide pseudo
./scripts/quick_username.sh pseudo123
```

## Structure

```
osint-workflow/
  run.sh                  # Point d'entree principal
  requirements.txt        # Dependances Python
  scripts/
    osint_runner.py       # Orchestrateur principal
    quick_email.sh        # Scan rapide email
    quick_username.sh     # Scan rapide pseudo
  reports/                # Rapports generes (gitignore)
    YYYYMMDD_HHMMSS_cible/
      holehe_results.txt
      sherlock_results.txt
      maigret_results.txt
      summary.json
      RAPPORT.md
  venv/                   # Environnement Python (gitignore)
```

## Outils integres

| Outil | Input | Ce qu'il trouve |
|-------|-------|-----------------|
| Holehe | Email | Sites ou l'email est inscrit |
| Sherlock | Username | Profils sur 400+ reseaux |
| Maigret | Username | Profils sur 3000+ sites + rapport detaille |

## Workflow type pour un client

1. Le client fournit: nom, email, pseudo, telephone
2. Lancer `./run.sh` avec toutes les infos
3. Les resultats sont dans `reports/`
4. Le fichier `RAPPORT.md` est le livrable client
5. Croiser manuellement les resultats pour confirmer
