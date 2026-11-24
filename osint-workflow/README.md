# OSINT Workflow

Audit d'exposition numerique : a partir des emails et pseudos d'un client, liste les comptes publics
qu'un tiers pourrait relier a lui, et produit un rapport avec un plan d'action pour reduire cette exposition.

## Installation

```bash
cd osint-workflow
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Un email et un pseudo
./run.sh --mandat MANDAT-2026-014 --nom "Jean Dupont" --email jean@example.com --username jdupont

# Plusieurs identifiants, recherche sur tous les sites connus de Maigret (long)
./run.sh -m MANDAT-2026-014 -e jean@example.com -e j.dupont@example.org -u jdupont -u jd_75 --all-sites
```

| Option | Role |
|---|---|
| `--mandat`, `-m` | Obligatoire. Reference de l'accord ecrit de la personne concernee |
| `--email`, `-e` | Email a analyser (repetable) |
| `--username`, `-u` | Pseudo a analyser (repetable) |
| `--nom`, `-n` | Nom affiche dans le rapport |
| `--all-sites` / `--top-sites N` | Etendue de la recherche Maigret (defaut : top 500) |
| `--skip OUTIL` | Ne pas lancer `holehe`, `sherlock` ou `maigret` |
| `--timeout`, `--tool-timeout` | Timeout par requete (10 s) et duree maximale par outil (1800 s) |

## Resultats

Chaque audit cree `reports/<date>_<mandat>/` (jamais versionne) :

- `RAPPORT.md` : livrable client (synthese, comptes trouves, plan d'action, limites)
- `resultats.json` : memes donnees, exploitables par un autre outil
- `brut/` : journaux et exports de chaque outil, dont le rapport HTML de Maigret

Le tableau de synthese indique pour chaque scan s'il a abouti et sa couverture reelle. Un scan en echec
ou limite en debit n'est jamais presente comme « rien trouve ».

## Outils

| Outil | Entree | Ce qu'il trouve |
|---|---|---|
| Holehe | Email | Services ou l'email est inscrit, et les indices qu'ils divulguent |
| Sherlock | Pseudo | Profils sur 400+ sites |
| Maigret | Pseudo | Profils sur 3000+ sites et informations visibles sur ces profils |

Les scans tournent en parallele et les comptes vus par plusieurs outils sont fusionnes.

## Cadre

L'outil sert a auditer l'exposition d'une personne qui l'a demande. Les donnees traitees sont des donnees
personnelles (RGPD) : garder l'accord ecrit du client, ne rechercher que ses propres identifiants, et supprimer
les rapports une fois la mission terminee. Les identifiants de tiers reperes en cours de route sont listes
comme pistes a confirmer et ne sont pas recherches automatiquement.

## Tests

```bash
python -m unittest discover -s tests
```
