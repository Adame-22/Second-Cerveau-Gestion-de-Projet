# OSINT Workflow

Audit d'exposition numerique complet : a partir des emails, pseudos, numeros de telephone et nom d'une personne,
identifie les comptes publics, fuites de donnees, entreprises liees, informations de profil et exposition dans
les registres publics. Produit un rapport d'investigation professionnel avec plan d'action priorise, score de risque,
export PDF et CSV.

## Installation

```bash
cd osint-workflow
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Sous Windows (PowerShell), puis utiliser `.\run.bat` a la place de `./run.sh` :

```powershell
cd osint-workflow
py -m venv venv
venv\Scripts\pip install -r requirements.txt
```

## Usage

```bash
# Investigation complete (email + pseudo + telephone + nom)
./run.sh --mandat MANDAT-2026-014 --nom "Jean Dupont" --email jean@example.com --username jdupont --phone +33612345678

# Plusieurs identifiants, recherche etendue
./run.sh -m MANDAT-2026-014 -n "Jean Dupont" -e jean@example.com -e j.dupont@example.org -u jdupont -u jd_75 -p +33612345678 --all-sites

# Scan rapide sans recherche d'entreprise ni telephone
./run.sh -m MANDAT-2026-014 -e jean@example.com --skip company --skip phone

# Avec export PDF
./run.sh -m MANDAT-2026-014 -e jean@example.com -n "Jean Dupont" --pdf
```

| Option | Role |
|---|---|
| `--mandat`, `-m` | Obligatoire. Reference de l'accord ecrit de la personne concernee |
| `--email`, `-e` | Email a analyser (repetable) |
| `--username`, `-u` | Pseudo a analyser (repetable) |
| `--phone`, `-p` | Numero de telephone (repetable, format international recommande) |
| `--nom`, `-n` | Nom complet (active la recherche d'entreprise, dorks famille, registres internationaux) |
| `--all-sites` / `--top-sites N` | Etendue de la recherche Maigret (defaut : top 500) |
| `--prenom` | Prenom (ameliore les dorks famille/proches) |
| `--dob JJ/MM/AAAA` | Date de naissance (active les dorks par age) |
| `--skip OUTIL` | Ne pas lancer un module : `holehe`, `sherlock`, `maigret`, `breach`, `company`, `whois`, `phone`, `reputation`, `wayback`, `dns`, `paste`, `social`, `family` |
| `--timeout`, `--tool-timeout` | Timeout par requete (10 s) et duree maximale par outil (1800 s) |
| `--pdf` | Generer un export PDF en plus du Markdown (necessite `weasyprint`) |
| `--json-only` | Generer uniquement `resultats.json` (pas de Markdown/PDF/CSV) |
| `--quiet`, `-q` | Mode silencieux : supprime les messages de progression |
| `--config CHEMIN` | Fichier config.json alternatif (cles API, options par defaut) |

## Rapport genere

Chaque audit cree `reports/<date>_<mandat>/` (jamais versionne) :

- `RAPPORT.md` : livrable client complet avec 20+ sections
- `RAPPORT.pdf` : version PDF professionnelle (si `--pdf`)
- `resultats.json` : memes donnees, exploitables par un autre outil
- `comptes.csv` : export tableur des comptes trouves
- `resume.csv` : resume de l'audit
- `fuites.csv` : detail des fuites (si trouvees)
- `brut/` : journaux et exports de chaque outil

### Sections du rapport

1. **Synthese executive** : score de risque pondere (0-100) et niveau (FAIBLE/MOYEN/ELEVE/CRITIQUE), compteurs
2. **Fiche d'identite numerique consolidee** : croisement de toutes les sources
3. **Profil synthetique** : nom, bio, localisation, profession extraits des profils trouves
4. **Analyse telephone** : validation, operateur, type de ligne, pays
5. **Fuites de donnees** : breaches connues via HIBP / h8mail avec types de donnees exposees
6. **Classification des donnees exposees** : tri par niveau de sensibilite (CRITIQUE/ELEVE/MOYEN/FAIBLE)
7. **Entreprises** : registres francais (Pappers.fr) + registres internationaux (OpenCorporates)
8. **WHOIS** : domaines email personnels, exposition du nom et de l'adresse du proprietaire
9. **Reputation email** : reputation, blacklist, credentials leaked, profils detectes (emailrep.io)
10. **Detection d'adresses** : croisement fuites/WHOIS/entreprises/profils pour localiser l'exposition geographique
11. **Chronologie d'exposition** : timeline de tous les evenements (fuites, archives, creations d'entreprises)
12. **Detail des scans** : tableau de synthese par outil
13. **Comptes (pseudos)** : sites, liens, informations visibles sur chaque profil
14. **Comptes (email)** : services ou l'email est inscrit
15. **Identifiants supplementaires** : autres pseudos reperes sur les profils
16. **Google dorks** : liens cliquables pour approfondir manuellement
17. **Dorks famille/proches** : Pages Blanches, Geneanet, Copains d'avant, avis de deces, annuaire
18. **Permutations de pseudos** : variantes generees automatiquement
19. **Pastes et fuites** : liens vers Pastebin, GitHub Gists, IntelligenceX, Dehashed
20. **DNS** : enregistrements MX, SPF, DMARC des domaines email personnels
21. **Wayback Machine** : historique d'archivage des profils trouves
22. **Liens directs** : liens de verification manuelle vers 20+ plateformes
23. **Recherche inverse d'image** : Google Lens, TinEye, Yandex pour les avatars Gravatar/GitHub
24. **Bases de fuites** : liens vers HIBP, DeHashed, LeakCheck, IntelX, Snusbase, Truecaller
25. **Correlations** : croisement des identites entre toutes les sources
26. **Plan d'action** : recommandations priorisees

## Modules d'investigation

| Module | Entree | Ce qu'il trouve |
|---|---|---|
| Holehe | Email | Services ou l'email est inscrit |
| Sherlock | Pseudo | Profils sur 400+ sites |
| Maigret | Pseudo | Profils sur 3000+ sites + infos de profil (nom, bio, localisation) |
| Breach check | Email | Fuites de donnees (HIBP, h8mail) |
| Pappers.fr | Nom | Entreprises francaises (dirigeant, siege, SIREN) |
| OpenCorporates | Nom | Entreprises internationales (230+ juridictions) |
| phonenumbers | Telephone | Validation, operateur, pays, type de ligne |
| WHOIS | Email | Proprietaire de domaines email personnels |
| emailrep.io | Email | Reputation, blacklist, profils sociaux detectes, credentials leaked |
| Wayback Machine | URLs trouvees | Archives historiques des profils (CDX API, gratuit) |
| DNS (dig) | Domaines email | MX, SPF, DMARC, hebergeur email |
| Paste search | Tous | Liens vers Pastebin, GitHub Gists, IntelligenceX, Dehashed |
| Google dorks | Tous | 17+ liens de recherche avancee + dorks famille/proches |
| Profils sociaux | Pseudo/Email | Liens directs vers 20+ plateformes |
| Reverse image | Pseudo/Email | Google Lens, TinEye, Yandex pour les avatars |
| Classification | Toutes fuites | Tri des donnees exposees par sensibilite |
| Correlation | Toutes sources | Croisement des identites entre sources |
| Timeline | Toutes sources | Chronologie d'exposition triee |
| Detection adresses | Toutes sources | Localisation geographique exposee |
| Dark web check | Tous | Liens de verification manuelle sur bases de fuites |
| Reverse image | Pseudo/Email | Recherche d'image inversee (Gravatar, GitHub) via Google Lens, TinEye, Yandex |

Les scans de la phase 1 (comptes) et de la phase 2 (analyse approfondie) tournent en parallele.

## Configuration

Copier `config.example.json` en `config.json` :

```json
{
    "hibp_api_key": "",
    "intelx_api_key": "",
    "emailrep_api_key": "",
    "export_pdf": true,
    "default_top_sites": 500,
    "default_timeout": 10,
    "default_tool_timeout": 1800
}
```

Aucune cle n'est obligatoire. Sans cle HIBP, le systeme utilise h8mail en fallback.

## Cadre

L'outil sert a auditer l'exposition d'une personne qui l'a demande. Les donnees traitees sont des donnees
personnelles (RGPD) : garder l'accord ecrit du client, ne rechercher que ses propres identifiants, et supprimer
les rapports une fois la mission terminee. Les identifiants de tiers reperes en cours de route sont listes
comme pistes a confirmer et ne sont pas recherches automatiquement.

## Tests

```bash
python -m unittest discover -s tests
```
