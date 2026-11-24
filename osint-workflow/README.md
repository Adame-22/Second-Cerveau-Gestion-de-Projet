# OSINT Workflow

Audit d'exposition numerique complet : a partir des emails, pseudos, numeros de telephone et nom d'une personne,
identifie les comptes publics, fuites de donnees, entreprises liees, informations de profil et exposition dans
les registres publics. Produit un rapport d'investigation avec plan d'action priorise.

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
```

| Option | Role |
|---|---|
| `--mandat`, `-m` | Obligatoire. Reference de l'accord ecrit de la personne concernee |
| `--email`, `-e` | Email a analyser (repetable) |
| `--username`, `-u` | Pseudo a analyser (repetable) |
| `--phone`, `-p` | Numero de telephone (repetable, format international recommande) |
| `--nom`, `-n` | Nom complet (active la recherche d'entreprise et les Google dorks) |
| `--prenom` | Prenom de la personne (ameliore la recherche famille/proches) |
| `--dob` | Date de naissance (JJ/MM/AAAA, active les dorks par age et date de naissance) |
| `--all-sites` / `--top-sites N` | Etendue de la recherche Maigret (defaut : top 500) |
| `--skip OUTIL` | Ne pas lancer un module : `holehe`, `sherlock`, `maigret`, `breach`, `company`, `whois`, `phone`, `reputation`, `wayback`, `dns`, `paste`, `social`, `family` |
| `--timeout`, `--tool-timeout` | Timeout par requete (10 s) et duree maximale par outil (1800 s) |
| `--pdf` | Generer un export PDF en plus du Markdown (necessite `weasyprint`) |
| `--config CHEMIN` | Fichier config.json alternatif (cles API, options par defaut) |

## Rapport genere

Chaque audit cree `reports/<date>_<mandat>/` (jamais versionne) :

- `RAPPORT.md` : livrable client complet avec 18+ sections
- `resultats.json` : memes donnees, exploitables par un autre outil
- `brut/` : journaux et exports de chaque outil

### Sections du rapport

1. **Synthese executive** : score de risque pondere (0-100) et niveau (FAIBLE/MOYEN/ELEVE/CRITIQUE), compteurs, fiche d'identite numerique consolidee
2. **Profil synthetique** : nom, bio, localisation, profession extraits des profils trouves
3. **Analyse telephone** : validation, operateur, type de ligne, pays
4. **Fuites de donnees** : breaches connues via HIBP / h8mail avec types de donnees exposees
5. **Entreprises** : registres francais (Pappers.fr) et internationaux (OpenCorporates), adresse du siege, role du dirigeant
6. **WHOIS** : domaines email personnels, exposition du nom et de l'adresse du proprietaire
7. **Reputation email** : reputation, blacklist, credentials leaked, profils detectes (emailrep.io)
8. **Detail des scans** : tableau de synthese par outil
9. **Comptes (pseudos)** : sites, liens, informations visibles sur chaque profil
10. **Comptes (email)** : services ou l'email est inscrit
11. **Identifiants supplementaires** : autres pseudos reperes sur les profils
12. **Google dorks** : liens cliquables pour approfondir manuellement (LinkedIn, Facebook, societe.com, Pages Blanches, documents PDF/XLS)
13. **Permutations de pseudos** : variantes generees automatiquement a partir du nom et des identifiants connus (jean.dupont → jdupont, dupontj, etc.)
14. **Pastes et fuites** : liens vers Pastebin, GitHub Gists, IntelligenceX, Dehashed
15. **DNS** : enregistrements MX, SPF, DMARC des domaines email personnels, hebergeur detecte
16. **Wayback Machine** : historique d'archivage des profils trouves (plus ancien/recent snapshot)
17. **Liens directs** : liens de verification manuelle vers les plateformes majeures
18. **Famille et proches** : dorks genealogiques (Geneanet, Filae), annuaires inverses, registres civils, avis de deces, recherche par age/date de naissance

## Modules d'investigation

| Module | Entree | Ce qu'il trouve |
|---|---|---|
| Holehe | Email | Services ou l'email est inscrit |
| Sherlock | Pseudo | Profils sur 400+ sites |
| Maigret | Pseudo | Profils sur 3000+ sites + infos de profil (nom, bio, localisation) |
| Breach check | Email | Fuites de donnees (HIBP, h8mail) |
| Pappers.fr + OpenCorporates | Nom | Entreprises liees (FR + international, dirigeant, siege, SIREN) |
| phonenumbers | Telephone | Validation, operateur, pays, type de ligne |
| WHOIS | Email | Proprietaire de domaines email personnels |
| emailrep.io | Email | Reputation, blacklist, profils sociaux detectes, credentials leaked |
| Wayback Machine | URLs trouvees | Archives historiques des profils (CDX API, gratuit) |
| DNS (dig) | Domaines email | MX, SPF, DMARC, hebergeur email (Google Workspace, Microsoft 365, OVH...) |
| Paste search | Tous | Liens vers Pastebin, GitHub Gists, IntelligenceX, Dehashed |
| Google dorks | Tous | Liens de recherche avancee a ouvrir manuellement |
| Family dorks | Nom, prenom, DOB | Geneanet, Filae, annuaires inverses, etat civil, necrologie, recherche par age |
| Permutations | Nom, pseudos, emails | Variantes de pseudos generees automatiquement pour elargir la recherche |
| Correlations | Toutes sources | Recoupements detectes entre les donnees (memes pseudos, multi-fuites, identite WHOIS) |
| Score de risque | Toutes sources | Score pondere 0-100 avec niveau FAIBLE/MOYEN/ELEVE/CRITIQUE |

Les scans de la phase 1 (comptes) et de la phase 2 (analyse approfondie) tournent en parallele.

## Cadre

L'outil sert a auditer l'exposition d'une personne qui l'a demande. Les donnees traitees sont des donnees
personnelles (RGPD) : garder l'accord ecrit du client, ne rechercher que ses propres identifiants, et supprimer
les rapports une fois la mission terminee. Les identifiants de tiers reperes en cours de route sont listes
comme pistes a confirmer et ne sont pas recherches automatiquement.

## Tests

```bash
python -m unittest discover -s tests
```
