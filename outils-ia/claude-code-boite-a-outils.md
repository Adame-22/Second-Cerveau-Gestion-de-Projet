# Boîte à outils Claude Code

> Origine : `@ViniJr~JohnMurphy#Micasa` · Vérifié le 2026-11-22 sur les dépôts officiels.

| # | Outil | Rôle en une phrase | Où ça s'installe |
|---|-------|--------------------|------------------|
| 1 | **Ponytail** | Fait écrire moins de code à Claude, donc consommer moins de tokens | Plugin Claude Code |
| 2 | **Graphify** | Transforme un dossier (code, notes, PDF, images) en graphe de connaissances | Sur ton ordi (Python) |
| 3 | **Agent Skills** | Déclenche le bon skill au bon moment (spec, plan, build, test, review, ship) | Plugin Claude Code |
| 4 | **OmniRoute** | Passerelle locale qui branche Claude Code sur des IA gratuites, avec bascule automatique | Sur ton ordi (Node.js ou Docker) |

---

## 1. Ponytail : moins de code, moins de tokens

- **Dépôt :** [DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail) (licence MIT). Installe uniquement depuis ce dépôt ou le paquet npm `@dietrichgebert/ponytail`, les copies sont à éviter.
- **Principe :** le « senior dev paresseux ». Avant d'écrire du code, Claude se demande : est-ce nécessaire ? est-ce que ça existe déjà dans le projet ? est-ce que la bibliothèque standard le fait ? Il ne retire jamais la validation, la gestion d'erreurs, la sécurité ni l'accessibilité.
- **Chiffres :** l'auteur annonce −53 % de code, −45 % de tokens et −26 % de coût. Un test indépendant de JetBrains (80 tâches) mesure plutôt −15 % de code et −10 % de coût. Le gain est réel, mais plus modeste que ce qu'annonce l'auteur.

**Installation** (deux messages séparés dans Claude Code) :
```
/plugin marketplace add DietrichGebert/ponytail
/plugin install ponytail@ponytail
```

**Commandes utiles :**
| Commande | Effet |
|----------|-------|
| `/ponytail lite \| full \| ultra \| off` | Régler l'intensité |
| `/ponytail-review` | Relire le diff en cours (bugs, sécurité, tests manquants, code en trop) |
| `/ponytail-audit` | Auditer tout le dépôt, classé par priorité |
| `/ponytail band` | Afficher/masquer le bandeau coût + tokens au-dessus du prompt |

---

## 2. Graphify : le graphe de connaissances du second cerveau

- **Dépôt :** [safishamsi/graphify](https://github.com/safishamsi/graphify)
- **Principe :** lit un dossier (code, `.md`, PDF, captures d'écran, photos de tableau blanc) et construit un graphe : concepts centraux, liens inattendus, questions à poser. L'auteur annonce jusqu'à 71x moins de tokens par question sur un gros corpus. Sur quelques fichiers seulement, le gain est surtout la structure, pas l'économie.
- **Bonus second cerveau :** il génère un **coffre Obsidian** (`graphify-out/obsidian/`) et un wiki navigable.

**Installation** (Python 3.10+, sur ton ordi) :
```bash
pip install graphifyy && graphify install     # oui, "graphifyy" avec deux y
# macOS si pip refuse : pipx install graphifyy
```

**Utilisation** dans Claude Code, à la racine de ce dépôt :
```
/graphify .                               # construire le graphe
/graphify . --update                      # ne retraiter que les fichiers modifiés
/graphify query "quels projets dépendent de X ?"
/graphify . --wiki                        # wiki markdown navigable
graphify hook install                     # reconstruire le graphe à chaque commit
```

Résultats dans `graphify-out/` : `graph.html` (graphe interactif), `GRAPH_REPORT.md`, `graph.json`, `obsidian/`.

⚠️ `graphify install` ajoute aussi une section dans ton `CLAUDE.md` et un hook qui s'exécute avant chaque recherche de fichiers. C'est voulu, mais c'est bon à savoir.

---

## 3. Agent Skills : le bon skill au bon moment

- **Dépôt :** [addyosmani/agent-skills](https://github.com/addyosmani/agent-skills) (Addy Osmani)
- **Principe :** 26 skills d'ingénierie. Un méta-skill `using-agent-skills` regarde ce que tu demandes et active le bon workflow tout seul. Par exemple, concevoir une API déclenche `api-and-interface-design` et construire une interface déclenche `frontend-ui-engineering`.
- **Cycle couvert :**
  ```
  /spec → /plan → /build → /test → /review → /ship
  ```
  Plus `/constraints`, `/webperf`, `/a11y` et `/code-simplify`. `/build auto` enchaîne tout le plan après une seule validation.

**Installation :**
```
/plugin marketplace add addyosmani/agent-skills
/plugin install agent-skills@addy-agent-skills
```
Si tu as une erreur SSH, utilise `/plugin marketplace add https://github.com/addyosmani/agent-skills.git`.

`/review` existe déjà dans Claude Code. Pour la version Agent Skills, tape `/agent-skills:review`.

---

## 4. OmniRoute : brancher Claude Code sur des IA gratuites

- **Dépôt :** [diegosouzapw/OmniRoute](https://github.com/diegosouzapw/OmniRoute) (licence MIT)
- **Principe :** une passerelle qui tourne sur ton ordi (`http://localhost:20128`). Tu y connectes tes comptes chez différents fournisseurs, et quand l'un est épuisé elle bascule tout seule : abonnement → clé API → modèle pas cher → modèle gratuit.
- **Important :** OmniRoute ne donne pas de tokens gratuits lui-même. Il additionne les offres gratuites des fournisseurs, et c'est toi qui crées les comptes chez chacun.

**Installation :**
```bash
npm install -g omniroute
omniroute                     # tableau de bord sur http://localhost:20128
omniroute doctor              # diagnostic en cas de souci
```
Ensuite : Dashboard → **Providers** → ajoute tes comptes. Puis lance Claude Code à travers la passerelle :
```bash
omniroute run claude --model <fournisseur>/<modèle>
# ou, pour écrire la config de Claude Code une fois pour toutes :
omniroute configure claude
```

**⚠️ Précautions avant de l'utiliser :**
- Quand Claude Code passe par un fournisseur gratuit, **ton code et tes notes partent chez ce fournisseur**. Pas de données clients ni de secrets sur les modèles gratuits.
- Les modèles gratuits sont moins bons que Claude. Garde-les pour les tâches simples ou en secours.
- Des articles critiques signalent des questions de sécurité et de maturité. Lis la doc sécurité du dépôt et ses issues ouvertes avant d'y faire passer de vraies clés API.
- Lis les conditions d'utilisation de chaque fournisseur : certains interdisent ce type de passerelle.

---

## Ordre d'installation conseillé

1. **Agent Skills + Ponytail** : colle les deux commandes `/plugin` de chaque section dans Claude Code. Ça prend 1 minute, sans rien à installer sur l'ordi.
   *Option, activation automatique pour ce dépôt :* crée toi-même le fichier `.claude/settings.json` à la racine avec ce contenu. Claude Code proposera alors d'installer les deux plugins à chaque ouverture du dépôt :
   ```json
   {
     "extraKnownMarketplaces": {
       "ponytail": { "source": { "source": "github", "repo": "DietrichGebert/ponytail" } },
       "addy-agent-skills": { "source": { "source": "github", "repo": "addyosmani/agent-skills" } }
     },
     "enabledPlugins": {
       "ponytail@ponytail": true,
       "agent-skills@addy-agent-skills": true
     }
   }
   ```
2. **Graphify** : dès qu'il y a une vingtaine de notes, lance `/graphify .`.
3. **OmniRoute** : seulement si tu arrives souvent au bout de tes quotas Claude, et après avoir lu les précautions ci-dessus.
