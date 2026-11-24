# DocuSeal : ta signature électronique

Avec DocuSeal, tu envoies un devis ou un contrat en PDF, ton client le signe sur son téléphone, et tu récupères le PDF signé avec un historique des signatures. C'est une alternative gratuite et open source à SignWell ou DocuSign.

## 1. Quelle option choisir ?

| | **DocuSeal Cloud gratuit** | **Ton propre serveur (ce kit)** |
|---|---|---|
| Installation | Aucune : tu crées un compte sur [docuseal.com](https://docuseal.com/sign_up) | Environ 30 minutes, une seule fois |
| Coût | 0 € | Prix d'un petit serveur, quelques euros par mois |
| Limite | Nombre d'envois par mois limité (environ 10 d'après les comparatifs, à vérifier sur [la page tarifs](https://www.docuseal.com/pricing)) | Illimité |
| Entretien | Aucun | Sauvegardes et mises à jour, à ta charge (expliquées plus bas) |

**Mon conseil :** commence par le **cloud gratuit**. Passe à ton propre serveur avec ce kit quand tu dépasses la limite d'envois.

---

## 2. Installer sur ton serveur (environ 30 minutes)

**Avant de commencer, il te faut :**
- un nom de domaine, par exemple `monentreprise.fr` ;
- les paramètres SMTP de ton adresse e-mail pro (serveur, port, identifiant, mot de passe). Ton fournisseur e-mail les donne. Sans eux, les demandes de signature ne partent pas.

**Étapes :**

1. **Louer un serveur** Linux (VPS) sous Ubuntu, avec 2 Go de mémoire, chez Hetzner, OVH ou DigitalOcean par exemple. Si l'hébergeur propose des sauvegardes automatiques en option, active-les.
2. **Créer l'adresse** : chez ton fournisseur de nom de domaine, ajoute un enregistrement DNS de type **A** nommé `signature` qui pointe vers l'adresse IP du serveur. Ton adresse sera `signature.monentreprise.fr`.
3. **Te connecter au serveur** depuis ton ordinateur :
   ```bash
   ssh root@IP_DU_SERVEUR
   ```
4. **Installer Docker** :
   ```bash
   curl -fsSL https://get.docker.com | sh
   ```
5. **Copier ce dossier sur le serveur**. Depuis ton ordinateur, dans le dossier du dépôt :
   ```bash
   scp -r deploiement/docuseal root@IP_DU_SERVEUR:~/docuseal
   ```
6. **Lancer l'installation** sur le serveur :
   ```bash
   cd ~/docuseal && ./installer.sh
   ```
   Il te demande l'adresse (`signature.monentreprise.fr`), crée un mot de passe de base de données et démarre tout. Le certificat HTTPS se crée automatiquement.
7. **Créer ton compte** : ouvre `https://signature.monentreprise.fr`, remplis le formulaire et choisis **Français** dans « Langue ».
8. **Deux réglages obligatoires** :
   - **Paramètres → Profil → « Configurer la 2FA »** : la double authentification protège ton compte.
   - **Paramètres → E-mail** : renseigne tes paramètres SMTP.
9. **Premier modèle** : importe ton devis en PDF, place les champs « Signature » et « Date », enregistre-le comme modèle, puis envoie-toi un test.

---

## 3. Sauvegardes (obligatoire)

Sans sauvegarde, une panne du serveur fait perdre tous les documents signés.

- **Sauvegarde automatique chaque nuit** : sur le serveur, tape `crontab -e` et ajoute cette ligne :
  ```
  0 3 * * * /root/docuseal/sauvegarde.sh
  ```
  Les archives vont dans `~/docuseal/sauvegardes/`. Celles des 14 derniers jours sont gardées.
- **Copier les archives hors du serveur**, une fois par semaine par exemple, depuis ton ordinateur :
  ```bash
  scp root@IP_DU_SERVEUR:~/docuseal/sauvegardes/*.tar.gz .
  ```
  ⚠️ Ces archives contiennent les clés secrètes de DocuSeal. Range-les dans un endroit protégé.
- **Tester une restauration** une fois, pour être sûr que ça marche le jour où tu en auras besoin :
  ```bash
  ./restaurer.sh sauvegardes/docuseal_AAAA-MM-JJ_HHMM.tar.gz
  ```

## 4. Mises à jour (une fois par mois)

```bash
cd ~/docuseal && ./sauvegarde.sh && docker compose pull && docker compose up -d
```

## 5. Bon à savoir

- **Licence** : la mention « DocuSeal » reste affichée pendant la signature, c'est une condition de la licence gratuite. Ton logo est réservé à la version Pro.
- **Sécurité** : l'application n'est joignable qu'en HTTPS. Le mot de passe de la base est dans `.env` : ne le partage pas.
- **Valeur juridique** : DocuSeal fournit une signature électronique simple avec historique (date et e-mail du signataire). C'est adapté aux devis et contrats courants. Pour un document très engageant, vérifie le niveau de signature exigé.
- **Bonus Claude** : DocuSeal a son propre serveur MCP (**Paramètres → MCP**). Claude peut s'en servir pour préparer et envoyer des documents à signer.

---

*Kit testé le 2026-11-24 avec DocuSeal 3.3.8 : installation, HTTPS, création du compte, interface en français, 2FA et SMTP trouvés dans les menus indiqués, sauvegarde, effacement complet puis restauration (le compte et ses données reviennent), redémarrage automatique après une coupure du serveur.*
