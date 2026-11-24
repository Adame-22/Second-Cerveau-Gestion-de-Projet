# Remplacer des abonnements par de l'open source

> Source : guide « Stop renting software you could own » de Divya Gugnani (`divyagugnani.com/vanta-setup`), lu depuis une capture d'écran. Licences et mises en garde vérifiées le 2026-11-24 sur les dépôts GitHub officiels.

## L'idée

Le guide propose 5 logiciels gratuits à héberger soi-même à la place d'abonnements payants. Gratuit veut dire que la licence ne coûte rien, pas que ça ne demande aucun effort : il faut un serveur, des sauvegardes et quelqu'un qui fait les mises à jour.

## Le vrai calcul

Le guide annonce **20 720 $ d'économies par an** (1 726,67 $/mois). D'après son propre tableau, **environ 1 667 $/mois viennent de Vanta seul**, un outil de certification de sécurité (SOC 2) dont la plupart des petites structures n'ont pas besoin. Les 4 autres outils ne remplacent qu'**environ 60 $/mois** d'abonnements, à comparer au prix d'un serveur (quelques euros par mois) et au temps de maintenance.

## Les 5 outils

| Outil | Remplace | Sert à | Licence (vérifiée) | Piège |
|-------|----------|--------|--------------------|-------|
| [DocuSeal](https://github.com/docusealco/docuseal) | SignWell | Faire signer devis et contrats en ligne | AGPLv3, et la mention « DocuSeal » doit rester visible dans l'interface | Ton logo et la marque blanche sont réservés à la version Pro payante |
| [InvoiceShelf](https://github.com/InvoiceShelf/InvoiceShelf) | FreshBooks | Factures, devis, paiements, dépenses | AGPLv3 | Ce n'est pas une compta. La v2 ne reçoit plus de correctifs de sécurité après le **1er septembre 2027**. Ce n'est pas une plateforme agréée (voir plus bas) |
| [Vaultwarden](https://github.com/dani-garcia/vaultwarden) | Bitwarden Teams | Coffre de mots de passe d'équipe, utilisable avec les applis Bitwarden | AGPLv3 | Projet communautaire, **non affilié à Bitwarden**. Sans sauvegarde quotidienne, une panne du serveur fait perdre tous les mots de passe. Si tu es seul, Bitwarden gratuit suffit |
| [Infisical](https://github.com/Infisical/infisical) | Doppler | Ranger les clés API et les secrets des développeurs | MIT, sauf le dossier `ee/` qui est sous licence payante | Utile seulement s'il y a des développeurs dans l'équipe |
| [Comp AI](https://github.com/trycompai/comp) | Vanta | Préparer une certification SOC 2, ISO 27001, HIPAA ou RGPD | AGPLv3 pour la Community Edition ; la version Cloud est payante et séparée | **Ne délivre pas le certificat** : l'auditeur agréé reste payant. L'installation est technique (Postgres et plusieurs services) |

## Hébergement : 3 options proposées par le guide

1. **Déploiement en un clic** (Railway, Render, DigitalOcean) : quelques dollars par mois. Pour les fondateurs non techniques.
2. **Un seul petit serveur pour les 5** (Hetzner, DigitalOcean, Hostinger) avec Docker : le moins cher à grande échelle, s'il y a une personne technique.
3. **L'offre gratuite de l'éditeur**, comme Infisical Cloud : pour tester avant de s'engager.

**Non négociable, quelle que soit l'option :** un nom de domaine en HTTPS, des sauvegardes automatiques, une personne responsable des mises à jour, et la double authentification pour chaque administrateur.

## Ordre conseillé par le guide

| Quand | Quoi |
|-------|------|
| Semaine 1 | DocuSeal + InvoiceShelf : peu de risque, économie immédiate |
| Semaine 2 | Vaultwarden, avec les sauvegardes mises en place le jour même |
| Semaine 3 | Infisical : sortir tous les secrets de Slack |
| Quand un client l'exige | Comp AI, pas avant |

Ne résilie l'ancien abonnement qu'après **2 semaines sans problème** avec le nouvel outil, et **exporte tes données avant**.

## Ne change pas si…

- Personne ne peut s'occuper des mises à jour et des sauvegardes. Un outil auto-hébergé négligé est un risque, pas une économie.
- Tu as besoin d'un support téléphonique, d'une garantie de service (SLA) ou d'un contrat de sécurité signé.
- Ton abonnement est déjà presque gratuit.
- Tu es en plein audit : on ne change jamais d'outil de conformité pendant un audit.

## ⚠️ Si ton entreprise est en France : facturation électronique

La réforme impose de passer par une **plateforme agréée** pour les factures entre entreprises :
- **Réception** de factures électroniques : obligatoire pour toutes les entreprises depuis le 1er septembre 2026. C'est la date la plus citée, mais les sources divergent pour les TPE et micro-entreprises.
- **Émission** : obligatoire pour les PME, TPE et micro-entreprises au **1er septembre 2027**.

InvoiceShelf n'est pas une plateforme agréée. Pour tes factures entre entreprises, un logiciel de facturation relié à une plateforme agréée est plus sûr. Vérifie ton cas sur [impots.gouv.fr](https://www.impots.gouv.fr/foire-aux-questions-je-decouvre-la-facturation-electronique).

## Mon avis pour une petite structure

- **Utile tout de suite :** DocuSeal, pour faire signer devis et contrats. Le kit testé et son guide sont dans [`deploiement/docuseal/`](../deploiement/docuseal/GUIDE.md).
- **Si tu as une équipe :** Vaultwarden, avec des sauvegardes. Si tu es seul, Bitwarden gratuit suffit.
- **À éviter pour l'instant :** InvoiceShelf, à cause de la réforme et de la fin des correctifs de la v2 en 2027.
- **Inutile sans développeur ni gros client exigeant :** Infisical et Comp AI.
