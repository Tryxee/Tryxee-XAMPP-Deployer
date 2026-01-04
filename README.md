# Tryxee XAMPP Deployer — README

> Interface graphique (PySide6) pour déployer des projets depuis un dossier `htdocs` vers une cible locale ou distante (SSH).  
> Mode **clé SSH only** pour les opérations non interactives. Rsync (+ options) ou fallback tar/SFTP.

---

## Sommaire
1. [Fonctionnalités](#fonctionnalit%C3%A9s)  
2. [Prérequis](#pr%C3%A9requis)  
3. [Installation](#installation)  
4. [Configuration (.env / UI)](#configuration-env--ui)  
5. [Générer la clé SSH (client Windows)](#g%C3%A9n%C3%A9rer-la-cl%C3%A9-ssh-client-windows)  
6. [Mettre la clé côté serveur (Linux)](#mettre-la-cl%C3%A9-c%C3%B4t%C3%A9-serveur-linux)  
7. [Utilisation de l’application](#utilisation-de-lapplication)  
8. [Fichiers d’aide fournis (`helper.txt`)](#fichiers-daide-fournis-helpertxt)  
9. [Dépannage & erreurs courantes](#d%C3%A9pannage--erreurs-courantes)  
10. [Sécurité](#s%C3%A9curit%C3%A9)  
11. [FAQ rapide](#faq-rapide)  
12. [Changelog court](#changelog-court)  
13. [Licence / Contact](#licence--contact)

---

## Fonctionnalités
- UI PySide6 avec onglets **Deploy** / **Settings**.
- Sélection visuelle des fichiers/projets depuis `htdocs`.
- Prévisualisation des fichiers inclus/exclus (exclusions glob/regex).
- Modes de déploiement :
  - `local` : extraction d’une archive sur machine locale.
  - `ssh` : upload + extraction via SFTP (Paramiko) ou rsync (si disponible).
- **Authentification clé SSH uniquement** pour éviter les prompts interactifs.
- rsync direct (`--files-from` + `--relative`) ou via tmpdir + rsync distant.
- Fallback tar + SFTP si rsync non possible.
- Sauvegarde (backup) avant écrasement.
- Options centralisées dans `.xampp_deployer.env` (onglet Settings).
- Bouton pour ouvrir/afficher `helper.txt` (instructions côté serveur).
- Bouton pour sauvegarder mot de passe sudo (optionnel, stocké dans `.env` — **voir avertissement sécurité**).

---

## Prérequis
- Python 3.8+ (Windows ou Linux)
- Pip
- Dépendances Python :
  ```bash
  pip install PySide6 paramiko python-dotenv
  ```
- Côté serveur (pour rsync) : `rsync` (optionnel mais recommandé)
- SSH configuré sur le serveur

---

## Installation
1. Clone / place le script Python (fichier principal).
2. (Optionnel) Crée un environnement virtuel :
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1   # PowerShell (Windows)
   source .venv/bin/activate      # Linux / Mac
   ```
3. Installe les dépendances :
   ```bash
   pip install PySide6 paramiko python-dotenv
   ```

4. Lance l’application :
   ```bash
   python deployer.py
   ```

---

## Configuration (.env & UI)
Le fichier par défaut est `~/.xampp_deployer.env`. Exemple minimal :

```ini
SSH_HOST=example.com
SSH_PORT=PORT
SSH_USER=HOST
SSH_KEY=C:\Users\TON_USER\.ssh\key_name
SSH_SUDO_PASS=
SSH_TARGET=/var/www/html
RSYNC_FLAGS=-az
BACKUP_DIR=~/.xampp_deployer_backups
```

- Ouvre l’onglet **Settings** dans l’UI pour éditer et sauvegarder `.env`.
- Après `Enregistrer .env`, les champs du tab **Deploy** sont mis à jour automatiquement.
- **Ne mettez pas** `SSH_KEY` pointant sur un `.pub` (clé publique) — indiquez la **clé privée**.
- `SSH_SUDO_PASS` : si tu utilises des commandes sudo côté serveur (extraction dans des répertoires protégés), tu peux enregistrer le mot de passe sudo via le bouton *Enregistrer sudo* — **attention : fichier .env en clair**.

---

## Générer la clé SSH (client Windows)
1. Ouvre PowerShell :
   ```powershell
   ssh-keygen -t ed25519 -C "xampp-deployer"
   ```
   - Appuie sur Entrée pour le chemin par défaut (`C:\Users\<USER>\.ssh\id_ed25519`).
   - Pas de passhphrase

2. Vérifie la présence :
   ```powershell
   dir $env:USERPROFILE\.ssh
   # id_ed25519  id_ed25519.pub
   ```

3. Affiche la clé publique pour la copier :
   ```powershell
   type $env:USERPROFILE\.ssh\id_ed25519.pub
   ```

---

## Mettre la clé côté serveur (Linux)
1. Connecte-toi une dernière fois avec mot de passe (si nécessaire) :
   ```bash
   ssh -p <PORT> <USER>@<HOST>
   ```

2. Sur le serveur :
   ```bash
   mkdir -p ~/.ssh
   nano ~/.ssh/authorized_keys
   # -> coller la ligne entière de la clé publique (id_ed25519.pub)
   chmod 700 ~/.ssh
   chmod 600 ~/.ssh/authorized_keys
   ```

3. Tester :
   Depuis le client :
   ```powershell
   ssh -i C:\Users\<USER>\.ssh\id_ed25519 -p <PORT> <USER>@<HOST>
   ```
   - Si connexion sans mot de passe → OK
   - Sinon -> vérifier clé, permissions et utilisateur

---

## Utilisation de l’application
1. Lance l’application.
2. Dans **Deploy** :
   - `Chemin htdocs` : dossier racine contenant tes projets.
   - Sélectionne un `Projet` (ou racine).
   - Coche les fichiers / dossiers à déployer (l’arbre conserve le nom du projet dans les chemins).
   - Dans **Options** :
     - `mode` = `ssh` ou `local`.
     - `Cible locale` (pour mode local).
     - Renseigne `SSH Host`, `SSH Port`, `SSH User`, `SSH Key` (chemin complet).
     - **SSH Password** : en lecture seule (désactivé, clé-only).
     - `SSH sudo password` : si nécessaire, remplir puis cliquer **Enregistrer sudo**.
   - Exclusions : ajoute des patterns (glob) ou regex (si désactivé 'Mode glob').
   - `Prévisualiser` pour vérifier.
   - `Test connexion & checks` pour tests rapides (ssh connectivity, rsync remote, write permission).
   - `Déployer maintenant` pour lancer le worker.

3. Logs / progression :
   - Console intégrée affiche les messages.
   - Barre de progression indique %.

---

## Fichiers d’aide fournis (`helper.txt`)
- Le repo / dossier courant contient `helper.txt` (nous avons fourni un modèle).
- Dans l’UI, bouton **Récupérer helper.txt** ouvre le fichier local `./helper.txt` (ou te permet d’en sélectionner un).
- `helper.txt` contient les étapes côté serveur et côté client pour générer et installer la clé.

---

## Dépannage & erreurs courantes

### `Permission denied (publickey)`
- Clé publique mal copiée dans `~/.ssh/authorized_keys`.
- Permissions : `chmod 700 ~/.ssh` et `chmod 600 ~/.ssh/authorized_keys`.
- Mauvais utilisateur / mauvais port / clé privée non correspondante.

### L’application me demande un mot de passe en console
- Tu as laissé des flux SSH subprocess sans clé : le code a été modifié pour exiger clé-only.
- Vérifie que `SSH_KEY` est renseigné et accessible (chemin correct, droits).

### `rsync` absent sur Windows
- rsync direct nécessite rsync local (WSL/Git-Bash/Cygwin). Sinon le code doit utiliser tar+SFTP (mais le flux rsync nécessite une clé).

### Erreurs SFTP/Paramiko
- Vérifie version paramiko installée : `pip show paramiko`.
- Vérifie que la clé est lisible depuis Python (chemin sans espaces/avec bonnes permissions).

---

## Sécurité
- **Ne commit pas** `.xampp_deployer.env` contenant `SSH_SUDO_PASS`.
- Restreins l’accès au fichier `.env` (`chmod 600`) sur ta machine.
- Si tu enregistres `SSH_SUDO_PASS`, comprends que c’est stocké en clair — **risque**.

---

## FAQ rapide
- **Q** : Puis-je déployer depuis Windows ?  
  **A** : Oui. Le client peut être Windows. Le serveur cible est typiquement Linux.
- **Q** : La clé doit-elle être `ed25519` ?  
  **A** : Recommandé. `rsa` fonctionne mais `ed25519` est moderne et meilleur.
- **Q** : Doit-on installer rsync sur le serveur ?  
  **A** : Recommandé. Le système utilisera rsync si disponible pour des transferts plus rapides.
- **Q** : Puis-je stocker un mot de passe SSH ?  
  **A** : Non — l’app est en mode clé-only pour SSH. Seul le `SSH_SUDO_PASS` peut être sauvegardé (voir avertissement).

---

## Changelog court
- Version actuelle : UI remaniée, clé-only authentication, rsync direct/temps/fallbacks, preview inclusion/exclusion, .env centralisé, helper.txt support.

---

## Licence & Contact
- Utilisation libre pour usages internes.  
- Pour problèmes : copie-colle les logs et le message d'erreur exact (console intégrée) et ouvre une issue / demande d'aide.

---

### Exemples rapides de commandes

**Générer clé (Windows PowerShell)**:
```powershell
ssh-keygen -t ed25519 -C "xampp-deployer"
```

**Ajouter clé publique côté serveur**:
```bash
ssh -p 2128 tryxee62@tryxee62.fr
mkdir -p ~/.ssh
echo "ssh-ed25519 AAAA... comment" >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

---
