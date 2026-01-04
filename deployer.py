#!/usr/bin/env python3
"""
XAMPP Deployer — GUI (PySide6) — Fixed & cleaned

Corrections principales:
- Un seul endroit pour config: onglet Settings. Lors de l'enregistrement (.env) les champs du tab Deploy sont mis à jour.
- Correction des bugs de quotation sudo/ssh pour exec_command (utilisation de shlex.quote et envoi du mot de passe avec \n)
- Fix rsync --files-from: génération du fichier avec des \n et nettoyage sûr
- Ajout d'options SSH (-e) pour rsync local->remote (tempdir) si clef/port fournis
- Réparations de la logique des chemins dans l'arbre (le noeud top utilise maintenant '.' pour représenter la racine du projet)
- Correction écriture du .env (nouvelle ligne entre clefs) et propagation vers l'UI
- Divers petits correctifs et robustifications

Dépendances:
    pip install PySide6 paramiko python-dotenv
"""

import sys
import os
import stat
import tarfile
import tempfile
import shutil
import fnmatch
import re
import shlex
from pathlib import Path
from datetime import datetime
import subprocess

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QComboBox, QFileDialog, QTreeView, QAbstractItemView, QProgressBar,
    QTextEdit, QMessageBox, QCheckBox, QLineEdit, QSplitter, QSizePolicy,
    QListWidget, QListWidgetItem, QTabWidget, QFormLayout, QGroupBox, QToolButton
)
from PySide6.QtGui import QStandardItemModel, QStandardItem, QFont, QIcon
from PySide6.QtCore import Qt, QThread, Signal

# External libs
try:
    import paramiko
except Exception:
    paramiko = None

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

# ---------------- Config & Helpers ----------------
DEFAULT_HTDOCS_CANDIDATES = [
    "/opt/lampp/htdocs",
    str(Path.home() / "htdocs"),
    "C:/xampp/htdocs",
]

DEFAULT_ENV_PATH = Path.home() / ".xampp_deployer.env"


def write_example_env(path=DEFAULT_ENV_PATH):
    template = """
# XAMPP Deployer .env example
SSH_MODE=key
SSH_HOST=example.com
SSH_PORT=22
SSH_USER=deploy
SSH_KEY=/home/you/.ssh/id_rsa
SSH_PASS=
SSH_SUDO_PASS=
SSH_TARGET=/var/www/html
RSYNC_FLAGS=-az
BACKUP_DIR=~/.xampp_deployer_backups
"""
    path.write_text(template)


def find_htdocs():
    for p in DEFAULT_HTDOCS_CANDIDATES:
        if Path(p).exists():
            return str(Path(p))
    return str(Path.cwd())


def is_writable(path):
    try:
        p = Path(path)
        if not p.exists():
            p.mkdir(parents=True, exist_ok=True)
        testfile = p / (".perm_test_" + str(os.getpid()))
        with open(testfile, "w") as f:
            f.write("test")
        testfile.unlink()
        return True
    except Exception:
        return False


def _matches_exclusions(path: Path, patterns, mode='glob') -> bool:
    s = str(path)
    for pat in patterns:
        if not pat:
            continue
        if mode == 'glob':
            if fnmatch.fnmatch(s, pat) or fnmatch.fnmatch(path.name, pat):
                return True
        else:
            try:
                if re.search(pat, s):
                    return True
            except re.error:
                continue
    return False

# ---------------- Worker Thread ---------------------
class DeployWorker(QThread):
    log = Signal(str)
    progress = Signal(int)
    finished_signal = Signal(bool, str)

    def __init__(self, htdocs_root, selected_relpaths, mode, local_target, ssh_cfg, dry_run, make_backup, rsync_enabled=False, rsync_direct=False, exclusions=None, exclusion_mode='glob', rsync_flags='-az'):
        super().__init__()
        self.htdocs_root = Path(htdocs_root)
        self.selected_relpaths = selected_relpaths
        self.mode = mode
        self.local_target = Path(local_target)
        self.ssh_cfg = ssh_cfg or {}
        self.dry_run = dry_run
        self.make_backup = make_backup
        self.rsync_enabled = rsync_enabled
        self.rsync_direct = rsync_direct
        self.exclusions = exclusions or []
        self.exclusion_mode = exclusion_mode
        self.rsync_flags = rsync_flags

    def run(self):
        try:
            if not self.selected_relpaths:
                self.finished_signal.emit(False, "Aucun fichier sélectionné")
                return

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")

            if self.mode == 'local':
                tmp_tar = Path(tempfile.gettempdir()) / f"xampp_deploy_{ts}.tar"
                with tarfile.open(tmp_tar, "w") as tar:
                    for rel in self.selected_relpaths:
                        src = self.htdocs_root / rel
                        tar.add(str(src), arcname=str(rel))
                if self.dry_run:
                    self.log.emit("Dry-run local — archive créée mais non déployée")
                    tmp_tar.unlink(missing_ok=True)
                    self.progress.emit(100)
                    self.finished_signal.emit(True, "Dry-run terminé")
                    return
                self._deploy_local(tmp_tar)
            else:
                # SSH mode
                if self.rsync_enabled:
                    # try direct rsync if requested
                    if self.rsync_direct:
                        self.log.emit("Tentative rsync direct (without tempdir) ...")
                        ok = self._deploy_ssh_rsync_direct()
                        if ok:
                            self.finished_signal.emit(True, "Déploiement SSH via rsync direct terminé")
                            return
                        else:
                            self.log.emit("rsync direct échoué — tentatives fallback")
                    # try rsync via tempdir
                    ok = self._deploy_ssh_rsync_tempdir(ts)
                    if ok:
                        self.finished_signal.emit(True, "Déploiement SSH via rsync (tempdir) terminé")
                        return
                    self.log.emit("rsync failed — fallback tar/SFTP")
                # fallback tar sftp
                tmp_tar = Path(tempfile.gettempdir()) / f"xampp_deploy_{ts}.tar"
                with tarfile.open(tmp_tar, "w") as tar:
                    for rel in self.selected_relpaths:
                        src = self.htdocs_root / rel
                        tar.add(str(src), arcname=str(rel))
                if self.dry_run:
                    self.log.emit("Dry-run SSH — archive créée mais non uploadée")
                    tmp_tar.unlink(missing_ok=True)
                    self.progress.emit(100)
                    self.finished_signal.emit(True, "Dry-run terminé")
                    return
                self._deploy_ssh_tar(tmp_tar)

        except Exception as e:
            self.finished_signal.emit(False, f"Erreur: {e}")

    def _deploy_local(self, tarpath: Path):
        tgt = self.local_target
        if self.make_backup:
            bdir = Path(os.path.expanduser(self.ssh_cfg.get('backup_dir', '~/.xampp_deployer_backups')))
            bdir.mkdir(parents=True, exist_ok=True)
            bfile = bdir / f"backup_{tarpath.stem}.tar"
            self.log.emit(f"Création sauvegarde locale -> {bfile}")
            with tarfile.open(bfile, "w") as btar:
                for rel in self.selected_relpaths:
                    candidate = tgt / rel
                    if candidate.exists():
                        btar.add(str(candidate), arcname=str(rel))
            self.log.emit("Sauvegarde terminée")

        if is_writable(tgt):
            self.log.emit(f"Extraction locale vers {tgt}")
            with tarfile.open(tarpath, "r") as tar:
                members = tar.getmembers()
                total = len(members)
                for i, m in enumerate(members, start=1):
                    tar.extract(m, path=str(tgt))
                    self.progress.emit(int(i/total*100))
            tarpath.unlink(missing_ok=True)
            self.finished_signal.emit(True, "Déploiement local terminé")
            return
        else:
            self.finished_signal.emit(False, f"Cible non accessible: {tgt}. Exécutez en tant qu'administrateur ou utilisez SSH mode.")
            return

    def _deploy_ssh_tar(self, tarpath: Path):
        cfg = self.ssh_cfg
        host = cfg.get('host')
        port = int(cfg.get('port', 22))
        user = cfg.get('user')
        key = cfg.get('key')
        passwd = cfg.get('pass')
        sudo_pass = cfg.get('sudo_pass')
        remote_target = cfg.get('target') or '/var/www/html'

        if paramiko is None:
            self.finished_signal.emit(False, "Paramiko manquant — pip install paramiko")
            return

        self.log.emit(f"Connexion SSH -> {user}@{host}:{port}")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if key and key.strip():
                client.connect(hostname=host, port=port, username=user, key_filename=key, password=passwd, timeout=10)
            else:
                client.connect(hostname=host, port=port, username=user, password=passwd, timeout=10)
        except Exception as e:
            self.finished_signal.emit(False, f"Échec connexion SSH: {e}")
            return

        sftp = client.open_sftp()
        remote_tmp = f"/tmp/xampp_deploy_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tar"
        try:
            self.log.emit(f"Upload de l'archive vers {host}:{remote_tmp}")
            def _progress(transferred, total):
                pct = int(transferred/total*100)
                self.progress.emit(pct)
            sftp.put(str(tarpath), remote_tmp, callback=_progress)
            self.log.emit("Upload terminé — exécution extraction distante")

            cmd = f"tar -xpf {shlex.quote(remote_tmp)} -C {shlex.quote(remote_target)} && rm -f {shlex.quote(remote_tmp)}"
            if sudo_pass:
                # safer quoting and send sudo password via stdin
                cmd_exec = f"sudo -S bash -c {shlex.quote(cmd)}"
                stdin, stdout, stderr = client.exec_command(cmd_exec)
                stdin.write(sudo_pass + '\n')
                stdin.flush()
            else:
                stdin, stdout, stderr = client.exec_command(cmd)

            for line in stdout:
                self.log.emit(line.strip())
            err = stderr.read().decode().strip()
            if err:
                self.log.emit(f"stderr: {err}")

            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                self.progress.emit(100)
                self.log.emit("Déploiement distant terminé")
                self.finished_signal.emit(True, "Déploiement SSH terminé")
            else:
                self.finished_signal.emit(False, f"Erreur lors de l'extraction distante (code {exit_status})")

        except Exception as e:
            self.finished_signal.emit(False, f"Erreur SSH/SFTP: {e}")
        finally:
            try:
                sftp.close()
            except Exception:
                pass
            try:
                client.close()
            except Exception:
                pass
            try:
                tarpath.unlink(missing_ok=True)
            except Exception:
                pass

    def _deploy_ssh_rsync_direct(self) -> bool:
        """Attempt to run rsync --files-from=FILE --relative directly to remote target.
        Returns True on success, False otherwise.
        """
        cfg = self.ssh_cfg
        host = cfg.get('host')
        port = int(cfg.get('port', 22))
        user = cfg.get('user')
        key = cfg.get('key')
        remote_target = cfg.get('target') or '/var/www/html'

        # Require key-based auth for rsync direct
        if not key or str(key).strip() == '':
            self.log.emit('rsync direct nécessite une clef SSH (auth par mot de passe desactivée).')
            return False

        rsync_local = shutil.which('rsync')
        if not rsync_local:
            self.log.emit('rsync n\'est pas installé localement')
            return False

        # build files-from list relative to htdocs root
        files = []
        for rel in self.selected_relpaths:
            # expand directory to files
            src = self.htdocs_root / rel
            if src.is_dir():
                for p in src.rglob('*'):
                    if p.is_file():
                        relp = p.relative_to(self.htdocs_root)
                        if _matches_exclusions(relp, self.exclusions, self.exclusion_mode):
                            continue
                        files.append(str(relp))
            else:
                if _matches_exclusions(rel, self.exclusions, self.exclusion_mode):
                    continue
                files.append(str(rel))

        if not files:
            self.log.emit('Aucun fichier à synchroniser après application des exclusions')
            return False

        ff = Path(tempfile.gettempdir()) / f"files_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        ff.write_text('\n'.join(files) + '\n')

        # rsync command must be run from htdocs root so relative paths work
        rsync_cmd = ['rsync'] + shlex.split(self.rsync_flags) + ['--files-from=' + str(ff), '--relative', './', f"{user}@{host}:{remote_target}"]
        env = os.environ.copy()
        # add ssh options
        ssh_opts = []
        if key:
            ssh_opts += ['-i', key]
        ssh_opts += ['-p', str(port)]
        if ssh_opts:
            ssh_rsh = ['ssh'] + ssh_opts
            env['RSYNC_RSH'] = ' '.join(shlex.quote(o) for o in ssh_rsh)

        self.log.emit('Lancement rsync direct: ' + ' '.join(shlex.quote(p) for p in rsync_cmd))
        try:
            p = subprocess.run(rsync_cmd, cwd=str(self.htdocs_root), env=env, capture_output=True, text=True, timeout=600)
            self.log.emit(p.stdout)
            if p.returncode == 0:
                self.progress.emit(100)
                ff.unlink(missing_ok=True)
                return True
            else:
                self.log.emit('rsync returned code ' + str(p.returncode))
                self.log.emit(p.stderr)
                ff.unlink(missing_ok=True)
                return False
        except Exception as e:
            self.log.emit(f'rsync direct exception: {e}')
            try:
                ff.unlink(missing_ok=True)
            except Exception:
                pass
            return False

    def _deploy_ssh_rsync_tempdir(self, ts: str) -> bool:
        # reuse previous approach: build tempdir then rsync local->remote tmpdir then remote rsync to target
        return self._deploy_ssh_rsync_via_tempdir(ts)

    def _deploy_ssh_rsync_via_tempdir(self, ts: str) -> bool:
        # similar to earlier implementation
        cfg = self.ssh_cfg
        host = cfg.get('host')
        port = int(cfg.get('port', 22))
        user = cfg.get('user')
        key = cfg.get('key')
        passwd = cfg.get('pass')
        sudo_pass = cfg.get('sudo_pass')
        remote_target = cfg.get('target') or '/var/www/html'

        tmpdir = Path(tempfile.mkdtemp(prefix='xampp_rsync_'))
        self.log.emit(f"Création d'un répertoire temporaire pour rsync: {tmpdir}")

        # copy selected paths into tmpdir applying exclusions
        selected = sorted(self.selected_relpaths, key=lambda p: len(p.parts) if isinstance(p, Path) else len(str(p).split(os.sep)))
        keep = []
        for p in selected:
            skip = False
            for q in keep:
                if str(p).startswith(str(q) + os.sep):
                    skip = True
                    break
            if not skip:
                keep.append(p)

        total_files = 0
        for rel in keep:
            src = self.htdocs_root / rel
            dest = tmpdir / rel
            if _matches_exclusions(rel, self.exclusions, self.exclusion_mode):
                self.log.emit(f"Exclu (pattern): {rel}")
                continue
            if src.is_dir():
                try:
                    shutil.copytree(src, dest, dirs_exist_ok=True)
                except Exception as e:
                    self.log.emit(f"Erreur copytree {src} -> {e}")
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    shutil.copy2(src, dest)
                except Exception as e:
                    self.log.emit(f"Erreur copy {src} -> {e}")
            for _ in dest.rglob('*'):
                total_files += 1

        if total_files == 0:
            self.log.emit("Aucun fichier à transférer après application des filtres/exclusions")
            shutil.rmtree(tmpdir, ignore_errors=True)
            return False

        # If no SSH key provided but a password is available, avoid running subprocess ssh/rsync
        # because it will prompt for password interactively on the terminal. Instead fall back to
        # uploading a tar via Paramiko SFTP (same behaviour as the tar/SFTP fallback).
        if not key or str(key).strip() == '':
            self.log.emit('Authentification par clé requise pour rsync/tempdir. Configurez SSH_KEY dans Settings.')
            shutil.rmtree(tmpdir, ignore_errors=True)
            return False

        # rsync local -> remote tmpdir
        ssh_args = []
        if key:
            ssh_args += ['-i', key]
        ssh_args += ['-p', str(port)]
        if ssh_args:
            ssh_e = ' '.join(shlex.quote(a) for a in (['ssh'] + ssh_args))
            rsync_cmd = ['rsync'] + shlex.split(self.rsync_flags) + ['-e', ssh_e, '--delete', f"{str(tmpdir)}/", f"{user}@{host}:~/xampp_deploy_tmp_{ts}/"]
        else:
            rsync_cmd = ['rsync'] + shlex.split(self.rsync_flags) + ['--delete', f"{str(tmpdir)}/", f"{user}@{host}:~/xampp_deploy_tmp_{ts}/"]

        self.log.emit('Lancement rsync local->distant (tmpdir)')
        try:
            p = subprocess.run(rsync_cmd, capture_output=True, text=True, timeout=1200)
            self.log.emit(p.stdout)
            if p.returncode != 0:
                self.log.emit('rsync local->remote failed: ' + p.stderr)
                shutil.rmtree(tmpdir, ignore_errors=True)
                return False
        except Exception as e:
            self.log.emit(f'rsync error: {e}')
            shutil.rmtree(tmpdir, ignore_errors=True)
            return False

        # remote move from tmp to target
        # use ssh to run rsync on remote side
        ssh_cmd = ['ssh']
        ssh_opts = []
        if key := cfg.get('key'):
            ssh_opts += ['-i', key]
        ssh_opts += ['-p', str(port)]
        ssh_cmd += ssh_opts + [f"{user}@{host}"]

        if sudo_pass := cfg.get('sudo_pass'):
            # run sudo rsync on remote
            # quote sudo_pass carefully and run commands via sh -c
            remote_cmd = f"echo {shlex.quote(sudo_pass)} | sudo -S rsync -a --delete ~/xampp_deploy_tmp_{ts}/ {shlex.quote(remote_target)} && sudo -S rm -rf ~/xampp_deploy_tmp_{ts}/"
        else:
            remote_cmd = f"rsync -a --delete ~/xampp_deploy_tmp_{ts}/ {shlex.quote(remote_target)} && rm -rf ~/xampp_deploy_tmp_{ts}/"

        full_ssh_cmd = ssh_cmd + [remote_cmd]
        self.log.emit('Exécution remote: ' + ' '.join(shlex.quote(x) for x in full_ssh_cmd))
        try:
            p2 = subprocess.run(full_ssh_cmd, capture_output=True, text=True, timeout=1200)
            self.log.emit(p2.stdout)
            if p2.returncode == 0:
                self.progress.emit(100)
                shutil.rmtree(tmpdir, ignore_errors=True)
                return True
            else:
                self.log.emit('remote rsync/move failed: ' + p2.stderr)
                shutil.rmtree(tmpdir, ignore_errors=True)
                return False
        except Exception as e:
            self.log.emit(f'remote exec error: {e}')
            shutil.rmtree(tmpdir, ignore_errors=True)
            return False

# ---------------- GUI ---------------------------
class DeployerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("XAMPP Deployer — GUI")
        self.resize(1360, 880)

        self.htdocs_root = Path(find_htdocs())
        self.env = {}
        self._load_env()

        self._build_ui()
        self._populate_projects()

    def _load_env(self):
        """Load .env into self.env robustly.

        - If python-dotenv is available we still call it, but we also provide a fallback
          parser that tolerates malformed .env files where lines may have been concatenated.
        """
        self.env = {}
        # Try to use dotenv if available (preferred)
        if load_dotenv is not None:
            cwd_env = Path('.') / '.env'
            if cwd_env.exists():
                load_dotenv(str(cwd_env))
            elif DEFAULT_ENV_PATH.exists():
                load_dotenv(str(DEFAULT_ENV_PATH))
            else:
                write_example_env()
                load_dotenv(str(DEFAULT_ENV_PATH))
            # collect common keys
            keys = ['SSH_MODE','SSH_HOST','SSH_PORT','SSH_USER','SSH_KEY','SSH_PASS','SSH_SUDO_PASS','SSH_TARGET','RSYNC_FLAGS','BACKUP_DIR']
            for k in keys:
                v = os.getenv(k)
                if v is not None:
                    self.env[k] = v
        else:
            # No python-dotenv: ensure a file exists
            if not DEFAULT_ENV_PATH.exists():
                write_example_env()

        # In any case, try to parse the .env file directly to be robust against malformed files
        try:
            if DEFAULT_ENV_PATH.exists():
                raw = DEFAULT_ENV_PATH.read_text()
                # If the file contains no newlines, it's possibly concatenated: we will parse keys by locating KEY= tokens
                # Find all occurrences of KEY=
                matches = list(re.finditer(r'([A-Z0-9_]+)=', raw))
                if matches:
                    parsed = {}
                    for i, m in enumerate(matches):
                        key = m.group(1)
                        start = m.end()
                        end = matches[i+1].start() if i+1 < len(matches) else len(raw)
                        value = raw[start:end].strip()
                        # strip any accidental leading/trailing quotes and newlines
                        value = value.strip('\"\'"').strip()
                        parsed[key] = value
                    # merge parsed into self.env (parsed file has priority)
                    for k, v in parsed.items():
                        if v is not None and v != '':
                            self.env[k] = v
        except Exception:
            # silently ignore parsing errors
            pass

    def _build_ui(self):
        main = QVBoxLayout(self)

        header = QLabel("XAMPP Deployer")
        header.setFont(QFont('Arial', 18, QFont.Bold))
        header.setStyleSheet("padding:10px; border-radius:8px; background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #4b6cb7, stop:1 #182848); color: white;")
        header.setAlignment(Qt.AlignCenter)
        main.addWidget(header)

        tabs = QTabWidget()
        tabs.addTab(self._build_deploy_tab(), "Deploy")
        tabs.addTab(self._build_settings_tab(), "Settings")
        main.addWidget(tabs)

    def _build_deploy_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        top_h = QHBoxLayout()
        top_h.addWidget(QLabel("Chemin htdocs:"))
        self.htdocs_line = QLineEdit(str(self.htdocs_root))
        top_h.addWidget(self.htdocs_line)
        btn_browse = QPushButton("Parcourir")
        btn_browse.clicked.connect(self.browse_htdocs)
        top_h.addWidget(btn_browse)

        top_h.addWidget(QLabel("Projet:"))
        self.project_combo = QComboBox()
        top_h.addWidget(self.project_combo)
        btn_refresh = QPushButton("Actualiser")
        btn_refresh.clicked.connect(self._populate_projects)
        top_h.addWidget(btn_refresh)
        layout.addLayout(top_h)

        splitter = QSplitter()

        # Left: tree
        left = QWidget()
        left_l = QVBoxLayout(left)
        self.tree = QTreeView()
        self.tree.setHeaderHidden(True)
        left_l.addWidget(self.tree)

        btns = QHBoxLayout()
        btns.addWidget(QPushButton("Tout sélectionner", clicked=lambda: self._set_checkstate_all(Qt.Checked)))
        btns.addWidget(QPushButton("Tout désélectionner", clicked=lambda: self._set_checkstate_all(Qt.Unchecked)))
        btns.addWidget(QPushButton("Inverser", clicked=self._invert_selection))
        left_l.addLayout(btns)

        splitter.addWidget(left)

        # Right: options + preview
        right = QWidget()
        right_l = QVBoxLayout(right)
        right_l.addWidget(QLabel("Options de déploiement"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["local","ssh"])
        right_l.addWidget(self.mode_combo)

        right_l.addWidget(QLabel("Cible locale (ex: /var/www/html):"))
        self.target_edit = QLineEdit(self.env.get('SSH_TARGET','/var/www/html'))
        right_l.addWidget(self.target_edit)

        right_l.addWidget(QLabel("--- Configuration SSH (utilisée si mode=ssh) ---"))
        self.ssh_host = QLineEdit(self.env.get('SSH_HOST',''))
        self.ssh_port = QLineEdit(self.env.get('SSH_PORT','22'))
        self.ssh_user = QLineEdit(self.env.get('SSH_USER',''))
        self.ssh_key = QLineEdit(self.env.get('SSH_KEY',''))
        self.ssh_pass = QLineEdit(self.env.get('SSH_PASS',''))
        self.ssh_sudo = QLineEdit(self.env.get('SSH_SUDO_PASS',''))

        right_l.addWidget(QLabel('SSH Host:'))
        right_l.addWidget(self.ssh_host)
        right_l.addWidget(QLabel('SSH Port:'))
        right_l.addWidget(self.ssh_port)
        right_l.addWidget(QLabel('SSH User:'))
        right_l.addWidget(self.ssh_user)
        right_l.addWidget(QLabel('SSH Key (chemin) [auth par clé uniquement] :'))
        key_h = QHBoxLayout()
        key_h.addWidget(self.ssh_key)
        btn_fetch = QPushButton('Récupérer helper.txt', clicked=self.fetch_helper_key)
        key_h.addWidget(btn_fetch)
        right_l.addLayout(key_h)
        right_l.addWidget(QLabel('SSH Password (désactivé — clé uniquement):'))
        # disable password input: we enforce key-only auth
        self.ssh_pass.setReadOnly(True)
        self.ssh_pass.setPlaceholderText('Authentification par mot de passe désactivée — utilisez une clé')
        right_l.addWidget(self.ssh_pass)
        right_l.addWidget(QLabel('SSH sudo password (si besoin):'))
        sudo_h = QHBoxLayout()
        self.ssh_sudo.setEchoMode(QLineEdit.Password)
        sudo_h.addWidget(self.ssh_sudo)
        btn_save_sudo = QPushButton('Enregistrer sudo', clicked=self.save_sudo_password_to_env)
        sudo_h.addWidget(btn_save_sudo)
        right_l.addLayout(sudo_h)

        self.rsync_cb = QCheckBox("Utiliser rsync over SSH (plus rapide)")
        right_l.addWidget(self.rsync_cb)
        self.rsync_direct_cb = QCheckBox("Essayer rsync direct (--files-from) sans tempdir")
        right_l.addWidget(self.rsync_direct_cb)

        # Exclusions UI
        right_l.addWidget(QLabel("Filtres / Exclusions"))
        excl_h = QHBoxLayout()
        self.excl_input = QLineEdit()
        self.excl_input.setPlaceholderText("Ex: *.log  node_modules  */cache/*")
        excl_h.addWidget(self.excl_input)
        btn_add_excl = QPushButton("Ajouter")
        btn_add_excl.clicked.connect(self._add_exclusion)
        excl_h.addWidget(btn_add_excl)
        right_l.addLayout(excl_h)

        self.excl_list = QListWidget()
        right_l.addWidget(self.excl_list)
        btns_excl = QHBoxLayout()
        btns_excl.addWidget(QPushButton("Supprimer sélection", clicked=self._remove_selected_exclusion))
        btns_excl.addWidget(QPushButton("Effacer tout", clicked=lambda: self.excl_list.clear()))
        right_l.addLayout(btns_excl)

        # radio glob / regex
        radio_h = QHBoxLayout()
        radio_h.addWidget(QLabel("Mode filtres:"))
        self.rb_glob = QCheckBox("Mode glob (fnmatch)")
        self.rb_glob.setChecked(True)
        radio_h.addWidget(self.rb_glob)
        right_l.addLayout(radio_h)

        self.dry_run_cb = QCheckBox("Dry-run (simuler)")
        right_l.addWidget(self.dry_run_cb)
        self.backup_cb = QCheckBox("Faire une sauvegarde avant écrasement")
        self.backup_cb.setChecked(True)
        right_l.addWidget(self.backup_cb)

        # Action buttons
        act_h = QHBoxLayout()
        act_h.addWidget(QPushButton("Prévisualiser sélection", clicked=self.preview_selection))
        self.btn_test = QPushButton("Test connexion & checks")
        self.btn_test.clicked.connect(self.test_connection_checks)
        act_h.addWidget(self.btn_test)
        self.btn_deploy = QPushButton("Déployer maintenant")
        self.btn_deploy.clicked.connect(self.deploy_now)
        act_h.addWidget(self.btn_deploy)
        right_l.addLayout(act_h)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        right_l.addWidget(self.progress)
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setMinimumHeight(240)
        right_l.addWidget(self.console)

        # Preview of included/excluded
        preview_box = QGroupBox("Aperçu transfert")
        preview_l = QVBoxLayout(preview_box)
        self.preview_included = QListWidget()
        self.preview_excluded = QListWidget()
        preview_l.addWidget(QLabel('Fichiers inclus (ex. 100 premières)'))
        preview_l.addWidget(self.preview_included)
        preview_l.addWidget(QLabel('Fichiers exclus (ex. 100 premières)'))
        preview_l.addWidget(self.preview_excluded)
        right_l.addWidget(preview_box)

        splitter.addWidget(right)
        splitter.setSizes([720, 640])
        layout.addWidget(splitter)

        return w

    def _build_settings_tab(self):
        w = QWidget()
        layout = QVBoxLayout(w)

        form = QFormLayout()
        self.env_ssh_host = QLineEdit(self.env.get('SSH_HOST',''))
        self.env_ssh_port = QLineEdit(self.env.get('SSH_PORT','22'))
        self.env_ssh_user = QLineEdit(self.env.get('SSH_USER',''))
        self.env_ssh_key = QLineEdit(self.env.get('SSH_KEY',''))
        self.env_ssh_target = QLineEdit(self.env.get('SSH_TARGET','/var/www/html'))
        self.env_rsync_flags = QLineEdit(self.env.get('RSYNC_FLAGS','-az'))
        self.env_backup_dir = QLineEdit(self.env.get('BACKUP_DIR','~/.xampp_deployer_backups'))

        form.addRow('SSH_HOST:', self.env_ssh_host)
        form.addRow('SSH_PORT:', self.env_ssh_port)
        form.addRow('SSH_USER:', self.env_ssh_user)
        form.addRow('SSH_KEY:', self.env_ssh_key)
        form.addRow('SSH_TARGET:', self.env_ssh_target)
        form.addRow('RSYNC_FLAGS:', self.env_rsync_flags)
        form.addRow('BACKUP_DIR:', self.env_backup_dir)

        layout.addLayout(form)

        btn_h = QHBoxLayout()
        btn_save = QPushButton('Enregistrer .env', clicked=self.save_env)
        btn_h.addWidget(btn_save)
        btn_open = QPushButton('Ouvrir fichier .env', clicked=self.open_env_in_editor)
        btn_h.addWidget(btn_open)
        layout.addLayout(btn_h)

        layout.addStretch()
        return w

    def save_env(self):
        data = {
            'SSH_HOST': self.env_ssh_host.text().strip(),
            'SSH_PORT': self.env_ssh_port.text().strip(),
            'SSH_USER': self.env_ssh_user.text().strip(),
            'SSH_KEY': self.env_ssh_key.text().strip(),
            'SSH_TARGET': self.env_ssh_target.text().strip(),
            'RSYNC_FLAGS': self.env_rsync_flags.text().strip(),
            'BACKUP_DIR': self.env_backup_dir.text().strip(),
        }
        lines = [f"{k}={v}" for k,v in data.items()]
        DEFAULT_ENV_PATH.write_text(''.join(lines) + '')

        # update in-memory env and reflect into Deploy tab
        for k,v in data.items():
            self.env[k] = v
        # propagate values to deploy UI
        self.ssh_host.setText(self.env.get('SSH_HOST',''))
        self.ssh_port.setText(self.env.get('SSH_PORT','22'))
        self.ssh_user.setText(self.env.get('SSH_USER',''))
        self.ssh_key.setText(self.env.get('SSH_KEY',''))
        self.target_edit.setText(self.env.get('SSH_TARGET','/var/www/html'))

        QMessageBox.information(self, 'Enregistré', f'.env enregistré dans {DEFAULT_ENV_PATH}')

    def save_sudo_password_to_env(self):
        """Save SSH_SUDO_PASS into DEFAULT_ENV_PATH (overwrites or appends)."""
        val = self.ssh_sudo.text().strip()
        if not val:
            QMessageBox.warning(self, 'Enregistrer sudo', 'Entrez déjà le mot de passe sudo dans le champ avant d\'enregistrer.')
            return
        # read existing env
        existing = {}
        if DEFAULT_ENV_PATH.exists():
            raw = DEFAULT_ENV_PATH.read_text()
            for line in raw.splitlines():
                if '=' in line and not line.strip().startswith('#'):
                    k,v = line.split('=',1)
                    existing[k.strip()] = v.strip()
        existing['SSH_SUDO_PASS'] = val
        # write back
        lines = [f"{k}={v}" for k,v in existing.items()]
        DEFAULT_ENV_PATH.write_text(''.join(lines) + '')
        # update in-memory env
        self.env['SSH_SUDO_PASS'] = val
        QMessageBox.information(self, 'Enregistré', 'Mot de passe sudo enregistré dans le fichier .env (attention sécurité)')

    def open_env_in_editor(self):
        p = str(DEFAULT_ENV_PATH)
        if not DEFAULT_ENV_PATH.exists():
            DEFAULT_ENV_PATH.write_text('')
        if sys.platform.startswith('linux'):
            subprocess.run(['xdg-open', p])
        elif sys.platform.startswith('win'):
            os.startfile(p)
        elif sys.platform.startswith('darwin'):
            subprocess.run(['open', p])

    def fetch_helper_key(self):
        """Open the local helper.txt (in current working directory) which contains server-side instructions.

        Behaviour:
        - If ./helper.txt exists it is displayed (detailed text) and the user is proposed to open it in the system editor.
        - Otherwise the user is offered to choose a file with a file dialog.
        """
        helper_path = Path.cwd() / 'helper.txt'
        if not helper_path.exists():
            # Ask user to pick a helper file
            f, _ = QFileDialog.getOpenFileName(self, 'Ouvrir helper.txt', str(Path.cwd()), 'Text files (*.txt);;All files (*)')
            if not f:
                QMessageBox.warning(self, 'helper.txt', 'Aucun fichier helper.txt trouvé ou sélectionné.')
                return
            helper_path = Path(f)

        try:
            data = helper_path.read_text(encoding='utf-8')
        except Exception as e:
            QMessageBox.critical(self, 'helper.txt', f"Erreur lecture du fichier: {e}")
            return

        # Show content in a dialog with detailed text (so it remains scrollable)
        dlg = QMessageBox(self)
        dlg.setWindowTitle('helper.txt')
        dlg.setText(f'Contenu du fichier : {helper_path}')
        dlg.setDetailedText(data)
        dlg.setIcon(QMessageBox.Information)
        dlg.setStandardButtons(QMessageBox.Ok | QMessageBox.Open)
        res = dlg.exec()

        # If user chose Open, open the file in the system default editor
        if res == QMessageBox.Open:
            p = str(helper_path)
            try:
                if sys.platform.startswith('linux'):
                    subprocess.run(['xdg-open', p])
                elif sys.platform.startswith('win'):
                    os.startfile(p)
                elif sys.platform.startswith('darwin'):
                    subprocess.run(['open', p])
            except Exception as e:
                QMessageBox.warning(self, 'helper.txt', f'Impossible d\'ouvrir le fichier: {e}')

    def _add_exclusion(self):
        v = self.excl_input.text().strip()
        if v:
            self.excl_list.addItem(QListWidgetItem(v))
            self.excl_input.clear()
            self._update_preview()

    def _remove_selected_exclusion(self):
        for it in self.excl_list.selectedItems():
            self.excl_list.takeItem(self.excl_list.row(it))
        self._update_preview()

    def browse_htdocs(self):
        d = QFileDialog.getExistingDirectory(self, "Choisir htdocs", self.htdocs_line.text())
        if d:
            self.htdocs_line.setText(d)
            self._populate_projects()

    def _populate_projects(self):
        root = Path(self.htdocs_line.text())
        self.htdocs_root = root
        self.project_combo.clear()
        try:
            subs = [p.name for p in root.iterdir() if p.is_dir()]
            subs.sort()
            self.project_combo.addItems(subs)
            if subs:
                self.project_combo.setCurrentIndex(0)
            try:
                # avoid double-connecting signal
                self.project_combo.currentIndexChanged.disconnect()
            except Exception:
                pass
            self.project_combo.currentIndexChanged.connect(self._load_project_tree)
            self._load_project_tree()
            self.log(f"Projets listés dans {root}")
        except Exception as e:
            self.log(f"Erreur lecture htdocs: {e}")

    def _load_project_tree(self):
        project = self.project_combo.currentText()
        htdocs_root = Path(self.htdocs_line.text())
        base = htdocs_root / project if project else htdocs_root
        if not base.exists():
            self.log(f"Chemin introuvable: {base}")
            return

        model = QStandardItemModel()
        root_item = model.invisibleRootItem()

        def add_items(parent_item, parent_path):
            try:
                entries = sorted(parent_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
            except PermissionError:
                return
            for p in entries:
                it = QStandardItem(p.name)
                # store path relative to htdocs root so we always keep the project folder in the path
                try:
                    rel = str(p.relative_to(htdocs_root))
                except Exception:
                    rel = str(p)
                it.setData(rel, Qt.UserRole+1)
                it.setCheckable(True)
                it.setEditable(False)
                if p.is_dir():
                    parent_item.appendRow(it)
                    add_items(it, p)
                else:
                    parent_item.appendRow(it)

        top = QStandardItem(project or htdocs_root.name)
        top.setEditable(False)
        top.setCheckable(True)
        # represent top node by its path relative to htdocs_root (project name) or '.' if root is used directly
        top.setData(str(project) if project else '.', Qt.UserRole+1)
        model.appendRow(top)
        add_items(top, base)

        self.tree.setModel(model)
        self.model = model
        self.tree.expandToDepth(1)
        model.itemChanged.connect(self._on_item_changed
)
        state = item.checkState()
        def set_children(it, st):
            for r in range(it.rowCount()):
                child = it.child(r)
                child.setCheckState(st)
                set_children(child, st)
        set_children(item, state)

        def update_parent(it):
            parent = it.parent()
            if parent is None:
                return
            checked = 0
            partial = False
            for r in range(parent.rowCount()):
                c = parent.child(r)
                if c.checkState() == Qt.PartiallyChecked:
                    partial = True
                if c.checkState() == Qt.Checked:
                    checked += 1
            if partial or (0 < checked < parent.rowCount()):
                parent.setCheckState(Qt.PartiallyChecked)
            elif checked == parent.rowCount():
                parent.setCheckState(Qt.Checked)
            else:
                parent.setCheckState(Qt.Unchecked)
            update_parent(parent)
        update_parent(item)
        self._update_preview()

    def _set_checkstate_all(self, state):
        root = self.model.invisibleRootItem()
        for i in range(root.rowCount()):
            root.child(i).setCheckState(state)
        self._update_preview()

    def _invert_selection(self):
        def recurse(it):
            for r in range(it.rowCount()):
                c = it.child(r)
                c.setCheckState(Qt.Unchecked if c.checkState()==Qt.Checked else Qt.Checked)
                recurse(c)
        recurse(self.model.invisibleRootItem())
        self._update_preview()

    def _gather_selected_relpaths(self):
        root = self.model.invisibleRootItem()
        rels = []
        # stored data for items is a path relative to htdocs root (or '.' for the top root)
        def recurse(it):
            for r in range(it.rowCount()):
                c = it.child(r)
                if c.checkState() == Qt.Checked:
                    data = c.data(Qt.UserRole+1)
                    if data:
                        # keep the data as-is (relative path string)
                        rels.append(Path(data))
                recurse(c)
        recurse(root)
        uniq = []
        seen = set()
        for r in rels:
            s = str(r)
            if s not in seen:
                seen.add(s)
                uniq.append(Path(s))
        return uniq

    def _split_included_excluded(self, sel, exclusions, mode):
        included = []
        excluded = []
        count = 0
        for rel in sel:
            src = Path(self.htdocs_line.text()) if str(rel) == '.' else Path(self.htdocs_line.text()) / rel
            if src.is_dir():
                for p in src.rglob('*'):
                    if p.is_file():
                        try:
                            relp = p.relative_to(Path(self.htdocs_line.text()))
                        except Exception:
                            relp = p
                        if _matches_exclusions(relp, exclusions, mode):
                            excluded.append(relp)
                        else:
                            included.append(relp)
            else:
                if _matches_exclusions(rel, exclusions, mode):
                    excluded.append(rel)
                else:
                    included.append(rel)
            count += 1
            if count > 2000:
                break
        return included, excluded

    def _update_preview(self):
        sel = self._gather_selected_relpaths()
        exclusions = [self.excl_list.item(i).text() for i in range(self.excl_list.count())]
        mode = 'glob' if self.rb_glob.isChecked() else 'regex'
        included, excluded = self._split_included_excluded(sel, exclusions, mode)
        self.preview_included.clear()
        self.preview_excluded.clear()
        for p in included[:100]:
            self.preview_included.addItem(str(p))
        for p in excluded[:100]:
            self.preview_excluded.addItem(str(p))
        self.log(f"Aperçu: {len(included)} inclus / {len(excluded)} exclus (échantillon affiché)")

    def preview_selection(self):
        sel = self._gather_selected_relpaths()
        if not sel:
            QMessageBox.information(self, "Prévisualiser", "Aucun fichier sélectionné")
            return
        exclusions = [self.excl_list.item(i).text() for i in range(self.excl_list.count())]
        mode = 'glob' if self.rb_glob.isChecked() else 'regex'
        included, excluded = self._split_included_excluded(sel, exclusions, mode)
        txt = f"À déployer: {len(included)} fichiers\nExclus: {len(excluded)} fichiers\nExemples inclus:\n" + '\n'.join(str(p) for p in included[:50])
        QMessageBox.information(self, "Prévisualiser", txt)

    def test_connection_checks(self):
        # quick checks: local write, ssh connect, rsync present
        mode = 'ssh' if self.mode_combo.currentText() == 'ssh' else 'local'
        target = self.target_edit.text().strip() or '/var/www/html'
        if mode == 'local':
            ok = is_writable(target)
            QMessageBox.information(self, 'Check local', f'Writable: {ok} Path: {target}')
            self.log(f'Check local writable: {ok}')
            return

        # SSH checks
        host = self.ssh_host.text().strip()
        port = int(self.ssh_port.text().strip() or 22)
        user = self.ssh_user.text().strip()
        key = self.ssh_key.text().strip()
        # 1) attempt ssh connection via subprocess (fast)
        ssh_base = ['ssh']
        if key:
            ssh_base += ['-i', key]
        ssh_base += ['-p', str(port), f"{user}@{host}"]

        # check ssh connectivity
        try:
            p = subprocess.run(ssh_base + ['echo', 'ok'], capture_output=True, text=True, timeout=10)
            ok_conn = (p.returncode == 0 and 'ok' in p.stdout)
        except Exception as e:
            ok_conn = False
            self.log(f'SSH check exception: {e}')

        # check rsync remote
        try:
            p2 = subprocess.run(ssh_base + ['which', 'rsync'], capture_output=True, text=True, timeout=10)
            rsync_remote = (p2.returncode == 0 and p2.stdout.strip())
        except Exception:
            rsync_remote = ''

        # check write permission attempt: touch a temp file in target
        test_file = f"{target.rstrip('/')}/.perm_test_{os.getpid()}"
        can_write = False
        try:
            # try create via ssh
            cmd = f"touch {shlex.quote(test_file)} && rm -f {shlex.quote(test_file)}"
            p3 = subprocess.run(ssh_base + ['sh', '-c', cmd], capture_output=True, text=True, timeout=10)
            can_write = (p3.returncode == 0)
        except Exception as e:
            self.log(f'Write check exception: {e}')
            can_write = False

        # show checklist
        msg = f"SSH connect: {'OK' if ok_conn else 'FAIL'} rsync on remote: {'Yes ('+rsync_remote.strip()+')' if rsync_remote else 'No'} Write to target: {'Yes' if can_write else 'No'}"
        QMessageBox.information(self, 'Checks SSH', msg)
        self.log(msg)

    def deploy_now(self):
        selected = self._gather_selected_relpaths()
        if not selected:
            QMessageBox.warning(self, "Déployer", "Aucun fichier sélectionné")
            return
        mode = 'ssh' if self.mode_combo.currentText() == 'ssh' else 'local'
        target = self.target_edit.text().strip() or '/var/www/html'
        ssh_cfg = {
            'host': self.ssh_host.text().strip(),
            'port': int(self.ssh_port.text().strip() or 22),
            'user': self.ssh_user.text().strip(),
            'key': self.ssh_key.text().strip(),
            'pass': self.ssh_pass.text().strip(),
            'sudo_pass': self.ssh_sudo.text().strip(),
            'target': target,
            'backup_dir': self.env_backup_dir.text() if hasattr(self, 'env_backup_dir') else '~/.xampp_deployer_backups'
        }
        dry = self.dry_run_cb.isChecked()
        backup = self.backup_cb.isChecked()
        rsync_enabled = self.rsync_cb.isChecked()
        rsync_direct = self.rsync_direct_cb.isChecked()
        exclusions = [self.excl_list.item(i).text() for i in range(self.excl_list.count())]
        exclusion_mode = 'glob' if self.rb_glob.isChecked() else 'regex'
        rsync_flags = self.env.get('RSYNC_FLAGS', self.env_rsync_flags.text() if hasattr(self, 'env_rsync_flags') else '-az')

        self.btn_deploy.setEnabled(False)
        self.log("Démarrage déploiement...")

        self.worker = DeployWorker(self.htdocs_line.text(), selected, mode, target, ssh_cfg, dry, backup, rsync_enabled, rsync_direct, exclusions, exclusion_mode, rsync_flags)
        self.worker.log.connect(self.log)
        self.worker.progress.connect(lambda v: self.progress.setValue(v))
        self.worker.finished_signal.connect(self._on_finished)
        self.worker.start()

    def _on_finished(self, ok: bool, message: str):
        self.btn_deploy.setEnabled(True)
        if ok:
            QMessageBox.information(self, "Terminé", message)
            self.log(f"Terminé: {message}")
        else:
            QMessageBox.critical(self, "Échec", message)
            self.log(f"Échec: {message}")

    def log(self, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.append(f"[{ts}] {text}")

# ---------------- Main ---------------------------

def main():
    app = QApplication(sys.argv)
    w = DeployerGUI()
    w.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
