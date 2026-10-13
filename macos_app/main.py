#!/usr/bin/env python3
"""MacSCP — cliente SFTP nativo para macOS (estilo WinSCP). Não inicia servidor web."""
import os, sys, stat, json, shutil, hashlib, base64, posixpath, time, uuid, subprocess, socket, errno, ipaddress, threading
import copy, math
from collections import deque
from pathlib import Path

import paramiko
import pyte
from PySide6.QtCore import Qt, QMimeData, QThread, Signal, QUrl, QTimer, QFile
from PySide6.QtGui import (QDrag, QAction, QKeySequence, QBrush, QColor, QIcon, QPixmap, QPainter, QFont, QPalette,
                           QTextDocument, QTextCursor)
from PySide6.QtCore import QFileInfo, QByteArray, QSize, QRect, QRegularExpression, QPointF, QRectF, QEvent
from PySide6.QtGui import QRegularExpressionValidator, QFontMetricsF, QResizeEvent
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QSpinBox,
    QPushButton, QTreeWidget, QTreeWidgetItem, QFileDialog, QMessageBox, QInputDialog, QSplitter,
    QDialog, QFormLayout, QDialogButtonBox, QPlainTextEdit, QMenu, QAbstractItemView, QTabWidget,
    QToolButton, QCheckBox, QListWidget, QListWidgetItem, QProgressBar, QFileIconProvider, QGridLayout,
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM   # já vem com o paramiko

APP_NAME = "MacSCP"
MIME_PATHS = "application/x-macscp-paths"   # JSON: {"session": id, "side": "local|remote", "paths": [...]}
PATH_ROLE = Qt.UserRole
ISDIR_ROLE = Qt.UserRole + 1
HOVER_BRUSH = QBrush(QColor(80, 140, 255, 90))


def human_size(n):
    units = ['B', 'KB', 'MB', 'GB', 'TB']; v = float(n or 0); i = 0
    while v >= 1024 and i < len(units) - 1: v /= 1024; i += 1
    return f"{int(v)} {units[i]}" if i == 0 else f"{v:.1f} {units[i]}"


def valid_name(name):
    return bool(name) and name not in ('.', '..') and '/' not in name and '\0' not in name


# ============================================================================= favoritos

def config_dir():
    base = Path.home() / "Library" / "Application Support" if sys.platform == "darwin" else Path.home() / ".config"
    d = base / APP_NAME; d.mkdir(parents=True, exist_ok=True)
    return d


class Favorites:
    """Favoritos em JSON (sem senha). A senha fica no Keychain do macOS."""

    def __init__(self):
        self.path = config_dir() / "favoritos.json"
        self.items = []
        try:
            self.items = json.loads(self.path.read_text("utf-8")) if self.path.exists() else []
        except Exception:
            self.items = []

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.items, ensure_ascii=False, indent=2), "utf-8")
        os.chmod(tmp, 0o600); tmp.replace(self.path)

    def get(self, fav_id):
        return next((f for f in self.items if f["id"] == fav_id), None)

    def upsert(self, fav):
        fav.setdefault("id", uuid.uuid4().hex)
        for i, f in enumerate(self.items):
            if f["id"] == fav["id"]: self.items[i] = fav; break
        else:
            self.items.append(fav)
        self.items.sort(key=lambda f: f.get("name", "").lower()); self.save()
        return fav

    def remove(self, fav_id):
        self.items = [f for f in self.items if f["id"] != fav_id]; self.save()
        self.delete_password(fav_id)

    # --- senhas: cofre próprio do MacSCP (não usa as Chaves do macOS, então não pede a senha das Chaves)
    _cache = {}

    @classmethod
    def get_password(cls, fav_id):
        if fav_id not in cls._cache: cls._cache[fav_id] = SecretStore.get(fav_id)
        return cls._cache[fav_id]

    @classmethod
    def set_password(cls, fav_id, password):
        if cls._cache.get(fav_id) == password: return
        SecretStore.set(fav_id, password); cls._cache[fav_id] = password

    @classmethod
    def delete_password(cls, fav_id):
        cls._cache.pop(fav_id, None); SecretStore.delete(fav_id)


class SecretStore:
    """Senhas criptografadas (AES-256-GCM) em ~/Library/Application Support/MacSCP/senhas.bin.
    A chave fica num arquivo que só o seu usuário do Mac pode ler. O acesso pelo app é liberado com Touch ID."""

    @staticmethod
    def _paths():
        d = config_dir()
        try: os.chmod(d, 0o700)
        except OSError: pass
        return d / ".chave", d / "senhas.bin"

    @classmethod
    def _key(cls):
        key_path, _ = cls._paths()
        if key_path.exists():
            key = key_path.read_bytes()
            if len(key) == 32: return key
        key = AESGCM.generate_key(bit_length=256)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f: f.write(key)
        return key

    @classmethod
    def _load(cls):
        _, data_path = cls._paths()
        try: return json.loads(data_path.read_text("utf-8")) if data_path.exists() else {}
        except Exception: return {}

    @classmethod
    def _save(cls, items):
        _, data_path = cls._paths(); tmp = data_path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f: json.dump(items, f)
        tmp.replace(data_path)

    @classmethod
    def get(cls, fav_id):
        blob = cls._load().get(fav_id)
        if not blob: return ""
        try:
            raw = base64.b64decode(blob)
            return AESGCM(cls._key()).decrypt(raw[:12], raw[12:], fav_id.encode()).decode("utf-8")
        except Exception:
            return ""

    @classmethod
    def set(cls, fav_id, password):
        nonce = os.urandom(12)
        ct = AESGCM(cls._key()).encrypt(nonce, password.encode("utf-8"), fav_id.encode())
        items = cls._load(); items[fav_id] = base64.b64encode(nonce + ct).decode(); cls._save(items)

    @classmethod
    def delete(cls, fav_id):
        items = cls._load()
        if items.pop(fav_id, None) is not None: cls._save(items)


# ============================================================================= Touch ID

LA_POLICY_OWNER_AUTH = 2   # LAPolicyDeviceOwnerAuthentication: Touch ID / Apple Watch, com a senha do Mac como alternativa


TOUCH_ID_PROBLEM = ""   # motivo, quando o Touch ID não está disponível


def touch_id(reason):
    """Pede Touch ID. Retorna True (ok), False (cancelado) ou None (Touch ID indisponível neste Mac/build)."""
    global TOUCH_ID_PROBLEM
    if sys.platform != "darwin": TOUCH_ID_PROBLEM = "só existe no macOS"; return None
    try:
        from LocalAuthentication import LAContext
    except Exception as e:
        TOUCH_ID_PROBLEM = f"módulo LocalAuthentication ausente no app ({e})"; return None
    try:
        ctx = LAContext.alloc().init()
        can, err = ctx.canEvaluatePolicy_error_(LA_POLICY_OWNER_AUTH, None)
        if not can:
            TOUCH_ID_PROBLEM = str(err.localizedDescription()) if err is not None else "não disponível"; return None
        done = threading.Event(); result = {}
        def reply(success, error):
            result["ok"] = bool(success); done.set()
        ctx.evaluatePolicy_localizedReason_reply_(LA_POLICY_OWNER_AUTH, reason, reply)
        while not done.wait(0.05): QApplication.processEvents()
        return result.get("ok", False)
    except Exception as e:
        TOUCH_ID_PROBLEM = str(e); return None


def check_mac_password(pwd):
    """Confere a senha do usuário do Mac (via dscl, sem precisar das Chaves)."""
    try:
        r = subprocess.run(["dscl", ".", "-authonly", os.environ.get("USER") or os.getlogin(), pwd],
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


class Unlock:
    """Touch ID uma vez por abertura do app; “Bloquear favoritos” exige de novo."""
    unlocked = False

    @classmethod
    def ensure(cls, what):
        if cls.unlocked: return True
        r = touch_id(f"usar a senha salva de “{what}”")
        if r is False: return False
        if r is None and sys.platform == "darwin":
            # sem Touch ID: pede a senha do Mac (do seu usuário, não a das Chaves)
            pwd, ok = QInputDialog.getText(None, "Desbloquear favoritos",
                                           f"Touch ID indisponível ({TOUCH_ID_PROBLEM}).\n"
                                           "Digite a senha do seu usuário do Mac para usar as senhas salvas:",
                                           QLineEdit.Password)
            if not ok or not check_mac_password(pwd):
                if ok: QMessageBox.warning(None, "Senha incorreta", "Senha do Mac incorreta.")
                return False
        cls.unlocked = True
        return True

    @classmethod
    def lock(cls):
        cls.unlocked = False; Favorites._cache.clear()


class ConnectionDialog(QDialog):
    """Nova conexão (com opção de salvar nos favoritos)."""

    def __init__(self, parent=None):
        super().__init__(parent); self.setWindowTitle("Nova conexão SSH/SFTP"); self.setMinimumWidth(440)
        form = QFormLayout(self)
        self.host = QLineEdit(); self.host.setPlaceholderText("192.168.1.100 ou host.example")
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(22)
        self.user = QLineEdit()
        self.password = QLineEdit(); self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("vazio = usar chave SSH (~/.ssh)")
        self.remote_dir = QLineEdit(); self.remote_dir.setPlaceholderText("opcional, ex.: /var/www")
        form.addRow("Servidor / IP", self.host); form.addRow("Porta", self.port)
        form.addRow("Usuário", self.user); form.addRow("Senha SSH", self.password)
        form.addRow("Pasta remota inicial", self.remote_dir)
        self.save_fav = QCheckBox("Salvar nos favoritos"); form.addRow(self.save_fav)
        self.fav_name = QLineEdit(); self.fav_name.setPlaceholderText("Nome do favorito (ex.: Raspberry)")
        self.save_pwd = QCheckBox("Salvar senha (protegida por Touch ID)"); self.save_pwd.setChecked(True)
        form.addRow("Nome", self.fav_name); form.addRow(self.save_pwd)
        self.save_fav.toggled.connect(self._toggle); self._toggle(False)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Conectar")
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject); form.addRow(buttons)

    def _toggle(self, on):
        self.fav_name.setEnabled(on); self.save_pwd.setEnabled(on)

    def values(self):
        return dict(host=self.host.text().strip(), port=self.port.value(), user=self.user.text().strip(),
                    password=self.password.text(), remote_dir=self.remote_dir.text().strip())


class FavoritesDialog(QDialog):
    """Gerenciar favoritos: lista à esquerda, formulário à direita."""
    connect_requested = Signal(dict, object)   # favorito, senha (None = usar a salva)

    def __init__(self, favorites, parent=None):
        super().__init__(parent); self.setWindowTitle("Favoritos"); self.resize(680, 380)
        self.favs = favorites; self.current_id = None
        root = QHBoxLayout(self)
        left = QVBoxLayout(); self.list = QListWidget(); left.addWidget(self.list, 1)
        lb = QHBoxLayout(); nb = QPushButton("＋ Novo"); db = QPushButton("Excluir")
        lb.addWidget(nb); lb.addWidget(db); left.addLayout(lb); root.addLayout(left, 1)

        right = QVBoxLayout(); form = QFormLayout()
        self.name = QLineEdit(); self.host = QLineEdit()
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(22)
        self.user = QLineEdit(); self.password = QLineEdit(); self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("vazio = usar chave SSH")
        self.remote_dir = QLineEdit(); self.remote_dir.setPlaceholderText("opcional")
        self.local_dir = QLineEdit(); self.local_dir.setPlaceholderText("opcional")
        pick = QPushButton("…"); pick.setFixedWidth(32); pick.clicked.connect(self._pick_local)
        ld = QHBoxLayout(); ld.addWidget(self.local_dir, 1); ld.addWidget(pick)
        self.save_pwd = QCheckBox("Salvar senha (protegida por Touch ID)"); self.save_pwd.setChecked(True)
        form.addRow("Nome", self.name); form.addRow("Servidor / IP", self.host); form.addRow("Porta", self.port)
        form.addRow("Usuário", self.user); form.addRow("Senha", self.password)
        form.addRow("Pasta remota inicial", self.remote_dir); form.addRow("Pasta local inicial", ld)
        form.addRow(self.save_pwd); right.addLayout(form); right.addStretch(1)
        rb = QHBoxLayout(); sb = QPushButton("Salvar"); cb = QPushButton("Conectar"); cb.setDefault(True)
        close = QPushButton("Fechar"); rb.addStretch(1); rb.addWidget(close); rb.addWidget(sb); rb.addWidget(cb)
        right.addLayout(rb); root.addLayout(right, 2)

        nb.clicked.connect(self.new); db.clicked.connect(self.delete); sb.clicked.connect(self.save)
        cb.clicked.connect(self.connect_selected); close.clicked.connect(self.reject)
        self.list.currentItemChanged.connect(self._load)
        self.list.itemDoubleClicked.connect(lambda *_: self.connect_selected())
        self._refresh_list()
        if self.list.count(): self.list.setCurrentRow(0)
        else: self.new()

    def _pick_local(self):
        p = QFileDialog.getExistingDirectory(self, "Pasta local inicial", self.local_dir.text() or str(Path.home()))
        if p: self.local_dir.setText(p)

    def _refresh_list(self, select_id=None):
        self.list.blockSignals(True); self.list.clear()
        for f in self.favs.items:
            it = QListWidgetItem(f"⭐ {f.get('name') or f['host']}"); it.setData(Qt.UserRole, f["id"])
            it.setToolTip(f"{f['user']}@{f['host']}:{f['port']}"); self.list.addItem(it)
            if f["id"] == select_id: self.list.setCurrentItem(it)
        self.list.blockSignals(False)

    def _load(self, item, _prev=None):
        if item is None: return
        f = self.favs.get(item.data(Qt.UserRole))
        if not f: return
        self.current_id = f["id"]
        self.name.setText(f.get("name", "")); self.host.setText(f["host"]); self.port.setValue(int(f.get("port", 22)))
        self.user.setText(f["user"]); self.remote_dir.setText(f.get("remote_dir", ""))
        self.local_dir.setText(f.get("local_dir", ""))
        # não lê as Chaves aqui (evita pedido de senha do macOS só por selecionar um favorito)
        self.password.clear()
        self.password.setPlaceholderText("🔒 senha salva — deixe vazio para manter" if f.get("save_password")
                                         else "vazio = perguntar ao conectar / usar chave SSH")
        self.save_pwd.setChecked(bool(f.get("save_password", True)))

    def new(self):
        self.current_id = None; self.list.clearSelection()
        for w in (self.name, self.host, self.user, self.password, self.remote_dir, self.local_dir): w.clear()
        self.password.setPlaceholderText("vazio = usar chave SSH")
        self.port.setValue(22); self.save_pwd.setChecked(True); self.name.setFocus()

    def _form_fav(self):
        host = self.host.text().strip(); user = self.user.text().strip()
        if not host or not user:
            QMessageBox.warning(self, "Dados incompletos", "Informe pelo menos servidor e usuário."); return None
        return dict(id=self.current_id or uuid.uuid4().hex, name=self.name.text().strip() or f"{user}@{host}",
                    host=host, port=self.port.value(), user=user, remote_dir=self.remote_dir.text().strip(),
                    local_dir=self.local_dir.text().strip(), save_password=self.save_pwd.isChecked())

    def save(self, quiet=False):
        fav = self._form_fav()
        if not fav: return None
        try:
            old = self.favs.get(fav["id"]) or {}
            if fav["save_password"] and self.password.text():          # só grava se digitou senha nova
                Favorites.set_password(fav["id"], self.password.text())
            elif not fav["save_password"] and old.get("save_password"):  # desmarcou "salvar senha"
                Favorites.delete_password(fav["id"])
        except Exception as e:
            QMessageBox.warning(self, "Senha não salva", f"O favorito foi salvo, mas a senha não:\n{e}")
        self.favs.upsert(fav); self.current_id = fav["id"]; self._refresh_list(fav["id"])
        return fav

    def delete(self):
        if not self.current_id: return
        f = self.favs.get(self.current_id)
        if QMessageBox.question(self, "Excluir favorito", f"Excluir “{f.get('name')}” e a senha salva?",
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes: return
        self.favs.remove(self.current_id); self._refresh_list(); self.new()
        if self.list.count(): self.list.setCurrentRow(0)

    def connect_selected(self):
        fav = self.save(quiet=True)
        if not fav: return
        # campo vazio → a senha salva é lida uma única vez na hora de conectar
        self.connect_requested.emit(fav, self.password.text() or None); self.accept()


# ============================================================================= ícones (pasta azul do macOS)

FOLDER_SVG = b"""<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>
<defs><linearGradient id='b' x1='0' y1='0' x2='0' y2='1'>
<stop offset='0' stop-color='#6CC4F5'/><stop offset='1' stop-color='#3A9BE0'/></linearGradient></defs>
<path d='M4 14a5 5 0 0 1 5-5h15l6 6h25a5 5 0 0 1 5 5v4H4z' fill='#2F8AD0'/>
<rect x='4' y='19' width='56' height='37' rx='5' fill='url(#b)'/>
<rect x='4' y='19' width='56' height='3' rx='1.5' fill='#9BD8FA' opacity='.8'/></svg>"""

FILE_SVG = b"""<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>
<path d='M14 4h26l14 14v38a4 4 0 0 1-4 4H14a4 4 0 0 1-4-4V8a4 4 0 0 1 4-4z' fill='#FFFFFF' stroke='#C8CCD2' stroke-width='2'/>
<path d='M40 4v10a4 4 0 0 0 4 4h10' fill='#E9ECEF' stroke='#C8CCD2' stroke-width='2'/></svg>"""


def svg_icon(data):
    icon = QIcon()
    for size in (16, 32, 64):
        pm = QPixmap(size, size); pm.fill(Qt.transparent)
        p = QPainter(pm); QSvgRenderer(QByteArray(data)).render(p); p.end()
        icon.addPixmap(pm)
    return icon


class Icons:
    """No macOS usa os ícones nativos do Finder (pasta azul, ícone de cada tipo de arquivo).
    Em qualquer outro caso, usa uma pasta azul desenhada no estilo do Mac."""
    _inst = None

    def __init__(self):
        self.native = sys.platform == "darwin"
        self.provider = QFileIconProvider()
        self.folder = self.provider.icon(QFileIconProvider.Folder) if self.native else QIcon()
        self.file = self.provider.icon(QFileIconProvider.File) if self.native else QIcon()
        if self.folder.isNull(): self.folder = svg_icon(FOLDER_SVG)
        if self.file.isNull(): self.file = svg_icon(FILE_SVG)
        self.by_ext = {}
        self._tmp = Path(config_dir()) / "icon-samples"

    @classmethod
    def get(cls):
        if cls._inst is None: cls._inst = Icons()
        return cls._inst

    def local(self, path, isdir):
        if self.native:
            ic = self.provider.icon(QFileInfo(path))   # pastas especiais (Downloads, Mesa…) e .app ficam iguais ao Finder
            if not ic.isNull(): return ic
        return self.folder if isdir else self.file

    def remote(self, name, isdir):
        if isdir: return self.folder
        ext = os.path.splitext(name)[1].lower()
        if not self.native or not ext: return self.file
        if ext not in self.by_ext:   # ícone do tipo de arquivo, igual ao Finder (via arquivo-amostra vazio)
            try:
                self._tmp.mkdir(parents=True, exist_ok=True); sample = self._tmp / f"amostra{ext}"
                if not sample.exists(): sample.touch()
                ic = self.provider.icon(QFileInfo(str(sample)))
                self.by_ext[ext] = ic if not ic.isNull() else self.file
            except Exception:
                self.by_ext[ext] = self.file
        return self.by_ext[ext]


# ============================================================================= SSH

def is_private(host):
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_private or ip.is_link_local
    except Exception:
        return False


def check_tcp(host, port, timeout=8):
    """Testa a conexão TCP antes do SSH para dar uma mensagem de erro que explique o problema."""
    try:
        socket.getaddrinfo(host, port)
    except socket.gaierror:
        raise RuntimeError(f"Não encontrei o servidor “{host}”. Confira o nome/IP.")
    try:
        socket.create_connection((host, port), timeout=timeout).close()
    except socket.timeout:
        raise RuntimeError(f"Tempo esgotado ao conectar em {host}:{port}.\n\n"
                           "O servidor não respondeu: pode estar desligado, fora da VPN (ZeroTier/Tailscale) "
                           "ou com firewall bloqueando a porta.")
    except OSError as e:
        code = e.errno
        if code == errno.ECONNREFUSED:
            raise RuntimeError(f"{host} recusou a conexão na porta {port}.\n\n"
                               "O servidor está acessível, mas o SSH não está rodando nessa porta (confira a porta e o serviço ssh).")
        if code in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EPERM, errno.EACCES) and sys.platform == "darwin" and is_private(host):
            raise RuntimeError(
                f"O macOS bloqueou o acesso a {host} (rede local/VPN).\n\n"
                "Provável causa: o MacSCP não tem permissão de Rede Local.\n"
                "Abra Ajustes do Sistema → Privacidade e Segurança → Rede Local e ative o MacSCP.\n"
                "Se ele não aparecer na lista, gere o app de novo com o build_macos.command atualizado.\n\n"
                f"Se continuar, teste no Terminal:  nc -vz {host} {port}\n"
                f"(erro do sistema: {e.strerror or code})")
        if code in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            raise RuntimeError(f"Sem rota até {host}. Confira se a VPN (ZeroTier/Tailscale) está conectada "
                               f"e se este Mac está autorizado na rede.\n\n(erro do sistema: {e.strerror or code})")
        raise RuntimeError(f"Não foi possível abrir conexão com {host}:{port}: {e.strerror or e}")


def open_ssh(parent, host, port, user, password):
    """Abre SSHClient verificando a chave do servidor (pergunta na primeira vez)."""
    known = os.path.expanduser('~/.ssh/known_hosts'); os.makedirs(os.path.dirname(known), mode=0o700, exist_ok=True)
    client = paramiko.SSHClient(); client.load_system_host_keys()
    use_keys = not password
    opts = dict(hostname=host, port=port, username=user, password=password or None, timeout=12, banner_timeout=12,
                auth_timeout=15, allow_agent=use_keys, look_for_keys=use_keys)
    try:
        check_tcp(host, port)
        if os.path.exists(known): client.load_host_keys(known)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            client.connect(**opts)
        except paramiko.SSHException as exc:
            if 'not found in known_hosts' not in str(exc).lower(): raise
            transport = paramiko.Transport((host, port)); transport.banner_timeout = 12
            transport.start_client(timeout=12); key = transport.get_remote_server_key(); transport.close()
            fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
            answer = QMessageBox.question(
                parent, "Confirmar chave SSH",
                f"Servidor: {host}:{port}\nTipo: {key.get_name()}\nImpressão digital: {fingerprint}\n\n"
                "Confirme com o administrador do servidor por um canal confiável. Deseja confiar nesta chave?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes: raise RuntimeError("Chave SSH não confirmada.")
            client.get_host_keys().add(f"[{host}]:{port}" if port != 22 else host, key.get_name(), key)
            client.save_host_keys(known); os.chmod(known, 0o600)
            client.connect(**opts)
        return client
    except Exception:
        client.close(); raise


class TerminalReader(QThread):
    output = Signal(bytes)
    closed = Signal()
    def __init__(self, channel): super().__init__(); self.channel = channel; self.running = True
    def run(self):
        while self.running and not self.channel.closed:
            try:
                if self.channel.recv_ready():
                    data = self.channel.recv(32768)
                    if not data: break
                    self.output.emit(bytes(data))
                elif self.channel.exit_status_ready():
                    break
                else:
                    time.sleep(0.01)
            except Exception:
                break
        if self.running: self.closed.emit()
    def stop(self): self.running = False


# ----------------------------------------------------------------------------- terminal (emulação xterm)

IS_MAC = sys.platform == "darwin"
MOD_CTRL = Qt.MetaModifier if IS_MAC else Qt.ControlModifier     # tecla Control física
MOD_CMD = Qt.ControlModifier if IS_MAC else None                  # tecla ⌘ (no macOS o Qt chama de Control)

TERM_COLORS = {   # tema escuro parecido com o Terminal do macOS
    "black": "#000000", "red": "#c23621", "green": "#25bc24", "brown": "#adad27", "yellow": "#adad27",
    "blue": "#3b6fe0", "magenta": "#d338d3", "cyan": "#33bbc8", "white": "#cbcccd",
    "brightblack": "#818383", "brightred": "#fc391f", "brightgreen": "#31e722", "brightbrown": "#eaec23",
    "brightyellow": "#eaec23", "brightblue": "#5c8cff", "brightmagenta": "#f935f8", "brightcyan": "#14f0f0",
    "brightwhite": "#e9ebeb",
}
TERM_FG = "#e5edf8"; TERM_BG = "#10151d"; TERM_SEL = "#33507f"
ALT_SCREEN_MODES = (1049, 1047, 47)
DECCKM = 1 << 5                 # setas em "modo aplicação" (vim, less…)
BRACKETED_PASTE = 2004 << 5


class TermScreen(pyte.Screen):
    """Tela pyte com histórico de rolagem próprio e tela alternativa (nano, vim, top, less…)."""

    def __init__(self, columns, lines, send):
        super().__init__(columns, lines)
        self.scrollback = deque(maxlen=5000); self._send = send; self.alt = None

    def write_process_input(self, data):   # respostas do terminal (posição do cursor etc.)
        self._send(data)

    def select_graphic_rendition(self, *attrs, **kwargs):
        if kwargs.get("private"): return     # ex.: CSI ? 4 m do vim (consulta de teclado) — ignorar
        super().select_graphic_rendition(*attrs)

    def index(self):
        top, bottom = self.margins or (0, self.lines - 1)
        if self.alt is None and top == 0 and self.cursor.y == bottom:
            self.scrollback.append(self.buffer[top])
        super().index()

    def set_mode(self, *modes, **kwargs):
        if kwargs.get("private") and any(m in ALT_SCREEN_MODES for m in modes):
            if self.alt is None:
                self.alt = (copy.deepcopy(self.buffer), copy.copy(self.cursor))
                self.erase_in_display(2)
            modes = tuple(m for m in modes if m not in ALT_SCREEN_MODES)
            if not modes: return
        super().set_mode(*modes, **kwargs)

    def reset_mode(self, *modes, **kwargs):
        if kwargs.get("private") and any(m in ALT_SCREEN_MODES for m in modes):
            if self.alt is not None:
                buf, cur = self.alt; self.alt = None
                self.buffer.clear(); self.buffer.update(buf); self.cursor = cur
                self.cursor.x = min(self.cursor.x, self.columns - 1); self.cursor.y = min(self.cursor.y, self.lines - 1)
                self.dirty.update(range(self.lines))
            modes = tuple(m for m in modes if m not in ALT_SCREEN_MODES)
            if not modes: return
        super().reset_mode(*modes, **kwargs)


class TerminalWidget(QWidget):
    """Terminal de verdade: digita direto na tela, cores, setas, Ctrl+C, Tab, nano/vim/top, copiar/colar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.channel = None; self.ended = False
        self.setFocusPolicy(Qt.StrongFocus); self.setAttribute(Qt.WA_InputMethodEnabled, True)
        self.setAttribute(Qt.WA_OpaquePaintEvent, True); self.setCursor(Qt.IBeamCursor)
        self.font_size = 13; self._set_font()
        self.screen = TermScreen(100, 30, self.send)
        self.stream = pyte.ByteStream(self.screen)
        self.offset = 0                  # linhas roladas para cima no histórico
        self.sel_a = self.sel_b = None   # seleção: (linha_absoluta, coluna)
        self._repaint = QTimer(self); self._repaint.setSingleShot(True); self._repaint.timeout.connect(self.update)
        self._colors = {}
        self.setContextMenuPolicy(Qt.CustomContextMenu); self.customContextMenuRequested.connect(self._menu)

    # --- fonte / tamanho
    def _set_font(self):
        f = QFont("Menlo"); f.setStyleHint(QFont.Monospace); f.setPointSize(self.font_size); self.font_ = f
        self.font_bold = QFont(f); self.font_bold.setBold(True)
        fm = QFontMetricsF(f); self.cw = fm.horizontalAdvance("M"); self.ch = math.ceil(fm.height()); self.ascent = fm.ascent()

    def grid_size(self):
        return max(20, int((self.width() - 8) // self.cw)), max(5, int((self.height() - 4) // self.ch))

    def sizeHint(self): return QSize(int(self.cw * 100 + 8), int(self.ch * 30 + 4))

    def resizeEvent(self, e):
        cols, rows = self.grid_size()
        if (cols, rows) != (self.screen.columns, self.screen.lines):
            self.screen.resize(rows, cols)
            if self.channel is not None and not self.channel.closed:
                try: self.channel.resize_pty(width=cols, height=rows)
                except Exception: pass
        super().resizeEvent(e)

    def zoom(self, delta):
        self.font_size = max(9, min(28, self.font_size + delta)); self._set_font()
        self.resizeEvent(QResizeEvent(self.size(), self.size())); self.update()

    # --- canal SSH
    def attach(self, channel):
        self.channel = channel

    def send(self, data):
        if self.channel is None or self.ended: return
        if isinstance(data, str): data = data.encode("utf-8")
        try: self.channel.send(data)
        except Exception: pass

    def feed(self, data):
        try:
            self.stream.feed(data)
        except Exception:
            # código de controle que o emulador não conhece: descarta e segue (não derruba a sessão)
            self.stream = pyte.ByteStream(self.screen)
        if self.offset: self.offset = min(self.offset, len(self.screen.scrollback))
        if not self._repaint.isActive(): self._repaint.start(8)

    def session_ended(self):
        self.ended = True
        self.feed("\r\n\x1b[90m[Sessão encerrada — pode fechar a janela]\x1b[0m\r\n".encode())

    # --- linhas visíveis (histórico + tela)
    def _line(self, absolute):
        sb = self.screen.scrollback
        if absolute < len(sb): return sb[absolute]
        return self.screen.buffer[absolute - len(sb)]

    def _top_line(self): return len(self.screen.scrollback) - self.offset

    def _color(self, name, default):
        if name == "default": return QColor(default)
        c = self._colors.get(name)
        if c is None:
            c = QColor(TERM_COLORS[name]) if name in TERM_COLORS else QColor("#" + name) if len(name) == 6 else QColor(default)
            self._colors[name] = c
        return c

    def _sel_range(self):
        if not self.sel_a or not self.sel_b or self.sel_a == self.sel_b: return None
        return (self.sel_a, self.sel_b) if self.sel_a <= self.sel_b else (self.sel_b, self.sel_a)

    def paintEvent(self, e):
        p = QPainter(self); p.fillRect(self.rect(), QColor(TERM_BG))
        scr = self.screen; cols, rows = scr.columns, scr.lines
        top = self._top_line(); sel = self._sel_range(); X0, Y0 = 4.0, 2.0
        sel_color = QColor(TERM_SEL)
        for r in range(rows):
            line = self._line(top + r); y = Y0 + r * self.ch; absl = top + r
            run_text = ""; run_x = 0; run_style = None
            def flush():
                if run_text:
                    fg, bold = run_style
                    p.setFont(self.font_bold if bold else self.font_); p.setPen(fg)
                    p.drawText(QPointF(X0 + run_x * self.cw, y + self.ascent), run_text)
            for x in range(cols):
                ch = line[x]
                fg = self._color(ch.fg, TERM_FG); bg = self._color(ch.bg, TERM_BG)
                if ch.reverse: fg, bg = (bg if ch.bg != "default" else QColor(TERM_BG)), (fg if ch.fg != "default" else QColor(TERM_FG))
                in_sel = sel and sel[0] <= (absl, x) < sel[1]
                if in_sel: bg = sel_color
                if bg.name() != TERM_BG or in_sel:
                    p.fillRect(QRectF(X0 + x * self.cw, y, self.cw + 0.6, self.ch), bg)
                data = ch.data
                style = (fg, ch.bold)
                if data and len(data) == 1 and data.isascii() and data != " " and style == run_style and run_text:
                    run_text += data; continue
                flush(); run_text = ""; run_style = None
                if not data or data == " ": continue
                if data.isascii() and len(data) == 1:
                    run_text = data; run_x = x; run_style = style
                else:   # acentos, emoji, chinês: um por célula
                    p.setFont(self.font_bold if ch.bold else self.font_); p.setPen(fg)
                    p.drawText(QPointF(X0 + x * self.cw, y + self.ascent), data)
            flush()
        # cursor
        if self.offset == 0 and not scr.cursor.hidden and not self.ended:
            cx, cy = scr.cursor.x, scr.cursor.y
            rect = QRectF(X0 + cx * self.cw, Y0 + cy * self.ch, self.cw, self.ch)
            if self.hasFocus():
                p.fillRect(rect, QColor(TERM_FG))
                ch = scr.buffer[cy][cx]
                if ch.data.strip():
                    p.setPen(QColor(TERM_BG)); p.setFont(self.font_)
                    p.drawText(QPointF(rect.x(), rect.y() + self.ascent), ch.data)
            else:
                p.setPen(QColor(TERM_FG)); p.drawRect(rect.adjusted(0, 0, -1, -1))
        p.end()

    # --- teclado
    def focusNextPrevChild(self, nxt): return False      # Tab vai para o shell, não troca de campo

    def event(self, e):
        # deixa Tab/Shift+Tab chegarem ao keyPressEvent
        if e.type() == QEvent.KeyPress and e.key() in (Qt.Key_Tab, Qt.Key_Backtab):
            self.keyPressEvent(e); return True
        return super().event(e)

    def keyPressEvent(self, e):
        key, mods, text = e.key(), e.modifiers(), e.text()
        app_cursor = DECCKM in self.screen.mode
        if MOD_CMD is not None and mods & MOD_CMD:            # atalhos ⌘ (macOS)
            if key == Qt.Key_C: self.copy(); return
            if key == Qt.Key_V: self.paste(); return
            if key == Qt.Key_A: self.select_all(); return
            if key == Qt.Key_K: self.clear(); return
            if key in (Qt.Key_Plus, Qt.Key_Equal): self.zoom(1); return
            if key == Qt.Key_Minus: self.zoom(-1); return
            if key == Qt.Key_Left: self.send("\x01"); return    # início da linha
            if key == Qt.Key_Right: self.send("\x05"); return   # fim da linha
            if key == Qt.Key_Backspace: self.send("\x15"); return
            e.ignore(); return
        if not IS_MAC and mods & Qt.ControlModifier and mods & Qt.ShiftModifier:   # Ctrl+Shift+C/V (Linux)
            if key == Qt.Key_C: self.copy(); return
            if key == Qt.Key_V: self.paste(); return
        if mods & Qt.ShiftModifier and key in (Qt.Key_PageUp, Qt.Key_PageDown):
            self.scroll_lines(self.screen.lines - 1 if key == Qt.Key_PageUp else -(self.screen.lines - 1)); return

        seq = None
        if mods & MOD_CTRL:
            if Qt.Key_A <= key <= Qt.Key_Z: seq = chr(key - Qt.Key_A + 1)
            elif key in (Qt.Key_Space, Qt.Key_At, Qt.Key_2): seq = "\x00"
            elif key == Qt.Key_BracketLeft: seq = "\x1b"
            elif key == Qt.Key_Backslash: seq = "\x1c"
            elif key == Qt.Key_BracketRight: seq = "\x1d"
            elif key in (Qt.Key_Underscore, Qt.Key_Minus): seq = "\x1f"
        if seq is None:
            ss3 = "\x1bO" if app_cursor else "\x1b["
            alt = bool(mods & Qt.AltModifier)
            arrows = {Qt.Key_Up: "A", Qt.Key_Down: "B", Qt.Key_Right: "C", Qt.Key_Left: "D"}
            if key in arrows:
                if alt and key == Qt.Key_Left: seq = "\x1bb"          # ⌥← palavra anterior
                elif alt and key == Qt.Key_Right: seq = "\x1bf"       # ⌥→ próxima palavra
                else: seq = ss3 + arrows[key]
            else:
                seq = {
                    Qt.Key_Return: "\r", Qt.Key_Enter: "\r", Qt.Key_Backspace: "\x7f", Qt.Key_Tab: "\t",
                    Qt.Key_Backtab: "\x1b[Z", Qt.Key_Escape: "\x1b", Qt.Key_Delete: "\x1b[3~", Qt.Key_Insert: "\x1b[2~",
                    Qt.Key_Home: ss3 + "H", Qt.Key_End: ss3 + "F", Qt.Key_PageUp: "\x1b[5~", Qt.Key_PageDown: "\x1b[6~",
                    Qt.Key_F1: "\x1bOP", Qt.Key_F2: "\x1bOQ", Qt.Key_F3: "\x1bOR", Qt.Key_F4: "\x1bOS",
                    Qt.Key_F5: "\x1b[15~", Qt.Key_F6: "\x1b[17~", Qt.Key_F7: "\x1b[18~", Qt.Key_F8: "\x1b[19~",
                    Qt.Key_F9: "\x1b[20~", Qt.Key_F10: "\x1b[21~", Qt.Key_F11: "\x1b[23~", Qt.Key_F12: "\x1b[24~",
                }.get(key)
                if alt and key == Qt.Key_Backspace: seq = "\x1b\x7f"   # ⌥⌫ apaga palavra
        if seq is None and text: seq = text
        if seq:
            self.offset = 0; self.sel_a = self.sel_b = None
            self.send(seq); self.update()
        else:
            super().keyPressEvent(e)

    def inputMethodEvent(self, e):     # acentos com teclas mortas (´ + a = á) no teclado brasileiro
        if e.commitString(): self.offset = 0; self.send(e.commitString())
        e.accept()

    def inputMethodQuery(self, q):
        if q == Qt.ImCursorRectangle:
            return QRect(int(4 + self.screen.cursor.x * self.cw), int(2 + self.screen.cursor.y * self.ch), int(self.cw), self.ch)
        return super().inputMethodQuery(q)

    # --- rolagem
    def scroll_lines(self, n):
        self.offset = max(0, min(len(self.screen.scrollback), self.offset + n)); self.update()

    def wheelEvent(self, e):
        steps = int(e.angleDelta().y() / 40) or (1 if e.angleDelta().y() > 0 else -1 if e.angleDelta().y() < 0 else 0)
        if not steps: return
        if self.screen.alt is not None:      # dentro do nano/vim/less: rolar = setas
            ss3 = "\x1bO" if DECCKM in self.screen.mode else "\x1b["
            self.send((ss3 + ("A" if steps > 0 else "B")) * min(abs(steps), 10))
        else:
            self.scroll_lines(steps)

    # --- seleção / copiar / colar
    def _cell_at(self, pos):
        x = int((pos.x() - 4) // self.cw); y = int((pos.y() - 2) // self.ch)
        x = max(0, min(self.screen.columns, x)); y = max(0, min(self.screen.lines - 1, y))
        return (self._top_line() + y, x)

    def mousePressEvent(self, e):
        self.setFocus()
        if e.button() == Qt.LeftButton:
            self.sel_a = self.sel_b = self._cell_at(e.position()); self.update()

    def mouseMoveEvent(self, e):
        if e.buttons() & Qt.LeftButton and self.sel_a:
            self.sel_b = self._cell_at(e.position())
            if e.position().y() < 0: self.scroll_lines(1)
            elif e.position().y() > self.height(): self.scroll_lines(-1)
            self.update()

    def mouseDoubleClickEvent(self, e):
        line, x = self._cell_at(e.position()); row = self._line(line)
        isw = lambda c: c.data.strip() and (c.data.isalnum() or c.data in "-_./~:@")
        if x >= self.screen.columns or not isw(row[x]): return
        a = x; b = x
        while a > 0 and isw(row[a - 1]): a -= 1
        while b < self.screen.columns - 1 and isw(row[b + 1]): b += 1
        self.sel_a, self.sel_b = (line, a), (line, b + 1); self.update()

    def selected_text(self):
        rng = self._sel_range()
        if not rng: return ""
        (l1, c1), (l2, c2) = rng; out = []
        for l in range(l1, l2 + 1):
            row = self._line(l); start = c1 if l == l1 else 0; end = c2 if l == l2 else self.screen.columns
            out.append("".join(row[x].data for x in range(start, end)).rstrip())
        return "\n".join(out)

    def copy(self):
        t = self.selected_text()
        if t: QApplication.clipboard().setText(t)

    def paste(self):
        t = QApplication.clipboard().text()
        if not t: return
        t = t.replace("\r\n", "\n").replace("\n", "\r")
        if BRACKETED_PASTE in self.screen.mode: t = "\x1b[200~" + t + "\x1b[201~"
        self.offset = 0; self.send(t)

    def select_all(self):
        self.sel_a = (0, 0); self.sel_b = (len(self.screen.scrollback) + self.screen.lines - 1, self.screen.columns); self.update()

    def clear(self):
        self.screen.scrollback.clear(); self.offset = 0; self.sel_a = self.sel_b = None
        self.send("\x0c")   # Ctrl+L: o shell redesenha o prompt no topo

    def _menu(self, pos):
        m = QMenu(self)
        a = m.addAction("Copiar", self.copy); a.setEnabled(bool(self._sel_range()))
        m.addAction("Colar", self.paste); m.addSeparator()
        m.addAction("Selecionar tudo", self.select_all); m.addAction("Limpar", self.clear)
        m.addSeparator(); m.addAction("Aumentar fonte", lambda: self.zoom(1)); m.addAction("Diminuir fonte", lambda: self.zoom(-1))
        m.exec(self.mapToGlobal(pos))

    def focusInEvent(self, e): self.update(); super().focusInEvent(e)
    def focusOutEvent(self, e): self.update(); super().focusOutEvent(e)


class TerminalDialog(QDialog):
    def __init__(self, ssh, title, parent=None):
        super().__init__(parent); self.setWindowTitle(f"Console SSH — {title}")
        self.setAttribute(Qt.WA_DeleteOnClose); self.channel = None; self.reader = None
        self.setWindowFlag(Qt.WindowMaximizeButtonHint, True)
        layout = QVBoxLayout(self); layout.setContentsMargins(0, 0, 0, 0)
        self.term = TerminalWidget(self); layout.addWidget(self.term)
        self.setStyleSheet(f"QDialog {{ background: {TERM_BG}; }}")
        self.resize(self.term.sizeHint())
        if IS_MAC:
            act = QAction(self); act.setShortcut(QKeySequence("Ctrl+W")); act.triggered.connect(self.close); self.addAction(act)
        try:
            cols, rows = 100, 30
            self.channel = ssh.invoke_shell(term='xterm-256color', width=cols, height=rows)
            self.channel.settimeout(0.0); self.term.attach(self.channel)
            self.reader = TerminalReader(self.channel)
            self.reader.output.connect(self.term.feed); self.reader.closed.connect(self.close)   # exit → fecha a janela
            self.reader.start()
        except Exception as e:
            self.term.feed(f"Não foi possível abrir o console: {e}\r\n".encode())
        QTimer.singleShot(0, self.term.setFocus)

    def showEvent(self, e):
        super().showEvent(e); QTimer.singleShot(0, lambda: self.term.resizeEvent(QResizeEvent(self.term.size(), self.term.size())))

    def keyPressEvent(self, e):
        # Esc não fecha a janela: vai para o terminal
        if e.key() == Qt.Key_Escape: self.term.keyPressEvent(e); return
        super().keyPressEvent(e)

    def closeEvent(self, event):
        try:
            if self.reader: self.reader.stop(); self.reader.wait(1000)
            if self.channel: self.channel.close()
        except Exception: pass
        event.accept()


# ============================================================================= transferência em segundo plano

class Cancelled(Exception):
    pass


class TransferWorker(QThread):
    """Faz upload/download num canal SFTP próprio, sem travar a janela. Pode ser cancelado."""
    progress = Signal(object, object, str)     # bytes feitos, bytes totais, arquivo atual
    finished_ok = Signal(bool, str, int)       # sucesso, mensagem, nº de arquivos

    def __init__(self, ssh, jobs):
        super().__init__(); self.ssh = ssh; self.jobs = jobs   # [(direção 'up'|'down', origem, destino)]
        self._cancel = False; self.done_bytes = 0; self.total = 0; self._last_emit = 0; self.files_done = 0

    def cancel(self): self._cancel = True

    def _check(self):
        if self._cancel: raise Cancelled()

    def _emit(self, name, force=False):
        now = time.monotonic()
        if force or now - self._last_emit > 0.1:
            self._last_emit = now; self.progress.emit(self.done_bytes, self.total, name)

    # --- monta a lista de passos e calcula o total de bytes
    def _plan_up(self, src, dst, plan):
        self._check()
        if os.path.islink(src): return
        if os.path.isdir(src):
            plan.append(('rmkdir', src, dst, 0))
            for n in sorted(os.listdir(src)): self._plan_up(os.path.join(src, n), posixpath.join(dst, n), plan)
        elif os.path.isfile(src):
            plan.append(('put', src, dst, os.path.getsize(src)))

    def _plan_down(self, sftp, src, dst, plan):
        self._check()
        st = sftp.lstat(src)
        if stat.S_ISLNK(st.st_mode): return
        if stat.S_ISDIR(st.st_mode):
            plan.append(('lmkdir', src, dst, 0))
            for a in sorted(sftp.listdir_attr(src), key=lambda a: a.filename):
                self._plan_down(sftp, posixpath.join(src, a.filename), os.path.join(dst, a.filename), plan)
        elif stat.S_ISREG(st.st_mode):
            plan.append(('get', src, dst, st.st_size or 0))

    def run(self):
        sftp = None; partial = None
        try:
            sftp = self.ssh.open_sftp()
            self.progress.emit(0, 0, "Analisando arquivos…")
            plan = []
            for direction, src, dst in self.jobs:
                if direction == 'up': self._plan_up(src, dst, plan)
                else: self._plan_down(sftp, src, dst, plan)
            self.total = sum(p[3] for p in plan)

            for kind, src, dst, size in plan:
                self._check()
                if kind == 'rmkdir':
                    try: sftp.mkdir(dst)
                    except IOError:
                        if not stat.S_ISDIR(sftp.stat(dst).st_mode):
                            raise RuntimeError(f"O destino já existe e não é pasta: {dst}")
                elif kind == 'lmkdir':
                    os.makedirs(dst, exist_ok=True)
                else:
                    base = self.done_bytes; name = os.path.basename(src)
                    def cb(sent, _total, base=base, name=name):
                        if self._cancel: raise Cancelled()
                        self.done_bytes = base + sent; self._emit(name)
                    self._emit(name, force=True)
                    partial = (kind, dst)
                    if kind == 'put': sftp.put(src, dst, callback=cb)
                    else:
                        os.makedirs(os.path.dirname(dst) or '.', exist_ok=True); sftp.get(src, dst, callback=cb)
                    partial = None
                    self.done_bytes = base + size; self.files_done += 1; self._emit(name, force=True)
            self.finished_ok.emit(True, "Transferência concluída", self.files_done)
        except Cancelled:
            self._remove_partial(sftp, partial)
            self.finished_ok.emit(False, "Transferência cancelada", self.files_done)
        except Exception as e:
            self._remove_partial(sftp, partial)
            self.finished_ok.emit(False, f"Erro: {e}", self.files_done)
        finally:
            try:
                if sftp: sftp.close()
            except Exception: pass

    @staticmethod
    def _remove_partial(sftp, partial):
        """Apaga o arquivo que ficou pela metade."""
        if not partial: return
        kind, dst = partial
        try:
            if kind == 'put' and sftp: sftp.remove(dst)
            elif kind == 'get' and os.path.exists(dst): os.remove(dst)
        except Exception: pass


class TransferDialog(QDialog):
    """Janela de progresso (não bloqueia o app) com botão Cancelar."""

    def __init__(self, title, worker, on_finish, parent=None):
        super().__init__(parent); self.setWindowTitle(title); self.setMinimumWidth(460)
        self.setAttribute(Qt.WA_DeleteOnClose); self.worker = worker; self.on_finish = on_finish
        self.started = time.monotonic(); self.finished = False
        lay = QVBoxLayout(self)
        self.file_label = QLabel("Preparando…"); self.file_label.setWordWrap(True)
        self.bar = QProgressBar(); self.bar.setRange(0, 0)
        self.info = QLabel("")
        self.cancel_btn = QPushButton("Cancelar"); self.cancel_btn.clicked.connect(self.cancel)
        bl = QHBoxLayout(); bl.addStretch(1); bl.addWidget(self.cancel_btn)
        lay.addWidget(self.file_label); lay.addWidget(self.bar); lay.addWidget(self.info); lay.addLayout(bl)
        worker.progress.connect(self._progress); worker.finished_ok.connect(self._done)

    def _progress(self, done, total, name):
        self.file_label.setText(name)
        if total:
            self.bar.setRange(0, 1000); self.bar.setValue(int(done * 1000 / total))
            el = max(time.monotonic() - self.started, 0.001); speed = done / el
            eta = (total - done) / speed if speed > 0 else 0
            self.info.setText(f"{human_size(done)} de {human_size(total)}  •  {human_size(speed)}/s  •  "
                              f"faltam ~{int(eta // 60)}min {int(eta % 60)}s")

    def cancel(self):
        if self.finished: self.close(); return
        self.cancel_btn.setEnabled(False); self.cancel_btn.setText("Cancelando…"); self.worker.cancel()

    def _done(self, ok, msg, count):
        self.finished = True
        self.on_finish(ok, msg, count)
        self.close()

    def closeEvent(self, e):
        if not self.finished:
            self.worker.cancel(); self.cancel_btn.setText("Cancelando…"); e.ignore(); return
        e.accept()


# ============================================================================= editor de texto

EDIT_MAX_BYTES = 10 * 1024 * 1024     # acima disso pergunta antes de abrir


def decode_text(data):
    """Retorna (texto, codificação, fim_de_linha, tem_bom) ou None se parecer binário."""
    if b"\0" in data[:65536]:
        return None
    bom = data.startswith(b"\xef\xbb\xbf")
    raw = data[3:] if bom else data
    try:
        text, enc = raw.decode("utf-8"), "UTF-8"
    except UnicodeDecodeError:
        text, enc = raw.decode("latin-1"), "Latin-1"
    eol = "\r\n" if "\r\n" in text else ("\r" if "\r" in text and "\n" not in text else "\n")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text, enc, eol, bom


def encode_text(text, enc, eol, bom):
    if eol != "\n": text = text.replace("\n", eol)
    data = text.encode("utf-8" if enc == "UTF-8" else "latin-1", errors="replace")
    return (b"\xef\xbb\xbf" + data) if bom else data


class LineNumberArea(QWidget):
    def __init__(self, editor): super().__init__(editor); self.editor = editor
    def sizeHint(self): return QSize(self.editor.number_width(), 0)
    def paintEvent(self, e): self.editor.paint_numbers(e)


class CodeEdit(QPlainTextEdit):
    """QPlainTextEdit com números de linha."""

    def __init__(self):
        super().__init__()
        f = QFont("Menlo"); f.setStyleHint(QFont.Monospace); f.setPointSize(13); self.setFont(f)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.setTabStopDistance(self.fontMetrics().horizontalAdvance(" ") * 4)
        self.numbers = LineNumberArea(self)
        self.blockCountChanged.connect(lambda _: self.setViewportMargins(self.number_width(), 0, 0, 0))
        self.updateRequest.connect(self._update_numbers)
        self.setViewportMargins(self.number_width(), 0, 0, 0)

    def number_width(self):
        digits = max(3, len(str(self.blockCount())))
        return 14 + self.fontMetrics().horizontalAdvance("9") * digits

    def _update_numbers(self, rect, dy):
        if dy: self.numbers.scroll(0, dy)
        else: self.numbers.update(0, rect.y(), self.numbers.width(), rect.height())

    def resizeEvent(self, e):
        super().resizeEvent(e); cr = self.contentsRect()
        self.numbers.setGeometry(QRect(cr.left(), cr.top(), self.number_width(), cr.height()))

    def paint_numbers(self, event):
        p = QPainter(self.numbers); pal = self.palette()
        p.fillRect(event.rect(), pal.color(QPalette.AlternateBase))
        p.setPen(pal.color(QPalette.PlaceholderText))
        block = self.firstVisibleBlock(); n = block.blockNumber()
        top = round(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + round(self.blockBoundingRect(block).height())
        h = self.fontMetrics().height(); w = self.numbers.width() - 6
        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                p.drawText(0, top, w, h, Qt.AlignRight, str(n + 1))
            block = block.next(); top = bottom
            bottom = top + round(self.blockBoundingRect(block).height()); n += 1
        p.end()


class EditorWindow(QMainWindow):
    """Janela de edição de um arquivo (local ou no servidor). ⌘S salva, ⌘F busca."""

    def __init__(self, session, side, path, data, mtime):
        super().__init__(session.main); self.setAttribute(Qt.WA_DeleteOnClose)
        self.session = session; self.side = side; self.path = path; self.mtime = mtime
        decoded = decode_text(data)
        self.text0, self.enc, self.eol, self.bom = decoded
        self.resize(980, 680)

        central = QWidget(); lay = QVBoxLayout(central); lay.setContentsMargins(0, 0, 0, 0); lay.setSpacing(0)
        self.edit = CodeEdit(); self.edit.setPlainText(self.text0); self.edit.document().setModified(False)
        lay.addWidget(self.edit, 1)

        # barra de busca (⌘F)
        self.find_bar = QWidget(); fl = QHBoxLayout(self.find_bar); fl.setContentsMargins(8, 4, 8, 4)
        self.find_input = QLineEdit(); self.find_input.setPlaceholderText("Buscar…  (Enter = próximo, ⇧Enter = anterior)")
        self.find_case = QCheckBox("Aa"); self.find_case.setToolTip("Diferenciar maiúsculas/minúsculas")
        fl.addWidget(QLabel("Buscar:")); fl.addWidget(self.find_input, 1); fl.addWidget(self.find_case)
        for text, back in (("◀", True), ("▶", False)):
            b = QPushButton(text); b.setFixedWidth(36); b.clicked.connect(lambda _=False, back=back: self.find(back)); fl.addWidget(b)
        close = QPushButton("✕"); close.setFixedWidth(30); close.clicked.connect(self.find_bar.hide); fl.addWidget(close)
        self.find_input.returnPressed.connect(lambda: self.find(bool(QApplication.keyboardModifiers() & Qt.ShiftModifier)))
        self.find_bar.hide(); lay.addWidget(self.find_bar)
        self.setCentralWidget(central)

        where = session.title if side == "remote" else "Computador local"
        self.pos_label = QLabel(); self.statusBar().addPermanentWidget(self.pos_label)
        eol_name = {"\n": "LF (Unix)", "\r\n": "CRLF (Windows)", "\r": "CR"}[self.eol]
        self.statusBar().showMessage(f"{where}  •  {self.enc}{' com BOM' if self.bom else ''}  •  {eol_name}")
        self.edit.cursorPositionChanged.connect(self._update_pos); self._update_pos()
        self.edit.document().modificationChanged.connect(self._update_title); self._update_title(False)

        for keys, slot in (("Ctrl+S", self.save), ("Ctrl+F", self.show_find), ("Ctrl+W", self.close),
                           ("Ctrl+G", lambda: self.find(False)), ("Ctrl+Shift+G", lambda: self.find(True)),
                           ("Escape", self.find_bar.hide)):
            act = QAction(self); act.setShortcut(QKeySequence(keys)); act.triggered.connect(slot); self.addAction(act)

    def _update_title(self, modified):
        name = posixpath.basename(self.path)
        where = f"{self.session.title}:" if self.side == "remote" else ""
        # [*] = indicador nativo de "não salvo" (bolinha no botão vermelho no macOS)
        self.setWindowTitle(f"{name}[*] — {where}{self.path}")
        self.setWindowModified(modified)

    def _update_pos(self):
        c = self.edit.textCursor()
        self.pos_label.setText(f"Linha {c.blockNumber() + 1}, Coluna {c.positionInBlock() + 1}  ")

    def show_find(self):
        self.find_bar.show()
        sel = self.edit.textCursor().selectedText()
        if sel and " " not in sel: self.find_input.setText(sel)
        self.find_input.setFocus(); self.find_input.selectAll()

    def find(self, backward=False):
        text = self.find_input.text()
        if not text: self.show_find(); return
        flags = QTextDocument.FindFlag(0)
        if backward: flags |= QTextDocument.FindBackward
        if self.find_case.isChecked(): flags |= QTextDocument.FindCaseSensitively
        if not self.edit.find(text, flags):            # dá a volta no arquivo
            c = self.edit.textCursor(); c.movePosition(QTextCursor.End if backward else QTextCursor.Start)
            self.edit.setTextCursor(c)
            if not self.edit.find(text, flags):
                self.statusBar().showMessage(f"“{text}” não encontrado", 3000)

    # --- salvar
    def save(self):
        data = encode_text(self.edit.toPlainText(), self.enc, self.eol, self.bom)
        try:
            if self.side == "local":
                cur = os.stat(self.path).st_mtime if os.path.exists(self.path) else None
                if not self._confirm_conflict(cur): return False
                with open(self.path, "wb") as f: f.write(data)
                self.mtime = os.stat(self.path).st_mtime
            else:
                sftp = self.session.sftp
                if sftp is None: raise RuntimeError("A conexão com o servidor foi encerrada. Reconecte para salvar.")
                try: cur = sftp.stat(self.path).st_mtime
                except IOError: cur = None
                if not self._confirm_conflict(cur): return False
                QApplication.setOverrideCursor(Qt.WaitCursor)
                try:
                    # grava no próprio arquivo (mantém dono, permissões e links); se falhar no meio, tenta restaurar
                    try:
                        with sftp.open(self.path, "rb") as f: backup = f.read()
                    except IOError:
                        backup = None
                    try:
                        with sftp.open(self.path, "wb") as f: f.set_pipelined(True); f.write(data)
                    except Exception:
                        if backup is not None:
                            try:
                                with sftp.open(self.path, "wb") as f: f.write(backup)
                            except Exception: pass
                        raise
                    self.mtime = sftp.stat(self.path).st_mtime
                finally:
                    QApplication.restoreOverrideCursor()
        except PermissionError:
            QMessageBox.critical(self, "Sem permissão", f"Seu usuário não tem permissão para gravar em:\n{self.path}")
            return False
        except Exception as e:
            msg = str(e)
            if "permission" in msg.lower() or getattr(e, "errno", None) == errno.EACCES:
                msg = f"Seu usuário não tem permissão para gravar em:\n{self.path}"
            QMessageBox.critical(self, "Não foi possível salvar", msg)
            return False
        self.edit.document().setModified(False)
        self.statusBar().showMessage(f"Salvo às {time.strftime('%H:%M:%S')}  •  {human_size(len(data))}", 5000)
        if self.side == "remote": self.session.load_remote(select=posixpath.basename(self.path))
        else: self.session.load_local(select=os.path.basename(self.path))
        return True

    def _confirm_conflict(self, current_mtime):
        if current_mtime is None or self.mtime is None or int(current_mtime) == int(self.mtime): return True
        return QMessageBox.warning(
            self, "Arquivo alterado por fora",
            "Este arquivo foi modificado depois que você o abriu (por outra pessoa ou programa).\n\n"
            "Salvar mesmo assim e sobrescrever essas alterações?",
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel) == QMessageBox.Yes

    def closeEvent(self, e):
        if self.edit.document().isModified():
            r = QMessageBox.question(self, "Alterações não salvas",
                                     f"Salvar as alterações em “{posixpath.basename(self.path)}”?",
                                     QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel, QMessageBox.Save)
            if r == QMessageBox.Cancel or (r == QMessageBox.Save and not self.save()):
                e.ignore(); return
        if self in self.session.editors: self.session.editors.remove(self)
        e.accept()


# ============================================================================= permissões (chmod)

class PermissionsDialog(QDialog):
    """Caixinhas Ler/Gravar/Executar para Dono/Grupo/Outros + número octal (ex.: 644, 755)."""
    BITS = [[stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR],
            [stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP],
            [stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH]]

    def __init__(self, names, mode, owner_info="", parent=None):
        super().__init__(parent); self.setWindowTitle("Permissões"); self.setMinimumWidth(380)
        self.special = mode & 0o7000          # setuid/setgid/sticky: preservados
        lay = QVBoxLayout(self)
        title = names[0] if len(names) == 1 else f"{len(names)} arquivos"
        head = QLabel(f"<b>{title}</b>" + (f"<br><span style='color:gray'>{owner_info}</span>" if owner_info else ""))
        head.setTextFormat(Qt.RichText); lay.addWidget(head)

        grid = QGridLayout(); grid.setHorizontalSpacing(18)
        for c, t in enumerate(("Ler", "Gravar", "Executar")): grid.addWidget(QLabel(f"<b>{t}</b>"), 0, c + 1, Qt.AlignCenter)
        self.boxes = []
        for r, who in enumerate(("Dono", "Grupo", "Outros")):
            grid.addWidget(QLabel(who), r + 1, 0)
            row = []
            for c in range(3):
                cb = QCheckBox(); cb.setChecked(bool(mode & self.BITS[r][c])); cb.toggled.connect(self._boxes_changed)
                grid.addWidget(cb, r + 1, c + 1, Qt.AlignCenter); row.append(cb)
            self.boxes.append(row)
        lay.addLayout(grid)

        ol = QHBoxLayout(); ol.addWidget(QLabel("Octal:"))
        self.octal = QLineEdit(); self.octal.setMaxLength(4); self.octal.setFixedWidth(70)
        self.octal.setValidator(QRegularExpressionValidator(QRegularExpression("[0-7]{3,4}")))
        self.octal.textEdited.connect(self._octal_changed); ol.addWidget(self.octal)
        self.preview = QLabel(); self.preview.setStyleSheet("font-family: Menlo, monospace; color: gray")
        ol.addWidget(self.preview); ol.addStretch(1); lay.addLayout(ol)

        quick = QHBoxLayout(); quick.addWidget(QLabel("Rápido:"))
        for m, tip in ((0o644, "arquivo comum"), (0o755, "script/executável"), (0o600, "privado"), (0o664, "grupo grava")):
            b = QPushButton(f"{m:o}"); b.setToolTip(tip); b.clicked.connect(lambda _=False, m=m: self.set_mode(m)); quick.addWidget(b)
        quick.addStretch(1); lay.addLayout(quick)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Aplicar")
        buttons.accepted.connect(self.accept); buttons.rejected.connect(self.reject); lay.addWidget(buttons)
        self._sync_text()

    def mode(self):
        m = self.special
        for r in range(3):
            for c in range(3):
                if self.boxes[r][c].isChecked(): m |= self.BITS[r][c]
        return m

    def set_mode(self, m):
        self.special = m & 0o7000
        for r in range(3):
            for c in range(3):
                self.boxes[r][c].blockSignals(True); self.boxes[r][c].setChecked(bool(m & self.BITS[r][c]))
                self.boxes[r][c].blockSignals(False)
        self._sync_text()

    def _boxes_changed(self, *_): self._sync_text()

    def _sync_text(self):
        m = self.mode()
        self.octal.setText(f"{m:04o}" if self.special else f"{m:03o}")
        self.preview.setText(stat.filemode(stat.S_IFREG | m)[1:])

    def _octal_changed(self, text):
        if len(text) >= 3:
            try: m = int(text, 8)
            except ValueError: return
            pos = self.octal.cursorPosition(); self.set_mode(m)
            self.octal.setText(text); self.octal.setCursorPosition(pos)


# ============================================================================= árvore de arquivos

class FileTree(QTreeWidget):
    """Painel com arrastar/soltar (inclusive em cima de pastas) e menu de contexto."""

    def __init__(self, side, session):
        super().__init__(); self.side = side; self.session = session; self._hover = None
        self.setColumnCount(3); self.setHeaderLabels(["Nome", "Tamanho", "Modificado"])
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setDragEnabled(True); self.setAcceptDrops(True); self.viewport().setAcceptDrops(True)
        self.setDropIndicatorShown(False); self.setDefaultDropAction(Qt.CopyAction)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(lambda pos: session.show_context_menu(self.side, pos))
        self.itemDoubleClicked.connect(lambda item, col: session.open_item(self.side, item))
        self.setColumnWidth(0, 300); self.setIconSize(QSize(18, 18))

    def selected_paths(self):
        return [it.data(0, PATH_ROLE) for it in self.selectedItems() if it.data(0, PATH_ROLE)]

    def _set_hover(self, item):
        if self._hover is item: return
        if self._hover is not None:
            try:
                for c in range(self.columnCount()): self._hover.setBackground(c, QBrush())
            except RuntimeError: pass
        self._hover = item
        if item is not None:
            for c in range(self.columnCount()): item.setBackground(c, HOVER_BRUSH)

    def startDrag(self, supported):
        paths = self.selected_paths()
        if not paths: return
        mime = QMimeData()
        mime.setData(MIME_PATHS, json.dumps({"session": id(self.session), "side": self.side, "paths": paths}).encode())
        if self.side == 'local': mime.setUrls([QUrl.fromLocalFile(p) for p in paths])
        drag = QDrag(self); drag.setMimeData(mime); drag.exec(Qt.CopyAction)

    @staticmethod
    def parse_mime(mime):
        """Retorna (sessão, lado_origem, [caminhos])."""
        if mime.hasFormat(MIME_PATHS):
            try:
                d = json.loads(bytes(mime.data(MIME_PATHS)).decode())
                return d.get("session"), d.get("side"), list(d.get("paths") or [])
            except Exception:
                return None, None, []
        if mime.hasUrls():
            paths = [u.toLocalFile() for u in mime.urls() if u.isLocalFile()]
            return None, ('finder' if paths else None), paths
        return None, None, []

    def _drop_target(self, event):
        sess, src, paths = self.parse_mime(event.mimeData())
        if not paths: return None
        if src == 'remote' and sess != id(self.session): return None   # remoto de outra aba
        item = self.itemAt(event.position().toPoint())
        folder = item if item is not None and item.data(0, ISDIR_ROLE) else None
        if folder is not None and folder.data(0, PATH_ROLE) in paths: folder = None
        if src == self.side and folder is None: return None            # mover no mesmo painel só em cima de pasta
        if self.side == 'remote' and not self.session.sftp: return None
        dest = folder.data(0, PATH_ROLE) if folder is not None else self.session.current_dir(self.side)
        return src, paths, dest, folder

    def dragEnterEvent(self, e):
        if self.parse_mime(e.mimeData())[2]: e.setDropAction(Qt.CopyAction); e.accept()
        else: e.ignore()

    def dragMoveEvent(self, e):
        t = self._drop_target(e)
        if t is None: self._set_hover(None); e.ignore(); return
        self._set_hover(t[3]); e.setDropAction(Qt.CopyAction); e.accept()

    def dragLeaveEvent(self, e):
        self._set_hover(None); super().dragLeaveEvent(e)

    def dropEvent(self, e):
        t = self._drop_target(e); self._set_hover(None)
        if t is None: e.ignore(); return
        src, paths, dest, _ = t
        e.setDropAction(Qt.CopyAction); e.accept()
        QTimer.singleShot(0, lambda: self.session.handle_drop(src, paths, self.side, dest))

    def keyPressEvent(self, e):
        if e.key() in (Qt.Key_Delete, Qt.Key_Backspace):
            self.session.delete_selected(self.side); return
        if e.key() in (Qt.Key_Return, Qt.Key_Enter) and self.currentItem():
            self.session.open_item(self.side, self.currentItem()); return
        super().keyPressEvent(e)


# ============================================================================= sessão (uma aba = um servidor)

class Session(QWidget):
    title_changed = Signal(object, str)

    def __init__(self, main):
        super().__init__(); self.main = main
        self.ssh = None; self.sftp = None; self.title = "Sem conexão"
        self.remote_path = '.'; self.local_path = str(Path.home()); self.transfers = []; self.editors = []
        layout = QVBoxLayout(self); layout.setContentsMargins(4, 4, 4, 4)
        split = QSplitter(Qt.Horizontal); layout.addWidget(split, 1)

        left = QWidget(); ll = QVBoxLayout(left); ll.setContentsMargins(0, 0, 0, 0); lh = QHBoxLayout()
        lh.addWidget(QLabel("<b>Computador local</b>"), 1)
        lh.addWidget(self._btn("Escolher pasta", self.choose_local))
        lh.addWidget(self._btn("＋ Nova pasta", lambda: self.create_folder('local'), "Criar pasta (⇧⌘N)"))
        lh.addWidget(self._btn("Excluir", lambda: self.delete_selected('local'), "Excluir selecionados (⌫)"))
        lh.addWidget(self._btn("↑", self.local_up, "Pasta acima"))
        ll.addLayout(lh)
        self.local_label = QLabel(self.local_path); self.local_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        ll.addWidget(self.local_label)
        self.local_tree = FileTree('local', self); ll.addWidget(self.local_tree, 1); split.addWidget(left)

        right = QWidget(); rl = QVBoxLayout(right); rl.setContentsMargins(0, 0, 0, 0); rh = QHBoxLayout()
        self.remote_title = QLabel("<b>Servidor remoto</b>"); rh.addWidget(self.remote_title, 1)
        rh.addWidget(self._btn("＋ Nova pasta", lambda: self.create_folder('remote'), "Criar pasta no servidor"))
        rh.addWidget(self._btn("Excluir", lambda: self.delete_selected('remote'), "Excluir selecionados no servidor (⌫)"))
        rh.addWidget(self._btn("↑", self.remote_up, "Pasta acima"))
        rl.addLayout(rh)
        self.remote_label = QLabel("Não conectado — use “Nova conexão” ou “Favoritos”")
        self.remote_label.setTextInteractionFlags(Qt.TextSelectableByMouse); rl.addWidget(self.remote_label)
        self.remote_tree = FileTree('remote', self); rl.addWidget(self.remote_tree, 1); split.addWidget(right)
        split.setSizes([560, 560])
        self.load_local()

    def _btn(self, text, slot, tip=None):
        b = QPushButton(text); b.clicked.connect(slot)
        if tip: b.setToolTip(tip)
        return b

    def status(self, msg): self.main.statusBar().showMessage(msg)
    def tree(self, side): return self.local_tree if side == 'local' else self.remote_tree
    def current_dir(self, side): return self.local_path if side == 'local' else self.remote_path
    def focused_side(self): return 'remote' if self.remote_tree.hasFocus() else 'local'
    @property
    def connected(self): return self.sftp is not None

    def require_remote(self):
        if not self.sftp:
            QMessageBox.warning(self, "Sem conexão", "Esta aba não está conectada a um servidor."); return False
        return True

    # ------------------------------------------------------------------ conexão
    def connect_to(self, host, port, user, password, title=None, remote_dir="", local_dir=""):
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            client = open_ssh(self, host, port, user, password)
            sftp = client.open_sftp()
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, "Falha na conexão",
                                 f"Não foi possível conectar em {host}.\n\n{e}")
            return False
        QApplication.restoreOverrideCursor()
        self.ssh = client; self.sftp = sftp
        self.remote_path = sftp.normalize('.')
        if remote_dir:
            try:
                if stat.S_ISDIR(sftp.stat(remote_dir).st_mode): self.remote_path = sftp.normalize(remote_dir)
            except IOError:
                self.status(f"Pasta remota inicial não encontrada: {remote_dir}")
        if local_dir and os.path.isdir(local_dir): self.local_path = local_dir; self.load_local()
        self.title = title or f"{user}@{host}"
        self.remote_title.setText(f"<b>Servidor:</b> {user}@{host}:{port}")
        self.title_changed.emit(self, self.title); self.load_remote()
        self.status(f"Conectado a {user}@{host}:{port}")
        return True

    def disconnect(self, ask=True):
        if not self.close_editors(remote_only=True): return False
        running = [t for t in self.transfers if t.isRunning()]
        if running:
            if ask and QMessageBox.question(self, "Transferências em andamento",
                                            f"Há {len(running)} transferência(s) em andamento nesta conexão. Cancelar e desconectar?",
                                            QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return False
            for t in running: t.cancel()
            for t in running: t.wait(5000)
        try:
            if self.sftp: self.sftp.close()
            if self.ssh: self.ssh.close()
        except Exception: pass
        self.sftp = self.ssh = None; self.title = "Sem conexão"
        self.remote_title.setText("<b>Servidor remoto</b>")
        self.remote_label.setText("Não conectado"); self.remote_tree.clear()
        self.title_changed.emit(self, self.title)
        return True

    def open_console(self):
        if not self.ssh: QMessageBox.information(self, "Console SSH", "Esta aba não está conectada."); return
        TerminalDialog(self.ssh, self.title, self.main).show()

    # ------------------------------------------------------------------ listagem / navegação
    def choose_local(self):
        path = QFileDialog.getExistingDirectory(self, "Escolher pasta local", self.local_path)
        if path: self.local_path = path; self.load_local()

    def _add_row(self, tree, name, path, isdir, size, extra):
        row = QTreeWidgetItem([name, size, extra])
        icons = Icons.get()
        row.setIcon(0, icons.local(path, isdir) if tree.side == 'local' else icons.remote(name, isdir))
        row.setData(0, PATH_ROLE, path); row.setData(0, ISDIR_ROLE, isdir)
        if isdir: row.setToolTip(0, "Solte arquivos aqui para colocá-los dentro desta pasta")
        tree.addTopLevelItem(row); return row

    def load_local(self, select=None):
        self.local_label.setText(self.local_path); self.local_tree.clear()
        try: items = sorted(os.scandir(self.local_path), key=lambda x: (not x.is_dir(follow_symlinks=False), x.name.lower()))
        except Exception as e: self.status(f"Erro ao listar pasta local: {e}"); return
        for ent in items:
            try:
                isdir = ent.is_dir(follow_symlinks=False); st = ent.stat(follow_symlinks=False)
                row = self._add_row(self.local_tree, ent.name, ent.path, isdir, '' if isdir else human_size(st.st_size),
                                    time.strftime('%d/%m/%Y %H:%M', time.localtime(st.st_mtime)))
                if select and ent.name == select: self.local_tree.setCurrentItem(row)
            except OSError: pass

    def load_remote(self, select=None):
        self.remote_tree.clear()
        if not self.sftp: return
        self.remote_label.setText(self.remote_path)
        try: attrs = sorted(self.sftp.listdir_attr(self.remote_path), key=lambda a: (not stat.S_ISDIR(a.st_mode or 0), a.filename.lower()))
        except Exception as e: self.status(f"Erro ao listar servidor: {e}"); return
        for a in attrs:
            mode = a.st_mode or 0; isdir = stat.S_ISDIR(mode)
            mt = time.strftime('%d/%m/%Y %H:%M', time.localtime(a.st_mtime)) if a.st_mtime else ''
            row = self._add_row(self.remote_tree, a.filename, posixpath.join(self.remote_path, a.filename), isdir,
                                '' if isdir else human_size(a.st_size or 0), f"{mt}  {stat.filemode(mode)}".strip())
            if select and a.filename == select: self.remote_tree.setCurrentItem(row)

    def refresh(self): self.load_local(); self.load_remote()

    def open_item(self, side, item):
        path = item.data(0, PATH_ROLE)
        if not item.data(0, ISDIR_ROLE):
            self.edit_file(side, path); return
        if side == 'local': self.local_path = path; self.load_local()
        elif self.sftp: self.remote_path = path; self.load_remote()

    def local_up(self):
        parent = os.path.dirname(self.local_path.rstrip(os.sep)) or os.sep
        if parent != self.local_path: self.local_path = parent; self.load_local()

    def remote_up(self):
        if self.sftp and self.remote_path != '/':
            self.remote_path = posixpath.dirname(self.remote_path.rstrip('/')) or '/'; self.load_remote()

    # ------------------------------------------------------------------ menu de contexto
    def show_context_menu(self, side, pos):
        tree = self.tree(side); item = tree.itemAt(pos)
        if item is not None and not item.isSelected():
            tree.clearSelection(); item.setSelected(True); tree.setCurrentItem(item)
        if item is None: tree.clearSelection()
        sel = tree.selectedItems(); menu = QMenu(self)
        remote_ok = side == 'local' or self.sftp is not None
        if len(sel) == 1 and sel[0].data(0, ISDIR_ROLE):
            menu.addAction("Abrir", lambda: self.open_item(side, sel[0]))
            a = menu.addAction("Nova pasta dentro de “%s”" % posixpath.basename(sel[0].data(0, PATH_ROLE)),
                               lambda: self.create_folder(side, sel[0].data(0, PATH_ROLE)))
            a.setEnabled(remote_ok)
            a = menu.addAction("Novo arquivo dentro de “%s”" % posixpath.basename(sel[0].data(0, PATH_ROLE)),
                               lambda: self.create_file(side, sel[0].data(0, PATH_ROLE)))
            a.setEnabled(remote_ok)
        a = menu.addAction("Nova pasta aqui…", lambda: self.create_folder(side)); a.setEnabled(remote_ok)
        a = menu.addAction("Novo arquivo de texto aqui…", lambda: self.create_file(side)); a.setEnabled(remote_ok)
        if sel:
            paths = [i.data(0, PATH_ROLE) for i in sel]
            menu.addSeparator()
            if side == 'local':
                a = menu.addAction("Enviar para o servidor  →", lambda: self.handle_drop('local', paths, 'remote', self.remote_path))
                a.setEnabled(self.sftp is not None)
            else:
                menu.addAction("←  Baixar para o computador", lambda: self.handle_drop('remote', paths, 'local', self.local_path))
            if len(sel) == 1 and not sel[0].data(0, ISDIR_ROLE):
                menu.addAction("✏️  Editar", lambda: self.edit_file(side, paths[0]))
                if side == 'local': menu.addAction("Abrir com o app padrão", lambda: self.open_default(paths[0]))
            files = [i.data(0, PATH_ROLE) for i in sel if not i.data(0, ISDIR_ROLE)]
            if files: menu.addAction("🔐  Permissões…", lambda: self.change_permissions(side, files))
            if len(sel) == 1: menu.addAction("Renomear…", lambda: self.rename_item(side, sel[0]))
            if side == 'local': menu.addAction("Mostrar no Finder", lambda: self.reveal_in_finder(paths[0]))
            menu.addSeparator()
            label = "Excluir “%s”" % posixpath.basename(paths[0]) if len(sel) == 1 else f"Excluir {len(sel)} itens"
            menu.addAction(label, lambda: self.delete_selected(side))
        menu.addSeparator()
        menu.addAction("Atualizar", self.load_local if side == 'local' else self.load_remote)
        menu.exec(tree.viewport().mapToGlobal(pos))

    def open_default(self, path):
        try: subprocess.Popen(['open', path])
        except Exception as e: self.status(f"Não foi possível abrir: {e}")

    def edit_file(self, side, path):
        """Abre um arquivo de texto no editor (local ou no servidor)."""
        for ed in self.editors:
            if ed.side == side and ed.path == path: ed.show(); ed.raise_(); ed.activateWindow(); return
        if side == 'remote' and not self.require_remote(): return
        name = posixpath.basename(path)
        try:
            if side == 'local':
                st = os.stat(path)
            else:
                st = self.sftp.stat(path)
                if not stat.S_ISREG(st.st_mode or 0): raise RuntimeError("Não é um arquivo comum.")
            size = st.st_size or 0
            if size > EDIT_MAX_BYTES and QMessageBox.question(
                    self, "Arquivo grande", f"“{name}” tem {human_size(size)}. Abrir no editor mesmo assim?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return
            QApplication.setOverrideCursor(Qt.WaitCursor)
            try:
                if side == 'local':
                    with open(path, 'rb') as f: data = f.read()
                else:
                    with self.sftp.open(path, 'rb') as f:
                        f.prefetch(size); data = f.read()
            finally:
                QApplication.restoreOverrideCursor()
        except Exception as e:
            QMessageBox.critical(self, "Não foi possível abrir", f"{name}\n\n{e}"); return
        if decode_text(data) is None:
            if side == 'local': self.open_default(path)      # imagem, PDF etc. → app padrão do Mac
            else: QMessageBox.information(self, "Arquivo binário",
                                          f"“{name}” não é um arquivo de texto, então não dá para editar aqui.\n"
                                          "Baixe para o computador para abrir com outro app.")
            return
        ed = EditorWindow(self, side, path, data, st.st_mtime); self.editors.append(ed); ed.show()

    def close_editors(self, remote_only=False):
        """Fecha editores (perguntando sobre alterações). Retorna False se o usuário cancelar."""
        for ed in list(self.editors):
            if remote_only and ed.side != 'remote': continue
            if not ed.close(): return False
        return True

    def reveal_in_finder(self, path):
        try: subprocess.Popen(['open', '-R', path])
        except Exception as e: self.status(f"Não foi possível abrir o Finder: {e}")

    # ------------------------------------------------------------------ criar / renomear / excluir
    def create_folder(self, side, parent_dir=None):
        if side == 'remote' and not self.require_remote(): return
        parent_dir = parent_dir or self.current_dir(side)
        name, ok = QInputDialog.getText(self, "Nova pasta", f"Nome da nova pasta em:\n{parent_dir}", text="Nova pasta")
        if not ok: return
        name = name.strip()
        if not valid_name(name):
            QMessageBox.warning(self, "Nome inválido", "Use um nome sem “/” e diferente de “.” ou “..”."); return
        try:
            if side == 'local':
                target = os.path.join(parent_dir, name)
                if os.path.lexists(target): raise FileExistsError(f"Já existe um item chamado “{name}”.")
                os.mkdir(target)
            else:
                target = posixpath.join(parent_dir, name)
                if self.remote_exists(target): raise FileExistsError(f"Já existe um item chamado “{name}” no servidor.")
                self.sftp.mkdir(target)
        except Exception as e:
            QMessageBox.critical(self, "Não foi possível criar a pasta", str(e)); return
        self.status(f"Pasta criada: {target}")
        same = parent_dir == self.current_dir(side)
        (self.load_local if side == 'local' else self.load_remote)(select=name if same else None)

    def create_file(self, side, parent_dir=None):
        """Cria um arquivo de texto vazio e já abre no editor."""
        if side == 'remote' and not self.require_remote(): return
        parent_dir = parent_dir or self.current_dir(side)
        name, ok = QInputDialog.getText(self, "Novo arquivo", f"Nome do novo arquivo em:\n{parent_dir}", text="novo.txt")
        if not ok: return
        name = name.strip()
        if not valid_name(name):
            QMessageBox.warning(self, "Nome inválido", "Use um nome sem “/” e diferente de “.” ou “..”."); return
        try:
            if side == 'local':
                target = os.path.join(parent_dir, name)
                if os.path.lexists(target): raise FileExistsError(f"Já existe um item chamado “{name}”.")
                with open(target, 'x'): pass
            else:
                target = posixpath.join(parent_dir, name)
                if self.remote_exists(target): raise FileExistsError(f"Já existe um item chamado “{name}” no servidor.")
                with self.sftp.open(target, 'w'): pass
        except Exception as e:
            QMessageBox.critical(self, "Não foi possível criar o arquivo", str(e)); return
        self.status(f"Arquivo criado: {target}")
        same = parent_dir == self.current_dir(side)
        (self.load_local if side == 'local' else self.load_remote)(select=name if same else None)
        self.edit_file(side, target)

    def change_permissions(self, side, paths):
        """chmod de um ou mais arquivos (local ou no servidor)."""
        if side == 'remote' and not self.require_remote(): return
        try:
            st = os.stat(paths[0]) if side == 'local' else self.sftp.stat(paths[0])
        except Exception as e:
            QMessageBox.critical(self, "Permissões", f"Não foi possível ler as permissões:\n{e}"); return
        mode = stat.S_IMODE(st.st_mode or 0)
        info = ""
        if len(paths) == 1:
            uid, gid = getattr(st, "st_uid", None), getattr(st, "st_gid", None)
            if side == 'local':
                try:
                    import pwd, grp
                    info = f"Dono: {pwd.getpwuid(uid).pw_name}  •  Grupo: {grp.getgrgid(gid).gr_name}"
                except Exception: info = f"Dono (uid): {uid}  •  Grupo (gid): {gid}"
            elif uid is not None:
                info = f"Dono (uid): {uid}  •  Grupo (gid): {gid}"
        names = [posixpath.basename(p) for p in paths]
        dlg = PermissionsDialog(names, mode, info, self)
        if dlg.exec() != QDialog.Accepted: return
        new_mode = dlg.mode(); errors = []
        for p in paths:
            try:
                if side == 'local': os.chmod(p, new_mode)
                else: self.sftp.chmod(p, new_mode)
            except Exception as e:
                msg = "sem permissão (só o dono do arquivo ou o root pode alterar)" if (
                    isinstance(e, PermissionError) or "permission" in str(e).lower()) else str(e)
                errors.append(f"{posixpath.basename(p)}: {msg}")
        (self.load_local if side == 'local' else self.load_remote)(select=names[0] if len(names) == 1 else None)
        if errors: QMessageBox.critical(self, "Permissões não alteradas", "\n".join(errors[:15]))
        else: self.status(f"Permissões {new_mode:03o} aplicadas em {len(paths)} arquivo(s).")

    def rename_item(self, side, item):
        if side == 'remote' and not self.require_remote(): return
        old = item.data(0, PATH_ROLE); j = os.path if side == 'local' else posixpath
        old_name = j.basename(old)
        name, ok = QInputDialog.getText(self, "Renomear", "Novo nome:", text=old_name)
        name = (name or '').strip()
        if not ok or name == old_name: return
        if not valid_name(name):
            QMessageBox.warning(self, "Nome inválido", "Use um nome sem “/” e diferente de “.” ou “..”."); return
        new = j.join(j.dirname(old), name)
        try:
            if side == 'local':
                if os.path.lexists(new): raise FileExistsError(f"Já existe um item chamado “{name}”.")
                os.rename(old, new); self.load_local(select=name)
            else:
                if self.remote_exists(new): raise FileExistsError(f"Já existe um item chamado “{name}” no servidor.")
                self.sftp.rename(old, new); self.load_remote(select=name)
        except Exception as e:
            QMessageBox.critical(self, "Não foi possível renomear", str(e))

    def delete_selected(self, side):
        if side == 'remote' and not self.require_remote(): return
        tree = self.tree(side); paths = tree.selected_paths()
        if not paths:
            QMessageBox.information(self, "Excluir", "Selecione um arquivo ou pasta para excluir."); return
        n_dirs = sum(1 for it in tree.selectedItems() if it.data(0, ISDIR_ROLE))
        names = "\n".join("• " + posixpath.basename(p.rstrip('/')) for p in paths[:10]) + ("\n…" if len(paths) > 10 else "")
        if side == 'local':
            msg = f"Mover para o Lixo {len(paths)} item(ns)?\n\n{names}"
        else:
            msg = (f"Excluir DEFINITIVAMENTE do servidor {len(paths)} item(ns)?\n\n{names}"
                   + ("\n\nPastas serão apagadas com todo o conteúdo." if n_dirs else "")
                   + "\n\nEssa ação não pode ser desfeita.")
        if QMessageBox.warning(self, "Confirmar exclusão", msg, QMessageBox.Yes | QMessageBox.Cancel,
                               QMessageBox.Cancel) != QMessageBox.Yes:
            return
        errors = []
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            for p in paths:
                try:
                    if side == 'local': self.local_delete(p)
                    else: self.remote_rmtree(p)
                except Exception as e: errors.append(f"{p}: {e}")
        finally:
            QApplication.restoreOverrideCursor()
        (self.load_local if side == 'local' else self.load_remote)()
        if errors: QMessageBox.critical(self, "Alguns itens não foram excluídos", "\n".join(errors[:15]))
        else: self.status(f"{len(paths)} item(ns) excluído(s).")

    def local_delete(self, path):
        res = QFile.moveToTrash(path)
        ok = res[0] if isinstance(res, tuple) else bool(res)
        if ok: return
        if QMessageBox.question(self, "Lixo indisponível",
                                f"Não foi possível mover para o Lixo:\n{path}\n\nApagar definitivamente?",
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            raise RuntimeError("cancelado")
        if os.path.isdir(path) and not os.path.islink(path): shutil.rmtree(path)
        else: os.remove(path)

    def remote_exists(self, path):
        try: self.sftp.lstat(path); return True
        except IOError: return False

    def remote_rmtree(self, path):
        st = self.sftp.lstat(path)
        if stat.S_ISDIR(st.st_mode):
            for a in self.sftp.listdir_attr(path):
                QApplication.processEvents(); self.remote_rmtree(posixpath.join(path, a.filename))
            self.sftp.rmdir(path)
        else:
            self.sftp.remove(path)

    # ------------------------------------------------------------------ arrastar e soltar
    def handle_drop(self, src_side, paths, dest_side, dest_dir):
        if dest_side == 'remote' and not self.require_remote(): return
        finder = src_side == 'finder'
        if finder: src_side = 'local'
        if src_side == dest_side:
            if finder: self.copy_local_items(paths, dest_dir)
            else: self.move_items(dest_side, paths, dest_dir)
            return
        self.start_transfer(paths, src_side, dest_side, dest_dir)

    def _confirm_overwrite(self, name, where):
        return QMessageBox.question(
            self, "Destino existente",
            f"Já existe um item chamado “{name}” {where}.\n"
            "Pastas serão mescladas e arquivos com o mesmo nome poderão ser substituídos. Continuar?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes

    def start_transfer(self, paths, source_side, dest_side, dest_dir):
        if not self.require_remote(): return
        jobs = []
        for path in paths:
            if source_side == 'local':
                name = os.path.basename(path.rstrip(os.sep)); target = posixpath.join(dest_dir, name)
                if self.remote_exists(target) and not self._confirm_overwrite(name, "no servidor"): continue
                jobs.append(('up', path, target))
            else:
                name = posixpath.basename(path.rstrip('/')); target = os.path.join(dest_dir, name)
                if os.path.lexists(target) and not self._confirm_overwrite(name, "no computador"): continue
                jobs.append(('down', path, target))
        if not jobs: return
        worker = TransferWorker(self.ssh, jobs); self.transfers.append(worker)
        verb = "Enviando para" if source_side == 'local' else "Baixando de"
        title = f"{verb} {self.title}"

        def finish(ok, msg, count, worker=worker):
            if worker in self.transfers: self.transfers.remove(worker)
            self.status(f"{msg} — {count} arquivo(s) • {self.title}")
            if self.sftp: self.refresh()
            else: self.load_local()
            if not ok and msg.startswith("Erro"): QMessageBox.critical(self, "Falha na transferência", msg)

        dlg = TransferDialog(title, worker, finish, self.main); dlg.show()
        worker.finished.connect(worker.deleteLater)
        worker.start(); self.status(f"{title}…")

    def move_items(self, side, paths, dest_dir):
        j = os.path if side == 'local' else posixpath
        errors = []; moved = 0
        for p in paths:
            name = j.basename(p.rstrip('/')); target = j.join(dest_dir, name)
            np_, nd = p.rstrip('/'), dest_dir.rstrip('/')
            if nd == np_ or nd.startswith(np_ + '/') or j.dirname(np_) == nd: continue
            try:
                if side == 'local':
                    if os.path.lexists(target): raise FileExistsError("já existe no destino")
                    shutil.move(p, target)
                else:
                    if self.remote_exists(target): raise FileExistsError("já existe no destino")
                    self.sftp.rename(p, target)
                moved += 1
            except Exception as e: errors.append(f"{name}: {e}")
        (self.load_local if side == 'local' else self.load_remote)()
        if errors: QMessageBox.warning(self, "Alguns itens não foram movidos", "\n".join(errors[:15]))
        if moved: self.status(f"{moved} item(ns) movido(s) para {dest_dir}")

    def copy_local_items(self, paths, dest_dir):
        for p in paths:
            name = os.path.basename(p.rstrip(os.sep)); target = os.path.join(dest_dir, name)
            if os.path.abspath(target) == os.path.abspath(p): continue
            if os.path.lexists(target) and not self._confirm_overwrite(name, "nesta pasta"): continue
            try:
                if os.path.isdir(p) and not os.path.islink(p): shutil.copytree(p, target, symlinks=True, dirs_exist_ok=True)
                else: shutil.copy2(p, target, follow_symlinks=False)
            except Exception as e: QMessageBox.critical(self, "Falha ao copiar", f"{name}: {e}")
        self.load_local()


# ============================================================================= janela principal

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle(APP_NAME); self.resize(1240, 760)
        self.favorites = Favorites()
        root = QWidget(); self.setCentralWidget(root); layout = QVBoxLayout(root)

        top = QHBoxLayout()
        b = QPushButton("＋ Nova conexão"); b.setToolTip("Conectar a um servidor (⌘T abre nova aba)")
        b.clicked.connect(self.new_connection); top.addWidget(b)
        # botão comum (mesmo visual dos outros); o menu abre logo abaixo dele
        self.fav_btn = QPushButton("⭐ Favoritos"); self.fav_btn.setToolTip("Conectar a um favorito ou gerenciar")
        self.fav_menu = QMenu(self); self.fav_btn.clicked.connect(self._show_fav_menu)
        top.addWidget(self.fav_btn)
        top.addStretch(1)
        for text, slot in (("Console SSH", lambda: self.session().open_console()),
                           ("Atualizar", lambda: self.session().refresh()),
                           ("Desconectar", lambda: self.session().disconnect())):
            btn = QPushButton(text); btn.clicked.connect(slot); top.addWidget(btn)
        layout.addLayout(top)

        self.tabs = QTabWidget(); self.tabs.setTabsClosable(True); self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True); self.tabs.tabCloseRequested.connect(self.close_tab)
        plus = QToolButton(); plus.setText("＋"); plus.setToolTip("Nova aba (⌘T)"); plus.clicked.connect(lambda: self.add_session())
        self.tabs.setCornerWidget(plus, Qt.TopRightCorner)
        layout.addWidget(self.tabs, 1)
        self.add_session()

        for keys, slot in (("Ctrl+T", lambda: self.add_session()),
                           ("Ctrl+W", lambda: self.close_tab(self.tabs.currentIndex())),
                           ("Ctrl+Shift+N", lambda: self.session().create_folder(self.session().focused_side())),
                           ("Ctrl+N", self.new_connection), ("Ctrl+R", lambda: self.session().refresh())):
            act = QAction(self); act.setShortcut(QKeySequence(keys)); act.triggered.connect(slot); self.addAction(act)

        self.statusBar().showMessage("Cada aba é uma conexão. Arraste entre os painéis ou solte em cima de uma pasta. "
                                     "Botão direito para mais opções.")

    # --- abas
    def session(self): return self.tabs.currentWidget()

    def add_session(self):
        s = Session(self); s.title_changed.connect(self._retitle)
        i = self.tabs.addTab(s, s.title); self.tabs.setCurrentIndex(i)
        return s

    def _retitle(self, s, title):
        i = self.tabs.indexOf(s)
        if i >= 0: self.tabs.setTabText(i, ("🟢 " if s.connected else "") + title)

    def close_tab(self, index):
        s = self.tabs.widget(index)
        if s is None or not s.close_editors() or not s.disconnect(): return
        self.tabs.removeTab(index); s.deleteLater()
        if self.tabs.count() == 0: self.add_session()

    def target_session(self):
        """Usa a aba atual se estiver livre; senão abre uma nova aba."""
        s = self.session()
        return s if s is not None and not s.connected else self.add_session()

    # --- conexões
    def new_connection(self):
        dlg = ConnectionDialog(self)
        if dlg.exec() != QDialog.Accepted: return
        v = dlg.values()
        if not v["host"] or not v["user"]:
            QMessageBox.warning(self, "Dados incompletos", "Informe servidor e usuário."); return
        title = None
        if dlg.save_fav.isChecked():
            fav = dict(name=dlg.fav_name.text().strip() or f"{v['user']}@{v['host']}", host=v["host"], port=v["port"],
                       user=v["user"], remote_dir=v["remote_dir"], local_dir="", save_password=dlg.save_pwd.isChecked())
            fav = self.favorites.upsert(fav); title = fav["name"]
            if fav["save_password"] and v["password"]:
                try: Favorites.set_password(fav["id"], v["password"])
                except Exception as e: QMessageBox.warning(self, "Senha não salva", str(e))
        s = self.target_session()
        s.connect_to(v["host"], v["port"], v["user"], v["password"], title, v["remote_dir"])

    def connect_favorite(self, fav, password=None):
        asked = False
        if password is None:
            password = ""
            if fav.get("save_password"):
                if not Unlock.ensure(fav.get("name") or fav["host"]):
                    self.statusBar().showMessage("Conexão cancelada (Touch ID não confirmado)."); return
                password = Favorites.get_password(fav["id"])
            if not password:
                extra = "\n\nEla será salva e, das próximas vezes, liberada pelo Touch ID." if fav.get("save_password") else ""
                pwd, ok = QInputDialog.getText(self, f"Senha — {fav['name']}",
                                               f"Senha SSH de {fav['user']}@{fav['host']}\n(vazio = usar chave SSH){extra}",
                                               QLineEdit.Password)
                if not ok: return
                password = pwd; asked = True
        s = self.target_session()
        ok = s.connect_to(fav["host"], int(fav.get("port", 22)), fav["user"], password, fav.get("name"),
                          fav.get("remote_dir", ""), fav.get("local_dir", ""))
        if ok and asked and password and fav.get("save_password"):
            try: Favorites.set_password(fav["id"], password); Unlock.unlocked = True
            except Exception as e: self.statusBar().showMessage(f"Senha não salva: {e}")

    def _show_fav_menu(self):
        self._build_fav_menu()
        self.fav_menu.exec(self.fav_btn.mapToGlobal(self.fav_btn.rect().bottomLeft()))

    def _build_fav_menu(self):
        self.fav_menu.clear()
        if not self.favorites.items:
            a = self.fav_menu.addAction("(nenhum favorito ainda)"); a.setEnabled(False)
        for f in self.favorites.items:
            self.fav_menu.addAction(f"{f.get('name')}   —   {f['user']}@{f['host']}",
                                    lambda f=f: self.connect_favorite(f))
        self.fav_menu.addSeparator()
        if self.session() and self.session().connected:
            self.fav_menu.addAction("Adicionar esta conexão aos favoritos…", self.add_current_to_favorites)
        self.fav_menu.addAction("Gerenciar favoritos…", self.manage_favorites)
        if Unlock.unlocked:
            self.fav_menu.addAction("🔒 Bloquear favoritos (pedir Touch ID de novo)", self._lock)

    def _lock(self):
        Unlock.lock(); self.statusBar().showMessage("Favoritos bloqueados — o próximo uso de senha salva pede Touch ID.")

    def add_current_to_favorites(self):
        s = self.session(); t = s.ssh.get_transport(); host, port = t.getpeername()[:2]
        user = t.get_username()
        name, ok = QInputDialog.getText(self, "Adicionar aos favoritos", "Nome do favorito:", text=s.title)
        if not ok: return
        fav = self.favorites.upsert(dict(name=name.strip() or s.title, host=host, port=port, user=user,
                                         remote_dir=s.remote_path, local_dir=s.local_path, save_password=False))
        QMessageBox.information(self, "Favorito salvo",
                                f"“{fav['name']}” foi salvo. Para guardar a senha, abra “Gerenciar favoritos…”.")

    def manage_favorites(self):
        dlg = FavoritesDialog(self.favorites, self)
        dlg.connect_requested.connect(lambda fav, pwd: QTimer.singleShot(0, lambda: self.connect_favorite(fav, pwd)))
        dlg.exec()

    def closeEvent(self, event):
        running = sum(1 for i in range(self.tabs.count()) for t in self.tabs.widget(i).transfers if t.isRunning())
        if running and QMessageBox.question(self, "Sair", f"Há {running} transferência(s) em andamento. Cancelar e sair?",
                                            QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            event.ignore(); return
        for i in range(self.tabs.count()):
            if not self.tabs.widget(i).close_editors(): event.ignore(); return
        for i in range(self.tabs.count()): self.tabs.widget(i).disconnect(ask=False)
        event.accept()


def self_test():
    """Usado pelo build: confere se as partes importantes foram empacotadas."""
    ok = True
    try:
        from LocalAuthentication import LAContext
        ctx = LAContext.alloc().init(); can, err = ctx.canEvaluatePolicy_error_(LA_POLICY_OWNER_AUTH, None)
        print(f"  Touch ID: {'OK' if can else 'indisponível — ' + str(err.localizedDescription() if err else '')}")
    except Exception as e:
        print(f"  Touch ID: ERRO — {e}"); ok = False
    try:
        k = AESGCM.generate_key(bit_length=256); n = os.urandom(12)
        assert AESGCM(k).decrypt(n, AESGCM(k).encrypt(n, b"x", None), None) == b"x"
        print("  Cofre de senhas: OK")
    except Exception as e:
        print(f"  Cofre de senhas: ERRO — {e}"); ok = False
    return 0 if ok else 1


def main():
    if "--self-test" in sys.argv: sys.exit(self_test())
    app = QApplication(sys.argv); app.setApplicationName(APP_NAME)
    win = MainWindow(); win.show(); sys.exit(app.exec())


if __name__ == '__main__':
    main()
