#!/usr/bin/env python3
"""MacSCP — cliente SFTP nativo para macOS (estilo WinSCP). Não inicia servidor web."""
import os, sys, stat, json, shutil, hashlib, base64, posixpath, time, uuid, subprocess, socket, errno, ipaddress, threading
import copy, math, re
from collections import deque
from pathlib import Path

import paramiko
import pyte
from PySide6.QtCore import Qt, QMimeData, QThread, Signal, QUrl, QTimer, QFile
from PySide6.QtGui import (QDrag, QAction, QKeySequence, QBrush, QColor, QIcon, QPixmap, QPainter, QFont, QPalette,
                           QTextDocument, QTextCursor)
from PySide6.QtCore import QFileInfo, QByteArray, QSize, QRect, QRegularExpression, QPointF, QRectF, QEvent
from PySide6.QtGui import QRegularExpressionValidator, QFontMetricsF, QResizeEvent, QDesktopServices, QActionGroup
from PySide6.QtCore import QProcess, QTranslator, QLibraryInfo
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QSpinBox,
    QPushButton, QTreeWidget, QTreeWidgetItem, QFileDialog, QMessageBox, QInputDialog, QSplitter,
    QDialog, QFormLayout, QDialogButtonBox, QPlainTextEdit, QMenu, QAbstractItemView, QTabWidget,
    QToolButton, QCheckBox, QListWidget, QListWidgetItem, QProgressBar, QFileIconProvider, QGridLayout,
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM   # já vem com o paramiko

APP_NAME = "MacSCP"
APP_VERSION = "1.2.1"          # única fonte da versão (o build lê daqui)
APP_AUTHOR = "Xela"
APP_URL = "https://github.com/xelaex/MacSCP"



def resource_path(name):
    """Arquivo que vai junto com o app (funciona rodando o .py ou o .app gerado pelo PyInstaller)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def app_icon():
    p = resource_path("MacSCP_icon.png")
    return QIcon(p) if os.path.exists(p) else QIcon()


# ============================================================================= idiomas (Português / English)

LANG = "pt"          # definido em main() a partir da preferência salva (ou do idioma do Mac)
LANGUAGES = (("pt", "Português (Brasil)"), ("en", "English"))

TR_EN = {
 "só existe no macOS": "macOS only",
 "módulo LocalAuthentication ausente no app ({0})": "LocalAuthentication module missing from the app ({0})",
 "não disponível": "not available",
 "usar a senha salva de “{0}”": "use the saved password for “{0}”",
 "Desbloquear favoritos": "Unlock favorites",
 "Touch ID indisponível ({0}).\nDigite a senha do seu usuário do Mac para usar as senhas salvas:": "Touch ID unavailable ({0}).\nEnter your Mac user password to use the saved passwords:",
 "Senha incorreta": "Wrong password",
 "Senha do Mac incorreta.": "Incorrect Mac password.",
 "Nova conexão SSH/SFTP": "New SSH/SFTP connection",
 "192.168.1.100 ou host.example": "192.168.1.100 or host.example",
 "vazio = usar chave SSH (~/.ssh)": "empty = use SSH key (~/.ssh)",
 "opcional, ex.: /var/www": "optional, e.g. /var/www",
 "Servidor / IP": "Server / IP",
 "Porta": "Port",
 "Usuário": "User",
 "Senha SSH": "SSH password",
 "Pasta remota inicial": "Initial remote folder",
 "Salvar nos favoritos": "Save to favorites",
 "Nome do favorito (ex.: Raspberry)": "Favorite name (e.g. Raspberry)",
 "Salvar senha (protegida por Touch ID)": "Save password (protected by Touch ID)",
 "Nome": "Name",
 "Conectar": "Connect",
 "Favoritos": "Favorites",
 "＋ Novo": "＋ New",
 "Excluir": "Delete",
 "vazio = usar chave SSH": "empty = use SSH key",
 "opcional": "optional",
 "…": "…",
 "Senha": "Password",
 "Pasta local inicial": "Initial local folder",
 "Salvar": "Save",
 "Fechar": "Close",
 "🔒 senha salva — deixe vazio para manter": "🔒 password saved — leave empty to keep it",
 "vazio = perguntar ao conectar / usar chave SSH": "empty = ask when connecting / use SSH key",
 "Dados incompletos": "Missing information",
 "Informe pelo menos servidor e usuário.": "Enter at least the server and user.",
 "Senha não salva": "Password not saved",
 "O favorito foi salvo, mas a senha não:\n{0}": "The favorite was saved, but the password was not:\n{0}",
 "Excluir favorito": "Delete favorite",
 "Excluir “{0}” e a senha salva?": "Delete “{0}” and its saved password?",
 "Não encontrei o servidor “{0}”. Confira o nome/IP.": "Server “{0}” not found. Check the name/IP.",
 "Tempo esgotado ao conectar em {0}:{1}.\n\nO servidor não respondeu: pode estar desligado, fora da VPN (ZeroTier/Tailscale) ou com firewall bloqueando a porta.": "Timed out connecting to {0}:{1}.\n\nThe server did not respond: it may be off, outside the VPN (ZeroTier/Tailscale) or behind a firewall blocking the port.",
 "{0} recusou a conexão na porta {1}.\n\nO servidor está acessível, mas o SSH não está rodando nessa porta (confira a porta e o serviço ssh).": "{0} refused the connection on port {1}.\n\nThe server is reachable, but SSH is not running on that port (check the port and the ssh service).",
 "O macOS bloqueou o acesso a {0} (rede local/VPN).\n\nProvável causa: o MacSCP não tem permissão de Rede Local.\nAbra Ajustes do Sistema → Privacidade e Segurança → Rede Local e ative o MacSCP.\nSe ele não aparecer na lista, gere o app de novo com o build_macos.command atualizado.\n\nSe continuar, teste no Terminal:  nc -vz {1} {2}\n(erro do sistema: {3})": "macOS blocked access to {0} (local network/VPN).\n\nLikely cause: MacSCP does not have Local Network permission.\nOpen System Settings → Privacy & Security → Local Network and turn MacSCP on.\nIf it is not in the list, rebuild the app with the updated build_macos.command.\n\nIf it still fails, test in Terminal:  nc -vz {1} {2}\n(system error: {3})",
 "Sem rota até {0}. Confira se a VPN (ZeroTier/Tailscale) está conectada e se este Mac está autorizado na rede.\n\n(erro do sistema: {1})": "No route to {0}. Check that the VPN (ZeroTier/Tailscale) is connected and that this Mac is authorized on the network.\n\n(system error: {1})",
 "Não foi possível abrir conexão com {0}:{1}: {2}": "Could not open a connection to {0}:{1}: {2}",
 "A chave do servidor mudou": "The server key has changed",
 "A chave SSH de {0}:{1} é diferente da que estava gravada neste Mac.": "The SSH key of {0}:{1} is different from the one saved on this Mac.",
 "Isso é normal se o servidor foi reinstalado/formatado, se esse IP agora é de outra máquina ou se a chave foi trocada. Se nada disso aconteceu, pode ser alguém interceptando a conexão.\n\nChave gravada:  {0}  {1}\nChave nova:     {2}  {3}\n\nAtualizar o known_hosts com a chave nova e conectar?": "This is normal if the server was reinstalled/reformatted, if this IP now belongs to another machine or if the key was changed. If none of that happened, someone may be intercepting the connection.\n\nSaved key:  {0}  {1}\nNew key:    {2}  {3}\n\nUpdate known_hosts with the new key and connect?",
 "Atualizar e conectar": "Update and connect",
 "Cancelar": "Cancel",
 "Chave SSH alterada não foi aceita.": "The changed SSH key was not accepted.",
 "Confirmar chave SSH": "Confirm SSH key",
 "Servidor: {0}:{1}\nTipo: {2}\nImpressão digital: {3}\n\nConfirme com o administrador do servidor por um canal confiável. Deseja confiar nesta chave?": "Server: {0}:{1}\nType: {2}\nFingerprint: {3}\n\nConfirm it with the server administrator through a trusted channel. Do you want to trust this key?",
 "Chave SSH não confirmada.": "SSH key not confirmed.",
 "Não foi possível validar a chave do servidor.": "Could not validate the server key.",
 "\r\n\u001b[90m[Sessão encerrada — pode fechar a janela]\u001b[0m\r\n": "\r\n\u001b[90m[Session ended — you can close the window]\u001b[0m\r\n",
 "Copiar": "Copy",
 "Colar": "Paste",
 "Selecionar tudo": "Select all",
 "Limpar": "Clear",
 "Aumentar fonte": "Bigger font",
 "Diminuir fonte": "Smaller font",
 "Console SSH — {0}": "SSH Console — {0}",
 "Não foi possível abrir o console: {0}\r\n": "Could not open the console: {0}\r\n",
 "Analisando arquivos…": "Scanning files…",
 "O destino já existe e não é pasta: {0}": "The destination already exists and is not a folder: {0}",
 "Transferência concluída": "Transfer complete",
 "Transferência cancelada": "Transfer cancelled",
 "Erro: {0}": "Error: {0}",
 "Preparando…": "Preparing…",
 "{0} de {1}  •  {2}/s  •  faltam ~{3}min {4}s": "{0} of {1}  •  {2}/s  •  ~{3}min {4}s left",
 "Cancelando…": "Cancelling…",
 "Buscar…  (Enter = próximo, ⇧Enter = anterior)": "Find…  (Enter = next, ⇧Enter = previous)",
 "Diferenciar maiúsculas/minúsculas": "Match case",
 "Buscar:": "Find:",
 "Computador local": "Local computer",
 "Linha {0}, Coluna {1}  ": "Line {0}, Column {1}  ",
 "“{0}” não encontrado": "“{0}” not found",
 "A conexão com o servidor foi encerrada. Reconecte para salvar.": "The connection to the server was closed. Reconnect to save.",
 "Sem permissão": "Permission denied",
 "Seu usuário não tem permissão para gravar em:\n{0}": "Your user does not have permission to write to:\n{0}",
 "Não foi possível salvar": "Could not save",
 "Arquivo alterado por fora": "File changed elsewhere",
 "Este arquivo foi modificado depois que você o abriu (por outra pessoa ou programa).\n\nSalvar mesmo assim e sobrescrever essas alterações?": "This file was modified after you opened it (by someone else or another program).\n\nSave anyway and overwrite those changes?",
 "Alterações não salvas": "Unsaved changes",
 "Salvar as alterações em “{0}”?": "Save changes to “{0}”?",
 "Permissões": "Permissions",
 "Ler": "Read",
 "Gravar": "Write",
 "Executar": "Execute",
 "Dono": "Owner",
 "Grupo": "Group",
 "Outros": "Others",
 "Octal:": "Octal:",
 "Rápido:": "Quick:",
 "arquivo comum": "regular file",
 "script/executável": "script/executable",
 "privado": "private",
 "grupo grava": "group can write",
 "Aplicar": "Apply",
 "Tamanho": "Size",
 "Modificado": "Modified",
 "Sem conexão": "Not connected",
 "<b>Computador local</b>": "<b>Local computer</b>",
 "Escolher pasta": "Choose folder",
 "＋ Nova pasta": "＋ New folder",
 "Criar pasta (⇧⌘N)": "Create folder (⇧⌘N)",
 "Excluir selecionados (⌫)": "Delete selected (⌫)",
 "Pasta acima": "Parent folder",
 "<b>Servidor remoto</b>": "<b>Remote server</b>",
 "Criar pasta no servidor": "Create folder on the server",
 "Excluir selecionados no servidor (⌫)": "Delete selected on the server (⌫)",
 "Não conectado — use “Nova conexão” ou “Favoritos”": "Not connected — use “New connection” or “Favorites”",
 "Esta aba não está conectada a um servidor.": "This tab is not connected to a server.",
 "Falha na conexão": "Connection failed",
 "Não foi possível conectar em {0}.\n\n{1}": "Could not connect to {0}.\n\n{1}",
 "Pasta remota inicial não encontrada: {0}": "Initial remote folder not found: {0}",
 "<b>Servidor:</b> {0}@{1}:{2}": "<b>Server:</b> {0}@{1}:{2}",
 "Transferências em andamento": "Transfers in progress",
 "Há {0} transferência(s) em andamento nesta conexão. Cancelar e desconectar?": "There are {0} transfer(s) in progress on this connection. Cancel and disconnect?",
 "Não conectado": "Not connected",
 "Console SSH": "SSH Console",
 "Esta aba não está conectada.": "This tab is not connected.",
 "Escolher pasta local": "Choose local folder",
 "Solte arquivos aqui para colocá-los dentro desta pasta": "Drop files here to put them inside this folder",
 "Erro ao listar pasta local: {0}": "Error listing local folder: {0}",
 "Erro ao listar servidor: {0}": "Error listing server: {0}",
 "Abrir": "Open",
 "Nova pasta dentro de “%s”": "New folder inside “%s”",
 "Novo arquivo dentro de “%s”": "New file inside “%s”",
 "Nova pasta aqui…": "New folder here…",
 "Novo arquivo de texto aqui…": "New text file here…",
 "Enviar para o servidor  →": "Upload to server  →",
 "←  Baixar para o computador": "←  Download to computer",
 "✏️  Editar": "✏️  Edit",
 "Abrir com o app padrão": "Open with default app",
 "🔐  Permissões…": "🔐  Permissions…",
 "Renomear…": "Rename…",
 "Mostrar no Finder": "Show in Finder",
 "Excluir “%s”": "Delete “%s”",
 "Excluir {0} itens": "Delete {0} items",
 "Atualizar": "Refresh",
 "Não foi possível abrir: {0}": "Could not open: {0}",
 "Não é um arquivo comum.": "Not a regular file.",
 "Arquivo grande": "Large file",
 "“{0}” tem {1}. Abrir no editor mesmo assim?": "“{0}” is {1}. Open it in the editor anyway?",
 "Não foi possível abrir": "Could not open",
 "Arquivo binário": "Binary file",
 "“{0}” não é um arquivo de texto, então não dá para editar aqui.\nBaixe para o computador para abrir com outro app.": "“{0}” is not a text file, so it cannot be edited here.\nDownload it to your computer to open it with another app.",
 "Não foi possível abrir o Finder: {0}": "Could not open Finder: {0}",
 "Nova pasta": "New folder",
 "Nome da nova pasta em:\n{0}": "Name of the new folder in:\n{0}",
 "Nome inválido": "Invalid name",
 "Use um nome sem “/” e diferente de “.” ou “..”.": "Use a name without “/” that is not “.” or “..”.",
 "Já existe um item chamado “{0}”.": "An item named “{0}” already exists.",
 "Já existe um item chamado “{0}” no servidor.": "An item named “{0}” already exists on the server.",
 "Não foi possível criar a pasta": "Could not create the folder",
 "Pasta criada: {0}": "Folder created: {0}",
 "Novo arquivo": "New file",
 "Nome do novo arquivo em:\n{0}": "Name of the new file in:\n{0}",
 "novo.txt": "new.txt",
 "Não foi possível criar o arquivo": "Could not create the file",
 "Arquivo criado: {0}": "File created: {0}",
 "Não foi possível ler as permissões:\n{0}": "Could not read the permissions:\n{0}",
 "Dono: {0}  •  Grupo: {1}": "Owner: {0}  •  Group: {1}",
 "Dono (uid): {0}  •  Grupo (gid): {1}": "Owner (uid): {0}  •  Group (gid): {1}",
 "sem permissão (só o dono do arquivo ou o root pode alterar)": "permission denied (only the file owner or root can change it)",
 "Permissões não alteradas": "Permissions not changed",
 "Permissões {0} aplicadas em {1} arquivo(s).": "Permissions {0} applied to {1} file(s).",
 "Renomear": "Rename",
 "Novo nome:": "New name:",
 "Não foi possível renomear": "Could not rename",
 "Selecione um arquivo ou pasta para excluir.": "Select a file or folder to delete.",
 "\n…": "\n…",
 "Mover para o Lixo {0} item(ns)?\n\n{1}": "Move {0} item(s) to the Trash?\n\n{1}",
 "Excluir DEFINITIVAMENTE do servidor {0} item(ns)?\n\n{1}": "PERMANENTLY delete {0} item(s) from the server?\n\n{1}",
 "\n\nPastas serão apagadas com todo o conteúdo.": "\n\nFolders will be deleted with all their contents.",
 "\n\nEssa ação não pode ser desfeita.": "\n\nThis cannot be undone.",
 "Confirmar exclusão": "Confirm deletion",
 "Alguns itens não foram excluídos": "Some items were not deleted",
 "{0} item(ns) excluído(s).": "{0} item(s) deleted.",
 "Lixo indisponível": "Trash unavailable",
 "Não foi possível mover para o Lixo:\n{0}\n\nApagar definitivamente?": "Could not move to the Trash:\n{0}\n\nDelete permanently?",
 "Destino existente": "Destination exists",
 "Já existe um item chamado “{0}” {1}.\nPastas serão mescladas e arquivos com o mesmo nome poderão ser substituídos. Continuar?": "An item named “{0}” already exists {1}.\nFolders will be merged and files with the same name may be replaced. Continue?",
 "no servidor": "on the server",
 "no computador": "on this computer",
 "Enviando para": "Uploading to",
 "Baixando de": "Downloading from",
 "Erro": "Error",
 "Falha na transferência": "Transfer failed",
 "já existe no destino": "already exists at the destination",
 "Alguns itens não foram movidos": "Some items were not moved",
 "{0} item(ns) movido(s) para {1}": "{0} item(s) moved to {1}",
 "Falha ao copiar": "Copy failed",
 "Sobre o {0}": "About {0}",
 "Versão {0}": "Version {0}",
 "Cliente SFTP/SSH nativo para macOS — o “WinSCP do Mac”.": "Native SFTP/SSH client for macOS — the “WinSCP for Mac”.",
 "Arrastar e soltar • várias conexões em abas<br>favoritos com Touch ID • editor de texto<br>permissões (chmod) • console SSH completo": "Drag and drop • multiple connections in tabs<br>favorites with Touch ID • text editor<br>permissions (chmod) • full SSH console",
 "© {0} {1}. Feito no Brasil 🇧🇷": "© {0} {1}. Made in Brazil 🇧🇷",
 "Ajuda": "Help",
 "Página do MacSCP no GitHub": "MacSCP on GitHub",
 "＋ Nova conexão": "＋ New connection",
 "Conectar a um servidor (⌘T abre nova aba)": "Connect to a server (⌘T opens a new tab)",
 "⭐ Favoritos": "⭐ Favorites",
 "Conectar a um favorito ou gerenciar": "Connect to a favorite or manage them",
 "Desconectar": "Disconnect",
 "Nova aba (⌘T)": "New tab (⌘T)",
 "Cada aba é uma conexão. Arraste entre os painéis ou solte em cima de uma pasta. Botão direito para mais opções.": "Each tab is a connection. Drag between the panels or drop onto a folder. Right-click for more options.",
 "Informe servidor e usuário.": "Enter the server and user.",
 "Conexão cancelada (Touch ID não confirmado).": "Connection cancelled (Touch ID not confirmed).",
 "\n\nEla será salva e, das próximas vezes, liberada pelo Touch ID.": "\n\nIt will be saved and, next time, unlocked with Touch ID.",
 "Senha — {0}": "Password — {0}",
 "Senha SSH de {0}@{1}\n(vazio = usar chave SSH){2}": "SSH password for {0}@{1}\n(empty = use SSH key){2}",
 "Senha não salva: {0}": "Password not saved: {0}",
 "Adicionar esta conexão aos favoritos…": "Add this connection to favorites…",
 "Gerenciar favoritos…": "Manage favorites…",
 "🔒 Bloquear favoritos (pedir Touch ID de novo)": "🔒 Lock favorites (ask for Touch ID again)",
 "Favoritos bloqueados — o próximo uso de senha salva pede Touch ID.": "Favorites locked — the next use of a saved password asks for Touch ID.",
 "Adicionar aos favoritos": "Add to favorites",
 "Nome do favorito:": "Favorite name:",
 "“{0}” foi salvo. Para guardar a senha, abra “Gerenciar favoritos…”.": "“{0}” was saved. To store the password, open “Manage favorites…”.",
 "Há {0} transferência(s) em andamento. Cancelar e sair?": "There are {0} transfer(s) in progress. Cancel and quit?",
 "Salvo às {0}  •  {1}": "Saved at {0}  •  {1}",
 "Conectado a {0}@{1}:{2}": "Connected to {0}@{1}:{2}",
 "Favorito salvo": "Favorite saved",
 "cancelado": "cancelled",
 "{0} — {1} arquivo(s) • {2}": "{0} — {1} file(s) • {2}",
 "(nenhum favorito ainda)": "(no favorites yet)",
 "Sair": "Quit",
 # menu de idioma
 "Idioma": "Language",
 "Reiniciar agora": "Restart now",
 "Depois": "Later",
 "Idioma alterado": "Language changed",
 "O MacSCP precisa reiniciar para mudar o idioma. Reiniciar agora?": "MacSCP needs to restart to change the language. Restart now?",
}


_TR_EXACT = {k: v for k, v in TR_EN.items() if not re.search(r"\{\d+\}", k)}
_TR_PATTERNS = []
for _k, _v in TR_EN.items():
    if re.search(r"\{\d+\}", _k):
        _parts = re.split(r"\{(\d+)\}", _k)
        _rx = "".join(re.escape(p) if i % 2 == 0 else f"(?P<g{p}>.*?)" for i, p in enumerate(_parts))
        _literal = len("".join(_parts[::2]))
        _TR_PATTERNS.append((_literal, re.compile(_rx + r"\Z", re.DOTALL), _v))
_TR_PATTERNS = [(rx, v) for _lit, rx, v in sorted(_TR_PATTERNS, key=lambda t: -t[0])]


def _(text):
    """Traduz um texto da interface para o idioma escolhido (o texto-fonte é o português)."""
    if LANG == "pt" or not isinstance(text, str):
        return text
    hit = _TR_EXACT.get(text)
    if hit is not None:
        return hit
    for rx, en in _TR_PATTERNS:
        m = rx.match(text)
        if m:
            vals = {k[1:]: _(val) for k, val in m.groupdict().items()}
            return re.sub(r"\{(\d+)\}", lambda mm: vals.get(mm.group(1), ""), en)
    return text


def settings_path():
    return config_dir() / "config.json"


def load_language():
    try:
        lang = json.loads(settings_path().read_text("utf-8")).get("language")
        if lang in dict(LANGUAGES): return lang
    except Exception:
        pass
    from PySide6.QtCore import QLocale
    return "pt" if QLocale.system().name().lower().startswith("pt") else "en"


def save_language(lang):
    try: data = json.loads(settings_path().read_text("utf-8"))
    except Exception: data = {}
    data["language"] = lang
    settings_path().write_text(json.dumps(data, indent=2), "utf-8")
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
        key_path, _unused = cls._paths()
        if key_path.exists():
            key = key_path.read_bytes()
            if len(key) == 32: return key
        key = AESGCM.generate_key(bit_length=256)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f: f.write(key)
        return key

    @classmethod
    def _load(cls):
        _unused, data_path = cls._paths()
        try: return json.loads(data_path.read_text("utf-8")) if data_path.exists() else {}
        except Exception: return {}

    @classmethod
    def _save(cls, items):
        _unused, data_path = cls._paths(); tmp = data_path.with_suffix(".tmp")
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
    if sys.platform != "darwin": TOUCH_ID_PROBLEM = _("só existe no macOS"); return None
    try:
        from LocalAuthentication import LAContext
    except Exception as e:
        TOUCH_ID_PROBLEM = _(f"módulo LocalAuthentication ausente no app ({e})"); return None
    try:
        ctx = LAContext.alloc().init()
        can, err = ctx.canEvaluatePolicy_error_(LA_POLICY_OWNER_AUTH, None)
        if not can:
            TOUCH_ID_PROBLEM = str(err.localizedDescription()) if err is not None else _("não disponível"); return None
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
        r = touch_id(_(f"usar a senha salva de “{what}”"))
        if r is False: return False
        if r is None and sys.platform == "darwin":
            # sem Touch ID: pede a senha do Mac (do seu usuário, não a das Chaves)
            pwd, ok = QInputDialog.getText(None, _("Desbloquear favoritos"),
                                           _(f"Touch ID indisponível ({TOUCH_ID_PROBLEM}).\n"
                                           "Digite a senha do seu usuário do Mac para usar as senhas salvas:"),
                                           QLineEdit.Password)
            if not ok or not check_mac_password(pwd):
                if ok: QMessageBox.warning(None, _("Senha incorreta"), _("Senha do Mac incorreta."))
                return False
        cls.unlocked = True
        return True

    @classmethod
    def lock(cls):
        cls.unlocked = False; Favorites._cache.clear()


class ConnectionDialog(QDialog):
    """Nova conexão (com opção de salvar nos favoritos)."""

    def __init__(self, parent=None):
        super().__init__(parent); self.setWindowTitle(_("Nova conexão SSH/SFTP")); self.setMinimumWidth(440)
        form = QFormLayout(self)
        self.host = QLineEdit(); self.host.setPlaceholderText(_("192.168.1.100 ou host.example"))
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(22)
        self.user = QLineEdit()
        self.password = QLineEdit(); self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText(_("vazio = usar chave SSH (~/.ssh)"))
        self.remote_dir = QLineEdit(); self.remote_dir.setPlaceholderText(_("opcional, ex.: /var/www"))
        form.addRow(_("Servidor / IP"), self.host); form.addRow(_("Porta"), self.port)
        form.addRow(_("Usuário"), self.user); form.addRow(_("Senha SSH"), self.password)
        form.addRow(_("Pasta remota inicial"), self.remote_dir)
        self.save_fav = QCheckBox(_("Salvar nos favoritos")); form.addRow(self.save_fav)
        self.fav_name = QLineEdit(); self.fav_name.setPlaceholderText(_("Nome do favorito (ex.: Raspberry)"))
        self.save_pwd = QCheckBox(_("Salvar senha (protegida por Touch ID)")); self.save_pwd.setChecked(True)
        form.addRow(_("Nome"), self.fav_name); form.addRow(self.save_pwd)
        self.save_fav.toggled.connect(self._toggle); self._toggle(False)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(_("Conectar"))
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
        super().__init__(parent); self.setWindowTitle(_("Favoritos")); self.resize(680, 380)
        self.favs = favorites; self.current_id = None
        root = QHBoxLayout(self)
        left = QVBoxLayout(); self.list = QListWidget(); left.addWidget(self.list, 1)
        lb = QHBoxLayout(); nb = QPushButton(_("＋ Novo")); db = QPushButton(_("Excluir"))
        lb.addWidget(nb); lb.addWidget(db); left.addLayout(lb); root.addLayout(left, 1)

        right = QVBoxLayout(); form = QFormLayout()
        self.name = QLineEdit(); self.host = QLineEdit()
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(22)
        self.user = QLineEdit(); self.password = QLineEdit(); self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText(_("vazio = usar chave SSH"))
        self.remote_dir = QLineEdit(); self.remote_dir.setPlaceholderText(_("opcional"))
        self.local_dir = QLineEdit(); self.local_dir.setPlaceholderText(_("opcional"))
        pick = QPushButton("…"); pick.setFixedWidth(32); pick.clicked.connect(self._pick_local)
        ld = QHBoxLayout(); ld.addWidget(self.local_dir, 1); ld.addWidget(pick)
        self.save_pwd = QCheckBox(_("Salvar senha (protegida por Touch ID)")); self.save_pwd.setChecked(True)
        form.addRow(_("Nome"), self.name); form.addRow(_("Servidor / IP"), self.host); form.addRow(_("Porta"), self.port)
        form.addRow(_("Usuário"), self.user); form.addRow(_("Senha"), self.password)
        form.addRow(_("Pasta remota inicial"), self.remote_dir); form.addRow(_("Pasta local inicial"), ld)
        form.addRow(self.save_pwd); right.addLayout(form); right.addStretch(1)
        rb = QHBoxLayout(); sb = QPushButton(_("Salvar")); cb = QPushButton(_("Conectar")); cb.setDefault(True)
        close = QPushButton(_("Fechar")); rb.addStretch(1); rb.addWidget(close); rb.addWidget(sb); rb.addWidget(cb)
        right.addLayout(rb); root.addLayout(right, 2)

        nb.clicked.connect(self.new); db.clicked.connect(self.delete); sb.clicked.connect(self.save)
        cb.clicked.connect(self.connect_selected); close.clicked.connect(self.reject)
        self.list.currentItemChanged.connect(self._load)
        self.list.itemDoubleClicked.connect(lambda *_: self.connect_selected())
        self._refresh_list()
        if self.list.count(): self.list.setCurrentRow(0)
        else: self.new()

    def _pick_local(self):
        p = QFileDialog.getExistingDirectory(self, _("Pasta local inicial"), self.local_dir.text() or str(Path.home()))
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
        self.password.setPlaceholderText(_("🔒 senha salva — deixe vazio para manter") if f.get("save_password")
                                         else _("vazio = perguntar ao conectar / usar chave SSH"))
        self.save_pwd.setChecked(bool(f.get("save_password", True)))

    def new(self):
        self.current_id = None; self.list.clearSelection()
        for w in (self.name, self.host, self.user, self.password, self.remote_dir, self.local_dir): w.clear()
        self.password.setPlaceholderText(_("vazio = usar chave SSH"))
        self.port.setValue(22); self.save_pwd.setChecked(True); self.name.setFocus()

    def _form_fav(self):
        host = self.host.text().strip(); user = self.user.text().strip()
        if not host or not user:
            QMessageBox.warning(self, _("Dados incompletos"), _("Informe pelo menos servidor e usuário.")); return None
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
            QMessageBox.warning(self, _("Senha não salva"), _(f"O favorito foi salvo, mas a senha não:\n{e}"))
        self.favs.upsert(fav); self.current_id = fav["id"]; self._refresh_list(fav["id"])
        return fav

    def delete(self):
        if not self.current_id: return
        f = self.favs.get(self.current_id)
        if QMessageBox.question(self, _("Excluir favorito"), _(f"Excluir “{f.get('name')}” e a senha salva?"),
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
        raise RuntimeError(_(f"Não encontrei o servidor “{host}”. Confira o nome/IP."))
    try:
        socket.create_connection((host, port), timeout=timeout).close()
    except socket.timeout:
        raise RuntimeError(_(f"Tempo esgotado ao conectar em {host}:{port}.\n\n"
                           "O servidor não respondeu: pode estar desligado, fora da VPN (ZeroTier/Tailscale) "
                           "ou com firewall bloqueando a porta."))
    except OSError as e:
        code = e.errno
        if code == errno.ECONNREFUSED:
            raise RuntimeError(_(f"{host} recusou a conexão na porta {port}.\n\n"
                               "O servidor está acessível, mas o SSH não está rodando nessa porta (confira a porta e o serviço ssh)."))
        if code in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EPERM, errno.EACCES) and sys.platform == "darwin" and is_private(host):
            raise RuntimeError(
                _(f"O macOS bloqueou o acesso a {host} (rede local/VPN).\n\n"
                "Provável causa: o MacSCP não tem permissão de Rede Local.\n"
                "Abra Ajustes do Sistema → Privacidade e Segurança → Rede Local e ative o MacSCP.\n"
                "Se ele não aparecer na lista, gere o app de novo com o build_macos.command atualizado.\n\n"
                f"Se continuar, teste no Terminal:  nc -vz {host} {port}\n"
                f"(erro do sistema: {e.strerror or code})"))
        if code in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            raise RuntimeError(_(f"Sem rota até {host}. Confira se a VPN (ZeroTier/Tailscale) está conectada "
                               f"e se este Mac está autorizado na rede.\n\n(erro do sistema: {e.strerror or code})"))
        raise RuntimeError(_(f"Não foi possível abrir conexão com {host}:{port}: {e.strerror or e}"))


def key_fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def known_hosts_name(host, port):
    return host if port == 22 else f"[{host}]:{port}"


def known_hosts_set(path, host, port, key):
    """Grava a chave do servidor no known_hosts mexendo SÓ nas linhas desse servidor.
    Remove as chaves antigas dele (texto ou hash) e acrescenta a nova; o resto do arquivo fica intacto."""
    name = known_hosts_name(host, port)

    def same_host(entry):
        if entry.startswith("|1|"):
            try: return paramiko.HostKeys.hash_host(name, entry) == entry
            except Exception: return False
        return entry == name

    lines = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="surrogateescape") as f: lines = f.read().splitlines()
    out = []
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#") and not s.startswith("@"):
            fields = s.split(None, 1)
            hosts = fields[0].split(",")
            keep = [h for h in hosts if not same_host(h)]
            if len(keep) != len(hosts):
                if not keep: continue                       # linha só desse servidor → sai
                line = ",".join(keep) + (" " + fields[1] if len(fields) > 1 else "")
        out.append(line)
    out.append(f"{name} {key.get_name()} {key.get_base64()}")
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".macscp-tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape") as f: f.write("\n".join(out) + "\n")
    os.replace(tmp, path)


def load_known_hosts_safe(client, path):
    """Lê o known_hosts linha por linha, ignorando o que o paramiko não entende
    (@cert-authority, @revoked, tipos de chave novos do OpenSSH, linhas com defeito).
    Sem isso, UMA linha estranha faz o paramiko recusar o arquivo inteiro."""
    if not os.path.exists(path): return
    hk = client.get_host_keys()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("@"): continue
            try:
                entry = paramiko.hostkeys.HostKeyEntry.from_line(s)
            except Exception:
                continue
            if entry is None or entry.key is None: continue
            for name in entry.hostnames:
                try: hk.add(name, entry.key.get_name(), entry.key)
                except Exception: pass


def fetch_server_key(host, port):
    transport = paramiko.Transport((host, port)); transport.banner_timeout = 12
    try:
        transport.start_client(timeout=12); return transport.get_remote_server_key()
    finally:
        transport.close()


def open_ssh(parent, host, port, user, password):
    """Abre SSHClient verificando a chave do servidor.
    Chave nova → pergunta e grava. Chave diferente da gravada → avisa, mostra antiga e nova e, se aceitar, atualiza."""
    known = os.path.expanduser('~/.ssh/known_hosts'); os.makedirs(os.path.dirname(known), mode=0o700, exist_ok=True)
    use_keys = not password
    opts = dict(hostname=host, port=port, username=user, password=password or None, timeout=12, banner_timeout=12,
                auth_timeout=15, allow_agent=use_keys, look_for_keys=use_keys)
    check_tcp(host, port)
    for attempt in range(2):
        client = paramiko.SSHClient()
        try:
            load_known_hosts_safe(client, known)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            client.connect(**opts)
            return client
        except paramiko.BadHostKeyException as exc:
            client.close()
            if attempt: raise
            new, old = exc.key, exc.expected_key
            box = QMessageBox(QMessageBox.Warning, _("A chave do servidor mudou"),
                              _(f"A chave SSH de {host}:{port} é diferente da que estava gravada neste Mac."),
                              QMessageBox.Yes | QMessageBox.No, parent)
            box.setInformativeText(
                _("Isso é normal se o servidor foi reinstalado/formatado, se esse IP agora é de outra máquina "
                "ou se a chave foi trocada. Se nada disso aconteceu, pode ser alguém interceptando a conexão.\n\n"
                f"Chave gravada:  {old.get_name()}  {key_fingerprint(old)}\n"
                f"Chave nova:     {new.get_name()}  {key_fingerprint(new)}\n\n"
                "Atualizar o known_hosts com a chave nova e conectar?"))
            box.button(QMessageBox.Yes).setText(_("Atualizar e conectar")); box.button(QMessageBox.No).setText(_("Cancelar"))
            box.setDefaultButton(QMessageBox.No)
            if box.exec() != QMessageBox.Yes: raise RuntimeError(_("Chave SSH alterada não foi aceita."))
            known_hosts_set(known, host, port, new)
        except paramiko.SSHException as exc:
            client.close()
            if attempt or 'not found in known_hosts' not in str(exc).lower(): raise
            key = fetch_server_key(host, port)
            answer = QMessageBox.question(
                parent, _("Confirmar chave SSH"),
                _(f"Servidor: {host}:{port}\nTipo: {key.get_name()}\nImpressão digital: {key_fingerprint(key)}\n\n"
                "Confirme com o administrador do servidor por um canal confiável. Deseja confiar nesta chave?"),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes: raise RuntimeError(_("Chave SSH não confirmada."))
            known_hosts_set(known, host, port, key)
        except Exception:
            client.close(); raise
    raise RuntimeError(_("Não foi possível validar a chave do servidor."))


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
        self.feed(_("\r\n\x1b[90m[Sessão encerrada — pode fechar a janela]\x1b[0m\r\n").encode())

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
        a = m.addAction(_("Copiar"), self.copy); a.setEnabled(bool(self._sel_range()))
        m.addAction(_("Colar"), self.paste); m.addSeparator()
        m.addAction(_("Selecionar tudo"), self.select_all); m.addAction(_("Limpar"), self.clear)
        m.addSeparator(); m.addAction(_("Aumentar fonte"), lambda: self.zoom(1)); m.addAction(_("Diminuir fonte"), lambda: self.zoom(-1))
        m.exec(self.mapToGlobal(pos))

    def focusInEvent(self, e): self.update(); super().focusInEvent(e)
    def focusOutEvent(self, e): self.update(); super().focusOutEvent(e)


class TerminalDialog(QDialog):
    def __init__(self, ssh, title, parent=None):
        super().__init__(parent); self.setWindowTitle(_(f"Console SSH — {title}"))
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
            self.term.feed(_(f"Não foi possível abrir o console: {e}\r\n").encode())
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
            self.progress.emit(0, 0, _("Analisando arquivos…"))
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
                            raise RuntimeError(_(f"O destino já existe e não é pasta: {dst}"))
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
            self.finished_ok.emit(True, _("Transferência concluída"), self.files_done)
        except Cancelled:
            self._remove_partial(sftp, partial)
            self.finished_ok.emit(False, _("Transferência cancelada"), self.files_done)
        except Exception as e:
            self._remove_partial(sftp, partial)
            self.finished_ok.emit(False, _(f"Erro: {e}"), self.files_done)
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
        self.file_label = QLabel(_("Preparando…")); self.file_label.setWordWrap(True)
        self.bar = QProgressBar(); self.bar.setRange(0, 0)
        self.info = QLabel("")
        self.cancel_btn = QPushButton(_("Cancelar")); self.cancel_btn.clicked.connect(self.cancel)
        bl = QHBoxLayout(); bl.addStretch(1); bl.addWidget(self.cancel_btn)
        lay.addWidget(self.file_label); lay.addWidget(self.bar); lay.addWidget(self.info); lay.addLayout(bl)
        worker.progress.connect(self._progress); worker.finished_ok.connect(self._done)

    def _progress(self, done, total, name):
        self.file_label.setText(name)
        if total:
            self.bar.setRange(0, 1000); self.bar.setValue(int(done * 1000 / total))
            el = max(time.monotonic() - self.started, 0.001); speed = done / el
            eta = (total - done) / speed if speed > 0 else 0
            self.info.setText(_(f"{human_size(done)} de {human_size(total)}  •  {human_size(speed)}/s  •  "
                              f"faltam ~{int(eta // 60)}min {int(eta % 60)}s"))

    def cancel(self):
        if self.finished: self.close(); return
        self.cancel_btn.setEnabled(False); self.cancel_btn.setText(_("Cancelando…")); self.worker.cancel()

    def _done(self, ok, msg, count):
        self.finished = True
        self.on_finish(ok, msg, count)
        self.close()

    def closeEvent(self, e):
        if not self.finished:
            self.worker.cancel(); self.cancel_btn.setText(_("Cancelando…")); e.ignore(); return
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
        self.blockCountChanged.connect(lambda _arg: self.setViewportMargins(self.number_width(), 0, 0, 0))
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
        self.find_input = QLineEdit(); self.find_input.setPlaceholderText(_("Buscar…  (Enter = próximo, ⇧Enter = anterior)"))
        self.find_case = QCheckBox("Aa"); self.find_case.setToolTip(_("Diferenciar maiúsculas/minúsculas"))
        fl.addWidget(QLabel(_("Buscar:"))); fl.addWidget(self.find_input, 1); fl.addWidget(self.find_case)
        for text, back in (("◀", True), ("▶", False)):
            b = QPushButton(text); b.setFixedWidth(36); b.clicked.connect(lambda _chk=False, back=back: self.find(back)); fl.addWidget(b)
        close = QPushButton("✕"); close.setFixedWidth(30); close.clicked.connect(self.find_bar.hide); fl.addWidget(close)
        self.find_input.returnPressed.connect(lambda: self.find(bool(QApplication.keyboardModifiers() & Qt.ShiftModifier)))
        self.find_bar.hide(); lay.addWidget(self.find_bar)
        self.setCentralWidget(central)

        where = session.title if side == "remote" else _("Computador local")
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
        self.pos_label.setText(_(f"Linha {c.blockNumber() + 1}, Coluna {c.positionInBlock() + 1}  "))

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
                self.statusBar().showMessage(_(f"“{text}” não encontrado"), 3000)

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
                if sftp is None: raise RuntimeError(_("A conexão com o servidor foi encerrada. Reconecte para salvar."))
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
            QMessageBox.critical(self, _("Sem permissão"), _(f"Seu usuário não tem permissão para gravar em:\n{self.path}"))
            return False
        except Exception as e:
            msg = str(e)
            if "permission" in msg.lower() or getattr(e, "errno", None) == errno.EACCES:
                msg = _(f"Seu usuário não tem permissão para gravar em:\n{self.path}")
            QMessageBox.critical(self, _("Não foi possível salvar"), msg)
            return False
        self.edit.document().setModified(False)
        self.statusBar().showMessage(_(f"Salvo às {time.strftime('%H:%M:%S')}  •  {human_size(len(data))}"), 5000)
        if self.side == "remote": self.session.load_remote(select=posixpath.basename(self.path))
        else: self.session.load_local(select=os.path.basename(self.path))
        return True

    def _confirm_conflict(self, current_mtime):
        if current_mtime is None or self.mtime is None or int(current_mtime) == int(self.mtime): return True
        return QMessageBox.warning(
            self, _("Arquivo alterado por fora"),
            _("Este arquivo foi modificado depois que você o abriu (por outra pessoa ou programa).\n\n"
            "Salvar mesmo assim e sobrescrever essas alterações?"),
            QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel) == QMessageBox.Yes

    def closeEvent(self, e):
        if self.edit.document().isModified():
            r = QMessageBox.question(self, _("Alterações não salvas"),
                                     _(f"Salvar as alterações em “{posixpath.basename(self.path)}”?"),
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
        super().__init__(parent); self.setWindowTitle(_("Permissões")); self.setMinimumWidth(380)
        self.special = mode & 0o7000          # setuid/setgid/sticky: preservados
        lay = QVBoxLayout(self)
        title = names[0] if len(names) == 1 else f"{len(names)} arquivos"
        head = QLabel(f"<b>{title}</b>" + (f"<br><span style='color:gray'>{owner_info}</span>" if owner_info else ""))
        head.setTextFormat(Qt.RichText); lay.addWidget(head)

        grid = QGridLayout(); grid.setHorizontalSpacing(18)
        for c, t in enumerate((_("Ler"), _("Gravar"), _("Executar"))): grid.addWidget(QLabel(f"<b>{t}</b>"), 0, c + 1, Qt.AlignCenter)
        self.boxes = []
        for r, who in enumerate((_("Dono"), _("Grupo"), _("Outros"))):
            grid.addWidget(QLabel(who), r + 1, 0)
            row = []
            for c in range(3):
                cb = QCheckBox(); cb.setChecked(bool(mode & self.BITS[r][c])); cb.toggled.connect(self._boxes_changed)
                grid.addWidget(cb, r + 1, c + 1, Qt.AlignCenter); row.append(cb)
            self.boxes.append(row)
        lay.addLayout(grid)

        ol = QHBoxLayout(); ol.addWidget(QLabel(_("Octal:")))
        self.octal = QLineEdit(); self.octal.setMaxLength(4); self.octal.setFixedWidth(70)
        self.octal.setValidator(QRegularExpressionValidator(QRegularExpression("[0-7]{3,4}")))
        self.octal.textEdited.connect(self._octal_changed); ol.addWidget(self.octal)
        self.preview = QLabel(); self.preview.setStyleSheet("font-family: Menlo, monospace; color: gray")
        ol.addWidget(self.preview); ol.addStretch(1); lay.addLayout(ol)

        quick = QHBoxLayout(); quick.addWidget(QLabel(_("Rápido:")))
        for m, tip in ((0o644, _("arquivo comum")), (0o755, _("script/executável")), (0o600, _("privado")), (0o664, _("grupo grava"))):
            b = QPushButton(f"{m:o}"); b.setToolTip(tip); b.clicked.connect(lambda _chk=False, m=m: self.set_mode(m)); quick.addWidget(b)
        quick.addStretch(1); lay.addLayout(quick)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText(_("Aplicar"))
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
        self.setColumnCount(3); self.setHeaderLabels([_("Nome"), _("Tamanho"), _("Modificado")])
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
        src, paths, dest, _unused = t
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
        self.ssh = None; self.sftp = None; self.title = _("Sem conexão")
        self.remote_path = '.'; self.local_path = str(Path.home()); self.transfers = []; self.editors = []
        layout = QVBoxLayout(self); layout.setContentsMargins(4, 4, 4, 4)
        split = QSplitter(Qt.Horizontal); layout.addWidget(split, 1)

        left = QWidget(); ll = QVBoxLayout(left); ll.setContentsMargins(0, 0, 0, 0); lh = QHBoxLayout()
        lh.addWidget(QLabel(_("<b>Computador local</b>")), 1)
        lh.addWidget(self._btn(_("Escolher pasta"), self.choose_local))
        lh.addWidget(self._btn(_("＋ Nova pasta"), lambda: self.create_folder('local'), _("Criar pasta (⇧⌘N)")))
        lh.addWidget(self._btn(_("Excluir"), lambda: self.delete_selected('local'), _("Excluir selecionados (⌫)")))
        lh.addWidget(self._btn("↑", self.local_up, _("Pasta acima")))
        ll.addLayout(lh)
        self.local_label = QLabel(self.local_path); self.local_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        ll.addWidget(self.local_label)
        self.local_tree = FileTree('local', self); ll.addWidget(self.local_tree, 1); split.addWidget(left)

        right = QWidget(); rl = QVBoxLayout(right); rl.setContentsMargins(0, 0, 0, 0); rh = QHBoxLayout()
        self.remote_title = QLabel(_("<b>Servidor remoto</b>")); rh.addWidget(self.remote_title, 1)
        rh.addWidget(self._btn(_("＋ Nova pasta"), lambda: self.create_folder('remote'), _("Criar pasta no servidor")))
        rh.addWidget(self._btn(_("Excluir"), lambda: self.delete_selected('remote'), _("Excluir selecionados no servidor (⌫)")))
        rh.addWidget(self._btn("↑", self.remote_up, _("Pasta acima")))
        rl.addLayout(rh)
        self.remote_label = QLabel(_("Não conectado — use “Nova conexão” ou “Favoritos”"))
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
            QMessageBox.warning(self, _("Sem conexão"), _("Esta aba não está conectada a um servidor.")); return False
        return True

    # ------------------------------------------------------------------ conexão
    def connect_to(self, host, port, user, password, title=None, remote_dir="", local_dir=""):
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            client = open_ssh(self, host, port, user, password)
            sftp = client.open_sftp()
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.critical(self, _("Falha na conexão"),
                                 _(f"Não foi possível conectar em {host}.\n\n{e}"))
            return False
        QApplication.restoreOverrideCursor()
        self.ssh = client; self.sftp = sftp
        self.remote_path = sftp.normalize('.')
        if remote_dir:
            try:
                if stat.S_ISDIR(sftp.stat(remote_dir).st_mode): self.remote_path = sftp.normalize(remote_dir)
            except IOError:
                self.status(_(f"Pasta remota inicial não encontrada: {remote_dir}"))
        if local_dir and os.path.isdir(local_dir): self.local_path = local_dir; self.load_local()
        self.title = title or f"{user}@{host}"
        self.remote_title.setText(_(f"<b>Servidor:</b> {user}@{host}:{port}"))
        self.title_changed.emit(self, self.title); self.load_remote()
        self.status(_(f"Conectado a {user}@{host}:{port}"))
        return True

    def disconnect(self, ask=True):
        if not self.close_editors(remote_only=True): return False
        running = [t for t in self.transfers if t.isRunning()]
        if running:
            if ask and QMessageBox.question(self, _("Transferências em andamento"),
                                            _(f"Há {len(running)} transferência(s) em andamento nesta conexão. Cancelar e desconectar?"),
                                            QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return False
            for t in running: t.cancel()
            for t in running: t.wait(5000)
        try:
            if self.sftp: self.sftp.close()
            if self.ssh: self.ssh.close()
        except Exception: pass
        self.sftp = self.ssh = None; self.title = _("Sem conexão")
        self.remote_title.setText(_("<b>Servidor remoto</b>"))
        self.remote_label.setText(_("Não conectado")); self.remote_tree.clear()
        self.title_changed.emit(self, self.title)
        return True

    def open_console(self):
        if not self.ssh: QMessageBox.information(self, _("Console SSH"), _("Esta aba não está conectada.")); return
        TerminalDialog(self.ssh, self.title, self.main).show()

    # ------------------------------------------------------------------ listagem / navegação
    def choose_local(self):
        path = QFileDialog.getExistingDirectory(self, _("Escolher pasta local"), self.local_path)
        if path: self.local_path = path; self.load_local()

    def _add_row(self, tree, name, path, isdir, size, extra):
        row = QTreeWidgetItem([name, size, extra])
        icons = Icons.get()
        row.setIcon(0, icons.local(path, isdir) if tree.side == 'local' else icons.remote(name, isdir))
        row.setData(0, PATH_ROLE, path); row.setData(0, ISDIR_ROLE, isdir)
        if isdir: row.setToolTip(0, _("Solte arquivos aqui para colocá-los dentro desta pasta"))
        tree.addTopLevelItem(row); return row

    def load_local(self, select=None):
        self.local_label.setText(self.local_path); self.local_tree.clear()
        try: items = sorted(os.scandir(self.local_path), key=lambda x: (not x.is_dir(follow_symlinks=False), x.name.lower()))
        except Exception as e: self.status(_(f"Erro ao listar pasta local: {e}")); return
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
        except Exception as e: self.status(_(f"Erro ao listar servidor: {e}")); return
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
            menu.addAction(_("Abrir"), lambda: self.open_item(side, sel[0]))
            a = menu.addAction(_("Nova pasta dentro de “%s”") % posixpath.basename(sel[0].data(0, PATH_ROLE)),
                               lambda: self.create_folder(side, sel[0].data(0, PATH_ROLE)))
            a.setEnabled(remote_ok)
            a = menu.addAction(_("Novo arquivo dentro de “%s”") % posixpath.basename(sel[0].data(0, PATH_ROLE)),
                               lambda: self.create_file(side, sel[0].data(0, PATH_ROLE)))
            a.setEnabled(remote_ok)
        a = menu.addAction(_("Nova pasta aqui…"), lambda: self.create_folder(side)); a.setEnabled(remote_ok)
        a = menu.addAction(_("Novo arquivo de texto aqui…"), lambda: self.create_file(side)); a.setEnabled(remote_ok)
        if sel:
            paths = [i.data(0, PATH_ROLE) for i in sel]
            menu.addSeparator()
            if side == 'local':
                a = menu.addAction(_("Enviar para o servidor  →"), lambda: self.handle_drop('local', paths, 'remote', self.remote_path))
                a.setEnabled(self.sftp is not None)
            else:
                menu.addAction(_("←  Baixar para o computador"), lambda: self.handle_drop('remote', paths, 'local', self.local_path))
            if len(sel) == 1 and not sel[0].data(0, ISDIR_ROLE):
                menu.addAction(_("✏️  Editar"), lambda: self.edit_file(side, paths[0]))
                if side == 'local': menu.addAction(_("Abrir com o app padrão"), lambda: self.open_default(paths[0]))
            files = [i.data(0, PATH_ROLE) for i in sel if not i.data(0, ISDIR_ROLE)]
            if files: menu.addAction(_("🔐  Permissões…"), lambda: self.change_permissions(side, files))
            if len(sel) == 1: menu.addAction(_("Renomear…"), lambda: self.rename_item(side, sel[0]))
            if side == 'local': menu.addAction(_("Mostrar no Finder"), lambda: self.reveal_in_finder(paths[0]))
            menu.addSeparator()
            label = _("Excluir “%s”") % posixpath.basename(paths[0]) if len(sel) == 1 else _(f"Excluir {len(sel)} itens")
            menu.addAction(label, lambda: self.delete_selected(side))
        menu.addSeparator()
        menu.addAction(_("Atualizar"), self.load_local if side == 'local' else self.load_remote)
        menu.exec(tree.viewport().mapToGlobal(pos))

    def open_default(self, path):
        try: subprocess.Popen(['open', path])
        except Exception as e: self.status(_(f"Não foi possível abrir: {e}"))

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
                if not stat.S_ISREG(st.st_mode or 0): raise RuntimeError(_("Não é um arquivo comum."))
            size = st.st_size or 0
            if size > EDIT_MAX_BYTES and QMessageBox.question(
                    self, _("Arquivo grande"), _(f"“{name}” tem {human_size(size)}. Abrir no editor mesmo assim?"),
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
            QMessageBox.critical(self, _("Não foi possível abrir"), f"{name}\n\n{e}"); return
        if decode_text(data) is None:
            if side == 'local': self.open_default(path)      # imagem, PDF etc. → app padrão do Mac
            else: QMessageBox.information(self, _("Arquivo binário"),
                                          _(f"“{name}” não é um arquivo de texto, então não dá para editar aqui.\n"
                                          "Baixe para o computador para abrir com outro app."))
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
        except Exception as e: self.status(_(f"Não foi possível abrir o Finder: {e}"))

    # ------------------------------------------------------------------ criar / renomear / excluir
    def create_folder(self, side, parent_dir=None):
        if side == 'remote' and not self.require_remote(): return
        parent_dir = parent_dir or self.current_dir(side)
        name, ok = QInputDialog.getText(self, _("Nova pasta"), _(f"Nome da nova pasta em:\n{parent_dir}"), text=_("Nova pasta"))
        if not ok: return
        name = name.strip()
        if not valid_name(name):
            QMessageBox.warning(self, _("Nome inválido"), _("Use um nome sem “/” e diferente de “.” ou “..”.")); return
        try:
            if side == 'local':
                target = os.path.join(parent_dir, name)
                if os.path.lexists(target): raise FileExistsError(_(f"Já existe um item chamado “{name}”."))
                os.mkdir(target)
            else:
                target = posixpath.join(parent_dir, name)
                if self.remote_exists(target): raise FileExistsError(_(f"Já existe um item chamado “{name}” no servidor."))
                self.sftp.mkdir(target)
        except Exception as e:
            QMessageBox.critical(self, _("Não foi possível criar a pasta"), str(e)); return
        self.status(_(f"Pasta criada: {target}"))
        same = parent_dir == self.current_dir(side)
        (self.load_local if side == 'local' else self.load_remote)(select=name if same else None)

    def create_file(self, side, parent_dir=None):
        """Cria um arquivo de texto vazio e já abre no editor."""
        if side == 'remote' and not self.require_remote(): return
        parent_dir = parent_dir or self.current_dir(side)
        name, ok = QInputDialog.getText(self, _("Novo arquivo"), _(f"Nome do novo arquivo em:\n{parent_dir}"), text=_("novo.txt"))
        if not ok: return
        name = name.strip()
        if not valid_name(name):
            QMessageBox.warning(self, _("Nome inválido"), _("Use um nome sem “/” e diferente de “.” ou “..”.")); return
        try:
            if side == 'local':
                target = os.path.join(parent_dir, name)
                if os.path.lexists(target): raise FileExistsError(_(f"Já existe um item chamado “{name}”."))
                with open(target, 'x'): pass
            else:
                target = posixpath.join(parent_dir, name)
                if self.remote_exists(target): raise FileExistsError(_(f"Já existe um item chamado “{name}” no servidor."))
                with self.sftp.open(target, 'w'): pass
        except Exception as e:
            QMessageBox.critical(self, _("Não foi possível criar o arquivo"), str(e)); return
        self.status(_(f"Arquivo criado: {target}"))
        same = parent_dir == self.current_dir(side)
        (self.load_local if side == 'local' else self.load_remote)(select=name if same else None)
        self.edit_file(side, target)

    def change_permissions(self, side, paths):
        """chmod de um ou mais arquivos (local ou no servidor)."""
        if side == 'remote' and not self.require_remote(): return
        try:
            st = os.stat(paths[0]) if side == 'local' else self.sftp.stat(paths[0])
        except Exception as e:
            QMessageBox.critical(self, _("Permissões"), _(f"Não foi possível ler as permissões:\n{e}")); return
        mode = stat.S_IMODE(st.st_mode or 0)
        info = ""
        if len(paths) == 1:
            uid, gid = getattr(st, "st_uid", None), getattr(st, "st_gid", None)
            if side == 'local':
                try:
                    import pwd, grp
                    info = _(f"Dono: {pwd.getpwuid(uid).pw_name}  •  Grupo: {grp.getgrgid(gid).gr_name}")
                except Exception: info = _(f"Dono (uid): {uid}  •  Grupo (gid): {gid}")
            elif uid is not None:
                info = _(f"Dono (uid): {uid}  •  Grupo (gid): {gid}")
        names = [posixpath.basename(p) for p in paths]
        dlg = PermissionsDialog(names, mode, info, self)
        if dlg.exec() != QDialog.Accepted: return
        new_mode = dlg.mode(); errors = []
        for p in paths:
            try:
                if side == 'local': os.chmod(p, new_mode)
                else: self.sftp.chmod(p, new_mode)
            except Exception as e:
                msg = _("sem permissão (só o dono do arquivo ou o root pode alterar)") if (
                    isinstance(e, PermissionError) or "permission" in str(e).lower()) else str(e)
                errors.append(f"{posixpath.basename(p)}: {msg}")
        (self.load_local if side == 'local' else self.load_remote)(select=names[0] if len(names) == 1 else None)
        if errors: QMessageBox.critical(self, _("Permissões não alteradas"), "\n".join(errors[:15]))
        else: self.status(_(f"Permissões {new_mode:03o} aplicadas em {len(paths)} arquivo(s)."))

    def rename_item(self, side, item):
        if side == 'remote' and not self.require_remote(): return
        old = item.data(0, PATH_ROLE); j = os.path if side == 'local' else posixpath
        old_name = j.basename(old)
        name, ok = QInputDialog.getText(self, _("Renomear"), _("Novo nome:"), text=old_name)
        name = (name or '').strip()
        if not ok or name == old_name: return
        if not valid_name(name):
            QMessageBox.warning(self, _("Nome inválido"), _("Use um nome sem “/” e diferente de “.” ou “..”.")); return
        new = j.join(j.dirname(old), name)
        try:
            if side == 'local':
                if os.path.lexists(new): raise FileExistsError(_(f"Já existe um item chamado “{name}”."))
                os.rename(old, new); self.load_local(select=name)
            else:
                if self.remote_exists(new): raise FileExistsError(_(f"Já existe um item chamado “{name}” no servidor."))
                self.sftp.rename(old, new); self.load_remote(select=name)
        except Exception as e:
            QMessageBox.critical(self, _("Não foi possível renomear"), str(e))

    def delete_selected(self, side):
        if side == 'remote' and not self.require_remote(): return
        tree = self.tree(side); paths = tree.selected_paths()
        if not paths:
            QMessageBox.information(self, _("Excluir"), _("Selecione um arquivo ou pasta para excluir.")); return
        n_dirs = sum(1 for it in tree.selectedItems() if it.data(0, ISDIR_ROLE))
        names = "\n".join("• " + posixpath.basename(p.rstrip('/')) for p in paths[:10]) + ("\n…" if len(paths) > 10 else "")
        if side == 'local':
            msg = _(f"Mover para o Lixo {len(paths)} item(ns)?\n\n{names}")
        else:
            msg = (_(f"Excluir DEFINITIVAMENTE do servidor {len(paths)} item(ns)?\n\n{names}")
                   + (_("\n\nPastas serão apagadas com todo o conteúdo.") if n_dirs else "")
                   + _("\n\nEssa ação não pode ser desfeita."))
        if QMessageBox.warning(self, _("Confirmar exclusão"), msg, QMessageBox.Yes | QMessageBox.Cancel,
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
        if errors: QMessageBox.critical(self, _("Alguns itens não foram excluídos"), "\n".join(errors[:15]))
        else: self.status(_(f"{len(paths)} item(ns) excluído(s)."))

    def local_delete(self, path):
        res = QFile.moveToTrash(path)
        ok = res[0] if isinstance(res, tuple) else bool(res)
        if ok: return
        if QMessageBox.question(self, _("Lixo indisponível"),
                                _(f"Não foi possível mover para o Lixo:\n{path}\n\nApagar definitivamente?"),
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            raise RuntimeError(_("cancelado"))
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
            self, _("Destino existente"),
            _(f"Já existe um item chamado “{name}” {where}.\n"
            "Pastas serão mescladas e arquivos com o mesmo nome poderão ser substituídos. Continuar?"),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes

    def start_transfer(self, paths, source_side, dest_side, dest_dir):
        if not self.require_remote(): return
        jobs = []
        for path in paths:
            if source_side == 'local':
                name = os.path.basename(path.rstrip(os.sep)); target = posixpath.join(dest_dir, name)
                if self.remote_exists(target) and not self._confirm_overwrite(name, _("no servidor")): continue
                jobs.append(('up', path, target))
            else:
                name = posixpath.basename(path.rstrip('/')); target = os.path.join(dest_dir, name)
                if os.path.lexists(target) and not self._confirm_overwrite(name, _("no computador")): continue
                jobs.append(('down', path, target))
        if not jobs: return
        worker = TransferWorker(self.ssh, jobs); self.transfers.append(worker)
        verb = _("Enviando para") if source_side == 'local' else _("Baixando de")
        title = f"{verb} {self.title}"

        def finish(ok, msg, count, worker=worker):
            if worker in self.transfers: self.transfers.remove(worker)
            self.status(_(f"{msg} — {count} arquivo(s) • {self.title}"))
            if self.sftp: self.refresh()
            else: self.load_local()
            if not ok and msg.startswith(_("Erro")): QMessageBox.critical(self, _("Falha na transferência"), msg)

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
                    if os.path.lexists(target): raise FileExistsError(_("já existe no destino"))
                    shutil.move(p, target)
                else:
                    if self.remote_exists(target): raise FileExistsError(_("já existe no destino"))
                    self.sftp.rename(p, target)
                moved += 1
            except Exception as e: errors.append(f"{name}: {e}")
        (self.load_local if side == 'local' else self.load_remote)()
        if errors: QMessageBox.warning(self, _("Alguns itens não foram movidos"), "\n".join(errors[:15]))
        if moved: self.status(_(f"{moved} item(ns) movido(s) para {dest_dir}"))

    def copy_local_items(self, paths, dest_dir):
        for p in paths:
            name = os.path.basename(p.rstrip(os.sep)); target = os.path.join(dest_dir, name)
            if os.path.abspath(target) == os.path.abspath(p): continue
            if os.path.lexists(target) and not self._confirm_overwrite(name, "nesta pasta"): continue
            try:
                if os.path.isdir(p) and not os.path.islink(p): shutil.copytree(p, target, symlinks=True, dirs_exist_ok=True)
                else: shutil.copy2(p, target, follow_symlinks=False)
            except Exception as e: QMessageBox.critical(self, _("Falha ao copiar"), f"{name}: {e}")
        self.load_local()



class AboutDialog(QDialog):
    """Sobre o MacSCP."""

    def __init__(self, parent=None):
        super().__init__(parent); self.setWindowTitle(_(f"Sobre o {APP_NAME}")); self.setFixedWidth(420)
        lay = QVBoxLayout(self); lay.setSpacing(6); lay.setContentsMargins(28, 24, 28, 18)
        ic = app_icon()
        icon = QLabel(); icon.setPixmap((ic if not ic.isNull() else Icons.get().folder).pixmap(96, 96)); icon.setAlignment(Qt.AlignCenter)
        name = QLabel(f"<span style='font-size:22pt; font-weight:600'>{APP_NAME}</span>"); name.setAlignment(Qt.AlignCenter)
        ver = QLabel(_(f"Versão {APP_VERSION}")); ver.setAlignment(Qt.AlignCenter)
        ver.setTextInteractionFlags(Qt.TextSelectableByMouse)
        desc = QLabel(_("Cliente SFTP/SSH nativo para macOS — o “WinSCP do Mac”.")); desc.setAlignment(Qt.AlignCenter); desc.setWordWrap(True)
        feats = QLabel(_("Arrastar e soltar • várias conexões em abas<br>"
                       "favoritos com Touch ID • editor de texto<br>"
                       "permissões (chmod) • console SSH completo"))
        feats.setAlignment(Qt.AlignCenter); feats.setWordWrap(True); feats.setStyleSheet("color: gray")
        link = QLabel(f"<a href='{APP_URL}'>{APP_URL.replace('https://', '')}</a>"); link.setAlignment(Qt.AlignCenter)
        link.setOpenExternalLinks(True)
        try:
            import PySide6
            from PySide6.QtCore import qVersion
            pyside = f"PySide6 {PySide6.__version__} (Qt {qVersion()})"
        except Exception:
            pyside = "PySide6"
        try:
            from importlib.metadata import version as _pkg_version
            pyte_v = _pkg_version("pyte")
        except Exception:
            pyte_v = ""
        tech = QLabel(f"Python {sys.version.split()[0]} • {pyside}<br>paramiko {paramiko.__version__} • pyte {pyte_v}".strip())
        tech.setAlignment(Qt.AlignCenter); tech.setStyleSheet("color: gray; font-size: 11px")
        copy_ = QLabel(_(f"© {time.strftime('%Y')} {APP_AUTHOR}. Feito no Brasil 🇧🇷")); copy_.setAlignment(Qt.AlignCenter)
        copy_.setStyleSheet("color: gray; font-size: 11px")
        for wdg in (icon, name, ver):
            lay.addWidget(wdg)
        lay.addSpacing(8)
        for wdg in (desc, feats, link):
            lay.addWidget(wdg)
        lay.addSpacing(10); lay.addWidget(tech); lay.addWidget(copy_); lay.addSpacing(8)
        ok = QPushButton("OK"); ok.setDefault(True); ok.clicked.connect(self.accept)
        bl = QHBoxLayout(); bl.addStretch(1); bl.addWidget(ok); bl.addStretch(1); lay.addLayout(bl)


# ============================================================================= janela principal

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__(); self.setWindowTitle(f"{APP_NAME} {APP_VERSION}"); self.resize(1240, 760)
        # menu: no macOS “Sobre o MacSCP” vai automaticamente para o menu do app (MacSCP ▸ Sobre o MacSCP)
        help_menu = self.menuBar().addMenu(_("Ajuda"))
        about = QAction(_(f"Sobre o {APP_NAME}"), self); about.setMenuRole(QAction.AboutRole)
        about.triggered.connect(lambda: AboutDialog(self).exec()); help_menu.addAction(about)
        gh = QAction(_("Página do MacSCP no GitHub"), self); gh.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(APP_URL)))
        help_menu.addAction(gh)
        lang_menu = self.menuBar().addMenu("Idioma / Language")
        group = QActionGroup(self); group.setExclusive(True)
        for code, label in LANGUAGES:
            act = QAction(label, self, checkable=True); act.setChecked(code == LANG)
            act.triggered.connect(lambda _c=False, code=code: self.change_language(code))
            group.addAction(act); lang_menu.addAction(act)
        self.favorites = Favorites()
        root = QWidget(); self.setCentralWidget(root); layout = QVBoxLayout(root)

        top = QHBoxLayout()
        b = QPushButton(_("＋ Nova conexão")); b.setToolTip(_("Conectar a um servidor (⌘T abre nova aba)"))
        b.clicked.connect(self.new_connection); top.addWidget(b)
        # botão comum (mesmo visual dos outros); o menu abre logo abaixo dele
        self.fav_btn = QPushButton(_("⭐ Favoritos")); self.fav_btn.setToolTip(_("Conectar a um favorito ou gerenciar"))
        self.fav_menu = QMenu(self); self.fav_btn.clicked.connect(self._show_fav_menu)
        top.addWidget(self.fav_btn)
        top.addStretch(1)
        for text, slot in ((_("Console SSH"), lambda: self.session().open_console()),
                           (_("Atualizar"), lambda: self.session().refresh()),
                           (_("Desconectar"), lambda: self.session().disconnect())):
            btn = QPushButton(text); btn.clicked.connect(slot); top.addWidget(btn)
        layout.addLayout(top)

        self.tabs = QTabWidget(); self.tabs.setTabsClosable(True); self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True); self.tabs.tabCloseRequested.connect(self.close_tab)
        plus = QToolButton(); plus.setText("＋"); plus.setToolTip(_("Nova aba (⌘T)")); plus.clicked.connect(lambda: self.add_session())
        self.tabs.setCornerWidget(plus, Qt.TopRightCorner)
        layout.addWidget(self.tabs, 1)
        self.add_session()

        for keys, slot in (("Ctrl+T", lambda: self.add_session()),
                           ("Ctrl+W", lambda: self.close_tab(self.tabs.currentIndex())),
                           ("Ctrl+Shift+N", lambda: self.session().create_folder(self.session().focused_side())),
                           ("Ctrl+N", self.new_connection), ("Ctrl+R", lambda: self.session().refresh())):
            act = QAction(self); act.setShortcut(QKeySequence(keys)); act.triggered.connect(slot); self.addAction(act)

        self.statusBar().showMessage(_("Cada aba é uma conexão. Arraste entre os painéis ou solte em cima de uma pasta. "
                                     "Botão direito para mais opções."))

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
            QMessageBox.warning(self, _("Dados incompletos"), _("Informe servidor e usuário.")); return
        title = None
        if dlg.save_fav.isChecked():
            fav = dict(name=dlg.fav_name.text().strip() or f"{v['user']}@{v['host']}", host=v["host"], port=v["port"],
                       user=v["user"], remote_dir=v["remote_dir"], local_dir="", save_password=dlg.save_pwd.isChecked())
            fav = self.favorites.upsert(fav); title = fav["name"]
            if fav["save_password"] and v["password"]:
                try: Favorites.set_password(fav["id"], v["password"])
                except Exception as e: QMessageBox.warning(self, _("Senha não salva"), str(e))
        s = self.target_session()
        s.connect_to(v["host"], v["port"], v["user"], v["password"], title, v["remote_dir"])

    def connect_favorite(self, fav, password=None):
        asked = False
        if password is None:
            password = ""
            if fav.get("save_password"):
                if not Unlock.ensure(fav.get("name") or fav["host"]):
                    self.statusBar().showMessage(_("Conexão cancelada (Touch ID não confirmado).")); return
                password = Favorites.get_password(fav["id"])
            if not password:
                extra = _("\n\nEla será salva e, das próximas vezes, liberada pelo Touch ID.") if fav.get("save_password") else ""
                pwd, ok = QInputDialog.getText(self, _(f"Senha — {fav['name']}"),
                                               _(f"Senha SSH de {fav['user']}@{fav['host']}\n(vazio = usar chave SSH){extra}"),
                                               QLineEdit.Password)
                if not ok: return
                password = pwd; asked = True
        s = self.target_session()
        ok = s.connect_to(fav["host"], int(fav.get("port", 22)), fav["user"], password, fav.get("name"),
                          fav.get("remote_dir", ""), fav.get("local_dir", ""))
        if ok and asked and password and fav.get("save_password"):
            try: Favorites.set_password(fav["id"], password); Unlock.unlocked = True
            except Exception as e: self.statusBar().showMessage(_(f"Senha não salva: {e}"))

    def _show_fav_menu(self):
        self._build_fav_menu()
        self.fav_menu.exec(self.fav_btn.mapToGlobal(self.fav_btn.rect().bottomLeft()))

    def _build_fav_menu(self):
        self.fav_menu.clear()
        if not self.favorites.items:
            a = self.fav_menu.addAction(_("(nenhum favorito ainda)")); a.setEnabled(False)
        for f in self.favorites.items:
            self.fav_menu.addAction(f"{f.get('name')}   —   {f['user']}@{f['host']}",
                                    lambda f=f: self.connect_favorite(f))
        self.fav_menu.addSeparator()
        if self.session() and self.session().connected:
            self.fav_menu.addAction(_("Adicionar esta conexão aos favoritos…"), self.add_current_to_favorites)
        self.fav_menu.addAction(_("Gerenciar favoritos…"), self.manage_favorites)
        if Unlock.unlocked:
            self.fav_menu.addAction(_("🔒 Bloquear favoritos (pedir Touch ID de novo)"), self._lock)

    def _lock(self):
        Unlock.lock(); self.statusBar().showMessage(_("Favoritos bloqueados — o próximo uso de senha salva pede Touch ID."))

    def add_current_to_favorites(self):
        s = self.session(); t = s.ssh.get_transport(); host, port = t.getpeername()[:2]
        user = t.get_username()
        name, ok = QInputDialog.getText(self, _("Adicionar aos favoritos"), _("Nome do favorito:"), text=s.title)
        if not ok: return
        fav = self.favorites.upsert(dict(name=name.strip() or s.title, host=host, port=port, user=user,
                                         remote_dir=s.remote_path, local_dir=s.local_path, save_password=False))
        QMessageBox.information(self, _("Favorito salvo"),
                                _(f"“{fav['name']}” foi salvo. Para guardar a senha, abra “Gerenciar favoritos…”."))

    def manage_favorites(self):
        dlg = FavoritesDialog(self.favorites, self)
        dlg.connect_requested.connect(lambda fav, pwd: QTimer.singleShot(0, lambda: self.connect_favorite(fav, pwd)))
        dlg.exec()

    def change_language(self, code):
        if code == LANG: return
        save_language(code)
        new = TR_EN if code == "en" else {}
        ask = lambda t: new.get(t, t)       # pergunta já no idioma escolhido
        box = QMessageBox(QMessageBox.Question, ask("Idioma alterado"),
                          ask("O MacSCP precisa reiniciar para mudar o idioma. Reiniciar agora?"),
                          QMessageBox.Yes | QMessageBox.No, self)
        box.button(QMessageBox.Yes).setText(ask("Reiniciar agora")); box.button(QMessageBox.No).setText(ask("Depois"))
        if box.exec() == QMessageBox.Yes: self.restart_app()

    def restart_app(self):
        if not self.close(): return          # usuário cancelou (transferências/edições pendentes)
        if getattr(sys, "frozen", False): QProcess.startDetached(sys.executable, sys.argv[1:])
        else: QProcess.startDetached(sys.executable, sys.argv)
        QApplication.quit()

    def closeEvent(self, event):
        running = sum(1 for i in range(self.tabs.count()) for t in self.tabs.widget(i).transfers if t.isRunning())
        if running and QMessageBox.question(self, _("Sair"), _(f"Há {running} transferência(s) em andamento. Cancelar e sair?"),
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
        print(f"  Ícone: {'OK' if os.path.exists(resource_path('MacSCP_icon.png')) else 'não encontrado'}")
    except Exception as e:
        print(f"  Cofre de senhas: ERRO — {e}"); ok = False
    return 0 if ok else 1


def main():
    if "--self-test" in sys.argv: sys.exit(self_test())
    app = QApplication(sys.argv); app.setApplicationName(APP_NAME); app.setApplicationVersion(APP_VERSION)
    app.setWindowIcon(app_icon())
    global LANG
    LANG = load_language()
    if LANG == "pt":   # botões padrão do Qt (Yes/No/Cancel…) em português
        tr = QTranslator(app)
        if tr.load("qtbase_pt_BR", QLibraryInfo.path(QLibraryInfo.TranslationsPath)): app.installTranslator(tr)
    win = MainWindow(); win.show(); sys.exit(app.exec())


if __name__ == '__main__':
    main()
