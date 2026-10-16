#!/usr/bin/env python3
"""MacSCP — cliente SFTP nativo para macOS (estilo WinSCP). Não inicia servidor web."""
import os, sys, stat, json, shutil, hashlib, base64, posixpath, time, uuid, subprocess, socket, errno, ipaddress, threading
import copy, math, re
from collections import deque
from pathlib import Path

import paramiko
import pyte
from PySide6.QtCore import Qt, QMimeData, QThread, Signal, QUrl, QTimer, QFile, QObject
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
    QToolButton, QCheckBox, QListWidget, QListWidgetItem, QProgressBar, QFileIconProvider, QGridLayout, QComboBox,
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM   # já vem com o paramiko

APP_NAME = "MacSCP"
APP_VERSION = "1.4.0"          # única fonte da versão (o build lê daqui)
APP_AUTHOR = "Xela"
APP_URL = "https://github.com/xelaex/MacSCP"



def resource_path(name):
    """Arquivo que vai junto com o app (funciona rodando o .py ou o .app gerado pelo PyInstaller)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)



def unique_copy_name(name, exists):
    """“foto.jpg” → “foto cópia.jpg”, “foto cópia 2.jpg”…  (exists(nome) diz se já existe)."""
    multi = next((e for e in (".tar.gz", ".tar.bz2", ".tar.xz") if name.lower().endswith(e)), None)
    base, ext = (name[: -len(multi)], name[-len(multi):]) if multi else os.path.splitext(name)
    if base.startswith('.') and not ext: base, ext = name, ""
    suffix = _(" cópia")
    cand = f"{base}{suffix}{ext}"; n = 2
    while exists(cand):
        cand = f"{base}{suffix} {n}{ext}"; n += 1
    return cand


def app_bundle_path():
    """Caminho do MacSCP.app quando rodando o app empacotado no macOS (senão None)."""
    if sys.platform != "darwin" or not getattr(sys, "frozen", False): return None
    p = os.path.abspath(sys.executable)          # .../MacSCP.app/Contents/MacOS/MacSCP
    for _i in range(3): p = os.path.dirname(p)
    return p if p.endswith(".app") else None

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
 "Colar dentro de “%s”": "Paste into “%s”",
 "{0} item(ns) copiado(s)": "{0} item(s) copied",
 "Nada para colar.": "Nothing to paste.",
 " cópia": " copy",
 "nesta pasta": "in this folder",
 "Substituir": "Replace",
 "Manter os dois": "Keep both",
 "Pular": "Skip",
 "Já existe um item chamado “{0}” {1}.": "An item named “{0}” already exists {1}.",
 "Copiar entre servidores": "Copy between servers",
 "Itens de outra aba (outro servidor) não podem ser colados aqui. Baixe para o computador primeiro.": "Items from another tab (another server) can't be pasted here. Download them to your computer first.",
 "Não dá para copiar “{0}” para dentro dela mesma.": "Can't copy “{0}” into itself.",
 "Copiando em": "Copying on",
 # --- versão 1.4.0
 "Criado: {0}": "Created: {0}",
 "Extraído em: {0}": "Extracted to: {0}",
 "Transferências": "Transfers",
 "Limpar concluídas": "Clear finished",
 "Histórico (log)": "History (log)",
 "Filtrar…": "Filter…",
 "Sincronizar pastas": "Sync folders",
 "Apagar no destino o que não existe na origem": "Delete at the destination what doesn't exist at the source",
 "Pasta local": "Local folder",
 "Pasta no servidor": "Server folder",
 "Direção": "Direction",
 "Comparar": "Compare",
 "Clique em “Comparar” para ver o que vai mudar.": "Click “Compare” to see what will change.",
 "Sincronizar": "Sync",
 "Comparando…": "Comparing…",
 "Novo": "New",
 "Alterado": "Changed",
 "Apagar no destino": "Delete at destination",
 "Sincronizar → servidor": "Sync → server",
 "Sincronizar → computador": "Sync → computer",
 "SINCRONIZOU": "SYNCED",
 "SALVOU": "SAVED",
 "Digite um caminho e tecle Enter": "Type a path and press Enter",
 "CONECTOU": "CONNECTED",
 "Carregando…": "Loading…",
 "CRIOU PASTA": "CREATED FOLDER",
 "CRIOU ARQUIVO": "CREATED FILE",
 "Aplicar a todos": "Apply to all",
 "Compactar": "Compress",
 "Formato:": "Format:",
 "Arquivos": "Files",
 "Nome do arquivo compactado:": "Archive name:",
 "Compactando {0}": "Compressing {0}",
 "Extraindo {0}": "Extracting {0}",
 "Ferramentas": "Tools",
 "⇅ Transferências": "⇅ Transfers",
 "Sincronizar…": "Sync…",
 " ({0} retomado(s))": " ({0} resumed)",
 "Retomando {0}": "Resuming {0}",
 "Transferência": "Transfer",
 "Servidor": "Server",
 "Progresso": "Progress",
 "Detalhes": "Details",
 "Status": "Status",
 "Pausar": "Pause",
 "Retomar": "Resume",
 "Simultâneas:": "Simultaneous:",
 "Limpar histórico": "Clear history",
 "(histórico vazio)": "(history is empty)",
 "Apagar todo o histórico?": "Delete the whole history?",
 "o servidor devolveu o código {0}": "the server returned code {0}",
 "Computador → Servidor (enviar)": "Computer → Server (upload)",
 "Servidor → Computador (baixar)": "Server → Computer (download)",
 "Ação": "Action",
 "Caminho": "Path",
 "A pasta local não existe.": "The local folder does not exist.",
 "{0} novo(s) • {1} alterado(s) • {2} para apagar": "{0} new • {1} changed • {2} to delete",
 "Tudo igual — nada para sincronizar.": "Everything matches — nothing to sync.",
 "{0} item(ns) com “{1}”": "{0} item(s) matching “{1}”",
 "DESCONECTOU": "DISCONNECTED",
 "{0} item(ns) • {1}": "{0} item(s) • {1}",
 "Mover para cá": "Move here",
 "🗜  Compactar…": "🗜  Compress…",
 "PERMISSÕES": "PERMISSIONS",
 "Movendo para": "Moving to",
 "Movendo de": "Moving from",
 "{0} item(ns) recortado(s) — ⌘V para mover": "{0} item(s) cut — ⌘V to move",
 "Sincronizar pastas…": "Sync folders…",
 "Histórico (log)…": "History (log)…",
 "COPIOU": "COPIED",
 "Concluído": "Done",
 "{0} item(ns) serão apagados no destino. Continuar?": "{0} item(s) will be deleted at the destination. Continue?",
 "Pasta não encontrada: {0}": "Folder not found: {0}",
 "FALHA AO CONECTAR": "CONNECTION FAILED",
 "Recortar": "Cut",
 "📦  Extrair aqui": "📦  Extract here",
 "RENOMEOU": "RENAMED",
 "MOVEU": "MOVED",
 "COMPACTOU": "COMPRESSED",
 "EXTRAIU": "EXTRACTED",
 "Pausada": "Paused",
 "📦  Extrair em “%s/”": "📦  Extract to “%s/”",
 " (pasta)": " (folder)",
 "MANDOU PARA O LIXO": "MOVED TO TRASH",
 "EXCLUIU": "DELETED",
 "ENVIOU": "UPLOADED",
 "BAIXOU": "DOWNLOADED",
 "APAGOU": "DELETED",
 "Na fila": "Queued",
 "Transferindo": "Transferring",
 "Concluída": "Done",
 "Cancelada": "Cancelled",
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


# ============================================================================= histórico (log)

LOG_MAX_BYTES = 5 * 1024 * 1024
_LOG_LOCK = threading.Lock()


def log_path():
    return config_dir() / "historico.log"


def log_event(action, detail="", server=""):
    """Grava uma linha no histórico: data/hora, servidor, ação e detalhes. Nunca derruba o app."""
    try:
        p = log_path()
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}  " + (f"[{server}]  " if server else "") + f"{action}  {detail}"
        with _LOG_LOCK:
            if p.exists() and p.stat().st_size > LOG_MAX_BYTES:
                p.replace(p.with_name("historico.1.log"))
            with open(p, "a", encoding="utf-8") as f:
                f.write(line.rstrip() + "\n")
    except Exception:
        pass


# ============================================================================= transferência em segundo plano

PART_SUFFIX = ".macscp-part"      # arquivo incompleto (permite retomar)
CHUNK = 262144
ARCHIVE_EXTS = (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar", ".zip", ".gz")


def archive_ext(name):
    low = name.lower()
    for ext in ARCHIVE_EXTS:
        if low.endswith(ext): return ext
    return None


class Cancelled(Exception):
    pass


_LIVE_THREADS = set()


class _Reaper(QObject):
    """Vive na thread principal: só solta a thread depois que ela terminou de verdade."""

    def reap(self):
        t = self.sender()
        if t is None: return
        try: t.wait(2000)
        except RuntimeError: pass
        QTimer.singleShot(0, lambda t=t: _LIVE_THREADS.discard(t))


_REAPER = None


def wait_all_threads(timeout_ms=4000):
    """Ao sair: pede para as tarefas pararem e espera elas terminarem."""
    for t in list(_LIVE_THREADS):
        try:
            if hasattr(t, "cancel"): t.cancel(discard=False) if "discard" in t.cancel.__code__.co_varnames else t.cancel()
            t.wait(timeout_ms)
        except Exception: pass


def keep_alive(thread):
    """Guarda a referência da thread até ela terminar (soltar antes derruba o app)."""
    global _REAPER
    if _REAPER is None: _REAPER = _Reaper()
    _LIVE_THREADS.add(thread)
    thread.finished.connect(_REAPER.reap)          # conexão “queued”: roda na thread principal
    return thread


class TransferWorker(QThread):
    """Envia/baixa/copia num canal SFTP próprio, sem travar a janela.
    - arquivos são gravados como “nome.macscp-part” e só ganham o nome final no fim → dá para retomar;
    - mantém a data de modificação original (arquivos e pastas) e as permissões de quem já existia;
    - jobs: ('up'|'down'|'rcopy', origem, destino) e ('rdel'|'ldel', caminho, None)."""
    progress = Signal(object, object, str)     # bytes feitos, bytes totais, texto
    finished_ok = Signal(bool, str, int)       # sucesso, mensagem, nº de arquivos

    def __init__(self, ssh, jobs, server="", move=False):
        super().__init__(); self.ssh = ssh; self.jobs = jobs; self.server = server; self.move = move
        self._cancel = False; self.discard = True; self.done_bytes = 0; self.total = 0
        self._last_emit = 0; self.files_done = 0; self.resumed = 0; self._partial = None; self.dir_times = []

    def cancel(self, discard=True):
        """discard=False = pausar (mantém o pedaço já transferido para retomar depois)."""
        self.discard = discard; self._cancel = True

    def _check(self):
        if self._cancel: raise Cancelled()

    def _emit(self, text, force=False):
        now = time.monotonic()
        if force or now - self._last_emit > 0.1:
            self._last_emit = now; self.progress.emit(self.done_bytes, self.total, text)

    # --- planejamento: (tipo, origem, destino, tamanho, mtime)
    def _plan_up(self, src, dst, plan):
        self._check()
        if os.path.islink(src): return
        st = os.stat(src)
        if os.path.isdir(src):
            plan.append(('rmkdir', src, dst, 0, st.st_mtime))
            for n in sorted(os.listdir(src)):
                if n.endswith(PART_SUFFIX): continue
                self._plan_up(os.path.join(src, n), posixpath.join(dst, n), plan)
        elif os.path.isfile(src):
            plan.append(('put', src, dst, st.st_size, st.st_mtime))

    def _plan_down(self, sftp, src, dst, plan):
        self._check()
        st = sftp.lstat(src)
        if stat.S_ISLNK(st.st_mode): return
        if stat.S_ISDIR(st.st_mode):
            plan.append(('lmkdir', src, dst, 0, st.st_mtime))
            for a in sorted(sftp.listdir_attr(src), key=lambda a: a.filename):
                if a.filename.endswith(PART_SUFFIX): continue
                self._plan_down(sftp, posixpath.join(src, a.filename), os.path.join(dst, a.filename), plan)
        elif stat.S_ISREG(st.st_mode):
            plan.append(('get', src, dst, st.st_size or 0, st.st_mtime))

    def _remote_copy(self, sftp, src, dst, plan):
        """Copia no servidor com `cp -a` (rápido, mantém permissões/datas); sem shell, copia pelo SFTP."""
        import shlex
        self.progress.emit(0, 0, posixpath.basename(src))
        try: is_dir_target = stat.S_ISDIR(sftp.stat(dst).st_mode)
        except IOError: is_dir_target = False
        if is_dir_target and stat.S_ISDIR(sftp.stat(src).st_mode):
            cmd = f"cp -a -- {shlex.quote(src.rstrip('/') + '/.')} {shlex.quote(dst.rstrip('/') + '/')}"
        else:
            cmd = f"cp -a -- {shlex.quote(src)} {shlex.quote(dst)}"
        try:
            if run_remote(self.ssh, cmd, self)[0] == 0:
                self.files_done += 1; log_event(_("COPIOU"), f"{src} → {dst}", self.server); return
        except Cancelled:
            raise
        except Exception:
            pass
        self._plan_rcopy(sftp, src, dst, plan)

    def _plan_rcopy(self, sftp, src, dst, plan):
        self._check()
        st = sftp.lstat(src)
        if stat.S_ISLNK(st.st_mode): return
        if stat.S_ISDIR(st.st_mode):
            plan.append(('rmkdir', src, dst, 0, st.st_mtime))
            for a in sorted(sftp.listdir_attr(src), key=lambda a: a.filename):
                self._plan_rcopy(sftp, posixpath.join(src, a.filename), posixpath.join(dst, a.filename), plan)
        elif stat.S_ISREG(st.st_mode):
            plan.append(('rcp', src, dst, st.st_size or 0, st.st_mtime))

    # --- execução
    def run(self):
        sftp = None
        try:
            sftp = self.ssh.open_sftp()
            self.progress.emit(0, 0, _("Analisando arquivos…"))
            plan = []
            for direction, src, dst in self.jobs:
                if direction == 'up': self._plan_up(src, dst, plan)
                elif direction == 'down': self._plan_down(sftp, src, dst, plan)
                elif direction == 'rcopy': self._remote_copy(sftp, src, dst, plan)
                elif direction in ('rdel', 'ldel'): plan.append((direction, src, None, 0, None))
            self.total = sum(p[3] for p in plan)

            for kind, src, dst, size, mtime in plan:
                self._check()
                if kind == 'rmkdir':
                    try: sftp.mkdir(dst)
                    except IOError:
                        if not stat.S_ISDIR(sftp.stat(dst).st_mode):
                            raise RuntimeError(_(f"O destino já existe e não é pasta: {dst}"))
                    self.dir_times.append(('remote', dst, mtime))
                elif kind == 'lmkdir':
                    os.makedirs(dst, exist_ok=True); self.dir_times.append(('local', dst, mtime))
                elif kind == 'put':
                    self._put(sftp, src, dst, size, mtime); self.files_done += 1
                    log_event(_("ENVIOU"), f"{src} → {dst}", self.server)
                elif kind == 'get':
                    self._get(sftp, src, dst, size, mtime); self.files_done += 1
                    log_event(_("BAIXOU"), f"{src} → {dst}", self.server)
                elif kind == 'rcp':
                    self._rcp(sftp, src, dst, size, mtime); self.files_done += 1
                    log_event(_("COPIOU"), f"{src} → {dst}", self.server)
                elif kind == 'rdel':
                    self._emit(posixpath.basename(src), force=True); remote_rmtree_raw(sftp, src)
                    log_event(_("APAGOU"), src, self.server)
                elif kind == 'ldel':
                    self._emit(os.path.basename(src), force=True); local_remove(src)
                    log_event(_("APAGOU"), src, self.server)

            for side, path, mt in reversed(self.dir_times):        # data original das pastas (depois do conteúdo)
                if mt is None: continue
                try:
                    if side == 'remote': sftp.utime(path, (mt, mt))
                    else: os.utime(path, (mt, mt))
                except Exception: pass

            if self.move:                                          # mover = apagar a origem depois de tudo certo
                for direction, src, dst in self.jobs:
                    self._check()
                    if direction == 'up': local_remove(src)
                    elif direction == 'down': remote_rmtree_raw(sftp, src)
                    log_event(_("MOVEU"), f"{src} → {dst}", self.server)
            extra = _(f" ({self.resumed} retomado(s))") if self.resumed else ""
            self.finished_ok.emit(True, _("Transferência concluída") + extra, self.files_done)
        except Cancelled:
            if self.discard: self._remove_partial(sftp)
            self.finished_ok.emit(False, _("Transferência cancelada") if self.discard else _("Pausada"), self.files_done)
        except Exception as e:
            # o pedaço já transferido fica guardado: “Retomar” continua de onde parou
            self.finished_ok.emit(False, _(f"Erro: {e}"), self.files_done)
        finally:
            try:
                if sftp: sftp.close()
            except Exception: pass

    def _put(self, sftp, src, dst, size, mtime):
        name = os.path.basename(src); part = dst + PART_SUFFIX; offset = 0
        try:
            psize = sftp.stat(part).st_size or 0
            if 0 < psize <= size: offset = psize
        except IOError:
            pass
        try: old_mode = stat.S_IMODE(sftp.stat(dst).st_mode)
        except IOError: old_mode = None
        base = self.done_bytes; self.done_bytes = base + offset
        if offset: self.resumed += 1; self._emit(_(f"Retomando {name}"), force=True)
        else: self._emit(name, force=True)
        self._partial = ('remote', part)
        with open(src, 'rb') as fi, sftp.open(part, 'r+b' if offset else 'wb') as fo:
            fo.set_pipelined(True)
            if offset: fi.seek(offset); fo.seek(offset)
            done = offset
            while True:
                self._check()
                chunk = fi.read(CHUNK)
                if not chunk: break
                fo.write(chunk); done += len(chunk); self.done_bytes = base + done; self._emit(name)
        try:
            sftp.posix_rename(part, dst)
        except Exception:
            try: sftp.remove(dst)
            except IOError: pass
            sftp.rename(part, dst)
        self._partial = None
        try: sftp.chmod(dst, old_mode if old_mode is not None else stat.S_IMODE(os.stat(src).st_mode))
        except Exception: pass
        try: sftp.utime(dst, (mtime, mtime))
        except Exception: pass
        self.done_bytes = base + size

    def _get(self, sftp, src, dst, size, mtime):
        name = posixpath.basename(src); part = dst + PART_SUFFIX; offset = 0
        if os.path.exists(part):
            psize = os.path.getsize(part)
            if 0 < psize <= size: offset = psize
        old_mode = stat.S_IMODE(os.stat(dst).st_mode) if os.path.exists(dst) else None
        os.makedirs(os.path.dirname(dst) or '.', exist_ok=True)
        base = self.done_bytes; self.done_bytes = base + offset
        if offset: self.resumed += 1; self._emit(_(f"Retomando {name}"), force=True)
        else: self._emit(name, force=True)
        self._partial = ('local', part)
        with sftp.open(src, 'rb') as fi, open(part, 'r+b' if offset else 'wb') as fo:
            if offset: fi.seek(offset); fo.seek(offset)
            fi.prefetch(size)                      # lê adiantado a partir da posição atual (rápido)
            done = offset
            while True:
                self._check()
                chunk = fi.read(CHUNK)
                if not chunk: break
                fo.write(chunk); done += len(chunk); self.done_bytes = base + done; self._emit(name)
        os.replace(part, dst); self._partial = None
        if old_mode is not None:
            try: os.chmod(dst, old_mode)
            except Exception: pass
        if mtime:
            try: os.utime(dst, (mtime, mtime))
            except Exception: pass
        self.done_bytes = base + size

    def _rcp(self, sftp, src, dst, size, mtime):
        base = self.done_bytes; name = posixpath.basename(src); self._emit(name, force=True)
        self._partial = ('remote', dst)
        with sftp.open(src, 'rb') as fi, sftp.open(dst, 'wb') as fo:
            fi.prefetch(size); fo.set_pipelined(True); done = 0
            while True:
                self._check()
                chunk = fi.read(CHUNK)
                if not chunk: break
                fo.write(chunk); done += len(chunk); self.done_bytes = base + done; self._emit(name)
        self._partial = None
        try: sftp.chmod(dst, stat.S_IMODE(sftp.stat(src).st_mode))
        except Exception: pass
        try: sftp.utime(dst, (mtime, mtime))
        except Exception: pass
        self.done_bytes = base + size

    def _remove_partial(self, sftp):
        """Cancelar (não pausar): apaga o arquivo que ficou pela metade."""
        if not self._partial: return
        side, path = self._partial
        try:
            if side == 'remote' and sftp: sftp.remove(path)
            elif side == 'local' and os.path.exists(path): os.remove(path)
        except Exception: pass


def remote_rmtree_raw(sftp, path):
    st = sftp.lstat(path)
    if stat.S_ISDIR(st.st_mode):
        for a in sftp.listdir_attr(path): remote_rmtree_raw(sftp, posixpath.join(path, a.filename))
        sftp.rmdir(path)
    else:
        sftp.remove(path)


def local_remove(path):
    if os.path.isdir(path) and not os.path.islink(path): shutil.rmtree(path)
    elif os.path.lexists(path): os.remove(path)


def run_remote(ssh, cmd, worker=None, timeout=None):
    """Executa um comando no servidor. Retorna (código de saída, stdout, stderr). Cancelável pelo worker."""
    _i, out, err = ssh.exec_command(cmd, timeout=30)
    ch = out.channel; t0 = time.monotonic(); buf_out = b""; buf_err = b""
    while not ch.exit_status_ready():
        if worker is not None and worker._cancel: ch.close(); raise Cancelled()
        if timeout and time.monotonic() - t0 > timeout: ch.close(); raise RuntimeError("timeout")
        while ch.recv_ready(): buf_out += ch.recv(65536)
        while ch.recv_stderr_ready(): buf_err += ch.recv_stderr(65536)
        time.sleep(0.05)
    code = ch.recv_exit_status()
    buf_out += out.read(); buf_err += err.read()
    return code, buf_out.decode("utf-8", "replace"), buf_err.decode("utf-8", "replace")


class TaskWorker(QThread):
    """Tarefa genérica em segundo plano (compactar, extrair…). fn(worker) devolve a mensagem final."""
    progress = Signal(object, object, str)
    finished_ok = Signal(bool, str, int)

    def __init__(self, fn, label=""):
        super().__init__(); self.fn = fn; self.label = label; self._cancel = False; self.discard = True

    def cancel(self, discard=True): self.discard = discard; self._cancel = True

    def _check(self):
        if self._cancel: raise Cancelled()

    def run(self):
        try:
            self.progress.emit(0, 0, self.label)
            msg = self.fn(self)
            self.finished_ok.emit(True, msg or _("Concluído"), 1)
        except Cancelled:
            self.finished_ok.emit(False, _("Transferência cancelada"), 0)
        except Exception as e:
            self.finished_ok.emit(False, _(f"Erro: {e}"), 0)


# ============================================================================= fila de transferências

class TransferEntry:
    def __init__(self, session, title, jobs=None, move=False, task=None, on_done=None):
        self.session = session; self.title = title; self.jobs = jobs or []; self.move = move
        self.task = task; self.on_done = on_done
        self.status = "queued"; self.worker = None; self.done = 0; self.total = 0; self.text = ""
        self.started = None; self.message = ""; self.files = 0
        self.pause_requested = False; self.cancel_requested = False
        try: self.server = session.title
        except Exception: self.server = ""


STATUS_LABELS = {"queued": "Na fila", "running": "Transferindo", "paused": "Pausada", "done": "Concluída",
                 "cancelled": "Cancelada", "error": "Erro"}


class TransferQueue(QObject):
    """Fila única para todas as abas: no máximo N transferências ao mesmo tempo, o resto espera."""
    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent); self.entries = []; self.max_parallel = 2

    def running(self): return [e for e in self.entries if e.status == "running"]
    def active(self, session=None):
        return [e for e in self.entries if e.status in ("queued", "running", "paused")
                and (session is None or e.session is session)]

    def add(self, entry):
        self.entries.append(entry); self.changed.emit(); self._pump()
        return entry

    def _pump(self):
        for e in list(self.entries):
            if len(self.running()) >= self.max_parallel: break
            if e.status == "queued": self._start(e)

    def _start(self, e):
        ssh = getattr(e.session, "ssh", None) if e.session is not None else None
        if e.task is None and ssh is None:
            e.status = "error"; e.message = _("Sem conexão"); self.changed.emit(); return
        e.pause_requested = e.cancel_requested = False
        w = TaskWorker(e.task, e.title) if e.task is not None else TransferWorker(ssh, e.jobs, e.server, e.move)
        e.worker = w; e.status = "running"; e.started = time.monotonic(); e.done = e.total = 0; e.message = ""
        w.progress.connect(lambda d, t, txt, e=e: self._progress(e, d, t, txt))
        w.finished_ok.connect(lambda ok, msg, n, e=e: self._finished(e, ok, msg, n))
        keep_alive(w); w.start(); self.changed.emit()

    def _progress(self, e, done, total, text):
        e.done, e.total, e.text = done, total, text

    def _finished(self, e, ok, msg, count):
        e.files = count; e.message = msg; e.worker = None
        if e.pause_requested: e.status = "paused"
        elif ok: e.status = "done"
        elif e.cancel_requested: e.status = "cancelled"
        else: e.status = "error"
        if e.on_done:
            try: e.on_done(e)
            except RuntimeError: pass        # aba já fechada
        self.changed.emit(); self._pump()

    def pause(self, e):
        if e.status == "running" and e.worker: e.pause_requested = True; e.worker.cancel(discard=False)
        elif e.status == "queued": e.status = "paused"; self.changed.emit()

    def resume(self, e):
        if e.status in ("paused", "error", "cancelled"):
            e.status = "queued"; e.message = ""; self.changed.emit(); self._pump()

    def cancel(self, e):
        if e.status == "running" and e.worker: e.cancel_requested = True; e.worker.cancel(discard=True)
        elif e.status in ("queued", "paused"): e.status = "cancelled"; self.changed.emit(); self._pump()

    def clear_finished(self):
        self.entries = [e for e in self.entries if e.status in ("queued", "running", "paused", "error")]
        self.changed.emit()

    def cancel_session(self, session, wait=True):
        workers = []
        for e in self.entries:
            if e.session is session and e.status in ("queued", "running", "paused"):
                if e.worker: workers.append(e.worker)
                self.cancel(e)
        if wait:
            for w in workers:
                try: w.wait(5000)
                except RuntimeError: pass


class TransferQueueWindow(QDialog):
    """Janela “Transferências”: tudo o que está na fila, com pausar / retomar / cancelar."""

    def __init__(self, queue, parent=None):
        super().__init__(parent); self.queue = queue
        self.setWindowTitle(_("Transferências")); self.resize(860, 380)
        lay = QVBoxLayout(self)
        self.tree = QTreeWidget(); self.tree.setColumnCount(5); self.tree.setRootIsDecorated(False)
        self.tree.setHeaderLabels([_("Transferência"), _("Servidor"), _("Progresso"), _("Detalhes"), _("Status")])
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree.setColumnWidth(0, 280); self.tree.setColumnWidth(1, 120); self.tree.setColumnWidth(2, 150)
        self.tree.setColumnWidth(3, 200)
        lay.addWidget(self.tree, 1)
        bl = QHBoxLayout()
        for text, fn in ((_("Pausar"), self.queue.pause), (_("Retomar"), self.queue.resume), (_("Cancelar"), self.queue.cancel)):
            b = QPushButton(text); b.clicked.connect(lambda _c=False, fn=fn: self._apply(fn)); bl.addWidget(b)
        bl.addStretch(1)
        bl.addWidget(QLabel(_("Simultâneas:")))
        self.par = QSpinBox(); self.par.setRange(1, 6); self.par.setValue(queue.max_parallel)
        self.par.valueChanged.connect(self._set_parallel); bl.addWidget(self.par)
        clr = QPushButton(_("Limpar concluídas")); clr.clicked.connect(queue.clear_finished); bl.addWidget(clr)
        lay.addLayout(bl)
        self.items = {}
        queue.changed.connect(self.rebuild)
        self.timer = QTimer(self); self.timer.timeout.connect(self.update_progress); self.timer.start(300)
        self.rebuild()

    def _set_parallel(self, v):
        self.queue.max_parallel = v; self.queue._pump()

    def _selected(self):
        return [it.data(0, Qt.UserRole) for it in self.tree.selectedItems()]

    def _apply(self, fn):
        for e in self._selected(): fn(e)

    def rebuild(self):
        sel = set(id(e) for e in self._selected())
        self.tree.clear(); self.items = {}
        for e in self.queue.entries:
            it = QTreeWidgetItem([e.title, e.server, "", "", ""]); it.setData(0, Qt.UserRole, e)
            self.tree.addTopLevelItem(it)
            bar = QProgressBar(); bar.setRange(0, 1000); bar.setTextVisible(False); bar.setMaximumHeight(14)
            self.tree.setItemWidget(it, 2, bar); self.items[id(e)] = (it, bar)
            if id(e) in sel: it.setSelected(True)
        self.update_progress()

    def update_progress(self):
        for e in self.queue.entries:
            pair = self.items.get(id(e))
            if not pair: continue
            it, bar = pair
            label = _(STATUS_LABELS.get(e.status, e.status))
            if e.status == "running":
                if e.total:
                    bar.setRange(0, 1000); bar.setValue(int(e.done * 1000 / max(e.total, 1)))
                    el = max(time.monotonic() - (e.started or time.monotonic()), 0.001); speed = e.done / el
                    eta = (e.total - e.done) / speed if speed > 0 else 0
                    det = _(f"{human_size(e.done)} de {human_size(e.total)}  •  {human_size(speed)}/s  •  "
                            f"faltam ~{int(eta // 60)}min {int(eta % 60)}s")
                else:
                    bar.setRange(0, 0); det = e.text
                it.setText(3, det); it.setToolTip(3, e.text)
            else:
                bar.setRange(0, 1000)
                if e.status == "done": bar.setValue(1000)
                elif e.total: bar.setValue(int(e.done * 1000 / max(e.total, 1)))     # pausada/erro: mostra até onde foi
                it.setText(3, e.message + (f"  •  {human_size(e.done)} / {human_size(e.total)}" if e.total and e.status in ("paused", "error") else ""))
            it.setText(4, label)
            color = {"error": QColor("#d33"), "done": QColor("#2a8a3a"), "cancelled": QColor("#888")}.get(e.status)
            it.setForeground(4, QBrush(color) if color else QBrush())


class LogDialog(QDialog):
    """Histórico de tudo o que foi feito (enviado, baixado, apagado, renomeado…)."""

    def __init__(self, parent=None):
        super().__init__(parent); self.setWindowTitle(_("Histórico (log)")); self.resize(900, 520)
        lay = QVBoxLayout(self)
        self.filter = QLineEdit(); self.filter.setPlaceholderText(_("Filtrar…")); self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(self.reload); lay.addWidget(self.filter)
        self.text = QPlainTextEdit(); self.text.setReadOnly(True); self.text.setLineWrapMode(QPlainTextEdit.NoWrap)
        f = QFont("Menlo"); f.setStyleHint(QFont.Monospace); f.setPointSize(12); self.text.setFont(f)
        lay.addWidget(self.text, 1)
        bl = QHBoxLayout()
        for text, fn in ((_("Atualizar"), self.reload), (_("Mostrar no Finder"), self.reveal), (_("Limpar histórico"), self.clear)):
            b = QPushButton(text); b.clicked.connect(fn); bl.addWidget(b)
        bl.addStretch(1); close = QPushButton(_("Fechar")); close.clicked.connect(self.accept); bl.addWidget(close)
        lay.addLayout(bl); self.reload()

    def reload(self, *a):
        try: lines = log_path().read_text("utf-8", errors="replace").splitlines()[-5000:]
        except Exception: lines = []
        q = self.filter.text().strip().lower()
        if q: lines = [l for l in lines if q in l.lower()]
        self.text.setPlainText("\n".join(lines) if lines else _("(histórico vazio)"))
        self.text.moveCursor(QTextCursor.End)

    def reveal(self):
        p = log_path()
        if not p.exists(): p.touch()
        try: subprocess.Popen(['open', '-R', str(p)])
        except Exception: pass

    def clear(self):
        if QMessageBox.question(self, _("Limpar histórico"), _("Apagar todo o histórico?"),
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes: return
        try: log_path().write_text("", "utf-8")
        except Exception: pass
        self.reload()


# ============================================================================= compactar / extrair

def archive_stem(name):
    ext = archive_ext(name)
    return name[: -len(ext)] if ext else name


def compress_local(worker, folder, names, archive, fmt):
    import zipfile, tarfile
    dest = os.path.join(folder, archive)
    try:
        if fmt == "zip":
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
                for n in names:
                    p = os.path.join(folder, n)
                    if os.path.isdir(p) and not os.path.islink(p):
                        for root, dirs, files in os.walk(p):
                            worker._check()
                            rel_root = os.path.relpath(root, folder)
                            if not files and not dirs: z.write(root, rel_root)
                            for f in files:
                                worker._check(); worker.progress.emit(0, 0, os.path.join(rel_root, f))
                                z.write(os.path.join(root, f), os.path.join(rel_root, f))
                    else:
                        worker._check(); z.write(p, n)
        else:
            def flt(ti):
                worker._check(); worker.progress.emit(0, 0, ti.name); return ti
            with tarfile.open(dest, "w:gz") as t:
                for n in names: t.add(os.path.join(folder, n), arcname=n, filter=flt)
    except BaseException:
        try: os.remove(dest)
        except OSError: pass
        raise
    return _(f"Criado: {archive}")


def extract_local(worker, archive_path, dest):
    import zipfile, tarfile
    os.makedirs(dest, exist_ok=True)
    ext = archive_ext(archive_path)
    if ext == ".zip":
        with zipfile.ZipFile(archive_path) as z:
            for m in z.infolist():
                worker._check(); worker.progress.emit(0, 0, m.filename); z.extract(m, dest)   # zipfile já barra “../”
    elif ext == ".gz":
        import gzip
        out = os.path.join(dest, os.path.basename(archive_path)[:-3])
        with gzip.open(archive_path, "rb") as fi, open(out, "wb") as fo: shutil.copyfileobj(fi, fo)
    else:
        with tarfile.open(archive_path) as t:
            base = os.path.realpath(dest)
            inside = lambda p: p == base or p.startswith(base + os.sep)
            safe_filter = hasattr(tarfile, "data_filter")        # Python 3.12+: filtro de segurança oficial
            for m in t.getmembers():
                worker._check(); worker.progress.emit(0, 0, m.name)
                if safe_filter:
                    try: t.extract(m, dest, filter="data")
                    except tarfile.FilterError: pass               # caminho perigoso (“../”, link para fora): ignora
                    continue
                target = os.path.realpath(os.path.join(dest, m.name))
                if not inside(target): continue
                if m.issym() and not inside(os.path.realpath(os.path.join(os.path.dirname(target), m.linkname))): continue
                if m.islnk() and not inside(os.path.realpath(os.path.join(dest, m.linkname))): continue
                t.extract(m, dest)
    return _(f"Extraído em: {dest}")


_PY_ZIP = ("import sys,os,zipfile\n"
           "z=zipfile.ZipFile(sys.argv[1],'w',zipfile.ZIP_DEFLATED)\n"
           "for p in sys.argv[2:]:\n"
           " if os.path.isdir(p):\n"
           "  for r,d,f in os.walk(p):\n"
           "   for x in f: z.write(os.path.join(r,x))\n"
           " else: z.write(p)\n"
           "z.close()\n")


def compress_remote(worker, ssh, folder, names, archive, fmt):
    import shlex
    q = shlex.quote; items = " ".join(q(n) for n in names)
    if fmt == "zip":
        cmd = (f"cd {q(folder)} && if command -v zip >/dev/null 2>&1; then zip -r -q -y {q(archive)} -- {items}; "
               f"else python3 -c {q(_PY_ZIP)} {q(archive)} {items}; fi")
    else:
        cmd = f"cd {q(folder)} && tar -czf {q(archive)} -- {items}"
    code, out, err = run_remote(ssh, cmd, worker)
    if code != 0: raise RuntimeError((err or out).strip() or _(f"o servidor devolveu o código {code}"))
    return _(f"Criado: {archive}")


def extract_remote(worker, ssh, archive_path, dest):
    import shlex
    q = shlex.quote; ext = archive_ext(archive_path)
    if ext == ".zip":
        x = (f"if command -v unzip >/dev/null 2>&1; then unzip -o -q {q(archive_path)} -d {q(dest)}; "
             f"else python3 -m zipfile -e {q(archive_path)} {q(dest)}; fi")
    elif ext == ".gz":
        out_name = posixpath.join(dest, posixpath.basename(archive_path)[:-3])
        x = f"gzip -dc {q(archive_path)} > {q(out_name)}"
    else:
        flag = {".tar.gz": "z", ".tgz": "z", ".tar.bz2": "j", ".tbz2": "j", ".tar.xz": "J", ".txz": "J"}.get(ext, "")
        x = f"tar -x{flag}f {q(archive_path)} -C {q(dest)}"
    code, out, err = run_remote(ssh, f"mkdir -p {q(dest)} && {x}", worker)
    if code != 0: raise RuntimeError((err or out).strip() or _(f"o servidor devolveu o código {code}"))
    return _(f"Extraído em: {dest}")


# ============================================================================= sincronizar pastas

SYNC_SKIP = (".DS_Store",)


def _list_local(path):
    out = {}
    for ent in os.scandir(path):
        if ent.name in SYNC_SKIP or ent.name.endswith(PART_SUFFIX) or ent.is_symlink(): continue
        st = ent.stat(follow_symlinks=False); isdir = ent.is_dir(follow_symlinks=False)
        out[ent.name] = (isdir, 0 if isdir else st.st_size, st.st_mtime)
    return out


def _list_remote(sftp, path):
    out = {}
    for a in sftp.listdir_attr(path):
        mode = a.st_mode or 0
        if a.filename in SYNC_SKIP or a.filename.endswith(PART_SUFFIX) or stat.S_ISLNK(mode): continue
        isdir = stat.S_ISDIR(mode)
        out[a.filename] = (isdir, 0 if isdir else (a.st_size or 0), a.st_mtime or 0)
    return out


def compare_trees(list_src, list_dst, src_root, dst_root, j_src, j_dst, delete_extra, check=None, rel=""):
    """Compara origem × destino. Devolve [(ação, caminho_relativo, é_pasta, tamanho)].
    ação: 'new' (não existe no destino), 'changed' (tamanho ou data diferente), 'extra' (só no destino)."""
    res = []
    if check: check()
    src = list_src(j_src(src_root, rel) if rel else src_root)
    try: dst = list_dst(j_dst(dst_root, rel) if rel else dst_root)
    except (IOError, OSError): dst = {}
    for name, (isdir, size, mt) in sorted(src.items()):
        r = f"{rel}/{name}" if rel else name
        if name not in dst:
            res.append(("new", r, isdir, size))
        else:
            d_isdir, d_size, d_mt = dst[name]
            if isdir and d_isdir:
                res += compare_trees(list_src, list_dst, src_root, dst_root, j_src, j_dst, delete_extra, check, r)
            elif isdir != d_isdir:
                res.append(("changed", r, isdir, size))
            elif size != d_size or abs((mt or 0) - (d_mt or 0)) > 2:
                res.append(("changed", r, isdir, size))
    if delete_extra:
        for name, (isdir, size, mt) in sorted(dst.items()):
            if name not in src: res.append(("extra", f"{rel}/{name}" if rel else name, isdir, size))
    return res


class CompareWorker(QThread):
    done = Signal(object, str)

    def __init__(self, ssh, local_root, remote_root, upload, delete_extra):
        super().__init__(); self.ssh = ssh; self.local_root = local_root; self.remote_root = remote_root
        self.upload = upload; self.delete_extra = delete_extra; self._cancel = False

    def run(self):
        sftp = None
        try:
            sftp = self.ssh.open_sftp()
            lj = lambda root, rel: os.path.join(root, *rel.split("/"))
            rj = lambda root, rel: posixpath.join(root, rel)
            ll = _list_local; rl = lambda p: _list_remote(sftp, p)
            if self.upload:
                res = compare_trees(ll, rl, self.local_root, self.remote_root, lj, rj, self.delete_extra)
            else:
                res = compare_trees(rl, ll, self.remote_root, self.local_root, rj, lj, self.delete_extra)
            self.done.emit(res, "")
        except Exception as e:
            self.done.emit(None, str(e))
        finally:
            try:
                if sftp: sftp.close()
            except Exception: pass


class SyncDialog(QDialog):
    """Sincronizar pastas: compara computador × servidor e transfere só o que mudou."""

    def __init__(self, session):
        super().__init__(session.main); self.session = session; self.result = []; self.worker = None
        self.setWindowTitle(_("Sincronizar pastas")); self.resize(820, 560)
        lay = QVBoxLayout(self); form = QFormLayout()
        self.local = QLineEdit(session.local_path)
        pick = QPushButton("…"); pick.setFixedWidth(32); pick.clicked.connect(self._pick)
        lrow = QHBoxLayout(); lrow.addWidget(self.local, 1); lrow.addWidget(pick)
        self.remote = QLineEdit(session.remote_path)
        self.direction = QComboBox()
        self.direction.addItems([_("Computador → Servidor (enviar)"), _("Servidor → Computador (baixar)")])
        self.delete_extra = QCheckBox(_("Apagar no destino o que não existe na origem"))
        form.addRow(_("Pasta local"), lrow); form.addRow(_("Pasta no servidor"), self.remote)
        form.addRow(_("Direção"), self.direction); form.addRow("", self.delete_extra)
        lay.addLayout(form)
        cmp_row = QHBoxLayout(); self.cmp_btn = QPushButton(_("Comparar")); self.cmp_btn.clicked.connect(self.compare)
        self.summary = QLabel(_("Clique em “Comparar” para ver o que vai mudar.")); cmp_row.addWidget(self.cmp_btn)
        cmp_row.addWidget(self.summary, 1); lay.addLayout(cmp_row)
        self.tree = QTreeWidget(); self.tree.setColumnCount(3); self.tree.setRootIsDecorated(False)
        self.tree.setHeaderLabels([_("Ação"), _("Caminho"), _("Tamanho")]); self.tree.setColumnWidth(0, 170)
        self.tree.setColumnWidth(1, 470); lay.addWidget(self.tree, 1)
        bl = QHBoxLayout(); bl.addStretch(1)
        cancel = QPushButton(_("Cancelar")); cancel.clicked.connect(self.reject); bl.addWidget(cancel)
        self.go = QPushButton(_("Sincronizar")); self.go.setEnabled(False); self.go.setDefault(True)
        self.go.clicked.connect(self.run_sync); bl.addWidget(self.go); lay.addLayout(bl)
        for w in (self.local, self.remote): w.textChanged.connect(self._invalidate)
        self.direction.currentIndexChanged.connect(self._invalidate); self.delete_extra.toggled.connect(self._invalidate)

    def _pick(self):
        p = QFileDialog.getExistingDirectory(self, _("Escolher pasta local"), self.local.text())
        if p: self.local.setText(p)

    def _invalidate(self, *a):
        self.go.setEnabled(False); self.tree.clear(); self.result = []
        self.summary.setText(_("Clique em “Comparar” para ver o que vai mudar."))

    def compare(self):
        if not self.session.require_remote(): return
        if not os.path.isdir(self.local.text()):
            QMessageBox.warning(self, _("Sincronizar pastas"), _("A pasta local não existe.")); return
        self.cmp_btn.setEnabled(False); self.summary.setText(_("Comparando…")); self.tree.clear()
        self.worker = CompareWorker(self.session.ssh, self.local.text(), self.remote.text().rstrip("/") or "/",
                                    self.direction.currentIndex() == 0, self.delete_extra.isChecked())
        self.worker.done.connect(self._compared); keep_alive(self.worker); self.worker.start()

    def _compared(self, res, err):
        self.cmp_btn.setEnabled(True); self.worker = None
        if res is None:
            self.summary.setText(_(f"Erro: {err}")); return
        self.result = res
        labels = {"new": _("Novo"), "changed": _("Alterado"), "extra": _("Apagar no destino")}
        for action, rel, isdir, size in res:
            it = QTreeWidgetItem([labels[action] + (_(" (pasta)") if isdir else ""), rel, "" if isdir else human_size(size)])
            it.setCheckState(0, Qt.Checked); it.setData(0, Qt.UserRole, (action, rel, isdir, size))
            if action == "extra": it.setForeground(0, QBrush(QColor("#d33")))
            self.tree.addTopLevelItem(it)
        n = {k: sum(1 for r in res if r[0] == k) for k in ("new", "changed", "extra")}
        self.summary.setText(_(f"{n['new']} novo(s) • {n['changed']} alterado(s) • {n['extra']} para apagar")
                             if res else _("Tudo igual — nada para sincronizar."))
        self.go.setEnabled(bool(res))

    def run_sync(self):
        chosen = [self.tree.topLevelItem(i).data(0, Qt.UserRole) for i in range(self.tree.topLevelItemCount())
                  if self.tree.topLevelItem(i).checkState(0) == Qt.Checked]
        if not chosen: return
        if any(c[0] == "extra" for c in chosen) and QMessageBox.warning(
                self, _("Confirmar exclusão"), _(f"{sum(1 for c in chosen if c[0] == 'extra')} item(ns) serão apagados no destino. Continuar?"),
                QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel) != QMessageBox.Yes:
            return
        lroot = self.local.text(); rroot = self.remote.text().rstrip("/") or "/"; up = self.direction.currentIndex() == 0
        jobs = []
        for action, rel, isdir, size in chosen:
            lp = os.path.join(lroot, *rel.split("/")); rp = posixpath.join(rroot, rel)
            if action == "extra": jobs.append(('rdel' if up else 'ldel', rp if up else lp, None))
            elif up: jobs.append(('up', lp, rp))
            else: jobs.append(('down', rp, lp))
        jobs.sort(key=lambda j: j[0] in ('rdel', 'ldel'))          # apagar só depois de transferir
        title = _("Sincronizar → servidor") if up else _("Sincronizar → computador")
        s = self.session
        log_event(_("SINCRONIZOU"), f"{lroot} {'→' if up else '←'} {rroot} ({len(jobs)})", s.title)
        s.main.queue.add(TransferEntry(s, title, jobs, on_done=lambda e, s=s: s.after_transfer(e)))
        self.accept()


# ============================================================================= área de transferência

def clipboard_side():
    """De onde vieram os itens na área de transferência: 'local' | 'remote' | 'finder' | None."""
    return FileTree.parse_mime(QApplication.clipboard().mimeData())[1]


def clipboard_is_cut(mime):
    if mime is None or not mime.hasFormat(MIME_PATHS): return False
    try: return bool(json.loads(bytes(mime.data(MIME_PATHS)).decode()).get("cut"))
    except Exception: return False


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
        log_event(_("SALVOU"), self.path, self.session.title if self.side == "remote" else _("Computador local"))
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

SORT_ROLE = Qt.UserRole + 2
SYNC_LISTING = False        # True = lista o servidor de forma síncrona (usado nos testes automáticos)


class FileItem(QTreeWidgetItem):
    """Linha do painel: ordena por nome/tamanho/data de verdade e mantém as pastas sempre no topo."""

    def __lt__(self, other):
        tree = self.treeWidget(); col = tree.sortColumn() if tree else 0
        asc = tree.header().sortIndicatorOrder() == Qt.AscendingOrder if tree else True
        a_dir, b_dir = bool(self.data(0, ISDIR_ROLE)), bool(other.data(0, ISDIR_ROLE))
        if a_dir != b_dir: return a_dir if asc else b_dir
        ka, kb = self.data(col, SORT_ROLE), other.data(col, SORT_ROLE)
        if ka is None or kb is None or ka == kb:
            return (self.data(0, SORT_ROLE) or "") < (other.data(0, SORT_ROLE) or "")
        return ka < kb


class ListWorker(QThread):
    """Lista uma pasta do servidor sem travar a janela (canal SFTP só para listagens)."""
    done = Signal(int, str, object, str)

    def __init__(self, sftp, lock, gen, path):
        super().__init__(); self.sftp = sftp; self.lock = lock; self.gen = gen; self.path = path

    def run(self):
        try:
            with self.lock:
                p = self.sftp.normalize(self.path)
                attrs = self.sftp.listdir_attr(p)
            self.done.emit(self.gen, p, attrs, "")
        except Exception as e:
            self.done.emit(self.gen, self.path, None, str(e) or e.__class__.__name__)



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
        self.setSortingEnabled(True); self.sortByColumn(0, Qt.AscendingOrder)   # clicar no cabeçalho ordena

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
        if mime is None:                     # área de transferência vazia
            return None, None, []
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
        if e.matches(QKeySequence.Copy):
            self.session.copy_selected(self.side); return
        if e.matches(QKeySequence.Cut):
            self.session.copy_selected(self.side, cut=True); return
        if e.key() == Qt.Key_V and e.modifiers() & Qt.ControlModifier and e.modifiers() & Qt.AltModifier:
            self.session.paste(self.side, move=True); return           # ⌥⌘V: mover para cá (como no Finder)
        if e.matches(QKeySequence.Paste):
            self.session.paste(self.side); return
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
        self.remote_path = '.'; self.local_path = str(Path.home()); self.editors = []
        self.list_sftp = None; self.list_lock = threading.Lock(); self._list_gen = 0; self._list_worker = None
        self._list_pending = None; self._ok_remote_path = None; self.remote_home = "/"
        self._listed = {"local": None, "remote": None}
        layout = QVBoxLayout(self); layout.setContentsMargins(4, 4, 4, 4)
        split = QSplitter(Qt.Horizontal); layout.addWidget(split, 1)

        left = QWidget(); ll = QVBoxLayout(left); ll.setContentsMargins(0, 0, 0, 0); lh = QHBoxLayout()
        lh.addWidget(QLabel(_("<b>Computador local</b>")), 1)
        lh.addWidget(self._btn(_("Escolher pasta"), self.choose_local))
        lh.addWidget(self._btn(_("＋ Nova pasta"), lambda: self.create_folder('local'), _("Criar pasta (⇧⌘N)")))
        lh.addWidget(self._btn(_("Excluir"), lambda: self.delete_selected('local'), _("Excluir selecionados (⌫)")))
        lh.addWidget(self._btn("↑", self.local_up, _("Pasta acima")))
        ll.addLayout(lh)
        self.local_label, self.local_filter = self._path_row(ll, 'local')
        self.local_tree = FileTree('local', self); ll.addWidget(self.local_tree, 1); split.addWidget(left)

        right = QWidget(); rl = QVBoxLayout(right); rl.setContentsMargins(0, 0, 0, 0); rh = QHBoxLayout()
        self.remote_title = QLabel(_("<b>Servidor remoto</b>")); rh.addWidget(self.remote_title, 1)
        rh.addWidget(self._btn(_("＋ Nova pasta"), lambda: self.create_folder('remote'), _("Criar pasta no servidor")))
        rh.addWidget(self._btn(_("Excluir"), lambda: self.delete_selected('remote'), _("Excluir selecionados no servidor (⌫)")))
        rh.addWidget(self._btn("↑", self.remote_up, _("Pasta acima")))
        rl.addLayout(rh)
        self.remote_label, self.remote_filter = self._path_row(rl, 'remote')
        self.remote_label.setPlaceholderText(_("Não conectado — use “Nova conexão” ou “Favoritos”")); self.remote_label.setReadOnly(True)
        self.remote_tree = FileTree('remote', self); rl.addWidget(self.remote_tree, 1); split.addWidget(right)
        split.setSizes([560, 560])
        self.load_local()

    def _path_row(self, layout, side):
        """Barra de caminho editável (Enter navega) + campo de filtro."""
        row = QHBoxLayout()
        path = QLineEdit(); path.setToolTip(_("Digite um caminho e tecle Enter"))
        path.returnPressed.connect(lambda: self.path_entered(side))
        flt = QLineEdit(); flt.setPlaceholderText(_("Filtrar…")); flt.setClearButtonEnabled(True); flt.setMaximumWidth(170)
        flt.textChanged.connect(lambda _t: self.apply_filter(side))
        row.addWidget(path, 1); row.addWidget(flt); layout.addLayout(row)
        return path, flt

    def apply_filter(self, side):
        tree = self.tree(side); q = (self.local_filter if side == 'local' else self.remote_filter).text().strip().lower()
        shown = 0
        for i in range(tree.topLevelItemCount()):
            it = tree.topLevelItem(i); hide = bool(q) and q not in (it.text(0) or "").lower()
            it.setHidden(hide); shown += not hide
        if q: self.status(_(f"{shown} item(ns) com “{q}”"))

    def path_entered(self, side):
        if side == 'local':
            p = os.path.expanduser(self.local_label.text().strip())
            if os.path.isdir(p): self.local_path = os.path.abspath(p); self.load_local()
            else:
                self.status(_(f"Pasta não encontrada: {p}")); self.local_label.setText(self.local_path)
        else:
            if not self.sftp: return
            p = self.remote_label.text().strip() or "/"
            if p == "~" or p.startswith("~/"): p = self.remote_home.rstrip("/") + p[1:]
            self.load_remote(path=p)

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
            log_event(_("FALHA AO CONECTAR"), f"{user}@{host}:{port} — {str(e).splitlines()[0] if str(e) else e}", title or host)
            QMessageBox.critical(self, _("Falha na conexão"),
                                 _(f"Não foi possível conectar em {host}.\n\n{e}"))
            return False
        QApplication.restoreOverrideCursor()
        self.ssh = client; self.sftp = sftp
        try: self.list_sftp = client.open_sftp()            # canal separado para listar sem travar
        except Exception: self.list_sftp = None
        try: self.remote_home = sftp.normalize('.')
        except Exception: self.remote_home = "/"
        self.remote_label.setReadOnly(False); self._ok_remote_path = None
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
        log_event(_("CONECTOU"), f"{user}@{host}:{port}", self.title)
        return True

    def disconnect(self, ask=True):
        if not self.close_editors(remote_only=True): return False
        active = self.main.queue.active(self)
        if active:
            if ask and QMessageBox.question(self, _("Transferências em andamento"),
                                            _(f"Há {len(active)} transferência(s) em andamento nesta conexão. Cancelar e desconectar?"),
                                            QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return False
            self.main.queue.cancel_session(self)
        if self._list_worker is not None:
            try: self._list_worker.wait(3000)
            except RuntimeError: pass
        was = self.title if self.sftp else None
        try:
            if self.list_sftp: self.list_sftp.close()
            if self.sftp: self.sftp.close()
            if self.ssh: self.ssh.close()
        except Exception: pass
        if was: log_event(_("DESCONECTOU"), "", was)
        self.sftp = self.ssh = self.list_sftp = None; self.title = _("Sem conexão"); self.remote_label.setReadOnly(True)
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

    def _add_row(self, tree, name, path, isdir, size, mtime, extra):
        row = FileItem([name, "" if isdir else human_size(size), extra])
        icons = Icons.get()
        row.setIcon(0, icons.local(path, isdir) if tree.side == 'local' else icons.remote(name, isdir))
        row.setData(0, PATH_ROLE, path); row.setData(0, ISDIR_ROLE, isdir)
        row.setData(0, SORT_ROLE, name.lower()); row.setData(1, SORT_ROLE, -1 if isdir else int(size or 0))
        row.setData(2, SORT_ROLE, float(mtime or 0))
        if isdir: row.setToolTip(0, _("Solte arquivos aqui para colocá-los dentro desta pasta"))
        tree.addTopLevelItem(row); return row

    def _fill(self, side, entries, select):
        """entries: [(nome, caminho, é_pasta, tamanho, mtime, texto_extra)]"""
        tree = self.tree(side); tree.setSortingEnabled(False); tree.clear()
        chosen = None
        for name, path, isdir, size, mtime, extra in entries:
            row = self._add_row(tree, name, path, isdir, size, mtime, extra)
            if select and name == select: chosen = row
        tree.setSortingEnabled(True)
        if chosen is not None: tree.setCurrentItem(chosen); tree.scrollToItem(chosen)
        cur = self.current_dir(side)
        flt = self.local_filter if side == 'local' else self.remote_filter
        if self._listed[side] != cur and flt.text(): flt.blockSignals(True); flt.clear(); flt.blockSignals(False)
        self._listed[side] = cur
        self.apply_filter(side)

    def load_local(self, select=None):
        self.local_label.setText(self.local_path)
        try: items = list(os.scandir(self.local_path))
        except Exception as e: self.status(_(f"Erro ao listar pasta local: {e}")); self.local_tree.clear(); return
        entries = []
        for ent in items:
            if ent.name.endswith(PART_SUFFIX): continue
            try:
                isdir = ent.is_dir(follow_symlinks=False); st = ent.stat(follow_symlinks=False)
                entries.append((ent.name, ent.path, isdir, st.st_size, st.st_mtime,
                                time.strftime('%d/%m/%Y %H:%M', time.localtime(st.st_mtime))))
            except OSError: pass
        self._fill('local', entries, select)

    def load_remote(self, select=None, path=None):
        """Lista a pasta do servidor em segundo plano (a janela não trava em pastas grandes/servidores lentos)."""
        if not self.sftp: self.remote_tree.clear(); return
        path = path or self.remote_path
        self._list_gen += 1; req = (self._list_gen, path, select)
        if SYNC_LISTING or self.list_sftp is None:
            try:
                p = self.sftp.normalize(path); attrs = self.sftp.listdir_attr(p)
                self._list_done(req[0], p, attrs, "", select)
            except Exception as e:
                self._list_done(req[0], path, None, str(e), select)
            return
        if self._list_worker is not None: self._list_pending = req; return
        self._start_list(req)

    def _start_list(self, req):
        gen, path, select = req
        self.remote_tree.setCursor(Qt.BusyCursor); self.remote_label.setText(path); self.status(_("Carregando…"))
        w = ListWorker(self.list_sftp, self.list_lock, gen, path); self._list_worker = w
        w.done.connect(lambda g, p, a, err, select=select: self._list_done(g, p, a, err, select))
        keep_alive(w); w.start()

    def _list_done(self, gen, path, attrs, err, select=None):
        self._list_worker = None; self.remote_tree.unsetCursor()
        if self._list_pending is not None:
            req = self._list_pending; self._list_pending = None
            if req[0] != gen: self._start_list(req); return
        if gen != self._list_gen or not self.sftp: return
        if attrs is None:
            self.status(_(f"Erro ao listar servidor: {err}"))
            if self._ok_remote_path and self._ok_remote_path != path:
                self.remote_path = self._ok_remote_path
            self.remote_label.setText(self.remote_path); return
        self.remote_path = path; self._ok_remote_path = path; self.remote_label.setText(path)
        entries = []
        for a in attrs:
            if a.filename.endswith(PART_SUFFIX): continue
            mode = a.st_mode or 0; isdir = stat.S_ISDIR(mode)
            mt = time.strftime('%d/%m/%Y %H:%M', time.localtime(a.st_mtime)) if a.st_mtime else ''
            entries.append((a.filename, posixpath.join(path, a.filename), isdir, a.st_size or 0, a.st_mtime or 0,
                            f"{mt}  {stat.filemode(mode)}".strip()))
        self._fill('remote', entries, select)
        if self.main.statusBar().currentMessage() == _("Carregando…"):   # não apaga mensagens mais importantes
            self.status(_(f"{len(entries)} item(ns) • {path}"))

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
        menu.addSeparator()
        if sel:
            menu.addAction(_("Copiar") + "\t⌘C", lambda: self.copy_selected(side))
            menu.addAction(_("Recortar") + "\t⌘X", lambda: self.copy_selected(side, cut=True))
        can_paste = bool(FileTree.parse_mime(QApplication.clipboard().mimeData())[2]) and remote_ok
        a = menu.addAction(_("Colar") + "\t⌘V", lambda: self.paste(side)); a.setEnabled(can_paste)
        a = menu.addAction(_("Mover para cá") + "\t⌥⌘V", lambda: self.paste(side, move=True))
        a.setEnabled(can_paste and clipboard_side() != 'finder')
        if len(sel) == 1 and sel[0].data(0, ISDIR_ROLE):
            a = menu.addAction(_("Colar dentro de “%s”") % posixpath.basename(sel[0].data(0, PATH_ROLE)),
                               lambda: self.paste(side, sel[0].data(0, PATH_ROLE)))
            a.setEnabled(can_paste)
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
            menu.addSeparator()
            menu.addAction(_("🗜  Compactar…"), lambda: self.compress(side, paths))
            if len(sel) == 1 and not sel[0].data(0, ISDIR_ROLE) and archive_ext(posixpath.basename(paths[0])):
                stem = archive_stem(posixpath.basename(paths[0]))
                menu.addAction(_("📦  Extrair aqui"), lambda: self.extract(side, paths[0], False))
                menu.addAction(_("📦  Extrair em “%s/”") % stem, lambda: self.extract(side, paths[0], True))
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
        self.status(_(f"Pasta criada: {target}")); log_event(_("CRIOU PASTA"), target, self._where(side))
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
        self.status(_(f"Arquivo criado: {target}")); log_event(_("CRIOU ARQUIVO"), target, self._where(side))
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
        for p in paths: log_event(_("PERMISSÕES"), f"{new_mode:03o} {p}", self._where(side))

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
                os.rename(old, new); self.load_local(select=name); log_event(_("RENOMEOU"), f"{old} → {new}", self._where(side))
            else:
                if self.remote_exists(new): raise FileExistsError(_(f"Já existe um item chamado “{name}” no servidor."))
                self.sftp.rename(old, new); self.load_remote(select=name); log_event(_("RENOMEOU"), f"{old} → {new}", self._where(side))
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
                    if side == 'local': self.local_delete(p); log_event(_("MANDOU PARA O LIXO"), p, self._where(side))
                    else: self.remote_rmtree(p); log_event(_("EXCLUIU"), p, self._where(side))
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
    def handle_drop(self, src_side, paths, dest_side, dest_dir, move=False):
        if dest_side == 'remote' and not self.require_remote(): return
        finder = src_side == 'finder'
        if finder: src_side = 'local'
        if src_side == dest_side:
            if finder: self.copy_local_items(paths, dest_dir)
            else: self.move_items(dest_side, paths, dest_dir)
            return
        self.start_transfer(paths, src_side, dest_side, dest_dir, move=move)

    def _where(self, side):
        return self.title if side == 'remote' else _("Computador local")

    def _conflict(self, name, where, memo):
        """Item com o mesmo nome no destino → 'replace' | 'both' | 'skip'. “Manter os dois” é o padrão
        (o original fica e a cópia ganha “ cópia” no nome). memo guarda “aplicar a todos”."""
        if memo.get("all"): return memo["all"]
        box = QMessageBox(QMessageBox.Question, _("Destino existente"),
                          _(f"Já existe um item chamado “{name}” {where}."), QMessageBox.NoButton, self)
        rb = box.addButton(_("Substituir"), QMessageBox.DestructiveRole)
        kb = box.addButton(_("Manter os dois"), QMessageBox.AcceptRole)
        box.addButton(_("Pular"), QMessageBox.RejectRole)
        box.setDefaultButton(kb)
        cb = QCheckBox(_("Aplicar a todos")); box.setCheckBox(cb)
        box.exec()
        choice = {id(rb): "replace", id(kb): "both"}.get(id(box.clickedButton()), "skip")
        if cb.isChecked(): memo["all"] = choice
        return choice

    # compatibilidade (testes antigos chamam _ask_conflict)
    def _ask_conflict(self, name, where):
        return self._conflict(name, where, {})

    def start_transfer(self, paths, source_side, dest_side, dest_dir, move=False):
        if not self.require_remote(): return
        jobs = []; memo = {}
        for path in paths:
            if source_side == 'local':
                name = os.path.basename(path.rstrip(os.sep)); target = posixpath.join(dest_dir, name)
                if self.remote_exists(target):
                    choice = self._conflict(name, _("no servidor"), memo)
                    if choice == "skip": continue
                    if choice == "both":
                        target = posixpath.join(dest_dir, unique_copy_name(name, lambda n: self.remote_exists(posixpath.join(dest_dir, n))))
                jobs.append(('up', path, target))
            else:
                name = posixpath.basename(path.rstrip('/')); target = os.path.join(dest_dir, name)
                if os.path.lexists(target):
                    choice = self._conflict(name, _("no computador"), memo)
                    if choice == "skip": continue
                    if choice == "both":
                        target = os.path.join(dest_dir, unique_copy_name(name, lambda n: os.path.lexists(os.path.join(dest_dir, n))))
                jobs.append(('down', path, target))
        if not jobs: return None
        if move: verb = _("Movendo para") if source_side == 'local' else _("Movendo de")
        else: verb = _("Enviando para") if source_side == 'local' else _("Baixando de")
        names = ", ".join(posixpath.basename(j[1].rstrip('/')) for j in jobs[:3]) + ("…" if len(jobs) > 3 else "")
        entry = TransferEntry(self, f"{verb} {self.title}: {names}", jobs, move=move,
                              on_done=lambda e, s=self: s.after_transfer(e))
        self.main.queue.add(entry); self.main.show_transfers()
        self.status(f"{verb} {self.title}…")
        return entry

    def after_transfer(self, entry):
        self.status(_(f"{entry.message} — {entry.files} arquivo(s) • {self.title}"))
        if self.sftp: self.refresh()
        else: self.load_local()

    def move_items(self, side, paths, dest_dir):
        """Mover dentro do mesmo painel (arrastar para uma pasta, recortar/colar)."""
        j = os.path if side == 'local' else posixpath
        errors = []; moved = 0; memo = {}
        for p in paths:
            name = j.basename(p.rstrip('/')); target = j.join(dest_dir, name)
            np_, nd = p.rstrip('/'), dest_dir.rstrip('/') or '/'
            if nd == np_ or nd.startswith(np_ + '/'): continue
            if j.dirname(np_) == nd: continue                       # já está nessa pasta
            exists = os.path.lexists(target) if side == 'local' else self.remote_exists(target)
            try:
                if exists:
                    choice = self._conflict(name, _("nesta pasta") if side == 'local' else _("no servidor"), memo)
                    if choice == "skip": continue
                    if choice == "both":
                        ex = (lambda n: os.path.lexists(os.path.join(dest_dir, n))) if side == 'local' else \
                             (lambda n: self.remote_exists(posixpath.join(dest_dir, n)))
                        target = j.join(dest_dir, unique_copy_name(name, ex))
                    else:
                        if side == 'local': local_remove(target)
                        else: self.remote_rmtree(target)
                if side == 'local': shutil.move(p, target)
                else: self.sftp.rename(p, target)
                moved += 1; log_event(_("MOVEU"), f"{p} → {target}", self._where(side))
            except Exception as e: errors.append(f"{name}: {e}")
        (self.load_local if side == 'local' else self.load_remote)()
        if errors: QMessageBox.warning(self, _("Alguns itens não foram movidos"), "\n".join(errors[:15]))
        if moved: self.status(_(f"{moved} item(ns) movido(s) para {dest_dir}"))

    # ------------------------------------------------------------------ copiar / recortar / colar
    def copy_selected(self, side, cut=False):
        paths = self.tree(side).selected_paths()
        if not paths: return
        mime = QMimeData()
        mime.setData(MIME_PATHS, json.dumps({"session": id(self), "side": side, "paths": paths, "cut": cut}).encode())
        if side == 'local' and not cut: mime.setUrls([QUrl.fromLocalFile(p) for p in paths])   # ⌘V no Finder também
        mime.setText("\n".join(paths))
        QApplication.clipboard().setMimeData(mime)
        if cut: self.status(_(f"{len(paths)} item(ns) recortado(s) — ⌘V para mover"))
        else: self.status(_(f"{len(paths)} item(ns) copiado(s)"))

    def paste(self, side, dest_dir=None, move=None):
        if side == 'remote' and not self.require_remote(): return
        mime = QApplication.clipboard().mimeData()
        sess, src, paths = FileTree.parse_mime(mime)
        if not paths:
            self.status(_("Nada para colar.")); return
        cut = clipboard_is_cut(mime)
        move = cut if move is None else (move and src != 'finder')
        dest_dir = dest_dir or self.current_dir(side)
        if src == 'remote' and sess != id(self):
            QMessageBox.information(self, _("Copiar entre servidores"),
                                    _("Itens de outra aba (outro servidor) não podem ser colados aqui. Baixe para o computador primeiro."))
            return
        if src in ('local', 'finder'):
            if side == 'local': (self.move_items('local', paths, dest_dir) if move else self.copy_local_items(paths, dest_dir))
            else: self.start_transfer(paths, 'local', 'remote', dest_dir, move=move)
        else:
            if side == 'local': self.start_transfer(paths, 'remote', 'local', dest_dir, move=move)
            elif move: self.move_items('remote', paths, dest_dir)
            else: self.remote_copy(paths, dest_dir)
        if cut: QApplication.clipboard().clear()                      # recortar vale uma vez só

    def remote_copy(self, paths, dest_dir):
        """Copia itens dentro do mesmo servidor (feito no próprio servidor, sem passar pelo Mac)."""
        jobs = []; memo = {}
        for p in paths:
            name = posixpath.basename(p.rstrip('/')); target = posixpath.join(dest_dir, name)
            np_, nd = p.rstrip('/'), dest_dir.rstrip('/') or '/'
            if nd == np_ or nd.startswith(np_ + '/'):
                QMessageBox.warning(self, _("Falha ao copiar"), _(f"Não dá para copiar “{name}” para dentro dela mesma."))
                continue
            if target.rstrip('/') == np_:
                target = posixpath.join(dest_dir, unique_copy_name(name, lambda n: self.remote_exists(posixpath.join(dest_dir, n))))
            elif self.remote_exists(target):
                choice = self._conflict(name, _("no servidor"), memo)
                if choice == "skip": continue
                if choice == "both":
                    target = posixpath.join(dest_dir, unique_copy_name(name, lambda n: self.remote_exists(posixpath.join(dest_dir, n))))
            jobs.append(('rcopy', p, target))
        if not jobs: return None
        entry = TransferEntry(self, f"{_('Copiando em')} {self.title}", jobs, on_done=lambda e, s=self: s.after_transfer(e))
        self.main.queue.add(entry); self.main.show_transfers()
        return entry

    def copy_local_items(self, paths, dest_dir):
        memo = {}
        for p in paths:
            name = os.path.basename(p.rstrip(os.sep)); target = os.path.join(dest_dir, name)
            if os.path.abspath(target) == os.path.abspath(p):          # colar na mesma pasta → "nome cópia"
                target = os.path.join(dest_dir, unique_copy_name(name, lambda n: os.path.lexists(os.path.join(dest_dir, n))))
            elif os.path.lexists(target):
                choice = self._conflict(name, _("nesta pasta"), memo)
                if choice == "skip": continue
                if choice == "both":
                    target = os.path.join(dest_dir, unique_copy_name(name, lambda n: os.path.lexists(os.path.join(dest_dir, n))))
            try:
                if os.path.isdir(p) and not os.path.islink(p): shutil.copytree(p, target, symlinks=True, dirs_exist_ok=True)
                else: shutil.copy2(p, target, follow_symlinks=False)
                log_event(_("COPIOU"), f"{p} → {target}", _("Computador local"))
            except Exception as e: QMessageBox.critical(self, _("Falha ao copiar"), f"{name}: {e}")
        self.load_local()

    # ------------------------------------------------------------------ compactar / extrair
    def compress(self, side, paths):
        if side == 'remote' and not self.require_remote(): return
        if not paths: return
        j = os.path if side == 'local' else posixpath
        folder = j.dirname(paths[0].rstrip('/')) or '/'
        names = [j.basename(p.rstrip('/')) for p in paths]
        fmts = ["ZIP (.zip)", "TAR.GZ (.tar.gz)"]
        fmt_label, ok = QInputDialog.getItem(self, _("Compactar"), _("Formato:"), fmts, 0, False)
        if not ok: return
        fmt = "zip" if fmt_label.startswith("ZIP") else "tar.gz"
        base = names[0] if len(names) == 1 else _("Arquivos")
        name, ok = QInputDialog.getText(self, _("Compactar"), _("Nome do arquivo compactado:"), text=f"{base}.{fmt}")
        if not ok or not valid_name(name.strip()): return
        name = name.strip()
        exists = (lambda n: os.path.lexists(os.path.join(folder, n))) if side == 'local' else \
                 (lambda n: self.remote_exists(posixpath.join(folder, n)))
        if exists(name): name = unique_copy_name(name if not name.endswith(".tar.gz") else name, exists)
        where = self._where(side)
        if side == 'local':
            fn = lambda w: compress_local(w, folder, names, name, fmt)
        else:
            ssh = self.ssh; fn = lambda w: compress_remote(w, ssh, folder, names, name, fmt)

        def done(e, s=self):
            if e.status == "done": log_event(_("COMPACTOU"), f"{', '.join(names)} → {j.join(folder, name)}", where)
            s.after_task(e, side, name)
        entry = TransferEntry(self, _(f"Compactando {name}"), task=fn, on_done=done)
        self.main.queue.add(entry); self.main.show_transfers()

    def extract(self, side, path, into_folder):
        if side == 'remote' and not self.require_remote(): return
        j = os.path if side == 'local' else posixpath
        folder = j.dirname(path); fname = j.basename(path)
        dest = folder
        if into_folder:
            stem = archive_stem(fname)
            exists = (lambda n: os.path.lexists(os.path.join(folder, n))) if side == 'local' else \
                     (lambda n: self.remote_exists(posixpath.join(folder, n)))
            dest = j.join(folder, stem if not exists(stem) else unique_copy_name(stem, exists))
        where = self._where(side)
        if side == 'local': fn = lambda w: extract_local(w, path, dest)
        else:
            ssh = self.ssh; fn = lambda w: extract_remote(w, ssh, path, dest)

        def done(e, s=self):
            if e.status == "done": log_event(_("EXTRAIU"), f"{path} → {dest}", where)
            s.after_task(e, side, j.basename(dest) if into_folder else None)
        entry = TransferEntry(self, _(f"Extraindo {fname}"), task=fn, on_done=done)
        self.main.queue.add(entry); self.main.show_transfers()

    def after_task(self, entry, side, select=None):
        self.status(entry.message)
        if side == 'local': self.load_local(select=select)
        elif self.sftp: self.load_remote(select=select)

    # ------------------------------------------------------------------ sincronizar
    def open_sync(self):
        if not self.require_remote(): return
        SyncDialog(self).exec()


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
        self.queue = TransferQueue(self); self.queue_window = None
        self.queue.changed.connect(self._queue_changed)
        tools = self.menuBar().addMenu(_("Ferramentas"))
        for text, keys, slot in ((_("Transferências"), "Ctrl+Shift+T", self.show_transfers),
                                 (_("Sincronizar pastas…"), "Ctrl+Shift+S", lambda: self.session().open_sync()),
                                 (_("Histórico (log)…"), "Ctrl+Shift+L", lambda: LogDialog(self).exec())):
            act = QAction(text, self); act.setShortcut(QKeySequence(keys)); act.triggered.connect(slot); tools.addAction(act)
        root = QWidget(); self.setCentralWidget(root); layout = QVBoxLayout(root)

        top = QHBoxLayout()
        b = QPushButton(_("＋ Nova conexão")); b.setToolTip(_("Conectar a um servidor (⌘T abre nova aba)"))
        b.clicked.connect(self.new_connection); top.addWidget(b)
        # botão comum (mesmo visual dos outros); o menu abre logo abaixo dele
        self.fav_btn = QPushButton(_("⭐ Favoritos")); self.fav_btn.setToolTip(_("Conectar a um favorito ou gerenciar"))
        self.fav_menu = QMenu(self); self.fav_btn.clicked.connect(self._show_fav_menu)
        top.addWidget(self.fav_btn)
        top.addStretch(1)
        self.queue_btn = QPushButton(_("⇅ Transferências")); self.queue_btn.clicked.connect(self.show_transfers)
        top.addWidget(self.queue_btn)
        sync_btn = QPushButton(_("Sincronizar…")); sync_btn.clicked.connect(lambda: self.session().open_sync()); top.addWidget(sync_btn)
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

    # --- fila de transferências
    def show_transfers(self):
        if self.queue_window is None: self.queue_window = TransferQueueWindow(self.queue, self)
        self.queue_window.show(); self.queue_window.raise_()

    def _queue_changed(self):
        n = len(self.queue.active())
        self.queue_btn.setText(_("⇅ Transferências") + (f" ({n})" if n else ""))

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
        bundle = app_bundle_path()
        if bundle:
            # abre pelo LaunchServices (igual a dar dois cliques no Finder): assim o macOS reconhece o app
            # e aplica as permissões dele (Rede Local etc.). Abrir o executável direto perde essas permissões.
            QProcess.startDetached("/usr/bin/open", ["-n", bundle])
        elif getattr(sys, "frozen", False):
            QProcess.startDetached(sys.executable, sys.argv[1:])
        else:
            QProcess.startDetached(sys.executable, sys.argv)
        QApplication.quit()

    def closeEvent(self, event):
        running = len(self.queue.active())
        if running and QMessageBox.question(self, _("Sair"), _(f"Há {running} transferência(s) em andamento. Cancelar e sair?"),
                                            QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            event.ignore(); return
        for i in range(self.tabs.count()):
            if not self.tabs.widget(i).close_editors(): event.ignore(); return
        for i in range(self.tabs.count()): self.tabs.widget(i).disconnect(ask=False)
        if self.queue_window: self.queue_window.close()
        wait_all_threads()
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
    import atexit
    app.aboutToQuit.connect(wait_all_threads); atexit.register(wait_all_threads)
    global LANG
    LANG = load_language()
    if LANG == "pt":   # botões padrão do Qt (Yes/No/Cancel…) em português
        tr = QTranslator(app)
        if tr.load("qtbase_pt_BR", QLibraryInfo.path(QLibraryInfo.TranslationsPath)): app.installTranslator(tr)
    win = MainWindow(); win.show(); sys.exit(app.exec())


if __name__ == '__main__':
    main()
