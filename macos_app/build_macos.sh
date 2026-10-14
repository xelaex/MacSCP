#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Este empacotador precisa ser executado no macOS para gerar um .app nativo." >&2
  exit 2
fi
export PYTHONIOENCODING=utf-8
export PIP_DISABLE_PIP_VERSION_CHECK=1

# Usa o Python mais novo disponível (Homebrew / python.org); o 3.9 da Apple é o último recurso.
PY=""
for c in python3.13 python3.12 python3.11 python3.10 /opt/homebrew/bin/python3 /usr/local/bin/python3 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
    PY="$(command -v "$c")"; break
  fi
done
if [[ -z "$PY" ]]; then
  echo "Python 3.9+ não encontrado. Instale com:  brew install python@3.12" >&2; exit 1
fi
PYVER="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
echo "Usando Python $PYVER ($PY)"

# Recria o ambiente se ele foi feito com outra versão do Python ou ficou quebrado
if [[ -x .venv/bin/python ]]; then
  VENVVER="$(.venv/bin/python -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo x)"
  [[ "$VENVVER" == "$PYVER" ]] || { echo "Recriando .venv (era Python $VENVVER)"; rm -rf .venv; }
fi
# Ambiente antigo com o PySide6 completo (WebEngine etc.) → recria para o app ficar bem menor
if [[ -x .venv/bin/python ]] && .venv/bin/python -m pip show PySide6_Addons >/dev/null 2>&1; then
  echo "Recriando .venv (removendo PySide6 completo)"; rm -rf .venv
fi
[[ -x .venv/bin/python ]] || "$PY" -m venv .venv
source .venv/bin/activate

# --no-compile evita o erro do pip ao pré-compilar arquivos-modelo do PySide6 (falha na 1ª execução)
python -m pip install --no-compile --upgrade pip setuptools wheel
python -m pip install --no-compile -r requirements.txt
pyinstaller --noconfirm --clean --windowed --name "MacSCP" --osx-bundle-identifier "MacSCP.clientesftp" \
  --icon MacSCP.icns --add-data "MacSCP_icon.png:." \
  --collect-all objc --collect-all Foundation --collect-all CoreFoundation --collect-all LocalAuthentication \
  main.py
APP="$PWD/dist/MacSCP.app"
PLIST="$APP/Contents/Info.plist"
# Permissão de Rede Local (macOS 15+): sem isso o app não alcança IPs privados (ZeroTier, LAN, 10.x, 192.168.x)
plutil -replace NSLocalNetworkUsageDescription -string "O MacSCP precisa acessar a rede local/VPN para conectar aos seus servidores SSH/SFTP." "$PLIST"
VERSION="$(sed -n 's/^APP_VERSION = "\([^"]*\)".*/\1/p' main.py | head -1)"   # versão vem do main.py
plutil -replace CFBundleShortVersionString -string "$VERSION" "$PLIST"
plutil -replace CFBundleVersion -string "$VERSION" "$PLIST"
# Reassina (ad-hoc) depois de alterar o Info.plist. Não pede senha nenhuma.
codesign --force --deep --sign - "$APP"
xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true
echo
echo "Autoteste do app:"
"$APP/Contents/MacOS/MacSCP" --self-test || echo "  (autoteste falhou — me envie esta saída)"
printf '\nAplicativo criado em: %s\n' "$APP"
printf 'Na primeira conexão a um IP de rede local/ZeroTier, o macOS vai pedir permissão: clique em Permitir.\n'
