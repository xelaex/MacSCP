#!/bin/bash
cd "$(dirname "$0")"
./build_macos.sh
printf '\nProcesso finalizado. Pressione Enter para fechar esta janela. '
read -r _
