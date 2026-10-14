# MacSCP — cliente SFTP/SSH nativo para macOS

Esta é uma aplicação desktop independente. **Não inicia servidor web e não precisa de Docker, Flask ou navegador.**

## Gerar o aplicativo

Passo a passo completo em português: veja o **[LEIAME.txt](LEIAME.txt)**.

Resumo, no Terminal:

```bash
cd macos_app
chmod +x build_macos.sh
./build_macos.sh
```

O arquivo `.app` será criado em `macos_app/dist/MacSCP.app`. Para distribuir para outros Macs, considere assinar/notarizar o aplicativo com um certificado Apple Developer; sem assinatura, o macOS pode mostrar um aviso na primeira abertura.

## Segurança

- Conexão SSH autenticada diretamente no servidor informado.
- A primeira conexão pede confirmação da impressão digital da chave do servidor; confirme-a por um canal independente e confiável.
- Chaves aceitas são gravadas em `~/.ssh/known_hosts` com permissões restritas.
- Se a chave de um servidor mudar (servidor reinstalado, IP reaproveitado…), o app mostra a chave antiga e a nova e, se você aceitar, atualiza só a linha daquele servidor no `known_hosts` — o resto do arquivo (usado pelo `ssh` do Mac) fica intacto.
- Senhas de favoritos ficam criptografadas (AES-256) em `~/Library/Application Support/MacSCP/senhas.bin`, liberadas pelo **Touch ID**. Não usa o app Acesso às Chaves.
- Os favoritos (sem senha) ficam em `~/Library/Application Support/MacSCP/favoritos.json`.
- Conexões que não estão nos favoritos não têm a senha salva.
- Pastas e subpastas são copiadas recursivamente, sem seguir links simbólicos locais/remotos.

## Uso

1. Abra o app e clique em **＋ Nova conexão** (ou escolha um servidor em **⭐ Favoritos**).
2. Informe IP/nome, porta, usuário e senha SSH (senha vazia = login por chave SSH em `~/.ssh`).
3. Confirme a chave SSH somente após verificar sua impressão digital.
4. Escolha a pasta local desejada.
5. Arraste arquivos ou pastas entre os painéis. Soltando em área vazia, o destino é a pasta aberta; **soltando em cima de uma pasta** (ela fica destacada em azul), os itens vão para dentro dela.
6. Arrastar um item para uma pasta **no mesmo painel** move o item para dentro dela.
7. Também dá para arrastar arquivos do **Finder** direto para o painel do servidor (envio) ou para o painel local (cópia).
8. Selecione vários itens com ⌘+clique ou ⇧+clique.

### Pastas e arquivos

- Botões **＋ Nova pasta** e **Excluir** em cada painel.
- **Botão direito**: Abrir, Nova pasta aqui, Nova pasta dentro da pasta clicada, **Novo arquivo de texto** (aqui ou dentro da pasta clicada, já abre no editor), **🔐 Permissões…** (chmod com caixinhas Ler/Gravar/Executar ou número octal, inclusive em vários arquivos de uma vez), Enviar/Baixar, Renomear, Mostrar no Finder, Excluir, Atualizar.
- Atalhos: **⇧⌘N** cria pasta no painel em foco; **⌫** exclui a seleção; **Enter** abre a pasta.
- No computador local, excluir manda para o **Lixo**. No servidor, a exclusão é definitiva (com confirmação) e apaga pastas com todo o conteúdo.

### Vários servidores ao mesmo tempo

- Cada **aba** é uma conexão independente (com seus próprios painéis local e remoto). **⌘T** ou **＋** abre nova aba; **⌘W** fecha (e desconecta).
- Conectar quando a aba atual já está em uso abre automaticamente uma aba nova. Abas conectadas mostram 🟢.
- Console SSH abre uma janela por servidor, e dá para ter várias abertas.

### Console SSH

- É um terminal de verdade (xterm-256color): você digita direto na tela, com cores, setas, Tab, Ctrl+C/Ctrl+D/Ctrl+Z, histórico do shell e programas de tela cheia (nano, vim, htop, less, mc…).
- **⌘C / ⌘V** copiam e colam (selecione com o mouse; dois cliques selecionam uma palavra). **⌘K** limpa, **⌘+ / ⌘−** mudam o tamanho da fonte, **⌘W** fecha.
- **⌥← / ⌥→** pulam palavras, **⌘← / ⌘→** vão para o início/fim da linha, **⌥⌫** apaga uma palavra.
- A rolagem do mouse e **⇧PageUp/PageDown** mostram o histórico (até 5000 linhas). Dentro do nano/vim/less, a rolagem move o cursor.
- Ao redimensionar a janela, o servidor recebe o novo tamanho do terminal.

### Favoritos

- **⭐ Favoritos ▾** → clique num favorito para conectar direto.
- **Gerenciar favoritos…**: criar, editar, excluir; nome, servidor, porta, usuário, senha, pasta remota e pasta local iniciais.
- Na janela de nova conexão, marque **Salvar nos favoritos**. Com uma aba conectada, também dá para usar **Adicionar esta conexão aos favoritos…**.

### Transferências

- Rodam em segundo plano: o app continua usável e dá para fazer várias ao mesmo tempo, inclusive em servidores diferentes.
- Cada transferência abre uma janelinha com progresso, velocidade, tempo restante e **Cancelar**. Fechar a janelinha também cancela.
- Ao cancelar, o arquivo que estava pela metade é apagado do destino. Os arquivos que já tinham terminado ficam.

### Touch ID

- Na primeira conexão a um favorito, o app pede a senha do servidor uma vez e guarda criptografada.
- Daí em diante, conectar pede só o **Touch ID**: uma vez a cada abertura do app. Em **⭐ Favoritos → 🔒 Bloquear favoritos** dá para exigir de novo.
- Se o Touch ID não estiver disponível, o app pede a senha do seu usuário do Mac (não a das Chaves).
- No fim do build aparece um autoteste dizendo se o Touch ID entrou no app.

### Editar arquivos de texto

- **Dois cliques** num arquivo (ou botão direito → **✏️ Editar**) abre o editor, tanto no servidor quanto no computador.
- **⌘S** salva direto no servidor. **⌘F** busca, **⌘G**/**⇧⌘G** vai para o próximo/anterior e **⌘W** fecha.
- Mantém a codificação (UTF-8 ou Latin-1), as quebras de linha (Unix/Windows), as permissões e o dono do arquivo.
- Se outra pessoa alterou o arquivo enquanto ele estava aberto, o app avisa antes de sobrescrever.
- Fechar, desconectar ou sair com alterações pendentes pergunta se você quer salvar.
- Arquivos binários não abrem no editor. No painel local, eles abrem no app padrão do Mac.
