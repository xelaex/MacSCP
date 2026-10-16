==============================================================
  MacSCP - SFTP/SSH client for macOS (WinSCP style)
==============================================================

WHAT IT IS
----------
A native macOS app to transfer files between your Mac and servers
over SFTP/SSH: drag and drop, multiple connections in tabs,
favorites unlocked with Touch ID, text editor, permissions (chmod)
and a full SSH console.

The app is available in English and Portuguese. To switch, use the
menu bar: "Idioma / Language" > English (the app restarts itself).
On a Mac set to Portuguese it starts in Portuguese; otherwise in English.


BEFORE YOU START
----------------
- macOS with Python 3 installed.
  If this Mac has never had the developer tools, open Terminal and run:
      xcode-select --install
  (then follow the window that appears).
- An internet connection (the installer downloads the required libraries).


INSTALLATION
------------
1. Download MacSCP
   On GitHub, either:
   - open "Releases" (right column) and download "Source code (zip)"
     of the latest version, or
   - click "Code" > "Download ZIP".

2. Unzip it
   Double-click the downloaded .zip file (usually in your Downloads
   folder). A folder named "MacSCP-<version>", e.g. "MacSCP-1.2.1"
   (from Releases), or
   "MacSCP-main" (from Code > Download ZIP) appears, with the
   "macos_app" folder inside it.

3. Open Terminal
   Applications > Utilities > Terminal
   (or press Cmd + Space, type "Terminal" and press Enter).

4. Go into the macos_app folder
   Type "cd " (with a space at the end), drag the macos_app folder
   from Finder into the Terminal window and press Enter.
   Example:
       cd ~/Downloads/MacSCP-main/macos_app

5. Make the installer executable:
       chmod +x build_macos.sh

6. Run the installer:
       ./build_macos.sh

   Wait a few minutes. At the end you will see:
       Autoteste do app:            (app self-test)
         Touch ID: OK
         Cofre de senhas: OK        (password vault)
       Aplicativo criado em: .../macos_app/dist/MacSCP.app


ALLOW LOCAL NETWORK ACCESS (required for local IPs / ZeroTier / VPN)
--------------------------------------------------------------------
7. Open System Settings > Privacy & Security > Local Network
   and turn MacSCP on.

   Note: if MacSCP does not show up in the list yet, open the app and
   try to connect to a server once. macOS will ask for permission to
   access the local network (click "Allow"), or MacSCP will then
   appear in the list.


OPEN THE APP
------------
8. In the macos_app folder you unzipped, open the "dist" folder and
   double-click MacSCP.

9. If you prefer, drag MacSCP.app into your Applications folder so
   you can open it from Launchpad or Spotlight (Cmd + Space > "MacSCP").


QUICK TIPS
----------
- New connection: "+ New connection" button (each server opens in its own tab).
- Favorites: save server, user and password. After the
  first login, Touch ID is all you need.
- Drag files between the panels, or drop them onto a folder.
- Copy and paste: Cmd + C / Cmd + V (or right-click). Works in the
  same panel, between computer and server, inside the server and
  with Finder.
- Right-click: new folder, new file, edit, rename, permissions,
  delete...
- Cut and move: Cmd + X then Cmd + V (or Cmd + Option + V to move what
  you copied).
- Same name at the destination: Replace / Keep both / Skip. The default
  is "Keep both" (the copy becomes "name copy.ext").
- Path bar: type a path (e.g. /var/www or ~) and press Enter. Next to it,
  "Filter…" shows only matching items.
- Sorting: click Name, Size or Modified (folders always on top).
- Compress / extract: right-click > Compress… (zip or tar.gz) or
  Extract here / Extract to folder. Works locally and on the server.
- Transfers: queue window ("⇅ Transfers" button) with pause, resume and
  cancel. Interrupted transfers (pause, network drop) resume where they
  stopped. Files keep their original date.
- Sync…: compares a local folder with a server folder and transfers only
  what is new or changed (optionally deleting extras).
- History: Tools > History (log)… shows everything uploaded, downloaded,
  deleted, renamed, etc.
- Double-click a text file to open the editor (Cmd + S saves it
  directly on the server).
- SSH Console: full terminal. Typing "exit" closes the window.
- About: menu bar MacSCP > "About MacSCP". The version also shows
  in the window title.
- Language: menu bar "Idioma / Language" > English or Português
  (the app restarts itself).


UPDATING TO A NEW VERSION
-------------------------
Download and unzip the new version and repeat steps 3 to 6.
Your favorites and saved passwords are kept (they live in
~/Library/Application Support/MacSCP).
After updating, check step 7 again (Local Network) in case macOS
turned the permission off for the new build.


TROUBLESHOOTING
---------------
- "Unable to connect" or "macOS blocked access" on a local/ZeroTier IP:
  check step 7 (Local Network).
- "Python 3.9+ não encontrado" (Python not found): run
      xcode-select --install
  or install it with
      brew install python@3.12
- macOS says the app "can't be opened": right-click MacSCP > Open > Open.
