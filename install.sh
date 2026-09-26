#!/usr/bin/env bash
# ============================================
# OTP-SNIPER v2.0
# Script d'installation automatique
# Ubuntu / Debian / Kali / WSL
# ============================================

set -e

# --- Couleurs ---
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
BOLD='\033[1m'
NC='\033[0m'

log()   { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[X]${NC} $1"; }

# --- Bannière ---
echo ""
cat << "EOF"

   ____  _____ ____     ____  _   _ ___ ____  _____ ____  
  / __ \|_   _|  _ \   / ___|| \ | |_ _|  _ \| ____|  _ \ 
 | |  | | | | | |_) |  \___ \|  \| || || |_) |  _| | |_) |
 | |__| | | | |  __/    ___) | |\  || ||  __/| |___|  _ < 
  \____/  |_| |_|      |____/|_| \_|___|_|   |_____|_| \_\

        OTP-SNIPER v2.0 — Installation
        Usage educatif / CTF / pentest autorise uniquement

EOF
echo ""

# --- 1. Vérifier Python ---
log "Verification de Python..."
if ! command -v python3 &> /dev/null; then
    err "Python3 n'est pas installe."
    log "Installation de Python3..."
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv
else
    PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    ok "Python3 detecte : $PY_VERSION"
fi

# --- 2. Vérifier pip ---
log "Verification de pip..."
if ! python3 -m pip --version &> /dev/null; then
    warn "pip manquant, installation..."
    sudo apt update
    sudo apt install -y python3-pip
else
    ok "pip disponible"
fi

# --- 3. Vérifier venv ---
log "Verification de venv..."
if ! python3 -c "import venv" &> /dev/null; then
    warn "venv manquant, installation..."
    sudo apt install -y python3-venv
else
    ok "venv disponible"
fi

# --- 4. Détecter ou créer le venv ---
if [ -d ".venv" ]; then
    VENV_DIR=".venv"
    warn "Dossier '.venv' detecte, reutilisation..."
elif [ -d "venv" ]; then
    VENV_DIR="venv"
    warn "Dossier 'venv' detecte, reutilisation..."
else
    VENV_DIR=".venv"
    log "Creation du venv dans '$VENV_DIR'..."
    python3 -m venv "$VENV_DIR"
    ok "Venv cree dans ./$VENV_DIR"
fi

# --- 5. Activer le venv ---
log "Activation de ./$VENV_DIR ..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
ok "Python actif : $(which python3)"

# --- 6. Mettre à jour pip ---
log "Mise a jour de pip..."
python3 -m pip install --upgrade pip setuptools wheel 2>&1 | tail -1
ok "pip a jour"

# --- 7. Installer les dépendances ---
log "Installation des dependances..."
if [ -f "requirements.txt" ]; then
    python3 -m pip install -r requirements.txt
    ok "Dependances installees via requirements.txt"
else
    warn "requirements.txt introuvable, installation manuelle..."
    python3 -m pip install rich requests flask cryptography websocket-client hyper h2
    ok "Dependances installees manuellement"
fi

# --- 8. Vérification des imports ---
log "Verification des imports..."
python3 -c "
import sys
modules_ok = True
try:
    import rich
    print('  rich: OK')
except ImportError:
    print('  rich: MANQUANT'); modules_ok = False
try:
    import requests
    print('  requests:', requests.__version__)
except ImportError:
    print('  requests: MANQUANT'); modules_ok = False
try:
    import flask
    print('  flask:', flask.__version__)
except ImportError:
    print('  flask: MANQUANT'); modules_ok = False
try:
    import cryptography
    print('  cryptography:', cryptography.__version__)
except ImportError:
    print('  cryptography: MANQUANT'); modules_ok = False
try:
    import websocket
    print('  websocket-client: OK')
except ImportError:
    print('  websocket-client: MANQUANT'); modules_ok = False
try:
    import hyper
    print('  hyper: OK')
except ImportError:
    print('  hyper: MANQUANT'); modules_ok = False
try:
    import h2
    print('  h2: OK')
except ImportError:
    print('  h2: MANQUANT'); modules_ok = False
try:
    import sqlite3
    print('  sqlite3: OK (stdlib)')
except ImportError:
    print('  sqlite3: MANQUANT'); modules_ok = False

if modules_ok:
    print('  => Tous les modules OK')
    sys.exit(0)
else:
    print('  => Certains modules manquants')
    sys.exit(1)
" && ok "Tous les imports critiques OK" || warn "Certains imports sont manquants"

# --- 9. Créer les dossiers ---
log "Creation des dossiers de travail..."
mkdir -p otp_sniper_ca
ok "Dossier 'otp_sniper_ca/' cree"

# --- 10. Vérifier frida_bypass.js ---
log "Verification du script Frida..."
if [ -f "frida_bypass.js" ]; then
    ok "frida_bypass.js detecte"
else
    warn "frida_bypass.js absent (optionnel pour mobile)"
    warn "-> Telecharge-le depuis ton dossier OTP-Sniper"
fi

# --- 11. Détection du fichier principal ---
MAIN_FILE=""
for f in otp_sniper.py otp-sniper.py OTP-SNIPER.py OTP_SNIPER.py; do
    if [ -f "$f" ]; then
        MAIN_FILE="$f"
        break
    fi
done

if [ -n "$MAIN_FILE" ]; then
    ok "Fichier principal detecte : $MAIN_FILE"
else
    warn "Aucun fichier otp_sniper.py detecte"
fi

# --- 12. Optionnel : Frida tools ---
echo ""
log "Verification de frida-tools (pour mobile)..."
if ! python3 -c "import frida" &> /dev/null 2>&1; then
    warn "frida-tools non installe (optionnel, pour mobile roote)"
    read -p "  Installer frida-tools ? (o/n) : " install_frida
    if [[ "$install_frida" =~ ^[oOyY] ]]; then
        python3 -m pip install frida-tools
        ok "frida-tools installe"
        warn "Rappel : frida-server doit aussi etre sur le mobile"
    fi
else
    ok "frida-tools deja installe"
fi

# --- 13. Résumé ---
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  INSTALLATION TERMINEE${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo -e "  ${BOLD}Prochaines etapes :${NC}"
echo ""
echo -e "  1. Activer le venv :"
echo -e "     ${CYAN}source $VENV_DIR/bin/activate${NC}"
echo ""
echo -e "  2. Lancer OTP-SNIPER :"
if [ -n "$MAIN_FILE" ]; then
    echo -e "     ${CYAN}python3 $MAIN_FILE${NC}"
else
    echo -e "     ${CYAN}python3 otp_sniper.py${NC}"
fi
echo ""
echo -e "  3. Menu recommande (ordre) :"
echo -e "     ${CYAN}-> Option 1  : Demarrer le proxy${NC}"
echo -e "     ${CYAN}-> Option 14 : Voir le chemin du CA (a installer)${NC}"
echo -e "     ${CYAN}-> Option 16 : Aide pour configurer le client${NC}"
echo ""
echo -e "  4. Pour mobile :"
echo -e "     ${CYAN}-> Option 15 : Aide Frida (bypass pinning)${NC}"
echo -e "     ${CYAN}-> Installer le CA sur le mobile (root)${NC}"
echo -e "     ${CYAN}-> Configurer le proxy Wi-Fi : [IP_PC]:8080${NC}"
echo ""
echo -e "  ${YELLOW}Rappel legal :${NC}"
echo -e "     Usage educatif / CTF / pentest AUTORISE uniquement."
echo -e "     Ne JAMAIS intercepter le trafic d'un tiers sans autorisation."
echo ""
echo -e "${GREEN}============================================================${NC}"
echo ""