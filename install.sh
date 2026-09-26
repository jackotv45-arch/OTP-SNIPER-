#!/usr/bin/env bash
# ============================================
# OTP-SNIPER v1.1
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

# --- Bannière (ASCII pur compatible partout) ---
echo ""
cat << "EOF"

   ____  _____ ____     ____  _   _ ___ ____  _____ ____  
  / __ \|_   _|  _ \   / ___|| \ | |_ _|  _ \| ____|  _ \ 
 | |  | | | | | |_) |  \___ \|  \| || || |_) |  _| | |_) |
 | |__| | | | |  __/    ___) | |\  || ||  __/| |___|  _ < 
  \____/  |_| |_|      |____/|_| \_|___|_|   |_____|_| \_\

        OTP-SNIPER v1.1 — Installation
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

# --- 6. Mettre à jour pip dans le venv ---
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
    python3 -m pip install rich requests flask cryptography
    ok "Dependances installees manuellement"
fi

# --- 8. Vérification des imports ---
log "Verification des imports..."
python3 -c "
import sys
modules_ok = True
try:
    import rich
    print('  rich:', rich.__version__ if hasattr(rich, '__version__') else 'OK')
except ImportError:
    print('  rich: MANQUANT')
    modules_ok = False
try:
    import requests
    print('  requests:', requests.__version__)
except ImportError:
    print('  requests: MANQUANT')
    modules_ok = False
try:
    import flask
    print('  flask:', flask.__version__)
except ImportError:
    print('  flask: MANQUANT')
    modules_ok = False
try:
    import cryptography
    print('  cryptography:', cryptography.__version__)
except ImportError:
    print('  cryptography: MANQUANT')
    modules_ok = False
try:
    import sqlite3
    print('  sqlite3: OK (stdlib)')
except ImportError:
    print('  sqlite3: MANQUANT')
    modules_ok = False

if modules_ok:
    print('  => Tous les modules sont OK')
    sys.exit(0)
else:
    print('  => Certains modules sont manquants')
    sys.exit(1)
" && ok "Tous les imports critiques OK" || warn "Certains imports sont manquants"

# --- 9. Créer les dossiers de sortie ---
log "Creation des dossiers de travail..."
mkdir -p otp_sniper_ca
ok "Dossier 'otp_sniper_ca/' cree"

# --- 10. Détection du fichier principal ---
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
    warn "-> Place ton fichier .py dans ce dossier"
fi

# --- 11. Instructions HTTPS/CA ---
echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${CYAN}  INFORMATIONS HTTPS${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo -e "  Pour intercepter le trafic HTTPS, tu dois installer"
echo -e "  le certificat CA dans ton navigateur / systeme."
echo ""
echo -e "  Le CA sera genere automatiquement au premier lancement"
echo -e "  du proxy, dans le dossier : ${CYAN}otp_sniper_ca/ca.crt${NC}"
echo ""
echo -e "  Installation rapide sur Linux (Debian/Ubuntu) :"
echo -e "  ${YELLOW}sudo cp otp_sniper_ca/ca.crt /usr/local/share/ca-certificates/otp-sniper.crt${NC}"
echo -e "  ${YELLOW}sudo update-ca-certificates${NC}"
echo ""

# --- 12. Résumé ---
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
echo -e "     ${CYAN}-> Option 12 : Voir le chemin du CA (a installer dans le client)${NC}"
echo -e "     ${CYAN}-> Option 13 : Aide pour configurer le client${NC}"
echo ""
echo -e "  ${YELLOW}Rappel legal :${NC}"
echo -e "     Usage educatif / CTF / pentest AUTORISE uniquement."
echo -e "     Ne JAMAIS intercepter le trafic d'un tiers sans autorisation."
echo ""
echo -e "${GREEN}============================================================${NC}"
echo ""