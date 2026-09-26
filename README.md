# 🔫 OTP-SNIPER v1.1

**Capture et analyse de codes 2FA avec HTTPS MITM et Replay automatique.**

Outil de laboratoire pour :
- Comprendre le fonctionnement des codes 2FA
- Auditer la robustesse d'une implémentation 2FA
- Tester les mécanismes de replay, expiration, rate limiting
- Former des étudiants en sécurité offensive/défensive

**Usage éducatif / CTF / pentest autorisé uniquement.**

---

## 📋 Table des matières

- [Fonctionnalités](#-fonctionnalités)
- [Installation](#-installation)
- [Démarrage rapide](#-démarrage-rapide)
- [Utilisation](#-utilisation)
- [HTTPS et certificat CA](#-https-et-certificat-ca)
- [Replay automatique](#-replay-automatique)
- [Configuration des clients](#-configuration-des-clients)
- [Structure des fichiers](#-structure-des-fichiers)
- [FAQ](#-faq)
- [Avertissement](#-avertissement)

---

## ✨ Fonctionnalités

### 🎯 Capture automatique
- Détection des codes **TOTP** (6-8 chiffres)
- Détection des codes **SMS / email**
- Détection des **backup codes** et **codes de récupération**
- Détection des **credentials** (username/password)
- Capture des **cookies de session**

### 🌐 Reconnaissance d'environnement
- Détection du framework (Django, Laravel, Rails, Express, Flask, Spring, ASP.NET)
- Identification du type de cible (web, API, SPA)
- Adaptation automatique aux formats (JSON, form-urlencoded)

### 🔐 HTTPS MITM
- Génération automatique d'un **certificat CA**
- Signature des certificats **à la volée** pour chaque domaine
- Déchiffrement du trafic HTTPS
- Instructions d'installation du CA pour tous les OS/clients

### 🔄 Replay
- **Mode manuel** : test d'un code précis avec confirmation
- **Mode automatique** : intervalles croissants (1s, 5s, 30s, 60s, 5min)
- Mesure de la **fenêtre de validité** réelle
- Détection des **vulnérabilités de replay**

### 🖥️ Interfaces
- **TUI rich** : menu interactif, coloré, propre
- **Web** : interface navigateur avec auto-refresh
- **Les deux en parallèle** si souhaité

### 💾 Stockage
- **SQLite** : toutes les captures dans une DB locale
- **Export JSON** : portabilité
- **Consultation** : TUI ou Web

---

## 🚀 Installation

### Prérequis
- Python 3.8+
- pip
- Linux / macOS / WSL (Windows natif possible mais non testé)

### Étapes

```bash
# 1. Créer un dossier
mkdir OTP-Sniper && cd OTP-Sniper

# 2. Placer les fichiers
#    - otp_sniper.py
#    - requirements.txt
#    - README.md

# 3. Créer un venv
python3 -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate sur Windows

# 4. Installer
pip install -r requirements.txt

# 5. Lancer
python3 otp_sniper.py
 
 
🚀 Démarrage rapide
python3 otp_sniper.py
 
Choix de l'interface :
[1] 🖥️  TUI (Terminal riche)
[2] 🌐 Web (Navigateur)
[3] 🔄 Les deux
[0] ❌ Quitter
 
Menu principal (TUI) :
[1]  🚀  Démarrer le proxy MITM
[2]  ⏸️   Arrêter le proxy
[3]  🔴  Voir les codes 2FA capturés
[4]  🍪  Voir les sessions / cookies
[5]  🔑  Voir les credentials
[6]  🔄  Replay manuel
[7]  ⚡  Replay automatique
[8]  📊  Statistiques
[9]  📜  Logs
[10] 💾  Export JSON
[11] 🌐  Interface Web
[12] 📜  Chemin du CA
[13] 🧪  Aide config client
[0]  ❌  Quitter
 
 
🎯 Utilisation
 
Workflow typique
1. Lance le proxy → Menu option 1
2. Note ton IP locale (affichée dans les logs)
3. Installe le CA dans ton client (voir section HTTPS)
4. Configure le proxy dans ton navigateur/app
5. Navigue sur ta cible 2FA (labo)
6. Entre les codes normalement
7. Retourne dans OTP-SNIPER → Menu option 3 (codes capturés)
8. Teste le replay → Menu option 6 (manuel) ou 7 (auto)
9. Export → Menu option 10 
Exemple concret
 
Terminal 1 — OTP-SNIPER
python3 otp_sniper.py
# → Choisir 1 (TUI)
# → Menu option 1 (démarrer proxy)
# → Note ton IP : 192.168.1.42
 
Client (Firefox)
# Configurer proxy : 127.0.0.1:8080
# Installer CA : otp_sniper_ca/ca.crt
 
Navigue :
• Va sur https://ton-labo.local/login
• Entre admin / admin123
• Sur la page 2FA, entre 123456
• → OTP-SNIPER capture le code 
Retour à OTP-SNIPER :
• Menu option 3 → tu vois 123456 capturé
• Menu option 6 → replay manuel
• Menu option 7 → replay auto (test la fenêtre) 
 
🔐 HTTPS et certificat CA
 
Comment ça marche
1. Au premier démarrage du proxy, un CA est généré dans otp_sniper_ca/
2. Pour chaque domaine HTTPS, un certificat signé par ce CA est créé à la volée
3. Ton client accepte le trafic HTTPS si le CA est installé comme autorité de confiance 
Fichiers générés
otp_sniper_ca/
├── ca.key          # ⚠️ Clé privée du CA (NE PAS PARTAGER)
├── ca.crt          # 🔐 Certificat CA (à installer dans les clients)
├── example.com.crt # Certificats de domaine (générés à la volée)
└── example.com.key
 
Trouver le CA
• TUI : Menu option 12
• Terminal : ls otp_sniper_ca/ca.crt 
Installation du CA
 
Firefox
1. about:preferences
2. Vie privée → Certificats → Voir les certificats
3. Onglet Autorités → Importer → sélectionner ca.crt
4. Cocher : "Confier cette autorité pour identifier les sites web"
5. OK 
Chrome / Chromium (Linux)
sudo cp otp_sniper_ca/ca.crt /usr/local/share/ca-certificates/otp-sniper.crt
sudo update-ca-certificates
 
Windows
1. Copier ca.crt sur Windows
2. Double-clic → Installer le certificat
3. Ordinateur local → Suivant
4. Autorités de certification racines de confiance → OK
5. Terminer 
Android
1. Copier ca.crt sur le téléphone
2. Paramètres → Sécurité → Chiffrement et identifiants
3. Installer un certificat → Certificat CA
4. Sélectionner ca.crt 
iOS
1. Envoyer ca.crt sur l'iPhone (email, AirDrop)
2. Ouvrir → Installer le profil
3. Réglages → Général → VPN et gestion → Installer
4. Réglages → Général → À propos → Confiance des certificats
5. Activer le toggle pour "OTP-SNIPER CA" 
 
⚡ Replay automatique
 
Le replay automatique teste un code capturé à intervalles croissants pour trouver la fenêtre de validité réelle.
 
Intervalles par défaut
Tentative Délai après capture Cumul
1 1s 1s
2 5s 6s
3 30s 36s
4 60s 1m36s
5 5min 6m36s

 
Ce que ça détecte
• Code à usage unique : accepté une fois, rejeté ensuite
• Code réutilisable : accepté plusieurs fois (faille)
• Expiration : à quel moment le code devient invalide
• Rate limiting : blocage après N tentatives 
Sortie typique
Fenêtre de validité :
  +1s → accepted
  +6s → accepted
  +36s → rejected
  +1m36s → rejected
  +6m36s → rejected

Dernier test : rejected
 
→ Le code est réutilisable pendant ~36 secondes. 
 
🔧 Configuration des clients
 
Firefox (PC)
1. Paramètres → Vie privée → Paramètres réseau → Paramètres
2. Configuration manuelle du proxy
3. HTTP : 127.0.0.1 port 8080
4. Cocher "Utiliser pour tous les protocoles"
5. OK 
Chrome (PC)
google-chrome --proxy-server="http://127.0.0.1:8080"
 
curl
# HTTP
curl -x http://127.0.0.1:8080 http://lab.local/api

# HTTPS (avec CA installé)
curl -x http://127.0.0.1:8080 https://lab.local/api

# HTTPS sans installer le CA (-k)
curl -x http://127.0.0.1:8080 -k https://lab.local/api
 
Python requests
import requests
proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080',
}
r = requests.post('https://lab.local/api/verify',
                  data={'code': '123456'},
                  proxies=proxies,
                  verify=False)
 
Android
1. Paramètres → Wi-Fi
2. Appui long sur le réseau → Modifier
3. Options avancées → Proxy → Manuel
4. Hôte : 192.168.x.x (ton IP)
5. Port : 8080 
Postman
1. Settings → Proxy
2. Proxy Server : 127.0.0.1:8080
3. Proxy Type : HTTP
4. Désactiver SSL verification : Settings → General → SSL certificate verification : OFF 
 
📁 Structure des fichiers
OTP-Sniper/
├── otp_sniper.py           # Le programme principal
├── requirements.txt         # Dépendances
├── README.md               # Documentation
├── otp_sniper.db           # Base SQLite (créée au runtime)
├── otp_sniper_ca/          # CA et certificats (créé au runtime)
│   ├── ca.key
│   ├── ca.crt
│   └── <domaine>.crt/key
└── otp_sniper_export_*.json # Exports (créés au runtime)
 
Base SQLite
• requests : toutes les requêtes capturées
• otp_codes : codes 2FA détectés
• credentials : username/password capturés
• sessions : cookies de session 
Interroger la DB manuellement
sqlite3 otp_sniper.db

sqlite> SELECT * FROM otp_codes ORDER BY id DESC LIMIT 10;
sqlite> SELECT * FROM credentials;
sqlite> SELECT code, replay_count FROM otp_codes WHERE replay_count > 0;
 
 
❓ FAQ
 
Le proxy ne démarre pas
 
→ Vérifier que le port 8080 est libre :
sudo lsof -i :8080
# ou
ss -tlnp | grep 8080
 
→ Si occupé, changer de port :
python3 otp_sniper.py --port 8081
 
Les codes ne sont pas capturés
1. Le client utilise-t-il bien le proxy ? (vérifier 127.0.0.1:8080)
2. Le trafic passe-t-il en HTTPS ? (installer le CA)
3. Les champs s'appellent-ils code, otp, token, etc. ? 
Erreur de certificat sur HTTPS
 
→ Le CA n'est pas installé dans le client
→ Voir section HTTPS et certificat CA
 
cryptography non installé
pip install cryptography
 
Le replay ne fonctionne pas
 
→ Vérifier l'URL cible dans la DB (option 3, colonne URL)
→ Le format des données peut être du JSON et non du form-urlencoded
→ Modifier le code si nécessaire (fonction replay() dans ReplayEngine)
 
Comment réinitialiser la DB ?
rm otp_sniper.db
# Un nouveau sera créé au prochain lancement
 
Comment supprimer le CA ?
rm -rf otp_sniper_ca/
# Régénéré au prochain lancement du proxy
 
⚠️ N'oublie pas de retirer le CA de tes navigateurs après usage. 
