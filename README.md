Je vais te reformater ce README avec une structure GitHub propre, hiérarchisée et bien organisée. Voici la version optimisée :

---

```markdown
# 🔐 OTP-SNIPER v1.1 — JATHNIEL EDITION

## 📌 Description

OTP-SNIPER est un outil Python destiné à l'analyse et au test de mécanismes d'authentification OTP / 2FA dans un environnement de laboratoire contrôlé.

Il fournit une interface en terminal (TUI) ainsi qu'une interface Web permettant de centraliser les événements observés pendant les tests.

### ✨ Fonctionnalités

| Fonctionnalité | Description |
|----------------|-------------|
| 🖥️ | Interface TUI |
| 🌐 | Interface Web |
| 🔐 | Gestion d'un environnement HTTPS de test |
| 🔢 | Détection d'OTP de laboratoire |
| 🍪 | Analyse des sessions de test |
| 🔑 | Analyse des identifiants de test |
| 🔄 | Tests de rejeu sur des environnements autorisés |
| ⚡ | Tests automatisés de fenêtres de validité |
| 📊 | Statistiques |
| 📜 | Logs |
| 💾 | Export JSON |
| 🗄️ | Base de données SQLite |
| 🌍 | Utilisation depuis plusieurs machines d'un même réseau de laboratoire |

**Utilisation prévue :** laboratoire personnel, CTF, environnement de développement ou test de sécurité explicitement autorisé.

---

## 📋 Table des matières

- [Prérequis](#-prérequis)
- [Installation](#-installation)
  - [Linux / macOS](#linux--macos)
  - [Windows](#windows)
- [Configuration](#-configuration)
  - [Réseau](#configuration-réseau)
  - [HTTPS](#configuration-https)
  - [Clients](#configuration-des-clients)
- [Utilisation](#-utilisation)
- [Dépannage](#-dépannage)
- [Avertissement](#-avertissement)

---

## 📋 1. Prérequis

### Systèmes supportés

| Système | Statut |
|---------|--------|
| Linux | ✅ |
| Windows | ✅ |
| macOS | ✅ |

### Clients de laboratoire supportés

- Firefox
- Chrome / Chromium
- curl
- Python Requests
- Postman
- Android
- iOS

### Logiciels nécessaires

**Linux**
```bash
python3 --version
pip3 --version
```

**Windows**
```powershell
python --version
pip --version
```

**macOS**
```bash
python3 --version
pip3 --version
```

---

## 📁 2. Installation

### Linux / macOS

```bash
# Créer le dossier du projet
mkdir OTP-Sniper
cd OTP-Sniper

# Structure des fichiers
# OTP-Sniper/
# ├── otp_sniper.py
# ├── requirements.txt
# └── README.md

# Créer l'environnement virtuel
python3 -m venv venv

# Activer l'environnement
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Lancer
python3 otp_sniper.py
```

### Windows

```powershell
# Ouvrir PowerShell
mkdir OTP-Sniper
cd OTP-Sniper

# Placer les fichiers : otp_sniper.py, requirements.txt, README.md

# Créer le venv
python -m venv venv

# Activer
venv\Scripts\activate

# Installer
pip install -r requirements.txt

# Lancer
python otp_sniper.py
```

> **Note :** Si PowerShell bloque l'activation, utilisez directement :
> ```powershell
> venv\Scripts\python.exe otp_sniper.py
> venv\Scripts\pip.exe install -r requirements.txt
> ```

### macOS (résumé)

```bash
mkdir OTP-Sniper && cd OTP-Sniper
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 otp_sniper.py
```

### Linux (résumé)

```bash
mkdir OTP-Sniper && cd OTP-Sniper
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 otp_sniper.py
```

---

## ⚙️ 3. Configuration générale

### Architecture du laboratoire

```
                    RÉSEAU DE LABORATOIRE
                 ┌──────────────────────┐
                 │      Application     │
                 │      de test         │
                 └──────────┬───────────┘
                            │
                 ┌──────────▼───────────┐
                 │     OTP-SNIPER       │
                 │                      │
                 │ IP : 192.168.1.42    │
                 │ Proxy : 8080         │
                 └──────────┬───────────┘
                            │
             ┌──────────────┼──────────────┐
             │              │              │
             ▼              ▼              ▼
         Firefox         Android        Postman
        PC de test      appareil       PC de test
```

**Configuration :**
- **Machine OTP-SNIPER :** IP `192.168.1.42`, Port `8080`
- **Clients :** Proxy `192.168.1.42`, Port `8080`
- **Même machine :** Proxy `127.0.0.1`, Port `8080`

---

## 🌐 4. Configuration réseau

### 4.1 Même machine

```
Firefox
   │
   ▼
127.0.0.1:8080
   │
   ▼
OTP-SNIPER
```

### 4.2 Deux machines

```
Machine OTP-SNIPER          Machine cliente
   192.168.1.42          ──▶    192.168.1.50
```

### 4.3 Plusieurs machines

```
                    ┌────────────────────┐
                    │    OTP-SNIPER      │
                    │   192.168.1.42     │
                    │      :8080         │
                    └─────────┬──────────┘
                              │
              ┌───────────────┼────────────────┐
              │               │                │
              ▼               ▼                ▼
        192.168.1.50    192.168.1.51     192.168.1.52
          Firefox          Android          Postman
```

---

## 🔥 5. Pare-feu

Vérifier l'écoute du port :

**Linux :**
```bash
ss -lntp
# ou
sudo lsof -i :8080
```

**Windows :**
```powershell
netstat -ano | findstr :8080
```

> ⚠️ Évitez d'exposer le port du proxy directement sur Internet.

---

## 🖥️ 6. Démarrage

```bash
python3 otp_sniper.py
```

**Menu de démarrage :**
| Option | Description |
|--------|-------------|
| [1] | 🖥️ TUI (Terminal riche) |
| [2] | 🌐 Web (Navigateur) |
| [3] | 🔄 Les deux |
| [0] | ❌ Quitter |

---

## 🖥️ 7. Interface TUI

| Option | Fonction |
|--------|----------|
| [1] | 🚀 Démarrer le proxy |
| [2] | ⏸️ Arrêter le proxy |
| [3] | 🔴 Voir les codes 2FA |
| [4] | 🍪 Voir les sessions / cookies |
| [5] | 🔑 Voir les credentials |
| [6] | 🔄 Replay manuel |
| [7] | ⚡ Replay automatique |
| [8] | 📊 Statistiques |
| [9] | 📜 Logs |
| [10] | 💾 Export JSON |
| [11] | 🌐 Interface Web |
| [12] | 📜 Chemin du CA |
| [13] | 🧪 Aide configuration client |
| [0] | ❌ Quitter |

---

## 🌐 8. Interface Web

Choisir `[2] 🌐 Web` ou `[3] 🔄 Les deux`

Accès depuis une machine autorisée :
```
http://192.168.1.42:PORT
```

---

## 🔐 9. Configuration HTTPS

OTP-SNIPER utilise une autorité de certification de laboratoire.

### Structure générée

```
otp_sniper_ca/
├── ca.key          # Clé privée du CA (⚠️ NE JAMAIS PARTAGER)
├── ca.crt          # Certificat public du CA
├── example.com.crt # Certificat de test
└── example.com.key # Clé du certificat de test
```

> ⚠️ **Important :** Ne partagez jamais `ca.key` et ne committez jamais `otp_sniper_ca/` dans un dépôt public.

### Trouver le certificat CA

**Depuis la TUI :** `[12] 📜 Chemin du CA`

**Manuellement :**
```bash
ls otp_sniper_ca/ca.crt
```

---

## 🔧 10. Configuration des clients

### 🦊 Firefox

**Proxy :**
```
Paramètres → Général → Paramètres réseau → Configuration manuelle
```

| Configuration | Valeur |
|---------------|--------|
| Même machine | `127.0.0.1:8080` |
| Machine distante | `192.168.1.42:8080` |

**Certificat :**
```
Paramètres → Vie privée et sécurité → Certificats → Afficher → Autorités → Importer
```
Sélectionner : `ca.crt`

### 🌐 Chrome / Chromium

```bash
# Local
google-chrome --proxy-server="http://127.0.0.1:8080"

# Distant
google-chrome --proxy-server="http://192.168.1.42:8080"
```

### 🪟 Windows (Certificat)

1. Double-cliquer sur `ca.crt`
2. Installer le certificat → Ordinateur local
3. Placer dans : **Autorités de certification racines de confiance**

### 🐧 Linux (Certificat)

```bash
sudo cp otp_sniper_ca/ca.crt /usr/local/share/ca-certificates/otp-sniper.crt
sudo update-ca-certificates
```

### 🍎 macOS (Certificat)

Importer `ca.crt` dans **Trousseaux d'accès** et configurer comme autorité de confiance.

### 📱 Android

```
Paramètres → Wi-Fi → Réseau connecté → Modifier → Options avancées → Proxy → Manuel
```

| Champ | Valeur |
|-------|--------|
| Hôte | `192.168.1.42` |
| Port | `8080` |

### 🍎 iOS

1. Transférer `ca.crt`
2. Ouvrir et installer le profil
3. Activer la confiance dans : `Réglages → Général → Informations → Réglages de confiance`

### 🔧 curl

```bash
# Même machine
curl -x http://127.0.0.1:8080 http://lab.local/api

# Distant
curl -x http://192.168.1.42:8080 http://lab.local/api
```

### 🐍 Python Requests

```python
import requests

proxies = {
    "http": "http://192.168.1.42:8080",
    "https": "http://192.168.1.42:8080",
}

response = requests.get("https://lab.local/api", proxies=proxies)
print(response.status_code)
```

### 📮 Postman

```
Settings → Proxy
```
| Paramètre | Valeur |
|-----------|--------|
| Proxy type | HTTP |
| Host | `192.168.1.42` (ou `127.0.0.1`) |
| Port | `8080` |

---

## 🧪 11. Tests OTP / 2FA

Le laboratoire permet d'étudier :
- Durée de validité d'un OTP
- Comportement après expiration
- Comportement après réutilisation
- Limitation du nombre de tentatives
- Réponses HTTP
- Journaux de l'application
- Mécanismes de protection

> Utilisez exclusivement des **comptes de test**, **codes de test**, **applications de test** et **données synthétiques**.

---

## ⚡ 12. Replay automatique

Séquence de test type :

| Tentative | Délai |
|-----------|-------|
| 1 | +1s |
| 2 | +5s |
| 3 | +30s |
| 4 | +60s |
| 5 | +5min |

Exemple de résultat :
```
+1s      → accepted
+6s      → accepted
+36s     → rejected
+1m36s   → rejected
+6m36s   → rejected
```

---

## 📊 13. Statistiques & Logs

| Menu | Fonction |
|------|----------|
| `[8] 📊 Statistiques` | Vue synthétique des événements |
| `[9] 📜 Logs` | Diagnostic des problèmes |

**Checklist dépannage :**
1. ✅ Vérifier l'adresse IP
2. ✅ Vérifier le port
3. ✅ Vérifier la connexion réseau
4. ✅ Vérifier le proxy du client
5. ✅ Vérifier le certificat
6. ✅ Consulter les logs

---

## 💾 14. Export & Base de données

### Export JSON

Menu : `[10] 💾 Export JSON`

> ⚠️ Ne publiez pas ces fichiers sur GitHub (données sensibles de test).

### Base SQLite

Fichier : `otp_sniper.db`

**Structure logique :**
- `requests`
- `otp_codes`
- `credentials`
- `sessions`

**Accès :**
```bash
sqlite3 otp_sniper.db

# Exemple de requête
SELECT * FROM otp_codes ORDER BY id DESC LIMIT 10;

.quit
```

---

## 📁 15. Structure finale

```
OTP-Sniper/
├── otp_sniper.py
├── requirements.txt
├── README.md
├── venv/
├── otp_sniper.db
├── otp_sniper_ca/
│   ├── ca.key
│   ├── ca.crt
│   └── ...
└── otp_sniper_export_*.json
```

---

## 🧹 16. Réinitialisation

### Supprimer la base

```bash
# Linux / macOS
rm otp_sniper.db

# Windows
Remove-Item otp_sniper.db
```

### Supprimer le CA

```bash
# Linux / macOS
rm -rf otp_sniper_ca/

# Windows
Remove-Item -Recurse -Force otp_sniper_ca
```

---

## 🔒 17. .gitignore

```gitignore
venv/
.venv/
__pycache__/
*.pyc
otp_sniper.db
otp_sniper_ca/
*.key
*.crt
otp_sniper_export_*.json
.env
.vscode/
.idea/
```

---

## ❓ 18. Dépannage

### Le programme ne démarre pas

```bash
python3 --version
pip install -r requirements.txt
```

### Module `cryptography` manquant

```bash
pip install cryptography
# ou
pip install -r requirements.txt
```

### Port 8080 déjà utilisé

```bash
# Linux
sudo lsof -i :8080

# Windows
netstat -ano | findstr :8080

# Solution : utiliser un autre port
python3 otp_sniper.py --port 8081
```

### Le client ne peut pas joindre OTP-SNIPER

Vérifier :
1. ✅ Adresse IP de la machine OTP-SNIPER
2. ✅ Port utilisé
3. ✅ Pare-feu
4. ✅ Connexion réseau
5. ✅ Configuration du proxy

### HTTPS affiche une erreur

Vérifier :
- ✅ `ca.crt` présent
- ✅ Certificat installé dans le client
- ✅ Bonne machine
- ✅ Bonne autorité de confiance
- ✅ Proxy correctement configuré

---

## ✅ 19. Checklist avant un test

- [ ] Python installé
- [ ] venv créé
- [ ] requirements.txt installé
- [ ] OTP-SNIPER démarre
- [ ] Adresse IP du serveur connue
- [ ] Port disponible
- [ ] Pare-feu configuré pour le laboratoire
- [ ] Client connecté au même réseau
- [ ] Proxy configuré
- [ ] CA installé si nécessaire
- [ ] Application de test disponible
- [ ] Compte de test disponible
- [ ] OTP de test disponible
- [ ] Données réelles exclues du test

---

## 🛑 20. Fin du laboratoire

Après les tests :

1. ⏹️ Arrêter le proxy
2. 🗑️ Supprimer les données de test inutiles
3. 🔐 Supprimer le certificat CA des appareils
4. 🗑️ Supprimer les exports sensibles
5. 🚫 Ne pas publier `otp_sniper.db`
6. 🚫 Ne pas publier `otp_sniper_ca/`
7. 🚫 Ne jamais publier `ca.key`

---

## ⚠️ Avertissement

OTP-SNIPER est destiné à la **recherche en cybersécurité**, aux **environnements de laboratoire**, aux **CTF** et aux **tests explicitement autorisés**.

L'utilisateur doit disposer de l'autorisation nécessaire avant de tester une application, un réseau, un appareil ou un compte.

**N'utilisez pas cet outil pour intercepter, collecter ou rejouer des données appartenant à des tiers.**

---

## 👨‍💻 Auteur

**JATHNIEL**

*OTP-SNIPER v1.1 — JATHNIEL EDITION*
```

---

Ce formatage GitHub inclut :

1. **Hiérarchie claire** avec `#` pour le titre principal, `##` pour les sections, `###` pour les sous-sections
2. **Table des matières** cliquable
3. **Tableaux** pour les références rapides (fonctionnalités, menu, configurations)
4. **Blocs de code** avec syntaxe highlighting
5. **Emojis** conservés pour la lisibilité visuelle
6. **Alertes** (`> ⚠️`) pour les avertissements importants
7. **Checkboxes** pour les listes de vérification
8. **Structure arborescente** avec des diagrammes ASCII

Tu peux copier-coller directement ce contenu dans ton fichier `README.md` sur GitHub !