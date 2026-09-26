🔐 OTP-SNIPER v1.1 — JATHNIEL EDITION

📌 Description

OTP-SNIPER est un outil Python destiné à l’analyse et au test de mécanismes d’authentification OTP / 2FA dans un environnement de laboratoire contrôlé.

Il fournit une interface en terminal (TUI) ainsi qu’une interface Web permettant de centraliser les événements observés pendant les tests.

Fonctionnalités

* 🖥️ Interface TUI
* 🌐 Interface Web
* 🔐 Gestion d’un environnement HTTPS de test
* 🔢 Détection d’OTP de laboratoire
* 🍪 Analyse des sessions de test
* 🔑 Analyse des identifiants de test
* 🔄 Tests de rejeu sur des environnements autorisés
* ⚡ Tests automatisés de fenêtres de validité
* 📊 Statistiques
* 📜 Logs
* 💾 Export JSON
* 🗄️ Base de données SQLite
* 🌍 Utilisation depuis plusieurs machines d’un même réseau de laboratoire

Utilisation prévue : laboratoire personnel, CTF, environnement de développement ou test de sécurité explicitement autorisé.

⸻

📋 1. Prérequis

Systèmes supportés

OTP-SNIPER peut être exécuté sur :

* Linux
* Windows
* macOS

Les clients de laboratoire peuvent être :

* Firefox
* Chrome / Chromium
* curl
* Python Requests
* Postman
* Android
* iOS

Logiciels nécessaires

Linux

Installer Python et les outils nécessaires :

python3 --version
pip3 --version

Si Python n’est pas installé, utilisez le gestionnaire de paquets de votre distribution.

Windows

Vérifier :

python --version
pip --version

macOS

Vérifier :

python3 --version
pip3 --version

⸻

📁 2. Installation

Linux / macOS

Créer le dossier du projet :

mkdir OTP-Sniper
cd OTP-Sniper

Copier les fichiers du projet :

OTP-Sniper/
├── otp_sniper.py
├── requirements.txt
└── README.md

Créer l’environnement virtuel :

python3 -m venv venv

Activer l’environnement :

source venv/bin/activate

Installer les dépendances :

pip install -r requirements.txt

Lancer :

python3 otp_sniper.py

⸻

🪟 3. Installation Windows

Ouvrir PowerShell.

Créer le dossier :

mkdir OTP-Sniper
cd OTP-Sniper

Placer ensuite :

otp_sniper.py
requirements.txt
README.md

Créer le venv :

python -m venv venv

Activer :

venv\Scripts\activate

Installer les dépendances :

pip install -r requirements.txt

Lancer :

python otp_sniper.py

Si PowerShell bloque l’activation

Selon la politique d’exécution configurée sur Windows, l’activation peut être bloquée.

Vous pouvez utiliser directement :

venv\Scripts\python.exe otp_sniper.py

et :

venv\Scripts\pip.exe install -r requirements.txt

⸻

🍎 4. Installation macOS

Créer le projet :

mkdir OTP-Sniper
cd OTP-Sniper

Créer le venv :

python3 -m venv venv

Activer :

source venv/bin/activate

Installer :

pip install -r requirements.txt

Lancer :

python3 otp_sniper.py

⸻

🐧 5. Installation Linux

mkdir OTP-Sniper
cd OTP-Sniper
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 otp_sniper.py

⸻

⚙️ 6. Configuration générale

Avant de commencer les tests, définir clairement l’architecture du laboratoire.

Exemple :

                    RÉSEAU DE LABORATOIRE
                 ┌──────────────────────┐
                 │      Application     │
                 │      de test         │
                 └──────────┬───────────┘
                            │
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

Dans cet exemple :

Machine OTP-SNIPER
IP : 192.168.1.42
Port : 8080

Les clients du laboratoire doivent utiliser :

Proxy : 192.168.1.42
Port  : 8080

Lorsque le client et OTP-SNIPER sont sur la même machine :

Proxy : 127.0.0.1
Port  : 8080

⸻

🌐 7. Configuration réseau

7.1 Même machine

Si le navigateur et OTP-SNIPER fonctionnent sur le même ordinateur :

Adresse : 127.0.0.1
Port    : 8080

Architecture :

Firefox
   │
   ▼
127.0.0.1:8080
   │
   ▼
OTP-SNIPER

⸻

7.2 Deux machines

Si OTP-SNIPER fonctionne sur une machine différente du client :

Machine OTP-SNIPER
192.168.1.42
       │
       │ réseau local
       ▼
Machine cliente
192.168.1.50

Le client utilise :

Serveur proxy : 192.168.1.42
Port          : 8080

Vérifiez que les deux machines peuvent communiquer sur le réseau de laboratoire.

⸻

7.3 Plusieurs machines

Exemple :

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

Chaque client autorisé du laboratoire doit être configuré pour utiliser :

192.168.1.42:8080

⸻

🔥 8. Pare-feu

Si OTP-SNIPER est exécuté sur une machine distante, le port utilisé doit être accessible depuis les machines du laboratoire.

Vérifiez d’abord l’écoute du port.

Linux :

ss -lntp

ou :

sudo lsof -i :8080

Windows :

netstat -ano | findstr :8080

Si un pare-feu bloque le trafic, autorisez uniquement le réseau de laboratoire et le port nécessaire.

Évitez d’exposer le port du proxy directement sur Internet.

⸻

🖥️ 9. Démarrage d’OTP-SNIPER

Lancer :

python3 otp_sniper.py

Sous Windows :

python otp_sniper.py

Le programme propose :

[1] 🖥️  TUI (Terminal riche)
[2] 🌐 Web (Navigateur)
[3] 🔄 Les deux
[0] ❌ Quitter

⸻

🖥️ 10. Interface TUI

Le menu principal est :

[1]  🚀  Démarrer le proxy
[2]  ⏸️   Arrêter le proxy
[3]  🔴  Voir les codes 2FA
[4]  🍪  Voir les sessions / cookies
[5]  🔑  Voir les credentials
[6]  🔄  Replay manuel
[7]  ⚡  Replay automatique
[8]  📊  Statistiques
[9]  📜  Logs
[10] 💾  Export JSON
[11] 🌐  Interface Web
[12] 📜  Chemin du CA
[13] 🧪  Aide configuration client
[0]  ❌  Quitter

⸻

🌐 11. Configuration de l’interface Web

Choisir :

[2] 🌐 Web

ou :

[3] 🔄 Les deux

L’interface Web permet de consulter les informations disponibles depuis un navigateur de laboratoire.

Lorsque l’interface indique une adresse d’écoute, utilisez cette adresse depuis une machine autorisée du même réseau.

Exemple :

http://192.168.1.42:PORT

Le port exact dépend de la configuration de l’application.

⸻

🔐 12. Configuration HTTPS

OTP-SNIPER utilise une autorité de certification de laboratoire.

Au premier démarrage concerné, les fichiers sont générés dans :

otp_sniper_ca/

Structure :

otp_sniper_ca/
├── ca.key
├── ca.crt
├── example.com.crt
└── example.com.key

Signification

Fichier	Fonction
ca.key	Clé privée du CA
ca.crt	Certificat public du CA
<domaine>.crt	Certificat de test
<domaine>.key	Clé du certificat de test

⚠️ Important

Ne partagez jamais :

ca.key

Ne committez jamais :

otp_sniper_ca/

dans un dépôt public.

⸻

📜 13. Trouver le certificat CA

Depuis la TUI :

[12] 📜 Chemin du CA

Ou :

ls otp_sniper_ca/ca.crt

Sous Windows :

Get-ChildItem otp_sniper_ca

Le fichier à installer sur les clients de laboratoire est :

ca.crt

⸻

🦊 14. Configuration Firefox

Proxy

Dans Firefox :

Paramètres
→ Général
→ Paramètres réseau
→ Paramètres
→ Configuration manuelle du proxy

Même machine :

HTTP Proxy : 127.0.0.1
Port       : 8080

Machine distante :

HTTP Proxy : 192.168.1.42
Port       : 8080

Selon l’architecture, activez l’utilisation du proxy pour les protocoles nécessaires.

Certificat

Dans Firefox :

Paramètres
→ Vie privée et sécurité
→ Certificats
→ Afficher les certificats
→ Autorités
→ Importer

Sélectionner :

ca.crt

Ajoutez la confiance uniquement dans le profil Firefox utilisé pour le laboratoire.

⸻

🌐 15. Configuration Chrome / Chromium

Pour un environnement local de test :

google-chrome --proxy-server="http://127.0.0.1:8080"

Avec une machine OTP-SNIPER distante :

google-chrome --proxy-server="http://192.168.1.42:8080"

Le certificat de laboratoire doit également être reconnu par l’environnement de test.

⸻

🪟 16. Configuration du certificat sous Windows

Copier :

ca.crt

sur Windows.

Double-cliquer :

ca.crt

Puis :

Installer le certificat
→ Ordinateur local
→ Placer tous les certificats dans le magasin suivant
→ Autorités de certification racines de confiance
→ Terminer

Cette configuration doit être réalisée uniquement sur les machines de laboratoire.

⸻

🐧 17. Configuration du certificat sous Linux

Copier le certificat dans le magasin de certificats du système :

sudo cp otp_sniper_ca/ca.crt \
/usr/local/share/ca-certificates/otp-sniper.crt

Puis :

sudo update-ca-certificates

Vérifier :

ls /etc/ssl/certs/

⸻

🍎 18. Configuration du certificat sous macOS

Ouvrir :

Trousseaux d'accès

Importer :

ca.crt

dans le trousseau approprié pour le laboratoire.

Le certificat peut ensuite être configuré comme autorité de confiance pour cet environnement de test.

⸻

📱 19. Configuration Android

Sur un appareil de laboratoire :

Paramètres
→ Wi-Fi
→ Réseau connecté
→ Modifier
→ Options avancées
→ Proxy
→ Manuel

Si OTP-SNIPER se trouve sur :

192.168.1.42

utiliser :

Hôte : 192.168.1.42
Port : 8080

Le certificat ca.crt peut ensuite être installé via les paramètres de sécurité de l’appareil, selon la version d’Android.

Certaines applications Android modernes ne font volontairement pas confiance aux certificats utilisateurs. Cela peut nécessiter une configuration spécifique de l’application de laboratoire.

⸻

🍎 20. Configuration iOS

Sur un appareil de laboratoire :

1. Transférer ca.crt.
2. Ouvrir le fichier.
3. Installer le profil.
4. Aller dans :

Réglages
→ Général
→ VPN et gestion de l'appareil

Puis activer explicitement la confiance du certificat si nécessaire :

Réglages
→ Général
→ Informations
→ Réglages de confiance des certificats

⸻

🔧 21. Configuration curl

Pour un client situé sur la même machine :

curl -x http://127.0.0.1:8080 http://lab.local/api

Pour un OTP-SNIPER distant :

curl -x http://192.168.1.42:8080 http://lab.local/api

Pour HTTPS, utilisez le certificat de confiance du laboratoire plutôt que de désactiver la vérification TLS lorsque cela est possible.

⸻

🐍 22. Configuration Python Requests

Exemple pour une application de laboratoire :

import requests
proxies = {
    "http": "http://192.168.1.42:8080",
    "https": "http://192.168.1.42:8080",
}
response = requests.get(
    "https://lab.local/api",
    proxies=proxies
)
print(response.status_code)

Pour un test local :

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

⸻

📮 23. Configuration Postman

Dans :

Settings
→ Proxy

Configurer le proxy correspondant à la machine OTP-SNIPER :

Proxy type : HTTP
Host       : 192.168.1.42
Port       : 8080

Si Postman et OTP-SNIPER sont sur la même machine :

Host : 127.0.0.1
Port : 8080

Pour HTTPS, privilégiez l’installation correcte du certificat de laboratoire plutôt que la désactivation permanente de la vérification TLS.

⸻

🧪 24. Configuration d’un laboratoire multi-machines

Une architecture recommandée :

                  ┌─────────────────────────┐
                  │     ROUTEUR / SWITCH    │
                  │      LABORATOIRE        │
                  └────────────┬────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
       ┌────────────┐   ┌────────────┐   ┌────────────┐
       │ OTP-SNIPER │   │ Client PC  │   │  Android   │
       │            │   │            │   │            │
       │192.168.1.42│   │192.168.1.50│   │192.168.1.51│
       │    :8080   │   │            │   │            │
       └────────────┘   └────────────┘   └────────────┘

Configuration :

OTP-SNIPER
IP      : 192.168.1.42
Proxy   : 8080

Client PC :

Proxy   : 192.168.1.42
Port    : 8080

Android :

Proxy   : 192.168.1.42
Port    : 8080

⸻

🔄 25. Tests OTP / 2FA

Le laboratoire peut être utilisé pour étudier :

* durée de validité d’un OTP ;
* comportement après expiration ;
* comportement après une seconde utilisation ;
* limitation du nombre de tentatives ;
* réponses HTTP ;
* journaux de l’application ;
* mécanismes de protection contre les tentatives répétées.

Utilisez exclusivement des :

comptes de test
codes de test
applications de test
données synthétiques

⸻

⚡ 26. Replay automatique

Le module de rejeu permet d’étudier la fenêtre de validité d’un OTP dans un environnement de test.

Exemple de séquence :

Tentative    Délai
1            +1s
2            +5s
3            +30s
4            +60s
5            +5min

Exemple de résultat :

+1s      → accepted
+6s      → accepted
+36s     → rejected
+1m36s   → rejected
+6m36s   → rejected

L’objectif est d’observer le comportement du système de test, et non d’utiliser des codes appartenant à des utilisateurs réels.

⸻

📊 27. Statistiques

Le menu :

[8] 📊 Statistiques

permet d’obtenir une vue synthétique des événements enregistrés par l’application.

⸻

📜 28. Logs

Le menu :

[9] 📜 Logs

permet de diagnostiquer les problèmes de configuration.

En cas de problème :

1. Vérifier l’adresse IP.
2. Vérifier le port.
3. Vérifier la connexion réseau.
4. Vérifier le proxy du client.
5. Vérifier le certificat.
6. Consulter les logs.

⸻

💾 29. Export JSON

Le menu :

[10] 💾 Export JSON

permet d’exporter les résultats du laboratoire.

Les fichiers peuvent être générés sous la forme :

otp_sniper_export_*.json

Ces fichiers peuvent contenir des données sensibles de test.

Ne les publiez pas sur GitHub.

⸻

🗄️ 30. Base SQLite

La base est créée automatiquement :

otp_sniper.db

Structure logique :

requests
otp_codes
credentials
sessions

Pour l’ouvrir :

sqlite3 otp_sniper.db

Exemple :

SELECT *
FROM otp_codes
ORDER BY id DESC
LIMIT 10;

Quitter SQLite :

.quit

⸻

📁 31. Structure finale

Après exécution :

OTP-Sniper/
│
├── otp_sniper.py
├── requirements.txt
├── README.md
│
├── venv/
│
├── otp_sniper.db
│
├── otp_sniper_ca/
│   ├── ca.key
│   ├── ca.crt
│   └── ...
│
└── otp_sniper_export_*.json

⸻

🧹 32. Réinitialisation

Supprimer la base

Linux / macOS :

rm otp_sniper.db

Windows :

Remove-Item otp_sniper.db

⸻

Supprimer le CA

Linux / macOS :

rm -rf otp_sniper_ca/

Windows :

Remove-Item -Recurse -Force otp_sniper_ca

⸻

🔒 33. .gitignore

Créer un fichier :

.gitignore

avec :

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

⸻

❓ 34. Dépannage

Le programme ne démarre pas

Vérifier Python :

python3 --version

Puis :

pip install -r requirements.txt

⸻

cryptography manque

pip install cryptography

ou :

pip install -r requirements.txt

⸻

Le port 8080 est déjà utilisé

Linux :

sudo lsof -i :8080

Windows :

netstat -ano | findstr :8080

Si l’application accepte un autre port :

python3 otp_sniper.py --port 8081

⸻

Le client ne peut pas joindre OTP-SNIPER

Vérifier :

1. Adresse IP de la machine OTP-SNIPER
2. Port utilisé
3. Pare-feu
4. Connexion réseau
5. Configuration du proxy

Architecture correcte :

Client
  │
  │ 192.168.1.42:8080
  ▼
OTP-SNIPER

⸻

HTTPS affiche une erreur

Vérifier :

✓ ca.crt présent
✓ certificat installé dans le client
✓ bonne machine
✓ bonne autorité de confiance
✓ proxy correctement configuré

⸻

🧪 35. Checklist avant un test

[ ] Python installé
[ ] venv créé
[ ] requirements.txt installé
[ ] OTP-SNIPER démarre
[ ] Adresse IP du serveur connue
[ ] Port disponible
[ ] Pare-feu configuré pour le laboratoire
[ ] Client connecté au même réseau
[ ] Proxy configuré
[ ] CA installé si nécessaire
[ ] Application de test disponible
[ ] Compte de test disponible
[ ] OTP de test disponible
[ ] Données réelles exclues du test

⸻

🛑 36. Fin du laboratoire

Après les tests :

1. Arrêter le proxy.
2. Supprimer les données de test si elles ne sont plus nécessaires.
3. Supprimer le certificat CA des appareils utilisés.
4. Supprimer les exports contenant des données sensibles.
5. Ne pas publier otp_sniper.db.
6. Ne pas publier otp_sniper_ca/.
7. Ne jamais publier ca.key.

⸻

⚠️ Avertissement

OTP-SNIPER est destiné à la recherche en cybersécurité, aux environnements de laboratoire, aux CTF et aux tests explicitement autorisés.

L’utilisateur doit disposer de l’autorisation nécessaire avant de tester une application, un réseau, un appareil ou un compte.

N’utilisez pas cet outil pour intercepter, collecter ou rejouer des données appartenant à des tiers.

⸻

👨‍💻 Auteur

JATHNIEL

OTP-SNIPER v1.1 — JATHNIEL EDITION