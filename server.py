
import socket
import ssl
import threading
import json
import os
import time
import datetime
import hashlib
import secrets
import struct
import subprocess

HOST = '0.0.0.0'
PORT = 5555
USERS_FILE = 'users.json'
CERT_FILE  = 'server.crt'
KEY_FILE   = 'server.key'

def ensure_tls_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return
    print("[*] Генерирую самоподписанный TLS сертификат (RSA-4096)...")
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
        '-keyout', KEY_FILE, '-out', CERT_FILE,
        '-days', '3650', '-nodes',
        '-subj', '/CN=termes-server'
    ], check=True, capture_output=True)
    print("[+] Сертификат готов.")

def send_msg(sock, obj):
    data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
    sock.sendall(struct.pack('>I', len(data)) + data)

def recv_msg(sock):
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return None
    length = struct.unpack('>I', raw_len)[0]
    if length > 10 * 1024 * 1024:
        raise ValueError("Message too large")
    data = _recv_exact(sock, length)
    if not data:
        return None
    return json.loads(data.decode('utf-8'))

def _recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

class Server:
    def __init__(self):
        ensure_tls_cert()

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((HOST, PORT))
        raw.listen(128)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.server = ctx.wrap_socket(raw, server_side=True)

        self.users        = {}
        self.online       = {}
        self.active_chats = {}
        self._lock        = threading.Lock()
        self.load_users()

    def load_users(self):
        if os.path.exists(USERS_FILE):
            try:
                with open(USERS_FILE, 'r') as f:
                    self.users = json.load(f)
            except Exception:
                self.users = {}

    def save_users(self):
        with open(USERS_FILE, 'w') as f:
            json.dump(self.users, f, indent=2, ensure_ascii=False)

    def _hash_password(self, password: str, salt_hex: str) -> str:
        salt = bytes.fromhex(salt_hex)
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 300_000).hex()

    def log(self, event, addr, detail):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] [{event:<14}] {addr[0]}:{addr[1]} | {detail}")

    def _contacts_payload(self, username):
        contacts = []
        if username in self.users:
            for c in self.users[username].get('contacts', []):
                if c in self.users:
                    with self._lock:
                        status = 'ONLINE' if c in self.online else 'OFFLINE'
                    contacts.append({
                        'username': c,
                        'display_name': self.users[c]['display_name'],
                        'status': status
                    })
        return contacts

    def handle_client(self, client, address):
        current_user = None
        self.log("CONNECT", address, "TLS 1.3 handshake OK")

        try:
            while True:
                msg = recv_msg(client)
                if msg is None:
                    break

                cmd = msg.get('cmd', '')

                if cmd == 'REGISTER':
                    username     = msg.get('username', '').strip()
                    password     = msg.get('password', '')
                    display_name = msg.get('display_name', '').strip()

                    if not username or not password or not display_name:
                        send_msg(client, {'cmd': 'ERROR', 'text': 'Заполните все поля'})
                        continue
                    if len(username) > 32 or len(display_name) > 64:
                        send_msg(client, {'cmd': 'ERROR', 'text': 'Слишком длинное имя'})
                        continue
                    with self._lock:
                        if username in self.users:
                            send_msg(client, {'cmd': 'ERROR', 'text': 'Пользователь уже существует'})
                            continue
                        salt = secrets.token_hex(32)
                        self.users[username] = {
                            'password_hash': self._hash_password(password, salt),
                            'salt': salt,
                            'display_name': display_name,
                            'contacts': []
                        }
                        self.save_users()
                    send_msg(client, {'cmd': 'SUCCESS', 'text': 'Registered successfully'})
                    self.log("REGISTER", address, f"user={username}")

                elif cmd == 'LOGIN':
                    username = msg.get('username', '').strip()
                    password = msg.get('password', '')
                    with self._lock:
                        user = self.users.get(username)
                        if not user:
                            send_msg(client, {'cmd': 'ERROR', 'text': 'Неверный логин или пароль'})
                            continue
                        expected = self._hash_password(password, user['salt'])
                        if not secrets.compare_digest(expected, user['password_hash']):
                            send_msg(client, {'cmd': 'ERROR', 'text': 'Неверный логин или пароль'})
                            continue
                        current_user = username
                        self.online[username] = client
                    send_msg(client, {'cmd': 'SUCCESS', 'text': 'Logged in',
                                      'display_name': user['display_name']})
                    send_msg(client, {'cmd': 'CONTACTS',
                                      'contacts': self._contacts_payload(username)})
                    self.log("LOGIN", address, f"user={username}")

                elif cmd == 'FIND':
                    target = msg.get('target', '').strip()
                    with self._lock:
                        if target in self.users:
                            status = 'ONLINE' if target in self.online else 'OFFLINE'
                            send_msg(client, {'cmd': 'FOUND',
                                              'display_name': self.users[target]['display_name'],
                                              'status': status})
                        else:
                            send_msg(client, {'cmd': 'NOT_FOUND', 'text': 'Пользователь не найден'})

                elif cmd == 'INVITE':
                    if not current_user:
                        send_msg(client, {'cmd': 'ERROR', 'text': 'Не авторизован'})
                        continue
                    target = msg.get('target', '').strip()
                    with self._lock:
                        if target not in self.online:
                            send_msg(client, {'cmd': 'ERROR', 'text': 'Пользователь не в сети'})
                            continue
                        target_sock = self.online[target]
                    send_msg(target_sock, {'cmd': 'INVITE', 'from_user': current_user,
                                           'display_name': self.users[current_user]['display_name']})
                    send_msg(client, {'cmd': 'INVITE_SENT', 'text': 'Приглашение отправлено'})

                elif cmd == 'RESPONSE':
                    if not current_user:
                        continue
                    response = msg.get('response')
                    sender   = msg.get('sender', '').strip()
                    if response == 'ACCEPT':
                        with self._lock:
                            if sender not in self.online:
                                send_msg(client, {'cmd': 'ERROR', 'text': 'Пользователь оффлайн'})
                                continue
                            self.active_chats[sender]       = current_user
                            self.active_chats[current_user] = sender
                            sender_sock = self.online[sender]
                        send_msg(sender_sock, {'cmd': 'CHAT_START',
                                               'partner': self.users[current_user]['display_name'],
                                               'partner_user': current_user})
                        send_msg(client, {'cmd': 'CHAT_START',
                                          'partner': self.users[sender]['display_name'],
                                          'partner_user': sender})
                        self.log("CHAT_START", address, f"{current_user} <-> {sender}")
                    else:
                        with self._lock:
                            sock = self.online.get(sender)
                        if sock:
                            send_msg(sock, {'cmd': 'REJECTED', 'text': 'Запрос на чат отклонён'})

                elif cmd == 'KEY_EXCHANGE':
                    if not current_user:
                        continue
                    pubkey_b64 = msg.get('pubkey')
                    with self._lock:
                        partner      = self.active_chats.get(current_user)
                        partner_sock = self.online.get(partner) if partner else None
                    if partner_sock and pubkey_b64:
                        send_msg(partner_sock, {'cmd': 'KEY_EXCHANGE',
                                                'from_user': current_user,
                                                'pubkey': pubkey_b64})

                elif cmd == 'MESSAGE':
                    if not current_user:
                        continue
                    with self._lock:
                        partner      = self.active_chats.get(current_user)
                        partner_sock = self.online.get(partner) if partner else None
                    if partner_sock:
                        send_msg(partner_sock, {
                            'cmd':          'MESSAGE',
                            'from_display': self.users[current_user]['display_name'],
                            'ciphertext':   msg.get('ciphertext'),
                            'nonce':        msg.get('nonce'),
                        })

                elif cmd == 'TYPING':
                    if not current_user:
                        continue
                    with self._lock:
                        partner      = self.active_chats.get(current_user)
                        partner_sock = self.online.get(partner) if partner else None
                    if partner_sock:
                        send_msg(partner_sock, {'cmd': 'TYPING',
                                                'from_display': self.users[current_user]['display_name']})

                elif cmd == 'CHAT_END':
                    if not current_user:
                        continue
                    with self._lock:
                        partner = self.active_chats.pop(current_user, None)
                        if partner:
                            self.active_chats.pop(partner, None)
                            partner_sock = self.online.get(partner)
                        else:
                            partner_sock = None
                    if partner_sock:
                        send_msg(partner_sock, {'cmd': 'CHAT_END', 'text': 'Собеседник покинул чат'})

                elif cmd == 'ADD_CONTACT':
                    if not current_user:
                        continue
                    contact = msg.get('contact', '').strip()
                    with self._lock:
                        if contact not in self.users:
                            send_msg(client, {'cmd': 'ERROR', 'text': 'Пользователь не найден'})
                            continue
                        contacts = self.users[current_user]['contacts']
                        if contact not in contacts:
                            contacts.append(contact)
                            self.save_users()
                    send_msg(client, {'cmd': 'CONTACTS',
                                      'contacts': self._contacts_payload(current_user)})

                elif cmd == 'REMOVE_CONTACT':
                    if not current_user:
                        continue
                    contact = msg.get('contact', '').strip()
                    with self._lock:
                        contacts = self.users.get(current_user, {}).get('contacts', [])
                        if contact in contacts:
                            contacts.remove(contact)
                            self.save_users()
                    send_msg(client, {'cmd': 'CONTACTS',
                                      'contacts': self._contacts_payload(current_user)})

                elif cmd == 'CHANGE_PASSWORD':
                    if not current_user:
                        continue
                    old_pw = msg.get('old_password', '')
                    new_pw = msg.get('new_password', '')
                    with self._lock:
                        user     = self.users.get(current_user)
                        expected = self._hash_password(old_pw, user['salt'])
                        if not secrets.compare_digest(expected, user['password_hash']):
                            send_msg(client, {'cmd': 'ERROR', 'text': 'Неверный старый пароль'})
                            continue
                        new_salt             = secrets.token_hex(32)
                        user['salt']         = new_salt
                        user['password_hash'] = self._hash_password(new_pw, new_salt)
                        self.save_users()
                    send_msg(client, {'cmd': 'SUCCESS', 'text': 'Пароль изменён'})

                elif cmd == 'GET_CONTACTS':
                    if current_user:
                        send_msg(client, {'cmd': 'CONTACTS',
                                          'contacts': self._contacts_payload(current_user)})

                elif cmd == 'PING':
                    send_msg(client, {'cmd': 'PONG'})

                elif cmd == 'EXIT':
                    break

        except Exception as e:
            self.log("ERROR", address, str(e))
        finally:
            with self._lock:
                if current_user:
                    self.online.pop(current_user, None)
                    partner = self.active_chats.pop(current_user, None)
                    if partner:
                        self.active_chats.pop(partner, None)
                        p_sock = self.online.get(partner)
                        if p_sock:
                            try:
                                send_msg(p_sock, {'cmd': 'CHAT_END',
                                                  'text': 'Собеседник отключился'})
                            except Exception:
                                pass
            try:
                client.close()
            except Exception:
                pass
            self.log("DISCONNECT", address, f"user={current_user}")

    def start(self):
        print(f"╔{'═' * 60}╗")
        print(f"║{'TERMES SECURE SERVER':^60}║")
        print(f"║{'TLS 1.3  |  X25519  |  AES-256-GCM  |  E2E':^60}║")
        print(f"╠{'═' * 60}╣")
        print(f"║  Порт: {PORT:<52}║")
        print(f"╚{'═' * 60}╝\n")
        print("Ожидание подключений...\n")
        while True:
            try:
                client, address = self.server.accept()
                t = threading.Thread(target=self.handle_client,
                                     args=(client, address), daemon=True)
                t.start()
            except Exception as e:
                print(f"[!] Accept error: {e}")

if __name__ == '__main__':
    server = Server()
    server.start()
