
import ssl, socket, threading, json, os, sys, time, struct, base64
import datetime, getpass, platform, hashlib, secrets

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style

SERVER_IP = 'СПРОСИТЕ_ПОЖАЛУЙСТА_АЙПИ_СЕРВЕРА_У_@gurenov_ТГ'
PORT      = 5555
MSG_LIMIT = 500

def send_msg(sock, obj):
    data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
    sock.sendall(struct.pack('>I', len(data)) + data)

def recv_msg(sock):
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return None
    length = struct.unpack('>I', raw_len)[0]
    if length > 10 * 1024 * 1024:
        raise ValueError("Frame too large")
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

class E2ECrypto:

    def __init__(self):
        self._priv = X25519PrivateKey.generate()
        pub_bytes  = self._priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        self.pubkey_b64 = base64.b64encode(pub_bytes).decode()
        self._aes: AESGCM | None = None

    def compute_shared(self, peer_pubkey_b64: str):
        peer_bytes      = base64.b64decode(peer_pubkey_b64)
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        peer_pubkey_obj = X25519PublicKey.from_public_bytes(peer_bytes)
        shared          = self._priv.exchange(peer_pubkey_obj)

        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'termes-e2e-v1',
            backend=default_backend()
        ).derive(shared)
        self._aes = AESGCM(key)

    @property
    def ready(self):
        return self._aes is not None

    def encrypt(self, plaintext: str) -> tuple[str, str]:

        nonce = secrets.token_bytes(12)
        ct    = self._aes.encrypt(nonce, plaintext.encode('utf-8'), None)
        return base64.b64encode(ct).decode(), base64.b64encode(nonce).decode()

    def decrypt(self, ciphertext_b64: str, nonce_b64: str) -> str:
        ct    = base64.b64decode(ciphertext_b64)
        nonce = base64.b64decode(nonce_b64)
        return self._aes.decrypt(nonce, ct, None).decode('utf-8')

def _color(text, code): return f"\033[{code}m{text}\033[0m"
def _bold(t):   return _color(t, '1')
def _cyan(t):   return _color(t, '1;36')
def _green(t):  return _color(t, '1;32')
def _yellow(t): return _color(t, '1;33')
def _red(t):    return _color(t, '1;31')
def _grey(t):   return _color(t, '90')
def _white(t):  return _color(t, '1;97')

def clr():
    print("\033[H\033[J", end='', flush=True)

def header(title):
    print(f"\n{_cyan('╔' + '═'*60 + '╗')}")
    print(f"{_cyan('║')}{_bold(title):^60}{_cyan('║')}")
    print(f"{_cyan('╚' + '═'*60 + '╝')}\n")

def menu(options):
    print(_yellow("─" * 62))
    for i, o in enumerate(options, 1):
        print(f"  {_yellow(str(i) + '.')} {o}")
    print(_yellow("─" * 62))

def err(msg):
    print(_red(f"\n  [!] {msg}"))
    time.sleep(1.5)

def ok(msg):
    print(_green(f"\n  [✓] {msg}"))
    time.sleep(1)

def warn(msg):
    print(_yellow(f"\n  [!] {msg}"))
    time.sleep(1.5)

def _make_tls_ctx():
    ctx               = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx

class Client:
    def __init__(self):
        self._sock: ssl.SSLSocket | None = None
        self._lock = threading.Lock()

        self.connected    = False
        self.username     = None
        self.display_name = None
        self.password     = None
        self.status       = "🔴 Отключен"

        self.contacts       = []
        self.pending_invite = None

        self.in_chat      = False
        self.chat_partner_display = None
        self.chat_partner_user    = None
        self.chat_history = []
        self.crypto: E2ECrypto | None  = None
        self.typing_shown = False

        self.ping_ms     = 0
        self._last_ping  = 0
        self._last_pong  = time.time()
        self.start_time  = time.time()

        self._login_event   = threading.Event()
        self._login_result  = None
        self._reg_event     = threading.Event()
        self._reg_result    = None
        self._find_event    = threading.Event()
        self._find_result   = None
        self._generic_event  = threading.Event()
        self._generic_result = None
        self._chat_start_event = threading.Event()

        self._connect()

    def _connect(self):
        try:
            raw  = socket.create_connection((SERVER_IP, PORT), timeout=10)
            ctx  = _make_tls_ctx()
            self._sock = ctx.wrap_socket(raw, server_hostname=SERVER_IP)
            self.connected = True
            self.status    = "🟢 В сети"
        except Exception as e:
            self.connected = False
            self.status    = f"🔴 Отключен ({e})"
            return

        t = threading.Thread(target=self._receiver, daemon=True)
        t.start()

        p = threading.Thread(target=self._pinger, daemon=True)
        p.start()

    def _send(self, obj):
        with self._lock:
            if self._sock:
                try:
                    send_msg(self._sock, obj)
                except Exception:
                    self.connected = False

    def _pinger(self):
        while True:
            time.sleep(5)
            if self.connected:
                self._last_ping = time.time()
                self._send({'cmd': 'PING'})

                if time.time() - self._last_pong > 20:
                    self.connected = False
                    self.status    = "🔴 Отключен"

    def _receiver(self):
        while True:
            try:
                msg = recv_msg(self._sock)
                if msg is None:
                    break
                self._handle_server_msg(msg)
            except Exception:
                break
        self.connected = False
        self.status    = "🔴 Отключен"
        if self.in_chat:
            self._append_chat(_yellow("\n  [!] Соединение с сервером потеряно"))

    def _handle_server_msg(self, msg):
        cmd = msg.get('cmd', '')

        if cmd == 'PONG':
            self._last_pong = time.time()
            self.ping_ms    = int((time.time() - self._last_ping) * 1000)

        elif cmd == 'SUCCESS':
            text = msg.get('text', '')
            if text == 'Logged in':
                self.display_name   = msg.get('display_name')
                self._login_result  = True
                self._login_event.set()
            else:
                self._generic_result = ('ok', text)
                self._generic_event.set()
                self._reg_result = True
                self._reg_event.set()

        elif cmd == 'ERROR':
            text = msg.get('text', '')
            self._login_result  = ('err', text)
            self._login_event.set()
            self._reg_result    = ('err', text)
            self._reg_event.set()
            self._generic_result = ('err', text)
            self._generic_event.set()

        elif cmd == 'CONTACTS':
            self.contacts = msg.get('contacts', [])

        elif cmd == 'FOUND':
            self._find_result = msg
            self._find_event.set()

        elif cmd == 'NOT_FOUND':
            self._find_result = None
            self._find_event.set()

        elif cmd == 'INVITE_SENT':
            self._generic_result = ('ok', msg.get('text', ''))
            self._generic_event.set()

        elif cmd == 'INVITE':
            self.pending_invite = (msg.get('from_user'), msg.get('display_name'))
            self._show_invite_banner()

        elif cmd == 'REJECTED':
            self._generic_result = ('rej', msg.get('text', ''))
            self._generic_event.set()

        elif cmd == 'CHAT_START':
            self.chat_partner_display = msg.get('partner')
            self.chat_partner_user    = msg.get('partner_user')
            self.chat_history         = []
            self.crypto               = E2ECrypto()
            self.in_chat              = True
            self._chat_start_event.set()

            self._send({'cmd': 'KEY_EXCHANGE', 'pubkey': self.crypto.pubkey_b64})
            self._append_chat(_grey(
                f"  🔐 Сессия начата. Ожидание обмена ключами..."))

        elif cmd == 'KEY_EXCHANGE':
            if self.crypto and not self.crypto.ready:
                self.crypto.compute_shared(msg.get('pubkey'))
                self._append_chat(_green(
                    f"  🔒 E2E шифрование активно (X25519 + AES-256-GCM)"))

                self._send({'cmd': 'KEY_EXCHANGE', 'pubkey': self.crypto.pubkey_b64})

        elif cmd == 'MESSAGE':
            if not self.in_chat:
                return
            sender  = msg.get('from_display', '?')
            ct      = msg.get('ciphertext')
            nonce   = msg.get('nonce')
            ts      = datetime.datetime.now().strftime("%H:%M:%S")
            if self.crypto and self.crypto.ready:
                try:
                    text = self.crypto.decrypt(ct, nonce)
                    line = (f"{_grey('['+ts+']')} "
                            f"{_cyan('['+sender+']')}: "
                            f"{_white(text)}")
                except Exception:
                    line = _red(f"  [!] Не удалось расшифровать сообщение")
            else:
                line = _red(f"  [!] Ключ не установлен — сообщение отброшено")
            self._append_chat(line)

        elif cmd == 'TYPING':
            if self.in_chat and not self.typing_shown:
                sender = msg.get('from_display', '')
                self.typing_shown = True
                def _clear_typing():
                    time.sleep(2)
                    self.typing_shown = False
                threading.Thread(target=_clear_typing, daemon=True).start()

        elif cmd == 'CHAT_END':
            self.in_chat = False
            self.crypto  = None
            self._append_chat(_yellow(f"\n  [!] {msg.get('text', 'Чат завершён')}"))
            self.chat_partner_display = None

    def _show_invite_banner(self):

        user, dname = self.pending_invite
        print(f"\n{_yellow('  ◆ Входящий запрос чата от')} {_cyan(dname)} {_grey('('+user+')')}")
        print(_grey("    Перейдите в меню → 'Обработать запрос'"))

    def _append_chat(self, line: str):
        self.chat_history.append(line)
        if len(self.chat_history) > 200:
            self.chat_history = self.chat_history[-200:]
        if self.in_chat:
            print(line)

    def start(self):
        if not self.connected:
            err(f"Не удалось подключиться к серверу: {self.status}")
            return

        clr()
        header("TERMES SECURE MESSENGER")
        print(_grey("  TLS 1.3 + X25519 ECDH + AES-256-GCM\n"))
        self._auth_loop()

    def _auth_loop(self):
        while not self.username:
            clr()
            header("ГЛАВНОЕ МЕНЮ")
            print(f"  Соединение: {self.status}  |  Пинг: {self.ping_ms}ms\n")
            menu(["Регистрация", "Вход", "Выход"])
            choice = input("  Выберите: ").strip()
            if choice == '1':
                self._register()
            elif choice == '2':
                self._login()
            elif choice == '3':
                sys.exit(0)
        self._main_loop()

    def _register(self):
        clr()
        header("РЕГИСТРАЦИЯ")
        username     = input("  Логин: ").strip()
        password     = getpass.getpass("  Пароль: ")
        display_name = input("  Имя для отображения: ").strip()
        if not username or not password or not display_name:
            err("Заполните все поля")
            return
        self._reg_event.clear()
        self._reg_result = None
        self._send({'cmd': 'REGISTER', 'username': username,
                    'password': password, 'display_name': display_name})
        self._reg_event.wait(timeout=10)
        if self._reg_result is True:
            ok("Аккаунт создан! Войдите в систему.")
        elif isinstance(self._reg_result, tuple):
            err(self._reg_result[1])

    def _login(self):
        clr()
        header("АВТОРИЗАЦИЯ")
        username = input("  Логин: ").strip()
        password = getpass.getpass("  Пароль: ")
        self._login_event.clear()
        self._login_result = None
        self._send({'cmd': 'LOGIN', 'username': username, 'password': password})
        self._login_event.wait(timeout=10)
        if self._login_result is True:
            self.username = username
            self.password = password
            ok(f"Добро пожаловать, {self.display_name}!")
        elif isinstance(self._login_result, tuple):
            err(self._login_result[1])

    def _main_loop(self):
        while self.username:
            clr()
            header(f"ДОБРО ПОЖАЛОВАТЬ, {self.display_name.upper()}")
            print(f"  {self.status}  |  Пинг: {self.ping_ms}ms\n")

            options = ["Найти пользователя", "Мои контакты",
                       "Настройки аккаунта", "Выйти из аккаунта"]
            if self.pending_invite:
                options.append("⬤ Обработать запрос чата")
            menu(options)

            choice = input("  Выберите: ").strip()

            if choice == '1':
                self._find_and_chat()
            elif choice == '2':
                self._contacts_menu()
            elif choice == '3':
                self._account_settings()
            elif choice == '4':
                self._send({'cmd': 'EXIT'})
                self.username = self.display_name = None
                self._auth_loop()
                return
            elif choice == '5' and self.pending_invite:
                self._handle_invite()

    def _find_and_chat(self):
        clr()
        header("ПОИСК ПОЛЬЗОВАТЕЛЯ")
        target = input("  Введите username: ").strip()
        if not target:
            return
        self._find_event.clear()
        self._find_result = None
        self._send({'cmd': 'FIND', 'target': target})
        self._find_event.wait(timeout=10)

        if not self._find_result:
            err("Пользователь не найден")
            return

        r = self._find_result
        status_str = _green("🟢 В сети") if r['status'] == 'ONLINE' else _red("🔴 Не в сети")
        print(f"\n  Имя: {_cyan(r['display_name'])}  Статус: {status_str}")
        menu(["Пригласить в чат", "Добавить в контакты", "Назад"])
        ch = input("  Выберите: ").strip()

        if ch == '1':
            if r['status'] != 'ONLINE':
                err("Пользователь не в сети")
                return
            self._generic_event.clear()
            self._chat_start_event.clear()
            self._send({'cmd': 'INVITE', 'target': target})
            print(_yellow("\n  Ожидание принятия приглашения... (/cancel для отмены)"))

            deadline = time.time() + 120
            accepted = False
            while time.time() < deadline:
                if self._chat_start_event.wait(timeout=0.3):
                    accepted = True
                    break
                if (isinstance(self._generic_result, tuple)
                        and self._generic_result[0] == 'rej'):
                    err(self._generic_result[1])
                    return
            if accepted and self.in_chat:
                self._chat_session()
            else:
                warn("Собеседник не принял приглашение")

        elif ch == '2':
            self._send({'cmd': 'ADD_CONTACT', 'contact': target})
            ok("Контакт добавлен")

    def _handle_invite(self):
        if not self.pending_invite:
            return
        from_user, disp = self.pending_invite
        clr()
        header("ВХОДЯЩИЙ ЗАПРОС ЧАТА")
        print(f"  Пользователь {_cyan(disp)} {_grey('('+from_user+')')} хочет начать чат\n")
        menu(["Принять", "Отклонить"])
        ch = input("  Выберите: ").strip()
        self.pending_invite = None

        if ch == '1':
            self._send({'cmd': 'RESPONSE', 'response': 'ACCEPT', 'sender': from_user})

            deadline = time.time() + 10
            while not self.in_chat and time.time() < deadline:
                time.sleep(0.1)
            if self.in_chat:
                self._chat_session()
            else:
                err("Не удалось начать чат")
        else:
            self._send({'cmd': 'RESPONSE', 'response': 'REJECT', 'sender': from_user})

    def _chat_session(self):

        deadline = time.time() + 10
        while self.crypto and not self.crypto.ready and time.time() < deadline:
            time.sleep(0.05)

        partner = self.chat_partner_display or "?"

        session = PromptSession()
        style   = Style.from_dict({'prompt': '#ansicyan bold'})

        _ANSI_RE = __import__('re').compile(r'\x1b\[[0-9;]*m')

        with patch_stdout(raw=True):
            clr()
            print(f"{_cyan('╔' + '═'*60 + '╗')}")
            print(f"{_cyan('║')} ЧАТ С {_bold(partner.upper()):<54}{_cyan('║')}")
            print(f"{_cyan('╠' + '═'*60 + '╣')}")
            print(f"{_grey('  /exit — покинуть чат  |  /clear — очистить экран')}")
            print(f"{_cyan('╚' + '═'*60 + '╝')}\n")

            for line in self.chat_history:
                print(line)

            while self.in_chat:
                try:
                    hint = f" [{partner} печатает...]" if self.typing_shown else ""
                    text = session.prompt(
                        HTML(f'<prompt>Вы{hint}</prompt>> '),
                        style=style,
                    )
                except (EOFError, KeyboardInterrupt):
                    break

                text = _ANSI_RE.sub('', text).strip()

                if not text:
                    continue
                if text == '/exit':
                    break
                if text == '/clear':
                    clr()
                    for line in self.chat_history[-20:]:
                        print(line)
                    continue
                if len(text) > MSG_LIMIT:
                    print(_red(f"  [!] Сообщение слишком длинное (макс {MSG_LIMIT} символов)"))
                    continue

                if not (self.crypto and self.crypto.ready):
                    print(_red("  [!] Шифрование не установлено, сообщение не отправлено"))
                    continue

                ct, nonce = self.crypto.encrypt(text)
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                mine = (f"{_grey('['+ts+']')} "
                        f"{_yellow('[Вы]')}: "
                        f"{_white(text)}")
                self.chat_history.append(mine)
                print(mine)
                self._send({'cmd': 'MESSAGE', 'ciphertext': ct, 'nonce': nonce})

            if self.in_chat:
                self.in_chat = False
                self._send({'cmd': 'CHAT_END'})
            self.crypto = None
            print(_yellow("\n  ╔" + "═"*40 + "╗"))
            print(_yellow("  ║  Чат завершён. Нажмите Enter для меню   ║"))
            print(_yellow("  ╚" + "═"*40 + "╝"))

        input()

    def _contacts_menu(self):
        while True:
            clr()
            header("МОИ КОНТАКТЫ")
            if not self.contacts:
                print("  У вас пока нет контактов.\n")
            else:
                for i, c in enumerate(self.contacts, 1):
                    st = _green("🟢") if c['status'] == 'ONLINE' else _red("🔴")
                    print(f"  {i}. {_cyan(c['display_name'])} "
                          f"{_grey('('+c['username']+')')} {st}")
            print()
            menu(["Добавить контакт", "Удалить контакт", "Назад"])
            ch = input("  Выберите: ").strip()

            if ch == '1':
                u = input("  Username пользователя: ").strip()
                if u:
                    self._send({'cmd': 'ADD_CONTACT', 'contact': u})
                    ok("Запрос отправлен")
            elif ch == '2' and self.contacts:
                u = input("  Username для удаления: ").strip()
                if u:
                    self._send({'cmd': 'REMOVE_CONTACT', 'contact': u})
                    ok("Контакт удалён")
            elif ch == '3':
                return
            else:
                time.sleep(0.5)

                self._send({'cmd': 'GET_CONTACTS'})
                time.sleep(0.5)

    def _account_settings(self):
        while True:
            clr()
            header("НАСТРОЙКИ АККАУНТА")
            print(f"  Статус: {self.status}  |  Пинг: {self.ping_ms}ms")
            print(f"  Время сессии: {int(time.time()-self.start_time)} сек\n")
            menu(["Сменить пароль", "Обновить контакты", "Назад"])
            ch = input("  Выберите: ").strip()

            if ch == '1':
                clr()
                header("СМЕНА ПАРОЛЯ")
                old = getpass.getpass("  Старый пароль: ")
                new = getpass.getpass("  Новый пароль: ")
                cnf = getpass.getpass("  Подтвердите новый: ")
                if new != cnf:
                    err("Пароли не совпадают")
                    continue
                self._generic_event.clear()
                self._send({'cmd': 'CHANGE_PASSWORD',
                            'old_password': old, 'new_password': new})
                self._generic_event.wait(5)
                if isinstance(self._generic_result, tuple):
                    if self._generic_result[0] == 'ok':
                        self.password = new
                        ok(self._generic_result[1])
                    else:
                        err(self._generic_result[1])
            elif ch == '2':
                self._send({'cmd': 'GET_CONTACTS'})
                ok("Контакты обновлены")
            elif ch == '3':
                return

if __name__ == '__main__':
    try:
        c = Client()
        c.start()
    except KeyboardInterrupt:
        print("\n  До свидания!")
        sys.exit(0)
