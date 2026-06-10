import os
import json
import base64
import time
import threading
import itertools
import sys
import requests

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

VAULT_FILE = "vault.json"
REPO_VERSION_URL = "https://raw.githubusercontent.com/sungjinwoodev/EncPass/main/version.json"
LOCAL_FILE = __file__

AUTO_LOCK_SECONDS = 180
UPDATE_INTERVAL = 10

LOCAL_VERSION = "1.0.2"

print_lock = threading.Lock()
interrupt_event = threading.Event()


def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)


def safe_input(prompt):
    with print_lock:
        return input(prompt)


class C:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"


class Updater:
    def __init__(self):
        self.running = True
        self.update = None

    def check(self):
        try:
            r = requests.get(REPO_VERSION_URL, timeout=5)
            return r.json()
        except:
            return None

    def loop(self):
        while self.running:
            data = self.check()

            if data:
                v = data.get("version")

                if v and v != LOCAL_VERSION:
                    self.update = data
                    interrupt_event.set()
                    return

            time.sleep(UPDATE_INTERVAL)


updater = Updater()


def apply_update(url):
    r = requests.get(url, timeout=10)
    code = r.text

    tmp = LOCAL_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(code)

    os.replace(tmp, LOCAL_FILE)
    os.execv(sys.executable, [sys.executable, LOCAL_FILE])


def derive_key(password, salt):
    return hash_secret_raw(
        password.encode(),
        salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )


def encrypt(data, password, salt):
    key = derive_key(password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    enc = aes.encrypt(nonce, json.dumps(data).encode(), None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "data": base64.b64encode(enc).decode()
    }


def decrypt(blob, password, salt):
    key = derive_key(password, salt)
    aes = AESGCM(key)
    nonce = base64.b64decode(blob["nonce"])
    enc = base64.b64decode(blob["data"])
    raw = aes.decrypt(nonce, enc, None)
    return json.loads(raw.decode())


def load_vault_file():
    if not os.path.exists(VAULT_FILE):
        return None
    with open(VAULT_FILE, "r") as f:
        return json.load(f)


def save_vault_file(vault):
    tmp = VAULT_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(vault, f)
    os.replace(tmp, VAULT_FILE)


def init_vault():
    if not os.path.exists(VAULT_FILE):
        safe_print(f"{C.YELLOW}First time setup{C.RESET}")
        pw = safe_input("Create Master Password: ")
        salt = os.urandom(16)
        blob = encrypt([], pw, salt)
        save_vault_file({"salt": base64.b64encode(salt).decode(), "blob": blob})
        safe_print(f"{C.GREEN}Vault created{C.RESET}")
        time.sleep(1)


def clear():
    os.system("cls" if os.name == "nt" else "clear")


class App:
    def __init__(self):
        self.master = None
        self.salt = None
        self.data = []
        self.locked = True
        self.last_action = time.time()
        self.timer = threading.Thread(target=self.auto_lock, daemon=True)

    def auto_lock(self):
        while True:
            if not self.locked and time.time() - self.last_action > AUTO_LOCK_SECONDS:
                clear()
                safe_print(f"{C.RED}Session expired{C.RESET}")
                self.lock()
            time.sleep(1)

    def reset_timer(self):
        self.last_action = time.time()

    def load(self, password):
        vault = load_vault_file()
        if not vault:
            return False

        try:
            salt = base64.b64decode(vault["salt"])
            data = decrypt(vault["blob"], password, salt)
        except:
            return False

        self.master = password
        self.salt = salt
        self.data = data
        self.locked = False
        return True

    def save(self):
        blob = encrypt(self.data, self.master, self.salt)
        save_vault_file({"salt": base64.b64encode(self.salt).decode(), "blob": blob})

    def unlock(self):
        clear()
        safe_print(f"{C.CYAN}{C.BOLD}=== ENCPASS LOGIN ==={C.RESET}\n")

        while True:
            if interrupt_event.is_set():
                return "UPDATE"

            pw = safe_input("Master Password: ")

            if interrupt_event.is_set():
                return "UPDATE"

            if self.load(pw):
                safe_print(f"{C.GREEN}Unlocked{C.RESET}")
                time.sleep(1)
                return True

            safe_print(f"{C.RED}Wrong password{C.RESET}")

    def lock(self):
        self.master = None
        self.data = []
        self.locked = True

    def add(self):
        clear()

        if interrupt_event.is_set():
            return

        site = safe_input("Site: ")
        user = safe_input("Username: ")
        pw = safe_input("Password: ")

        self.data.append({"site": site, "username": user, "password": pw})
        self.save()

        safe_print(f"{C.GREEN}Saved{C.RESET}")
        time.sleep(1)

    def view(self):
        clear()

        for i, item in enumerate(self.data):
            safe_print(f"[{i}] {item['site']} - {item['username']}")

        safe_input("")

    def delete(self):
        clear()

        for i, item in enumerate(self.data):
            safe_print(f"[{i}] {item['site']}")

        try:
            idx = int(safe_input("Delete: "))
            self.data.pop(idx)
            self.save()
        except:
            pass

    def menu(self):
        clear()
        safe_print(f"{C.CYAN}{C.BOLD}=== ENCPASS ==={C.RESET}")
        safe_print("1. Add")
        safe_print("2. View")
        safe_print("3. Delete")
        safe_print("4. Lock")
        safe_print("5. Exit")

    def force_update(self):
        clear()
        safe_print(f"\n{C.YELLOW}UPDATE FOUND. APPLYING...{C.RESET}")
        time.sleep(0.5)
        apply_update(updater.update["download_url"])

    def run(self):
        init_vault()
        self.timer.start()
        threading.Thread(target=updater.loop, daemon=True).start()

        while True:

            if interrupt_event.is_set():
                self.force_update()

            if self.locked:
                r = self.unlock()
                if r == "UPDATE":
                    continue

            if interrupt_event.is_set():
                self.force_update()

            self.menu()

            if interrupt_event.is_set():
                self.force_update()

            c = safe_input("Choice: ")

            if interrupt_event.is_set():
                self.force_update()

            self.reset_timer()

            if c == "1":
                self.add()
            elif c == "2":
                self.view()
            elif c == "3":
                self.delete()
            elif c == "4":
                self.lock()
            elif c == "5":
                updater.running = False
                break

            if interrupt_event.is_set():
                self.force_update()


if __name__ == "__main__":
    App().run()