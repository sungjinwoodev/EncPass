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
UPDATE_INTERVAL = 10800
LOCAL_VERSION = "1.0.0"

print_lock = threading.Lock()


def p(*a):
    with print_lock:
        print(*a)


def i(x):
    with print_lock:
        return input(x)


class C:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"


class Updater:
    def __init__(self):
        self.enabled = True
        self.update_available = False
        self.data = None

    def check(self):
        try:
            r = requests.get(REPO_VERSION_URL, timeout=5)
            if r.status_code != 200:
                return None
            return r.json()
        except:
            return None

    def is_newer(self, remote, local):
        try:
            r = tuple(map(int, remote.split(".")))
            l = tuple(map(int, local.split(".")))
            return r > l
        except:
            return False

    def run_check(self):
        if not self.enabled or self.update_available:
            return

        data = self.check()
        if not data:
            return

        remote_version = data.get("version")
        download_url = data.get("download_url")

        if not remote_version or not download_url:
            return

        if self.is_newer(remote_version, LOCAL_VERSION):
            self.update_available = True
            self.data = data


updater = Updater()


def apply_update(url):
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return

        code = r.text

        tmp = LOCAL_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(code)

        os.replace(tmp, LOCAL_FILE)
        os.execv(sys.executable, [sys.executable, LOCAL_FILE])

    except:
        pass


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
    return json.loads(aes.decrypt(nonce, enc, None).decode())


def load_vault_file():
    if not os.path.exists(VAULT_FILE):
        return None
    with open(VAULT_FILE, "r") as f:
        return json.load(f)


def save_vault_file(v):
    tmp = VAULT_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(v, f)
    os.replace(tmp, VAULT_FILE)


def init_vault():
    if os.path.exists(VAULT_FILE):
        return
    p(f"{C.YELLOW}First time setup{C.RESET}")
    pw = i("Create Master Password: ")
    salt = os.urandom(16)
    blob = encrypt([], pw, salt)
    save_vault_file({"salt": base64.b64encode(salt).decode(), "blob": blob})
    p(f"{C.GREEN}Vault created{C.RESET}")
    time.sleep(1)


def clear():
    os.system("cls" if os.name == "nt" else "clear")


class App:
    def __init__(self):
        self.master = None
        self.salt = None
        self.data = []
        self.locked = True
        self.last = time.time()
        self.timer = threading.Thread(target=self.auto_lock, daemon=True)

    def auto_lock(self):
        while True:
            if not self.locked and time.time() - self.last > AUTO_LOCK_SECONDS:
                clear()
                p(f"{C.RED}Session expired{C.RESET}")
                self.lock()
            time.sleep(1)

    def reset(self):
        self.last = time.time()

    def load(self, pw):
        v = load_vault_file()
        if not v:
            return False
        try:
            salt = base64.b64decode(v["salt"])
            data = decrypt(v["blob"], pw, salt)
        except:
            return False

        self.master = pw
        self.salt = salt
        self.data = data
        self.locked = False
        return True

    def save(self):
        blob = encrypt(self.data, self.master, self.salt)
        save_vault_file({"salt": base64.b64encode(self.salt).decode(), "blob": blob})

    def unlock(self):
        clear()
        p(f"{C.CYAN}{C.BOLD}=== ENCPASS LOGIN ==={C.RESET}\n")

        while True:
            pw = i("Master Password: ")

            if updater.update_available:
                return "UPDATE"

            if self.load(pw):
                p(f"{C.GREEN}Unlocked{C.RESET}")
                time.sleep(1)
                return True

            p(f"{C.RED}Wrong password{C.RESET}")

    def lock(self):
        self.master = None
        self.data = []
        self.locked = True

    def menu(self):
        clear()
        p(f"{C.CYAN}{C.BOLD}=== ENCPASS ==={C.RESET}")
        p("1. Add")
        p("2. View")
        p("3. Delete")
        p("4. Lock")
        p("5. Exit")
        p(f"Auto-update: {'ON' if updater.enabled else 'OFF'}")

    def add(self):
        clear()
        site = i("Site: ")
        user = i("Username: ")
        pw = i("Password: ")
        self.data.append({"site": site, "username": user, "password": pw})
        self.save()
        p(f"{C.GREEN}Saved{C.RESET}")
        time.sleep(1)

    def view(self):
        clear()
        for k, v in enumerate(self.data):
            p(f"[{k}] {v['site']} - {v['username']}")
        i("")

    def delete(self):
        clear()
        for k, v in enumerate(self.data):
            p(f"[{k}] {v['site']}")
        try:
            idx = int(i("Delete: "))
            self.data.pop(idx)
            self.save()
        except:
            pass

    def run_update(self):
        clear()
        p(f"{C.YELLOW}Update available. Apply? (y/n){C.RESET}")
        c = i("> ").lower()
        if c == "y":
            apply_update(updater.data["download_url"])
        updater.update_available = False

    def run(self):
        init_vault()
        self.timer.start()

        while True:
            updater.run_check()

            if updater.update_available and updater.enabled:
                self.run_update()

            if self.locked:
                r = self.unlock()
                if r == "UPDATE":
                    continue
                continue

            self.menu()
            c = i("Choice: ")
            self.reset()

            if updater.update_available and updater.enabled:
                self.run_update()

            if c == "1":
                self.add()
            elif c == "2":
                self.view()
            elif c == "3":
                self.delete()
            elif c == "4":
                self.lock()
            elif c == "5":
                break


if __name__ == "__main__":
    App().run()