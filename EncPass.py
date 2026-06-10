import os
import json
import base64
import hashlib
import time
import threading
import itertools
import sys
import requests
import shutil
import tempfile

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

VAULT_FILE = "vault.json"
REPO_VERSION_URL = "https://raw.githubusercontent.com/sungjinwoodev/EncPass/main/version.json"
LOCAL_FILE = __file__

AUTO_LOCK_SECONDS = 180
UPDATE_INTERVAL = 10800 

LOCAL_VERSION = "1.0.1"

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
        self.latest = None

    def version_url(self):
        return REPO_VERSION_URL + f"?t={time.time()}"

    def check(self):
        try:
            r = requests.get(self.version_url(), timeout=5)
            data = r.json()
            return data
        except:
            return None

    def download_new_version(self, url):
        try:
            r = requests.get(url, timeout=10)
            return r.text
        except:
            return None

    def apply_update(self, new_code):
        try:
            tmp_file = LOCAL_FILE + ".tmp"

            with open(tmp_file, "w", encoding="utf-8") as f:
                f.write(new_code)

            shutil.move(tmp_file, LOCAL_FILE)

            print(f"{C.GREEN}Updated successfully! Restarting...{C.RESET}")
            time.sleep(1)

            os.execv(sys.executable, [sys.executable, LOCAL_FILE])

        except Exception as e:
            print(f"{C.RED}Update failed: {e}{C.RESET}")

    def loop(self):
        while self.running:
            data = self.check()

            if data:
                remote_version = data.get("version")
                download_url = data.get("download_url")

                if remote_version and remote_version != LOCAL_VERSION:
                    print(f"\n{C.YELLOW}Update found: {remote_version}{C.RESET}")
                    choice = input("Do you want to update now? (y/n): ").strip().lower()

                    if choice == "y":
                        print("Downloading update...")
                        code = self.download_new_version(download_url)

                        if code:
                            self.apply_update(code)
                        else:
                            print(f"{C.RED}Download failed{C.RESET}")

                    else:
                        print(f"{C.CYAN}Update skipped{C.RESET}")

            time.sleep(UPDATE_INTERVAL)


updater = Updater()


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
    with open(VAULT_FILE, "w") as f:
        json.dump(vault, f)


def init_vault():
    if not os.path.exists(VAULT_FILE):
        print(f"{C.YELLOW}First time setup{C.RESET}")
        pw = input("Create Master Password: ")

        salt = os.urandom(16)
        blob = encrypt([], pw, salt)

        save_vault_file({
            "salt": base64.b64encode(salt).decode(),
            "blob": blob
        })

        print(f"{C.GREEN}Vault created{C.RESET}")
        time.sleep(1)


# ---------------- UI ----------------
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def loader(text="Loading", duration=2):
    spinner = itertools.cycle(["|", "/", "-", "\\"])
    end = time.time() + duration

    while time.time() < end:
        sys.stdout.write(f"\r{text} {next(spinner)}")
        sys.stdout.flush()
        time.sleep(0.1)

    sys.stdout.write("\r")


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
                print(f"\n{C.RED}Session expired{C.RESET}")
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
        save_vault_file({
            "salt": base64.b64encode(self.salt).decode(),
            "blob": blob
        })

    def unlock(self):
        clear()
        print(f"{C.CYAN}{C.BOLD}=== ENCPASS LOGIN ==={C.RESET}\n")

        while True:
            pw = input("Master Password: ")

            loader("Verifying", 1)

            if self.load(pw):
                print(f"{C.GREEN}Unlocked{C.RESET}")
                time.sleep(1)
                return True

            print(f"{C.RED}Wrong password{C.RESET}")

    def lock(self):
        self.master = None
        self.data = []
        self.locked = True

    def add(self):
        clear()
        site = input("Site: ")
        user = input("Username: ")
        pw = input("Password: ")

        self.data.append({"site": site, "username": user, "password": pw})
        self.save()

        print(f"{C.GREEN}Saved{C.RESET}")
        time.sleep(1)

    def view(self):
        clear()

        for i, item in enumerate(self.data):
            print(f"[{i}] {item['site']} - {item['username']}")

        try:
            idx = int(input("Index: "))
            item = self.data[idx]
            clear()
            print(item)
        except:
            print("Invalid")

        input()

    def delete(self):
        clear()

        for i, item in enumerate(self.data):
            print(f"[{i}] {item['site']}")

        try:
            idx = int(input("Delete: "))
            self.data.pop(idx)
            self.save()
        except:
            pass

    def menu(self):
        clear()
        print(f"{C.CYAN}{C.BOLD}=== ENCPASS ==={C.RESET}")
        print("1. Add")
        print("2. View")
        print("3. Delete")
        print("4. Lock")
        print("5. Exit")

    def run(self):
        init_vault()

        self.timer.start()
        threading.Thread(target=updater.loop, daemon=True).start()

        while True:
            if self.locked:
                if not self.unlock():
                    continue

            self.menu()
            c = input("Choice: ")
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


if __name__ == "__main__":
    App().run()
