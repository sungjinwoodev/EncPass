import os
import json
import base64
import hashlib
import time
import threading
import itertools
import sys
import requests

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# ---------------- CONFIG ----------------
VAULT_FILE = "vault.json"
REPO_VERSION_URL = "https://raw.githubusercontent.com/sungjinwoodev/EncPass/main/version.json"
AUTO_LOCK_SECONDS = 60
UPDATE_INTERVAL = 300 

# ---------------- COLORS (UNCHANGED UI) ----------------
class C:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"


# ---------------- UPDATE MANAGER ----------------
class UpdateManager:
    def __init__(self):
        self.latest_version = None
        self.running = True
        self.lock = threading.Lock()

    def check_update(self):
        try:
            r = requests.get(REPO_VERSION_URL, timeout=5)
            return r.json().get("version")
        except:
            return None

    def updater_loop(self):
        while self.running:
            latest = self.check_update()

            if latest:
                with self.lock:
                    self.latest_version = latest

            time.sleep(UPDATE_INTERVAL)


update_manager = UpdateManager()


# ---------------- CRYPTO CORE ----------------
def derive_key(password: str, salt: bytes) -> bytes:
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


# ---------------- VAULT ----------------
def load_vault_file():
    if not os.path.exists(VAULT_FILE):
        return None
    with open(VAULT_FILE, "r") as f:
        return json.load(f)


def save_vault_file(vault):
    with open(VAULT_FILE, "w") as f:
        json.dump(vault, f)


def init_vault_if_needed():
    if not os.path.exists(VAULT_FILE):
        print(f"{C.YELLOW}No vault found. Creating new vault...{C.RESET}")
        password = input("Create Master Password: ")

        salt = os.urandom(16)
        blob = encrypt([], password, salt)

        save_vault_file({
            "salt": base64.b64encode(salt).decode(),
            "blob": blob
        })

        print(f"{C.GREEN}Vault created successfully!{C.RESET}")
        time.sleep(1)


# ---------------- UI HELPERS (UNCHANGED) ----------------
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def loader(text="Loading", duration=2):
    spinner = itertools.cycle(["|", "/", "-", "\\"])
    end = time.time() + duration

    while time.time() < end:
        sys.stdout.write(f"\r{text} {next(spinner)}")
        sys.stdout.flush()
        time.sleep(0.1)

    sys.stdout.write("\r" + " " * (len(text) + 2) + "\r")


# ---------------- MAIN APP ----------------
class App:
    def __init__(self):
        self.master = None
        self.salt = None
        self.data = []
        self.locked = True
        self.last_action = time.time()
        self.timer = threading.Thread(target=self.auto_lock, daemon=True)

    # ---------- AUTO LOCK ----------
    def auto_lock(self):
        while True:
            if not self.locked and time.time() - self.last_action > AUTO_LOCK_SECONDS:
                clear()
                print(f"\n{C.RED}Session expired.{C.RESET}")
                self.lock()
            time.sleep(1)

    def reset_timer(self):
        self.last_action = time.time()

    # ---------- LOAD ----------
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

    # ---------- SAVE ----------
    def save(self):
        blob = encrypt(self.data, self.master, self.salt)
        save_vault_file({
            "salt": base64.b64encode(self.salt).decode(),
            "blob": blob
        })

    # ---------- LOGIN ----------
    def unlock(self):
        clear()
        print(f"{C.CYAN}{C.BOLD}=== ENCPASS LOGIN ==={C.RESET}\n")

        while True:
            password = input("Master Password: ")

            loader("Verifying", 1.2)

            if self.load(password):
                loader("Unlocking vault", 1.2)
                print(f"{C.GREEN}Unlocked successfully!{C.RESET}")
                time.sleep(1)
                return True

            print(f"{C.RED}Wrong password!{C.RESET}")
            time.sleep(1)

    # ---------- LOCK ----------
    def lock(self):
        self.master = None
        self.data = []
        self.locked = True

    # ---------- FEATURES (UNCHANGED) ----------
    def add(self):
        clear()
        site = input("Site: ")
        username = input("Username: ")
        password = input("Password: ")

        self.data.append({
            "site": site,
            "username": username,
            "password": password
        })

        self.save()
        self.reset_timer()
        print(f"{C.GREEN}Saved{C.RESET}")
        time.sleep(1)

    def view(self):
        clear()

        if not self.data:
            print(f"{C.RED}Empty vault{C.RESET}")
            input()
            return

        for i, item in enumerate(self.data):
            print(f"[{i}] {item['site']} - {item['username']}")

        try:
            idx = int(input("\nIndex: "))
            item = self.data[idx]
            clear()
            print("Site:", item["site"])
            print("Username:", item["username"])
            print("Password:", item["password"])
        except:
            print(f"{C.RED}Invalid{C.RESET}")

        self.reset_timer()
        input()

    def delete(self):
        clear()

        for i, item in enumerate(self.data):
            print(f"[{i}] {item['site']}")

        try:
            idx = int(input("Delete index: "))
            removed = self.data.pop(idx)
            self.save()
            print(f"{C.GREEN}Deleted {removed['site']}{C.RESET}")
        except:
            print(f"{C.RED}Invalid{C.RESET}")

        self.reset_timer()
        time.sleep(1)

    # ---------- MENU (UNCHANGED) ----------
    def menu(self):
        clear()
        print(f"{C.CYAN}{C.BOLD}=== ENCPASS ==={C.RESET}")

        # update notice (non-intrusive)
        with update_manager.lock:
            if update_manager.latest_version:
                print(f"{C.YELLOW}Update Available: v{update_manager.latest_version}{C.RESET}")

        print("1. Add")
        print("2. View")
        print("3. Delete")
        print("4. Lock")
        print("5. Exit")

    # ---------- RUN ----------
    def run(self):
        init_vault_if_needed()

        self.timer.start()
        threading.Thread(target=update_manager.updater_loop, daemon=True).start()

        while True:
            if self.locked:
                if not self.unlock():
                    continue

            self.menu()
            choice = input("Choice: ")
            self.reset_timer()

            if choice == "1":
                self.add()
            elif choice == "2":
                self.view()
            elif choice == "3":
                self.delete()
            elif choice == "4":
                self.lock()
                print(f"{C.RED}Locked{C.RESET}")
                time.sleep(1)
            elif choice == "5":
                update_manager.running = False
                break
            else:
                print(f"{C.RED}Invalid{C.RESET}")
                time.sleep(1)


if __name__ == "__main__":
    App().run()
