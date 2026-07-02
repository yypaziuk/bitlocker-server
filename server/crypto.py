"""At-rest encryption for recovery passwords (variant A2).

Master passphrase is provided at runtime via /unlock and NEVER stored on disk.
A 32-byte key is derived with scrypt(passphrase, salt). Only `salt.bin` and a
`verifier.bin` (a known token encrypted with the key) are persisted, so we can
validate the passphrase on unlock. The derived key lives only in process RAM.
"""
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATA_DIR = os.environ.get("ESCROW_DATA", "/opt/escrow/data")
SALT_FILE = os.path.join(DATA_DIR, "salt.bin")
VERIFIER_FILE = os.path.join(DATA_DIR, "verifier.bin")
_VERIFY_TOKEN = b"ESCROW-VERIFY-OK"
_SCRYPT = dict(length=32, n=2**15, r=8, p=1)   # ~strong, ~100ms


class Vault:
    def __init__(self):
        self._key = None  # in RAM only

    def _derive(self, passphrase: str, salt: bytes) -> bytes:
        return Scrypt(salt=salt, **_SCRYPT).derive(passphrase.encode())

    def is_setup(self) -> bool:
        return os.path.exists(SALT_FILE) and os.path.exists(VERIFIER_FILE)

    def is_unlocked(self) -> bool:
        return self._key is not None

    def setup(self, passphrase: str):
        """First-time: create salt + verifier, load key into RAM."""
        os.makedirs(DATA_DIR, exist_ok=True)
        if self.is_setup():
            raise RuntimeError("master already initialized")
        salt = os.urandom(16)
        key = self._derive(passphrase, salt)
        nonce = os.urandom(12)
        blob = nonce + AESGCM(key).encrypt(nonce, _VERIFY_TOKEN, None)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        with open(VERIFIER_FILE, "wb") as f:
            f.write(blob)
        os.chmod(SALT_FILE, 0o600)
        os.chmod(VERIFIER_FILE, 0o600)
        self._key = key

    def unlock(self, passphrase: str) -> bool:
        if not self.is_setup():
            raise RuntimeError("not initialized")
        salt = open(SALT_FILE, "rb").read()
        key = self._derive(passphrase, salt)
        blob = open(VERIFIER_FILE, "rb").read()
        try:
            AESGCM(key).decrypt(blob[:12], blob[12:], None)
        except Exception:
            return False
        self._key = key
        return True

    def lock(self):
        self._key = None

    def encrypt(self, plaintext: str) -> bytes:
        if not self._key:
            raise RuntimeError("vault is locked")
        nonce = os.urandom(12)
        return nonce + AESGCM(self._key).encrypt(nonce, plaintext.encode(), None)

    def decrypt(self, blob: bytes) -> str:
        if not self._key:
            raise RuntimeError("vault is locked")
        return AESGCM(self._key).decrypt(blob[:12], blob[12:], None).decode()


vault = Vault()


# ---- standalone helpers (used by the offline master-passphrase rotation tool) ----
def derive_key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, **_SCRYPT).derive(passphrase.encode())


def enc_with(key: bytes, plaintext: str) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext.encode(), None)


def dec_with(key: bytes, blob: bytes) -> str:
    return AESGCM(key).decrypt(blob[:12], blob[12:], None).decode()


def make_verifier(key: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, _VERIFY_TOKEN, None)


def check_verifier(key: bytes, blob: bytes) -> bool:
    try:
        AESGCM(key).decrypt(blob[:12], blob[12:], None)
        return True
    except Exception:
        return False
