import os
import yaml
import base64
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

POSTS_DIR = "_posts"
PASSWORD = os.environ.get("PROTECTOR_PASSWORD", "debug").encode()

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

def aes_encrypt(password: bytes, plaintext: bytes):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    digest = h.finalize()

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode(),
        "salt": base64.b64encode(salt).decode(),
        "hmac": base64.b64encode(digest).decode()
    }

def encrypt_md_file(path: Path):
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return

    parts = text.split("---", 2)
    if len(parts) < 3:
        return
    frontmatter = parts[1]
    try:
        fm = yaml.safe_load(frontmatter)
    except Exception:
        return

    categories = fm.get("categories", [])
    if "Active" not in categories:
        return

    print(f"Encrypting: {path}")
    encrypted = aes_encrypt(PASSWORD, text.encode("utf-8"))

    # overwrite the file with encrypted YAML
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(encrypted, f, sort_keys=False)

def main():
    for md_file in Path(POSTS_DIR).glob("*.md"):
        encrypt_md_file(md_file)

if __name__ == "__main__":
    main()
