# ecc_crypto.py
# ECC demo dùng cho đồ án Bảo mật thông tin

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, base64


class ECCRoomKey:
    def __init__(self):
        # tạo private key
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.shared_key = None

    def _derive_key(self):
        # sinh key đối xứng từ ECC (demo)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ecc-chat",
        ).derive(b"shared-secret")

    def encrypt(self, plaintext: str) -> str:
        key = self._derive_key()
        iv = os.urandom(12)

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv)
        ).encryptor()

        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        data = iv + encryptor.tag + ciphertext
        return base64.b64encode(data).decode()

    def decrypt(self, ciphertext: str) -> str:
        raw = base64.b64decode(ciphertext.encode())
        iv = raw[:12]
        tag = raw[12:28]
        data = raw[28:]

        key = self._derive_key()
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag)
        ).decryptor()

        plaintext = decryptor.update(data) + decryptor.finalize()
        return plaintext.decode()
