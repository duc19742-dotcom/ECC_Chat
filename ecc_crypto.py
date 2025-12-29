# ecc_crypto.py
from __future__ import annotations
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os


def pubkey_to_bytes(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize public key to bytes (PEM) for sending over network."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def bytes_to_pubkey(data: bytes) -> ec.EllipticCurvePublicKey:
    """Deserialize public key bytes (PEM) to object."""
    return serialization.load_pem_public_key(data)


@dataclass
class ECCSession:
    """
    ECC session:
    - Generate private/public key on curve SECP256R1 (P-256)
    - Perform ECDH -> shared secret
    - HKDF derive 32-byte AES key
    - Encrypt/Decrypt with AES-GCM
    """
    private_key: ec.EllipticCurvePrivateKey
    public_key: ec.EllipticCurvePublicKey
    peer_public_key: ec.EllipticCurvePublicKey | None = None
    aes_key: bytes | None = None

    @staticmethod
    def create() -> "ECCSession":
        priv = ec.generate_private_key(ec.SECP256R1())
        return ECCSession(private_key=priv, public_key=priv.public_key())

    def get_public_key_bytes(self) -> bytes:
        return pubkey_to_bytes(self.public_key)

    def set_peer_public_key_bytes(self, peer_pub_bytes: bytes) -> None:
        self.peer_public_key = bytes_to_pubkey(peer_pub_bytes)
        self._derive_aes_key()

    def _derive_aes_key(self) -> None:
        if self.peer_public_key is None:
            raise ValueError("Peer public key not set.")
        shared_secret = self.private_key.exchange(ec.ECDH(), self.peer_public_key)

        # HKDF: derive symmetric key for AES-GCM
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ECC-CHAT-AESGCM",
        )
        self.aes_key = hkdf.derive(shared_secret)

    def encrypt(self, plaintext: str) -> tuple[bytes, bytes]:
        """
        Returns (nonce, ciphertext).
        AESGCM output includes auth tag inside ciphertext bytes.
        """
        if self.aes_key is None:
            raise ValueError("AES key not derived yet (missing peer public key).")
        aesgcm = AESGCM(self.aes_key)
        nonce = os.urandom(12)  # 96-bit nonce
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return nonce, ct

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> str:
        if self.aes_key is None:
            raise ValueError("AES key not derived yet (missing peer public key).")
        aesgcm = AESGCM(self.aes_key)
        pt = aesgcm.decrypt(nonce, ciphertext, None)
        return pt.decode("utf-8")
